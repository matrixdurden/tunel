package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"syscall"
	"time"
)

// The server is a Linux machine with systemd. Everything it owns:
//   /etc/tunel/server.json                     keys and users
//   /etc/systemd/system/tunel-server.service   runs `tunel serve`
//   /usr/local/bin/tunel                       this binary

const (
	serverStatePath = "/etc/tunel/server.json"
	serverUnitPath  = "/etc/systemd/system/tunel-server.service"
	serverUnit      = "tunel-server"
	linuxBin        = "/usr/local/bin/tunel"
	oldXrayConfig   = "/usr/local/etc/xray/config.json"
)

// Reality borrows the TLS handshake of one of these sites. The first that
// works from the server is used.
var snis = []string{"dl.google.com", "www.samsung.com", "www.nvidia.com", "addons.mozilla.org"}

type User struct {
	Name string `json:"name"`
	UUID string `json:"uuid"`
}

type ServerState struct {
	Host       string `json:"host"` // public IP, found by the self-test
	Port       int    `json:"port"`
	SNI        string `json:"sni"`
	PrivateKey string `json:"private_key"`
	PublicKey  string `json:"public_key"`
	ShortID    string `json:"short_id"`
	Users      []User `json:"users"`
}

func loadServer() (*ServerState, error) {
	raw, err := os.ReadFile(serverStatePath)
	if err != nil {
		return nil, err
	}
	s := &ServerState{}
	if err := json.Unmarshal(raw, s); err != nil {
		return nil, fmt.Errorf("%s: %w", serverStatePath, err)
	}
	return s, nil
}

func (s *ServerState) save() error {
	raw, _ := json.MarshalIndent(s, "", "  ")
	return writeFileAtomic(serverStatePath, append(raw, '\n'), 0o600)
}

func (s *ServerState) user(name string) *User {
	for i := range s.Users {
		if s.Users[i].Name == name {
			return &s.Users[i]
		}
	}
	return nil
}

func (s *ServerState) link(u User) Link {
	return Link{
		UUID: u.UUID, Host: s.Host, Port: s.Port, SNI: s.SNI,
		PublicKey: s.PublicKey, ShortID: s.ShortID, SSHPort: sshdPort(), Name: u.Name,
	}
}

func requireLinuxServer() error {
	if runtime.GOOS != "linux" {
		return fmt.Errorf("the server needs Linux")
	}
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("the server needs systemd")
	}
	return nil
}

// ---------- tunel server ----------

func adminServer(args []string) error {
	if err := requireLinuxServer(); err != nil {
		return err
	}
	port := 443
	if len(args) > 0 {
		p, err := strconv.Atoi(args[0])
		if err != nil || p < 1 || p > 65535 {
			return fmt.Errorf("invalid port %q", args[0])
		}
		port = p
	}

	s, err := loadServer()
	fresh := errors.Is(err, os.ErrNotExist)
	if err != nil && !fresh {
		return err
	}
	if fresh {
		if s, err = importOldXray(); err != nil {
			return err
		}
		if s != nil {
			ok("imported the keys of the old xray server; existing links keep working")
		} else {
			s = newServer(port)
		}
		if err := portFree(s.Port); err != nil {
			return err
		}
	}

	if err := installSelf(linuxBin); err != nil {
		return err
	}
	if err := s.save(); err != nil {
		return err
	}
	if err := writeFileAtomic(serverUnitPath, []byte(serverUnitFile), 0o644); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if err := systemctl("enable", "--quiet", serverUnit); err != nil {
		return err
	}
	if err := restartServer(); err != nil {
		return err
	}
	ok("tunel %s :%d", version, s.Port)

	ip, err := s.selfTest()
	if err != nil {
		bad("sni %s", s.SNI)
		for _, sni := range snis {
			if sni == s.SNI {
				continue
			}
			s.SNI = sni
			if err := s.save(); err != nil {
				return err
			}
			if err := restartServer(); err != nil {
				return err
			}
			if ip, err = s.selfTest(); err == nil {
				break
			}
			bad("sni %s", sni)
		}
		if err != nil {
			return fmt.Errorf("no working SNI; see: journalctl -u %s", serverUnit)
		}
	}
	ok("sni %s", s.SNI)
	ok("self-test %s", ip)
	ok("ssh %d", sshdPort())
	if s.Host != ip {
		s.Host = ip
		if err := s.save(); err != nil {
			return err
		}
	}

	printLink(s.link(s.Users[0]))
	fmt.Printf("  %susers: %s · more: sudo tunel add NAME%s\n\n", cDim, userNames(s), cReset)
	return nil
}

func newServer(port int) *ServerState {
	priv, pub := newRealityKeys()
	return &ServerState{
		Port: port, SNI: snis[0], PrivateKey: priv, PublicKey: pub, ShortID: newShortID(),
		Users: []User{{Name: ownerName(), UUID: newUUID()}},
	}
}

// ownerName is the account that ran `sudo tunel server`; clients use it for ssh.
func ownerName() string {
	name := os.Getenv("SUDO_USER")
	if name == "" {
		if u, err := user.Current(); err == nil {
			name = u.Username
		}
	}
	if !nameRe.MatchString(name) || name == "root" {
		name = "me"
	}
	return name
}

// importOldXray takes over the keys of the server the earlier bash tunel set
// up, so links already handed out stay valid, then stops that xray.
func importOldXray() (*ServerState, error) {
	raw, err := os.ReadFile(oldXrayConfig)
	if err != nil {
		return nil, nil
	}
	var c struct {
		Inbounds []struct {
			Port     int `json:"port"`
			Settings struct {
				Clients []struct {
					ID string `json:"id"`
				} `json:"clients"`
			} `json:"settings"`
			StreamSettings struct {
				Security        string `json:"security"`
				RealitySettings struct {
					ServerNames []string `json:"serverNames"`
					PrivateKey  string   `json:"privateKey"`
					ShortIDs    []string `json:"shortIds"`
				} `json:"realitySettings"`
			} `json:"streamSettings"`
		} `json:"inbounds"`
	}
	if json.Unmarshal(raw, &c) != nil || len(c.Inbounds) == 0 {
		return nil, nil
	}
	in := c.Inbounds[0]
	r := in.StreamSettings.RealitySettings
	if in.StreamSettings.Security != "reality" || len(in.Settings.Clients) == 0 ||
		len(r.ServerNames) == 0 || len(r.ShortIDs) == 0 {
		return nil, nil
	}
	pub, err := realityPublicKey(r.PrivateKey)
	if err != nil {
		return nil, nil
	}
	s := &ServerState{Port: in.Port, SNI: r.ServerNames[0], PrivateKey: r.PrivateKey, PublicKey: pub, ShortID: r.ShortIDs[0]}
	for i, cl := range in.Settings.Clients {
		name := ownerName()
		if i > 0 {
			name = fmt.Sprintf("user%d", i+1)
		}
		s.Users = append(s.Users, User{Name: name, UUID: cl.ID})
	}
	// Free the port. xray stays installed; `tunel` never deletes what it did not create.
	if exec.Command("systemctl", "disable", "--now", "xray").Run() == nil {
		ok("stopped and disabled xray.service (it stays installed; tunel does not delete what it did not create)")
	}
	return s, nil
}

const serverUnitFile = `[Unit]
Description=tunel server
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/tunel serve
Restart=on-failure
RestartSec=3
LimitNOFILE=1048576

[Install]
WantedBy=multi-user.target
`

func restartServer() error {
	if err := systemctl("restart", serverUnit); err != nil {
		return err
	}
	if !waitTCP(fmt.Sprintf("127.0.0.1:%d", mustServerPort()), 5*time.Second) {
		return fmt.Errorf("the server did not start; see: journalctl -u %s", serverUnit)
	}
	return nil
}

func mustServerPort() int {
	if s, err := loadServer(); err == nil {
		return s.Port
	}
	return 443
}

// selfTest connects to this server exactly like a client would and returns
// the public IP the traffic leaves from.
func (s *ServerState) selfTest() (string, error) {
	l := s.link(s.Users[0])
	l.Host = "127.0.0.1"
	return probeLink(l)
}

// probeLink starts a throwaway client for l and asks api.ipify.org who we are.
func probeLink(l Link) (string, error) {
	port, err := freePort()
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	b, err := startBox(ctx, clientConfig(l, port, os.DevNull))
	if err != nil {
		return "", err
	}
	defer b.Close()
	proxy, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", port))
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	return publicIP(hc)
}

func publicIP(hc *http.Client) (string, error) {
	resp, err := hc.Get("https://api.ipify.org")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 64))
	ip := net.ParseIP(strings.TrimSpace(string(body)))
	if resp.StatusCode != 200 || ip == nil {
		return "", fmt.Errorf("unexpected answer from api.ipify.org")
	}
	return ip.String(), nil
}

// runServer is what tunel-server.service executes.
func runServer() error {
	s, err := loadServer()
	if err != nil {
		return err
	}
	b, err := startBox(context.Background(), serverConfig(s, ""))
	if err != nil {
		return err
	}
	waitSignal()
	return b.Close()
}

// ---------- users ----------

func loadServerForAdmin() (*ServerState, error) {
	if err := requireLinuxServer(); err != nil {
		return nil, err
	}
	s, err := loadServer()
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("this machine is not a server yet; run: tunel server")
	}
	return s, err
}

func nameArg(args []string) (string, error) {
	if len(args) != 1 || !nameRe.MatchString(args[0]) {
		return "", fmt.Errorf("give one name: letters, digits, . _ - (at most 32)")
	}
	return args[0], nil
}

func adminAdd(args []string) error {
	name, err := nameArg(args)
	if err != nil {
		return err
	}
	s, err := loadServerForAdmin()
	if err != nil {
		return err
	}
	if s.user(name) != nil {
		return fmt.Errorf("%s already exists; tunel link %s shows the link", name, name)
	}
	s.Users = append(s.Users, User{Name: name, UUID: newUUID()})
	if err := s.save(); err != nil {
		return err
	}
	if err := restartServer(); err != nil {
		return err
	}
	ok("added %s", name)
	printLink(s.link(*s.user(name)))
	return nil
}

func adminDel(args []string) error {
	name, err := nameArg(args)
	if err != nil {
		return err
	}
	s, err := loadServerForAdmin()
	if err != nil {
		return err
	}
	if s.user(name) == nil {
		return fmt.Errorf("no user %s", name)
	}
	if len(s.Users) == 1 {
		return fmt.Errorf("%s is the last user; tunel remove removes the server", name)
	}
	kept := s.Users[:0]
	for _, u := range s.Users {
		if u.Name != name {
			kept = append(kept, u)
		}
	}
	s.Users = kept
	if err := s.save(); err != nil {
		return err
	}
	if err := restartServer(); err != nil {
		return err
	}
	ok("removed %s; their link no longer works", name)
	return nil
}

func adminUsers() error {
	s, err := loadServerForAdmin()
	if err != nil {
		return err
	}
	for _, u := range s.Users {
		fmt.Println(u.Name)
	}
	return nil
}

func adminLink(args []string) error {
	name, err := nameArg(args)
	if err != nil {
		return err
	}
	s, err := loadServerForAdmin()
	if err != nil {
		return err
	}
	u := s.user(name)
	if u == nil {
		return fmt.Errorf("no user %s", name)
	}
	printLink(s.link(*u))
	return nil
}

func userNames(s *ServerState) string {
	names := make([]string, len(s.Users))
	for i, u := range s.Users {
		names[i] = u.Name
	}
	return strings.Join(names, ", ")
}

const scripts = "https://raw.githubusercontent.com/matrixdurden/tunel/main"

func printLink(l Link) {
	fmt.Printf("\n  %sLink for %s:%s\n\n  %s\n\n", cBold, l.Name, cReset, l)
	fmt.Printf("  Set up a computer with it:\n\n")
	fmt.Printf("  %sWindows%s  in PowerShell, then paste the link when asked:\n", cBold, cReset)
	fmt.Printf("           irm %s/install.ps1 | iex\n\n", scripts)
	fmt.Printf("  %sLinux%s    curl -fsSL %s/install.sh | sh -s -- client '%s'\n\n", cBold, cReset, scripts, l)
}

// serverStatus needs no root: the state file is private, the unit is not.
func serverStatus() error {
	if exec.Command("systemctl", "is-active", "--quiet", serverUnit).Run() == nil {
		fmt.Printf("%s●%s server on\n", cGreen, cReset)
	} else {
		fmt.Printf("%s○%s server stopped%s  sudo systemctl start %s%s\n", cYellow, cReset, cDim, serverUnit, cReset)
	}
	fmt.Printf("%s  tunel users · tunel add NAME · tunel link NAME%s\n", cDim, cReset)
	return nil
}

func adminRemoveServer() (bool, error) {
	if _, err := os.Stat(serverStatePath); err != nil {
		if _, err := os.Stat(serverUnitPath); err != nil {
			return false, nil
		}
	}
	exec.Command("systemctl", "disable", "--now", serverUnit).Run()
	for _, p := range []string{serverUnitPath, serverStatePath} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return true, err
		}
	}
	systemctl("daemon-reload")
	return true, nil
}

// ---------- helpers ----------

func sshdPort() int {
	files, _ := filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
	files = append(files, "/etc/ssh/sshd_config")
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		for sc.Scan() {
			fields := strings.Fields(sc.Text())
			if len(fields) >= 2 && strings.EqualFold(fields[0], "port") {
				if p, err := strconv.Atoi(fields[1]); err == nil {
					fh.Close()
					return p
				}
			}
		}
		fh.Close()
	}
	return 22
}

var spaces = regexp.MustCompile(`\s+`)

func systemctl(args ...string) error {
	out, err := exec.Command("systemctl", args...).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl %s: %s", strings.Join(args, " "),
			spaces.ReplaceAllString(strings.TrimSpace(string(out)), " "))
	}
	return nil
}

func portFree(port int) error {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		return fmt.Errorf("port %d is already in use", port)
	}
	return l.Close()
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

func waitTCP(addr string, d time.Duration) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if c, err := net.DialTimeout("tcp", addr, 500*time.Millisecond); err == nil {
			c.Close()
			return true
		}
		time.Sleep(200 * time.Millisecond)
	}
	return false
}

func waitSignal() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, syscall.SIGINT, syscall.SIGTERM)
	<-ch
}

func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
