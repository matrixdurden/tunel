package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// A client owns (see sys_*.go for the exact paths): the installed binary,
// client.json with the link, a stopped-by-default system service that runs
// `tunel service`, and a marked Host block in the user's ~/.ssh/config.

func loadClient() (Link, error) {
	raw, err := os.ReadFile(clientStatePath)
	if err != nil {
		return Link{}, err
	}
	var l Link
	if err := json.Unmarshal(raw, &l); err != nil {
		return Link{}, fmt.Errorf("%s: %w", clientStatePath, err)
	}
	return l, nil
}

func clientInstalled() bool {
	_, err := os.Stat(clientStatePath)
	return err == nil
}

// ---------- tunel client LINK ----------

func cmdClient(args []string) error {
	var raw string
	switch len(args) {
	case 0:
		fmt.Print("Paste the link from your server: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("no link given")
		}
		raw = line
	case 1:
		raw = args[0]
	default:
		return fmt.Errorf("usage: tunel client 'vless://…' (quote the link)")
	}
	l, err := ParseLink(strings.TrimSpace(raw))
	if err != nil {
		return err
	}
	if err := asAdmin("client-install", l.String()); err != nil {
		return err
	}
	if err := sshBlock(l); err != nil {
		bad("ssh config: %v", err)
	} else {
		ok("ssh %s", l.Name)
	}
	fmt.Println()
	return cmdStatus()
}

func adminClientInstall(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("internal: missing link")
	}
	l, err := ParseLink(args[0])
	if err != nil {
		return err
	}
	// Check the link before touching the system: a wrong link must not leave
	// a half-installed tunnel that blocks the internet. The check must reach
	// the server directly, so a running tunnel is paused for it.
	wasOn := svcRunning()
	if wasOn {
		if err := svcStop(); err != nil {
			return err
		}
	}
	ip, err := probeLink(l)
	if err != nil {
		if wasOn {
			svcStart()
		}
		return fmt.Errorf("could not reach the server through the link (%v); nothing was changed", err)
	}
	ok("server %s answers", ip)
	raw, _ := json.MarshalIndent(l, "", "  ")
	if err := writeFileAtomic(clientStatePath, append(raw, '\n'), 0o600); err != nil {
		return err
	}
	if err := installClient(); err != nil {
		return err
	}
	ok("installed %s", installedBin)
	return svcStart()
}

// ---------- on / off / status ----------

func cmdOn() error {
	if !clientInstalled() {
		return fmt.Errorf("not set up; run: tunel client 'vless://…'")
	}
	if err := svcControl("on"); err != nil {
		return err
	}
	return cmdStatus()
}

func cmdOff() error {
	if !clientInstalled() {
		return fmt.Errorf("not set up")
	}
	if err := svcControl("off"); err != nil {
		return err
	}
	return cmdStatus()
}

func cmdStatus() error {
	if !clientInstalled() {
		if _, err := os.Stat(serverUnitPath); err == nil {
			return serverStatus()
		}
		usage()
		return nil
	}
	l, err := loadClient()
	if err != nil {
		return err
	}
	if !svcRunning() {
		fmt.Printf("%s○%s off\n", cYellow, cReset)
		fmt.Printf("%s  tunel on  sends all traffic through %s%s\n", cDim, l.Host, cReset)
		return nil
	}
	// With the tunnel on, a plain request already leaves through the server.
	var ip string
	for i := 0; i < 4; i++ {
		if ip, err = publicIP(&http.Client{Timeout: 5 * time.Second}); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if err != nil {
		fmt.Printf("%s●%s on  %sno route to the server%s\n", cYellow, cReset, cYellow, cReset)
		fmt.Printf("%s  the internet is blocked until the server answers or you run: tunel off%s\n", cDim, cReset)
		fmt.Printf("%s  log: %s%s\n", cDim, clientLogHint, cReset)
		return nil
	}
	fmt.Printf("%s●%s on  %s\n", cGreen, cReset, ip)
	fmt.Printf("%s  all traffic goes through the server · ssh %s%s\n", cDim, l.Name, cReset)
	warnConflicts()
	return nil
}

func warnConflicts() {
	for _, name := range conflictingPrograms() {
		fmt.Printf("\n%s⚠ %s is running.%s It rewrites outgoing packets, which breaks some\n", cYellow, name, cReset)
		fmt.Printf("  connections through the tunnel (TLS 1.2 sites and apps). The tunnel already\n")
		fmt.Printf("  gets around DPI, so close %s while tunel is on.\n", name)
	}
}

// ---------- tunel remove ----------

func cmdRemove() error {
	if err := asAdmin("remove"); err != nil {
		return err
	}
	if removed, err := sshUnblock(); err != nil {
		bad("ssh config: %v", err)
	} else if removed {
		ok("ssh config")
	}
	return nil
}

func adminRemove() error {
	any := false
	if clientInstalled() || serviceExists() {
		if err := uninstallClient(); err != nil {
			return err
		}
		ok("client: service, network adapter and settings")
		any = true
	}
	if isLinux {
		removed, err := adminRemoveServer()
		if err != nil {
			return err
		}
		if removed {
			ok("server: service and keys")
			any = true
		}
	}
	if _, err := os.Stat(installedBin); err == nil {
		any = true
	}
	if err := removeInstalledBin(); err != nil {
		return err
	}
	if any {
		ok("removed %s", installedBin)
	} else {
		fmt.Println("  nothing to remove")
	}
	return nil
}

// ---------- running the tunnel ----------

// startTunnel brings the tunnel up; closing the result takes it down. The
// service wrapper of each OS calls it.
func startTunnel(logPath string) (io.Closer, error) {
	l, err := loadClient()
	if err != nil {
		return nil, err
	}
	if logPath != "" {
		os.WriteFile(logPath, nil, 0o644) // start each run with a fresh log
	}
	return startBox(context.Background(), clientConfig(l, 0, logPath))
}

// ---------- ~/.ssh/config ----------

const (
	sshBegin = "# >>> tunel"
	sshEnd   = "# <<< tunel"
)

func sshConfigPath() (string, error) {
	home, err := userHome()
	if err != nil {
		return "", err
	}
	return filepath.Join(home, ".ssh", "config"), nil
}

// sshBlock puts `Host NAME` first in ~/.ssh/config. It points at the server's
// own address; with the tunnel on that reaches the server through the tunnel.
func sshBlock(l Link) error {
	path, err := sshConfigPath()
	if err != nil {
		return err
	}
	rest, err := sshWithoutBlock(path)
	if err != nil {
		return err
	}
	block := fmt.Sprintf("%s\nHost %s\n  HostName %s\n  Port %d\n  User %s\n  ServerAliveInterval 30\n%s\n",
		sshBegin, l.Name, l.Host, l.SSHPort, l.Name, sshEnd)
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	return rewriteInPlace(path, block+rest)
}

func sshUnblock() (bool, error) {
	path, err := sshConfigPath()
	if err != nil {
		return false, err
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return false, nil
	}
	rest, err := sshWithoutBlock(path)
	if err != nil || rest == string(raw) {
		return false, err
	}
	if strings.TrimSpace(rest) == "" {
		// Only the tunel block was there, so tunel created the file.
		return true, os.Remove(path)
	}
	return true, rewriteInPlace(path, rest)
}

func sshWithoutBlock(path string) (string, error) {
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	var out []string
	in := false
	for _, line := range strings.SplitAfter(string(raw), "\n") {
		t := strings.TrimRight(line, "\r\n")
		switch {
		case t == sshBegin:
			in = true
		case t == sshEnd && in:
			in = false
		case !in:
			out = append(out, line)
		}
	}
	return strings.Join(out, ""), nil
}

// rewriteInPlace keeps the file (and so its permissions and ACL, which
// Windows OpenSSH checks) instead of replacing it.
func rewriteInPlace(path, content string) error {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.WriteString(content); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}
