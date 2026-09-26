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

// A client owns (see sys_*.go for the exact paths): the installed binary, a
// stopped-by-default system service that runs `tunel service`, the mode it
// last ran in, and, once a server link was given, client.json with the link
// and a marked Host block in the user's ~/.ssh/config.
//
// The service runs in one of two modes:
//   server  all traffic goes through the server (tunel on)
//   dpi     traffic leaves directly, past DPI blocks, no server (tunel dpi)

const (
	modeServer = "server"
	modeDPI    = "dpi"
)

// currentMode is the mode the service runs in, or last ran in.
func currentMode() string {
	raw, _ := os.ReadFile(clientModePath)
	switch m := strings.TrimSpace(string(raw)); m {
	case modeServer, modeDPI:
		return m
	}
	if hasLink() {
		return modeServer
	}
	return modeDPI
}

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

// hasLink reports whether a server link was set up (tunel on works).
func hasLink() bool {
	_, err := os.Stat(clientStatePath)
	return err == nil
}

// ---------- tunel client LINK ----------

func cmdClient(args []string) error {
	var raw string
	switch len(args) {
	case 0:
		fmt.Print("Paste the link from your server, or press Enter for DPI bypass only: ")
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return fmt.Errorf("no link given")
		}
		if strings.TrimSpace(line) == "" {
			return cmdDPI()
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
	sshUnblock() // tunel before v0.1.5 added a Host block; it is not needed
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
	wasOn, mode := svcRunning(), currentMode()
	if wasOn {
		if err := svcStop(); err != nil {
			return err
		}
	}
	ip, err := probeLink(l)
	if err != nil {
		if wasOn {
			svcStart(mode)
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
	return svcStart(modeServer)
}

// ---------- tunel dpi ----------

// cmdDPI sets up the service if needed; no server or link is involved.
func cmdDPI() error {
	if !serviceExists() || isLinux {
		if err := asAdmin("dpi"); err != nil {
			return err
		}
	} else if err := svcStart(modeDPI); err != nil {
		return err
	}
	return cmdStatus()
}

func adminDPI() error {
	if !serviceExists() {
		if err := installClient(); err != nil {
			return err
		}
		ok("installed %s", installedBin)
	}
	return svcStart(modeDPI)
}

// ---------- on / off / status ----------

func cmdOn() error {
	if !hasLink() {
		return fmt.Errorf("no server link yet; run: tunel client 'vless://…'  (or tunel dpi for DPI bypass only)")
	}
	if err := svcControl("on"); err != nil {
		return err
	}
	return cmdStatus()
}

func cmdOff() error {
	if !serviceExists() {
		return fmt.Errorf("not set up")
	}
	if err := svcControl("off"); err != nil {
		return err
	}
	return cmdStatus()
}

func cmdStatus() error {
	if !serviceExists() {
		if _, err := os.Stat(serverUnitPath); err == nil {
			return serverStatus()
		}
		usage()
		return nil
	}
	var l Link
	if hasLink() {
		var err error
		if l, err = loadClient(); err != nil {
			return err
		}
	}
	if svcStarting() {
		// A start at boot waiting for the network, and in on mode for the server.
		what := "the network"
		if currentMode() == modeServer {
			what = "the server; if it does not answer, the tunnel stays off"
		}
		fmt.Printf("%s◌%s starting  %swaiting for %s%s\n", cYellow, cReset, cDim, what, cReset)
		fmt.Printf("%s  tunel off stops waiting%s\n", cDim, cReset)
		return nil
	}
	if !svcRunning() {
		fmt.Printf("%s○%s off\n", cYellow, cReset)
		if hasLink() {
			fmt.Printf("%s  tunel on   all traffic through %s%s\n", cDim, l.Host, cReset)
		}
		fmt.Printf("%s  tunel dpi  your own connection, past DPI blocks%s\n", cDim, cReset)
		autostartHint()
		return nil
	}
	// A plain request already takes the tunnel's way out.
	var ip string
	var err error
	for i := 0; i < 4; i++ {
		if ip, err = publicIP(&http.Client{Timeout: 5 * time.Second}); err == nil {
			break
		}
		time.Sleep(time.Second)
	}
	if currentMode() == modeDPI {
		if err != nil {
			fmt.Printf("%s●%s dpi  %sno internet%s\n", cYellow, cReset, cYellow, cReset)
			fmt.Printf("%s  log: %s%s\n", cDim, clientLogHint, cReset)
		} else {
			fmt.Printf("%s●%s dpi  %s\n", cGreen, cReset, ip)
			fmt.Printf("%s  your own connection · DNS over HTTPS · TLS split against DPI%s\n", cDim, cReset)
		}
		autostartHint()
		warnConflicts()
		return nil
	}
	if err != nil {
		fmt.Printf("%s●%s on  %sno route to the server%s\n", cYellow, cReset, cYellow, cReset)
		fmt.Printf("%s  the internet is blocked until the server answers or you run: tunel off%s\n", cDim, cReset)
		fmt.Printf("%s  log: %s%s\n", cDim, clientLogHint, cReset)
		return nil
	}
	fmt.Printf("%s●%s on  %s\n", cGreen, cReset, ip)
	fmt.Printf("%s  all traffic goes through the server%s\n", cDim, cReset)
	autostartHint()
	warnConflicts()
	return nil
}

// ---------- tunel autostart ----------

// With autostart on, the service starts at boot and picks up where it was
// left: in the last mode, or not at all after `tunel off`. In server mode it
// first waits for the server, and stays off if the server does not answer.

func cmdAutostart(args []string) error {
	if !serviceExists() {
		return fmt.Errorf("not set up; run: tunel client")
	}
	if len(args) == 0 {
		if autostartEnabled() {
			fmt.Println("autostart on: at boot tunel comes back as you left it")
		} else {
			fmt.Println("autostart off: after a reboot tunel is off until you turn it on")
		}
		return nil
	}
	if len(args) != 1 || (args[0] != "on" && args[0] != "off") {
		return fmt.Errorf("usage: tunel autostart on | off")
	}
	if err := asAdmin("autostart", args[0]); err != nil {
		return err
	}
	if args[0] == "on" {
		ok("at boot tunel comes back as you left it: on, dpi, or off")
		ok("in on mode it first waits for the server; if the server does not answer, it stays off")
	} else {
		ok("after a reboot tunel is off until you turn it on")
	}
	return nil
}

func adminAutostart(args []string) error {
	if len(args) != 1 {
		return fmt.Errorf("internal: autostart needs on or off")
	}
	return setAutostart(args[0] == "on")
}

func autostartHint() {
	if autostartEnabled() {
		fmt.Printf("%s  starts at boot as you left it · tunel autostart off%s\n", cDim, cReset)
	}
}

func warnConflicts() {
	for _, name := range conflictingPrograms() {
		fmt.Printf("\n%s⚠ %s is running.%s It rewrites outgoing packets, which breaks some\n", cYellow, name, cReset)
		fmt.Printf("  connections through tunel (TLS 1.2 sites and apps). tunel already gets\n")
		fmt.Printf("  around DPI in both modes, so %s is not needed; close it.\n", name)
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
		ok("the old tunel block in ~/.ssh/config")
	}
	return nil
}

func adminRemove() error {
	any := false
	if hasLink() || serviceExists() {
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

// errServerDown means the server did not answer, so the tunnel stays off
// rather than cutting the computer off the internet.
var errServerDown = errors.New("the server does not answer")

// startFailure explains a service that stopped while starting, from its log.
func startFailure(log string) error {
	if strings.Contains(log, errServerDown.Error()) {
		return fmt.Errorf("the server does not answer, so the tunnel stays off and the internet works as usual")
	}
	return fmt.Errorf("the tunnel did not start:\n%s", log)
}

// startTunnel brings the tunnel up in mode; closing the result takes it down.
// The service wrapper of each OS calls it. patient is for a start nobody is
// waiting on (at boot, after a crash): the network may still be coming up,
// so it keeps trying for up to 90 seconds; tick reports progress meanwhile,
// and ending ctx gives up at once.
func startTunnel(ctx context.Context, mode, logPath string, patient bool, tick func()) (io.Closer, error) {
	if logPath != "" {
		os.WriteFile(logPath, nil, 0o644) // start each run with a fresh log
	}
	logf := func(format string, a ...any) {
		if logPath != "" {
			appendLog(logPath, "tunel: "+fmt.Sprintf(format, a...))
		} else {
			fmt.Fprintf(os.Stderr, "tunel: "+format+"\n", a...)
		}
	}
	deadline := time.Now().Add(90 * time.Second)
	retry := func(f func() bool) {
		for !f() && patient && time.Now().Before(deadline) {
			tick()
			select {
			case <-ctx.Done():
				return
			case <-time.After(3 * time.Second):
			}
		}
	}

	if mode == modeDPI {
		// Picked before the tunnel is up, so on the network as it is.
		doh := ""
		retry(func() bool { doh = pickDoH(); return doh != "" })
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		logf("DNS over HTTPS via %q (\"\" = none answers; plain DNS %s)", doh, fallbackDNS)
		return startBox(context.Background(), dpiConfig(0, logPath, doh))
	}

	l, err := loadClient()
	if err != nil {
		return nil, err
	}
	var probeErr error
	retry(func() bool { _, probeErr = probeLink(l); return probeErr == nil })
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if probeErr != nil {
		logf("%v (%v); the tunnel stays off and the internet works as usual", errServerDown, shortErr(probeErr))
		return nil, errServerDown
	}
	return startBox(context.Background(), clientConfig(l, 0, logPath))
}

func appendLog(path, line string) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o644)
	if err != nil {
		return
	}
	fmt.Fprintln(f, line)
	f.Close()
}

// ---------- ~/.ssh/config left by older versions ----------

// tunel no longer touches ~/.ssh/config: with the whole computer in the
// tunnel, `ssh` to the server's address already goes through it. Versions
// before v0.1.5 added a marked Host block; setup and remove take it out.

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
