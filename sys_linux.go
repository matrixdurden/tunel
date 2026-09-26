package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"time"
)

// On Linux a client owns:
//   /usr/local/bin/tunel                this binary
//   /etc/tunel/client.json              the link
//   /etc/systemd/system/tunel.service   runs `tunel service`; enabled only by tunel autostart on
//   /etc/tunel/mode, /etc/tunel/off     the last mode, and whether tunel off was the last word
//   the "tunel" TUN device              exists only while the tunnel is on

const (
	isLinux         = true
	installedBin    = linuxBin
	clientStatePath = "/etc/tunel/client.json"
	clientModePath  = "/etc/tunel/mode"
	offFlagPath     = "/etc/tunel/off"
	clientUnitPath  = "/etc/systemd/system/tunel.service"
	clientUnit      = "tunel"
	clientLogHint   = "journalctl -u tunel"
	// Marks a start by tunel on/dpi. /run is emptied at boot, so a start at
	// boot never sees it.
	explicitMark = "/run/tunel-explicit-start"
)

const clientUnitFile = `[Unit]
Description=tunel client
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/tunel service
Restart=on-failure
RestartSec=3

[Install]
WantedBy=multi-user.target
`

func setupConsole() {
	if fi, err := os.Stdout.Stat(); err != nil || fi.Mode()&os.ModeCharDevice == 0 {
		noColor()
	}
}

// ownConsole reports a double-click start; there is no such thing on Linux.
func ownConsole() bool {
	return false
}

// conflictingPrograms lists running programs known to break the tunnel.
func conflictingPrograms() []string {
	return nil
}

func isAdmin() bool {
	return os.Geteuid() == 0
}

func runElevated(args []string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command("sudo", append([]string{exe}, adminChildArgs("-", args)...)...)
	cmd.Stdin, cmd.Stdout, cmd.Stderr = os.Stdin, os.Stdout, os.Stderr
	if err := cmd.Run(); err != nil {
		var exit *exec.ExitError
		if errors.As(err, &exit) {
			return errReported
		}
		return fmt.Errorf("sudo: %w", err)
	}
	return nil
}

// userHome is the invoking user's home, also under sudo.
func userHome() (string, error) {
	if os.Geteuid() == 0 {
		if name := os.Getenv("SUDO_USER"); name != "" {
			if u, err := user.Lookup(name); err == nil {
				return u.HomeDir, nil
			}
		}
	}
	return os.UserHomeDir()
}

// installSelf copies the running binary to dst.
func installSelf(dst string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	return installFile(exe, dst)
}

// installFile copies src to dst. Writing a new file and renaming it over dst
// works even while dst is running.
func installFile(src, dst string) error {
	if a, errA := os.Stat(src); errA == nil {
		if b, errB := os.Stat(dst); errB == nil && os.SameFile(a, b) {
			return nil
		}
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	tmp := dst + ".tmp"
	out, err := os.OpenFile(tmp, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o755)
	if err != nil {
		return err
	}
	if _, err := io.Copy(out, in); err != nil {
		out.Close()
		os.Remove(tmp)
		return err
	}
	if err := out.Close(); err != nil {
		return err
	}
	return os.Rename(tmp, dst)
}

func installClient() error {
	if _, err := exec.LookPath("systemctl"); err != nil {
		return fmt.Errorf("the client needs systemd")
	}
	if err := installSelf(installedBin); err != nil {
		return err
	}
	if err := writeFileAtomic(clientUnitPath, []byte(clientUnitFile), 0o644); err != nil {
		return err
	}
	return systemctl("daemon-reload")
}

func uninstallClient() error {
	exec.Command("systemctl", "disable", "--now", clientUnit).Run()
	for _, p := range []string{clientUnitPath, clientStatePath, clientModePath, offFlagPath, explicitMark} {
		if err := os.Remove(p); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	systemctl("daemon-reload")
	return nil
}

func removeInstalledBin() error {
	os.Remove(filepath.Dir(clientStatePath)) // /etc/tunel, only if empty
	if err := os.Remove(installedBin); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func serviceExists() bool {
	_, err := os.Stat(clientUnitPath)
	return err == nil
}

func unitActive() bool {
	return exec.Command("systemctl", "is-active", "--quiet", clientUnit).Run() == nil
}

func tunUp() bool {
	_, err := net.InterfaceByName(tunName)
	return err == nil
}

// svcRunning reports whether the tunnel is up, not just its service.
func svcRunning() bool {
	return unitActive() && tunUp()
}

// svcStarting reports a service still waiting to bring the tunnel up.
func svcStarting() bool {
	return unitActive() && !tunUp()
}

func svcControl(op string) error {
	return asAdmin(op)
}

// svcStart starts the service in mode, switching if it runs in the other one.
func svcStart(mode string) error {
	if svcRunning() && currentMode() == mode {
		return nil
	}
	if err := writeFileAtomic(clientModePath, []byte(mode+"\n"), 0o644); err != nil {
		return err
	}
	os.Remove(offFlagPath)
	os.WriteFile(explicitMark, nil, 0o644)
	if err := systemctl("restart", clientUnit); err != nil {
		return err
	}
	// The unit reports active at once; the tunnel is up once its device is.
	// Server mode first checks the server, which takes a moment.
	for i := 0; i < 60; i++ {
		time.Sleep(500 * time.Millisecond)
		if !unitActive() {
			out, _ := exec.Command("journalctl", "-u", clientUnit, "-n", "8", "--no-pager", "-o", "cat").Output()
			return startFailure(string(out))
		}
		if tunUp() {
			return nil
		}
	}
	return fmt.Errorf("the tunnel is taking too long to start; see: %s", clientLogHint)
}

// svcStop turns the tunnel off and remembers that it was turned off, so
// autostart leaves it off. Callers that turn it back on right after clear this.
func svcStop() error {
	if !serviceExists() {
		return nil
	}
	os.WriteFile(offFlagPath, nil, 0o644)
	return systemctl("stop", clientUnit)
}

func runClientService() error {
	_, err := os.Stat(explicitMark)
	explicit := err == nil
	os.Remove(explicitMark)
	if !explicit {
		if _, err := os.Stat(offFlagPath); err == nil {
			fmt.Fprintln(os.Stderr, "tunel: turned off before; staying off")
			return nil
		}
	}
	// systemctl stop sends SIGTERM, which ends a start still waiting too.
	b, err := startTunnel(context.Background(), currentMode(), "", !explicit, func() {})
	if errors.Is(err, errServerDown) {
		return nil // stopped on purpose; systemd does not restart a clean exit
	}
	if err != nil {
		return err
	}
	waitSignal()
	return b.Close()
}

// ---------- autostart ----------

func autostartEnabled() bool {
	return exec.Command("systemctl", "is-enabled", "--quiet", clientUnit).Run() == nil
}

func setAutostart(on bool) error {
	// Units written before autostart existed have no [Install] section.
	if err := writeFileAtomic(clientUnitPath, []byte(clientUnitFile), 0o644); err != nil {
		return err
	}
	if err := systemctl("daemon-reload"); err != nil {
		return err
	}
	if on {
		return systemctl("enable", "--quiet", clientUnit)
	}
	return systemctl("disable", "--quiet", clientUnit)
}
