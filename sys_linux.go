package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/user"
	"path/filepath"
	"time"
)

// On Linux a client owns:
//   /usr/local/bin/tunel                this binary
//   /etc/tunel/client.json              the link
//   /etc/systemd/system/tunel.service   runs `tunel service`; never enabled, so off after a reboot
//   the "tunel" TUN device              exists only while the tunnel is on

const (
	isLinux         = true
	installedBin    = linuxBin
	clientStatePath = "/etc/tunel/client.json"
	clientUnitPath  = "/etc/systemd/system/tunel.service"
	clientUnit      = "tunel"
	clientLogHint   = "journalctl -u tunel"
)

const clientUnitFile = `[Unit]
Description=tunel client
After=network-online.target
Wants=network-online.target

[Service]
ExecStart=/usr/local/bin/tunel service
Restart=on-failure
RestartSec=3
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

// installSelf copies the running binary to dst. Writing a new file and
// renaming it over dst works even while dst is running.
func installSelf(dst string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	if a, errA := os.Stat(exe); errA == nil {
		if b, errB := os.Stat(dst); errB == nil && os.SameFile(a, b) {
			return nil
		}
	}
	in, err := os.Open(exe)
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
	exec.Command("systemctl", "stop", clientUnit).Run()
	for _, p := range []string{clientUnitPath, clientStatePath} {
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

func svcRunning() bool {
	return exec.Command("systemctl", "is-active", "--quiet", clientUnit).Run() == nil
}

func svcControl(op string) error {
	return asAdmin(op)
}

func svcStart() error {
	if err := systemctl("start", clientUnit); err != nil {
		return err
	}
	// The unit reports active at once; give sing-box a moment to fail if it will.
	time.Sleep(1500 * time.Millisecond)
	if !svcRunning() {
		out, _ := exec.Command("journalctl", "-u", clientUnit, "-n", "8", "--no-pager", "-o", "cat").Output()
		return fmt.Errorf("the tunnel did not start:\n%s", out)
	}
	return nil
}

func svcStop() error {
	if !serviceExists() {
		return nil
	}
	return systemctl("stop", clientUnit)
}

func runClientService() error {
	b, err := startTunnel("")
	if err != nil {
		return err
	}
	waitSignal()
	return b.Close()
}
