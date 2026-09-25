package main

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
)

// tunel update replaces the installed binary with the latest release and
// restarts what was running. Keys, users and the link stay as they are.

const releases = "https://github.com/matrixdurden/tunel/releases"

var tagRe = regexp.MustCompile(`^v\d+\.\d+\.\d+$`)

func serverInstalled() bool {
	_, err := os.Stat(serverUnitPath)
	return isLinux && err == nil
}

func cmdUpdate() error {
	if !clientInstalled() && !serverInstalled() {
		return fmt.Errorf("tunel is not set up on this computer; see %s", "https://github.com/matrixdurden/tunel")
	}
	latest, err := latestTag()
	if err != nil {
		return fmt.Errorf("could not check for updates: %w", err)
	}
	current := installedVersion()
	if current == latest {
		ok("already up to date (%s)", current)
		return nil
	}

	tmp, err := os.MkdirTemp("", "tunel-update-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(tmp)
	asset := "tunel-" + runtime.GOOS + "-" + runtime.GOARCH
	if runtime.GOOS == "windows" {
		asset += ".exe"
	}
	file := filepath.Join(tmp, asset)
	base := releases + "/download/" + latest // the tag, not "latest", so binary and checksum match
	if err := download(base+"/"+asset, file); err != nil {
		return err
	}
	sums := filepath.Join(tmp, "checksums.txt")
	if err := download(base+"/checksums.txt", sums); err != nil {
		return err
	}
	want, err := checksumFor(sums, asset)
	if err != nil {
		return err
	}
	if got, err := sha256File(file); err != nil || got != want {
		return fmt.Errorf("checksum mismatch; nothing was changed")
	}
	os.Chmod(file, 0o755)
	ok("downloaded %s", latest)

	if err := asAdmin("upgrade", file, want); err != nil {
		return err
	}
	ok("updated %s → %s", current, latest)
	if clientInstalled() {
		fmt.Println()
		return cmdStatus()
	}
	return nil
}

func adminUpgrade(args []string) error {
	if len(args) != 2 {
		return fmt.Errorf("internal: upgrade needs a file and its checksum")
	}
	file, want := args[0], args[1]
	// Check again: the file sat in a folder the unprivileged user can write.
	if got, err := sha256File(file); err != nil || got != want {
		return fmt.Errorf("checksum mismatch; nothing was changed")
	}
	wasOn := clientInstalled() && svcRunning()
	if wasOn {
		if err := svcStop(); err != nil {
			return err
		}
	}
	if err := installFile(file, installedBin); err != nil {
		if wasOn {
			svcStart()
		}
		return err
	}
	if wasOn {
		if err := svcStart(); err != nil {
			return err
		}
	}
	if serverInstalled() {
		if err := restartServer(); err != nil {
			return err
		}
	}
	return nil
}

// installedVersion asks the installed binary, which may be older than this one.
func installedVersion() string {
	out, err := exec.Command(installedBin, "version").Output()
	if v := strings.TrimSpace(string(out)); err == nil && v != "" {
		return v
	}
	return version
}

// latestTag reads the tag that /releases/latest redirects to; unlike the API
// this has no rate limit.
func latestTag() (string, error) {
	hc := &http.Client{
		Timeout:       20 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := hc.Get(releases + "/latest")
	if err != nil {
		return "", err
	}
	resp.Body.Close()
	tag := path.Base(resp.Header.Get("Location"))
	if !tagRe.MatchString(tag) {
		return "", fmt.Errorf("unexpected answer from GitHub (%s)", resp.Status)
	}
	return tag, nil
}

func download(url, dst string) error {
	hc := &http.Client{Timeout: 5 * time.Minute}
	resp, err := hc.Get(url)
	if err != nil {
		return fmt.Errorf("download %s: %w", url, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download %s: %s", url, resp.Status)
	}
	f, err := os.Create(dst)
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, resp.Body); err != nil {
		f.Close()
		return fmt.Errorf("download %s: %w", url, err)
	}
	return f.Close()
}

func checksumFor(sumsFile, asset string) (string, error) {
	raw, err := os.ReadFile(sumsFile)
	if err != nil {
		return "", err
	}
	for _, line := range strings.Split(string(raw), "\n") {
		f := strings.Fields(line)
		if len(f) == 2 && strings.TrimPrefix(f[1], "*") == asset {
			return strings.ToLower(f[0]), nil
		}
	}
	return "", errors.New("the release has no checksum for " + asset)
}

func sha256File(p string) (string, error) {
	f, err := os.Open(p)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
