package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func waitGone(t *testing.T, p string) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if _, err := os.Stat(p); os.IsNotExist(err) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s is still there", p)
}

// The folder name has a space, like "Program Files".
func TestDeleteLaterFolder(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tunel test")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "tunel.exe"), []byte("x"), 0o644)
	if err := deleteLater(dir); err != nil {
		t.Fatal(err)
	}
	waitGone(t, dir)
}

// A running .exe can be replaced; the old copy goes once it exits.
func TestInstallFileOverRunningExe(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tunel test")
	dst := filepath.Join(dir, "tunel.exe")
	ping, _ := exec.LookPath("ping.exe")
	if err := installFile(ping, dst); err != nil {
		t.Fatal(err)
	}
	run := exec.Command(dst, "-n", "4", "127.0.0.1") // runs about 3 seconds
	if err := run.Start(); err != nil {
		t.Fatal(err)
	}
	newer := filepath.Join(t.TempDir(), "new.exe")
	os.WriteFile(newer, []byte("new version"), 0o755)
	if err := installFile(newer, dst); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(dst); string(got) != "new version" {
		t.Fatalf("dst not replaced: %q", got)
	}
	run.Wait()
	waitGone(t, dst+".old")
}

func TestWintunDriversParses(t *testing.T) {
	t.Logf("wintun packages in the driver store: %v", wintunDrivers())
}
