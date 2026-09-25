package main

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

// The folder name has a space, like "Program Files".
func TestDeleteLater(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "tunel test")
	os.MkdirAll(dir, 0o755)
	os.WriteFile(filepath.Join(dir, "tunel.exe"), []byte("x"), 0o644)
	if err := deleteLater(dir, 1); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dir); err != nil {
		t.Fatal("deleted too early")
	}
	for i := 0; i < 50; i++ {
		if _, err := os.Stat(dir); os.IsNotExist(err) {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("folder still there")
}

func TestWintunDriversParses(t *testing.T) {
	t.Logf("wintun packages in the driver store: %v", wintunDrivers())
}
