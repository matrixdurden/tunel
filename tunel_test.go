package main

import (
	"context"
	"crypto/tls"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestLinkRoundTrip(t *testing.T) {
	_, pub := newRealityKeys()
	want := Link{
		UUID: newUUID(), Host: "203.0.113.7", Port: 443, SNI: "dl.google.com",
		PublicKey: pub, ShortID: newShortID(), Name: "ali",
	}
	got, err := ParseLink(want.String())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

// The bash tunel and tunel before v0.1.5 printed links with an ssh= port;
// they must keep working.
func TestParseOldLink(t *testing.T) {
	old := "vless://abdcb308-c39d-46e6-9ecf-690f7197ad64@176.40.71.186:443?encryption=none&flow=xtls-rprx-vision" +
		"&security=reality&sni=dl.google.com&fp=chrome&pbk=rkXAfADOSJiKVB_saF64fcDBtqfIKbN8GQ_5jtOfwFI" +
		"&sid=dd1a9f36dc990730&type=tcp&ssh=60001#justrises"
	l, err := ParseLink(old)
	if err != nil {
		t.Fatal(err)
	}
	if l.Host != "176.40.71.186" || l.Name != "justrises" || l.ShortID != "dd1a9f36dc990730" {
		t.Fatalf("%+v", l)
	}
}

func TestParseLinkRejects(t *testing.T) {
	good := Link{UUID: newUUID(), Host: "1.2.3.4", Port: 443, SNI: "a.com", PublicKey: "k", ShortID: "ab"}.String()
	for name, s := range map[string]string{
		"not vless":  "https://example.com",
		"bad uuid":   strings.Replace(good, "vless://", "vless://x", 1),
		"no reality": strings.Replace(good, "security=reality", "security=tls", 1),
		"no pbk":     strings.Replace(good, "pbk=k", "pbk=", 1),
		"ws":         strings.Replace(good, "type=tcp", "type=ws", 1),
	} {
		if _, err := ParseLink(s); err == nil {
			t.Errorf("%s: accepted %s", name, s)
		}
	}
	if l, err := ParseLink(good); err != nil || l.Name != "tunel" {
		t.Errorf("defaults: %+v %v", l, err)
	}
}

func TestRealityPublicKey(t *testing.T) {
	priv, pub := newRealityKeys()
	got, err := realityPublicKey(priv)
	if err != nil || got != pub {
		t.Fatalf("got %q %v, want %q", got, err, pub)
	}
}

func TestClientConfigParses(t *testing.T) {
	_, pub := newRealityKeys()
	l := Link{UUID: newUUID(), Host: "203.0.113.7", Port: 443, SNI: "dl.google.com", PublicKey: pub, ShortID: "ab"}
	for _, socks := range []int{0, 1080} {
		cfg := clientConfig(l, socks, "")
		if err := checkConfig(cfg); err != nil {
			t.Errorf("socks=%d: %v", socks, err)
		}
	}
	s := newServer(443)
	if err := checkConfig(serverConfig(s, "")); err != nil {
		t.Errorf("server: %v", err)
	}
	for _, socks := range []int{0, 1080} {
		if err := checkConfig(dpiConfig(socks, "")); err != nil {
			t.Errorf("dpi socks=%d: %v", socks, err)
		}
	}
}

// TestDPIDirect checks that DPI mode's DNS over HTTPS and TLS record
// splitting leave ordinary sites working. It needs internet access.
func TestDPIDirect(t *testing.T) {
	if testing.Short() {
		t.Skip("needs internet")
	}
	port, _ := freePort()
	b, err := startBox(context.Background(), dpiConfig(port, os.DevNull))
	if err != nil {
		t.Fatal(err)
	}
	defer b.Close()
	proxy, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", port))
	for _, max := range []uint16{tls.VersionTLS13, tls.VersionTLS12} {
		hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
			Proxy:           http.ProxyURL(proxy),
			TLSClientConfig: &tls.Config{MaxVersion: max},
		}}
		if _, err := publicIP(hc); err != nil {
			t.Errorf("TLS max %x: %v", max, err)
		}
	}
}

// TestEndToEnd runs a real server and a real client on this machine and
// fetches a page through them. It needs internet access.
func TestEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("needs internet")
	}
	port, err := freePort()
	if err != nil {
		t.Fatal(err)
	}
	s := newServer(port)
	srv, err := startBox(context.Background(), serverConfig(s, os.DevNull))
	if err != nil {
		t.Fatal(err)
	}
	defer srv.Close()
	if !waitTCP(fmt.Sprintf("127.0.0.1:%d", port), 5*time.Second) {
		t.Fatal("server did not listen")
	}

	ip, err := s.selfTest()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("through the tunnel: %s", ip)

	// Inner TLS 1.2 takes a different path through the Vision flow than 1.3.
	l0 := s.link(s.Users[0])
	l0.Host = "127.0.0.1"
	sp, _ := freePort()
	cli, err := startBox(context.Background(), clientConfig(l0, sp, os.DevNull))
	if err != nil {
		t.Fatal(err)
	}
	proxy, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", sp))
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{
		Proxy:           http.ProxyURL(proxy),
		TLSClientConfig: &tls.Config{MaxVersion: tls.VersionTLS12},
	}}
	if _, err := publicIP(hc); err != nil {
		t.Errorf("TLS 1.2 through the tunnel: %v", err)
	}
	cli.Close()

	// A wrong key must not get through.
	l := s.link(s.Users[0])
	l.Host = "127.0.0.1"
	_, l.PublicKey = newRealityKeys()
	if _, err := probeLink(l); err == nil {
		t.Fatal("a client with the wrong key got through")
	}
}

func TestChecksumFor(t *testing.T) {
	sums := filepath.Join(t.TempDir(), "checksums.txt")
	os.WriteFile(sums, []byte("AA11  tunel-linux-amd64\nbb22 *tunel-windows-amd64.exe\n"), 0o644)
	for asset, want := range map[string]string{"tunel-linux-amd64": "aa11", "tunel-windows-amd64.exe": "bb22"} {
		if got, err := checksumFor(sums, asset); err != nil || got != want {
			t.Errorf("%s: %q %v", asset, got, err)
		}
	}
	if _, err := checksumFor(sums, "tunel-linux-arm64"); err == nil {
		t.Error("missing asset accepted")
	}
}

func TestLatestTag(t *testing.T) {
	if testing.Short() {
		t.Skip("needs internet")
	}
	tag, err := latestTag()
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("latest release: %s", tag)
}

// Older versions added a marked Host block; it must go, and nothing else.
func TestSSHUnblock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SUDO_USER", "")
	path := filepath.Join(home, ".ssh", "config")
	os.MkdirAll(filepath.Dir(path), 0o700)

	own := "Host justrises\n    HostName 176.40.71.186\n    Port 60001\n    IdentityFile ~/.ssh/id_ed25519\n"
	old := sshBegin + "\nHost justrises\n  HostName 176.40.71.186\n  Port 60001\n" + sshEnd + "\n"
	os.WriteFile(path, []byte(old+own), 0o600)
	if removed, err := sshUnblock(); err != nil || !removed {
		t.Fatal(removed, err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != own {
		t.Fatalf("not restored:\n%q", raw)
	}
	if removed, err := sshUnblock(); err != nil || removed {
		t.Fatal("second run changed something", removed, err)
	}

	// A file that held only the block was tunel's own, and goes.
	os.WriteFile(path, []byte(old), 0o600)
	sshUnblock()
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("empty config left behind")
	}
}
