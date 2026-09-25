package main

import (
	"context"
	"fmt"
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
		PublicKey: pub, ShortID: newShortID(), SSHPort: 60001, Name: "ali",
	}
	got, err := ParseLink(want.String())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("got %+v\nwant %+v", got, want)
	}
}

// The bash tunel printed links in this shape; they must keep working.
func TestParseOldLink(t *testing.T) {
	old := "vless://abdcb308-c39d-46e6-9ecf-690f7197ad64@176.40.71.186:443?encryption=none&flow=xtls-rprx-vision" +
		"&security=reality&sni=dl.google.com&fp=chrome&pbk=rkXAfADOSJiKVB_saF64fcDBtqfIKbN8GQ_5jtOfwFI" +
		"&sid=dd1a9f36dc990730&type=tcp&ssh=60001#justrises"
	l, err := ParseLink(old)
	if err != nil {
		t.Fatal(err)
	}
	if l.Host != "176.40.71.186" || l.SSHPort != 60001 || l.Name != "justrises" || l.ShortID != "dd1a9f36dc990730" {
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
	if l, err := ParseLink(good); err != nil || l.SSHPort != 22 || l.Name != "tunel" {
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

	// A wrong key must not get through.
	l := s.link(s.Users[0])
	l.Host = "127.0.0.1"
	_, l.PublicKey = newRealityKeys()
	if _, err := probeLink(l); err == nil {
		t.Fatal("a client with the wrong key got through")
	}
}

func TestSSHBlock(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Setenv("SUDO_USER", "")
	path := filepath.Join(home, ".ssh", "config")
	os.MkdirAll(filepath.Dir(path), 0o700)
	orig := "Host other\n  HostName 10.0.0.1\n"
	os.WriteFile(path, []byte(orig), 0o600)

	l := Link{Host: "203.0.113.7", SSHPort: 60001, Name: "ali"}
	for i := 0; i < 2; i++ { // twice: must not duplicate
		if err := sshBlock(l); err != nil {
			t.Fatal(err)
		}
	}
	raw, _ := os.ReadFile(path)
	if strings.Count(string(raw), sshBegin) != 1 || !strings.HasPrefix(string(raw), sshBegin) ||
		!strings.Contains(string(raw), "Port 60001") || !strings.HasSuffix(string(raw), orig) {
		t.Fatalf("unexpected config:\n%s", raw)
	}
	if removed, err := sshUnblock(); err != nil || !removed {
		t.Fatal(removed, err)
	}
	raw, _ = os.ReadFile(path)
	if string(raw) != orig {
		t.Fatalf("not restored:\n%q", raw)
	}
}
