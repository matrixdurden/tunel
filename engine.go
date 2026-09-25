package main

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/netip"
	"runtime"

	box "github.com/sagernet/sing-box"
	"github.com/sagernet/sing-box/include"
	"github.com/sagernet/sing-box/option"
	sjson "github.com/sagernet/sing/common/json"
)

// The tunnel engine is sing-box, embedded. These functions only build its
// configuration; nothing here touches the system until startBox runs it.

type obj = map[string]any

const tunName = "tunel"

// Traffic to these never enters the tunnel: the LAN, link-local, multicast.
var lanRanges = []string{
	"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16",
	"224.0.0.0/4", "255.255.255.255/32",
	"fc00::/7", "fe80::/10", "ff00::/8",
}

func logOptions(path string) obj {
	o := obj{"level": "warn", "timestamp": true}
	if path != "" {
		o["output"] = path
	}
	return o
}

// clientConfig routes the whole machine through the server when socksPort is 0.
// With a socksPort it only opens a local SOCKS5/HTTP proxy (used by self-tests).
func clientConfig(l Link, socksPort int, logPath string) obj {
	proxy := obj{
		"type": "vless", "tag": "proxy",
		"server": l.Host, "server_port": l.Port,
		"uuid": l.UUID, "flow": "xtls-rprx-vision", "packet_encoding": "xudp",
		"tls": obj{
			"enabled": true, "server_name": l.SNI,
			"utls":    obj{"enabled": true, "fingerprint": "chrome"},
			"reality": obj{"enabled": true, "public_key": l.PublicKey, "short_id": l.ShortID},
		},
	}
	cfg := obj{
		"log":       logOptions(logPath),
		"outbounds": []obj{proxy, {"type": "direct", "tag": "direct"}},
	}
	if socksPort != 0 {
		cfg["inbounds"] = []obj{{"type": "mixed", "tag": "socks", "listen": "127.0.0.1", "listen_port": socksPort}}
		cfg["route"] = obj{"final": "proxy"}
		return cfg
	}

	// gVisor on Windows: the system stack needs a firewall exception there.
	stack := "mixed"
	if runtime.GOOS == "windows" {
		stack = "gvisor"
	}
	cfg["inbounds"] = []obj{{
		"type": "tun", "tag": "tun",
		"interface_name":        tunName,
		"address":               []string{"198.18.0.1/30", "fdfe:dcba:9876::1/126"},
		"auto_route":            true,
		"strict_route":          true,
		"route_exclude_address": lanRanges,
		"stack":                 stack,
	}}
	cfg["dns"] = obj{
		"servers": []obj{
			// DNS goes through the tunnel too, so the local network never sees names.
			{"type": "https", "tag": "remote", "server": "1.1.1.1", "detour": "proxy"},
			// Only for resolving the server itself if the link uses a domain.
			{"type": "udp", "tag": "bootstrap", "server": "1.1.1.1"},
		},
		"final":    "remote",
		"strategy": "ipv4_only",
	}
	rules := []obj{
		{"action": "sniff"},
		{"protocol": "dns", "action": "hijack-dns"},
		// QUIC cannot ride the Vision flow; rejecting it makes apps fall back to TCP at once.
		{"network": "udp", "port": 443, "action": "reject"},
	}
	if ip, err := netip.ParseAddr(l.Host); err == nil {
		// The server's own address means the server itself: SSH and its local
		// web apps work without the server's router having to loop back.
		loopback := "127.0.0.1"
		if ip.Is6() {
			loopback = "::1"
		}
		rules = append(rules, obj{
			"ip_cidr": []string{netip.PrefixFrom(ip, ip.BitLen()).String()},
			"action":  "route-options", "override_address": loopback,
		})
	}
	cfg["route"] = obj{
		"rules":                   rules,
		"final":                   "proxy",
		"auto_detect_interface":   true,
		"default_domain_resolver": "bootstrap",
	}
	return cfg
}

func serverConfig(s *ServerState, logPath string) obj {
	users := make([]obj, 0, len(s.Users))
	for _, u := range s.Users {
		users = append(users, obj{"name": u.Name, "uuid": u.UUID, "flow": "xtls-rprx-vision"})
	}
	return obj{
		"log": logOptions(logPath),
		"inbounds": []obj{{
			"type": "vless", "tag": "vless",
			"listen": "::", "listen_port": s.Port,
			"users": users,
			"tls": obj{
				"enabled": true, "server_name": s.SNI,
				"reality": obj{
					"enabled":     true,
					"handshake":   obj{"server": s.SNI, "server_port": 443},
					"private_key": s.PrivateKey,
					"short_id":    []string{s.ShortID},
				},
			},
		}},
		"outbounds": []obj{{"type": "direct", "tag": "direct"}},
	}
}

func newBox(ctx context.Context, cfg obj) (*box.Box, error) {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return nil, err
	}
	ctx = include.Context(ctx)
	opts, err := sjson.UnmarshalExtendedContext[option.Options](ctx, raw)
	if err != nil {
		return nil, fmt.Errorf("config: %w", err)
	}
	return box.New(box.Options{Context: ctx, Options: opts})
}

// checkConfig validates cfg without starting anything.
func checkConfig(cfg obj) error {
	b, err := newBox(context.Background(), cfg)
	if err != nil {
		return err
	}
	return b.Close()
}

func startBox(ctx context.Context, cfg obj) (*box.Box, error) {
	b, err := newBox(ctx, cfg)
	if err != nil {
		return nil, err
	}
	if err := b.Start(); err != nil {
		b.Close()
		return nil, err
	}
	return b, nil
}

// ---------- key material ----------

func newUUID() string {
	var b [16]byte
	rand.Read(b[:])
	b[6] = b[6]&0x0f | 0x40
	b[8] = b[8]&0x3f | 0x80
	h := hex.EncodeToString(b[:])
	return h[0:8] + "-" + h[8:12] + "-" + h[12:16] + "-" + h[16:20] + "-" + h[20:32]
}

func newShortID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// newRealityKeys returns an X25519 key pair in the encoding Xray and sing-box use.
func newRealityKeys() (private, public string) {
	k, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic(err)
	}
	enc := base64.RawURLEncoding
	return enc.EncodeToString(k.Bytes()), enc.EncodeToString(k.PublicKey().Bytes())
}

func realityPublicKey(private string) (string, error) {
	enc := base64.RawURLEncoding
	raw, err := enc.DecodeString(private)
	if err != nil {
		return "", err
	}
	k, err := ecdh.X25519().NewPrivateKey(raw)
	if err != nil {
		return "", err
	}
	return enc.EncodeToString(k.PublicKey().Bytes()), nil
}
