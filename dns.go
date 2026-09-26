package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// DNS over HTTPS servers, by address so no lookup is needed to reach them, in
// order of preference. Networks that filter DNS often block some of them.
var dohServers = []string{"1.1.1.1", "8.8.8.8", "9.9.9.9", "1.0.0.1", "8.8.4.4", "149.112.112.112", "94.140.14.140"}

// fallbackDNS is used when no DoH server answers: plain DNS, which a filtering
// network may redirect to its own resolver, but the internet keeps working.
const fallbackDNS = "8.8.8.8"

type dohResult struct {
	Server string
	Addrs  []string
	Took   time.Duration
	Err    error
}

// probeDoH asks every DoH server for name at once.
func probeDoH(name string, timeout time.Duration) []dohResult {
	res := make([]dohResult, len(dohServers))
	var wg sync.WaitGroup
	for i, s := range dohServers {
		wg.Add(1)
		go func(i int, s string) {
			defer wg.Done()
			start := time.Now()
			addrs, err := dohLookup(s, name, timeout)
			res[i] = dohResult{Server: s, Addrs: addrs, Took: time.Since(start), Err: err}
		}(i, s)
	}
	wg.Wait()
	return res
}

// pickDoH returns the most preferred DoH server that answers on this
// network, or "" if none does.
func pickDoH() string {
	for _, r := range probeDoH("www.google.com", 4*time.Second) {
		if r.Err == nil {
			return r.Server
		}
	}
	return ""
}

// dohLookup resolves name's IPv4 addresses with an RFC 8484 GET.
func dohLookup(server, name string, timeout time.Duration) ([]string, error) {
	q := dnsQuery(name)
	url := fmt.Sprintf("https://%s/dns-query?dns=%s", server, base64.RawURLEncoding.EncodeToString(q))
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	req.Header.Set("Accept", "application/dns-message")
	resp, err := (&http.Client{Transport: &http.Transport{Proxy: nil}}).Do(req)
	if err != nil {
		return nil, shortErr(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("HTTP %d", resp.StatusCode)
	}
	addrs, err := dnsAnswers(body)
	if err != nil {
		return nil, err
	}
	if len(addrs) == 0 {
		return nil, fmt.Errorf("no answer")
	}
	return addrs, nil
}

func dnsQuery(name string) []byte {
	var b bytes.Buffer
	b.Write([]byte{0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0}) // id 0, RD, one question
	for _, label := range strings.Split(strings.TrimSuffix(name, "."), ".") {
		b.WriteByte(byte(len(label)))
		b.WriteString(label)
	}
	b.Write([]byte{0, 0, 1, 0, 1}) // root, type A, class IN
	return b.Bytes()
}

// dnsAnswers returns the A records of a DNS response.
func dnsAnswers(m []byte) ([]string, error) {
	if len(m) < 12 {
		return nil, fmt.Errorf("short DNS answer")
	}
	if rcode := m[3] & 0x0f; rcode != 0 {
		return nil, fmt.Errorf("DNS error %d", rcode)
	}
	qd, an := int(binary.BigEndian.Uint16(m[4:])), int(binary.BigEndian.Uint16(m[6:]))
	off := 12
	skipName := func() bool {
		for off < len(m) {
			l := int(m[off])
			switch {
			case l == 0:
				off++
				return true
			case l&0xc0 == 0xc0:
				off += 2
				return true
			default:
				off += 1 + l
			}
		}
		return false
	}
	for i := 0; i < qd; i++ {
		if !skipName() {
			return nil, fmt.Errorf("bad DNS answer")
		}
		off += 4
	}
	var addrs []string
	for i := 0; i < an; i++ {
		if !skipName() || off+10 > len(m) {
			return nil, fmt.Errorf("bad DNS answer")
		}
		typ := binary.BigEndian.Uint16(m[off:])
		rdlen := int(binary.BigEndian.Uint16(m[off+8:]))
		off += 10
		if off+rdlen > len(m) {
			return nil, fmt.Errorf("bad DNS answer")
		}
		if typ == 1 && rdlen == 4 {
			addrs = append(addrs, net.IP(m[off:off+4]).String())
		}
		off += rdlen
	}
	return addrs, nil
}

// shortErr turns Go's long network errors into a few words.
func shortErr(err error) error {
	s := err.Error()
	for _, k := range []struct{ in, out string }{
		{"deadline exceeded", "timeout"}, {"i/o timeout", "timeout"}, {"Client.Timeout", "timeout"},
		{"connection reset", "connection reset"}, {"forcibly closed", "connection reset"},
		{"wsarecv", "connection reset"}, {"wsasend", "connection reset"}, // Windows, any language
		{"connection refused", "refused"}, {"actively refused", "refused"},
		{"no such host", "no such host"}, {"unknown authority", "certificate not trusted"},
		{"EOF", "closed by the network"}, {"unreachable", "unreachable"},
	} {
		if strings.Contains(s, k.in) {
			return fmt.Errorf("%s", k.out)
		}
	}
	if len(s) > 80 {
		s = s[:80] + "…"
	}
	return fmt.Errorf("%s", s)
}
