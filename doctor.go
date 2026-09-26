package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"
)

// tunel doctor measures what this network does to traffic and says which
// mode will work. The report is also saved to a file, so it can be read at
// home when the network in question blocks everything else.

type report struct {
	b strings.Builder
}

var ansiRe = regexp.MustCompile("\x1b\\[[0-9;]*m")

func (r *report) line(format string, a ...any) {
	s := fmt.Sprintf(format, a...)
	fmt.Println(s)
	r.b.WriteString(ansiRe.ReplaceAllString(s, "") + "\n")
}

func (r *report) check(good bool, name, format string, a ...any) {
	mark := cGreen + "✓" + cReset
	plain := "✓"
	if !good {
		mark, plain = cRed+"✗"+cReset, "✗"
	}
	detail := fmt.Sprintf(format, a...)
	fmt.Printf("  %s %-22s %s\n", mark, name, detail)
	r.b.WriteString(fmt.Sprintf("  %s %-22s %s\n", plain, name, detail))
}

// The site used to see whether the network blocks by site name.
const blockedSite = "discord.com"

func cmdDoctor() error {
	r := &report{}
	r.line("tunel doctor %s · %s · %s/%s", version, time.Now().Format("2006-01-02 15:04"), runtime.GOOS, runtime.GOARCH)

	// Measure the network itself, not the tunnel: pause it and bring it back after.
	if serviceExists() && svcRunning() {
		mode := currentMode()
		op := map[string]string{modeServer: "on", modeDPI: "dpi"}[mode]
		r.line("  (the tunnel is paused while measuring; it comes back in %s mode)", mode)
		if err := svcControl("off"); err != nil {
			return err
		}
		defer func() {
			if err := svcControl(op); err != nil {
				bad("could not turn the tunnel back on: %v; run: tunel %s", err, op)
			}
		}()
	}

	// Everything below runs at once; results print in order.
	var (
		wg                  sync.WaitGroup
		inetErr, portalErr  error
		portalNote          string
		sysAddrs            []string
		sysErr              error
		doh                 []dohResult
		tlsRes              []tlsResult
		tcpTook, realTook   time.Duration
		tcpErr, realErr     error
		exitIP              string
		directErr, dpiErr   error
		directTook, dpiTook time.Duration
		link                Link
		linked              = hasLink()
	)
	if linked {
		link, _ = loadClient()
	}
	run := func(f func()) { wg.Add(1); go func() { defer wg.Done(); f() }() }

	run(func() { inetErr = httpCheck("https://www.google.com/generate_204", 204) })
	run(func() { portalNote, portalErr = captivePortal() })
	run(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 6*time.Second)
		defer cancel()
		sysAddrs, sysErr = net.DefaultResolver.LookupHost(ctx, blockedSite)
	})
	run(func() { doh = probeDoH(blockedSite, 6*time.Second) })
	if linked {
		run(func() {
			start := time.Now()
			c, err := net.DialTimeout("tcp", net.JoinHostPort(link.Host, fmt.Sprint(link.Port)), 6*time.Second)
			tcpTook, tcpErr = time.Since(start), err
			if err == nil {
				c.Close()
			}
		})
		run(func() {
			start := time.Now()
			exitIP, realErr = probeLink(link)
			realTook = time.Since(start)
		})
	}
	run(func() {
		start := time.Now()
		directErr = httpCheck("https://"+blockedSite+"/", 0)
		directTook = time.Since(start)
	})
	wg.Wait()

	// These need the DNS server DPI mode would pick: its answers are the real
	// addresses, so a wrong certificate there means inspection, not a DNS block.
	dohPick := ""
	for _, d := range doh {
		if d.Err == nil {
			dohPick = d.Server
			break
		}
	}
	run(func() { tlsRes = tlsChecks(link, dohPick) })
	run(func() {
		start := time.Now()
		dpiErr = dpiCheck(dohPick)
		dpiTook = time.Since(start)
	})
	wg.Wait()

	r.line("\nNetwork")
	r.check(inetErr == nil, "internet", "%s", okOr(inetErr, "https works"))
	r.check(portalErr == nil, "no sign-in page", "%s", okOr(portalErr, portalNote))

	r.line("\nDNS")
	dohAddrs := []string{}
	for _, d := range doh {
		if d.Err == nil {
			dohAddrs = d.Addrs
			break
		}
	}
	dnsRewritten := sysErr == nil && len(dohAddrs) > 0 && !overlaps(sysAddrs, dohAddrs)
	switch {
	case sysErr != nil:
		r.check(false, "network DNS", "%s: %v", blockedSite, shortErr(sysErr))
	case dnsRewritten:
		r.check(false, "network DNS", "%s → %s, but really %s: the network rewrites DNS",
			blockedSite, strings.Join(sysAddrs, " "), strings.Join(dohAddrs, " "))
	default:
		r.check(true, "network DNS", "%s → %s", blockedSite, strings.Join(sysAddrs, " "))
	}
	var parts []string
	for _, d := range doh {
		if d.Err == nil {
			parts = append(parts, fmt.Sprintf("%s ✓%dms", d.Server, d.Took.Milliseconds()))
		} else {
			parts = append(parts, fmt.Sprintf("%s ✗%v", d.Server, d.Err))
		}
	}
	r.check(dohPick != "", "DNS over HTTPS", "%s", strings.Join(parts, " · "))

	r.line("\nTLS inspection (does the network open HTTPS? checked at the sites' real addresses)")
	inspected := false
	for _, t := range tlsRes {
		if t.inspectedBy != "" {
			inspected = true
			r.check(false, t.sni, "certificate from %q instead of the site's: the network opens HTTPS here", t.inspectedBy)
		} else if t.err != nil && t.err.Error() == "connection reset" {
			r.check(false, t.sni, "connection cut: the network filters this site name (SNI)")
		} else if t.err != nil {
			r.check(false, t.sni, "%v", t.err)
		} else {
			r.check(true, t.sni, "genuine, issued by %s", t.issuer)
		}
	}

	if linked {
		r.line("\nServer %s:%d (tunel on)", link.Host, link.Port)
		r.check(tcpErr == nil, "reachable", "%s", okOr(shortErrOrNil(tcpErr), fmt.Sprintf("TCP in %dms", tcpTook.Milliseconds())))
		r.check(realErr == nil, "tunnel handshake", "%s", okOr(shortErrOrNil(realErr), fmt.Sprintf("leaves as %s, %dms", exitIP, realTook.Milliseconds())))
	}

	r.line("\nA blocked site: %s (tunel dpi)", blockedSite)
	if directErr != nil && dnsRewritten {
		directErr = fmt.Errorf("blocked: the network's DNS sends it to a block page")
	}
	r.check(directErr == nil, "direct", "%s", okOr(shortErrOrNil(directErr), fmt.Sprintf("opens, %dms (not blocked here)", directTook.Milliseconds())))
	r.check(dpiErr == nil, "with tunel dpi", "%s", okOr(shortErrOrNil(dpiErr), fmt.Sprintf("opens, %dms", dpiTook.Milliseconds())))

	if names := conflictingPrograms(); len(names) > 0 {
		r.line("\n%s⚠ running: %s — close it, it breaks tunel%s", cYellow, strings.Join(names, ", "), cReset)
	}

	r.line("\nVerdict")
	switch {
	case portalErr != nil && inetErr != nil:
		r.line("  Sign in to the Wi-Fi first (open a browser), then run tunel doctor again.")
	case !linked:
		r.line("  tunel on:  no server link on this computer")
	case realErr == nil:
		r.line("  tunel on:  works on this network")
	case tcpErr != nil:
		r.line("  tunel on:  the network does not let this computer reach the server at all (%v).", shortErr(tcpErr))
		r.line("             A server abroad (a VPS) on port 443 would likely get through.")
	case inspected:
		r.line("  tunel on:  the server is reachable, but the network opens HTTPS, which breaks the")
		r.line("             disguise. A server name the network leaves alone (a ✓ line above) may work.")
	default:
		r.line("  tunel on:  the server is reachable, but the tunnel handshake fails (%v).", shortErr(realErr))
	}
	switch {
	case dpiErr == nil && directErr != nil:
		r.line("  tunel dpi: works: it opens %s, which is blocked here", blockedSite)
	case dpiErr == nil:
		r.line("  tunel dpi: works (but %s is not blocked here, so this proves little)", blockedSite)
	default:
		r.line("  tunel dpi: does not get past this network's filter (%v)", shortErr(dpiErr))
	}

	path := saveReport(r.b.String())
	if path != "" {
		fmt.Printf("\n%sSaved to %s%s\n", cDim, path, cReset)
	}
	return nil
}

func okOr(err error, good string) string {
	if err != nil {
		return err.Error()
	}
	return good
}

func shortErrOrNil(err error) error {
	if err == nil {
		return nil
	}
	return shortErr(err)
}

func overlaps(a, b []string) bool {
	for _, x := range a {
		for _, y := range b {
			if x == y {
				return true
			}
		}
	}
	return false
}

// httpCheck fetches url directly; want 0 accepts any HTTP answer.
func httpCheck(u string, want int) error {
	hc := &http.Client{Timeout: 8 * time.Second, Transport: &http.Transport{Proxy: nil}}
	resp, err := hc.Get(u)
	if err != nil {
		return shortErr(err)
	}
	resp.Body.Close()
	if want != 0 && resp.StatusCode != want {
		return fmt.Errorf("unexpected HTTP %d", resp.StatusCode)
	}
	return nil
}

// captivePortal looks for a Wi-Fi sign-in page between us and the internet.
func captivePortal() (string, error) {
	hc := &http.Client{
		Timeout:       8 * time.Second,
		Transport:     &http.Transport{Proxy: nil},
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
	}
	resp, err := hc.Get("http://www.msftconnecttest.com/connecttest.txt")
	if err != nil {
		return "", shortErr(err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(io.LimitReader(resp.Body, 256))
	if resp.StatusCode == 200 && strings.TrimSpace(string(body)) == "Microsoft Connect Test" {
		return "plain HTTP reaches the internet", nil
	}
	where := resp.Header.Get("Location")
	if where == "" {
		where = fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return "", fmt.Errorf("a sign-in page answers instead (%s): sign in first", where)
}

type tlsResult struct {
	sni, issuer, inspectedBy string
	err                      error
}

// tlsChecks connects to the sites whose names can disguise the tunnel and
// checks that the certificate is theirs, not the network's.
func tlsChecks(l Link, doh string) []tlsResult {
	names := append([]string{}, snis...)
	if l.SNI != "" && l.SNI != names[0] {
		names = append([]string{l.SNI}, names...)
	}
	names = append(names, blockedSite)
	res := make([]tlsResult, len(names))
	var wg sync.WaitGroup
	for i, n := range names {
		wg.Add(1)
		go func(i int, n string) {
			defer wg.Done()
			res[i] = tlsCheck(n, doh)
		}(i, n)
	}
	wg.Wait()
	return res
}

// tlsCheck connects to sni at its real address (from doh when there is one,
// since the network's DNS may point blocked names at a block page).
func tlsCheck(sni, doh string) tlsResult {
	r := tlsResult{sni: sni}
	addr := sni + ":443"
	if doh != "" {
		if ips, err := dohLookup(doh, sni, 6*time.Second); err == nil {
			addr = net.JoinHostPort(ips[0], "443")
		}
	}
	d := &net.Dialer{Timeout: 6 * time.Second}
	c, err := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: sni})
	if err == nil {
		st := c.ConnectionState()
		r.issuer = certName(st.PeerCertificates[0].Issuer.Organization, st.PeerCertificates[0].Issuer.CommonName)
		c.Close()
		return r
	}
	var unknown x509.UnknownAuthorityError
	if errors.As(err, &unknown) {
		// Look at what was presented instead.
		c, err2 := tls.DialWithDialer(d, "tcp", addr, &tls.Config{ServerName: sni, InsecureSkipVerify: true})
		if err2 == nil {
			cert := c.ConnectionState().PeerCertificates[0]
			r.inspectedBy = certName(cert.Issuer.Organization, cert.Issuer.CommonName)
			c.Close()
			return r
		}
	}
	r.err = shortErr(err)
	return r
}

func certName(org []string, cn string) string {
	if len(org) > 0 {
		return org[0] + " / " + cn
	}
	return cn
}

// dpiCheck opens the blocked site the way tunel dpi would.
func dpiCheck(doh string) error {
	port, err := freePort()
	if err != nil {
		return err
	}
	b, err := startBox(context.Background(), dpiConfig(port, os.DevNull, doh))
	if err != nil {
		return err
	}
	defer b.Close()
	proxy, _ := url.Parse(fmt.Sprintf("socks5h://127.0.0.1:%d", port))
	hc := &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{Proxy: http.ProxyURL(proxy)}}
	resp, err := hc.Get("https://" + blockedSite + "/")
	if err != nil {
		return shortErr(err)
	}
	resp.Body.Close()
	return nil
}

// saveReport writes the report where it is easy to find: the desktop.
func saveReport(text string) string {
	home, err := userHome()
	if err != nil {
		return ""
	}
	dir := home
	for _, d := range []string{filepath.Join(home, "Desktop"), filepath.Join(home, "OneDrive", "Desktop"), filepath.Join(home, "OneDrive", "Masaüstü")} {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			dir = d
			break
		}
	}
	path := filepath.Join(dir, "tunel-doctor-"+time.Now().Format("20060102-1504")+".txt")
	if err := os.WriteFile(path, []byte(text), 0o644); err != nil {
		return ""
	}
	return path
}
