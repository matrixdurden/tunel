package main

import (
	"fmt"
	"net"
	"net/url"
	"regexp"
	"strconv"
)

// Link is everything a client needs to reach a server. It travels as a standard
// vless:// URL, so phone apps (Hiddify, v2rayNG) can use the same link.
type Link struct {
	UUID      string `json:"uuid"`
	Host      string `json:"host"`
	Port      int    `json:"port"`
	SNI       string `json:"sni"`
	PublicKey string `json:"public_key"`
	ShortID   string `json:"short_id"`
	Name      string `json:"name"` // the user's name on the server
}

var (
	uuidRe = regexp.MustCompile(`^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$`)
	nameRe = regexp.MustCompile(`^[A-Za-z0-9._-]{1,32}$`)
	hexRe  = regexp.MustCompile(`^[0-9a-f]{0,16}$`)
)

func (l Link) String() string {
	q := url.Values{}
	q.Set("encryption", "none")
	q.Set("flow", "xtls-rprx-vision")
	q.Set("security", "reality")
	q.Set("sni", l.SNI)
	q.Set("fp", "chrome")
	q.Set("pbk", l.PublicKey)
	q.Set("sid", l.ShortID)
	q.Set("type", "tcp")
	u := url.URL{
		Scheme:   "vless",
		User:     url.User(l.UUID),
		Host:     net.JoinHostPort(l.Host, strconv.Itoa(l.Port)),
		RawQuery: q.Encode(),
		Fragment: l.Name,
	}
	return u.String()
}

func ParseLink(s string) (Link, error) {
	u, err := url.Parse(s)
	if err != nil || u.Scheme != "vless" || u.User == nil {
		return Link{}, fmt.Errorf("not a vless:// link")
	}
	q := u.Query()
	port, _ := strconv.Atoi(u.Port())
	l := Link{
		UUID:      u.User.Username(),
		Host:      u.Hostname(),
		Port:      port,
		SNI:       q.Get("sni"),
		PublicKey: q.Get("pbk"),
		ShortID:   q.Get("sid"),
		Name:      u.Fragment,
	}
	if !nameRe.MatchString(l.Name) {
		l.Name = "tunel"
	}
	switch {
	case !uuidRe.MatchString(l.UUID):
		return Link{}, fmt.Errorf("the link has no valid user id")
	case l.Host == "" || l.Port < 1 || l.Port > 65535:
		return Link{}, fmt.Errorf("the link has no valid server address")
	case q.Get("security") != "reality" || l.SNI == "" || l.PublicKey == "":
		return Link{}, fmt.Errorf("the link is not a Reality link (sni and pbk are required)")
	case !hexRe.MatchString(l.ShortID):
		return Link{}, fmt.Errorf("the link has an invalid sid")
	case q.Get("flow") != "" && q.Get("flow") != "xtls-rprx-vision":
		return Link{}, fmt.Errorf("unsupported flow %q", q.Get("flow"))
	case q.Get("type") != "" && q.Get("type") != "tcp":
		return Link{}, fmt.Errorf("unsupported transport %q", q.Get("type"))
	}
	return l, nil
}
