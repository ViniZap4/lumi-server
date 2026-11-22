package admin

import (
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// ParseTrustedProxies reads a comma-separated list of CIDRs or bare
// addresses (a bare address is a /32 or /128).
func ParseTrustedProxies(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("%q is not a CIDR", part)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("%q is not an address or CIDR", part)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func trusted(a netip.Addr, proxies []netip.Prefix) bool {
	a = a.Unmap()
	for _, p := range proxies {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP is the address recorded in the audit log and charged by the
// failure limiter. X-Forwarded-For counts only when the peer is a trusted
// proxy; it is then walked right to left and the first hop that is not a
// trusted proxy wins, so a client cannot spoof its address by sending its
// own header (the proxy appends the real one). The public API's proxy
// setting does not apply here.
func ClientIP(remote netip.Addr, xff []string, proxies []netip.Prefix) netip.Addr {
	remote = remote.Unmap()
	if !remote.IsValid() || len(proxies) == 0 || !trusted(remote, proxies) {
		return remote
	}
	var hops []string
	for _, h := range xff {
		hops = append(hops, strings.Split(h, ",")...)
	}
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			// A malformed hop ends the trustworthy chain: everything left
			// of it is client-controlled.
			return remote
		}
		a = a.Unmap()
		if !trusted(a, proxies) {
			return a
		}
		remote = a
	}
	return remote
}

// listener is a parsed host:port for SameListener.
type listener struct {
	port      int
	wildcard  bool // "", 0.0.0.0, ::
	localhost bool // the name "localhost"
	addr      netip.Addr
	name      string // any other host name, compared literally
}

func parseListener(s string) (listener, error) {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return listener{}, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 0 || port > 65535 {
		return listener{}, fmt.Errorf("bad port in %q", s)
	}
	l := listener{port: port}
	switch strings.ToLower(host) {
	case "", "0.0.0.0", "::", "[::]":
		l.wildcard = true
	case "localhost":
		l.localhost = true
	default:
		if a, err := netip.ParseAddr(host); err == nil {
			a = a.Unmap()
			if a.IsUnspecified() {
				l.wildcard = true
			} else {
				l.addr = a
			}
		} else {
			l.name = strings.ToLower(host)
		}
	}
	return l, nil
}

func (l listener) loopback() bool { return l.localhost || (l.addr.IsValid() && l.addr.IsLoopback()) }

// SameListener reports whether two listen addresses would collide: same
// port and overlapping hosts, comparing resolved forms (a wildcard covers
// every host; localhost, 127.0.0.1, ::1 and ::ffff:127.0.0.1 are one
// loopback). Port 0 never collides. Unparseable inputs compare literally.
func SameListener(a, b string) bool {
	if a == b {
		return true
	}
	la, errA := parseListener(a)
	lb, errB := parseListener(b)
	if errA != nil || errB != nil {
		return false
	}
	if la.port != lb.port || la.port == 0 {
		return false
	}
	switch {
	case la.wildcard || lb.wildcard:
		return true
	case la.loopback() || lb.loopback():
		return la.loopback() && lb.loopback()
	case la.name != "" || lb.name != "":
		// An unresolved host name may resolve to anything on the box:
		// refuse rather than guess.
		return true
	default:
		return la.addr == lb.addr
	}
}

// LoopbackOnly reports whether addr listens on loopback only.
func LoopbackOnly(addr string) bool {
	l, err := parseListener(addr)
	return err == nil && l.loopback()
}

// ValidateListenAddr checks that addr is a usable host:port.
func ValidateListenAddr(addr string) error {
	if _, err := parseListener(addr); err != nil {
		return fmt.Errorf("must be host:port: %v", err)
	}
	return nil
}
