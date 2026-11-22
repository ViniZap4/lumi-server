package federation

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"syscall"
	"time"

	fws "github.com/fasthttp/websocket"

	"github.com/ViniZap4/lumi-server/internal/domain"
)

// NetPolicy governs every outbound connection this server makes to a peer
// (identity/accept/sync-challenge over HTTP, relay over WebSocket). Peer URLs
// are attacker-influenced (a join request names an arbitrary home URL), so
// outbound traffic is treated as SSRF-prone:
//
//   - https only, unless AllowInsecureHTTP (dev/test);
//   - the resolved IP of every dial — not just the hostname — must be a
//     public unicast address; loopback, RFC1918/ULA, link-local (cloud
//     metadata), CGNAT, multicast and other special ranges are refused
//     unless explicitly listed in AllowedCIDRs;
//   - no proxies, no redirects, bounded timeouts.
//
// The zero value is the strict production policy.
type NetPolicy struct {
	AllowInsecureHTTP bool
	AllowedCIDRs      []netip.Prefix
}

// ParseCIDRList parses a comma-separated CIDR/IP allowlist (single IPs are
// widened to a host prefix). Empty input yields nil.
func ParseCIDRList(raw string) ([]netip.Prefix, error) {
	var out []netip.Prefix
	for _, part := range strings.Split(raw, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if strings.Contains(part, "/") {
			p, err := netip.ParsePrefix(part)
			if err != nil {
				return nil, fmt.Errorf("invalid CIDR %q: %w", part, err)
			}
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(part)
		if err != nil {
			return nil, fmt.Errorf("invalid IP %q: %w", part, err)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

// Outbound timeouts. Peer payloads are tiny; anything slow is broken or
// hostile.
const (
	peerDialTimeout     = 5 * time.Second
	peerTLSTimeout      = 10 * time.Second
	peerHeaderTimeout   = 10 * time.Second
	peerRequestTimeout  = 15 * time.Second
	peerHandshakeTimout = 15 * time.Second
	peerMaxHeaderBytes  = 64 << 10
)

// errBlockedAddress is returned when a dial targets a non-public address.
var errBlockedAddress = errors.New("federation: peer address is not publicly routable")

// specialPrefixes are non-public ranges not already covered by the netip
// predicates used in checkAddr.
var specialPrefixes = mustPrefixes(
	"0.0.0.0/8",       // "this network"
	"100.64.0.0/10",   // CGNAT (RFC 6598)
	"192.0.0.0/24",    // IETF protocol assignments
	"192.0.2.0/24",    // TEST-NET-1
	"198.18.0.0/15",   // benchmarking
	"198.51.100.0/24", // TEST-NET-2
	"203.0.113.0/24",  // TEST-NET-3
	"240.0.0.0/4",     // reserved + broadcast
	"2001:db8::/32",   // documentation
	"100::/64",        // discard-only
)

// nat64Prefix embeds an IPv4 address in its low 32 bits; the embedded
// address is checked too so NAT64 cannot be used to reach private v4.
var nat64Prefix = netip.MustParsePrefix("64:ff9b::/96")

func mustPrefixes(ss ...string) []netip.Prefix {
	out := make([]netip.Prefix, 0, len(ss))
	for _, s := range ss {
		out = append(out, netip.MustParsePrefix(s))
	}
	return out
}

// checkAddr reports whether ip may be dialled under p.
func (p NetPolicy) checkAddr(ip netip.Addr) error {
	ip = ip.Unmap()
	for _, allowed := range p.AllowedCIDRs {
		if allowed.Contains(ip) {
			return nil
		}
	}
	if !isPublicAddr(ip) {
		return fmt.Errorf("%w: %s", errBlockedAddress, ip)
	}
	return nil
}

func isPublicAddr(ip netip.Addr) bool {
	ip = ip.Unmap()
	if !ip.IsValid() || !ip.IsGlobalUnicast() || ip.IsPrivate() || ip.IsLoopback() ||
		ip.IsLinkLocalUnicast() || ip.IsMulticast() || ip.IsUnspecified() {
		return false
	}
	for _, pfx := range specialPrefixes {
		if pfx.Contains(ip) {
			return false
		}
	}
	if nat64Prefix.Contains(ip) {
		b := ip.As16()
		return isPublicAddr(netip.AddrFrom4([4]byte{b[12], b[13], b[14], b[15]}))
	}
	return true
}

// CheckPeerURL validates a peer base URL for use as a dial target or peer
// identity: syntactically strict (validateServerURL) and https unless the
// policy allows plain http.
func (p NetPolicy) CheckPeerURL(raw string) error {
	if err := validateServerURL(raw); err != nil {
		return err
	}
	if !p.AllowInsecureHTTP && !strings.HasPrefix(raw, "https://") {
		return fmt.Errorf("%w: server url must use https", domain.ErrValidation)
	}
	return nil
}

// netDialer returns a dialer whose Control hook vets the resolved address
// immediately before connect(2), so DNS rebinding between validation and
// dial cannot redirect us to an internal host.
func (p NetPolicy) netDialer() *net.Dialer {
	return &net.Dialer{
		Timeout:   peerDialTimeout,
		KeepAlive: 30 * time.Second,
		Control: func(network, address string, _ syscall.RawConn) error {
			if network != "tcp4" && network != "tcp6" && network != "tcp" {
				return fmt.Errorf("%w: network %q", errBlockedAddress, network)
			}
			host, _, err := net.SplitHostPort(address)
			if err != nil {
				return err
			}
			ip, err := netip.ParseAddr(host)
			if err != nil {
				return fmt.Errorf("%w: unparseable %q", errBlockedAddress, host)
			}
			return p.checkAddr(ip)
		},
	}
}

// HTTPClient builds the guarded client used for peer HTTP calls.
func (p NetPolicy) HTTPClient() *http.Client {
	d := p.netDialer()
	tr := &http.Transport{
		Proxy:                  nil, // a proxy would bypass the IP guard
		DialContext:            d.DialContext,
		TLSHandshakeTimeout:    peerTLSTimeout,
		ResponseHeaderTimeout:  peerHeaderTimeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: peerMaxHeaderBytes,
		IdleConnTimeout:        90 * time.Second,
		MaxIdleConns:           16,
		ForceAttemptHTTP2:      true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   peerRequestTimeout,
		// Never follow redirects: a 30x to http://169.254.169.254/ would
		// otherwise sidestep the URL checks done before the request.
		CheckRedirect: func(*http.Request, []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
}

// WSDialer builds the guarded relay WebSocket dialer.
func (p NetPolicy) WSDialer() Dialer {
	d := p.netDialer()
	wd := &fws.Dialer{
		NetDialContext:   d.DialContext,
		Proxy:            nil,
		HandshakeTimeout: peerHandshakeTimout,
	}
	return func(ctx context.Context, wsURL string) (wsConn, error) {
		u, err := url.Parse(wsURL)
		if err != nil {
			return nil, err
		}
		switch u.Scheme {
		case "wss":
		case "ws":
			if !p.AllowInsecureHTTP {
				return nil, fmt.Errorf("%w: relay must use wss", domain.ErrValidation)
			}
		default:
			return nil, fmt.Errorf("%w: unsupported relay scheme %q", domain.ErrValidation, u.Scheme)
		}
		conn, resp, err := wd.DialContext(ctx, wsURL, nil)
		if resp != nil && resp.Body != nil {
			_ = resp.Body.Close()
		}
		if err != nil {
			return nil, err
		}
		return conn, nil
	}
}

// validateServerURL is the syntactic check for a peer base URL: absolute
// http(s), a host, and nothing else — no userinfo, path, query or fragment
// (callers strip one trailing slash via normalizeServerURL first). It does
// not apply the https/network policy; see NetPolicy.CheckPeerURL.
func validateServerURL(raw string) error {
	bad := fmt.Errorf("%w: server url must be an absolute http(s) URL with no path, query, credentials or fragment", domain.ErrValidation)
	if raw == "" || strings.ContainsAny(raw, " \t\r\n\\") {
		return bad
	}
	u, err := url.Parse(raw)
	if err != nil {
		return bad
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Opaque != "" || u.User != nil ||
		u.Path != "" || u.RawPath != "" || u.RawQuery != "" || u.ForceQuery ||
		u.Fragment != "" || strings.Contains(raw, "#") || u.Hostname() == "" {
		return bad
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return bad
		}
	} else if strings.HasSuffix(u.Host, ":") {
		return bad
	}
	return nil
}
