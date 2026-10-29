package waf

import (
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"strings"
)

// TrustedProxies is a set of networks whose X-Forwarded-For headers are
// trusted to report the client address.
type TrustedProxies []netip.Prefix

// ParseTrustedProxies parses a comma-separated list of IP addresses and CIDR
// prefixes, e.g. "10.0.0.0/8, 192.0.2.1".
func ParseTrustedProxies(s string) (TrustedProxies, error) {
	var tp TrustedProxies
	for _, f := range strings.Split(s, ",") {
		f = strings.TrimSpace(f)
		if f == "" {
			continue
		}
		if strings.Contains(f, "/") {
			p, err := netip.ParsePrefix(f)
			if err != nil {
				return nil, fmt.Errorf("waf: invalid trusted proxy %q: %w", f, err)
			}
			tp = append(tp, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(f)
		if err != nil {
			return nil, fmt.Errorf("waf: invalid trusted proxy %q: %w", f, err)
		}
		tp = append(tp, netip.PrefixFrom(a, a.BitLen()))
	}
	return tp, nil
}

func (tp TrustedProxies) contains(a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range tp {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// ClientIP returns the address of the client that sent r.
//
// X-Forwarded-For can be set by anyone, so it is only used when the TCP peer
// is a trusted proxy. The header is then read from right to left, skipping
// trusted proxies, and the first untrusted address is the client. With no
// trusted proxies, the TCP peer address is returned.
func (tp TrustedProxies) ClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	peer, err := netip.ParseAddr(host)
	if err != nil || !tp.contains(peer) {
		return host
	}

	client := peer.Unmap()
	hops := strings.Split(strings.Join(r.Header.Values("X-Forwarded-For"), ","), ",")
	for i := len(hops) - 1; i >= 0; i-- {
		a, err := netip.ParseAddr(strings.TrimSpace(hops[i]))
		if err != nil {
			break // a malformed entry: stop at the last address we trust
		}
		client = a.Unmap()
		if !tp.contains(client) {
			break
		}
	}
	return client.String()
}
