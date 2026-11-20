// Package ddos protects PrismWAF and the backends from denial of service by
// clients that use up connections, requests in progress or time instead of
// sending many requests, which the rate limits count:
//
//   - Listener closes connections over a total limit and over a limit per
//     client address as soon as they are accepted, and connections from
//     banned clients. It also bounds the time until a new connection sends
//     its first request.
//   - Concurrency limits the requests in progress, in total (load
//     shedding) and per client.
//   - BodyTimeout makes clients send request bodies at a minimum rate
//     (slow POST attacks).
//   - Bans rejects every request of a client that has been rejected too
//     often, for a while, and Listener closes its connections.
//
// Clients are counted by IP address, the /64 network for IPv6, like the
// rate limits.
package ddos

import (
	"net/netip"
	"sync"
	"time"

	"github.com/cmc-labo/prism-waf/internal/ratelimit"
)

// clientKey returns the address, or the /64 network of an IPv6 address,
// that a client is counted by, and whether the address is valid.
func clientKey(ip string) (netip.Prefix, bool) {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return netip.Prefix{}, false
	}
	return addrKey(a), true
}

func addrKey(a netip.Addr) netip.Prefix {
	a = a.Unmap()
	if a.Is6() {
		p, _ := a.Prefix(ratelimit.IPv6Prefix)
		return p
	}
	return netip.PrefixFrom(a, a.BitLen())
}

func contains(prefixes []netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(ip)
	if err != nil {
		return false
	}
	return containsAddr(prefixes, a)
}

func containsAddr(prefixes []netip.Prefix, a netip.Addr) bool {
	a = a.Unmap()
	for _, p := range prefixes {
		if p.Contains(a) {
			return true
		}
	}
	return false
}

// throttle allows something, such as a log message, at most once a
// minute.
type throttle struct {
	mu   sync.Mutex
	last time.Time
	// count is the number of calls since the last allowed one.
	count int
}

// allow reports whether the minute since the last allowed call has passed,
// and the number of calls in it, including this one.
func (t *throttle) allow(now time.Time) (bool, int) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.count++
	if now.Sub(t.last) < time.Minute {
		return false, 0
	}
	n := t.count
	t.last, t.count = now, 0
	return true, n
}
