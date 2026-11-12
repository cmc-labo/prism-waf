package bot

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"time"
)

// Resolver looks up DNS names. *net.Resolver implements it.
type Resolver interface {
	LookupAddr(ctx context.Context, addr string) ([]string, error)
	LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error)
}

// How long verification results are cached. Failures caused by DNS errors,
// such as a timeout, are retried sooner than definite answers.
const (
	verifiedTTL    = 24 * time.Hour
	notVerifiedTTL = time.Hour
	dnsErrorTTL    = 5 * time.Minute
	// verifyTimeout limits the lookups of one verification.
	verifyTimeout = 2 * time.Second
	// maxVerifications limits the memory of the cache.
	maxVerifications = 10_000
)

// verifier checks with DNS that a client is the bot it claims to be: the
// reverse DNS name of its address must belong to the bot's domains, and
// that name must resolve back to the address. Results are cached per
// address and bot.
type verifier struct {
	resolver Resolver
	now      func() time.Time

	mu       sync.Mutex
	cache    map[verifyKey]verifyResult
	inflight map[verifyKey]*verifyCall
}

type verifyKey struct {
	addr netip.Addr
	bot  *knownBot
}

type verifyResult struct {
	ok      bool
	expires time.Time
}

type verifyCall struct {
	done chan struct{}
	ok   bool
}

func newVerifier(r Resolver, now func() time.Time) *verifier {
	if r == nil {
		r = net.DefaultResolver
	}
	return &verifier{resolver: r, now: now, cache: map[verifyKey]verifyResult{}, inflight: map[verifyKey]*verifyCall{}}
}

// verify reports whether the client at clientIP is bot. Concurrent
// requests for the same address and bot share one lookup.
func (v *verifier) verify(ctx context.Context, clientIP string, bot *knownBot) bool {
	addr, err := netip.ParseAddr(clientIP)
	if err != nil {
		return false
	}
	k := verifyKey{addr.Unmap(), bot}
	v.mu.Lock()
	if r, ok := v.cache[k]; ok && v.now().Before(r.expires) {
		v.mu.Unlock()
		return r.ok
	}
	if c, ok := v.inflight[k]; ok {
		v.mu.Unlock()
		select {
		case <-c.done:
			return c.ok
		case <-ctx.Done():
			return false
		}
	}
	c := &verifyCall{done: make(chan struct{})}
	v.inflight[k] = c
	v.mu.Unlock()

	// Not canceled with the request: the result is cached for others.
	lctx, cancel := context.WithTimeout(context.WithoutCancel(ctx), verifyTimeout)
	ok, err := v.lookup(lctx, k.addr, bot)
	cancel()
	ttl := notVerifiedTTL
	switch {
	case ok:
		ttl = verifiedTTL
	case err != nil:
		ttl = dnsErrorTTL
	}

	v.mu.Lock()
	delete(v.inflight, k)
	v.store(k, verifyResult{ok, v.now().Add(ttl)})
	v.mu.Unlock()
	c.ok = ok
	close(c.done)
	return ok
}

// lookup verifies an address. A non-nil error means that DNS failed, so
// the answer is not definite.
func (v *verifier) lookup(ctx context.Context, addr netip.Addr, bot *knownBot) (bool, error) {
	names, err := v.resolver.LookupAddr(ctx, addr.String())
	if err != nil {
		if isNotFound(err) {
			return false, nil // no reverse DNS name: definitely not the bot
		}
		return false, err
	}
	var lastErr error
	for _, name := range names {
		if !verifiedDomain(name, bot.domains) {
			continue
		}
		// Anyone can set the reverse DNS name of their own addresses, so
		// the name must also resolve to the address.
		addrs, err := v.resolver.LookupNetIP(ctx, "ip", name)
		if err != nil {
			if !isNotFound(err) {
				lastErr = err
			}
			continue
		}
		for _, a := range addrs {
			if a.Unmap() == addr {
				return true, nil
			}
		}
	}
	return false, lastErr
}

func isNotFound(err error) bool {
	var de *net.DNSError
	return errors.As(err, &de) && de.IsNotFound
}

// store caches a result. The cache is bounded: expired results are
// removed when it is full, then arbitrary ones.
func (v *verifier) store(k verifyKey, r verifyResult) {
	if len(v.cache) >= maxVerifications {
		now := v.now()
		for k, r := range v.cache {
			if !now.Before(r.expires) {
				delete(v.cache, k)
			}
		}
		for k := range v.cache {
			if len(v.cache) < maxVerifications {
				break
			}
			delete(v.cache, k)
		}
	}
	v.cache[k] = r
}
