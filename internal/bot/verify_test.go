package bot

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// fakeResolver answers from maps. Missing entries are "not found".
type fakeResolver struct {
	ptr     map[string][]string
	forward map[string][]string
	err     error         // returned by every lookup if set
	delay   time.Duration // of every reverse lookup
	lookups atomic.Int32
}

func (f *fakeResolver) LookupAddr(ctx context.Context, addr string) ([]string, error) {
	f.lookups.Add(1)
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	if f.err != nil {
		return nil, f.err
	}
	if names, ok := f.ptr[addr]; ok {
		return names, nil
	}
	return nil, &net.DNSError{Err: "no such host", Name: addr, IsNotFound: true}
}

func (f *fakeResolver) LookupNetIP(ctx context.Context, network, host string) ([]netip.Addr, error) {
	if f.err != nil {
		return nil, f.err
	}
	var out []netip.Addr
	for _, a := range f.forward[host] {
		out = append(out, netip.MustParseAddr(a))
	}
	if len(out) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: host, IsNotFound: true}
	}
	return out, nil
}

var googlebot = findBot("googlebot/2.1")

func TestVerify(t *testing.T) {
	r := &fakeResolver{
		ptr: map[string][]string{
			"66.249.66.1":  {"crawl-66-249-66-1.googlebot.com."},
			"203.0.113.7":  {"crawl-66-249-66-1.googlebot.com."},                 // PTR set by an impostor
			"203.0.113.8":  {"crawl.googlebot.com.evil.example."},                // not a subdomain
			"203.0.113.9":  {"vm-1.bc.googleusercontent.com."},                   // a cloud VM
			"2001:4860::1": {"other.example.", "rate-limited-proxy.google.com."}, // second name matches
		},
		forward: map[string][]string{
			"crawl-66-249-66-1.googlebot.com.":  {"66.249.66.1"},
			"crawl.googlebot.com.evil.example.": {"203.0.113.8"},
			"vm-1.bc.googleusercontent.com.":    {"203.0.113.9"},
			"rate-limited-proxy.google.com.":    {"2001:4860::1"},
		},
	}
	now := time.Now()
	v := newVerifier(r, func() time.Time { return now })
	for ip, want := range map[string]bool{
		"66.249.66.1":        true,
		"::ffff:66.249.66.1": true,
		"203.0.113.7":        false,
		"203.0.113.8":        false,
		"203.0.113.9":        false,
		"2001:4860::1":       true,
		"198.51.100.1":       false, // no PTR
		"not an address":     false,
	} {
		if got := v.verify(context.Background(), ip, googlebot); got != want {
			t.Errorf("verify(%s) = %v, want %v", ip, got, want)
		}
	}
	if bing := findBot("bingbot/2.0"); v.verify(context.Background(), "66.249.66.1", bing) {
		t.Error("Googlebot's address verified as Bingbot")
	}
}

func TestVerifyCaches(t *testing.T) {
	r := &fakeResolver{
		ptr:     map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		forward: map[string][]string{"crawl-66-249-66-1.googlebot.com.": {"66.249.66.1"}},
	}
	now := time.Now()
	v := newVerifier(r, func() time.Time { return now })
	ctx := context.Background()
	for range 3 {
		v.verify(ctx, "66.249.66.1", googlebot)
		v.verify(ctx, "198.51.100.1", googlebot)
	}
	if n := r.lookups.Load(); n != 2 {
		t.Errorf("%d lookups, want 2", n)
	}
	// A negative answer is cached for an hour, a positive one for a day.
	now = now.Add(notVerifiedTTL)
	v.verify(ctx, "66.249.66.1", googlebot)
	v.verify(ctx, "198.51.100.1", googlebot)
	if n := r.lookups.Load(); n != 3 {
		t.Errorf("%d lookups after an hour, want 3", n)
	}

	// DNS errors are not definite and retried after a few minutes.
	r.err = errors.New("i/o timeout")
	if v.verify(ctx, "192.0.2.1", googlebot) {
		t.Error("verified despite DNS error")
	}
	r.err = nil
	r.ptr["192.0.2.1"] = []string{"crawl-66-249-66-1.googlebot.com."}
	r.forward["crawl-66-249-66-1.googlebot.com."] = append(r.forward["crawl-66-249-66-1.googlebot.com."], "192.0.2.1")
	if v.verify(ctx, "192.0.2.1", googlebot) {
		t.Error("DNS error not cached")
	}
	now = now.Add(dnsErrorTTL)
	if !v.verify(ctx, "192.0.2.1", googlebot) {
		t.Error("not retried after the DNS error")
	}
}

func TestVerifySharesConcurrentLookups(t *testing.T) {
	r := &fakeResolver{
		ptr:     map[string][]string{"66.249.66.1": {"crawl-66-249-66-1.googlebot.com."}},
		forward: map[string][]string{"crawl-66-249-66-1.googlebot.com.": {"66.249.66.1"}},
		delay:   50 * time.Millisecond,
	}
	v := newVerifier(r, time.Now)
	var wg sync.WaitGroup
	var verified atomic.Int32
	for range 20 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if v.verify(context.Background(), "66.249.66.1", googlebot) {
				verified.Add(1)
			}
		}()
	}
	wg.Wait()
	if n := r.lookups.Load(); n != 1 || verified.Load() != 20 {
		t.Errorf("%d lookups, %d verified; want 1 and 20", n, verified.Load())
	}
}

func TestVerifiedDomain(t *testing.T) {
	for name, want := range map[string]bool{
		"crawl-1.googlebot.com.": true,
		"googlebot.com":          true,
		"CRAWL.GOOGLEBOT.COM":    true,
		"notgooglebot.com":       false,
		"googlebot.com.evil.io":  false,
		"":                       false,
	} {
		if got := verifiedDomain(name, []string{"googlebot.com"}); got != want {
			t.Errorf("verifiedDomain(%q) = %v", name, got)
		}
	}
}
