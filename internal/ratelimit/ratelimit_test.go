package ratelimit

import (
	"bytes"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseRate(t *testing.T) {
	for _, tc := range []struct {
		in     string
		limit  int
		window time.Duration
	}{
		{"100/1m", 100, time.Minute},
		{"5/10s", 5, 10 * time.Second},
		{"1000/h", 1000, time.Hour},
		{" 3 / 2m30s ", 3, 150 * time.Second},
	} {
		limit, window, err := ParseRate(tc.in)
		if err != nil || limit != tc.limit || window != tc.window {
			t.Errorf("ParseRate(%q) = %d, %v, %v; want %d, %v", tc.in, limit, window, err, tc.limit, tc.window)
		}
	}
	for _, in := range []string{"", "100", "0/1m", "-1/1m", "x/1m", "5/", "5/0s", "5/-1m", "5/fortnight", "2000000000/1ns"} {
		if _, _, err := ParseRate(in); err == nil {
			t.Errorf("ParseRate(%q) succeeded", in)
		}
	}
}

func TestParseRule(t *testing.T) {
	for _, tc := range []struct {
		in   string
		want Rule
		str  string
	}{
		{"POST /login=5/1m", Rule{Method: "POST", Path: "/login", Limit: 5, Window: time.Minute}, "POST /login=5/1m"},
		{"post /Login/=5/m", Rule{Method: "POST", Path: "/login", Limit: 5, Window: time.Minute}, "POST /login=5/1m"},
		{"/api/*=100/1m", Rule{Path: "/api/*", Limit: 100, Window: time.Minute}, "/api/*=100/1m"},
		{"/API//v1/*=100/1m", Rule{Path: "/api/v1/*", Limit: 100, Window: time.Minute}, "/api/v1/*=100/1m"},
		{"/admin*=10/1h", Rule{Path: "/admin*", Limit: 10, Window: time.Hour}, "/admin*=10/1h"},
		{"/*=10/1s", Rule{Path: "/*", Limit: 10, Window: time.Second}, "/*=10/1s"},
		{"/a=b=1/1s", Rule{Path: "/a=b", Limit: 1, Window: time.Second}, "/a=b=1/1s"},
	} {
		got, err := ParseRule(tc.in)
		if err != nil || got != tc.want {
			t.Errorf("ParseRule(%q) = %+v, %v; want %+v", tc.in, got, err, tc.want)
			continue
		}
		if got.String() != tc.str {
			t.Errorf("ParseRule(%q).String() = %q, want %q", tc.in, got.String(), tc.str)
		}
	}
	for _, in := range []string{"/login", "login=5/1m", "POST=5/1m", "POST /login extra=5/1m", "P0ST /login=5/1m", "/a*b=5/1m", "/login=5"} {
		if _, err := ParseRule(in); err == nil {
			t.Errorf("ParseRule(%q) succeeded", in)
		}
	}
	if s := (Rule{Limit: 300, Window: time.Minute}).String(); s != "300/1m" {
		t.Errorf("String() = %q", s)
	}
}

func TestCleanPath(t *testing.T) {
	for in, want := range map[string]string{
		"/login":                  "/login",
		"/LOGIN":                  "/login",
		"/login/":                 "/login",
		"//login":                 "/login",
		"/./login":                "/login",
		"/static/../login":        "/login",
		"/login;jsessionid=abc":   "/login",
		"/a;x=1/login;y":          "/a/login",
		`\login`:                  "/login",
		"":                        "/",
		"/../../login":            "/login",
		"/api/v1/../v2/users/":    "/api/v2/users",
		"/%2e%2e/login-literally": "/%2e%2e/login-literally",
	} {
		if got := CleanPath(in); got != want {
			t.Errorf("CleanPath(%q) = %q, want %q", in, got, want)
		}
	}
}

// testLimiter returns a limiter with a controllable clock.
func testLimiter(t *testing.T, cfg Config, rules ...string) (*Limiter, *time.Time) {
	t.Helper()
	for _, s := range rules {
		var r Rule
		if strings.Contains(s, "=") {
			var err error
			if r, err = ParseRule(s); err != nil {
				t.Fatal(err)
			}
		} else {
			limit, window, err := ParseRate(s)
			if err != nil {
				t.Fatal(err)
			}
			r = Rule{Limit: limit, Window: window}
		}
		cfg.Rules = append(cfg.Rules, r)
	}
	l, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 8, 12, 0, 0, 0, time.UTC)
	l.now = func() time.Time { return now }
	return l, &now
}

func allow(l *Limiter, method, target, ip string) Decision {
	return l.Allow(httptest.NewRequest(method, target, nil), ip)
}

func TestLimit(t *testing.T) {
	l, now := testLimiter(t, Config{}, "5/1m")
	for i := range 5 {
		if d := allow(l, "GET", "/", "192.0.2.1"); !d.Allowed {
			t.Fatalf("request %d rejected", i+1)
		}
	}
	d := allow(l, "GET", "/", "192.0.2.1")
	if d.Allowed {
		t.Fatal("6th request allowed")
	}
	if d.RetryAfter != 12*time.Second {
		t.Errorf("RetryAfter = %v, want 12s", d.RetryAfter)
	}
	if d.Client != netip.MustParsePrefix("192.0.2.1/32") || d.Rule.Limit != 5 {
		t.Errorf("decision = %+v", d)
	}
	// Other clients have their own allowance.
	if d := allow(l, "GET", "/", "192.0.2.2"); !d.Allowed {
		t.Error("other client rejected")
	}

	// The allowance refills by one request every 12 seconds.
	*now = now.Add(11 * time.Second)
	if d := allow(l, "GET", "/", "192.0.2.1"); d.Allowed || d.RetryAfter != time.Second {
		t.Errorf("after 11s: allowed = %v, RetryAfter = %v", d.Allowed, d.RetryAfter)
	}
	*now = now.Add(time.Second)
	if d := allow(l, "GET", "/", "192.0.2.1"); !d.Allowed {
		t.Error("after 12s: rejected")
	}
	if d := allow(l, "GET", "/", "192.0.2.1"); d.Allowed {
		t.Error("after 12s: second request allowed")
	}

	// A full window later, the whole allowance is back.
	*now = now.Add(time.Minute)
	for i := range 5 {
		if d := allow(l, "GET", "/", "192.0.2.1"); !d.Allowed {
			t.Fatalf("after a minute: request %d rejected", i+1)
		}
	}
}

func TestSustainedRate(t *testing.T) {
	// A client that keeps sending gets Limit requests per Window on
	// average, plus the initial burst.
	l, now := testLimiter(t, Config{}, "10/1m")
	allowed := 0
	for range 3600 { // one request per second for an hour
		if allow(l, "POST", "/", "192.0.2.1").Allowed {
			allowed++
		}
		*now = now.Add(time.Second)
	}
	if want := 10 + 60*10 - 1; allowed < want-1 || allowed > want+1 {
		t.Errorf("allowed %d requests in an hour, want about %d", allowed, want)
	}
}

func TestPathRules(t *testing.T) {
	l, _ := testLimiter(t, Config{}, "POST /login=2/1m", "/api/*=3/1m")
	ip := "192.0.2.1"
	for range 10 {
		if !allow(l, "GET", "/login", ip).Allowed {
			t.Fatal("GET /login limited by a POST rule")
		}
		if !allow(l, "POST", "/other", ip).Allowed {
			t.Fatal("unmatched path limited")
		}
	}
	// Variants of the path count for the same rule.
	for i, target := range []string{"/login", "//LOGIN/"} {
		if !allow(l, "POST", target, ip).Allowed {
			t.Fatalf("request %d rejected", i+1)
		}
	}
	for _, target := range []string{"/login", "/Login", "/login/", "/./login", "/x/../login", "/login;jsessionid=1", "/login?next=/"} {
		d := allow(l, "POST", target, ip)
		if d.Allowed {
			t.Errorf("POST %s allowed after the limit", target)
		} else if d.Rule.Path != "/login" {
			t.Errorf("POST %s: rule = %v", target, d.Rule)
		}
	}
	if allow(l, "POST", "/login-help", ip).Allowed != true {
		t.Error("/login-help limited by /login")
	}

	for i, target := range []string{"/api", "/api/users", "/API/orders/1"} {
		if !allow(l, "GET", target, ip).Allowed {
			t.Fatalf("API request %d rejected", i+1)
		}
	}
	if d := allow(l, "DELETE", "/api/users/1", ip); d.Allowed || d.Rule.Path != "/api/*" {
		t.Errorf("4th API request: %+v", d)
	}
	if !allow(l, "GET", "/apikeys", ip).Allowed {
		t.Error("/apikeys limited by /api/*")
	}
}

func TestRejectedRequestsDoNotCount(t *testing.T) {
	// A request rejected by one rule uses up the allowance of no rule.
	l, now := testLimiter(t, Config{}, "3/1m", "POST /login=1/1m")
	ip := "192.0.2.1"
	if !allow(l, "POST", "/login", ip).Allowed {
		t.Fatal("first login rejected")
	}
	for range 10 {
		if d := allow(l, "POST", "/login", ip); d.Allowed || d.Rule.Path != "/login" {
			t.Fatalf("login: %+v", d)
		}
	}
	// Only the first login counted for the overall limit.
	for i := range 2 {
		if !allow(l, "GET", "/", ip).Allowed {
			t.Fatalf("request %d rejected", i+1)
		}
	}
	if allow(l, "GET", "/", ip).Allowed {
		t.Fatal("4th request allowed")
	}
	// When both rules are exceeded, the longer wait is reported.
	*now = now.Add(20 * time.Second)
	d := allow(l, "POST", "/login", ip)
	if d.Allowed || d.RetryAfter != 40*time.Second {
		t.Errorf("both exceeded: allowed = %v, RetryAfter = %v, rule = %v", d.Allowed, d.RetryAfter, d.Rule)
	}
}

func TestIPv6Network(t *testing.T) {
	l, _ := testLimiter(t, Config{}, "2/1m")
	allow(l, "GET", "/", "2001:db8:1:2::1")
	allow(l, "GET", "/", "2001:db8:1:2:ffff::9")
	d := allow(l, "GET", "/", "2001:db8:1:2:aaaa:bbbb:cccc:dddd")
	if d.Allowed {
		t.Fatal("third address of the same /64 allowed")
	}
	if d.Client != netip.MustParsePrefix("2001:db8:1:2::/64") {
		t.Errorf("client = %v", d.Client)
	}
	if !allow(l, "GET", "/", "2001:db8:1:3::1").Allowed {
		t.Error("another /64 rejected")
	}
	// IPv4-mapped addresses count as IPv4.
	allow(l, "GET", "/", "::ffff:192.0.2.1")
	allow(l, "GET", "/", "192.0.2.1")
	if d := allow(l, "GET", "/", "192.0.2.1"); d.Allowed || d.Client != netip.MustParsePrefix("192.0.2.1/32") {
		t.Errorf("mapped address: %+v", d)
	}
}

func TestExempt(t *testing.T) {
	exempt, err := ParsePrefixes("10.0.0.0/8, 2001:db8::1")
	if err != nil {
		t.Fatal(err)
	}
	l, _ := testLimiter(t, Config{Exempt: exempt}, "1/1m")
	for _, ip := range []string{"10.1.2.3", "::ffff:10.1.2.3", "2001:db8::1"} {
		for range 5 {
			if !allow(l, "GET", "/", ip).Allowed {
				t.Fatalf("exempt %s limited", ip)
			}
		}
	}
	allow(l, "GET", "/", "2001:db8::2")
	if allow(l, "GET", "/", "2001:db8::2").Allowed {
		t.Error("non-exempt address in the same /64 allowed")
	}
	if l.Len() != 1 {
		t.Errorf("tracking %d clients, want 1", l.Len())
	}
	for _, s := range []string{"10.0.0.0/33", "example.com"} {
		if _, err := ParsePrefixes(s); err == nil {
			t.Errorf("ParsePrefixes(%q) succeeded", s)
		}
	}
}

func TestEventIDPerExcess(t *testing.T) {
	l, now := testLimiter(t, Config{}, "1/1m")
	ip := "192.0.2.1"
	allow(l, "GET", "/", ip)
	first := allow(l, "GET", "/", ip)
	if first.Allowed || !first.First || first.EventID == "" {
		t.Fatalf("first rejection: %+v", first)
	}
	for range 3 {
		d := allow(l, "GET", "/", ip)
		if d.First || d.EventID != first.EventID {
			t.Fatalf("later rejection: %+v, want event %s", d, first.EventID)
		}
	}
	*now = now.Add(time.Minute)
	allow(l, "GET", "/", ip)
	d := allow(l, "GET", "/", ip)
	if !d.First || d.EventID == first.EventID {
		t.Errorf("new excess: %+v", d)
	}
}

func TestIdleClientsAreForgotten(t *testing.T) {
	l, now := testLimiter(t, Config{}, "10/10s")
	for i := range 100 {
		allow(l, "GET", "/", netip.AddrFrom4([4]byte{192, 0, 2, byte(i)}).String())
	}
	if l.Len() != 100 {
		t.Fatalf("tracking %d clients", l.Len())
	}
	// Once their allowance has refilled, the next sweep of each shard
	// removes them.
	*now = now.Add(sweepInterval)
	for i := range 2000 {
		allow(l, "GET", "/", netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}).String())
	}
	*now = now.Add(sweepInterval)
	for i := range 2000 {
		allow(l, "GET", "/", netip.AddrFrom4([4]byte{198, 51, byte(i >> 8), byte(i)}).String())
	}
	if n := l.Len(); n != 2000 {
		t.Errorf("tracking %d clients, want 2000", n)
	}
}

func TestMaxClients(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(slog.NewTextHandler(&buf, nil))
	l, _ := testLimiter(t, Config{MaxClients: numShards * 2, Logger: logger}, "1/1h")
	for i := range 1000 {
		allow(l, "GET", "/", netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)}).String())
	}
	if n := l.Len(); n > numShards*2 {
		t.Errorf("tracking %d clients, want at most %d", n, numShards*2)
	}
	if c := strings.Count(buf.String(), "maximum number of clients"); c != 1 {
		t.Errorf("logged the warning %d times, want once:\n%s", c, buf.String())
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	for _, cfg := range []Config{
		{},
		{Rules: []Rule{{Limit: 0, Window: time.Minute}}},
		{Rules: []Rule{{Limit: 1, Window: 0}}},
		{Rules: []Rule{{Limit: 1, Window: time.Minute}}, MaxClients: -1},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
}

func BenchmarkAllow(b *testing.B) {
	rules := []Rule{{Limit: 1000, Window: time.Second}, {Method: "POST", Path: "/login", Limit: 5, Window: time.Minute}}
	l, err := New(Config{Rules: rules})
	if err != nil {
		b.Fatal(err)
	}
	r := httptest.NewRequest("GET", "/products/42", nil)
	b.RunParallel(func(pb *testing.PB) {
		i := 0
		for pb.Next() {
			i++
			l.Allow(r, netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}).String())
		}
	})
}
