package abuse

import (
	"io"
	"log/slog"
	"net/http/httptest"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestParseFailureRule(t *testing.T) {
	for in, want := range map[string]string{
		"POST /login=5/15m":                 "POST /login=5/15m 401,403",
		"post /Login/=5/15m  401":           "POST /login=5/15m 401",
		"/api/redeem=10/h 4xx, 5XX":         "/api/redeem=10/1h 4xx,5xx",
		"POST /otp=3/10m 400-409,422":       "POST /otp=3/10m 400-409,422",
		"/a=b=1/1m 200":                     "/a=b=1/1m 200",
		"POST /api/*=20/1m 401,403,401-401": "POST /api/*=20/1m 401,403,401",
	} {
		r, err := ParseFailureRule(in)
		if err != nil {
			t.Errorf("ParseFailureRule(%q): %v", in, err)
			continue
		}
		if r.String() != want {
			t.Errorf("ParseFailureRule(%q) = %q, want %q", in, r.String(), want)
		}
	}
	for _, in := range []string{"POST /login", "login=5/1m", "POST /login=5", "POST /login=5/1m abc", "POST /login=5/1m 99",
		"POST /login=5/1m 600", "POST /login=5/1m 1xx", "POST /login=5/1m 6xx", "POST /login=5/1m 410-400", "POST /login=5/1m 401,"} {
		if _, err := ParseFailureRule(in); err == nil {
			t.Errorf("ParseFailureRule(%q) succeeded", in)
		}
	}
	r, _ := ParseFailureRule("POST /login=5/15m 401,5xx")
	for status, want := range map[int]bool{200: false, 302: false, 400: false, 401: true, 403: false, 500: true, 503: true} {
		if r.Fails(status) != want {
			t.Errorf("Fails(%d) = %v", status, !want)
		}
	}
}

func TestParseEnumerationRule(t *testing.T) {
	for in, want := range map[string]string{
		"GET /api/orders/{id}=100/1h":     "GET /api/orders/{id}=100/1h",
		"/Users/{User}/Files/{f}/=50/10m": "/users/{user}/files/{f}=50/10m",
		"get //api/./invoices/{n}=5/m":    "GET /api/invoices/{n}=5/1m",
		"/{tenant}/a=b=1/1m":              "/{tenant}/a=b=1/1m",
	} {
		r, err := ParseEnumerationRule(in)
		if err != nil {
			t.Errorf("ParseEnumerationRule(%q): %v", in, err)
			continue
		}
		if r.String() != want {
			t.Errorf("ParseEnumerationRule(%q) = %q, want %q", in, r.String(), want)
		}
	}
	for _, in := range []string{"GET /api/orders=100/1h", "GET /api/orders/{id}", "api/{id}=1/1m", "GET /api/{id}.json=1/1m",
		"GET /api/{}=1/1m", "GET /api/*=1/1m", "G3T /api/{id}=1/1m", "GET /api/{id} x=1/1m", "GET /api/{id}=0/1m"} {
		if _, err := ParseEnumerationRule(in); err == nil {
			t.Errorf("ParseEnumerationRule(%q) succeeded", in)
		}
	}
}

func testGuard(t testing.TB, cfg Config, failures, enumerations []string) (*Guard, *time.Time) {
	t.Helper()
	for _, s := range failures {
		r, err := ParseFailureRule(s)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Failures = append(cfg.Failures, r)
	}
	for _, s := range enumerations {
		r, err := ParseEnumerationRule(s)
		if err != nil {
			t.Fatal(err)
		}
		cfg.Enumerations = append(cfg.Enumerations, r)
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 19, 12, 0, 0, 0, time.UTC)
	if g.enum != nil {
		g.enum.now = func() time.Time { return now }
	}
	return g, &now
}

func check(g *Guard, method, target, ip string) Decision {
	return g.Check(httptest.NewRequest(method, target, nil), ip)
}

func TestFailureLimit(t *testing.T) {
	g, _ := testGuard(t, Config{}, []string{"POST /login=3/1h", "POST /api/redeem=2/1h 4xx"}, nil)
	login := httptest.NewRequest("POST", "/login", nil)
	ip := "192.0.2.1"
	if !g.CountsFailures(login) || g.CountsFailures(httptest.NewRequest("GET", "/login", nil)) {
		t.Fatal("CountsFailures does not follow the rules")
	}
	// Successful logins are never limited.
	for range 20 {
		if d := g.Check(login, ip); !d.Allowed {
			t.Fatal("rejected without failures")
		}
		g.Record(login, ip, 200)
		g.Record(login, ip, 302)
		g.Record(login, ip, 404) // not a failure of this rule
	}
	for range 3 {
		if d := g.Check(login, ip); !d.Allowed {
			t.Fatal("rejected before the limit")
		}
		g.Record(login, ip, 401)
	}
	d := g.Check(login, ip)
	if d.Allowed || d.Reason != ReasonFailureLimit || d.Rule != "POST /login=3/1h 401,403" || !d.First || d.EventID == "" ||
		d.Client != netip.MustParsePrefix("192.0.2.1/32") || d.RetryAfter <= 19*time.Minute || d.RetryAfter > 20*time.Minute {
		t.Fatalf("after 3 failures: %+v", d)
	}
	if d2 := g.Check(login, ip); d2.Allowed || d2.First || d2.EventID != d.EventID {
		t.Errorf("second rejection: %+v", d2)
	}
	// The limit applies to the flow only, to this client only.
	if d := check(g, "GET", "/login", ip); !d.Allowed {
		t.Error("GET /login rejected")
	}
	if d := check(g, "POST", "/LOGIN/", "192.0.2.2"); !d.Allowed {
		t.Error("other client rejected")
	}
	if d := check(g, "POST", "/LOGIN/", ip); d.Allowed {
		t.Error("variant of the path allowed")
	}
	// The other rule counts its own statuses.
	redeem := httptest.NewRequest("POST", "/api/redeem", nil)
	g.Record(redeem, ip, 404)
	g.Record(redeem, ip, 401)
	if d := g.Check(redeem, ip); d.Allowed || d.Rule != "POST /api/redeem=2/1h 4xx" {
		t.Errorf("redeem after 2 failures: %+v", d)
	}
}

func TestFailureLimitIPv6AndExempt(t *testing.T) {
	g, _ := testGuard(t, Config{Exempt: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, []string{"POST /login=1/1h"}, nil)
	login := httptest.NewRequest("POST", "/login", nil)
	g.Record(login, "2001:db8:1:2::1", 403)
	// The whole /64 shares the limit.
	if d := g.Check(login, "2001:db8:1:2:ffff::9"); d.Allowed || d.Client != netip.MustParsePrefix("2001:db8:1:2::/64") {
		t.Errorf("same /64: %+v", d)
	}
	if d := g.Check(login, "2001:db8:1:3::1"); !d.Allowed {
		t.Error("other /64 rejected")
	}
	for range 5 {
		g.Record(login, "10.0.0.1", 401)
	}
	if d := g.Check(login, "10.0.0.1"); !d.Allowed {
		t.Error("exempt client rejected")
	}
}

func TestEnumerationLimit(t *testing.T) {
	g, now := testGuard(t, Config{}, nil, []string{"GET /api/orders/{id}=3/1h", "/users/{u}/files/{f}=2/10m"})
	ip := "192.0.2.1"
	for _, id := range []string{"1", "2", "3", "1", "2", "3", "3"} {
		if d := check(g, "GET", "/api/orders/"+id, ip); !d.Allowed {
			t.Fatalf("order %s rejected", id)
		}
	}
	d := check(g, "GET", "/api/orders/4", ip)
	if d.Allowed || d.Reason != ReasonEnumeration || d.Rule != "GET /api/orders/{id}=3/1h" || !d.First || d.RetryAfter != time.Hour {
		t.Fatalf("4th order: %+v", d)
	}
	*now = now.Add(10 * time.Minute)
	d2 := check(g, "GET", "/api/orders/5", ip)
	if d2.Allowed || d2.First || d2.EventID != d.EventID || d2.RetryAfter != 50*time.Minute {
		t.Errorf("5th order: %+v", d2)
	}
	// IDs already seen stay available, also in variants of the path;
	// other methods, paths and clients are not limited.
	for _, target := range []string{"/api/orders/2", "/API/orders/2/", "/api//orders/./3", "/api/orders/1;x=y", "/api/orders/1?page=2"} {
		if d := check(g, "GET", target, ip); !d.Allowed {
			t.Errorf("GET %s rejected", target)
		}
	}
	for _, target := range []string{"/api/orders/9/items", "/api/orders", "/api/orders/"} {
		if d := check(g, "GET", target, ip); !d.Allowed {
			t.Errorf("GET %s rejected", target)
		}
	}
	if d := check(g, "DELETE", "/api/orders/9", ip); !d.Allowed {
		t.Error("DELETE rejected by a GET rule")
	}
	if d := check(g, "GET", "/api/orders/9", "192.0.2.2"); !d.Allowed {
		t.Error("other client rejected")
	}
	// A new window starts after the old one ended.
	*now = now.Add(50 * time.Minute)
	for _, id := range []string{"7", "8", "9"} {
		if d := check(g, "GET", "/api/orders/"+id, ip); !d.Allowed {
			t.Fatalf("next window: order %s rejected", id)
		}
	}
	if d := check(g, "GET", "/api/orders/10", ip); d.Allowed || !d.First || d.EventID == d2.EventID {
		t.Errorf("next window: 4th order: %+v", d)
	}

	// With several parameters, their combination is counted.
	for _, target := range []string{"/users/a/files/1", "/users/b/files/1"} {
		if d := check(g, "PUT", target, ip); !d.Allowed {
			t.Fatalf("%s rejected", target)
		}
	}
	if d := check(g, "PUT", "/users/a/files/2", ip); d.Allowed {
		t.Error("3rd combination allowed")
	}
}

func TestEnumerationMaxClients(t *testing.T) {
	var logs strings.Builder
	g, _ := testGuard(t, Config{MaxClients: numShards}, nil, []string{"/items/{id}=1/1h"})
	g.enum.logger = newTestLogger(&logs)
	for i := range 10 * numShards {
		check(g, "GET", "/items/1", netip.AddrFrom4([4]byte{192, 0, byte(i >> 8), byte(i)}).String())
	}
	if n := g.enum.Len(); n > numShards {
		t.Errorf("tracking %d clients, want at most %d", n, numShards)
	}
	if !strings.Contains(logs.String(), "maximum number of clients") {
		t.Errorf("no warning logged: %q", logs.String())
	}
}

func newTestLogger(w io.Writer) *slog.Logger { return slog.New(slog.NewTextHandler(w, nil)) }

func TestNew(t *testing.T) {
	if _, err := New(Config{}); err == nil {
		t.Error("New without rules succeeded")
	}
	r, _ := ParseFailureRule("POST /login=5/1m")
	if _, err := New(Config{Failures: []FailureRule{r}, MaxClients: -1}); err == nil {
		t.Error("New with negative MaxClients succeeded")
	}
	r.Statuses = nil
	if _, err := New(Config{Failures: []FailureRule{r}}); err == nil {
		t.Error("New with a rule without statuses succeeded")
	}
	if _, err := New(Config{Enumerations: []EnumerationRule{{Path: "/a/{id}", Limit: 0, Window: time.Minute}}}); err == nil {
		t.Error("New with an invalid enumeration rule succeeded")
	}
	if !slices.Equal(DefaultFailureStatuses, []StatusRange{{401, 401}, {403, 403}}) {
		t.Error("DefaultFailureStatuses changed")
	}
}

func TestEnumerationExempt(t *testing.T) {
	g, _ := testGuard(t, Config{Exempt: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}}, nil, []string{"/items/{id}=1/1h"})
	for _, id := range []string{"1", "2", "3"} {
		if d := check(g, "GET", "/items/"+id, "::ffff:10.1.2.3"); !d.Allowed {
			t.Fatalf("exempt client: item %s rejected", id)
		}
	}
	if g.enum.Len() != 0 {
		t.Errorf("exempt client tracked")
	}
}

func TestEnumerationWindowEnds(t *testing.T) {
	// Within a minute, before the state of the client is swept.
	g, now := testGuard(t, Config{}, nil, []string{"/items/{id}=1/30s"})
	check(g, "GET", "/items/1", "192.0.2.1")
	if d := check(g, "GET", "/items/2", "192.0.2.1"); d.Allowed || d.RetryAfter != 30*time.Second {
		t.Fatalf("second item: %+v", d)
	}
	*now = now.Add(31 * time.Second)
	if d := check(g, "GET", "/items/2", "192.0.2.1"); !d.Allowed {
		t.Errorf("after the window: %+v", d)
	}
}

func BenchmarkCheck(b *testing.B) {
	g, _ := testGuard(b, Config{}, []string{"POST /login=5/15m"}, []string{"GET /api/orders/{id}=1000/1h"})
	login := httptest.NewRequest("POST", "/login", nil)
	order := httptest.NewRequest("GET", "/api/orders/12345", nil)
	other := httptest.NewRequest("GET", "/static/app.js", nil)
	// The worst case: a client at its limit of distinct IDs.
	for i := range 1000 {
		check(g, "GET", "/api/orders/"+strconv.Itoa(i), "192.0.2.1")
	}
	b.Run("other", func(b *testing.B) {
		for b.Loop() {
			g.Check(other, "192.0.2.1")
		}
	})
	b.Run("failure", func(b *testing.B) {
		for b.Loop() {
			g.Check(login, "192.0.2.1")
			g.Record(login, "192.0.2.2", 200)
		}
	})
	b.Run("enumeration-1000", func(b *testing.B) {
		for b.Loop() {
			g.Check(order, "192.0.2.1")
		}
	})
}
