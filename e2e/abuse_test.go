//go:build e2e

package e2e

import (
	"bufio"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"
)

// startShopBackend starts a backend with a login form that answers wrong
// passwords with 401, orders by ID, a streaming endpoint and a WebSocket-
// like upgrade.
func startShopBackend(t *testing.T) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/login":
			if r.FormValue("password") != "correct horse" {
				http.Error(w, "wrong password", http.StatusUnauthorized)
				return
			}
			fmt.Fprint(w, "welcome")
		case strings.HasPrefix(r.URL.Path, "/api/orders/"):
			id := strings.TrimPrefix(r.URL.Path, "/api/orders/")
			if strings.Trim(id, "0123456789") != "" {
				http.NotFound(w, r)
				return
			}
			fmt.Fprintf(w, `{"order":%q}`, id)
		case r.URL.Path == "/events":
			// The first event must reach the client before the second
			// is sent.
			w.Header().Set("Content-Type", "text/event-stream")
			fmt.Fprint(w, "data: first\n\n")
			http.NewResponseController(w).Flush()
			select {
			case <-r.Context().Done():
			case <-time.After(3 * time.Second):
			}
			fmt.Fprint(w, "data: second\n\n")
		case r.URL.Path == "/ws":
			conn, brw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			defer conn.Close()
			brw.WriteString("HTTP/1.1 101 Switching Protocols\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
			brw.Flush()
			line, _ := brw.ReadString('\n')
			brw.WriteString("echo " + line)
			brw.Flush()
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// startShopWAF starts prismwaf in front of the shop behind a trusted
// proxy, so that each request can name its client in X-Forwarded-For.
func startShopWAF(t *testing.T, args ...string) *waf {
	t.Helper()
	return startWAF(t, wafOptions{backend: startShopBackend(t).URL, args: append([]string{"-trusted-proxies", "127.0.0.1"}, args...)})
}

func (c *client) login(ip, password string) response {
	c.t.Helper()
	return c.do("POST", "/login", url.Values{"user": {"alice"}, "password": {password}}, "X-Forwarded-For", ip)
}

// checkLimited checks a request rejected by a failure or enumeration
// limit and returns its audit event.
func checkLimited(t *testing.T, w *waf, r response, reason, rule, client string) auditEvent {
	t.Helper()
	m := eventIDRe.FindStringSubmatch(r.body)
	if r.StatusCode != http.StatusTooManyRequests || m == nil || r.Header.Get("Retry-After") == "" {
		t.Fatalf("not limited: %d, Retry-After %q\n%s", r.StatusCode, r.Header.Get("Retry-After"), r.body)
	}
	e := w.eventByID(t, m[1])
	if e.Reason != reason || e.Action != "block" || e.RateLimit == nil || e.RateLimit.Rule != rule || e.RateLimit.Client != client ||
		fmt.Sprint(e.RateLimit.RetryAfter) != r.Header.Get("Retry-After") {
		t.Errorf("event %+v, rate_limit %+v", e, e.RateLimit)
	}
	return e
}

func TestFailureLimit(t *testing.T) {
	w := startShopWAF(t, "-failure-limit", "POST /login=5/15m")
	w.waitLog(t, "business flow protection enabled", `failure_limits="[POST /login=5/15m 401,403]"`)
	c := w.client(t, nil)
	const attacker, user = "198.51.100.7", "203.0.113.9"

	// A user who logs in, also again and again, is never limited.
	for range 10 {
		if r := c.login(user, "correct horse"); r.StatusCode != http.StatusOK || r.body != "welcome" {
			t.Fatalf("login: %d %q", r.StatusCode, r.body)
		}
	}
	// An attacker guessing passwords gets 5 attempts…
	for i, pw := range []string{"123456", "password", "qwerty", "letmein", "dragon"} {
		if r := c.login(attacker, pw); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("guess %d: %d", i+1, r.StatusCode)
		}
	}
	// …then even the right password is rejected without reaching the
	// backend, which only answers it with "welcome".
	r := c.login(attacker, "correct horse")
	e := checkLimited(t, w, r, "failure_limit", "POST /login=5/15m 401,403", attacker+"/32")
	if e.ClientIP != attacker || e.Request.Method != "POST" || e.Request.URI != "/login" {
		t.Errorf("event %+v", e)
	}
	if ra := r.Header.Get("Retry-After"); ra != "180" {
		t.Errorf("Retry-After %q, want 180 (15m / 5)", ra)
	}
	// Further attempts share the event; variants of the path are the same
	// flow.
	for _, path := range []string{"/login", "/LOGIN", "/login/", "//login", "/x/../login", "/login;jsessionid=1"} {
		r := c.do("POST", path, url.Values{"password": {"correct horse"}}, "X-Forwarded-For", attacker)
		if m := eventIDRe.FindStringSubmatch(r.body); r.StatusCode != http.StatusTooManyRequests || m == nil || m[1] != e.ID {
			t.Errorf("POST %s: %d\n%s", path, r.StatusCode, r.body)
		}
	}
	// The rest of the site, other clients and the user are not affected.
	if r := c.get("/api/orders/1", "X-Forwarded-For", attacker); r.StatusCode != http.StatusOK {
		t.Errorf("other path: %d", r.StatusCode)
	}
	if r := c.login(user, "correct horse"); r.StatusCode != http.StatusOK {
		t.Errorf("user after the attack: %d", r.StatusCode)
	}
	n := 0
	for _, e := range w.events(t) {
		if e.Reason == "failure_limit" {
			n++
		}
	}
	if n != 1 {
		t.Errorf("%d failure_limit events, want 1", n)
	}
}

func TestFailureLimitStatuses(t *testing.T) {
	// Failures of another flow: any 4xx, with an allowance that refills
	// by one attempt a second.
	w := startShopWAF(t, "-failure-limit", "POST /api/orders/*=2/2s 4xx")
	c := w.client(t, nil)
	ip := "198.51.100.8"
	post := func(id string) response {
		return c.do("POST", "/api/orders/"+id, url.Values{}, "X-Forwarded-For", ip)
	}
	for range 5 {
		if r := post("1"); r.StatusCode != http.StatusOK {
			t.Fatalf("existing order: %d", r.StatusCode)
		}
	}
	for range 2 {
		if r := post("bogus"); r.StatusCode != http.StatusNotFound {
			t.Fatalf("missing order: %d", r.StatusCode)
		}
	}
	r := post("1")
	checkLimited(t, w, r, "failure_limit", "POST /api/orders/*=2/2s 4xx", ip+"/32")
	if ra := r.Header.Get("Retry-After"); ra != "1" {
		t.Errorf("Retry-After %q", ra)
	}
	time.Sleep(1100 * time.Millisecond)
	if r := post("bogus"); r.StatusCode != http.StatusNotFound {
		t.Fatalf("after a second: %d", r.StatusCode)
	}
	if r := post("1"); r.StatusCode != http.StatusTooManyRequests {
		t.Errorf("second attempt after a second: %d", r.StatusCode)
	}
}

func TestEnumerationLimit(t *testing.T) {
	w := startShopWAF(t, "-enumeration-limit", "GET /api/orders/{id}=3/1h")
	w.waitLog(t, "business flow protection enabled", `enumeration_limits="[GET /api/orders/{id}=3/1h]"`)
	c := w.client(t, nil)
	const scraper = "198.51.100.9"

	// A customer looks at their orders as often as they like.
	for range 5 {
		for _, id := range []string{"1001", "1002", "1003"} {
			if h := c.get("/api/orders/"+id, "X-Forwarded-For", scraper); h.StatusCode != http.StatusOK || !strings.Contains(h.body, id) {
				t.Fatalf("order %s: %d %s", id, h.StatusCode, h.body)
			}
		}
	}
	// A scraper walking through the IDs is stopped at the fourth,
	// however it spells the path.
	r := c.get("/api/orders/1004", "X-Forwarded-For", scraper)
	e := checkLimited(t, w, r, "enumeration", "GET /api/orders/{id}=3/1h", scraper+"/32")
	if ra := r.Header.Get("Retry-After"); ra != "3600" {
		t.Errorf("Retry-After %q", ra)
	}
	for _, path := range []string{"/api/orders/1005", "/API/Orders/1006", "/api/orders/%31%30%30%37", "/api//orders/./1008/", "/api/orders/1009;x"} {
		r := c.get(path, "X-Forwarded-For", scraper)
		if m := eventIDRe.FindStringSubmatch(r.body); r.StatusCode != http.StatusTooManyRequests || m == nil || m[1] != e.ID {
			t.Errorf("GET %s: %d\n%s", path, r.StatusCode, r.body)
		}
	}
	// Orders already seen stay available; other clients have their own
	// allowance, and the /64 of an IPv6 client counts as one.
	if r := c.get("/api/orders/1002", "X-Forwarded-For", scraper); r.StatusCode != http.StatusOK {
		t.Errorf("order already seen: %d", r.StatusCode)
	}
	for i := range 3 {
		ip := fmt.Sprintf("2001:db8:5:6::%d", i+1)
		if r := c.get(fmt.Sprintf("/api/orders/%d", 2000+i), "X-Forwarded-For", ip); r.StatusCode != http.StatusOK {
			t.Fatalf("IPv6 order %d: %d", i, r.StatusCode)
		}
	}
	r = c.get("/api/orders/2003", "X-Forwarded-For", "2001:db8:5:6:ffff::1")
	checkLimited(t, w, r, "enumeration", "GET /api/orders/{id}=3/1h", "2001:db8:5:6::/64")
	if r := c.get("/api/orders/2003", "X-Forwarded-For", "2001:db8:5:7::1"); r.StatusCode != http.StatusOK {
		t.Errorf("other /64: %d", r.StatusCode)
	}
}

func TestBusinessFlowModes(t *testing.T) {
	// In detect mode, the excess is logged once and everything is
	// forwarded.
	w := startShopWAF(t, "-mode", "detect", "-failure-limit", "POST /login=2/1h", "-enumeration-limit", "/api/orders/{id}=1/1h")
	c := w.client(t, nil)
	ip := "198.51.100.10"
	for range 4 {
		if r := c.login(ip, "wrong"); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("detect mode login: %d", r.StatusCode)
		}
	}
	for _, id := range []string{"1", "2", "3"} {
		if r := c.get("/api/orders/"+id, "X-Forwarded-For", ip); r.StatusCode != http.StatusOK {
			t.Fatalf("detect mode order: %d", r.StatusCode)
		}
	}
	var got []string
	for _, e := range w.events(t) {
		got = append(got, e.Reason+":"+e.Action)
	}
	if strings.Join(got, " ") != "failure_limit:detect enumeration:detect" {
		t.Errorf("events %q", got)
	}

	// Exempt clients are never limited.
	w = startShopWAF(t, "-failure-limit", "POST /login=1/1h", "-rate-limit-exempt", "192.0.2.0/24")
	c = w.client(t, nil)
	for range 3 {
		if r := c.login("192.0.2.1", "wrong"); r.StatusCode != http.StatusUnauthorized {
			t.Fatalf("exempt client: %d", r.StatusCode)
		}
	}
}

// TestFailureLimitStreaming checks that responses of a flow with a failure
// limit still stream and upgrade, as the WAF watches their status.
func TestFailureLimitStreaming(t *testing.T) {
	w := startShopWAF(t, "-failure-limit", "/events=5/1m", "-failure-limit", "/ws=5/1m")
	resp, err := http.Get(w.URL + "/events")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	start := time.Now()
	line, err := bufio.NewReader(resp.Body).ReadString('\n')
	if err != nil || line != "data: first\n" || time.Since(start) > 2*time.Second {
		t.Errorf("first event %q after %v: %v", line, time.Since(start), err)
	}

	conn, err := net.Dial("tcp", strings.TrimPrefix(w.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprint(conn, "GET /ws HTTP/1.1\r\nHost: shop\r\nUpgrade: echo\r\nConnection: Upgrade\r\n\r\n")
	br := bufio.NewReader(conn)
	res, err := http.ReadResponse(br, nil)
	if err != nil || res.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", res, err)
	}
	fmt.Fprint(conn, "hello\n")
	if got, _ := br.ReadString('\n'); got != "echo hello\n" {
		t.Errorf("echo %q", got)
	}
}

func TestBusinessFlowStartup(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-failure-limit", "POST /login=5"}, "invalid -failure-limit"},
		{[]string{"-failure-limit", "POST /login=5/15m 302x"}, "want a code from 200 to 599"},
		{[]string{"-enumeration-limit", "GET /api/orders=100/1h"}, "the path has no parameter"},
		{[]string{"-enumeration-limit", "GET /api/{id}.json=100/1h"}, "a parameter must be a whole segment"},
	} {
		out, err := runWAF(t, tc.args...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%q: %v\n%s", tc.args, err, out)
		}
	}
}
