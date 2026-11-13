//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

// xff returns the headers with a client address. The tests start
// prismwaf with -trusted-proxies 127.0.0.1, so that each test client can
// have its own address.
func xff(headers map[string]string, ip string) map[string]string {
	return with(headers, "X-Forwarded-For", ip)
}

func curl(ip string) map[string]string {
	return xff(map[string]string{"User-Agent": curlUA, "Accept": "*/*"}, ip)
}

// eventID returns the event ID shown in a response.
func eventID(t *testing.T, r response) string {
	t.Helper()
	m := eventIDRe.FindStringSubmatch(r.body)
	if m == nil {
		t.Fatalf("no event ID in\n%s", r.body)
	}
	return strings.TrimSuffix(m[1], "</p>")
}

func TestBotProtection(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{
		"-trusted-proxies", "127.0.0.1",
		"-bot-difficulty", "12",
		"-bot-verify=false",
		"-bot-block-category", "scanner,ai_crawler",
		"-bot-allow-category", "monitoring",
		"-bot-exempt-path", "/api/*",
		"-bot-exempt", "192.0.2.0/24",
	}})

	t.Run("browsers pass", func(t *testing.T) {
		h := w.client(t, xff(browserHeaders, "198.51.100.1")).get("/").hit(t)
		if h.Score != "0" || h.Category != "browser" || h.Verified != "false" {
			t.Errorf("backend saw %+v", h)
		}
	})

	t.Run("bot headers from clients are replaced", func(t *testing.T) {
		c := w.client(t, xff(browserHeaders, "198.51.100.2"))
		h := c.get("/", "X-Prismwaf-Bot-Score", "0", "X-Prismwaf-Bot-Verified", "true", "X-Prismwaf-Bot-Category", "search_engine").hit(t)
		if h.Score != "0" || h.Category != "browser" || h.Verified != "false" {
			t.Errorf("backend saw %+v", h)
		}
		h = w.client(t, xff(map[string]string{"User-Agent": uptimeUA}, "198.51.100.2")).get("/", "X-Prismwaf-Bot-Score", "0", "X-Prismwaf-Bot-Verified", "true").hit(t)
		if h.Score != "50" || h.Verified != "false" {
			t.Errorf("backend saw %+v", h)
		}
	})

	t.Run("proof of work", func(t *testing.T) {
		c := w.client(t, curl("198.51.100.10"))
		r := c.get("/page?id=1&q=a+b")
		ch := parseChallenge(t, r)
		if ch.redirect != "/page?id=1&q=a+b" || ch.token == "" || ch.captcha {
			t.Errorf("challenge = %+v", ch)
		}
		csp := r.Header.Get("Content-Security-Policy")
		if m := nonceRe.FindStringSubmatch(csp); m == nil || !strings.Contains(r.body, `<script nonce="`+m[1]+`">`) ||
			!strings.Contains(csp, "worker-src blob:") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Errorf("CSP %q", csp)
		}
		if r.Header.Get("Cache-Control") != "no-store" || r.Header.Get("X-Robots-Tag") != "noindex" {
			t.Errorf("headers %v", r.Header)
		}

		// A wrong solution is rejected without a cookie.
		bad := c.do("POST", "/.prismwaf/challenge", url.Values{"c": {ch.token}, "r": {ch.redirect}, "n": {"x"}})
		if bad.StatusCode != http.StatusForbidden || bad.cookie() != nil || !strings.Contains(bad.body, "The browser check failed") {
			t.Errorf("wrong nonce: %d %v", bad.StatusCode, bad.Cookies())
		}

		ok := c.do("POST", "/.prismwaf/challenge", url.Values{"c": {ch.token}, "r": {ch.redirect}, "n": {solve(t, ch.token)}})
		cookie := ok.cookie()
		if ok.StatusCode != http.StatusSeeOther || ok.Header.Get("Location") != "/page?id=1&q=a+b" || cookie == nil {
			t.Fatalf("solution: %d %v", ok.StatusCode, ok.Header)
		}
		if !cookie.HttpOnly || cookie.Secure || cookie.SameSite != http.SameSiteLaxMode || cookie.Path != "/" || cookie.MaxAge != 86400 {
			t.Errorf("cookie %+v", cookie)
		}
		h := c.get(ok.Header.Get("Location")).hit(t)
		if h.URI != "/page?id=1&q=a+b" || h.Score != "60" || h.Category != "automation" {
			t.Errorf("backend saw %+v", h)
		}
		// The cookie covers the whole site and can be used again.
		for range 3 {
			c.get("/other").hit(t)
		}
	})

	t.Run("clearance is bound to the client and User-Agent", func(t *testing.T) {
		c := w.client(t, curl("198.51.100.20"))
		c.pass("/")
		c.get("/").hit(t)
		parseChallenge(t, c.as(curl("198.51.100.21")).get("/"))
		parseChallenge(t, c.as(with(curl("198.51.100.20"), "User-Agent", "curl/8.6.0")).get("/"))

		// IPv6 clients are one /64 network.
		c6 := w.client(t, curl("2001:db8:1:2::1"))
		c6.pass("/")
		c6.as(curl("2001:db8:1:2::ffff")).get("/").hit(t)
		parseChallenge(t, c6.as(curl("2001:db8:1:3::1")).get("/"))
	})

	t.Run("challenges are bound to the client", func(t *testing.T) {
		c := w.client(t, curl("198.51.100.30"))
		ch := parseChallenge(t, c.get("/"))
		form := url.Values{"c": {ch.token}, "r": {"/"}, "n": {solve(t, ch.token)}}
		if r := c.as(curl("198.51.100.31")).do("POST", "/.prismwaf/challenge", form); r.cookie() != nil {
			t.Error("solution accepted from another address")
		}
		if r := c.as(with(curl("198.51.100.30"), "User-Agent", "Wget/1.21")).do("POST", "/.prismwaf/challenge", form); r.cookie() != nil {
			t.Error("solution accepted from another User-Agent")
		}
		tampered := url.Values{"c": {strings.Replace(ch.token, ".12.", ".1.", 1)}, "r": {"/"}, "n": {"0"}}
		if r := c.do("POST", "/.prismwaf/challenge", tampered); r.cookie() != nil {
			t.Error("solution of a tampered token accepted")
		}
	})

	t.Run("forged cookies are rejected", func(t *testing.T) {
		c := w.client(t, curl("198.51.100.40"))
		cookie := c.pass("/").cookie()
		for _, v := range []string{
			strings.Replace(cookie.Value, ".1.", ".2.", 1),                 // level
			"9999999999" + cookie.Value[strings.Index(cookie.Value, "."):], // expiry
			cookie.Value[:len(cookie.Value)-2] + "AA",
			"",
		} {
			c2 := w.client(t, curl("198.51.100.40"))
			parseChallenge(t, c2.get("/", "Cookie", "prismwaf_clearance="+v))
		}
	})

	t.Run("redirects stay on the site", func(t *testing.T) {
		for _, r := range []string{"//evil.example/x", "https://evil.example/", `/\evil.example`, "javascript:alert(1)"} {
			c := w.client(t, curl("198.51.100.50"))
			ch := parseChallenge(t, c.get("/"))
			ok := c.do("POST", "/.prismwaf/challenge", url.Values{"c": {ch.token}, "r": {r}, "n": {solve(t, ch.token)}})
			if ok.Header.Get("Location") != "/" {
				t.Errorf("r=%q redirected to %q", r, ok.Header.Get("Location"))
			}
		}
	})

	t.Run("other methods and HEAD", func(t *testing.T) {
		c := w.client(t, curl("198.51.100.60"))
		r := c.do("POST", "/form", url.Values{"a": {"1"}})
		if r.StatusCode != http.StatusForbidden || !strings.Contains(r.body, "needs a browser check") || strings.Contains(r.body, "<html") {
			t.Errorf("POST: %d\n%s", r.StatusCode, r.body)
		}
		if r := c.do("HEAD", "/", nil); r.StatusCode != http.StatusForbidden || r.body != "" {
			t.Errorf("HEAD: %d %q", r.StatusCode, r.body)
		}
		if r := c.get("/.prismwaf/challenge"); r.StatusCode != http.StatusMethodNotAllowed {
			t.Errorf("GET of the verify path: %d", r.StatusCode)
		}
		c.pass("/")
		if r := c.do("POST", "/form", url.Values{"a": {"1"}}); r.StatusCode != http.StatusOK {
			t.Errorf("POST with clearance: %d", r.StatusCode)
		}
	})

	t.Run("exemptions", func(t *testing.T) {
		c := w.client(t, curl("198.51.100.70"))
		for _, p := range []string{"/robots.txt", "/favicon.ico", "/.well-known/security.txt", "/api/items", "/api/"} {
			if h := c.get(p).hit(t); h.Score != "60" {
				t.Errorf("%s: %+v", p, h)
			}
		}
		parseChallenge(t, c.get("/apix"))
		parseChallenge(t, c.get("/api/../admin"))
		w.client(t, curl("192.0.2.77")).get("/admin").hit(t)
	})

	t.Run("categories", func(t *testing.T) {
		for ip, b := range map[string][2]string{"198.51.100.80": {sqlmapUA, "scanner"}, "198.51.100.82": {gptbotUA, "ai_crawler"}} {
			want := b[1]
			c := w.client(t, xff(map[string]string{"User-Agent": b[0]}, ip))
			r := c.get("/robots-only")
			if r.StatusCode != http.StatusForbidden || strings.Contains(r.body, "<form") {
				t.Errorf("%s: %d\n%s", want, r.StatusCode, r.body)
			}
			e := w.eventByID(t, eventID(t, r))
			if e.Action != "block" || e.Bot == nil || e.Bot.Category != want {
				t.Errorf("%s: event %+v", want, e)
			}
			// Exempt paths are open to every category.
			c.get("/robots.txt").hit(t)
		}
		h := w.client(t, xff(map[string]string{"User-Agent": uptimeUA}, "198.51.100.81")).get("/status").hit(t)
		if h.Category != "monitoring" || h.Score != "50" {
			t.Errorf("monitoring: %+v", h)
		}
	})

	t.Run("clearance does not bypass inspection", func(t *testing.T) {
		c := w.client(t, curl("198.51.100.90"))
		c.pass("/")
		r := c.get("/items?id=1+UNION+SELECT+password+FROM+users")
		if r.StatusCode != http.StatusForbidden {
			t.Fatalf("SQL injection with clearance: %d", r.StatusCode)
		}
		if e := w.eventByID(t, eventID(t, r)); e.Reason == "bot" || e.Action != "block" {
			t.Errorf("event %+v", e)
		}
	})

	t.Run("audit events", func(t *testing.T) {
		c := w.client(t, curl("198.51.100.100"))
		var ids []string
		for range 5 {
			ids = append(ids, eventID(t, c.get("/")))
		}
		if len(slices.Compact(slices.Clone(ids))) != 1 {
			t.Errorf("event IDs %v, want one per minute", ids)
		}
		e := w.eventByID(t, ids[0])
		if e.Reason != "bot" || e.Action != "challenge" || e.ClientIP != "198.51.100.100" || e.Bot == nil ||
			e.Bot.Score != 60 || !slices.Equal(e.Bot.Signals, []string{"automation_tool"}) || e.Bot.Category != "automation" ||
			e.Bot.Challenge != "pow" || e.Bot.Client != "198.51.100.100/32" {
			t.Errorf("event %+v %+v", e, e.Bot)
		}
		n := 0
		for _, e := range w.events(t) {
			if e.ClientIP == "198.51.100.100" {
				n++
			}
		}
		if n != 1 {
			t.Errorf("%d events for 5 challenges", n)
		}
	})

	t.Run("concurrent clients", func(t *testing.T) {
		var wg sync.WaitGroup
		for i := range 20 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				c := w.client(t, curl(fmt.Sprintf("10.20.30.%d", i)))
				c.pass("/")
				c.get("/").hit(t)
			}()
		}
		wg.Wait()
	})
}

func TestBotBlockScore(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-trusted-proxies", "127.0.0.1", "-bot-block-score", "80"}})
	// A Chrome User-Agent without the headers of a browser scores 80.
	r := w.client(t, xff(map[string]string{"User-Agent": chromeUA}, "198.51.100.1")).get("/")
	if r.StatusCode != http.StatusForbidden || strings.Contains(r.body, "<form") {
		t.Errorf("score 80: %d\n%s", r.StatusCode, r.body)
	}
	if e := w.eventByID(t, eventID(t, r)); e.Action != "block" || e.Bot.Score != 80 || e.Bot.Challenge != "" {
		t.Errorf("event %+v %+v", e, e.Bot)
	}
	parseChallenge(t, w.client(t, curl("198.51.100.2")).get("/"))
}

func TestBotPaths(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-bot-path", "/search", "-bot-path", "/articles/*"}})
	c := w.client(t, map[string]string{"User-Agent": curlUA})
	c.get("/").hit(t)
	c.get("/search/x").hit(t)
	c.get("/articlesx").hit(t)
	parseChallenge(t, c.get("/search?q=x"))
	parseChallenge(t, c.get("/articles"))
	parseChallenge(t, c.get("/articles/"))
	parseChallenge(t, c.get("/articles/1"))
}

// TestBotHTTPS checks the signals that apply over HTTPS only and the Secure
// cookie.
func TestBotHTTPS(t *testing.T) {
	w := startWAF(t, wafOptions{tls: true})
	// Over HTTPS, browsers send fetch metadata and client hints.
	h := w.client(t, with(browserHeaders, "Sec-Fetch-Mode", "navigate", "Sec-CH-UA", `"Chromium";v="130"`)).get("/").hit(t)
	if h.Score != "0" {
		t.Errorf("browser: %+v", h)
	}
	if h := w.client(t, browserHeaders).get("/").hit(t); h.Score != "40" {
		t.Errorf("without fetch metadata: %+v", h)
	}
	c := w.client(t, map[string]string{"User-Agent": curlUA})
	if cookie := c.pass("/").cookie(); cookie == nil || !cookie.Secure {
		t.Errorf("cookie over HTTPS: %+v", cookie)
	}
	c.get("/").hit(t)
}

// TestBotSharedSecret checks that instances with the same -bot-secret-file
// accept each other's cookies, as behind a load balancer.
func TestBotSharedSecret(t *testing.T) {
	secret := writeFile(t, "secret", "0123456789abcdef0123456789abcdef\n")
	backend := startBackend(t).URL
	a := startWAF(t, wafOptions{backend: backend, args: []string{"-bot-secret-file", secret}})
	b := startWAF(t, wafOptions{backend: backend, args: []string{"-bot-secret-file", secret}})
	other := startWAF(t, wafOptions{backend: backend})

	cookie := a.client(t, map[string]string{"User-Agent": curlUA}).pass("/").cookie()
	for name, w := range map[string]*waf{"same secret": b, "random secret": other} {
		r := w.client(t, map[string]string{"User-Agent": curlUA}).get("/", "Cookie", cookie.Name+"="+cookie.Value)
		if (r.StatusCode == http.StatusOK) != (name == "same secret") {
			t.Errorf("%s: %d", name, r.StatusCode)
		}
	}
}

// TestBotFakeGooglebot checks that a client that claims to be Googlebot
// from an address that is not Google's is challenged. The DNS lookup
// fails or finds no googlebot.com name, both of which count as fake.
func TestBotFakeGooglebot(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-trusted-proxies", "127.0.0.1"}})
	r := w.client(t, xff(with(browserHeaders, "User-Agent", googleUA), "203.0.113.7")).get("/")
	parseChallenge(t, r)
	e := w.eventByID(t, eventID(t, r))
	if e.Bot.Score != 90 || !slices.Contains(e.Bot.Signals, "fake_bot") || e.Bot.Name != "Googlebot" ||
		e.Bot.Category != "search_engine" || e.Bot.Verified {
		t.Errorf("event %+v", e.Bot)
	}

	// Without verification, Googlebot is a crawler like any other.
	w = startWAF(t, wafOptions{args: []string{"-trusted-proxies", "127.0.0.1", "-bot-verify=false"}})
	r = w.client(t, xff(with(browserHeaders, "User-Agent", googleUA), "203.0.113.7")).get("/")
	parseChallenge(t, r)
	if e := w.eventByID(t, eventID(t, r)); e.Bot.Score != 50 || slices.Contains(e.Bot.Signals, "fake_bot") {
		t.Errorf("without verification: %+v", e.Bot)
	}
}

func TestBotInvalidFlags(t *testing.T) {
	secret := writeFile(t, "secret", "s3cr3t")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-bot-difficulty", "12"}, "-bot-* options require -bot-protection"},
		{[]string{"-bot-verify=false"}, "-bot-* options require -bot-protection"},
		{[]string{"-bot-protection", "-bot-captcha-min-score", "0.9"}, "-bot-captcha-* options require -bot-captcha"},
		{[]string{"-bot-protection", "-bot-difficulty", "31"}, "difficulty"},
		{[]string{"-bot-protection", "-bot-block-category", "robots"}, `unknown category`},
		{[]string{"-bot-protection", "-bot-allow-category", "seo", "-bot-block-category", "seo"}, "both allowed and blocked"},
		{[]string{"-bot-protection", "-bot-captcha", "turnstile"}, "-bot-captcha requires -bot-captcha-site-key and -bot-captcha-secret-file"},
		{[]string{"-bot-protection", "-bot-captcha", "friendlycaptcha", "-bot-captcha-site-key", "k", "-bot-captcha-secret-file", secret}, "unknown CAPTCHA provider"},
		{[]string{"-bot-protection", "-bot-captcha-site-key", "k"}, "-bot-captcha-* options require -bot-captcha"},
		{[]string{"-bot-protection", "-bot-captcha", "turnstile", "-bot-captcha-site-key", "k", "-bot-captcha-secret-file", "/nonexistent"}, "-bot-captcha-secret-file"},
		{[]string{"-bot-protection", "-bot-captcha", "turnstile", "-bot-captcha-site-key", "k", "-bot-captcha-secret-file", secret, "-bot-captcha-score", "40"}, "CAPTCHA score"},
		{[]string{"-bot-protection", "-bot-secret-file", secret}, "at least 32 bytes"},
	} {
		out, err := runWAF(t, tc.args...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%v: %v, output\n%s\nwant %q", tc.args, err, out, tc.want)
		}
	}
}
