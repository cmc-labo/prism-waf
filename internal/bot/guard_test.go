package bot

import (
	"crypto/sha256"
	"html"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newTestGuard(t *testing.T, cfg Config) (*Guard, *time.Time) {
	t.Helper()
	if cfg.Difficulty == 0 {
		cfg.Difficulty = 8 // fast to solve in tests
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 11, 9, 0, 0, 0, time.UTC)
	g.now = func() time.Time { return now }
	return g, &now
}

func request(method, target, ua string) *http.Request {
	r := httptest.NewRequest(method, target, nil)
	if ua != "" {
		for k, v := range browserHeaders(ua, false) {
			r.Header.Set(k, v)
		}
	}
	return r
}

// solve finds the nonce for a challenge token.
func solve(t *testing.T, token string) string {
	t.Helper()
	f := strings.Split(token, ".")
	d, _ := strconv.Atoi(f[1])
	for n := 0; ; n++ {
		s := strconv.Itoa(n)
		if leadingZeroBits(sha256.Sum256([]byte(f[2]+s))) >= d {
			return s
		}
	}
}

func TestCheck(t *testing.T) {
	g, now := newTestGuard(t, Config{BlockScore: 80})
	const ip = "203.0.113.7"

	if d := g.Check(request("GET", "/", chromeUA), ip, false); d.Action != Allow || d.EventID != "" {
		t.Errorf("browser: %+v", d)
	}
	d := g.Check(request("GET", "/", "curl/8.5.0"), ip, false)
	if d.Action != Challenge || d.Score != 60 || !d.First || d.EventID == "" || d.Client.String() != ip+"/32" {
		t.Errorf("curl: %+v", d)
	}
	// The event is logged once a minute per client and action.
	d2 := g.Check(request("GET", "/other", "curl/8.5.0"), ip, false)
	if d2.First || d2.EventID != d.EventID {
		t.Errorf("second request: %+v", d2)
	}
	if d3 := g.Check(request("GET", "/", "curl/8.5.0"), "203.0.113.8", false); !d3.First || d3.EventID == d.EventID {
		t.Errorf("another client: %+v", d3)
	}
	*now = now.Add(eventInterval)
	if d4 := g.Check(request("GET", "/", "curl/8.5.0"), ip, false); !d4.First || d4.EventID == d.EventID {
		t.Errorf("a minute later: %+v", d4)
	}

	r := request("GET", "/", "")
	r.Header.Set("User-Agent", chromeUA) // only a User-Agent: score 80
	if d := g.Check(r, ip, false); d.Action != Block || !d.First {
		t.Errorf("block score: %+v", d)
	}
}

func TestCheckIPv6ClientsArePer64(t *testing.T) {
	g, _ := newTestGuard(t, Config{})
	d := g.Check(request("GET", "/", "curl/8.5.0"), "2001:db8:1:2:3:4:5:6", false)
	if d.Client.String() != "2001:db8:1:2::/64" {
		t.Errorf("client = %v", d.Client)
	}
}

func TestCheckExemptions(t *testing.T) {
	g, _ := newTestGuard(t, Config{
		Paths:       []string{"/articles/*", "/search"},
		ExemptPaths: []string{"/articles/public/*"},
		Exempt:      []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	})
	for _, tc := range []struct {
		path, ip string
		want     Action
	}{
		{"/articles/1", "203.0.113.7", Challenge},
		{"/Articles//1/", "203.0.113.7", Challenge},
		{"/articles", "203.0.113.7", Challenge},
		{"/search?q=x", "203.0.113.7", Challenge},
		{"/", "203.0.113.7", Allow},
		{"/articles/public/1", "203.0.113.7", Allow},
		{"/articles/1", "192.0.2.10", Allow},
		{"/robots.txt", "203.0.113.7", Allow},
		{"/.well-known/security.txt", "203.0.113.7", Allow},
	} {
		if d := g.Check(request("GET", tc.path, "curl/8.5.0"), tc.ip, false); d.Action != tc.want {
			t.Errorf("%s from %s: %v, want %v", tc.path, tc.ip, d.Action, tc.want)
		}
	}
	// Exempt requests are still scored for the backend.
	if d := g.Check(request("GET", "/robots.txt", "curl/8.5.0"), "203.0.113.7", false); d.Score != 60 {
		t.Errorf("score of an exempt request = %d", d.Score)
	}
}

// pass solves a challenge like the browser and returns the response to
// the solution.
func pass(t *testing.T, g *Guard, ip, ua, redirect string) *httptest.ResponseRecorder {
	t.Helper()
	token, _ := g.newChallenge(clientKey(ip), ua)
	return postSolution(g, ip, ua, url.Values{"c": {token}, "n": {solve(t, token)}, "r": {redirect}})
}

func postSolution(g *Guard, ip, ua string, form url.Values) *httptest.ResponseRecorder {
	r := httptest.NewRequest("POST", VerifyPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", ua)
	w := httptest.NewRecorder()
	g.ServeVerify(w, r, ip, true)
	return w
}

func TestChallengeAndClearance(t *testing.T) {
	g, now := newTestGuard(t, Config{ClearanceTTL: time.Hour})
	const ip, ua = "203.0.113.7", "curl/8.5.0"

	w := pass(t, g, ip, ua, "/page?a=1")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/page?a=1" {
		t.Fatalf("verify: %d %v", w.Code, w.Header())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != CookieName || !cookies[0].HttpOnly || !cookies[0].Secure ||
		cookies[0].SameSite != http.SameSiteLaxMode || cookies[0].MaxAge != 3600 {
		t.Fatalf("cookies: %+v", cookies)
	}
	withCookie := func(ip, ua string, c *http.Cookie) Decision {
		r := request("GET", "/page", "")
		r.Header.Set("User-Agent", ua)
		r.AddCookie(c)
		return g.Check(r, ip, false)
	}
	if d := withCookie(ip, ua, cookies[0]); d.Action != Allow || !d.Cleared || d.Score != 60 {
		t.Errorf("with clearance: %+v", d)
	}
	// The cookie is bound to the client address and User-Agent.
	if d := withCookie("203.0.113.8", ua, cookies[0]); d.Action != Challenge {
		t.Errorf("other address: %+v", d)
	}
	if d := withCookie(ip, "curl/8.6.0", cookies[0]); d.Action != Challenge {
		t.Errorf("other User-Agent: %+v", d)
	}
	tampered := *cookies[0]
	exp, mac, _ := strings.Cut(tampered.Value, ".")
	n, _ := strconv.ParseInt(exp, 10, 64)
	tampered.Value = strconv.FormatInt(n+86400, 10) + "." + mac
	if d := withCookie(ip, ua, &tampered); d.Action != Challenge {
		t.Errorf("extended expiry: %+v", d)
	}
	*now = now.Add(time.Hour)
	if d := withCookie(ip, ua, cookies[0]); d.Action != Challenge {
		t.Errorf("expired: %+v", d)
	}
}

func TestVerifyRejectsWrongSolutions(t *testing.T) {
	g, now := newTestGuard(t, Config{})
	const ip, ua = "203.0.113.7", "curl/8.5.0"
	client := clientKey(ip)
	token, _ := g.newChallenge(client, ua)
	nonce := solve(t, token)

	if err := g.verify(token, nonce, client, ua); err != nil {
		t.Fatalf("correct solution: %v", err)
	}
	f := strings.Split(token, ".")
	easier := f[0] + ".1." + f[2] + "." + f[3]
	for _, tc := range []struct {
		name, token, nonce, ip, ua string
		want                       error
	}{
		{"wrong nonce", token, nonce + "1", ip, ua, errWrongNonce},
		{"non-digit nonce", token, "1e3", ip, ua, errWrongNonce},
		{"empty nonce", token, "", ip, ua, errWrongNonce},
		{"other address", token, nonce, "203.0.113.8", ua, errInvalidToken},
		{"other User-Agent", token, nonce, ip, "curl/8.6.0", errInvalidToken},
		{"lowered difficulty", easier, solve(t, easier), ip, ua, errInvalidToken},
		{"garbage", "x", nonce, ip, ua, errInvalidToken},
	} {
		if err := g.verify(tc.token, tc.nonce, clientKey(tc.ip), tc.ua); err != tc.want {
			t.Errorf("%s: %v, want %v", tc.name, err, tc.want)
		}
	}
	*now = now.Add(challengeTTL + time.Second)
	if err := g.verify(token, nonce, client, ua); err != errExpired {
		t.Errorf("expired: %v", err)
	}
	// Another Guard has another secret.
	other, _ := newTestGuard(t, Config{})
	if err := other.verify(token, nonce, client, ua); err != errInvalidToken {
		t.Errorf("other secret: %v", err)
	}
}

func TestSharedSecret(t *testing.T) {
	secret := []byte(strings.Repeat("k", MinSecretLength))
	a, _ := newTestGuard(t, Config{Secret: secret})
	b, _ := newTestGuard(t, Config{Secret: secret})
	token, _ := a.newChallenge(clientKey("203.0.113.7"), "curl/8.5.0")
	if err := b.verify(token, solve(t, token), clientKey("203.0.113.7"), "curl/8.5.0"); err != nil {
		t.Errorf("instances with the same secret: %v", err)
	}
}

func TestServeVerify(t *testing.T) {
	g, now := newTestGuard(t, Config{})
	const ip, ua = "203.0.113.7", "curl/8.5.0"

	// Redirects stay on the site.
	for target, want := range map[string]string{
		"/a?b=c":               "/a?b=c",
		"":                     "/",
		"https://evil.example": "/",
		"//evil.example/":      "/",
		`/\evil.example`:       "/",
		"javascript:alert(1)":  "/",
		"/a\r\nSet-Cookie: x":  "/",
	} {
		if w := pass(t, g, ip, ua, target); w.Header().Get("Location") != want {
			t.Errorf("redirect %q: Location %q, want %q", target, w.Header().Get("Location"), want)
		}
	}

	r := httptest.NewRequest("GET", VerifyPath, nil)
	w := httptest.NewRecorder()
	g.ServeVerify(w, r, ip, false)
	if w.Code != http.StatusMethodNotAllowed {
		t.Errorf("GET: %d", w.Code)
	}

	// An expired challenge is replaced by a new one, solved automatically.
	token, _ := g.newChallenge(clientKey(ip), ua)
	nonce := solve(t, token)
	*now = now.Add(challengeTTL + time.Second)
	w = postSolution(g, ip, ua, url.Values{"c": {token}, "n": {nonce}, "r": {"/x"}})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "Checking your browser") || len(w.Result().Cookies()) != 0 {
		t.Errorf("expired: %d\n%s", w.Code, w.Body)
	}
	// Other failures are not retried automatically.
	w = postSolution(g, ip, ua, url.Values{"c": {"x"}, "n": {"1"}, "r": {"/x"}})
	if w.Code != http.StatusForbidden || !strings.Contains(w.Body.String(), "The browser check failed") ||
		strings.Contains(w.Body.String(), "<script") || !strings.Contains(w.Body.String(), `href="/x"`) {
		t.Errorf("invalid: %d\n%s", w.Code, w.Body)
	}
}

func TestServeChallenge(t *testing.T) {
	g, _ := newTestGuard(t, Config{})
	const ip = "203.0.113.7"

	r := request("GET", `/search?q=<script>"x"`, "")
	r.Header.Set("User-Agent", "curl/8.5.0")
	d := g.Check(r, ip, false)
	w := httptest.NewRecorder()
	g.ServeChallenge(w, r, d)
	body := w.Body.String()
	if w.Code != http.StatusForbidden || w.Header().Get("Cache-Control") != "no-store" ||
		!strings.HasPrefix(w.Header().Get("Content-Type"), "text/html") {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if !strings.Contains(body, "Event ID: "+d.EventID) || strings.Contains(body, "<script>\"x\"") {
		t.Errorf("body:\n%s", body)
	}
	// The script runs only with the nonce of the Content-Security-Policy.
	m := regexp.MustCompile(`script-src 'nonce-([^']+)'`).FindStringSubmatch(w.Header().Get("Content-Security-Policy"))
	if m == nil || !strings.Contains(body, `<script nonce="`+m[1]+`">`) {
		t.Errorf("CSP %q does not match the script", w.Header().Get("Content-Security-Policy"))
	}
	// The page carries a valid challenge for this client and the
	// requested URL.
	token := regexp.MustCompile(`name="c" value="([^"]+)"`).FindStringSubmatch(body)
	redirect := regexp.MustCompile(`name="r" value="([^"]+)"`).FindStringSubmatch(body)
	if token == nil || redirect == nil {
		t.Fatalf("form fields missing:\n%s", body)
	}
	if err := g.verify(token[1], solve(t, token[1]), clientKey(ip), "curl/8.5.0"); err != nil {
		t.Errorf("challenge in page: %v", err)
	}
	if html.UnescapeString(redirect[1]) != `/search?q=<script>"x"` {
		t.Errorf("redirect = %q", redirect[1])
	}

	r = request("HEAD", "/", "")
	w = httptest.NewRecorder()
	g.ServeChallenge(w, r, d)
	if w.Code != http.StatusForbidden || w.Body.Len() != 0 {
		t.Errorf("HEAD: %d %q", w.Code, w.Body)
	}

	r = request("POST", "/form", "")
	w = httptest.NewRecorder()
	g.ServeChallenge(w, r, d)
	if w.Code != http.StatusForbidden || strings.Contains(w.Body.String(), "<html") || !strings.Contains(w.Body.String(), "Event ID: "+d.EventID) {
		t.Errorf("POST: %d %q", w.Code, w.Body)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	for _, cfg := range []Config{
		{ChallengeScore: 101},
		{ChallengeScore: -1},
		{BlockScore: 101},
		{Difficulty: MaxDifficulty + 1},
		{Difficulty: -1},
		{ClearanceTTL: time.Second},
		{Secret: []byte("short")},
		{Paths: []string{"search"}},
		{Paths: []string{"POST /login"}},
		{ExemptPaths: []string{"/a*b"}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
}
