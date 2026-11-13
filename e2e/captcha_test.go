//go:build e2e

package e2e

import (
	"crypto/tls"
	"encoding/json"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"
)

// fakeProvider is a siteverify API for all providers. prismwaf reaches it
// through an HTTPS proxy (HTTPS_PROXY) that connects every host to it, and
// trusts its certificate through SSL_CERT_FILE, so the binary is tested
// with the real provider URLs.
//
// The answer depends on the solution token: "pass", "fail", "other-site",
// "bad-secret", "down", and for reCAPTCHA v3 "low-score" and
// "wrong-action".
type fakeProvider struct {
	env []string

	mu       sync.Mutex
	connects []string
	calls    []providerCall
}

type providerCall struct {
	path string
	form url.Values
}

func startProvider(t *testing.T) *fakeProvider {
	t.Helper()
	p := &fakeProvider{}
	ca := newPKI(t)
	api := httptest.NewUnstartedServer(http.HandlerFunc(p.serveSiteverify))
	api.TLS = &tls.Config{Certificates: []tls.Certificate{ca.issue(t, "challenges.cloudflare.com", "api.hcaptcha.com", "www.google.com")}}
	api.StartTLS()
	t.Cleanup(api.Close)

	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodConnect {
			http.Error(w, "CONNECT only", http.StatusMethodNotAllowed)
			return
		}
		p.mu.Lock()
		p.connects = append(p.connects, r.Host)
		p.mu.Unlock()
		upstream, err := net.Dial("tcp", api.Listener.Addr().String())
		if err != nil {
			http.Error(w, err.Error(), http.StatusBadGateway)
			return
		}
		conn, buf, err := w.(http.Hijacker).Hijack()
		if err != nil {
			upstream.Close()
			return
		}
		conn.Write([]byte("HTTP/1.1 200 Connection established\r\n\r\n"))
		go func() {
			io.Copy(upstream, buf)
			upstream.Close()
		}()
		io.Copy(conn, upstream)
		conn.Close()
	}))
	t.Cleanup(proxy.Close)
	p.env = []string{"HTTPS_PROXY=" + proxy.URL, "https_proxy=" + proxy.URL, "NO_PROXY=", "no_proxy=", "SSL_CERT_FILE=" + ca.caFile, "SSL_CERT_DIR="}
	return p
}

func (p *fakeProvider) serveSiteverify(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	p.mu.Lock()
	p.calls = append(p.calls, providerCall{r.URL.Path, r.PostForm})
	p.mu.Unlock()
	resp := map[string]any{"success": true, "hostname": "127.0.0.1", "action": "prismwaf_challenge", "score": 0.9}
	switch r.PostForm.Get("response") {
	case "fail":
		resp = map[string]any{"success": false, "error-codes": []string{"invalid-input-response"}}
	case "other-site":
		resp["hostname"] = "other.example"
	case "bad-secret":
		resp = map[string]any{"success": false, "error-codes": []string{"invalid-input-secret"}}
	case "down":
		http.Error(w, "maintenance", http.StatusServiceUnavailable)
		return
	case "low-score":
		resp["score"] = 0.1
	case "wrong-action":
		resp["action"] = "login"
	}
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

func (p *fakeProvider) lastCall() providerCall {
	p.mu.Lock()
	defer p.mu.Unlock()
	if len(p.calls) == 0 {
		return providerCall{}
	}
	return p.calls[len(p.calls)-1]
}

func (p *fakeProvider) numCalls() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return len(p.calls)
}

func TestCaptcha(t *testing.T) {
	for _, tc := range []struct {
		provider    string
		host, path  string
		widget      string // in the page; empty for invisible CAPTCHAs
		script, csp string
		sendSiteKey bool
	}{
		{"turnstile", "challenges.cloudflare.com:443", "/turnstile/v0/siteverify", `class="captcha cf-turnstile" data-sitekey="site-key-1"`,
			"https://challenges.cloudflare.com/turnstile/v0/api.js", "frame-src https://challenges.cloudflare.com", false},
		{"hcaptcha", "api.hcaptcha.com:443", "/siteverify", `class="captcha h-captcha" data-sitekey="site-key-1"`,
			"https://js.hcaptcha.com/1/api.js", "connect-src https://hcaptcha.com https://*.hcaptcha.com", true},
		{"recaptcha", "www.google.com:443", "/recaptcha/api/siteverify", `class="captcha g-recaptcha" data-sitekey="site-key-1"`,
			"https://www.google.com/recaptcha/api.js", "connect-src https://www.google.com/recaptcha/", false},
		{"recaptcha-v3", "www.google.com:443", "/recaptcha/api/siteverify", "",
			"https://www.google.com/recaptcha/api.js?render=site-key-1", "connect-src https://www.google.com/recaptcha/", false},
	} {
		t.Run(tc.provider, func(t *testing.T) {
			p := startProvider(t)
			w := startWAF(t, wafOptions{env: p.env, args: []string{
				"-trusted-proxies", "127.0.0.1",
				"-bot-captcha", tc.provider,
				"-bot-captcha-site-key", "site-key-1",
				"-bot-captcha-secret-file", writeFile(t, "captcha-secret", "provider-secret\n"),
				"-bot-captcha-score", "70",
				"-bot-captcha-min-score", "0.7",
			}})
			const ip = "198.51.100.1"
			// The same User-Agent scores 60 with an Accept header and 80
			// without.
			low := xff(map[string]string{"User-Agent": chromeUA, "Accept": "*/*"}, ip)
			high := xff(map[string]string{"User-Agent": chromeUA}, ip)

			// Score 60: proof of work. Score 80: the CAPTCHA, also after the
			// proof of work.
			c := w.client(t, low)
			c.pass("/")
			c.get("/").hit(t)
			c = c.as(high)
			r := c.get("/x?y=1")
			ch := parseChallenge(t, r)
			if !ch.captcha || ch.token != "" || ch.redirect != "/x?y=1" {
				t.Fatalf("score 80 with proof of work: %+v\n%s", ch, r.body)
			}
			if tc.widget != "" && !strings.Contains(r.body, tc.widget) || tc.widget == "" && !strings.Contains(r.body, `grecaptcha.execute("site-key-1"`) {
				t.Errorf("widget missing\n%s", r.body)
			}
			if !strings.Contains(r.body, `script.src = "`+tc.script+`"`) {
				t.Errorf("script %s missing\n%s", tc.script, r.body)
			}
			csp := r.Header.Get("Content-Security-Policy")
			if m := nonceRe.FindStringSubmatch(csp); m == nil || !strings.Contains(csp, tc.csp) || !strings.Contains(r.body, `<script nonce="`+m[1]+`">`) {
				t.Errorf("CSP %q", csp)
			}
			// The event of a client is logged once a minute, so this one is
			// for the proof of work. Check the event of a new client.
			r = w.client(t, xff(map[string]string{"User-Agent": chromeUA}, "198.51.100.3")).get("/")
			if e := w.eventByID(t, eventID(t, r)); e.Bot.Challenge != "captcha" || e.Bot.Score != 80 {
				t.Errorf("event %+v", e.Bot)
			}

			// Rejected solutions. Only those that fail for every user are
			// logged.
			type attempt struct {
				token string
				warn  string
			}
			attempts := []attempt{
				{"fail", ""},
				{"other-site", `the solution is for \"other.example\", not \"127.0.0.1\"`},
				{"bad-secret", "invalid-input-secret"},
				{"down", "503 Service Unavailable"},
			}
			if tc.provider == "recaptcha-v3" {
				attempts = append(attempts, attempt{"low-score", ""}, attempt{"wrong-action", ""})
			}
			warnings := 0
			for _, a := range attempts {
				r := c.do("POST", "/.prismwaf/challenge", url.Values{"captcha": {a.token}, "r": {"/x?y=1"}})
				if r.StatusCode != http.StatusForbidden || r.cookie() != nil || !strings.Contains(r.body, "The CAPTCHA could not be verified.") {
					t.Errorf("%s: %d %v", a.token, r.StatusCode, r.Cookies())
				}
				if a.warn != "" {
					warnings++
					w.waitLog(t, `level=WARN msg="cannot verify CAPTCHA solutions" provider=`+tc.provider+` error="CAPTCHA`, a.warn)
				}
			}
			if n := strings.Count(w.stderr.String(), "level=WARN"); n != warnings {
				t.Errorf("%d warnings, want %d\n%s", n, warnings, w.stderr)
			}
			// Empty solutions are not sent to the provider.
			n := p.numCalls()
			if r := c.do("POST", "/.prismwaf/challenge", url.Values{"captcha": {""}, "r": {"/"}}); r.StatusCode != http.StatusForbidden || p.numCalls() != n {
				t.Errorf("empty solution: %d, %d calls", r.StatusCode, p.numCalls()-n)
			}

			ok := c.do("POST", "/.prismwaf/challenge", url.Values{"captcha": {"pass"}, "r": {"/x?y=1"}})
			if ok.StatusCode != http.StatusSeeOther || ok.Header.Get("Location") != "/x?y=1" || ok.cookie() == nil {
				t.Fatalf("solution: %d %v\n%s", ok.StatusCode, ok.Header, ok.body)
			}
			call := p.lastCall()
			want := url.Values{"secret": {"provider-secret"}, "response": {"pass"}, "remoteip": {ip}}
			if tc.sendSiteKey {
				want.Set("sitekey", "site-key-1")
			}
			if call.path != tc.path || !equalForms(call.form, want) {
				t.Errorf("siteverify call %s %v, want %s %v", call.path, call.form, tc.path, want)
			}
			p.mu.Lock()
			if slices.ContainsFunc(p.connects, func(h string) bool { return h != tc.host }) {
				t.Errorf("connected to %v, want %s", p.connects, tc.host)
			}
			p.mu.Unlock()

			// The CAPTCHA clears both levels.
			if h := c.get("/x?y=1").hit(t); h.Score != "80" {
				t.Errorf("backend saw %+v", h)
			}
			c.as(low).get("/").hit(t)
			// The cookie is bound to the client.
			parseChallenge(t, c.as(xff(map[string]string{"User-Agent": chromeUA}, "198.51.100.2")).get("/"))
		})
	}
}

func equalForms(a, b url.Values) bool {
	if len(a) != len(b) {
		return false
	}
	for k, v := range a {
		if !slices.Equal(v, b[k]) {
			return false
		}
	}
	return true
}

// TestCaptchaProviderUnreachable checks that clients cannot pass while the
// provider cannot be reached, and that the administrator is told.
func TestCaptchaProviderUnreachable(t *testing.T) {
	w := startWAF(t, wafOptions{
		env: []string{"HTTPS_PROXY=http://" + freeAddr(t), "https_proxy=", "NO_PROXY=", "no_proxy="},
		args: []string{
			"-bot-captcha", "turnstile",
			"-bot-captcha-site-key", "site-key-1",
			"-bot-captcha-secret-file", writeFile(t, "captcha-secret", "provider-secret"),
		},
	})
	c := w.client(t, map[string]string{"User-Agent": curlUA})
	if ch := parseChallenge(t, c.get("/")); !ch.captcha {
		t.Fatal("no CAPTCHA")
	}
	r := c.do("POST", "/.prismwaf/challenge", url.Values{"captcha": {"pass"}, "r": {"/"}})
	if r.StatusCode != http.StatusForbidden || r.cookie() != nil {
		t.Errorf("solution accepted: %d", r.StatusCode)
	}
	w.waitLog(t, `level=WARN msg="cannot verify CAPTCHA solutions" provider=turnstile error="CAPTCHA provider unavailable`)
}
