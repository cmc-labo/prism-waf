package bot

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"
)

// siteverify is a fake siteverify API that answers with resp and records
// the forms it receives.
type siteverify struct {
	mu    sync.Mutex
	forms []url.Values
	resp  any
}

func (s *siteverify) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.forms = append(s.forms, r.PostForm)
	json.NewEncoder(w).Encode(s.resp)
}

// newCaptchaGuard returns a Guard with a CAPTCHA whose provider is a fake.
func newCaptchaGuard(t *testing.T, provider string, cfg Config) (*Guard, *siteverify, *bytes.Buffer) {
	t.Helper()
	sv := &siteverify{resp: map[string]any{"success": true, "hostname": "example.com"}}
	srv := httptest.NewServer(sv)
	t.Cleanup(srv.Close)
	var logs bytes.Buffer
	cfg.Captcha = &CaptchaConfig{Provider: provider, SiteKey: "site-key", Secret: "secret-key"}
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	g, _ := newTestGuard(t, cfg)
	g.captcha.p.verifyURL = srv.URL
	return g, sv, &logs
}

func postCaptcha(g *Guard, token string) *httptest.ResponseRecorder {
	form := url.Values{"captcha": {token}, "r": {"/page"}}
	r := httptest.NewRequest("POST", "https://example.com"+VerifyPath, strings.NewReader(form.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	r.Header.Set("User-Agent", "curl/8.5.0")
	w := httptest.NewRecorder()
	g.ServeVerify(w, r, "203.0.113.7", true)
	return w
}

func TestCaptchaVerify(t *testing.T) {
	g, sv, logs := newCaptchaGuard(t, CaptchaHCaptcha, Config{})

	w := postCaptcha(g, "token-1")
	if w.Code != http.StatusSeeOther || w.Header().Get("Location") != "/page" || len(w.Result().Cookies()) != 1 {
		t.Fatalf("solved: %d %v", w.Code, w.Header())
	}
	f := sv.forms[0]
	if f.Get("secret") != "secret-key" || f.Get("response") != "token-1" || f.Get("remoteip") != "203.0.113.7" || f.Get("sitekey") != "site-key" {
		t.Errorf("siteverify form: %v", f)
	}

	for _, tc := range []struct {
		name string
		resp any
		log  string
	}{
		{"not solved", map[string]any{"success": false, "error-codes": []string{"invalid-input-response"}}, ""},
		{"other site", map[string]any{"success": true, "hostname": "other.example"}, "not \\\"example.com\\\""},
		{"wrong secret", map[string]any{"success": false, "error-codes": []string{"invalid-input-secret"}}, "invalid-input-secret"},
		{"broken provider", "not json", "invalid response"},
	} {
		sv.resp = tc.resp
		logs.Reset()
		w := postCaptcha(g, "token-2")
		if w.Code != http.StatusForbidden || len(w.Result().Cookies()) != 0 || !strings.Contains(w.Body.String(), "could not be verified") {
			t.Errorf("%s: %d %v", tc.name, w.Code, w.Result().Cookies())
		}
		if got := logs.String(); (tc.log == "") != (got == "") || !strings.Contains(got, tc.log) {
			t.Errorf("%s: log %q, want %q", tc.name, got, tc.log)
		}
	}

	sv.resp = map[string]any{"success": true}
	if w := postCaptcha(g, ""); w.Code != http.StatusForbidden || len(sv.forms) != 5 {
		t.Errorf("empty token: %d, %d calls", w.Code, len(sv.forms))
	}
}

func TestCaptchaRecaptchaV3(t *testing.T) {
	g, sv, _ := newCaptchaGuard(t, CaptchaRecaptchaV3, Config{})
	g.captcha.minScore = 0.7
	for _, tc := range []struct {
		resp map[string]any
		ok   bool
	}{
		{map[string]any{"success": true, "action": recaptchaAction, "score": 0.9}, true},
		{map[string]any{"success": true, "action": recaptchaAction, "score": 0.5}, false},
		{map[string]any{"success": true, "action": "login", "score": 0.9}, false},
		{map[string]any{"success": true, "action": recaptchaAction}, false},
	} {
		sv.resp = tc.resp
		if w := postCaptcha(g, "t"); (w.Code == http.StatusSeeOther) != tc.ok {
			t.Errorf("%v: %d", tc.resp, w.Code)
		}
	}
	if _, ok := sv.forms[0]["sitekey"]; ok {
		t.Error("site key sent to reCAPTCHA")
	}
}

func TestCaptchaLevels(t *testing.T) {
	g, _, _ := newCaptchaGuard(t, CaptchaTurnstile, Config{CaptchaScore: 70})
	const ip = "203.0.113.7"
	curl := request("GET", "/", "")
	curl.Header.Set("User-Agent", "curl/8.5.0") // 60
	fake := request("GET", "/", "")
	fake.Header.Set("User-Agent", chromeUA) // 80

	if d := g.Check(curl, ip, false); d.Action != Challenge || d.Captcha {
		t.Errorf("score 60: %+v", d)
	}
	if d := g.Check(fake, ip, false); d.Action != Challenge || !d.Captcha {
		t.Errorf("score 80: %+v", d)
	}
	with := func(r *http.Request, c *http.Cookie) Decision {
		r = r.Clone(r.Context())
		r.AddCookie(c)
		return g.Check(r, ip, false)
	}
	// A proof of work clears score 60, not 80.
	pow := g.clearanceCookie(clientKey(ip), chromeUA, levelPoW, false)
	if d := with(fake, pow); d.Action != Challenge || !d.Captcha {
		t.Errorf("score 80 with proof of work: %+v", d)
	}
	// A CAPTCHA clears both.
	if d := with(fake, g.clearanceCookie(clientKey(ip), chromeUA, levelCaptcha, false)); d.Action != Allow || !d.Cleared {
		t.Errorf("score 80 with CAPTCHA: %+v", d)
	}
	if d := with(curl, g.clearanceCookie(clientKey(ip), "curl/8.5.0", levelCaptcha, false)); d.Action != Allow {
		t.Errorf("score 60 with CAPTCHA: %+v", d)
	}
	// The level is signed.
	forged := *pow
	forged.Value = strings.Replace(forged.Value, "."+levelPoW+".", "."+levelCaptcha+".", 1)
	if d := with(fake, &forged); d.Action != Challenge {
		t.Errorf("forged level: %+v", d)
	}
}

func TestCaptchaPage(t *testing.T) {
	for _, tc := range []struct {
		provider, widget, script, csp string
	}{
		{CaptchaTurnstile, `class="captcha cf-turnstile" data-sitekey="site-key"`, `"https://challenges.cloudflare.com/turnstile/v0/api.js"`, "frame-src https://challenges.cloudflare.com"},
		{CaptchaHCaptcha, `class="captcha h-captcha"`, `"https://js.hcaptcha.com/1/api.js"`, "connect-src https://hcaptcha.com"},
		{CaptchaRecaptcha, `class="captcha g-recaptcha"`, `"https://www.google.com/recaptcha/api.js"`, "https://www.gstatic.com/recaptcha/"},
		{CaptchaRecaptchaV3, `grecaptcha.execute("site-key"`, `"https://www.google.com/recaptcha/api.js?render=site-key"`, "connect-src https://www.google.com/recaptcha/"},
	} {
		g, _, _ := newCaptchaGuard(t, tc.provider, Config{})
		r := request("GET", "/page", "")
		r.Header.Set("User-Agent", "curl/8.5.0")
		d := g.Check(r, "203.0.113.7", false)
		w := httptest.NewRecorder()
		g.ServeChallenge(w, r, d)
		body, csp := w.Body.String(), w.Header().Get("Content-Security-Policy")
		if !d.Captcha || w.Code != http.StatusForbidden || !strings.Contains(body, tc.widget) || !strings.Contains(body, tc.script) ||
			!strings.Contains(body, `name="captcha"`) || strings.Contains(body, "worker") {
			t.Errorf("%s: page\n%s", tc.provider, body)
		}
		m := regexp.MustCompile(`'nonce-([^']+)'`).FindStringSubmatch(csp)
		if !strings.Contains(csp, tc.csp) || m == nil || !strings.Contains(body, `<script nonce="`+m[1]+`">`) {
			t.Errorf("%s: CSP %q", tc.provider, csp)
		}
	}
}

func TestNewCaptchaRejectsInvalidConfig(t *testing.T) {
	for _, cfg := range []Config{
		{Captcha: &CaptchaConfig{Provider: "friendlycaptcha", SiteKey: "k", Secret: "s"}},
		{Captcha: &CaptchaConfig{Provider: CaptchaTurnstile, Secret: "s"}},
		{Captcha: &CaptchaConfig{Provider: CaptchaTurnstile, SiteKey: "k"}},
		{Captcha: &CaptchaConfig{Provider: CaptchaTurnstile, SiteKey: `k"><script>`, Secret: "s"}},
		{Captcha: &CaptchaConfig{Provider: CaptchaRecaptchaV3, SiteKey: "k", Secret: "s", MinScore: 1.5}},
		{Captcha: &CaptchaConfig{Provider: CaptchaTurnstile, SiteKey: "k", Secret: "s"}, ChallengeScore: 50, CaptchaScore: 40},
		{CaptchaScore: 70},
		{AllowCategories: []string{"robots"}},
		{AllowCategories: []string{CategorySEO}, BlockCategories: []string{CategorySEO}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
}

func TestHostOnly(t *testing.T) {
	for in, want := range map[string]string{"example.com": "example.com", "example.com:8443": "example.com", "[::1]:443": "::1", "[::1]": "::1"} {
		if got := hostOnly(in); got != want {
			t.Errorf("hostOnly(%q) = %q", in, got)
		}
	}
}
