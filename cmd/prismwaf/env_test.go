package main

import (
	"flag"
	"io"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
	"time"
)

// newFlagSet returns flags of each kind that applyEnv handles.
func newFlagSet(c *config) *flag.FlagSet {
	fs := flag.NewFlagSet("prismwaf", flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.StringVar(&c.listen, "listen", ":8080", "")
	fs.StringVar(&c.rateLimit, "rate-limit", "", "")
	fs.Var(&c.rateLimitPaths, "rate-limit-path", "")
	fs.Var(&c.backends, "backend", "")
	fs.IntVar(&c.maxConns, "max-conns", 0, "")
	fs.BoolVar(&c.botVerify, "bot-verify", true, "")
	fs.DurationVar(&c.banDuration, "ban-duration", 10*time.Minute, "")
	return fs
}

func TestApplyEnv(t *testing.T) {
	var c config
	fs := newFlagSet(&c)
	if err := fs.Parse([]string{"-listen", ":9000"}); err != nil {
		t.Fatal(err)
	}
	err := applyEnv(fs, []string{
		"HOME=/root",
		"PRISMWAF_LISTEN=:7000", // the command line takes precedence
		"PRISMWAF_RATE_LIMIT=300/1m",
		"PRISMWAF_RATE_LIMIT_PATH=POST /login=5/1m\n\n  /api/*=100/1m  \n",
		"PRISMWAF_BACKEND=http://127.0.0.1:3000,http://127.0.0.1:3001",
		"PRISMWAF_MAX_CONNS=100",
		"PRISMWAF_BOT_VERIFY=false",
		"PRISMWAF_BAN_DURATION=", // empty: ignored
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.listen != ":9000" || c.rateLimit != "300/1m" || c.maxConns != 100 || c.botVerify || c.banDuration != 10*time.Minute {
		t.Errorf("config %+v", c)
	}
	if want := []string{"POST /login=5/1m", "/api/*=100/1m"}; !slices.Equal(c.rateLimitPaths, want) {
		t.Errorf("rate limit paths %q, want %q", c.rateLimitPaths, want)
	}
	if want := []string{"http://127.0.0.1:3000", "http://127.0.0.1:3001"}; !slices.Equal(c.backendURLs(), want) {
		t.Errorf("backends %q, want %q", c.backendURLs(), want)
	}
	// Flags set from the environment count as given, so that options
	// that require others are checked.
	var set []string
	fs.Visit(func(f *flag.Flag) { set = append(set, f.Name) })
	slices.Sort(set)
	if want := []string{"backend", "bot-verify", "listen", "max-conns", "rate-limit", "rate-limit-path"}; !slices.Equal(set, want) {
		t.Errorf("set flags %q, want %q", set, want)
	}
}

func TestApplyEnvErrors(t *testing.T) {
	for _, tc := range []struct {
		env, want string
	}{
		{"PRISMWAF_RATE_LIMITS=300/1m", "unknown environment variable PRISMWAF_RATE_LIMITS"},
		{"PRISMWAF_MAX_CONNS=many", "invalid PRISMWAF_MAX_CONNS"},
		{"PRISMWAF_BOT_VERIFY=maybe", "invalid PRISMWAF_BOT_VERIFY"},
	} {
		var c config
		fs := newFlagSet(&c)
		fs.Parse(nil)
		if err := applyEnv(fs, []string{tc.env}); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: error %v, want %q", tc.env, err, tc.want)
		}
	}
}

func TestEnvName(t *testing.T) {
	if got := envName("bot-captcha-site-key"); got != "PRISMWAF_BOT_CAPTCHA_SITE_KEY" {
		t.Errorf("envName = %s", got)
	}
}

func TestProbes(t *testing.T) {
	p := &probes{}
	get := func(path string) (int, string) {
		rec := httptest.NewRecorder()
		p.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
		return rec.Code, rec.Body.String()
	}
	if code, body := get("/healthz"); code != 200 || body != "ok\n" {
		t.Errorf("/healthz: %d %q", code, body)
	}
	if code, _ := get("/readyz"); code != 503 {
		t.Errorf("/readyz before start: %d, want 503", code)
	}
	p.ready.Store(true)
	if code, body := get("/readyz"); code != 200 || body != "ready\n" {
		t.Errorf("/readyz: %d %q", code, body)
	}
	if code, _ := get("/"); code != 404 {
		t.Errorf("/: %d, want 404", code)
	}
}

func TestHealthcheck(t *testing.T) {
	p := &probes{}
	srv := httptest.NewServer(p)
	defer srv.Close()
	if code := healthcheck([]string{srv.URL + "/readyz"}); code != 1 {
		t.Errorf("not ready: exit status %d, want 1", code)
	}
	p.ready.Store(true)
	if code := healthcheck([]string{srv.URL + "/readyz"}); code != 0 {
		t.Errorf("ready: exit status %d, want 0", code)
	}
	srv.Close()
	if code := healthcheck([]string{srv.URL + "/readyz"}); code != 1 {
		t.Errorf("no connection: exit status %d, want 1", code)
	}
	if code := healthcheck([]string{"a", "b"}); code != 2 {
		t.Errorf("two arguments: exit status %d, want 2", code)
	}
}

func TestHealthcheckURL(t *testing.T) {
	for in, want := range map[string]string{
		":9191":          "http://127.0.0.1:9191/readyz",
		"0.0.0.0:9191":   "http://127.0.0.1:9191/readyz",
		"[::]:9191":      "http://127.0.0.1:9191/readyz",
		"10.1.2.3:9191":  "http://10.1.2.3:9191/readyz",
		"[::1]:9191":     "http://[::1]:9191/readyz",
		"localhost:9191": "http://localhost:9191/readyz",
		"":               defaultHealthcheckURL,
		"9191":           defaultHealthcheckURL,
	} {
		if got := healthcheckURL(in); got != want {
			t.Errorf("healthcheckURL(%q) = %s, want %s", in, got, want)
		}
	}
}
