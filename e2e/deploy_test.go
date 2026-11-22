//go:build e2e

package e2e

import (
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os/exec"
	"strings"
	"testing"
	"time"
)

// Options from environment variables, as containers are configured.
func TestEnvironmentConfig(t *testing.T) {
	w := startWAF(t, wafOptions{
		env: []string{
			"PRISMWAF_ENGINE=both",
			"PRISMWAF_RATE_LIMIT_PATH=POST /login=2/1m\n/api/*=100/1m",
			"PRISMWAF_MODE=detect", // the command line takes precedence
		},
		args: []string{"-mode", "block"},
	})
	c := w.client(t, browserHeaders)
	if r := c.get("/search?q=shoes"); r.StatusCode != 200 {
		t.Errorf("normal request: %d", r.StatusCode)
	}
	if r := c.get("/search?q=" + url.QueryEscape("1' OR '1'='1")); r.StatusCode != 403 {
		t.Errorf("SQL injection: %d, want 403 (-mode block from the command line)", r.StatusCode)
	}
	var codes []int
	for range 3 {
		codes = append(codes, c.do("POST", "/login", url.Values{"user": {"alice"}}).StatusCode)
	}
	if codes[0] != 200 || codes[1] != 200 || codes[2] != 429 {
		t.Errorf("logins: %v, want 200 200 429", codes)
	}
	w.waitLog(t, "prismwaf started", "engine=both")
	w.waitLog(t, "rate limiting enabled", `rules="[POST /login=2/1m /api/*=100/1m]"`)
}

func TestEnvironmentErrors(t *testing.T) {
	for _, tc := range []struct {
		env  string
		want string
	}{
		{"PRISMWAF_RATE_LIMITS=300/1m", "unknown environment variable PRISMWAF_RATE_LIMITS"},
		{"PRISMWAF_MAX_CONNS=many", "invalid PRISMWAF_MAX_CONNS"},
		// Set from the environment, an option still requires the others.
		{"PRISMWAF_BAN_DURATION=1m", "-ban-duration requires -ban"},
	} {
		out, err := runWAFEnv(t, []string{tc.env})
		var exit *exec.ExitError
		if !errors.As(err, &exit) || !strings.Contains(out, tc.want) {
			t.Errorf("%s: %v\n%s\nwant %q", tc.env, err, out, tc.want)
		}
	}
}

// The probes on their own port, including during a graceful shutdown.
func TestProbes(t *testing.T) {
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			<-release
		}
		io.WriteString(w, "backend")
	}))
	t.Cleanup(backend.Close)
	t.Cleanup(func() {
		select {
		case <-release:
		default:
			close(release)
		}
	})
	probeAddr := freeAddr(t)
	w := startWAF(t, wafOptions{backend: backend.URL, env: []string{"PRISMWAF_PROBE_LISTEN=" + probeAddr}})

	probe := func(path string) (int, string) {
		res, err := http.Get("http://" + probeAddr + path)
		if err != nil {
			return 0, err.Error()
		}
		defer res.Body.Close()
		b, _ := io.ReadAll(res.Body)
		return res.StatusCode, string(b)
	}
	waitProbe := func(path string, code int) {
		t.Helper()
		deadline := time.Now().Add(5 * time.Second)
		for {
			got, body := probe(path)
			if got == code {
				return
			}
			if time.Now().After(deadline) {
				t.Fatalf("%s: %d %s, want %d", path, got, body, code)
			}
			time.Sleep(20 * time.Millisecond)
		}
	}
	waitProbe("/readyz", 200)
	if code, body := probe("/healthz"); code != 200 || body != "ok\n" {
		t.Errorf("/healthz: %d %q", code, body)
	}
	// The probes do not reach the backend, and the WAF does not serve them.
	if code, _ := probe("/"); code != 404 {
		t.Errorf("/ on the probe port: %d, want 404", code)
	}
	if r := w.client(t, browserHeaders).get("/healthz"); r.body != "backend" {
		t.Errorf("/healthz on the WAF port: %d %q, want it forwarded", r.StatusCode, r.body)
	}

	// A request in progress when PrismWAF is told to stop.
	slow := make(chan response, 1)
	go func() {
		c := &http.Client{Timeout: 10 * time.Second}
		res, err := c.Get(w.URL + "/slow")
		if err != nil {
			slow <- response{body: err.Error()}
			return
		}
		b, _ := io.ReadAll(res.Body)
		res.Body.Close()
		slow <- response{res, string(b)}
	}()
	time.Sleep(200 * time.Millisecond)
	stopped := make(chan struct{})
	go func() { w.stop(); close(stopped) }()

	waitProbe("/readyz", 503)
	if code, _ := probe("/healthz"); code != 200 {
		t.Errorf("/healthz while shutting down: %d, want 200", code)
	}
	close(release)
	if r := <-slow; r.Response == nil || r.StatusCode != 200 || r.body != "backend" {
		t.Errorf("request in progress during the shutdown: %+v", r)
	}
	<-stopped
	if code, _ := probe("/healthz"); code != 0 {
		t.Errorf("/healthz after exit: %d, want no connection", code)
	}
}
