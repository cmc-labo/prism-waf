package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func testEvent() Event {
	notAfter := time.Date(2026, 11, 20, 0, 0, 0, 0, time.UTC)
	return Event{
		Time:     time.Date(2026, 11, 9, 3, 0, 0, 0, time.UTC),
		Event:    "certificate_expiring",
		Severity: SeverityWarning,
		Host:     "waf1",
		Message:  "The certificate for example.com expires in 10 days.",
		Domain:   "example.com",
		NotAfter: &notAfter,
	}
}

// webhook records the requests it receives and answers with the given
// statuses, then 200.
type webhook struct {
	mu       sync.Mutex
	bodies   [][]byte
	statuses []int
}

func (h *webhook) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	h.mu.Lock()
	defer h.mu.Unlock()
	if r.Method != http.MethodPost || r.Header.Get("Content-Type") != "application/json" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}
	h.bodies = append(h.bodies, body)
	if len(h.statuses) > 0 {
		w.WriteHeader(h.statuses[0])
		io.WriteString(w, "invalid_token")
		h.statuses = h.statuses[1:]
	}
}

func (h *webhook) received() [][]byte {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.bodies
}

func newTestNotifier(t *testing.T, cfg Config) (*Notifier, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	cfg.Logger = slog.New(slog.NewTextHandler(&logs, nil))
	n, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	n.sleep = func(context.Context, time.Duration) error { return nil }
	return n, &logs
}

func TestWebhookFormats(t *testing.T) {
	text := "[PrismWAF waf1] WARNING: The certificate for example.com expires in 10 days."
	for _, tc := range []struct {
		format string
		check  func(map[string]any) bool
	}{
		{"", func(m map[string]any) bool {
			return m["text"] == text && m["event"] == "certificate_expiring" && m["severity"] == "warning" &&
				m["domain"] == "example.com" && m["not_after"] == "2026-11-20T00:00:00Z" && m["host"] == "waf1" &&
				m["time"] == "2026-11-09T03:00:00Z" && m["error"] == nil
		}},
		{FormatSlack, func(m map[string]any) bool { return len(m) == 1 && m["text"] == text }},
		{FormatDiscord, func(m map[string]any) bool { return len(m) == 1 && m["content"] == text }},
	} {
		h := &webhook{}
		srv := httptest.NewServer(h)
		n, _ := newTestNotifier(t, Config{WebhookURL: srv.URL, WebhookFormat: tc.format})
		if err := n.Send(context.Background(), testEvent()); err != nil {
			t.Errorf("format %q: %v", tc.format, err)
		}
		var m map[string]any
		if b := h.received(); len(b) != 1 || json.Unmarshal(b[0], &m) != nil || !tc.check(m) {
			t.Errorf("format %q: payload %s", tc.format, b)
		}
		srv.Close()
	}
}

func TestWebhookRetries(t *testing.T) {
	h := &webhook{statuses: []int{http.StatusBadGateway, http.StatusServiceUnavailable}}
	srv := httptest.NewServer(h)
	defer srv.Close()
	n, logs := newTestNotifier(t, Config{WebhookURL: srv.URL})
	n.deliver(context.Background(), n.targets[0], testEvent())
	if len(h.received()) != 3 {
		t.Errorf("%d attempts, want 3", len(h.received()))
	}
	if strings.Count(logs.String(), "notification failed; retrying") != 2 || !strings.Contains(logs.String(), "notification sent") {
		t.Errorf("log:\n%s", logs)
	}

	// After three failures, the notification is logged as failed with its
	// message, so it is not lost.
	h.statuses = []int{401, 401, 401}
	logs.Reset()
	n.deliver(context.Background(), n.targets[0], testEvent())
	if !strings.Contains(logs.String(), `level=ERROR msg="notification failed"`) ||
		!strings.Contains(logs.String(), "401 Unauthorized: invalid_token") ||
		!strings.Contains(logs.String(), "expires in 10 days") {
		t.Errorf("log:\n%s", logs)
	}
}

func TestWebhookErrorsHideTheURL(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	url := srv.URL + "/hooks/secret-token"
	srv.Close() // connection refused
	n, logs := newTestNotifier(t, Config{WebhookURL: url})
	err := n.Send(context.Background(), testEvent())
	if err == nil || strings.Contains(err.Error(), "secret-token") {
		t.Errorf("Send = %v", err)
	}
	n.deliver(context.Background(), n.targets[0], testEvent())
	if strings.Contains(logs.String(), "secret-token") {
		t.Errorf("log contains the URL:\n%s", logs)
	}
	if got := strings.Join(n.Targets(), ","); strings.Contains(got, "secret-token") || !strings.Contains(got, "webhook http://127.0.0.1:") {
		t.Errorf("Targets = %q", got)
	}
}

func TestCommand(t *testing.T) {
	dir := t.TempDir()
	out := filepath.Join(dir, "out")
	n, _ := newTestNotifier(t, Config{
		Command: `{ printf '%s|%s|%s|%s|%s\n' "$PRISMWAF_EVENT" "$PRISMWAF_SEVERITY" "$PRISMWAF_DOMAIN" "$PRISMWAF_NOT_AFTER" "$PRISMWAF_TEXT"; cat; } > ` + out,
	})
	if err := n.Send(context.Background(), testEvent()); err != nil {
		t.Fatal(err)
	}
	b, err := os.ReadFile(out)
	if err != nil {
		t.Fatal(err)
	}
	env, stdin, _ := strings.Cut(string(b), "\n")
	if env != "certificate_expiring|warning|example.com|2026-11-20T00:00:00Z|[PrismWAF waf1] WARNING: The certificate for example.com expires in 10 days." {
		t.Errorf("environment: %q", env)
	}
	var e Event
	if err := json.Unmarshal([]byte(stdin), &e); err != nil || e.Domain != "example.com" || e.Event != "certificate_expiring" {
		t.Errorf("stdin: %q, %v", stdin, err)
	}

	n, _ = newTestNotifier(t, Config{Command: "echo no mail server >&2; exit 3"})
	if err := n.Send(context.Background(), testEvent()); err == nil || !strings.Contains(err.Error(), "exit status 3: no mail server") {
		t.Errorf("failing command: %v", err)
	}
}

func TestBothTargets(t *testing.T) {
	h := &webhook{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	n, _ := newTestNotifier(t, Config{WebhookURL: srv.URL, Command: "exit 1"})
	err := n.Send(context.Background(), testEvent())
	if err == nil || !strings.HasPrefix(err.Error(), "command: ") || len(h.received()) != 1 {
		t.Errorf("Send = %v, webhook got %d", err, len(h.received()))
	}
}

func TestRun(t *testing.T) {
	h := &webhook{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	n, _ := newTestNotifier(t, Config{WebhookURL: srv.URL})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { n.Run(ctx); close(done) }()
	e := testEvent()
	e.Time, e.Host = time.Time{}, ""
	n.Notify(e)
	n.Notify(e)
	deadline := time.Now().Add(5 * time.Second)
	for len(h.received()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
	var got Event
	if b := h.received(); len(b) != 2 || json.Unmarshal(b[0], &got) != nil || got.Time.IsZero() || got.Host == "" {
		t.Errorf("received %s", b)
	}
}

// TestRunTargetsAreIndependent checks that a webhook that does not answer
// does not delay the command.
func TestRunTargetsAreIndependent(t *testing.T) {
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)
	out := filepath.Join(t.TempDir(), "out")
	n, _ := newTestNotifier(t, Config{WebhookURL: srv.URL, Command: "echo $PRISMWAF_DOMAIN >> " + out})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { n.Run(ctx); close(done) }()
	for _, d := range []string{"a.example", "b.example"} {
		e := testEvent()
		e.Domain = d
		n.Notify(e)
	}
	deadline := time.Now().Add(5 * time.Second)
	for b, _ := os.ReadFile(out); string(b) != "a.example\nb.example\n"; b, _ = os.ReadFile(out) {
		if time.Now().After(deadline) {
			t.Fatalf("command output %q while the webhook hangs", b)
		}
		time.Sleep(10 * time.Millisecond)
	}
	cancel()
	<-done
}

func TestNotifyDropsWhenFull(t *testing.T) {
	n, logs := newTestNotifier(t, Config{Command: "true"})
	for range queueSize + 1 {
		n.Notify(testEvent())
	}
	if strings.Count(logs.String(), "notification dropped") != 1 {
		t.Errorf("log:\n%s", logs)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	for _, cfg := range []Config{
		{},
		{WebhookURL: "hooks.slack.com/services/x"},
		{WebhookURL: "ftp://example.com/hook"},
		{WebhookURL: "https://example.com/hook", WebhookFormat: "teams"},
		{Command: "true", RateLimit: 10},
		{Command: "true", RateLimit: -1, RateWindow: time.Hour},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
}

// eventFor returns a test event for a domain with a severity.
func eventFor(domain, severity string) Event {
	e := testEvent()
	e.Domain, e.Severity = domain, severity
	e.Message = "The certificate for " + domain + " has a problem."
	return e
}

// queued returns the domains of the events queued for the first target.
func queued(n *Notifier) []string {
	var out []string
	for {
		select {
		case e := <-n.queues[0]:
			if e.Event == EventDigest {
				out = append(out, "digest")
			} else {
				out = append(out, e.Domain)
			}
		default:
			return out
		}
	}
}

func TestRateLimit(t *testing.T) {
	n, logs := newTestNotifier(t, Config{Command: "true", RateLimit: 2, RateWindow: time.Hour})
	now := time.Date(2026, 11, 9, 3, 0, 0, 0, time.UTC)
	n.now = func() time.Time { return now }

	n.Notify(eventFor("a.example", SeverityWarning))
	n.Notify(eventFor("b.example", SeverityWarning))
	n.Notify(eventFor("c.example", SeverityInfo))
	n.Notify(eventFor("d.example", SeverityCritical))
	n.Notify(eventFor("e.example", SeverityWarning))
	if got := strings.Join(queued(n), ","); got != "a.example,b.example" {
		t.Errorf("queued %s, want the first two", got)
	}
	if c := strings.Count(logs.String(), "notification held back: rate limit reached"); c != 3 ||
		!strings.Contains(logs.String(), "send_at=2026-11-09T04:00:00Z") {
		t.Errorf("log:\n%s", logs)
	}

	// The window has not ended yet: later events wait behind the held ones,
	// even when the window ends before the digest is sent.
	now = now.Add(time.Hour)
	n.Notify(eventFor("f.example", SeverityInfo))
	if got := queued(n); got != nil {
		t.Errorf("queued %v before the digest", got)
	}
	e, ok := n.flush()
	if !ok || e.Event != EventDigest || e.Severity != SeverityCritical || len(e.Held) != 4 || !e.Time.Equal(now) || e.Host == "" {
		t.Fatalf("digest %+v", e)
	}
	want := "4 notifications were held back by the rate limit of 2 per 1h0m0s:\n" +
		"- 2026-11-09T03:00:00Z INFO: The certificate for c.example has a problem.\n" +
		"- 2026-11-09T03:00:00Z CRITICAL: The certificate for d.example has a problem.\n" +
		"- 2026-11-09T03:00:00Z WARNING: The certificate for e.example has a problem.\n" +
		"- 2026-11-09T03:00:00Z INFO: The certificate for f.example has a problem."
	if e.Message != want {
		t.Errorf("message:\n%s\nwant:\n%s", e.Message, want)
	}
	if env := strings.Join(commandEnv(e), "\n"); !strings.Contains(env, "PRISMWAF_HELD=4") {
		t.Errorf("environment:\n%s", env)
	}
	if _, ok := n.flush(); ok {
		t.Error("second flush returned events")
	}

	// The digest counts in the new window.
	n.Notify(eventFor("g.example", SeverityInfo))
	n.Notify(eventFor("h.example", SeverityInfo))
	if got := strings.Join(queued(n), ","); got != "g.example" {
		t.Errorf("queued %s in the new window", got)
	}
	// A single held event is sent as it is.
	now = now.Add(time.Hour)
	if e, ok := n.flush(); !ok || e.Domain != "h.example" || e.Held != nil {
		t.Errorf("flush = %+v", e)
	}
}

func TestDigestIsShortened(t *testing.T) {
	n, _ := newTestNotifier(t, Config{Command: "true", RateLimit: 1, RateWindow: time.Minute})
	var held []Event
	for range digestLines + 5 {
		held = append(held, testEvent())
	}
	e := n.digest(held)
	if lines := strings.Split(e.Message, "\n"); len(lines) != digestLines+2 || lines[len(lines)-1] != "- … and 5 more; see the PrismWAF log" {
		t.Errorf("message:\n%s", e.Message)
	}
	if len(e.Held) != digestLines+5 {
		t.Errorf("%d held events, want all", len(e.Held))
	}
}

func TestRunSendsDigests(t *testing.T) {
	h := &webhook{}
	srv := httptest.NewServer(h)
	defer srv.Close()
	n, logs := newTestNotifier(t, Config{WebhookURL: srv.URL, RateLimit: 1, RateWindow: time.Hour})
	var mu sync.Mutex
	now := time.Date(2026, 11, 9, 3, 0, 0, 0, time.UTC)
	n.now = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	slept := make(chan time.Duration, 1)
	release := make(chan struct{}) // ends the window
	digests := 0
	n.sleep = func(ctx context.Context, d time.Duration) error {
		if d < time.Hour-time.Minute { // a retry
			return nil
		}
		if digests++; digests > 1 { // the second digest waits for the shutdown
			<-ctx.Done()
			return ctx.Err()
		}
		slept <- d
		<-release
		mu.Lock()
		now = now.Add(d)
		mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { n.Run(ctx); close(done) }()
	for _, d := range []string{"a.example", "b.example", "c.example"} {
		n.Notify(eventFor(d, SeverityWarning))
	}
	select {
	case d := <-slept:
		if d != time.Hour {
			t.Errorf("waited %v for the digest, want the rest of the window", d)
		}
	case <-time.After(5 * time.Second):
		cancel()
		t.Fatal("no digest is waiting for the end of the window")
	}
	close(release)
	deadline := time.Now().Add(5 * time.Second)
	for len(h.received()) < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	var first, digest Event
	if b := h.received(); len(b) != 2 || json.Unmarshal(b[0], &first) != nil || json.Unmarshal(b[1], &digest) != nil ||
		first.Domain != "a.example" || digest.Event != EventDigest || len(digest.Held) != 2 || digest.Held[1].Domain != "c.example" {
		t.Errorf("received %s", b)
	}

	// The digest counts in the new window, so these are held. Events held
	// at shutdown are logged.
	n.Notify(eventFor("d.example", SeverityWarning))
	n.Notify(eventFor("e.example", SeverityWarning))
	cancel()
	<-done
	if !strings.Contains(logs.String(), `msg="notification not sent: shutting down" event=certificate_expiring domain=d.example`) ||
		!strings.Contains(logs.String(), `msg="notification not sent: shutting down" event=certificate_expiring domain=e.example`) {
		t.Errorf("log:\n%s", logs)
	}
}

func TestCommandEnvOfAlerts(t *testing.T) {
	env := strings.Join(commandEnv(Event{Event: "rate_limited_client", Metric: "client", Client: "203.0.113.7", Count: 300, Threshold: 300, Window: "5m0s"}), "\n")
	for _, want := range []string{"PRISMWAF_METRIC=client", "PRISMWAF_CLIENT=203.0.113.7", "PRISMWAF_COUNT=300", "PRISMWAF_THRESHOLD=300", "PRISMWAF_WINDOW=5m0s"} {
		if !strings.Contains(env, want+"\n") && !strings.HasSuffix(env, want) {
			t.Errorf("no %s in\n%s", want, env)
		}
	}
	// Certificate events have none of them.
	if env := strings.Join(commandEnv(testEvent()), "\n"); strings.Contains(env, "PRISMWAF_COUNT") || strings.Contains(env, "PRISMWAF_METRIC") {
		t.Errorf("certificate event:\n%s", env)
	}
}
