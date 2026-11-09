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
	n.deliver(context.Background(), testEvent())
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
	n.deliver(context.Background(), testEvent())
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
	n.deliver(context.Background(), testEvent())
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
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
}
