// Package notify sends notifications to administrators, such as a
// certificate that is about to expire, through a webhook or a command.
package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Severities of events.
const (
	SeverityInfo     = "info"
	SeverityWarning  = "warning"
	SeverityCritical = "critical"
)

// Event is a notification.
type Event struct {
	Time time.Time `json:"time"`
	// Event names what happened, e.g. "certificate_expiring".
	Event    string `json:"event"`
	Severity string `json:"severity"`
	// Host is the name of the machine PrismWAF runs on.
	Host string `json:"host"`
	// Message describes the event in a sentence for people.
	Message string `json:"message"`

	// Details of certificate events.
	Domain   string     `json:"domain,omitempty"`
	Issuer   string     `json:"issuer,omitempty"`
	Serial   string     `json:"serial,omitempty"`
	NotAfter *time.Time `json:"not_after,omitempty"`
	Error    string     `json:"error,omitempty"`
	Failures int        `json:"failures,omitempty"`
	RetryAt  *time.Time `json:"retry_at,omitempty"`

	// Held are the notifications of a digest (EventDigest).
	Held []Event `json:"held,omitempty"`
}

// EventDigest is the event of the notification that sends the
// notifications held back by Config.RateLimit.
const EventDigest = "notification_digest"

// digestLines is how many held notifications a digest's message lists.
const digestLines = 20

// Text returns the message with the host and severity, for chat services.
func (e Event) Text() string {
	return fmt.Sprintf("[PrismWAF %s] %s: %s", e.Host, strings.ToUpper(e.Severity), e.Message)
}

// Webhook payload formats.
const (
	// FormatJSON posts the Event as JSON, with the result of Text in an
	// additional "text" field.
	FormatJSON = "json"
	// FormatSlack posts {"text": "…"}, which Slack, Mattermost, Google
	// Chat and Rocket.Chat incoming webhooks accept.
	FormatSlack = "slack"
	// FormatDiscord posts {"content": "…"} for Discord webhooks.
	FormatDiscord = "discord"
)

// Timeouts and retries of a notification.
const (
	webhookTimeout = 10 * time.Second
	commandTimeout = 30 * time.Second
	// queueSize is how many notifications wait to be sent to a target
	// before new ones are dropped.
	queueSize = 100
)

// retryDelays are the waits before the second and third attempt.
var retryDelays = []time.Duration{10 * time.Second, time.Minute}

// Config configures a Notifier. At least one of WebhookURL and Command is
// required.
type Config struct {
	// WebhookURL receives each event as an HTTP POST.
	WebhookURL string
	// WebhookFormat is FormatJSON (the default), FormatSlack or
	// FormatDiscord.
	WebhookFormat string
	// Command is run with "sh -c" for each event, with the event as JSON
	// on standard input and its fields in PRISMWAF_* environment
	// variables.
	Command string
	// Logger is the operational log. Nil uses slog.Default().
	Logger *slog.Logger
	// HTTPClient sends webhooks. Nil uses a client with a 10 second
	// timeout.
	HTTPClient *http.Client
	// RateLimit is the most notifications queued by Notify per RateWindow.
	// The others are held back and sent together in one notification when
	// the window ends, so that many notifications at once, e.g. when the
	// certificates of all domains fail, do not flood the administrators.
	// Zero means no limit.
	RateLimit  int
	RateWindow time.Duration
}

// Notifier sends events. Notify queues them for Run, which sends them in
// the background and retries failures. Each target has its own queue, so
// that a target that fails or hangs does not delay the others.
type Notifier struct {
	cfg     Config
	logger  *slog.Logger
	client  *http.Client
	host    string
	targets []target
	queues  []chan Event                               // one per target
	sleep   func(context.Context, time.Duration) error // for tests
	now     func() time.Time                           // for tests

	mu          sync.Mutex
	windowStart time.Time // of the rate limit
	sent        int       // notifications queued in the window
	held        []Event   // held back by the rate limit
	wake        chan struct{}
}

// New returns a Notifier.
func New(cfg Config) (*Notifier, error) {
	if cfg.WebhookURL == "" && cfg.Command == "" {
		return nil, errors.New("notify: a webhook URL or a command is required")
	}
	if cfg.WebhookURL != "" {
		u, err := url.Parse(cfg.WebhookURL)
		if err != nil || (u.Scheme != "https" && u.Scheme != "http") || u.Host == "" {
			// Not quoted: webhook URLs often contain a secret token.
			return nil, errors.New("notify: invalid webhook URL: want an http:// or https:// URL")
		}
	}
	switch cfg.WebhookFormat {
	case "":
		cfg.WebhookFormat = FormatJSON
	case FormatJSON, FormatSlack, FormatDiscord:
	default:
		return nil, fmt.Errorf("notify: invalid webhook format %q: must be %q, %q or %q", cfg.WebhookFormat, FormatJSON, FormatSlack, FormatDiscord)
	}
	if cfg.RateLimit < 0 || cfg.RateLimit > 0 && cfg.RateWindow <= 0 {
		return nil, errors.New("notify: the rate limit requires a positive number of notifications and window")
	}
	n := &Notifier{
		cfg:    cfg,
		logger: cfg.Logger,
		client: cfg.HTTPClient,
		sleep:  sleep,
		now:    time.Now,
		wake:   make(chan struct{}, 1),
	}
	if n.logger == nil {
		n.logger = slog.Default()
	}
	if n.client == nil {
		n.client = &http.Client{Timeout: webhookTimeout}
	}
	n.host, _ = os.Hostname()
	if cfg.WebhookURL != "" {
		n.targets = append(n.targets, target{"webhook", n.postWebhook})
	}
	if cfg.Command != "" {
		n.targets = append(n.targets, target{"command", n.runCommand})
	}
	for range n.targets {
		n.queues = append(n.queues, make(chan Event, queueSize))
	}
	return n, nil
}

// Targets describes where notifications go, for the log. Webhook URLs
// often contain a secret token, so only their host is shown.
func (n *Notifier) Targets() []string {
	var t []string
	if n.cfg.WebhookURL != "" {
		t = append(t, "webhook "+redact(n.cfg.WebhookURL)+" ("+n.cfg.WebhookFormat+")")
	}
	if n.cfg.Command != "" {
		t = append(t, "command")
	}
	return t
}

// redact returns the scheme and host of a URL.
func redact(raw string) string {
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return "(invalid URL)"
	}
	return u.Scheme + "://" + u.Host + "/…"
}

// Notify queues an event to be sent by Run. Time and Host are filled in if
// empty. It never blocks: if too many events are waiting for a target, the
// event is dropped for that target and logged. Beyond Config.RateLimit,
// the event is held back for a digest.
func (n *Notifier) Notify(e Event) {
	n.fill(&e)
	if n.admit(e) {
		n.enqueue(e)
	}
}

// admit reports whether an event may be queued under the rate limit, and
// otherwise holds it back.
func (n *Notifier) admit(e Event) bool {
	if n.cfg.RateLimit == 0 {
		return true
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	now := n.now()
	// Events wait behind held ones, which the digest sends first.
	if len(n.held) == 0 {
		if now.Sub(n.windowStart) >= n.cfg.RateWindow {
			n.windowStart, n.sent = now, 0
		}
		if n.sent < n.cfg.RateLimit {
			n.sent++
			return true
		}
	}
	n.held = append(n.held, e)
	if len(n.held) == 1 {
		select {
		case n.wake <- struct{}{}:
		default: // already pending
		}
	}
	n.logger.Warn("notification held back: rate limit reached", "event", e.Event, "domain", e.Domain,
		"limit", n.cfg.RateLimit, "window", n.cfg.RateWindow, "send_at", n.windowStart.Add(n.cfg.RateWindow).UTC().Format(time.RFC3339))
	return false
}

// flush returns the held events as one event, starting a new window of the
// rate limit in which it counts.
func (n *Notifier) flush() (Event, bool) {
	n.mu.Lock()
	held := n.held
	n.held = nil
	if len(held) > 0 {
		n.windowStart, n.sent = n.now(), 1
	}
	n.mu.Unlock()
	switch len(held) {
	case 0:
		return Event{}, false
	case 1:
		return held[0], true
	}
	return n.digest(held), true
}

// digest returns an event that lists held events, with the highest
// severity among them.
func (n *Notifier) digest(held []Event) Event {
	e := Event{Event: EventDigest, Severity: SeverityInfo, Held: held}
	var b strings.Builder
	fmt.Fprintf(&b, "%d notifications were held back by the rate limit of %d per %s:", len(held), n.cfg.RateLimit, n.cfg.RateWindow)
	for i, h := range held {
		if severityRank(h.Severity) > severityRank(e.Severity) {
			e.Severity = h.Severity
		}
		if i < digestLines {
			fmt.Fprintf(&b, "\n- %s %s: %s", h.Time.UTC().Format(time.RFC3339), strings.ToUpper(h.Severity), h.Message)
		}
	}
	if len(held) > digestLines {
		fmt.Fprintf(&b, "\n- … and %d more; see the PrismWAF log", len(held)-digestLines)
	}
	e.Message = b.String()
	n.fill(&e)
	return e
}

func severityRank(s string) int {
	switch s {
	case SeverityCritical:
		return 2
	case SeverityWarning:
		return 1
	}
	return 0
}

// sendDigests queues the held events as a digest when each window of the
// rate limit ends, until ctx is canceled.
func (n *Notifier) sendDigests(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			n.dropHeld()
			return
		case <-n.wake:
		}
		n.mu.Lock()
		wait := n.windowStart.Add(n.cfg.RateWindow).Sub(n.now())
		n.mu.Unlock()
		if wait > 0 && n.sleep(ctx, wait) != nil {
			n.dropHeld()
			return
		}
		if e, ok := n.flush(); ok {
			n.enqueue(e)
		}
	}
}

// dropHeld logs the held events at shutdown, so that they are not lost.
func (n *Notifier) dropHeld() {
	n.mu.Lock()
	held := n.held
	n.held = nil
	n.mu.Unlock()
	for _, e := range held {
		n.logger.Error("notification not sent: shutting down", "event", e.Event, "domain", e.Domain, "message", e.Message)
	}
}

// enqueue queues an event for each target.
func (n *Notifier) enqueue(e Event) {
	for i, q := range n.queues {
		select {
		case q <- e:
		default:
			n.logger.Error("notification dropped: too many notifications waiting", "event", e.Event, "domain", e.Domain, "target", n.targets[i].name)
		}
	}
}

func (n *Notifier) fill(e *Event) {
	if e.Time.IsZero() {
		e.Time = n.now().UTC()
	}
	if e.Host == "" {
		e.Host = n.host
	}
}

// Run sends queued events until ctx is canceled, to each target in the
// order they were queued. Each event is tried up to three times per
// target. Events held back by the rate limit are sent as a digest when
// the window ends.
func (n *Notifier) Run(ctx context.Context) {
	var wg sync.WaitGroup
	if n.cfg.RateLimit > 0 {
		wg.Go(func() { n.sendDigests(ctx) })
	}
	for i, t := range n.targets {
		wg.Go(func() {
			for {
				select {
				case <-ctx.Done():
					return
				case e := <-n.queues[i]:
					n.deliver(ctx, t, e)
				}
			}
		})
	}
	wg.Wait()
}

// deliver sends an event to a target, with retries, and logs the outcome.
func (n *Notifier) deliver(ctx context.Context, t target, e Event) {
	var err error
	for attempt := 0; ; attempt++ {
		if err = t.send(ctx, e); err == nil {
			n.logger.Info("notification sent", "event", e.Event, "domain", e.Domain, "target", t.name)
			return
		}
		if attempt == len(retryDelays) || ctx.Err() != nil {
			break
		}
		n.logger.Warn("notification failed; retrying", "event", e.Event, "target", t.name, "error", err, "retry_in", retryDelays[attempt])
		if n.sleep(ctx, retryDelays[attempt]) != nil {
			break
		}
	}
	n.logger.Error("notification failed", "event", e.Event, "domain", e.Domain, "target", t.name, "error", err, "message", e.Message)
}

// Send sends an event to every target once, without retries, and returns
// the errors. It is meant for testing the configuration.
func (n *Notifier) Send(ctx context.Context, e Event) error {
	n.fill(&e)
	var errs []error
	for _, t := range n.targets {
		if err := t.send(ctx, e); err != nil {
			errs = append(errs, fmt.Errorf("%s: %w", t.name, err))
		}
	}
	return errors.Join(errs...)
}

type target struct {
	name string
	send func(context.Context, Event) error
}

func (n *Notifier) postWebhook(ctx context.Context, e Event) error {
	var payload any
	switch n.cfg.WebhookFormat {
	case FormatSlack:
		payload = map[string]string{"text": e.Text()}
	case FormatDiscord:
		payload = map[string]string{"content": e.Text()}
	default:
		payload = struct {
			Event
			Text string `json:"text"`
		}{e, e.Text()}
	}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, webhookTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, n.cfg.WebhookURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", "PrismWAF")
	resp, err := n.client.Do(req)
	if err != nil {
		// The error contains the URL, which may contain a token.
		var ue *url.Error
		if errors.As(err, &ue) {
			err = ue.Err
		}
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode/100 != 2 {
		msg, _ := io.ReadAll(io.LimitReader(resp.Body, 512))
		return fmt.Errorf("webhook returned %s: %s", resp.Status, strings.TrimSpace(string(msg)))
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 64<<10))
	return nil
}

func (n *Notifier) runCommand(ctx context.Context, e Event) error {
	body, err := json.Marshal(e)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, commandTimeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, "sh", "-c", n.cfg.Command)
	cmd.Stdin = bytes.NewReader(body)
	cmd.Env = append(os.Environ(), commandEnv(e)...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		if s := strings.TrimSpace(string(out)); s != "" {
			if len(s) > 512 {
				s = s[:512]
			}
			return fmt.Errorf("%w: %s", err, s)
		}
		return err
	}
	return nil
}

// commandEnv returns the environment variables that describe an event to
// a command.
func commandEnv(e Event) []string {
	env := []string{
		"PRISMWAF_EVENT=" + e.Event,
		"PRISMWAF_SEVERITY=" + e.Severity,
		"PRISMWAF_HOST=" + e.Host,
		"PRISMWAF_MESSAGE=" + e.Message,
		"PRISMWAF_TEXT=" + e.Text(),
		"PRISMWAF_TIME=" + e.Time.Format(time.RFC3339),
		"PRISMWAF_DOMAIN=" + e.Domain,
		"PRISMWAF_ERROR=" + e.Error,
	}
	if e.NotAfter != nil {
		env = append(env, "PRISMWAF_NOT_AFTER="+e.NotAfter.Format(time.RFC3339))
	}
	if e.Failures > 0 {
		env = append(env, "PRISMWAF_FAILURES="+strconv.Itoa(e.Failures))
	}
	if len(e.Held) > 0 {
		env = append(env, "PRISMWAF_HELD="+strconv.Itoa(len(e.Held)))
	}
	return env
}

func sleep(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
