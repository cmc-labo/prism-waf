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
}

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
	// queueSize is how many notifications wait to be sent before new ones
	// are dropped.
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
}

// Notifier sends events. Notify queues them for Run, which sends them in
// the background and retries failures.
type Notifier struct {
	cfg    Config
	logger *slog.Logger
	client *http.Client
	host   string
	queue  chan Event
	sleep  func(context.Context, time.Duration) error // for tests
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
	n := &Notifier{
		cfg:    cfg,
		logger: cfg.Logger,
		client: cfg.HTTPClient,
		queue:  make(chan Event, queueSize),
		sleep:  sleep,
	}
	if n.logger == nil {
		n.logger = slog.Default()
	}
	if n.client == nil {
		n.client = &http.Client{Timeout: webhookTimeout}
	}
	n.host, _ = os.Hostname()
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
// empty. It never blocks: if too many events are waiting, the event is
// dropped and logged.
func (n *Notifier) Notify(e Event) {
	n.fill(&e)
	select {
	case n.queue <- e:
	default:
		n.logger.Error("notification dropped: too many notifications waiting", "event", e.Event, "domain", e.Domain)
	}
}

func (n *Notifier) fill(e *Event) {
	if e.Time.IsZero() {
		e.Time = time.Now().UTC()
	}
	if e.Host == "" {
		e.Host = n.host
	}
}

// Run sends queued events until ctx is canceled. Each target is tried up
// to three times.
func (n *Notifier) Run(ctx context.Context) {
	for {
		select {
		case <-ctx.Done():
			return
		case e := <-n.queue:
			n.deliver(ctx, e)
		}
	}
}

// deliver sends an event to every target, with retries, and logs the
// outcome.
func (n *Notifier) deliver(ctx context.Context, e Event) {
	for _, t := range n.targets() {
		var err error
		for attempt := 0; ; attempt++ {
			if err = t.send(ctx, e); err == nil {
				n.logger.Info("notification sent", "event", e.Event, "domain", e.Domain, "target", t.name)
				break
			}
			if attempt == len(retryDelays) || ctx.Err() != nil {
				break
			}
			n.logger.Warn("notification failed; retrying", "event", e.Event, "target", t.name, "error", err, "retry_in", retryDelays[attempt])
			if n.sleep(ctx, retryDelays[attempt]) != nil {
				break
			}
		}
		if err != nil {
			n.logger.Error("notification failed", "event", e.Event, "domain", e.Domain, "target", t.name, "error", err, "message", e.Message)
		}
	}
}

// Send sends an event to every target once, without retries, and returns
// the errors. It is meant for testing the configuration.
func (n *Notifier) Send(ctx context.Context, e Event) error {
	n.fill(&e)
	var errs []error
	for _, t := range n.targets() {
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

func (n *Notifier) targets() []target {
	var t []target
	if n.cfg.WebhookURL != "" {
		t = append(t, target{"webhook", n.postWebhook})
	}
	if n.cfg.Command != "" {
		t = append(t, target{"command", n.runCommand})
	}
	return t
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
