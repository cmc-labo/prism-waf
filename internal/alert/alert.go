// Package alert watches how often the rate limits are triggered and alerts
// administrators when it exceeds a threshold: many rejected requests in
// total, many clients over a limit, or one client over a limit again and
// again. Alerts are logged and, with a Notifier, sent through a webhook or
// a command.
package alert

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"slices"
	"strings"
	"sync"
	"time"

	"github.com/cmc-labo/prism-waf/internal/notify"
)

// Events of alerts.
const (
	EventRequests = "rate_limited_requests"
	EventClients  = "rate_limited_clients"
	EventClient   = "rate_limited_client"
	EventResolved = "rate_limit_alert_resolved"
)

// Metrics, in Event.Metric.
const (
	MetricRequests = "requests"
	MetricClients  = "clients"
	MetricClient   = "client"
)

// MaxClients is how many clients each window counts individually. Clients
// beyond it still count as rejected requests, but not as distinct clients
// or towards the threshold of a single client.
const MaxClients = 10000

// topN is how many clients and rules an alert lists.
const topN = 5

// tickInterval is how often Run ends windows.
const tickInterval = time.Second

// Threshold is a number of events per window. The zero value disables it.
type Threshold struct {
	Count  int
	Window time.Duration
}

func (t Threshold) enabled() bool { return t.Count > 0 }

func (t Threshold) String() string { return fmt.Sprintf("%d per %s", t.Count, t.Window) }

// Notifier receives alerts; *notify.Notifier implements it.
type Notifier interface {
	Notify(notify.Event)
}

// Config configures a Monitor. At least one threshold is required.
type Config struct {
	// Requests alerts when the rate limits reject this many requests of
	// all clients together in a window.
	Requests Threshold
	// Clients alerts when this many distinct clients are rejected in a
	// window.
	Clients Threshold
	// Client alerts when the requests of one client are rejected this many
	// times in a window.
	Client Threshold
	// Notifier, if set, receives the alerts and their resolution.
	Notifier Notifier
	// Logger is the operational log. Nil uses slog.Default().
	Logger *slog.Logger
}

// Monitor counts the requests that the rate limits reject. It is safe for
// concurrent use.
type Monitor struct {
	notifier Notifier
	logger   *slog.Logger
	now      func() time.Time

	mu       sync.Mutex
	requests meter
	clients  meter
	client   clientMeter
}

// tally counts the rejected requests of a window.
type tally struct {
	start    time.Time
	first    time.Time // of the first rejected request
	requests int
	clients  map[netip.Prefix]*clientTally
	rules    map[string]int
	overflow bool // more than MaxClients clients
}

type clientTally struct {
	first time.Time
	count int
	rules map[string]int
}

func newTally(start time.Time) tally {
	return tally{start: start, clients: map[netip.Prefix]*clientTally{}, rules: map[string]int{}}
}

func (t *tally) add(client netip.Prefix, rule string, now time.Time) *clientTally {
	if t.requests == 0 {
		t.first = now
	}
	t.requests++
	t.rules[rule]++
	c := t.clients[client]
	if c == nil {
		if len(t.clients) >= MaxClients {
			t.overflow = true
			return nil
		}
		c = &clientTally{first: now, rules: map[string]int{}}
		t.clients[client] = c
	}
	c.count++
	c.rules[rule]++
	return c
}

// meter alerts on a total of a window: requests or distinct clients.
type meter struct {
	threshold Threshold
	metric    string
	tally     tally
	// The ongoing alert, if firing.
	firing bool
	since  time.Time
	total  int // requests of the windows since
	peak   int // the most requests or clients in one window
}

func (m *meter) value() int {
	if m.metric == MetricClients {
		return len(m.tally.clients)
	}
	return m.tally.requests
}

// clientMeter alerts on single clients.
type clientMeter struct {
	threshold Threshold
	tally     tally
	firing    map[netip.Prefix]bool
}

// New returns a Monitor.
func New(cfg Config) (*Monitor, error) {
	for _, t := range []Threshold{cfg.Requests, cfg.Clients, cfg.Client} {
		if t.Count < 0 || t.enabled() && t.Window <= 0 {
			return nil, errors.New("alert: a threshold requires a positive count and window")
		}
	}
	if cfg.Clients.Count > MaxClients {
		return nil, fmt.Errorf("alert: the threshold of clients must not exceed %d", MaxClients)
	}
	if !cfg.Requests.enabled() && !cfg.Clients.enabled() && !cfg.Client.enabled() {
		return nil, errors.New("alert: at least one threshold is required")
	}
	m := &Monitor{notifier: cfg.Notifier, logger: cfg.Logger, now: time.Now}
	if m.logger == nil {
		m.logger = slog.Default()
	}
	now := m.now()
	m.requests = meter{threshold: cfg.Requests, metric: MetricRequests, tally: newTally(now)}
	m.clients = meter{threshold: cfg.Clients, metric: MetricClients, tally: newTally(now)}
	m.client = clientMeter{threshold: cfg.Client, tally: newTally(now), firing: map[netip.Prefix]bool{}}
	return m, nil
}

// RateLimited records a request that a rate limit rejected, or would have
// rejected in detect mode: client is the address or network the limit
// counts, rule the exceeded rule.
func (m *Monitor) RateLimited(client netip.Prefix, rule string) {
	var events []notify.Event
	m.mu.Lock()
	now := m.now()
	m.roll(now, &events)
	for _, mt := range []*meter{&m.requests, &m.clients} {
		if !mt.threshold.enabled() {
			continue
		}
		mt.tally.add(client, rule, now)
		if !mt.firing && mt.value() >= mt.threshold.Count {
			mt.firing, mt.since, mt.total, mt.peak = true, now, 0, 0
			events = append(events, mt.alert(now))
		}
	}
	if cm := &m.client; cm.threshold.enabled() {
		c := cm.tally.add(client, rule, now)
		if c != nil && c.count >= cm.threshold.Count && !cm.firing[client] {
			cm.firing[client] = true
			events = append(events, cm.alert(client, c, now))
		}
	}
	m.mu.Unlock()
	m.send(events)
}

// Run ends the windows of the thresholds as time passes, which resolves
// alerts, until ctx is canceled.
func (m *Monitor) Run(ctx context.Context) {
	t := time.NewTicker(tickInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			m.tick()
		}
	}
}

func (m *Monitor) tick() {
	var events []notify.Event
	m.mu.Lock()
	m.roll(m.now(), &events)
	m.mu.Unlock()
	m.send(events)
}

// roll ends the windows that are over. An alert is resolved by a whole
// window below its threshold.
func (m *Monitor) roll(now time.Time, events *[]notify.Event) {
	for _, mt := range []*meter{&m.requests, &m.clients} {
		if !mt.threshold.enabled() || now.Sub(mt.tally.start) < mt.threshold.Window {
			continue
		}
		v := mt.value()
		if mt.firing {
			mt.total += v
			mt.peak = max(mt.peak, v)
			if v < mt.threshold.Count {
				mt.firing = false
				*events = append(*events, mt.resolved(now))
			}
		}
		mt.tally = newTally(now)
	}
	if cm := &m.client; cm.threshold.enabled() && now.Sub(cm.tally.start) >= cm.threshold.Window {
		for client := range cm.firing {
			if c := cm.tally.clients[client]; c == nil || c.count < cm.threshold.Count {
				delete(cm.firing, client)
				m.logger.Info("rate limit alert resolved", "metric", MetricClient, "client", formatClient(client), "threshold", cm.threshold.String())
			}
		}
		cm.tally = newTally(now)
	}
}

func (m *Monitor) send(events []notify.Event) {
	for _, e := range events {
		args := []any{"event", e.Event, "metric", e.Metric}
		if e.Client != "" {
			args = append(args, "client", e.Client)
		}
		args = append(args, "count", e.Count, "threshold", e.Threshold, "window", e.Window)
		if e.Event == EventResolved {
			m.logger.Info("rate limit alert resolved", append(args, "message", e.Message)...)
		} else {
			m.logger.Warn("rate limit alert", append(args, "message", e.Message)...)
		}
		if m.notifier != nil {
			m.notifier.Notify(e)
		}
	}
}

func (mt *meter) alert(now time.Time) notify.Event {
	t := &mt.tally
	e := notify.Event{
		Time:       now.UTC(),
		Severity:   notify.SeverityWarning,
		Metric:     mt.metric,
		Count:      mt.value(),
		Threshold:  mt.threshold.Count,
		Window:     mt.threshold.Window.String(),
		TopClients: topClients(t.clients),
		TopRules:   top(t.rules),
	}
	elapsed := within(now.Sub(t.first))
	if mt.metric == MetricClients {
		e.Event = EventClients
		e.Message = fmt.Sprintf("%d clients were rate limited within %s (alert threshold: %s).", e.Count, elapsed, mt.threshold)
	} else {
		e.Event = EventRequests
		e.Message = fmt.Sprintf("Rate limits rejected %d requests within %s (alert threshold: %s).", e.Count, elapsed, mt.threshold)
	}
	e.Message += describe(e.TopClients, e.TopRules, t.overflow)
	return e
}

// resolved returns the resolution of an alert. Count is the total of
// rejected requests while it lasted, or the most clients of a window, as
// the same clients appear in several windows.
func (mt *meter) resolved(now time.Time) notify.Event {
	e := notify.Event{
		Time:      now.UTC(),
		Event:     EventResolved,
		Severity:  notify.SeverityInfo,
		Metric:    mt.metric,
		Threshold: mt.threshold.Count,
		Window:    mt.threshold.Window.String(),
	}
	after := now.Sub(mt.since).Round(time.Second)
	if mt.metric == MetricClients {
		e.Count = mt.peak
		e.Message = fmt.Sprintf("Rate-limited clients are below the alert threshold (%s) again after %s: at most %d clients per window.",
			mt.threshold, after, mt.peak)
	} else {
		e.Count = mt.total
		e.Message = fmt.Sprintf("Rate-limited requests are below the alert threshold (%s) again after %s: %d requests rejected in total, at most %d per window.",
			mt.threshold, after, mt.total, mt.peak)
	}
	return e
}

func (cm *clientMeter) alert(client netip.Prefix, c *clientTally, now time.Time) notify.Event {
	e := notify.Event{
		Time:      now.UTC(),
		Event:     EventClient,
		Severity:  notify.SeverityWarning,
		Metric:    MetricClient,
		Client:    formatClient(client),
		Count:     c.count,
		Threshold: cm.threshold.Count,
		Window:    cm.threshold.Window.String(),
		TopRules:  top(c.rules),
	}
	e.Message = fmt.Sprintf("Client %s was rate limited %d times within %s (alert threshold: %s).",
		e.Client, e.Count, within(now.Sub(c.first)), cm.threshold) + describe(nil, e.TopRules, false)
	return e
}

// within formats the time in which a threshold was reached.
func within(d time.Duration) string {
	if d < time.Second {
		return "less than a second"
	}
	return d.Round(time.Second).String()
}

// describe lists the top clients and rules for a message.
func describe(clients, rules []notify.Count, overflow bool) string {
	var b strings.Builder
	list := func(label string, cs []notify.Count) {
		if len(cs) == 0 {
			return
		}
		b.WriteString(" " + label + ": ")
		for i, c := range cs {
			if i > 0 {
				b.WriteString(", ")
			}
			fmt.Fprintf(&b, "%s (%d)", c.Name, c.Count)
		}
		b.WriteString(".")
	}
	list("Top clients", clients)
	if overflow {
		fmt.Fprintf(&b, " More than %d clients; only the first are counted individually.", MaxClients)
	}
	list("Rules", rules)
	return b.String()
}

func topClients(clients map[netip.Prefix]*clientTally) []notify.Count {
	m := make(map[string]int, len(clients))
	for k, c := range clients {
		m[formatClient(k)] = c.count
	}
	return top(m)
}

// top returns the topN largest counts, largest first.
func top(m map[string]int) []notify.Count {
	cs := make([]notify.Count, 0, len(m))
	for name, n := range m {
		cs = append(cs, notify.Count{Name: name, Count: n})
	}
	slices.SortFunc(cs, func(a, b notify.Count) int {
		return cmp.Or(cmp.Compare(b.Count, a.Count), strings.Compare(a.Name, b.Name))
	})
	return cs[:min(len(cs), topN)]
}

// formatClient returns an IPv4 address without its /32, and IPv6
// networks as they are.
func formatClient(p netip.Prefix) string {
	if p.IsSingleIP() {
		return p.Addr().String()
	}
	return p.String()
}
