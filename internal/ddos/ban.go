package ddos

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/cmc-labo/prism-waf/internal/audit"
	"github.com/cmc-labo/prism-waf/internal/ratelimit"
)

// BanConfig configures Bans.
type BanConfig struct {
	// A client that is rejected Limit times per Window, by any protection
	// that rejects requests, is banned for Duration. Limit and Window
	// work like a rate limit.
	Limit    int
	Window   time.Duration
	Duration time.Duration
	// Exempt clients are never banned.
	Exempt []netip.Prefix
	// MaxClients limits the clients tracked at once, like the rate
	// limits. Zero means ratelimit.DefaultMaxClients.
	MaxClients int
	// Logger is the operational log. Nil uses slog.Default().
	Logger *slog.Logger
}

// Bans counts the rejected requests of each client and bans clients that
// are rejected too often. It is safe for concurrent use.
type Bans struct {
	cfg     BanConfig
	strikes *ratelimit.Limiter
	now     func() time.Time // for tests

	mu     sync.Mutex
	banned map[netip.Prefix]*ban
	max    int
	// lastSweep is when expired bans were last removed.
	lastSweep time.Time
	full      throttle
	logger    *slog.Logger
}

type ban struct {
	until   time.Time
	eventID string
}

// NewBans returns Bans.
func NewBans(cfg BanConfig) (*Bans, error) {
	if cfg.Duration <= 0 {
		return nil, errors.New("ddos: the ban duration must be positive")
	}
	if cfg.MaxClients < 0 {
		return nil, errors.New("ddos: the maximum number of clients must not be negative")
	}
	if cfg.Logger == nil {
		cfg.Logger = slog.Default()
	}
	strikes, err := ratelimit.New(ratelimit.Config{
		Rules:      []ratelimit.Rule{{Limit: cfg.Limit, Window: cfg.Window}},
		Exempt:     cfg.Exempt,
		MaxClients: cfg.MaxClients,
		Logger:     cfg.Logger,
	})
	if err != nil {
		return nil, fmt.Errorf("ddos: %w", err)
	}
	b := &Bans{cfg: cfg, strikes: strikes, now: time.Now, banned: map[netip.Prefix]*ban{}, max: cfg.MaxClients, logger: cfg.Logger}
	if b.max == 0 {
		b.max = ratelimit.DefaultMaxClients
	}
	return b, nil
}

// Rule returns the ban rule, e.g. "100/1m for 10m".
func (b *Bans) Rule() string {
	return ratelimit.Rule{Limit: b.cfg.Limit, Window: b.cfg.Window}.String() + " for " + formatDuration(b.cfg.Duration)
}

func formatDuration(d time.Duration) string {
	// The window of a rule has the same format.
	s := ratelimit.Rule{Limit: 1, Window: d}.String()
	return s[len("1/"):]
}

// BanDecision describes the ban of a client.
type BanDecision struct {
	// Banned reports whether the client is banned.
	Banned bool
	// Client is the address or, for IPv6, the /64 network that is banned.
	Client netip.Prefix
	// RetryAfter is the time until the ban ends.
	RetryAfter time.Duration
	// EventID identifies the audit event of the ban, which the requests
	// rejected during the ban share.
	EventID string
	// First reports whether the ban starts with this decision, which
	// should be logged.
	First bool
}

// Check reports whether a client is banned.
func (b *Bans) Check(clientIP string) BanDecision {
	key, ok := clientKey(clientIP)
	if !ok {
		return BanDecision{}
	}
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	bn := b.banned[key]
	if bn == nil || !now.Before(bn.until) {
		return BanDecision{}
	}
	return BanDecision{Banned: true, Client: key, RetryAfter: bn.until.Sub(now), EventID: bn.eventID}
}

func (b *Bans) bannedKey(key netip.Prefix) bool {
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	bn := b.banned[key]
	return bn != nil && now.Before(bn.until)
}

// Strike counts a rejected request of a client, and bans the client if it
// has been rejected too often. The decision is First if the ban starts.
func (b *Bans) Strike(r *http.Request, clientIP string) BanDecision {
	key, ok := clientKey(clientIP)
	if !ok {
		return BanDecision{}
	}
	// Exempt clients are not counted.
	b.strikes.Count(r, clientIP)
	if b.strikes.Check(r, clientIP).Allowed {
		return BanDecision{}
	}
	now := b.now()
	b.mu.Lock()
	defer b.mu.Unlock()
	if bn := b.banned[key]; bn != nil && now.Before(bn.until) {
		// Requests that were in progress when the ban started.
		return BanDecision{Banned: true, Client: key, RetryAfter: bn.until.Sub(now), EventID: bn.eventID}
	}
	if now.Sub(b.lastSweep) >= time.Minute || len(b.banned) >= b.max {
		b.sweep(now)
	}
	if len(b.banned) >= b.max {
		// Keep the bans that exist: under a distributed attack, the new
		// clients are only rate limited.
		if ok, _ := b.full.allow(now); ok {
			b.logger.Warn("ban list is full; not banning more clients", "max", b.max,
				"hint", "raise -rate-limit-max-clients if this happens without an attack")
		}
		return BanDecision{}
	}
	bn := &ban{until: now.Add(b.cfg.Duration), eventID: audit.NewID()}
	b.banned[key] = bn
	return BanDecision{Banned: true, Client: key, RetryAfter: b.cfg.Duration, EventID: bn.eventID, First: true}
}

// sweep removes the bans that have ended.
func (b *Bans) sweep(now time.Time) {
	b.lastSweep = now
	for k, bn := range b.banned {
		if !now.Before(bn.until) {
			delete(b.banned, k)
		}
	}
}

// Len returns the number of banned clients, including expired bans that
// have not been removed yet.
func (b *Bans) Len() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return len(b.banned)
}
