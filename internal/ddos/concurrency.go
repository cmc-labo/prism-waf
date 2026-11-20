package ddos

import (
	"errors"
	"net/netip"
	"sync"
	"sync/atomic"

	"github.com/cmc-labo/prism-waf/internal/audit"
)

// ConcurrencyConfig configures Concurrency.
type ConcurrencyConfig struct {
	// Max limits the requests in progress; more are rejected, so that
	// PrismWAF and the backends keep answering the others in time.
	// Zero means no limit.
	Max int
	// MaxPerClient limits the requests in progress of each client. Zero
	// means no limit.
	MaxPerClient int
	// Exempt clients are not limited per client.
	Exempt []netip.Prefix
}

// Concurrency limits the requests in progress. It is safe for concurrent
// use.
type Concurrency struct {
	cfg    ConcurrencyConfig
	active atomic.Int64

	mu      sync.Mutex
	clients map[netip.Prefix]*clientRequests
}

type clientRequests struct {
	n int
	// eventID identifies the audit event of the current excess.
	eventID string
}

// NewConcurrency returns a Concurrency.
func NewConcurrency(cfg ConcurrencyConfig) (*Concurrency, error) {
	if cfg.Max < 0 || cfg.MaxPerClient < 0 {
		return nil, errors.New("ddos: concurrency limits must not be negative")
	}
	return &Concurrency{cfg: cfg, clients: map[netip.Prefix]*clientRequests{}}, nil
}

// Config returns the configuration.
func (c *Concurrency) Config() ConcurrencyConfig { return c.cfg }

// ConcurrencyDecision is the result of Acquire.
type ConcurrencyDecision struct {
	// Allowed is false if a limit is reached; then the other fields
	// describe it.
	Allowed bool
	// Overloaded reports whether the total limit is reached; otherwise
	// the limit of the client is.
	Overloaded bool
	// Client is the address or, for IPv6, the /64 network that reached
	// its limit.
	Client netip.Prefix
	// EventID identifies the audit event of the excess of a client, which
	// all its requests rejected until one is allowed again share.
	EventID string
	// First reports whether this is the first rejected request of the
	// excess of a client, which should be logged.
	First bool
}

// Acquire counts a request of a client as in progress if it is within the
// limits. Then release must be called when the request is done. The limit
// of the client is checked first, so that a client that overloads
// PrismWAF on its own is told apart.
func (c *Concurrency) Acquire(clientIP string) (release func(), d ConcurrencyDecision) {
	key, ok := clientKey(clientIP)
	perClient := c.cfg.MaxPerClient > 0 && ok && !contains(c.cfg.Exempt, clientIP)
	var cr *clientRequests
	if perClient {
		c.mu.Lock()
		cr = c.clients[key]
		if cr == nil {
			cr = &clientRequests{}
			c.clients[key] = cr
		}
		if cr.n >= c.cfg.MaxPerClient {
			d := ConcurrencyDecision{Client: key}
			if cr.eventID == "" {
				cr.eventID = audit.NewID()
				d.First = true
			}
			d.EventID = cr.eventID
			c.mu.Unlock()
			return nil, d
		}
		cr.n++
		c.mu.Unlock()
	}
	releaseClient := func() {
		if !perClient {
			return
		}
		c.mu.Lock()
		defer c.mu.Unlock()
		if cr.n--; cr.n == 0 {
			delete(c.clients, key)
		}
	}
	if n := c.active.Add(1); c.cfg.Max > 0 && n > int64(c.cfg.Max) {
		c.active.Add(-1)
		releaseClient()
		return nil, ConcurrencyDecision{Overloaded: true}
	}
	if perClient {
		// The excess is over.
		c.mu.Lock()
		cr.eventID = ""
		c.mu.Unlock()
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			c.active.Add(-1)
			releaseClient()
		})
	}, ConcurrencyDecision{Allowed: true}
}

// Active returns the number of requests in progress.
func (c *Concurrency) Active() int { return int(c.active.Load()) }
