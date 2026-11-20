package ddos

import (
	"errors"
	"log/slog"
	"net"
	"net/netip"
	"os"
	"sync"
	"sync/atomic"
	"time"
)

// prefaceLength is the length of the HTTP/2 client preface, which net/http
// reads without a deadline from connections without TLS when it accepts
// HTTP/2 without TLS (h2c), before ReadHeaderTimeout applies.
const prefaceLength = 24

// ListenerConfig configures Listener.
type ListenerConfig struct {
	// FirstByteTimeout is how long a new connection may take to send the
	// beginning of its first request: until the server sets a deadline of
	// its own, such as the TLS handshake timeout or ReadHeaderTimeout, or
	// for 24 bytes. Zero disables it.
	FirstByteTimeout time.Duration
	// MaxConns limits the open connections; more are closed as soon as
	// they are accepted. Zero means no limit.
	MaxConns int
	// MaxConnsPerClient limits the open connections of each client
	// address. Zero means no limit.
	MaxConnsPerClient int
	// Exempt addresses are not limited per client and not checked for
	// bans, e.g. trusted proxies, whose connections carry many clients.
	Exempt []netip.Prefix
	// Bans, if set, closes connections from banned clients.
	Bans *Bans
	// Logger is the operational log. Nil uses slog.Default().
	Logger *slog.Logger
}

// Listener wraps a net.Listener with connection limits.
type Listener struct {
	net.Listener
	cfg    ListenerConfig
	logger *slog.Logger
	open   atomic.Int64

	mu      sync.Mutex
	clients map[netip.Prefix]int

	rejected throttle
}

// NewListener returns a Listener that accepts the connections of ln.
func NewListener(ln net.Listener, cfg ListenerConfig) *Listener {
	l := &Listener{Listener: ln, cfg: cfg, logger: cfg.Logger, clients: map[netip.Prefix]int{}}
	if l.logger == nil {
		l.logger = slog.Default()
	}
	return l
}

// Accept returns the next connection that is within the limits, closing
// the others.
func (l *Listener) Accept() (net.Conn, error) {
	for {
		c, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		conn, reason := l.admit(c)
		if conn != nil {
			return conn, nil
		}
		c.Close()
		if ok, n := l.rejected.allow(time.Now()); ok {
			l.logger.Warn("closing connections over the limits", "reason", reason, "client", c.RemoteAddr().String(),
				"closed_last_minute", n, "open", l.open.Load())
		}
	}
}

func (l *Listener) admit(c net.Conn) (net.Conn, string) {
	var key netip.Prefix
	limited := false
	if ap, err := netip.ParseAddrPort(c.RemoteAddr().String()); err == nil && !containsAddr(l.cfg.Exempt, ap.Addr()) {
		key = addrKey(ap.Addr())
		limited = true
		if l.cfg.Bans != nil && l.cfg.Bans.bannedKey(key) {
			return nil, "banned"
		}
	}
	if n := l.open.Add(1); l.cfg.MaxConns > 0 && n > int64(l.cfg.MaxConns) {
		l.open.Add(-1)
		return nil, "max_conns"
	}
	if limited && l.cfg.MaxConnsPerClient > 0 {
		l.mu.Lock()
		if l.clients[key] >= l.cfg.MaxConnsPerClient {
			l.mu.Unlock()
			l.open.Add(-1)
			return nil, "max_conns_per_client"
		}
		l.clients[key]++
		l.mu.Unlock()
	} else {
		limited = false
	}
	lc := &conn{Conn: c, l: l, key: key, counted: limited}
	if d := l.cfg.FirstByteTimeout; d > 0 {
		lc.armed.Store(true)
		c.SetReadDeadline(time.Now().Add(d))
	}
	return lc, ""
}

// Open returns the number of open connections.
func (l *Listener) Open() int { return int(l.open.Load()) }

func (l *Listener) release(c *conn) {
	l.open.Add(-1)
	if !c.counted {
		return
	}
	l.mu.Lock()
	if l.clients[c.key]--; l.clients[c.key] <= 0 {
		delete(l.clients, c.key)
	}
	l.mu.Unlock()
}

// conn is an accepted connection. Until the server sets a read deadline of
// its own or the connection has sent prefaceLength bytes, the deadline of
// FirstByteTimeout applies.
type conn struct {
	net.Conn
	l       *Listener
	key     netip.Prefix
	counted bool
	armed   atomic.Bool
	read    atomic.Int64
	// expired is set when FirstByteTimeout has passed: net/http sets a
	// deadline of its own after the h2c check failed, which must not give
	// the client more time.
	expired atomic.Bool
	closed  sync.Once
}

func (c *conn) Read(b []byte) (int, error) {
	if c.expired.Load() {
		return 0, os.ErrDeadlineExceeded
	}
	n, err := c.Conn.Read(b)
	if err != nil && c.armed.Load() && errors.Is(err, os.ErrDeadlineExceeded) {
		c.expired.Store(true)
	}
	if n > 0 && c.armed.Load() && c.read.Add(int64(n)) >= prefaceLength && c.armed.CompareAndSwap(true, false) {
		// An HTTP/2 connection without TLS, which the HTTP/2 server
		// times out when it is idle.
		c.Conn.SetReadDeadline(time.Time{})
	}
	return n, err
}

func (c *conn) SetReadDeadline(t time.Time) error {
	c.armed.Store(false)
	return c.Conn.SetReadDeadline(t)
}

func (c *conn) SetDeadline(t time.Time) error {
	c.armed.Store(false)
	return c.Conn.SetDeadline(t)
}

func (c *conn) Close() error {
	err := c.Conn.Close()
	c.closed.Do(func() { c.l.release(c) })
	return err
}
