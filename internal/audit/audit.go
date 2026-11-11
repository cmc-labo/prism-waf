// Package audit writes security events, such as blocked requests, as JSON
// Lines: one JSON object per line, which log shippers and tools like jq can
// consume directly.
package audit

import (
	"bytes"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"sync"
	"time"
	"unicode/utf8"
)

// Event describes a request that PrismWAF acted on.
type Event struct {
	Time time.Time `json:"time"`
	// ID identifies the event. It is also returned to the client in the
	// error response, so a user can report a false positive.
	ID string `json:"id"`
	// ClientIP is the address of the client, taken from X-Forwarded-For
	// when the request came through a trusted proxy.
	ClientIP string `json:"client_ip"`
	// RemoteAddr is the address of the TCP peer.
	RemoteAddr string `json:"remote_addr"`
	// Action is what PrismWAF did: "block" (rejected), "challenge" (asked
	// to prove it is a browser) or "detect" (only logged and forwarded, in
	// detection mode).
	Action string `json:"action"`
	// Reason is why: "signature" (built-in signatures), "crs" (OWASP CRS),
	// "body_too_large", "rate_limit" or "bot".
	Reason string `json:"reason"`
	Rule   *Rule  `json:"rule,omitempty"`
	Match  *Match `json:"match,omitempty"`
	// CRS holds the details of an OWASP CRS detection.
	CRS *CRS `json:"crs,omitempty"`
	// RateLimit holds the details of an exceeded rate limit.
	RateLimit *RateLimit `json:"rate_limit,omitempty"`
	// Bot holds the details of a client that looks like a bot.
	Bot     *Bot    `json:"bot,omitempty"`
	Request Request `json:"request"`
}

// Bot describes why a client was considered a bot. Only the first
// challenged or blocked request of a client in a minute is logged; the
// following ones share its event ID.
type Bot struct {
	// Score is from 0 (nothing suspicious) to 100 (certainly a bot).
	Score int `json:"score"`
	// Signals are the reasons for the score, e.g. "automation_tool" or
	// "missing_accept_language".
	Signals []string `json:"signals"`
	// Client is the address that a clearance cookie would be bound to:
	// the client IP, or its /64 network for IPv6.
	Client string `json:"client"`
}

// RateLimit describes an exceeded rate limit. Only the first rejected
// request of an excess is logged; the following ones share its event ID.
type RateLimit struct {
	// Rule is the exceeded rule, e.g. "POST /login=5/1m", or just the
	// rate for the limit on all requests, e.g. "300/1m".
	Rule string `json:"rule"`
	// Client is the address the requests were counted for: the client IP,
	// or its /64 network for IPv6.
	Client string `json:"client"`
	// RetryAfter is the number of seconds until the client may send the
	// next request.
	RetryAfter int `json:"retry_after"`
}

// CRS describes an OWASP CRS detection.
type CRS struct {
	// AnomalyScore is the inbound anomaly score, if it decided.
	AnomalyScore int `json:"anomaly_score,omitempty"`
	// DecidingRule is the rule that rejected the request, usually 949110
	// (anomaly score exceeded).
	DecidingRule int `json:"deciding_rule"`
	// Rules are the matched rules that add to the anomaly score.
	Rules []CRSRule `json:"rules"`
}

// CRSRule is a matched CRS rule.
type CRSRule struct {
	ID       int    `json:"id"`
	Message  string `json:"message"`
	Severity string `json:"severity,omitempty"`
	// Variable is where it matched, e.g. "ARGS:q".
	Variable string `json:"variable,omitempty"`
	// Value is the matched value, possibly truncated.
	Value string `json:"value,omitempty"`
}

// Rule identifies the signature that matched. For CRS detections, it is
// the most severe matched CRS rule.
type Rule struct {
	ID       string `json:"id"`
	Category string `json:"category"`
}

// Match describes where and how the rule matched.
type Match struct {
	// Location is the part of the request: path, query, header or body.
	// For CRS detections, it is the ModSecurity variable, e.g. ARGS or
	// REQUEST_HEADERS.
	Location string `json:"location"`
	// Field is the header name for header matches, the path of the value
	// in a JSON or XML body, or the key of a CRS variable (e.g. the
	// argument name).
	Field string `json:"field,omitempty"`
	// Base64 reports whether the match was in Base64-decoded data.
	Base64 bool `json:"base64,omitempty"`
	// Data is the text the rule matched, after normalization.
	Data string `json:"data"`
	// Value is the raw value of the inspected part, possibly truncated.
	Value          string `json:"value"`
	ValueLength    int    `json:"value_length"`
	ValueTruncated bool   `json:"value_truncated,omitempty"`
}

// Request summarizes the request.
type Request struct {
	Method        string            `json:"method"`
	URI           string            `json:"uri"`
	Proto         string            `json:"proto"`
	Host          string            `json:"host"`
	ContentLength int64             `json:"content_length"`
	Headers       map[string]string `json:"headers"`
}

// Logger writes events to an io.Writer. It is safe for concurrent use.
type Logger struct {
	mu sync.Mutex
	w  io.Writer
}

// New returns a Logger that writes to w.
func New(w io.Writer) *Logger {
	return &Logger{w: w}
}

// Open returns a Logger that appends to the file at path, or writes to
// standard output if path is "-". The returned io.Closer closes the file.
//
// The file is created with mode 0600 because events can contain secrets
// sent in attack payloads.
func Open(path string) (*Logger, io.Closer, error) {
	if path == "-" {
		return New(os.Stdout), nopCloser{}, nil
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_APPEND|os.O_CREATE, 0o600)
	if err != nil {
		return nil, nil, err
	}
	return New(f), f, nil
}

type nopCloser struct{}

func (nopCloser) Close() error { return nil }

// Log writes e as a single line of JSON.
func (l *Logger) Log(e *Event) error {
	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// Keep payloads such as <script> readable in the log instead of escaping
	// <, > and & as Unicode escapes.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(e); err != nil {
		return err
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	_, err := l.w.Write(buf.Bytes())
	return err
}

// NewID returns a random 16-character hex event ID.
func NewID() string {
	var b [8]byte
	rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// Truncate shortens s to at most max bytes without splitting a UTF-8
// character, and reports whether it did.
func Truncate(s string, max int) (string, bool) {
	if len(s) <= max {
		return s, false
	}
	cut := max
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut], true
}
