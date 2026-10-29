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
	// Action is what PrismWAF did, e.g. "block".
	Action string `json:"action"`
	// Reason is why, e.g. "signature" or "body_too_large".
	Reason  string  `json:"reason"`
	Rule    *Rule   `json:"rule,omitempty"`
	Match   *Match  `json:"match,omitempty"`
	Request Request `json:"request"`
}

// Rule identifies the signature that matched.
type Rule struct {
	ID       string `json:"id"`
	Category string `json:"category"`
}

// Match describes where and how the rule matched.
type Match struct {
	// Location is the part of the request: path, query, header or body.
	Location string `json:"location"`
	// Field is the header name for header matches.
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
