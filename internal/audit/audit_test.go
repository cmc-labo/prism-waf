package audit

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestLogWritesJSONLines(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	e := &Event{
		Time:     time.Date(2026, 10, 30, 1, 2, 3, 0, time.UTC),
		ID:       "0123456789abcdef",
		ClientIP: "203.0.113.7",
		Action:   "block",
		Reason:   "signature",
		Rule:     &Rule{ID: "XSS-001", Category: "xss"},
		Match:    &Match{Location: "query", Data: "<script", Value: "q=<script>&a=1\n"},
	}
	if err := l.Log(e); err != nil {
		t.Fatal(err)
	}
	if err := l.Log(e); err != nil {
		t.Fatal(err)
	}

	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) != 2 {
		t.Fatalf("got %d lines, want 2:\n%s", len(lines), buf.String())
	}
	// Payloads stay readable, and newlines inside values cannot break the
	// one-event-per-line format.
	if !strings.Contains(lines[0], `"value":"q=<script>&a=1\n"`) {
		t.Errorf("payload not logged verbatim: %s", lines[0])
	}
	var got Event
	if err := json.Unmarshal([]byte(lines[0]), &got); err != nil {
		t.Fatal(err)
	}
	if got.Rule.ID != "XSS-001" || got.ClientIP != "203.0.113.7" || got.Match.Value != e.Match.Value {
		t.Errorf("round trip mismatch: %+v", got)
	}
}

func TestLogConcurrent(t *testing.T) {
	var buf bytes.Buffer
	l := New(&buf)
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			l.Log(&Event{ID: NewID(), Match: &Match{Value: strings.Repeat("x", 2000)}})
		}()
	}
	wg.Wait()

	n := 0
	sc := bufio.NewScanner(&buf)
	sc.Buffer(nil, 1<<20)
	for sc.Scan() {
		var e Event
		if err := json.Unmarshal(sc.Bytes(), &e); err != nil {
			t.Fatalf("line %d is not valid JSON: %v", n, err)
		}
		n++
	}
	if n != 50 {
		t.Errorf("got %d events, want 50", n)
	}
}

func TestOpenCreatesPrivateFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.log")
	l, c, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Log(&Event{ID: "a"})
	c.Close()

	// Reopening appends instead of truncating.
	l, c, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	l.Log(&Event{ID: "b"})
	c.Close()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := fi.Mode().Perm(); perm != 0o600 {
		t.Errorf("mode = %o, want 600", perm)
	}
	b, _ := os.ReadFile(path)
	if n := strings.Count(string(b), "\n"); n != 2 {
		t.Errorf("got %d lines, want 2", n)
	}
}

func TestTruncate(t *testing.T) {
	tests := []struct {
		in        string
		max       int
		want      string
		truncated bool
	}{
		{"hello", 10, "hello", false},
		{"hello", 5, "hello", false},
		{"hello", 3, "hel", true},
		{"あいう", 4, "あ", true}, // never splits a 3-byte character
		{"あいう", 6, "あい", true},
	}
	for _, tc := range tests {
		got, tr := Truncate(tc.in, tc.max)
		if got != tc.want || tr != tc.truncated {
			t.Errorf("Truncate(%q, %d) = %q, %v; want %q, %v", tc.in, tc.max, got, tr, tc.want, tc.truncated)
		}
	}
}

func TestNewID(t *testing.T) {
	a, b := NewID(), NewID()
	if len(a) != 16 || a == b {
		t.Errorf("NewID() = %q, %q", a, b)
	}
}
