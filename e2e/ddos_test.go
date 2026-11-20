//go:build e2e

package e2e

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/http/httptrace"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/dynamicpb"
)

// dialFrom connects to prismwaf from a local address such as 127.0.0.2, so
// that each test client has an IP address of its own.
func dialFrom(t *testing.T, w *waf, src string) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 2 * time.Second}
	c, err := d.Dial("tcp", strings.TrimPrefix(strings.TrimPrefix(w.URL, "http://"), "https://"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// httpFrom returns an HTTP client that connects from a local address.
func httpFrom(src string) *http.Client {
	d := &net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 2 * time.Second}
	return &http.Client{Timeout: 10 * time.Second, Transport: &http.Transport{DialContext: d.DialContext}}
}

// closedAfter sends data and returns how long prismwaf took to close the
// connection, or 0 if it did not within d.
func closedAfter(c net.Conn, data string, d time.Duration) time.Duration {
	c.Write([]byte(data))
	start := time.Now()
	c.SetReadDeadline(start.Add(d))
	_, err := io.Copy(io.Discard, c)
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return 0
	}
	return time.Since(start)
}

func TestIdleConnections(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-read-header-timeout", "1s"}})
	// Connections that send nothing or not enough: the previous version
	// kept the first three for ever, as net/http reads the beginning of
	// h2c connections without a deadline.
	var wg sync.WaitGroup
	for _, data := range []string{"", "G", "PRI * HTTP/2.0", "GET / HTTP/1.1\r\nHost: x\r\n"} {
		c := dialFrom(t, w, "127.0.0.1")
		wg.Add(1)
		go func() {
			defer wg.Done()
			if after := closedAfter(c, data, 5*time.Second); after == 0 || after > 2*time.Second {
				t.Errorf("%q: closed after %v (0: not closed)", data, after)
			}
		}()
	}
	wg.Wait()

	// Connections that use HTTP/1.1 keep-alive or h2c are not affected,
	// also when they are idle for longer.
	for _, h2c := range []bool{false, true} {
		tr := &http.Transport{}
		if h2c {
			tr.Protocols = new(http.Protocols)
			tr.Protocols.SetUnencryptedHTTP2(true)
		}
		hc := &http.Client{Transport: tr, Timeout: 5 * time.Second}
		for i := range 2 {
			reused := false
			ctx := httptrace.WithClientTrace(context.Background(), &httptrace.ClientTrace{GotConn: func(i httptrace.GotConnInfo) { reused = i.Reused }})
			req, _ := http.NewRequestWithContext(ctx, "GET", w.URL+"/", nil)
			resp, err := hc.Do(req)
			if err != nil {
				t.Fatalf("h2c %v, request %d: %v", h2c, i+1, err)
			}
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			if i == 1 && !reused {
				t.Errorf("h2c %v: connection not reused after 1.5 s", h2c)
			}
			time.Sleep(1500 * time.Millisecond)
		}
		tr.CloseIdleConnections()
	}
}

func TestIdleConnectionsTLS(t *testing.T) {
	w := startWAF(t, wafOptions{tls: true, args: []string{"-read-header-timeout", "1s"}})
	c := dialFrom(t, w, "127.0.0.1")
	if after := closedAfter(c, "", 5*time.Second); after == 0 || after > 2*time.Second {
		t.Errorf("TLS connection without a handshake closed after %v", after)
	}
	cl := w.client(t, nil)
	for range 2 {
		if r := cl.get("/"); r.StatusCode != http.StatusOK {
			t.Fatalf("HTTPS: %d", r.StatusCode)
		}
		time.Sleep(1500 * time.Millisecond)
	}
}

func TestSlowBody(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-body-timeout", "1s", "-body-min-rate", "1000"}})
	// A body sent byte by byte.
	c := dialFrom(t, w, "127.0.0.2")
	fmt.Fprint(c, "POST /upload HTTP/1.1\r\nHost: x\r\nContent-Type: text/plain\r\nContent-Length: 1000\r\n\r\n")
	start := time.Now()
	go func() {
		for range 20 {
			if _, err := c.Write([]byte("a")); err != nil {
				return
			}
			time.Sleep(300 * time.Millisecond)
		}
	}()
	c.SetReadDeadline(time.Now().Add(5 * time.Second))
	resp, err := http.ReadResponse(bufio.NewReader(c), nil)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	if resp.StatusCode != http.StatusRequestTimeout || !resp.Close || time.Since(start) > 2500*time.Millisecond {
		t.Fatalf("slow body: %d after %v, close %v", resp.StatusCode, time.Since(start), resp.Close)
	}
	m := eventIDRe.FindStringSubmatch(string(body))
	if m == nil {
		t.Fatalf("no event ID: %q", body)
	}
	if e := w.eventByID(t, m[1]); e.Reason != "slow_request" || e.Action != "block" || e.ClientIP != "127.0.0.2" || e.Request.URI != "/upload" {
		t.Errorf("event %+v", e)
	}

	// An upload that takes longer than -body-timeout at more than the
	// minimum rate passes: 100 KB in 2 s.
	pr, pw := io.Pipe()
	go func() {
		for range 20 {
			pw.Write([]byte(strings.Repeat("a", 5000)))
			time.Sleep(100 * time.Millisecond)
		}
		pw.Close()
	}()
	req, _ := http.NewRequest("POST", w.URL+"/upload", pr)
	req.ContentLength = 100000
	req.Header.Set("Content-Type", "text/plain")
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer res.Body.Close()
	if b, _ := io.ReadAll(res.Body); res.StatusCode != http.StatusOK || !strings.Contains(string(b), `"method":"POST"`) {
		t.Errorf("upload: %d %s", res.StatusCode, b)
	}
}

// TestSlowBodyGRPC checks that gRPC streams may pause longer than
// -body-timeout and -read-header-timeout.
func TestSlowBodyGRPC(t *testing.T) {
	w, _ := startGRPCWAF(t, wafOptions{args: []string{"-body-timeout", "1s", "-read-header-timeout", "1s"}})
	conn := w.dial(t)
	s, err := conn.NewStream(grpcContext(t), &grpc.StreamDesc{ClientStreams: true, ServerStreams: true}, "/test.Search/Chat")
	if err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{"hello", "still there?"} {
		if err := s.SendMsg(searchRequest{query: q}.message()); err != nil {
			t.Fatal(err)
		}
		m := dynamicpb.NewMessage(searchReplyMD)
		if err := s.RecvMsg(m); err != nil || replyText(m) != "echo "+q {
			t.Fatalf("%s: %q %v", q, replyText(m), err)
		}
		time.Sleep(1500 * time.Millisecond)
	}
}

func TestConnectionLimits(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-max-conns-per-ip", "2", "-max-conns", "4"}})
	alive := func(c net.Conn) bool { return closedAfter(c, "", 300*time.Millisecond) == 0 }
	a1, a2, a3 := dialFrom(t, w, "127.0.0.2"), dialFrom(t, w, "127.0.0.2"), dialFrom(t, w, "127.0.0.2")
	if !alive(a1) || !alive(a2) || alive(a3) {
		t.Fatalf("per client: alive %v %v %v, want true true false", alive(a1), alive(a2), alive(a3))
	}
	b1, b2 := dialFrom(t, w, "127.0.0.3"), dialFrom(t, w, "127.0.0.3")
	if !alive(b1) || !alive(b2) {
		t.Fatal("other client limited")
	}
	if c := dialFrom(t, w, "127.0.0.4"); alive(c) {
		t.Error("connection over -max-conns accepted")
	}
	w.waitLog(t, "closing connections over the limits", "reason=max_conns_per_client")
	// A closed connection makes room, and requests work as usual.
	a1.Close()
	time.Sleep(100 * time.Millisecond)
	if r, err := httpFrom("127.0.0.2").Get(w.URL + "/"); err != nil || r.StatusCode != http.StatusOK {
		t.Errorf("request after a connection was closed: %v %v", r, err)
	}

	// Trusted proxies carry many clients: their connections are not
	// limited per address.
	w = startWAF(t, wafOptions{args: []string{"-max-conns-per-ip", "2", "-trusted-proxies", "127.0.0.2"}})
	p1, p2, p3 := dialFrom(t, w, "127.0.0.2"), dialFrom(t, w, "127.0.0.2"), dialFrom(t, w, "127.0.0.2")
	if !alive(p1) || !alive(p2) || !alive(p3) {
		t.Error("connections of a trusted proxy limited")
	}
}

func TestConcurrencyLimits(t *testing.T) {
	release := make(chan struct{})
	started := make(chan struct{}, 10)
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/slow" {
			started <- struct{}{}
			<-release
		}
		io.WriteString(w, "ok")
	}))
	defer backend.Close()
	defer close(release)
	w := startWAF(t, wafOptions{backend: backend.URL, args: []string{"-max-client-requests", "2", "-max-requests", "3", "-trusted-proxies", "127.0.0.1"}})
	c := w.client(t, nil)
	var wg sync.WaitGroup
	defer wg.Wait()
	for _, client := range []string{"198.51.100.1", "198.51.100.1", "198.51.100.2"} {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c.get("/slow", "X-Forwarded-For", client)
		}()
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatal("request did not reach the backend")
		}
	}
	// The client with two requests in progress gets 429…
	r := c.get("/fast", "X-Forwarded-For", "198.51.100.1")
	m := eventIDRe.FindStringSubmatch(r.body)
	if r.StatusCode != http.StatusTooManyRequests || r.Header.Get("Retry-After") != "1" || m == nil {
		t.Fatalf("client over its limit: %d %q", r.StatusCode, r.body)
	}
	e := w.eventByID(t, m[1])
	if e.Reason != "concurrency" || e.RateLimit == nil || e.RateLimit.Rule != "2 in progress" || e.RateLimit.Client != "198.51.100.1/32" {
		t.Errorf("event %+v %+v", e, e.RateLimit)
	}
	// …and with three in progress, everyone else 503.
	r = c.get("/fast", "X-Forwarded-For", "198.51.100.3")
	if r.StatusCode != http.StatusServiceUnavailable || r.Header.Get("Retry-After") != "1" || strings.Contains(r.body, "Event ID") {
		t.Errorf("overloaded: %d %q", r.StatusCode, r.body)
	}
	w.waitLog(t, "too many requests in progress", "max_requests=3")
	release <- struct{}{}
	release <- struct{}{}
	release <- struct{}{}
	wg.Wait()
	if r := c.get("/fast", "X-Forwarded-For", "198.51.100.3"); r.StatusCode != http.StatusOK {
		t.Errorf("after the slow requests: %d", r.StatusCode)
	}
}

func TestBan(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-rate-limit", "2/1m", "-ban", "3/1m", "-ban-duration", "2s"}})
	w.waitLog(t, "denial of service protection", `ban="3/1m for 2s"`)
	attacker, user := httpFrom("127.0.0.2"), httpFrom("127.0.0.3")
	get := func(hc *http.Client) (*http.Response, string) {
		t.Helper()
		resp, err := hc.Get(w.URL + "/")
		if err != nil {
			return nil, err.Error()
		}
		defer resp.Body.Close()
		b, _ := io.ReadAll(resp.Body)
		return resp, string(b)
	}
	var codes []int
	for range 5 {
		resp, _ := get(attacker)
		codes = append(codes, resp.StatusCode)
	}
	// Two allowed, three rate limited, then banned.
	if fmt.Sprint(codes) != "[200 200 429 429 429]" {
		t.Fatalf("codes %v", codes)
	}
	resp, body := get(attacker)
	if resp == nil || resp.StatusCode != http.StatusForbidden || !resp.Close {
		t.Fatalf("banned client: %v %q", resp, body)
	}
	m := eventIDRe.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no event ID: %q", body)
	}
	e := w.eventByID(t, m[1])
	if e.Reason != "ban" || e.RateLimit == nil || e.RateLimit.Rule != "3/1m for 2s" || e.RateLimit.Client != "127.0.0.2/32" || e.RateLimit.RetryAfter != 2 {
		t.Errorf("event %+v %+v", e, e.RateLimit)
	}
	// New connections of the banned client are closed when they are
	// accepted; other clients are served.
	if after := closedAfter(dialFrom(t, w, "127.0.0.2"), "GET / HTTP/1.1\r\nHost: x\r\n\r\n", 2*time.Second); after == 0 || after > 500*time.Millisecond {
		t.Errorf("connection of the banned client closed after %v", after)
	}
	w.waitLog(t, "closing connections over the limits", "reason=banned")
	if resp, _ := get(user); resp == nil || resp.StatusCode != http.StatusOK {
		t.Errorf("other client: %v", resp)
	}
	// After the ban, the rate limit applies again.
	time.Sleep(2100 * time.Millisecond)
	if resp, body := get(attacker); resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Errorf("after the ban: %v %q", resp, body)
	}
}

func TestDoSStartup(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-max-conns-per-ip", "-1"}, "must not be negative"},
		{[]string{"-ban", "100"}, "invalid -ban"},
		{[]string{"-ban-duration", "1m"}, "-ban-duration requires -ban"},
		{[]string{"-ban", "10/1m", "-ban-duration", "0s"}, "-ban-duration must be positive"},
		{[]string{"-body-min-rate", "-5"}, "-body-min-rate must not be negative"},
	} {
		out, err := runWAF(t, tc.args...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%q: %v\n%s", tc.args, err, out)
		}
	}
}
