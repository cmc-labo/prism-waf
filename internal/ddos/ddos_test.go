package ddos

import (
	"bufio"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"
)

// serve serves a handler on a Listener with the protocols of PrismWAF:
// HTTP/1.1 and HTTP/2 without TLS (h2c), which reads the client preface
// without a deadline.
func serve(t *testing.T, cfg ListenerConfig, h http.Handler) (*Listener, string) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l := NewListener(ln, cfg)
	p := new(http.Protocols)
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: cfg.FirstByteTimeout, IdleTimeout: time.Minute, Protocols: p}
	go srv.Serve(l)
	t.Cleanup(func() { srv.Close() })
	return l, ln.Addr().String()
}

var ok = http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { io.WriteString(w, "ok") })

// dialFrom connects from a local address such as 127.0.0.2.
func dialFrom(t *testing.T, src, addr string) net.Conn {
	t.Helper()
	d := net.Dialer{LocalAddr: &net.TCPAddr{IP: net.ParseIP(src)}, Timeout: 2 * time.Second}
	c, err := d.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

// closedWithin reports whether the server closes a connection within d,
// after the client sent data.
func closedWithin(c net.Conn, data string, d time.Duration) (bool, time.Duration) {
	c.Write([]byte(data))
	start := time.Now()
	c.SetReadDeadline(start.Add(d))
	_, err := io.Copy(io.Discard, c)
	var ne net.Error
	return !(errors.As(err, &ne) && ne.Timeout()), time.Since(start)
}

func TestFirstByteTimeout(t *testing.T) {
	_, addr := serve(t, ListenerConfig{FirstByteTimeout: 300 * time.Millisecond}, ok)
	// Without the listener, net/http keeps these connections forever.
	for _, data := range []string{"", "G", "PRI * HTTP/2.0", "GET / HTTP/1.1\r\n"} {
		c := dialFrom(t, "127.0.0.1", addr)
		if closed, after := closedWithin(c, data, 3*time.Second); !closed || after > time.Second {
			t.Errorf("%q: closed %v after %v", data, closed, after)
		}
	}

	// Connections that send requests in time live longer: HTTP/1.1 with
	// keep-alive and h2c, whose deadline must be cleared.
	c := dialFrom(t, "127.0.0.1", addr)
	br := bufio.NewReader(c)
	for i := range 2 {
		fmt.Fprint(c, "GET / HTTP/1.1\r\nHost: x\r\n\r\n")
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("HTTP/1.1 request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		time.Sleep(400 * time.Millisecond)
	}
	tr := &http.Transport{Protocols: new(http.Protocols)}
	tr.Protocols.SetUnencryptedHTTP2(true)
	defer tr.CloseIdleConnections()
	hc := &http.Client{Transport: tr}
	for i := range 2 {
		resp, err := hc.Get("http://" + addr + "/")
		if err != nil {
			t.Fatalf("h2c request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
		if resp.ProtoMajor != 2 {
			t.Fatalf("h2c request %d: %s", i, resp.Proto)
		}
		time.Sleep(400 * time.Millisecond)
	}
}

func TestFirstByteTimeoutTLS(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewUnstartedServer(ok)
	srv.Listener = NewListener(ln, ListenerConfig{FirstByteTimeout: 300 * time.Millisecond})
	srv.EnableHTTP2 = true
	srv.StartTLS()
	defer srv.Close()
	// The TLS handshake sets a deadline of its own, which takes over.
	tc, err := tls.Dial("tcp", ln.Addr().String(), &tls.Config{InsecureSkipVerify: true, NextProtos: []string{"h2"}})
	if err != nil {
		t.Fatal(err)
	}
	tc.Close()
	hc := srv.Client()
	for i := range 2 {
		resp, err := hc.Get(srv.URL)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		resp.Body.Close()
		time.Sleep(400 * time.Millisecond)
	}
}

func TestConnectionLimits(t *testing.T) {
	bans, _ := NewBans(BanConfig{Limit: 1, Window: time.Minute, Duration: time.Minute})
	l, addr := serve(t, ListenerConfig{
		MaxConns: 5, MaxConnsPerClient: 2,
		Exempt: []netip.Prefix{netip.MustParsePrefix("127.0.0.3/32")},
		Bans:   bans,
	}, ok)
	alive := func(c net.Conn) bool {
		closed, _ := closedWithin(c, "", 200*time.Millisecond)
		return !closed
	}
	a1, a2 := dialFrom(t, "127.0.0.1", addr), dialFrom(t, "127.0.0.1", addr)
	if !alive(a1) || !alive(a2) {
		t.Fatal("connections within the limit closed")
	}
	if a3 := dialFrom(t, "127.0.0.1", addr); alive(a3) {
		t.Error("third connection of a client accepted")
	}
	// Exempt clients, e.g. proxies, are only counted in the total.
	e1, e2, e3 := dialFrom(t, "127.0.0.3", addr), dialFrom(t, "127.0.0.3", addr), dialFrom(t, "127.0.0.3", addr)
	if !alive(e1) || !alive(e2) || !alive(e3) {
		t.Error("exempt client limited")
	}
	if b := dialFrom(t, "127.0.0.2", addr); alive(b) {
		t.Error("connection over the total accepted")
	}
	if l.Open() != 5 {
		t.Errorf("Open = %d, want 5", l.Open())
	}
	// Closing a connection makes room.
	a1.Close()
	time.Sleep(100 * time.Millisecond)
	if b := dialFrom(t, "127.0.0.2", addr); !alive(b) {
		t.Error("connection refused after another was closed")
	}

	// Banned clients are refused, unless they are exempt.
	for _, ip := range []string{"127.0.0.4", "127.0.0.3"} {
		bans.Strike(httptest.NewRequest("GET", "/", nil), ip)
	}
	e1.Close()
	a2.Close()
	time.Sleep(100 * time.Millisecond)
	if c := dialFrom(t, "127.0.0.4", addr); alive(c) {
		t.Error("banned client accepted")
	}
	if c := dialFrom(t, "127.0.0.3", addr); !alive(c) {
		t.Error("exempt client refused")
	}
}

func TestConnectionLimitsForget(t *testing.T) {
	l, addr := serve(t, ListenerConfig{MaxConnsPerClient: 2}, ok)
	for range 3 {
		c := dialFrom(t, "127.0.0.1", addr)
		closedWithin(c, "", 100*time.Millisecond)
		c.Close()
	}
	time.Sleep(100 * time.Millisecond)
	l.mu.Lock()
	n := len(l.clients)
	l.mu.Unlock()
	if n != 0 || l.Open() != 0 {
		t.Errorf("%d clients, %d connections after all were closed", n, l.Open())
	}
}

func TestBans(t *testing.T) {
	b, err := NewBans(BanConfig{Limit: 3, Window: time.Minute, Duration: 10 * time.Minute, Exempt: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 11, 20, 12, 0, 0, 0, time.UTC)
	b.now = func() time.Time { return now }
	if b.Rule() != "3/1m for 10m" {
		t.Errorf("Rule = %q", b.Rule())
	}
	r := httptest.NewRequest("GET", "/", nil)
	for i := range 2 {
		if d := b.Strike(r, "192.0.2.1"); d.Banned {
			t.Fatalf("banned after %d strikes", i+1)
		}
	}
	d := b.Strike(r, "192.0.2.1")
	if !d.Banned || !d.First || d.EventID == "" || d.RetryAfter != 10*time.Minute || d.Client != netip.MustParsePrefix("192.0.2.1/32") {
		t.Fatalf("third strike: %+v", d)
	}
	if d2 := b.Strike(r, "192.0.2.1"); !d2.Banned || d2.First || d2.EventID != d.EventID {
		t.Errorf("strike during the ban: %+v", d2)
	}
	now = now.Add(time.Minute)
	if c := b.Check("192.0.2.1"); !c.Banned || c.EventID != d.EventID || c.RetryAfter != 9*time.Minute {
		t.Errorf("Check during the ban: %+v", c)
	}
	if c := b.Check("192.0.2.2"); c.Banned {
		t.Error("other client banned")
	}
	// An IPv6 /64 is one client.
	for range 3 {
		b.Strike(r, "2001:db8::1")
	}
	if c := b.Check("2001:db8::ffff"); !c.Banned || c.Client != netip.MustParsePrefix("2001:db8::/64") {
		t.Errorf("same /64: %+v", c)
	}
	for range 10 {
		b.Strike(r, "10.1.2.3")
	}
	if c := b.Check("10.1.2.3"); c.Banned {
		t.Error("exempt client banned")
	}
	now = now.Add(9 * time.Minute)
	if c := b.Check("192.0.2.1"); c.Banned {
		t.Error("still banned after the duration")
	}
	if b.bannedKey(netip.MustParsePrefix("192.0.2.1/32")) {
		t.Error("bannedKey after the duration")
	}
}

func TestBansFull(t *testing.T) {
	b, _ := NewBans(BanConfig{Limit: 1, Window: time.Minute, Duration: time.Hour, MaxClients: 2})
	r := httptest.NewRequest("GET", "/", nil)
	b.Strike(r, "192.0.2.1")
	b.Strike(r, "192.0.2.2")
	if d := b.Strike(r, "192.0.2.3"); d.Banned {
		t.Error("banned beyond the maximum")
	}
	if !b.Check("192.0.2.1").Banned || b.Len() != 2 {
		t.Error("existing bans dropped")
	}
}

func TestNewBans(t *testing.T) {
	for _, cfg := range []BanConfig{
		{Limit: 1, Window: time.Minute},
		{Limit: 0, Window: time.Minute, Duration: time.Minute},
		{Limit: 1, Window: time.Minute, Duration: time.Minute, MaxClients: -1},
	} {
		if _, err := NewBans(cfg); err == nil {
			t.Errorf("NewBans(%+v) succeeded", cfg)
		}
	}
}

func TestConcurrency(t *testing.T) {
	c, err := NewConcurrency(ConcurrencyConfig{Max: 4, MaxPerClient: 2, Exempt: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	if err != nil {
		t.Fatal(err)
	}
	r1, d := c.Acquire("192.0.2.1")
	r2, _ := c.Acquire("192.0.2.1")
	if !d.Allowed || r1 == nil || r2 == nil {
		t.Fatal("requests within the limit rejected")
	}
	d = reject(c, "192.0.2.1")
	if d.Allowed || d.Overloaded || !d.First || d.EventID == "" || d.Client != netip.MustParsePrefix("192.0.2.1/32") {
		t.Fatalf("third request: %+v", d)
	}
	if d2 := reject(c, "192.0.2.1"); d2.First || d2.EventID != d.EventID {
		t.Errorf("fourth request: %+v", d2)
	}
	firstExcess := d.EventID
	// The exempt client is only counted in the total.
	r3, _ := c.Acquire("10.0.0.1")
	r4, _ := c.Acquire("10.0.0.1")
	if r3 == nil || r4 == nil {
		t.Fatal("exempt client limited")
	}
	if d := reject(c, "192.0.2.9"); d.Allowed || !d.Overloaded {
		t.Errorf("over the total: %+v", d)
	}
	if c.Active() != 4 {
		t.Errorf("Active = %d", c.Active())
	}
	// Releasing twice counts once.
	r1()
	r1()
	if c.Active() != 3 {
		t.Errorf("Active after release = %d", c.Active())
	}
	r5, d := c.Acquire("192.0.2.1")
	if r5 == nil {
		t.Fatalf("after release: %+v", d)
	}
	// A new excess has a new event.
	r3()
	if d3 := reject(c, "192.0.2.1"); d3.Allowed || !d3.First || d3.EventID == firstExcess {
		t.Errorf("new excess: %+v", d3)
	}
	for _, r := range []func(){r2, r4, r5} {
		r()
	}
	if c.Active() != 0 || len(c.clients) != 0 {
		t.Errorf("Active = %d, clients %d", c.Active(), len(c.clients))
	}
	if _, err := NewConcurrency(ConcurrencyConfig{Max: -1}); err == nil {
		t.Error("negative limit accepted")
	}
}

func TestConcurrencyExempt(t *testing.T) {
	c, _ := NewConcurrency(ConcurrencyConfig{MaxPerClient: 1, Exempt: []netip.Prefix{netip.MustParsePrefix("10.0.0.0/8")}})
	for i := range 3 {
		if r, d := c.Acquire("10.0.0.1"); r == nil {
			t.Fatalf("exempt client, request %d: %+v", i+1, d)
		}
	}
}

// reject acquires and releases a request, for requests that are rejected.
func reject(c *Concurrency, ip string) ConcurrencyDecision {
	release, d := c.Acquire(ip)
	if release != nil {
		release()
	}
	return d
}

func TestBodyTimeout(t *testing.T) {
	bt := BodyTimeout{Timeout: 300 * time.Millisecond, MinRate: 100}
	type result struct {
		n   int
		err error
	}
	results := make(chan result, 1)
	_, addr := serve(t, ListenerConfig{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bt.Apply(w, r)
		n, err := io.Copy(io.Discard, r.Body)
		results <- result{int(n), err}
		io.WriteString(w, "done")
	}))
	post := func(body func(c net.Conn), length int) result {
		c := dialFrom(t, "127.0.0.1", addr)
		fmt.Fprintf(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: %d\r\n\r\n", length)
		body(c)
		select {
		case res := <-results:
			return res
		case <-time.After(5 * time.Second):
			t.Fatal("handler did not finish")
			return result{}
		}
	}

	// A body that does not start in time.
	res := post(func(net.Conn) {}, 10)
	if !errors.Is(res.err, os.ErrDeadlineExceeded) {
		t.Errorf("no body: %+v", res)
	}
	// A body sent byte by byte, slower than the minimum rate.
	res = post(func(c net.Conn) {
		for range 10 {
			if _, err := c.Write([]byte("a")); err != nil {
				return
			}
			time.Sleep(150 * time.Millisecond)
		}
	}, 10)
	if !errors.Is(res.err, os.ErrDeadlineExceeded) || res.n == 0 || res.n == 10 {
		t.Errorf("slow body: %+v", res)
	}
	// A body that takes longer than Timeout, at more than the minimum
	// rate: 100 bytes every 200 ms for a second.
	res = post(func(c net.Conn) {
		for range 5 {
			c.Write([]byte(strings.Repeat("a", 100)))
			time.Sleep(200 * time.Millisecond)
		}
	}, 500)
	if res.err != nil || res.n != 500 {
		t.Errorf("body at the minimum rate: %+v", res)
	}

	// The deadline is cleared at the end of the body: the connection can
	// wait for the next request.
	c := dialFrom(t, "127.0.0.1", addr)
	br := bufio.NewReader(c)
	for i := range 2 {
		fmt.Fprint(c, "POST / HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\n\r\nab")
		<-results
		resp, err := http.ReadResponse(br, nil)
		if err != nil {
			t.Fatalf("request %d: %v", i, err)
		}
		io.Copy(io.Discard, resp.Body)
		time.Sleep(500 * time.Millisecond)
	}

	// After the body, the handler may take longer than the deadline, e.g.
	// for a slow backend: the request must not be canceled.
	canceled := make(chan error, 1)
	_, addr2 := serve(t, ListenerConfig{}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		bt.Apply(w, r)
		io.Copy(io.Discard, r.Body)
		time.Sleep(700 * time.Millisecond)
		canceled <- r.Context().Err()
		io.WriteString(w, "done")
	}))
	resp, err := http.Post("http://"+addr2+"/", "text/plain", strings.NewReader("abc"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if err := <-canceled; err != nil {
		t.Errorf("request canceled after its body: %v", err)
	}

	// Requests without a body and recorders without deadlines are left
	// alone.
	r := httptest.NewRequest("GET", "/", nil)
	body := r.Body
	bt.Apply(httptest.NewRecorder(), r)
	if r.Body != body {
		t.Error("body of a GET replaced")
	}
	r = httptest.NewRequest("POST", "/", strings.NewReader("x"))
	body = r.Body
	bt.Apply(httptest.NewRecorder(), r)
	if r.Body != body {
		t.Error("body replaced without deadlines")
	}
}
