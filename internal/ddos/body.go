package ddos

import (
	"io"
	"net/http"
	"time"
)

// Defaults of BodyTimeout.
const (
	DefaultBodyTimeout = 20 * time.Second
	DefaultBodyMinRate = 500
)

// BodyTimeout makes clients send request bodies at a minimum rate, so that
// a client cannot hold a connection and a request in progress by sending
// its body byte by byte (slow POST). The body must start within Timeout,
// which is extended by one second for every MinRate bytes received, like
// Apache's mod_reqtimeout: with the defaults, a 1 MB upload may take 20 s
// plus about 35 minutes. A body that is too slow fails to read with an
// error that matches os.ErrDeadlineExceeded.
type BodyTimeout struct {
	// Timeout is the time to receive the first bytes. Zero disables the
	// timeout.
	Timeout time.Duration
	// MinRate is the minimum rate in bytes per second. Zero only allows
	// Timeout for the whole body.
	MinRate int64
}

// Apply sets the read deadline of a request with a body and replaces its
// body with one that extends the deadline as data arrives, and clears it
// at the end of the body. It does nothing if the connection does not
// support deadlines.
func (t BodyTimeout) Apply(w http.ResponseWriter, r *http.Request) {
	if t.Timeout <= 0 || r.Body == nil || r.Body == http.NoBody || r.ContentLength == 0 {
		return
	}
	rc := http.NewResponseController(w)
	start := time.Now()
	if rc.SetReadDeadline(start.Add(t.Timeout)) != nil {
		return
	}
	r.Body = &timedBody{ReadCloser: r.Body, t: t, rc: rc, start: start}
}

type timedBody struct {
	io.ReadCloser
	t        BodyTimeout
	rc       *http.ResponseController
	start    time.Time
	received int64
	done     bool
}

func (b *timedBody) Read(p []byte) (int, error) {
	n, err := b.ReadCloser.Read(p)
	if b.done {
		return n, err
	}
	b.received += int64(n)
	switch {
	case err == io.EOF:
		// The last bytes may come with io.EOF, after net/http has
		// cleared the deadline of an HTTP/1 connection to watch it for
		// the client going away: setting it again would cancel the
		// request if the response takes longer.
		b.done = true
		b.rc.SetReadDeadline(time.Time{})
	case n > 0 && b.t.MinRate > 0:
		b.rc.SetReadDeadline(b.start.Add(b.t.Timeout + time.Duration(float64(b.received)/float64(b.t.MinRate)*float64(time.Second))))
	}
	return n, err
}
