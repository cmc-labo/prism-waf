package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

// defaultHealthcheckURL is the readiness probe at the port that the
// container image sets with PRISMWAF_PROBE_LISTEN.
const defaultHealthcheckURL = "http://127.0.0.1:9090/readyz"

// probes answers the liveness and readiness probes of container
// orchestrators on -probe-listen, a port of its own, so that they neither
// pass through the WAF to the backend nor are reachable by clients:
//
//   - GET /healthz: 200 while the process runs.
//   - GET /readyz: 200 once PrismWAF accepts connections, 503 before and
//     while it shuts down.
type probes struct {
	ready atomic.Bool
}

func (p *probes) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	switch r.URL.Path {
	case "/healthz":
		io.WriteString(w, "ok\n")
	case "/readyz":
		if !p.ready.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
			io.WriteString(w, "not ready\n")
			return
		}
		io.WriteString(w, "ready\n")
	default:
		http.NotFound(w, r)
	}
}

// healthcheck implements "prismwaf healthcheck [URL]", for the health
// checks of Docker and Compose: the image has no shell or curl to query
// the probes with. It returns the exit status, 0 if the URL answers 200.
func healthcheck(args []string) int {
	target := defaultHealthcheckURL
	switch len(args) {
	case 0:
	case 1:
		target = args[0]
	default:
		fmt.Fprintln(os.Stderr, "usage: prismwaf healthcheck [URL]  (default "+defaultHealthcheckURL+")")
		return 2
	}
	c := &http.Client{Timeout: 5 * time.Second}
	res, err := c.Get(target)
	if err != nil {
		fmt.Fprintln(os.Stderr, "healthcheck:", err)
		return 1
	}
	res.Body.Close()
	if res.StatusCode != http.StatusOK {
		fmt.Fprintln(os.Stderr, "healthcheck:", target, res.Status)
		return 1
	}
	return 0
}
