//go:build e2e

package e2e

import (
	"net/http"
	"strings"
	"testing"
	"time"
)

// TestRateLimitAlerts makes two clients exceed a rate limit: each client,
// the number of clients and the number of rejected requests are alerted
// once at the webhook and from the command, and resolved after a quiet
// window.
func TestRateLimitAlerts(t *testing.T) {
	hook, cmd := startWebhook(t), newCommand(t)
	w := startWAF(t, wafOptions{args: []string{
		"-trusted-proxies", "127.0.0.1",
		"-rate-limit", "2/1m",
		"-alert-rate-limited-requests", "6/4s",
		"-alert-rate-limited-clients", "2/4s",
		"-alert-rate-limited-client", "3/4s",
		"-alert-webhook", hook.URL, "-alert-command", cmd.line,
	}})
	w.waitLog(t, "rate limit alerts enabled", "requests=6/4s", "clients=2/4s", "client=3/4s", "rate_limit=10/1h")
	c := w.client(t, nil)
	for _, ip := range []string{"203.0.113.7", "198.51.100.4"} {
		for i := range 5 {
			r := c.get("/", "X-Forwarded-For", ip)
			if want := map[bool]int{true: http.StatusOK, false: http.StatusTooManyRequests}[i < 2]; r.StatusCode != want {
				t.Fatalf("%s request %d: status %d, want %d", ip, i+1, r.StatusCode, want)
			}
		}
	}

	got := cmd.wait(t, 4, 10*time.Second)
	gotHook := hook.wait(t, 4, 5*time.Second)
	var events []string
	for i, n := range got {
		events = append(events, n.Event+" "+n.Client)
		checkEvent(t, n, n.Event, "warning")
		checkEvent(t, gotHook[i], n.Event, "warning")
		if gotHook[i].Message != n.Message {
			t.Errorf("webhook %q, command %q", gotHook[i].Message, n.Message)
		}
	}
	if strings.Join(events, ",") != "rate_limited_client 203.0.113.7,rate_limited_clients ,rate_limited_requests ,rate_limited_client 198.51.100.4" {
		t.Fatalf("events %v", events)
	}
	if n := got[0]; n.Metric != "client" || n.Count != 3 || n.Threshold != 3 || n.Window != "4s" || len(n.TopRules) != 1 || n.TopRules[0].Name != "2/1m" ||
		!strings.HasPrefix(n.Message, "Client 203.0.113.7 was rate limited 3 times within ") || !strings.HasSuffix(n.Message, "(alert threshold: 3 per 4s). Rules: 2/1m (3).") ||
		n.env["PRISMWAF_CLIENT"] != "203.0.113.7" || n.env["PRISMWAF_COUNT"] != "3" || n.env["PRISMWAF_THRESHOLD"] != "3" || n.env["PRISMWAF_METRIC"] != "client" {
		t.Errorf("client alert %+v", n)
	}
	// Clients with the same count are listed by address.
	if n := got[2]; n.Count != 6 || len(n.TopClients) != 2 || n.TopClients[0].Name != "198.51.100.4" || n.TopClients[0].Count != 3 ||
		n.Message != "Rate limits rejected 6 requests within less than a second (alert threshold: 6 per 4s). Top clients: 198.51.100.4 (3), 203.0.113.7 (3). Rules: 2/1m (6)." {
		t.Errorf("requests alert %+v", n)
	}
	w.waitLog(t, "level=WARN", `msg="rate limit alert"`, "event=rate_limited_client", "client=198.51.100.4", "count=3")

	// Resolved by a window without rejected requests.
	got = cmd.wait(t, 6, 15*time.Second)
	for _, n := range got[4:] {
		checkEvent(t, n, "rate_limit_alert_resolved", "info")
	}
	if got[4].Metric != "requests" || !strings.HasSuffix(got[4].Message, ": 6 requests rejected in total, at most 6 per window.") ||
		got[5].Metric != "clients" || !strings.HasSuffix(got[5].Message, ": at most 2 clients per window.") {
		t.Errorf("resolved %+v", got[4:])
	}
	w.waitLog(t, "level=INFO", `msg="rate limit alert resolved"`, "metric=client", "client=203.0.113.7")
	time.Sleep(5 * time.Second)
	if n := len(cmd.received(t)) + len(hook.received()); n != 12 {
		t.Errorf("%d notifications, want 12", n)
	}
}

// TestRateLimitAlertFlags checks -alert-test and invalid alert options.
func TestRateLimitAlertFlags(t *testing.T) {
	cmd := newCommand(t)
	out, err := runWAF(t, "-alert-command", cmd.line, "-alert-test")
	if err != nil {
		t.Fatalf("-alert-test: %v\n%s", err, out)
	}
	got := cmd.received(t)
	if len(got) != 1 || got[0].Event != "test" || !strings.HasPrefix(got[0].Message, "Test alert: ") {
		t.Errorf("received %+v", got)
	}
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-alert-rate-limited-client", "10/1m"}, "-alert-rate-limited-* options require -rate-limit or -rate-limit-path"},
		{[]string{"-rate-limit", "10/1m", "-alert-rate-limited-requests", "many"}, "invalid -alert-rate-limited-requests"},
		{[]string{"-rate-limit", "10/1m", "-alert-webhook", "http://127.0.0.1:1/x"}, "-alert-webhook and -alert-command require an -alert-rate-limited-* threshold"},
		{[]string{"-rate-limit", "10/1m", "-alert-rate-limited-client", "10/1m", "-alert-notify-rate-limit", "off"}, "-alert-notify-rate-limit requires -alert-webhook or -alert-command"},
	} {
		out, err := runWAF(t, tc.args...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%q: %v, output %s", tc.args, err, out)
		}
	}
}
