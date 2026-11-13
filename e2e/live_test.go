//go:build e2e

package e2e

import (
	"os"
	"testing"
)

// TestLiveVerifiedBots verifies real crawler addresses with DNS. The
// addresses come from the ranges the operators publish and may change.
func TestLiveVerifiedBots(t *testing.T) {
	if os.Getenv("PRISMWAF_E2E_LIVE") == "" {
		t.Skip("set PRISMWAF_E2E_LIVE=1 to look up crawler addresses in DNS")
	}
	w := startWAF(t, wafOptions{args: []string{"-trusted-proxies", "127.0.0.1"}})
	for _, tc := range []struct {
		name, ua, ip string
	}{
		{"Googlebot", googleUA, "66.249.66.1"},
		{"Bingbot", "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)", "157.55.39.1"},
	} {
		h := w.client(t, xff(map[string]string{"User-Agent": tc.ua}, tc.ip)).get("/").hit(t)
		if h.Verified != "true" || h.Category != "search_engine" || h.Score != "50" {
			t.Errorf("%s from %s: backend saw %+v", tc.name, tc.ip, h)
		}
		// The same User-Agent from another address is an impostor.
		parseChallenge(t, w.client(t, xff(map[string]string{"User-Agent": tc.ua}, "203.0.113.9")).get("/"))
	}
}
