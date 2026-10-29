package waf

import (
	"net/http/httptest"
	"testing"
)

func TestClientIP(t *testing.T) {
	tp, err := ParseTrustedProxies("10.0.0.0/8, 192.0.2.1")
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		trusted TrustedProxies
		remote  string
		xff     []string
		want    string
	}{
		{"no proxy", tp, "203.0.113.7:5555", nil, "203.0.113.7"},
		{"untrusted peer, spoofed XFF ignored", tp, "203.0.113.7:5555", []string{"1.2.3.4"}, "203.0.113.7"},
		{"no trusted proxies configured", nil, "10.0.0.1:5555", []string{"1.2.3.4"}, "10.0.0.1"},
		{"trusted peer", tp, "10.0.0.1:5555", []string{"203.0.113.7"}, "203.0.113.7"},
		{"chain of trusted proxies", tp, "10.0.0.1:5555", []string{"203.0.113.7, 192.0.2.1, 10.1.1.1"}, "203.0.113.7"},
		{"client-supplied XFF prefix ignored", tp, "10.0.0.1:5555", []string{"1.2.3.4, 203.0.113.7"}, "203.0.113.7"},
		{"multiple XFF headers", tp, "10.0.0.1:5555", []string{"1.2.3.4", "203.0.113.7"}, "203.0.113.7"},
		{"all hops trusted", tp, "10.0.0.1:5555", []string{"10.2.2.2"}, "10.2.2.2"},
		{"malformed hop", tp, "10.0.0.1:5555", []string{"203.0.113.7, garbage"}, "10.0.0.1"},
		{"trusted peer without XFF", tp, "10.0.0.1:5555", nil, "10.0.0.1"},
		{"ipv6 peer", nil, "[2001:db8::1]:5555", nil, "2001:db8::1"},
		{"ipv4-mapped ipv6 peer", tp, "[::ffff:10.0.0.1]:5555", []string{"203.0.113.7"}, "203.0.113.7"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest("GET", "/", nil)
			r.RemoteAddr = tc.remote
			for _, v := range tc.xff {
				r.Header.Add("X-Forwarded-For", v)
			}
			if got := tc.trusted.ClientIP(r); got != tc.want {
				t.Errorf("ClientIP = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestParseTrustedProxiesInvalid(t *testing.T) {
	for _, s := range []string{"10.0.0.0/33", "not-an-ip", "10.0.0.0/8,,bad"} {
		if _, err := ParseTrustedProxies(s); err == nil {
			t.Errorf("ParseTrustedProxies(%q) succeeded, want error", s)
		}
	}
}
