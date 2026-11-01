package main

import (
	"testing"
	"time"

	"github.com/cmc-labo/prism-waf/internal/tlsutil"
)

func TestConfigValidate(t *testing.T) {
	https := func(c config) config {
		c.tlsCerts, c.tlsKeys = stringList{"c.pem"}, stringList{"k.pem"}
		return c
	}
	year := 365 * 24 * time.Hour
	tests := []struct {
		name    string
		cfg     config
		wantErr bool
	}{
		{"plain HTTP", config{}, false},
		{"HTTPS", https(config{}), false},
		{"HTTPS with redirect", https(config{httpRedirect: ":80"}), false},
		{"SNI certificates", config{tlsCerts: stringList{"a.pem", "b.pem"}, tlsKeys: stringList{"a.key", "b.key"}}, false},
		{"cert without key", config{tlsCerts: stringList{"c.pem"}}, true},
		{"key without cert", config{tlsKeys: stringList{"k.pem"}}, true},
		{"fewer keys than certs", config{tlsCerts: stringList{"a.pem", "b.pem"}, tlsKeys: stringList{"a.key"}}, true},
		{"redirect without TLS", config{httpRedirect: ":80"}, true},

		{"ACME", config{acmeDomains: "example.com", acmeCache: "/var/cache/prismwaf"}, false},
		{"ACME with redirect", config{acmeDomains: "example.com", acmeCache: "c", httpRedirect: ":80"}, false},
		{"ACME without cache", config{acmeDomains: "example.com"}, true},
		{"ACME and certificate files", https(config{acmeDomains: "example.com", acmeCache: "c"}), true},
		{"ACME email without domains", config{acmeEmail: "admin@example.com"}, true},

		{"HSTS", https(config{hsts: tlsutil.HSTSPolicy{MaxAge: year}}), false},
		{"HSTS preload", https(config{hsts: tlsutil.HSTSPolicy{MaxAge: year, IncludeSubdomains: true, Preload: true}}), false},
		{"HSTS without TLS", config{hsts: tlsutil.HSTSPolicy{MaxAge: year}}, true},
		{"HSTS preload too short", https(config{hsts: tlsutil.HSTSPolicy{MaxAge: time.Hour, IncludeSubdomains: true, Preload: true}}), true},
		{"HSTS subdomains without max-age", https(config{hsts: tlsutil.HSTSPolicy{IncludeSubdomains: true}}), true},

		{"client CA", https(config{clientCA: "ca.pem"}), false},
		{"client CA optional", https(config{clientCA: "ca.pem", clientAuth: "optional"}), false},
		{"client CA without TLS", config{clientCA: "ca.pem"}, true},
		{"client auth without CA", https(config{clientAuth: "require"}), true},
		{"invalid client auth", https(config{clientCA: "ca.pem", clientAuth: "maybe"}), true},
	}
	for _, tc := range tests {
		if err := tc.cfg.validate(); (err != nil) != tc.wantErr {
			t.Errorf("%s: validate() = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestStringListFlag(t *testing.T) {
	var l stringList
	l.Set("a.pem")
	l.Set("b.pem")
	if len(l) != 2 || l.String() != "a.pem,b.pem" {
		t.Errorf("stringList = %v", l)
	}
}

func TestSplitList(t *testing.T) {
	got := splitList(" example.com, ,www.example.com,")
	if len(got) != 2 || got[0] != "example.com" || got[1] != "www.example.com" {
		t.Errorf("splitList = %q", got)
	}
}
