package main

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cmc-labo/prism-waf/internal/bot"
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
		{"ACME webhook", config{acmeDomains: "example.com", acmeCache: "c", acmeNotifyWebhook: "https://hooks.example.com/x", acmeNotifyFormat: "slack"}, false},
		{"ACME command", config{acmeDomains: "example.com", acmeCache: "c", acmeNotifyCommand: "mail admin", acmeNotifyFormat: "json"}, false},
		{"ACME notification test", config{acmeDomains: "example.com", acmeCache: "c", acmeNotifyCommand: "true", acmeNotifyTest: true}, false},
		{"ACME notification test without target", config{acmeDomains: "example.com", acmeCache: "c", acmeNotifyTest: true}, true},
		{"ACME invalid webhook", config{acmeDomains: "example.com", acmeCache: "c", acmeNotifyWebhook: "hooks.example.com/x"}, true},
		{"ACME invalid webhook format", config{acmeDomains: "example.com", acmeCache: "c", acmeNotifyWebhook: "https://hooks.example.com/x", acmeNotifyFormat: "teams"}, true},
		{"notifications without ACME", config{acmeNotifyWebhook: "https://hooks.example.com/x"}, true},

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

		{"crs", config{engine: "crs"}, false},
		{"both engines with exclusions", config{engine: "both", crsAfter: stringList{"x.conf"}}, false},
		{"invalid engine", config{engine: "modsecurity"}, true},
		{"crs rules without crs", config{crsBefore: stringList{"x.conf"}}, true},

		{"rate limit", config{rateLimit: "300/1m", rateLimitPaths: stringList{"POST /login=5/1m"}, rateLimitExempt: "10.0.0.0/8"}, false},
		{"path rate limit only", config{rateLimitPaths: stringList{"/api/*=100/1m"}}, false},
		{"invalid rate limit", config{rateLimit: "300"}, true},
		{"invalid path rate limit", config{rateLimitPaths: stringList{"login=5/1m"}}, true},
		{"invalid rate limit exemption", config{rateLimit: "300/1m", rateLimitExempt: "office"}, true},
		{"rate limit exemption without limits", config{rateLimitExempt: "10.0.0.0/8"}, true},
		{"negative max clients", config{rateLimit: "300/1m", rateLimitMaxClients: -1}, true},

		{"bot protection", config{botProtection: true, botChallengeScore: 50, botDifficulty: 18, botClearanceTTL: time.Hour}, false},
		{"bot protection with paths", config{botProtection: true, botPaths: stringList{"/articles/*"}, botExemptPaths: stringList{"/api/*"}, botExempt: "10.0.0.0/8", botBlockScore: 90}, false},
		{"bot options without bot protection", config{botExemptPaths: stringList{"/api/*"}}, true},
		{"bot secret without bot protection", config{botSecretFile: "secret"}, true},
		{"invalid bot challenge score", config{botProtection: true, botChallengeScore: 101}, true},
		{"invalid bot block score", config{botProtection: true, botBlockScore: -1}, true},
		{"invalid bot difficulty", config{botProtection: true, botDifficulty: 64}, true},
		{"too short bot clearance", config{botProtection: true, botClearanceTTL: time.Second}, true},
		{"invalid bot path", config{botProtection: true, botPaths: stringList{"articles"}}, true},
		{"invalid bot exemption", config{botProtection: true, botExempt: "office"}, true},

		{"least-conn", config{lbPolicy: "least-conn"}, false},
		{"invalid lb policy", config{lbPolicy: "random"}, true},
		{"negative fail timeout", config{failTimeout: -time.Second}, true},
		{"health check", config{healthPath: "/healthz", healthInterval: time.Second, healthTimeout: time.Second}, false},
		{"relative health check path", config{healthPath: "healthz", healthInterval: time.Second, healthTimeout: time.Second}, true},
		{"zero health check interval", config{healthPath: "/healthz", healthTimeout: time.Second}, true},
	}
	for _, tc := range tests {
		if err := tc.cfg.validate(); (err != nil) != tc.wantErr {
			t.Errorf("%s: validate() = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}

func TestReadBotSecret(t *testing.T) {
	dir := t.TempDir()
	good := filepath.Join(dir, "good")
	os.WriteFile(good, []byte(strings.Repeat("k", bot.MinSecretLength)+"\n"), 0o600)
	short := filepath.Join(dir, "short")
	os.WriteFile(short, []byte("secret\n"), 0o600)
	if b, err := readBotSecret(good); err != nil || len(b) != bot.MinSecretLength {
		t.Errorf("good key: %q, %v", b, err)
	}
	if _, err := readBotSecret(short); err == nil {
		t.Error("short key accepted")
	}
	if _, err := readBotSecret(filepath.Join(dir, "missing")); err == nil {
		t.Error("missing file accepted")
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

func TestBackendURLs(t *testing.T) {
	if got := (config{}).backendURLs(); len(got) != 1 || got[0] != defaultBackend {
		t.Errorf("default = %q", got)
	}
	c := config{backends: stringList{"http://a:1, http://b:2", "http://c:3"}}
	if got := c.backendURLs(); !slices.Equal(got, []string{"http://a:1", "http://b:2", "http://c:3"}) {
		t.Errorf("backendURLs = %q", got)
	}
}
