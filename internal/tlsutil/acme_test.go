package tlsutil

import (
	"context"
	"testing"
)

func TestNewACMEManager(t *testing.T) {
	m, err := NewACMEManager(ACMEConfig{
		Domains:  []string{"example.com", "www.example.com"},
		CacheDir: t.TempDir(),
		Email:    "admin@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	// Only the configured domains may trigger a certificate request.
	for host, allowed := range map[string]bool{
		"example.com":      true,
		"www.example.com":  true,
		"evil.example.com": false,
		"example.org":      false,
	} {
		if err := m.HostPolicy(context.Background(), host); (err == nil) != allowed {
			t.Errorf("HostPolicy(%q) = %v, allowed %v", host, err, allowed)
		}
	}
	if m.Client != nil {
		t.Error("default directory: Client should be nil (Let's Encrypt)")
	}

	m, _ = NewACMEManager(ACMEConfig{Domains: []string{"example.com"}, CacheDir: "c", DirectoryURL: LetsEncryptStaging})
	if m.Client == nil || m.Client.DirectoryURL != LetsEncryptStaging {
		t.Error("custom directory URL not used")
	}

	for _, c := range []ACMEConfig{
		{CacheDir: "c"},
		{Domains: []string{"example.com"}},
		{Domains: []string{"*.example.com"}, CacheDir: "c"},
		{Domains: []string{"192.0.2.1"}, CacheDir: "c"},
		{Domains: []string{""}, CacheDir: "c"},
	} {
		if _, err := NewACMEManager(c); err == nil {
			t.Errorf("NewACMEManager(%+v) succeeded", c)
		}
	}
}
