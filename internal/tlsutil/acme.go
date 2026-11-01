package tlsutil

import (
	"errors"
	"fmt"
	"net"
	"strings"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
)

// LetsEncryptStaging is the directory URL of Let's Encrypt's staging
// environment, which has higher rate limits but issues untrusted
// certificates. Use it to test an ACME setup.
const LetsEncryptStaging = "https://acme-staging-v02.api.letsencrypt.org/directory"

// ACMEConfig configures automatic certificates from an ACME CA such as
// Let's Encrypt.
type ACMEConfig struct {
	// Domains are the only host names certificates are requested for.
	// Restricting them prevents clients from triggering requests for
	// arbitrary names, which would exhaust the CA's rate limits.
	Domains []string
	// CacheDir stores the account key and the certificates, so that they
	// survive restarts. It holds private keys and is created with mode 0700.
	CacheDir string
	// Email is the optional contact address for the CA's expiry notices.
	Email string
	// DirectoryURL is the CA's ACME directory; empty means Let's Encrypt.
	DirectoryURL string
}

// NewACMEManager returns a manager that obtains and renews certificates for
// the configured domains. Using it means agreeing to the CA's terms of
// service. The manager answers the TLS-ALPN-01 challenge through
// GetCertificate (see ServerOptions.ACME) and the HTTP-01 challenge through
// HTTPHandler, which must be served on port 80.
func NewACMEManager(c ACMEConfig) (*autocert.Manager, error) {
	if len(c.Domains) == 0 {
		return nil, errors.New("tlsutil: ACME requires at least one domain")
	}
	for _, d := range c.Domains {
		switch {
		case d == "":
			return nil, errors.New("tlsutil: empty ACME domain")
		case strings.Contains(d, "*"):
			return nil, fmt.Errorf("tlsutil: ACME domain %q: wildcard certificates are not supported", d)
		case net.ParseIP(d) != nil:
			return nil, fmt.Errorf("tlsutil: ACME domain %q: IP addresses are not supported", d)
		}
	}
	if c.CacheDir == "" {
		return nil, errors.New("tlsutil: ACME requires a cache directory")
	}
	m := &autocert.Manager{
		Prompt:     autocert.AcceptTOS,
		HostPolicy: autocert.HostWhitelist(c.Domains...),
		Cache:      autocert.DirCache(c.CacheDir),
		Email:      c.Email,
	}
	if c.DirectoryURL != "" {
		m.Client = &acme.Client{DirectoryURL: c.DirectoryURL}
	}
	return m, nil
}
