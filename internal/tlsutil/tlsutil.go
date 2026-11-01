// Package tlsutil provides the TLS configuration for PrismWAF: serving
// HTTPS to clients and connecting to HTTPS backends.
package tlsutil

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"slices"
	"strings"
	"sync/atomic"

	"golang.org/x/crypto/acme"
)

// CertPair names the files of a PEM-encoded certificate chain and its
// private key.
type CertPair struct {
	CertFile, KeyFile string
}

// CertReloader serves one or more certificates loaded from files and can
// reload them without a restart, e.g. after a renewal by certbot. With
// several certificates, each connection gets the first one that matches the
// server name requested by the client (SNI). It is safe for concurrent use.
type CertReloader struct {
	pairs []CertPair
	certs atomic.Pointer[[]*tls.Certificate]
}

// NewCertReloader loads the certificates. The first one is the default,
// served to clients whose server name matches none of them.
func NewCertReloader(pairs []CertPair) (*CertReloader, error) {
	if len(pairs) == 0 {
		return nil, errors.New("tlsutil: no certificates")
	}
	r := &CertReloader{pairs: pairs}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload reads the certificate files again. If any of them cannot be
// loaded, all current certificates stay in use and an error is returned.
func (r *CertReloader) Reload() error {
	certs := make([]*tls.Certificate, 0, len(r.pairs))
	for _, p := range r.pairs {
		cert, err := tls.LoadX509KeyPair(p.CertFile, p.KeyFile)
		if err != nil {
			return fmt.Errorf("tlsutil: loading certificate %s: %w", p.CertFile, err)
		}
		certs = append(certs, &cert)
	}
	r.certs.Store(&certs)
	return nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *CertReloader) GetCertificate(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
	certs := *r.certs.Load()
	for _, c := range certs {
		// SupportsCertificate checks the server name as well as the
		// signature algorithms, so RSA and ECDSA certificates for the same
		// name can be combined.
		if hello.SupportsCertificate(c) == nil {
			return c, nil
		}
	}
	return certs[0], nil
}

// ServerOptions configures ServerConfig.
type ServerOptions struct {
	// GetCertificate returns the certificate for a connection, e.g.
	// CertReloader.GetCertificate or autocert.Manager.GetCertificate.
	GetCertificate func(*tls.ClientHelloInfo) (*tls.Certificate, error)
	// ACME enables the TLS-ALPN-01 challenge of an ACME CA. GetCertificate
	// must then be able to answer it, as autocert.Manager does.
	ACME bool
	// ClientCAs and ClientAuth configure client certificate (mutual TLS)
	// authentication; see ParseClientAuth.
	ClientCAs  *x509.CertPool
	ClientAuth tls.ClientAuthType
}

// ServerConfig returns the TLS configuration for serving clients. It
// requires TLS 1.2 or later and otherwise relies on Go's defaults, which
// only enable secure cipher suites. HTTP/2 is negotiated automatically by
// net/http.
func ServerConfig(o ServerOptions) *tls.Config {
	cfg := &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: o.GetCertificate,
		ClientCAs:      o.ClientCAs,
		ClientAuth:     o.ClientAuth,
	}
	if !o.ACME {
		return cfg
	}
	cfg.NextProtos = []string{"h2", "http/1.1", acme.ALPNProto}
	if o.ClientAuth != tls.NoClientCert {
		// The CA's validation connection does not present a client
		// certificate. It only offers acme-tls/1, for which net/http has no
		// handler and closes the connection after the handshake, so no
		// request can be sent on such a connection.
		challenge := cfg.Clone()
		challenge.ClientAuth = tls.NoClientCert
		challenge.ClientCAs = nil
		challenge.NextProtos = []string{acme.ALPNProto}
		cfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			if slices.Equal(hello.SupportedProtos, []string{acme.ALPNProto}) {
				return challenge, nil
			}
			return nil, nil
		}
	}
	return cfg
}

// ParseClientAuth parses a client certificate mode: "" or "none" disables
// client certificates, "require" rejects clients without a valid one, and
// "optional" verifies a certificate only if the client sends one.
func ParseClientAuth(s string) (tls.ClientAuthType, error) {
	switch s {
	case "", "none":
		return tls.NoClientCert, nil
	case "require":
		return tls.RequireAndVerifyClientCert, nil
	case "optional":
		return tls.VerifyClientCertIfGiven, nil
	}
	return tls.NoClientCert, fmt.Errorf("tlsutil: invalid client auth mode %q: must be \"none\", \"require\" or \"optional\"", s)
}

// LoadCAs reads a file of PEM-encoded CA certificates.
func LoadCAs(file string) (*x509.CertPool, error) {
	pem, err := os.ReadFile(file)
	if err != nil {
		return nil, fmt.Errorf("tlsutil: reading CA file: %w", err)
	}
	pool := x509.NewCertPool()
	if !pool.AppendCertsFromPEM(pem) {
		return nil, fmt.Errorf("tlsutil: no PEM certificates found in %s", file)
	}
	return pool, nil
}

// BackendConfig returns the TLS configuration for connecting to an HTTPS
// backend. If caFile is set, the backend certificate must be signed by one
// of the PEM-encoded CAs in it instead of a system-trusted CA. insecure
// disables certificate verification entirely and should only be used for
// testing.
func BackendConfig(caFile string, insecure bool) (*tls.Config, error) {
	if caFile != "" && insecure {
		return nil, errors.New("tlsutil: a backend CA and skipping verification are mutually exclusive")
	}
	cfg := &tls.Config{
		MinVersion:         tls.VersionTLS12,
		InsecureSkipVerify: insecure,
	}
	if caFile != "" {
		pool, err := LoadCAs(caFile)
		if err != nil {
			return nil, err
		}
		cfg.RootCAs = pool
	}
	return cfg, nil
}

// RedirectHandler redirects every request to the same host and URI over
// HTTPS on httpsPort. It uses 308 Permanent Redirect so that clients keep
// the method and body.
func RedirectHandler(httpsPort string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		// Reduce the Host header to a bare host name or IP address.
		host := r.Host
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		} else {
			host = strings.TrimSuffix(strings.TrimPrefix(host, "["), "]")
		}
		if host == "" {
			http.Error(w, "missing Host header", http.StatusBadRequest)
			return
		}
		if httpsPort != "" && httpsPort != "443" {
			host = net.JoinHostPort(host, httpsPort)
		} else if strings.Contains(host, ":") {
			host = "[" + host + "]" // IPv6 literal
		}
		http.Redirect(w, r, "https://"+host+r.URL.RequestURI(), http.StatusPermanentRedirect)
	})
}
