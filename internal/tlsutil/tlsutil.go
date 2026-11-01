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
	"strings"
	"sync/atomic"
)

// CertReloader serves a certificate loaded from files and can reload it
// without a restart, e.g. after a renewal by certbot. It is safe for
// concurrent use.
type CertReloader struct {
	certFile, keyFile string
	cert              atomic.Pointer[tls.Certificate]
}

// NewCertReloader loads the PEM-encoded certificate chain and private key.
func NewCertReloader(certFile, keyFile string) (*CertReloader, error) {
	r := &CertReloader{certFile: certFile, keyFile: keyFile}
	if err := r.Reload(); err != nil {
		return nil, err
	}
	return r, nil
}

// Reload reads the certificate files again. If they cannot be loaded, the
// current certificate stays in use and an error is returned.
func (r *CertReloader) Reload() error {
	cert, err := tls.LoadX509KeyPair(r.certFile, r.keyFile)
	if err != nil {
		return fmt.Errorf("tlsutil: loading certificate: %w", err)
	}
	r.cert.Store(&cert)
	return nil
}

// GetCertificate implements tls.Config.GetCertificate.
func (r *CertReloader) GetCertificate(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return r.cert.Load(), nil
}

// ServerConfig returns the TLS configuration for serving clients. It
// requires TLS 1.2 or later and otherwise relies on Go's defaults, which
// only enable secure cipher suites. HTTP/2 is negotiated automatically by
// net/http.
func ServerConfig(certs *CertReloader) *tls.Config {
	return &tls.Config{
		MinVersion:     tls.VersionTLS12,
		GetCertificate: certs.GetCertificate,
	}
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
		pem, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("tlsutil: reading backend CA: %w", err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("tlsutil: no PEM certificates found in %s", caFile)
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
