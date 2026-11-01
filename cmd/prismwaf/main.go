// Command prismwaf runs the PrismWAF reverse proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cmc-labo/prism-waf/internal/audit"
	"github.com/cmc-labo/prism-waf/internal/proxy"
	"github.com/cmc-labo/prism-waf/internal/tlsutil"
	"github.com/cmc-labo/prism-waf/internal/waf"
)

func main() {
	var cfg config
	flag.StringVar(&cfg.listen, "listen", ":8080", "address to listen on")
	flag.StringVar(&cfg.backend, "backend", "http://127.0.0.1:8081", "backend server URL (http:// or https://)")
	flag.Int64Var(&cfg.maxBody, "max-body", waf.DefaultMaxBodySize, "maximum request body size in bytes to inspect; larger requests are rejected")
	flag.StringVar(&cfg.mode, "mode", string(waf.ModeBlock), `"block" to reject detected requests, "detect" to only log them`)
	flag.StringVar(&cfg.auditLog, "audit-log", "-", `file to append audit events (JSON Lines) to; "-" for standard output`)
	flag.StringVar(&cfg.trustedProxies, "trusted-proxies", "", "comma-separated IPs or CIDRs of proxies whose X-Forwarded-For is trusted")
	flag.StringVar(&cfg.tlsCert, "tls-cert", "", "PEM certificate chain file; enables HTTPS on -listen (requires -tls-key)")
	flag.StringVar(&cfg.tlsKey, "tls-key", "", "PEM private key file for -tls-cert")
	flag.StringVar(&cfg.httpRedirect, "http-redirect", "", `address of a plain HTTP listener that redirects to HTTPS, e.g. ":80" (requires -tls-cert)`)
	flag.StringVar(&cfg.backendCA, "backend-ca", "", "PEM CA file to verify an https:// backend with, instead of the system CAs")
	flag.BoolVar(&cfg.backendInsecure, "backend-insecure-skip-verify", false, "do not verify the https:// backend certificate (testing only)")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(cfg, logger); err != nil {
		logger.Error("prismwaf exited with error", "error", err)
		os.Exit(1)
	}
}

type config struct {
	listen          string
	backend         string
	maxBody         int64
	mode            string
	auditLog        string
	trustedProxies  string
	tlsCert         string
	tlsKey          string
	httpRedirect    string
	backendCA       string
	backendInsecure bool
}

func (c config) tlsEnabled() bool { return c.tlsCert != "" }

func (c config) validate() error {
	if (c.tlsCert == "") != (c.tlsKey == "") {
		return errors.New("-tls-cert and -tls-key must be set together")
	}
	if c.httpRedirect != "" && !c.tlsEnabled() {
		return errors.New("-http-redirect requires -tls-cert and -tls-key")
	}
	return nil
}

func run(cfg config, logger *slog.Logger) error {
	if err := cfg.validate(); err != nil {
		return err
	}
	u, err := proxy.ParseBackend(cfg.backend)
	if err != nil {
		return err
	}
	transport, err := backendTransport(cfg)
	if err != nil {
		return err
	}
	rp, err := proxy.New(u, transport, logger)
	if err != nil {
		return err
	}
	inspector, err := waf.NewInspector(waf.DefaultSignatures, cfg.maxBody)
	if err != nil {
		return err
	}
	mode, err := waf.ParseMode(cfg.mode)
	if err != nil {
		return err
	}
	tp, err := waf.ParseTrustedProxies(cfg.trustedProxies)
	if err != nil {
		return err
	}
	auditLogger, closeAudit, err := audit.Open(cfg.auditLog)
	if err != nil {
		return err
	}
	defer closeAudit.Close()

	srv := &http.Server{
		Addr: cfg.listen,
		Handler: waf.Middleware(rp, waf.Config{
			Inspector:      inspector,
			Mode:           mode,
			Audit:          auditLogger,
			TrustedProxies: tp,
			Logger:         logger,
		}),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}
	servers := []*http.Server{srv}

	var certs *tlsutil.CertReloader
	if cfg.tlsEnabled() {
		certs, err = tlsutil.NewCertReloader(cfg.tlsCert, cfg.tlsKey)
		if err != nil {
			return err
		}
		srv.TLSConfig = tlsutil.ServerConfig(certs)
		if cfg.httpRedirect != "" {
			_, httpsPort, err := net.SplitHostPort(cfg.listen)
			if err != nil {
				return fmt.Errorf("invalid -listen address %q: %w", cfg.listen, err)
			}
			servers = append(servers, &http.Server{
				Addr:              cfg.httpRedirect,
				Handler:           tlsutil.RedirectHandler(httpsPort),
				ReadHeaderTimeout: 10 * time.Second,
				IdleTimeout:       120 * time.Second,
			})
		}
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if certs != nil {
		go reloadOnSIGHUP(ctx, certs, logger)
	}

	scheme := "http"
	if cfg.tlsEnabled() {
		scheme = "https"
	}
	logger.Info("prismwaf started", "listen", cfg.listen, "scheme", scheme, "backend", u.String(), "mode", mode, "audit_log", cfg.auditLog)
	if cfg.httpRedirect != "" {
		logger.Info("redirecting HTTP to HTTPS", "listen", cfg.httpRedirect)
	}
	if mode == waf.ModeDetect {
		logger.Warn("detection mode: attacks are logged but NOT blocked")
	}
	if cfg.backendInsecure {
		logger.Warn("backend certificate verification is disabled")
	}

	errCh := make(chan error, len(servers))
	for _, s := range servers {
		go func() {
			if s.TLSConfig != nil {
				// The certificate comes from TLSConfig.GetCertificate.
				errCh <- s.ListenAndServeTLS("", "")
			} else {
				errCh <- s.ListenAndServe()
			}
		}()
	}

	var runErr error
	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	case <-ctx.Done():
		logger.Info("shutting down")
	}

	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	for _, s := range servers {
		if err := s.Shutdown(shutdownCtx); err != nil && runErr == nil {
			runErr = err
		}
	}
	return runErr
}

// backendTransport returns the transport for requests to the backend, or
// nil to use http.DefaultTransport.
func backendTransport(cfg config) (http.RoundTripper, error) {
	if cfg.backendCA == "" && !cfg.backendInsecure {
		return nil, nil
	}
	tlsCfg, err := tlsutil.BackendConfig(cfg.backendCA, cfg.backendInsecure)
	if err != nil {
		return nil, err
	}
	t := http.DefaultTransport.(*http.Transport).Clone()
	t.TLSClientConfig = tlsCfg
	return t, nil
}

// reloadOnSIGHUP reloads the TLS certificate whenever the process receives
// SIGHUP, so that renewed certificates are picked up without a restart.
func reloadOnSIGHUP(ctx context.Context, certs *tlsutil.CertReloader, logger *slog.Logger) {
	hup := make(chan os.Signal, 1)
	signal.Notify(hup, syscall.SIGHUP)
	defer signal.Stop(hup)
	for {
		select {
		case <-ctx.Done():
			return
		case <-hup:
			if err := certs.Reload(); err != nil {
				logger.Error("TLS certificate reload failed; keeping the current certificate", "error", err)
			} else {
				logger.Info("TLS certificate reloaded")
			}
		}
	}
}
