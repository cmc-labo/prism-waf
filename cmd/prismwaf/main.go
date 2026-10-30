// Command prismwaf runs the PrismWAF reverse proxy.
package main

import (
	"context"
	"errors"
	"flag"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/cmc-labo/prism-waf/internal/audit"
	"github.com/cmc-labo/prism-waf/internal/proxy"
	"github.com/cmc-labo/prism-waf/internal/waf"
)

func main() {
	listen := flag.String("listen", ":8080", "address to listen on")
	backend := flag.String("backend", "http://127.0.0.1:8081", "backend server URL")
	maxBody := flag.Int64("max-body", waf.DefaultMaxBodySize, "maximum request body size in bytes to inspect; larger requests are rejected")
	mode := flag.String("mode", string(waf.ModeBlock), `"block" to reject detected requests, "detect" to only log them`)
	auditLog := flag.String("audit-log", "-", `file to append audit events (JSON Lines) to; "-" for standard output`)
	trustedProxies := flag.String("trusted-proxies", "", "comma-separated IPs or CIDRs of proxies whose X-Forwarded-For is trusted")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	cfg := config{
		listen:         *listen,
		backend:        *backend,
		maxBody:        *maxBody,
		mode:           *mode,
		auditLog:       *auditLog,
		trustedProxies: *trustedProxies,
	}
	if err := run(cfg, logger); err != nil {
		logger.Error("prismwaf exited with error", "error", err)
		os.Exit(1)
	}
}

type config struct {
	listen         string
	backend        string
	maxBody        int64
	mode           string
	auditLog       string
	trustedProxies string
}

func run(cfg config, logger *slog.Logger) error {
	u, err := proxy.ParseBackend(cfg.backend)
	if err != nil {
		return err
	}
	rp, err := proxy.New(u, logger)
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("prismwaf started", "listen", cfg.listen, "backend", u.String(), "mode", mode, "audit_log", cfg.auditLog)
		if mode == waf.ModeDetect {
			logger.Warn("detection mode: attacks are logged but NOT blocked")
		}
		errCh <- srv.ListenAndServe()
	}()

	select {
	case err := <-errCh:
		if !errors.Is(err, http.ErrServerClosed) {
			return err
		}
		return nil
	case <-ctx.Done():
	}

	logger.Info("shutting down")
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	return srv.Shutdown(shutdownCtx)
}
