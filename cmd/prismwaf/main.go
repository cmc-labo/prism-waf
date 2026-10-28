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

	"github.com/cmc-labo/prism-waf/internal/proxy"
	"github.com/cmc-labo/prism-waf/internal/waf"
)

func main() {
	listen := flag.String("listen", ":8080", "address to listen on")
	backend := flag.String("backend", "http://127.0.0.1:8081", "backend server URL")
	maxBody := flag.Int64("max-body", waf.DefaultMaxBodySize, "maximum request body size in bytes to inspect; larger requests are rejected")
	flag.Parse()

	logger := slog.New(slog.NewTextHandler(os.Stderr, nil))
	if err := run(*listen, *backend, *maxBody, logger); err != nil {
		logger.Error("prismwaf exited with error", "error", err)
		os.Exit(1)
	}
}

func run(listen, backend string, maxBody int64, logger *slog.Logger) error {
	u, err := proxy.ParseBackend(backend)
	if err != nil {
		return err
	}
	rp, err := proxy.New(u, logger)
	if err != nil {
		return err
	}
	inspector, err := waf.NewInspector(waf.DefaultSignatures, maxBody)
	if err != nil {
		return err
	}

	srv := &http.Server{
		Addr:              listen,
		Handler:           waf.Middleware(rp, inspector, logger),
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	errCh := make(chan error, 1)
	go func() {
		logger.Info("prismwaf started", "listen", listen, "backend", u.String())
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
