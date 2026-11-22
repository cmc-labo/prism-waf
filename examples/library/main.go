// Command library is a small web application that embeds PrismWAF as
// middleware instead of running it in front of the application.
//
//	go run ./examples/library
//	curl 'http://localhost:8080/search?q=shoes'              # 200
//	curl "http://localhost:8080/search?q=1'+OR+'1'='1"       # 403
package main

import (
	"fmt"
	"log"
	"log/slog"
	"net/http"
	"os"
	"time"

	"github.com/cmc-labo/prism-waf/prismwaf"
)

func main() {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /search", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, "results for %q\n", r.URL.Query().Get("q"))
	})
	mux.HandleFunc("POST /login", func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "wrong password", http.StatusUnauthorized)
	})
	// Not inspected: registered on a mux of its own below.
	health := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "ok")
	})

	waf, err := prismwaf.New(prismwaf.Options{
		Engine:         prismwaf.EngineBuiltin,
		RateLimit:      "300/1m",
		RateLimitPaths: []string{"POST /login=5/1m"},
		AuditLog:       os.Stdout,
		Logger:         slog.New(slog.NewTextHandler(os.Stderr, nil)),
	})
	if err != nil {
		log.Fatal(err)
	}

	root := http.NewServeMux()
	root.Handle("/healthz", health)
	root.Handle("/", waf.Middleware(mux))

	srv := &http.Server{
		Addr:              ":8080",
		Handler:           root,
		ReadHeaderTimeout: 10 * time.Second,
		// The query string is inspected like the body, but MaxBodySize does
		// not limit it; the command uses the same limit.
		MaxHeaderBytes: 64 << 10,
	}
	log.Println("listening on", srv.Addr)
	log.Fatal(srv.ListenAndServe())
}
