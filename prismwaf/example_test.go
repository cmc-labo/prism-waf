package prismwaf_test

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httptest"

	"github.com/cmc-labo/prism-waf/prismwaf"
)

func Example() {
	mux := http.NewServeMux()
	mux.HandleFunc("/search", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintln(w, "results for", r.URL.Query().Get("q"))
	})

	w, err := prismwaf.New(prismwaf.Options{
		RateLimitPaths: []string{"POST /login=5/1m"},
		AuditLog:       io.Discard, // os.Stdout by default
	})
	if err != nil {
		log.Fatal(err)
	}
	srv := httptest.NewServer(w.Middleware(mux)) // or http.ListenAndServe(":8080", w.Middleware(mux))
	defer srv.Close()

	for _, q := range []string{"shoes", "1'+OR+'1'='1"} {
		res, err := http.Get(srv.URL + "/search?q=" + q)
		if err != nil {
			log.Fatal(err)
		}
		res.Body.Close()
		fmt.Println(q, res.StatusCode)
	}
	// Output:
	// shoes 200
	// 1'+OR+'1'='1 403
}

// Requests to a path over its rate limit get 429 Too Many Requests.
func Example_rateLimit() {
	login := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Error(w, "wrong password", http.StatusUnauthorized)
	})

	w, err := prismwaf.New(prismwaf.Options{
		RateLimitPaths: []string{"POST /login=2/1m"},
		AuditLog:       io.Discard,
	})
	if err != nil {
		log.Fatal(err)
	}
	h := w.Middleware(login)

	for range 3 {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("POST", "/login", nil))
		fmt.Println(rec.Code)
	}
	// Output:
	// 401
	// 401
	// 429
}

// In ModeDetect, attacks are only recorded in the audit log and passed on.
func Example_detectMode() {
	app := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})

	var auditLog bytes.Buffer
	w, err := prismwaf.New(prismwaf.Options{
		Mode:     prismwaf.ModeDetect,
		AuditLog: &auditLog,
	})
	if err != nil {
		log.Fatal(err)
	}

	rec := httptest.NewRecorder()
	w.Middleware(app).ServeHTTP(rec, httptest.NewRequest("GET", "/search?q=1'+OR+'1'='1", nil))

	var event struct {
		Action string `json:"action"`
		Reason string `json:"reason"`
	}
	if err := json.Unmarshal(auditLog.Bytes(), &event); err != nil {
		log.Fatal(err)
	}
	fmt.Println(rec.Code, rec.Body.String())
	fmt.Println(event.Action, event.Reason)
	// Output:
	// 200 ok
	// detect signature
}

// New reports invalid options.
func ExampleNew() {
	_, err := prismwaf.New(prismwaf.Options{RateLimit: "lots"})
	fmt.Println(err != nil)
	// Output:
	// true
}

// Handlers that should not be inspected, such as health checks, can be
// registered outside of the middleware.
func ExampleWAF_Middleware() {
	app := http.NewServeMux()
	app.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "app")
	})

	w, err := prismwaf.New(prismwaf.Options{
		RateLimit: "300/1m",
		// The load balancer in front of the program sets X-Forwarded-For.
		TrustedProxies: []string{"10.0.0.0/8"},
	})
	if err != nil {
		log.Fatal(err)
	}

	root := http.NewServeMux()
	root.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, "ok")
	})
	root.Handle("/", w.Middleware(app))

	log.Fatal(http.ListenAndServe(":8080", root))
}
