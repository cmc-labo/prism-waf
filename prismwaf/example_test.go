package prismwaf_test

import (
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
