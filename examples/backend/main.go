// Command backend is a tiny echo server used as a backend while developing
// PrismWAF. It responds with the details of every request it receives.
package main

import (
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"sort"
)

func main() {
	listen := flag.String("listen", ":8081", "address to listen on")
	flag.Parse()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)

		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		fmt.Fprintf(w, "%s %s %s\n", r.Method, r.URL.RequestURI(), r.Proto)
		fmt.Fprintf(w, "Host: %s\n", r.Host)

		names := make([]string, 0, len(r.Header))
		for name := range r.Header {
			names = append(names, name)
		}
		sort.Strings(names)
		for _, name := range names {
			for _, v := range r.Header[name] {
				fmt.Fprintf(w, "%s: %s\n", name, v)
			}
		}
		if len(body) > 0 {
			fmt.Fprintf(w, "\n%s\n", body)
		}
	})

	log.Printf("backend listening on %s", *listen)
	log.Fatal(http.ListenAndServe(*listen, nil))
}
