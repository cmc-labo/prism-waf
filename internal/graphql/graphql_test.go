package graphql

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"
)

func newGuard(t *testing.T, cfg Config) *Guard {
	t.Helper()
	if cfg.Paths == nil {
		cfg.Paths = []string{"/graphql"}
	}
	g, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return g
}

// post returns a POST of a JSON body.
func post(body string) (*http.Request, []byte) {
	r := httptest.NewRequest(http.MethodPost, "/graphql", strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	return r, []byte(body)
}

func check(g *Guard, body string) (*Violation, []Value) {
	r, b := post(body)
	return g.Check(r, b)
}

func TestLimits(t *testing.T) {
	g := newGuard(t, Config{MaxDepth: 3, MaxAliases: 2, MaxFields: 6, MaxBatch: 2})
	for _, tc := range []struct {
		name, body string
		kind       string
		limit, val int
		operation  string
	}{
		{"ok", `{"query":"{ a { b { c } } }"}`, "", 0, 0, ""},
		{"depth", `{"query":"query Deep { a { b { c { d } } } }"}`, ViolationDepth, 3, 4, "query Deep"},
		{"depth in fragment", `{"query":"{ a { ...F } } fragment F on T { b { c { d } } }"}`, ViolationDepth, 3, 4, "query"},
		{"depth in inline fragment", `{"query":"{ a { ... on T { b { c { d } } } } }"}`, ViolationDepth, 3, 4, "query"},
		{"aliases", `{"query":"mutation { a: login(p:\"1\") b: login(p:\"2\") c: login(p:\"3\") }"}`, ViolationAliases, 2, 3, "mutation"},
		{"same name is no alias", `{"query":"{ a: a b: b }"}`, "", 0, 0, ""},
		{"fields", `{"query":"{ a b c d e f g }"}`, ViolationFields, 6, 7, "query"},
		// A fragment counts each time it is used.
		{"fields of fragments", `{"query":"{ x { ...F } y { ...F } z } fragment F on T { a b }"}`, ViolationFields, 6, 7, "query"},
		{"fields of operations", `{"query":"query A { a b c } query B { d e f g }"}`, ViolationFields, 6, 7, "query B"},
		{"fields of a batch", `[{"query":"{ a b c d }"},{"query":"{ e f g }"}]`, ViolationFields, 6, 7, "query"},
		{"batch", `[{"query":"{a}"},{"query":"{b}"},{"query":"{c}"}]`, ViolationBatch, 2, 3, ""},
		{"introspection", `{"query":"{ __schema { types { name } } }"}`, ViolationIntrospection, 0, 0, "query"},
		{"introspection type", `{"query":"{ a { __type(name:\"User\") { name } } }"}`, ViolationIntrospection, 0, 0, "query"},
		{"typename", `{"query":"{ a { __typename } }"}`, "", 0, 0, ""},
		{"syntax", `{"query":"{ a { b }"}`, ViolationInvalid, 0, 0, ""},
		{"fragment cycle", `{"query":"{ ...A } fragment A on T { ...B } fragment B on T { ...A }"}`, ViolationInvalid, 0, 0, "query"},
		{"unknown fragment", `{"query":"{ ...A }"}`, ViolationInvalid, 0, 0, "query"},
		{"not JSON", `query { a }`, ViolationInvalid, 0, 0, ""},
		{"no query", `{"variables":{}}`, ViolationInvalid, 0, 0, ""},
		{"persisted query", `{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"abc"}}}`, "", 0, 0, ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v, _ := check(g, tc.body)
			if tc.kind == "" {
				if v != nil {
					t.Fatalf("violation %+v", v)
				}
				return
			}
			if v == nil || v.Kind != tc.kind || v.Limit != tc.limit || v.Value != tc.val || v.Operation != tc.operation || v.Message == "" {
				t.Fatalf("violation %+v", v)
			}
		})
	}
}

// TestFragmentBomb checks that fragments that expand exponentially are
// counted without being expanded.
func TestFragmentBomb(t *testing.T) {
	q := "{ ...F0 }"
	for i := range 40 {
		q += " fragment F" + itoa(i) + " on T { a: x { ...F" + itoa(i+1) + " } b: x { ...F" + itoa(i+1) + " } }"
	}
	q += " fragment F40 on T { y }"
	// 2^41 fields, counted in a few microseconds, and capped.
	g := newGuard(t, Config{MaxDepth: 100, MaxAliases: 1 << 50, MaxFields: 1000})
	v, _ := check(g, `{"query":`+quote(q)+`}`)
	if v == nil || v.Kind != ViolationFields || v.Value != maxCount {
		t.Fatalf("violation %+v", v)
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

func quote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func TestIntrospectionAllowed(t *testing.T) {
	g := newGuard(t, Config{Introspection: true})
	if v, _ := check(g, `{"query":"{ __schema { types { name } } }"}`); v != nil {
		t.Fatalf("violation %+v", v)
	}
}

func TestSchema(t *testing.T) {
	path := filepath.Join(t.TempDir(), "schema.graphql")
	os.WriteFile(path, []byte(`
type Query { user(id: ID!): User }
type User { id: ID! name: String posts(first: Int): [Post] }
type Post { title: String }
`), 0o644)
	schema, err := LoadSchema([]string{path})
	if err != nil {
		t.Fatal(err)
	}
	g := newGuard(t, Config{Schema: schema})
	if v, _ := check(g, `{"query":"{ user(id: 1) { name posts(first: 2) { title } } }"}`); v != nil {
		t.Fatalf("valid query: %+v", v)
	}
	for _, q := range []string{
		`{ user(id: 1) { password } }`,
		`{ user { name } }`,
		`{ admin { name } }`,
		`mutation { deleteUser(id: 1) }`,
	} {
		v, _ := check(g, `{"query":`+quote(q)+`}`)
		if v == nil || v.Kind != ViolationSchema || v.Message == "" {
			t.Errorf("%s: violation %+v", q, v)
		}
	}
	// Introspection is valid for every schema, but still blocked.
	if v, _ := check(g, `{"query":"{ __schema { types { name } } }"}`); v == nil || v.Kind != ViolationIntrospection {
		t.Errorf("introspection: %+v", v)
	}

	os.WriteFile(path, []byte(`type Query { user: Unknown }`), 0o644)
	if _, err := LoadSchema([]string{path}); err == nil || !strings.Contains(err.Error(), "invalid schema") {
		t.Errorf("invalid schema: %v", err)
	}
}

func TestValues(t *testing.T) {
	g := newGuard(t, Config{})
	q := `query Q($n: String = "default") @log(tag: "op") {
		user(name: "alice", filter: {city: "Tokyo", tags: ["a", "b"]}, order: DESC) @include(if: true) {
			posts(q: """block""") { ...P }
		}
		other: user(name: "bob") { id }
	}
	fragment P on Post @x(y: "frag") { title(lang: "en") }`
	v, values := check(g, `{"query":`+quote(q)+`}`)
	if v != nil {
		t.Fatal(v)
	}
	var got []string
	for _, val := range values {
		got = append(got, val.Path+"="+val.Value)
	}
	want := []string{
		"$n=default",
		"query Q@log(tag)=op",
		"user(name)=alice",
		"user(filter.city)=Tokyo",
		"user(filter.tags[0])=a",
		"user(filter.tags[1])=b",
		"user(order)=DESC",
		"user.posts(q)=block",
		"other(name)=bob",
		"...P@x(y)=frag",
		"...P.title(lang)=en",
	}
	if !slices.Equal(got, want) {
		t.Errorf("values\n%q\nwant\n%q", got, want)
	}
}

// TestRequests checks the forms of GraphQL requests.
func TestRequests(t *testing.T) {
	g := newGuard(t, Config{MaxDepth: 1})
	deep := "{ a { b } }"
	for _, tc := range []struct {
		name        string
		method      string
		target      string
		contentType string
		body        string
	}{
		{"GET", http.MethodGet, "/graphql?query=" + url.QueryEscape(deep), "", ""},
		{"application/graphql", http.MethodPost, "/graphql", "application/graphql", deep},
		{"form", http.MethodPost, "/graphql", "application/x-www-form-urlencoded", "query=" + url.QueryEscape(deep)},
		{"JSON as text/plain", http.MethodPost, "/graphql", "text/plain", `{"query":` + quote(deep) + `}`},
		{"multipart", http.MethodPost, "/graphql", "multipart/form-data; boundary=XX",
			"--XX\r\nContent-Disposition: form-data; name=\"operations\"\r\n\r\n{\"query\":" + quote(deep) + "}\r\n--XX\r\nContent-Disposition: form-data; name=\"0\"; filename=\"a.txt\"\r\n\r\nfile\r\n--XX--\r\n"},
		// Both the URL and the body: servers differ in which they use.
		{"URL and body", http.MethodPost, "/graphql?query=" + url.QueryEscape("{ a }"), "application/json", `{"query":` + quote(deep) + `}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := httptest.NewRequest(tc.method, tc.target, strings.NewReader(tc.body))
			if tc.contentType != "" {
				r.Header.Set("Content-Type", tc.contentType)
			}
			if v, _ := g.Check(r, []byte(tc.body)); v == nil || v.Kind != ViolationDepth {
				t.Errorf("violation %+v", v)
			}
		})
	}
	// Not GraphQL requests: an IDE page, and an empty POST.
	for _, r := range []*http.Request{
		httptest.NewRequest(http.MethodGet, "/graphql", nil),
		httptest.NewRequest(http.MethodPost, "/graphql", nil),
	} {
		if v, values := g.Check(r, nil); v != nil || values != nil {
			t.Errorf("%s: %+v", r.Method, v)
		}
	}
}

func TestHandles(t *testing.T) {
	g := newGuard(t, Config{Paths: []string{"/graphql", "/api/*"}})
	for path, want := range map[string]bool{
		"/graphql": true, "/GraphQL": true, "/graphql/": true, "//graphql": true, "/x/../graphql": true,
		"/api": true, "/api/v2/graphql": true, "/apis": false, "/graphql2": false, "/": false,
	} {
		if got := g.Handles(path); got != want {
			t.Errorf("Handles(%q) = %v", path, got)
		}
	}
	for _, cfg := range []Config{
		{},
		{Paths: []string{"graphql"}},
		{Paths: []string{"POST /graphql"}},
		{Paths: []string{"/graphql"}, MaxDepth: -1},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
}

func BenchmarkCheck(b *testing.B) {
	g, _ := New(Config{Paths: []string{"/graphql"}})
	body := []byte(`{"query":"query GetUser($id: ID!) { user(id: $id) { id name email posts(first: 10, orderBy: \"date\") { title body comments { author text } } } }","variables":{"id":"1"}}`)
	r := httptest.NewRequest(http.MethodPost, "/graphql", nil)
	r.Header.Set("Content-Type", "application/json")
	for b.Loop() {
		g.Check(r, body)
	}
}

// TestDeepQuery sends the deepest query that fits in the default body
// limit. The parser rejects queries nested more than 1000 deep, before
// they can cost much.
func TestDeepQuery(t *testing.T) {
	n := 128 << 10 / 4
	q := strings.Repeat("{a ", n) + strings.Repeat("}", n)
	g := newGuard(t, Config{})
	start := time.Now()
	v, _ := check(g, `{"query":`+quote(q)+`}`)
	if v == nil || v.Kind != ViolationInvalid || !strings.Contains(v.Message, "nesting depth") {
		t.Fatalf("violation %+v", v)
	}
	if d := time.Since(start); d > 100*time.Millisecond {
		t.Errorf("took %v", d)
	}
	q = strings.Repeat("{a ", 999) + strings.Repeat("}", 999)
	if v, _ := check(g, `{"query":`+quote(q)+`}`); v == nil || v.Kind != ViolationDepth || v.Value != 999 {
		t.Fatalf("violation %+v", v)
	}
}
