//go:build e2e

package e2e

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// graphqlBody is the JSON body of a GraphQL request.
func graphqlBody(query string) string {
	b, _ := json.Marshal(map[string]any{"query": query, "variables": map[string]any{}})
	return string(b)
}

// checkGraphQLBlock checks a GraphQL request that was blocked: a GraphQL
// error with the event ID, which it returns.
func checkGraphQLBlock(t *testing.T, w *waf, r response) auditEvent {
	t.Helper()
	var res struct {
		Errors []struct {
			Message    string `json:"message"`
			Extensions struct {
				Code    string `json:"code"`
				EventID string `json:"eventId"`
			} `json:"extensions"`
		} `json:"errors"`
	}
	if r.StatusCode != http.StatusForbidden || r.Header.Get("Content-Type") != "application/json" ||
		json.Unmarshal([]byte(r.body), &res) != nil || len(res.Errors) != 1 || res.Errors[0].Extensions.Code != "FORBIDDEN" {
		t.Fatalf("response %d %q", r.StatusCode, r.body)
	}
	return w.eventByID(t, res.Errors[0].Extensions.EventID)
}

// TestGraphQL protects a GraphQL endpoint: queries within the limits reach
// the backend; deep queries, alias batching, large batches and
// introspection get a GraphQL error; attacks in arguments are found on
// their own. Other paths are not affected.
func TestGraphQL(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-graphql-path", "/graphql", "-graphql-max-depth", "4", "-graphql-max-aliases", "3", "-graphql-max-batch", "2"}})
	w.waitLog(t, `msg="GraphQL protection enabled"`, "paths=[/graphql]", "max_depth=4", "max_aliases=3", "max_fields=1000", "max_batch=2", "introspection=false")
	c := w.client(t, nil)
	post := func(body string) response { return c.send("POST", "/graphql", "application/json", body) }

	clean := graphqlBody(`query Shop { products(first: 10, search: "running shoes") { name price reviews { stars } } }`)
	if r := post(clean); r.StatusCode != 200 || r.hit(t).Body != clean {
		t.Fatalf("clean query: %d %q", r.StatusCode, r.body)
	}
	if r := c.get("/graphql?query=" + url.QueryEscape("{ products { name } }")); r.StatusCode != 200 {
		t.Errorf("GET: %d %q", r.StatusCode, r.body)
	}
	if r := c.send("POST", "/graphql", "application/graphql", "{ products { name } }"); r.StatusCode != 200 {
		t.Errorf("application/graphql: %d %q", r.StatusCode, r.body)
	}
	// Persisted queries have no query to check.
	if r := post(`{"extensions":{"persistedQuery":{"version":1,"sha256Hash":"ecf4edb46db40b5132295c0291d62fb65d6759a9eedfa4d5d612dd5ec54a6b38"}}}`); r.StatusCode != 200 {
		t.Errorf("persisted query: %d %q", r.StatusCode, r.body)
	}

	for _, tc := range []struct {
		name, body, violation, operation string
		limit, value                     int
	}{
		{"depth", graphqlBody(`query Friends { user { friends { friends { friends { name } } } } }`), "depth", "query Friends", 4, 5},
		{"aliases", graphqlBody(`mutation { a: login(password: "1") b: login(password: "2") c: login(password: "3") d: login(password: "4") }`), "aliases", "mutation", 3, 4},
		{"batch", `[{"query":"{a}"},{"query":"{b}"},{"query":"{c}"}]`, "batch", "", 2, 3},
		{"introspection", graphqlBody(`{ __schema { types { name fields { name } } } }`), "introspection", "query", 0, 0},
		{"syntax", graphqlBody(`{ products { name }`), "invalid", "", 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := checkGraphQLBlock(t, w, post(tc.body))
			if e.Reason != "api" || e.API == nil || e.API.Protocol != "graphql" || e.API.Violation != tc.violation ||
				e.API.Operation != tc.operation || e.API.Limit != tc.limit || e.API.Value != tc.value {
				t.Errorf("event %+v, api %+v", e, e.API)
			}
		})
	}

	// An attack in an argument, which only shows as a value of its own:
	// "admin'--" ends a value, but not the query.
	e := checkGraphQLBlock(t, w, post(graphqlBody(`{ user(name: "admin'--") { name } }`)))
	if e.Reason != "signature" || e.Match == nil || e.Match.Location != "graphql" || e.Match.Field != "user(name)" || e.Match.Value != "admin'--" {
		t.Errorf("argument: %+v", e.Match)
	}
	e = checkGraphQLBlock(t, w, c.get("/graphql?query="+url.QueryEscape(`{ page(html: "<img src=x onerror=alert(1)>") }`)))
	if e.Reason != "signature" {
		t.Errorf("GET argument: %+v", e)
	}

	// Other paths: no GraphQL checks, and the usual responses.
	if r := c.send("POST", "/api/orders", "application/json", graphqlBody(`{ a { b { c { d { e { f } } } } } }`)); r.StatusCode != 200 {
		t.Errorf("other path: %d", r.StatusCode)
	}
	if r := c.get("/search?q=<script>alert(1)</script>"); r.StatusCode != 403 || !strings.HasPrefix(r.Header.Get("Content-Type"), "text/plain") {
		t.Errorf("other path: %d %s", r.StatusCode, r.Header.Get("Content-Type"))
	}
}

// TestGraphQLSchema validates queries against a schema, and allows
// introspection with -graphql-introspection.
func TestGraphQLSchema(t *testing.T) {
	schema := writeFile(t, "schema.graphql", `
type Query { product(id: ID!): Product  products(first: Int): [Product] }
type Product { id: ID! name: String price: Float }
`)
	w := startWAF(t, wafOptions{args: []string{"-graphql-path", "/graphql", "-graphql-schema", schema, "-graphql-introspection", "-engine", "both"}})
	c := w.client(t, nil)
	post := func(q string) response { return c.send("POST", "/graphql", "application/json", graphqlBody(q)) }

	for _, q := range []string{
		`{ product(id: 1) { name price } }`,
		`{ __schema { queryType { name } } }`,
		`{ __type(name: "Product") { fields { name } } }`,
	} {
		if r := post(q); r.StatusCode != 200 {
			t.Errorf("%s: %d %q", q, r.StatusCode, r.body)
		}
	}
	// The CRS allows application/graphql.
	if r := c.send("POST", "/graphql", "application/graphql", "{ products(first: 3) { name } }"); r.StatusCode != 200 {
		t.Errorf("application/graphql with the CRS: %d %q", r.StatusCode, r.body)
	}
	for _, q := range []string{
		`{ product(id: 1) { name costPrice } }`,
		`{ product { name } }`,
		`mutation { deleteProduct(id: 1) }`,
	} {
		e := checkGraphQLBlock(t, w, post(q))
		if e.API == nil || e.API.Violation != "schema" || e.API.Message == "" {
			t.Errorf("%s: api %+v", q, e.API)
		}
	}
}

// TestGraphQLStartup checks the options at startup.
func TestGraphQLStartup(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-graphql-max-depth", "5"}, "-graphql-* options require -graphql-path"},
		{[]string{"-graphql-introspection"}, "-graphql-* options require -graphql-path"},
		{[]string{"-graphql-path", "graphql"}, "invalid path"},
		{[]string{"-graphql-path", "/graphql", "-graphql-max-depth", "0"}, "-graphql-max-depth must be at least 1"},
		{[]string{"-graphql-path", "/graphql", "-graphql-schema", writeFile(t, "bad.graphql", "type Query { a: Missing }")}, "invalid schema"},
	} {
		out, err := runWAF(t, tc.args...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%q: %v\n%s", tc.args, err, out)
		}
	}
}

// shopAPI is the OpenAPI document of the tests.
const shopAPI = `
openapi: 3.1.0
info: {title: Shop, version: "1.0"}
servers: [{url: "https://shop.example.com/api/v1"}]
paths:
  /products:
    get:
      parameters:
        - {name: limit, in: query, schema: {type: integer, maximum: 100}}
      responses: {"200": {description: ok}}
    post:
      security: [{bearer: []}]
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              additionalProperties: false
              required: [name, price]
              properties:
                name: {type: string, maxLength: 50}
                price: {type: number, minimum: 0}
      responses: {"201": {description: created}}
  /products/{id}:
    get:
      parameters: [{name: id, in: path, required: true, schema: {type: integer}}]
      responses: {"200": {description: ok}}
components:
  securitySchemes:
    bearer: {type: http, scheme: bearer}
`

// TestOpenAPI validates requests under the API's base path against its
// OpenAPI document; other paths, such as the web site, are not affected.
func TestOpenAPI(t *testing.T) {
	spec := writeFile(t, "openapi.yaml", shopAPI)
	w := startWAF(t, wafOptions{args: []string{"-openapi", spec}})
	w.waitLog(t, `msg="OpenAPI validation enabled"`, "version=3.1.0", "operations=3", "paths=[/api/v1/]")
	c := w.client(t, nil)

	for _, r := range []response{
		c.get("/api/v1/products?limit=20"),
		c.get("/api/v1/products/42"),
		c.send("POST", "/api/v1/products", "application/json", `{"name":"Shoe","price":59.9}`, "Authorization", "Bearer token"),
		c.get("/"),
		c.get("/about/team"),
	} {
		if r.StatusCode != 200 {
			t.Errorf("%s %s: %d %q", r.Request.Method, r.Request.URL.Path, r.StatusCode, r.body)
		}
	}

	for _, tc := range []struct {
		name      string
		r         response
		violation string
		operation string
	}{
		{"unknown path", c.get("/api/v1/admin/users"), "unknown_path", ""},
		{"method", c.send("DELETE", "/api/v1/products/42", "", ""), "method_not_allowed", ""},
		{"parameter", c.get("/api/v1/products/abc"), "parameter", "GET /products/{id}"},
		{"limit", c.get("/api/v1/products?limit=100000"), "parameter", "GET /products"},
		{"no token", c.send("POST", "/api/v1/products", "application/json", `{"name":"Shoe","price":1}`), "security", "POST /products"},
		{"mass assignment", c.send("POST", "/api/v1/products", "application/json", `{"name":"Shoe","price":1,"discount":100}`, "Authorization", "Bearer t"), "body", "POST /products"},
		{"negative price", c.send("POST", "/api/v1/products", "application/json", `{"name":"Shoe","price":-1}`, "Authorization", "Bearer t"), "body", "POST /products"},
		{"path variant", c.get("/api/v1//admin"), "unknown_path", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			m := eventIDRe.FindStringSubmatch(tc.r.body)
			if tc.r.StatusCode != 403 || m == nil {
				t.Fatalf("%d %q", tc.r.StatusCode, tc.r.body)
			}
			e := w.eventByID(t, m[1])
			if e.Reason != "api" || e.API == nil || e.API.Protocol != "openapi" || e.API.Violation != tc.violation || e.API.Operation != tc.operation || e.API.Message == "" {
				t.Errorf("event %+v, api %+v", e, e.API)
			}
		})
	}

	// In detection mode, requests are only logged.
	w = startWAF(t, wafOptions{args: []string{"-openapi", spec, "-mode", "detect"}})
	if r := w.client(t, nil).get("/api/v1/admin/users"); r.StatusCode != 200 {
		t.Errorf("detect: %d", r.StatusCode)
	}
	if ev := w.events(t); len(ev) != 1 || ev[0].Action != "detect" || ev[0].API.Violation != "unknown_path" {
		t.Errorf("detect events %+v", ev)
	}
}

// TestOpenAPIStartup rejects documents that cannot be used.
func TestOpenAPIStartup(t *testing.T) {
	for _, tc := range []struct{ spec, want string }{
		{`{"swagger":"2.0","info":{"title":"x","version":"1"},"paths":{}}`, "not supported"},
		{"openapi: 3.0.0\ninfo: {title: x, version: '1'}\npaths:\n  /a/{id}: {get: {responses: {'200': {description: ok}}}}\n", "path parameters"},
	} {
		out, err := runWAF(t, "-openapi", writeFile(t, "spec.yaml", tc.spec))
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%v\n%s", err, out)
		}
	}
	if out, err := runWAF(t, "-openapi", "/nonexistent.yaml"); err == nil || !strings.Contains(out, "no such file") {
		t.Errorf("missing file: %v\n%s", err, out)
	}
}
