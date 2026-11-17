package openapi

import (
	"crypto/tls"
	"crypto/x509"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// spec30 is an OpenAPI 3.0 document of a small shop API under /api/v1.
const spec30 = `
openapi: 3.0.3
info: {title: Shop, version: "1.0"}
servers:
  - url: https://shop.example.com/api/{version}
    variables:
      version: {default: v1}
paths:
  /products:
    get:
      parameters:
        - {name: limit, in: query, schema: {type: integer, minimum: 1, maximum: 100}}
        - {name: sort, in: query, schema: {type: string, enum: [price, name]}}
      responses: {"200": {description: ok}}
    post:
      security: [{apiKey: []}, {bearer: []}]
      requestBody:
        required: true
        content:
          application/json:
            schema: {$ref: "#/components/schemas/Product"}
      responses: {"201": {description: created}}
  /products/{id}:
    parameters:
      - {name: id, in: path, required: true, schema: {type: integer}}
    get:
      responses: {"200": {description: ok}}
    delete:
      security: [{bearer: []}]
      responses: {"204": {description: deleted}}
  /upload:
    put:
      requestBody:
        content:
          application/xml: {schema: {type: object}}
      responses: {"204": {description: ok}}
components:
  securitySchemes:
    apiKey: {type: apiKey, in: header, name: X-API-Key}
    bearer: {type: http, scheme: bearer}
  schemas:
    Product:
      type: object
      additionalProperties: false
      required: [name, price]
      properties:
        name: {type: string, maxLength: 50}
        price: {type: number, minimum: 0}
        tags: {type: array, items: {type: string}, maxItems: 5}
        note: {type: string, nullable: true}
`

// spec31 is an OpenAPI 3.1 document, as FastAPI generates, without
// servers: every path is validated.
const spec31 = `
openapi: 3.1.0
info: {title: Users, version: "1.0"}
paths:
  /users/{id}:
    get:
      parameters:
        - {name: id, in: path, required: true, schema: {type: string, format: uuid, pattern: "^[0-9a-f-]{36}$"}}
      responses: {"200": {description: ok}}
  /users:
    post:
      requestBody:
        required: true
        content:
          application/json:
            schema:
              type: object
              required: [email]
              properties:
                email: {type: string, maxLength: 100}
                age: {type: [integer, "null"], exclusiveMinimum: 0}
      responses: {"201": {description: created}}
`

func load(t *testing.T, spec string) *Validator {
	t.Helper()
	path := filepath.Join(t.TempDir(), "openapi.yaml")
	if err := os.WriteFile(path, []byte(spec), 0o644); err != nil {
		t.Fatal(err)
	}
	v, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func request(method, target, contentType, body string, headers ...string) (*http.Request, []byte) {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Header.Set(headers[i], headers[i+1])
	}
	return r, []byte(body)
}

func TestCheck30(t *testing.T) {
	v := load(t, spec30)
	if v.Version() != "3.0.3" || v.Operations() != 5 || strings.Join(v.BasePaths(), ",") != "/api/v1/" {
		t.Errorf("version %s, %d operations, base paths %q", v.Version(), v.Operations(), v.BasePaths())
	}
	const product = `{"name":"Shoe","price":59.9,"tags":["sale"]}`
	for _, tc := range []struct {
		name, method, target, contentType, body string
		headers                                 []string
		kind, operation                         string
	}{
		{"list", "GET", "/api/v1/products?limit=10&sort=price", "", "", nil, "", ""},
		{"list without parameters", "GET", "/api/v1/products", "", "", nil, "", ""},
		{"get", "GET", "/api/v1/products/42", "", "", nil, "", ""},
		{"create with API key", "POST", "/api/v1/products", "application/json", product, []string{"X-API-Key", "k"}, "", ""},
		{"create with bearer token", "POST", "/api/v1/products", "application/json; charset=utf-8", product, []string{"Authorization", "Bearer t"}, "", ""},
		{"null", "POST", "/api/v1/products", "application/json", `{"name":"a","price":1,"note":null}`, []string{"X-API-Key", "k"}, "", ""},
		{"outside the API", "GET", "/index.html", "", "", nil, "", ""},
		{"other prefix", "GET", "/api/v10/products", "", "", nil, "", ""},
		{"XML is not validated", "PUT", "/api/v1/upload", "application/xml", "<a/>", nil, "", ""},

		{"unknown path", "GET", "/api/v1/admin", "", "", nil, ViolationUnknownPath, ""},
		{"base path", "GET", "/api/v1", "", "", nil, ViolationUnknownPath, ""},
		{"method", "PATCH", "/api/v1/products/42", "", "", nil, ViolationMethod, ""},
		{"path parameter", "GET", "/api/v1/products/42%20OR%201=1", "", "", nil, ViolationParameter, "GET /products/{id}"},
		{"query parameter type", "GET", "/api/v1/products?limit=ten", "", "", nil, ViolationParameter, "GET /products"},
		{"query parameter range", "GET", "/api/v1/products?limit=1000", "", "", nil, ViolationParameter, "GET /products"},
		{"query parameter enum", "GET", "/api/v1/products?sort=1;DROP", "", "", nil, ViolationParameter, "GET /products"},
		{"no credentials", "POST", "/api/v1/products", "application/json", product, nil, ViolationSecurity, "POST /products"},
		{"other scheme", "DELETE", "/api/v1/products/1", "", "", []string{"Authorization", "Basic dTpw"}, ViolationSecurity, "DELETE /products/{id}"},
		{"empty token", "DELETE", "/api/v1/products/1", "", "", []string{"Authorization", "Bearer "}, ViolationSecurity, "DELETE /products/{id}"},
		{"missing body", "POST", "/api/v1/products", "application/json", "", []string{"X-API-Key", "k"}, ViolationBody, "POST /products"},
		{"missing property", "POST", "/api/v1/products", "application/json", `{"name":"a"}`, []string{"X-API-Key", "k"}, ViolationBody, "POST /products"},
		{"extra property", "POST", "/api/v1/products", "application/json", `{"name":"a","price":1,"isAdmin":true}`, []string{"X-API-Key", "k"}, ViolationBody, "POST /products"},
		{"wrong type", "POST", "/api/v1/products", "application/json", `{"name":"a","price":"free"}`, []string{"X-API-Key", "k"}, ViolationBody, "POST /products"},
		{"too long", "POST", "/api/v1/products", "application/json", `{"name":"` + strings.Repeat("a", 51) + `","price":1}`, []string{"X-API-Key", "k"}, ViolationBody, "POST /products"},
		{"too many items", "POST", "/api/v1/products", "application/json", `{"name":"a","price":1,"tags":["1","2","3","4","5","6"]}`, []string{"X-API-Key", "k"}, ViolationBody, "POST /products"},
		{"invalid JSON", "POST", "/api/v1/products", "application/json", `{"name":`, []string{"X-API-Key", "k"}, ViolationBody, "POST /products"},
		{"content type", "POST", "/api/v1/products", "text/plain", product, []string{"X-API-Key", "k"}, ViolationBody, "POST /products"},
		// Variants of the path that backends may accept.
		{"double slash", "GET", "/api//v1/admin", "", "", nil, ViolationUnknownPath, ""},
		{"dot segment", "GET", "/static/../api/v1/admin", "", "", nil, ViolationUnknownPath, ""},
		{"case", "GET", "/API/V1/admin", "", "", nil, ViolationUnknownPath, ""},
		// The router ignores a trailing slash, like many backends.
		{"trailing slash", "GET", "/api/v1/products/", "", "", nil, "", ""},
		{"semicolon", "GET", "/api/v1/products?limit=1;sort=x", "", "", nil, ViolationParameter, "GET /products"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, body := request(tc.method, tc.target, tc.contentType, tc.body, tc.headers...)
			got := v.Check(r, body)
			if tc.kind == "" {
				if got != nil {
					t.Fatalf("violation %+v", got)
				}
				return
			}
			if got == nil || got.Kind != tc.kind || got.Operation != tc.operation || got.Message == "" {
				t.Fatalf("violation %+v, want %s", got, tc.kind)
			}
		})
	}
}

func TestCheck31(t *testing.T) {
	v := load(t, spec31)
	if strings.Join(v.BasePaths(), ",") != "/" {
		t.Errorf("base paths %q", v.BasePaths())
	}
	const id = "/users/3f8e2a1c-7b4d-4e5f-9a6b-1c2d3e4f5a6b"
	for _, tc := range []struct {
		name, method, target, body, kind string
	}{
		{"get", "GET", id, "", ""},
		{"create", "POST", "/users", `{"email":"a@example.com","age":30}`, ""},
		{"type array with null", "POST", "/users", `{"email":"a@example.com","age":null}`, ""},
		{"other path", "GET", "/", "", ViolationUnknownPath},
		{"pattern", "GET", "/users/1' OR '1'='1", "", ViolationParameter},
		{"exclusive minimum", "POST", "/users", `{"email":"a@example.com","age":0}`, ViolationBody},
		{"required", "POST", "/users", `{"age":3}`, ViolationBody},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, body := request(tc.method, strings.ReplaceAll(tc.target, " ", "%20"), "application/json", tc.body)
			got := v.Check(r, body)
			if (got == nil) != (tc.kind == "") || got != nil && got.Kind != tc.kind {
				t.Fatalf("violation %+v, want %q", got, tc.kind)
			}
		})
	}
}

// TestCheckForwardsBody checks that validation does not change the body
// that is forwarded, e.g. by setting default values.
func TestCheckForwardsBody(t *testing.T) {
	v := load(t, strings.Replace(spec30, "note: {type: string, nullable: true}", "note: {type: string, default: x}", 1))
	r, body := request("POST", "/api/v1/products", "application/json", `{"name":"a","price":1}`, "X-API-Key", "k")
	if got := v.Check(r, body); got != nil {
		t.Fatal(got)
	}
	b := make([]byte, 100)
	n, _ := r.Body.Read(b)
	if string(b[:n]) != `{"name":"a","price":1}` || string(body) != `{"name":"a","price":1}` || r.URL.Path != "/api/v1/products" {
		t.Errorf("body %q, path %s", b[:n], r.URL.Path)
	}
}

func TestMutualTLS(t *testing.T) {
	v := load(t, `
openapi: 3.1.0
info: {title: M, version: "1"}
security: [{mtls: []}]
paths:
  /x: {get: {responses: {"200": {description: ok}}}}
components:
  securitySchemes:
    mtls: {type: mutualTLS}
`)
	r, _ := request("GET", "/x", "", "")
	if got := v.Check(r, nil); got == nil || got.Kind != ViolationSecurity {
		t.Errorf("without certificate: %+v", got)
	}
	r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{{}}}
	if got := v.Check(r, nil); got != nil {
		t.Errorf("with certificate: %+v", got)
	}
}

func TestLoadErrors(t *testing.T) {
	dir := t.TempDir()
	write := func(name, s string) string {
		p := filepath.Join(dir, name)
		os.WriteFile(p, []byte(s), 0o644)
		return p
	}
	for _, tc := range []struct{ name, spec, want string }{
		{"swagger", `{"swagger":"2.0","info":{"title":"x","version":"1"},"paths":{}}`, "not supported"},
		{"invalid", "openapi: 3.0.0\ninfo: {title: x}\npaths: {}\n", "version"},
		{"remote ref", "openapi: 3.0.0\ninfo: {title: x, version: '1'}\npaths:\n  /a:\n    $ref: 'http://127.0.0.1:1/x.yaml#/a'\n", "URLs are not supported"},
		{"syntax", "openapi: [", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Load(write(tc.name+".yaml", tc.spec))
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("error %v, want %q", err, tc.want)
			}
		})
	}
	if _, err := Load(filepath.Join(dir, "missing.yaml")); err == nil {
		t.Error("missing file loaded")
	}

	// References to local files work.
	write("schemas.yaml", "Item: {type: object, required: [id], properties: {id: {type: integer}}}\n")
	path := write("main.yaml", `
openapi: 3.0.0
info: {title: x, version: '1'}
paths:
  /items:
    post:
      requestBody: {content: {application/json: {schema: {$ref: 'schemas.yaml#/Item'}}}}
      responses: {"200": {description: ok}}
`)
	v, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	r, body := request("POST", "/items", "application/json", `{"id":"x"}`)
	if got := v.Check(r, body); got == nil || got.Kind != ViolationBody {
		t.Errorf("violation %+v", got)
	}
}

func BenchmarkCheck(b *testing.B) {
	path := filepath.Join(b.TempDir(), "openapi.yaml")
	os.WriteFile(path, []byte(spec30), 0o644)
	v, _ := Load(path)
	body := []byte(`{"name":"Shoe","price":59.9,"tags":["sale"]}`)
	for b.Loop() {
		r, _ := request("POST", "/api/v1/products", "application/json", "", "X-API-Key", "k")
		v.Check(r, body)
	}
}

// TestRouter covers what the router accepts beyond kin-openapi's: paths
// that differ only in the names of their parameters, as in GitHub's API,
// literal segments before parameters, parameters within a segment, HEAD
// requests and CORS preflight requests.
func TestRouter(t *testing.T) {
	v := load(t, `
openapi: 3.0.3
info: {title: x, version: "1"}
paths:
  /items/{id}:
    get:
      parameters: [{name: id, in: path, required: true, schema: {type: integer}}]
      responses: {"200": {description: ok}}
  /items/{itemName}:
    delete:
      parameters: [{name: itemName, in: path, required: true, schema: {type: string, pattern: "^[a-z]+$"}}]
      responses: {"204": {description: ok}}
  /items/latest:
    get: {responses: {"200": {description: ok}}}
  /files/{name}.{ext}:
    get:
      parameters:
        - {name: name, in: path, required: true, schema: {type: string}}
        - {name: ext, in: path, required: true, schema: {type: string, enum: [png, jpg]}}
      responses: {"200": {description: ok}}
`)
	for _, tc := range []struct {
		method, target, kind, operation string
	}{
		{"GET", "/items/42", "", ""},
		{"GET", "/items/x", ViolationParameter, "GET /items/{id}"},
		{"DELETE", "/items/abc", "", ""},
		{"DELETE", "/items/42", ViolationParameter, "DELETE /items/{itemName}"},
		{"PUT", "/items/42", ViolationMethod, ""},
		{"GET", "/items/latest", "", ""},
		{"GET", "/files/logo.png", "", ""},
		{"GET", "/files/logo.exe", ViolationParameter, "GET /files/{name}.{ext}"},
		{"GET", "/files/logo", ViolationUnknownPath, ""},
		{"HEAD", "/items/42", "", ""},
		{"OPTIONS", "/items/42", "", ""},
		{"OPTIONS", "/nothing", ViolationUnknownPath, ""},
		{"GET", "/items/42/", "", ""},
		{"GET", "/items", ViolationUnknownPath, ""},
		{"GET", "/items/42/x", ViolationUnknownPath, ""},
	} {
		r, body := request(tc.method, tc.target, "", "")
		got := v.Check(r, body)
		if (got == nil) != (tc.kind == "") || got != nil && (got.Kind != tc.kind || got.Operation != tc.operation) {
			t.Errorf("%s %s: %+v, want %q", tc.method, tc.target, got, tc.kind)
		}
	}
}

// TestLenient covers what real documents need: wrong examples, which do
// not take part in validation, and features that the validator does not
// support, such as arrays in the deepObject style in Stripe's API, which
// are not validated instead of rejecting every request.
func TestLenient(t *testing.T) {
	v := load(t, `
openapi: 3.0.3
info: {title: x, version: "1"}
paths:
  /customers:
    get:
      parameters:
        - {name: expand, in: query, style: deepObject, explode: true, schema: {type: array, items: {type: string}}}
        - {name: limit, in: query, schema: {type: integer, example: "ten"}}
      responses: {"200": {description: ok}}
    post:
      requestBody:
        content:
          application/x-www-form-urlencoded:
            schema:
              type: object
              properties:
                tax: {type: array, items: {type: object, properties: {type: {type: string}}}}
                email: {type: string, maxLength: 10}
      responses: {"200": {description: ok}}
`)
	for _, tc := range []struct {
		method, target, contentType, body, kind string
	}{
		{"GET", "/customers?limit=10", "", "", ""},
		{"GET", "/customers?expand[]=a&limit=10", "", "", ""},
		// The other parameters are still validated.
		{"GET", "/customers?limit=ten", "", "", ViolationParameter},
		{"POST", "/customers", "application/x-www-form-urlencoded", "email=a%40b.c&tax[0][type]=vat", ""},
	} {
		r, body := request(tc.method, tc.target, tc.contentType, tc.body)
		got := v.Check(r, body)
		if (got == nil) != (tc.kind == "") || got != nil && got.Kind != tc.kind {
			t.Errorf("%s %s: %+v, want %q", tc.method, tc.target, got, tc.kind)
		}
	}
}
