package waf

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"google.golang.org/protobuf/encoding/protowire"

	"github.com/cmc-labo/prism-waf/internal/audit"
	"github.com/cmc-labo/prism-waf/internal/graphql"
	"github.com/cmc-labo/prism-waf/internal/grpc"
	"github.com/cmc-labo/prism-waf/internal/openapi"
)

func graphqlGuard(t *testing.T) *graphql.Guard {
	t.Helper()
	g, err := graphql.New(graphql.Config{Paths: []string{"/graphql"}, MaxDepth: 2})
	if err != nil {
		t.Fatal(err)
	}
	return g
}

func graphqlRequest(query string) *http.Request {
	b, _ := json.Marshal(map[string]string{"query": query})
	r := httptest.NewRequest("POST", "/graphql", bytes.NewReader(b))
	r.Header.Set("Content-Type", "application/json")
	return r
}

func TestGraphQL(t *testing.T) {
	cfg := Config{GraphQL: graphqlGuard(t)}

	rec, events := serveWithAudit(t, cfg, graphqlRequest("{ a { b } }"))
	if rec.Code != http.StatusOK || len(events) != 0 {
		t.Fatalf("clean query: %d %+v", rec.Code, events)
	}

	// Over a limit: a GraphQL error, which GraphQL clients can show.
	rec, events = serveWithAudit(t, cfg, graphqlRequest("query Deep { a { b { c } } }"))
	if len(events) != 1 {
		t.Fatalf("events %+v", events)
	}
	e := events[0]
	if e.Reason != "api" || e.API == nil || *e.API != (audit.API{Protocol: "graphql", Violation: "depth", Operation: "query Deep", Limit: 2, Value: 3, Message: "depth 3, more than 2"}) {
		t.Errorf("event %+v, api %+v", e, e.API)
	}
	var res graphqlResponse
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil || rec.Code != http.StatusForbidden ||
		rec.Header().Get("Content-Type") != "application/json" || len(res.Errors) != 1 ||
		res.Errors[0].Extensions.EventID != e.ID || res.Errors[0].Extensions.Code != "FORBIDDEN" || !strings.Contains(res.Errors[0].Message, e.ID) {
		t.Errorf("response %d %q", rec.Code, rec.Body)
	}

	// An attack in an argument is found on its own and located.
	_, events = serveWithAudit(t, cfg, graphqlRequest(`{ user(name: "admin'--") { id } }`))
	if len(events) != 1 || events[0].Reason != "signature" || events[0].Match.Location != "graphql" ||
		events[0].Match.Field != "user(name)" || events[0].Match.Value != "admin'--" {
		t.Errorf("events %+v", events)
	}

	// Other paths are not GraphQL endpoints, and their responses are text.
	r := httptest.NewRequest("GET", "/search?q=<script>alert(1)</script>", nil)
	if rec, _ := serveWithAudit(t, cfg, r); !strings.HasPrefix(rec.Header().Get("Content-Type"), "text/plain") {
		t.Errorf("content type %q", rec.Header().Get("Content-Type"))
	}
}

func TestOpenAPI(t *testing.T) {
	path := filepath.Join(t.TempDir(), "openapi.yaml")
	os.WriteFile(path, []byte(`
openapi: 3.0.3
info: {title: x, version: "1"}
servers: [{url: /api}]
paths:
  /items/{id}:
    get:
      parameters: [{name: id, in: path, required: true, schema: {type: integer}}]
      responses: {"200": {description: ok}}
`), 0o644)
	v, err := openapi.Load(path)
	if err != nil {
		t.Fatal(err)
	}
	cfg := Config{OpenAPI: v}
	for _, tc := range []struct {
		target    string
		code      int
		violation string
	}{
		{"/api/items/1", 200, ""},
		{"/about", 200, ""},
		{"/api/users", 403, "unknown_path"},
		{"/api/items/x", 403, "parameter"},
	} {
		rec, events := serveWithAudit(t, cfg, httptest.NewRequest("GET", tc.target, nil))
		if rec.Code != tc.code || tc.violation == "" && len(events) != 0 ||
			tc.violation != "" && (len(events) != 1 || events[0].API.Protocol != "openapi" || events[0].API.Violation != tc.violation) {
			t.Errorf("%s: %d %+v", tc.target, rec.Code, events)
		}
	}

	// Signatures come first: an attack is reported as such.
	_, events := serveWithAudit(t, cfg, httptest.NewRequest("GET", "/api/items/1%20UNION%20SELECT%20password%20FROM%20users", nil))
	if len(events) != 1 || events[0].Reason != "signature" {
		t.Errorf("events %+v", events)
	}

	// In detection mode, the request is forwarded and logged.
	cfg.Mode = ModeDetect
	rec, events := serveWithAudit(t, cfg, httptest.NewRequest("GET", "/api/users", nil))
	if rec.Code != http.StatusOK || len(events) != 1 || events[0].Action != "detect" {
		t.Errorf("detect: %d %+v", rec.Code, events)
	}
	// A body too large to read is not validated (it is logged for its size).
	r := httptest.NewRequest("POST", "/api/items/1", strings.NewReader(strings.Repeat("x", 2000)))
	cfg.Inspector = mustInspector(t, 1000)
	if _, events := serveWithAudit(t, cfg, r); len(events) != 1 || events[0].Reason != "body_too_large" {
		t.Errorf("too large: %+v", events)
	}
}

// grpcFrame frames a protobuf message with one string field.
func grpcFrame(field int, value string) []byte {
	msg := protowire.AppendTag(nil, protowire.Number(field), protowire.BytesType)
	msg = protowire.AppendString(msg, value)
	b := []byte{0, 0, 0, 0, byte(len(msg))}
	return append(b, msg...)
}

// serveGRPCCall sends a gRPC request through Middleware to a backend that
// reads the whole stream, like the proxy, and answers.
func serveGRPCCall(t *testing.T, cfg Config, contentType string, body []byte) (*httptest.ResponseRecorder, []audit.Event, []byte) {
	t.Helper()
	var buf bytes.Buffer
	cfg.Audit = audit.New(&buf)
	if cfg.Inspector == nil {
		cfg.Inspector = mustInspector(t, 0)
	}
	var got []byte
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var err error
		got, err = io.ReadAll(r.Body)
		if err != nil {
			if !errors.Is(err, errCallBlocked) || r.Context().Err() == nil {
				t.Errorf("read error %v, context %v", err, r.Context().Err())
			}
			// The proxy's answer, which Middleware replaces.
			http.Error(w, "Bad Gateway", http.StatusBadGateway)
			return
		}
		w.Header().Set("Content-Type", contentType)
		w.Header().Set("Grpc-Status", "0")
		w.WriteHeader(http.StatusOK)
	})
	r := httptest.NewRequest("POST", "/shop.Orders/Find", bytes.NewReader(body))
	r.Header.Set("Content-Type", contentType)
	rec := httptest.NewRecorder()
	Middleware(next, cfg).ServeHTTP(rec, r)
	return rec, decodeEvents(t, &buf), got
}

func TestGRPC(t *testing.T) {
	clean := grpcFrame(1, "running shoes")
	rec, events, got := serveGRPCCall(t, Config{}, "application/grpc", clean)
	if rec.Code != http.StatusOK || rec.Header().Get("Grpc-Status") != "0" || len(events) != 0 || !bytes.Equal(got, clean) {
		t.Fatalf("clean call: %d %v %+v", rec.Code, rec.Header(), events)
	}

	attack := append(clean, grpcFrame(2, "' OR 1=1--")...)
	rec, events, got = serveGRPCCall(t, Config{}, "application/grpc", attack)
	if len(events) != 1 || events[0].Match == nil || events[0].Match.Location != "grpc" || events[0].Match.Field != "[1].2" {
		t.Fatalf("events %+v", events)
	}
	if rec.Code != http.StatusOK || rec.Header().Get("Grpc-Status") != "7" || !strings.Contains(rec.Header().Get("Grpc-Message"), events[0].ID) ||
		rec.Header().Get("Content-Type") != "application/grpc" || rec.Body.Len() != 0 {
		t.Errorf("response %d %v %q", rec.Code, rec.Header(), rec.Body)
	}
	if bytes.Contains(got, []byte("OR 1=1")) {
		t.Errorf("the backend got the attack: %q", got)
	}

	// gRPC with JSON messages.
	msg := []byte(`{"user":{"name":"<script>alert(1)</script>"}}`)
	frame := append([]byte{0, 0, 0, 0, byte(len(msg))}, msg...)
	_, events, _ = serveGRPCCall(t, Config{}, "application/grpc+json", frame)
	if len(events) != 1 || events[0].Match.Field != "[0].user.name" {
		t.Errorf("JSON: %+v", events)
	}

	// Detection mode passes the stream on.
	rec, events, got = serveGRPCCall(t, Config{Mode: ModeDetect}, "application/grpc-web+proto", attack)
	if rec.Header().Get("Grpc-Status") != "0" || len(events) != 1 || events[0].Action != "detect" || !bytes.Equal(got, attack) {
		t.Errorf("detect: %v %+v", rec.Header(), events)
	}

	// Reflection is blocked unless allowed.
	r := httptest.NewRequest("POST", "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", bytes.NewReader(clean))
	r.Header.Set("Content-Type", "application/grpc")
	rec, events = serveWithAudit(t, Config{}, r)
	if rec.Header().Get("Grpc-Status") != "7" || len(events) != 1 || events[0].API.Violation != "reflection" {
		t.Errorf("reflection: %v %+v", rec.Header(), events)
	}
	r = httptest.NewRequest("POST", "/grpc.reflection.v1.ServerReflection/ServerReflectionInfo", bytes.NewReader(clean))
	r.Header.Set("Content-Type", "application/grpc")
	if rec, events = serveWithAudit(t, Config{GRPC: grpc.New(grpc.Config{Reflection: true})}, r); len(events) != 0 {
		t.Errorf("reflection allowed: %v %+v", rec.Header(), events)
	}
}

// TestGRPCRequiresPOST checks that a gRPC content type does not change how
// other requests are inspected.
func TestGRPCRequiresPOST(t *testing.T) {
	r := httptest.NewRequest("PUT", "/x", strings.NewReader("q=' OR 1=1--"))
	r.Header.Set("Content-Type", "application/grpc")
	rec, events := serveWithAudit(t, Config{}, r)
	if rec.Code != http.StatusForbidden || len(events) != 1 || events[0].Match.Location != "body" {
		t.Errorf("%d %+v", rec.Code, events)
	}
}
