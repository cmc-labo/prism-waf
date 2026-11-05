package waf

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"

	"github.com/cmc-labo/prism-waf/internal/crs"
)

var (
	crsOnce   sync.Once
	crsEngine *crs.Engine
	crsErr    error
)

func testCRS(t *testing.T) *crs.Engine {
	t.Helper()
	crsOnce.Do(func() { crsEngine, crsErr = crs.New(crs.Config{}) })
	if crsErr != nil {
		t.Fatal(crsErr)
	}
	return crsEngine
}

// crsOnly returns a Config that uses only the CRS.
func crsOnly(t *testing.T) Config {
	in, err := NewInspector(nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	return Config{Inspector: in, CRS: testCRS(t)}
}

func browserRequest(method, target, contentType, body string) *http.Request {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")
	r.Header.Set("Accept", "*/*")
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	return r
}

func TestCRSAuditEvent(t *testing.T) {
	r := browserRequest("POST", "/login", "application/json", `{"user":{"name":"1' OR '1'='1"}}`)
	rec, events := serveWithAudit(t, crsOnly(t), r)

	if rec.Code != http.StatusForbidden || len(events) != 1 {
		t.Fatalf("status %d, %d events", rec.Code, len(events))
	}
	e := events[0]
	if !strings.Contains(rec.Body.String(), "Event ID: "+e.ID) {
		t.Errorf("response %q does not contain event ID %s", rec.Body.String(), e.ID)
	}
	if e.Reason != "crs" || e.Action != "block" {
		t.Errorf("reason %q, action %q", e.Reason, e.Action)
	}
	if e.Rule == nil || e.Rule.ID != "942100" || e.Rule.Category != "sqli" {
		t.Errorf("rule = %+v", e.Rule)
	}
	if m := e.Match; m == nil || m.Location != "ARGS" || m.Field != "json.user.name" || m.Value != "1' OR '1'='1" {
		t.Errorf("match = %+v", e.Match)
	}
	c := e.CRS
	if c == nil || c.DecidingRule != 949110 || c.AnomalyScore < 5 || len(c.Rules) == 0 {
		t.Fatalf("crs = %+v", c)
	}
	for _, rule := range c.Rules {
		if rule.ID == 949110 {
			t.Error("the evaluation rule is listed among the matched rules")
		}
	}
}

func TestCRSRejectionStatus(t *testing.T) {
	r := browserRequest("POST", "/api", "application/json", `{"broken":`)
	r.Host = "192.0.2.1" // adds a warning (920350) besides the deciding rule
	rec, events := serveWithAudit(t, crsOnly(t), r)
	if rec.Code != http.StatusBadRequest || len(events) != 1 || events[0].CRS.DecidingRule != 200002 {
		t.Fatalf("status %d, events %+v; want 400 from rule 200002", rec.Code, events)
	}
	if e := events[0]; e.Rule == nil || e.Rule.ID != "200002" {
		t.Errorf("rule = %+v, want the deciding rule 200002", e.Rule)
	}
}

func TestCRSAllowsCleanRequest(t *testing.T) {
	r := browserRequest("POST", "/api/orders", "application/json", `{"item":"book","qty":2}`)
	var got string
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b, _ := io.ReadAll(r.Body)
		got = string(b)
	})
	rec := httptest.NewRecorder()
	Middleware(next, crsOnly(t)).ServeHTTP(rec, r)
	if rec.Code != http.StatusOK || got != `{"item":"book","qty":2}` {
		t.Errorf("status %d, backend got body %q", rec.Code, got)
	}
}

func TestCRSDetectMode(t *testing.T) {
	cfg := crsOnly(t)
	cfg.Mode = ModeDetect
	reached := false
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { reached = true })
	r := browserRequest("GET", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "", "")
	rec := httptest.NewRecorder()
	Middleware(next, cfg).ServeHTTP(rec, r)
	if !reached || rec.Code != http.StatusOK {
		t.Errorf("detect mode: reached %v, status %d", reached, rec.Code)
	}
}

func TestBuiltinSignaturesRunBeforeCRS(t *testing.T) {
	cfg := Config{CRS: testCRS(t)} // serveWithAudit adds the default signatures
	r := browserRequest("GET", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "", "")
	_, events := serveWithAudit(t, cfg, r)
	if len(events) != 1 || events[0].Reason != "signature" || events[0].CRS != nil {
		t.Fatalf("events = %+v, want one built-in signature event", events)
	}

	// A payload only the CRS knows is still caught.
	r = browserRequest("GET", "/?cmd=%3C%3Fphp+system%28%24_GET%5B%27c%27%5D%29%3B", "", "")
	_, events = serveWithAudit(t, cfg, r)
	if len(events) != 1 || events[0].Reason != "crs" {
		t.Errorf("events = %+v, want one CRS event", events)
	}
}

func TestCRSBodyTooLarge(t *testing.T) {
	cfg := crsOnly(t)
	cfg.Inspector, _ = NewInspector(nil, 16)
	r := browserRequest("POST", "/api", "application/json", `{"a":"0123456789abcdef"}`)
	rec, events := serveWithAudit(t, cfg, r)
	if rec.Code != http.StatusRequestEntityTooLarge || len(events) != 1 || events[0].Reason != "body_too_large" {
		t.Errorf("status %d, events %+v", rec.Code, events)
	}
}
