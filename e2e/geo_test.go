//go:build e2e

package e2e

import (
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cmc-labo/prism-waf/internal/geo/geotest"
)

// geoNetworks is the test database: documentation ranges, and the
// addresses that prismwaf checks to recognize a country database.
var geoNetworks = map[string]any{
	"8.8.8.0/24":      "US",
	"1.1.1.0/24":      geotest.RegisteredCountry("AU"), // anycast: no country
	"203.0.113.0/24":  "JP",
	"198.51.100.0/24": "CN",
	"2001:db8:1::/48": "JP",
	"2001:db8:2::/48": "CN",
	"192.0.2.0/24":    map[string]any{"country_code": "kr", "country": "South Korea"}, // IPinfo Lite
}

// writeGeoDB writes a database with geoNetworks unless db has networks.
func writeGeoDB(t *testing.T, db geotest.DB) string {
	t.Helper()
	if db.Networks == nil {
		db.Networks = geoNetworks
	}
	path := filepath.Join(t.TempDir(), "country.mmdb")
	if err := db.Write(path); err != nil {
		t.Fatal(err)
	}
	return path
}

// startGeoWAF starts prismwaf with the database behind a trusted proxy,
// so that each request can name its client in X-Forwarded-For.
func startGeoWAF(t *testing.T, db string, args ...string) *waf {
	t.Helper()
	return startWAF(t, wafOptions{args: append([]string{"-geo-db", db, "-trusted-proxies", "127.0.0.1"}, args...)})
}

// from sends a request from a client. It claims to come from Japan, which
// prismwaf must not believe.
func (c *client) from(ip, path string) response {
	c.t.Helper()
	return c.get(path, "X-Forwarded-For", ip, "X-Prismwaf-Country", "JP")
}

// checkGeoBlock checks a request that was blocked by its country, and
// returns its audit event.
func checkGeoBlock(t *testing.T, w *waf, r response, ip, country, list, key string) auditEvent {
	t.Helper()
	m := eventIDRe.FindStringSubmatch(r.body)
	if r.StatusCode != http.StatusForbidden || m == nil {
		t.Fatalf("%s: status %d, body %q", ip, r.StatusCode, r.body)
	}
	e := w.eventByID(t, m[1])
	if e.Reason != "geo" || e.Action != "block" || e.ClientIP != ip || e.Country != country ||
		e.Geo == nil || e.Geo.List != list || e.Geo.Client != key {
		t.Errorf("%s: event %+v, geo %+v", ip, e, e.Geo)
	}
	return e
}

// TestGeoAllow allows only some countries: clients from them reach the
// backend, which is told their country; other countries and unknown
// addresses get 403, logged once per client and minute.
func TestGeoAllow(t *testing.T) {
	w := startGeoWAF(t, writeGeoDB(t, geotest.DB{}), "-geo-allow", "jp,US,kr")
	w.waitLog(t, "level=INFO", `msg="GeoIP enabled"`, "type=GeoLite2-Country", "built="+time.Now().UTC().Format(time.DateOnly), "allow=jp,US,kr")
	c := w.client(t, nil)

	for _, tc := range []struct{ ip, country string }{
		{"203.0.113.7", "JP"},
		{"2001:db8:1::7", "JP"},
		{"::ffff:203.0.113.7", "JP"},
		{"8.8.8.8", "US"},
		{"192.0.2.1", "KR"}, // IPinfo's field
		// Private addresses have no country and pass.
		{"10.1.2.3", ""},
		{"192.168.0.1", ""},
		{"100.64.0.1", ""},
		{"fd00::1", ""},
	} {
		if h := c.from(tc.ip, "/").hit(t); h.Country != tc.country {
			t.Errorf("%s: backend got country %q, want %q", tc.ip, h.Country, tc.country)
		}
	}
	// So does the proxy itself.
	if h := c.get("/", "X-Prismwaf-Country", "JP").hit(t); h.Country != "" {
		t.Errorf("without X-Forwarded-For: country %q", h.Country)
	}

	cn := checkGeoBlock(t, w, c.from("198.51.100.7", "/"), "198.51.100.7", "CN", "allow", "198.51.100.7/32")
	cn6 := checkGeoBlock(t, w, c.from("2001:db8:2::7", "/login"), "2001:db8:2::7", "CN", "allow", "2001:db8:2::/64")
	checkGeoBlock(t, w, c.from("1.1.1.1", "/"), "1.1.1.1", "AU", "allow", "1.1.1.1/32")
	checkGeoBlock(t, w, c.from("9.9.9.9", "/"), "9.9.9.9", "XX", "allow", "9.9.9.9/32")

	// More requests of the same clients (an IPv6 client is its /64) get
	// the same event ID and are not logged again.
	for _, tc := range []struct {
		ip string
		e  auditEvent
	}{{"198.51.100.7", cn}, {"198.51.100.7", cn}, {"2001:db8:2::8", cn6}} {
		if r := c.from(tc.ip, "/"); r.StatusCode != http.StatusForbidden || !strings.Contains(r.body, "Event ID: "+tc.e.ID) {
			t.Errorf("%s again: %d %q, want event %s", tc.ip, r.StatusCode, r.body, tc.e.ID)
		}
	}
	time.Sleep(200 * time.Millisecond)
	if n := len(w.events(t)); n != 4 {
		t.Errorf("%d audit events, want 4: %+v", n, w.events(t))
	}
}

// TestGeoBlock blocks some countries and unknown addresses, except for an
// exempt network.
func TestGeoBlock(t *testing.T) {
	w := startGeoWAF(t, writeGeoDB(t, geotest.DB{}), "-geo-block", "CN,xx", "-geo-exempt", "198.51.100.128/25, 2001:db8:2:1::/64")
	c := w.client(t, nil)
	for _, tc := range []struct{ ip, country string }{
		{"203.0.113.7", "JP"},
		{"1.1.1.1", "AU"},
		{"10.1.2.3", ""},
		// Exempt, but still told to the backend.
		{"198.51.100.200", "CN"},
		{"2001:db8:2:1::7", "CN"},
	} {
		if h := c.from(tc.ip, "/").hit(t); h.Country != tc.country {
			t.Errorf("%s: backend got country %q, want %q", tc.ip, h.Country, tc.country)
		}
	}
	checkGeoBlock(t, w, c.from("198.51.100.7", "/"), "198.51.100.7", "CN", "block", "198.51.100.7/32")
	checkGeoBlock(t, w, c.from("2001:db8:2:2::7", "/"), "2001:db8:2:2::7", "CN", "block", "2001:db8:2:2::/64")
	checkGeoBlock(t, w, c.from("9.9.9.9", "/"), "9.9.9.9", "XX", "block", "9.9.9.9/32")
}

// TestGeoDetectMode only logs clients from other countries.
func TestGeoDetectMode(t *testing.T) {
	w := startGeoWAF(t, writeGeoDB(t, geotest.DB{}), "-geo-allow", "JP", "-mode", "detect")
	c := w.client(t, nil)
	r := c.from("198.51.100.7", "/")
	if h := r.hit(t); h.Country != "CN" {
		t.Errorf("country %q", h.Country)
	}
	var e auditEvent
	for deadline := time.Now().Add(2 * time.Second); e.ID == "" && time.Now().Before(deadline); time.Sleep(10 * time.Millisecond) {
		for _, ev := range w.events(t) {
			e = ev
		}
	}
	if e.Reason != "geo" || e.Action != "detect" || e.Country != "CN" || e.Geo == nil || e.Geo.List != "allow" {
		t.Errorf("event %+v", e)
	}
}

// TestGeoLookupOnly gives the backend the country without blocking.
func TestGeoLookupOnly(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-geo-db", writeGeoDB(t, geotest.DB{}), "-trusted-proxies", "127.0.0.1"}})
	c := w.client(t, nil)
	for ip, country := range map[string]string{"203.0.113.7": "JP", "198.51.100.7": "CN", "9.9.9.9": "XX"} {
		if h := c.from(ip, "/").hit(t); h.Country != country {
			t.Errorf("%s: country %q, want %q", ip, h.Country, country)
		}
	}
	if n := len(w.events(t)); n != 0 {
		t.Errorf("%d audit events", n)
	}
}

// TestGeoWithoutTrustedProxies ignores X-Forwarded-For: the TCP peer is
// looked up, here the loopback address, which passes.
func TestGeoWithoutTrustedProxies(t *testing.T) {
	w := startWAF(t, wafOptions{args: []string{"-geo-db", writeGeoDB(t, geotest.DB{}), "-geo-allow", "JP"}})
	w.waitLog(t, "level=INFO", "countries are looked up for the TCP peer address", "-trusted-proxies")
	c := w.client(t, nil)
	if h := c.from("198.51.100.7", "/").hit(t); h.Country != "" {
		t.Errorf("country %q", h.Country)
	}
}

// TestGeoComesFirst checks that blocked countries are rejected before rate
// limits and inspection, and that the other audit events carry the
// country.
func TestGeoComesFirst(t *testing.T) {
	w := startGeoWAF(t, writeGeoDB(t, geotest.DB{}), "-geo-block", "CN", "-rate-limit", "2/1m")
	c := w.client(t, nil)
	for range 4 {
		if r := c.from("198.51.100.7", "/?id=1+UNION+SELECT+password+FROM+users"); r.StatusCode != http.StatusForbidden {
			t.Fatalf("status %d", r.StatusCode)
		}
	}
	attack := c.from("203.0.113.7", "/?id=1+UNION+SELECT+password+FROM+users")
	c.from("203.0.113.7", "/")
	limited := c.from("203.0.113.7", "/")
	if attack.StatusCode != http.StatusForbidden || limited.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("status %d, %d", attack.StatusCode, limited.StatusCode)
	}
	time.Sleep(200 * time.Millisecond)
	var got []string
	for _, e := range w.events(t) {
		got = append(got, e.Reason+":"+e.Country)
	}
	if strings.Join(got, " ") != "geo:CN signature:JP rate_limit:JP" {
		t.Errorf("events %v", got)
	}
}

// TestGeoReload replaces the database file while prismwaf runs: a broken
// file is reported and ignored, a valid one is used from the next check,
// a minute later at most.
func TestGeoReload(t *testing.T) {
	slow(t)
	path := writeGeoDB(t, geotest.DB{})
	w := startGeoWAF(t, path, "-geo-allow", "JP")
	c := w.client(t, nil)
	c.from("203.0.113.7", "/").hit(t)

	replace := func(data []byte) {
		t.Helper()
		// Like geoipupdate: write a new file and rename it.
		if err := os.WriteFile(path+".tmp", data, 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.Rename(path+".tmp", path); err != nil {
			t.Fatal(err)
		}
	}
	replace([]byte("not a database"))
	w.waitLogFor(t, 70*time.Second, "level=ERROR", "cannot reload the GeoIP database; keeping the one in use", "not a valid MaxMind DB file")
	if h := c.from("203.0.113.7", "/").hit(t); h.Country != "JP" {
		t.Errorf("after a broken file: %q", h.Country)
	}

	networks := map[string]any{"8.8.8.0/24": "US", "203.0.113.0/24": "KR"}
	data, err := geotest.DB{Type: "DBIP-Country-Lite", Networks: networks}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	replace(data)
	start := time.Now()
	w.waitLogFor(t, 70*time.Second, "level=INFO", `msg="GeoIP database reloaded"`, "type=DBIP-Country-Lite")
	t.Logf("reloaded after %s", time.Since(start).Round(time.Second))
	checkGeoBlock(t, w, c.from("203.0.113.7", "/"), "203.0.113.7", "KR", "allow", "203.0.113.7/32")
	if n := strings.Count(w.stderr.String(), "cannot reload"); n != 1 {
		t.Errorf("%d reload errors", n)
	}
}

// TestGeoStartup checks the startup messages, and that a database prismwaf
// cannot use or an invalid option stops it.
func TestGeoStartup(t *testing.T) {
	dir := t.TempDir()
	text := writeFile(t, "countries.csv", "8.8.8.0/24,US\n")
	asn := filepath.Join(dir, "asn.mmdb")
	err := geotest.DB{Type: "GeoLite2-ASN", Networks: map[string]any{
		"8.8.8.0/24": map[string]any{"autonomous_system_number": uint32(15169), "autonomous_system_organization": "GOOGLE"},
	}}.Write(asn)
	if err != nil {
		t.Fatal(err)
	}
	good := writeGeoDB(t, geotest.DB{})
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"-geo-db", filepath.Join(dir, "missing.mmdb")}, "no such file or directory"},
		{[]string{"-geo-db", text}, "is not a valid MaxMind DB file"},
		{[]string{"-geo-db", asn, "-geo-block", "CN"}, "(GeoLite2-ASN) has no country for 8.8.8.8: use a country or city database"},
		{[]string{"-geo-db", good, "-geo-block", "UK"}, `invalid -geo-block: geo: invalid country \"UK\": the ISO 3166-1 code is GB`},
		{[]string{"-geo-db", good, "-geo-allow", "Japan"}, `invalid -geo-allow: geo: invalid country \"Japan\"`},
		{[]string{"-geo-db", good, "-geo-allow", "JP", "-geo-block", "CN"}, "-geo-allow and -geo-block are mutually exclusive"},
		{[]string{"-geo-allow", "JP"}, "-geo-allow, -geo-block and -geo-exempt require -geo-db"},
		{[]string{"-geo-db", good, "-geo-exempt", "10.0.0.0/8"}, "-geo-exempt requires -geo-allow or -geo-block"},
		{[]string{"-geo-db", good, "-geo-block", "CN", "-geo-exempt", "office"}, `invalid -geo-exempt`},
	} {
		out, err := runWAF(t, tc.args...)
		if err == nil || !strings.Contains(out, tc.want) {
			t.Errorf("%q: %v\n%s", tc.args, err, out)
		}
	}

	// An outdated database and an IPv4 database are used with a warning.
	old := writeGeoDB(t, geotest.DB{Built: time.Now().Add(-100 * 24 * time.Hour)})
	w := startGeoWAF(t, old, "-geo-allow", "JP")
	w.waitLog(t, "level=WARN", `msg="the GeoIP database is outdated"`, "hint=")
	v4 := writeGeoDB(t, geotest.DB{IPv4Only: true, Networks: map[string]any{"8.8.8.0/24": "US", "203.0.113.0/24": "JP"}})
	w = startGeoWAF(t, v4, "-geo-block", "XX")
	w.waitLog(t, "level=WARN", "the GeoIP database has only IPv4 addresses; IPv6 clients are unknown (XX)")
	c := w.client(t, nil)
	c.from("203.0.113.7", "/").hit(t)
	checkGeoBlock(t, w, c.from("2001:db8:1::7", "/"), "2001:db8:1::7", "XX", "block", "2001:db8:1::/64")
}

// TestGeoLiveDatabase uses a real database, given in PRISMWAF_E2E_GEO_DB,
// e.g. GeoLite2-Country.mmdb or dbip-country-lite-2026-11.mmdb.
func TestGeoLiveDatabase(t *testing.T) {
	db := os.Getenv("PRISMWAF_E2E_GEO_DB")
	if db == "" {
		t.Skip("set PRISMWAF_E2E_GEO_DB to a country database")
	}
	start := time.Now()
	w := startGeoWAF(t, db, "-geo-allow", "US")
	t.Logf("started in %s", time.Since(start).Round(time.Millisecond))
	w.waitLog(t, "level=INFO", `msg="GeoIP enabled"`)
	c := w.client(t, nil)
	// Google Public DNS is in the United States in all common databases.
	if h := c.from("8.8.8.8", "/").hit(t); h.Country != "US" {
		t.Errorf("8.8.8.8: %q", h.Country)
	}
	r := c.from("2001:db8::1", "/") // documentation: no country
	checkGeoBlock(t, w, r, "2001:db8::1", "XX", "allow", "2001:db8::/64")
	for _, line := range strings.Split(w.stderr.String(), "\n") {
		if strings.Contains(line, "GeoIP") {
			t.Log(line)
		}
	}
}
