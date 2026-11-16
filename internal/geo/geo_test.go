package geo

import (
	"bytes"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/cmc-labo/prism-waf/internal/geo/geotest"
)

// testNetworks covers the probes, so that the database is accepted.
var testNetworks = map[string]any{
	"8.8.8.0/24":         "US",
	"1.1.1.0/24":         geotest.RegisteredCountry("AU"),
	"203.0.113.0/24":     "JP",
	"198.51.100.0/25":    "CN",
	"198.51.100.128/25":  map[string]any{"country_code": "de", "country": "Germany"}, // IPinfo Lite
	"2001:db8:1::/48":    "JP",
	"2001:db8:2::/48":    "CN",
	"192.0.2.0/24":       map[string]any{"continent": map[string]any{"code": "AS"}}, // no country
	"2001:db8:ffff::/48": map[string]any{},
}

func writeDB(t *testing.T, db geotest.DB) string {
	t.Helper()
	if db.Networks == nil {
		db.Networks = testNetworks
	}
	path := filepath.Join(t.TempDir(), "country.mmdb")
	if err := db.Write(path); err != nil {
		t.Fatal(err)
	}
	return path
}

func openDB(t *testing.T, db geotest.DB) (*DB, *bytes.Buffer) {
	t.Helper()
	var logs bytes.Buffer
	d, err := OpenDB(writeDB(t, db), slog.New(slog.NewTextHandler(&logs, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return d, &logs
}

func TestParseCountries(t *testing.T) {
	got, err := ParseCountries(" jp, US,,JP , xx")
	if err != nil || strings.Join(got, ",") != "JP,US,XX" {
		t.Errorf("ParseCountries = %v, %v", got, err)
	}
	if got, err := ParseCountries(""); err != nil || got != nil {
		t.Errorf("empty: %v, %v", got, err)
	}
	for in, want := range map[string]string{
		"UK":     "the ISO 3166-1 code is GB",
		"JP,JPN": `"JPN"`,
		"J":      `"J"`,
		"EU":     `"EU"`, // not a country
		"ZZ":     `"ZZ"`,
		"419":    `"419"`,
		"Japan":  `"Japan"`,
	} {
		if _, err := ParseCountries(in); err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("ParseCountries(%q) = %v, want %s", in, err, want)
		}
	}
}

func TestCountry(t *testing.T) {
	d, _ := openDB(t, geotest.DB{})
	for ip, want := range map[string]string{
		"8.8.8.8":            "US",
		"1.1.1.1":            "AU", // registered country only
		"203.0.113.77":       "JP",
		"::ffff:203.0.113.7": "JP",
		"198.51.100.1":       "CN",
		"198.51.100.200":     "DE", // IPinfo, lower case
		"2001:db8:1::1":      "JP",
		"2001:db8:2:ab::1":   "CN",
		"192.0.2.1":          "", // a record without a country
		"2001:db8:ffff::1":   "",
		"9.9.9.9":            "", // not in the database
		"2001:db8:3::1":      "",
	} {
		if got := d.Country(netip.MustParseAddr(ip)); got != want {
			t.Errorf("Country(%s) = %q, want %q", ip, got, want)
		}
	}
	m := d.Metadata()
	if m.DatabaseType != "GeoLite2-Country" || m.IPVersion != 6 {
		t.Errorf("metadata %+v", m)
	}

	// An IPv4 database has no country for IPv6 addresses.
	d, _ = openDB(t, geotest.DB{IPv4Only: true, Networks: map[string]any{"8.8.8.0/24": "US"}})
	if got := d.Country(netip.MustParseAddr("8.8.8.8")); got != "US" {
		t.Errorf("IPv4 database: %q", got)
	}
	if got := d.Country(netip.MustParseAddr("2001:db8:1::1")); got != "" {
		t.Errorf("IPv6 in IPv4 database: %q", got)
	}
}

func TestOpenDBRejectsInvalidFiles(t *testing.T) {
	dir := t.TempDir()
	good, err := geotest.DB{Networks: testNetworks}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	asn, err := geotest.DB{Type: "GeoLite2-ASN", Networks: map[string]any{
		"8.8.8.0/24": map[string]any{"autonomous_system_number": uint32(15169)},
	}}.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for name, tc := range map[string]struct {
		data []byte
		want string
	}{
		"missing":   {nil, "no such file"},
		"empty":     {[]byte{}, "not a valid MaxMind DB file"},
		"text":      {[]byte("8.8.8.0/24,US\n"), "not a valid MaxMind DB file"},
		"truncated": {good[:len(good)/2], "not a valid MaxMind DB file"},
		"corrupt":   {append(bytes.Repeat([]byte{0xff}, 30), good[30:]...), "not a valid MaxMind DB file"},
		"asn":       {asn, "(GeoLite2-ASN) has no country for 8.8.8.8: use a country or city database"},
	} {
		path := filepath.Join(dir, name)
		if tc.data != nil {
			os.WriteFile(path, tc.data, 0o644)
		}
		if _, err := OpenDB(path, nil); err == nil || !strings.Contains(err.Error(), tc.want) {
			t.Errorf("%s: %v, want %q", name, err, tc.want)
		}
	}
}

func TestStale(t *testing.T) {
	built := time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC)
	d, _ := openDB(t, geotest.DB{Built: built})
	if d.Stale(built.Add(59*24*time.Hour)) || !d.Stale(built.Add(61*24*time.Hour)) {
		t.Error("Stale")
	}
}

func TestReload(t *testing.T) {
	d, logs := openDB(t, geotest.DB{})
	a := netip.MustParseAddr("203.0.113.1")
	replace := func(data []byte, mtime time.Time) {
		t.Helper()
		// Like geoipupdate: write a new file and rename it.
		tmp := d.path + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			t.Fatal(err)
		}
		os.Chtimes(tmp, mtime, mtime)
		if err := os.Rename(tmp, d.path); err != nil {
			t.Fatal(err)
		}
	}

	d.reload() // unchanged
	if logs.Len() != 0 {
		t.Errorf("log:\n%s", logs)
	}

	updated, _ := geotest.DB{Networks: map[string]any{"8.8.8.0/24": "US", "203.0.113.0/24": "KR"}}.Bytes()
	replace(updated, time.Now().Add(time.Minute))
	d.reload()
	if got := d.Country(a); got != "KR" {
		t.Errorf("after reload: %q", got)
	}
	if !strings.Contains(logs.String(), `level=INFO msg="GeoIP database reloaded"`) {
		t.Errorf("log:\n%s", logs)
	}

	// An invalid file is reported once, and the database is kept.
	logs.Reset()
	replace(updated[:100], time.Now().Add(2*time.Minute))
	d.reload()
	d.reload()
	if got := d.Country(a); got != "KR" {
		t.Errorf("after an invalid file: %q", got)
	}
	if n := strings.Count(logs.String(), "cannot reload the GeoIP database; keeping the one in use"); n != 1 {
		t.Errorf("%d errors:\n%s", n, logs)
	}

	// So is a missing file.
	logs.Reset()
	os.Remove(d.path)
	d.reload()
	d.reload()
	if n := strings.Count(logs.String(), "no such file"); n != 1 || d.Country(a) != "KR" {
		t.Errorf("%d errors:\n%s", n, logs)
	}

	// An outdated database is reported.
	logs.Reset()
	old, _ := geotest.DB{Built: time.Now().Add(-100 * 24 * time.Hour), Networks: testNetworks}.Bytes()
	replace(old, time.Now().Add(3*time.Minute))
	d.reload()
	if d.Country(a) != "JP" || !strings.Contains(logs.String(), `level=WARN msg="the GeoIP database is outdated"`) {
		t.Errorf("log:\n%s", logs)
	}
}

func newFilter(t *testing.T, cfg Config) *Filter {
	t.Helper()
	if cfg.DB == nil {
		cfg.DB, _ = openDB(t, geotest.DB{})
	}
	f, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

func TestCheck(t *testing.T) {
	allow := newFilter(t, Config{Allow: []string{"JP", "US"}})
	block := newFilter(t, Config{Block: []string{"CN", Unknown}})
	lookup := newFilter(t, Config{})
	for _, tc := range []struct {
		ip, country  string
		allow, block bool // allowed by the filter
	}{
		{"203.0.113.1", "JP", true, true},
		{"2001:db8:1::1", "JP", true, true},
		{"8.8.8.8", "US", true, true},
		{"::ffff:8.8.8.8", "US", true, true},
		{"198.51.100.1", "CN", false, false},
		{"2001:db8:2::1", "CN", false, false},
		{"1.1.1.1", "AU", false, true},
		{"9.9.9.9", Unknown, false, false},
		{"192.0.2.1", Unknown, false, false},
		// Not looked up: always allowed.
		{"127.0.0.1", "", true, true},
		{"::1", "", true, true},
		{"10.1.2.3", "", true, true},
		{"192.168.0.1", "", true, true},
		{"172.16.0.1", "", true, true},
		{"100.64.0.1", "", true, true},
		{"169.254.1.1", "", true, true},
		{"fe80::1", "", true, true},
		{"fd00::1", "", true, true},
		{"0.0.0.0", "", true, true},
		{"@", "", true, true}, // a Unix socket
	} {
		for _, c := range []struct {
			f       *Filter
			allowed bool
			list    string
		}{{allow, tc.allow, "allow"}, {block, tc.block, "block"}, {lookup, true, ""}} {
			d := c.f.Check(tc.ip)
			if d.Allowed != c.allowed || d.Country != tc.country {
				t.Errorf("%s with %s list: %+v", tc.ip, c.list, d)
			}
			if !d.Allowed && (d.List != c.list || d.EventID == "" || !d.Client.IsValid()) {
				t.Errorf("%s with %s list: %+v", tc.ip, c.list, d)
			}
		}
	}
}

func TestCheckExempt(t *testing.T) {
	f := newFilter(t, Config{Allow: []string{"JP"}, Exempt: []netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"), netip.MustParsePrefix("2001:db8:2::/64"),
	}})
	for _, ip := range []string{"198.51.100.1", "::ffff:198.51.100.1", "2001:db8:2::1"} {
		if d := f.Check(ip); !d.Allowed || d.Country != "CN" {
			t.Errorf("%s: %+v", ip, d)
		}
	}
	if d := f.Check("2001:db8:2:1::1"); d.Allowed {
		t.Errorf("outside the exempt network: %+v", d)
	}
}

func TestCheckEvents(t *testing.T) {
	f := newFilter(t, Config{Block: []string{"CN"}})
	now := time.Date(2026, 11, 17, 0, 0, 0, 0, time.UTC)
	f.now = func() time.Time { return now }

	d1 := f.Check("198.51.100.1")
	d2 := f.Check("198.51.100.1")
	other := f.Check("198.51.100.2")
	if !d1.First || d2.First || d1.EventID != d2.EventID || !other.First || other.EventID == d1.EventID {
		t.Errorf("events: %+v %+v %+v", d1, d2, other)
	}
	// An IPv6 client counts as its /64.
	v1, v2 := f.Check("2001:db8:2::1"), f.Check("2001:db8:2::2")
	if !v1.First || v2.First || v1.EventID != v2.EventID || v1.Client.String() != "2001:db8:2::/64" {
		t.Errorf("IPv6 events: %+v %+v", v1, v2)
	}
	now = now.Add(eventInterval)
	if d := f.Check("198.51.100.1"); !d.First || d.EventID == d1.EventID {
		t.Errorf("after a minute: %+v", d)
	}
}

func TestNewRejectsInvalidConfig(t *testing.T) {
	d, _ := openDB(t, geotest.DB{})
	for _, cfg := range []Config{
		{},
		{DB: d, Allow: []string{"JP"}, Block: []string{"CN"}},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("New(%+v) succeeded", cfg)
		}
	}
}

func BenchmarkCheck(b *testing.B) {
	path := filepath.Join(b.TempDir(), "country.mmdb")
	if err := (geotest.DB{Networks: testNetworks}).Write(path); err != nil {
		b.Fatal(err)
	}
	d, err := OpenDB(path, nil)
	if err != nil {
		b.Fatal(err)
	}
	f, _ := New(Config{DB: d, Allow: []string{"JP"}})
	for b.Loop() {
		f.Check("203.0.113.1")
	}
}
