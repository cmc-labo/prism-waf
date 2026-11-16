// Package geo looks up the country of clients in a MaxMind DB file, such as
// GeoLite2 or GeoIP2 Country or City, DB-IP IP to Country or IPinfo Lite,
// and allows or blocks requests by country.
package geo

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"os"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/oschwald/maxminddb-golang/v2"
	"golang.org/x/text/language"

	"github.com/cmc-labo/prism-waf/internal/audit"
	"github.com/cmc-labo/prism-waf/internal/ratelimit"
)

// Unknown is the country code of public addresses that the database has
// no country for. It can be listed like a country.
const Unknown = "XX"

// CountryHeader passes the client's country to the backend, e.g. "JP". It
// is absent for clients with a private address.
const CountryHeader = "X-Prismwaf-Country"

// reloadInterval is how often the database file is checked for changes.
const reloadInterval = time.Minute

// staleAge is the age from which a database is reported as outdated.
// Addresses move between countries, and providers update their
// databases weekly or monthly.
const staleAge = 60 * 24 * time.Hour

// Audit events of blocked clients are logged once per client and
// eventInterval; at most maxEvents clients are remembered.
const (
	eventInterval = time.Minute
	maxEvents     = 100_000
)

// probes are well-known public addresses that a country database must
// have a country for.
var probes = []netip.Addr{netip.MustParseAddr("8.8.8.8"), netip.MustParseAddr("1.1.1.1")}

// sharedAddressSpace is used inside carrier networks (RFC 6598); like
// private addresses, it has no country.
var sharedAddressSpace = netip.MustParsePrefix("100.64.0.0/10")

// ParseCountries parses a comma-separated list of ISO 3166-1 alpha-2
// country codes, e.g. "JP,US", in any case. Unknown (XX) is accepted.
func ParseCountries(s string) ([]string, error) {
	var out []string
	for _, f := range strings.Split(s, ",") {
		code := strings.ToUpper(strings.TrimSpace(f))
		if code == "" {
			continue
		}
		if code != Unknown {
			r, err := language.ParseRegion(code)
			if len(code) != 2 || err != nil || !r.IsCountry() {
				return nil, fmt.Errorf("geo: invalid country %q: want an ISO 3166-1 alpha-2 code, e.g. JP, or %s for unknown", f, Unknown)
			}
			if c := r.Canonicalize().String(); c != code {
				return nil, fmt.Errorf("geo: invalid country %q: the ISO 3166-1 code is %s", f, c)
			}
		}
		if !slices.Contains(out, code) {
			out = append(out, code)
		}
	}
	return out, nil
}

// countryPaths are the fields that hold the country code in the supported
// databases, in order of preference.
var countryPaths = [][]any{
	{"country", "iso_code"},
	// The country in which the network is registered, which GeoLite2
	// gives alone for some networks, e.g. anycast ones.
	{"registered_country", "iso_code"},
	// IPinfo, whose "country" is the name.
	{"country_code"},
}

// DB is a country database that is reloaded when its file changes. It is
// safe for concurrent use.
type DB struct {
	path   string
	logger *slog.Logger
	reader atomic.Pointer[maxminddb.Reader]

	mu   sync.Mutex
	seen fileState // the file last loaded or tried
}

type fileState struct {
	modTime time.Time
	size    int64
}

// OpenDB loads the database at path. Nil logger uses slog.Default().
func OpenDB(path string, logger *slog.Logger) (*DB, error) {
	if logger == nil {
		logger = slog.Default()
	}
	d := &DB{path: path, logger: logger}
	r, st, err := d.load()
	if err != nil {
		return nil, err
	}
	d.reader.Store(r)
	d.seen = st
	return d, nil
}

// load reads and checks the file. The whole file is read into memory, so
// that replacing it cannot affect lookups in progress.
func (d *DB) load() (*maxminddb.Reader, fileState, error) {
	fi, err := os.Stat(d.path)
	if err != nil {
		return nil, fileState{}, fmt.Errorf("geo: %w", err)
	}
	st := fileState{fi.ModTime(), fi.Size()}
	b, err := os.ReadFile(d.path)
	if err != nil {
		return nil, st, fmt.Errorf("geo: %w", err)
	}
	r, err := maxminddb.OpenBytes(b)
	if err == nil {
		// Also catches files that are truncated or still being written.
		err = r.Verify()
	}
	if err != nil {
		return nil, st, fmt.Errorf("geo: %s is not a valid MaxMind DB file: %w", d.path, err)
	}
	for _, a := range probes {
		if country(r, a) != "" {
			return r, st, nil
		}
	}
	return nil, st, fmt.Errorf("geo: %s (%s) has no country for %s: use a country or city database",
		d.path, r.Metadata.DatabaseType, probes[0])
}

// Metadata describes the database in use.
func (d *DB) Metadata() maxminddb.Metadata { return d.reader.Load().Metadata }

// Stale reports whether the database was built more than staleAge ago.
func (d *DB) Stale(now time.Time) bool {
	return now.Sub(d.Metadata().BuildTime()) > staleAge
}

// Country returns the country code of a, or "" if the database has none.
func (d *DB) Country(a netip.Addr) string { return country(d.reader.Load(), a) }

func country(r *maxminddb.Reader, a netip.Addr) string {
	res := r.Lookup(a.Unmap())
	if !res.Found() {
		// Also for errors: an IPv6 address in an IPv4 database.
		return ""
	}
	for _, path := range countryPaths {
		var c string
		// A field of another type is skipped, like a missing one.
		if res.DecodePath(&c, path...) == nil && c != "" {
			return strings.ToUpper(c)
		}
	}
	return ""
}

// Run reloads the database when its file changes, until ctx is done. A
// file that cannot be loaded is reported, and the database in use is kept.
func (d *DB) Run(ctx context.Context) {
	t := time.NewTicker(reloadInterval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			d.reload()
		}
	}
}

func (d *DB) reload() {
	d.mu.Lock()
	defer d.mu.Unlock()
	var st fileState
	fi, err := os.Stat(d.path)
	if err == nil {
		st = fileState{fi.ModTime(), fi.Size()}
	}
	if st == d.seen {
		return // unchanged, or still missing
	}
	d.seen = st
	var r *maxminddb.Reader
	if err == nil {
		r, _, err = d.load()
	}
	if err != nil {
		// A file still being written is tried again once it changes.
		d.logger.Error("cannot reload the GeoIP database; keeping the one in use", "path", d.path, "error", err)
		return
	}
	d.reader.Store(r)
	m := r.Metadata
	d.logger.Info("GeoIP database reloaded", "path", d.path, "type", m.DatabaseType, "built", m.BuildTime().UTC().Format(time.DateOnly))
	if d.Stale(time.Now()) {
		d.logger.Warn("the GeoIP database is outdated", "built", m.BuildTime().UTC().Format(time.DateOnly), "hint", "update it at least monthly")
	}
}

// Config configures a Filter.
type Config struct {
	DB *DB
	// Allow lets only clients from these countries through. Block rejects
	// clients from these countries. At most one of them may be set; with
	// neither, the filter only looks up countries.
	Allow, Block []string
	// Exempt clients are never blocked, e.g. partners abroad.
	Exempt []netip.Prefix
}

// Filter allows or blocks clients by country. It is safe for concurrent
// use.
type Filter struct {
	db           *DB
	allow, block []string
	exempt       []netip.Prefix
	now          func() time.Time // for tests

	mu     sync.Mutex
	events map[netip.Prefix]event
}

type event struct {
	id      string
	expires time.Time
}

// New returns a Filter.
func New(cfg Config) (*Filter, error) {
	if cfg.DB == nil {
		return nil, errors.New("geo: no database")
	}
	if len(cfg.Allow) > 0 && len(cfg.Block) > 0 {
		return nil, errors.New("geo: allowed and blocked countries are mutually exclusive")
	}
	return &Filter{
		db:     cfg.DB,
		allow:  cfg.Allow,
		block:  cfg.Block,
		exempt: cfg.Exempt,
		now:    time.Now,
		events: map[netip.Prefix]event{},
	}, nil
}

// DB returns the database of the filter.
func (f *Filter) DB() *DB { return f.db }

// Filtering reports whether the filter blocks any clients.
func (f *Filter) Filtering() bool { return len(f.allow) > 0 || len(f.block) > 0 }

// Decision is the result of Check.
type Decision struct {
	// Allowed is false if the client's country is not allowed.
	Allowed bool
	// Country is the client's country code, Unknown if the database has
	// none, or "" for private addresses and non-IP clients, which are not
	// looked up.
	Country string
	// List is the list that blocked the client: "allow" (not in it) or
	// "block".
	List string
	// Client is the address or, for IPv6, the /64 network that audit
	// events are counted for.
	Client netip.Prefix
	// EventID identifies the audit event of a blocked client. A client
	// gets the same ID for a minute.
	EventID string
	// First reports whether the event is new and should be logged.
	First bool
}

// Check looks up the country of the client with the given IP address and
// reports whether it may pass. Clients with private, loopback, link-local
// or shared (100.64.0.0/10) addresses have no country and always pass.
func (f *Filter) Check(clientIP string) Decision {
	a, err := netip.ParseAddr(clientIP)
	if err != nil {
		// Not an IP address, e.g. a Unix socket.
		return Decision{Allowed: true}
	}
	a = a.Unmap()
	if !a.IsGlobalUnicast() || a.IsPrivate() || sharedAddressSpace.Contains(a) {
		return Decision{Allowed: true}
	}
	d := Decision{Allowed: true, Country: f.db.Country(a)}
	if d.Country == "" {
		d.Country = Unknown
	}
	switch {
	case len(f.allow) > 0 && !slices.Contains(f.allow, d.Country):
		d.Allowed, d.List = false, "allow"
	case slices.Contains(f.block, d.Country):
		d.Allowed, d.List = false, "block"
	}
	if d.Allowed {
		return d
	}
	for _, p := range f.exempt {
		if p.Contains(a) {
			return Decision{Allowed: true, Country: d.Country}
		}
	}
	d.Client = clientKey(a)
	d.EventID, d.First = f.event(d.Client)
	return d
}

// event returns the audit event ID of a blocked client, and whether it is
// new.
func (f *Filter) event(client netip.Prefix) (id string, first bool) {
	now := f.now()
	f.mu.Lock()
	defer f.mu.Unlock()
	if e, ok := f.events[client]; ok && now.Before(e.expires) {
		return e.id, false
	}
	if len(f.events) >= maxEvents {
		for k, e := range f.events {
			if !now.Before(e.expires) {
				delete(f.events, k)
			}
		}
	}
	id = audit.NewID()
	if len(f.events) < maxEvents {
		f.events[client] = event{id, now.Add(eventInterval)}
	}
	return id, true
}

// clientKey returns the address, or the /64 network of an IPv6 address,
// that audit events are counted for.
func clientKey(a netip.Addr) netip.Prefix {
	if a.Is6() {
		p, _ := a.Prefix(ratelimit.IPv6Prefix)
		return p
	}
	return netip.PrefixFrom(a, a.BitLen())
}
