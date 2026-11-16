// Package geotest writes small MaxMind DB files for tests, in the format
// of the country databases that PrismWAF reads.
//
// See https://maxmind.github.io/MaxMind-DB/ for the format.
package geotest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"maps"
	"net/netip"
	"os"
	"slices"
	"time"
)

// DB describes a database to write.
type DB struct {
	// Type is the database_type in the metadata, e.g. "GeoLite2-Country".
	// Empty means "GeoLite2-Country".
	Type string
	// Built is the build time in the metadata. Zero means now.
	Built time.Time
	// IPv4Only writes an IPv4 database (ip_version 4), which cannot hold
	// IPv6 networks.
	IPv4Only bool
	// Networks maps CIDR prefixes to records. A string is a country code,
	// stored as {"country": {"iso_code": code}} like GeoLite2; any other
	// value is stored as it is (string, uint16, uint32, uint64, []string or
	// map[string]any). Networks must not overlap.
	Networks map[string]any
}

// RegisteredCountry returns a GeoLite2 record with only a registered country, as
// for some anycast networks.
func RegisteredCountry(code string) map[string]any {
	return map[string]any{"registered_country": map[string]any{"iso_code": code}}
}

// Write writes the database to path.
func (db DB) Write(path string) error {
	b, err := db.Bytes()
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o644)
}

// node is a node of the search tree. A record is the index of a child node,
// or -1 for no data, or -2-offset for data at offset in the data section.
type node [2]int

const empty = -1

// Bytes returns the database file.
func (db DB) Bytes() ([]byte, error) {
	nodes := []node{{empty, empty}}
	var data bytes.Buffer
	for _, cidr := range slices.Sorted(maps.Keys(db.Networks)) {
		p, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, err
		}
		p = p.Masked()
		addr, length := p.Addr().As16(), p.Bits()
		if p.Addr().Is4() {
			if db.IPv4Only {
				a4 := p.Addr().As4()
				addr = [16]byte{}
				copy(addr[:], a4[:])
			} else {
				// IPv4 addresses are looked up in ::/96.
				a4 := p.Addr().As4()
				addr = [16]byte{}
				copy(addr[12:], a4[:])
				length += 96
			}
		} else if db.IPv4Only {
			return nil, fmt.Errorf("geotest: IPv6 network %s in an IPv4 database", cidr)
		}
		if length == 0 {
			return nil, fmt.Errorf("geotest: network %s covers everything", cidr)
		}

		rec := db.Networks[cidr]
		if code, ok := rec.(string); ok {
			rec = map[string]any{"country": map[string]any{"iso_code": code}}
		}
		offset := data.Len()
		if err := encode(&data, rec); err != nil {
			return nil, err
		}

		n := 0
		for i := range length {
			bit := int(addr[i/8]>>(7-i%8)) & 1
			if i == length-1 {
				if nodes[n][bit] != empty {
					return nil, fmt.Errorf("geotest: network %s overlaps another", cidr)
				}
				nodes[n][bit] = -2 - offset
				break
			}
			switch next := nodes[n][bit]; {
			case next == empty:
				nodes = append(nodes, node{empty, empty})
				nodes[n][bit] = len(nodes) - 1
				n = len(nodes) - 1
			case next < 0:
				return nil, fmt.Errorf("geotest: network %s overlaps another", cidr)
			default:
				n = next
			}
		}
	}
	var out bytes.Buffer
	count := len(nodes)
	value := func(r int) int {
		switch {
		case r == empty:
			return count
		case r < 0:
			return count + 16 + (-2 - r)
		}
		return r
	}
	for _, n := range nodes {
		for _, r := range n {
			v := value(r)
			if v >= 1<<24 {
				return nil, fmt.Errorf("geotest: database too large")
			}
			out.Write([]byte{byte(v >> 16), byte(v >> 8), byte(v)})
		}
	}
	out.Write(make([]byte, 16))
	out.Write(data.Bytes())

	typ, built, version := db.Type, db.Built, uint16(6)
	if typ == "" {
		typ = "GeoLite2-Country"
	}
	if built.IsZero() {
		built = time.Now()
	}
	if db.IPv4Only {
		version = 4
	}
	out.WriteString("\xab\xcd\xefMaxMind.com")
	err := encode(&out, map[string]any{
		"binary_format_major_version": uint16(2),
		"binary_format_minor_version": uint16(0),
		"build_epoch":                 uint64(built.Unix()),
		"database_type":               typ,
		"description":                 map[string]any{"en": "PrismWAF test database"},
		"ip_version":                  version,
		"languages":                   []string{"en"},
		"node_count":                  uint32(count),
		"record_size":                 uint16(24),
	})
	return out.Bytes(), err
}

// Data types of the format.
const (
	typeString = 2
	typeUint16 = 5
	typeUint32 = 6
	typeMap    = 7
	typeUint64 = 9
	typeArray  = 11
)

func encode(w *bytes.Buffer, v any) error {
	switch v := v.(type) {
	case string:
		control(w, typeString, len(v))
		w.WriteString(v)
	case uint16:
		writeUint(w, typeUint16, uint64(v))
	case uint32:
		writeUint(w, typeUint32, uint64(v))
	case uint64:
		writeUint(w, typeUint64, v)
	case []string:
		control(w, typeArray, len(v))
		for _, s := range v {
			encode(w, s)
		}
	case map[string]any:
		control(w, typeMap, len(v))
		for _, k := range slices.Sorted(maps.Keys(v)) {
			encode(w, k)
			if err := encode(w, v[k]); err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("geotest: cannot encode %T", v)
	}
	return nil
}

func writeUint(w *bytes.Buffer, typ int, v uint64) {
	var b [8]byte
	binary.BigEndian.PutUint64(b[:], v)
	i := 0
	for i < 8 && b[i] == 0 {
		i++
	}
	control(w, typ, 8-i)
	w.Write(b[i:])
}

// control writes the control byte of a value: its type and size.
func control(w *bytes.Buffer, typ, size int) {
	first, ext := byte(typ<<5), -1
	if typ > 7 {
		first, ext = 0, typ-7
	}
	var extra []byte
	switch {
	case size < 29:
		first |= byte(size)
	case size < 29+256:
		first |= 29
		extra = []byte{byte(size - 29)}
	case size < 285+65536:
		first |= 30
		extra = []byte{byte((size - 285) >> 8), byte(size - 285)}
	default:
		first |= 31
		s := size - 65821
		extra = []byte{byte(s >> 16), byte(s >> 8), byte(s)}
	}
	w.WriteByte(first)
	if ext >= 0 {
		w.WriteByte(byte(ext))
	}
	w.Write(extra)
}
