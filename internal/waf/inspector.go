package waf

import (
	"bytes"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/cmc-labo/prism-waf/internal/normalize"
)

// DefaultMaxBodySize is the default limit for request bodies that are
// buffered for inspection.
const DefaultMaxBodySize = 1 << 20 // 1 MiB

// ErrBodyTooLarge is returned when a request body exceeds the inspection limit.
var ErrBodyTooLarge = errors.New("waf: request body too large to inspect")

// Location identifies the part of a request where a signature matched.
type Location string

const (
	LocationPath   Location = "path"
	LocationQuery  Location = "query"
	LocationHeader Location = "header"
	LocationBody   Location = "body"
)

// Match describes a signature hit.
type Match struct {
	Signature Signature
	Location  Location
	// Field is the header name for LocationHeader and empty otherwise.
	Field string
}

// Inspector checks requests against a set of signatures.
type Inspector struct {
	signatures  []Signature
	maxBodySize int64
}

// NewInspector returns an Inspector using the given signatures. Patterns are
// matched case-insensitively. maxBodySize <= 0 selects DefaultMaxBodySize.
func NewInspector(signatures []Signature, maxBodySize int64) *Inspector {
	if maxBodySize <= 0 {
		maxBodySize = DefaultMaxBodySize
	}
	sigs := make([]Signature, len(signatures))
	for i, s := range signatures {
		s.Pattern = strings.ToLower(s.Pattern)
		sigs[i] = s
	}
	return &Inspector{signatures: sigs, maxBodySize: maxBodySize}
}

// Inspect checks the path, query string, headers and body of r, in that
// order, and returns the first match, or nil if the request is clean.
//
// The body is read into memory and r.Body is replaced so the request can
// still be forwarded. Bodies larger than the configured limit are rejected
// with ErrBodyTooLarge rather than partially inspected.
func (in *Inspector) Inspect(r *http.Request) (*Match, error) {
	if m := in.match(LocationPath, "", r.URL.EscapedPath(), normalize.Options{}); m != nil {
		return m, nil
	}
	if m := in.match(LocationQuery, "", r.URL.RawQuery, normalize.Options{PlusAsSpace: true}); m != nil {
		return m, nil
	}
	for name, values := range r.Header {
		for _, v := range values {
			if m := in.match(LocationHeader, name, v, normalize.Options{PlusAsSpace: true}); m != nil {
				return m, nil
			}
		}
	}

	body, err := in.readBody(r)
	if err != nil {
		return nil, err
	}
	if len(body) > 0 {
		opts := normalize.Options{PlusAsSpace: isFormEncoded(r.Header.Get("Content-Type"))}
		if m := in.match(LocationBody, "", string(body), opts); m != nil {
			return m, nil
		}
	}
	return nil, nil
}

// readBody buffers the request body and restores it on r.
func (in *Inspector) readBody(r *http.Request) ([]byte, error) {
	if r.Body == nil || r.Body == http.NoBody {
		return nil, nil
	}
	if r.ContentLength > in.maxBodySize {
		return nil, ErrBodyTooLarge
	}
	body, err := io.ReadAll(io.LimitReader(r.Body, in.maxBodySize+1))
	r.Body.Close()
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > in.maxBodySize {
		return nil, ErrBodyTooLarge
	}
	r.Body = io.NopCloser(bytes.NewReader(body))
	return body, nil
}

// match checks raw against every signature. Three forms of the value are
// tried: the raw value (lowercased), its normalized form, and the normalized
// form with SQL comments removed.
func (in *Inspector) match(loc Location, field, raw string, opts normalize.Options) *Match {
	if raw == "" {
		return nil
	}
	normalized := normalize.Normalize(raw, opts)
	candidates := uniq(
		normalize.CollapseSpaces(strings.ToLower(raw)),
		normalized,
		normalize.StripSQLComments(normalized),
	)
	for _, s := range in.signatures {
		for _, c := range candidates {
			if strings.Contains(c, s.Pattern) {
				return &Match{Signature: s, Location: loc, Field: field}
			}
		}
	}
	return nil
}

// uniq returns ss without consecutive duplicates.
func uniq(ss ...string) []string {
	out := ss[:1]
	for _, s := range ss[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}

func isFormEncoded(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "application/x-www-form-urlencoded"
}
