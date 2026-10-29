package waf

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"

	"github.com/cmc-labo/prism-waf/internal/normalize"
)

// DefaultMaxBodySize is the default limit for request bodies that are
// buffered for inspection. It matches ModSecurity's default for request
// bodies without files. Inspection time grows linearly with body size: a
// body crafted to defeat the signature prefilters costs roughly 100ms of
// CPU at this size.
const DefaultMaxBodySize = 128 << 10 // 128 KiB

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
	// Base64 reports whether the match was found in Base64-decoded data.
	Base64 bool
	// Value is the raw value of the inspected part: the escaped path, the
	// raw query string, the header value or the body.
	Value string
	// Data is the text the signature matched, taken from the normalized
	// form of Value that matched.
	Data string
}

// Inspector checks requests against a set of signatures.
type Inspector struct {
	signatures  []compiledSignature
	maxBodySize int64
}

type compiledSignature struct {
	Signature
	re *regexp.Regexp
}

// find reports whether the signature matches text and returns the matched
// substring. The cheaper MatchString runs first, so the cost of extracting
// the match is only paid for requests that are blocked.
func (s *compiledSignature) find(text string) (string, bool) {
	if s.re == nil {
		if strings.Contains(text, s.Pattern) {
			return s.Pattern, true
		}
		return "", false
	}
	if len(s.Keywords) > 0 && !containsAny(text, s.Keywords) {
		return "", false
	}
	if !s.re.MatchString(text) {
		return "", false
	}
	return s.re.FindString(text), true
}

func containsAny(s string, substrs []string) bool {
	for _, sub := range substrs {
		if strings.Contains(s, sub) {
			return true
		}
	}
	return false
}

// NewInspector returns an Inspector using the given signatures. Patterns are
// matched case-insensitively. maxBodySize <= 0 selects DefaultMaxBodySize.
func NewInspector(signatures []Signature, maxBodySize int64) (*Inspector, error) {
	if maxBodySize <= 0 {
		maxBodySize = DefaultMaxBodySize
	}
	sigs := make([]compiledSignature, len(signatures))
	for i, s := range signatures {
		cs := compiledSignature{Signature: s}
		switch {
		case (s.Pattern == "") == (s.Regex == ""):
			return nil, fmt.Errorf("waf: signature %s: exactly one of Pattern and Regex must be set", s.ID)
		case s.Pattern != "" && len(s.Keywords) > 0:
			return nil, fmt.Errorf("waf: signature %s: Keywords requires Regex", s.ID)
		case s.Regex != "":
			re, err := regexp.Compile(s.Regex)
			if err != nil {
				return nil, fmt.Errorf("waf: signature %s: %w", s.ID, err)
			}
			cs.re = re
			cs.Keywords = make([]string, len(s.Keywords))
			for j, k := range s.Keywords {
				cs.Keywords[j] = strings.ToLower(k)
			}
		default:
			cs.Pattern = strings.ToLower(s.Pattern)
		}
		sigs[i] = cs
	}
	return &Inspector{signatures: sigs, maxBodySize: maxBodySize}, nil
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

// candidate is one form of an inspected value.
type candidate struct {
	text   string
	base64 bool
}

// match checks raw against every signature, trying each form returned by
// candidates.
func (in *Inspector) match(loc Location, field, raw string, opts normalize.Options) *Match {
	if raw == "" {
		return nil
	}
	cands := candidates(raw, opts)
	for _, s := range in.signatures {
		for _, c := range cands {
			if data, ok := s.find(c.text); ok {
				return &Match{
					Signature: s.Signature,
					Location:  loc,
					Field:     field,
					Base64:    c.base64,
					Value:     raw,
					Data:      data,
				}
			}
		}
	}
	return nil
}

// candidates returns the forms of raw that signatures are matched against:
//
//   - the raw value, lowercased
//   - the normalized value
//   - the normalized value with SQL comments replaced by spaces
//   - the normalized value with split keywords joined back together
//
// plus the last three forms of each Base64-encoded token found in raw.
func candidates(raw string, opts normalize.Options) []candidate {
	var out []candidate
	seen := map[string]bool{}
	add := func(text string, b64 bool) {
		if !seen[text] {
			seen[text] = true
			out = append(out, candidate{text: text, base64: b64})
		}
	}
	addForms := func(normalized string, b64 bool) {
		add(normalized, b64)
		add(normalize.StripSQLComments(normalized), b64)
		add(normalize.JoinSplitKeywords(normalized), b64)
	}

	add(normalize.CollapseSpaces(strings.ToLower(raw)), false)
	addForms(normalize.Normalize(raw, opts), false)
	for _, decoded := range normalize.DecodeBase64(raw) {
		addForms(normalize.Normalize(decoded, normalize.Options{}), true)
	}
	return out
}

func isFormEncoded(contentType string) bool {
	mt, _, err := mime.ParseMediaType(contentType)
	return err == nil && mt == "application/x-www-form-urlencoded"
}
