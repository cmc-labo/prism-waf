package normalize

import (
	"encoding/base64"
	"strings"
	"unicode"
	"unicode/utf8"
)

const (
	// minBase64Len is the shortest token treated as Base64. 12 characters
	// encode 9 bytes, enough for short payloads such as "<script>".
	minBase64Len = 12
	// maxBase64Tokens bounds the work spent on a single value.
	maxBase64Tokens = 32
)

// DecodeBase64 finds Base64-encoded tokens in s (as-is and after URL
// decoding) and returns the decoded text of those that decode to printable
// UTF-8. Tokens that decode to binary data, such as random IDs or ordinary
// words that happen to use only Base64 characters, are ignored.
//
// s must be the raw value: lowercasing or decoding '+' as a space would
// corrupt the encoding.
func DecodeBase64(s string) []string {
	var out []string
	seen := map[string]bool{}
	sources := []string{s}
	if u := percentDecode(s, false); u != s {
		sources = append(sources, u)
	}
	for _, src := range sources {
		for _, tok := range base64Tokens(src) {
			if d, ok := decodeBase64Token(tok); ok && !seen[d] {
				seen[d] = true
				out = append(out, d)
			}
		}
	}
	return out
}

// base64Tokens returns up to maxBase64Tokens runs of at least minBase64Len
// characters from the standard and URL-safe Base64 alphabets, each with up
// to two trailing '=' characters.
func base64Tokens(s string) []string {
	var toks []string
	for i := 0; i < len(s) && len(toks) < maxBase64Tokens; {
		if !isBase64Char(s[i]) {
			i++
			continue
		}
		start := i
		for i < len(s) && isBase64Char(s[i]) {
			i++
		}
		if i-start < minBase64Len {
			continue
		}
		for pad := 0; pad < 2 && i < len(s) && s[i] == '='; pad++ {
			i++
		}
		toks = append(toks, s[start:i])
	}
	return toks
}

func isBase64Char(c byte) bool {
	return 'A' <= c && c <= 'Z' || 'a' <= c && c <= 'z' || '0' <= c && c <= '9' ||
		c == '+' || c == '/' || c == '-' || c == '_'
}

func decodeBase64Token(tok string) (string, bool) {
	tok = strings.TrimRight(tok, "=")
	if len(tok) < minBase64Len || len(tok)%4 == 1 {
		return "", false
	}
	enc := base64.RawStdEncoding
	if strings.ContainsAny(tok, "-_") {
		if strings.ContainsAny(tok, "+/") {
			return "", false // mixed alphabets
		}
		enc = base64.RawURLEncoding
	}
	b, err := enc.DecodeString(tok)
	if err != nil || !isPrintableText(b) {
		return "", false
	}
	return string(b), true
}

func isPrintableText(b []byte) bool {
	if !utf8.Valid(b) {
		return false
	}
	for _, r := range string(b) {
		if !unicode.IsPrint(r) && !unicode.IsSpace(r) {
			return false
		}
	}
	return true
}
