// Package normalize turns obfuscated request data into a canonical form so
// that simple signatures can match it.
//
// Attackers hide payloads behind encodings that the backend will undo but a
// naive WAF will not, for example "%253Cscript" (double URL encoding),
// "&#x3c;script" (HTML entities), "<script" (JavaScript escapes) or
// "＜script" (fullwidth characters). Normalize reverses these encodings and
// canonicalizes the result before signatures are matched.
package normalize

import (
	"html"
	"regexp"
	"strings"
	"unicode"
	"unicode/utf8"

	"golang.org/x/text/unicode/norm"
)

// maxDecodeRounds bounds how many times the decoders are applied, so that
// nested encodings (e.g. URL-encoded HTML entities) are unwrapped without
// letting a crafted input loop for long.
const maxDecodeRounds = 5

// Options controls location-specific decoding.
type Options struct {
	// PlusAsSpace decodes '+' as a space, as in query strings and
	// application/x-www-form-urlencoded bodies.
	PlusAsSpace bool
}

// Normalize decodes and canonicalizes s. The steps are:
//
//  1. Repeatedly decode, until the value stops changing:
//     percent-encoding (including the non-standard %uXXXX form),
//     overlong UTF-8 sequences (e.g. %c0%ae for '.'),
//     HTML entities (&lt; &#60; &#x3c;) and
//     backslash escapes (\x3c, <).
//  2. Apply Unicode NFKC normalization, which maps fullwidth and other
//     compatibility characters to their ASCII equivalents (＜ → <).
//  3. Lowercase.
//  4. Remove NUL, control and invisible formatting characters
//     (e.g. zero-width spaces).
//  5. Expand Log4j-style lookups that only rewrite text, such as
//     "${lower:j}" or "${::-j}", so "${${lower:j}ndi:" becomes "${jndi:".
//  6. Convert backslashes to slashes and simplify "//" and "/./".
//  7. Collapse each run of whitespace into a single space.
func Normalize(s string, o Options) string {
	for range maxDecodeRounds {
		d := s
		d = percentDecode(d, o.PlusAsSpace)
		d = decodeOverlongUTF8(d)
		d = html.UnescapeString(d)
		d = decodeEscapes(d)
		if d == s {
			break
		}
		s = d
	}
	s = norm.NFKC.String(s)
	s = strings.ToLower(s)
	s = removeInvisible(s)
	s = expandLookups(s)
	s = normalizeSlashes(s)
	return CollapseSpaces(s)
}

// CollapseSpaces collapses each run of whitespace into a single space and
// trims leading and trailing whitespace.
func CollapseSpaces(s string) string {
	return strings.Join(strings.Fields(s), " ")
}

var (
	reSQLVersionedComment = regexp.MustCompile(`(?s)/\*!\d*(.*?)\*/`)
	reSQLBlockComment     = regexp.MustCompile(`(?s)/\*.*?\*/`)
)

// StripSQLComments replaces SQL block comments with a space, so that
// "union/**/select" becomes "union select". MySQL versioned comments such as
// "/*!50000select*/" are executed by MySQL, so their content is kept.
//
// The result is meant as an additional candidate for matching, not a
// replacement for the input: removing comments can also remove text that
// matters, such as "/*/../*/" in a path.
func StripSQLComments(s string) string {
	s = reSQLVersionedComment.ReplaceAllString(s, " $1 ")
	s = reSQLBlockComment.ReplaceAllString(s, " ")
	return CollapseSpaces(s)
}

// maxLookupRounds bounds how many levels of nested lookups are expanded.
const maxLookupRounds = 10

var (
	// ${lower:x} and ${upper:x}
	reLookupCase = regexp.MustCompile(`\$\{(?:lower|upper):([^${}]*)\}`)
	// ${anything:-x}, e.g. ${::-x} or ${env:UNDEFINED:-x}
	reLookupDefault = regexp.MustCompile(`\$\{[^${}]*?:-([^${}]*)\}`)
	// ${date:'x'}
	reLookupDate = regexp.MustCompile(`\$\{date:'([^${}']*)'\}`)
)

// expandLookups replaces Log4j lookups whose result is a literal string with
// that string. Attackers nest them to spell out "jndi" without writing it,
// e.g. "${${::-j}${lower:N}di:ldap://...}". The same syntax covers shell
// default-value expansion (${VAR:-x}).
func expandLookups(s string) string {
	if !strings.Contains(s, "${") {
		return s
	}
	for range maxLookupRounds {
		d := reLookupCase.ReplaceAllString(s, "$1")
		d = reLookupDefault.ReplaceAllString(d, "$1")
		d = reLookupDate.ReplaceAllString(d, "$1")
		if d == s {
			break
		}
		s = d
	}
	return s
}

// percentDecode decodes %XX and %uXXXX sequences. Unlike url.QueryUnescape it
// never fails: malformed sequences are kept as-is, so that a single "%zz"
// cannot be used to disable decoding of the whole value.
func percentDecode(s string, plusAsSpace bool) string {
	if !strings.ContainsRune(s, '%') && !(plusAsSpace && strings.ContainsRune(s, '+')) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '+' && plusAsSpace:
			b.WriteByte(' ')
		case c == '%' && i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') && isHex(s[i+2:i+6]):
			b.WriteRune(rune(hexValue(s[i+2 : i+6])))
			i += 5
		case c == '%' && i+2 < len(s) && isHex(s[i+1:i+3]):
			b.WriteByte(byte(hexValue(s[i+1 : i+3])))
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// decodeOverlongUTF8 replaces overlong UTF-8 encodings of ASCII characters
// (e.g. 0xC0 0xAE for '.') with the character itself. Such sequences are
// invalid UTF-8, but some decoders accept them, which historically allowed
// path traversal bypasses.
func decodeOverlongUTF8(s string) string {
	if utf8.ValidString(s) {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case (c == 0xC0 || c == 0xC1) && i+1 < len(s) && isContinuation(s[i+1]):
			b.WriteByte((c&0x1F)<<6 | s[i+1]&0x3F)
			i++
		case c == 0xE0 && i+2 < len(s) && s[i+1] == 0x80 && isContinuation(s[i+2]):
			b.WriteByte(s[i+2] & 0x3F)
			i += 2
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// decodeEscapes decodes \xXX and \uXXXX escape sequences as used in
// JavaScript, JSON and many other languages.
func decodeEscapes(s string) string {
	if !strings.ContainsRune(s, '\\') {
		return s
	}
	var b strings.Builder
	b.Grow(len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\\' && i+5 < len(s) && (s[i+1] == 'u' || s[i+1] == 'U') && isHex(s[i+2:i+6]):
			b.WriteRune(rune(hexValue(s[i+2 : i+6])))
			i += 5
		case c == '\\' && i+3 < len(s) && (s[i+1] == 'x' || s[i+1] == 'X') && isHex(s[i+2:i+4]):
			b.WriteByte(byte(hexValue(s[i+2 : i+4])))
			i += 3
		default:
			b.WriteByte(c)
		}
	}
	return b.String()
}

// removeInvisible drops control characters (other than whitespace) and
// invisible formatting characters such as U+200B ZERO WIDTH SPACE, which
// attackers insert to split keywords ("<scr\x00ipt>").
func removeInvisible(s string) string {
	return strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return r
		}
		if unicode.IsControl(r) || unicode.Is(unicode.Cf, r) {
			return -1
		}
		return r
	}, s)
}

// normalizeSlashes converts backslashes to slashes and simplifies "//" and
// "/./" to "/". It deliberately does not resolve "..", since "../" is itself
// an attack indicator.
func normalizeSlashes(s string) string {
	if !strings.ContainsAny(s, `/\`) {
		return s
	}
	s = strings.ReplaceAll(s, `\`, "/")
	for strings.Contains(s, "//") {
		s = strings.ReplaceAll(s, "//", "/")
	}
	for strings.Contains(s, "/./") {
		s = strings.ReplaceAll(s, "/./", "/")
	}
	return s
}

func isContinuation(c byte) bool { return c&0xC0 == 0x80 }

func isHex(s string) bool {
	for i := 0; i < len(s); i++ {
		if hexDigit(s[i]) < 0 {
			return false
		}
	}
	return true
}

func hexValue(s string) int {
	v := 0
	for i := 0; i < len(s); i++ {
		v = v<<4 | hexDigit(s[i])
	}
	return v
}

func hexDigit(c byte) int {
	switch {
	case '0' <= c && c <= '9':
		return int(c - '0')
	case 'a' <= c && c <= 'f':
		return int(c-'a') + 10
	case 'A' <= c && c <= 'F':
		return int(c-'A') + 10
	}
	return -1
}
