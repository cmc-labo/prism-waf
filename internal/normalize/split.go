package normalize

import (
	"regexp"
	"strings"
)

var (
	// A closing quote, an optional concatenation operator (+ in JavaScript,
	// || in SQL, . in PHP) and an opening quote: 'al'+'ert' -> 'alert'.
	reStringConcat = regexp.MustCompile("['\"`]\\s*(?:\\+|\\|\\||\\.)?\\s*['\"`]")
	// Shell expansions that evaluate to nothing or to a space:
	// c$@at, c$*at, cat${IFS}/etc/passwd, cat$IFS/etc/passwd.
	reShellEmpty = regexp.MustCompile(`\$[@*]`)
	reShellIFS   = regexp.MustCompile(`\$\{ifs\}|\$ifs\b`)
)

// wordBreakers are characters that interpreters drop when used inside a word:
// quotes in shells (c'a't, c"a"t) and ^ in cmd.exe (w^hoami).
const wordBreakers = "'\"`^"

// JoinSplitKeywords undoes common ways of splitting a keyword into pieces
// that an interpreter joins back together. s must already be normalized.
//
//   - SQL comment markers are removed rather than replaced by a space, so
//     "un/**/ion" becomes "union" and "union/**/select" becomes "unionselect".
//   - String concatenation is joined: 'al'+'ert', 'sel'||'ect', "a"."b".
//   - Shell no-op expansions are removed: c$@at, cat${IFS}/etc/passwd.
//   - Quotes and carets inside words are removed: c'a't, w^hoami.
//
// Like StripSQLComments, the result is an additional candidate for
// matching. It removes all quotes, so signatures that rely on quotes will
// only match the other candidates.
func JoinSplitKeywords(s string) string {
	if !strings.ContainsAny(s, "/*'\"`^$") {
		return s
	}
	if strings.Contains(s, "/*") {
		s = reSQLVersionedComment.ReplaceAllString(s, "$1")
		s = reSQLBlockComment.ReplaceAllString(s, "")
	}
	if strings.ContainsAny(s, "'\"`") {
		s = reStringConcat.ReplaceAllString(s, "")
	}
	if strings.ContainsRune(s, '$') {
		s = reShellEmpty.ReplaceAllString(s, "")
		s = reShellIFS.ReplaceAllString(s, " ")
	}
	s = strings.Map(func(r rune) rune {
		if strings.ContainsRune(wordBreakers, r) {
			return -1
		}
		return r
	}, s)
	return CollapseSpaces(s)
}
