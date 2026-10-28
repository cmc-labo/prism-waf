// Package waf implements request inspection for PrismWAF.
package waf

// Signature is an attack pattern. Exactly one of Pattern and Regex is set.
//
// Signatures are matched against normalized request data (see package
// normalize), so they should be written for normalized input: decoded,
// lowercase, single spaces, and forward slashes instead of backslashes.
// Because one of the candidates has SQL comments and quotes removed,
// regular expressions should allow zero whitespace between keywords
// ("union\s*select", not "union\s+select").
type Signature struct {
	ID       string
	Category string
	// Pattern matches when the input contains it (case-insensitive).
	Pattern string
	// Regex matches when the RE2 regular expression matches the input. RE2
	// runs in linear time, so patterns cannot cause catastrophic backtracking.
	Regex string
	// Keywords is an optional prefilter for Regex: the regular expression is
	// only evaluated when the input contains at least one keyword. A
	// substring search is much faster than a regex scan on large bodies.
	// Every string the regex can match must contain one of the keywords,
	// otherwise the signature can be bypassed.
	Keywords []string
}

// jsEventHandlers lists HTML event handler attributes commonly used in XSS.
const jsEventHandlers = `on(?:error|load|click|dblclick|auxclick|contextmenu|mouse[a-z]+|pointer[a-z]+|key[a-z]+|focus(?:in|out)?|blur|change|input|submit|reset|select|toggle|begin|end|start|finish|animation[a-z]+|transition[a-z]+|drag[a-z]*|drop|copy|cut|paste|scroll|wheel|resize|play|pause|show|search|unload|beforeunload|hashchange|message|popstate|pageshow|readystatechange)`

// DefaultSignatures is the built-in signature set.
//
// It targets common attack payloads and their usual syntax-level variations.
// It is a starting point rather than complete protection.
var DefaultSignatures = []Signature{
	// SQL injection
	{
		// ' or '1'='1, ' or 1=1, '||1=1, " and 2>1, ' or 'a' like 'a
		ID: "SQLI-001", Category: "sqli",
		Regex:    `['"]\s*(?:\b(?:or|and|xor)\b|\|\||&&)\s*['"(]?\s*[\w.]+\s*['")]?\s*(?:=|<>|!=|<|>|\blike\b)`,
		Keywords: []string{"=", "<", ">", "like"},
	},
	{
		// union select, union all select, union(select ...), union distinct select
		ID: "SQLI-002", Category: "sqli",
		Regex:    `\bunion[\s(]*(?:all|distinct)?[\s(]*select\b`,
		Keywords: []string{"union"},
	},
	{
		// '; drop table users, ;shutdown, ; exec xp_cmdshell
		ID: "SQLI-003", Category: "sqli",
		Regex: `;\s*(?:drop\s*(?:table|database|schema)\b|truncate\s*table\b|shutdown\b|exec(?:ute)?\s*(?:xp|sp)_)`,
	},
	{
		ID: "SQLI-004", Category: "sqli",
		Regex:    `\b(?:information_schema|mysql\.user|pg_catalog|pg_shadow|sysobjects|sqlite_master)\b`,
		Keywords: []string{"information_schema", "mysql.user", "pg_catalog", "pg_shadow", "sysobjects", "sqlite_master"},
	},
	{
		// Time-based blind injection.
		ID: "SQLI-005", Category: "sqli",
		Regex:    `\b(?:sleep|pg_sleep|benchmark)\s*\(|\bwaitfor\s*delay\b`,
		Keywords: []string{"sleep", "benchmark", "waitfor"},
	},
	{
		// File access and error-based extraction.
		ID: "SQLI-006", Category: "sqli",
		Regex:    `\bload_file\s*\(|\binto\s*(?:out|dump)file\b|\b(?:extractvalue|updatexml)\s*\(`,
		Keywords: []string{"load_file", "outfile", "dumpfile", "extractvalue", "updatexml"},
	},
	{
		// admin'-- and admin'#: a quote followed by a comment ending the value.
		ID: "SQLI-007", Category: "sqli",
		Regex:    `['"]\s*(?:--|#)\s*$`,
		Keywords: []string{"--", "#"},
	},

	// Cross-site scripting
	{
		ID: "XSS-001", Category: "xss",
		Regex: `<\s*/?\s*script\b`,
	},
	{
		// javascript:, java script: (browsers ignore tabs and newlines in
		// URL schemes), vbscript:, data:text/html
		ID: "XSS-002", Category: "xss",
		Regex:    `\b(?:j\s*a\s*v\s*a|v\s*b)\s*s\s*c\s*r\s*i\s*p\s*t\s*:|\bdata\s*:\s*text/html\b`,
		Keywords: []string{"t:", "t :", "text/html"},
	},
	{
		// An event handler inside a tag: <img src=x onerror=...>, <svg/onload=...>
		ID: "XSS-003", Category: "xss",
		Regex: `<[a-z][^>]*[\s/"']on[a-z]{3,}\s*=`,
	},
	{
		// Breaking out of an attribute: " onmouseover="...
		ID: "XSS-004", Category: "xss",
		Regex:    `["']\s*` + jsEventHandlers + `\s*=`,
		Keywords: []string{"="},
	},
	{
		ID: "XSS-005", Category: "xss",
		Regex: `<\s*(?:iframe|object|embed|applet)\b`,
	},
	{
		// alert(1), alert`1`, top[alert](1) (after joining 'al'+'ert'),
		// document.cookie, String.fromCharCode(...)
		ID: "XSS-006", Category: "xss",
		Regex:    "\\b(?:alert|prompt|confirm|eval)\\]?[(`]|\\bdocument\\s*\\.\\s*(?:cookie|domain|write)\\b|\\bstring\\s*\\.\\s*fromcharcode\\s*\\(",
		Keywords: []string{"alert", "prompt", "confirm", "eval", "document", "fromcharcode"},
	},

	// Path traversal
	{
		// ../ and Tomcat's ..;/
		ID: "PT-001", Category: "path-traversal",
		Regex: `\.\.;?/`,
	},
	{
		ID: "PT-002", Category: "path-traversal",
		Regex:    `/etc/(?:passwd|shadow|group|hosts)\b|/proc/self/|\b(?:win|boot|system)\.ini\b|\bc:/windows/`,
		Keywords: []string{"/etc/", "/proc/self/", ".ini", "c:/windows/"},
	},

	// OS command injection
	{
		// A command after a shell separator: ; cat /etc/x, | id, && whoami,
		// `uname`, $(curl ...). Short names that are also ordinary words
		// (id, ls, cat, ...) only count when they end the value, are followed
		// by another operator, or take an argument that looks like an option
		// or a path, so "dogs; id cards" is not flagged.
		ID: "CMDI-001", Category: "command-injection",
		Regex: "(?:;|\\|\\|?|&&|`|\\$\\()\\s*(?:" +
			"(?:whoami|uname|wget|curl|ncat|netcat|bash|zsh|python[0-9.]*|perl|nslookup|powershell|chmod)\\b|" +
			"(?:cat|ls|id|nc|sh|rm|ruby|php)(?:\\s*$|\\s*[;|&)`]|\\s+[-/.~$]))",
		Keywords: []string{";", "|", "&&", "`", "$("},
	},
	{
		ID: "CMDI-002", Category: "command-injection",
		Regex:    `/bin/(?:ba|z|da|k|c)?sh\b|\bcmd(?:\.exe)?\s*/c\b|\bpowershell(?:\.exe)?\s+-`,
		Keywords: []string{"/bin/", "cmd", "powershell"},
	},

	// Log4Shell (CVE-2021-44228). Nested lookups such as ${${lower:j}ndi:
	// are expanded during normalization.
	{
		ID: "JNDI-001", Category: "jndi-injection",
		Regex: `\$\{\s*jndi\s*:`,
	},
}
