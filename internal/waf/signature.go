// Package waf implements request inspection for PrismWAF.
package waf

// Signature is a simple attack pattern. A request matches a signature when
// any inspected part of it contains Pattern (case-insensitive).
type Signature struct {
	ID       string
	Category string
	Pattern  string
}

// DefaultSignatures is the built-in signature set.
//
// The patterns are intentionally simple substrings. They catch common,
// unobfuscated attack payloads and are meant as a starting point rather than
// complete protection.
var DefaultSignatures = []Signature{
	// SQL injection
	{ID: "SQLI-001", Category: "sqli", Pattern: "' or '1'='1"},
	{ID: "SQLI-002", Category: "sqli", Pattern: "' or 1=1"},
	{ID: "SQLI-003", Category: "sqli", Pattern: "union select"},
	{ID: "SQLI-004", Category: "sqli", Pattern: "union all select"},
	{ID: "SQLI-005", Category: "sqli", Pattern: "; drop table"},
	{ID: "SQLI-006", Category: "sqli", Pattern: "information_schema"},
	{ID: "SQLI-007", Category: "sqli", Pattern: "sleep("},
	{ID: "SQLI-008", Category: "sqli", Pattern: "benchmark("},

	// Cross-site scripting
	{ID: "XSS-001", Category: "xss", Pattern: "<script"},
	{ID: "XSS-002", Category: "xss", Pattern: "javascript:"},
	{ID: "XSS-003", Category: "xss", Pattern: "onerror="},
	{ID: "XSS-004", Category: "xss", Pattern: "onload="},
	{ID: "XSS-005", Category: "xss", Pattern: "<iframe"},
	{ID: "XSS-006", Category: "xss", Pattern: "document.cookie"},

	// Path traversal
	{ID: "PT-001", Category: "path-traversal", Pattern: "../"},
	{ID: "PT-002", Category: "path-traversal", Pattern: `..\`},
	{ID: "PT-003", Category: "path-traversal", Pattern: "/etc/passwd"},
	{ID: "PT-004", Category: "path-traversal", Pattern: `c:\windows\`},

	// OS command injection
	{ID: "CMDI-001", Category: "command-injection", Pattern: "/bin/sh"},
	{ID: "CMDI-002", Category: "command-injection", Pattern: "/bin/bash"},
	{ID: "CMDI-003", Category: "command-injection", Pattern: "cmd.exe"},
	{ID: "CMDI-004", Category: "command-injection", Pattern: "; cat "},
	{ID: "CMDI-005", Category: "command-injection", Pattern: "| cat "},
	{ID: "CMDI-006", Category: "command-injection", Pattern: "$(curl"},
	{ID: "CMDI-007", Category: "command-injection", Pattern: "$(wget"},

	// Log4Shell (CVE-2021-44228)
	{ID: "JNDI-001", Category: "jndi-injection", Pattern: "${jndi:"},
}
