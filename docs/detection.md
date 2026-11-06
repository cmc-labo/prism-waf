# Signature detection

Each request is checked against the built-in signatures in
[`internal/waf/signature.go`](../internal/waf/signature.go). A signature is
either a case-insensitive substring or an [RE2](https://github.com/google/re2/wiki/Syntax)
regular expression, so variants such as `UNION(SELECT …)`, `' || 1=1` or
`<svg/onload=…>` are covered by a single rule. RE2 runs in linear time, so a
signature cannot be abused for ReDoS. A request is blocked when a signature
matches any of the following:

- the URL path
- the query string
- any header value
- the request body; JSON and XML bodies value by value (see below)

Before matching, every value is normalized so that encoded or obfuscated
payloads are detected (see [`internal/normalize`](../internal/normalize)):

| Evasion technique              | Example                      | Normalized    |
|--------------------------------|------------------------------|---------------|
| URL encoding (nested)          | `%253Cscript`                | `<script`     |
| IIS `%u` encoding              | `%u003Cscript`               | `<script`     |
| HTML entities                  | `&lt;` `&#60;` `&#x3c;`      | `<`           |
| JavaScript / JSON escapes      | `\x3c` `\u003c`              | `<`           |
| Overlong UTF-8                 | `%c0%ae%c0%ae/`              | `../`         |
| Fullwidth / compatibility (NFKC) | `＜ｓｃｒｉｐｔ＞`             | `<script>`    |
| Mixed case                     | `UnIoN SeLeCt`               | `union select`|
| NUL and zero-width characters  | `<scr%00ipt>`                | `<script>`    |
| Backslashes, `//`, `/./`       | `..\..\windows`              | `../../windows` |
| Whitespace variations          | `union%09%0aselect`          | `union select`|
| SQL comments                   | `union/**/select`            | `union select`|
| Log4j nested lookups           | `${${lower:j}ndi:`           | `${jndi:`     |

Decoders are applied repeatedly (up to five rounds) until the value stops
changing, so combinations such as URL-encoded HTML entities are unwrapped too.
Malformed escapes such as `%zz` are left as-is instead of aborting decoding.

Each value is matched in several forms:

| Form              | Purpose                                                        |
|-------------------|----------------------------------------------------------------|
| Raw (lowercased)  | Baseline                                                       |
| Normalized        | Decoded and canonicalized as above                             |
| Comments → spaces | `union/**/select` → `union select`                             |
| Keywords joined   | Undoes keyword splitting: `un/**/ion` → `union`, `'al'+'ert'` → `alert`, `c'a't` → `cat`, `c$@at` → `cat`, `cat${IFS}x` → `cat x`, `w^hoami` → `whoami` |
| Base64-decoded    | Tokens of 12+ Base64 / Base64url characters that decode to printable text are decoded and run through all of the above. Matches are logged with `base64=true`. |

Signature patterns should therefore be written in normalized form.

Large inputs are expensive to scan with regular expressions, so a signature
can declare `Keywords`: substrings that every match must contain. The regex
only runs when one of them is present, which makes typical inspection about
10× faster.

## JSON and XML bodies

Bodies with a JSON content type (`application/json`, `application/*+json`)
or an XML content type (`application/xml`, `text/xml`, `application/*+xml`
such as SOAP) are parsed, and every value is inspected on its own instead
of the body as a whole:

| Format | Inspected values | Example `match.field` |
|--------|------------------|-----------------------|
| JSON | Every string value and object key, including duplicate keys | `$.user.name`, `$.items[2]`, `$["a.b"]` |
| XML | Element text, attribute values, start tags (names only, to catch event handler attributes), comments, processing instructions, the DOCTYPE | `/order/item`, `/order/item/@id`, `/order/comment()`, `<!DOCTYPE>` |

This has three benefits:

- **Fewer false positives.** JSON and XML syntax around values can complete
  a pattern that no value contains: `{"filter":"and price>100"}` looks like
  `" and price>100` (SQL injection) to a raw scan, but the value alone is
  harmless.
- **Better detection.** Patterns that require the end of a value, such as
  `admin'--` or `; id`, now match inside a document. Escapes are decoded by
  the parser, and XML text is joined across CDATA sections, entity
  references and comments, so `<![CDATA[<scr]]><![CDATA[ipt>]]>` is
  inspected as `<script>`.
- **Precise audit events.** `match.field` names the value that matched and
  `match.value` holds its decoded content.

A body that is not valid UTF-8 or does not parse, for example truncated
JSON, a payload after the document, or an XML entity that only a DTD can
define, is inspected as a whole as before, so a malformed document cannot
hide a payload. Bodies with other content types are always inspected as a
whole.

XML bodies are also checked for XML external entity (XXE) attacks: external
entities and DTDs (`<!ENTITY x SYSTEM "…">`), entity expansion ("billion
laughs") and XInclude. These signatures apply to all other locations too.

## Body size

Request bodies are buffered in memory for inspection. Bodies larger than
`-max-body` (default 128 KiB, the same as ModSecurity's default for bodies
without files) are rejected with `413 Request Entity Too Large` rather than
partially inspected. Inspection cost grows with body size; a body crafted
to defeat the keyword prefilters takes about 100 ms of CPU at 128 KiB,
whether it is inspected raw or as JSON or XML, so raise the limit with
care.

The built-in signatures cover common payloads and their usual variations,
but no signature set is complete. Treat them as a baseline, not complete
protection.

For broader coverage, the built-in signatures can be combined with the
OWASP Core Rule Set; see [OWASP Core Rule Set](crs.md).
