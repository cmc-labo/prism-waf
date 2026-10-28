package normalize

import "testing"

func TestNormalize(t *testing.T) {
	tests := []struct {
		name string
		in   string
		opts Options
		want string
	}{
		{"plain", "Hello World", Options{}, "hello world"},
		{"percent", "%3Cscript%3E", Options{}, "<script>"},
		{"double percent", "%253Cscript%253E", Options{}, "<script>"},
		{"triple percent", "%25253Cscript%25253E", Options{}, "<script>"},
		{"percent unicode", "%u003Cscript%u003E", Options{}, "<script>"},
		{"malformed percent does not stop decoding", "%zz%3Cscript%3E%", Options{}, "%zz<script>%"},
		{"plus as space", "1+UNION+SELECT", Options{PlusAsSpace: true}, "1 union select"},
		{"plus kept", "a+b", Options{}, "a+b"},
		{"html named entity", "&lt;script&gt;", Options{}, "<script>"},
		{"html decimal entity", "&#60;script&#62;", Options{}, "<script>"},
		{"html hex entity", "&#x3C;script&#x3e;", Options{}, "<script>"},
		{"html entity no semicolon", "&#60script", Options{}, "<script"},
		{"html entity zero padded", "&#0000060;script", Options{}, "<script"},
		{"js hex escape", `\x3cscript\x3e`, Options{}, "<script>"},
		{"js unicode escape", `<script>`, Options{}, "<script>"},
		{"url-encoded html entity", "%26lt%3Bscript%26gt%3B", Options{}, "<script>"},
		{"html-encoded url escape", "&#37;3Cscript", Options{}, "<script"},
		{"fullwidth", "＜ｓｃｒｉｐｔ＞", Options{}, "<script>"},
		{"fullwidth sql", "ＵＮＩＯＮ　ＳＥＬＥＣＴ", Options{}, "union select"},
		{"mixed case", "UnIoN SeLeCt", Options{}, "union select"},
		{"null byte", "<scr%00ipt>", Options{}, "<script>"},
		{"zero width space", "<scr​ipt>", Options{}, "<script>"},
		{"tabs and newlines", "union%09%0a%0dselect", Options{}, "union select"},
		{"overlong dot", "%c0%ae%c0%ae/etc/passwd", Options{}, "../etc/passwd"},
		{"overlong slash", "..%c0%afetc%c0%afpasswd", Options{}, "../etc/passwd"},
		{"3-byte overlong dot", "%e0%80%ae%e0%80%ae/", Options{}, "../"},
		{"backslash", `..\..\windows\win.ini`, Options{}, "../../windows/win.ini"},
		{"encoded backslash", "..%5c..%5cwindows", Options{}, "../../windows"},
		{"duplicate slashes", "/etc//passwd", Options{}, "/etc/passwd"},
		{"dot segments", "/etc/./passwd", Options{}, "/etc/passwd"},
		{"dot-dot kept", "/a/../b", Options{}, "/a/../b"},
		{"utf-8 text preserved", "%E3%81%93%E3%82%93%E3%81%AB%E3%81%A1%E3%81%AF", Options{}, "こんにちは"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := Normalize(tc.in, tc.opts); got != tc.want {
				t.Errorf("Normalize(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}

func TestStripSQLComments(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"union/**/select", "union select"},
		{"union/*foo*/all/*bar*/select", "union all select"},
		{"/*!50000union*//*!select*/", "union select"},
		{"1 /*\nmultiline\n*/ or 1=1", "1 or 1=1"},
		{"no comments", "no comments"},
		{"*/*", "*/*"},
	}
	for _, tc := range tests {
		if got := StripSQLComments(tc.in); got != tc.want {
			t.Errorf("StripSQLComments(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}

func TestNormalizeTerminates(t *testing.T) {
	// Each round of decoding peels off one layer; more layers than
	// maxDecodeRounds must not hang and must leave the rest encoded.
	in := "%2525252525253C"
	if got := Normalize(in, Options{}); got == "<" {
		t.Errorf("Normalize(%q) decoded more than %d layers", in, maxDecodeRounds)
	}
}
