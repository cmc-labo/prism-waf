package normalize

import "testing"

func TestJoinSplitKeywords(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"un/**/ion se/**/lect", "union select"},
		{"union/**/select", "unionselect"},
		{"un/*comment*/ion", "union"},
		{"/*!50000un*/ion", "union"},
		{"'al'+'ert'", "alert"},
		{"'sel'||'ect'", "select"},
		{`"doc"."ument"`, "document"},
		{"c'a't /etc/passwd", "cat /etc/passwd"},
		{`c"a"t`, "cat"},
		{"c$@at", "cat"},
		{"cat${ifs}/etc/passwd", "cat /etc/passwd"},
		{"cat$ifs/etc/passwd", "cat /etc/passwd"},
		{"w^ho^ami", "whoami"},
		{"plain text", "plain text"},
	}
	for _, tc := range tests {
		if got := JoinSplitKeywords(tc.in); got != tc.want {
			t.Errorf("JoinSplitKeywords(%q) = %q, want %q", tc.in, got, tc.want)
		}
	}
}
