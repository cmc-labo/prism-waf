package normalize

import (
	"slices"
	"testing"
)

func TestDecodeBase64(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"standard", "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg==", []string{"<script>alert(1)</script>"}},
		{"unpadded", "PHNjcmlwdD5hbGVydCgxKTwvc2NyaXB0Pg", []string{"<script>alert(1)</script>"}},
		{"in query", "a=1&q=JyBPUiAnMSc9JzE%3D", []string{"' OR '1'='1"}},
		{"url-safe", "data=Li4vLi4vZXRjL3Bhc3N3ZA", []string{"../../etc/passwd"}},
		{"url-encoded plus and slash", "x=Pz8_Pz8%2BPz8%2F", nil},
		{"multiple tokens", "PHNjcmlwdD4x JHtqbmRpOmxkYXA6Ly94fQ==", []string{"<script>1", "${jndi:ldap://x}"}},
		{"binary is ignored", "AAECAwQFBgcICQoLDA0ODw==", nil},
		{"ordinary words are ignored", "/api/v1/users/profile?sort=createdAt", nil},
		{"short tokens are ignored", "YWJj", nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := DecodeBase64(tc.in); !slices.Equal(got, tc.want) {
				t.Errorf("DecodeBase64(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
