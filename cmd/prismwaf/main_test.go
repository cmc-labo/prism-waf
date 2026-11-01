package main

import "testing"

func TestConfigValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     config
		wantErr bool
	}{
		{"plain HTTP", config{}, false},
		{"HTTPS", config{tlsCert: "c.pem", tlsKey: "k.pem"}, false},
		{"HTTPS with redirect", config{tlsCert: "c.pem", tlsKey: "k.pem", httpRedirect: ":80"}, false},
		{"cert without key", config{tlsCert: "c.pem"}, true},
		{"key without cert", config{tlsKey: "k.pem"}, true},
		{"redirect without TLS", config{httpRedirect: ":80"}, true},
	}
	for _, tc := range tests {
		if err := tc.cfg.validate(); (err != nil) != tc.wantErr {
			t.Errorf("%s: validate() = %v, wantErr %v", tc.name, err, tc.wantErr)
		}
	}
}
