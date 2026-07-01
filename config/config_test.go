package config

import (
	"testing"
	"time"

	yaml "gopkg.in/yaml.v3"
)

func TestOCSPSourceOrDefault(t *testing.T) {
	if got := (OCSPProbe{}).SourceOrDefault(); got != OCSPSourceTLS {
		t.Fatalf("SourceOrDefault() = %q, want %q", got, OCSPSourceTLS)
	}
}

func TestOCSPSourceUnmarshalYAML(t *testing.T) {
	tests := []struct {
		name    string
		source  string
		want    OCSPSource
		wantErr bool
	}{
		{name: "empty", source: "", want: ""},
		{name: "off", source: "off", want: OCSPSourceOff},
		{name: "tls", source: "tls", want: OCSPSourceTLS},
		{name: "responder", source: "responder", want: OCSPSourceResponder},
		{name: "both", source: "both", want: OCSPSourceBoth},
		{name: "invalid", source: "invalid", wantErr: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var got OCSPSource
			err := yaml.Unmarshal([]byte(tt.source), &got)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %s", err)
			}
			if got != tt.want {
				t.Fatalf("OCSPSource = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestOCSPProbeUnmarshalYAML(t *testing.T) {
	var cfg Config
	err := yaml.Unmarshal([]byte(`
modules:
  https:
    prober: https
    ocsp:
      source: both
      timeout: 3s
      responder_url: http://ocsp.example.test
`), &cfg)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	ocsp := cfg.Modules["https"].OCSP
	if got := ocsp.SourceOrDefault(); got != OCSPSourceBoth {
		t.Fatalf("source = %q, want %q", got, OCSPSourceBoth)
	}
	if ocsp.Timeout != 3*time.Second {
		t.Fatalf("timeout = %s, want 3s", ocsp.Timeout)
	}
	if ocsp.ResponderURL.URL == nil || ocsp.ResponderURL.String() != "http://ocsp.example.test" {
		t.Fatalf("responder_url = %v, want http://ocsp.example.test", ocsp.ResponderURL.URL)
	}
}
