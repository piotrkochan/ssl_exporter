package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	yaml "gopkg.in/yaml.v3"
)

func TestKubernetesSecretLabelsConfig(t *testing.T) {
	tests := []struct {
		name, mapping, want string
	}{
		{"valid", "{ssl-exporter.env: env, app.kubernetes.io/name: app}", ""},
		{"empty", "{}", ""},
		{"null", "null", ""},
		{"duplicate output", "{app: env, environment: env}", "duplicate or reserved"},
		{"empty source", "{'': env}", "source label key"},
		{"empty output", "{app: ''}", "invalid metric label"},
		{"invalid output", "{app: app-name}", "invalid metric label"},
		{"numeric output", "{app: 123}", "invalid metric label"},
		{"internal output", "{app: __name__}", "invalid metric label"},
		{"list instead of mapping", "[env, app]", "cannot unmarshal"},
		{"duplicate source", "{app: first, app: second}", "already defined"},
	}
	for _, label := range []string{"namespace", "secret", "key", "serial_no", "issuer_cn", "cn", "dnsnames", "ips", "emails", "ou"} {
		tests = append(tests, struct{ name, mapping, want string }{
			"reserved " + label, "{app: " + label + "}", "duplicate or reserved",
		})
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			data := fmt.Sprintf("modules:\n  kubernetes:\n    prober: kubernetes\n    kubernetes:\n      secret_labels: %s\n", tt.mapping)
			if err := os.WriteFile(path, []byte(data), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadConfig(path)
			if tt.want != "" {
				if err == nil || !strings.Contains(err.Error(), tt.want) {
					t.Fatalf("expected %q, got %v", tt.want, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if tt.name == "valid" {
				labels := cfg.Modules["kubernetes"].Kubernetes.SecretLabels
				if len(labels) != 2 || labels["ssl-exporter.env"] != "env" || labels["app.kubernetes.io/name"] != "app" {
					t.Fatalf("unexpected mapping: %v", labels)
				}
			}
		})
	}
}

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

func TestKubernetesProbeUnmarshalYAML(t *testing.T) {
	var cfg Config
	err := yaml.Unmarshal([]byte(`
modules:
  kubernetes:
    prober: kubernetes
    kubernetes:
      kubeconfig: /etc/kubernetes/config
      client:
        qps: 20
        burst: 30
        user_agent: ssl-exporter
        read_timeout: 8s
        connect_timeout: 2s
`), &cfg)
	if err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	kubernetes := cfg.Modules["kubernetes"].Kubernetes
	if kubernetes.Kubeconfig != "/etc/kubernetes/config" {
		t.Errorf("kubeconfig = %q, want %q", kubernetes.Kubeconfig, "/etc/kubernetes/config")
	}
	if kubernetes.Client.QPS != 20 {
		t.Errorf("qps = %v, want 20", kubernetes.Client.QPS)
	}
	if kubernetes.Client.Burst != 30 {
		t.Errorf("burst = %d, want 30", kubernetes.Client.Burst)
	}
	if kubernetes.Client.UserAgent != "ssl-exporter" {
		t.Errorf("user_agent = %q, want %q", kubernetes.Client.UserAgent, "ssl-exporter")
	}
	if kubernetes.Client.ReadTimeout != 8*time.Second {
		t.Errorf("read_timeout = %s, want 8s", kubernetes.Client.ReadTimeout)
	}
	if kubernetes.Client.ConnectTimeout != 2*time.Second {
		t.Errorf("connect_timeout = %s, want 2s", kubernetes.Client.ConnectTimeout)
	}
}
