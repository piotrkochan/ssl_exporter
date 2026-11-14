package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	yaml "gopkg.in/yaml.v3"
)

func TestLoadConfig(t *testing.T) {
	valid := "default_module: tls\nmodules:\n  tls:\n    prober: tcp\n    timeout: 3s\n"
	tests := []struct {
		name, content, wantErr string
		missing                bool
	}{
		{name: "valid", content: valid},
		{name: "trailing comment", content: valid + "\n# end of configuration\n"},
		{name: "missing file", missing: true, wantErr: "error reading config file"},
		{name: "empty file", wantErr: "error parsing config file"},
		{name: "invalid YAML", content: "modules: [", wantErr: "error parsing config file"},
		{name: "unknown field", content: "moduels: {}", wantErr: "field moduels not found"},
		{name: "null", content: "null", wantErr: "configuration must not be null"},
		{name: "second document", content: valid + "---\nmodules: {}\n", wantErr: "single YAML document"},
		{name: "empty second document", content: valid + "---\n", wantErr: "single YAML document"},
		{name: "malformed second document", content: valid + "---\nmodules: [", wantErr: "single YAML document"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if !tt.missing {
				if err := os.WriteFile(path, []byte(tt.content), 0600); err != nil {
					t.Fatal(err)
				}
			}
			cfg, err := LoadConfig(path)
			if tt.wantErr != "" {
				if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
					t.Fatalf("expected %q, got %v", tt.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if cfg == nil || cfg.DefaultModule != "tls" || len(cfg.Modules) != 1 {
				t.Fatalf("unexpected configuration: %+v", cfg)
			}
			module := cfg.Modules["tls"]
			if module.Prober != "tcp" || module.Timeout != 3*time.Second {
				t.Fatalf("unexpected module: %+v", module)
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
