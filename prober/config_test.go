package prober

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/piotrkochan/ssl_exporter/v2/config"
)

func TestValidateConfig(t *testing.T) {
	if err := ValidateConfig(config.DefaultConfig); err != nil {
		t.Fatalf("built-in defaults: %v", err)
	}
	example, err := config.LoadConfig("../examples/ssl_exporter.yaml")
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateConfig(example); err != nil {
		t.Fatalf("example configuration: %v", err)
	}
	if err := ValidateConfig(nil); err == nil {
		t.Fatal("expected error for nil configuration")
	}
	for name := range Probers {
		cfg := &config.Config{Modules: map[string]config.Module{"test": {Prober: name}}}
		if err := ValidateConfig(cfg); err != nil {
			t.Errorf("registered prober %q: %v", name, err)
		}
	}
	for protocol := range startTLSqueryResponses {
		cfg := &config.Config{Modules: map[string]config.Module{"test": {Prober: "tcp", TCP: config.TCPProbe{StartTLS: protocol}}}}
		if err := ValidateConfig(cfg); err != nil {
			t.Errorf("supported STARTTLS protocol %q: %v", protocol, err)
		}
	}

	tests := []struct {
		name, yaml, want string
	}{
		{"no modules", "modules: {}", ""},
		{"unknown default", "default_module: typo", "unknown default_module"},
		{"empty module name", "modules:\n  '': {prober: tcp}", "module name must not be empty"},
		{"missing prober", "modules:\n  test: {}", "unknown prober"},
		{"unknown prober", "modules:\n  test: {prober: typo}", "unknown prober"},
		{"negative timeout", "modules:\n  test: {prober: tcp, timeout: -1s}", "timeout must not be negative"},
		{"invalid STARTTLS", "modules:\n  test: {prober: tcp, tcp: {starttls: typo}}", "unsupported STARTTLS"},
		{"unpaired certificate", "modules:\n  test: {prober: tcp, tls_config: {cert_file: client.pem}}", "key_file"},
		{"unpaired key", "modules:\n  test: {prober: https, tls_config: {key_file: client.key}}", "cert_file"},
		{"unpaired http file key", "modules:\n  test: {prober: http_file, tls_config: {key_file: client.key}}", "cert_file"},
		{"negative OCSP timeout", "modules:\n  test: {prober: tcp, ocsp: {timeout: -1s}}", "ocsp.timeout"},
		{"OCSP URL scheme", "modules:\n  test: {prober: tcp, ocsp: {responder_url: ftp://example.com}}", "unsupported OCSP"},
		{"OCSP URL host", "modules:\n  test: {prober: tcp, ocsp: {responder_url: 'https:/path'}}", "must include a host"},
		{"cipher set", "modules:\n  test: {prober: tls_cipher, tls_cipher: {cipher_set: typo}}", "cipher_set"},
		{"key exchange set", "modules:\n  test: {prober: tls_cipher, tls_cipher: {key_exchange_set: typo}}", "key_exchange_set"},
		{"cache mode", "modules:\n  test: {prober: tls_cipher, tls_cipher: {cache_mode: typo}}", "cache_mode"},
		{"Kubernetes read timeout", "modules:\n  test: {prober: kubernetes, kubernetes: {client: {read_timeout: -1s}}}", "timeouts"},
		{"Kubernetes connect timeout", "modules:\n  test: {prober: kubernetes, kubernetes: {client: {connect_timeout: -1s}}}", "timeouts"},
		{"Kubernetes burst", "modules:\n  test: {prober: kubernetes, kubernetes: {client: {burst: -1}}}", "burst"},
		{"Kubernetes disabled rate limit", "modules:\n  test: {prober: kubernetes, kubernetes: {client: {qps: -1, burst: -1}}}", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "config.yml")
			if err := os.WriteFile(path, []byte(tt.yaml), 0600); err != nil {
				t.Fatal(err)
			}
			cfg, err := config.LoadConfig(path)
			if err != nil {
				t.Fatal(err)
			}
			err = ValidateConfig(cfg)
			if tt.want == "" {
				if err != nil {
					t.Fatal(err)
				}
			} else if err == nil || !strings.Contains(err.Error(), tt.want) {
				t.Fatalf("expected %q, got %v", tt.want, err)
			}
		})
	}
}
