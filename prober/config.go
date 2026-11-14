package prober

import (
	"fmt"
	"slices"

	"github.com/piotrkochan/ssl_exporter/v2/config"
	pconfig "github.com/prometheus/common/config"
)

// ValidateConfig checks module settings without probing targets or reading
// module credentials. The prober registry and STARTTLS table are shared with
// runtime probing so supported names stay in sync.
func ValidateConfig(cfg *config.Config) error {
	if cfg == nil {
		return fmt.Errorf("configuration must not be null")
	}
	if cfg.DefaultModule != "" {
		if _, ok := cfg.Modules[cfg.DefaultModule]; !ok {
			return fmt.Errorf("unknown default_module %q", cfg.DefaultModule)
		}
	}
	names := make([]string, 0, len(cfg.Modules))
	for name := range cfg.Modules {
		names = append(names, name)
	}
	slices.Sort(names)
	for _, name := range names {
		if name == "" {
			return fmt.Errorf("module name must not be empty")
		}
		if err := validateModule(cfg.Modules[name]); err != nil {
			return fmt.Errorf("module %q: %w", name, err)
		}
	}
	return nil
}

func validateModule(module config.Module) error {
	if _, ok := Probers[module.Prober]; !ok {
		return fmt.Errorf("unknown prober %q", module.Prober)
	}
	if module.Timeout < 0 {
		return fmt.Errorf("timeout must not be negative")
	}

	switch module.Prober {
	case "tcp", "http", "https", "http_file":
		tlsConfig := pconfig.TLSConfig{
			CertFile: module.TLSConfig.CertFile,
			KeyFile:  module.TLSConfig.KeyFile,
		}
		if err := tlsConfig.Validate(); err != nil {
			return fmt.Errorf("tls_config: %w", err)
		}
	}
	if module.Prober == "tcp" && module.TCP.StartTLS != "" {
		if _, ok := startTLSqueryResponses[module.TCP.StartTLS]; !ok {
			return fmt.Errorf("unsupported STARTTLS protocol %q", module.TCP.StartTLS)
		}
	}
	if module.Prober == "tcp" || module.Prober == "http" || module.Prober == "https" {
		if module.OCSP.Timeout < 0 {
			return fmt.Errorf("ocsp.timeout must not be negative")
		}
		if module.OCSP.ResponderURL.URL != nil {
			if _, err := validateOCSPResponderURL(module.OCSP.ResponderURL.URL); err != nil {
				return err
			}
			if module.OCSP.ResponderURL.Hostname() == "" {
				return fmt.Errorf("ocsp.responder_url must include a host")
			}
		}
	}
	if module.Prober == "tls_cipher" {
		if !slices.Contains([]string{"", "insecure", "all"}, module.TLSCipher.CipherSet) {
			return fmt.Errorf("unsupported tls_cipher.cipher_set %q", module.TLSCipher.CipherSet)
		}
		if !slices.Contains([]string{"", "pqc", "all"}, module.TLSCipher.KeyExchangeSet) {
			return fmt.Errorf("unsupported tls_cipher.key_exchange_set %q", module.TLSCipher.KeyExchangeSet)
		}
		if !slices.Contains([]string{"", "hostname", "ip", "sni"}, module.TLSCipher.CacheMode) {
			return fmt.Errorf("unsupported tls_cipher.cache_mode %q", module.TLSCipher.CacheMode)
		}
	}
	if module.Prober == "kubernetes" {
		client := module.Kubernetes.Client
		if client.ReadTimeout < 0 || client.ConnectTimeout < 0 {
			return fmt.Errorf("kubernetes client timeouts must not be negative")
		}
		// A negative QPS disables rate limiting; zero uses client-go defaults.
		if client.QPS >= 0 && client.Burst < 0 {
			return fmt.Errorf("kubernetes client burst must not be negative when rate limiting is enabled")
		}
	}
	return nil
}
