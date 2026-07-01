package config

import (
	"crypto/tls"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"

	pconfig "github.com/prometheus/common/config"
	yaml "gopkg.in/yaml.v3"
)

var (
	// DefaultConfig is the default configuration that is used when no
	// configuration file is provided
	DefaultConfig = &Config{
		DefaultModule: "tcp",
		Modules: map[string]Module{
			"tcp": {
				Prober: "tcp",
			},
			"http": {
				Prober: "https",
			},
			"https": {
				Prober: "https",
			},
			"file": {
				Prober: "file",
			},
			"http_file": {
				Prober: "http_file",
			},
			"tls_cipher": {
				Prober: "tls_cipher",
			},
			"keystore": {
				Prober: "keystore",
			},
			"kubernetes": {
				Prober: "kubernetes",
			},
			"kubeconfig": {
				Prober: "kubeconfig",
			},
		},
	}
)

// LoadConfig loads configuration from a file
func LoadConfig(confFile string) (*Config, error) {
	var c *Config

	yamlReader, err := os.Open(confFile)
	if err != nil {
		return c, fmt.Errorf("error reading config file: %s", err)
	}
	defer yamlReader.Close()
	decoder := yaml.NewDecoder(yamlReader)
	decoder.KnownFields(true)

	if err = decoder.Decode(&c); err != nil {
		return c, fmt.Errorf("error parsing config file: %s", err)
	}

	return c, nil
}

// Config configures the exporter
type Config struct {
	DefaultModule string            `yaml:"default_module"`
	Modules       map[string]Module `yaml:"modules"`
}

// Module configures a prober
type Module struct {
	Prober     string          `yaml:"prober,omitempty"`
	Target     string          `yaml:"target,omitempty"`
	Timeout    time.Duration   `yaml:"timeout,omitempty"`
	TLSConfig  TLSConfig       `yaml:"tls_config,omitempty"`
	OCSP       OCSPProbe       `yaml:"ocsp,omitempty"`
	Keystore   KeystoreProbe   `yaml:"keystore,omitempty"`
	HTTPS      HTTPSProbe      `yaml:"https,omitempty"`
	TCP        TCPProbe        `yaml:"tcp,omitempty"`
	Kubernetes KubernetesProbe `yaml:"kubernetes,omitempty"`
	HTTPFile   HTTPFileProbe   `yaml:"http_file,omitempty"`
	TLSCipher  TLSCipherProbe  `yaml:"tls_cipher,omitempty"`
}

// TLSConfig is a superset of config.TLSConfig that supports TLS renegotiation
type TLSConfig struct {
	CAFile             string `yaml:"ca_file,omitempty"`
	CertFile           string `yaml:"cert_file,omitempty"`
	KeyFile            string `yaml:"key_file,omitempty"`
	ServerName         string `yaml:"server_name,omitempty"`
	InsecureSkipVerify bool   `yaml:"insecure_skip_verify"`
	// Renegotiation controls what types of TLS renegotiation are supported.
	// Supported values: never (default), once, freely.
	Renegotiation renegotiation `yaml:"renegotiation,omitempty"`
}

type renegotiation tls.RenegotiationSupport

func (r *renegotiation) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v string
	if err := unmarshal(&v); err != nil {
		return err
	}
	switch v {
	case "", "never":
		*r = renegotiation(tls.RenegotiateNever)
	case "once":
		*r = renegotiation(tls.RenegotiateOnceAsClient)
	case "freely":
		*r = renegotiation(tls.RenegotiateFreelyAsClient)
	default:
		return fmt.Errorf("unsupported TLS renegotiation type %s", v)
	}

	return nil
}

// NewTLSConfig creates a new tls.Config from the given TLSConfig,
// plus our local extensions
func NewTLSConfig(cfg *TLSConfig) (*tls.Config, error) {
	tlsConfig, err := pconfig.NewTLSConfig(&pconfig.TLSConfig{
		CAFile:             cfg.CAFile,
		CertFile:           cfg.CertFile,
		KeyFile:            cfg.KeyFile,
		ServerName:         cfg.ServerName,
		InsecureSkipVerify: cfg.InsecureSkipVerify,
	})
	if err != nil {
		return nil, err
	}

	tlsConfig.Renegotiation = tls.RenegotiationSupport(cfg.Renegotiation)

	return tlsConfig, nil
}

// OCSPSource configures where OCSP metrics are collected from.
type OCSPSource string

const (
	OCSPSourceOff       OCSPSource = "off"
	OCSPSourceTLS       OCSPSource = "tls"
	OCSPSourceResponder OCSPSource = "responder"
	OCSPSourceBoth      OCSPSource = "both"
)

func (s *OCSPSource) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var v string
	if err := unmarshal(&v); err != nil {
		return err
	}
	switch OCSPSource(v) {
	case "", OCSPSourceOff, OCSPSourceTLS, OCSPSourceResponder, OCSPSourceBoth:
		*s = OCSPSource(v)
		return nil
	default:
		return fmt.Errorf("unsupported OCSP source %s", v)
	}
}

// SourceOrDefault returns the configured OCSP source. The zero value preserves
// the historical behaviour: collect OCSP only from the TLS connection state.
func (o OCSPProbe) SourceOrDefault() OCSPSource {
	if o.Source == "" {
		return OCSPSourceTLS
	}
	return o.Source
}

func (s OCSPSource) UsesTLS() bool {
	switch s {
	case "", OCSPSourceTLS, OCSPSourceBoth:
		return true
	default:
		return false
	}
}

func (s OCSPSource) UsesResponder() bool {
	switch s {
	case OCSPSourceResponder, OCSPSourceBoth:
		return true
	default:
		return false
	}
}

// OCSPProbe configures OCSP metric collection for TLS-based probers.
type OCSPProbe struct {
	Source       OCSPSource    `yaml:"source,omitempty"`
	Timeout      time.Duration `yaml:"timeout,omitempty"`
	ResponderURL URL           `yaml:"responder_url,omitempty"`
}

// TCPProbe configures a tcp probe
type TCPProbe struct {
	StartTLS string `yaml:"starttls,omitempty"`
}

// KeystoreProbe configures a Java KeyStore (JKS) or PKCS12 probe
type KeystoreProbe struct {
	Password     pconfig.Secret `yaml:"password,omitempty"`
	PasswordFile string         `yaml:"password_file,omitempty"`
}

// GetPassword returns the keystore password, reading it from PasswordFile when
// configured and otherwise falling back to the inline Password.
func (k KeystoreProbe) GetPassword() (string, error) {
	if k.PasswordFile != "" {
		data, err := os.ReadFile(k.PasswordFile)
		if err != nil {
			return "", fmt.Errorf("failed to read keystore password_file %q: %w", k.PasswordFile, err)
		}
		return strings.TrimSpace(string(data)), nil
	}
	return string(k.Password), nil
}

// HTTPSProbe configures a https probe
type HTTPSProbe struct {
	ProxyURL URL `yaml:"proxy_url,omitempty"`
}

// KubernetesProbe configures a kubernetes probe
type KubernetesProbe struct {
	Kubeconfig string `yaml:"kubeconfig,omitempty"`
}

// HTTPFileProbe configures a http_file probe
type HTTPFileProbe struct {
	ProxyURL URL `yaml:"proxy_url,omitempty"`
}

// TLSCipherProbe configures a tls_cipher probe
type TLSCipherProbe struct {
	CipherSet      string        `yaml:"cipher_set,omitempty"`
	KeyExchangeSet string        `yaml:"key_exchange_set,omitempty"`
	CacheTTL       time.Duration `yaml:"cache_ttl,omitempty"`
	CacheMode      string        `yaml:"cache_mode,omitempty"`
}

// URL is a custom URL type that allows validation at configuration load time
type URL struct {
	*url.URL
}

// UnmarshalYAML implements the yaml.Unmarshaler interface for URLs.
func (u *URL) UnmarshalYAML(unmarshal func(interface{}) error) error {
	var s string
	if err := unmarshal(&s); err != nil {
		return err
	}

	urlp, err := url.Parse(s)
	if err != nil {
		return err
	}
	u.URL = urlp
	return nil
}
