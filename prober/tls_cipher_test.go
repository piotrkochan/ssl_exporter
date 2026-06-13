package prober

import (
	"context"
	"crypto/tls"
	"net"
	"testing"
	"time"

	"github.com/piotrkochan/ssl_exporter/v2/config"
	"github.com/piotrkochan/ssl_exporter/v2/test"
	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
)

// startCipherTestServer starts a TLS server that handles unlimited concurrent
// connections. The existing test.TCPServer accepts exactly one connection and
// is therefore not usable for the tls_cipher prober, which fires one
// goroutine per cipher/KX group in parallel.
func startCipherTestServer(t *testing.T) (addr string, stop func()) {
	t.Helper()
	certPEM, keyPEM := test.GenerateTestCertificate(time.Now().Add(24 * time.Hour))
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				_ = tls.Server(c, tlsCfg).Handshake()
			}(conn)
		}
	}()
	return ln.Addr().String(), func() {
		ln.Close()
		<-done
	}
}

func cipherMetricCount(mfs []*dto.MetricFamily, name string) int {
	for _, mf := range mfs {
		if mf.GetName() == name {
			return len(mf.GetMetric())
		}
	}
	return 0
}

func cipherMetricLabelValues(mfs []*dto.MetricFamily, name, labelName string) map[string]bool {
	values := map[string]bool{}
	for _, mf := range mfs {
		if mf.GetName() != name {
			continue
		}
		for _, m := range mf.GetMetric() {
			for _, l := range m.GetLabel() {
				if l.GetName() == labelName {
					values[l.GetValue()] = true
				}
			}
		}
	}
	return values
}

func TestProbeTLSCipherUnreachable(t *testing.T) {
	registry := prometheus.NewRegistry()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := ProbeTLSCipher(ctx, newTestLogger(), "127.0.0.1:1", config.Module{}, registry); err == nil {
		t.Fatal("expected error for unreachable target, got nil")
	}
}

func TestProbeTLSCipherDefaultEmitsInsecureCiphers(t *testing.T) {
	addr, stop := startCipherTestServer(t)
	defer stop()

	registry := prometheus.NewRegistry()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := ProbeTLSCipher(ctx, newTestLogger(), addr, config.Module{}, registry); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	// Default cipher_set → only insecure suites.
	want := len(tls.InsecureCipherSuites())
	if got := cipherMetricCount(mfs, "ssl_cipher_suite_supported"); got != want {
		t.Errorf("ssl_cipher_suite_supported: want %d series, got %d", want, got)
	}

	// Every emitted cipher must carry insecure="true".
	for v := range cipherMetricLabelValues(mfs, "ssl_cipher_suite_supported", "insecure") {
		if v != "true" {
			t.Errorf("default cipher_set: expected insecure=true, found insecure=%s", v)
		}
	}
}

func TestProbeTLSCipherAllEmitsSecureAndTLS13(t *testing.T) {
	addr, stop := startCipherTestServer(t)
	defer stop()

	registry := prometheus.NewRegistry()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	module := config.Module{
		TLSCipher: config.TLSCipherProbe{CipherSet: "all"},
	}
	if err := ProbeTLSCipher(ctx, newTestLogger(), addr, module, registry); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	// cipher_set=all → secure + insecure + TLS 1.3 ciphers, deduplicated by name
	// (CipherSuites() may already include TLS 1.3 names in some Go versions).
	seen := map[string]bool{}
	for _, c := range buildCipherList("all") {
		seen[c.name] = true
	}
	for _, c := range tls13Ciphers {
		seen[c.name] = true
	}
	want := len(seen)
	if got := cipherMetricCount(mfs, "ssl_cipher_suite_supported"); got != want {
		t.Errorf("cipher_set=all: want %d cipher series, got %d", want, got)
	}

	// Secure suites (insecure=false) must appear.
	insecureVals := cipherMetricLabelValues(mfs, "ssl_cipher_suite_supported", "insecure")
	if !insecureVals["false"] {
		t.Error("cipher_set=all: expected at least one ssl_cipher_suite_supported with insecure=false")
	}
}

func TestProbeTLSCipherDefaultPQCKeyExchange(t *testing.T) {
	addr, stop := startCipherTestServer(t)
	defer stop()

	registry := prometheus.NewRegistry()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if err := ProbeTLSCipher(ctx, newTestLogger(), addr, config.Module{}, registry); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	// Default key_exchange_set → 3 PQC groups only.
	want := len(pqcKeyExchangeGroups)
	if got := cipherMetricCount(mfs, "ssl_key_exchange_supported"); got != want {
		t.Errorf("ssl_key_exchange_supported: want %d series, got %d", want, got)
	}

	// All PQC metrics must carry post_quantum="true".
	for v := range cipherMetricLabelValues(mfs, "ssl_key_exchange_supported", "post_quantum") {
		if v != "true" {
			t.Errorf("default key_exchange_set: expected post_quantum=true, found post_quantum=%s", v)
		}
	}

	// Go 1.26 enables all three PQC groups by default — the server supports them.
	checkRegistryResult(&registryResult{
		Name:        "ssl_key_exchange_supported",
		LabelValues: map[string]string{"key_exchange": "X25519MLKEM768", "post_quantum": "true"},
		Value:       1,
	}, mfs, t)
}

func TestProbeTLSCipherAllKeyExchangeIncludesClassical(t *testing.T) {
	addr, stop := startCipherTestServer(t)
	defer stop()

	registry := prometheus.NewRegistry()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	module := config.Module{
		TLSCipher: config.TLSCipherProbe{KeyExchangeSet: "all"},
	}
	if err := ProbeTLSCipher(ctx, newTestLogger(), addr, module, registry); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}

	// key_exchange_set=all → PQC + classical.
	want := len(pqcKeyExchangeGroups) + len(classicalKeyExchangeGroups)
	if got := cipherMetricCount(mfs, "ssl_key_exchange_supported"); got != want {
		t.Errorf("key_exchange_set=all: want %d KX series, got %d", want, got)
	}

	pqVals := cipherMetricLabelValues(mfs, "ssl_key_exchange_supported", "post_quantum")
	if !pqVals["true"] {
		t.Error("key_exchange_set=all: missing post_quantum=true metrics")
	}
	if !pqVals["false"] {
		t.Error("key_exchange_set=all: missing post_quantum=false metrics for classical groups")
	}

	// Classical groups are universally supported by a Go TLS 1.3 server.
	checkRegistryResult(&registryResult{
		Name:        "ssl_key_exchange_supported",
		LabelValues: map[string]string{"key_exchange": "X25519", "post_quantum": "false"},
		Value:       1,
	}, mfs, t)
}

func TestBuildCipherCacheKey(t *testing.T) {
	ctx := context.Background()

	cases := []struct {
		name      string
		host      string
		port      string
		cacheMode string
		wantKey   string
	}{
		{
			name:      "empty mode defaults to hostname",
			host:      "example.com",
			port:      "443",
			cacheMode: "",
			wantKey:   "example.com:443",
		},
		{
			name:      "hostname mode",
			host:      "example.com",
			port:      "8443",
			cacheMode: "hostname",
			wantKey:   "example.com:8443",
		},
		{
			// 127.0.0.1 is an IP literal: LookupHost returns it as-is, no network call.
			name:      "ip mode resolves to ip:port",
			host:      "127.0.0.1",
			port:      "443",
			cacheMode: "ip",
			wantKey:   "127.0.0.1:443",
		},
		{
			name:      "sni mode appends hostname after pipe",
			host:      "127.0.0.1",
			port:      "443",
			cacheMode: "sni",
			wantKey:   "127.0.0.1:443|127.0.0.1",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.TLSCipherProbe{CacheMode: tc.cacheMode}
			got, err := buildCipherCacheKey(ctx, tc.host, tc.port, cfg)
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if got != tc.wantKey {
				t.Errorf("cache key: want %q, got %q", tc.wantKey, got)
			}
		})
	}
}

func TestBuildCipherCacheKeyDNSFallback(t *testing.T) {
	// A very short deadline forces the DNS lookup to time out, exercising the
	// fallback path that returns hostname:port unchanged.
	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Millisecond)
	defer cancel()

	cfg := config.TLSCipherProbe{CacheMode: "ip"}
	got, err := buildCipherCacheKey(ctx, "this-will-not-resolve.invalid", "443", cfg)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "this-will-not-resolve.invalid:443"
	if got != want {
		t.Errorf("DNS fallback: want %q, got %q", want, got)
	}
}

func TestProbeTLSCipherCacheReturnsSameMetrics(t *testing.T) {
	addr, stop := startCipherTestServer(t)
	defer stop()

	module := config.Module{
		TLSCipher: config.TLSCipherProbe{CacheTTL: 5 * time.Minute},
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	r1 := prometheus.NewRegistry()
	if err := ProbeTLSCipher(ctx, newTestLogger(), addr, module, r1); err != nil {
		t.Fatalf("first probe error: %v", err)
	}
	mfs1, _ := r1.Gather()

	r2 := prometheus.NewRegistry()
	if err := ProbeTLSCipher(ctx, newTestLogger(), addr, module, r2); err != nil {
		t.Fatalf("second probe error: %v", err)
	}
	mfs2, _ := r2.Gather()

	c1 := cipherMetricCount(mfs1, "ssl_cipher_suite_supported")
	c2 := cipherMetricCount(mfs2, "ssl_cipher_suite_supported")
	if c1 != c2 {
		t.Errorf("cache: cipher metric count changed between probes: %d vs %d", c1, c2)
	}

	k1 := cipherMetricCount(mfs1, "ssl_key_exchange_supported")
	k2 := cipherMetricCount(mfs2, "ssl_key_exchange_supported")
	if k1 != k2 {
		t.Errorf("cache: KX metric count changed between probes: %d vs %d", k1, k2)
	}
}
