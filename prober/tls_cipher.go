package prober

import (
	"context"
	"crypto/tls"
	"fmt"
	"log/slog"
	"net"
	"sync"
	"time"

	"github.com/piotrkochan/ssl_exporter/v2/config"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/sync/errgroup"
	"golang.org/x/sync/singleflight"
)

// tls13Ciphers are the fixed TLS 1.3 cipher suites. Go's crypto/tls does not
// allow constraining them individually, so they are tested as a group via a
// single TLS 1.3-only handshake.
var tls13Ciphers = []cipherEntry{
	{id: tls.TLS_AES_128_GCM_SHA256, name: "TLS_AES_128_GCM_SHA256"},
	{id: tls.TLS_AES_256_GCM_SHA384, name: "TLS_AES_256_GCM_SHA384"},
	{id: tls.TLS_CHACHA20_POLY1305_SHA256, name: "TLS_CHACHA20_POLY1305_SHA256"},
}

// pqcKeyExchangeGroups are the NIST-standardised ML-KEM hybrid key exchange
// groups available in Go 1.26. Tested by default (key_exchange_set: "pqc").
var pqcKeyExchangeGroups = []keyExchangeEntry{
	{id: tls.X25519MLKEM768, name: "X25519MLKEM768", postQuantum: true},
	{id: tls.SecP256r1MLKEM768, name: "SecP256r1MLKEM768", postQuantum: true},
	{id: tls.SecP384r1MLKEM1024, name: "SecP384r1MLKEM1024", postQuantum: true},
}

// classicalKeyExchangeGroups are the classical elliptic-curve groups. Included
// when key_exchange_set is "all"; omitted by default as they produce no
// actionable security signal (all are equally safe).
var classicalKeyExchangeGroups = []keyExchangeEntry{
	{id: tls.X25519, name: "X25519", postQuantum: false},
	{id: tls.CurveP256, name: "P-256", postQuantum: false},
	{id: tls.CurveP384, name: "P-384", postQuantum: false},
	{id: tls.CurveP521, name: "P-521", postQuantum: false},
}

type cipherEntry struct {
	id       uint16
	name     string
	insecure bool
}

type keyExchangeEntry struct {
	id          tls.CurveID
	name        string
	postQuantum bool
}

type cipherCacheEntry struct {
	results   map[uint16]bool
	kxResults map[tls.CurveID]bool
	expiresAt time.Time
}

var (
	cipherCacheMu  sync.RWMutex
	cipherCacheMap = map[string]*cipherCacheEntry{}
	cipherSF       singleflight.Group
)

// ProbeTLSCipher enumerates the cipher suites and PQC key exchange groups
// supported by a TLS server.
func ProbeTLSCipher(ctx context.Context, logger *slog.Logger, target string, module config.Module, registry *prometheus.Registry) error {
	host, port, err := net.SplitHostPort(target)
	if err != nil {
		host = target
		port = "443"
	}

	// Verify the target is reachable before running enumeration.
	// Without this, an unreachable target would return ssl_probe_success 1
	// with all metrics = 0, indistinguishable from "nothing supported".
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return fmt.Errorf("target unreachable: %w", err)
	}
	conn.Close()

	cfg := module.TLSCipher
	ciphers := buildCipherList(cfg.CipherSet)
	testTLS13 := cfg.CipherSet == "all"
	kxGroups := buildKeyExchangeList(cfg.KeyExchangeSet)

	cacheKey, err := buildCipherCacheKey(ctx, host, port, cfg)
	if err != nil {
		return err
	}

	results, kxResults, ok := cipherCacheGet(cacheKey)
	if ok {
		logger.Debug("tls_cipher cache hit", "key", cacheKey)
		return emitTLSCipherMetrics(ciphers, testTLS13, results, kxResults, kxGroups, registry)
	}

	type sfPayload struct {
		results   map[uint16]bool
		kxResults map[tls.CurveID]bool
	}
	v, err, _ := cipherSF.Do(cacheKey, func() (any, error) {
		r, kx, err := runTLSCipherProbe(ctx, host, port, ciphers, testTLS13, kxGroups)
		if err != nil {
			return nil, err
		}
		ttl := cfg.CacheTTL
		if ttl == 0 {
			ttl = time.Hour
		}
		cipherCacheMu.Lock()
		cipherCacheMap[cacheKey] = &cipherCacheEntry{
			results:   r,
			kxResults: kx,
			expiresAt: time.Now().Add(ttl),
		}
		cipherCacheMu.Unlock()
		return &sfPayload{results: r, kxResults: kx}, nil
	})
	if err != nil {
		return err
	}

	p := v.(*sfPayload)
	return emitTLSCipherMetrics(ciphers, testTLS13, p.results, p.kxResults, kxGroups, registry)
}

func buildCipherList(cipherSet string) []cipherEntry {
	var list []cipherEntry
	if cipherSet == "all" {
		for _, s := range tls.CipherSuites() {
			list = append(list, cipherEntry{id: s.ID, name: s.Name})
		}
	}
	for _, s := range tls.InsecureCipherSuites() {
		list = append(list, cipherEntry{id: s.ID, name: s.Name, insecure: true})
	}
	return list
}

func buildKeyExchangeList(kxSet string) []keyExchangeEntry {
	list := make([]keyExchangeEntry, len(pqcKeyExchangeGroups))
	copy(list, pqcKeyExchangeGroups)
	if kxSet == "all" {
		list = append(list, classicalKeyExchangeGroups...)
	}
	return list
}

func buildCipherCacheKey(ctx context.Context, host, port string, cfg config.TLSCipherProbe) (string, error) {
	if !cfg.DeduplicateByIP {
		return net.JoinHostPort(host, port), nil
	}
	addrs, err := net.DefaultResolver.LookupHost(ctx, host)
	if err != nil || len(addrs) == 0 {
		return net.JoinHostPort(host, port), nil
	}
	key := net.JoinHostPort(addrs[0], port)
	if cfg.SNIAware {
		key += "|" + host
	}
	return key, nil
}

func cipherCacheGet(key string) (map[uint16]bool, map[tls.CurveID]bool, bool) {
	cipherCacheMu.RLock()
	defer cipherCacheMu.RUnlock()
	e, ok := cipherCacheMap[key]
	if !ok || time.Now().After(e.expiresAt) {
		return nil, nil, false
	}
	return e.results, e.kxResults, true
}

func runTLSCipherProbe(ctx context.Context, host, port string, ciphers []cipherEntry, testTLS13 bool, kxGroups []keyExchangeEntry) (map[uint16]bool, map[tls.CurveID]bool, error) {
	results := make(map[uint16]bool, len(ciphers)+len(tls13Ciphers))
	kxResults := make(map[tls.CurveID]bool, len(kxGroups))
	var mu sync.Mutex

	g, ctx := errgroup.WithContext(ctx)

	for _, c := range ciphers {
		c := c
		g.Go(func() error {
			ok := testCipherSuite(ctx, host, port, c.id)
			mu.Lock()
			results[c.id] = ok
			mu.Unlock()
			return nil
		})
	}

	if testTLS13 {
		g.Go(func() error {
			ok := testTLS13Support(ctx, host, port)
			mu.Lock()
			for _, c := range tls13Ciphers {
				results[c.id] = ok
			}
			mu.Unlock()
			return nil
		})
	}

	for _, kx := range kxGroups {
		kx := kx
		g.Go(func() error {
			ok := testKeyExchangeGroup(ctx, host, port, kx.id)
			mu.Lock()
			kxResults[kx.id] = ok
			mu.Unlock()
			return nil
		})
	}

	return results, kxResults, g.Wait()
}

// testCipherSuite attempts a TLS 1.2 handshake advertising only the given
// cipher suite. InsecureSkipVerify is intentional: we are testing cipher
// support, not certificate validity.
func testCipherSuite(ctx context.Context, host, port string, id uint16) bool {
	cfg := &tls.Config{
		ServerName:         host,
		CipherSuites:       []uint16{id},
		MaxVersion:         tls.VersionTLS12,
		InsecureSkipVerify: true, //nolint:gosec
	}
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	tlsConn := tls.Client(conn, cfg)
	defer tlsConn.Close()
	return tlsConn.HandshakeContext(ctx) == nil
}

// testTLS13Support attempts a TLS 1.3-only handshake. If it succeeds, all
// three standard TLS 1.3 cipher suites are reported as supported.
func testTLS13Support(ctx context.Context, host, port string) bool {
	cfg := &tls.Config{
		ServerName:         host,
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec
	}
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	tlsConn := tls.Client(conn, cfg)
	defer tlsConn.Close()
	return tlsConn.HandshakeContext(ctx) == nil
}

// testKeyExchangeGroup attempts a TLS 1.3 handshake advertising only the given
// key exchange group. InsecureSkipVerify is intentional: we are testing key
// exchange support, not certificate validity.
func testKeyExchangeGroup(ctx context.Context, host, port string, group tls.CurveID) bool {
	cfg := &tls.Config{
		ServerName:         host,
		CurvePreferences:   []tls.CurveID{group},
		MinVersion:         tls.VersionTLS13,
		InsecureSkipVerify: true, //nolint:gosec
	}
	dialer := &net.Dialer{}
	conn, err := dialer.DialContext(ctx, "tcp", net.JoinHostPort(host, port))
	if err != nil {
		return false
	}
	tlsConn := tls.Client(conn, cfg)
	defer tlsConn.Close()
	return tlsConn.HandshakeContext(ctx) == nil
}

func emitTLSCipherMetrics(ciphers []cipherEntry, testTLS13 bool, results map[uint16]bool, kxResults map[tls.CurveID]bool, kxGroups []keyExchangeEntry, registry *prometheus.Registry) error {
	if err := emitCipherSuiteMetrics(ciphers, testTLS13, results, registry); err != nil {
		return err
	}
	return emitKeyExchangeMetrics(kxResults, kxGroups, registry)
}

func emitCipherSuiteMetrics(ciphers []cipherEntry, testTLS13 bool, results map[uint16]bool, registry *prometheus.Registry) error {
	cipherSupported := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: prometheus.BuildFQName(namespace, "", "cipher_suite_supported"),
			Help: "Whether the cipher suite is supported by the server (1=supported 0=not supported)",
		},
		[]string{"cipher_suite", "insecure"},
	)
	registry.MustRegister(cipherSupported)

	for _, c := range ciphers {
		insecure := "false"
		if c.insecure {
			insecure = "true"
		}
		val := 0.0
		if results[c.id] {
			val = 1.0
		}
		cipherSupported.WithLabelValues(c.name, insecure).Set(val)
	}

	if testTLS13 {
		for _, c := range tls13Ciphers {
			val := 0.0
			if results[c.id] {
				val = 1.0
			}
			cipherSupported.WithLabelValues(c.name, "false").Set(val)
		}
	}

	return nil
}

func emitKeyExchangeMetrics(kxResults map[tls.CurveID]bool, kxGroups []keyExchangeEntry, registry *prometheus.Registry) error {
	kxSupported := prometheus.NewGaugeVec(
		prometheus.GaugeOpts{
			Name: prometheus.BuildFQName(namespace, "", "key_exchange_supported"),
			Help: "Whether the key exchange group is supported by the server (1=supported 0=not supported)",
		},
		[]string{"key_exchange", "post_quantum"},
	)
	registry.MustRegister(kxSupported)

	for _, kx := range kxGroups {
		pq := "false"
		if kx.postQuantum {
			pq = "true"
		}
		val := 0.0
		if kxResults[kx.id] {
			val = 1.0
		}
		kxSupported.WithLabelValues(kx.name, pq).Set(val)
	}

	return nil
}
