package main

import (
	"crypto/tls"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/piotrkochan/ssl_exporter/v2/config"
	"github.com/piotrkochan/ssl_exporter/v2/test"
)

func startSNICaptureTLSServer(t *testing.T) (addr string, seen <-chan string, stop func()) {
	t.Helper()
	certPEM, keyPEM := test.GenerateTestCertificate(time.Now().Add(24 * time.Hour))
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatal(err)
	}

	seenCh := make(chan string, 64)
	tlsCfg := &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}
	tlsCfg.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		select {
		case seenCh <- hello.ServerName:
		default:
		}
		return nil, nil
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

	return ln.Addr().String(), seenCh, func() {
		ln.Close()
		<-done
	}
}

// TestProbeHandler tests that the probe handler sets the ssl_probe_success and
// ssl_prober metrics correctly
func TestProbeHandler(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	conf := &config.Config{
		Modules: map[string]config.Module{
			"https": {
				Prober: "https",
				TLSConfig: config.TLSConfig{
					CAFile: caFile,
				},
			},
		},
	}

	rr, err := probe(server.URL, "https", conf)
	if err != nil {
		t.Fatal(err)
	}

	// Check probe success
	if ok := strings.Contains(rr.Body.String(), "ssl_probe_success 1"); !ok {
		t.Errorf("expected `ssl_probe_success 1`")
	}

	// Check prober metric
	if ok := strings.Contains(rr.Body.String(), "ssl_prober{prober=\"https\"} 1"); !ok {
		t.Errorf("expected `ssl_prober{prober=\"https\"} 1`")
	}

	// Check probe duration metric
	if ok := strings.Contains(rr.Body.String(), "ssl_probe_duration_seconds"); !ok {
		t.Errorf("expected `ssl_probe_duration_seconds`")
	}
}

// TestProbeHandlerFail tests that the probe handler sets the ssl_probe_success and
// ssl_prober metrics correctly when the probe fails
func TestProbeHandlerFail(t *testing.T) {
	rr, err := probe("localhost:6666", "", config.DefaultConfig)
	if err != nil {
		t.Fatal(err)
	}

	// Check probe success
	if ok := strings.Contains(rr.Body.String(), "ssl_probe_success 0"); !ok {
		t.Errorf("expected `ssl_probe_success 0`")
	}

	// Check prober metric
	if ok := strings.Contains(rr.Body.String(), "ssl_prober{prober=\"tcp\"} 1"); !ok {
		t.Errorf("expected `ssl_prober{prober=\"tcp\"} 1`")
	}

	// Check probe duration metric (should be present even on failure)
	if ok := strings.Contains(rr.Body.String(), "ssl_probe_duration_seconds"); !ok {
		t.Errorf("expected `ssl_probe_duration_seconds`")
	}
}

// TestProbeHandlerDefaultModule tests the default module is used correctly
func TestProbeHandlerDefaultModule(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	conf := &config.Config{
		DefaultModule: "https",
		Modules: map[string]config.Module{
			"tcp": {
				Prober: "tcp",
				TLSConfig: config.TLSConfig{
					CAFile: caFile,
				},
			},
			"https": {
				Prober: "https",
				TLSConfig: config.TLSConfig{
					CAFile: caFile,
				},
			},
		},
	}

	rr, err := probe(server.URL, "", conf)
	if err != nil {
		t.Fatal(err)
	}

	// Should have used the https prober
	if ok := strings.Contains(rr.Body.String(), "ssl_prober{prober=\"https\"} 1"); !ok {
		t.Errorf("expected `ssl_prober{prober=\"https\"} 1`")
	}

	conf.DefaultModule = ""

	rr, err = probe(server.URL, "", conf)
	if err != nil {
		t.Fatal(err)
	}

	// It should fail when there's no default module
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected code: %d, got: %d", http.StatusBadRequest, rr.Code)
	}

}

// TestProbeHandlerTarget tests the target module parameter is used correctly
func TestProbeHandlerDefaultTarget(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	conf := &config.Config{
		Modules: map[string]config.Module{
			"https": {
				Prober: "https",
				Target: server.URL,
				TLSConfig: config.TLSConfig{
					CAFile: caFile,
				},
			},
		},
	}

	// Should use the target in the module configuration
	rr, err := probe("", "https", conf)
	if err != nil {
		t.Fatal(err)
	}

	// Check probe success
	if ok := strings.Contains(rr.Body.String(), "ssl_probe_success 1"); !ok {
		t.Errorf("expected `ssl_probe_success 1`")
	}

	// Check prober metric
	if ok := strings.Contains(rr.Body.String(), "ssl_prober{prober=\"https\"} 1"); !ok {
		t.Errorf("expected `ssl_prober{prober=\"https\"} 1`")
	}

	// Should ignore a different target in the target parameter
	rr, err = probe("localhost:6666", "https", conf)
	if err != nil {
		t.Fatal(err)
	}

	// Check probe success
	if ok := strings.Contains(rr.Body.String(), "ssl_probe_success 1"); !ok {
		t.Errorf("expected `ssl_probe_success 1`")
	}

	// Check prober metric
	if ok := strings.Contains(rr.Body.String(), "ssl_prober{prober=\"https\"} 1"); !ok {
		t.Errorf("expected `ssl_prober{prober=\"https\"} 1`")
	}

	conf.Modules["tcp"] = config.Module{
		Prober: "tcp",
		TLSConfig: config.TLSConfig{
			CAFile: caFile,
		},
	}

	rr, err = probe("", "tcp", conf)
	if err != nil {
		t.Fatal(err)
	}

	// It should fail when there's no target in the module configuration or
	// the query parameters
	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected code: %d, got: %d", http.StatusBadRequest, rr.Code)
	}
}

func TestProbeHandlerTLSCipherWithServerName(t *testing.T) {
	addr, seen, stop := startSNICaptureTLSServer(t)
	defer stop()

	conf := &config.Config{
		Modules: map[string]config.Module{
			"tls_cipher": {
				Prober: "tls_cipher",
			},
		},
	}

	const wantSNI = "vhost.example.com"
	rr, err := probeWithServerName(addr, "tls_cipher", wantSNI, conf)
	if err != nil {
		t.Fatal(err)
	}

	body := rr.Body.String()
	if ok := strings.Contains(body, "ssl_probe_success 1"); !ok {
		t.Errorf("expected `ssl_probe_success 1`, got:\n%s", body)
	}
	if ok := strings.Contains(body, "ssl_prober{prober=\"tls_cipher\"} 1"); !ok {
		t.Errorf("expected `ssl_prober{prober=\"tls_cipher\"} 1`, got:\n%s", body)
	}
	if ok := strings.Contains(body, "ssl_cipher_suite_supported"); !ok {
		t.Errorf("expected `ssl_cipher_suite_supported`, got:\n%s", body)
	}
	if ok := strings.Contains(body, "ssl_key_exchange_supported"); !ok {
		t.Errorf("expected `ssl_key_exchange_supported`, got:\n%s", body)
	}

	for {
		select {
		case got := <-seen:
			if got == wantSNI {
				return
			}
		default:
			t.Fatalf("server did not observe configured SNI %q", wantSNI)
		}
	}
}

// TestProbeHandlerServerName tests that the server_name query parameter
// overrides the module's TLS ServerName (SNI). With certificate validation
// enabled, a mismatched server_name must fail verification, proving the
// parameter reaches the TLS handshake.
func TestProbeHandlerServerName(t *testing.T) {
	server, _, _, caFile, teardown, err := test.SetupHTTPSServer()
	if err != nil {
		t.Fatal(err)
	}
	defer teardown()

	server.StartTLS()
	defer server.Close()

	conf := &config.Config{
		Modules: map[string]config.Module{
			"https": {
				Prober: "https",
				TLSConfig: config.TLSConfig{
					CAFile: caFile,
				},
			},
		},
	}

	rr, err := probeWithServerName(server.URL, "https", "wrong.example.invalid", conf)
	if err != nil {
		t.Fatal(err)
	}

	if ok := strings.Contains(rr.Body.String(), "ssl_probe_success 0"); !ok {
		t.Errorf("expected `ssl_probe_success 0` for mismatched server_name")
	}
}

// TestProbeHandlerServerNameConflict tests that supplying server_name both in
// the module configuration and as a query parameter is rejected with 400.
func TestProbeHandlerServerNameConflict(t *testing.T) {
	conf := &config.Config{
		Modules: map[string]config.Module{
			"https": {
				Prober: "https",
				TLSConfig: config.TLSConfig{
					ServerName: "configured.example.com",
				},
			},
		},
	}

	rr, err := probeWithServerName("127.0.0.1:443", "https", "query.example.com", conf)
	if err != nil {
		t.Fatal(err)
	}

	if rr.Code != http.StatusBadRequest {
		t.Errorf("expected code %d, got %d", http.StatusBadRequest, rr.Code)
	}
}

func probeWithServerName(target, module, serverName string, conf *config.Config) (*httptest.ResponseRecorder, error) {
	uri := "/probe?target=" + target
	if module != "" {
		uri = uri + "&module=" + module
	}
	if serverName != "" {
		uri = uri + "&server_name=" + serverName
	}
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeHandler(newTestLogger(), w, r, conf)
	})
	handler.ServeHTTP(rr, req)

	return rr, nil
}

func probe(target, module string, conf *config.Config) (*httptest.ResponseRecorder, error) {
	uri := "/probe?target=" + target
	if module != "" {
		uri = uri + "&module=" + module
	}
	req, err := http.NewRequest("GET", uri, nil)
	if err != nil {
		return nil, err
	}

	rr := httptest.NewRecorder()
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		probeHandler(newTestLogger(), w, r, conf)
	})

	handler.ServeHTTP(rr, req)

	return rr, nil
}

func newTestLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(os.Stdout, nil))
}
