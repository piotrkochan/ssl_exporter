package prober

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"github.com/piotrkochan/ssl_exporter/v2/config"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

func TestCollectOCSPResponderMetricsRevoked(t *testing.T) {
	state, ocspResponse, responderURL := testOCSPResponderState(t, ocsp.Revoked)
	registry := prometheus.NewRegistry()

	collectOCSPResponderMetrics(context.Background(), state, config.OCSPProbe{
		ResponderURL: config.URL{URL: responderURL},
	}, registry)

	checkOCSPResponderMetrics(ocspResponse, 1, registry, t)
}

func TestCollectOCSPResponderMetricsStatus(t *testing.T) {
	tests := []struct {
		name   string
		status int
	}{
		{name: "good", status: ocsp.Good},
		{name: "unknown", status: ocsp.Unknown},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, ocspResponse, responderURL := testOCSPResponderState(t, tt.status)
			registry := prometheus.NewRegistry()

			collectOCSPResponderMetrics(context.Background(), state, config.OCSPProbe{
				ResponderURL: config.URL{URL: responderURL},
			}, registry)

			checkOCSPResponderMetrics(ocspResponse, 1, registry, t)
		})
	}
}

func TestCollectOCSPResponderMetricsNoResponderURL(t *testing.T) {
	state, _, _ := testOCSPResponderState(t, ocsp.Good)
	state.PeerCertificates[0].OCSPServer = nil
	registry := prometheus.NewRegistry()

	collectOCSPResponderMetrics(context.Background(), state, config.OCSPProbe{}, registry)

	checkOCSPResponderMetrics(nil, 0, registry, t)
}

func TestCollectConnectionStateMetricsOCSPResponderSourceSkipsTLSOCSPMetrics(t *testing.T) {
	state, _, _ := testOCSPResponderState(t, ocsp.Good)
	registry := prometheus.NewRegistry()

	if err := collectConnectionStateMetrics(state, registry, config.OCSPSourceResponder); err != nil {
		t.Fatalf("unexpected error: %s", err)
	}

	if metricFamilyExists(registry, "ssl_ocsp_response_status", t) {
		t.Fatalf("ssl_ocsp_response_status should not be registered for responder-only source")
	}
}

func checkOCSPResponderMetrics(resp []byte, success float64, registry *prometheus.Registry, t *testing.T) {
	var (
		status     float64
		nextUpdate float64
		thisUpdate float64
		revokedAt  float64
		producedAt float64
	)
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(resp) > 0 {
		parsedResponse, err := ocsp.ParseResponse(resp, nil)
		if err != nil {
			t.Fatal(err)
		}
		status = float64(parsedResponse.Status)
		nextUpdate = float64(parsedResponse.NextUpdate.Unix())
		thisUpdate = float64(parsedResponse.ThisUpdate.Unix())
		revokedAt = float64(parsedResponse.RevokedAt.Unix())
		producedAt = float64(parsedResponse.ProducedAt.Unix())
	}
	expectedResults := []*registryResult{
		{Name: "ssl_ocsp_responder_success", Value: success},
		{Name: "ssl_ocsp_responder_status", Value: status},
		{Name: "ssl_ocsp_responder_next_update", Value: nextUpdate},
		{Name: "ssl_ocsp_responder_this_update", Value: thisUpdate},
		{Name: "ssl_ocsp_responder_revoked_at", Value: revokedAt},
		{Name: "ssl_ocsp_responder_produced_at", Value: producedAt},
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func metricFamilyExists(registry *prometheus.Registry, name string, t *testing.T) bool {
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == name {
			return true
		}
	}
	return false
}

func testOCSPResponderState(t *testing.T, status int) (tls.ConnectionState, []byte, *url.URL) {
	t.Helper()

	issuerKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	issuerTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test issuer"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	issuerDER, err := x509.CreateCertificate(rand.Reader, issuerTemplate, issuerTemplate, &issuerKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	issuer, err := x509.ParseCertificate(issuerDER)
	if err != nil {
		t.Fatal(err)
	}

	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(2),
		Subject:               pkix.Name{CommonName: "test leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		DNSNames:              []string{"example.test"},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, issuer, &leafKey.PublicKey, issuerKey)
	if err != nil {
		t.Fatal(err)
	}
	leaf, err := x509.ParseCertificate(leafDER)
	if err != nil {
		t.Fatal(err)
	}

	ocspResponse, err := ocsp.CreateResponse(issuer, issuer, ocsp.Response{
		SerialNumber: leaf.SerialNumber,
		Status:       status,
		ProducedAt:   time.Now(),
		ThisUpdate:   time.Now(),
		NextUpdate:   time.Now().Add(time.Hour),
		RevokedAt:    time.Now().Add(-time.Hour),
	}, issuerKey)
	if err != nil {
		t.Fatal(err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Errorf("method = %s, want POST", r.Method)
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		_, _ = w.Write(ocspResponse)
	}))
	t.Cleanup(server.Close)

	responderURL, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	leaf.OCSPServer = []string{server.URL}

	return tls.ConnectionState{
		Version:     tls.VersionTLS13,
		CipherSuite: tls.TLS_AES_128_GCM_SHA256,
		PeerCertificates: []*x509.Certificate{
			leaf,
			issuer,
		},
		VerifiedChains: [][]*x509.Certificate{{
			leaf,
			issuer,
		}},
	}, ocspResponse, responderURL
}
