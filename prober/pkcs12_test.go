package prober

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"testing"
	"time"

	"github.com/piotrkochan/ssl_exporter/v2/config"
	"github.com/piotrkochan/ssl_exporter/v2/test"

	"github.com/prometheus/client_golang/prometheus"
	pkcs12 "software.sslmate.com/src/go-pkcs12"
)

// TestProbeKeystorePKCS12TrustStore tests that the keystore prober also reads
// PKCS12 files via format autodetection.
func TestProbeKeystorePKCS12TrustStore(t *testing.T) {
	cert, certFile, err := createTestPKCS12File("", "tls*.p12")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(certFile)

	module := config.Module{
		Keystore: config.KeystoreProbe{
			Password: "changeit",
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeKeystore(ctx, newTestLogger(), certFile, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkKeystoreMetrics(cert, certFile, registry, t)
}

// createTestPKCS12File creates a PKCS12 truststore containing a certificate and
// writes it to a file.
func createTestPKCS12File(dir, filename string) (*x509.Certificate, string, error) {
	certPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 1))
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", err
	}

	data, err := pkcs12.Modern.EncodeTrustStore([]*x509.Certificate{cert}, "changeit")
	if err != nil {
		return nil, "", err
	}

	tmpFile, err := os.CreateTemp(dir, filename)
	if err != nil {
		return nil, "", err
	}
	if _, err := tmpFile.Write(data); err != nil {
		return nil, tmpFile.Name(), err
	}
	if err := tmpFile.Close(); err != nil {
		return nil, tmpFile.Name(), err
	}

	return cert, tmpFile.Name(), nil
}
