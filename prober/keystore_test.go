package prober

import (
	"context"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/piotrkochan/ssl_exporter/v2/config"
	"github.com/piotrkochan/ssl_exporter/v2/test"

	"github.com/prometheus/client_golang/prometheus"
)

// TestProbeKeystoreDuplicateAliases verifies that the same certificate stored
// under multiple aliases is deduplicated into a single time series.
func TestProbeKeystoreDuplicateAliases(t *testing.T) {
	certPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 1))
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	tmpFile, err := os.CreateTemp("", "dup*.keystore")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())

	// Same certificate under two aliases (cert-0, cert-1).
	jks := test.GenerateTestJKSWithCertificate([]*x509.Certificate{cert, cert})
	if err := jks.Store(tmpFile, []byte("changeit")); err != nil {
		t.Fatal(err)
	}
	tmpFile.Close()

	module := config.Module{Keystore: config.KeystoreProbe{Password: "changeit"}}
	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := ProbeKeystore(ctx, newTestLogger(), tmpFile.Name(), module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, mf := range mfs {
		if mf.GetName() == "ssl_keystore_cert_not_after" {
			if got := len(mf.GetMetric()); got != 1 {
				t.Fatalf("expected 1 ssl_keystore_cert_not_after series, got %d", got)
			}
		}
	}
}

// TestReadKeyStoreDetection covers the format-detection branches of readKeyStore,
// including the error paths for unrecognized and undersized inputs.
func TestReadKeyStoreDetection(t *testing.T) {
	tests := []struct {
		name    string
		data    []byte
		wantErr bool
	}{
		{"too small", []byte{0x01, 0x02}, true},
		{"unrecognized format", []byte{0xDE, 0xAD, 0xBE, 0xEF}, true},
		{"jks magic but invalid body", []byte{0xFE, 0xED, 0xFE, 0xED, 0x00}, true},
		{"pkcs12 tag but invalid body", []byte{0x30, 0x00, 0x00, 0x00}, true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := readKeyStore(tt.data, "changeit"); (err != nil) != tt.wantErr {
				t.Fatalf("readKeyStore() err = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

// TestProbeKeystoreFile tests a java keystore file
func TestProbeKeystoreFile(t *testing.T) {
	cert, certFile, err := createTestJKSFile("", "tls*.keystore")
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

// TestProbeKeystoreFileGlob tests matching a java keystore file with a glob
func TestProbeKeystoreFileGlob(t *testing.T) {
	cert, certFile, err := createTestJKSFile("", "tls*.keystore")
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

	glob := filepath.Dir(certFile) + "/*.keystore"

	if err := ProbeKeystore(ctx, newTestLogger(), glob, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkKeystoreMetrics(cert, certFile, registry, t)
}

// TestProbeKeystoreFileGlobDoubleStar tests matching a java keystore file with a ** glob
func TestProbeKeystoreFileGlobDoubleStar(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "testdir")
	if err != nil {
		t.Fatal(err)
	}
	cert, certFile, err := createTestJKSFile(tmpDir, "tls*.keystore")
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

	glob := filepath.Dir(filepath.Dir(certFile)) + "/**/*.keystore"

	if err := ProbeKeystore(ctx, newTestLogger(), glob, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkKeystoreMetrics(cert, certFile, registry, t)
}

// TestProbeKeystoreFileGlobDoubleStarMultiple tests matching multiple java keystore files with a ** glob
func TestProbeKeystoreFileGlobDoubleStarMultiple(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "testdir")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(tmpDir)

	tmpDir1, err := os.MkdirTemp(tmpDir, "testdir")
	if err != nil {
		t.Fatal(err)
	}
	cert1, certFile1, err := createTestJKSFile(tmpDir1, "1*.keystore")
	if err != nil {
		t.Fatal(err)
	}

	tmpDir2, err := os.MkdirTemp(tmpDir, "testdir")
	if err != nil {
		t.Fatal(err)
	}
	cert2, certFile2, err := createTestJKSFile(tmpDir2, "2*.keystore")
	if err != nil {
		t.Fatal(err)
	}

	module := config.Module{
		Keystore: config.KeystoreProbe{
			Password: "changeit",
		},
	}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	glob := tmpDir + "/**/*.keystore"

	if err := ProbeKeystore(ctx, newTestLogger(), glob, module, registry); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkKeystoreMetrics(cert1, certFile1, registry, t)
	checkKeystoreMetrics(cert2, certFile2, registry, t)
}

// createTestJKSFile creates a java keystore containing a certificate and writes
// it to a file.
func createTestJKSFile(dir, filename string) (*x509.Certificate, string, error) {
	certPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 1))
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, "", err
	}
	tmpFile, err := os.CreateTemp(dir, filename)
	if err != nil {
		return nil, tmpFile.Name(), err
	}
	jks := test.GenerateTestJKSWithCertificate([]*x509.Certificate{cert})
	if err := jks.Store(tmpFile, []byte("changeit")); err != nil {
		return nil, "", err
	}
	if err := tmpFile.Close(); err != nil {
		return nil, tmpFile.Name(), err
	}

	return cert, tmpFile.Name(), nil
}

// checkKeystoreMetrics verifies the gauges exported for a keystore certificate.
func checkKeystoreMetrics(cert *x509.Certificate, certFile string, registry *prometheus.Registry, t *testing.T) {
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	ips := ","
	for _, ip := range cert.IPAddresses {
		ips = ips + ip.String() + ","
	}
	expectedResults := []*registryResult{
		{
			Name: "ssl_keystore_cert_not_after",
			LabelValues: map[string]string{
				"file":      certFile,
				"serial_no": cert.SerialNumber.String(),
				"issuer_cn": cert.Issuer.CommonName,
				"cn":        cert.Subject.CommonName,
				"dnsnames":  "," + strings.Join(cert.DNSNames, ",") + ",",
				"ips":       ips,
				"emails":    "," + strings.Join(cert.EmailAddresses, ",") + ",",
				"ou":        "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
			},
			Value: float64(cert.NotAfter.Unix()),
		},
		{
			Name: "ssl_keystore_cert_not_before",
			LabelValues: map[string]string{
				"file":      certFile,
				"serial_no": cert.SerialNumber.String(),
				"issuer_cn": cert.Issuer.CommonName,
				"cn":        cert.Subject.CommonName,
				"dnsnames":  "," + strings.Join(cert.DNSNames, ",") + ",",
				"ips":       ips,
				"emails":    "," + strings.Join(cert.EmailAddresses, ",") + ",",
				"ou":        "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
			},
			Value: float64(cert.NotBefore.Unix()),
		},
	}
	checkRegistryResults(expectedResults, mfs, t)
}
