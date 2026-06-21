package prober

import (
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"reflect"
	"strconv"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"
	"golang.org/x/crypto/ocsp"
)

type registryResult struct {
	Name        string
	LabelValues map[string]string
	Value       float64
}

func (rr *registryResult) String() string {
	var labels []string
	for k, v := range rr.LabelValues {
		labels = append(labels, k+"=\""+v+"\"")
	}
	m := rr.Name
	if len(labels) > 0 {
		m = fmt.Sprintf("%s{%s}", m, strings.Join(labels, ","))
	}
	return fmt.Sprintf("%s %f", m, rr.Value)
}

func checkRegistryResults(expectedResults []*registryResult, mfs []*dto.MetricFamily, t *testing.T) {
	for _, expRes := range expectedResults {
		checkRegistryResult(expRes, mfs, t)
	}
}

func checkRegistryResult(expRes *registryResult, mfs []*dto.MetricFamily, t *testing.T) {
	var results []*registryResult
	for _, mf := range mfs {
		for _, metric := range mf.Metric {
			result := &registryResult{
				Name:  mf.GetName(),
				Value: metric.GetGauge().GetValue(),
			}
			if len(metric.GetLabel()) > 0 {
				labelValues := make(map[string]string)
				for _, l := range metric.GetLabel() {
					labelValues[l.GetName()] = l.GetValue()
				}
				result.LabelValues = labelValues
			}
			results = append(results, result)
		}
	}
	var ok bool
	var resStr string
	for _, res := range results {
		resStr = resStr + "\n" + res.String()
		if reflect.DeepEqual(res, expRes) {
			ok = true
		}
	}
	if !ok {
		t.Fatalf("Expected %s, got: %s", expRes.String(), resStr)
	}
}

func checkCertificateMetrics(cert *x509.Certificate, registry *prometheus.Registry, t *testing.T) {
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	ips := ","
	for _, ip := range cert.IPAddresses {
		ips = ips + ip.String() + ","
	}
	expectedLabels := map[string]string{
		"serial_no": cert.SerialNumber.String(),
		"issuer_cn": cert.Issuer.CommonName,
		"cn":        cert.Subject.CommonName,
		"dnsnames":  "," + strings.Join(cert.DNSNames, ",") + ",",
		"ips":       ips,
		"emails":    "," + strings.Join(cert.EmailAddresses, ",") + ",",
		"ou":        "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
	}
	expectedResults := []*registryResult{
		{
			Name:        "ssl_cert_not_after",
			LabelValues: expectedLabels,
			Value:       float64(cert.NotAfter.Unix()),
		},
		{
			Name:        "ssl_cert_not_before",
			LabelValues: expectedLabels,
			Value:       float64(cert.NotBefore.Unix()),
		},
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func checkVerifiedChainMetrics(verifiedChains [][]*x509.Certificate, registry *prometheus.Registry, t *testing.T) {
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	for i, chain := range verifiedChains {
		for _, cert := range chain {
			ips := ","
			for _, ip := range cert.IPAddresses {
				ips = ips + ip.String() + ","
			}
			expectedLabels := map[string]string{
				"chain_no":  strconv.Itoa(i),
				"serial_no": cert.SerialNumber.String(),
				"issuer_cn": cert.Issuer.CommonName,
				"cn":        cert.Subject.CommonName,
				"dnsnames":  "," + strings.Join(cert.DNSNames, ",") + ",",
				"ips":       ips,
				"emails":    "," + strings.Join(cert.EmailAddresses, ",") + ",",
				"ou":        "," + strings.Join(cert.Subject.OrganizationalUnit, ",") + ",",
			}
			expectedResults := []*registryResult{
				{
					Name:        "ssl_verified_cert_not_after",
					LabelValues: expectedLabels,
					Value:       float64(cert.NotAfter.Unix()),
				},
				{
					Name:        "ssl_verified_cert_not_before",
					LabelValues: expectedLabels,
					Value:       float64(cert.NotBefore.Unix()),
				},
			}
			checkRegistryResults(expectedResults, mfs, t)
		}
	}
}

func checkOCSPMetrics(resp []byte, registry *prometheus.Registry, t *testing.T) {
	var (
		stapled    float64
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
		stapled = 1
		status = float64(parsedResponse.Status)
		nextUpdate = float64(parsedResponse.NextUpdate.Unix())
		thisUpdate = float64(parsedResponse.ThisUpdate.Unix())
		revokedAt = float64(parsedResponse.RevokedAt.Unix())
		producedAt = float64(parsedResponse.ProducedAt.Unix())
	}
	expectedResults := []*registryResult{
		{
			Name:  "ssl_ocsp_response_stapled",
			Value: stapled,
		},
		{
			Name:  "ssl_ocsp_response_status",
			Value: status,
		},
		{
			Name:  "ssl_ocsp_response_next_update",
			Value: nextUpdate,
		},
		{
			Name:  "ssl_ocsp_response_this_update",
			Value: thisUpdate,
		},
		{
			Name:  "ssl_ocsp_response_revoked_at",
			Value: revokedAt,
		},
		{
			Name:  "ssl_ocsp_response_produced_at",
			Value: producedAt,
		},
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func checkTLSVersionMetrics(version string, registry *prometheus.Registry, t *testing.T) {
	mfs, err := registry.Gather()
	if err != nil {
		t.Fatal(err)
	}
	expectedResults := []*registryResult{
		{
			Name: "ssl_tls_version_info",
			LabelValues: map[string]string{
				"version": version,
			},
			Value: 1,
		},
	}
	checkRegistryResults(expectedResults, mfs, t)
}

func TestCollectCipherMetricsSecure(t *testing.T) {
	registry := prometheus.NewRegistry()
	suite := tls.CipherSuites()[0]
	if err := collectCipherMetrics(suite.ID, registry); err != nil {
		t.Fatal(err)
	}
	mfs, _ := registry.Gather()
	checkRegistryResult(&registryResult{
		Name:        "ssl_tls_cipher_suite",
		LabelValues: map[string]string{"cipher_suite": suite.Name, "insecure": "false"},
		Value:       1,
	}, mfs, t)
}

func TestCollectCipherMetricsInsecure(t *testing.T) {
	registry := prometheus.NewRegistry()
	suite := tls.InsecureCipherSuites()[0]
	if err := collectCipherMetrics(suite.ID, registry); err != nil {
		t.Fatal(err)
	}
	mfs, _ := registry.Gather()
	checkRegistryResult(&registryResult{
		Name:        "ssl_tls_cipher_suite",
		LabelValues: map[string]string{"cipher_suite": suite.Name, "insecure": "true"},
		Value:       1,
	}, mfs, t)
}

func TestCollectKeyExchangeMetricsPQC(t *testing.T) {
	registry := prometheus.NewRegistry()
	if err := collectKeyExchangeMetrics(tls.X25519MLKEM768, registry); err != nil {
		t.Fatal(err)
	}
	mfs, _ := registry.Gather()
	checkRegistryResult(&registryResult{
		Name:        "ssl_tls_key_exchange",
		LabelValues: map[string]string{"key_exchange": tls.X25519MLKEM768.String(), "post_quantum": "true"},
		Value:       1,
	}, mfs, t)
}

func TestCollectKeyExchangeMetricsClassical(t *testing.T) {
	registry := prometheus.NewRegistry()
	if err := collectKeyExchangeMetrics(tls.X25519, registry); err != nil {
		t.Fatal(err)
	}
	mfs, _ := registry.Gather()
	checkRegistryResult(&registryResult{
		Name:        "ssl_tls_key_exchange",
		LabelValues: map[string]string{"key_exchange": tls.X25519.String(), "post_quantum": "false"},
		Value:       1,
	}, mfs, t)
}

func TestCollectKeyExchangeMetricsRSA(t *testing.T) {
	registry := prometheus.NewRegistry()
	if err := collectKeyExchangeMetrics(0, registry); err != nil {
		t.Fatal(err)
	}
	mfs, _ := registry.Gather()
	checkRegistryResult(&registryResult{
		Name:        "ssl_tls_key_exchange",
		LabelValues: map[string]string{"key_exchange": "RSA", "post_quantum": "false"},
		Value:       1,
	}, mfs, t)
}

func newCertificate(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	return x509.ParseCertificate(block.Bytes)
}

func newKey(keyPEM []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(keyPEM))
	return x509.ParsePKCS1PrivateKey(block.Bytes)
}
