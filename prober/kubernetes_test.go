package prober

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/piotrkochan/ssl_exporter/v2/config"
	"github.com/piotrkochan/ssl_exporter/v2/test"
	"github.com/prometheus/client_golang/prometheus"
)

type fakeKubernetesClient struct {
	secrets []kubernetesSecret
}

func (c *fakeKubernetesClient) ListTLSSecrets(context.Context) ([]kubernetesSecret, error) {
	return c.secrets, nil
}

func TestKubernetesRESTClient_ListTLSSecrets(t *testing.T) {
	expected := kubernetesSecret{
		Metadata: kubernetesObjectMeta{
			Name:      "certificate",
			Namespace: "monitoring",
		},
		Data: map[string][]byte{
			"tls.crt": []byte("certificate data"),
		},
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: got %q, want %q", r.Method, http.MethodGet)
		}
		if r.URL.Path != "/api/v1/secrets" {
			t.Errorf("unexpected path: got %q, want %q", r.URL.Path, "/api/v1/secrets")
		}
		if got := r.URL.Query().Get("fieldSelector"); got != "type=kubernetes.io/tls" {
			t.Errorf("unexpected field selector: got %q", got)
		}
		if got := r.Header.Get("Accept"); got != "application/json" {
			t.Errorf("unexpected Accept header: got %q", got)
		}

		if err := json.NewEncoder(w).Encode(kubernetesSecretList{Items: []kubernetesSecret{expected}}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	client := &kubernetesRESTClient{
		httpClient: server.Client(),
		secretsURL: server.URL + "/api/v1/secrets?fieldSelector=type%3Dkubernetes.io%2Ftls",
	}
	secrets, err := client.ListTLSSecrets(t.Context())
	if err != nil {
		t.Fatalf("ListTLSSecrets() error: %v", err)
	}
	if len(secrets) != 1 {
		t.Fatalf("ListTLSSecrets() returned %d secrets, want 1", len(secrets))
	}
	if secrets[0].Metadata != expected.Metadata {
		t.Errorf("unexpected metadata: got %+v, want %+v", secrets[0].Metadata, expected.Metadata)
	}
	if got := string(secrets[0].Data["tls.crt"]); got != "certificate data" {
		t.Errorf("unexpected certificate data: got %q", got)
	}
}

func TestKubernetesClientEndToEnd(t *testing.T) {
	const token = "test-bearer-token"

	certPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour))
	block, _ := pem.Decode(certPEM)
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatalf("parsing test certificate: %v", err)
	}

	expected := kubernetesSecret{
		Metadata: kubernetesObjectMeta{
			Name:      "certificate",
			Namespace: "monitoring",
		},
		Data: map[string][]byte{
			"tls.crt": certPEM,
		},
	}

	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.Header.Get("Authorization"); got != "Bearer "+token {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if r.Method != http.MethodGet {
			t.Errorf("unexpected method: got %q, want %q", r.Method, http.MethodGet)
		}
		if r.URL.Path != "/cluster/api/v1/secrets" {
			t.Errorf("unexpected path: got %q, want %q", r.URL.Path, "/cluster/api/v1/secrets")
		}
		if got := r.URL.Query().Get("fieldSelector"); got != "type=kubernetes.io/tls" {
			t.Errorf("unexpected field selector: got %q", got)
		}

		w.Header().Set("Content-Type", "application/json")
		if err := json.NewEncoder(w).Encode(kubernetesSecretList{Items: []kubernetesSecret{expected}}); err != nil {
			t.Errorf("encoding response: %v", err)
		}
	}))
	t.Cleanup(server.Close)

	caPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: server.Certificate().Raw,
	})
	kubeconfig := fmt.Sprintf(`apiVersion: v1
kind: Config
clusters:
- name: test-cluster
  cluster:
    server: %s/cluster
    certificate-authority-data: %s
users:
- name: test-user
  user:
    token: %s
contexts:
- name: test-context
  context:
    cluster: test-cluster
    user: test-user
current-context: test-context
`, server.URL, base64.StdEncoding.EncodeToString(caPEM), token)
	kubeconfigPath := filepath.Join(t.TempDir(), "config")
	if err := os.WriteFile(kubeconfigPath, []byte(kubeconfig), 0o600); err != nil {
		t.Fatalf("writing kubeconfig: %v", err)
	}

	registry := prometheus.NewRegistry()
	module := config.Module{
		Kubernetes: config.KubernetesProbe{Kubeconfig: kubeconfigPath},
	}
	if err := ProbeKubernetes(t.Context(), slog.Default(), "monitoring/certificate", module, registry); err != nil {
		t.Fatalf("ProbeKubernetes() error: %v", err)
	}

	checkKubernetesMetrics(cert, "monitoring", "certificate", "tls.crt", registry, t)
}

func TestKubernetesRESTClient_ListTLSSecretsError(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	t.Cleanup(server.Close)

	client := &kubernetesRESTClient{
		httpClient: server.Client(),
		secretsURL: server.URL,
	}
	_, err := client.ListTLSSecrets(t.Context())
	if err == nil || !strings.Contains(err.Error(), "403 Forbidden: forbidden") {
		t.Fatalf("ListTLSSecrets() error = %v, want a 403 error", err)
	}
}

func TestKubernetesProbe(t *testing.T) {
	certPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 1))
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	caPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 10))
	block, _ = pem.Decode([]byte(caPEM))
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	fakeKubeClient := &fakeKubernetesClient{secrets: []kubernetesSecret{
		{
			Metadata: kubernetesObjectMeta{
				Name:      "foo",
				Namespace: "bar",
			},
			Data: map[string][]byte{
				"tls.crt": certPEM,
				"ca.crt":  caPEM,
			},
		},
	}}

	module := config.Module{}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := probeKubernetes(ctx, "bar/foo", module, registry, fakeKubeClient); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkKubernetesMetrics(cert, "bar", "foo", "tls.crt", registry, t)
	checkKubernetesMetrics(caCert, "bar", "foo", "ca.crt", registry, t)
}

func TestKubernetesProbeGlob(t *testing.T) {
	certPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 1))
	block, _ := pem.Decode([]byte(certPEM))
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	caPEM, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 10))
	block, _ = pem.Decode([]byte(caPEM))
	caCert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	certPEM2, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 1))
	block, _ = pem.Decode([]byte(certPEM2))
	cert2, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	caPEM2, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour * 10))
	block, _ = pem.Decode([]byte(caPEM2))
	caCert2, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		t.Fatal(err)
	}

	fakeKubeClient := &fakeKubernetesClient{secrets: []kubernetesSecret{
		{
			Metadata: kubernetesObjectMeta{
				Name:      "foo",
				Namespace: "bar",
			},
			Data: map[string][]byte{
				"tls.crt": certPEM,
				"ca.crt":  caPEM,
			},
		},
		{
			Metadata: kubernetesObjectMeta{
				Name:      "fooz",
				Namespace: "baz",
			},
			Data: map[string][]byte{
				"tls.crt": certPEM2,
				"ca.crt":  caPEM2,
			},
		},
	}}

	module := config.Module{}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := probeKubernetes(ctx, "ba*/*", module, registry, fakeKubeClient); err != nil {
		t.Fatalf("error: %s", err)
	}

	checkKubernetesMetrics(cert, "bar", "foo", "tls.crt", registry, t)
	checkKubernetesMetrics(caCert, "bar", "foo", "ca.crt", registry, t)
	checkKubernetesMetrics(cert2, "baz", "fooz", "tls.crt", registry, t)
	checkKubernetesMetrics(caCert2, "baz", "fooz", "ca.crt", registry, t)
}

func TestKubernetesProbeBadTarget(t *testing.T) {
	fakeKubeClient := &fakeKubernetesClient{}

	module := config.Module{}

	registry := prometheus.NewRegistry()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	if err := probeKubernetes(ctx, "bar/foo/bar", module, registry, fakeKubeClient); err != ErrKubeBadTarget {
		t.Fatalf("Expected error: %v, but got %v", ErrKubeBadTarget, err)
	}
}

func checkKubernetesMetrics(cert *x509.Certificate, namespace, name, key string, registry *prometheus.Registry, t *testing.T) {
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
			Name: "ssl_kubernetes_cert_not_after",
			LabelValues: map[string]string{
				"namespace": namespace,
				"secret":    name,
				"key":       key,
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
			Name: "ssl_kubernetes_cert_not_before",
			LabelValues: map[string]string{
				"namespace": namespace,
				"secret":    name,
				"key":       key,
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
