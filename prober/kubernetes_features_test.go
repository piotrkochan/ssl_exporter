package prober

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/piotrkochan/ssl_exporter/v2/config"
	"github.com/piotrkochan/ssl_exporter/v2/test"
	"github.com/prometheus/client_golang/prometheus"
)

func TestKubernetesNamespaceScope(t *testing.T) {
	cert, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour))
	for _, tt := range []struct {
		target, path string
	}{
		{"monitoring/certificate", "/api/v1/namespaces/monitoring/secrets"},
		{"monitoring/*", "/api/v1/namespaces/monitoring/secrets"},
		{"*/*", "/api/v1/secrets"},
		{"mon*/*", "/api/v1/secrets"},
		{"monitorin?/*", "/api/v1/secrets"},
		{"monitorin[g]/*", "/api/v1/secrets"},
		{"{monitoring,production}/*", "/api/v1/secrets"},
		{`\monitoring/*`, "/api/v1/secrets"},
	} {
		t.Run(tt.target, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != tt.path {
					t.Errorf("path = %q, want %q", r.URL.Path, tt.path)
					// Reject requests outside the service account's allowed scope.
					http.Error(w, "forbidden", http.StatusForbidden)
					return
				}
				if got := r.URL.Query().Get("fieldSelector"); got != "type=kubernetes.io/tls" {
					t.Errorf("fieldSelector = %q", got)
				}
				w.Header().Set("Content-Type", "application/json")
				if err := json.NewEncoder(w).Encode(kubernetesSecretList{Items: []kubernetesSecret{{
					Metadata: kubernetesObjectMeta{Name: "certificate", Namespace: "monitoring"},
					Data:     map[string][]byte{"tls.crt": cert},
				}}}); err != nil {
					t.Error(err)
				}
			}))
			t.Cleanup(server.Close)
			registry := prometheus.NewRegistry()
			if err := probeKubernetes(t.Context(), tt.target, config.Module{}, registry, newTestKubernetesSecretsClient(t, server)); err != nil {
				t.Fatal(err)
			}
			metrics, err := registry.Gather()
			if err != nil || len(metrics) != 2 {
				t.Fatalf("expected certificate metrics, got %d families, error %v", len(metrics), err)
			}
		})
	}
}

func TestKubernetesSecretLabels(t *testing.T) {
	cert, _ := test.GenerateTestCertificate(time.Now().Add(time.Hour))
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		// Use maps to test decoding metadata.labels from the API response.
		items := []any{}
		for _, name := range []string{"labelled", "unlabelled"} {
			metadata := map[string]any{"name": name, "namespace": "monitoring"}
			if name == "labelled" {
				metadata["labels"] = map[string]string{
					"ssl-exporter.env": "DEV", "app.kubernetes.io/name": "myapp", "ignored": "value",
				}
			}
			items = append(items, map[string]any{
				"metadata": metadata,
				"data":     map[string][]byte{"tls.crt": cert, "ca.crt": cert},
			})
		}
		if err := json.NewEncoder(w).Encode(map[string]any{"items": items}); err != nil {
			t.Error(err)
		}
	}))
	defer server.Close()
	path := filepath.Join(t.TempDir(), "config.yml")
	if err := os.WriteFile(path, []byte(`modules:
  kubernetes:
    prober: kubernetes
    kubernetes:
      secret_labels:
        ssl-exporter.env: env
        app.kubernetes.io/name: app
`), 0600); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	for _, mapped := range []bool{false, true} {
		module := config.Module{}
		if mapped {
			module = cfg.Modules["kubernetes"]
		}
		registry := prometheus.NewRegistry()
		if err := probeKubernetes(t.Context(), "monitoring/*", module, registry, newTestKubernetesSecretsClient(t, server)); err != nil {
			t.Fatal(err)
		}
		families, err := registry.Gather()
		if err != nil {
			t.Fatal(err)
		}
		if len(families) != 2 {
			t.Fatalf("got %d metric families, want 2", len(families))
		}
		for _, family := range families {
			if len(family.Metric) != 4 {
				t.Fatalf("got %d metrics, want 4 (two secrets, two certificate keys)", len(family.Metric))
			}
			for _, metric := range family.Metric {
				labels := map[string]string{}
				for _, label := range metric.Label {
					labels[label.GetName()] = label.GetValue()
				}
				wantCount := 10
				if mapped {
					wantCount += 2
					wantEnv, wantApp := "", ""
					if labels["secret"] == "labelled" {
						wantEnv, wantApp = "DEV", "myapp"
					}
					if env, ok := labels["env"]; !ok || env != wantEnv {
						t.Errorf("env = %q (present %v), want %q", env, ok, wantEnv)
					}
					if app, ok := labels["app"]; !ok || app != wantApp {
						t.Errorf("app = %q (present %v), want %q", app, ok, wantApp)
					}
				}
				if len(labels) != wantCount {
					t.Errorf("got labels %v, want %d labels (mapped %v)", labels, wantCount, mapped)
				}
			}
		}
	}
}

func TestKubernetesNamespaceForbidden(t *testing.T) {
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.URL.Path != "/api/v1/namespaces/monitoring/secrets" {
			t.Errorf("unexpected path: %s", r.URL.Path)
		}
		http.Error(w, "forbidden", http.StatusForbidden)
	}))
	defer server.Close()
	// A 403 must not cause a retry against all namespaces.
	if err := probeKubernetes(t.Context(), "monitoring/*", config.Module{}, prometheus.NewRegistry(), newTestKubernetesSecretsClient(t, server)); err == nil {
		t.Fatal("expected authorization error")
	}
	if got := calls.Load(); got != 1 {
		t.Errorf("got %d requests, want 1", got)
	}
}
