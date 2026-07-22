package prober

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/bmatcuk/doublestar/v2"
	"github.com/piotrkochan/ssl_exporter/v2/config"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	// Support oidc in kube config files
	_ "k8s.io/client-go/plugin/pkg/client/auth/oidc"
)

var (
	// ErrKubeBadTarget is returned when the target doesn't match the
	// expected form for the kubernetes prober
	ErrKubeBadTarget = fmt.Errorf("Target secret must be provided in the form: <namespace>/<name>")
)

type kubernetesObjectMeta struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

type kubernetesSecret struct {
	Metadata kubernetesObjectMeta `json:"metadata"`
	Data     map[string][]byte    `json:"data"`
}

type kubernetesSecretList struct {
	Items []kubernetesSecret `json:"items"`
}

type kubernetesClient interface {
	ListTLSSecrets(context.Context) ([]kubernetesSecret, error)
}

type kubernetesRESTClient struct {
	httpClient *http.Client
	secretsURL string
}

// ProbeKubernetes collects certificate metrics from kubernetes.io/tls Secrets
func ProbeKubernetes(ctx context.Context, logger *slog.Logger, target string, module config.Module, registry *prometheus.Registry) error {
	client, err := newKubeClient(module.Kubernetes.Kubeconfig)
	if err != nil {
		return err
	}

	return probeKubernetes(ctx, target, module, registry, client)
}

func probeKubernetes(ctx context.Context, target string, module config.Module, registry *prometheus.Registry, client kubernetesClient) error {
	parts := strings.Split(target, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] == "" {
		return ErrKubeBadTarget
	}

	ns := parts[0]
	name := parts[1]

	var tlsSecrets []kubernetesSecret
	secrets, err := client.ListTLSSecrets(ctx)
	if err != nil {
		return err
	}
	for _, secret := range secrets {
		nMatch, err := doublestar.Match(ns, secret.Metadata.Namespace)
		if err != nil {
			return err
		}
		sMatch, err := doublestar.Match(name, secret.Metadata.Name)
		if err != nil {
			return err
		}
		if nMatch && sMatch {
			tlsSecrets = append(tlsSecrets, secret)
		}
	}

	return collectKubernetesSecretMetrics(tlsSecrets, registry)
}

// newKubeClient returns a minimal Kubernetes Secrets client from the supplied
// kubeconfig path, the KUBECONFIG environment variable, the default config file
// location ($HOME/.kube/config) or from the in-cluster service account environment.
func newKubeClient(path string) (kubernetesClient, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if path != "" {
		loadingRules.ExplicitPath = path
	}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{},
	)
	restConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, err
	}

	httpClient, err := rest.HTTPClientFor(restConfig)
	if err != nil {
		return nil, err
	}

	secretsURL, err := url.Parse(restConfig.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid Kubernetes API URL: %w", err)
	}
	secretsURL.Path = strings.TrimRight(secretsURL.Path, "/") + "/api/v1/secrets"
	query := secretsURL.Query()
	query.Set("fieldSelector", "type=kubernetes.io/tls")
	secretsURL.RawQuery = query.Encode()

	return &kubernetesRESTClient{
		httpClient: httpClient,
		secretsURL: secretsURL.String(),
	}, nil
}

func (c *kubernetesRESTClient) ListTLSSecrets(ctx context.Context) ([]kubernetesSecret, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.secretsURL, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		body, readErr := io.ReadAll(io.LimitReader(resp.Body, 4096))
		if readErr != nil {
			return nil, fmt.Errorf("kubernetes API returned %s", resp.Status)
		}
		return nil, fmt.Errorf("kubernetes API returned %s: %s", resp.Status, strings.TrimSpace(string(body)))
	}

	var secrets kubernetesSecretList
	if err := json.NewDecoder(resp.Body).Decode(&secrets); err != nil {
		return nil, fmt.Errorf("decoding Kubernetes Secrets: %w", err)
	}

	return secrets.Items, nil
}
