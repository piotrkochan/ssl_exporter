package prober

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v2"
	"github.com/piotrkochan/ssl_exporter/v2/config"
	"github.com/prometheus/client_golang/prometheus"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/flowcontrol"

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

type kubernetesSecretsClient struct {
	restClient *rest.RESTClient
}

// ProbeKubernetes collects certificate metrics from kubernetes.io/tls Secrets
func ProbeKubernetes(ctx context.Context, logger *slog.Logger, target string, module config.Module, registry *prometheus.Registry) error {
	client, err := newKubeClient(module.Kubernetes)
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
func newKubeClient(kubernetesConfig config.KubernetesProbe) (kubernetesClient, error) {
	loadingRules := clientcmd.NewDefaultClientConfigLoadingRules()
	if kubernetesConfig.Kubeconfig != "" {
		loadingRules.ExplicitPath = kubernetesConfig.Kubeconfig
	}
	kubeConfig := clientcmd.NewNonInteractiveDeferredLoadingClientConfig(
		loadingRules,
		&clientcmd.ConfigOverrides{},
	)
	restConfig, err := kubeConfig.ClientConfig()
	if err != nil {
		return nil, err
	}
	restConfig.QPS = kubernetesConfig.Client.QPS
	restConfig.Burst = kubernetesConfig.Client.Burst
	restConfig.Timeout = kubernetesConfig.Client.ReadTimeout
	if kubernetesConfig.Client.UserAgent != "" {
		restConfig.UserAgent = kubernetesConfig.Client.UserAgent
	}
	if kubernetesConfig.Client.ConnectTimeout > 0 {
		restConfig.Dial = (&net.Dialer{
			Timeout:   kubernetesConfig.Client.ConnectTimeout,
			KeepAlive: 30 * time.Second,
		}).DialContext
	}
	if restConfig.UserAgent == "" {
		restConfig.UserAgent = rest.DefaultKubernetesUserAgent()
	}

	httpClient, err := rest.HTTPClientFor(restConfig)
	if err != nil {
		return nil, err
	}

	return newKubernetesSecretsClient(restConfig, httpClient)
}

func newKubernetesSecretsClient(restConfig *rest.Config, httpClient *http.Client) (*kubernetesSecretsClient, error) {
	baseURL, err := url.Parse(restConfig.Host)
	if err != nil {
		return nil, fmt.Errorf("invalid Kubernetes API URL: %w", err)
	}

	rateLimiter := restConfig.RateLimiter
	if rateLimiter == nil {
		qps := restConfig.QPS
		if qps == 0 {
			qps = rest.DefaultQPS
		}
		burst := restConfig.Burst
		if burst == 0 {
			burst = rest.DefaultBurst
		}
		if qps > 0 {
			if burst <= 0 {
				return nil, fmt.Errorf("burst is required to be greater than 0 when RateLimiter is not set and QPS is set to greater than 0")
			}
			rateLimiter = flowcontrol.NewTokenBucketRateLimiter(qps, burst)
		}
	}

	client, err := rest.NewRESTClient(
		baseURL,
		"/api/v1",
		rest.ClientContentConfig{
			AcceptContentTypes: "application/json",
			ContentType:        "application/json",
		},
		rateLimiter,
		httpClient,
	)
	if err != nil {
		return nil, err
	}

	return &kubernetesSecretsClient{restClient: client}, nil
}

func (c *kubernetesSecretsClient) ListTLSSecrets(ctx context.Context) ([]kubernetesSecret, error) {
	body, err := c.restClient.Get().
		Resource("secrets").
		Param("fieldSelector", "type=kubernetes.io/tls").
		DoRaw(ctx)
	if err != nil {
		return nil, err
	}

	var secrets kubernetesSecretList
	if err := json.Unmarshal(body, &secrets); err != nil {
		return nil, fmt.Errorf("decoding Kubernetes Secrets: %w", err)
	}

	return secrets.Items, nil
}
