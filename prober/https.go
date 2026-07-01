package prober

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"

	"github.com/piotrkochan/ssl_exporter/v2/config"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/common/version"
)

var userAgent = fmt.Sprintf("SSLExporter/%s", version.Version)

// ProbeHTTPS performs a https probe
func ProbeHTTPS(ctx context.Context, logger *slog.Logger, target string, module config.Module, registry *prometheus.Registry) error {
	ocspSource := module.OCSP.SourceOrDefault()
	tlsConfig, err := newTLSConfig("", registry, &module.TLSConfig, ocspSource)
	if err != nil {
		return err
	}

	if strings.HasPrefix(target, "http://") {
		return fmt.Errorf("Target is using http scheme: %s", target)
	}

	if !strings.HasPrefix(target, "https://") {
		target = "https://" + target
	}

	targetURL, err := url.Parse(target)
	if err != nil {
		return err
	}

	proxy := http.ProxyFromEnvironment
	if module.HTTPS.ProxyURL.URL != nil {
		proxy = http.ProxyURL(module.HTTPS.ProxyURL.URL)
	}

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Transport: &http.Transport{
			TLSClientConfig:   tlsConfig,
			Proxy:             proxy,
			DisableKeepAlives: true,
		},
	}

	// Issue a GET request to the target
	request, err := http.NewRequest(http.MethodGet, targetURL.String(), nil)
	if err != nil {
		return err
	}
	request = request.WithContext(ctx)
	request.Header.Set("User-Agent", userAgent)
	resp, err := client.Do(request)
	if err != nil {
		return err
	}
	defer func() {
		_, err := io.Copy(io.Discard, resp.Body)
		if err != nil {
			logger.Error(err.Error())
		}
		resp.Body.Close()
	}()

	// Check if the response from the target is encrypted
	if resp.TLS == nil {
		return fmt.Errorf("The response from %s is unencrypted", targetURL.String())
	}

	if ocspSource.UsesResponder() {
		collectOCSPResponderMetrics(ctx, *resp.TLS, module.OCSP, registry)
	}

	return nil
}
