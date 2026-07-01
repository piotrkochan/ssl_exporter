package prober

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/piotrkochan/ssl_exporter/v2/config"
	"github.com/prometheus/client_golang/prometheus"
	"golang.org/x/crypto/ocsp"
)

const (
	defaultOCSPResponderTimeout = 5 * time.Second
	maxOCSPResponderBodySize    = 1 << 20
)

func collectOCSPResponderMetrics(ctx context.Context, state tls.ConnectionState, cfg config.OCSPProbe, registry *prometheus.Registry) {
	var (
		success = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "ocsp_responder", "success"),
				Help: "If the OCSP responder request completed and returned a parseable response",
			},
		)
		status = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "ocsp_responder", "status"),
				Help: "The certificate status in the OCSP responder response 0=Good 1=Revoked 2=Unknown",
			},
		)
		producedAt = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "ocsp_responder", "produced_at"),
				Help: "The producedAt value in the OCSP responder response, expressed as a Unix Epoch Time",
			},
		)
		thisUpdate = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "ocsp_responder", "this_update"),
				Help: "The thisUpdate value in the OCSP responder response, expressed as a Unix Epoch Time",
			},
		)
		nextUpdate = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "ocsp_responder", "next_update"),
				Help: "The nextUpdate value in the OCSP responder response, expressed as a Unix Epoch Time",
			},
		)
		revokedAt = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "ocsp_responder", "revoked_at"),
				Help: "The revocationTime value in the OCSP responder response, expressed as a Unix Epoch Time",
			},
		)
	)
	registry.MustRegister(success, status, producedAt, thisUpdate, nextUpdate, revokedAt)

	resp, err := fetchOCSPResponderResponse(ctx, state, cfg)
	if err != nil {
		return
	}

	success.Set(1)
	status.Set(float64(resp.Status))
	producedAt.Set(float64(resp.ProducedAt.Unix()))
	thisUpdate.Set(float64(resp.ThisUpdate.Unix()))
	nextUpdate.Set(float64(resp.NextUpdate.Unix()))
	revokedAt.Set(float64(resp.RevokedAt.Unix()))
}

func fetchOCSPResponderResponse(ctx context.Context, state tls.ConnectionState, cfg config.OCSPProbe) (*ocsp.Response, error) {
	leaf, issuer, err := ocspCertificatePair(state)
	if err != nil {
		return nil, err
	}

	responderURL, err := ocspResponderURL(leaf, cfg)
	if err != nil {
		return nil, err
	}

	body, err := ocsp.CreateRequest(leaf, issuer, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP request: %w", err)
	}

	timeout := cfg.Timeout
	if timeout == 0 {
		timeout = defaultOCSPResponderTimeout
	}
	reqCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(reqCtx, http.MethodPost, responderURL.String(), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("failed to create OCSP HTTP request: %w", err)
	}
	req.Header.Set("Content-Type", "application/ocsp-request")
	req.Header.Set("Accept", "application/ocsp-response")

	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	httpResp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("OCSP responder request failed: %w", err)
	}
	defer httpResp.Body.Close()

	if httpResp.StatusCode < http.StatusOK || httpResp.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("OCSP responder returned HTTP status %d", httpResp.StatusCode)
	}

	respBody, err := io.ReadAll(io.LimitReader(httpResp.Body, maxOCSPResponderBodySize+1))
	if err != nil {
		return nil, fmt.Errorf("failed to read OCSP responder response: %w", err)
	}
	if len(respBody) > maxOCSPResponderBodySize {
		return nil, fmt.Errorf("OCSP responder response is too large")
	}

	resp, err := ocsp.ParseResponseForCert(respBody, leaf, issuer)
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP responder response: %w", err)
	}

	return resp, nil
}

func ocspCertificatePair(state tls.ConnectionState) (*x509.Certificate, *x509.Certificate, error) {
	if len(state.PeerCertificates) == 0 {
		return nil, nil, fmt.Errorf("no peer certificates found")
	}
	leaf := state.PeerCertificates[0]

	if len(state.VerifiedChains) > 0 && len(state.VerifiedChains[0]) > 1 {
		return leaf, state.VerifiedChains[0][1], nil
	}
	if len(state.PeerCertificates) > 1 {
		return leaf, state.PeerCertificates[1], nil
	}

	return nil, nil, fmt.Errorf("no issuer certificate found")
}

func ocspResponderURL(leaf *x509.Certificate, cfg config.OCSPProbe) (*url.URL, error) {
	if cfg.ResponderURL.URL != nil {
		return validateOCSPResponderURL(cfg.ResponderURL.URL)
	}
	if len(leaf.OCSPServer) == 0 {
		return nil, fmt.Errorf("certificate does not include an OCSP responder URL")
	}
	u, err := url.Parse(leaf.OCSPServer[0])
	if err != nil {
		return nil, fmt.Errorf("failed to parse OCSP responder URL: %w", err)
	}
	return validateOCSPResponderURL(u)
}

func validateOCSPResponderURL(u *url.URL) (*url.URL, error) {
	switch strings.ToLower(u.Scheme) {
	case "http", "https":
		return u, nil
	default:
		return nil, fmt.Errorf("unsupported OCSP responder URL scheme %q", u.Scheme)
	}
}
