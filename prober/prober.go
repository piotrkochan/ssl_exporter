package prober

import (
	"context"
	"log/slog"

	"github.com/piotrkochan/ssl_exporter/v2/config"
	"github.com/prometheus/client_golang/prometheus"
)

var (
	// Probers maps a friendly name to a corresponding probe function
	Probers = map[string]ProbeFn{
		"https":      ProbeHTTPS,
		"http":       ProbeHTTPS,
		"tcp":        ProbeTCP,
		"file":       ProbeFile,
		"http_file":  ProbeHTTPFile,
		"keystore":   ProbeKeystore,
		"kubernetes": ProbeKubernetes,
		"kubeconfig": ProbeKubeconfig,
	}
)

// ProbeFn probes
type ProbeFn func(ctx context.Context, logger *slog.Logger, target string, module config.Module, registry *prometheus.Registry) error
