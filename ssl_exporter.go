package main

import (
	"context"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/alecthomas/kingpin/v2"
	"github.com/prometheus/client_golang/prometheus"
	versioncollector "github.com/prometheus/client_golang/prometheus/collectors/version"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/promslog"
	promslogflag "github.com/prometheus/common/promslog/flag"
	"github.com/prometheus/common/version"
	"github.com/prometheus/exporter-toolkit/web"
	webflag "github.com/prometheus/exporter-toolkit/web/kingpinflag"
	"github.com/piotrkochan/ssl_exporter/v2/config"
	"github.com/piotrkochan/ssl_exporter/v2/prober"
)

const (
	namespace = "ssl"
)

func probeHandler(logger *slog.Logger, w http.ResponseWriter, r *http.Request, conf *config.Config) {
	moduleName := r.URL.Query().Get("module")
	if moduleName == "" {
		moduleName = conf.DefaultModule
		if moduleName == "" {
			http.Error(w, "Module parameter must be set", http.StatusBadRequest)
			return
		}
	}
	module, ok := conf.Modules[moduleName]
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown module %q", moduleName), http.StatusBadRequest)
		return
	}

	timeout := module.Timeout
	if timeout == 0 {
		// The following timeout block was taken wholly from the blackbox exporter
		//   https://github.com/prometheus/blackbox_exporter/blob/master/main.go
		var timeoutSeconds float64
		if v := r.Header.Get("X-Prometheus-Scrape-Timeout-Seconds"); v != "" {
			var err error
			timeoutSeconds, err = strconv.ParseFloat(v, 64)
			if err != nil {
				http.Error(w, fmt.Sprintf("Failed to parse timeout from Prometheus header: %s", err), http.StatusInternalServerError)
				return
			}
		} else {
			timeoutSeconds = 10
		}
		if timeoutSeconds == 0 {
			timeoutSeconds = 10
		}

		timeout = time.Duration((timeoutSeconds) * 1e9)
	}

	ctx, cancel := context.WithTimeout(r.Context(), timeout)
	defer cancel()

	target := module.Target
	if target == "" {
		target = r.URL.Query().Get("target")
		if target == "" {
			http.Error(w, "Target parameter is missing", http.StatusBadRequest)
			return
		}
	}

	// The server_name query parameter sets the TLS ServerName (SNI) for a single
	// probe, which is useful when the target is an IP address. To keep explicit
	// module configuration authoritative, it is rejected when the module already
	// defines a server_name.
	if serverName := r.URL.Query().Get("server_name"); serverName != "" {
		if module.TLSConfig.ServerName != "" {
			http.Error(w, "server_name is set in both the module configuration and the query parameter", http.StatusBadRequest)
			return
		}
		logger.Debug(fmt.Sprintf("Using %s as server name", serverName))
		logger = logger.With("server_name", serverName)
		module.TLSConfig.ServerName = serverName
	}

	probeFunc, ok := prober.Probers[module.Prober]
	if !ok {
		http.Error(w, fmt.Sprintf("Unknown prober %q", module.Prober), http.StatusBadRequest)
		return
	}

	var (
		probeSuccess = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "probe_success"),
				Help: "If the probe was a success",
			},
		)
		probeDuration = prometheus.NewGauge(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "probe_duration_seconds"),
				Help: "Returns how long the probe took to complete in seconds",
			},
		)
		proberType = prometheus.NewGaugeVec(
			prometheus.GaugeOpts{
				Name: prometheus.BuildFQName(namespace, "", "prober"),
				Help: "The prober used by the exporter to connect to the target",
			},
			[]string{"prober"},
		)
	)

	registry := prometheus.NewRegistry()
	registry.MustRegister(probeSuccess, probeDuration, proberType)
	proberType.WithLabelValues(module.Prober).Set(1)

	probeLogger := logger.With("target", target, "prober", module.Prober, "timeout", timeout)

	start := time.Now()
	err := probeFunc(ctx, probeLogger, target, module, registry)
	probeDuration.Set(time.Since(start).Seconds())
	if err != nil {
		probeLogger.Error(err.Error())
		probeSuccess.Set(0)
	} else {
		probeSuccess.Set(1)
	}

	// Serve
	h := promhttp.HandlerFor(registry, promhttp.HandlerOpts{})
	h.ServeHTTP(w, r)
}

func init() {
	prometheus.MustRegister(versioncollector.NewCollector(namespace + "_exporter"))
}

func main() {
	var (
		metricsPath    = kingpin.Flag("web.metrics-path", "Path under which to expose metrics").Default("/metrics").String()
		probePath      = kingpin.Flag("web.probe-path", "Path under which to expose the probe endpoint").Default("/probe").String()
		configFile     = kingpin.Flag("config.file", "SSL exporter configuration file").Default("").String()
		toolkitFlags   = webflag.AddFlags(kingpin.CommandLine, ":9219")
		promslogConfig = &promslog.Config{}
		err            error
	)

	promslogflag.AddFlags(kingpin.CommandLine, promslogConfig)
	kingpin.Version(version.Print(namespace + "_exporter"))
	kingpin.HelpFlag.Short('h')
	kingpin.Parse()

	logger := promslog.New(promslogConfig)

	conf := config.DefaultConfig
	if *configFile != "" {
		conf, err = config.LoadConfig(*configFile)
		if err != nil {
			logger.Error("Error loading config", "err", err)
			os.Exit(1)
		}
	}

	logger.Info(fmt.Sprintf("Starting %s_exporter %s", namespace, version.Info()))
	logger.Info(fmt.Sprintf("Build context %s", version.BuildContext()))

	http.Handle(*metricsPath, promhttp.Handler())
	http.HandleFunc(*probePath, func(w http.ResponseWriter, r *http.Request) {
		probeHandler(logger, w, r, conf)
	})
	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<html>
						 <head><title>SSL Exporter</title></head>
						 <body>
						 <h1>SSL Exporter</h1>
						 <p><a href="` + *probePath + `?target=example.com:443">Probe example.com:443 for SSL cert metrics</a></p>
						 <p><a href='` + *metricsPath + `'>Metrics</a></p>
						 </body>
						 </html>`))
	})

	server := &http.Server{}
	if err := web.ListenAndServe(server, toolkitFlags, logger); err != nil {
		logger.Error("Error starting HTTP server", "err", err)
		os.Exit(1)
	}
}
