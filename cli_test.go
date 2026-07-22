package main

import (
	"bytes"
	"errors"
	"flag"
	"strings"
	"testing"
)

func TestParseCLIDefaults(t *testing.T) {
	config, err := parseCLI(nil, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseCLI() error: %v", err)
	}

	if config.metricsPath != "/metrics" {
		t.Errorf("metrics path = %q, want %q", config.metricsPath, "/metrics")
	}
	if config.probePath != "/probe" {
		t.Errorf("probe path = %q, want %q", config.probePath, "/probe")
	}
	if config.configFile != "" {
		t.Errorf("config file = %q, want empty", config.configFile)
	}
	if config.showVersion {
		t.Error("show version = true, want false")
	}
	if got := *config.toolkitFlags.WebListenAddresses; len(got) != 1 || got[0] != defaultWebListenAddress {
		t.Errorf("listen addresses = %v, want [%s]", got, defaultWebListenAddress)
	}
	if *config.toolkitFlags.WebSystemdSocket {
		t.Error("systemd socket = true, want false")
	}
	if *config.toolkitFlags.WebConfigFile != "" {
		t.Errorf("web config file = %q, want empty", *config.toolkitFlags.WebConfigFile)
	}
	if got := config.promslogConfig.Level.String(); got != "info" {
		t.Errorf("log level = %q, want %q", got, "info")
	}
	if got := config.promslogConfig.Format.String(); got != "logfmt" {
		t.Errorf("log format = %q, want %q", got, "logfmt")
	}
}

func TestParseCLICustomFlags(t *testing.T) {
	config, err := parseCLI([]string{
		"--web.metrics-path=/custom-metrics",
		"--web.probe-path=/custom-probe",
		"--config.file=/etc/ssl-exporter.yaml",
		"--web.listen-address=:9218",
		"--web.listen-address=127.0.0.1:9219",
		"--web.config.file=/etc/web-config.yaml",
		"--log.level=debug",
		"--log.format=json",
		"--version",
	}, &bytes.Buffer{})
	if err != nil {
		t.Fatalf("parseCLI() error: %v", err)
	}

	if config.metricsPath != "/custom-metrics" {
		t.Errorf("metrics path = %q, want %q", config.metricsPath, "/custom-metrics")
	}
	if config.probePath != "/custom-probe" {
		t.Errorf("probe path = %q, want %q", config.probePath, "/custom-probe")
	}
	if config.configFile != "/etc/ssl-exporter.yaml" {
		t.Errorf("config file = %q, want %q", config.configFile, "/etc/ssl-exporter.yaml")
	}
	if !config.showVersion {
		t.Error("show version = false, want true")
	}
	wantAddresses := []string{":9218", "127.0.0.1:9219"}
	if got := *config.toolkitFlags.WebListenAddresses; strings.Join(got, ",") != strings.Join(wantAddresses, ",") {
		t.Errorf("listen addresses = %v, want %v", got, wantAddresses)
	}
	if *config.toolkitFlags.WebConfigFile != "/etc/web-config.yaml" {
		t.Errorf("web config file = %q, want %q", *config.toolkitFlags.WebConfigFile, "/etc/web-config.yaml")
	}
	if got := config.promslogConfig.Level.String(); got != "debug" {
		t.Errorf("log level = %q, want %q", got, "debug")
	}
	if got := config.promslogConfig.Format.String(); got != "json" {
		t.Errorf("log format = %q, want %q", got, "json")
	}
}

func TestParseCLIHelp(t *testing.T) {
	var output bytes.Buffer
	_, err := parseCLI([]string{"--help"}, &output)
	if !errors.Is(err, flag.ErrHelp) {
		t.Fatalf("parseCLI() error = %v, want flag.ErrHelp", err)
	}
	if !strings.Contains(output.String(), "Usage: ssl_exporter [flags]") {
		t.Errorf("help output does not contain usage: %q", output.String())
	}
	if strings.Contains(output.String(), "panic") {
		t.Errorf("help output contains panic warning: %q", output.String())
	}
}

func TestParseCLIRejectsUnexpectedArguments(t *testing.T) {
	_, err := parseCLI([]string{"unexpected"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
		t.Fatalf("parseCLI() error = %v, want unexpected arguments error", err)
	}
}
