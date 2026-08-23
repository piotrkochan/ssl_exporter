package main

import (
	"bytes"
	"errors"
	"flag"
	"runtime"
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
	for _, prefix := range []string{"-", "--"} {
		t.Run(prefix, func(t *testing.T) {
			args := []string{
				prefix + "web.metrics-path=/custom-metrics",
				prefix + "web.probe-path=/custom-probe",
				prefix + "config.file=/etc/ssl-exporter.yaml",
				prefix + "web.listen-address=:9218",
				prefix + "web.listen-address=127.0.0.1:9219",
				prefix + "web.config.file=/etc/web-config.yaml",
				prefix + "log.level=debug",
				prefix + "log.format=json",
				prefix + "version",
			}
			if runtime.GOOS == "linux" {
				args = append(args, prefix+"web.systemd-socket")
			}

			config, err := parseCLI(args, &bytes.Buffer{})
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
			if runtime.GOOS == "linux" && !*config.toolkitFlags.WebSystemdSocket {
				t.Error("web systemd socket = false, want true")
			}
		})
	}
}

func TestParseCLIHelp(t *testing.T) {
	for _, option := range []string{"-h", "--h", "-help", "--help"} {
		t.Run(option, func(t *testing.T) {
			var output bytes.Buffer
			_, err := parseCLI([]string{option}, &output)
			if !errors.Is(err, flag.ErrHelp) {
				t.Fatalf("parseCLI() error = %v, want flag.ErrHelp", err)
			}
			if !strings.Contains(output.String(), "Usage: ssl_exporter [flags]") {
				t.Errorf("help output does not contain usage: %q", output.String())
			}
			if strings.Contains(output.String(), "panic") {
				t.Errorf("help output contains panic warning: %q", output.String())
			}
		})
	}
}

func TestParseCLIRejectsInvalidFlagValues(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "unknown flag", args: []string{"--unknown"}},
		{name: "invalid log format", args: []string{"--log.format=text"}},
		{name: "invalid log level", args: []string{"--log.level=trace"}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()

			if _, err := parseCLI(test.args, &bytes.Buffer{}); err == nil {
				t.Fatal("parseCLI() error = nil, want an error")
			}
		})
	}
}

func TestParseCLIRejectsUnexpectedArguments(t *testing.T) {
	_, err := parseCLI([]string{"unexpected"}, &bytes.Buffer{})
	if err == nil || !strings.Contains(err.Error(), "unexpected arguments") {
		t.Fatalf("parseCLI() error = %v, want unexpected arguments error", err)
	}
}
