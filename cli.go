package main

import (
	"flag"
	"fmt"
	"io"
	"runtime"
	"strings"

	"github.com/prometheus/common/promslog"
	"github.com/prometheus/exporter-toolkit/web"
)

const defaultWebListenAddress = ":9219"

type cliConfig struct {
	metricsPath    string
	probePath      string
	configFile     string
	showVersion    bool
	toolkitFlags   *web.FlagConfig
	promslogConfig *promslog.Config
}

type stringSliceFlag struct {
	values []string
	isSet  bool
}

func (f *stringSliceFlag) String() string {
	return strings.Join(f.values, ",")
}

func (f *stringSliceFlag) Set(value string) error {
	if !f.isSet {
		f.values = []string{}
		f.isSet = true
	}
	f.values = append(f.values, value)
	return nil
}

func parseCLI(args []string, output io.Writer) (*cliConfig, error) {
	flags := flag.NewFlagSet("ssl_exporter", flag.ContinueOnError)
	flags.SetOutput(output)
	flags.Usage = func() {
		fmt.Fprintf(output, "Usage: %s [flags]\n\nFlags:\n", flags.Name())
		flags.PrintDefaults()
	}

	config := &cliConfig{}
	flags.StringVar(&config.metricsPath, "web.metrics-path", "/metrics", "Path under which to expose metrics")
	flags.StringVar(&config.probePath, "web.probe-path", "/probe", "Path under which to expose the probe endpoint")
	flags.StringVar(&config.configFile, "config.file", "", "SSL exporter configuration file")
	flags.BoolVar(&config.showVersion, "version", false, "Show application version")

	showHelp := false
	flags.BoolVar(&showHelp, "h", false, "Show help")
	flags.BoolVar(&showHelp, "help", false, "Show help")

	listenAddresses := &stringSliceFlag{values: []string{defaultWebListenAddress}}
	flags.Var(
		listenAddresses,
		"web.listen-address",
		"Addresses on which to expose metrics and web interface. Repeatable for multiple addresses.",
	)
	webSystemdSocket := false
	if runtime.GOOS == "linux" {
		flags.BoolVar(
			&webSystemdSocket,
			"web.systemd-socket",
			false,
			"Use systemd socket activation listeners instead of port listeners.",
		)
	}
	webConfigFile := ""
	flags.StringVar(
		&webConfigFile,
		"web.config.file",
		"",
		"Path to configuration file that can enable TLS or authentication.",
	)

	logLevel := promslog.NewLevel()
	logFormat := promslog.NewFormat()
	_ = logFormat.Set("logfmt")
	flags.Func(
		"log.level",
		"Only log messages with the given severity or above. One of: "+strings.Join(promslog.LevelFlagOptions, ", ")+" (default info)",
		logLevel.Set,
	)
	flags.Func(
		"log.format",
		"Output format of log messages. One of: "+strings.Join(promslog.FormatFlagOptions, ", ")+" (default logfmt)",
		logFormat.Set,
	)

	if err := flags.Parse(args); err != nil {
		return nil, err
	}
	if showHelp {
		flags.Usage()
		return nil, flag.ErrHelp
	}
	if flags.NArg() != 0 {
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(flags.Args(), " "))
	}

	config.toolkitFlags = &web.FlagConfig{
		WebListenAddresses: &listenAddresses.values,
		WebSystemdSocket:   &webSystemdSocket,
		WebConfigFile:      &webConfigFile,
	}
	config.promslogConfig = &promslog.Config{
		Level:  logLevel,
		Format: logFormat,
	}
	return config, nil
}
