package main

import (
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Run the actual CLI in a subprocess to exercise flag parsing and exit codes.
func TestConfigCheckProcess(t *testing.T) {
	if os.Getenv("SSL_EXPORTER_CONFIG_CHECK_TEST") != "1" {
		return
	}
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"ssl_exporter"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	t.Fatal("missing CLI arguments")
}

func TestConfigCheck(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()

	valid := "default_module: local\nmodules:\n  local:\n    prober: file\n    target: /does/not/exist.pem\n"
	tests := []struct {
		name, config, webConfig, want string
		missingFile, defaults         bool
	}{
		{name: "defaults", defaults: true},
		{name: "valid without probing or listening", config: valid},
		{name: "valid web config", config: valid, webConfig: "http_server_config:\n  http2: false\n"},
		{name: "missing file", missingFile: true, want: "Error loading config"},
		{name: "invalid yaml", config: "modules: [", want: "Error loading config"},
		{name: "unknown field", config: "moduels: {}", want: "Error loading config"},
		{name: "empty file", want: "Error loading config"},
		{name: "null config", config: "null", want: "configuration must not be null"},
		{name: "multiple documents", config: valid + "---\nmodules: {}\n", want: "single YAML document"},
		{name: "unknown prober", config: "modules:\n  test:\n    prober: typo\n", want: "unknown prober"},
		{name: "unknown default", config: "default_module: missing\nmodules: {}", want: "unknown default_module"},
		{name: "invalid web config", config: valid, webConfig: "unknown_setting: true\n", want: "Error validating web config"},
		{name: "invalid web password", config: valid, webConfig: "basic_auth_users:\n  user: not-a-bcrypt-hash\n", want: "Error validating web config"},
		{name: "missing web certificate", config: valid, webConfig: "tls_server_config:\n  cert_file: missing.pem\n  key_file: missing.key\n", want: "Error validating web config"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			args := []string{"-test.run=^TestConfigCheckProcess$", "--", "--config.check", "--web.listen-address=" + listener.Addr().String()}
			if !tt.defaults {
				path := filepath.Join(dir, "config.yml")
				if !tt.missingFile {
					if err := os.WriteFile(path, []byte(tt.config), 0600); err != nil {
						t.Fatal(err)
					}
				}
				args = append(args, "--config.file="+path)
			}
			if tt.webConfig != "" {
				path := filepath.Join(dir, "web.yml")
				if err := os.WriteFile(path, []byte(tt.webConfig), 0600); err != nil {
					t.Fatal(err)
				}
				args = append(args, "--web.config.file="+path)
			}
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, os.Args[0], args...)
			cmd.Env = append(os.Environ(), "SSL_EXPORTER_CONFIG_CHECK_TEST=1")
			output, err := cmd.CombinedOutput()
			if ctx.Err() != nil {
				t.Fatalf("check did not exit: %s", output)
			}
			if tt.want == "" {
				if err != nil || !strings.Contains(string(output), "Configuration is valid") {
					t.Fatalf("expected successful check, got %v: %s", err, output)
				}
			} else if exit, ok := err.(*exec.ExitError); !ok || exit.ExitCode() != 1 || !strings.Contains(string(output), tt.want) {
				t.Fatalf("expected exit 1 and %q, got %v: %s", tt.want, err, output)
			}
		})
	}
}
