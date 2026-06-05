# SSL Certificate Exporter

[![test](https://github.com/piotrkochan/ssl_exporter/actions/workflows/test.yaml/badge.svg)](https://github.com/piotrkochan/ssl_exporter/actions/workflows/test.yaml)
[![E2E Tests](https://github.com/piotrkochan/ssl_exporter/actions/workflows/e2e.yml/badge.svg)](https://github.com/piotrkochan/ssl_exporter/actions/workflows/e2e.yml)
[![CodeQL](https://github.com/piotrkochan/ssl_exporter/actions/workflows/codeql.yml/badge.svg)](https://github.com/piotrkochan/ssl_exporter/actions/workflows/codeql.yml)
[![codecov](https://codecov.io/gh/piotrkochan/ssl_exporter/branch/master/graph/badge.svg)](https://codecov.io/gh/piotrkochan/ssl_exporter)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/piotrkochan/ssl_exporter/badge)](https://scorecard.dev/viewer/?uri=github.com/piotrkochan/ssl_exporter)
[![Go Report Card](https://goreportcard.com/badge/github.com/piotrkochan/ssl_exporter/v2)](https://goreportcard.com/report/github.com/piotrkochan/ssl_exporter/v2)
[![Latest Release](https://img.shields.io/github/v/release/piotrkochan/ssl_exporter?logo=github)](https://github.com/piotrkochan/ssl_exporter/releases/latest)
[![Docker Image](https://img.shields.io/badge/ghcr.io-ssl__exporter-blue?logo=docker)](https://github.com/piotrkochan/ssl_exporter/pkgs/container/ssl_exporter)
[![License](https://img.shields.io/github/license/piotrkochan/ssl_exporter)](LICENSE)

Exports metrics for certificates collected from various sources:
- [TCP probes](#tcp)
- [HTTPS probes](#https)
- [PEM files](#file)
- [Remote PEM files](#http_file)
- [Java KeyStore / PKCS12 files](#keystore)
- [Kubernetes secrets](#kubernetes)
- [Kubeconfig files](#kubeconfig)

The metrics are labelled with fields from the certificate, which allows for
informational dashboards and flexible alert routing.

## Building

    make
    ./ssl_exporter <flags>

Similarly to the blackbox_exporter, visiting
[http://localhost:9219/probe?target=example.com:443](http://localhost:9219/probe?target=example.com:443)
will return certificate metrics for example.com. The `ssl_probe_success`
metric indicates if the probe has been successful.

### Docker

    docker run -p 9219:9219 ghcr.io/piotrkochan/ssl_exporter:latest <flags>

### Release process

- Create a release in Github with a semver tag and GH actions will:
  - Add a changelog
  - Upload binaries
  - Build and push a Docker image

## Usage

```
usage: ssl_exporter [<flags>]

Flags:
  -h, --help                     Show context-sensitive help (also try --help-long and
                                 --help-man).
      --web.metrics-path="/metrics"
                                 Path under which to expose metrics
      --web.probe-path="/probe"  Path under which to expose the probe endpoint
      --config.file=""           SSL exporter configuration file
      --web.listen-address=:9219 ...
                                 Addresses on which to expose metrics and web interface.
                                 Repeatable for multiple addresses.
      --web.config.file=""       Path to configuration file that can enable TLS or
                                 authentication. See:
                                 https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md
      --log.level=info           Only log messages with the given severity or above.
                                 One of: [debug, info, warn, error]
      --log.format=logfmt        Output format of log messages. One of: [logfmt, json]
      --version                  Show application version.
```

### TLS and basic authentication

The SSL Exporter supports TLS and basic authentication. This enables better
control of the various HTTP endpoints.

To use TLS and/or basic authentication, you need to pass a configuration file
using the `--web.config.file` parameter. The format of the file is described
[in the exporter-toolkit repository](https://github.com/prometheus/exporter-toolkit/blob/master/docs/web-configuration.md).

Note that the TLS and basic authentication settings affect all HTTP endpoints:
/metrics for scraping, /probe for probing, and the web UI.

## Metrics

| Metric                         | Meaning                                                                                                          | Labels                                                                      | Probers    |
| ------------------------------ | ---------------------------------------------------------------------------------------------------------------- | --------------------------------------------------------------------------- | ---------- |
| ssl_cert_not_after             | The date after which a peer certificate expires. Expressed as a Unix Epoch Time.                                 | serial_no, issuer_cn, cn, dnsnames, ips, emails, ou                         | tcp, https |
| ssl_cert_not_before            | The date before which a peer certificate is not valid. Expressed as a Unix Epoch Time.                           | serial_no, issuer_cn, cn, dnsnames, ips, emails, ou                         | tcp, https |
| ssl_file_cert_not_after        | The date after which a certificate found by the file prober expires. Expressed as a Unix Epoch Time.             | file, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou                   | file       |
| ssl_file_cert_not_before       | The date before which a certificate found by the file prober is not valid. Expressed as a Unix Epoch Time.       | file, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou                   | file       |
| ssl_keystore_cert_not_after    | The date after which a certificate found by the keystore prober expires. Expressed as a Unix Epoch Time.         | file, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou                   | keystore   |
| ssl_keystore_cert_not_before   | The date before which a certificate found by the keystore prober is not valid. Expressed as a Unix Epoch Time.   | file, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou                   | keystore   |
| ssl_kubernetes_cert_not_after  | The date after which a certificate found by the kubernetes prober expires. Expressed as a Unix Epoch Time.       | namespace, secret, key, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou | kubernetes |
| ssl_kubernetes_cert_not_before | The date before which a certificate found by the kubernetes prober is not valid. Expressed as a Unix Epoch Time. | namespace, secret, key, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou | kubernetes |
| ssl_kubeconfig_cert_not_after  | The date after which a certificate found by the kubeconfig prober expires. Expressed as a Unix Epoch Time.       | kubeconfig, name, type, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou | kubeconfig |
| ssl_kubeconfig_cert_not_before | The date before which a certificate found by the kubeconfig prober is not valid. Expressed as a Unix Epoch Time. | kubeconfig, name, type, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou | kubeconfig |
| ssl_ocsp_response_next_update  | The nextUpdate value in the OCSP response. Expressed as a Unix Epoch Time                                        |                                                                             | tcp, https |
| ssl_ocsp_response_produced_at  | The producedAt value in the OCSP response. Expressed as a Unix Epoch Time                                        |                                                                             | tcp, https |
| ssl_ocsp_response_revoked_at   | The revocationTime value in the OCSP response. Expressed as a Unix Epoch Time                                    |                                                                             | tcp, https |
| ssl_ocsp_response_status       | The status in the OCSP response. 0=Good 1=Revoked 2=Unknown                                                      |                                                                             | tcp, https |
| ssl_ocsp_response_stapled      | Does the connection state contain a stapled OCSP response? Boolean.                                              |                                                                             | tcp, https |
| ssl_ocsp_response_this_update  | The thisUpdate value in the OCSP response. Expressed as a Unix Epoch Time                                        |                                                                             | tcp, https |
| ssl_probe_duration_seconds     | Returns how long the probe took to complete in seconds.                                                          |                                                                             | all        |
| ssl_probe_success              | Was the probe successful? Boolean.                                                                               |                                                                             | all        |
| ssl_prober                     | The prober used by the exporter to connect to the target. Boolean.                                               | prober                                                                      | all        |
| ssl_tls_version_info           | The TLS version used. Always 1.                                                                                  | version                                                                     | tcp, https |
| ssl_verified_cert_not_after    | The date after which a certificate in the verified chain expires. Expressed as a Unix Epoch Time.                | chain_no, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou               | tcp, https |
| ssl_verified_cert_not_before   | The date before which a certificate in the verified chain is not valid. Expressed as a Unix Epoch Time.          | chain_no, serial_no, issuer_cn, cn, dnsnames, ips, emails, ou               | tcp, https |

## Configuration

### TCP

Just like with the blackbox_exporter, you should pass the targets to a single
instance of the exporter in a scrape config with a clever bit of relabelling.
This allows you to leverage service discovery and keeps configuration
centralised to your Prometheus config.

```yml
scrape_configs:
  - job_name: "ssl"
    metrics_path: /probe
    static_configs:
      - targets:
          - example.com:443
          - prometheus.io:443
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9219 # SSL exporter.
```

### HTTPS

By default the exporter will make a TCP connection to the target. This will be
suitable for most cases but if you want to take advantage of http proxying you
can use a HTTPS client by setting the `https` module parameter:

```yml
scrape_configs:
  - job_name: "ssl"
    metrics_path: /probe
    params:
      module: ["https"] # <-----
    static_configs:
      - targets:
          - example.com:443
          - prometheus.io:443
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9219
```

This will use proxy servers discovered by the environment variables `HTTP_PROXY`,
`HTTPS_PROXY` and `ALL_PROXY`. Or, you can set the `https.proxy_url` option in the module
configuration.

The latter takes precedence.

#### server_name

The `server_name` query parameter sets the TLS server name (SNI) for a single
probe, which is useful when the target is an IP address:

```
curl "localhost:9219/probe?module=https&target=1.2.3.4:443&server_name=example.com"
```

### File

The `file` prober exports `ssl_file_cert_not_after` and
`ssl_file_cert_not_before` for PEM encoded certificates found in local files.

Files local to the exporter can be scraped by providing them as the target
parameter:

```
curl "localhost:9219/probe?module=file&target=/etc/ssl/cert.pem"
```

The target parameter supports globbing (as provided by the
[doublestar](https://github.com/bmatcuk/doublestar) package),
which allows you to capture multiple files at once:

```
curl "localhost:9219/probe?module=file&target=/etc/ssl/**/*.pem"
```

One specific usage of this prober could be to run the exporter as a DaemonSet in
Kubernetes and then scrape each instance to check the expiry of certificates on
each node:

```yml
scrape_configs:
  - job_name: "ssl-kubernetes-file"
    metrics_path: /probe
    params:
      module: ["file"]
      target: ["/etc/kubernetes/**/*.crt"]
    kubernetes_sd_configs:
      - role: node
    relabel_configs:
      - source_labels: [__address__]
        regex: ^(.*):(.*)$
        target_label: __address__
        replacement: ${1}:9219
```

### HTTP File

The `http_file` prober exports `ssl_cert_not_after` and
`ssl_cert_not_before` for PEM encoded certificates found at the
specified URL.

```
curl "localhost:9219/probe?module=http_file&target=https://www.paypalobjects.com/marketing/web/logos/paypal_com.pem"
```

Here's a sample Prometheus configuration:

```yml
scrape_configs:
  - job_name: 'ssl-http-files'
    metrics_path: /probe
    params:
      module: ["http_file"]
    static_configs:
      - targets:
        - 'https://www.paypalobjects.com/marketing/web/logos/paypal_com.pem'
        - 'https://d3frv9g52qce38.cloudfront.net/amazondefault/amazon_web_services_inc_2024.pem'
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9219
```

For proxying to the target resource, this prober will use proxy servers
discovered in the environment variables `HTTP_PROXY`, `HTTPS_PROXY` and
`ALL_PROXY`. Or, you can set the `http_file.proxy_url` option in the module
configuration.

The latter takes precedence.

### Keystore

The `keystore` prober exports `ssl_keystore_cert_not_after` and `ssl_keystore_cert_not_before`
for certificates found in local keystore files. Both **Java KeyStore (JKS)** and
**PKCS12** files are supported - the format is detected automatically from the
file contents. For PKCS12 this covers both truststores (CA certificates) and
keystores (a private key with its certificate chain). Note that the default
`cacerts` shipped with JDK 9+ is PKCS12.

Keystore files local to the exporter can be scraped by providing them as the
target parameter:

```
curl "localhost:9219/probe?module=keystore&target=/usr/java/jdkXXX/jre/lib/security/cacerts"
```

The target parameter supports globbing (as provided by the
[doublestar](https://github.com/bmatcuk/doublestar) package), which allows you
to capture multiple files at once:

```
curl "localhost:9219/probe?module=keystore&target=/usr/java/jdkXXX/jre/lib/security/*.keystore"
```

A password is **required** (there is no default); for the standard `cacerts`
truststore it is `changeit`. Configure it per module, inline or preferably
from a file. The examples above assume such a module:

```yml
modules:
  keystore:
    prober: keystore
    keystore:
      password: changeit
      # password_file: /etc/ssl_exporter/keystore_password
```

A keystore (such as `cacerts`) can hold many certificates; each one is exported
as its own time series, so expect high cardinality for large truststores.

One specific usage of this prober is to run the exporter as a Systemd service on
a host that runs a JVM and scrape its keystores to check certificate expiry on
each node:

```yml
scrape_configs:
  - job_name: "java-cacerts-keystore"
    metrics_path: /probe
    params:
      module: ["keystore"]
      target: ["/usr/java/jdkXXX/jre/lib/security/cacerts"]
    relabel_configs:
      - source_labels: [__address__]
        target_label: __param_target
      - source_labels: [__param_target]
        target_label: instance
      - target_label: __address__
        replacement: 127.0.0.1:9219 # SSL exporter.
```

### Kubernetes

The `kubernetes` prober exports `ssl_kubernetes_cert_not_after` and
`ssl_kubernetes_cert_not_before` for PEM encoded certificates found in secrets
of type `kubernetes.io/tls`.

Provide the namespace and name of the secret in the form `<namespace>/<name>` as
the target:

```
curl "localhost:9219/probe?module=kubernetes&target=kube-system/secret-name"
```

Both the namespace and name portions of the target support glob matching (as provided by the
[doublestar](https://github.com/bmatcuk/doublestar) package):

```
curl "localhost:9219/probe?module=kubernetes&target=kube-system/*"

```

```
curl "localhost:9219/probe?module=kubernetes&target=*/*"

```

The exporter retrieves credentials and context configuration from the following
sources in the following order:

- The `kubeconfig` path in the module configuration
- The `$KUBECONFIG` environment variable
- The default configuration file (`$HOME/.kube/config`)
- The in-cluster environment, if running in a pod

```yml
- job_name: "ssl-kubernetes"
  metrics_path: /probe
  params:
    module: ["kubernetes"]
  static_configs:
   - targets:
      - "test-namespace/nginx-cert"
  relabel_configs:
   - source_labels: [ __address__ ]
     target_label: __param_target
   - source_labels: [ __param_target ]
     target_label: instance
   - target_label: __address__
     replacement: 127.0.0.1:9219
```

### Kubeconfig

The `kubeconfig` prober exports `ssl_kubeconfig_cert_not_after` and
`ssl_kubeconfig_cert_not_before` for PEM encoded certificates found in the specified kubeconfig file.

Kubeconfigs local to the exporter can be scraped by providing them as the target
parameter:

```
curl "localhost:9219/probe?module=kubeconfig&target=/etc/kubernetes/admin.conf"
```

One specific usage of this prober could be to run the exporter as a DaemonSet in
Kubernetes and then scrape each instance to check the expiry of certificates on
each node:

```yml
scrape_configs:
  - job_name: "ssl-kubernetes-kubeconfig"
    metrics_path: /probe
    params:
      module: ["kubeconfig"]
      target: ["/etc/kubernetes/admin.conf"]
    kubernetes_sd_configs:
      - role: node
    relabel_configs:
      - source_labels: [__address__]
        regex: ^(.*):(.*)$
        target_label: __address__
        replacement: ${1}:9219
```

## Configuration file

You can provide further module configuration by providing the path to a
configuration file with `--config.file`. The file is written in yaml format,
defined by the schema below.

```
# The default module to use. If omitted, then the module must be provided by the
# 'module' query parameter
default_module: <string>

# Module configuration
modules: [<module>]
```

### \<module\>

```
# The type of probe (https, tcp, file, http_file, keystore, kubernetes, kubeconfig)
prober: <prober_string>

# The probe target. If set, then the 'target' query parameter is ignored.
# If omitted, then the 'target' query parameter is required.
target: <string>

# How long the probe will wait before giving up.
[ timeout: <duration> ]

# Configuration for TLS
[ tls_config: <tls_config> ]

# The specific probe configuration
[ https: <https_probe> ]
[ tcp: <tcp_probe> ]
[ kubernetes: <kubernetes_probe> ]
[ http_file: <http_file_probe> ]
[ keystore: <keystore_probe> ]
```

### <tls_config>

```
# Disable target certificate validation.
[ insecure_skip_verify: <boolean> | default = false ]

# Configure TLS renegotiation support.
# Valid options: never, once, freely
[ renegotiation: <string> | default = never ]

# The CA cert to use for the targets.
[ ca_file: <filename> ]

# The client cert file for the targets.
[ cert_file: <filename> ]

# The client key file for the targets.
[ key_file: <filename> ]

# Used to verify the hostname for the targets.
[ server_name: <string> ]
```

### <https_probe>

```
# HTTP proxy server to use to connect to the targets.
[ proxy_url: <string> ]
```

### <tcp_probe>

```
# Use the STARTTLS command before starting TLS for those protocols that support it (smtp, ftp, imap, pop3, postgres)
[ starttls: <string> ]
```

### <kubernetes_probe>

```
# The path of a kubeconfig file to configure the probe
[ kubeconfig: <string> ]
```

### <http_file_probe>

```
# HTTP proxy server to use to connect to the targets.
[ proxy_url: <string> ]
```

### <keystore_probe>

```
# The password protecting the keystore (JKS or PKCS12).
[ password: <secret> ]

# Path to a file containing the keystore password. Takes precedence over
# 'password' when set.
[ password_file: <filename> ]
```

## Examples

The [`examples/`](examples) directory contains ready-to-use files:

- [`ssl_exporter.yaml`](examples/ssl_exporter.yaml) - exporter module configuration covering every prober.
- [`example.prometheus.yml`](examples/example.prometheus.yml) - Prometheus scrape configuration.
- [`ssl_exporter.rules.yml`](examples/ssl_exporter.rules.yml) - Prometheus alerting rules (probe failures, certificate expiry and revocation, deprecated TLS).

## Example Queries

Certificates that expire within 7 days:

```
ssl_cert_not_after - time() < 86400 * 7
```

Certificates from any prober (tcp, https, file, keystore, kubernetes,
kubeconfig) that expire within 7 days:

```
{__name__=~"ssl_.*cert_not_after"} - time() < 86400 * 7
```

Wildcard certificates that are expiring:

```
ssl_cert_not_after{cn=~"\*.*"} - time() < 86400 * 7
```

Certificates that expire within 7 days in the verified chain that expires
latest:

```
ssl_verified_cert_not_after{chain_no="0"} - time() < 86400 * 7
```

Number of certificates presented by the server:

```
count(ssl_cert_not_after) by (instance)
```

Identify failed probes:

```
ssl_probe_success == 0
```

## Peer Certificates vs Verified Chain Certificates

Metrics are exported for the `NotAfter` and `NotBefore` fields for peer
certificates as well as for the verified chain that is
constructed by the client.

The former only includes the certificates that are served explicitly by the
target, while the latter can contain multiple chains of trust that are
constructed from root certificates held by the client to the target's server
certificate.

This has important implications when monitoring certificate expiry.

For instance, it may be the case that `ssl_cert_not_after` reports that the root
certificate served by the target is expiring soon even though clients can form
another, much longer lived, chain of trust using another valid root certificate
held locally. In this case, you may want to use `ssl_verified_cert_not_after` to
alert on expiry instead, as this will contain the chain that the client actually
constructs:

```
ssl_verified_cert_not_after{chain_no="0"} - time() < 86400 * 7
```

Each chain is numbered by the exporter in reverse order of expiry, so that
`chain_no="0"` is the chain that will expire the latest. Therefore the query
above will only alert when the chain of trust between the exporter and the
target is truly nearing expiry.

It's very important to note that a query of this kind only represents the chain
of trust between the exporter and the target. Genuine clients may hold different
root certs than the exporter and therefore have different verified chains of
trust.

## Grafana

You can find a simple dashboard [here](contrib/grafana/dashboard.json) that tracks
certificate expiration dates and target connection errors.
