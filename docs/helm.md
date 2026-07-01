# Helm

## Installation

```bash
helm repo add ssl-exporter https://piotrkochan.github.io/ssl_exporter
helm repo update
helm install ssl-exporter ssl-exporter/ssl-exporter
```

All configuration options are documented in
[`charts/ssl-exporter/values.yaml`](../charts/ssl-exporter/values.yaml).

The generated chart reference is available in
[`charts/ssl-exporter/README.md`](../charts/ssl-exporter/README.md).

## Examples

### ServiceMonitor

```yaml
serviceMonitor:
  enabled: true
  labels:
    release: prometheus
```

### Basic auth

```yaml
webConfig:
  enabled: true
  data:
    basic_auth_users:
      admin: "$2y$10$hashedpassword"
```

When `serviceMonitor.enabled=true`, configure Prometheus scrape credentials
separately:

```yaml
serviceMonitor:
  enabled: true
  basicAuth:
    username:
      name: scrape-auth
      key: username
    password:
      name: scrape-auth
      key: password
```

### Basic auth with an existing Secret

Use an existing Secret to avoid storing passwords in Helm values:

```yaml
webConfig:
  enabled: true
  secretName: my-web-config
```

The Secret must contain a `web-config.yaml` key.

### TLS with an existing Secret

```yaml
tls:
  enabled: true
  secretName: my-tls-secret
```

When scraping with ServiceMonitor and a custom CA or self-signed certificate,
set `serviceMonitor.tlsConfig` explicitly.

### TLS with cert-manager

```yaml
tls:
  enabled: true
  certManager:
    enabled: true
    issuerRef:
      name: letsencrypt-prod
      kind: ClusterIssuer
```

### Kubernetes Secrets RBAC

The regular install does not give ssl_exporter access to Kubernetes Secrets.
Enable this only when using the kubernetes prober to read TLS certificates from
Kubernetes Secrets:

```yaml
serviceAccount:
  automountServiceAccountToken: true
rbac:
  create: true
```
