# ssl-exporter

SSL Certificate Exporter for Prometheus

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 2.5.1](https://img.shields.io/badge/AppVersion-2.5.1-informational?style=flat-square)

## Installation

```bash
helm repo add ssl-exporter https://piotrkochan.github.io/ssl_exporter
helm repo update
helm install ssl-exporter ssl-exporter/ssl-exporter
```

## Examples

### Basic auth

```yaml
webConfig:
  enabled: true
  data:
    basic_auth_users:
      admin: "$2y$10$hashedpassword"
```

### Basic auth with an existing Secret

To avoid storing passwords in Helm values, create a Secret separately
(e.g. via SealedSecrets or ExternalSecrets):

```yaml
apiVersion: v1
kind: Secret
metadata:
  name: my-web-config
type: Opaque
stringData:
  web-config.yaml: |
    basic_auth_users:
      admin: "$2y$10$hashedpassword"
```

Then reference it:

```yaml
webConfig:
  enabled: true
  existingSecret: my-web-config
```

### TLS with an existing Secret

```yaml
tls:
  enabled: true
  existingSecret: my-tls-secret
webConfig:
  enabled: true  # auto-generates web-config.yaml with tls_server_config
```

### TLS with cert-manager

```yaml
tls:
  enabled: true
  certManager:
    enabled: true
    issuerRef:
      name: letsencrypt-prod
      kind: ClusterIssuer
webConfig:
  enabled: true
```

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity rules |
| config.data | string | `"modules:\n  https:\n    prober: https\n  tcp:\n    prober: tcp\n  file:\n    prober: file\n  kubernetes:\n    prober: kubernetes\n"` | Exporter configuration in YAML |
| config.enabled | bool | `true` |  |
| config.existingConfigMap | string | `""` | Use an existing ConfigMap (config.data is ignored when set) |
| extraArgs | list | `[]` | Extra command-line arguments for ssl_exporter |
| extraEnv | list | `[]` | Extra environment variables |
| extraVolumeMounts | list | `[]` | Extra volume mounts for the container |
| extraVolumes | list | `[]` | Extra volumes for the pod |
| fullnameOverride | string | `""` | Override the full release name |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| image.repository | string | `"piotrkochan/ssl-exporter"` | Image repository |
| image.tag | string | `""` | Image tag (defaults to chart appVersion) |
| imagePullSecrets | list | `[]` | Image pull secrets |
| livenessProbe | object | `{"failureThreshold":3,"httpGet":{"path":"/","port":"http"},"initialDelaySeconds":5,"periodSeconds":10,"timeoutSeconds":5}` | Liveness probe configuration |
| nameOverride | string | `""` | Override the chart name |
| nodeSelector | object | `{}` | Node selector |
| podAnnotations | object | `{}` | Additional pod annotations |
| podLabels | object | `{}` | Additional pod labels |
| podSecurityContext | object | `{"fsGroup":1000}` | Pod security context |
| readinessProbe | object | `{"failureThreshold":3,"httpGet":{"path":"/","port":"http"},"initialDelaySeconds":5,"periodSeconds":10,"timeoutSeconds":5}` | Readiness probe configuration |
| replicaCount | int | `1` | Number of replicas |
| resources | object | `{}` | Resource requests and limits |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsGroup":1000,"runAsNonRoot":true,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"}}` | Container security context |
| service.port | int | `9219` | Service port |
| service.type | string | `"ClusterIP"` | Service type |
| serviceAccount.annotations | object | `{}` | Annotations for the service account |
| serviceAccount.automountServiceAccountToken | bool | `false` | Automount the service account token |
| serviceAccount.create | bool | `true` | Create a service account |
| serviceAccount.name | string | `""` | Service account name (generated if not set and create is true) |
| serviceMonitor.enabled | bool | `false` | Enable ServiceMonitor |
| serviceMonitor.interval | string | `"30s"` | Scrape interval |
| serviceMonitor.labels | object | `{}` | Additional labels for ServiceMonitor selection |
| serviceMonitor.metricRelabelings | list | `[]` | Metric relabeling rules |
| serviceMonitor.relabelings | list | `[]` | Target relabeling rules |
| serviceMonitor.scrapeTimeout | string | `"10s"` | Scrape timeout |
| tls.certManager.dnsNames | list | `[]` | DNS names for the certificate (defaults to service FQDN) |
| tls.certManager.duration | string | `"8760h"` | Certificate duration |
| tls.certManager.enabled | bool | `false` | Create a cert-manager Certificate resource to provision the TLS Secret |
| tls.certManager.issuerRef.kind | string | `"ClusterIssuer"` | Issuer kind (Issuer or ClusterIssuer) |
| tls.certManager.issuerRef.name | string | `""` | Issuer name |
| tls.certManager.renewBefore | string | `"720h"` | Renew before expiry |
| tls.enabled | bool | `false` | Enable TLS (mounts a TLS Secret into the container) |
| tls.existingSecret | string | `""` | Existing `kubernetes.io/tls` Secret name. If set, certManager section is ignored. |
| tls.mountPath | string | `"/etc/tls"` | Mount path for TLS cert/key inside the container |
| tolerations | list | `[]` | Tolerations |
| webConfig.data | object | `{}` | Inline web-config.yaml content. When `tls.enabled`, `tls_server_config` is auto-injected. Passwords in `basic_auth_users` must be bcrypt-hashed. |
| webConfig.enabled | bool | `false` |  |
| webConfig.existingSecret | string | `""` | Use an existing Secret containing a `web-config.yaml` key (chart will not create one) |

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| @skoef |  | <https://github.com/skoef> |
| @piotrkochan |  | <https://github.com/piotrkochan> |
