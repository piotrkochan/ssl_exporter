# ssl-exporter

SSL Certificate Exporter for Prometheus

![Version: 0.1.0](https://img.shields.io/badge/Version-0.1.0-informational?style=flat-square) ![Type: application](https://img.shields.io/badge/Type-application-informational?style=flat-square) ![AppVersion: 2.6.1](https://img.shields.io/badge/AppVersion-2.6.1-informational?style=flat-square)

## Installation

```bash
helm repo add ssl-exporter https://piotrkochan.github.io/ssl_exporter
helm repo update
helm install ssl-exporter ssl-exporter/ssl-exporter
```

Or install static manifests directly:

```bash
kubectl apply -f https://raw.githubusercontent.com/piotrkochan/ssl_exporter/master/deploy/manifests/ssl-exporter.yaml
```

Use the cluster-wide RBAC variant only when ssl_exporter should read TLS certificates from Kubernetes Secrets:

```bash
kubectl apply -f https://raw.githubusercontent.com/piotrkochan/ssl_exporter/master/deploy/manifests/ssl-exporter-kubernetes-secrets.yaml
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
  secretName: my-web-config
```

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

### Kubernetes prober RBAC

The kubernetes prober needs cluster-wide permission to list TLS Secrets. Enable
RBAC only when this prober is used with in-cluster authentication:

```yaml
serviceAccount:
  automountServiceAccountToken: true
rbac:
  create: true
```

## Values

| Key | Type | Default | Description |
|-----|------|---------|-------------|
| affinity | object | `{}` | Affinity rules |
| commonLabels | object | `{}` | Labels added to all resources |
| config.data | string | `"modules:\n  https:\n    prober: https\n  tcp:\n    prober: tcp\n  file:\n    prober: file\n  kubernetes:\n    prober: kubernetes\n"` | Exporter configuration in YAML |
| config.enabled | bool | `true` |  |
| config.existingConfigMap | string | `""` | Use an existing ConfigMap (config.data is ignored when set) |
| deploymentAnnotations | object | `{}` | Additional Deployment annotations |
| dnsConfig | object | `{}` | Pod DNS config |
| dnsPolicy | string | `""` | Pod DNS policy |
| extraArgs | list | `[]` | Extra command-line arguments for ssl_exporter |
| extraEnv | list | `[]` | Extra environment variables |
| extraEnvFrom | list | `[]` | Extra environment variables from ConfigMaps or Secrets |
| extraVolumeMounts | list | `[]` | Extra volume mounts for the container |
| extraVolumes | list | `[]` | Extra volumes for the pod |
| fullnameOverride | string | `""` | Override the full release name |
| global.imageRegistry | string | `""` | Global image registry override |
| image.digest | string | `""` | Image digest. If set, it takes precedence over tag |
| image.pullPolicy | string | `"IfNotPresent"` | Image pull policy |
| image.registry | string | `"ghcr.io"` | Image registry |
| image.repository | string | `"piotrkochan/ssl_exporter"` | Image repository |
| image.tag | string | `""` | Image tag (defaults to chart appVersion) |
| imagePullSecrets | list | `[]` | Image pull secrets |
| livenessProbe | object | `{"failureThreshold":3,"httpGet":{"path":"/","port":"http"},"initialDelaySeconds":5,"periodSeconds":10,"timeoutSeconds":5}` | Liveness probe configuration |
| nameOverride | string | `""` | Override the chart name |
| namespaceOverride | string | `""` | Override the namespace for namespaced resources |
| networkPolicy.allowMonitoringNamespace | bool | `false` | Limit ingress to the monitoring namespace |
| networkPolicy.enabled | bool | `false` | Create NetworkPolicy for ssl_exporter pods |
| networkPolicy.monitoringNamespaceName | string | `"monitoring"` | Monitoring namespace name used when allowMonitoringNamespace=true |
| nodeSelector | object | `{}` | Node selector |
| podAnnotations | object | `{}` | Additional pod annotations |
| podDisruptionBudget | object | `{}` | PodDisruptionBudget spec. Set maxUnavailable or minAvailable to create it. |
| podLabels | object | `{}` | Additional pod labels |
| podSecurityContext | object | `{"fsGroup":1000}` | Pod security context |
| priorityClassName | string | `""` | Priority class name |
| rbac.create | bool | `false` | Create ClusterRole and ClusterRoleBinding for the kubernetes prober. Also set serviceAccount.automountServiceAccountToken=true when using in-cluster auth. |
| readinessProbe | object | `{"failureThreshold":3,"httpGet":{"path":"/","port":"http"},"initialDelaySeconds":5,"periodSeconds":10,"timeoutSeconds":5}` | Readiness probe configuration |
| replicaCount | int | `1` | Number of replicas |
| resources | object | `{}` | Resource requests and limits |
| revisionHistoryLimit | int | `10` | Number of old ReplicaSets to retain |
| securityContext | object | `{"allowPrivilegeEscalation":false,"capabilities":{"drop":["ALL"]},"readOnlyRootFilesystem":true,"runAsGroup":1000,"runAsNonRoot":true,"runAsUser":1000,"seccompProfile":{"type":"RuntimeDefault"}}` | Container security context |
| service.annotations | object | `{}` | Additional Service annotations |
| service.ipDualStack.enabled | bool | `false` | Enable dual-stack Service fields |
| service.ipDualStack.ipFamilies | list | `["IPv6","IPv4"]` | Service IP families |
| service.ipDualStack.ipFamilyPolicy | string | `"PreferDualStack"` | Service IP family policy |
| service.labels | object | `{}` | Additional Service labels |
| service.port | int | `9219` | Service port |
| service.type | string | `"ClusterIP"` | Service type |
| serviceAccount.annotations | object | `{}` | Annotations for the service account |
| serviceAccount.automountServiceAccountToken | bool | `false` | Automount the service account token |
| serviceAccount.create | bool | `true` | Create a service account |
| serviceAccount.name | string | `""` | Service account name (generated if not set and create is true) |
| serviceMonitor.annotations | object | `{}` | ServiceMonitor annotations |
| serviceMonitor.basicAuth | object | `{}` | Basic auth config for scraping /metrics when webConfig enables basic_auth_users |
| serviceMonitor.enabled | bool | `false` | Enable ServiceMonitor |
| serviceMonitor.honorLabels | bool | `false` | Whether Prometheus should honor labels from scraped metrics |
| serviceMonitor.honorTimestamps | bool | `true` | Whether Prometheus should honor timestamps from scraped metrics |
| serviceMonitor.interval | string | `"30s"` | Scrape interval |
| serviceMonitor.labelLimit | int | `0` | Per-scrape label limit. 0 means no limit. |
| serviceMonitor.labelNameLengthLimit | int | `0` | Per-scrape label name length limit. 0 means no limit. |
| serviceMonitor.labelValueLengthLimit | int | `0` | Per-scrape label value length limit. 0 means no limit. |
| serviceMonitor.labels | object | `{}` | Additional labels for ServiceMonitor selection |
| serviceMonitor.metricRelabelings | list | `[]` | Metric relabeling rules |
| serviceMonitor.podTargetLabels | list | `[]` | Pod labels copied from Pod to Prometheus target labels |
| serviceMonitor.proxyUrl | string | `""` | Optional proxy URL for scraping |
| serviceMonitor.relabelings | list | `[]` | Target relabeling rules |
| serviceMonitor.sampleLimit | int | `0` | Per-scrape sample limit. 0 means no limit. |
| serviceMonitor.scrapeTimeout | string | `"10s"` | Scrape timeout |
| serviceMonitor.targetLabels | list | `[]` | Target labels copied from Service to Prometheus target labels |
| serviceMonitor.targetLimit | int | `0` | Per-scrape target limit. 0 means no limit. |
| serviceMonitor.tlsConfig | object | `{}` | TLS config for scraping the exporter when tls.enabled=true |
| strategy | object | `{"rollingUpdate":{"maxSurge":1,"maxUnavailable":0},"type":"RollingUpdate"}` | Deployment update strategy |
| tls.certManager.dnsNames | list | `[]` | DNS names for the certificate (defaults to service FQDN) |
| tls.certManager.duration | string | `"8760h"` | Certificate duration |
| tls.certManager.enabled | bool | `false` | Create a cert-manager Certificate resource to provision the TLS Secret |
| tls.certManager.issuerRef.kind | string | `"ClusterIssuer"` | Issuer kind (Issuer or ClusterIssuer) |
| tls.certManager.issuerRef.name | string | `""` | Issuer name |
| tls.certManager.renewBefore | string | `"720h"` | Renew before expiry |
| tls.enabled | bool | `false` | Enable TLS for the exporter's own HTTP endpoints. Requires secretName or certManager.enabled=true. |
| tls.mountPath | string | `"/etc/tls"` | Mount path for TLS cert/key inside the container |
| tls.secretName | string | `""` | TLS Secret name to mount. With cert-manager enabled, this is the Secret cert-manager writes to. Defaults to a generated name. |
| tolerations | list | `[]` | Tolerations |
| topologySpreadConstraints | list | `[]` | Topology spread constraints |
| webConfig.data | object | `{}` | Inline web-config.yaml content. When `tls.enabled`, `tls_server_config` is auto-injected. Passwords in `basic_auth_users` must be bcrypt-hashed. |
| webConfig.enabled | bool | `false` |  |
| webConfig.secretName | string | `""` | Existing Secret name containing a `web-config.yaml` key. When set, chart will not create the web config Secret. |

## Maintainers

| Name | Email | Url |
| ---- | ------ | --- |
| skoef |  | <https://github.com/skoef> |
| piotrkochan |  | <https://github.com/piotrkochan> |
