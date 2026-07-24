# Example Queries

Certificates that expire within 7 days:

```
ssl_cert_not_after - time() < 86400 * 7
```

Certificates from any prober (tcp, https, file, keystore, kubernetes,
kubeconfig, tls_cipher) that expire within 7 days:

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
