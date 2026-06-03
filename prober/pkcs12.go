package prober

import (
	"crypto/x509"

	"software.sslmate.com/src/go-pkcs12"
)

// readPKCS12 reads certificates from a PKCS12 file, handling both truststores
// (CA certificates only) and keystores (a private key with its chain).
func readPKCS12(data []byte, password string) ([]*x509.Certificate, error) {
	if certs, err := pkcs12.DecodeTrustStore(data, password); err == nil {
		return certs, nil
	}

	_, cert, caCerts, err := pkcs12.DecodeChain(data, password)
	if err != nil {
		return nil, err
	}

	certs := make([]*x509.Certificate, 0, 1+len(caCerts))
	if cert != nil {
		certs = append(certs, cert)
	}
	certs = append(certs, caCerts...)
	return certs, nil
}
