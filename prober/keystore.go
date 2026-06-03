package prober

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/binary"
	"fmt"
	"log/slog"

	"github.com/bmatcuk/doublestar/v2"
	"github.com/pavlo-v-chernykh/keystore-go/v4"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/piotrkochan/ssl_exporter/v2/config"
)

// magicJKS is the 4-byte magic number at the start of every Java KeyStore file.
const magicJKS = 0xFEEDFEED

// asn1Sequence is the DER tag (SEQUENCE) that begins a PKCS12 file.
const asn1Sequence = 0x30

// ProbeKeystore collects certificate metrics from local Java KeyStore (JKS) and
// PKCS12 files.
func ProbeKeystore(ctx context.Context, logger *slog.Logger, target string, module config.Module, registry *prometheus.Registry) error {
	errCh := make(chan error, 1)

	password, err := module.Keystore.GetPassword()
	if err != nil {
		return err
	}

	go func() {
		files, err := doublestar.Glob(target)
		if err != nil {
			errCh <- err
			return
		}

		if len(files) == 0 {
			errCh <- fmt.Errorf("No keystore files found")
		} else {
			errCh <- collectKeystoreMetrics(logger, files, registry, password)
		}
	}()

	select {
	case <-ctx.Done():
		return fmt.Errorf("context timeout, ran out of time")
	case err := <-errCh:
		return err
	}
}

// readKeyStore reads certificates from a keystore file, detecting whether it is
// a Java KeyStore (JKS) or a PKCS12 file from its leading bytes. Unrecognized
// formats produce an explicit error rather than a misleading parse failure.
func readKeyStore(data []byte, password string) ([]*x509.Certificate, error) {
	if len(data) < 4 {
		return nil, fmt.Errorf("keystore is too small to identify (%d bytes)", len(data))
	}

	switch {
	case binary.BigEndian.Uint32(data[:4]) == magicJKS:
		return readJKS(data, password)
	case data[0] == asn1Sequence:
		return readPKCS12(data, password)
	default:
		return nil, fmt.Errorf(
			"unrecognized keystore format (leading bytes 0x%08x); supported formats are JKS and PKCS12",
			binary.BigEndian.Uint32(data[:4]),
		)
	}
}

// readJKS reads all trusted certificates and private-key certificate chains
// from a Java KeyStore.
func readJKS(data []byte, password string) ([]*x509.Certificate, error) {
	ks := keystore.New()
	if err := ks.Load(bytes.NewReader(data), []byte(password)); err != nil {
		return nil, err
	}

	var certs []*x509.Certificate
	for _, alias := range ks.Aliases() {
		switch {
		case ks.IsTrustedCertificateEntry(alias):
			entry, err := ks.GetTrustedCertificateEntry(alias)
			if err != nil {
				return certs, err
			}
			cert, err := x509.ParseCertificate(entry.Certificate.Content)
			if err != nil {
				return certs, err
			}
			certs = append(certs, cert)
		case ks.IsPrivateKeyEntry(alias):
			entry, err := ks.GetPrivateKeyEntry(alias, []byte(password))
			if err != nil {
				// The private key may use a different password; its certificate
				// chain is unreachable in that case, so skip rather than fail.
				continue
			}
			for _, c := range entry.CertificateChain {
				cert, err := x509.ParseCertificate(c.Content)
				if err != nil {
					return certs, err
				}
				certs = append(certs, cert)
			}
		}
	}
	return certs, nil
}
