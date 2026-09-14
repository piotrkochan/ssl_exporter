package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"
	"net/url"
	"os"
	"strings"
)

const (
	probeErrorCanceled    = "canceled"
	probeErrorCertificate = "certificate"
	probeErrorConnection  = "connection"
	probeErrorDNS         = "dns"
	probeErrorFile        = "file"
	probeErrorHTTP        = "http"
	probeErrorKubernetes  = "kubernetes"
	probeErrorOther       = "other"
	probeErrorProtocol    = "protocol"
	probeErrorTimeout     = "timeout"
	probeErrorTLS         = "tls"
)

// probeErrorReason classifies probe errors into a bounded set of values safe
// to use as a Prometheus label.
func probeErrorReason(err error, prober string) string {
	switch {
	case errors.Is(err, context.Canceled):
		return probeErrorCanceled
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, os.ErrDeadlineExceeded):
		return probeErrorTimeout
	}

	var netErr net.Error
	if errors.As(err, &netErr) && netErr.Timeout() {
		return probeErrorTimeout
	}

	var dnsErr *net.DNSError
	if errors.As(err, &dnsErr) {
		return probeErrorDNS
	}

	if isCertificateError(err) {
		return probeErrorCertificate
	}

	var recordHeaderErr tls.RecordHeaderError
	if errors.As(err, &recordHeaderErr) {
		return probeErrorTLS
	}

	var opErr *net.OpError
	if errors.As(err, &opErr) {
		return probeErrorConnection
	}

	var pathErr *os.PathError
	if errors.As(err, &pathErr) {
		return probeErrorFile
	}

	// Untyped keystore errors concern the input file, format, or password. Typed
	// certificate errors have already been handled above.
	if prober == "keystore" {
		return probeErrorFile
	}

	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "certificate"), strings.Contains(message, "x509:"):
		return probeErrorCertificate
	case strings.Contains(message, "tls:"):
		return probeErrorTLS
	case strings.Contains(message, "starttls"), strings.Contains(message, "protocol"), strings.Contains(message, "regex:"):
		return probeErrorProtocol
	case strings.Contains(message, "http status"), strings.Contains(message, "response code"):
		return probeErrorHTTP
	}

	var urlErr *url.Error
	if errors.As(err, &urlErr) {
		return probeErrorHTTP
	}

	switch prober {
	case "file", "keystore", "kubeconfig":
		return probeErrorFile
	case "http", "https", "http_file":
		return probeErrorHTTP
	case "kubernetes":
		return probeErrorKubernetes
	case "tcp":
		return probeErrorProtocol
	case "tls_cipher":
		return probeErrorTLS
	default:
		return probeErrorOther
	}
}

func isCertificateError(err error) bool {
	var verificationErr *tls.CertificateVerificationError
	var unknownAuthorityErr x509.UnknownAuthorityError
	var hostnameErr x509.HostnameError
	var invalidErr x509.CertificateInvalidError
	var rootsErr x509.SystemRootsError
	var algorithmErr x509.InsecureAlgorithmError

	return errors.As(err, &verificationErr) ||
		errors.As(err, &unknownAuthorityErr) ||
		errors.As(err, &hostnameErr) ||
		errors.As(err, &invalidErr) ||
		errors.As(err, &rootsErr) ||
		errors.As(err, &algorithmErr)
}
