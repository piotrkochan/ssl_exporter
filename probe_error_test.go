package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"net/url"
	"os"
	"testing"
)

func TestProbeErrorReason(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want string
	}{
		{
			name: "canceled",
			err:  fmt.Errorf("probe: %w", context.Canceled),
			want: probeErrorCanceled,
		},
		{
			name: "deadline exceeded",
			err:  fmt.Errorf("probe: %w", context.DeadlineExceeded),
			want: probeErrorTimeout,
		},
		{
			name: "network timeout",
			err:  &net.DNSError{Err: "timeout", Name: "example.com", IsTimeout: true},
			want: probeErrorTimeout,
		},
		{
			name: "dns",
			err:  &net.DNSError{Err: "no such host", Name: "example.invalid"},
			want: probeErrorDNS,
		},
		{
			name: "certificate",
			err:  x509.UnknownAuthorityError{},
			want: probeErrorCertificate,
		},
		{
			name: "tls record",
			err:  tls.RecordHeaderError{Msg: "bad record"},
			want: probeErrorTLS,
		},
		{
			name: "connection",
			err:  &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")},
			want: probeErrorConnection,
		},
		{
			name: "file",
			err:  &os.PathError{Op: "open", Path: "/missing", Err: os.ErrNotExist},
			want: probeErrorFile,
		},
		{
			name: "http",
			err:  &url.Error{Op: "Get", URL: "https://example.com", Err: errors.New("redirect rejected")},
			want: probeErrorHTTP,
		},
		{
			name: "certificate text",
			err:  errors.New("decoding certificates from response body"),
			want: probeErrorCertificate,
		},
		{
			name: "tls text",
			err:  errors.New("remote error: tls: handshake failure"),
			want: probeErrorTLS,
		},
		{
			name: "protocol",
			err:  errors.New("STARTTLS is not supported"),
			want: probeErrorProtocol,
		},
		{
			name: "http status",
			err:  errors.New("unexpected response code: 500"),
			want: probeErrorHTTP,
		},
		{
			name: "other",
			err:  errors.New("unknown failure"),
			want: probeErrorOther,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := probeErrorReason(tt.err); got != tt.want {
				t.Fatalf("probeErrorReason() = %q, want %q", got, tt.want)
			}
		})
	}
}
