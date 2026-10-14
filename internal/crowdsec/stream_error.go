package crowdsec

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"net"
	"syscall"
)

type streamFailure string

const (
	failureHTTP         streamFailure = "HTTP"
	failureWireLimit    streamFailure = "wire size limit exceeded"
	failureDecodedLimit streamFailure = "decoded size limit exceeded"
	failureEncoding     streamFailure = "unsupported content encoding"
	failureGzip         streamFailure = "malformed or truncated gzip"
	failureEnvelope     streamFailure = "malformed envelope"
	failureDecision     streamFailure = "malformed decision data"
	failureDNS          streamFailure = "DNS failure"
	failureConnection   streamFailure = "connection failure"
	failureTLS          streamFailure = "TLS failure"
	failureTimeout      streamFailure = "timeout"
	failureCanceled     streamFailure = "canceled"
	failureTransport    streamFailure = "transport/read failure"
)

var errMalformedEnvelope = &streamError{kind: failureEnvelope}

// streamError contains only locally chosen categories and numeric metadata.
// cause is restricted to a context sentinel, never an arbitrary wrapped error.
type streamError struct {
	kind   streamFailure
	status int
	limit  int64
	cause  error
}

func (e *streamError) Error() string {
	const prefix = "crowdsec stream request failed: "
	switch e.kind {
	case failureHTTP:
		return fmt.Sprintf("%sHTTP %d", prefix, e.status)
	case failureWireLimit, failureDecodedLimit:
		return fmt.Sprintf("%s%s (%d bytes)", prefix, e.kind, e.limit)
	default:
		return prefix + string(e.kind)
	}
}

func (e *streamError) Unwrap() error { return e.cause }

// sanitizeStreamError is the sole boundary between untrusted HTTP/SDK/parser
// errors and callers/logs. Typed inspection is safe; arbitrary Error text is not.
func sanitizeStreamError(err, contextErr error, closed bool) error {
	var safe *streamError
	if errors.As(err, &safe) && safe.kind == failureHTTP {
		return safe // A canceled/error-body read must never hide the status.
	}
	if closed {
		return errClientClosed
	}
	if contextErr != nil {
		err = contextErr
	}
	if errors.Is(err, context.Canceled) {
		return &streamError{kind: failureCanceled, cause: context.Canceled}
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return &streamError{kind: failureTimeout, cause: context.DeadlineExceeded}
	}
	if errors.As(err, &safe) {
		return safe
	}
	var dns *net.DNSError
	if errors.As(err, &dns) {
		if dns.Timeout() {
			return &streamError{kind: failureTimeout}
		}
		return &streamError{kind: failureDNS}
	}
	var verification *tls.CertificateVerificationError
	var unknownAuthority x509.UnknownAuthorityError
	var hostname x509.HostnameError
	var invalidCertificate x509.CertificateInvalidError
	var recordHeader tls.RecordHeaderError
	var alert tls.AlertError
	if errors.As(err, &verification) || errors.As(err, &unknownAuthority) || errors.As(err, &hostname) ||
		errors.As(err, &invalidCertificate) || errors.As(err, &recordHeader) || errors.As(err, &alert) {
		return &streamError{kind: failureTLS}
	}
	var network net.Error
	if errors.As(err, &network) && network.Timeout() {
		return &streamError{kind: failureTimeout}
	}
	var operation *net.OpError
	if (errors.As(err, &operation) && operation.Op == "dial") ||
		errors.Is(err, syscall.ECONNREFUSED) || errors.Is(err, syscall.ECONNRESET) ||
		errors.Is(err, syscall.ECONNABORTED) || errors.Is(err, syscall.ENETUNREACH) ||
		errors.Is(err, syscall.EHOSTUNREACH) || errors.Is(err, syscall.EPIPE) {
		return &streamError{kind: failureConnection}
	}
	return &streamError{kind: failureTransport}
}
