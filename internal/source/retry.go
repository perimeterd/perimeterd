package source

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"syscall"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

const maxFetchAttempts = 3

// Only transport/read failures and selected HTTP statuses carry this marker.
// Parsing, validation, size limits and permanent HTTP errors never acquire it.
type retryableFetchError struct{ error }

func (e *retryableFetchError) Unwrap() error { return e.error }

func retryableFetchFailure(err, cause error) error {
	var network net.Error
	var dns *net.DNSError
	if errors.Is(cause, context.DeadlineExceeded) ||
		(errors.As(cause, &network) && network.Timeout()) ||
		(errors.As(cause, &dns) && dns.IsTemporary) ||
		errors.Is(cause, io.EOF) || errors.Is(cause, io.ErrUnexpectedEOF) ||
		errors.Is(cause, syscall.ECONNRESET) || errors.Is(cause, syscall.ECONNREFUSED) ||
		errors.Is(cause, syscall.ECONNABORTED) || errors.Is(cause, syscall.EPIPE) ||
		errors.Is(cause, syscall.ENETUNREACH) || errors.Is(cause, syscall.EHOSTUNREACH) {
		return &retryableFetchError{err}
	}
	return err
}

func (r *Resolver) fetchOne(ctx context.Context, cfg config.Config, selector policy.Selector) (Record, error) {
	success := false
	if r.observeRequest != nil {
		defer func() { r.observeRequest(selectorMetricSource(selector.Kind), success) }()
	}
	record, err := retryFetch(ctx, func() (Record, error) { return r.fetchAttempt(ctx, cfg, selector) })
	success = err == nil
	return record, err
}

// retryFetch is the single retry budget for both selector and artifact work.
func retryFetch[T any](ctx context.Context, fetch func() (T, error)) (T, error) {
	var zero T
	var lastErr error
	for attempt := range maxFetchAttempts {
		if err := ctx.Err(); err != nil {
			return zero, err
		}
		if attempt > 0 {
			// Two short, interruptible waits: one second, then two seconds.
			timer := time.NewTimer(time.Duration(attempt) * time.Second)
			select {
			case <-ctx.Done():
				timer.Stop()
				return zero, ctx.Err()
			case <-timer.C:
			}
		}
		record, err := fetch()
		if err == nil {
			return record, nil
		}
		if contextErr := ctx.Err(); contextErr != nil {
			return zero, contextErr
		}
		var retryable *retryableFetchError
		if !errors.As(err, &retryable) {
			return zero, err
		}
		lastErr = err
	}
	return zero, fmt.Errorf("after %d attempts: %w", maxFetchAttempts, lastErr)
}
