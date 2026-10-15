package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"os/exec"
	"time"

	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/state"
)

// Unknown native failures remain retryable. Any explicitly permanent cause in
// a wrapped or joined error stops recovery, even if another cause is transient.
// Lifecycle context checks, not child-operation errors, stop canceled recovery.
func recoveryRetryable(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errEngineClosed) {
		return false
	}
	if errors.Is(err, exec.ErrNotFound) || errors.Is(err, os.ErrPermission) || errors.Is(err, os.ErrNotExist) {
		return false
	}
	if classified, ok := err.(interface{ RecoveryRetryable() bool }); ok && !classified.RecoveryRetryable() {
		return false
	}
	switch wrapped := err.(type) {
	case interface{ Unwrap() []error }:
		for _, cause := range wrapped.Unwrap() {
			if cause != nil && !recoveryRetryable(cause) {
				return false
			}
		}
	case interface{ Unwrap() error }:
		if cause := wrapped.Unwrap(); cause != nil {
			return recoveryRetryable(cause)
		}
	}
	return true
}

func recoveryContextError(err, contextErr error) error {
	if contextErr == nil || errors.Is(err, contextErr) {
		return err
	}
	return errors.Join(err, contextErr)
}

// Only locally defined categories and numeric capacity fields cross the new
// bootstrap log/notification boundary. Never render arbitrary backend errors.
func recoveryCause(err, contextErr error) string {
	var capacity *firewall.CapacityError
	var invalidState *state.ValidationError
	var invalidTarget *firewall.ValidationError
	switch {
	case errors.As(err, &capacity):
		return "firewall capacity exceeded"
	case errors.As(err, &invalidState):
		return "persisted state validation failed"
	case errors.As(err, &invalidTarget):
		return "firewall validation or ownership conflict"
	case errors.Is(contextErr, context.Canceled), errors.Is(err, errEngineClosed):
		return "startup canceled"
	case errors.Is(contextErr, context.DeadlineExceeded):
		return "startup deadline exceeded"
	case errors.Is(err, context.Canceled):
		return "recovery operation canceled"
	case errors.Is(err, context.DeadlineExceeded):
		return "recovery operation timed out"
	case errors.Is(err, exec.ErrNotFound):
		return "native firewall executable unavailable"
	case errors.Is(err, os.ErrPermission):
		return "firewall or state permission denied"
	case errors.Is(err, os.ErrNotExist):
		return "required recovery state is absent"
	default:
		return "backend or state operation failed"
	}
}

func recoveryReporter(ctx context.Context, logger *slog.Logger, notifier *startupNotifier) func(error, int, time.Duration) {
	return func(err error, attempt int, delay time.Duration) {
		cause := recoveryCause(err, ctx.Err())
		attrs := []any{"cause", cause, "attempt", attempt, "retry_delay", delay}
		var capacity *firewall.CapacityError
		if errors.As(err, &capacity) {
			attrs = append(attrs, "required_bytes", capacity.RequiredBytes, "limit_bytes", capacity.LimitBytes,
				"static_generations", capacity.StaticGenerations, "dynamic_generations", capacity.DynamicGenerations)
		}
		logger.Warn("firewall recovery failed", attrs...)
		if notifier != nil {
			status := "recovery blocked: " + cause
			if delay > 0 {
				status = "recovery retry pending: " + cause
			}
			notifier.Status(status)
		}
	}
}

// startupRecoveryError sanitizes the final CLI diagnostic once, at the process
// boundary. Unwrap retains native/state causes for errors.Is and errors.As.
type startupRecoveryError struct {
	err        error
	contextErr error
}

func (e *startupRecoveryError) Error() string {
	var capacity *firewall.CapacityError
	if errors.As(e.err, &capacity) {
		return fmt.Sprintf("startup recovery failed: firewall capacity exceeded (required_bytes=%d limit_bytes=%d static_generations=%d dynamic_generations=%d)",
			capacity.RequiredBytes, capacity.LimitBytes, capacity.StaticGenerations, capacity.DynamicGenerations)
	}
	return "startup recovery failed: " + recoveryCause(e.err, e.contextErr)
}

func (e *startupRecoveryError) Unwrap() error { return e.err }
