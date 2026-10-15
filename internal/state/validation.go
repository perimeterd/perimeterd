package state

import "errors"

// ValidationError identifies immutable corrupt or inconsistent durable metadata.
// Filesystem and synchronization failures are not classified as validation errors.
// The underlying diagnostic remains available to local callers through Unwrap.
// Recovery logs must use a fixed category, not the underlying diagnostic.
type ValidationError struct {
	Err error
}

func (e *ValidationError) Error() string { return "state validation: " + e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }

// RecoveryRetryable rejects unchanged corrupt or inconsistent durable records.
func (*ValidationError) RecoveryRetryable() bool { return false }

func validationError(err error) error {
	if err == nil {
		return nil
	}
	var existing *ValidationError
	if errors.As(err, &existing) {
		return err
	}
	return &ValidationError{Err: err}
}
