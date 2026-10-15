package firewall

import "fmt"

// CapacityError rejects an operation before mutation when bounded installation
// or complete-inventory inspection cannot safely contain its retained objects.
// It exposes numbers, never targets, prefixes, credentials or native diagnostics.
type CapacityError struct {
	Scope              string
	RequiredBytes      int64
	LimitBytes         int64
	StaticGenerations  int
	DynamicGenerations int
}

func (e *CapacityError) Error() string {
	scope := "inventory"
	switch e.Scope {
	case "input", "output":
		scope = e.Scope
	}
	return fmt.Sprintf("nft backend: %s capacity exceeded: required %d bytes, limit %d bytes (%d static generations, %d dynamic generations)", scope, e.RequiredBytes, e.LimitBytes, e.StaticGenerations, e.DynamicGenerations)
}

// RecoveryRetryable distinguishes unchanged over-capacity state from transient
// native execution failures. Wrapping/joining must retain this classification.
func (*CapacityError) RecoveryRetryable() bool { return false }

// ValidationError marks invalid persisted target identity or an ownership
// conflict. Its cause remains available to existing callers, but early logs
// must use a fixed category rather than printing untrusted metadata.
type ValidationError struct{ Err error }

func (e *ValidationError) Error() string { return e.Err.Error() }
func (e *ValidationError) Unwrap() error { return e.Err }

// RecoveryRetryable rejects immutable target and ownership conflicts.
func (*ValidationError) RecoveryRetryable() bool { return false }
