package firewall

import "fmt"

// CapacityError rejects work when bounded installation or complete inventory
// inspection cannot safely contain it, including failures found during inspection.
// It exposes numbers, never targets, prefixes, credentials or native diagnostics.
type CapacityError struct {
	Backend            string
	Resource           string
	Scope              string
	RequiredBytes      int64
	LimitBytes         int64
	StaticGenerations  int
	DynamicGenerations int
}

func (e *CapacityError) Error() string {
	return fmt.Sprintf("%s backend: %s %s capacity exceeded: required %d bytes, limit %d bytes (%d static generations, %d dynamic generations; zero counts may be unknown)", e.SafeBackend(), e.SafeResource(), e.SafeScope(), e.RequiredBytes, e.LimitBytes, e.StaticGenerations, e.DynamicGenerations)
}

// SafeBackend returns only local diagnostic categories, never supplied names.
func (e *CapacityError) SafeBackend() string {
	switch e.Backend {
	case "nftables", "iptables":
		return e.Backend
	default:
		return "unknown"
	}
}

// SafeResource returns only local diagnostic categories, never supplied names.
func (e *CapacityError) SafeResource() string {
	switch e.Resource {
	case "nft-table", "ipsets", "ipv4-rules", "ipv6-rules", "native-io":
		return e.Resource
	default:
		return "unknown"
	}
}

// SafeScope returns only local diagnostic categories, never supplied names.
func (e *CapacityError) SafeScope() string {
	switch e.Scope {
	case "input", "inventory", "output":
		return e.Scope
	default:
		return "unknown"
	}
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
