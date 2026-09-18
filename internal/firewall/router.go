package firewall

import (
	"context"
	"errors"
	"fmt"

	"github.com/perimeterd/perimeterd/internal/policy"
)

// Native routes persisted targets without auto-detection or fallback. A backend
// migration installs the replacement first; retirement happens after commit.
type Native struct {
	nft      Backend
	iptables Backend
}

// NewNative constructs a dispatcher without probing unused backend tools.
func NewNative(progress FamilyProgress) *Native {
	return &Native{nft: NewNFT(), iptables: NewIPTables(progress)}
}

func (n *Native) implementation(kind string) Backend {
	if kind == "iptables" {
		return n.iptables
	}
	return n.nft
}

func validateTargetPair(previous, candidate *Target) error {
	for _, target := range []*Target{previous, candidate} {
		if err := ValidateTarget(target); err != nil {
			return err
		}
	}
	if previous != nil && candidate != nil && previous.Owner != candidate.Owner {
		return errors.New("firewall migration: target owner mismatch")
	}
	return nil
}

func targetBackend(previous, candidate *Target) string {
	if candidate != nil {
		return candidate.Backend()
	}
	return previous.Backend()
}

// Preflight validates both ownership scopes before a backend migration.
func (n *Native) Preflight(ctx context.Context, previous, candidate *Target) error {
	if err := validateTargetPair(previous, candidate); err != nil {
		return err
	}
	kind := targetBackend(previous, candidate)
	if kind == "" {
		return ctx.Err()
	}
	if previous == nil || candidate == nil || previous.Backend() == candidate.Backend() {
		return n.implementation(kind).Preflight(ctx, previous, candidate)
	}
	if err := n.implementation(previous.Backend()).Preflight(ctx, previous, nil); err != nil {
		return fmt.Errorf("migration previous target: %w", err)
	}
	return n.implementation(kind).Preflight(ctx, nil, candidate)
}

// Apply installs the candidate without retiring a different previous backend.
func (n *Native) Apply(ctx context.Context, previous, candidate *Target) error {
	if err := validateTargetPair(previous, candidate); err != nil {
		return err
	}
	kind := targetBackend(previous, candidate)
	if kind == "" {
		return ctx.Err()
	}
	if previous == nil || candidate == nil || previous.Backend() == candidate.Backend() {
		return n.implementation(kind).Apply(ctx, previous, candidate)
	}
	// Both targets are recorded by this point, including during reverse apply
	// after a failed migration. Never remove the previous enforcement first.
	if err := n.implementation(previous.Backend()).Preflight(ctx, previous, nil); err != nil {
		return fmt.Errorf("migration previous target: %w", err)
	}
	return n.implementation(kind).Apply(ctx, nil, candidate)
}

// Retire removes obsolete ownership after durable candidate publication.
func (n *Native) Retire(ctx context.Context, previous, candidate *Target) error {
	if err := validateTargetPair(previous, candidate); err != nil {
		return err
	}
	if previous == nil {
		return ctx.Err()
	}
	if candidate != nil && previous.Backend() != candidate.Backend() {
		return n.implementation(previous.Backend()).Retire(ctx, previous, nil)
	}
	return n.implementation(previous.Backend()).Retire(ctx, previous, candidate)
}

// Cleanup dispatches recorded ownership to its original backend.
func (n *Native) Cleanup(ctx context.Context, targets []*Target) error {
	groups := make(map[string][]*Target)
	for _, target := range targets {
		if target == nil {
			continue
		}
		if err := ValidateTarget(target); err != nil {
			return err
		}
		groups[target.Backend()] = append(groups[target.Backend()], target)
	}
	var result error
	for _, kind := range []string{"nftables", "iptables"} {
		if len(groups[kind]) != 0 {
			if err := n.implementation(kind).Cleanup(ctx, groups[kind]); err != nil {
				result = errors.Join(result, fmt.Errorf("%s cleanup: %w", kind, err))
			}
		}
	}
	return result
}

// UpdateDynamic reconciles the selected backend's owned dynamic projection
// without changing the static packet path or creating unrecorded targets.
func (n *Native) UpdateDynamic(ctx context.Context, target *Target, prefixes []policy.TimedPrefix) error {
	if err := ValidateTarget(target); err != nil {
		return err
	}
	if target == nil || target.DynamicGeneration == "" {
		return errors.New("firewall dynamic update requires an active dynamic target")
	}
	if err := ValidateDynamic(prefixes); err != nil {
		return err
	}
	return n.implementation(target.Backend()).UpdateDynamic(ctx, target, prefixes)
}
