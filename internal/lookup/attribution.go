package lookup

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
)

func explain(ctx context.Context, static *Static, rule policy.Rule, address netip.Prefix, dynamic Dynamic, stage string, limit int) ([]Evidence, bool) {
	var result []Evidence
	addr := address.Addr()
	// Global entries are retained even when an earlier global rule shadows a
	// later source-backed decision. Contributing marks only the executed entry.
	for _, value := range static.globalAllow {
		if value.Contains(addr) {
			if len(result) >= limit {
				return nil, false
			}
			result = append(result, Evidence{Kind: "global", Name: "global_allowlist", Role: "allow", Prefix: value, Contributing: stage == "global_allow"})
		}
	}
	for _, value := range static.globalBlock {
		if value.Contains(addr) {
			if len(result) >= limit {
				return nil, false
			}
			result = append(result, Evidence{Kind: "global", Name: "global_blocklist", Role: "block", Prefix: value, Contributing: stage == "global_block"})
		}
	}

	// Report every matching source membership, but make causal contribution
	// conditional on the winning policy and effective include-minus-exclude
	// result. Disabled policies and absent snapshot records are not evidence.
	for _, configured := range static.policyList {
		if configured.Mode == "disabled" {
			continue
		}
		if contextErr(ctx) != nil {
			return nil, false
		}
		sources := static.sources[configured.Name]
		includeMatch := false
		excludeMatch := false
		for _, value := range sources.include {
			if _, ok := sourcePrefix(value.record, addr); ok {
				includeMatch = true
				break
			}
		}
		for _, value := range sources.exclude {
			if _, ok := sourcePrefix(value.record, addr); ok {
				excludeMatch = true
				break
			}
		}
		effective := includeMatch && !excludeMatch
		deciding := stage == "policy" && rule.Policy == configured.Name
		for _, value := range sources.include {
			if contextErr(ctx) != nil {
				return nil, false
			}
			if covered, ok := sourcePrefix(value.record, addr); ok {
				if len(result) >= limit {
					return nil, false
				}
				result = append(result, sourceEvidence(value, configured.Name, "include", covered, deciding && effective))
			}
		}
		for _, value := range sources.exclude {
			if contextErr(ctx) != nil {
				return nil, false
			}
			if covered, ok := sourcePrefix(value.record, addr); ok {
				if len(result) >= limit {
					return nil, false
				}
				result = append(result, sourceEvidence(value, configured.Name, "exclude", covered, deciding && includeMatch && excludeMatch))
			}
		}
	}

	if stage == "crowdsec" || dynamic.Decisions != nil {
		for _, decision := range dynamic.Decisions {
			if contextErr(ctx) != nil {
				return nil, false
			}
			if !decision.Prefix.Contains(addr) {
				continue
			}
			lease := time.Time{}
			for _, timed := range dynamic.Prefixes {
				if timed.Prefix.Contains(addr) && (lease.IsZero() || timed.Deadline.Before(lease)) {
					lease = timed.Deadline
				}
			}
			if len(result) >= limit {
				return nil, false
			}
			result = append(result, Evidence{Kind: "crowdsec", Name: "crowdsec", Role: "decision", Prefix: decision.Prefix, Contributing: stage == "crowdsec", DecisionID: decision.ID, DecisionDeadline: decision.Deadline, LeaseDeadline: lease})
		}
	}
	sort.Slice(result, func(i, j int) bool { return evidenceLess(result[i], result[j]) })
	return result, true
}

func sourcePrefix(record source.Record, address netip.Addr) (netip.Prefix, bool) {
	values := record.IPv6
	if address.Is4() {
		values = record.IPv4
	}
	return containingPrefix(values, address)
}

func containingPrefix(values []netip.Prefix, address netip.Addr) (netip.Prefix, bool) {
	index := sort.Search(len(values), func(index int) bool {
		return values[index].Addr().Compare(address) > 0
	}) - 1
	if index >= 0 && values[index].Contains(address) {
		return values[index], true
	}
	return netip.Prefix{}, false
}

func sourceEvidence(value sourceRef, policyName, role string, covered netip.Prefix, contributing bool) Evidence {
	kind := string(value.record.Selector.Kind)
	name := value.record.Selector.Value
	if value.record.SourceKind != "" {
		kind = value.record.SourceKind
	}
	if value.record.SourceName != "" {
		name = value.record.SourceName
	}
	return Evidence{Kind: kind, Name: name, Policy: policyName, Role: role, Via: append([]string(nil), value.via...), Prefix: covered, Contributing: contributing, RetrievedAt: value.record.RetrievedAt}
}

func evidenceLess(left, right Evidence) bool {
	if left.Kind != right.Kind {
		return left.Kind < right.Kind
	}
	if left.Name != right.Name {
		return left.Name < right.Name
	}
	if left.Policy != right.Policy {
		return left.Policy < right.Policy
	}
	if left.Role != right.Role {
		return left.Role < right.Role
	}
	if order := left.Prefix.Addr().Compare(right.Prefix.Addr()); order != 0 {
		return order < 0
	}
	if left.Prefix.Bits() != right.Prefix.Bits() {
		return left.Prefix.Bits() < right.Prefix.Bits()
	}
	if left.Contributing != right.Contributing {
		return !left.Contributing
	}
	if left.DecisionID != right.DecisionID {
		return left.DecisionID < right.DecisionID
	}
	if !left.DecisionDeadline.Equal(right.DecisionDeadline) {
		return left.DecisionDeadline.Before(right.DecisionDeadline)
	}
	if !left.LeaseDeadline.Equal(right.LeaseDeadline) {
		return left.LeaseDeadline.Before(right.LeaseDeadline)
	}
	if !left.RetrievedAt.Equal(right.RetrievedAt) {
		return left.RetrievedAt.Before(right.RetrievedAt)
	}
	if len(left.Via) != len(right.Via) {
		return len(left.Via) < len(right.Via)
	}
	for index := range left.Via {
		if left.Via[index] != right.Via[index] {
			return left.Via[index] < right.Via[index]
		}
	}
	return false
}
