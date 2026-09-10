// Package policy compiles normalized configuration and resolved prefixes into
// deterministic backend-neutral packet-policy state.
package policy

import (
	"fmt"
	"sort"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/prefix"
)

type compiledPolicy struct {
	policy   config.Policy
	included prefix.Set
}

// Compile turns a normalized configuration and complete prefix snapshot into
// immutable policy state. Selector resolution is deliberately performed by the
// caller; a missing selector never silently becomes an empty result.
func Compile(cfg config.Config, snapshot Snapshot) (State, error) {
	deny, err := denyAction(cfg.Firewall.DenyAction)
	if err != nil {
		return State{}, err
	}

	allow, err := prefix.New(cfg.Global.Allowlist)
	if err != nil {
		return State{}, fmt.Errorf("global allowlist: %w", err)
	}
	block, err := prefix.New(cfg.Global.Blocklist)
	if err != nil {
		return State{}, fmt.Errorf("global blocklist: %w", err)
	}

	policies, err := compilePolicies(cfg.Policies, snapshot)
	if err != nil {
		return State{}, err
	}
	if len(policies) == 0 && block.Len() == 0 && !cfg.CrowdSec.Enabled {
		return State{}, nil
	}

	families := make([]FamilyPlan, 0, 2)
	if cfg.Firewall.IPv4 {
		families = append(families, compileFamily(IPv4, allow, block, policies, cfg.CrowdSec.Enabled, deny))
	}
	if cfg.Firewall.IPv6 {
		families = append(families, compileFamily(IPv6, allow, block, policies, cfg.CrowdSec.Enabled, deny))
	}
	if len(families) == 0 {
		return State{}, fmt.Errorf("active policy configuration requires at least one enabled address family (set firewall.ipv4 or firewall.ipv6 to true)")
	}
	return State{families: families}, nil
}

func denyAction(value string) (Action, error) {
	switch value {
	case "drop":
		return Drop, nil
	case "reject":
		return Reject, nil
	default:
		return "", fmt.Errorf("firewall.deny_action: unsupported value %q", value)
	}
}

func compilePolicies(values []config.Policy, snapshot Snapshot) ([]compiledPolicy, error) {
	policies := append([]config.Policy(nil), values...)
	sort.SliceStable(policies, func(i, j int) bool {
		if policies[i].Direction != policies[j].Direction {
			return policies[i].Direction < policies[j].Direction
		}
		if policies[i].Priority != policies[j].Priority {
			return policies[i].Priority < policies[j].Priority
		}
		return policies[i].Name < policies[j].Name
	})

	seenNames := make(map[string]struct{}, len(policies))
	seenPriorities := make(map[string]map[int64]string)
	compiled := make([]compiledPolicy, 0, len(policies))
	for _, value := range policies {
		if _, exists := seenNames[value.Name]; exists {
			return nil, fmt.Errorf("policy %s: duplicate policy name", value.Name)
		}
		seenNames[value.Name] = struct{}{}
		if value.Direction != string(Ingress) && value.Direction != string(Egress) {
			return nil, fmt.Errorf("policy %s: unsupported direction %q", value.Name, value.Direction)
		}
		priorities := seenPriorities[value.Direction]
		if priorities == nil {
			priorities = make(map[int64]string)
			seenPriorities[value.Direction] = priorities
		}
		if other, exists := priorities[value.Priority]; exists {
			return nil, fmt.Errorf("policies %s and %s: duplicate priority %d in %s direction", other, value.Name, value.Priority, value.Direction)
		}
		priorities[value.Priority] = value.Name
		if value.Mode == "disabled" {
			continue
		}
		if value.Mode != "allowlist" && value.Mode != "blocklist" {
			return nil, fmt.Errorf("policy %s: unsupported mode %q", value.Name, value.Mode)
		}

		includeKeys, err := selectorKeys(value.Include)
		if err != nil {
			return nil, fmt.Errorf("policy %s include: %w", value.Name, err)
		}
		excludeKeys, err := selectorKeys(value.Exclude)
		if err != nil {
			return nil, fmt.Errorf("policy %s exclude: %w", value.Name, err)
		}
		include, err := snapshotUnion(value.Name, "include", includeKeys, snapshot)
		if err != nil {
			return nil, err
		}
		exclude, err := snapshotUnion(value.Name, "exclude", excludeKeys, snapshot)
		if err != nil {
			return nil, err
		}
		effective := prefix.Difference(include, exclude)
		if effective.Len() == 0 {
			return nil, fmt.Errorf("policy %s: effective selector set is empty overall", value.Name)
		}
		compiled = append(compiled, compiledPolicy{policy: value, included: effective})
	}
	return compiled, nil
}

func snapshotUnion(policy, category string, selectors []Selector, snapshot Snapshot) (prefix.Set, error) {
	sets := make([]prefix.Set, 0, len(selectors))
	for _, selector := range selectors {
		set, ok := snapshot.Lookup(selector)
		if !ok {
			var empty prefix.Set
			return empty, fmt.Errorf("policy %s %s: missing snapshot selector %s=%s", policy, category, selector.Kind, selector.Value)
		}
		sets = append(sets, set)
	}
	return prefix.Union(sets...), nil
}

func compileFamily(family Family, allow, block prefix.Set, policies []compiledPolicy, crowdsec bool, deny Action) FamilyPlan {
	allow = allowFamily(allow, family)
	block = allowFamily(block, family)
	sets := make([]PrefixSet, 0, 3+len(policies))
	if allow.Len() != 0 {
		sets = append(sets, PrefixSet{ID: "global_allowlist", Kind: StaticSet, Prefixes: allow.Prefixes()})
	}
	if block.Len() != 0 {
		sets = append(sets, PrefixSet{ID: "global_blocklist", Kind: StaticSet, Prefixes: block.Prefixes()})
	}
	if crowdsec {
		sets = append(sets, PrefixSet{ID: "crowdsec", Kind: DynamicCrowdSecSet})
	}
	familyPolicies := make([]compiledPolicy, 0, len(policies))
	for _, value := range policies {
		if !policyApplies(value.policy.Traffic, family) {
			continue
		}
		familyPolicies = append(familyPolicies, value)
	}
	if len(familyPolicies) != 0 {
		sets = append(sets, PrefixSet{ID: "geo_eligible", Kind: StaticSet, Prefixes: GeoEligible(family).Prefixes()})
	}
	for _, value := range familyPolicies {
		sets = append(sets, PrefixSet{ID: "geo/" + value.policy.Name, Kind: StaticSet, Prefixes: value.includedFamily(family).Prefixes()})
	}

	paths := []Path{
		compilePath(Ingress, SourceAddress, family, allow, block, familyPolicies, crowdsec, deny),
		compilePath(Egress, DestinationAddress, family, allow, block, familyPolicies, false, deny),
	}
	return FamilyPlan{Family: family, Sets: sets, Paths: paths}
}

func (p compiledPolicy) includedFamily(family Family) prefix.Set {
	if family == IPv4 {
		return p.included.IPv4()
	}
	return p.included.IPv6()
}

func allowFamily(value prefix.Set, family Family) prefix.Set {
	if family == IPv4 {
		return value.IPv4()
	}
	return value.IPv6()
}

func compilePath(direction Direction, remote RemoteField, family Family, allow, block prefix.Set, policies []compiledPolicy, crowdsec bool, deny Action) Path {
	processed := CounterRole{Kind: Processed}
	path := Path{Direction: direction, Remote: remote, Processed: processed}
	any := Scope{Any: true}
	path.Rules = append(path.Rules,
		Rule{Match: Match{Flow: EstablishedRelated, Traffic: any}, Action: Return},
		Rule{Match: Match{Flow: NotNew, Traffic: any}, Action: Return},
	)
	if allow.Len() != 0 {
		path.Rules = append(path.Rules, Rule{Match: Match{SetID: "global_allowlist", Traffic: any}, Action: Return})
	}
	if block.Len() != 0 {
		path.Rules = append(path.Rules, Rule{
			Match:   Match{SetID: "global_blocklist", Traffic: any},
			Action:  deny,
			Counter: CounterRole{Kind: Denied, Reason: GlobalBlocklist, Action: deny},
		})
	}
	if crowdsec && direction == Ingress {
		path.Rules = append(path.Rules, Rule{
			Match:   Match{SetID: "crowdsec", Traffic: any},
			Action:  deny,
			Counter: CounterRole{Kind: Denied, Reason: CrowdSec, Action: deny},
		})
	}
	hasGeo := false
	for _, value := range policies {
		if value.policy.Direction == string(direction) {
			hasGeo = true
			break
		}
	}
	if hasGeo {
		path.Rules = append(path.Rules, Rule{Match: Match{SetID: "geo_eligible", NegateSet: true, Traffic: any}, Action: Return})
	}
	for _, value := range policies {
		if value.policy.Direction != string(direction) {
			continue
		}
		scope, ok := policyScope(value.policy.Traffic, family)
		if !ok {
			continue
		}
		setID := "geo/" + value.policy.Name
		if value.policy.Mode == "blocklist" {
			path.Rules = append(path.Rules,
				Rule{Match: Match{SetID: setID, Traffic: scope}, Action: deny, Policy: value.policy.Name, Counter: CounterRole{Kind: Denied, Reason: GeoPolicy, Action: deny}},
				Rule{Match: Match{Traffic: scope}, Action: Return, Policy: value.policy.Name},
			)
		} else {
			path.Rules = append(path.Rules,
				Rule{Match: Match{SetID: setID, Traffic: scope}, Action: Return, Policy: value.policy.Name},
				Rule{Match: Match{Traffic: scope}, Action: deny, Policy: value.policy.Name, Counter: CounterRole{Kind: Denied, Reason: GeoPolicy, Action: deny}},
			)
		}
	}
	path.Rules = append(path.Rules, Rule{Match: Match{Traffic: any}, Action: Return})
	return path
}

func policyApplies(traffic config.TrafficScope, family Family) bool {
	if traffic.Any || len(traffic.TCP) != 0 || len(traffic.UDP) != 0 {
		return true
	}
	if family == IPv4 {
		return traffic.ICMP
	}
	return traffic.ICMPv6
}

func policyScope(traffic config.TrafficScope, family Family) (Scope, bool) {
	if !policyApplies(traffic, family) {
		return Scope{}, false
	}
	if traffic.Any {
		return Scope{Any: true}, true
	}
	scope := Scope{
		TCP: trafficRanges(traffic.TCP),
		UDP: trafficRanges(traffic.UDP),
	}
	if family == IPv4 {
		scope.ICMP = traffic.ICMP
	} else {
		scope.ICMP = traffic.ICMPv6
	}
	if len(scope.TCP) == 0 && len(scope.UDP) == 0 && !scope.ICMP {
		return Scope{}, false
	}
	return scope, true
}

func trafficRanges(values []config.PortRange) []PortRange {
	if len(values) == 0 {
		return nil
	}
	out := make([]PortRange, len(values))
	for i, value := range values {
		out[i] = PortRange{Start: value.Start, End: value.End}
	}
	return out
}
