// Package firewall contains the typed backend contract and native firewall
// reconciliation models.
package firewall

import (
	"context"
	"fmt"
	"net/netip"
	"regexp"
	"strings"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

// CounterSpec identifies one bounded, backend-owned accounting counter.
type CounterSpec struct {
	Name      string             `json:"name"`
	Family    policy.Family      `json:"family"`
	Direction policy.Direction   `json:"direction"`
	Role      policy.CounterRole `json:"role"`
}

// Target is an immutable, serializable desired nftables state. It contains the
// complete model required to recover after a process or host restart.
type Target struct {
	Owner      string              `json:"owner"`
	Table      string              `json:"table"`
	Priority   int32               `json:"priority"`
	Generation string              `json:"generation"`
	Families   []policy.FamilyPlan `json:"families"`
	Counters   []CounterSpec       `json:"counters"`
}

// Backend applies and retires complete desired firewall targets. Every pair is
// (previous, candidate); a nil candidate is the canonical unhook operation.
type Backend interface {
	Preflight(context.Context, *Target, *Target) error
	Apply(context.Context, *Target, *Target) error
	Retire(context.Context, *Target, *Target) error
	Cleanup(context.Context, []*Target) error
}

var targetIDPattern = regexp.MustCompile(`^[0-9a-f]{32}$`)

func validTargetID(value string) bool { return targetIDPattern.MatchString(value) }

func validFamily(value policy.Family) bool { return value == policy.IPv4 || value == policy.IPv6 }

func validDirection(value policy.Direction) bool {
	return value == policy.Ingress || value == policy.Egress
}

func validRole(role policy.CounterRole) bool {
	if role.Kind == policy.Processed {
		return role.Reason == "" && role.Action == ""
	}
	return role.Kind == policy.Denied && role.Reason == policy.GlobalBlocklist &&
		(role.Action == policy.Drop || role.Action == policy.Reject)
}

// ValidateConfig validates the runtime subset implemented by this backend.
// Offline configuration validation intentionally remains broader than this
// first kernel-backed vertical slice.
func ValidateConfig(value config.Config) error {
	if value.Version != 1 {
		return fmt.Errorf("firewall runtime: unsupported config version %d", value.Version)
	}
	if value.Firewall.Backend != "nftables" {
		return fmt.Errorf("firewall runtime: backend %q is unsupported; only nftables is available", value.Firewall.Backend)
	}
	if value.CrowdSec.Enabled {
		return fmt.Errorf("firewall runtime: crowdsec is not supported in the initial nftables slice")
	}
	if value.Firewall.DenyAction != "drop" && value.Firewall.DenyAction != "reject" {
		return fmt.Errorf("firewall runtime: unsupported deny action %q", value.Firewall.DenyAction)
	}
	for _, item := range value.Policies {
		if item.Mode != "disabled" {
			return fmt.Errorf("firewall runtime: policy %q is enabled; geo policy is not supported in the initial nftables slice", item.Name)
		}
	}
	table := value.Firewall.Nftables.Table
	if table == "" {
		return fmt.Errorf("firewall runtime: nftables table must not be empty")
	}
	if len([]byte(table)) > 255 {
		return fmt.Errorf("firewall runtime: nftables table exceeds 255 bytes")
	}
	if strings.IndexByte(table, 0) >= 0 {
		return fmt.Errorf("firewall runtime: nftables table contains NUL")
	}
	if value.Firewall.Nftables.Priority <= -200 {
		return fmt.Errorf("firewall runtime: nftables priority %d must be greater than -200", value.Firewall.Nftables.Priority)
	}
	return nil
}

// ValidateTarget checks the complete typed target before it can become
// mutation authority. Raw nft syntax, geo policy, and dynamic models are not
// representable in a Target in this runtime slice.
func ValidateTarget(value *Target) error {
	if value == nil {
		return nil
	}
	if !validTargetID(value.Owner) {
		return fmt.Errorf("firewall target: owner must be 32 lowercase hexadecimal characters")
	}
	if !validTargetID(value.Generation) {
		return fmt.Errorf("firewall target: generation must be 32 lowercase hexadecimal characters")
	}
	if value.Table == "" || len([]byte(value.Table)) > 255 || strings.IndexByte(value.Table, 0) >= 0 {
		return fmt.Errorf("firewall target: invalid table name")
	}
	if value.Priority <= -200 {
		return fmt.Errorf("firewall target: priority %d must be greater than -200", value.Priority)
	}
	if len(value.Families) == 0 {
		return fmt.Errorf("firewall target: non-empty target requires at least one family")
	}
	seenFamilies := make(map[policy.Family]struct{}, len(value.Families))
	expectedCounters := make(map[string]CounterSpec)
	for _, family := range value.Families {
		if !validFamily(family.Family) {
			return fmt.Errorf("firewall target: unsupported family %d", family.Family)
		}
		if _, ok := seenFamilies[family.Family]; ok {
			return fmt.Errorf("firewall target: duplicate family %d", family.Family)
		}
		seenFamilies[family.Family] = struct{}{}
		setIDs := make(map[string]struct{}, len(family.Sets))
		for _, set := range family.Sets {
			if set.Kind != policy.StaticSet || (set.ID != "global_allowlist" && set.ID != "global_blocklist") {
				return fmt.Errorf("firewall target: unsupported set %q", set.ID)
			}
			if _, ok := setIDs[set.ID]; ok {
				return fmt.Errorf("firewall target: duplicate set %q", set.ID)
			}
			setIDs[set.ID] = struct{}{}
			for _, prefix := range set.Prefixes {
				if err := validatePrefix(prefix, family.Family); err != nil {
					return fmt.Errorf("firewall target: set %s: %w", set.ID, err)
				}
			}
		}
		pathDirections := make(map[policy.Direction]struct{}, 2)
		for _, path := range family.Paths {
			if !validDirection(path.Direction) {
				return fmt.Errorf("firewall target: unsupported path direction %q", path.Direction)
			}
			wantRemote := policy.SourceAddress
			if path.Direction == policy.Egress {
				wantRemote = policy.DestinationAddress
			}
			if path.Remote != wantRemote {
				return fmt.Errorf("firewall target: %s path has remote field %q", path.Direction, path.Remote)
			}
			if _, ok := pathDirections[path.Direction]; ok {
				return fmt.Errorf("firewall target: duplicate path direction %q", path.Direction)
			}
			pathDirections[path.Direction] = struct{}{}
			if path.Processed != (policy.CounterRole{Kind: policy.Processed}) {
				return fmt.Errorf("firewall target: %s path has invalid processed role", path.Direction)
			}
			name := counterName(value.Owner, family.Family, path.Direction, path.Processed)
			expectedCounters[name] = CounterSpec{Name: name, Family: family.Family, Direction: path.Direction, Role: path.Processed}
			for _, rule := range path.Rules {
				if err := validateRuntimeRule(rule, setIDs); err != nil {
					return fmt.Errorf("firewall target: %s path rule: %w", path.Direction, err)
				}
				if rule.Counter.Kind == policy.Denied {
					if !validRole(rule.Counter) {
						return fmt.Errorf("firewall target: invalid denial role")
					}
					name = counterName(value.Owner, family.Family, path.Direction, rule.Counter)
					expectedCounters[name] = CounterSpec{Name: name, Family: family.Family, Direction: path.Direction, Role: rule.Counter}
				}
			}
		}
		if len(pathDirections) != 2 {
			return fmt.Errorf("firewall target: family %d must have ingress and egress paths", family.Family)
		}
	}
	if len(value.Counters) == 0 {
		return fmt.Errorf("firewall target: missing counters")
	}
	seenCounters := make(map[string]struct{}, len(value.Counters))
	for _, counter := range value.Counters {
		if counter.Name == "" || !validFamily(counter.Family) || !validDirection(counter.Direction) || !validRole(counter.Role) {
			return fmt.Errorf("firewall target: invalid counter %q", counter.Name)
		}
		want := counterName(value.Owner, counter.Family, counter.Direction, counter.Role)
		if counter.Name != want {
			return fmt.Errorf("firewall target: counter %q has unexpected stable name", counter.Name)
		}
		if _, ok := seenCounters[counter.Name]; ok {
			return fmt.Errorf("firewall target: duplicate counter %q", counter.Name)
		}
		seenCounters[counter.Name] = struct{}{}
	}
	for name := range expectedCounters {
		if _, ok := seenCounters[name]; !ok {
			return fmt.Errorf("firewall target: required counter %q is missing", name)
		}
	}
	return nil
}

func validatePrefix(value netip.Prefix, family policy.Family) error {
	if !value.IsValid() {
		return fmt.Errorf("invalid prefix")
	}
	if family == policy.IPv4 && !value.Addr().Is4() {
		return fmt.Errorf("IPv4 family contains %s", value)
	}
	if family == policy.IPv6 && !value.Addr().Is6() {
		return fmt.Errorf("IPv6 family contains %s", value)
	}
	if value != value.Masked() {
		return fmt.Errorf("prefix %s is not canonical", value)
	}
	return nil
}

func validateRuntimeRule(rule policy.Rule, setIDs map[string]struct{}) error {
	if rule.Policy != "" || rule.Action == "" {
		return fmt.Errorf("geo policy metadata/action is not supported")
	}
	if rule.Action != policy.Return && rule.Action != policy.Drop && rule.Action != policy.Reject {
		return fmt.Errorf("unsupported action %q", rule.Action)
	}
	if rule.Match.SetID != "" {
		if _, ok := setIDs[rule.Match.SetID]; !ok || rule.Match.NegateSet {
			return fmt.Errorf("unsupported set reference %q", rule.Match.SetID)
		}
	}
	if !rule.Match.Traffic.Any || len(rule.Match.Traffic.TCP) != 0 || len(rule.Match.Traffic.UDP) != 0 || rule.Match.Traffic.ICMP {
		return fmt.Errorf("non-global traffic scope is not supported")
	}
	if rule.Match.Flow != "" && rule.Match.Flow != policy.EstablishedRelated && rule.Match.Flow != policy.NotNew {
		return fmt.Errorf("unsupported flow guard %q", rule.Match.Flow)
	}
	if rule.Counter != (policy.CounterRole{}) {
		if !validRole(rule.Counter) {
			return fmt.Errorf("unsupported counter role")
		}
		if rule.Counter.Kind == policy.Processed {
			return fmt.Errorf("processed counter must be attached to path entry")
		}
	}
	return nil
}
