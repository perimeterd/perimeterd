// Package policy contains the backend-neutral policy model and compiler inputs.
package policy

import (
	"net/netip"
	"slices"

	"github.com/perimeterd/perimeterd/internal/prefix"
)

// Family identifies the address family to which a plan applies.
type Family uint8

const (
	// IPv4 identifies Internet Protocol version 4.
	IPv4 Family = 4
	// IPv6 identifies Internet Protocol version 6.
	IPv6 Family = 6
)

// Direction identifies whether a path handles packets entering or leaving the host.
type Direction string

const (
	// Ingress identifies packets entering the host.
	Ingress Direction = "ingress"
	// Egress identifies packets leaving the host.
	Egress Direction = "egress"
)

// RemoteField identifies which packet address is compared with policy sets.
type RemoteField string

const (
	// SourceAddress selects the packet source address for ingress paths.
	SourceAddress RemoteField = "source"
	// DestinationAddress selects the packet destination address for egress paths.
	DestinationAddress RemoteField = "destination"
)

// Action is the terminal decision represented by a policy rule.
type Action string

const (
	// Return leaves the packet to the surrounding firewall; it is never ACCEPT.
	Return Action = "return"
	// Drop silently discards the packet.
	Drop Action = "drop"
	// Reject discards the packet; backends lower it to a TCP reset for TCP and
	// administratively prohibited ICMP/ICMPv6 for other protocols in the owning family.
	Reject Action = "reject"
)

// FlowMatch identifies a conntrack flow guard. Guards are evaluated in declaration order.
type FlowMatch string

const (
	// EstablishedRelated matches ESTABLISHED,RELATED traffic.
	EstablishedRelated FlowMatch = "established_related"
	// NotNew matches traffic that is not a NEW conntrack flow.
	NotNew FlowMatch = "not_new"
)

// SetKind describes whether a prefix set is static configuration data or a dynamic feed.
type SetKind string

const (
	// StaticSet is a compiler-owned, immutable prefix set.
	StaticSet SetKind = "static"
	// DynamicCrowdSecSet is populated by the CrowdSec runtime and is not captured in a State.
	DynamicCrowdSecSet SetKind = "crowdsec"
)

// PrefixSet names prefixes referenced by rules. Static sets contain compiled prefixes;
// dynamic CrowdSec sets intentionally contain no captured decisions.
type PrefixSet struct {
	ID       string
	Kind     SetKind
	Prefixes []netip.Prefix
}

// PortRange is an inclusive transport-port interval.
type PortRange struct {
	Start uint16
	End   uint16
}

// Scope is the protocol and port portion of a match. Any true means unrestricted
// traffic. With Any false, an all-zero scope matches nothing. ICMP refers to the
// protocol belonging to the owning address family.
type Scope struct {
	Any  bool
	TCP  []PortRange
	UDP  []PortRange
	ICMP bool
}

// Match is a conjunction of its flow, address-set, and traffic constraints. An
// empty SetID omits the address test; NegateSet negates membership when SetID is
// present. Global and flow guard rules use Traffic.Any true.
type Match struct {
	Flow      FlowMatch
	SetID     string
	NegateSet bool
	Traffic   Scope
}

// CounterKind identifies the bounded accounting role of a counter.
type CounterKind string

const (
	// Processed counts one traversal of a direction path on entry.
	Processed CounterKind = "processed"
	// Denied counts a terminal denial actually executed on a traversal.
	Denied CounterKind = "denied"
)

// DenyReason classifies a terminal denial without operator-derived metric labels.
type DenyReason string

const (
	// GlobalBlocklist identifies a denial from the configured global blocklist.
	GlobalBlocklist DenyReason = "global_blocklist"
	// CrowdSec identifies a denial from a CrowdSec dynamic decision.
	CrowdSec DenyReason = "crowdsec"
	// GeoPolicy identifies a denial from an enabled static geo policy.
	GeoPolicy DenyReason = "geo_policy"
)

// CounterRole describes one bounded accounting role and, for denied counters,
// the action that was executed. Policy names and address labels are not metric labels.
type CounterRole struct {
	Kind   CounterKind
	Reason DenyReason
	Action Action
}

// Rule combines a conjunction match with its action and optional trace identity.
// Policy is for tracing only and must never become a metric label. A counter role
// is attached only to a terminal rule or to the path's processed entry counter.
type Rule struct {
	Match   Match
	Action  Action
	Policy  string
	Counter CounterRole
}

// Path is one ingress or egress logical packet path. Processed is counted once
// on entry, including packets which subsequently return; denied counters belong
// only to executed terminal denial rules.
type Path struct {
	Direction Direction
	Remote    RemoteField
	Processed CounterRole
	Rules     []Rule
}

// FamilyPlan contains all static and dynamic sets and packet paths for one family.
type FamilyPlan struct {
	Family Family
	Sets   []PrefixSet
	Paths  []Path
}

// State is the immutable backend-neutral compiled policy state. Its zero value is
// the canonical empty desired state. The compiler in this package is the only
// production writer of its unexported family plans.
type State struct {
	families []FamilyPlan
}

// Empty reports whether the state has no family plans and therefore no model artifacts.
func (s State) Empty() bool {
	return len(s.families) == 0
}

// Families returns a deep copy of every family plan. Callers may freely mutate
// the returned plans, rules, prefixes, and TCP/UDP port ranges without changing
// subsequent observations of this State.
func (s State) Families() []FamilyPlan {
	if len(s.families) == 0 {
		return nil
	}
	families := make([]FamilyPlan, len(s.families))
	for i, family := range s.families {
		families[i].Family = family.Family
		if family.Sets != nil {
			families[i].Sets = make([]PrefixSet, len(family.Sets))
		}
		for j, set := range family.Sets {
			families[i].Sets[j] = set
			families[i].Sets[j].Prefixes = slices.Clone(set.Prefixes)
		}
		if family.Paths != nil {
			families[i].Paths = make([]Path, len(family.Paths))
		}
		for j, path := range family.Paths {
			families[i].Paths[j] = path
			if path.Rules != nil {
				families[i].Paths[j].Rules = make([]Rule, len(path.Rules))
			}
			for k, rule := range path.Rules {
				families[i].Paths[j].Rules[k] = rule
				families[i].Paths[j].Rules[k].Match.Traffic.TCP = slices.Clone(rule.Match.Traffic.TCP)
				families[i].Paths[j].Rules[k].Match.Traffic.UDP = slices.Clone(rule.Match.Traffic.UDP)
			}
		}
	}
	return families
}

// GeoEligible returns the fixed, release-pinned geo-eligible prefix set for a
// family. Unsupported families return an empty immutable set. The classifier is
// compiled in and never refreshed from the network or a library classification.
func GeoEligible(family Family) prefix.Set {
	return geoEligible(family)
}
