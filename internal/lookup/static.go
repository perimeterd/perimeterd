package lookup

import (
	"fmt"
	"net/netip"
	"slices"
	"sort"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/config/catalog"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
)

// Static is the immutable, backend-neutral query view for one applied static
// target and one exact source manifest. All source records are copied once at
// construction; Evaluate never reads disk, compiles policy, or performs I/O.
type Static struct {
	globalAllow []netip.Prefix
	globalBlock []netip.Prefix
	policyList  []config.Policy
	groups      map[string][]string
	families    []policy.FamilyPlan
	records     []source.Record
	manifest    string
	priorities  map[string]int64
	policies    map[string]config.Policy
	sources     map[string]policySources
	attachments map[policy.Direction][]config.Attachment
	boundaries  map[policy.Family][]netip.Prefix
	setIndex    map[policy.Family]map[string][]netip.Prefix
	table       string
	nft         bool
	crowdsec    bool
}

// NewStatic builds an immutable query view from the successfully selected
// target. A nil target represents no managed enforcement, which is distinct
// from a constructor error and permits querying a confirmed empty state.
func NewStatic(cfg config.Config, target *firewall.Target, snapshot source.Snapshot) (*Static, error) {
	if err := snapshot.ValidateConfig(cfg); err != nil {
		return nil, fmt.Errorf("lookup source snapshot: %w", err)
	}
	policies := clonePolicies(cfg.Policies)
	view := &Static{
		globalAllow: append([]netip.Prefix(nil), cfg.Global.Allowlist...),
		globalBlock: append([]netip.Prefix(nil), cfg.Global.Blocklist...),
		policyList:  policies,
		groups:      cloneGroups(cfg.Groups),
		manifest:    snapshot.ManifestID(),
		records:     snapshot.Records(),
		priorities:  make(map[string]int64, len(policies)),
		policies:    make(map[string]config.Policy, len(policies)),
		sources:     make(map[string]policySources, len(policies)),
		attachments: make(map[policy.Direction][]config.Attachment),
		boundaries:  make(map[policy.Family][]netip.Prefix),
		setIndex:    make(map[policy.Family]map[string][]netip.Prefix),
		crowdsec:    cfg.CrowdSec.Enabled,
	}
	for _, item := range policies {
		view.priorities[item.Name] = item.Priority
		view.policies[item.Name] = item
		view.sources[item.Name] = policySources{include: view.sourceRefs(item.Include), exclude: view.sourceRefs(item.Exclude)}
	}
	if target == nil {
		return view, nil
	}
	if len(target.Families) == 0 {
		view.families = nil
	} else {
		view.families = policy.CloneFamilies(target.Families)
	}
	view.table = target.Table
	view.buildIndexes()
	if target.IPTables != nil {
		for _, item := range target.IPTables.Attachments {
			copyItem := item
			copyItem.InputInterfaces = append([]string(nil), item.InputInterfaces...)
			copyItem.OutputInterfaces = append([]string(nil), item.OutputInterfaces...)
			direction := policy.Direction(item.Direction)
			view.attachments[direction] = append(view.attachments[direction], copyItem)
		}
	} else {
		view.nft = true
	}
	for direction := range view.attachments {
		sort.Slice(view.attachments[direction], func(i, j int) bool {
			left, right := view.attachments[direction][i], view.attachments[direction][j]
			if left.Chain != right.Chain {
				return left.Chain < right.Chain
			}
			if left.OriginalDestination != right.OriginalDestination {
				return !left.OriginalDestination
			}
			return stringsJoin(left.InputInterfaces) < stringsJoin(right.InputInterfaces)
		})
	}
	return view, nil
}

func clonePolicies(values []config.Policy) []config.Policy {
	out := make([]config.Policy, len(values))
	for i, item := range values {
		out[i] = item
		out[i].Include = cloneSelector(item.Include)
		out[i].Exclude = cloneSelector(item.Exclude)
		out[i].Traffic.TCP = append([]config.PortRange(nil), item.Traffic.TCP...)
		out[i].Traffic.UDP = append([]config.PortRange(nil), item.Traffic.UDP...)
	}
	return out
}

func cloneGroups(values map[string][]string) map[string][]string {
	out := make(map[string][]string, len(values))
	for name, countries := range values {
		out[name] = append([]string(nil), countries...)
	}
	return out
}

func cloneSelector(value config.Selector) config.Selector {
	value.Countries = append([]string(nil), value.Countries...)
	value.RIRs = append([]string(nil), value.RIRs...)
	value.Groups = append([]string(nil), value.Groups...)
	value.ASNs = append([]string(nil), value.ASNs...)
	value.IPLists = append([]string(nil), value.IPLists...)
	value.Providers = append([]string(nil), value.Providers...)
	value.ExpandedCountries = append([]string(nil), value.ExpandedCountries...)
	return value
}

func stringsJoin(values []string) string {
	if len(values) == 0 {
		return ""
	}
	out := values[0]
	for _, value := range values[1:] {
		out += "\x00" + value
	}
	return out
}

func (s *Static) buildIndexes() {
	for _, plan := range s.families {
		if s.setIndex[plan.Family] == nil {
			s.setIndex[plan.Family] = make(map[string][]netip.Prefix)
		}
		for _, set := range plan.Sets {
			s.setIndex[plan.Family][set.ID] = set.Prefixes
			s.boundaries[plan.Family] = append(s.boundaries[plan.Family], set.Prefixes...)
		}
	}
	for _, record := range s.records {
		s.boundaries[policy.IPv4] = append(s.boundaries[policy.IPv4], record.IPv4...)
		s.boundaries[policy.IPv6] = append(s.boundaries[policy.IPv6], record.IPv6...)
	}
	for _, values := range [][]netip.Prefix{s.globalAllow, s.globalBlock} {
		for _, value := range values {
			family := policy.IPv6
			if value.Addr().Is4() {
				family = policy.IPv4
			}
			s.boundaries[family] = append(s.boundaries[family], value)
		}
	}
	for family := range s.boundaries {
		sort.Slice(s.boundaries[family], func(i, j int) bool {
			left, right := s.boundaries[family][i], s.boundaries[family][j]
			if order := left.Addr().Compare(right.Addr()); order != 0 {
				return order < 0
			}
			return left.Bits() < right.Bits()
		})
		s.boundaries[family] = slices.Compact(s.boundaries[family])
	}
}

func (s *Static) family(family policy.Family) (policy.FamilyPlan, bool) {
	if s == nil {
		return policy.FamilyPlan{}, false
	}
	for _, value := range s.families {
		if value.Family == family {
			return value, true
		}
	}
	return policy.FamilyPlan{}, false
}

func (s *Static) familyBoundaries(family policy.Family) []netip.Prefix {
	if s == nil {
		return nil
	}
	return s.boundaries[family]
}

// sourceRefs returns records selected by one policy selector, preserving all
// deterministic group and RIR expansion paths for explanation. It intentionally
// does not query a source or infer membership from a missing record.
type (
	sourceRef struct {
		record source.Record
		via    []string
	}
	policySources struct{ include, exclude []sourceRef }
)

func (s *Static) sourceRefs(value config.Selector) []sourceRef {
	keys := make(map[policy.Selector][]string)
	add := func(kind policy.SelectorKind, name, via string) {
		selector, err := policy.CanonicalSelector(kind, name)
		if err != nil {
			return
		}
		if via != "" {
			keys[selector] = append(keys[selector], via)
		} else if _, ok := keys[selector]; !ok {
			keys[selector] = nil
		}
	}
	for _, name := range value.Countries {
		add(policy.Country, name, "")
	}
	for _, group := range value.Groups {
		members, ok := s.groups[group]
		if !ok {
			members, ok = catalog.Countries(group)
		}
		if !ok {
			continue
		}
		for _, country := range members {
			add(policy.Country, country, "group:"+group)
		}
	}
	for _, name := range value.RIRs {
		canonical, err := policy.CanonicalSelector(policy.RIR, name)
		if err != nil {
			continue
		}
		for _, country := range catalog.RIRCountries(canonical.Value) {
			add(policy.Country, country, "rir:"+canonical.Value)
		}
	}
	for _, name := range value.ASNs {
		add(policy.ASN, name, "")
	}
	for _, name := range value.IPLists {
		add(policy.IPList, name, "")
	}
	for _, name := range value.Providers {
		add(policy.Provider, name, "")
	}
	for selector, vias := range keys {
		sort.Strings(vias)
		keys[selector] = vias
	}
	out := make([]sourceRef, 0)
	for _, record := range s.records {
		vias, ok := keys[record.Selector]
		if !ok {
			continue
		}
		out = append(out, sourceRef{record: record, via: append([]string(nil), vias...)})
	}
	return out
}
