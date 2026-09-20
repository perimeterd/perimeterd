// Package policy contains the backend-neutral policy compiler and its immutable inputs.
package policy

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/config/catalog"
	"github.com/perimeterd/perimeterd/internal/prefix"
)

// SelectorKind identifies the source namespace of a resolved selector.
type SelectorKind string

const (
	// Country selects a country by its ISO-3166-1 alpha-2 code.
	Country SelectorKind = "country"
	// RIR selects a Regional Internet Registry service region.
	RIR SelectorKind = "rir"
	// ASN selects an autonomous system number.
	ASN SelectorKind = "asn"
	// IPList selects a named configured HTTP(S) text list.
	IPList SelectorKind = "ip_list"
)

// Selector is a canonical source identity used as a snapshot key.
type Selector struct {
	Kind  SelectorKind
	Value string
}

// Less reports the canonical selector order used by policy snapshots and source
// manifests: namespace first, then the canonical value, both lexicographically.
func (s Selector) Less(other Selector) bool {
	if s.Kind != other.Kind {
		return s.Kind < other.Kind
	}
	return s.Value < other.Value
}

// CanonicalSelector validates and canonicalizes one source identity.
// Countries and RIR names are case-insensitive; ASNs must already use the
// canonical AS<number> spelling used by normalized configuration.
func CanonicalSelector(kind SelectorKind, value string) (Selector, error) {
	canonical := Selector{Kind: kind, Value: value}
	switch kind {
	case Country:
		canonical.Value = strings.ToUpper(value)
		if !catalog.ValidCountry(canonical.Value) {
			return Selector{}, fmt.Errorf("unknown country selector %q", value)
		}
	case RIR:
		canonical.Value = strings.ToUpper(value)
		if !catalog.ValidRIR(canonical.Value) {
			return Selector{}, fmt.Errorf("unknown RIR selector %q", value)
		}
	case ASN:
		if !catalog.ValidASN(value) {
			return Selector{}, fmt.Errorf("ASN selector %q must use canonical AS<number> form", value)
		}
	case IPList:
		if !config.ValidName(value) {
			return Selector{}, fmt.Errorf("IP list selector %q must use a lowercase DNS-label-like name", value)
		}
		canonical.Value = value
	default:
		return Selector{}, fmt.Errorf("unknown selector kind %q", kind)
	}
	return canonical, nil
}

// ResolvedSelector is one complete source result, including explicit empty
// family results. An omitted record is distinct from an empty record.
type ResolvedSelector struct {
	Selector Selector
	IPv4     []netip.Prefix
	IPv6     []netip.Prefix
}

// Snapshot is an immutable collection of complete, canonical selector results.
// Its zero value is an empty snapshot.
type Snapshot struct {
	entries map[Selector]prefix.Set
}

// NewSnapshot validates, canonicalizes, and copies resolved selector records.
// Prefixes are masked, deduplicated, and reduced to canonical non-containing
// sets. A record with no prefixes is retained as a valid explicit empty result.
func NewSnapshot(records []ResolvedSelector) (Snapshot, error) {
	entries := make(map[Selector]prefix.Set, len(records))
	for i, record := range records {
		selector, err := CanonicalSelector(record.Selector.Kind, record.Selector.Value)
		if err != nil {
			return Snapshot{}, fmt.Errorf("snapshot record %d: %w", i, err)
		}
		if _, exists := entries[selector]; exists {
			return Snapshot{}, fmt.Errorf("snapshot record %d: duplicate selector %s/%s", i, selector.Kind, selector.Value)
		}

		if err := validateFamily(record.IPv4, true, i, selector); err != nil {
			return Snapshot{}, err
		}
		if err := validateFamily(record.IPv6, false, i, selector); err != nil {
			return Snapshot{}, err
		}
		v4, err := prefix.New(record.IPv4)
		if err != nil {
			return Snapshot{}, fmt.Errorf("snapshot record %d %s/%s IPv4: %w", i, selector.Kind, selector.Value, err)
		}
		v6, err := prefix.New(record.IPv6)
		if err != nil {
			return Snapshot{}, fmt.Errorf("snapshot record %d %s/%s IPv6: %w", i, selector.Kind, selector.Value, err)
		}
		entries[selector] = prefix.Union(v4, v6)
	}
	return Snapshot{entries: entries}, nil
}

func validateFamily(prefixes []netip.Prefix, ipv4 bool, index int, selector Selector) error {
	for j, candidate := range prefixes {
		if !candidate.IsValid() {
			return fmt.Errorf("snapshot record %d %s/%s prefix %s[%d]: malformed prefix", index, selector.Kind, selector.Value, familyName(ipv4), j)
		}
		if candidate.Addr().Is4() != ipv4 {
			return fmt.Errorf("snapshot record %d %s/%s prefix %s[%d]: wrong address family", index, selector.Kind, selector.Value, familyName(ipv4), j)
		}
	}
	return nil
}

func familyName(ipv4 bool) string {
	if ipv4 {
		return "IPv4"
	}
	return "IPv6"
}

// Lookup returns the immutable set for a canonical selector. The boolean is
// false only when that selector is absent; an explicit empty record returns
// true with a valid empty set.
func (s Snapshot) Lookup(selector Selector) (prefix.Set, bool) {
	set, ok := s.entries[selector]
	return set, ok
}

// Selectors returns canonical snapshot keys sorted by kind and then value.
func (s Snapshot) Selectors() []Selector {
	selectors := make([]Selector, 0, len(s.entries))
	for selector := range s.entries {
		selectors = append(selectors, selector)
	}
	sort.Slice(selectors, func(i, j int) bool {
		if selectors[i].Kind != selectors[j].Kind {
			return selectors[i].Kind < selectors[j].Kind
		}
		return selectors[i].Value < selectors[j].Value
	})
	return selectors
}

// RequiredSelectors returns the canonical source identities needed by enabled
// policies, including both include and exclude selectors. Groups and RIRs are
// expanded to their deterministic country memberships; source lookup is not
// performed here.
func RequiredSelectors(cfg config.Config) ([]Selector, error) {
	seen := make(map[Selector]struct{})
	for i, policy := range cfg.Policies {
		if policy.Mode == "disabled" {
			continue
		}
		for _, selection := range []struct {
			name string
			data config.Selector
		}{
			{name: "include", data: policy.Include},
			{name: "exclude", data: policy.Exclude},
		} {
			selectors, err := selectorKeys(selection.data)
			if err != nil {
				return nil, fmt.Errorf("policy %d %s: %w", i, selection.name, err)
			}
			for _, selector := range selectors {
				seen[selector] = struct{}{}
			}
		}
	}
	selectors := make([]Selector, 0, len(seen))
	for selector := range seen {
		selectors = append(selectors, selector)
	}
	sortSelectors(selectors)
	return selectors, nil
}

// selectorKeys converts one normalized configuration selector to canonical
// source identities. It is deliberately package-private because the compiler
// uses it while enforcing the same selector expansion contract.
func selectorKeys(selection config.Selector) ([]Selector, error) {
	if len(selection.Groups) > 0 && len(selection.ExpandedCountries) == 0 {
		return nil, fmt.Errorf("groups are unresolved")
	}
	seen := make(map[Selector]struct{}, len(selection.Countries)+len(selection.ExpandedCountries)+len(selection.RIRs)+len(selection.ASNs)+len(selection.IPLists))
	addCountry := func(value string) error {
		selector, err := CanonicalSelector(Country, value)
		if err != nil {
			return err
		}
		seen[selector] = struct{}{}
		return nil
	}
	for _, country := range append(append([]string{}, selection.Countries...), selection.ExpandedCountries...) {
		if err := addCountry(country); err != nil {
			return nil, err
		}
	}
	for _, rir := range selection.RIRs {
		selector, err := CanonicalSelector(RIR, rir)
		if err != nil {
			return nil, err
		}
		for _, country := range catalog.RIRCountries(selector.Value) {
			if err := addCountry(country); err != nil {
				return nil, fmt.Errorf("RIR %s: %w", selector.Value, err)
			}
		}
	}
	for _, asn := range selection.ASNs {
		selector, err := CanonicalSelector(ASN, asn)
		if err != nil {
			return nil, err
		}
		seen[selector] = struct{}{}
	}
	for _, list := range selection.IPLists {
		selector, err := CanonicalSelector(IPList, list)
		if err != nil {
			return nil, err
		}
		seen[selector] = struct{}{}
	}
	selectors := make([]Selector, 0, len(seen))
	for selector := range seen {
		selectors = append(selectors, selector)
	}
	sortSelectors(selectors)
	return selectors, nil
}

func sortSelectors(selectors []Selector) {
	sort.Slice(selectors, func(i, j int) bool {
		return selectors[i].Less(selectors[j])
	})
}
