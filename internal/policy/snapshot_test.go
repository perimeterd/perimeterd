package policy_test

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestSnapshotDistinguishesMissingFromExplicitEmpty(t *testing.T) {
	selector, err := policy.CanonicalSelector(policy.Country, "us")
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := policy.NewSnapshot([]policy.ResolvedSelector{{Selector: selector, IPv4: []netip.Prefix{}}})
	if err != nil {
		t.Fatal(err)
	}
	set, ok := snapshot.Lookup(selector)
	if !ok {
		t.Fatal("explicit empty selector was treated as missing")
	}
	if set.Len() != 0 || set.Prefixes() == nil {
		t.Fatalf("explicit empty selector has unexpected set: len=%d prefixes=%v", set.Len(), set.Prefixes())
	}
	missing, err := policy.CanonicalSelector(policy.Country, "ca")
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := snapshot.Lookup(missing); ok {
		t.Fatal("missing selector was reported as present")
	}
}

func TestNewSnapshotRejectsCanonicalCollisions(t *testing.T) {
	_, err := policy.NewSnapshot([]policy.ResolvedSelector{
		{Selector: policy.Selector{Kind: policy.Country, Value: "us"}},
		{Selector: policy.Selector{Kind: policy.Country, Value: "US"}},
	})
	if err == nil {
		t.Fatal("canonical selector collision was accepted")
	}
}

func TestNewSnapshotRejectsMalformedAndWrongFamilyPrefixes(t *testing.T) {
	tests := []struct {
		name   string
		record policy.ResolvedSelector
	}{
		{
			name: "malformed IPv4",
			record: policy.ResolvedSelector{
				Selector: policy.Selector{Kind: policy.Country, Value: "US"},
				IPv4:     []netip.Prefix{{}},
			},
		},
		{
			name: "IPv6 in IPv4",
			record: policy.ResolvedSelector{
				Selector: policy.Selector{Kind: policy.Country, Value: "US"},
				IPv4:     []netip.Prefix{netip.MustParsePrefix("::/0")},
			},
		},
		{
			name: "IPv4 in IPv6",
			record: policy.ResolvedSelector{
				Selector: policy.Selector{Kind: policy.Country, Value: "US"},
				IPv6:     []netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")},
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := policy.NewSnapshot([]policy.ResolvedSelector{test.record}); err == nil {
				t.Fatal("invalid snapshot record was accepted")
			}
		})
	}
}

func TestSnapshotCopiesInputAndLookupOutput(t *testing.T) {
	prefixes := []netip.Prefix{
		netip.MustParsePrefix("198.51.100.99/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	record := policy.ResolvedSelector{
		Selector: policy.Selector{Kind: policy.Country, Value: "US"},
		IPv4:     prefixes[:1],
		IPv6:     prefixes[1:],
	}
	snapshot, err := policy.NewSnapshot([]policy.ResolvedSelector{record})
	if err != nil {
		t.Fatal(err)
	}
	prefixes[0] = netip.MustParsePrefix("203.0.113.0/24")
	prefixes[1] = netip.MustParsePrefix("2001:db8:1::/48")
	record.IPv4[0] = netip.MustParsePrefix("192.0.2.0/24")

	selector, err := policy.CanonicalSelector(policy.Country, "us")
	if err != nil {
		t.Fatal(err)
	}
	set, ok := snapshot.Lookup(selector)
	if !ok {
		t.Fatal("snapshot selector disappeared")
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if got := set.Prefixes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot retained caller mutation: got %v want %v", got, want)
	}
	out := set.Prefixes()
	out[0] = netip.MustParsePrefix("192.0.2.0/24")
	if got := set.Prefixes(); !reflect.DeepEqual(got, want) {
		t.Fatalf("lookup output was not defensive: got %v want %v", got, want)
	}
}

func TestSnapshotSelectorsAreDeterministicallySorted(t *testing.T) {
	snapshot, err := policy.NewSnapshot([]policy.ResolvedSelector{
		{Selector: policy.Selector{Kind: policy.RIR, Value: "ripe"}},
		{Selector: policy.Selector{Kind: policy.ASN, Value: "AS3333"}},
		{Selector: policy.Selector{Kind: policy.Country, Value: "us"}},
		{Selector: policy.Selector{Kind: policy.Country, Value: "CA"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []policy.Selector{
		{Kind: policy.ASN, Value: "AS3333"},
		{Kind: policy.Country, Value: "CA"},
		{Kind: policy.Country, Value: "US"},
		{Kind: policy.RIR, Value: "RIPE"},
	}
	if got := snapshot.Selectors(); !reflect.DeepEqual(got, want) {
		t.Fatalf("snapshot selectors = %v, want %v", got, want)
	}
}

func TestRequiredSelectorsEnabledUnionAndDeterministicOrder(t *testing.T) {
	cfg := config.Config{Policies: []config.Policy{
		{
			Mode: "allowlist",
			Include: config.Selector{
				Countries:         []string{"US"},
				ExpandedCountries: []string{"CA", "US"},
				Groups:            []string{"partners"},
				RIRs:              []string{"arin"},
				ASNs:              []string{"AS3333"},
			},
			Exclude: config.Selector{
				Countries: []string{"CA"},
				RIRs:      []string{"RIPE"},
				ASNs:      []string{"AS64512"},
			},
		},
		{
			Mode: "disabled",
			Include: config.Selector{
				Countries:         []string{"DE"},
				ExpandedCountries: []string{"DE"},
				RIRs:              []string{"APNIC"},
				ASNs:              []string{"AS64513"},
			},
		},
	}}
	got, err := policy.RequiredSelectors(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) == 0 {
		t.Fatal("required selector expansion was empty")
	}
	for _, selector := range got {
		if selector.Kind == policy.RIR {
			t.Fatalf("RIR selector was not expanded: %v", selector)
		}
	}
	for _, want := range []policy.Selector{
		{Kind: policy.ASN, Value: "AS3333"},
		{Kind: policy.ASN, Value: "AS64512"},
		{Kind: policy.Country, Value: "CA"},
		{Kind: policy.Country, Value: "US"},
		{Kind: policy.Country, Value: "DE"},
	} {
		if !containsSelector(got, want) {
			t.Fatalf("required selectors missing %v: %v", want, got)
		}
	}
}

func containsSelector(values []policy.Selector, want policy.Selector) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestRequiredSelectorsRIRServiceRegionBoundaries(t *testing.T) {
	// These assignments cross M49 geographic boundaries or split the Caribbean.
	// Expected owners come from the RIR service-region table, not group expansion.
	owners := map[string]string{
		"TW": "APNIC", "IR": "RIPE", "CY": "RIPE", "KW": "RIPE",
		"EG": "AFRINIC", "GL": "RIPE", "DO": "LACNIC", "CW": "LACNIC",
		"AI": "ARIN", "SH": "ARIN", "IO": "APNIC", "HM": "ARIN",
	}
	all := make(map[policy.Selector]string)
	for _, rir := range []string{"AFRINIC", "APNIC", "ARIN", "LACNIC", "RIPE"} {
		cfg := config.Config{Policies: []config.Policy{{
			Mode: "blocklist", Include: config.Selector{RIRs: []string{rir}},
		}}}
		selectors, err := policy.RequiredSelectors(cfg)
		if err != nil {
			t.Fatal(err)
		}
		for _, selector := range selectors {
			if previous, exists := all[selector]; exists {
				t.Errorf("%s assigned to both %s and %s", selector.Value, previous, rir)
			}
			all[selector] = rir
		}
		for country, owner := range owners {
			found := containsSelector(selectors, policy.Selector{Kind: policy.Country, Value: country})
			if found != (owner == rir) {
				t.Errorf("%s membership in %s = %t; service-region owner is %s", country, rir, found, owner)
			}
		}
	}
	if len(all) != 249 {
		t.Fatalf("RIR service regions cover %d ISO countries, want 249", len(all))
	}
}

func TestRequiredSelectorsRejectsUnresolvedGroups(t *testing.T) {
	cfg := config.Config{Policies: []config.Policy{{
		Mode:    "blocklist",
		Include: config.Selector{Groups: []string{"not-expanded"}},
	}}}
	if _, err := policy.RequiredSelectors(cfg); err == nil {
		t.Fatal("unresolved group was silently ignored")
	}
}

func TestCanonicalSelectorASNSyntax(t *testing.T) {
	for _, value := range []string{"AS0", "AS3333", "AS4294967295"} {
		got, err := policy.CanonicalSelector(policy.ASN, value)
		if err != nil {
			t.Errorf("CanonicalSelector(%q): %v", value, err)
		}
		if got != (policy.Selector{Kind: policy.ASN, Value: value}) {
			t.Errorf("CanonicalSelector(%q) = %#v", value, got)
		}
	}
	for _, value := range []string{"", "3333", "as3333", "AS01", "AS4294967296", "AS+1", "AS1 "} {
		if _, err := policy.CanonicalSelector(policy.ASN, value); err == nil {
			t.Errorf("CanonicalSelector(%q) unexpectedly accepted", value)
		}
	}
	for _, test := range []struct {
		kind  policy.SelectorKind
		value string
		want  policy.Selector
	}{
		{kind: policy.Country, value: "us", want: policy.Selector{Kind: policy.Country, Value: "US"}},
		{kind: policy.RIR, value: "ripe", want: policy.Selector{Kind: policy.RIR, Value: "RIPE"}},
	} {
		got, err := policy.CanonicalSelector(test.kind, test.value)
		if err != nil {
			t.Errorf("CanonicalSelector(%s/%q): %v", test.kind, test.value, err)
			continue
		}
		if got != test.want {
			t.Errorf("CanonicalSelector(%s/%q) = %#v, want %#v", test.kind, test.value, got, test.want)
		}
	}

	for _, test := range []struct {
		kind  policy.SelectorKind
		value string
	}{
		{kind: policy.Country, value: "ZZ"},
		{kind: policy.RIR, value: "IANA"},
		{kind: policy.SelectorKind("unknown"), value: "value"},
	} {
		if _, err := policy.CanonicalSelector(test.kind, test.value); err == nil {
			t.Errorf("CanonicalSelector(%s/%q) unexpectedly accepted", test.kind, test.value)
		}
	}
}
