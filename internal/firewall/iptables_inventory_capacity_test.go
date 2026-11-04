package firewall

import (
	"errors"
	"net/netip"
	"strings"
	"testing"

	"github.com/perimeterd/perimeterd/internal/policy"
)

func requireIPTCapacityBoundary(t *testing.T, inventory *iptInventory, expected *iptExpected, required int64, resource string) {
	t.Helper()
	if err := validateIPTCapacityWithLimits(inventory, expected, 1<<30, required); err != nil {
		t.Fatalf("exact inventory boundary rejected: %v", err)
	}
	err := validateIPTCapacityWithLimits(inventory, expected, 1<<30, required-1)
	var capacity *CapacityError
	if !errors.As(err, &capacity) || capacity.Backend != "iptables" || capacity.Scope != "inventory" || capacity.Resource != resource || capacity.RequiredBytes != required || capacity.LimitBytes != required-1 || capacity.RecoveryRetryable() {
		t.Fatalf("lost numeric inventory boundary: %+v (%v)", capacity, err)
	}
}

func TestIPTCapacityObservedChainIdentityAndForeignBytes(t *testing.T) {
	declaration := ":pdshared - [17:29]\n"
	rule := "[17:29] -A pdshared -m comment --comment \"first line\nsecond line\" -j RETURN\n"
	foreign := ":FOREIGN - [0:0]\n-A FOREIGN -m comment --comment \"" + strings.Repeat("foreign", 100) + "\" -j RETURN\n"
	data := []byte("*filter\n" + declaration + foreign + rule + "COMMIT\n")
	inventory, err := parseIPTablesSave(policy.IPv4, data)
	if err != nil {
		t.Fatal(err)
	}
	inventory.TableBytes[policy.IPv4] = int64(len(data))
	key := chainKey(policy.IPv4, "pdshared")
	observed := inventory.Chains[key]
	if want := int64(len(declaration) + len(rule)); observed.SerializedBytes != want {
		t.Fatalf("complete serialized chain bytes = %d, want %d", observed.SerializedBytes, want)
	}
	chain := iptChain{Name: key.Chain, Rules: []iptRule{{Args: observed.Rules[0].Args}}}
	expected := &iptExpected{chains: map[iptChainKey][]iptChain{key: {chain, chain}}}
	t.Run("reused identity costs once", func(t *testing.T) {
		requireIPTCapacityBoundary(t, inventory, expected, int64(len(data)), "ipv4-rules")
	})
	t.Run("larger replacement adds only observed difference", func(t *testing.T) {
		larger := iptChain{Name: chain.Name, Rules: []iptRule{{Args: []string{"-m", "comment", "--comment", strings.Repeat("replacement", 100), "-j", "RETURN"}}}}
		expected := &iptExpected{chains: map[iptChainKey][]iptChain{key: {chain, larger}}}
		required := int64(len(data)) + iptChainInspectionSize(larger) - observed.SerializedBytes
		requireIPTCapacityBoundary(t, inventory, expected, required, "ipv4-rules")
	})
	t.Run("distinct chain retains foreign bytes", func(t *testing.T) {
		distinct := iptChain{Name: "pddistinct", Rules: chain.Rules}
		expected := &iptExpected{chains: map[iptChainKey][]iptChain{key: {chain}, chainKey(policy.IPv4, distinct.Name): {distinct}}}
		requireIPTCapacityBoundary(t, inventory, expected, int64(len(data))+iptChainInspectionSize(distinct), "ipv4-rules")
	})
	t.Run("missing observation never subtracts estimate", func(t *testing.T) {
		withoutMeasurement := *inventory
		withoutMeasurement.Chains = map[iptChainKey]iptObservedChain{key: {iptChainKey: key, Rules: observed.Rules}}
		requireIPTCapacityBoundary(t, &withoutMeasurement, expected, int64(len(data))+iptChainInspectionSize(chain), "ipv4-rules")
	})
}

func TestIPTCapacityStaticDynamicAndResizePeak(t *testing.T) {
	static := iptSet{Name: "pdstatic", Family: policy.IPv4, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}}
	live := iptSet{Name: "pdddlive", Family: policy.IPv4, Dynamic: true, DynamicProjection: true, Prefixes: []netip.Prefix{netip.MustParsePrefix("198.51.100.1/32"), netip.MustParsePrefix("198.51.100.3/32")}}
	spareName := iptDynamicSpareName(live.Name)
	for _, test := range []struct {
		name       string
		capacity   string
		spareBytes int64
		resize     bool
	}{
		{name: "in place", capacity: "8"},
		{name: "resize keeps old and populated spare", capacity: "1", resize: true},
		{name: "resize replaces existing spare", capacity: "1", spareBytes: 200, resize: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			inventory := newIPTInventory()
			const oldBytes = int64(1200)
			inventory.SetBytes = oldBytes + test.spareBytes
			inventory.Sets[live.Name] = iptObservedSet{InspectionBytes: oldBytes, Options: []string{"maxelem", test.capacity}}
			if test.spareBytes != 0 {
				inventory.Sets[spareName] = iptObservedSet{InspectionBytes: test.spareBytes}
			}
			spare := live
			spare.Name = spareName
			expected := &iptExpected{sets: map[string]iptSet{static.Name: static, live.Name: live, spareName: spare}}
			peak := ipsetInspectionSize(live)
			if test.resize {
				peak += oldBytes
			}
			required := max(inventory.SetBytes, peak) + ipsetInspectionSize(static)
			requireIPTCapacityBoundary(t, inventory, expected, required, "ipsets")
		})
	}
}

func TestIPTCapacityDeterministicResourcesAndInputBoundary(t *testing.T) {
	inventory := newIPTInventory()
	inventory.SetBytes = 100
	inventory.TableBytes[policy.IPv4] = 100
	inventory.TableBytes[policy.IPv6] = 100
	expected := &iptExpected{}
	requireIPTCapacityBoundary(t, inventory, expected, 100, "ipsets")
	inventory.SetBytes = 0
	requireIPTCapacityBoundary(t, inventory, expected, 100, "ipv4-rules")
	inventory.TableBytes[policy.IPv4] = 0
	requireIPTCapacityBoundary(t, inventory, expected, 100, "ipv6-rules")

	inventory = newIPTInventory()
	target := &Target{Generation: "static", DynamicGeneration: "dynamic"}
	chain := iptChain{Name: "pdinput", Rules: []iptRule{{Args: []string{"-j", "RETURN"}}}}
	expected = &iptExpected{models: map[*Target]map[policy.Family]iptFamilyModel{target: {policy.IPv6: {Staging: []iptChain{chain}}}}}
	required := int64(4096) + iptChainInspectionSize(chain)
	if err := validateIPTCapacityWithLimits(inventory, expected, required, 1<<30); err != nil {
		t.Fatal(err)
	}
	var capacity *CapacityError
	err := validateIPTCapacityWithLimits(inventory, expected, required-1, 1<<30)
	if !errors.As(err, &capacity) || capacity.Scope != "input" || capacity.Resource != "ipv6-rules" || capacity.RequiredBytes != required || capacity.LimitBytes != required-1 || capacity.StaticGenerations != 1 || capacity.DynamicGenerations != 1 {
		t.Fatalf("lost numeric family input boundary: %+v (%v)", capacity, err)
	}
}

func TestIPTCapacityAttachmentPeakDeduplicatesIdentities(t *testing.T) {
	inventory := newIPTInventory()
	attachment := iptAttachment{Parent: "INPUT", Rule: iptRule{Args: []string{"-j", "pdentry"}}}
	first, second := &Target{}, &Target{}
	model := iptFamilyModel{Attachments: []iptAttachment{attachment}}
	expected := &iptExpected{models: map[*Target]map[policy.Family]iptFamilyModel{first: {policy.IPv4: model}, second: {policy.IPv4: model}}}
	required := iptChainInspectionSize(iptChain{Name: attachment.Parent, Rules: []iptRule{attachment.Rule}})
	requireIPTCapacityBoundary(t, inventory, expected, required, "ipv4-rules")
	key := chainKey(policy.IPv4, attachment.Parent)
	inventory.Chains[key] = iptObservedChain{iptChainKey: key, Rules: []iptObservedRule{{Args: attachment.Rule.Args}}}
	inventory.TableBytes[policy.IPv4] = 80
	requireIPTCapacityBoundary(t, inventory, expected, 80, "ipv4-rules")
}

func TestIPTCapacityStaticSetIdentityUnion(t *testing.T) {
	first := iptSet{Name: "pdstaticfirst", Family: policy.IPv4, Prefixes: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")}}
	second := first
	second.Name = "pdstaticsecond"
	one := &iptExpected{sets: map[string]iptSet{first.Name: first}}
	inventory := newIPTInventory()
	requireIPTCapacityBoundary(t, inventory, one, ipsetInspectionSize(first), "ipsets")
	distinct := &iptExpected{sets: map[string]iptSet{first.Name: first, second.Name: second}}
	requireIPTCapacityBoundary(t, inventory, distinct, ipsetInspectionSize(first)+ipsetInspectionSize(second), "ipsets")
	// Fully observed static sets remain one object, not an extra staging copy.
	inventory.SetBytes = ipsetInspectionSize(first)
	inventory.Sets[first.Name] = iptObservedSet{InspectionBytes: inventory.SetBytes}
	requireIPTCapacityBoundary(t, inventory, one, inventory.SetBytes, "ipsets")
}
