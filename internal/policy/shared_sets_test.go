package policy_test

import (
	"fmt"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func sharingConfig(t *testing.T, policies string) config.Config {
	t.Helper()
	return parseTestConfig(t, "version: 1\nfirewall:\n  backend: nftables\n  ipv4: true\n  ipv6: true\n  deny_action: drop\npolicies:\n"+policies)
}

func geoSets(plan policy.FamilyPlan) []policy.PrefixSet {
	var result []policy.PrefixSet
	for _, set := range plan.Sets {
		if strings.HasPrefix(set.ID, "geo/") {
			result = append(result, set)
		}
	}
	return result
}

func policyBindings(plan policy.FamilyPlan) map[string]string {
	result := make(map[string]string)
	for _, path := range plan.Paths {
		for _, rule := range path.Rules {
			if rule.Policy != "" && rule.Match.SetID != "" {
				result[rule.Policy] = rule.Match.SetID
			}
		}
	}
	return result
}

func TestSharedGeoRulesPreservePolicyIdentityAndEvaluation(t *testing.T) {
	cfg := sharingConfig(t, `  - name: zeta
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["22/tcp"]
    include:
      countries: [US]
  - name: beta
    priority: 20
    direction: ingress
    mode: allowlist
    traffic: [any]
    include:
      countries: [US]
  - name: alpha
    priority: 100
    direction: egress
    mode: allowlist
    traffic: [any]
    include:
      countries: [US]
`)
	snapshot := mustSnapshot(t, snapshotRecord{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}, ipv6: []netip.Prefix{mustPrefix("2600::/32")}})
	state, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for _, plan := range state.Families() {
		sets := geoSets(plan)
		if len(sets) != 1 || sets[0].ID != "geo/alpha" || len(sets[0].Prefixes) != 1 {
			t.Fatalf("expected one lexical representative per family: %#v", sets)
		}
		wantBindings := map[string]string{"alpha": "geo/alpha", "beta": "geo/alpha", "zeta": "geo/alpha"}
		if !reflect.DeepEqual(policyBindings(plan), wantBindings) {
			t.Fatalf("rules lost original policy identities: %#v", plan.Paths)
		}
		for _, path := range plan.Paths {
			wantRemote := policy.SourceAddress
			if path.Direction == policy.Egress {
				wantRemote = policy.DestinationAddress
			}
			if path.Remote != wantRemote || path.Processed.Kind != policy.Processed {
				t.Fatalf("path orientation/accounting changed: %#v", path)
			}
		}
		member, miss := "8.1.1.1", "9.1.1.1"
		if plan.Family == policy.IPv6 {
			member, miss = "2600::1", "2601::1"
		}
		for _, test := range []struct {
			direction policy.Direction
			address   string
			port      uint16
			action    policy.Action
			trace     string
		}{
			{policy.Ingress, member, 22, policy.Drop, "zeta"},
			{policy.Ingress, member, 80, policy.Return, "beta"},
			{policy.Ingress, miss, 22, policy.Return, "zeta"},
			{policy.Ingress, miss, 80, policy.Drop, "beta"},
			{policy.Egress, member, 22, policy.Return, "alpha"},
			{policy.Egress, miss, 80, policy.Drop, "alpha"},
		} {
			flow := testFlow{Family: plan.Family, Direction: test.direction, Source: netip.MustParseAddr(miss), Destination: netip.MustParseAddr(miss), Protocol: "tcp", Port: test.port, New: true}
			if test.direction == policy.Ingress {
				flow.Source = netip.MustParseAddr(test.address)
			} else {
				flow.Destination = netip.MustParseAddr(test.address)
			}
			got := evaluate(plan, flow, nil)
			if got.Action != test.action || got.Trace != test.trace || got.HasDenied != (test.action == policy.Drop) || got.Processed.Kind != policy.Processed {
				t.Fatalf("family %v flow %#v: got %#v, want %s/%s", plan.Family, flow, got, test.action, test.trace)
			}
			if got.HasDenied && (got.Denied.Reason != policy.GeoPolicy || got.Denied.Action != policy.Drop || got.Denied.Kind != policy.Denied) {
				t.Fatalf("denial accounting changed: %#v", got)
			}
			flow.Established = true
			if established := evaluate(plan, flow, nil); established.Action != policy.Return || established.Trace != "" || established.HasDenied {
				t.Fatalf("established guard changed: %#v", established)
			}
		}
	}
	// Input order does not affect either data object order or rule order.
	slices.Reverse(cfg.Policies)
	reordered, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(state.Families(), reordered.Families()) {
		t.Fatal("declaration reordering changed compiled output")
	}
	// Priority changes alter rule order but not the representative or memberships.
	for i := range cfg.Policies {
		if cfg.Policies[i].Name == "zeta" {
			cfg.Policies[i].Priority = 30
		}
	}
	reprioritized, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	for i, plan := range reprioritized.Families() {
		if !reflect.DeepEqual(plan.Sets, state.Families()[i].Sets) {
			t.Fatal("priority change altered representative or set ordering")
		}
		var ordered []string
		for _, rule := range findPath(t, plan, policy.Ingress).Rules {
			if rule.Match.SetID != "" && rule.Policy != "" {
				ordered = append(ordered, rule.Policy)
			}
		}
		if !reflect.DeepEqual(ordered, []string{"beta", "zeta"}) {
			t.Fatalf("priority order not preserved: %v", ordered)
		}
	}
}

func TestGeoSharingUsesEffectiveMembershipIndependentlyPerFamily(t *testing.T) {
	for _, test := range []struct {
		name                 string
		left, right, exclude string
		records              []snapshotRecord
		counts               [2]int
	}{
		{"different selectors", "countries: [US]", "asns: [AS64496]", "", []snapshotRecord{
			{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}, ipv6: []netip.Prefix{mustPrefix("2600::/32")}},
			{kind: policy.ASN, value: "AS64496", ipv4: []netip.Prefix{mustPrefix("8.1.1.1/8"), mustPrefix("8.0.0.0/9")}, ipv6: []netip.Prefix{mustPrefix("2600::/32")}},
		}, [2]int{1, 1}},
		{"effective exclusion", "countries: [US]", "countries: [CA]", "    exclude:\n      countries: [DE]\n", []snapshotRecord{
			{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}},
			{kind: policy.Country, value: "CA", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8"), mustPrefix("9.0.0.0/8")}},
			{kind: policy.Country, value: "DE", ipv4: []netip.Prefix{mustPrefix("9.0.0.0/8")}},
		}, [2]int{1, 1}},
		{"partial overlap", "countries: [US]", "countries: [CA]", "", []snapshotRecord{
			{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8"), mustPrefix("9.0.0.0/8")}},
			{kind: policy.Country, value: "CA", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8"), mustPrefix("11.0.0.0/8")}},
		}, [2]int{2, 1}},
		{"exclusion creates inequality", "countries: [US]", "countries: [US]", "    exclude:\n      countries: [DE]\n", []snapshotRecord{
			{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}},
			{kind: policy.Country, value: "DE", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/9")}},
		}, [2]int{2, 1}},
		{"unequal subset", "countries: [US]", "countries: [CA]", "", []snapshotRecord{
			{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8"), mustPrefix("9.0.0.0/8")}},
			{kind: policy.Country, value: "CA", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}},
		}, [2]int{2, 1}},
		{"family divergence", "countries: [US]", "countries: [CA]", "", []snapshotRecord{
			{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}, ipv6: []netip.Prefix{mustPrefix("2600::/32")}},
			{kind: policy.Country, value: "CA", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}, ipv6: []netip.Prefix{mustPrefix("2601::/32")}},
		}, [2]int{1, 2}},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := sharingConfig(t, fmt.Sprintf(`  - name: zulu
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      %s
  - name: alpha
    priority: 20
    direction: egress
    mode: allowlist
    traffic: [any]
    include:
      %s
%s`, test.left, test.right, test.exclude))
			state, err := policy.Compile(cfg, mustSnapshot(t, test.records...))
			if err != nil {
				t.Fatal(err)
			}
			slices.Reverse(cfg.Policies)
			reordered, err := policy.Compile(cfg, mustSnapshot(t, test.records...))
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(state.Families(), reordered.Families()) {
				t.Fatal("reordering changed class ordering or bindings")
			}
			for i, plan := range state.Families() {
				sets := geoSets(plan)
				if len(sets) != test.counts[i] || sets[0].ID != "geo/alpha" {
					t.Fatalf("family %v: unexpected materialized classes %#v", plan.Family, sets)
				}
				bindings := policyBindings(plan)
				wantZulu := "geo/alpha"
				if test.counts[i] == 2 {
					wantZulu = "geo/zulu"
				}
				if bindings["zulu"] != wantZulu || bindings["alpha"] != "geo/alpha" {
					t.Fatalf("family %v: incorrect bindings %v", plan.Family, bindings)
				}
			}
		})
	}
}

func TestGeoSharingExcludesInapplicableFamiliesAndOtherSetKinds(t *testing.T) {
	cfg := sharingConfig(t, `  - name: zulu
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
  - name: alpha
    priority: 10
    direction: egress
    mode: allowlist
    traffic: [any]
    include:
      countries: [US]
  - name: aardvark-v4
    priority: 20
    direction: ingress
    mode: blocklist
    traffic: [icmp]
    include:
      countries: [US]
  - name: aardvark-v6
    priority: 30
    direction: ingress
    mode: blocklist
    traffic: [icmpv6]
    include:
      countries: [US]
`)
	cfg.Global.Allowlist = []netip.Prefix{mustPrefix("8.0.0.0/8")}
	cfg.Global.Blocklist = []netip.Prefix{mustPrefix("8.0.0.0/8")}
	cfg.CrowdSec.Enabled = true
	state, err := policy.Compile(cfg, mustSnapshot(t, snapshotRecord{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}}))
	if err != nil {
		t.Fatal(err)
	}
	for _, plan := range state.Families() {
		want, absent := "aardvark-v4", "aardvark-v6"
		if plan.Family == policy.IPv6 {
			want, absent = absent, want
		}
		sets := geoSets(plan)
		if len(sets) != 1 || sets[0].ID != "geo/"+want {
			t.Fatalf("applicability changed representative: %#v", sets)
		}
		if plan.Family == policy.IPv6 && len(sets[0].Prefixes) != 0 {
			t.Fatalf("applicable empty family lost empty membership: %#v", sets)
		}
		bindings := policyBindings(plan)
		if len(bindings) != 3 || bindings[want] != sets[0].ID || bindings["alpha"] != sets[0].ID || bindings["zulu"] != sets[0].ID {
			t.Fatalf("incorrect family bindings: %v", bindings)
		}
		for _, path := range plan.Paths {
			for _, rule := range path.Rules {
				if rule.Policy == absent {
					t.Fatalf("inapplicable policy gained family rule: %#v", rule)
				}
			}
		}
		kinds := make(map[string]policy.SetKind)
		for _, set := range plan.Sets {
			kinds[set.ID] = set.Kind
		}
		if kinds["crowdsec"] != policy.DynamicCrowdSecSet || kinds["geo_eligible"] != policy.StaticSet {
			t.Fatalf("internal/dynamic sets were interned: %v", kinds)
		}
		if plan.Family == policy.IPv4 && (kinds["global_allowlist"] != policy.StaticSet || kinds["global_blocklist"] != policy.StaticSet || len(plan.Sets) != 5) {
			t.Fatalf("equal global memberships were interned: %#v", plan.Sets)
		}
	}
}
