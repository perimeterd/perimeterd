package policy_test

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

type snapshotRecord struct {
	kind  policy.SelectorKind
	value string
	ipv4  []netip.Prefix
	ipv6  []netip.Prefix
}

func parseTestConfig(t *testing.T, text string) config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

func mustPrefix(value string) netip.Prefix {
	return netip.MustParsePrefix(value)
}

func mustSnapshot(t *testing.T, records ...snapshotRecord) policy.Snapshot {
	t.Helper()
	resolved := make([]policy.ResolvedSelector, 0, len(records))
	for _, record := range records {
		selector, err := policy.CanonicalSelector(record.kind, record.value)
		if err != nil {
			t.Fatalf("canonical selector %s/%s: %v", record.kind, record.value, err)
		}
		resolved = append(resolved, policy.ResolvedSelector{
			Selector: selector,
			IPv4:     append([]netip.Prefix(nil), record.ipv4...),
			IPv6:     append([]netip.Prefix(nil), record.ipv6...),
		})
	}
	snapshot, err := policy.NewSnapshot(resolved)
	if err != nil {
		t.Fatalf("new snapshot: %v", err)
	}
	return snapshot
}

func TestCompileCanonicalEmptyStateAndActiveArtifacts(t *testing.T) {
	base := `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
`
	allowOnly := parseTestConfig(t, base+`global:
  allowlist: [8.0.0.0/8]
`)
	state, err := policy.Compile(allowOnly, mustSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	if !state.Empty() || len(state.Families()) != 0 {
		t.Fatalf("allow-only configuration must compile to the canonical empty state: %#v", state.Families())
	}

	block := parseTestConfig(t, base+`global:
  blocklist: [9.0.0.0/8]
`)
	state, err = policy.Compile(block, mustSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	if state.Empty() || len(state.Families()) != 2 {
		t.Fatalf("global block must retain both enabled family paths: empty=%v families=%d", state.Empty(), len(state.Families()))
	}
	for _, family := range state.Families() {
		if len(family.Paths) != 2 {
			t.Fatalf("global block must compile ingress and egress paths: %#v", family.Paths)
		}
	}

	crowdsec := parseTestConfig(t, base+`crowdsec:
  enabled: true
  api_key_file: /run/secrets/crowdsec
`)
	state, err = policy.Compile(crowdsec, mustSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	if state.Empty() || len(state.Families()) != 2 {
		t.Fatalf("enabled CrowdSec must retain its dynamic path even with no decisions: empty=%v families=%d", state.Empty(), len(state.Families()))
	}
	for _, family := range state.Families() {
		plan := findPlan(t, state, family.Family, policy.Ingress)
		foundDynamic := false
		for _, set := range plan.Sets {
			if set.Kind == policy.DynamicCrowdSecSet {
				foundDynamic = true
				if len(set.Prefixes) != 0 {
					t.Fatalf("dynamic set must not capture decisions: %#v", set)
				}
			}
		}
		if !foundDynamic {
			t.Fatalf("missing CrowdSec dynamic set in %v plan", family.Family)
		}
	}
}

func TestCompileRejectsActiveConfigurationWithoutEnabledFamilies(t *testing.T) {
	base := `version: 1
firewall:
  backend: nftables
  ipv4: false
  ipv6: false
`
	empty := parseTestConfig(t, base)
	state, err := policy.Compile(empty, mustSnapshot(t))
	if err != nil {
		t.Fatalf("genuinely empty all-disabled configuration must remain valid: %v", err)
	}
	if !state.Empty() {
		t.Fatal("genuinely empty all-disabled configuration must remain canonical empty")
	}

	active := parseTestConfig(t, base+`global:
  blocklist: [9.0.0.0/8]
`)
	state, err = policy.Compile(active, mustSnapshot(t))
	if err == nil || !state.Empty() {
		t.Fatalf("active global block with both families disabled must fail without returning partial state: state=%#v err=%v", state.Families(), err)
	}

	crowdsec := parseTestConfig(t, base+`crowdsec:
  enabled: true
  api_key_file: /run/secrets/crowdsec
`)
	state, err = policy.Compile(crowdsec, mustSnapshot(t))
	if err == nil || !state.Empty() {
		t.Fatalf("enabled CrowdSec with both families disabled must fail without returning partial state: state=%#v err=%v", state.Families(), err)
	}

	geo := parseTestConfig(t, base+`policies:
  - name: geo
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
`)
	snapshot := mustSnapshot(t, snapshotRecord{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}})
	state, err = policy.Compile(geo, snapshot)
	if err == nil || !state.Empty() {
		t.Fatalf("enabled geo policy with both families disabled must fail without returning partial state: state=%#v err=%v", state.Families(), err)
	}
}

func TestCompileRetainsShadowedDeniesAndEnabledCrowdSec(t *testing.T) {
	base := `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
`
	shadowed := parseTestConfig(t, base+`global:
  allowlist: [0.0.0.0/0, "::/0"]
  blocklist: [0.0.0.0/0, "::/0"]
crowdsec:
  enabled: true
  api_key_file: /run/secrets/crowdsec
`)
	state, err := policy.Compile(shadowed, mustSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	if state.Empty() {
		t.Fatal("shadowed global deny and enabled CrowdSec must remain active artifacts")
	}
	for _, family := range state.Families() {
		plan := findPlan(t, state, family.Family, policy.Ingress)
		foundBlock, foundDynamic := false, false
		for _, rule := range findPath(t, plan, policy.Ingress).Rules {
			foundBlock = foundBlock || rule.Counter.Kind == policy.Denied && rule.Counter.Reason == policy.GlobalBlocklist
			foundDynamic = foundDynamic || rule.Counter.Kind == policy.Denied && rule.Counter.Reason == policy.CrowdSec
		}
		if !foundBlock || !foundDynamic {
			t.Fatalf("shadowed deny/CrowdSec artifacts disappeared from %v plan: %#v", family.Family, plan.Sets)
		}
	}
}

func TestCompileRejectsMissingAndOverallEmptyEnabledSelectors(t *testing.T) {
	cfg := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
policies:
  - name: geo
    priority: 10
    direction: ingress
    mode: allowlist
    traffic: [any]
    include:
      countries: [US]
`)
	if _, err := policy.Compile(cfg, mustSnapshot(t)); err == nil {
		t.Fatal("missing required selector record must fail compilation")
	}
	empty := mustSnapshot(t, snapshotRecord{kind: policy.Country, value: "US", ipv4: []netip.Prefix{}, ipv6: []netip.Prefix{}})
	if _, err := policy.Compile(cfg, empty); err == nil {
		t.Fatal("enabled policy empty in every family must fail compilation")
	}
}

func TestCompileSelectorUnionSubtractionAcrossCategoriesAndFamilies(t *testing.T) {
	cfg := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
policies:
  - name: selected
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US, CN]
      asns: [AS64496]
    exclude:
      countries: [CA, DE]
      asns: [AS64497]
`)
	snapshot := mustSnapshot(t,
		snapshotRecord{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}, ipv6: []netip.Prefix{mustPrefix("2600::/32")}},
		snapshotRecord{kind: policy.Country, value: "CN", ipv4: []netip.Prefix{mustPrefix("9.0.0.0/8")}, ipv6: []netip.Prefix{mustPrefix("2a00::/12")}},
		snapshotRecord{kind: policy.ASN, value: "AS64496", ipv4: []netip.Prefix{mustPrefix("11.0.0.0/8")}, ipv6: []netip.Prefix{mustPrefix("2800::/12")}},
		snapshotRecord{kind: policy.Country, value: "CA", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/9")}, ipv6: []netip.Prefix{mustPrefix("2600::/33")}},
		snapshotRecord{kind: policy.Country, value: "DE", ipv4: []netip.Prefix{mustPrefix("9.0.0.0/9")}, ipv6: []netip.Prefix{mustPrefix("2a00::/13")}},
		snapshotRecord{kind: policy.ASN, value: "AS64497", ipv4: []netip.Prefix{mustPrefix("11.0.0.0/9")}, ipv6: []netip.Prefix{mustPrefix("2800::/13")}},
	)
	state, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	plan := findPlan(t, state, policy.IPv4, policy.Ingress)
	var geo policy.PrefixSet
	for _, set := range plan.Sets {
		if set.Kind == policy.StaticSet && len(set.Prefixes) > 0 {
			for _, prefix := range set.Prefixes {
				if prefix == mustPrefix("8.128.0.0/9") || prefix == mustPrefix("9.128.0.0/9") || prefix == mustPrefix("11.128.0.0/9") {
					geo = set
				}
			}
		}
	}
	if len(geo.Prefixes) == 0 {
		t.Fatal("compiled geo prefix set was not found")
	}
	if !containsPrefix(geo.Prefixes, mustPrefix("8.128.0.0/9")) || !containsPrefix(geo.Prefixes, mustPrefix("9.128.0.0/9")) || !containsPrefix(geo.Prefixes, mustPrefix("11.128.0.0/9")) {
		t.Fatalf("category subtraction did not retain the non-excluded halves: %v", geo.Prefixes)
	}
	if containsPrefix(geo.Prefixes, mustPrefix("8.0.0.0/9")) || containsPrefix(geo.Prefixes, mustPrefix("9.0.0.0/9")) || containsPrefix(geo.Prefixes, mustPrefix("11.0.0.0/9")) {
		t.Fatalf("category subtraction retained excluded halves: %v", geo.Prefixes)
	}
	plan6 := findPlan(t, state, policy.IPv6, policy.Ingress)
	if len(plan6.Sets) == 0 {
		t.Fatal("IPv6 selector subtraction must be compiled independently")
	}
}

func containsPrefix(prefixes []netip.Prefix, wanted netip.Prefix) bool {
	for _, prefix := range prefixes {
		if prefix == wanted {
			return true
		}
	}
	return false
}

func TestCompileFamilyEmptyAllowlistAndBlocklistAreExplicit(t *testing.T) {
	allowConfig := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
policies:
  - name: allow
    priority: 10
    direction: ingress
    mode: allowlist
    traffic: [any]
    include:
      countries: [US]
`)
	snapshot := mustSnapshot(t, snapshotRecord{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}, ipv6: []netip.Prefix{}})
	allowState, err := policy.Compile(allowConfig, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	v6 := findPlan(t, allowState, policy.IPv6, policy.Ingress)
	if len(v6.Sets) == 0 {
		t.Fatal("empty-family allowlist must retain an explicit policy set")
	}

	blockConfig := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
policies:
  - name: block
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
`)
	blockState, err := policy.Compile(blockConfig, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	v6 = findPlan(t, blockState, policy.IPv6, policy.Ingress)
	if len(v6.Sets) == 0 {
		t.Fatal("empty-family blocklist must retain an explicit policy set")
	}
}

func TestCompileDisabledEqualsRemovedAndDeclarationsAreDeterministic(t *testing.T) {
	withDisabled := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
policies:
  - name: disabled
    priority: 10
    direction: ingress
    mode: disabled
    traffic: ["22"]
    include:
      countries: [US]
  - name: active
    priority: 20
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
`)
	removed := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
policies:
  - name: active
    priority: 20
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
`)
	snapshot := mustSnapshot(t, snapshotRecord{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}, ipv6: []netip.Prefix{mustPrefix("2600::/32")}})
	withState, err := policy.Compile(withDisabled, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	removedState, err := policy.Compile(removed, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(withState.Families(), removedState.Families()) {
		t.Fatalf("disabled and removed policies must have equivalent model output:\n%#v\n%#v", withState.Families(), removedState.Families())
	}

	reordered := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
policies:
  - name: active
    priority: 20
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
  - name: other
    priority: 5
    direction: egress
    mode: allowlist
    traffic: [any]
    include:
      countries: [US]
`)
	declarationOrder := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
policies:
  - name: other
    priority: 5
    direction: egress
    mode: allowlist
    traffic: [any]
    include:
      countries: [US]
  - name: active
    priority: 20
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
`)
	first, err := policy.Compile(reordered, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	second, err := policy.Compile(declarationOrder, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(first.Families(), second.Families()) {
		t.Fatal("reordering independent-direction declarations changed compiled state")
	}
}

func TestSnapshotRejectsCanonicalDuplicatesAndPreservesOwnership(t *testing.T) {
	selectorUS, err := policy.CanonicalSelector(policy.Country, "us")
	if err != nil {
		t.Fatal(err)
	}
	selectorLower, err := policy.CanonicalSelector(policy.Country, "US")
	if err != nil {
		t.Fatal(err)
	}
	if selectorUS != selectorLower {
		t.Fatalf("country selector canonicalization mismatch: %#v %#v", selectorUS, selectorLower)
	}
	_, err = policy.NewSnapshot([]policy.ResolvedSelector{
		{Selector: selectorUS, IPv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}},
		{Selector: selectorLower, IPv4: []netip.Prefix{mustPrefix("9.0.0.0/8")}},
	})
	if err == nil {
		t.Fatal("duplicate canonical selector identities must be rejected")
	}

	inputPrefixes := []netip.Prefix{mustPrefix("8.0.0.0/8")}
	snapshot, err := policy.NewSnapshot([]policy.ResolvedSelector{{
		Selector: selectorUS,
		IPv4:     inputPrefixes,
		IPv6:     []netip.Prefix{mustPrefix("2600::/32")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	inputPrefixes[0] = mustPrefix("9.0.0.0/8")
	cfg := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
policies:
  - name: geo
    priority: 1
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
`)
	state, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	firstPlan := findPlan(t, state, policy.IPv4, policy.Ingress)
	families := state.Families()
	families[0].Sets[0].Prefixes = nil
	secondPlan := findPlan(t, state, policy.IPv4, policy.Ingress)
	if !reflect.DeepEqual(firstPlan, secondPlan) {
		t.Fatal("State.Families must return independent deep copies")
	}
	prefixes := firstPlan.Sets[0].Prefixes
	if len(prefixes) == 0 {
		t.Fatal("expected a compiled static set")
	}
	prefixes[0] = mustPrefix("9.0.0.0/8")
	again := findPlan(t, state, policy.IPv4, policy.Ingress)
	if again.Sets[0].Prefixes[0] == mustPrefix("9.0.0.0/8") {
		t.Fatal("model getter exposed mutable prefix storage")
	}
}

func TestCompileIPListAndMixedSelectors(t *testing.T) {
	cfg := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
ip_lists:
  zoom:
    url: https://example.com/zoom
policies:
  - name: mixed
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
      ip_lists: [zoom]
    exclude:
      countries: [CA]
  - name: list-only
    priority: 10
    direction: egress
    mode: allowlist
    traffic: [any]
    include:
      ip_lists: [zoom]
  - name: disabled-list
    priority: 20
    direction: ingress
    mode: disabled
    traffic: [any]
    include:
      ip_lists: [zoom]
`)
	required, err := policy.RequiredSelectors(cfg)
	if err != nil {
		t.Fatal(err)
	}
	wantRequired := []policy.Selector{
		{Kind: policy.Country, Value: "CA"},
		{Kind: policy.Country, Value: "US"},
		{Kind: policy.IPList, Value: "zoom"},
	}
	if !reflect.DeepEqual(required, wantRequired) {
		t.Fatalf("required selectors = %#v, want %#v", required, wantRequired)
	}

	snapshot := mustSnapshot(t,
		snapshotRecord{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}},
		snapshotRecord{kind: policy.Country, value: "CA", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/9")}},
		snapshotRecord{kind: policy.IPList, value: "zoom", ipv4: []netip.Prefix{mustPrefix("9.0.0.0/8")}, ipv6: []netip.Prefix{mustPrefix("2001:db8::/32")}},
	)
	state, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	ingress := findPlan(t, state, policy.IPv4, policy.Ingress)
	foundMixed := false
	for _, set := range ingress.Sets {
		if set.ID != "geo/mixed" {
			continue
		}
		foundMixed = true
		if !containsPrefix(set.Prefixes, mustPrefix("8.128.0.0/9")) || !containsPrefix(set.Prefixes, mustPrefix("9.0.0.0/8")) {
			t.Fatalf("mixed list/country union-subtraction was not compiled: %v", set.Prefixes)
		}
		if containsPrefix(set.Prefixes, mustPrefix("8.0.0.0/9")) {
			t.Fatalf("excluded country prefix remained in mixed policy: %v", set.Prefixes)
		}
	}
	if !foundMixed {
		t.Fatal("mixed policy set was not emitted")
	}
	egress := findPlan(t, state, policy.IPv6, policy.Egress)
	foundListOnly := false
	for _, set := range egress.Sets {
		if set.ID == "geo/list-only" {
			foundListOnly = containsPrefix(set.Prefixes, mustPrefix("2001:db8::/32"))
		}
	}
	if !foundListOnly {
		t.Fatal("list-only policy did not retain custom-list IPv6 prefixes")
	}
}
