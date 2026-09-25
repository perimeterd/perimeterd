package lookup_test

import (
	"context"
	"fmt"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/lookup"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
)

func buildStatic(t *testing.T, text string, records ...policy.ResolvedSelector) (*lookup.Static, config.Config) {
	t.Helper()
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	cache, err := source.NewCache(filepath.Join(t.TempDir(), "state"), nil)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	sourceRecords := make([]source.Record, 0, len(records))
	for _, record := range records {
		sourceRecords = append(sourceRecords, source.Record{
			Selector:   record.Selector,
			Endpoint:   "https://stat.ripe.net/data/country-resource-list/data.json",
			APIVersion: "0.2",
			Parameters: map[string]string{"resource": record.Selector.Value, "sourceapp": "perimeterd", "v4_format": "prefix"},
			QueryStart: when, QueryEnd: when, RetrievedAt: when,
			IPv4: record.IPv4, IPv6: record.IPv6,
		})
	}
	snapshot, err := cache.Stage(sourceRecords)
	if err != nil {
		t.Fatal(err)
	}
	state, err := policy.Compile(cfg, snapshot.Policy())
	if err != nil {
		t.Fatal(err)
	}
	target, err := firewall.BuildTarget("11111111111111111111111111111111", "22222222222222222222222222222222", cfg, state, nil)
	if err != nil {
		t.Fatal(err)
	}
	static, err := lookup.NewStatic(cfg, target, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	return static, cfg
}

func TestNewStaticOwnsTargetFamilies(t *testing.T) {
	cfg, err := config.Parse([]byte(`version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: false
policies:
  - name: owned
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["80", "443/udp"]
    include:
      countries: [US]
`))
	if err != nil {
		t.Fatal(err)
	}
	cache, err := source.NewCache(filepath.Join(t.TempDir(), "state"), nil)
	if err != nil {
		t.Fatal(err)
	}
	when := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	snapshot, err := cache.Stage([]source.Record{{
		Selector:   policy.Selector{Kind: policy.Country, Value: "US"},
		Endpoint:   "https://stat.ripe.net/data/country-resource-list/data.json",
		APIVersion: "0.2",
		Parameters: map[string]string{"resource": "US", "sourceapp": "perimeterd", "v4_format": "prefix"},
		QueryStart: when, QueryEnd: when, RetrievedAt: when,
		IPv4: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/8")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	model, err := policy.Compile(cfg, snapshot.Policy())
	if err != nil {
		t.Fatal(err)
	}
	target, err := firewall.BuildTarget("11111111111111111111111111111111", "22222222222222222222222222222222", cfg, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	static, err := lookup.NewStatic(cfg, target, snapshot)
	if err != nil {
		t.Fatal(err)
	}

	var family *policy.FamilyPlan
	for i := range target.Families {
		if target.Families[i].Family == policy.IPv4 {
			family = &target.Families[i]
			break
		}
	}
	if family == nil {
		t.Fatal("compiled target has no IPv4 family")
	}
	var prefixMutated, ruleMutated bool
	for setIndex := range family.Sets {
		set := &family.Sets[setIndex]
		if set.ID == "geo/owned" {
			if len(set.Prefixes) != 1 {
				t.Fatalf("compiled geo set prefixes = %#v", set.Prefixes)
			}
			set.Prefixes[0] = netip.MustParsePrefix("9.0.0.0/8")
			prefixMutated = true
		}
	}
	for pathIndex := range family.Paths {
		path := &family.Paths[pathIndex]
		if path.Direction != policy.Ingress {
			continue
		}
		path.Direction = policy.Egress
		for ruleIndex := range path.Rules {
			rule := &path.Rules[ruleIndex]
			if rule.Policy != "owned" || rule.Counter.Kind != policy.Denied {
				continue
			}
			if len(rule.Match.Traffic.TCP) != 1 || len(rule.Match.Traffic.UDP) != 1 {
				t.Fatalf("compiled policy traffic ranges = %#v", rule.Match.Traffic)
			}
			rule.Policy = "mutated"
			rule.Action = policy.Return
			rule.Match.SetID = "missing"
			rule.Match.Traffic.TCP[0].Start = 81
			rule.Match.Traffic.UDP[0].Start = 444
			ruleMutated = true
		}
	}
	if !prefixMutated || !ruleMutated {
		t.Fatalf("ownership fixture did not expose all nested family fields (prefix=%v, rule=%v)", prefixMutated, ruleMutated)
	}

	assertOwnedBlock := func(protocol string, port uint16) {
		t.Helper()
		response := lookup.Evaluate(context.Background(), static, lookup.Dynamic{}, lookup.Request{
			Address: "8.1.1.1", Direction: policy.Ingress, Protocol: protocol, Port: ptr(port),
		}, when)
		if response.Verdict != "blocked" || len(response.Outcomes) != 1 ||
			response.Outcomes[0].Policy != "owned" || response.Outcomes[0].Action != policy.Drop {
			t.Fatalf("%s/%d lookup changed after mutating constructor target: %#v", protocol, port, response)
		}
		if !response.Outcomes[0].Prefix.Contains(netip.MustParseAddr("8.1.1.1")) {
			t.Fatalf("%s/%d lookup returned unrelated prefix: %#v", protocol, port, response.Outcomes[0])
		}
	}
	assertOwnedBlock("tcp", 80)
	assertOwnedBlock("udp", 443)
}

func TestNormalizeRejectsZonesAndMappedIPv6BeforeMasking(t *testing.T) {
	for _, address := range []string{"fe80::1%eth0", "2001:db8::1%eth0/128", "::ffff:192.0.2.1/80", "::ffff:192.0.2.1"} {
		if _, err := lookup.Normalize(lookup.Request{Address: address}); err == nil {
			t.Fatalf("Normalize(%q) accepted invalid mapped/zoned address", address)
		}
	}
}

func TestEvaluateCanonicalCIDRPartitionAndFirstPolicyPass(t *testing.T) {
	static, _ := buildStatic(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: false
policies:
  - name: narrow
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["80"]
    include:
      countries: [US]
  - name: broad
    priority: 20
    direction: ingress
    mode: allowlist
    traffic: [any]
    include:
      countries: [US]
`, policy.ResolvedSelector{Selector: policy.Selector{Kind: policy.Country, Value: "US"}, IPv4: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/8")}})
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	response := lookup.Evaluate(context.Background(), static, lookup.Dynamic{}, lookup.Request{Address: "8.1.2.3/0", Direction: policy.Ingress, Protocol: "tcp"}, when)
	if response.Verdict != "mixed" {
		t.Fatalf("aggregate verdict = %q, want mixed", response.Verdict)
	}
	var foundBlocked, foundPass bool
	for _, outcome := range response.Outcomes {
		if outcome.Prefix == netip.MustParsePrefix("8.0.0.0/8") && outcome.Ports != nil && outcome.Ports.Start == 80 && outcome.Verdict == "blocked" && outcome.Policy == "narrow" {
			foundBlocked = true
		}
		if outcome.Prefix == netip.MustParsePrefix("8.0.0.0/8") && outcome.Ports != nil && outcome.Ports.Start == 81 && outcome.Verdict == "not_blocked" && outcome.Policy == "broad" {
			foundPass = true
		}
	}
	if !foundBlocked || !foundPass {
		t.Fatalf("missing canonical /8 traffic partitions: %#v", response.Outcomes)
	}
	if response.Query.Address != "0.0.0.0/0" {
		t.Fatalf("canonical query = %q", response.Query.Address)
	}
	pass := lookup.Evaluate(context.Background(), static, lookup.Dynamic{}, lookup.Request{Address: "9.1.1.1", Direction: policy.Ingress, Protocol: "tcp", Port: ptr(uint16(80))}, when)
	if pass.Verdict != "not_blocked" || len(pass.Outcomes) != 1 || pass.Outcomes[0].Policy != "narrow" {
		t.Fatalf("first policy pass fell through to the later allowlist: %#v", pass)
	}
}

func TestEvaluateExclusionEvidenceIsCausal(t *testing.T) {
	static, _ := buildStatic(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: false
policies:
  - name: exclude-half
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
    exclude:
      countries: [CN]
`,
		policy.ResolvedSelector{Selector: policy.Selector{Kind: policy.Country, Value: "US"}, IPv4: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/8")}},
		policy.ResolvedSelector{Selector: policy.Selector{Kind: policy.Country, Value: "CN"}, IPv4: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/9")}},
	)
	response := lookup.Evaluate(context.Background(), static, lookup.Dynamic{}, lookup.Request{Address: "8.0.0.0/8", Direction: policy.Ingress, Protocol: "tcp", Port: ptr(uint16(80))}, time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC))
	var excluded, included bool
	for _, outcome := range response.Outcomes {
		for _, evidence := range outcome.Evidence {
			if outcome.Verdict == "not_blocked" && evidence.Name == "CN" && evidence.Role == "exclude" && evidence.Contributing {
				excluded = true
			}
			if outcome.Verdict == "blocked" && evidence.Name == "US" && evidence.Role == "include" && evidence.Contributing {
				included = true
			}
		}
	}
	if response.Verdict != "mixed" || !excluded || !included {
		t.Fatalf("exclusion causality mismatch: %#v", response.Outcomes)
	}
}

func TestEvaluateLeaseUncertaintyAndCancellation(t *testing.T) {
	static, _ := buildStatic(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: false
crowdsec:
  enabled: true
  api_key_file: /run/secrets/crowdsec
`)
	when := time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)
	dynamic := lookup.Dynamic{Prefixes: []policy.TimedPrefix{{Prefix: netip.MustParsePrefix("8.0.0.0/8"), Deadline: when.Add(-time.Second)}}}
	response := lookup.Evaluate(context.Background(), static, dynamic, lookup.Request{Address: "8.1.1.1", Direction: policy.Ingress, Protocol: "tcp", Port: ptr(uint16(80))}, when)
	if response.Verdict != "unknown" || response.Error == nil || response.Error.Code != "enforcement_unavailable" {
		t.Fatalf("expired lease = %#v", response)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response = lookup.Evaluate(ctx, static, lookup.Dynamic{}, lookup.Request{Address: "8.1.1.1"}, when)
	if response.Verdict != "unknown" || response.Error == nil || response.Error.Code != "enforcement_unavailable" {
		t.Fatalf("canceled lookup = %#v", response)
	}
}

func ptr(value uint16) *uint16 { return &value }

func TestEvaluateEvidenceLimitDoesNotReturnPartialSuccessOrCancellation(t *testing.T) {
	var text strings.Builder
	text.WriteString("version: 1\nfirewall:\n  backend: nftables\n  ipv6: false\npolicies:\n")
	for index := range lookup.MaxRecords + 1 {
		fmt.Fprintf(&text, "  - name: policy-%d\n    priority: %d\n    direction: ingress\n    mode: blocklist\n    traffic: [any]\n    include:\n      countries: [US]\n", index, index)
	}
	static, _ := buildStatic(t, text.String(), policy.ResolvedSelector{
		Selector: policy.Selector{Kind: policy.Country, Value: "US"},
		IPv4:     []netip.Prefix{netip.MustParsePrefix("8.0.0.0/8")},
	})
	response := lookup.Evaluate(context.Background(), static, lookup.Dynamic{}, lookup.Request{
		Address: "8.1.1.1", Direction: policy.Ingress, Protocol: "tcp", Port: ptr(443),
	}, time.Now())
	if response.Verdict != "unknown" || response.Error == nil || response.Error.Code != "limit_exceeded" || len(response.Outcomes) != 0 {
		t.Fatalf("over-budget response = %#v", response)
	}
}
