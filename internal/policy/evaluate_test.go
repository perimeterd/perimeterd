package policy_test

import (
	"net/netip"
	"testing"

	"github.com/perimeterd/perimeterd/internal/policy"
)

type testFlow struct {
	Family      policy.Family
	Direction   policy.Direction
	Source      netip.Addr
	Destination netip.Addr
	Protocol    string
	Port        uint16
	New         bool
	Established bool
}

type evaluation struct {
	Action    policy.Action
	Trace     string
	Processed policy.CounterRole
	Denied    policy.CounterRole
	HasDenied bool
}

func evaluate(plan policy.FamilyPlan, flow testFlow, dynamic []netip.Prefix) evaluation {
	for _, path := range plan.Paths {
		if path.Direction != flow.Direction {
			continue
		}
		result := evaluation{Action: policy.Return, Processed: path.Processed}
		for _, rule := range path.Rules {
			if !ruleMatches(plan, path, rule, flow, dynamic) {
				continue
			}
			result.Action = rule.Action
			result.Trace = rule.Policy
			if rule.Action != policy.Return {
				result.Denied = rule.Counter
				result.HasDenied = true
			}
			return result
		}
		return result
	}
	return evaluation{Action: policy.Return}
}

func ruleMatches(plan policy.FamilyPlan, path policy.Path, rule policy.Rule, flow testFlow, dynamic []netip.Prefix) bool {
	match := rule.Match
	switch match.Flow {
	case policy.EstablishedRelated:
		if !flow.Established {
			return false
		}
	case policy.NotNew:
		if flow.New {
			return false
		}
	}
	if match.SetID != "" {
		member := false
		for _, set := range plan.Sets {
			if set.ID != match.SetID {
				continue
			}
			if set.Kind == policy.DynamicCrowdSecSet {
				for _, prefix := range dynamic {
					if prefix.Contains(remoteAddress(path, flow)) {
						member = true
						break
					}
				}
			} else {
				for _, prefix := range set.Prefixes {
					if prefix.Contains(remoteAddress(path, flow)) {
						member = true
						break
					}
				}
			}
			break
		}
		if match.NegateSet {
			member = !member
		}
		if !member {
			return false
		}
	}
	return scopeMatches(match.Traffic, flow.Family, flow.Protocol, flow.Port)
}

func remoteAddress(path policy.Path, flow testFlow) netip.Addr {
	if path.Remote == policy.DestinationAddress {
		return flow.Destination
	}
	return flow.Source
}

func scopeMatches(scope policy.Scope, family policy.Family, protocol string, port uint16) bool {
	if scope.Any {
		return true
	}
	switch protocol {
	case "tcp":
		return portInRanges(scope.TCP, port)
	case "udp":
		return portInRanges(scope.UDP, port)
	case "icmp":
		return scope.ICMP && (family == policy.IPv4 || family == policy.IPv6)
	default:
		return false
	}
}

func portInRanges(ranges []policy.PortRange, port uint16) bool {
	for _, r := range ranges {
		if port >= r.Start && port <= r.End {
			return true
		}
	}
	return false
}

func findPlan(t *testing.T, state policy.State, family policy.Family, direction policy.Direction) policy.FamilyPlan {
	t.Helper()
	for _, plan := range state.Families() {
		if plan.Family != family {
			continue
		}
		for _, path := range plan.Paths {
			if path.Direction == direction {
				return plan
			}
		}
	}
	t.Fatalf("missing %v %v plan", family, direction)
	return policy.FamilyPlan{}
}

func findPath(t *testing.T, plan policy.FamilyPlan, direction policy.Direction) policy.Path {
	t.Helper()
	for _, path := range plan.Paths {
		if path.Direction == direction {
			return path
		}
	}
	t.Fatalf("missing %v path", direction)
	return policy.Path{}
}

func TestEvaluationOrderingAndAccounting(t *testing.T) {
	cfg := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
global:
  allowlist: [8.0.0.0/8]
  blocklist: [8.0.0.0/8, 9.0.0.0/8, 10.0.0.0/8]
crowdsec:
  enabled: true
  api_key_file: /run/secrets/crowdsec
policies:
  - name: geo-allow
    priority: 10
    direction: ingress
    mode: allowlist
    traffic: [any]
    include:
      countries: [US]
`)
	snapshot := mustSnapshot(t, snapshotRecord{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("11.0.0.0/8")}, ipv6: []netip.Prefix{mustPrefix("2600::/32")}})
	state, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	plan4 := findPlan(t, state, policy.IPv4, policy.Ingress)

	cases := []struct {
		name       string
		flow       testFlow
		dynamic    []netip.Prefix
		wantAction policy.Action
		wantReason policy.DenyReason
		wantDenied bool
	}{
		{
			name:       "established bypasses every denial source",
			flow:       testFlow{Family: policy.IPv4, Direction: policy.Ingress, Source: netip.MustParseAddr("9.1.1.1"), New: true, Established: true, Protocol: "tcp", Port: 22},
			wantAction: policy.Return,
		},
		{
			name:       "non-new bypasses every denial source",
			flow:       testFlow{Family: policy.IPv4, Direction: policy.Ingress, Source: netip.MustParseAddr("9.1.1.1"), Protocol: "tcp", Port: 22},
			wantAction: policy.Return,
		},
		{
			name:    "configured public allow overrides block crowdsec and geo",
			flow:    testFlow{Family: policy.IPv4, Direction: policy.Ingress, Source: netip.MustParseAddr("8.1.1.1"), New: true, Protocol: "tcp", Port: 22},
			dynamic: []netip.Prefix{mustPrefix("8.0.0.0/8")}, wantAction: policy.Return,
		},
		{
			name:    "built-in local allow overrides all denial sources",
			flow:    testFlow{Family: policy.IPv4, Direction: policy.Ingress, Source: netip.MustParseAddr("10.1.1.1"), New: true, Protocol: "tcp", Port: 22},
			dynamic: []netip.Prefix{mustPrefix("10.0.0.0/8")}, wantAction: policy.Return,
		},
		{
			name:    "global block precedes crowdsec and geo",
			flow:    testFlow{Family: policy.IPv4, Direction: policy.Ingress, Source: netip.MustParseAddr("9.1.1.1"), New: true, Protocol: "tcp", Port: 22},
			dynamic: []netip.Prefix{mustPrefix("9.0.0.0/8")}, wantAction: policy.Drop, wantReason: policy.GlobalBlocklist, wantDenied: true,
		},
		{
			name:    "ingress crowdsec precedes geo allowlist",
			flow:    testFlow{Family: policy.IPv4, Direction: policy.Ingress, Source: netip.MustParseAddr("11.1.1.1"), New: true, Protocol: "tcp", Port: 22},
			dynamic: []netip.Prefix{mustPrefix("11.0.0.0/8")}, wantAction: policy.Drop, wantReason: policy.CrowdSec, wantDenied: true,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := evaluate(plan4, tc.flow, tc.dynamic)
			if result.Action != tc.wantAction {
				t.Fatalf("action = %s, want %s (trace %q)", result.Action, tc.wantAction, result.Trace)
			}
			if result.Processed.Kind != policy.Processed {
				t.Fatalf("processed counter role = %#v", result.Processed)
			}
			if result.HasDenied != tc.wantDenied {
				t.Fatalf("denied counter presence = %v, want %v", result.HasDenied, tc.wantDenied)
			}
			if tc.wantDenied {
				if result.Denied.Kind != policy.Denied || result.Denied.Reason != tc.wantReason || result.Denied.Action != tc.wantAction {
					t.Fatalf("denied counter role = %#v, want reason=%s action=%s", result.Denied, tc.wantReason, tc.wantAction)
				}
			}
		})
	}
	planEgress := findPlan(t, state, policy.IPv4, policy.Egress)
	result := evaluate(planEgress, testFlow{
		Family: policy.IPv4, Direction: policy.Egress,
		Source: netip.MustParseAddr("8.1.1.1"), Destination: netip.MustParseAddr("9.1.1.1"),
		New: true, Protocol: "tcp", Port: 22,
	}, nil)
	if result.Action != policy.Drop || !result.HasDenied || result.Denied.Reason != policy.GlobalBlocklist {
		t.Fatalf("egress global block did not deny destination before geo evaluation: %#v", result)
	}

	plan6 := findPlan(t, state, policy.IPv6, policy.Ingress)
	result = evaluate(plan6, testFlow{Family: policy.IPv6, Direction: policy.Ingress, Source: netip.MustParseAddr("2600::1"), New: true, Protocol: "tcp", Port: 22}, nil)
	if result.Action != policy.Return || result.Trace != "geo-allow" {
		t.Fatalf("IPv6 geo allow was not selected without a CrowdSec ban: %#v", result)
	}
	result = evaluate(plan6, testFlow{Family: policy.IPv6, Direction: policy.Ingress, Source: netip.MustParseAddr("2600::1"), New: true, Protocol: "tcp", Port: 22}, []netip.Prefix{mustPrefix("2600::/32")})
	if result.Action != policy.Drop || !result.HasDenied || result.Denied.Reason != policy.CrowdSec || result.Denied.Action != policy.Drop {
		t.Fatalf("IPv6 CrowdSec ban must precede geo allowlist: %#v", result)
	}
}

func TestEvaluationCrowdSecIsIngressOnlyAndEmptyDecisionsKeepModel(t *testing.T) {
	cfg := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: false
crowdsec:
  enabled: true
  api_key_file: /run/secrets/crowdsec
`)
	state, err := policy.Compile(cfg, mustSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	plan := findPlan(t, state, policy.IPv4, policy.Ingress)
	result := evaluate(plan, testFlow{Family: policy.IPv4, Direction: policy.Ingress, Source: netip.MustParseAddr("11.1.1.1"), New: true, Protocol: "tcp", Port: 22}, nil)
	if result.Action != policy.Return {
		t.Fatalf("an empty dynamic decision store must not deny traffic: %#v", result)
	}
	egress := findPlan(t, state, policy.IPv4, policy.Egress)
	result = evaluate(egress, testFlow{Family: policy.IPv4, Direction: policy.Egress, Destination: netip.MustParseAddr("11.1.1.1"), New: true, Protocol: "tcp", Port: 22}, []netip.Prefix{mustPrefix("11.0.0.0/8")})
	if result.Action != policy.Return {
		t.Fatalf("CrowdSec must not be consulted on egress: %#v", result)
	}
}

func TestEvaluationTrafficScopeAndFirstScopeTermination(t *testing.T) {
	cfg := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
policies:
  - name: narrow-block
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["80", "443/udp"]
    include:
      countries: [US]
  - name: broad-allow
    priority: 20
    direction: ingress
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
	plan := findPlan(t, state, policy.IPv4, policy.Ingress)
	cases := []struct {
		name  string
		flow  testFlow
		want  policy.Action
		trace string
	}{
		{name: "bare port is TCP and matching block denies", flow: testFlow{Family: policy.IPv4, Direction: policy.Ingress, Source: netip.MustParseAddr("8.1.1.1"), New: true, Protocol: "tcp", Port: 80}, want: policy.Drop, trace: "narrow-block"},
		{name: "matching block scope nonmatch returns before later policy", flow: testFlow{Family: policy.IPv4, Direction: policy.Ingress, Source: netip.MustParseAddr("9.1.1.1"), New: true, Protocol: "tcp", Port: 80}, want: policy.Return, trace: "narrow-block"},
		{name: "UDP does not match bare TCP port", flow: testFlow{Family: policy.IPv4, Direction: policy.Ingress, Source: netip.MustParseAddr("9.1.1.1"), New: true, Protocol: "udp", Port: 80}, want: policy.Drop, trace: "broad-allow"},
		{name: "explicit UDP scope matches", flow: testFlow{Family: policy.IPv4, Direction: policy.Ingress, Source: netip.MustParseAddr("8.1.1.1"), New: true, Protocol: "udp", Port: 443}, want: policy.Drop, trace: "narrow-block"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			result := evaluate(plan, tc.flow, nil)
			if result.Action != tc.want || result.Trace != tc.trace {
				t.Fatalf("evaluation = %#v, want action=%s trace=%q", result, tc.want, tc.trace)
			}
		})
	}
}

func TestEvaluationClassifierBoundariesAndRestoredExceptions(t *testing.T) {
	globalCfg := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
global:
  blocklist: [192.0.2.0/24]
`)
	globalState, err := policy.Compile(globalCfg, mustSnapshot(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
		plan := findPlan(t, globalState, policy.IPv4, direction)
		flow := testFlow{
			Family: policy.IPv4, Direction: direction,
			Source: netip.MustParseAddr("192.0.2.1"), Destination: netip.MustParseAddr("192.0.2.1"),
			New: true, Protocol: "tcp", Port: 443,
		}
		result := evaluate(plan, flow, nil)
		if result.Action != policy.Drop || !result.HasDenied || result.Denied.Reason != policy.GlobalBlocklist {
			t.Fatalf("%s global block must deny non-eligible documentation space: %#v", direction, result)
		}
	}
	cfg := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
policies:
  - name: all-geo
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
`)
	snapshot := mustSnapshot(t, snapshotRecord{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("0.0.0.0/0")}, ipv6: []netip.Prefix{mustPrefix("::/0")}})
	state, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	plan4 := findPlan(t, state, policy.IPv4, policy.Ingress)
	v4 := []struct {
		address string
		want    policy.Action
	}{
		{address: "8.0.0.1", want: policy.Drop},
		{address: "10.0.0.1", want: policy.Return},
		{address: "100.64.0.1", want: policy.Return},
		{address: "192.0.2.1", want: policy.Return},
		{address: "192.0.0.9", want: policy.Drop},
		{address: "192.0.0.10", want: policy.Drop},
	}
	for _, tc := range v4 {
		result := evaluate(plan4, testFlow{Family: policy.IPv4, Direction: policy.Ingress, Source: netip.MustParseAddr(tc.address), New: true, Protocol: "tcp", Port: 443}, nil)
		if result.Action != tc.want {
			t.Errorf("IPv4 %s action = %s, want %s", tc.address, result.Action, tc.want)
		}
	}
	plan6 := findPlan(t, state, policy.IPv6, policy.Ingress)
	v6 := []struct {
		address string
		want    policy.Action
	}{
		{address: "2600::1", want: policy.Drop},
		{address: "2001:db8::1", want: policy.Return},
		{address: "fc00::1", want: policy.Return},
		{address: "2001:1::1", want: policy.Drop},
		{address: "2001:3::1", want: policy.Drop},
	}
	for _, tc := range v6 {
		result := evaluate(plan6, testFlow{Family: policy.IPv6, Direction: policy.Ingress, Source: netip.MustParseAddr(tc.address), New: true, Protocol: "tcp", Port: 443}, nil)
		if result.Action != tc.want {
			t.Errorf("IPv6 %s action = %s, want %s", tc.address, result.Action, tc.want)
		}
	}
}

func TestEvaluationDirectionProtocolAndFamilyEmptyBehavior(t *testing.T) {
	cfg := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
policies:
  - name: ingress-v4
    priority: 10
    direction: ingress
    mode: allowlist
    traffic: [any]
    include:
      countries: [US]
  - name: egress-v4
    priority: 20
    direction: egress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
`)
	snapshot := mustSnapshot(t, snapshotRecord{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}, ipv6: []netip.Prefix{}})
	state, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	in4 := findPlan(t, state, policy.IPv4, policy.Ingress)
	result := evaluate(in4, testFlow{Family: policy.IPv4, Direction: policy.Ingress, Source: netip.MustParseAddr("8.1.1.1"), Destination: netip.MustParseAddr("9.1.1.1"), New: true, Protocol: "tcp", Port: 443}, nil)
	if result.Action != policy.Return {
		t.Fatalf("ingress must inspect source, not destination: %#v", result)
	}
	eg4 := findPlan(t, state, policy.IPv4, policy.Egress)
	result = evaluate(eg4, testFlow{Family: policy.IPv4, Direction: policy.Egress, Source: netip.MustParseAddr("8.1.1.1"), Destination: netip.MustParseAddr("9.1.1.1"), New: true, Protocol: "tcp", Port: 443}, nil)
	if result.Action != policy.Return {
		t.Fatalf("egress must inspect destination, not source: %#v", result)
	}

	in6 := findPlan(t, state, policy.IPv6, policy.Ingress)
	result = evaluate(in6, testFlow{Family: policy.IPv6, Direction: policy.Ingress, Source: netip.MustParseAddr("2600::1"), New: true, Protocol: "tcp", Port: 443}, nil)
	if result.Action != policy.Drop || result.Trace != "ingress-v4" {
		t.Fatalf("empty-family allowlist must deny globally eligible IPv6: %#v", result)
	}
	result = evaluate(in6, testFlow{Family: policy.IPv6, Direction: policy.Ingress, Source: netip.MustParseAddr("2001:db8::1"), New: true, Protocol: "tcp", Port: 443}, nil)
	if result.Action != policy.Return {
		t.Fatalf("non-eligible IPv6 must bypass an empty-family allowlist: %#v", result)
	}
}

func TestEvaluationEmptyFamilyBlockDoesNotFallThrough(t *testing.T) {
	cfg := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
policies:
  - name: empty-block
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
  - name: later-allow
    priority: 20
    direction: ingress
    mode: allowlist
    traffic: [any]
    include:
      countries: [US]
`)
	snapshot := mustSnapshot(t, snapshotRecord{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}, ipv6: []netip.Prefix{}})
	state, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	plan := findPlan(t, state, policy.IPv6, policy.Ingress)
	result := evaluate(plan, testFlow{Family: policy.IPv6, Direction: policy.Ingress, Source: netip.MustParseAddr("2600::1"), New: true, Protocol: "tcp", Port: 443}, nil)
	if result.Action != policy.Return || result.Trace != "empty-block" {
		t.Fatalf("empty-family blocklist scope must return and terminate before later policy: %#v", result)
	}
}

func TestEvaluationRejectActionAndICMPScopeByFamily(t *testing.T) {
	cfg := parseTestConfig(t, `version: 1
firewall:
  backend: nftables
  deny_action: reject
  ipv4: true
  ipv6: true
policies:
  - name: icmp-v6
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [icmpv6]
    include:
      countries: [US]
`)
	snapshot := mustSnapshot(t, snapshotRecord{kind: policy.Country, value: "US", ipv4: []netip.Prefix{mustPrefix("8.0.0.0/8")}, ipv6: []netip.Prefix{mustPrefix("2600::/32")}})
	state, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	v6 := findPlan(t, state, policy.IPv6, policy.Ingress)
	result := evaluate(v6, testFlow{Family: policy.IPv6, Direction: policy.Ingress, Source: netip.MustParseAddr("2600::1"), New: true, Protocol: "icmp"}, nil)
	if result.Action != policy.Reject || result.Trace != "icmp-v6" || result.Denied.Action != policy.Reject || result.Denied.Reason != policy.GeoPolicy {
		t.Fatalf("IPv6 ICMP scope did not produce a typed reject decision: %#v", result)
	}
	v4 := findPlan(t, state, policy.IPv4, policy.Ingress)
	result = evaluate(v4, testFlow{Family: policy.IPv4, Direction: policy.Ingress, Source: netip.MustParseAddr("8.1.1.1"), New: true, Protocol: "icmp"}, nil)
	if result.Action != policy.Return {
		t.Fatalf("icmpv6 policy must not match IPv4 ICMP: %#v", result)
	}
}
