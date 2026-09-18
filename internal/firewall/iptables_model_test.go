package firewall

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func iptModelTestTarget(generation string, attachments []config.Attachment) *Target {
	owner := "0123456789abcdef0123456789abcdef"
	block := netip.MustParsePrefix("0.0.0.0/0")
	paths := []policy.Path{
		{
			Direction: policy.Ingress,
			Remote:    policy.SourceAddress,
			Processed: policy.CounterRole{Kind: policy.Processed},
			Rules: []policy.Rule{
				{Match: policy.Match{Flow: policy.EstablishedRelated, Traffic: policy.Scope{Any: true}}, Action: policy.Return},
				{Match: policy.Match{Flow: policy.NotNew, Traffic: policy.Scope{Any: true}}, Action: policy.Return},
				{Match: policy.Match{SetID: "global_blocklist", Traffic: policy.Scope{Any: true}}, Action: policy.Drop, Counter: policy.CounterRole{Kind: policy.Denied, Reason: policy.GlobalBlocklist, Action: policy.Drop}},
				{Match: policy.Match{Traffic: policy.Scope{Any: true}}, Action: policy.Return},
			},
		},
		{
			Direction: policy.Egress,
			Remote:    policy.DestinationAddress,
			Processed: policy.CounterRole{Kind: policy.Processed},
			Rules: []policy.Rule{
				{Match: policy.Match{Flow: policy.EstablishedRelated, Traffic: policy.Scope{Any: true}}, Action: policy.Return},
				{Match: policy.Match{Flow: policy.NotNew, Traffic: policy.Scope{Any: true}}, Action: policy.Return},
				{Match: policy.Match{SetID: "global_blocklist", Traffic: policy.Scope{TCP: []policy.PortRange{{Start: 80, End: 82}}}}, Action: policy.Drop, Counter: policy.CounterRole{Kind: policy.Denied, Reason: policy.GlobalBlocklist, Action: policy.Drop}},
				{Match: policy.Match{Traffic: policy.Scope{Any: true}}, Action: policy.Return},
			},
		},
	}
	return &Target{
		Owner:      owner,
		Table:      "unused-for-iptables",
		Generation: generation,
		Families: []policy.FamilyPlan{{
			Family: policy.IPv4,
			Sets:   []policy.PrefixSet{{ID: "global_blocklist", Kind: policy.StaticSet, Prefixes: []netip.Prefix{block}}},
			Paths:  paths,
		}},
		IPTables: &IPTablesTarget{Attachments: attachments},
	}
}

func TestIPTFamilyLowersZeroPrefixAndPreservesPolicyDirection(t *testing.T) {
	target := iptModelTestTarget("abcdefabcdefabcdefabcdefabcdefab", []config.Attachment{{Chain: "INPUT", Direction: "ingress"}, {Chain: "OUTPUT", Direction: "egress", OriginalDestination: true}})
	model, err := buildIPTFamily(target, policy.IPv4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(model.Sets) != 1 || !reflect.DeepEqual(model.Sets[0].Prefixes, []netip.Prefix{netip.MustParsePrefix("0.0.0.0/1"), netip.MustParsePrefix("128.0.0.0/1")}) {
		t.Fatalf("/0 was not lowered into deterministic hash:net entries: %#v", model.Sets)
	}
	if len(model.Staging) != 2 {
		t.Fatalf("expected one staging chain per direction/profile, got %d", len(model.Staging))
	}
	foundDestination := false
	foundSource := false
	for _, chain := range model.Staging {
		if len(chain.Rules) == 0 {
			t.Fatal("staging chain lost policy rules")
		}
		for _, rule := range chain.Rules {
			if !hasArg(rule.Args, "-m") || !hasArg(rule.Args, "comment") {
				t.Fatalf("owned staging rule lacks exact comment module: %#v", rule.Args)
			}
			if hasArg(rule.Args, "--ctorigdstport") {
				foundDestination = hasArg(rule.Args, "dst")
			}
			if hasArg(rule.Args, "--match-set") && hasArg(rule.Args, "src") {
				foundSource = true
			}
		}
	}
	if !foundDestination {
		t.Fatal("original-destination attachment did not preserve conntrack destination-port matching")
	}
	if !foundSource {
		t.Fatal("ingress policy did not match source addresses")
	}
}

func TestIPTActiveAttachmentNamesStableAcrossGeneration(t *testing.T) {
	attachments := []config.Attachment{{Chain: "FORWARD", Direction: "ingress", InputInterfaces: []string{"eth0", "eth1"}}}
	first, err := buildIPTFamily(iptModelTestTarget("abcdefabcdefabcdefabcdefabcdefab", attachments), policy.IPv4, nil)
	if err != nil {
		t.Fatal(err)
	}
	second, err := buildIPTFamily(iptModelTestTarget("fedcbafedcbafedcbafedcbafedcbafe", attachments), policy.IPv4, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(first.Active) != len(second.Active) || first.Active[0].Name != second.Active[0].Name {
		t.Fatalf("active attachment chain changed across generation: %q -> %q", first.Active[0].Name, second.Active[0].Name)
	}
	if first.Staging[0].Name == second.Staging[0].Name {
		t.Fatal("staging generation chain was not immutable across generation")
	}
	if len(first.Active) != 2 || len(first.Active[1].Rules) != 2 {
		t.Fatalf("interface OR helper did not preserve one rule per input interface: %#v", first.Active)
	}
	if len(first.Attachments) != 1 || !hasArg(first.Attachments[0].Rule.Args, "-j") {
		t.Fatalf("attachment did not produce exactly one owned parent jump: %#v", first.Attachments)
	}
}

func TestIPTDynamicSetNameUsesIndependentFullIdentity(t *testing.T) {
	target := iptModelTestTarget("abcdefabcdefabcdefabcdefabcdefab", nil)
	target.DynamicGeneration = "11111111111111111111111111111111"
	first := iptDynamicSetName(target, policy.IPv4)
	target.Generation = "fedcbafedcbafedcbafedcbafedcbafe"
	if second := iptDynamicSetName(target, policy.IPv4); first != second || len([]byte(first)) != maxIPTSetNameBytes {
		t.Fatalf("dynamic set identity changed with static generation or exceeded native limit: %q -> %q", first, second)
	}
	target.DynamicGeneration = "22222222222222222222222222222222"
	if third := iptDynamicSetName(target, policy.IPv4); third == first {
		t.Fatal("dynamic generation did not change the native set identity")
	}
}

func TestValidateIPTablesTargetRejectsMalformedAndDuplicateAttachments(t *testing.T) {
	bad := iptModelTestTarget("abcdefabcdefabcdefabcdefabcdefab", []config.Attachment{{Chain: "bad chain", Direction: "ingress"}})
	if err := validateIPTablesTarget(bad); err == nil {
		t.Fatal("malformed parent chain identifier was accepted")
	}
	duplicate := iptModelTestTarget("abcdefabcdefabcdefabcdefabcdefab", []config.Attachment{{Chain: "INPUT", Direction: "ingress"}, {Chain: "INPUT", Direction: "ingress"}})
	if err := validateIPTablesTarget(duplicate); err == nil {
		t.Fatal("duplicate normalized attachment was accepted")
	}
	custom := iptModelTestTarget("abcdefabcdefabcdefabcdefabcdefab", []config.Attachment{{Chain: "FORWARD", Direction: "ingress"}})
	if err := validateIPTablesTarget(custom); err == nil {
		t.Fatal("unconstrained custom ingress attachment was accepted")
	}
	collision := iptModelTestTarget("abcdefabcdefabcdefabcdefabcdefab", nil)
	collision.IPTables.Attachments = []config.Attachment{{Chain: iptSetName(collision, policy.IPv4, "global_blocklist"), Direction: "ingress", InputInterfaces: []string{"eth0"}}}
	if err := validateIPTablesTarget(collision); err == nil {
		t.Fatal("attachment parent colliding with an owned set name was accepted")
	}
}

func TestIPTQuoteAndSplitBoundaries(t *testing.T) {
	value := "comment with spaces \"quotes\" \\slashes\\ and\nnewline"
	line := "-m comment --comment " + iptQuote(value) + " tail"
	got, _, err := splitIPTLine(line)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"-m", "comment", "--comment", value, "tail"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("splitIPTLine = %#v, want %#v", got, want)
	}
	for _, malformed := range []string{`--comment "unterminated`, `--comment trailing\`} {
		if _, _, err := splitIPTLine(malformed); err == nil {
			t.Fatalf("malformed restore line %q was accepted", malformed)
		}
	}
}

func TestIPTRejectVariantsUseProtocolSpecificTargets(t *testing.T) {
	v4 := iptTrafficVariants(policy.Scope{Any: true}, policy.IPv4, false, policy.Reject)
	if len(v4) != 2 || !hasArg(v4[0], "tcp-reset") || !hasArg(v4[1], "icmp-admin-prohibited") {
		t.Fatalf("IPv4 reject variants = %#v", v4)
	}
	v6 := iptTrafficVariants(policy.Scope{Any: true}, policy.IPv6, false, policy.Reject)
	if len(v6) != 2 || !hasArg(v6[0], "tcp-reset") || !hasArg(v6[1], "icmp6-adm-prohibited") {
		t.Fatalf("IPv6 reject variants = %#v", v6)
	}
}

func hasArg(args []string, value string) bool {
	for _, arg := range args {
		if arg == value {
			return true
		}
	}
	return false
}
