package firewall

import (
	"context"
	"encoding/binary"
	"net/netip"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestIPSetPartialStagingRemainsRecoverable(t *testing.T) {
	const name = "owned_set"
	first, second := netip.MustParsePrefix("203.0.113.1/32"), netip.MustParsePrefix("203.0.113.3/32")
	expected := &iptExpected{sets: map[string]iptSet{name: {Name: name, Family: policy.IPv4, Prefixes: []netip.Prefix{first, second}}}, rules: make(map[iptChainKey]map[string]bool)}
	inventory := newIPTInventory()
	set := iptObservedSet{Name: name, Type: "hash:net", Family: "inet", Options: []string{"family", "inet", "maxelem", "65536"}, Entries: []string{first.String()}}
	inventory.Sets[name] = set
	if err := validateIPTInventory(inventory, expected); err != nil {
		t.Fatalf("authorized partial staging cannot be recovered: %v", err)
	}
	set.Entries = append(set.Entries, "203.0.113.5/32")
	inventory.Sets[name] = set
	if err := validateIPTInventory(inventory, expected); err == nil {
		t.Fatal("unrecorded staging contents were accepted")
	}
	set.Entries = []string{first.String()}
	set.References = 1
	inventory.Sets[name] = set
	rule := iptObservedRule{iptChainKey: chainKey(policy.IPv4, "owned_chain"), Args: []string{"-m", "set", "--match-set", name, "src", "-j", "RETURN"}, References: []iptRuleReference{{Kind: iptSetReference, Value: name}}}
	inventory.Rules = []iptObservedRule{rule}
	expected.addRule(rule.iptChainKey, rule.Args)
	if err := validateIPTInventory(inventory, expected); err == nil {
		t.Fatal("missing contents of a referenced static generation were accepted")
	}
	set.Entries = append(set.Entries, second.String())
	inventory.Sets[name] = set
	if err := validateIPTInventory(inventory, expected); err != nil {
		t.Fatalf("complete referenced generation rejected: %v", err)
	}
}

func TestNFTLargeTimedProjectionFitsBoundedAtomicBatch(t *testing.T) {
	cfg := config.Config{Version: 1, CrowdSec: config.CrowdSecConfig{Enabled: true}, Firewall: config.FirewallConfig{Backend: "nftables", DenyAction: "drop", IPv4: true, IPv6: true, Nftables: config.NftablesConfig{Table: "large"}}}
	model, err := policy.Compile(cfg, policy.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	target, err := BuildTarget(testOwner, testGenA, cfg, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	values := make([]policy.TimedPrefix, 100000)
	for index := range values {
		bytes := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89}
		binary.BigEndian.PutUint32(bytes[12:], uint32(index)*4)
		values[index] = policy.TimedPrefix{Prefix: netip.PrefixFrom(netip.AddrFrom16(bytes), 127), Deadline: now.Add(time.Hour)}
	}
	target.Dynamic = &DynamicState{Prefixes: values}
	if err := validateNFTCapacity(target); err != nil {
		t.Fatalf("100000 timed IPv6 ranges failed bounded preflight: %v", err)
	}
	commands, err := dynamicSetCommands(target, policy.IPv6, nftObject{}, values, now)
	if err != nil {
		t.Fatal(err)
	}
	calls := 0
	backend := &NFT{exec: func(context.Context, []string, []byte) ([]byte, error) { calls++; return nil, nil }}
	if err := backend.applyBatch(context.Background(), nftBatch{Nftables: commands}); err != nil {
		t.Fatalf("100000 timed ranges cannot be submitted: %v", err)
	}
	if calls != 1 {
		t.Fatalf("logical update used %d native transactions, want one", calls)
	}
}
