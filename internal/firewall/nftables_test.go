package firewall

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

const (
	testOwner = "0123456789abcdef0123456789abcdef"
	testGenA  = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	testGenB  = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

func testTarget(t *testing.T, generation string) *Target {
	t.Helper()
	cfg := config.Config{
		Version:  1,
		Global:   config.GlobalConfig{Blocklist: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		Firewall: config.FirewallConfig{Backend: "nftables", DenyAction: "drop", IPv4: true, IPv6: true, Nftables: config.NftablesConfig{Table: "test-perimeterd", Priority: -10}},
	}
	model, err := policy.Compile(cfg, policy.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	target, err := BuildTarget(testOwner, generation, cfg, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestTargetSerializationAndStableCounters(t *testing.T) {
	first := testTarget(t, testGenA)
	data, err := json.Marshal(first)
	if err != nil {
		t.Fatal(err)
	}
	var decoded Target
	if err := json.Unmarshal(data, &decoded); err != nil {
		t.Fatal(err)
	}
	if err := ValidateTarget(&decoded); err != nil {
		t.Fatal(err)
	}
	if len(decoded.Counters) == 0 || len(decoded.Families) != 2 {
		t.Fatalf("decoded target lost model: %+v", decoded)
	}
	cfg := config.Config{Version: 1, Global: config.GlobalConfig{Blocklist: []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}}, Firewall: config.FirewallConfig{Backend: "nftables", DenyAction: "drop", IPv4: true, IPv6: true, Nftables: config.NftablesConfig{Table: first.Table, Priority: -20}}}
	model, err := policy.Compile(cfg, policy.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildTarget(testOwner, testGenB, cfg, model, first)
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation != testGenB {
		t.Fatalf("static model changed without generation replacement: %s", second.Generation)
	}
	if len(second.Counters) < len(first.Counters) {
		t.Fatal("stable counters were discarded")
	}
}

func TestPriorityOnlyKeepsGenerationAndBaseReplacement(t *testing.T) {
	first := testTarget(t, testGenA)
	candidate := *first
	candidate.Priority = -199
	if !sameFamilies(first.Families, candidate.Families) {
		t.Fatal("family comparison is not deterministic")
	}
	if candidate.Generation != first.Generation {
		t.Fatal("priority-only target changed generation")
	}
	inventory := newNFTInventory()
	inventory.present = true
	inventory.table = nftObject{Kind: "table", Family: "inet", Name: first.Table, Comment: tableComment(first.Owner)}
	name := baseChainName(first, policy.Ingress)
	inventory.chains[name] = nftObject{Kind: "chain", Family: "inet", Table: first.Table, Name: name, Comment: ownershipComment(first.Owner, stableToken, baseRole(policy.Ingress), true), Prio: first.Priority, HasPrio: true}
	batch, err := commandBatch(&candidate, inventory, first)
	if err != nil {
		t.Fatal(err)
	}
	data, _ := json.Marshal(batch)
	text := string(data)
	if !strings.Contains(text, `"delete":{"chain"`) {
		t.Fatalf("priority replacement did not delete base chain: %s", text)
	}
	if strings.Contains(text, testGenB) {
		t.Fatal("priority replacement staged unrelated generation")
	}
}

func TestCommandBatchRepairsMissingGenerationRules(t *testing.T) {
	target := testTarget(t, testGenA)
	inventory := newNFTInventory()
	inventory.present = true
	inventory.table = nftObject{Kind: "table", Family: "inet", Name: target.Table, Comment: tableComment(target.Owner)}
	name := generationChainName(target, policy.IPv4, policy.Ingress)
	inventory.chains[name] = nftObject{
		Kind: "chain", Family: "inet", Table: target.Table, Name: name,
		Comment: ownershipComment(target.Owner, target.Generation, chainRole(policy.IPv4, policy.Ingress), false),
	}
	batch, err := commandBatch(target, inventory, target)
	if err != nil {
		t.Fatal(err)
	}
	repaired := false
	for _, command := range batch.Nftables {
		if flush, ok := command.Flush.(map[string]any); ok {
			if chain, ok := flush["chain"].(map[string]any); ok && chain["name"] == name {
				repaired = true
				break
			}
		}
	}
	if !repaired {
		t.Fatalf("missing generation rules were treated as complete: %+v", batch)
	}
}

func TestForeignOwnershipRefusedBeforeMutation(t *testing.T) {
	target := testTarget(t, testGenA)
	inventory := newNFTInventory()
	inventory.present = true
	inventory.table = nftObject{Kind: "table", Family: "inet", Name: target.Table, Comment: "foreign manager"}
	if err := validateInventory(inventory, target); err == nil {
		t.Fatal("foreign table was accepted")
	}
}

func TestPreflightRejectsExistingSameOwnerEmptyCandidateTable(t *testing.T) {
	target := testTarget(t, testGenA)
	table := `{"table":{"family":"inet","name":"` + target.Table + `","comment":"` + tableComment(target.Owner) + `"}}`
	backend := &NFT{exec: func(_ context.Context, args []string, input []byte) ([]byte, error) {
		if len(args) >= 3 && args[1] == "list" && args[2] == "tables" {
			return []byte(`{"nftables":[` + table + `]}`), nil
		}
		if len(args) >= 3 && args[1] == "-f" && args[2] == "-" && strings.Contains(string(input), `"list"`) {
			return []byte(`{"nftables":[` + table + `]}`), nil
		}
		return []byte(`{"nftables":[]}`), nil
	}}
	if err := backend.Preflight(context.Background(), nil, target); err == nil {
		t.Fatal("preflight adopted an existing same-owner candidate table")
	}
}

func TestInspectUsesTypedTableQuery(t *testing.T) {
	target := testTarget(t, testGenA)
	target.Table = "sentinel; delete table inet foreign"
	tableObject, err := json.Marshal(map[string]any{"table": map[string]any{
		"family": "inet", "name": target.Table, "comment": tableComment(target.Owner),
	}})
	if err != nil {
		t.Fatal(err)
	}
	response := []byte(`{"nftables":[` + string(tableObject) + `]}`)
	var queryArgs []string
	var queryInput []byte
	backend := &NFT{exec: func(_ context.Context, args []string, input []byte) ([]byte, error) {
		if len(args) >= 3 && args[1] == "list" && args[2] == "tables" {
			return response, nil
		}
		queryArgs = append([]string(nil), args...)
		queryInput = append([]byte(nil), input...)
		return response, nil
	}}
	if _, err := backend.inspect(context.Background(), target.Table, target); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(queryArgs, " "), target.Table) {
		t.Fatalf("table name was passed through nft argv: %v", queryArgs)
	}
	if len(queryArgs) != 3 || queryArgs[0] != "-j" || queryArgs[1] != "-f" || queryArgs[2] != "-" {
		t.Fatalf("unexpected typed list-table argv: %v", queryArgs)
	}
	if !strings.Contains(string(queryInput), target.Table) {
		t.Fatalf("typed list-table JSON omitted table name: %s", queryInput)
	}
}

func TestRetireAbsentAndFirstInstallRetention(t *testing.T) {
	target := testTarget(t, testGenA)
	calls := 0
	backend := &NFT{exec: func(context.Context, []string, []byte) ([]byte, error) {
		calls++
		return []byte(`{"nftables":[]}`), nil
	}}
	if err := backend.Retire(context.Background(), target, nil); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("absent retirement performed %d inspections", calls)
	}
	calls = 0
	if err := backend.Retire(context.Background(), nil, target); err != nil {
		t.Fatal(err)
	}
	if calls != 0 {
		t.Fatal("first-install retention inspected or mutated kernel")
	}
}

func TestNativePrefixAndRejectLowering(t *testing.T) {
	prefix := prefixExpression(netip.MustParsePrefix("0.0.0.0/0"))
	if prefix["prefix"].(map[string]any)["len"] != 0 {
		t.Fatal("/0 was not represented natively")
	}
	reject := verdictExpression(policy.Reject, policy.IPv6, map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "l4proto"}}, "right": "tcp"}})
	if reject["reject"].(map[string]any)["type"] != "tcp reset" {
		t.Fatal("TCP reject was not lowered to reset")
	}
}

func TestLongGeoSetNamesAreBoundedAndSuffixSensitive(t *testing.T) {
	const repeated = 199
	leftPolicy := strings.Repeat("a", repeated) + "b"
	rightPolicy := strings.Repeat("a", repeated) + "c"
	cfg := config.Config{
		Version: 1,
		Firewall: config.FirewallConfig{
			Backend: "nftables", DenyAction: "drop", IPv4: true,
			Nftables: config.NftablesConfig{Table: "long-geo", Priority: -10},
		},
		Policies: []config.Policy{
			{Name: leftPolicy, Priority: 10, Direction: "ingress", Mode: "allowlist", Traffic: config.TrafficScope{Any: true}, Include: config.Selector{Countries: []string{"US"}}},
			{Name: rightPolicy, Priority: 20, Direction: "ingress", Mode: "allowlist", Traffic: config.TrafficScope{Any: true}, Include: config.Selector{Countries: []string{"CA"}}},
		},
	}
	snapshot, err := policy.NewSnapshot([]policy.ResolvedSelector{
		{Selector: policy.Selector{Kind: policy.Country, Value: "US"}, IPv4: []netip.Prefix{netip.MustParsePrefix("8.0.0.0/8")}},
		{Selector: policy.Selector{Kind: policy.Country, Value: "CA"}, IPv4: []netip.Prefix{netip.MustParsePrefix("9.0.0.0/8")}},
	})
	if err != nil {
		t.Fatal(err)
	}
	model, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target, err := BuildTarget(testOwner, testGenA, cfg, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTarget(target); err != nil {
		t.Fatal(err)
	}

	wantIDs := []string{"geo/" + leftPolicy, "geo/" + rightPolicy}
	native := make(map[string]string, len(wantIDs))
	for _, family := range target.Families {
		for _, set := range family.Sets {
			if set.ID != wantIDs[0] && set.ID != wantIDs[1] {
				continue
			}
			name := setName(target, family.Family, set.ID)
			if len(name) > maxNFTNameBytes {
				t.Fatalf("long geo set %q exceeds native length limit %d: %q", set.ID, maxNFTNameBytes, name)
			}
			native[set.ID] = name
		}
	}
	for _, id := range wantIDs {
		if native[id] == "" {
			t.Fatalf("compiled target omitted %s", id)
		}
	}
	if native[wantIDs[0]] == native[wantIDs[1]] {
		t.Fatalf("long geo IDs differing only in suffix collided as %q", native[wantIDs[0]])
	}
}

func TestGeoPolicyEligibleSetNameDoesNotAliasReservedSet(t *testing.T) {
	target := testTarget(t, testGenA)
	target.Families = cloneFamilies(target.Families)
	target.Families[0].Sets = append(target.Families[0].Sets,
		policy.PrefixSet{ID: "geo_eligible", Kind: policy.StaticSet},
		policy.PrefixSet{ID: "geo/eligible", Kind: policy.StaticSet},
	)
	if err := ValidateTarget(target); err != nil {
		t.Fatal(err)
	}
	reserved := setName(target, target.Families[0].Family, "geo_eligible")
	policySet := setName(target, target.Families[0].Family, "geo/eligible")
	if reserved == policySet {
		t.Fatalf("reserved geo set and policy set share native name %q", reserved)
	}
}

func TestSetElementsCompareCanonicalNftIntervals(t *testing.T) {
	observed := nftObject{Elem: json.RawMessage(`["8.20.0.2",{"range":["8.20.0.0","8.20.1.127"]}]`)}
	expected := []netip.Prefix{
		netip.MustParsePrefix("8.20.0.0/24"),
		netip.MustParsePrefix("8.20.1.0/25"),
		netip.MustParsePrefix("8.20.0.2/32"),
	}
	if !setElementsComplete(observed, policy.IPv4, expected) {
		t.Fatal("canonical nft host/range elements did not match desired prefix union")
	}
}

func TestValidateConfigSupportsSourcesAndRejectsUnknownPolicyMode(t *testing.T) {
	cfg := config.Config{
		Version:  1,
		Firewall: config.FirewallConfig{Backend: "nftables", DenyAction: "drop", Nftables: config.NftablesConfig{Table: "perimeterd", Priority: -10}},
		Policies: []config.Policy{{Name: "geo", Mode: "allowlist"}},
	}
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("static geo policy was rejected: %v", err)
	}
	cfg.Policies[0].Mode = "unexpected"
	if err := ValidateConfig(cfg); err == nil {
		t.Fatal("unsupported policy mode was accepted")
	}
	cfg.Policies = nil
	cfg.CrowdSec.Enabled = true
	if err := ValidateConfig(cfg); err != nil {
		t.Fatalf("CrowdSec configuration was rejected: %v", err)
	}
}

func TestValidateTargetAcceptsStaticGeoRulesAndCounters(t *testing.T) {
	cfg := config.Config{
		Version: 1,
		Firewall: config.FirewallConfig{
			Backend: "nftables", DenyAction: "reject", IPv4: true, IPv6: true,
			Nftables: config.NftablesConfig{Table: "geo-test", Priority: -10},
		},
		Policies: []config.Policy{{
			Name: "geo", Priority: 10, Direction: "ingress", Mode: "allowlist",
			Traffic: config.TrafficScope{TCP: []config.PortRange{{Start: 443, End: 443}}, UDP: []config.PortRange{{Start: 53, End: 53}}},
			Include: config.Selector{Countries: []string{"US"}},
		}},
	}
	snapshot, err := policy.NewSnapshot([]policy.ResolvedSelector{{
		Selector: policy.Selector{Kind: policy.Country, Value: "US"},
		IPv4:     []netip.Prefix{netip.MustParsePrefix("8.0.0.0/8")},
		IPv6:     []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	model, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target, err := BuildTarget(testOwner, testGenA, cfg, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := ValidateTarget(target); err != nil {
		t.Fatalf("compiled static geo target was rejected: %v", err)
	}
	var geoCounter, negated bool
	for _, family := range target.Families {
		for _, set := range family.Sets {
			if strings.HasPrefix(set.ID, "geo/") && set.Kind != policy.StaticSet {
				t.Fatalf("geo policy set is not static: %#v", set)
			}
		}
		for _, path := range family.Paths {
			for _, rule := range path.Rules {
				negated = negated || rule.Match.SetID == "geo_eligible" && rule.Match.NegateSet
				geoCounter = geoCounter || rule.Counter.Reason == policy.GeoPolicy
			}
		}
	}
	if !negated || !geoCounter {
		t.Fatalf("compiled geo target omitted bypass or denial counter: negated=%t counter=%t", negated, geoCounter)
	}
}

func TestEmptyGeoFamilySetIsMaterialized(t *testing.T) {
	cfg := config.Config{
		Version: 1,
		Firewall: config.FirewallConfig{
			Backend: "nftables", DenyAction: "drop", IPv4: true, IPv6: true,
			Nftables: config.NftablesConfig{Table: "geo-empty", Priority: -10},
		},
		Policies: []config.Policy{{
			Name: "geo", Priority: 10, Direction: "ingress", Mode: "allowlist",
			Traffic: config.TrafficScope{Any: true}, Include: config.Selector{Countries: []string{"US"}},
		}},
	}
	snapshot, err := policy.NewSnapshot([]policy.ResolvedSelector{{
		Selector: policy.Selector{Kind: policy.Country, Value: "US"},
		IPv6:     []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	model, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target, err := BuildTarget(testOwner, testGenA, cfg, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	var emptyName string
	for _, family := range target.Families {
		if family.Family != policy.IPv4 {
			continue
		}
		for _, set := range family.Sets {
			if strings.HasPrefix(set.ID, "geo/") {
				emptyName = setName(target, family.Family, set.ID)
				if len(set.Prefixes) != 0 {
					t.Fatalf("expected empty IPv4 geo set, got %v", set.Prefixes)
				}
			}
		}
	}
	if emptyName == "" {
		t.Fatal("compiled target omitted empty geo family set")
	}
	batch, err := commandBatch(target, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, command := range batch.Nftables {
		value, ok := command.Add.(map[string]any)
		if !ok {
			continue
		}
		set, ok := value["set"].(map[string]any)
		if !ok || set["name"] != emptyName {
			continue
		}
		found = true
		if _, exists := set["elem"]; exists {
			t.Fatalf("empty set unexpectedly supplied elements: %#v", set)
		}
	}
	if !found {
		t.Fatalf("empty geo set %q was omitted from nftables batch", emptyName)
	}
	if !setElementsComplete(nftObject{}, policy.IPv4, nil) {
		t.Fatal("missing element field was not accepted for an empty set")
	}
	if !setElementsComplete(nftObject{Elem: json.RawMessage(`[]`)}, policy.IPv4, nil) {
		t.Fatal("empty element array was not accepted for an empty set")
	}
}

func TestRetireFlushesEntryBeforeGeneration(t *testing.T) {
	previous := testTarget(t, testGenA)
	candidate := *previous
	candidate.Generation = testGenB
	candidate.Families = []policy.FamilyPlan{cloneFamilies(previous.Families)[1]}
	candidate.Counters = desiredCounters(&candidate, nil)
	var payload []byte
	backend := &NFT{exec: func(_ context.Context, args []string, input []byte) ([]byte, error) {
		if len(args) >= 3 && args[1] == "list" && args[2] == "tables" {
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"test-perimeterd","comment":"perimeterd owner=0123456789abcdef0123456789abcdef role=table"}}]}`), nil
		}
		if len(args) >= 3 && args[1] == "-f" && args[2] == "-" && strings.Contains(string(input), `"list"`) {
			entry := entryChainName(previous, policy.IPv4, policy.Ingress)
			path := generationChainName(previous, policy.IPv4, policy.Ingress)
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"test-perimeterd","comment":"perimeterd owner=0123456789abcdef0123456789abcdef role=table"}},{"chain":{"family":"inet","table":"test-perimeterd","name":"` + entry + `","comment":"` + ownershipComment(previous.Owner, stableToken, entryRole(policy.IPv4, policy.Ingress), true) + `"}},{"chain":{"family":"inet","table":"test-perimeterd","name":"` + path + `","comment":"` + ownershipComment(previous.Owner, previous.Generation, chainRole(policy.IPv4, policy.Ingress), false) + `"}}]}`), nil
		}
		payload = append([]byte(nil), input...)
		return []byte(`{"nftables":[]}`), nil
	}}
	if err := backend.Retire(context.Background(), previous, &candidate); err != nil {
		t.Fatal(err)
	}
	var batch nftBatch
	if err := json.Unmarshal(payload, &batch); err != nil {
		t.Fatal(err)
	}
	if len(batch.Nftables) < 4 {
		t.Fatalf("retirement batch too small: %s", payload)
	}
	first := batch.Nftables[0].Flush.(map[string]any)["chain"].(map[string]any)["name"]
	if first != entryChainName(previous, policy.IPv4, policy.Ingress) {
		t.Fatalf("first retirement operation deleted %v, want entry chain", first)
	}
}

func TestRetireDeletesCandidateOnlyCountersOnRollback(t *testing.T) {
	previous := testTarget(t, testGenA)
	candidate := *previous
	candidate.Generation = testGenB
	candidate.Families = cloneFamilies(previous.Families)
	for familyIndex := range candidate.Families {
		for pathIndex := range candidate.Families[familyIndex].Paths {
			for ruleIndex := range candidate.Families[familyIndex].Paths[pathIndex].Rules {
				rule := &candidate.Families[familyIndex].Paths[pathIndex].Rules[ruleIndex]
				if rule.Counter.Kind == policy.Denied {
					rule.Counter.Action = policy.Reject
					rule.Action = policy.Reject
				}
			}
		}
	}
	candidate.Counters = desiredCounters(&candidate, nil)
	var oldCounter CounterSpec
	for _, counter := range previous.Counters {
		if counter.Role.Kind == policy.Denied {
			oldCounter = counter
			break
		}
	}
	if oldCounter.Name == "" {
		t.Fatal("test target did not contain a denial counter")
	}
	var payload []byte
	backend := &NFT{exec: func(_ context.Context, args []string, input []byte) ([]byte, error) {
		if len(args) >= 3 && args[1] == "list" && args[2] == "tables" {
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"test-perimeterd","comment":"perimeterd owner=0123456789abcdef0123456789abcdef role=table"}}]}`), nil
		}
		if len(args) >= 3 && args[1] == "-f" && args[2] == "-" && strings.Contains(string(input), `"list"`) {
			return []byte(`{"nftables":[{"table":{"family":"inet","name":"test-perimeterd","comment":"perimeterd owner=0123456789abcdef0123456789abcdef role=table"}},{"counter":{"family":"inet","table":"test-perimeterd","name":"` + oldCounter.Name + `","comment":"` + ownershipComment(previous.Owner, stableToken, "counter/"+oldCounter.Name, true) + `"}}]}`), nil
		}
		payload = append([]byte(nil), input...)
		return []byte(`{"nftables":[]}`), nil
	}}
	if err := backend.Retire(context.Background(), previous, &candidate); err != nil {
		t.Fatal(err)
	}
	var batch nftBatch
	if err := json.Unmarshal(payload, &batch); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, command := range batch.Nftables {
		if value, ok := command.Delete.(map[string]any); ok {
			if counter, ok := value["counter"].(map[string]any); ok && counter["name"] == oldCounter.Name {
				found = true
			}
		}
	}
	if !found {
		t.Fatalf("rollback retirement omitted candidate-only counter %q", oldCounter.Name)
	}
}

func TestValidateInventoryRejectsWrongOwnedBaseHook(t *testing.T) {
	target := testTarget(t, testGenA)
	inventory := newNFTInventory()
	inventory.present = true
	inventory.table = nftObject{Kind: "table", Family: "inet", Name: target.Table, Comment: tableComment(target.Owner)}
	name := baseChainName(target, policy.Ingress)
	inventory.chains[name] = nftObject{Kind: "chain", Family: "inet", Table: target.Table, Name: name, Comment: ownershipComment(target.Owner, stableToken, baseRole(policy.Ingress), true), Type: "filter", Hook: "output", Policy: "accept", Prio: target.Priority, HasPrio: true}
	if err := validateInventory(inventory, target); err == nil {
		t.Fatal("wrong owned base hook was accepted")
	}
}

func TestCaptureLimitCannotBeBypassedByIOCopy(t *testing.T) {
	buffer := boundedBuffer{limit: 16}
	// LimitReader hides strings.Reader.WriteTo, exercising io.Copy's destination
	// ReaderFrom path if bytes.Buffer is accidentally embedded again.
	source := io.LimitReader(strings.NewReader(strings.Repeat("x", 64)), 64)
	if _, err := io.Copy(&buffer, source); err == nil {
		t.Fatal("output capture accepted bytes beyond its limit")
	}
	if len(buffer.Bytes()) > buffer.limit {
		t.Fatal("output capture retained bytes beyond its limit")
	}
}

func TestOversizedTargetRejectedBeforeNativeCommands(t *testing.T) {
	cfg := config.Config{
		Version: 1,
		Firewall: config.FirewallConfig{
			Backend: "nftables", DenyAction: "drop", IPv6: true,
			Nftables: config.NftablesConfig{Table: "capacity-test", Priority: -10},
		},
	}
	base := netip.MustParseAddr("2600:1234:5678:9abc:def0:1234:1234:1000").As16()
	for index := uint32(0); index < 600000; index++ {
		address := base
		binary.BigEndian.PutUint32(address[12:], 0x12341000+index*2)
		cfg.Global.Blocklist = append(cfg.Global.Blocklist, netip.PrefixFrom(netip.AddrFrom16(address), 128))
	}
	model, err := policy.Compile(cfg, policy.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	target, err := BuildTarget(testOwner, testGenA, cfg, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	backend := &NFT{exec: func(context.Context, []string, []byte) ([]byte, error) {
		t.Fatal("oversized target reached native execution")
		return nil, nil
	}}
	if err := backend.Preflight(context.Background(), nil, target); err == nil {
		t.Fatal("oversized target passed preflight")
	}
	if err := backend.Apply(context.Background(), nil, target); err == nil {
		t.Fatal("oversized target passed direct apply")
	}
}

func TestGenerationReconciliationRequiresRuleOrder(t *testing.T) {
	target := testTarget(t, testGenA)
	inventory := newNFTInventory()
	for _, family := range target.Families {
		for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
			for _, rule := range familyPathRules(target, family, direction) {
				data, err := json.Marshal(rule)
				if err != nil {
					t.Fatal(err)
				}
				object, err := decodeNFTObject("rule", data)
				if err != nil {
					t.Fatal(err)
				}
				inventory.rules = append(inventory.rules, object)
			}
		}
	}
	if !generationRulesComplete(inventory, target) {
		t.Fatal("generated ordered policy was rejected")
	}
	// Reversing each chain puts its final unconditional return before denials,
	// without changing any rule's expression or ownership marker.
	for left, right := 0, len(inventory.rules)-1; left < right; left, right = left+1, right-1 {
		inventory.rules[left], inventory.rules[right] = inventory.rules[right], inventory.rules[left]
	}
	if generationRulesComplete(inventory, target) {
		t.Fatal("reordered policy bypassing denials was accepted as complete")
	}
}

func TestBuildTargetKeepsDynamicIdentityAcrossStaticReplacement(t *testing.T) {
	base := config.Config{
		Version:  1,
		Global:   config.GlobalConfig{Blocklist: []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}},
		CrowdSec: config.CrowdSecConfig{Enabled: true},
		Firewall: config.FirewallConfig{Backend: "nftables", DenyAction: "drop", IPv4: true, IPv6: true, Nftables: config.NftablesConfig{Table: "crowd-test", Priority: -10}},
	}
	firstModel, err := policy.Compile(base, policy.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	first, err := BuildTarget(testOwner, testGenA, base, firstModel, nil)
	if err != nil {
		t.Fatal(err)
	}
	replacement := base
	replacement.Global.Blocklist = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	secondModel, err := policy.Compile(replacement, policy.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	second, err := BuildTarget(testOwner, testGenB, replacement, secondModel, first)
	if err != nil {
		t.Fatal(err)
	}
	if second.DynamicGeneration != first.DynamicGeneration {
		t.Fatalf("static replacement changed dynamic identity: old=%q new=%q", first.DynamicGeneration, second.DynamicGeneration)
	}
	if second.Generation == first.Generation {
		t.Fatal("static replacement unexpectedly reused packet-path generation")
	}
	var dynamicName string
	for _, family := range second.Families {
		for _, set := range family.Sets {
			if set.Kind == policy.DynamicCrowdSecSet {
				dynamicName = setName(second, family.Family, set.ID)
			}
		}
	}
	if dynamicName == "" || !strings.Contains(dynamicName, second.DynamicGeneration) {
		t.Fatalf("dynamic set name omitted independent identity: %q", dynamicName)
	}
}

func TestDynamicSetCommandsUseTimedBothFamilyIntervals(t *testing.T) {
	target := testTarget(t, testGenA)
	target.DynamicGeneration = testGenA
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	desired := []policy.TimedPrefix{
		{Prefix: netip.MustParsePrefix("::/0"), Deadline: now.Add(2 * time.Hour)},
		{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Deadline: now.Add(2 * time.Hour)},
	}
	commands, err := dynamicSetCommands(target, policy.IPv4, nftObject{}, desired, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 {
		t.Fatalf("IPv4 projection emitted %d commands, want 1", len(commands))
	}
	data, err := json.Marshal(commands[0])
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	if !strings.Contains(text, `"len":0`) || !strings.Contains(text, `"timeout":7200`) ||
		!strings.Contains(text, `"elem":[{"elem":{"timeout":7200,"val":{"prefix"`) {
		t.Fatalf("IPv4 /0 timed element was not lowered exactly: %s", text)
	}
	commands, err = dynamicSetCommands(target, policy.IPv6, nftObject{}, desired, now)
	if err != nil {
		t.Fatal(err)
	}
	if len(commands) != 1 || !strings.Contains(string(marshalNFTJSONForTest(t, commands[0])), `"name":"`+dynamicSetName(target, policy.IPv6)+`"`) {
		t.Fatalf("IPv6 projection was not isolated to its family: %#v", commands)
	}
}

func TestDynamicInventoryRejectsPermanentOrMalformedElements(t *testing.T) {
	target := testTarget(t, testGenA)
	target.DynamicGeneration = testGenA
	now := time.Date(2026, time.January, 2, 3, 4, 5, 0, time.UTC)
	expired := nftObject{Elem: json.RawMessage(`[{"elem":{"val":"203.0.113.7","timeout":5,"expires":0}}]`)}
	commands, err := dynamicSetCommands(target, policy.IPv4, expired, []policy.TimedPrefix{{Prefix: netip.MustParsePrefix("203.0.113.7/32"), Deadline: now.Add(time.Minute)}}, now)
	if err != nil || len(commands) != 2 {
		t.Fatalf("finite expired element was not replaced safely: commands=%#v err=%v", commands, err)
	}
	malformed := []nftObject{
		{Elem: json.RawMessage(`[{"elem":{"val":"203.0.113.7","timeout":0,"expires":0}}]`)},
		{Elem: json.RawMessage(`[{"elem":{"val":"203.0.113.7","timeout":5}}]`)},
		{Elem: json.RawMessage(`[{"elem":{"val":"203.0.113.7","timeout":5,"expires":5,"foreign":true}}]`)},
	}
	for index, observed := range malformed {
		if _, err := dynamicSetCommands(target, policy.IPv4, observed, []policy.TimedPrefix{{Prefix: netip.MustParsePrefix("203.0.113.7/32"), Deadline: now.Add(time.Minute)}}, now); err == nil {
			t.Fatalf("malformed dynamic element %d was accepted", index)
		}
	}
}

func marshalNFTJSONForTest(t *testing.T, value any) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}
