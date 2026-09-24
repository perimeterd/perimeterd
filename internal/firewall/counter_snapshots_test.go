package firewall

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestNFTSnapshotCountersReadsOnlyOwnedNativeValues(t *testing.T) {
	target := testTarget(t, testGenA)
	backend := &NFT{exec: func(_ context.Context, args []string, input []byte) ([]byte, error) {
		if len(args) == 3 && args[1] == "list" && args[2] == "tables" {
			return nftCounterTableJSON(target), nil
		}
		if strings.Contains(string(input), `"list"`) {
			return nftCounterInventoryJSON(target, false, true), nil
		}
		t.Fatalf("unexpected nft counter command: args=%v input=%s", args, input)
		return nil, nil
	}}

	values, err := backend.SnapshotCounters(context.Background(), target)
	if err != nil {
		t.Fatal(err)
	}
	if len(values) != len(target.Counters) {
		t.Fatalf("snapshot returned %d rows for %d owned counters", len(values), len(target.Counters))
	}
	var processed, denied bool
	for _, value := range values {
		if value.Backend != "nftables" || value.Generation != target.Generation || value.Retired {
			t.Fatalf("snapshot identity is wrong: %+v", value)
		}
		if value.ProcessedPackets != 0 {
			processed = true
			if value.ProcessedPackets != 17 || value.ProcessedBytes != 1700 || value.DeniedPackets != 0 {
				t.Fatalf("processed counter values are wrong: %+v", value)
			}
		}
		if value.DeniedPackets != 0 {
			denied = true
			if value.DeniedPackets != 5 || value.DeniedBytes != 500 || value.ProcessedPackets != 0 {
				t.Fatalf("denied counter values are wrong: %+v", value)
			}
		}
		if strings.Contains(value.Rule, "foreign") {
			t.Fatalf("foreign counter escaped the ownership filter: %+v", value)
		}
	}
	if !processed || !denied {
		t.Fatalf("snapshot omitted a counter class: processed=%t denied=%t", processed, denied)
	}
}

func TestNFTRetirementReportsFinalCountersBeforeDelete(t *testing.T) {
	for _, malformed := range []bool{false, true} {
		name := "valid"
		if malformed {
			name = "malformed-native-value"
		}
		t.Run(name, func(t *testing.T) {
			target := testTarget(t, testGenA)
			hookCalled, deletedBeforeHook := false, false
			var hookRows []CounterSnapshot
			var hookErr error
			backend := &NFT{exec: func(_ context.Context, args []string, input []byte) ([]byte, error) {
				if len(args) == 3 && args[1] == "list" && args[2] == "tables" {
					return nftCounterTableJSON(target), nil
				}
				request := string(input)
				if strings.Contains(request, `"list"`) {
					return nftCounterInventoryJSON(target, malformed, false), nil
				}
				if strings.Contains(request, `"delete"`) {
					if !hookCalled {
						deletedBeforeHook = true
					}
					return []byte(`{"nftables":[]}`), nil
				}
				t.Fatalf("unexpected nft counter command: args=%v input=%s", args, input)
				return nil, nil
			}}
			backend.SetCounterRetirementHook(func(rows []CounterSnapshot, err error) {
				hookCalled = true
				hookRows = rows
				hookErr = err
			})

			if err := backend.Retire(context.Background(), target, nil); err != nil {
				t.Fatalf("telemetry failure changed enforcement retirement: %v", err)
			}
			if !hookCalled || deletedBeforeHook {
				t.Fatalf("retirement hook/deletion order is wrong: hook=%t delete-before-hook=%t", hookCalled, deletedBeforeHook)
			}
			if malformed {
				if hookErr == nil || len(hookRows) != 1 || hookRows[0].Rule != "" || !hookRows[0].Retired {
					t.Fatalf("malformed native telemetry was not reported as metadata-only: rows=%+v err=%v", hookRows, hookErr)
				}
				return
			}
			if hookErr != nil || len(hookRows) != len(target.Counters)+1 {
				t.Fatalf("final retirement snapshot is incomplete: rows=%d want=%d err=%v", len(hookRows), len(target.Counters)+1, hookErr)
			}
			if hookRows[0].Backend != "nftables" || hookRows[0].Generation != target.Generation || !hookRows[0].Retired {
				t.Fatalf("missing retired-generation marker: %+v", hookRows[0])
			}
			for _, value := range hookRows[1:] {
				if !value.Retired || value.Generation != target.Generation {
					t.Fatalf("counter was not marked retired: %+v", value)
				}
			}
		})
	}
}

func TestIPTablesSnapshotCountersRequireAndSelectOwnedRuleStats(t *testing.T) {
	attachments := []config.Attachment{{Chain: "INPUT", Direction: "ingress"}, {Chain: "OUTPUT", Direction: "egress"}}
	first := iptModelTestTarget(testGenA, attachments)
	first.Table = "filter"
	first.Counters = desiredCounters(first, nil)
	backend := &IPTables{exec: func(_ context.Context, command string, args []string, _ []byte) ([]byte, error) {
		if command != "iptables-save" || len(args) != 1 || args[0] != "--counters" {
			return nil, fmt.Errorf("unexpected counter command: %s %v", command, args)
		}
		return iptCounterSaveForTest(t, first, true), nil
	}}
	values, err := backend.SnapshotCounters(context.Background(), first)
	if err != nil {
		t.Fatal(err)
	}
	var processedCount, deniedCount int
	processedIDs, deniedIDs := make(map[string]bool), make(map[string]bool)
	for _, value := range values {
		if value.Backend != "iptables" || value.Generation != testGenA || value.Retired {
			t.Fatalf("snapshot identity is wrong: %+v", value)
		}
		if value.ProcessedPackets != 0 {
			processedCount++
			processedIDs[value.Rule] = true
			if value.ProcessedPackets != 11 || value.ProcessedBytes != 1100 {
				t.Fatalf("processed native counters were not preserved: %+v", value)
			}
		}
		if value.DeniedPackets != 0 {
			deniedCount++
			deniedIDs[value.Rule] = true
			if value.DeniedPackets != 4 || value.DeniedBytes != 400 || value.Reason != policy.GlobalBlocklist || value.Action != policy.Drop {
				t.Fatalf("denied native counters or role were not preserved: %+v", value)
			}
		}
		if strings.Contains(value.Rule, "foreign") {
			t.Fatalf("foreign iptables rule escaped the ownership filter: %+v", value)
		}
	}
	if processedCount != 2 || deniedCount != 2 {
		t.Fatalf("snapshot returned unexpected owned counter classes: processed=%d denied=%d rows=%+v", processedCount, deniedCount, values)
	}

	second := iptModelTestTarget(testGenB, attachments)
	second.Table = "filter"
	second.Counters = desiredCounters(second, nil)
	secondBackend := &IPTables{exec: func(context.Context, string, []string, []byte) ([]byte, error) {
		return iptCounterSaveForTest(t, second, true), nil
	}}
	secondValues, err := secondBackend.SnapshotCounters(context.Background(), second)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range secondValues {
		if value.ProcessedPackets != 0 && !processedIDs[value.Rule] {
			t.Fatalf("processed rule identity changed across generation: %q", value.Rule)
		}
		if value.DeniedPackets != 0 && deniedIDs[value.Rule] {
			t.Fatalf("generation-specific denial identity was reused: %q", value.Rule)
		}
	}

	missingBackend := &IPTables{exec: func(context.Context, string, []string, []byte) ([]byte, error) {
		return iptCounterSaveForTest(t, first, false), nil
	}}
	if _, err := missingBackend.SnapshotCounters(context.Background(), first); err == nil {
		t.Fatal("snapshot accepted iptables-save output without native counters")
	}
}

func nftCounterTableJSON(target *Target) []byte {
	data, _ := json.Marshal(map[string]any{"nftables": []any{
		map[string]any{"table": map[string]any{"family": "inet", "name": target.Table, "comment": tableComment(target.Owner)}},
	}})
	return data
}

func nftCounterInventoryJSON(target *Target, malformed, foreign bool) []byte {
	objects := []any{map[string]any{"table": map[string]any{"family": "inet", "name": target.Table, "comment": tableComment(target.Owner)}}}
	for index, spec := range target.Counters {
		packets, byteCount := any(uint64(17)), any(uint64(1700))
		if spec.Role.Kind == policy.Denied {
			packets, byteCount = uint64(5), uint64(500)
		}
		if malformed && index == 0 {
			packets = "bad-counter-value"
		}
		objects = append(objects, map[string]any{"counter": map[string]any{
			"family": "inet", "table": target.Table, "name": spec.Name,
			"comment": ownershipComment(target.Owner, stableToken, "counter/"+spec.Name, true),
			"packets": packets, "bytes": byteCount,
		}})
	}
	if foreign {
		objects = append(objects, map[string]any{"counter": map[string]any{
			"family": "inet", "table": target.Table, "name": "foreign-counter", "comment": "foreign",
			"packets": uint64(99), "bytes": uint64(9900),
		}})
	}
	data, _ := json.Marshal(map[string]any{"nftables": objects})
	return data
}

func iptCounterSaveForTest(t *testing.T, target *Target, includeCounters bool) []byte {
	t.Helper()
	family := policy.IPv4
	model, err := buildIPTFamily(target, family, nil)
	if err != nil {
		t.Fatal(err)
	}
	chains := append(append([]iptChain(nil), model.Active...), model.Staging...)
	chainNames := map[string]struct{}{"INPUT": {}, "OUTPUT": {}}
	for _, chain := range chains {
		chainNames[chain.Name] = struct{}{}
	}
	names := make([]string, 0, len(chainNames))
	for name := range chainNames {
		names = append(names, name)
	}
	sort.Strings(names)
	var output strings.Builder
	output.WriteString("*filter\n")
	for _, name := range names {
		fmt.Fprintf(&output, ":%s - [0:0]\n", name)
	}
	for _, group := range []struct {
		chains         []iptChain
		generationRule bool
	}{{model.Active, false}, {model.Staging, true}} {
		for _, chain := range group.chains {
			for _, rule := range chain.Rules {
				packets, byteCount := uint64(1), uint64(100)
				if _, role, ok := iptCounterRole(target, family, rule.Args, group.generationRule); ok {
					if role.Kind == policy.Processed {
						packets, byteCount = 11, 1100
					} else {
						packets, byteCount = 4, 400
					}
				}
				line, err := renderIPTRule(chain.Name, rule)
				if err != nil {
					t.Fatal(err)
				}
				if includeCounters {
					fmt.Fprintf(&output, "[%d:%d] %s\n", packets, byteCount, line)
				} else {
					fmt.Fprintf(&output, "%s\n", line)
				}
			}
		}
	}
	output.WriteString("[99:9900] -A INPUT -m comment --comment foreign -j RETURN\nCOMMIT\n")
	return []byte(output.String())
}
