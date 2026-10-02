package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

// These native-shaped witness objects deliberately do not use the renderer.
func nativeWitnessFixture(target *Target) []map[string]any {
	name := "pd_" + target.Owner + "_stable_ownership"
	return []map[string]any{
		{"chain": map[string]any{"family": "inet", "table": target.Table, "name": name}},
		{"rule": map[string]any{"family": "inet", "table": target.Table, "chain": name, "comment": "perimeterd owner=" + target.Owner + " role=table_witness_v1", "expr": []any{map[string]any{"return": nil}}}},
	}
}

func nftFixtureResponse(t *testing.T, target *Target, children ...map[string]any) []byte {
	t.Helper()
	objects := []map[string]any{{"table": map[string]any{"family": "inet", "name": target.Table}}}
	objects = append(objects, nativeWitnessFixture(target)...)
	objects = append(objects, children...)
	data, err := json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// The executor interprets typed list-table/list-chain requests and atomic batches.
// It models object-comment loss separately from the submitted transaction.
type nftFixtureExecutor struct {
	t            *testing.T
	objects      []map[string]any
	batches      [][]map[string]any
	dropComments bool
	lostAck      bool
	badReadback  bool
}

func (f *nftFixtureExecutor) encode(objects []map[string]any) []byte {
	data, err := json.Marshal(map[string]any{"nftables": objects})
	if err != nil {
		f.t.Fatal(err)
	}
	return data
}

func (f *nftFixtureExecutor) execute(_ context.Context, args []string, input []byte) ([]byte, error) {
	if len(args) == 3 && args[1] == "list" && args[2] == "tables" {
		tables := []map[string]any{}
		for _, object := range f.objects {
			if _, ok := object["table"]; ok {
				tables = append(tables, object)
			}
		}
		return f.encode(tables), nil
	}
	var batch struct {
		NFTables []map[string]any `json:"nftables"`
	}
	if err := json.Unmarshal(input, &batch); err != nil {
		return nil, err
	}
	if len(batch.NFTables) == 1 {
		if list, ok := batch.NFTables[0]["list"].(map[string]any); ok {
			if _, ok := list["table"]; ok {
				return f.encode(f.objects), nil
			}
			if chain, ok := list["chain"].(map[string]any); ok {
				if f.badReadback {
					return f.encode([]map[string]any{}), nil
				}
				objects := []map[string]any{}
				for _, object := range f.objects {
					if value, ok := object["chain"].(map[string]any); ok && value["name"] == chain["name"] {
						objects = append(objects, object)
					}
					if value, ok := object["rule"].(map[string]any); ok && value["chain"] == chain["name"] {
						objects = append(objects, object)
					}
				}
				return f.encode(objects), nil
			}
			return nil, errors.New("unsupported typed list request")
		}
	}
	f.batches = append(f.batches, batch.NFTables)
	for _, command := range batch.NFTables {
		for operation, raw := range command {
			definition := raw.(map[string]any)
			for kind, raw := range definition {
				value := raw.(map[string]any)
				switch operation {
				case "add", "create":
					if kind == "element" {
						for _, object := range f.objects {
							if set, ok := object["set"].(map[string]any); ok && set["name"] == value["name"] {
								elements := make([]any, 0, len(value["elem"].([]any)))
								for _, raw := range value["elem"].([]any) {
									element := raw.(map[string]any)["elem"].(map[string]any)
									elements = append(elements, map[string]any{"elem": map[string]any{
										"val": element["val"], "timeout": element["timeout"], "expires": element["timeout"],
									}})
								}
								set["elem"] = elements
							}
						}
						continue
					}
					if f.dropComments && kind != "rule" {
						delete(value, "comment")
					}
					if kind == "counter" {
						value["packets"] = float64(17)
						value["bytes"] = float64(1700)
					}
					f.objects = append(f.objects, map[string]any{kind: value})
				case "flush", "delete":
					retained := f.objects[:0]
					for _, object := range f.objects {
						remove := false
						if kind == "table" {
							remove = true
						}
						if objectValue, ok := object[kind].(map[string]any); ok && objectValue["name"] == value["name"] && operation == "delete" {
							remove = true
						}
						if kind == "set" && operation == "flush" {
							if set, ok := object["set"].(map[string]any); ok && set["name"] == value["name"] {
								delete(set, "elem")
							}
						}
						if kind == "chain" {
							if rule, ok := object["rule"].(map[string]any); ok && rule["chain"] == value["name"] {
								remove = true
							}
						}
						if !remove {
							retained = append(retained, object)
						}
					}
					f.objects = retained
				default:
					return nil, errors.New("unsupported mutation")
				}
			}
		}
	}
	if f.lostAck {
		f.lostAck = false
		return nil, errors.New("lost native acknowledgement")
	}
	return f.encode([]map[string]any{}), nil
}

func fixtureTable(target *Target) map[string]any {
	return map[string]any{"table": map[string]any{"family": "inet", "name": target.Table}}
}

func TestNFTWitnessOwnershipMatrix(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Target, []map[string]any) []map[string]any
	}{
		{"missing-chain", func(_ *Target, o []map[string]any) []map[string]any { return o[1:] }},
		{"missing-rule", func(_ *Target, o []map[string]any) []map[string]any { return o[:1] }},
		{"duplicate-chain", func(_ *Target, o []map[string]any) []map[string]any { return append(o, o[0]) }},
		{"duplicate-rule", func(_ *Target, o []map[string]any) []map[string]any { return append(o, o[1]) }},
		{"foreign-owner", func(_ *Target, o []map[string]any) []map[string]any {
			o[1]["rule"].(map[string]any)["comment"] = "perimeterd owner=ffffffffffffffffffffffffffffffff role=table_witness_v1"
			return o
		}},
		{"wrong-table", func(_ *Target, o []map[string]any) []map[string]any {
			o[0]["chain"].(map[string]any)["table"] = "foreign"
			return o
		}},
		{"wrong-family", func(_ *Target, o []map[string]any) []map[string]any {
			o[1]["rule"].(map[string]any)["family"] = "ip"
			return o
		}},
		{"malformed-expression", func(_ *Target, o []map[string]any) []map[string]any {
			o[1]["rule"].(map[string]any)["expr"] = []any{map[string]any{"accept": nil}}
			return o
		}},
		{"hook", func(_ *Target, o []map[string]any) []map[string]any {
			o[0]["chain"].(map[string]any)["hook"] = "input"
			return o
		}},
		{"empty-type", func(_ *Target, o []map[string]any) []map[string]any {
			o[0]["chain"].(map[string]any)["type"] = ""
			return o
		}},
		{"empty-hook", func(_ *Target, o []map[string]any) []map[string]any {
			o[0]["chain"].(map[string]any)["hook"] = ""
			return o
		}},
		{"empty-policy", func(_ *Target, o []map[string]any) []map[string]any {
			o[0]["chain"].(map[string]any)["policy"] = ""
			return o
		}},
		{"priority-zero", func(_ *Target, o []map[string]any) []map[string]any {
			o[0]["chain"].(map[string]any)["prio"] = 0
			return o
		}},
		{"flags", func(_ *Target, o []map[string]any) []map[string]any {
			o[0]["chain"].(map[string]any)["flags"] = []string{"offload"}
			return o
		}},
		{"empty-flags", func(_ *Target, o []map[string]any) []map[string]any {
			o[0]["chain"].(map[string]any)["flags"] = []string{}
			return o
		}},
		{"null-flags", func(_ *Target, o []map[string]any) []map[string]any {
			o[0]["chain"].(map[string]any)["flags"] = nil
			return o
		}},
		{"timeout", func(_ *Target, o []map[string]any) []map[string]any {
			o[0]["chain"].(map[string]any)["timeout"] = 0
			return o
		}},
		{"reference", func(target *Target, o []map[string]any) []map[string]any {
			return append(o, map[string]any{"rule": map[string]any{"family": "inet", "table": target.Table, "chain": "foreign", "expr": []any{map[string]any{"goto": map[string]any{"target": "pd_" + target.Owner + "_stable_ownership"}}}}})
		}},
		{"contradictory-table-comment", func(target *Target, o []map[string]any) []map[string]any {
			table := fixtureTable(target)
			table["table"].(map[string]any)["comment"] = "foreign"
			return append(o, table)
		}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := testTarget(t, testGenA)
			objects := append([]map[string]any{fixtureTable(target)}, tc.mutate(target, nativeWitnessFixture(target))...)
			fixture := &nftFixtureExecutor{t: t, objects: objects}
			backend := &NFT{exec: fixture.execute}
			if err := backend.Apply(context.Background(), target, target, nil); err == nil {
				t.Fatal("invalid ownership accepted")
			}
			if err := backend.Preflight(context.Background(), target, target, nil); err == nil {
				t.Fatal("preflight accepted invalid ownership")
			}
			if err := backend.Cleanup(context.Background(), []*Target{target}); err == nil {
				t.Fatal("cleanup accepted invalid ownership")
			}
			if err := backend.Retire(context.Background(), target, nil); err == nil {
				t.Fatal("retirement accepted invalid ownership")
			}
			if len(fixture.batches) != 0 {
				t.Fatal("invalid ownership reached mutation")
			}
		})
	}
}

func TestNFTWitnessPortableLifecycleAndCounterAuthority(t *testing.T) {
	target := testTarget(t, testGenA)
	fixture := &nftFixtureExecutor{t: t, dropComments: true}
	backend := &NFT{exec: fixture.execute}
	ctx := context.Background()
	if err := backend.Preflight(ctx, nil, target, nil); err != nil {
		t.Fatal(err)
	}
	if len(fixture.batches) != 0 {
		t.Fatal("preflight mutated kernel")
	}
	if err := backend.Apply(ctx, nil, target, nil); err != nil {
		t.Fatal(err)
	}
	if len(fixture.batches) != 1 {
		t.Fatal("fresh installation was not atomic")
	}
	inventory, err := backend.inspect(ctx, target.Table, target)
	if err != nil {
		t.Fatal(err)
	}
	values, err := nftCounterSnapshots(target, inventory, target)
	if err != nil {
		t.Fatal(err)
	}
	for _, value := range values {
		if value.ProcessedPackets != 17 && value.DeniedPackets != 17 {
			t.Fatalf("counter value changed: %+v", value)
		}
	}
	foreign := *target
	foreign.Owner = testGenB
	if _, err := nftCounterSnapshots(target, inventory, &foreign); err == nil {
		t.Fatal("foreign identity supplied counter authority")
	}
	candidate := *target
	candidate.Priority = -20
	if err := backend.Preflight(ctx, target, &candidate, nil); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, target, &candidate, nil); err != nil {
		t.Fatal(err)
	}
	if err := backend.Retire(ctx, target, &candidate); err != nil {
		t.Fatal(err)
	}
	after, err := backend.SnapshotCounters(ctx, &candidate)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(values, after) {
		t.Fatal("priority replacement changed counters")
	}
	if err := backend.Cleanup(ctx, []*Target{target, &candidate}); err != nil {
		t.Fatal(err)
	}
	if len(fixture.objects) != 0 {
		t.Fatal("cleanup left owned table")
	}
}

func TestNFTWitnessSurvivesOwnedRuleRepair(t *testing.T) {
	target := testTarget(t, testGenA)
	fixture := &nftFixtureExecutor{t: t, dropComments: true}
	backend := &NFT{exec: fixture.execute}
	ctx := context.Background()
	if err := backend.Apply(ctx, nil, target, nil); err != nil {
		t.Fatal(err)
	}
	before, err := backend.SnapshotCounters(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	path := generationChainName(target, policy.IPv4, policy.Ingress)
	for i, object := range fixture.objects {
		if rule, ok := object["rule"].(map[string]any); ok && rule["chain"] == path {
			fixture.objects = append(fixture.objects[:i], fixture.objects[i+1:]...)
			break
		}
	}
	if err := backend.Apply(ctx, target, target, nil); err != nil {
		t.Fatal(err)
	}
	after, err := backend.SnapshotCounters(ctx, target)
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(before, after) {
		t.Fatal("repair reset retained counters")
	}
	inventory, err := backend.inspect(ctx, target.Table, target)
	if err != nil {
		t.Fatal(err)
	}
	if !generationRulesComplete(inventory, target) {
		t.Fatal("owned incomplete packet path was not repaired")
	}
	// A committed existing table cannot use the reboot reconstruction exception.
	retained := fixture.objects[:0]
	for _, object := range fixture.objects {
		if chain, ok := object["chain"].(map[string]any); ok && chain["name"] == witnessChainName(target) {
			continue
		}
		if rule, ok := object["rule"].(map[string]any); ok && rule["chain"] == witnessChainName(target) {
			continue
		}
		retained = append(retained, object)
	}
	fixture.objects = retained
	fixture.batches = nil
	if _, err := backend.SnapshotCounters(ctx, target); err == nil {
		t.Fatal("snapshot ignored missing witness")
	}
	if err := backend.Apply(ctx, target, target, nil); err == nil {
		t.Fatal("committed table missing witness was adopted")
	}
	if len(fixture.batches) != 0 {
		t.Fatal("missing witness was repaired")
	}
}

func TestNFTFreshReadbackFailureAndLostAck(t *testing.T) {
	for _, fault := range []string{"readback", "ack"} {
		t.Run(fault, func(t *testing.T) {
			target := testTarget(t, testGenA)
			fixture := &nftFixtureExecutor{t: t, dropComments: true, badReadback: fault == "readback", lostAck: fault == "ack"}
			backend := &NFT{exec: fixture.execute}
			if err := backend.Apply(context.Background(), nil, target, nil); err == nil {
				t.Fatal("uncertain native boundary reported success")
			}
			if len(fixture.batches) != 1 {
				t.Fatal("fresh mutation was split")
			}
			fixture.badReadback = false
			if err := backend.Apply(context.Background(), nil, target, nil); err != nil {
				t.Fatal(err)
			}
			if len(fixture.batches) != 1 {
				t.Fatal("lost acknowledgement reset policy or counters")
			}
		})
	}
}

func TestNFTPreflightDoesNotAuthorizeCandidateChildren(t *testing.T) {
	previous := testTarget(t, testGenA)
	candidate := testTarget(t, testGenB)
	fixture := &nftFixtureExecutor{t: t, dropComments: true}
	backend := &NFT{exec: fixture.execute}
	ctx := context.Background()
	if err := backend.Apply(ctx, nil, previous, nil); err != nil {
		t.Fatal(err)
	}
	name := generationChainName(candidate, policy.IPv4, policy.Ingress)
	fixture.objects = append(fixture.objects, map[string]any{"chain": map[string]any{"family": "inet", "table": previous.Table, "name": name}})
	fixture.batches = nil
	if err := backend.Preflight(ctx, previous, candidate, nil); err == nil {
		t.Fatal("in-memory candidate expanded durable authority")
	}
	if len(fixture.batches) != 0 {
		t.Fatal("preflight mutated table")
	}
	if err := backend.Apply(ctx, previous, candidate, nil); err != nil {
		t.Fatal("recorded union rejected repairable candidate chain:", err)
	}
}

func TestNFTWitnessDynamicAndFamilyRetirement(t *testing.T) {
	cfg := config.Config{Version: 1, CrowdSec: config.CrowdSecConfig{Enabled: true}, Firewall: config.FirewallConfig{Backend: "nftables", DenyAction: "drop", IPv4: true, IPv6: true, Nftables: config.NftablesConfig{Table: "dynamic-witness", Priority: -10}}}
	model, err := policy.Compile(cfg, policy.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	target, err := BuildTarget(testOwner, testGenA, cfg, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &nftFixtureExecutor{t: t, dropComments: true}
	backend := &NFT{exec: fixture.execute}
	ctx := context.Background()
	if err := backend.Apply(ctx, nil, target, nil); err != nil {
		t.Fatal(err)
	}
	desired := []policy.TimedPrefix{{Prefix: netip.MustParsePrefix("198.51.100.0/24"), Deadline: time.Now().Add(time.Hour)}}
	if err := backend.UpdateDynamic(ctx, target, desired); err != nil {
		t.Fatal(err)
	}
	inventory, err := backend.inspect(ctx, target.Table, target)
	if err != nil {
		t.Fatal(err)
	}
	set := inventory.sets[dynamicSetName(target, policy.IPv4)]
	if len(set.Elem) == 0 {
		t.Fatal("dynamic update did not materialize requested denial")
	}
	cfg.Firewall.IPv6 = false
	model, err = policy.Compile(cfg, policy.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := BuildTarget(testOwner, testGenB, cfg, model, target)
	if err != nil {
		t.Fatal(err)
	}
	if err := backend.Preflight(ctx, target, candidate, nil); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, target, candidate, nil); err != nil {
		t.Fatal(err)
	}
	if err := backend.Retire(ctx, target, candidate); err != nil {
		t.Fatal(err)
	}
	inventory, err = backend.inspect(ctx, candidate.Table, candidate)
	if err != nil {
		t.Fatal(err)
	}
	if inventory.hasSet(dynamicSetName(target, policy.IPv6)) {
		t.Fatal("obsolete dynamic family survived retirement")
	}
	if _, err := backend.SnapshotCounters(ctx, candidate); err != nil {
		t.Fatal(err)
	}
}

func TestNFTWitnessDoesNotAuthorizeForeignChildren(t *testing.T) {
	for _, kind := range []string{"chain", "set", "counter", "known-chain-comment", "known-counter-comment", "table-comment", "duplicate-counter", "duplicate-set"} {
		t.Run(kind, func(t *testing.T) {
			target := testTarget(t, testGenA)
			fixture := &nftFixtureExecutor{t: t, dropComments: true}
			backend := &NFT{exec: fixture.execute}
			ctx := context.Background()
			if err := backend.Apply(ctx, nil, target, nil); err != nil {
				t.Fatal(err)
			}
			switch kind {
			case "chain", "set", "counter":
				fixture.objects = append(fixture.objects, map[string]any{kind: map[string]any{"family": "inet", "table": target.Table, "name": "foreign_child"}})
			default:
				objectKind := "chain"
				if kind == "known-counter-comment" || kind == "duplicate-counter" {
					objectKind = "counter"
				}
				if kind == "table-comment" {
					objectKind = "table"
				}
				if kind == "duplicate-set" {
					objectKind = "set"
				}
				for _, object := range fixture.objects {
					if value, ok := object[objectKind].(map[string]any); ok {
						if kind == "duplicate-counter" || kind == "duplicate-set" {
							fixture.objects = append(fixture.objects, object)
						} else {
							value["comment"] = "foreign"
						}
						break
					}
				}
			}
			fixture.batches = nil
			if err := backend.Cleanup(ctx, []*Target{target}); err == nil {
				t.Fatal("witness adopted foreign or duplicate child")
			}
			if len(fixture.batches) != 0 {
				t.Fatal("foreign child reached mutation")
			}
		})
	}
}
