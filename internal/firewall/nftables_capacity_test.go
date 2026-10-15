package firewall

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func capacityClone(target *Target) *Target {
	copy := *target
	copy.Families = policy.CloneFamilies(target.Families)
	copy.Counters = append([]CounterSpec(nil), target.Counters...)
	return &copy
}

func capacityDynamicTarget(t *testing.T) *Target {
	t.Helper()
	cfg := config.Config{Version: 1, CrowdSec: config.CrowdSecConfig{Enabled: true}, Firewall: config.FirewallConfig{Backend: "nftables", DenyAction: "drop", IPv4: true, IPv6: true, Nftables: config.NftablesConfig{Table: "dynamic-capacity", Priority: -10}}}
	model, err := policy.Compile(cfg, policy.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	target, err := BuildTarget(testOwner, testGenA, cfg, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func TestNFTCapacityChargesReusedNativeIdentityOnce(t *testing.T) {
	target := testTarget(t, testGenA)
	one, err := validateNFTCapacity(t.Context(), nil, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	budget := one.tables[target.Table].estimate()
	for _, previous := range []*Target{target, capacityClone(target)} {
		pair, err := validateNFTCapacity(t.Context(), previous, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		if err := pair.check(maxNFTInput, budget); err != nil {
			t.Fatalf("same identity failed single-generation budget: %v", err)
		}
		if err := pair.check(maxNFTInput, budget-1); err == nil {
			t.Fatal("inventory accepted one byte above its budget")
		}
	}
	other := capacityClone(target)
	other.Generation = testGenB // Equal memberships are not the same native objects.
	pair, err := validateNFTCapacity(t.Context(), target, other, nil)
	if err != nil {
		t.Fatal(err)
	}
	var capacity *CapacityError
	err = pair.check(maxNFTInput, budget)
	if !errors.As(fmt.Errorf("wrapped: %w", errors.Join(errors.New("other cause"), err)), &capacity) || capacity.RequiredBytes <= budget || capacity.LimitBytes != budget || capacity.StaticGenerations != 2 || capacity.RecoveryRetryable() {
		t.Fatalf("distinct transition lost bounded capacity diagnostic: %+v %v", capacity, err)
	}
	input := one.inputs[target]
	if err := one.check(input, budget); err != nil {
		t.Fatal(err)
	}
	if err := one.check(input-1, budget); !errors.As(err, &capacity) || capacity.Scope != "input" {
		t.Fatalf("input bound not enforced: %v", err)
	}
}

func TestNFTCapacityRejectsConflictingSharedMetadataBeforeNative(t *testing.T) {
	target := testTarget(t, testGenA)
	conflict := capacityClone(target)
	for i := range conflict.Families {
		for j := range conflict.Families[i].Sets {
			set := &conflict.Families[i].Sets[j]
			if set.ID == "global_blocklist" && conflict.Families[i].Family == policy.IPv4 {
				set.Prefixes = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
			}
		}
	}
	backend := &NFT{exec: func(context.Context, []string, []byte) ([]byte, error) {
		t.Fatal("conflicting identity reached native command")
		return nil, nil
	}}
	var invalid *ValidationError
	if err := backend.Preflight(t.Context(), target, conflict, nil); !errors.As(err, &invalid) {
		t.Fatalf("conflicting shared set was admitted: %v", err)
	}
	if err := backend.Apply(t.Context(), target, conflict, nil); !errors.As(err, &invalid) {
		t.Fatalf("recovery admitted conflicting shared set: %v", err)
	}
}

func TestNFTCapacityAccountsIndependentStaticAndDynamicIdentity(t *testing.T) {
	target := capacityDynamicTarget(t)
	projection := &DynamicState{Prefixes: []policy.TimedPrefix{{Prefix: netip.MustParsePrefix("198.51.100.1/32"), Deadline: time.Now().Add(time.Hour)}}}
	one, err := validateNFTCapacity(t.Context(), nil, target, projection)
	if err != nil {
		t.Fatal(err)
	}
	budget := one.tables[target.Table].estimate()
	copy := capacityClone(target)
	shared, err := validateNFTCapacity(t.Context(), target, copy, projection)
	if err != nil || shared.check(maxNFTInput, budget) != nil {
		t.Fatalf("shared static/dynamic identity charged twice: %v", err)
	}
	copy.Generation = testGenB
	differentStatic, err := validateNFTCapacity(t.Context(), target, copy, projection)
	if err != nil {
		t.Fatal(err)
	}
	table := differentStatic.tables[target.Table]
	if len(table.staticIDs) != 2 || len(table.dynamicIDs) != 1 || table.estimate() <= budget {
		t.Fatalf("independent generation accounting: %+v", table)
	}
	// A different dynamic reference under an immutable path identity conflicts.
	copy = capacityClone(target)
	copy.DynamicGeneration = testGenB
	var invalid *ValidationError
	if _, err := validateNFTCapacity(t.Context(), target, copy, projection); !errors.As(err, &invalid) {
		t.Fatalf("same path with conflicting dynamic reference accepted: %v", err)
	}
	// Unreferenced dynamic containers may independently coexist with shared
	// static artifacts; their distinct identities must still be charged.
	for i := range target.Families {
		for j := range target.Families[i].Paths {
			rules := target.Families[i].Paths[j].Rules[:0]
			for _, rule := range target.Families[i].Paths[j].Rules {
				if rule.Match.SetID != "crowdsec" {
					rules = append(rules, rule)
				}
			}
			target.Families[i].Paths[j].Rules = rules
		}
	}
	copy = capacityClone(target)
	copy.DynamicGeneration = testGenB
	differentDynamic, err := validateNFTCapacity(t.Context(), target, copy, projection)
	if err != nil {
		t.Fatal(err)
	}
	table = differentDynamic.tables[target.Table]
	if len(table.staticIDs) != 1 || len(table.dynamicIDs) != 2 {
		t.Fatalf("shared static generation hid dynamic identity: %+v", table)
	}
}

func TestNFTCapacityIncludesRetainedLiveLeases(t *testing.T) {
	target := capacityDynamicTarget(t)
	copy := capacityClone(target)
	copy.Generation, copy.DynamicGeneration = testGenB, testGenB
	projection := &DynamicState{Prefixes: []policy.TimedPrefix{{Prefix: netip.MustParsePrefix("198.51.100.1/32"), Deadline: time.Now().Add(time.Hour)}}}
	capacity, err := validateNFTCapacity(t.Context(), target, copy, projection)
	if err != nil {
		t.Fatal(err)
	}
	before := capacity.tables[target.Table].estimate()
	inventory := newNFTInventory()
	inventory.present = true
	var values []any
	for i := range 128 {
		values = append(values, map[string]any{"elem": map[string]any{"val": fmt.Sprintf("203.0.113.%d", i*2), "timeout": 3600, "expires": 3500}})
	}
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatal(err)
	}
	name := dynamicSetName(target, policy.IPv4)
	inventory.sets[name] = nftObject{Elem: encoded}
	if err := capacity.observe(t.Context(), target.Table, inventory); err != nil {
		t.Fatal(err)
	}
	var exceeded *CapacityError
	if err := capacity.check(maxNFTInput, before); !errors.As(err, &exceeded) || exceeded.DynamicGenerations != 2 {
		t.Fatalf("old live authority was omitted from transition: %v", err)
	}
	// Observing the same retained identity again must not accumulate its cost.
	after := capacity.tables[target.Table].estimate()
	if err := capacity.observe(t.Context(), target.Table, inventory); err != nil {
		t.Fatal(err)
	}
	if err := capacity.check(maxNFTInput, after); err != nil {
		t.Fatalf("retained dynamic inventory double counted: %v", err)
	}
}

func TestNFTInventoryCompleteBoundedAdmission(t *testing.T) {
	valid := `{"nftables":[{"table":{"family":"inet","name":"owned"}},{"set":{"family":"inet","table":"owned","name":"addresses","type":"ipv4_addr","elem":["198.51.100.1"]}}]}`
	objects, err := decodeNFTObjects(t.Context(), []byte(valid), len(valid))
	if err != nil || len(objects) != 2 || objects[0].Name != "owned" || objects[1].Name != "addresses" || string(objects[1].Elem) != `["198.51.100.1"]` {
		t.Fatalf("exact-boundary inventory: %+v %v", objects, err)
	}
	for _, data := range []string{valid + " ", valid + `{}`, valid[:len(valid)-2], `{"nftables":null}`, `{"nftables":[],"nftables":[]}`, `{"nftables":[{"table":null}]}`} {
		limit := len(valid)
		if data != valid+" " {
			limit = len(data) + 1
		}
		objects, err := decodeNFTObjects(t.Context(), []byte(data), limit)
		if err == nil || objects != nil {
			t.Fatalf("invalid/over-limit inventory accepted a partial result: %q %+v %v", data, objects, err)
		}
	}
	ctx, cancel := context.WithCancel(t.Context())
	cancel()
	if _, err := decodeNFTObjects(ctx, []byte(valid), len(valid)); !errors.Is(err, context.Canceled) {
		t.Fatalf("inventory ignored cancellation: %v", err)
	}
	backend := &NFT{exec: func(context.Context, []string, []byte) ([]byte, error) {
		t.Fatal("canceled estimation reached native command")
		return nil, nil
	}}
	if err := backend.Apply(ctx, testTarget(t, testGenA), testTarget(t, testGenA), nil); !errors.Is(err, context.Canceled) {
		t.Fatalf("capacity ignored cancellation: %v", err)
	}
}

func TestNativeOutputOverflowNeverReturnsPartialInventory(t *testing.T) {
	data, err := executeNative(t.Context(), "sh", []string{"-c", "printf '12345678901234567890123456789012'; printf 'SECRET' >&2; exit 1"}, nil, 0, 16)
	var overflow *nativeOutputLimitError
	if data != nil || !errors.As(err, &overflow) || overflow.limit != 16 || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("overflow returned partial data or arbitrary diagnostics: %q %v", data, err)
	}
}
