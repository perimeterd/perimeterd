//go:build linux && e2e

package e2e

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/crowdsec"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func nativeScaleTarget(t *testing.T, kind string, static []netip.Prefix) *firewall.Target {
	t.Helper()
	cfg, err := config.Parse([]byte(fmt.Sprintf("version: 1\nfirewall:\n  backend: %s\n  deny_action: reject\ncrowdsec:\n  enabled: true\n  api_key_file: /unused/native-only-fixture\n", kind)))
	if err != nil {
		t.Fatal(err)
	}
	cfg.Global.Blocklist = static
	model, err := policy.Compile(cfg, policy.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	target, err := firewall.BuildTarget("11111111111111111111111111111111", "22222222222222222222222222222222", cfg, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func largeNativeProjection(ipv6 bool) []policy.TimedPrefix {
	deadline := time.Now().Add(time.Hour)
	values := make([]policy.TimedPrefix, 100000)
	for index := range values {
		var prefix netip.Prefix
		if ipv6 {
			address := [16]byte{0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89}
			binary.BigEndian.PutUint32(address[12:], uint32(index)*4)
			prefix = netip.PrefixFrom(netip.AddrFrom16(address), 127)
		} else {
			var address [4]byte
			binary.BigEndian.PutUint32(address[:], 0x0b000000+uint32(index)*2)
			prefix = netip.PrefixFrom(netip.AddrFrom4(address), 32)
		}
		values[index] = policy.TimedPrefix{Prefix: prefix, Deadline: deadline}
	}
	if ipv6 {
		values[len(values)-1].Prefix = netip.MustParsePrefix(fixtureIPv6Peer + "/128")
	} else {
		values[0].Prefix = netip.MustParsePrefix(fixtureIPv4Peer + "/32")
	}
	return values
}

// Count the actual finite kernel elements, not the requested command payload.
// Exactly two timeout sets also proves successful resizing removed its spare.
func assertNativeProjectionCount(t *testing.T, target *firewall.Target, want int) {
	t.Helper()
	count, sets := 0, 0
	if target.Backend() == "nftables" {
		var response struct {
			NFTables []struct {
				Set *struct {
					Flags    []string          `json:"flags"`
					Elements []json.RawMessage `json:"elem"`
				} `json:"set"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal(command(t, 30*time.Second, "nft", "-j", "list", "table", "inet", target.Table), &response); err != nil {
			t.Fatal(err)
		}
		for _, row := range response.NFTables {
			if row.Set != nil {
				for _, flag := range row.Set.Flags {
					if flag == "timeout" {
						sets++
						count += len(row.Set.Elements)
					}
				}
			}
		}
	} else {
		timed := make(map[string]bool)
		for line := range strings.SplitSeq(string(command(t, 30*time.Second, "ipset", "save")), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			if fields[0] == "create" && strings.Contains(line, " timeout ") {
				timed[fields[1]] = true
				sets++
			}
			if fields[0] == "add" && timed[fields[1]] {
				count++
			}
		}
	}
	if count != want || sets != 2 {
		t.Fatalf("native projection has %d entries across %d timeout sets, want %d entries in two live sets", count, sets, want)
	}
}

func TestE2ECrowdSecNativeScale(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, kind := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(kind, func(t *testing.T) { runIsolated(t, "TestE2ECrowdSecNativeScale", kind) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	kind := os.Getenv(e2eScenario)
	if strings.HasPrefix(kind, "iptables-") {
		installIPTablesTools(t, strings.TrimPrefix(kind, "iptables-"))
		kind = "iptables"
	}
	target := nativeScaleTarget(t, kind, nil)
	backend := firewall.NewNative(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := backend.Preflight(ctx, nil, target, nil); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, nil, target, nil); err != nil {
		t.Fatal(err)
	}
	for _, ipv6 := range []bool{false, true} {
		values := largeNativeProjection(ipv6)
		// Grow an already attached empty set, then renew and replace the complete list.
		if err := backend.UpdateDynamic(ctx, target, values); err != nil {
			t.Fatal(err)
		}
		assertNativeProjectionCount(t, target, len(values))
		if err := backend.UpdateDynamic(ctx, target, values); err != nil {
			t.Fatalf("renew large projection: %v", err)
		}
		network, address := "tcp4", fixtureIPv4Host+":18790"
		if ipv6 {
			network, address = "tcp6", "["+fixtureIPv6Host+"]:18790"
		}
		probeIngress(t, peer, network, address, "reject", "tcp")
		assertNativeProjectionCount(t, target, len(values))
		if ipv6 {
			// Disjoint replacement needs more than one bounded ipset restore:
			// removal and addition text together exceed the 16 MiB call limit.
			for index := range len(values) - 1 {
				address := values[index].Prefix.Addr().As16()
				binary.BigEndian.PutUint32(address[12:], 0x10000000+uint32(index)*4)
				values[index].Prefix = netip.PrefixFrom(netip.AddrFrom16(address), 127)
			}
			if err := backend.UpdateDynamic(ctx, target, values); err != nil {
				t.Fatalf("replace large IPv6 projection: %v", err)
			}
			assertNativeProjectionCount(t, target, len(values))
			probeIngress(t, peer, network, address, "reject", "tcp")
		}
	}
	// A valid source union may produce mapped IPv6 residuals. Exercise install,
	// inspection/reconciliation, and deletion without reinterpreting them as IPv4.
	now := time.Now()
	store := crowdsec.NewStore("native", 1)
	if err := store.Apply(crowdsec.Batch{Startup: true, New: []crowdsec.Decision{
		{ID: 1, Prefix: netip.MustParsePrefix("::/80"), Deadline: now.Add(time.Hour)},
		{ID: 2, Prefix: netip.MustParsePrefix("::fffe:0:0/96"), Deadline: now.Add(2 * time.Hour)},
	}}, 1, now); err != nil {
		t.Fatal(err)
	}
	values := store.Projection(now)
	if err := backend.UpdateDynamic(ctx, target, values); err != nil {
		t.Fatal(err)
	}
	assertNativeProjectionCount(t, target, len(values))
	if err := backend.UpdateDynamic(ctx, target, values); err != nil {
		t.Fatalf("mapped IPv6 reconciliation: %v", err)
	}
	if err := backend.UpdateDynamic(ctx, target, nil); err != nil {
		t.Fatal(err)
	}
	assertNativeProjectionCount(t, target, 0)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18791", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18791", "success", "tcp")
	// Initial installation also goes through bounded preflight with the full list.
	if err := backend.Cleanup(ctx, []*firewall.Target{target}); err != nil {
		t.Fatal(err)
	}
	large := largeNativeProjection(true)
	if err := backend.Preflight(ctx, nil, target, &firewall.DynamicState{Prefixes: large}); err != nil {
		t.Fatalf("preflight large initial projection: %v", err)
	}
	if err := backend.Apply(ctx, nil, target, nil); err != nil {
		t.Fatalf("apply after admission-only projection: %v", err)
	}
	assertNativeProjectionCount(t, target, 0)
	if err := backend.Apply(ctx, nil, target, &firewall.DynamicState{Prefixes: large}); err != nil {
		t.Fatalf("install large initial projection: %v", err)
	}
	assertNativeProjectionCount(t, target, len(large))
	if err := backend.Apply(ctx, target, target, &firewall.DynamicState{}); err != nil {
		t.Fatalf("clear shared leases with explicit empty activation: %v", err)
	}
	assertNativeProjectionCount(t, target, 0)
}

func TestE2ECrowdSecNFTInventoryCapacity(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		runIsolated(t, "TestE2ECrowdSecNFTInventoryCapacity", "nftables")
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	// Each individual payload fits its input bound, but the unguarded combined
	// result exceeds the 64 MiB native inspection limit.
	makePrefix := func(index uint32, dynamic bool) netip.Prefix {
		address := [16]byte{0x20, 0x01, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd}
		if dynamic {
			address[1] = 0x02
		}
		binary.BigEndian.PutUint32(address[12:], 0xa0000000+index*4)
		return netip.PrefixFrom(netip.AddrFrom16(address), 127)
	}
	static := make([]netip.Prefix, 340000)
	for index := range static {
		static[index] = makePrefix(uint32(index), false)
	}
	target := nativeScaleTarget(t, "nftables", static)
	backend := firewall.NewNative(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	if err := backend.Preflight(ctx, nil, target, nil); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, nil, target, nil); err != nil {
		t.Fatal(err)
	}
	retained := []policy.TimedPrefix{{Prefix: netip.MustParsePrefix(fixtureIPv4Peer + "/32"), Deadline: time.Now().Add(time.Hour)}}
	if err := backend.UpdateDynamic(ctx, target, retained); err != nil {
		t.Fatal(err)
	}
	oversized := make([]policy.TimedPrefix, 319000)
	deadline := time.Now().Add(25 * time.Hour)
	for index := range oversized {
		oversized[index] = policy.TimedPrefix{Prefix: makePrefix(uint32(index), true), Deadline: deadline}
	}
	if err := backend.UpdateDynamic(ctx, target, oversized); err == nil {
		t.Fatal("update admitted an unrecoverable combined native inventory")
	}
	// Rejection must preserve existing enforcement, including the IPv4 set that
	// the rejected transaction would have flushed.
	assertNativeProjectionCount(t, target, 1)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18795", "reject", "tcp")
	admissible := largeNativeProjection(true)
	if err := backend.UpdateDynamic(ctx, target, admissible); err != nil {
		t.Fatalf("admissible replacement after rejection: %v", err)
	}
	assertNativeProjectionCount(t, target, len(admissible))
	if err := backend.UpdateDynamic(ctx, target, admissible); err != nil {
		t.Fatalf("renewal double-counted replaced native contents: %v", err)
	}
	if err := backend.UpdateDynamic(ctx, target, nil); err != nil {
		t.Fatalf("remove dynamic authority after rejection: %v", err)
	}
	assertNativeProjectionCount(t, target, 0)
	if err := backend.Cleanup(ctx, []*firewall.Target{target}); err != nil {
		t.Fatalf("cleanup after capacity rejection: %v", err)
	}
}

func TestE2ECrowdSecIPSetInterruptedWrites(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, kind := range []string{"legacy", "nft"} {
			t.Run(kind, func(t *testing.T) { runIsolated(t, "TestE2ECrowdSecIPSetInterruptedWrites", kind) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	tools := installIPTablesTools(t, os.Getenv(e2eScenario))
	backend := firewall.NewNative(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	for _, recovery := range []string{"retry", "cleanup"} {
		t.Run("partial-static-"+recovery, func(t *testing.T) {
			target := nativeScaleTarget(t, "iptables", []netip.Prefix{netip.MustParsePrefix(fixtureIPv4Peer + "/32"), netip.MustParsePrefix("203.0.113.3/32")})
			writeFailureMode(t, tools, "set-partial")
			if err := backend.Apply(ctx, nil, target, nil); err == nil {
				t.Fatal("partial restore was not interrupted")
			}
			waitForFailureMarker(t, tools, ".set-partial")
			writeFailureMode(t, tools, "")
			if recovery == "retry" {
				if err := backend.Apply(ctx, nil, target, nil); err != nil {
					t.Fatalf("repair partial static set: %v", err)
				}
				probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18792", "reject", "tcp")
			}
			if err := backend.Cleanup(ctx, []*firewall.Target{target}); err != nil {
				t.Fatalf("cleanup partial/complete staging: %v", err)
			}
			if output := command(t, 10*time.Second, "ipset", "save"); len(output) != 0 {
				t.Fatalf("cleanup retained sets: %s", output)
			}
		})
	}
	for _, cut := range []string{"set-before-swap", "set-after-swap"} {
		t.Run(cut, func(t *testing.T) {
			target := nativeScaleTarget(t, "iptables", nil)
			if err := backend.Apply(ctx, nil, target, nil); err != nil {
				t.Fatal(err)
			}
			values := largeNativeProjection(false)
			writeFailureMode(t, tools, cut)
			if err := backend.UpdateDynamic(ctx, target, values); err == nil {
				t.Fatal("resize was not interrupted")
			}
			waitForFailureMarker(t, tools, "."+cut)
			want := "success"
			if cut == "set-after-swap" {
				want = "reject"
			}
			probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18793", want, "tcp")
			writeFailureMode(t, tools, "")
			var spare string
			for name := range strings.FieldsSeq(string(command(t, 10*time.Second, "ipset", "list", "-name"))) {
				if strings.HasPrefix(name, "pdv4r") {
					spare = name
				}
			}
			if spare == "" {
				t.Fatal("interruption did not retain the resize spare")
			}
			command(t, 10*time.Second, "iptables", "-I", "INPUT", "-m", "set", "--match-set", spare, "src", "-j", "RETURN")
			if err := backend.UpdateDynamic(ctx, target, values); err == nil {
				t.Fatal("resize recovery accepted an unrecorded reference to its spare")
			}
			if err := backend.Cleanup(ctx, []*firewall.Target{target}); err == nil {
				t.Fatal("cleanup accepted an unrecorded reference to the spare")
			}
			command(t, 10*time.Second, "iptables", "-D", "INPUT", "-m", "set", "--match-set", spare, "src", "-j", "RETURN")
			// Reconcile newer authority, not the interrupted snapshot.
			values = values[1:]
			if err := backend.UpdateDynamic(ctx, target, values); err != nil {
				t.Fatalf("recover interrupted resize: %v", err)
			}
			assertNativeProjectionCount(t, target, len(values))
			probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18794", "success", "tcp")
			if err := backend.Cleanup(ctx, []*firewall.Target{target}); err != nil {
				t.Fatal(err)
			}
			command(t, 10*time.Second, "ipset", "create", spare, "hash:net", "family", "inet", "timeout", "86400")
			if err := backend.Preflight(ctx, nil, target, nil); err == nil {
				t.Fatal("initial preflight adopted a foreign resize-spare collision")
			}
			command(t, 10*time.Second, "ipset", "destroy", spare)
		})
	}
}

func TestE2ECrowdSecIPSetProjectionCapacity(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, kind := range []string{"legacy", "nft"} {
			t.Run(kind, func(t *testing.T) { runIsolated(t, "TestE2ECrowdSecIPSetProjectionCapacity", kind) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	installIPTablesTools(t, os.Getenv(e2eScenario))
	backend := firewall.NewNative(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	// Two overlapping source decisions yield five disjoint native prefixes.
	// This valid snapshot exceeds one restore invocation, but not inspection.
	now := time.Now()
	decisions := make([]crowdsec.Decision, 100000)
	for index := range 50000 {
		address := [16]byte{0x20, 0x01, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd}
		binary.BigEndian.PutUint32(address[12:], 0xa0000000+uint32(index)*32)
		parent := netip.PrefixFrom(netip.AddrFrom16(address), 124)
		if index == 49999 {
			parent = netip.MustParsePrefix(fixtureIPv6Peer + "/124").Masked()
		}
		decisions[2*index] = crowdsec.Decision{ID: int64(2*index + 1), Prefix: parent, Deadline: now.Add(25 * time.Hour)}
		decisions[2*index+1] = crowdsec.Decision{ID: int64(2*index + 2), Prefix: netip.PrefixFrom(parent.Addr().Next(), 128), Deadline: now.Add(49 * time.Hour)}
	}
	store := crowdsec.NewStore("http://lapi.example/", 1)
	if err := store.Apply(crowdsec.Batch{Startup: true, New: decisions}, 1, now); err != nil {
		t.Fatal(err)
	}
	values := store.Projection(now)
	if len(values) != 250000 {
		t.Fatalf("unexpected source projection: %d prefixes", len(values))
	}
	target := nativeScaleTarget(t, "iptables", nil)
	projection := &firewall.DynamicState{Prefixes: values}
	if err := backend.Preflight(ctx, nil, target, projection); err != nil {
		t.Fatalf("admit chunked initial snapshot: %v", err)
	}
	if err := backend.Apply(ctx, nil, target, nil); err != nil {
		t.Fatalf("admission projection leaked into activation: %v", err)
	}
	assertNativeProjectionCount(t, target, 0)
	if err := backend.Apply(ctx, nil, target, projection); err != nil {
		t.Fatalf("install chunked initial snapshot: %v", err)
	}
	assertNativeProjectionCount(t, target, len(values))
	if err := backend.Apply(ctx, target, target, &firewall.DynamicState{}); err != nil {
		t.Fatalf("explicit empty activation did not clear shared leases: %v", err)
	}
	assertNativeProjectionCount(t, target, 0)
	if err := backend.UpdateDynamic(ctx, target, values); err != nil {
		t.Fatalf("grow empty live set: %v", err)
	}
	assertNativeProjectionCount(t, target, len(values))
	if err := backend.Preflight(ctx, target, target, projection); err != nil {
		t.Fatalf("admit unchanged authority: %v", err)
	}
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18796", "reject", "tcp")
	if err := store.Apply(crowdsec.Batch{Deleted: []int64{99999}}, 2, time.Now()); err != nil {
		t.Fatal(err)
	}
	values = store.Projection(time.Now())
	if len(values) != 249996 {
		t.Fatalf("unexpected projection after deletion: %d prefixes", len(values))
	}
	if err := backend.UpdateDynamic(ctx, target, values); err != nil {
		t.Fatalf("remove source authority from a large live set: %v", err)
	}
	assertNativeProjectionCount(t, target, len(values))
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18797", "success", "tcp")

	// A resize must still reserve both the current live set and the populated
	// spare. The desired set fits alone, but their combined peak does not.
	oversized := make([]policy.TimedPrefix, 350000)
	for index := range oversized {
		address := [16]byte{0x20, 0x02, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd}
		binary.BigEndian.PutUint32(address[12:], 0xa0000000+uint32(index)*4)
		oversized[index] = policy.TimedPrefix{Prefix: netip.PrefixFrom(netip.AddrFrom16(address), 127), Deadline: now.Add(25 * time.Hour)}
	}
	if err := backend.UpdateDynamic(ctx, target, oversized); err == nil {
		t.Fatal("resize exceeded combined live/spare inspection capacity")
	}
	assertNativeProjectionCount(t, target, len(values))
	if err := backend.UpdateDynamic(ctx, target, nil); err != nil {
		t.Fatalf("clear authority after capacity rejection: %v", err)
	}
	assertNativeProjectionCount(t, target, 0)
	if err := backend.Cleanup(ctx, []*firewall.Target{target}); err != nil {
		t.Fatalf("cleanup after capacity rejection: %v", err)
	}
}
