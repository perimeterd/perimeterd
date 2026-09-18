//go:build linux && e2e

package e2e

import (
	"context"
	"encoding/binary"
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

const (
	nativeMeasurementEnabled    = "PERIMETERD_NATIVE_MEASURE"
	nativeMeasurementProfileEnv = "PERIMETERD_NATIVE_PROFILE"
	nativeMeasurementOwner      = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

type nativeMeasurementProfile struct {
	name        string
	geoPrefixes uint32
	decisions   int
}

func nativeMeasurementProfiles() []nativeMeasurementProfile {
	profiles := []nativeMeasurementProfile{
		{name: "small", geoPrefixes: 1_024, decisions: 1_024},
		{name: "large-geo100k-crowd250k", geoPrefixes: 100_000, decisions: 250_000},
	}
	switch os.Getenv(nativeMeasurementProfileEnv) {
	case "small":
		return profiles[:1]
	case "large":
		return profiles[1:]
	default:
		return profiles
	}
}

func nativeMeasurementBatch(count int, deadline time.Time) crowdsec.Batch {
	decisions := make([]crowdsec.Decision, count)
	for index := range count {
		var addressBytes [16]byte
		binary.BigEndian.PutUint16(addressBytes[0:2], 0x2001)
		binary.BigEndian.PutUint16(addressBytes[2:4], 0x0db8)
		binary.BigEndian.PutUint16(addressBytes[4:6], uint16(index>>16))
		binary.BigEndian.PutUint16(addressBytes[6:8], uint16(index))
		decisions[index] = crowdsec.Decision{
			ID: int64(index + 1), Prefix: netip.PrefixFrom(netip.AddrFrom16(addressBytes), 127), Deadline: deadline,
		}
	}
	return crowdsec.Batch{Startup: true, New: decisions}
}

func nativeMeasurementGeoSnapshot(t *testing.T, count, offset uint32) policy.Snapshot {
	t.Helper()
	prefixes := make([]netip.Prefix, count)
	for index := range count {
		addressValue := uint32(0x64400000) + (index+offset)*2
		var addressBytes [4]byte
		binary.BigEndian.PutUint32(addressBytes[:], addressValue)
		prefixes[index] = netip.PrefixFrom(netip.AddrFrom4(addressBytes), 32)
	}
	snapshot, err := policy.NewSnapshot([]policy.ResolvedSelector{{
		Selector: policy.Selector{Kind: policy.Country, Value: "US"}, IPv4: prefixes,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func nativeMeasurementConfig(t *testing.T, backend string) config.Config {
	t.Helper()
	text := fmt.Sprintf(`version: 1
firewall:
  backend: %s
  deny_action: reject
crowdsec:
  enabled: true
  api_key_file: /unused/native-measurement-key
policies:
  - name: synthetic-geo
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
`, backend)
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func nativeMeasurementTarget(t *testing.T, backend string, geoPrefixes, offset uint32, generation string, previous *firewall.Target) *firewall.Target {
	t.Helper()
	cfg := nativeMeasurementConfig(t, backend)
	snapshot := nativeMeasurementGeoSnapshot(t, geoPrefixes, offset)
	model, err := policy.Compile(cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	target, err := firewall.BuildTarget(nativeMeasurementOwner, generation, cfg, model, previous)
	if err != nil {
		t.Fatal(err)
	}
	return target
}

func nativeCapacityError(err error) bool {
	if err == nil {
		return false
	}
	message := strings.TrimSpace(err.Error())
	switch message {
	case "nft backend: complete target exceeds input limit",
		"nft backend: retained generations exceed inspection capacity",
		"nft backend: combined static and dynamic contents exceed inspection capacity",
		"iptables complete family exceeds input budget",
		"iptables retained generations exceed inspection budget":
		return true
	}
	return strings.HasSuffix(message, " input exceeds 16777216 bytes")
}

func TestE2ECrowdSecNativeMeasurement(t *testing.T) {
	if os.Getenv(nativeMeasurementEnabled) != "1" {
		t.Skip("set PERIMETERD_NATIVE_MEASURE=1 to run the isolated native measurement")
	}
	if os.Getenv(e2eChildEnv) != "1" {
		for _, backend := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(backend, func(t *testing.T) {
				t.Logf("%s", runIsolated(t, "TestE2ECrowdSecNativeMeasurement", backend))
			})
		}
		return
	}

	requireIsolatedChild(t)
	prepareMounts(t)
	backendName := os.Getenv(e2eScenario)
	if strings.HasPrefix(backendName, "iptables-") {
		installIPTablesTools(t, strings.TrimPrefix(backendName, "iptables-"))
		backendName = "iptables"
	}
	backend := firewall.NewNative(nil)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	for _, profile := range nativeMeasurementProfiles() {
		profile := profile
		t.Run(profile.name, func(t *testing.T) {
			owned := make([]*firewall.Target, 0, 2)
			defer func() {
				if len(owned) == 0 {
					return
				}
				if err := backend.Cleanup(ctx, owned); err != nil {
					t.Errorf("cleanup measured targets: %v", err)
				}
			}()

			store := crowdsec.NewStore("native-measurement", 1)
			startup := nativeMeasurementBatch(profile.decisions, time.Now().Add(time.Hour))
			started := time.Now()
			if err := store.Apply(startup, 1, started); err != nil {
				t.Fatal(err)
			}
			projection := store.Projection(started)
			t.Logf("profile=%s backend=%s authority=accepted decisions=%d projected-prefixes=%d", profile.name, backendName, profile.decisions, len(projection))
			dynamic := &firewall.DynamicState{Prefixes: projection}
			target := nativeMeasurementTarget(t, backendName, profile.geoPrefixes, 0, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil)

			preflightStarted := time.Now()
			if err := backend.Preflight(ctx, nil, target, dynamic); err != nil {
				if profile.decisions > 1_024 && nativeCapacityError(err) {
					t.Logf("profile=%s backend=%s admission=rejected-capacity phase=activation-preflight elapsed=%s error=%v", profile.name, backendName, time.Since(preflightStarted), err)
					return
				}
				t.Fatalf("profile=%s backend=%s admission=error phase=activation-preflight elapsed=%s: %v", profile.name, backendName, time.Since(preflightStarted), err)
			}
			t.Logf("profile=%s backend=%s admission=accepted phase=activation-preflight elapsed=%s", profile.name, backendName, time.Since(preflightStarted))

			owned = append(owned, target)
			applyStarted := time.Now()
			if err := backend.Apply(ctx, nil, target, dynamic); err != nil {
				if profile.decisions > 1_024 && nativeCapacityError(err) {
					t.Logf("profile=%s backend=%s execution=rejected-capacity phase=activation-apply elapsed=%s error=%v", profile.name, backendName, time.Since(applyStarted), err)
					return
				}
				t.Fatalf("profile=%s backend=%s execution=error phase=activation-apply elapsed=%s: %v", profile.name, backendName, time.Since(applyStarted), err)
			}
			t.Logf("profile=%s backend=%s execution=accepted phase=activation-apply elapsed=%s", profile.name, backendName, time.Since(applyStarted))

			// Renewal writes the exact unchanged source projection and deadlines.
			renewalStarted := time.Now()
			if err := backend.UpdateDynamic(ctx, target, projection); err != nil {
				if profile.decisions > 1_024 && nativeCapacityError(err) {
					t.Logf("profile=%s backend=%s execution=rejected-capacity phase=renewal elapsed=%s error=%v", profile.name, backendName, time.Since(renewalStarted), err)
					return
				}
				t.Fatalf("profile=%s backend=%s execution=error phase=renewal elapsed=%s: %v", profile.name, backendName, time.Since(renewalStarted), err)
			}
			t.Logf("profile=%s backend=%s execution=accepted phase=renewal elapsed=%s prefixes=%d", profile.name, backendName, time.Since(renewalStarted), len(projection))

			reconnected := crowdsec.NewStore("native-measurement", 2)
			reconnectStarted := time.Now()
			if err := reconnected.Apply(startup, 1, reconnectStarted); err != nil {
				t.Fatal(err)
			}
			reconnectedProjection := reconnected.Projection(reconnectStarted)
			if err := backend.UpdateDynamic(ctx, target, reconnectedProjection); err != nil {
				if profile.decisions > 1_024 && nativeCapacityError(err) {
					t.Logf("profile=%s backend=%s execution=rejected-capacity phase=cold-reconnect elapsed=%s error=%v", profile.name, backendName, time.Since(reconnectStarted), err)
					return
				}
				t.Fatalf("profile=%s backend=%s execution=error phase=cold-reconnect elapsed=%s: %v", profile.name, backendName, time.Since(reconnectStarted), err)
			}
			t.Logf("profile=%s backend=%s execution=accepted phase=cold-reconnect elapsed=%s prefixes=%d", profile.name, backendName, time.Since(reconnectStarted), len(reconnectedProjection))

			// A geo refresh changes the static source target. Admission receives
			// the live CrowdSec projection, while activation is nil so existing
			// dynamic leases are preserved by the static switch.
			refreshedTarget := nativeMeasurementTarget(t, backendName, profile.geoPrefixes, 500_000, "cccccccccccccccccccccccccccccccc", target)
			refreshPreflightStarted := time.Now()
			if err := backend.Preflight(ctx, target, refreshedTarget, dynamic); err != nil {
				if profile.decisions > 1_024 && nativeCapacityError(err) {
					t.Logf("profile=%s backend=%s admission=rejected-capacity phase=geo-refresh-preflight elapsed=%s error=%v", profile.name, backendName, time.Since(refreshPreflightStarted), err)
					return
				}
				t.Fatalf("profile=%s backend=%s admission=error phase=geo-refresh-preflight elapsed=%s: %v", profile.name, backendName, time.Since(refreshPreflightStarted), err)
			}
			t.Logf("profile=%s backend=%s admission=accepted phase=geo-refresh-preflight elapsed=%s", profile.name, backendName, time.Since(refreshPreflightStarted))

			owned = append(owned, refreshedTarget)
			refreshApplyStarted := time.Now()
			if err := backend.Apply(ctx, target, refreshedTarget, nil); err != nil {
				if profile.decisions > 1_024 && nativeCapacityError(err) {
					t.Logf("profile=%s backend=%s execution=rejected-capacity phase=geo-refresh-apply elapsed=%s error=%v", profile.name, backendName, time.Since(refreshApplyStarted), err)
					return
				}
				t.Fatalf("profile=%s backend=%s execution=error phase=geo-refresh-apply elapsed=%s: %v", profile.name, backendName, time.Since(refreshApplyStarted), err)
			}
			t.Logf("profile=%s backend=%s execution=accepted phase=geo-refresh-apply elapsed=%s", profile.name, backendName, time.Since(refreshApplyStarted))
			retireStarted := time.Now()
			if err := backend.Retire(ctx, target, refreshedTarget); err != nil {
				t.Fatalf("profile=%s backend=%s execution=error phase=geo-refresh-retire elapsed=%s: %v", profile.name, backendName, time.Since(retireStarted), err)
			}
			t.Logf("profile=%s backend=%s execution=accepted phase=geo-refresh-retire elapsed=%s", profile.name, backendName, time.Since(retireStarted))
			target = refreshedTarget

			refreshReconcileStarted := time.Now()
			if err := backend.UpdateDynamic(ctx, target, projection); err != nil {
				if profile.decisions > 1_024 && nativeCapacityError(err) {
					t.Logf("profile=%s backend=%s execution=rejected-capacity phase=geo-refresh-reconcile elapsed=%s error=%v", profile.name, backendName, time.Since(refreshReconcileStarted), err)
					return
				}
				t.Fatalf("profile=%s backend=%s execution=error phase=geo-refresh-reconcile elapsed=%s: %v", profile.name, backendName, time.Since(refreshReconcileStarted), err)
			}
			t.Logf("profile=%s backend=%s execution=accepted phase=geo-refresh-reconcile elapsed=%s", profile.name, backendName, time.Since(refreshReconcileStarted))
		})
	}
}
