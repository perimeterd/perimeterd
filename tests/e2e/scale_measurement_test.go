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

func TestE2ECrowdSecNativeMeasurement(t *testing.T) {
	if os.Getenv(nativeMeasurementEnabled) != "1" {
		t.Skip("set PERIMETERD_NATIVE_MEASURE=1 to run the isolated native measurement")
	}
	if os.Getenv(e2eChildEnv) != "1" {
		for _, backend := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(backend, func(t *testing.T) {
				runIsolated(t, "TestE2ECrowdSecNativeMeasurement", backend)
			})
		}
		return
	}

	requireIsolatedChild(t)
	prepareMounts(t)
	backendScenario := os.Getenv(e2eScenario)
	backendName := backendScenario
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
			report := func(phase string, started time.Time, projected int) {
				recordE2EPhase(t, e2ePhaseRecord{
					Backend: backendScenario, Profile: profile.name, Phase: phase,
					Event: "measurement", Outcome: "success",
					StaticMemberships: int(profile.geoPrefixes), SourceDecisions: len(startup.New),
					ProjectedMemberships: projected, DurationNS: time.Since(started).Nanoseconds(),
				})
			}
			report("authority-admission", started, len(projection))
			dynamic := &firewall.DynamicState{Prefixes: projection}
			target := nativeMeasurementTarget(t, backendName, profile.geoPrefixes, 0, "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", nil)

			preflightStarted := time.Now()
			if err := backend.Preflight(ctx, nil, target, dynamic); err != nil {
				t.Fatalf("profile=%s backend=%s admission=error phase=activation-preflight elapsed=%s: %v", profile.name, backendName, time.Since(preflightStarted), err)
			}
			report("activation-preflight", preflightStarted, len(projection))

			owned = append(owned, target)
			applyStarted := time.Now()
			if err := backend.Apply(ctx, nil, target, dynamic); err != nil {
				t.Fatalf("profile=%s backend=%s execution=error phase=activation-apply elapsed=%s: %v", profile.name, backendName, time.Since(applyStarted), err)
			}
			report("activation-apply", applyStarted, len(projection))

			// Renewal writes the exact unchanged source projection and deadlines.
			renewalStarted := time.Now()
			if err := backend.UpdateDynamic(ctx, target, projection); err != nil {
				t.Fatalf("profile=%s backend=%s execution=error phase=renewal elapsed=%s: %v", profile.name, backendName, time.Since(renewalStarted), err)
			}
			report("renewal", renewalStarted, len(projection))

			reconnected := crowdsec.NewStore("native-measurement", 2)
			reconnectStarted := time.Now()
			if err := reconnected.Apply(startup, 1, reconnectStarted); err != nil {
				t.Fatal(err)
			}
			reconnectedProjection := reconnected.Projection(reconnectStarted)
			if err := backend.UpdateDynamic(ctx, target, reconnectedProjection); err != nil {
				t.Fatalf("profile=%s backend=%s execution=error phase=cold-reconnect elapsed=%s: %v", profile.name, backendName, time.Since(reconnectStarted), err)
			}
			report("cold-reconnect", reconnectStarted, len(reconnectedProjection))

			// A geo refresh changes the static source target. Admission receives
			// the live CrowdSec projection, while activation is nil so existing
			// dynamic leases are preserved by the static switch.
			refreshedTarget := nativeMeasurementTarget(t, backendName, profile.geoPrefixes, 500_000, "cccccccccccccccccccccccccccccccc", target)
			refreshPreflightStarted := time.Now()
			if err := backend.Preflight(ctx, target, refreshedTarget, dynamic); err != nil {
				t.Fatalf("profile=%s backend=%s admission=error phase=geo-refresh-preflight elapsed=%s: %v", profile.name, backendName, time.Since(refreshPreflightStarted), err)
			}
			report("geo-refresh-preflight", refreshPreflightStarted, len(projection))

			owned = append(owned, refreshedTarget)
			refreshApplyStarted := time.Now()
			if err := backend.Apply(ctx, target, refreshedTarget, nil); err != nil {
				t.Fatalf("profile=%s backend=%s execution=error phase=geo-refresh-apply elapsed=%s: %v", profile.name, backendName, time.Since(refreshApplyStarted), err)
			}
			report("geo-refresh-apply", refreshApplyStarted, len(projection))
			retireStarted := time.Now()
			if err := backend.Retire(ctx, target, refreshedTarget); err != nil {
				t.Fatalf("profile=%s backend=%s execution=error phase=geo-refresh-retire elapsed=%s: %v", profile.name, backendName, time.Since(retireStarted), err)
			}
			report("geo-refresh-retire", retireStarted, len(projection))
			target = refreshedTarget

			refreshReconcileStarted := time.Now()
			if err := backend.UpdateDynamic(ctx, target, projection); err != nil {
				t.Fatalf("profile=%s backend=%s execution=error phase=geo-refresh-reconcile elapsed=%s: %v", profile.name, backendName, time.Since(refreshReconcileStarted), err)
			}
			report("geo-refresh-reconcile", refreshReconcileStarted, len(projection))
		})
	}
}
