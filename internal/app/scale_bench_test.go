package app

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	crowd "github.com/perimeterd/perimeterd/internal/crowdsec"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
	"github.com/perimeterd/perimeterd/internal/state"
)

const benchmarkGeoPrefixCount = 100_000

func benchmarkGeoRecords(count int) []policy.ResolvedSelector {
	prefixes := make([]netip.Prefix, count)
	for index := range count {
		addressValue := uint32(0x64400000) + uint32(index*2)
		var addressBytes [4]byte
		binary.BigEndian.PutUint32(addressBytes[:], addressValue)
		prefixes[index] = netip.PrefixFrom(netip.AddrFrom4(addressBytes), 32)
	}
	return []policy.ResolvedSelector{{
		Selector: policy.Selector{Kind: policy.Country, Value: "US"},
		IPv4:     prefixes,
	}}
}

func benchmarkGeoConfig(b *testing.B) config.Config {
	b.Helper()
	cfg, err := config.Parse([]byte(`version: 1
firewall:
  backend: nftables
  deny_action: reject
crowdsec:
  enabled: true
  api_key_file: /unused/scale-key
policies:
  - name: synthetic-geo
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
`))
	if err != nil {
		b.Fatal(err)
	}
	return cfg
}

func benchmarkGeoSnapshot(b *testing.B, count int) (policy.Snapshot, int, int) {
	b.Helper()
	records := benchmarkGeoRecords(count)
	snapshot, err := policy.NewSnapshot(records)
	if err != nil {
		b.Fatal(err)
	}
	selector, err := policy.CanonicalSelector(policy.Country, "US")
	if err != nil {
		b.Fatal(err)
	}
	set, ok := snapshot.Lookup(selector)
	if !ok {
		b.Fatal("synthetic country record was not admitted")
	}
	prefixes := set.Prefixes()
	serialized, err := json.Marshal(prefixes)
	if err != nil {
		b.Fatal(err)
	}
	return snapshot, len(prefixes), len(serialized)
}

func BenchmarkSyntheticGeoNormalization(b *testing.B) {
	for _, profile := range []struct {
		name  string
		count int
	}{
		{name: "baseline", count: 1_024},
		{name: "large-100k", count: benchmarkGeoPrefixCount},
	} {
		b.Run(profile.name, func(b *testing.B) {
			records := benchmarkGeoRecords(profile.count)
			serialized, err := json.Marshal(records[0].IPv4)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				snapshot, err := policy.NewSnapshot(records)
				if err != nil {
					b.Fatal(err)
				}
				if len(snapshot.Selectors()) != 1 {
					b.Fatal("normalized snapshot lost synthetic selector")
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(profile.count), "input-prefixes/op")
			b.ReportMetric(float64(len(serialized)), "input-bytes/op")
		})
	}
}

func BenchmarkSyntheticGeoCompileAndTarget(b *testing.B) {
	for _, profile := range []struct {
		name  string
		count int
	}{
		{name: "baseline", count: 1_024},
		{name: "large-100k", count: benchmarkGeoPrefixCount},
	} {
		b.Run(profile.name, func(b *testing.B) {
			snapshot, normalizedCount, serializedBytes := benchmarkGeoSnapshot(b, profile.count)
			cfg := benchmarkGeoConfig(b)
			model, err := policy.Compile(cfg, snapshot)
			if err != nil {
				b.Fatal(err)
			}
			target, err := firewall.BuildTarget("11111111111111111111111111111111", "22222222222222222222222222222222", cfg, model, nil)
			if err != nil {
				b.Fatal(err)
			}
			serializedTarget, err := json.Marshal(target)
			if err != nil {
				b.Fatal(err)
			}
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				model, err := policy.Compile(cfg, snapshot)
				if err != nil {
					b.Fatal(err)
				}
				if _, err := firewall.BuildTarget("11111111111111111111111111111111", "22222222222222222222222222222222", cfg, model, nil); err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(normalizedCount), "normalized-prefixes/op")
			b.ReportMetric(float64(serializedBytes), "input-bytes/op")
			b.ReportMetric(float64(len(serializedTarget)), "target-bytes/op")
		})
	}
}

type benchmarkReconcileBackend struct {
	prefixes int
}

func (b *benchmarkReconcileBackend) Preflight(context.Context, *firewall.Target, *firewall.Target, *firewall.DynamicState) error {
	return nil
}

func (b *benchmarkReconcileBackend) Apply(context.Context, *firewall.Target, *firewall.Target, *firewall.DynamicState) error {
	return nil
}

func (b *benchmarkReconcileBackend) Retire(context.Context, *firewall.Target, *firewall.Target) error {
	return nil
}

func (b *benchmarkReconcileBackend) Cleanup(context.Context, []*firewall.Target) error {
	return nil
}

func (b *benchmarkReconcileBackend) UpdateDynamic(_ context.Context, _ *firewall.Target, projection []policy.TimedPrefix) error {
	b.prefixes = len(projection)
	return nil
}

func benchmarkAppCrowdBatch(count int, deadline time.Time) crowd.Batch {
	decisions := make([]crowd.Decision, count)
	for index := range count {
		var addressBytes [16]byte
		binary.BigEndian.PutUint16(addressBytes[0:2], 0x2001)
		binary.BigEndian.PutUint16(addressBytes[2:4], 0x0db8)
		binary.BigEndian.PutUint16(addressBytes[4:6], uint16(index>>16))
		binary.BigEndian.PutUint16(addressBytes[6:8], uint16(index))
		decisions[index] = crowd.Decision{ID: int64(index + 1), Prefix: netip.PrefixFrom(netip.AddrFrom16(addressBytes), 127), Deadline: deadline}
	}
	return crowd.Batch{Startup: true, New: decisions}
}

func benchmarkAppReconcileSetup(b *testing.B, geoCount, crowdCount int) (*Engine, *crowdState, *benchmarkReconcileBackend) {
	b.Helper()
	store, err := state.Open(b.TempDir()+"/state", nil)
	if err != nil {
		b.Fatal(err)
	}
	keyPath := b.TempDir() + "/crowdsec-key"
	if err := os.WriteFile(keyPath, []byte("benchmark-key"), 0o600); err != nil {
		b.Fatal(err)
	}
	cfg := benchmarkGeoConfig(b)
	cfg.CrowdSec.APIKeyFile = keyPath
	resolved := benchmarkGeoRecords(geoCount)[0]
	base := time.Unix(1_700_000_000, 0).UTC()
	cached, err := store.Prefixes().Stage([]source.Record{{
		Selector:   resolved.Selector,
		Endpoint:   "https://stat.ripe.net/data/country-resource-list/data.json",
		APIVersion: "0.2",
		Parameters: map[string]string{"resource": "US", "sourceapp": "perimeterd", "v4_format": "prefix"},
		QueryStart: base, QueryEnd: base, RetrievedAt: base.Add(time.Minute),
		IPv4: resolved.IPv4,
	}})
	if err != nil {
		b.Fatal(err)
	}
	model, err := policy.Compile(cfg, cached.Policy())
	if err != nil {
		b.Fatal(err)
	}
	generation := "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	target, err := firewall.BuildTarget(store.Owner(), generation, cfg, model, nil)
	if err != nil {
		b.Fatal(err)
	}
	revision := &state.Revision{
		Version: 1, ID: generation, Epoch: 1, ConfigPath: "benchmark.yaml", Config: cfg,
		Manifest: cached.ManifestID(), Target: target,
	}
	client, err := crowd.NewClient(cfg.CrowdSec, nil)
	if err != nil {
		b.Fatal(err)
	}
	if err := store.Prepare(nil, revision); err != nil {
		b.Fatal(err)
	}
	if err := store.Commit(revision); err != nil {
		b.Fatal(err)
	}
	if err := store.Finish(); err != nil {
		b.Fatal(err)
	}
	backend := &benchmarkReconcileBackend{}
	engine := NewEngine(store, backend, nil)
	engine.healthy.Store(true)
	live := &crowdState{
		client: client, store: crowd.NewStore(client.Endpoint(), 1), epoch: 1, cfg: cfg.CrowdSec,
		wake: make(chan struct{}, 1),
	}
	crowdNow := time.Now()
	if err := live.store.Apply(benchmarkAppCrowdBatch(crowdCount, crowdNow.Add(time.Hour)), 1, crowdNow); err != nil {
		b.Fatal(err)
	}
	engine.crowd.active = live
	b.Cleanup(engine.Close)
	return engine, live, backend
}

func BenchmarkAppReconcileCombinedAuthorityAndGeo(b *testing.B) {
	for _, profile := range []struct {
		name       string
		geoCount   int
		crowdCount int
	}{
		{name: "baseline", geoCount: 1_024, crowdCount: 1_024},
		{name: "large-100k", geoCount: benchmarkGeoPrefixCount, crowdCount: 250_000},
	} {
		b.Run(profile.name, func(b *testing.B) {
			engine, live, backend := benchmarkAppReconcileSetup(b, profile.geoCount, profile.crowdCount)
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				engine.mu.Lock()
				err := engine.crowd.reconcileLocked(context.Background(), live, false)
				engine.mu.Unlock()
				if err != nil {
					b.Fatal(err)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(profile.geoCount), "geo-prefixes/op")
			b.ReportMetric(float64(profile.crowdCount), "crowdsec-decisions/op")
			if backend.prefixes != profile.crowdCount {
				b.Fatalf("combined reconciliation projected %d CrowdSec prefixes, want %d", backend.prefixes, profile.crowdCount)
			}
		})
	}
}
