package app

import (
	"context"
	"errors"
	"net/netip"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/control"
	"github.com/perimeterd/perimeterd/internal/lookup"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
	"github.com/perimeterd/perimeterd/internal/state"
)

func dbipAppSnapshot(t *testing.T, store *state.Store, release string, retrieved time.Time) source.Snapshot {
	t.Helper()
	snapshot, err := store.Prefixes().Stage([]source.Record{{
		Selector: policy.Selector{Kind: policy.Country, Value: "CZ"}, SourceKind: "dbip-lite", APIVersion: "dbip-country-csv-1", Release: release,
		Endpoint: "https://download.db-ip.com/free/dbip-country-lite-" + release + ".csv.gz", Parameters: map[string]string{"resource": "CZ", "sha256": strings.Repeat("a", 64)}, RetrievedAt: retrieved,
		IPv4: []netip.Prefix{netip.MustParsePrefix("8.8.8.8/32")}, IPv6: []netip.Prefix{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestDBIPCommittedProvenanceSurvivesRejectedSwitch(t *testing.T) {
	for _, failure := range []string{"native", "publication", "durable"} {
		t.Run(failure, func(t *testing.T) {
			fail := false
			backend := &recordingBackend{}
			engine, store := newTestEngine(t, backend, func(phase string) error {
				if fail && (failure == "publication" && phase == "after-switch" || failure == "durable" && phase == "active:before-file-sync") {
					return errors.New("publication rejected")
				}
				return nil
			})
			defer engine.Close()
			cfg := geoEngineConfig(t)
			epoch, err := engine.Admit()
			if err != nil {
				t.Fatal(err)
			}
			old := geoEngineSnapshot(t, store, "8.8.8.8/32")
			candidate, err := NewCandidate(epoch, "policy.yaml", cfg, old)
			if err != nil {
				t.Fatal(err)
			}
			if outcome, err := engine.Apply(context.Background(), candidate); err != nil || !outcome.Committed {
				t.Fatalf("initial apply: %+v %v", outcome, err)
			}
			before := engine.Status(context.Background()).Applied
			cfg.Geo.CountryProvider = config.CountryProviderDBIPLite
			next := dbipAppSnapshot(t, store, "2026-10", time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC))
			epoch, err = engine.Admit()
			if err != nil {
				t.Fatal(err)
			}
			if _, err := NewCandidate(epoch, "policy.yaml", cfg, old); err == nil {
				t.Fatal("RIPE snapshot admitted for DB-IP switch")
			}
			candidate, err = NewCandidate(epoch, "policy.yaml", cfg, next)
			if err != nil {
				t.Fatal(err)
			}
			fail = true
			if failure == "native" {
				backend.applyFailures = 1
			}
			if outcome, err := engine.Apply(context.Background(), candidate); err == nil || outcome.Committed {
				t.Fatalf("failed switch committed: %+v %v", outcome, err)
			}
			if after := engine.Status(context.Background()).Applied; !reflect.DeepEqual(after, before) {
				t.Fatalf("failed switch changed committed status: before=%+v after=%+v", before, after)
			}
			fail = false
			if outcome, err := engine.Apply(context.Background(), candidate); err != nil || !outcome.Committed {
				t.Fatalf("DB-IP switch: %+v %v", outcome, err)
			}
			applied := engine.Status(context.Background()).Applied
			want := []control.StatusSource{{Provider: "dbip-lite", Release: "2026-10", RetrievedAt: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}}
			if !reflect.DeepEqual(applied.Details.Sources, want) {
				t.Fatalf("wrong committed sources: %+v", applied.Details.Sources)
			}
			committed, err := store.Read()
			if err != nil {
				t.Fatal(err)
			}
			runtime := newSourceRuntime(store.Prefixes(), nil)
			defer runtime.close()
			if err := runtime.selectRevision(committed.Active, nil); err != nil {
				t.Fatal(err)
			}
			timestamps := runtime.snapshotTimestamps()
			if timestamps.dbip != want[0].RetrievedAt.Unix() || timestamps.ripe != 0 {
				t.Fatalf("wrong committed freshness: %+v", timestamps)
			}
			age := time.Since(want[0].RetrievedAt)
			if got := runtime.age(); got < age-time.Second || got > age+time.Second {
				t.Fatalf("overall age omitted actual DB-IP retrieval: got %s want %s", got, age)
			}
			result := engine.Lookup(context.Background(), lookup.Request{Address: "8.8.8.8", Direction: "ingress", Protocol: "tcp", Port: func() *uint16 { v := uint16(443); return &v }()})
			found := false
			for _, outcome := range result.Outcomes {
				for _, evidence := range outcome.Evidence {
					if evidence.Kind == "country" {
						found = true
						if evidence.Provider != "dbip-lite" || evidence.Release != "2026-10" {
							t.Fatalf("wrong applied lookup evidence: %+v", evidence)
						}
					}
				}
			}
			if !found {
				t.Fatalf("missing country evidence: %+v", result)
			}
			applied.Details.Sources[0].Provider = "mutated"
			if got := engine.Status(context.Background()).Applied.Details.Sources; !reflect.DeepEqual(got, want) {
				t.Fatal("status caller mutated committed provenance")
			}
			counts := prefixCounts(candidate)
			found = false
			for _, count := range counts {
				if count.Type == "country" {
					found = true
					if count.Source != "dbip-lite" {
						t.Fatalf("wrong country count labels: %+v", count)
					}
				}
			}
			if !found {
				t.Fatal("missing country counts")
			}
		})
	}
}
