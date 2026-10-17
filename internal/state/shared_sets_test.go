package state

import (
	"bytes"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
	"github.com/perimeterd/perimeterd/internal/testutil/historicalfixture"
)

func historicalRevision(t *testing.T, store *Store, backend string) *Revision {
	t.Helper()
	cfg, err := historicalfixture.Config(backend, "http://127.0.0.1:18080", "/fixture-key")
	if err != nil {
		t.Fatal(err)
	}
	// This fixture deliberately exercises the historical RIPE country contract.
	cfg.Geo.CountryProvider = config.CountryProviderRIPEstat
	now := time.Now().UTC().Truncate(time.Second)
	var records []source.Record
	for _, resolved := range historicalfixture.Records() {
		records = append(records, source.Record{
			Selector: resolved.Selector, Endpoint: "https://stat.ripe.net/data/country-resource-list/data.json", APIVersion: "0.2",
			Parameters: map[string]string{"resource": resolved.Selector.Value, "v4_format": "prefix", "sourceapp": "perimeterd"},
			QueryStart: now.Add(-time.Hour), QueryEnd: now.Add(-time.Hour), RetrievedAt: now,
			IPv4: resolved.IPv4, IPv6: resolved.IPv6,
		})
	}
	snapshot, err := store.Prefixes().Stage(records)
	if err != nil {
		t.Fatal(err)
	}
	target, err := historicalfixture.Target(backend, store.Owner())
	if err != nil {
		t.Fatal(err)
	}
	return &Revision{Version: recordVersion, ID: target.Generation, Epoch: 1, Manifest: snapshot.ManifestID(), ConfigPath: "/fixture.yaml", Config: cfg, Target: target}
}

func TestHistoricalUnsharedRevisionAndSharedTransition(t *testing.T) {
	for _, backend := range []string{"nftables", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			store, _ := openTestStore(t, nil)
			old := historicalRevision(t, store, backend)
			if err := store.Prepare(nil, old); err != nil {
				t.Fatal(err)
			}
			if err := store.Commit(old); err != nil {
				t.Fatal(err)
			}
			if err := store.Finish(); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(store.dir, "revisions", old.ID+".json")
			before, err := os.ReadFile(path) // #nosec G304 -- private fixture revision under t.TempDir.
			if err != nil {
				t.Fatal(err)
			}
			if err := store.Prepare(old, old); err != nil {
				t.Fatal(err)
			}
			view, err := store.Read()
			if err != nil || view.Journal == nil || len(view.Revisions) != 1 || !reflect.DeepEqual(view.Active.Target, old.Target) {
				t.Fatalf("same-revision historical journal: %+v, %v", view, err)
			}
			if err := store.Finish(); err != nil {
				t.Fatal(err)
			}
			snapshot, err := store.Prefixes().Load(old.Manifest)
			if err != nil {
				t.Fatal(err)
			}
			model, err := policy.Compile(old.Config, snapshot.Policy())
			if err != nil {
				t.Fatal(err)
			}
			id := "cccccccccccccccccccccccccccccccc"
			target, err := firewall.BuildTarget(store.Owner(), id, old.Config, model, old.Target)
			if err != nil {
				t.Fatal(err)
			}
			if target.Generation == old.Target.Generation || reflect.DeepEqual(target.Families, old.Target.Families) {
				t.Fatal("new compilation did not migrate recorded unshared storage")
			}
			candidate := *old
			candidate.ID, candidate.Epoch, candidate.Target = id, 2, target
			if err := store.Prepare(old, &candidate); err != nil {
				t.Fatalf("distinct unshared/shared journal: %v", err)
			}
			view, err = store.Read()
			if err != nil || len(view.Revisions) != 2 || view.Active.ID != old.ID || !reflect.DeepEqual(view.Revisions[old.ID].Target, old.Target) {
				t.Fatalf("prepared migration changed prior authority: %+v, %v", view, err)
			}
			if err := store.Commit(&candidate); err != nil {
				t.Fatal(err)
			}
			view, err = store.Read()
			if err != nil || view.Active.ID != id || !reflect.DeepEqual(view.Active.Target, target) {
				t.Fatalf("committed shared authority: %+v, %v", view, err)
			}
			after, err := os.ReadFile(path) // #nosec G304 -- same private immutable historical revision.
			if err != nil || !bytes.Equal(before, after) {
				t.Fatalf("historical revision was rewritten during validation/migration: %v", err)
			}
		})
	}
}

func TestHistoricalAliasValidationRejectsSemanticChanges(t *testing.T) {
	mutateGeo := func(target *firewall.Target) *policy.PrefixSet {
		for i := range target.Families[0].Sets {
			if target.Families[0].Sets[i].ID == "geo/ingress" {
				return &target.Families[0].Sets[i]
			}
		}
		panic("recorded fixture has no ingress data")
	}
	mutateRule := func(target *firewall.Target) *policy.Rule {
		for i := range target.Families[0].Paths {
			for j := range target.Families[0].Paths[i].Rules {
				rule := &target.Families[0].Paths[i].Rules[j]
				if rule.Policy == "ingress" && rule.Match.SetID != "" {
					return rule
				}
			}
		}
		panic("recorded fixture has no ingress rule")
	}
	for _, tc := range []struct {
		name   string
		mutate func(*firewall.Target)
	}{
		{"different geo contents", func(target *firewall.Target) {
			mutateGeo(target).Prefixes = []netip.Prefix{netip.MustParsePrefix("8.22.0.2/32")}
		}},
		{"larger overlapping geo contents", func(target *firewall.Target) {
			mutateGeo(target).Prefixes = []netip.Prefix{netip.MustParsePrefix("8.20.0.0/24")}
		}},
		{"wrong original policy", func(target *firewall.Target) { mutateRule(target).Policy = "egress" }},
		{"wrong action", func(target *firewall.Target) { mutateRule(target).Action = policy.Drop }},
		{"wrong traffic", func(target *firewall.Target) {
			mutateRule(target).Match.Traffic = policy.Scope{TCP: []policy.PortRange{{Start: 443, End: 443}}}
		}},
		{"wrong orientation", func(target *firewall.Target) { target.Families[0].Paths[0].Remote = policy.DestinationAddress }},
		{"changed internal contents", func(target *firewall.Target) {
			target.Families[0].Sets[0].Prefixes = []netip.Prefix{netip.MustParsePrefix("8.20.0.2/32")}
		}},
		{"unreferenced geo object", func(target *firewall.Target) {
			target.Families[0].Sets = append(target.Families[0].Sets, policy.PrefixSet{ID: "geo/orphan", Kind: policy.StaticSet})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			store, _ := openTestStore(t, nil)
			revision := historicalRevision(t, store, "nftables")
			tc.mutate(revision.Target)
			var invalid *ValidationError
			if err := store.Prepare(nil, revision); !errors.As(err, &invalid) {
				t.Fatalf("modified historical semantics accepted: %v", err)
			}
		})
	}
}
