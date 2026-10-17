package app

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/control"
	"github.com/perimeterd/perimeterd/internal/source"
	"github.com/perimeterd/perimeterd/internal/state"
	"github.com/perimeterd/perimeterd/internal/testutil/historicalfixture"
)

func TestHistoricalRecoveryFailedAndSuccessfulSharedMigration(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"new":[],"deleted":[]}`))
	}))
	defer server.Close()
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte("fixture-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := historicalfixture.Config("nftables", server.URL, key)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Geo.CountryProvider = config.CountryProviderRIPEstat
	cfg.CrowdSec.UpdateFrequency = time.Hour
	backend := &recordingBackend{}
	dir := filepath.Join(t.TempDir(), "state")
	store, err := state.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(store, backend, nil)
	defer engine.Close()
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
	target, err := historicalfixture.Target("nftables", store.Owner())
	if err != nil {
		t.Fatal(err)
	}
	old := &state.Revision{Version: 2, ID: target.Generation, Epoch: 1, Manifest: snapshot.ManifestID(), ConfigPath: "/fixture.yaml", Config: cfg, Target: target}
	if err := store.Prepare(nil, old); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(old); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "revisions", old.ID+".json")
	beforeBytes, err := os.ReadFile(path) // #nosec G304 -- private historical revision under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Prepare(old, old); err != nil {
		t.Fatal(err)
	}
	recovered, err := engine.Recover(context.Background())
	if err != nil || recovered == nil || !reflect.DeepEqual(recovered.Target, target) {
		t.Fatalf("historical same-ID recovery: %+v, %v", recovered, err)
	}
	before := engine.Status(context.Background())
	if before.Applied.State != "unavailable" || before.Applied.Details != nil {
		t.Fatalf("cold recovery published before CrowdSec synchronization: %+v", before)
	}
	recorded := Candidate{cfg: cfg, snapshot: snapshot}
	recorded.prefixes = prefixCounts(recorded)
	beforeDetails, err := buildStatusDetails(recorded, target)
	if err != nil {
		t.Fatal(err)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, name := range []string{"egress", "ingress"} {
			want := control.StatusCompiledSet{Family: family, ID: "geo/" + name, Policies: []string{name}, Count: 1}
			if !slices.ContainsFunc(beforeDetails.CompiledSets.Sets, func(row control.StatusCompiledSet) bool { return reflect.DeepEqual(row, want) }) {
				t.Fatalf("historical target reported hypothetical sharing: %+v", beforeDetails.CompiledSets)
			}
		}
	}
	apply := func() (Outcome, error) {
		t.Helper()
		epoch, err := engine.Admit()
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := NewCandidate(epoch, "/fixture.yaml", cfg, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		return engine.Apply(context.Background(), candidate)
	}
	failure := errors.New("migration native switch failed")
	backend.applyErr, backend.applyFailures = failure, 1
	outcome, err := apply()
	if !errors.Is(err, failure) || outcome.Committed {
		t.Fatalf("failed migration: %+v, %v", outcome, err)
	}
	after := engine.Status(context.Background())
	view, readErr := store.Read()
	if readErr != nil || view.Active.ID != old.ID || !reflect.DeepEqual(view.Active.Target, target) || after.Applied.State != "unavailable" || after.Applied.Details != nil {
		t.Fatalf("failed migration changed recorded authority or exposed unsynchronized status: %+v, %v", after, readErr)
	}
	afterBytes, err := os.ReadFile(path) // #nosec G304 -- same immutable private fixture record.
	if err != nil || !bytes.Equal(beforeBytes, afterBytes) {
		t.Fatalf("recovery/rollback rewrote historical record: %v", err)
	}
	outcome, err = apply()
	if err != nil || !outcome.Committed || outcome.Active.Target.Generation == old.Target.Generation {
		t.Fatalf("shared migration: %+v, %v", outcome, err)
	}
	shared := engine.Status(context.Background())
	if !shared.Successful() || shared.Applied.Revision != outcome.Active.ID || !reflect.DeepEqual(shared.Applied.Details.PrefixCounts, beforeDetails.PrefixCounts) {
		t.Fatalf("shared revision/source counts: %+v", shared)
	}
	for _, family := range []string{"ipv4", "ipv6"} {
		want := control.StatusCompiledSet{Family: family, ID: "geo/egress", Policies: []string{"egress", "ingress"}, Count: 1}
		if !slices.ContainsFunc(shared.Applied.Details.CompiledSets.Sets, func(row control.StatusCompiledSet) bool { return reflect.DeepEqual(row, want) }) || slices.ContainsFunc(shared.Applied.Details.CompiledSets.Sets, func(row control.StatusCompiledSet) bool { return row.Family == family && row.ID == "geo/ingress" }) {
			t.Fatalf("committed shared target not reflected in status: %+v", shared.Applied.Details.CompiledSets)
		}
	}
	engine.Close()
	restarted := NewEngine(store, backend, nil)
	defer restarted.Close()
	if _, err := restarted.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if status := restarted.Status(context.Background()); status.Applied.State != "unavailable" {
		t.Fatalf("restart exposed static revision before CrowdSec synchronization: %+v", status)
	}
	epoch, err := restarted.Admit()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := NewCandidate(epoch, "/fixture.yaml", cfg, snapshot)
	if err != nil {
		t.Fatal(err)
	}
	applied, err := restarted.Apply(context.Background(), candidate)
	if err != nil || !applied.Committed {
		t.Fatalf("restart activation: %+v, %v", applied, err)
	}
	report := restarted.Status(context.Background())
	if !report.Successful() || report.Applied.Revision != applied.Active.ID || !reflect.DeepEqual(report.Applied.Details.CompiledSets, shared.Applied.Details.CompiledSets) {
		t.Fatalf("shared restart summary: %+v", report)
	}
}
