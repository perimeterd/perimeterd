package app

import (
	"context"
	"errors"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
	"github.com/perimeterd/perimeterd/internal/state"
	"github.com/perimeterd/perimeterd/internal/upstream"
)

func geoEngineConfig(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`version: 1
metrics:
  listen: ""
firewall:
  backend: nftables
policies:
  - name: country
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["443/tcp"]
    include:
      countries: [CZ]
`))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func geoEngineSnapshot(t *testing.T, store *state.Store, address string) source.Snapshot {
	t.Helper()
	now := time.Now().UTC().Truncate(time.Second)
	snapshot, err := store.Prefixes().Stage([]source.Record{{
		Selector:    policy.Selector{Kind: policy.Country, Value: "CZ"},
		Endpoint:    "https://stat.ripe.net/data/country-resource-list/data.json",
		APIVersion:  "0.2",
		Parameters:  map[string]string{"resource": "CZ", "v4_format": "prefix", "sourceapp": "perimeterd"},
		QueryStart:  now.Add(-time.Hour),
		QueryEnd:    now.Add(-time.Hour),
		RetrievedAt: now,
		IPv4:        []netip.Prefix{netip.MustParsePrefix(address)},
		IPv6:        []netip.Prefix{},
	}})
	if err != nil {
		t.Fatal(err)
	}
	return snapshot
}

func TestSourceManifestFollowsFirewallCommit(t *testing.T) {
	failSwitch := false
	backend := &recordingBackend{}
	engine, store := newTestEngine(t, backend, func(phase string) error {
		if failSwitch && phase == "after-switch" {
			return errors.New("failed after changing kernel selection")
		}
		return nil
	})
	defer engine.Close()
	cfg := geoEngineConfig(t)
	oldSnapshot := geoEngineSnapshot(t, store, "8.8.8.8/32")
	epoch, err := engine.Admit()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := NewCandidate(epoch, "policy.yaml", cfg, oldSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	initial, err := engine.Apply(context.Background(), candidate)
	if err != nil || !initial.Committed {
		t.Fatalf("initial source apply: %+v, %v", initial, err)
	}
	newSnapshot := geoEngineSnapshot(t, store, "9.9.9.9/32")
	candidate, err = NewCandidate(epoch, "policy.yaml", cfg, newSnapshot)
	if err != nil {
		t.Fatal(err)
	}
	candidate.refresh, err = engine.AdmitRefresh(epoch)
	if err != nil {
		t.Fatal(err)
	}
	failSwitch = true
	failed, err := engine.Apply(context.Background(), candidate)
	if err == nil || failed.Committed || failed.Degraded {
		t.Fatalf("source switch rollback: %+v, %v", failed, err)
	}
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if view.Active == nil || view.Active.Manifest != oldSnapshot.ManifestID() || view.Active.ID != initial.Transaction {
		t.Fatalf("failed source candidate selected its manifest: %+v", view.Active)
	}
	if backend.selection() != initial.Active.Target.Generation {
		t.Fatal("failed source candidate did not restore committed packet policy")
	}
	failSwitch = false
	committed, err := engine.Apply(context.Background(), candidate)
	if err != nil || !committed.Committed {
		t.Fatalf("source refresh commit: %+v, %v", committed, err)
	}
	view, err = store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if view.Active == nil || view.Active.Manifest != newSnapshot.ManifestID() || view.Active.ID != committed.Transaction {
		t.Fatalf("committed source candidate lost its manifest: %+v", view.Active)
	}
	// Reopen and recover from the selected manifest, not current YAML or the
	// previous generation's still-present cache objects.
	engine.Close()
	recovered := NewEngine(store, &recordingBackend{}, nil)
	defer recovered.Close()
	active, err := recovered.Recover(context.Background())
	if err != nil || active == nil || active.Manifest != newSnapshot.ManifestID() {
		t.Fatalf("recover committed source generation: %+v, %v", active, err)
	}
}

func TestSourceRefreshDeadlineResetsTransportRetryFence(t *testing.T) {
	store, err := state.Open(filepath.Join(t.TempDir(), "state"), nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC().Truncate(time.Second)
	selector := policy.Selector{Kind: policy.IPList, Value: "private"}
	bindingOne := upstream.Binding{
		Type:               upstream.TypeOpenZiti,
		Identity:           "profile",
		IdentityGeneration: strings.Repeat("a", 64),
		Service:            "list",
	}
	bindingTwo := bindingOne
	bindingTwo.IdentityGeneration = strings.Repeat("b", 64)
	record := func(binding upstream.Binding) source.Record {
		return source.Record{
			Selector: selector, SourceKind: "ip_list", SourceName: "private",
			Endpoint: "https://example.invalid/list", APIVersion: "1",
			Parameters: map[string]string{}, RetrievedAt: now,
			IPv4: []netip.Prefix{netip.MustParsePrefix("192.0.2.1/32")},
			IPv6: []netip.Prefix{}, Transport: binding,
		}
	}
	first, err := store.Prefixes().Stage([]source.Record{record(bindingOne)})
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Prefixes().Stage([]source.Record{record(bindingTwo)})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		IPLists: map[string]config.IPListConfig{
			"private": {URL: "https://example.invalid/list", RefreshInterval: time.Hour, RequestTimeout: time.Second},
		},
	}
	runtime := newSourceRuntime(store.Prefixes(), nil)
	defer runtime.close()
	if err := runtime.selectRevision(&state.Revision{Epoch: 1, Manifest: first.ManifestID(), Config: cfg}, nil); err != nil {
		t.Fatal(err)
	}
	deadline := runtime.deadlines[selector]
	deadline.retry = now.Add(time.Hour)
	runtime.deadlines[selector] = deadline
	if err := runtime.selectRevision(&state.Revision{Epoch: 2, Manifest: second.ManifestID(), Config: cfg}, nil); err != nil {
		t.Fatal(err)
	}
	if got := runtime.deadlines[selector].retry; !got.IsZero() {
		t.Fatalf("transport generation change retained retry fence until %s", got)
	}
}
