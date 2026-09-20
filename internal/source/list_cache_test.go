package source

import (
	"crypto/sha256"
	"fmt"
	"os"
	"reflect"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestLegacyRIPEstatCacheRemainsRecoverable(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	// Original v1 bytes, deliberately independent of the current wire structs
	// and serializers. Existing immutable evidence must not be rewritten to v2
	// or have its object ID recomputed from a newer schema during recovery.
	object := []byte(`{"api_version":"0.2","content_id":"f5e915b2378f18c10f18ebb417216a9d407d4c753606659271dd1ed8f40a0e35","endpoint":"https://stat.ripe.net/data/country-resource-list/data.json","ipv4":["198.51.100.0/24"],"ipv6":["2001:db8::/32"],"parameters":{"resource":"US","sourceapp":"perimeterd","v4_format":"prefix"},"query_end":"2026-09-01T00:00:00Z","query_start":"2026-09-01T00:00:00Z","retrieved_at":"2026-09-20T00:00:00Z","schema_version":1,"selector":{"kind":"country","value":"US"}}`)
	objectID := fmt.Sprintf("%x", sha256.Sum256(object))
	manifest := []byte(fmt.Sprintf(`{"schema_version":1,"selectors":[{"api_version":"0.2","endpoint":"https://stat.ripe.net/data/country-resource-list/data.json","object":"%s","parameters":{"resource":"US","sourceapp":"perimeterd","v4_format":"prefix"},"query_end":"2026-09-01T00:00:00Z","query_start":"2026-09-01T00:00:00Z","retrieved_at":"2026-09-20T00:00:00Z","selector":{"kind":"country","value":"US"}}],"source":"ripestat"}`, objectID))
	manifestID := fmt.Sprintf("%x", sha256.Sum256(manifest))
	if err := os.WriteFile(cache.objectPath(objectID), object, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache.manifestPath(manifestID), manifest, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cache.Stabilize(manifestID); err != nil {
		t.Fatalf("legacy durable evidence cannot stabilize: %v", err)
	}
	if err := cache.Collect([]string{manifestID}); err != nil {
		t.Fatalf("legacy evidence cannot survive collection: %v", err)
	}
	snapshot, err := cache.Load(manifestID)
	if err != nil {
		t.Fatal(err)
	}
	set, ok := snapshot.Policy().Lookup(policy.Selector{Kind: policy.Country, Value: "US"})
	var got []string
	for _, prefix := range set.Prefixes() {
		got = append(got, prefix.String())
	}
	if !ok || !reflect.DeepEqual(got, []string{"198.51.100.0/24", "2001:db8::/32"}) {
		t.Fatalf("legacy snapshot recovered different policy: %v", got)
	}
}

func TestCustomListSnapshotBindsURLAndRejectsInvalidEvidence(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	record, err := parseList([]byte("8.8.8.8\n"), "https://example.com/feed", policy.Selector{Kind: policy.IPList, Value: "feed"})
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := cache.Stage([]Record{record})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		IPLists:  map[string]config.IPListConfig{"feed": {URL: "https://example.com/feed", RefreshInterval: time.Hour, RequestTimeout: time.Second}},
		Policies: []config.Policy{{Mode: "blocklist", Include: config.Selector{IPLists: []string{"feed"}}}},
	}
	if err := snapshot.ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	cfg.IPLists["feed"] = config.IPListConfig{URL: "https://example.com/changed", RefreshInterval: time.Hour, RequestTimeout: time.Second}
	if err := snapshot.ValidateConfig(cfg); err == nil {
		t.Fatal("snapshot admitted under a changed endpoint")
	}
	fakeQuery := record
	fakeQuery.QueryStart = time.Now().UTC()
	if _, err := cache.Stage([]Record{fakeQuery}); err == nil {
		t.Fatal("custom-list cache accepted fabricated RIPEstat query metadata")
	}
	empty := record
	empty.IPv4, empty.IPv6 = nil, nil
	if _, err := cache.Stage([]Record{empty}); err == nil {
		t.Fatal("custom-list cache accepted an empty source object")
	}
}
