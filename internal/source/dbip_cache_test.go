package source

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/upstream"
)

func dbipCacheRecord(country string) Record {
	return Record{
		Selector:   policy.Selector{Kind: policy.Country, Value: country},
		SourceKind: dbipSourceKind, APIVersion: dbipFormatVersion,
		Release: "2026-10", Endpoint: dbipEndpoint("2026-10"),
		Parameters:  map[string]string{"resource": country, "sha256": strings.Repeat("a", 64)},
		RetrievedAt: time.Date(2026, 10, 17, 12, 0, 0, 123, time.UTC),
		IPv4:        []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
	}
}

// Write deliberately forged canonical, correctly hashed evidence without Stage.
func writeDBIPCacheFixture(t *testing.T, cache *Cache, records []Record, schema int, mutate func(*manifestFile)) string {
	t.Helper()
	manifest := manifestFile{SchemaVersion: schema, Source: "static"}
	for _, record := range records {
		object := objectFromRecord(record)
		object.SchemaVersion = schema
		if schema < cacheSchemaVersion {
			object.Transport = upstream.Binding{}
		}
		data, err := dbipFixtureJSON(object, schema < cacheSchemaVersion, false)
		if err != nil {
			t.Fatal(err)
		}
		id := digestID(data)
		if err := os.WriteFile(cache.objectPath(id), data, cacheFileMode); err != nil {
			t.Fatal(err)
		}
		entry := manifestEntryFromRecord(record, id)
		if schema < cacheSchemaVersion {
			entry.Transport = upstream.Binding{}
		}
		manifest.Entries = append(manifest.Entries, entry)
	}
	if mutate != nil {
		mutate(&manifest)
	}
	data, err := dbipFixtureJSON(manifest, schema < cacheSchemaVersion, true)
	if err != nil {
		t.Fatal(err)
	}
	id := digestID(data)
	if err := os.WriteFile(cache.manifestPath(id), data, cacheFileMode); err != nil {
		t.Fatal(err)
	}
	return id
}

func dbipFixtureJSON(value any, legacy, manifest bool) ([]byte, error) {
	data, err := canonicalJSON(value)
	if err != nil || !legacy {
		return data, err
	}
	var fields map[string]any
	if err := json.Unmarshal(data, &fields); err != nil {
		return nil, err
	}
	if manifest {
		for _, entry := range fields["selectors"].([]any) {
			delete(entry.(map[string]any), "transport")
		}
	} else {
		delete(fields, "transport")
	}
	return canonicalJSON(fields)
}

func TestDBIPCacheStageAndLoadRejectForgedMetadata(t *testing.T) {
	cases := []struct {
		name   string
		mutate func(*Record)
	}{
		{"provider", func(r *Record) { r.SourceKind = ripeSourceKind }},
		{"historical provider", func(r *Record) { r.SourceKind = "" }},
		{"source name", func(r *Record) { r.SourceName = "US" }},
		{"parser", func(r *Record) { r.APIVersion = "dbip-country-csv-2" }},
		{"month", func(r *Record) { r.Release = "2026-1" }},
		{"invalid month", func(r *Record) { r.Release = "2026-13" }},
		{"endpoint", func(r *Record) { r.Endpoint = dbipEndpoint("2026-09") }},
		{"resource", func(r *Record) { r.Parameters["resource"] = "SK" }},
		{"extra parameter", func(r *Record) { r.Parameters["extra"] = "x" }},
		{"missing digest", func(r *Record) { delete(r.Parameters, "sha256") }},
		{"uppercase digest", func(r *Record) { r.Parameters["sha256"] = strings.Repeat("A", 64) }},
		{"short digest", func(r *Record) { r.Parameters["sha256"] = "abc" }},
		{"nonhex digest", func(r *Record) { r.Parameters["sha256"] = strings.Repeat("g", 64) }},
		{"query start", func(r *Record) { r.QueryStart = r.RetrievedAt }},
		{"query end", func(r *Record) { r.QueryEnd = r.RetrievedAt }},
		{"retrieval", func(r *Record) { r.RetrievedAt = time.Time{} }},
		{"transport", func(r *Record) {
			r.Transport = upstream.Binding{Type: upstream.TypeOpenZiti, Identity: "identity", IdentityGeneration: strings.Repeat("a", 64), Service: "service"}
		}},
		{"direct identity", func(r *Record) { r.Transport = upstream.Binding{Type: upstream.TypeDirect, Service: "service"} }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cache, _ := openCacheTest(t, nil)
			record := dbipCacheRecord("US")
			tc.mutate(&record)
			if _, err := cache.Stage([]Record{record}); err == nil {
				t.Fatal("Stage accepted forged metadata")
			}
			id := writeDBIPCacheFixture(t, cache, []Record{record}, cacheSchemaVersion, nil)
			if _, err := cache.Load(id); err == nil {
				t.Fatal("Load accepted correctly hashed forged metadata")
			}
		})
	}
}

func TestDBIPCacheRejectsMixedBatchesAndLoadsCoherentSubsets(t *testing.T) {
	for _, field := range []string{"release", "digest", "retrieval", "country provider"} {
		t.Run(field, func(t *testing.T) {
			cache, _ := openCacheTest(t, nil)
			first, second := dbipCacheRecord("SK"), dbipCacheRecord("US")
			switch field {
			case "release":
				second.Release = "2026-09"
				second.Endpoint = dbipEndpoint(second.Release)
			case "digest":
				second.Parameters["sha256"] = strings.Repeat("b", 64)
			case "retrieval":
				second.RetrievedAt = second.RetrievedAt.Add(time.Nanosecond)
			case "country provider":
				second = cacheTestRecord(first.RetrievedAt)
			}
			if _, err := cache.Stage([]Record{first, second}); err == nil {
				t.Fatal("Stage accepted mixed artifacts")
			}
			if len(cacheJSONFiles(t, cache.manifests)) != 0 {
				t.Fatal("rejected candidate published manifest")
			}
			id := writeDBIPCacheFixture(t, cache, []Record{first, second}, cacheSchemaVersion, nil)
			if _, err := cache.Load(id); err == nil {
				t.Fatal("Load accepted mixed artifacts")
			}
		})
	}
	cache, _ := openCacheTest(t, nil)
	records := []Record{dbipCacheRecord("SK"), dbipCacheRecord("US"), cacheTestRecord(time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC))}
	// Keep an independent RIPE ASN in the same manifest.
	records[2].Selector = policy.Selector{Kind: policy.ASN, Value: "AS123"}
	request, err := ripeRequestFor(records[2].Selector)
	if err != nil {
		t.Fatal(err)
	}
	records[2].Endpoint, records[2].APIVersion, records[2].Parameters = request.endpoint, request.apiVersion, request.parameters
	full, err := cache.Stage(records)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(full.ManifestID()); err != nil {
		t.Fatal(err)
	}
	subset, err := cache.Stage(records[:1])
	if err != nil {
		t.Fatal(err)
	}
	if got := subset.Records()[0]; got.Release != records[0].Release || got.Parameters["sha256"] != records[0].Parameters["sha256"] {
		t.Fatal("subset lost provenance")
	}
}

func TestDBIPCacheArtifactDigestAffectsIdentityNotMembership(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	record := dbipCacheRecord("US")
	first, err := cache.Stage([]Record{record})
	if err != nil {
		t.Fatal(err)
	}
	record.Parameters["sha256"] = strings.Repeat("b", 64)
	second, err := cache.Stage([]Record{record})
	if err != nil {
		t.Fatal(err)
	}
	if first.ManifestID() == second.ManifestID() {
		t.Fatal("artifact change did not change manifest identity")
	}
	if prefixContentID(first.Records()[0].IPv4, first.Records()[0].IPv6) != prefixContentID(second.Records()[0].IPv4, second.Records()[0].IPv6) {
		t.Fatal("artifact change changed membership hash")
	}
	firstManifest, err := cache.readManifest(first.ManifestID())
	if err != nil {
		t.Fatal(err)
	}
	secondManifest, err := cache.readManifest(second.ManifestID())
	if err != nil {
		t.Fatal(err)
	}
	if firstManifest.Source != "static" || firstManifest.Entries[0].Object == secondManifest.Entries[0].Object {
		t.Fatal("artifact change did not change object identity or source classification")
	}
}

func TestDBIPCacheRejectsObjectManifestReleaseMismatch(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	id := writeDBIPCacheFixture(t, cache, []Record{dbipCacheRecord("US")}, cacheSchemaVersion, func(m *manifestFile) {
		m.Entries[0].Release = "2026-09"
		m.Entries[0].Endpoint = dbipEndpoint("2026-09")
	})
	if _, err := cache.Load(id); err == nil || !strings.Contains(err.Error(), "manifest metadata does not match") {
		t.Fatalf("Load mismatch = %v", err)
	}
}

func TestDBIPCacheRejectsLegacySchemasAndNonDBIPRelease(t *testing.T) {
	for _, schema := range []int{1, 2} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			cache, _ := openCacheTest(t, nil)
			id := writeDBIPCacheFixture(t, cache, []Record{dbipCacheRecord("US")}, schema, nil)
			if _, err := cache.Load(id); err == nil {
				t.Fatal("legacy schema accepted DB-IP")
			}
		})
	}
	cache, _ := openCacheTest(t, nil)
	ripe := cacheTestRecord(time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC))
	ripe.Release = "2026-10"
	if _, err := cache.Stage([]Record{ripe}); err == nil {
		t.Fatal("RIPE accepted release")
	}
	id := writeDBIPCacheFixture(t, cache, []Record{ripe}, cacheSchemaVersion, nil)
	if _, err := cache.Load(id); err == nil {
		t.Fatal("Load accepted RIPE release")
	}
}

func TestDBIPCacheWireReleaseRoundTrip(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	record := dbipCacheRecord("US")
	snapshot, err := cache.Stage([]Record{record})
	if err != nil {
		t.Fatal(err)
	}
	manifest, err := cache.readManifest(snapshot.ManifestID())
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(cache.root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = root.Close() })
	for _, path := range []string{"manifests/" + snapshot.ManifestID() + ".json", "objects/" + manifest.Entries[0].Object + ".json"} {
		data, err := root.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Contains(data, []byte(`"release":"2026-10"`)) {
			t.Fatalf("release missing from %s", path)
		}
		var payload any
		if err := json.Unmarshal(data, &payload); err != nil {
			t.Fatal(err)
		}
	}
	if got := snapshot.Records()[0]; got.Release != record.Release || !got.QueryStart.IsZero() || !got.QueryEnd.IsZero() {
		t.Fatalf("roundtrip = %+v", got)
	}
}

func TestCachePreDBIPHistoricalBytesRemainExact(t *testing.T) {
	const manifestID = "4ec9d336e3346cb5ff0659f5ddd3c1b077e10c19f97df9f6f9cb89079e23c5dd"
	const objectID = "efcff69b9bd71169fa680ee4b3817db55d4ecf8b1ba28e7d5fcd90c5de56b793"
	cache, _ := openCacheTest(t, nil)
	fixtures, err := os.OpenRoot(filepath.Join("..", "state", "testdata", "pre-dbip", "prefixes"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixtures.Close() })
	destination, err := os.OpenRoot(cache.root)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = destination.Close() })
	for _, fixture := range []struct {
		directory, id string
		value         any
	}{
		{"manifests", manifestID, &manifestFile{}},
		{"objects", objectID, &objectFile{}},
	} {
		data, err := fixtures.ReadFile(filepath.Join(fixture.directory, fixture.id+".json"))
		if err != nil {
			t.Fatal(err)
		}
		if digestID(data) != fixture.id {
			t.Fatal("historical fixture identity changed")
		}
		if err := decodeCanonical(data, fixture.value, maxCacheManifestSize); err != nil {
			t.Fatal(err)
		}
		reencoded, err := canonicalJSON(fixture.value)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(data, reencoded) {
			t.Fatalf("historical %s canonical bytes changed", fixture.directory)
		}
		if bytes.Contains(reencoded, []byte(`"release"`)) || bytes.Contains(reencoded, []byte(`"source_kind"`)) {
			t.Fatal("historical optional metadata was filled in")
		}
		if err := destination.WriteFile(filepath.Join(fixture.directory, fixture.id+".json"), data, cacheFileMode); err != nil {
			t.Fatal(err)
		}
	}
	loaded, err := cache.Load(manifestID)
	if err != nil {
		t.Fatal(err)
	}
	if got := loaded.Records()[0]; got.SourceKind != "" || got.Release != "" || got.Selector.Value != "SK" {
		t.Fatalf("historical RIPE identity reinterpreted: %+v", got)
	}
	restaged, err := cache.Stage(loaded.Records())
	if err != nil {
		t.Fatal(err)
	}
	if restaged.ManifestID() != manifestID {
		t.Fatal("historical restaging changed immutable identity")
	}
}

func TestDBIPCacheProviderCoverageIsExact(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	dbip, err := cache.Stage([]Record{dbipCacheRecord("US")})
	if err != nil {
		t.Fatal(err)
	}
	ripe, err := cache.Stage([]Record{cacheTestRecord(time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC))})
	if err != nil {
		t.Fatal(err)
	}
	for _, provider := range []string{config.CountryProviderDBIPLite, config.CountryProviderRIPEstat, ""} {
		cfg := config.Config{
			Geo:      config.GeoConfig{CountryProvider: provider},
			Policies: []config.Policy{{Mode: "blocklist", Include: config.Selector{Countries: []string{"US"}}}},
		}
		dbipErr, ripeErr := dbip.ValidateConfig(cfg), ripe.ValidateConfig(cfg)
		if provider == config.CountryProviderDBIPLite {
			if dbipErr != nil || ripeErr == nil {
				t.Fatalf("DB-IP coverage: DB-IP=%v RIPE=%v", dbipErr, ripeErr)
			}
		} else {
			if ripeErr != nil || dbipErr == nil {
				t.Fatalf("RIPE coverage: DB-IP=%v RIPE=%v", dbipErr, ripeErr)
			}
		}
	}
}

func TestDBIPCacheRejectsLegacyObjectsBehindValidRIPEManifest(t *testing.T) {
	for _, schema := range []int{1, 2} {
		t.Run(fmt.Sprint(schema), func(t *testing.T) {
			cache, _ := openCacheTest(t, nil)
			id := writeDBIPCacheFixture(t, cache, []Record{dbipCacheRecord("US")}, schema, func(m *manifestFile) {
				objectID := m.Entries[0].Object
				m.Source = ripeSourceKind
				m.Entries[0] = manifestEntryFromRecord(cacheTestRecord(time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC)), objectID)
				m.Entries[0].Transport = upstream.Binding{}
			})
			if _, err := cache.Load(id); err == nil || (!strings.Contains(err.Error(), "legacy object") && !strings.Contains(err.Error(), "legacy object contains custom")) {
				t.Fatalf("legacy DB-IP object rejection = %v", err)
			}
		})
	}
}

func TestDBIPCacheRejectsReleaseOnStaticSources(t *testing.T) {
	for _, sourceKind := range []string{listSourceKind, providerSourceKind} {
		t.Run(sourceKind, func(t *testing.T) {
			cache, _ := openCacheTest(t, nil)
			record := Record{
				Selector:   policy.Selector{Kind: policy.IPList, Value: "feed"},
				SourceKind: sourceKind, SourceName: "feed", Endpoint: "https://example.com/feed",
				APIVersion: listFormatVersion, Parameters: map[string]string{},
				RetrievedAt: time.Date(2026, 10, 17, 0, 0, 0, 0, time.UTC),
				IPv4:        []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
			}
			if sourceKind == providerSourceKind {
				record.Selector = policy.Selector{Kind: policy.Provider, Value: "cloudflare"}
				record.SourceName = "cloudflare"
				endpoint, err := providerEndpoint("cloudflare")
				if err != nil {
					t.Fatal(err)
				}
				record.Endpoint = endpoint
			}
			if _, err := cache.Stage([]Record{record}); err != nil {
				t.Fatalf("valid static control: %v", err)
			}
			record.Release = "2026-10"
			if _, err := cache.Stage([]Record{record}); err == nil {
				t.Fatal("Stage accepted non-DBIP release")
			}
			id := writeDBIPCacheFixture(t, cache, []Record{record}, cacheSchemaVersion, nil)
			if _, err := cache.Load(id); err == nil {
				t.Fatal("Load accepted non-DBIP release")
			}
		})
	}
}

func TestDBIPCacheRejectsRIPEManifestSource(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	id := writeDBIPCacheFixture(t, cache, []Record{dbipCacheRecord("US")}, cacheSchemaVersion, func(m *manifestFile) {
		m.Source = ripeSourceKind
	})
	if _, err := cache.Load(id); err == nil {
		t.Fatal("DB-IP admitted with RIPE manifest source")
	}
}

func TestDBIPCacheEmptyCountryAndHistoricalMonthRemainValid(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	record := dbipCacheRecord("US")
	record.Release = "2025-01"
	record.Endpoint = dbipEndpoint(record.Release)
	record.IPv4, record.IPv6 = nil, nil
	snapshot, err := cache.Stage([]Record{record})
	if err != nil {
		t.Fatalf("valid absent country: %v", err)
	}
	loaded, err := cache.Load(snapshot.ManifestID())
	if err != nil {
		t.Fatal(err)
	}
	if len(loaded.Records()[0].IPv4) != 0 || len(loaded.Records()[0].IPv6) != 0 {
		t.Fatal("empty country acquired fabricated membership")
	}
	cfg := config.Config{
		Geo:      config.GeoConfig{CountryProvider: config.CountryProviderDBIPLite},
		Policies: []config.Policy{{Mode: "blocklist", Include: config.Selector{Countries: []string{"US"}}}},
	}
	if err := loaded.ValidateConfig(cfg); err != nil {
		t.Fatalf("same-provider historical month rejected: %v", err)
	}
}
