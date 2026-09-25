package source

import (
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
)

func cacheTestRecord(retrieved time.Time) Record {
	return Record{
		Selector:    policy.Selector{Kind: policy.Country, Value: "US"},
		Endpoint:    "https://stat.ripe.net/data/country-resource-list/data.json",
		APIVersion:  "0.2",
		Parameters:  map[string]string{"resource": "US", "sourceapp": "perimeterd", "v4_format": "prefix"},
		QueryStart:  time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		QueryEnd:    time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC),
		RetrievedAt: retrieved,
		IPv4:        []netip.Prefix{netip.MustParsePrefix("198.51.100.99/24")},
		IPv6:        []netip.Prefix{netip.MustParsePrefix("2001:db8:1::/48")},
	}
}

func openCacheTest(t *testing.T, checkpoint func(string) error) (*Cache, string) {
	t.Helper()
	stateDir := filepath.Join(t.TempDir(), "state")
	cache, err := NewCache(stateDir, checkpoint)
	if err != nil {
		t.Fatal(err)
	}
	return cache, stateDir
}

func cacheJSONFiles(t *testing.T, path string) []string {
	t.Helper()
	entries, err := os.ReadDir(path)
	if err != nil {
		t.Fatal(err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if strings.HasSuffix(entry.Name(), ".json") {
			files = append(files, entry.Name())
		}
	}
	return files
}

func TestCacheStageLoadProvidesOneImmutableSnapshot(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	retrieved := time.Date(2026, 9, 14, 12, 0, 0, 0, time.FixedZone("test", 3600))
	input := cacheTestRecord(retrieved)
	snapshot, err := cache.Stage([]Record{input})
	if err != nil {
		t.Fatalf("stage: %v", err)
	}
	if snapshot.ManifestID() == "" {
		t.Fatal("stage returned a zero manifest")
	}
	if snapshot.OldestRetrieved().Location() != time.UTC || !snapshot.OldestRetrieved().Equal(retrieved) {
		t.Fatalf("oldest retrieval = %v, want UTC %v", snapshot.OldestRetrieved(), retrieved)
	}
	input.Parameters["resource"] = "CA"
	input.IPv4[0] = netip.MustParsePrefix("203.0.113.0/24")
	loaded, err := cache.Load(snapshot.ManifestID())
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	want := cacheTestRecord(retrieved)
	want.QueryStart = want.QueryStart.UTC()
	want.QueryEnd = want.QueryEnd.UTC()
	want.RetrievedAt = want.RetrievedAt.UTC()
	want.IPv4 = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	if got := loaded.Records(); !reflect.DeepEqual(got, []Record{want}) {
		t.Fatalf("loaded records = %#v, want %#v", got, []Record{want})
	}
	records := loaded.Records()
	records[0].Parameters["resource"] = "DE"
	records[0].IPv4[0] = netip.MustParsePrefix("192.0.2.0/24")
	if got := loaded.Records()[0]; !reflect.DeepEqual(got, want) {
		t.Fatalf("records output aliases snapshot: %#v", got)
	}
	if got := loaded.Policy().Selectors(); !reflect.DeepEqual(got, []policy.Selector{{Kind: policy.Country, Value: "US"}}) {
		t.Fatalf("policy selectors = %v", got)
	}
	if got := cacheJSONFiles(t, cache.manifests); len(got) != 1 {
		t.Fatalf("manifest files = %v", got)
	}
	if got := cacheJSONFiles(t, cache.objects); len(got) != 1 {
		t.Fatalf("object files = %v", got)
	}
}

func TestCacheLoadRejectsInvalidManifest(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	snapshot, err := cache.Stage([]Record{cacheTestRecord(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))})
	if err != nil {
		t.Fatal(err)
	}
	original, err := os.ReadFile(cache.manifestPath(snapshot.ManifestID()))
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name   string
		mutate func(*manifestFile)
	}{
		{"unsupported source", func(manifest *manifestFile) { manifest.Source = "unsupported" }},
		{"unsupported empty schema", func(manifest *manifestFile) {
			manifest.SchemaVersion = 999
			manifest.Entries = nil
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var manifest manifestFile
			if err := json.Unmarshal(original, &manifest); err != nil {
				t.Fatal(err)
			}
			tc.mutate(&manifest)
			data, err := canonicalJSON(manifest)
			if err != nil {
				t.Fatal(err)
			}
			id := digestID(data)
			if err := os.WriteFile(cache.manifestPath(id), data, cacheFileMode); err != nil {
				t.Fatal(err)
			}
			if _, err := cache.Load(id); err == nil {
				t.Fatal("cache accepted an invalid content-addressed manifest")
			}
		})
	}
}

func TestCacheStageRejectsWholeCandidateWithoutManifest(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	bad := cacheTestRecord(time.Now().UTC())
	bad.Selector = policy.Selector{Kind: policy.Country, Value: "CA"}
	bad.Parameters["resource"] = "CA"
	bad.IPv6 = []netip.Prefix{netip.MustParsePrefix("198.51.100.0/24")}
	if _, err := cache.Stage([]Record{cacheTestRecord(time.Now().UTC()), bad}); err == nil {
		t.Fatal("stage accepted a wrong-family selector result")
	}
	if got := cacheJSONFiles(t, cache.manifests); len(got) != 0 {
		t.Fatalf("rejected stage published manifests: %v", got)
	}
}

func TestCacheLoadRejectsMissingOrCorruptEvidence(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	snapshot, err := cache.Stage([]Record{cacheTestRecord(time.Now().UTC())})
	if err != nil {
		t.Fatal(err)
	}
	manifestPath := cache.manifestPath(snapshot.ManifestID())
	data, err := os.ReadFile(manifestPath) // #nosec G304 -- fixture path is beneath t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(manifestPath, append(data, '\n'), cacheFileMode); err != nil { // #nosec G703 -- fixture path is fixed beneath t.TempDir.
		t.Fatal(err)
	}
	if _, err := cache.Load(snapshot.ManifestID()); err == nil {
		t.Fatal("load accepted a manifest whose bytes no longer match its ID")
	}
	if err := os.WriteFile(manifestPath, data, cacheFileMode); err != nil { // #nosec G703 -- fixture path is fixed beneath t.TempDir.
		t.Fatal(err)
	}
	objectIDs, err := cache.manifestObjectIDs(snapshot.ManifestID())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(cache.objectPath(objectIDs[0])); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(snapshot.ManifestID()); err == nil {
		t.Fatal("load accepted a manifest with a missing referenced object")
	}
}

func TestCacheCollectOnlyRemovesUnreferencedCompleteObjects(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	first, err := cache.Stage([]Record{cacheTestRecord(time.Now().UTC())})
	if err != nil {
		t.Fatal(err)
	}
	secondRecord := cacheTestRecord(time.Now().UTC().Add(time.Minute))
	secondRecord.Parameters["resource"] = "US"
	secondRecord.IPv4 = []netip.Prefix{netip.MustParsePrefix("203.0.113.0/24")}
	second, err := cache.Stage([]Record{secondRecord})
	if err != nil {
		t.Fatal(err)
	}
	if first.ManifestID() == second.ManifestID() {
		t.Fatal("test snapshots unexpectedly share a manifest")
	}
	if err := cache.Collect([]string{first.ManifestID()}); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if _, err := cache.Load(first.ManifestID()); err != nil {
		t.Fatalf("collect removed live manifest: %v", err)
	}
	if _, err := os.Stat(cache.manifestPath(second.ManifestID())); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("orphan manifest after collect: %v", err)
	}
}

func TestCachePublicationFailureCannotSelectOrOverwriteObjects(t *testing.T) {
	failManifest := true
	cache, _ := openCacheTest(t, func(phase string) error {
		if failManifest && phase == "manifest:before-rename" {
			return errors.New("manifest durability failure")
		}
		return nil
	})
	record := cacheTestRecord(time.Now().UTC())
	if _, err := cache.Stage([]Record{record}); err == nil {
		t.Fatal("failed manifest publication succeeded")
	}
	if got := cacheJSONFiles(t, cache.manifests); len(got) != 0 {
		t.Fatalf("failed publication exposed a manifest: %v", got)
	}
	failManifest = false
	snapshot, err := cache.Stage([]Record{record})
	if err != nil {
		t.Fatal(err)
	}
	objects, err := cache.manifestObjectIDs(snapshot.ManifestID())
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache.objectPath(objects[0]), []byte("corrupt"), cacheFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Stage([]Record{record}); err == nil {
		t.Fatal("staging overwrote existing corrupt immutable evidence")
	}
	if _, err := cache.Load(snapshot.ManifestID()); err == nil {
		t.Fatal("corrupt referenced object remained admissible")
	}
}

func TestCacheCanonicalEncoding(t *testing.T) {
	got, err := canonicalJSON(map[string]any{
		"z": "<>&\u2028",
		"a": []any{1, "line\n", "\U0001f600"},
	})
	if err != nil {
		t.Fatal(err)
	}
	want := "{\"a\":[1,\"line\\n\",\"\U0001f600\"],\"z\":\"<>&\u2028\"}"
	if string(got) != want {
		t.Fatalf("canonical bytes = %q, want %q", got, want)
	}
}

func TestCacheLoadChecksCanonicalPayloadAfterValidContentHashes(t *testing.T) {
	for _, tc := range []struct {
		name      string
		malformed string
		wantError string
	}{
		{name: "valid control"},
		{name: "duplicate object key", malformed: "duplicate-object", wantError: `duplicate object key "selector"`},
		{name: "noncanonical manifest", malformed: "noncanonical-manifest", wantError: "cache record is not canonical JSON"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cache, _ := openCacheTest(t, nil)
			snapshot, err := cache.Stage([]Record{cacheTestRecord(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))})
			if err != nil {
				t.Fatal(err)
			}
			manifestData, err := os.ReadFile(cache.manifestPath(snapshot.ManifestID()))
			if err != nil {
				t.Fatal(err)
			}
			var manifest manifestFile
			if err := json.Unmarshal(manifestData, &manifest); err != nil {
				t.Fatal(err)
			}

			manifestID := snapshot.ManifestID()
			switch tc.malformed {
			case "duplicate-object":
				objectData, err := os.ReadFile(cache.objectPath(manifest.Entries[0].Object))
				if err != nil {
					t.Fatal(err)
				}
				validSelector := `"selector":{"kind":"country","value":"US"}`
				duplicateSelector := validSelector + `,"selector":{"kind":"country","value":"US"}`
				malformedObject := []byte(strings.Replace(string(objectData), validSelector, duplicateSelector, 1))
				if string(malformedObject) == string(objectData) {
					t.Fatal("test fixture did not add a duplicate selector key")
				}
				objectID := digestID(malformedObject)
				if err := os.WriteFile(cache.objectPath(objectID), malformedObject, cacheFileMode); err != nil { // #nosec G703 -- content ID and cache path belong to a private test fixture.
					t.Fatal(err)
				}
				manifest.Entries[0].Object = objectID
				updatedManifest, err := canonicalJSON(manifest)
				if err != nil {
					t.Fatal(err)
				}
				manifestID = digestID(updatedManifest)
				if err := os.WriteFile(cache.manifestPath(manifestID), updatedManifest, cacheFileMode); err != nil {
					t.Fatal(err)
				}
			case "noncanonical-manifest":
				malformedManifest := append(append([]byte(nil), manifestData...), '\n')
				manifestID = digestID(malformedManifest)
				if err := os.WriteFile(cache.manifestPath(manifestID), malformedManifest, cacheFileMode); err != nil { // #nosec G703 -- content ID and cache path belong to a private test fixture.
					t.Fatal(err)
				}
			}

			loaded, err := cache.Load(manifestID)
			if tc.wantError == "" {
				if err != nil {
					t.Fatalf("load valid content-addressed fixture: %v", err)
				}
				if loaded.ManifestID() != snapshot.ManifestID() || len(loaded.Records()) != 1 {
					t.Fatalf("loaded control snapshot = %q with %d records", loaded.ManifestID(), len(loaded.Records()))
				}
				return
			}
			if err == nil {
				t.Fatal("cache admitted malformed canonical payload")
			}
			if !strings.Contains(err.Error(), tc.wantError) {
				t.Fatalf("load error = %v, want canonical rejection containing %q", err, tc.wantError)
			}
			if strings.Contains(err.Error(), "content hash mismatch") || errors.Is(err, os.ErrNotExist) {
				t.Fatalf("load failed before the intended canonical boundary: %v", err)
			}
		})
	}
}

func TestCacheLoadRevalidatesRIPERequestIdentityAfterValidHashes(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	snapshot, err := cache.Stage([]Record{cacheTestRecord(time.Date(2026, 9, 1, 0, 0, 0, 0, time.UTC))})
	if err != nil {
		t.Fatal(err)
	}
	manifestData, err := os.ReadFile(cache.manifestPath(snapshot.ManifestID()))
	if err != nil {
		t.Fatal(err)
	}
	var manifest manifestFile
	if err := json.Unmarshal(manifestData, &manifest); err != nil {
		t.Fatal(err)
	}
	objectData, err := os.ReadFile(cache.objectPath(manifest.Entries[0].Object))
	if err != nil {
		t.Fatal(err)
	}
	var object objectFile
	if err := json.Unmarshal(objectData, &object); err != nil {
		t.Fatal(err)
	}
	object.Parameters["resource"] = "CA"
	mutatedObject, err := canonicalJSON(object)
	if err != nil {
		t.Fatal(err)
	}
	objectID := digestID(mutatedObject)
	if err := os.WriteFile(cache.objectPath(objectID), mutatedObject, cacheFileMode); err != nil {
		t.Fatal(err)
	}
	manifest.Entries[0].Object = objectID
	manifest.Entries[0].Parameters["resource"] = "CA"
	mutatedManifest, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestID := digestID(mutatedManifest)
	if err := os.WriteFile(cache.manifestPath(manifestID), mutatedManifest, cacheFileMode); err != nil {
		t.Fatal(err)
	}

	if _, err := cache.Load(manifestID); err == nil {
		t.Fatal("cache admitted request parameters inconsistent with the selector")
	} else {
		if !strings.Contains(err.Error(), "selector request parameters do not match its identity") {
			t.Fatalf("load error = %v, want selector identity rejection", err)
		}
		if strings.Contains(err.Error(), "content hash mismatch") || errors.Is(err, os.ErrNotExist) {
			t.Fatalf("load failed before request identity validation: %v", err)
		}
	}
}
