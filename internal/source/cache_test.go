package source

import (
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
