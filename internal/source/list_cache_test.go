package source

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/upstream"
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

func TestProviderSnapshotBindsDerivedEndpointAndIdentity(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	id := "future_provider_via_code"
	selector := policy.Selector{Kind: policy.Provider, Value: id}
	endpoint, err := providerEndpoint(id)
	if err != nil {
		t.Fatal(err)
	}
	record, err := parseList([]byte("198.51.100.0/24\n"), endpoint, selector)
	if err != nil {
		t.Fatal(err)
	}
	snapshot, err := cache.Stage([]Record{record})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Providers: config.ProvidersConfig{RefreshInterval: 24 * time.Hour, RequestTimeout: 30 * time.Second},
		Policies:  []config.Policy{{Mode: "blocklist", Include: config.Selector{Providers: []string{id}}}},
	}
	if err := snapshot.ValidateConfig(cfg); err != nil {
		t.Fatalf("provider snapshot rejected under matching config: %v", err)
	}
	if err := cache.Stabilize(snapshot.ManifestID()); err != nil {
		t.Fatal(err)
	}
	if err := cache.Collect([]string{snapshot.ManifestID()}); err != nil {
		t.Fatal(err)
	}
	loaded, err := cache.Load(snapshot.ManifestID())
	if err != nil {
		t.Fatal(err)
	}
	prefixes, ok := loaded.Policy().Lookup(selector)
	if !ok || !reflect.DeepEqual(prefixStrings(prefixes.Prefixes()), []string{"198.51.100.0/24"}) {
		t.Fatalf("provider policy did not survive durable cache recovery: %v", prefixes.Prefixes())
	}
	cfg.Policies[0].Include.Providers[0] = "another_provider"
	if err := loaded.ValidateConfig(cfg); err == nil {
		t.Fatal("provider evidence was admitted under a different required identity")
	}

	for name, mutate := range map[string]func(*Record){
		"endpoint":    func(value *Record) { value.Endpoint += "?mirror=1" },
		"name":        func(value *Record) { value.SourceName = "other_provider" },
		"parser":      func(value *Record) { value.APIVersion = "2" },
		"source-kind": func(value *Record) { value.SourceKind = listSourceKind },
	} {
		t.Run(name, func(t *testing.T) {
			corrupt := record
			mutate(&corrupt)
			if _, err := cache.Stage([]Record{corrupt}); err == nil {
				t.Fatalf("cache accepted corrupted provider %s identity", name)
			}
		})
	}
}

func TestLegacyV2StaticCacheRemainsRecoverable(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	selector := policy.Selector{Kind: policy.IPList, Value: "feed"}
	retrieved := "2026-09-20T00:00:00Z"
	prefixes := []string{"198.51.100.0/24"}
	contentID := prefixContentID([]netip.Prefix{netip.MustParsePrefix(prefixes[0])}, nil)
	objectValue := map[string]any{
		"api_version":    "1",
		"content_id":     contentID,
		"endpoint":       "https://example.com/feed",
		"ipv4":           prefixes,
		"ipv6":           []string{},
		"parameters":     map[string]string{},
		"query_end":      "",
		"query_start":    "",
		"retrieved_at":   retrieved,
		"schema_version": 2,
		"selector":       map[string]string{"kind": string(selector.Kind), "value": selector.Value},
		"source_kind":    listSourceKind,
		"source_name":    selector.Value,
	}
	object, err := canonicalJSON(objectValue)
	if err != nil {
		t.Fatal(err)
	}
	objectID := digestID(object)
	entryValue := map[string]any{
		"api_version":  "1",
		"endpoint":     "https://example.com/feed",
		"object":       objectID,
		"parameters":   map[string]string{},
		"query_end":    "",
		"query_start":  "",
		"retrieved_at": retrieved,
		"selector":     map[string]string{"kind": string(selector.Kind), "value": selector.Value},
		"source_kind":  listSourceKind,
		"source_name":  selector.Value,
	}
	manifestValue := map[string]any{
		"schema_version": 2,
		"selectors":      []any{entryValue},
		"source":         "static",
	}
	manifest, err := canonicalJSON(manifestValue)
	if err != nil {
		t.Fatal(err)
	}
	manifestID := digestID(manifest)
	if err := os.WriteFile(cache.objectPath(objectID), object, cacheFileMode); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(cache.manifestPath(manifestID), manifest, cacheFileMode); err != nil {
		t.Fatal(err)
	}
	snapshot, err := cache.Load(manifestID)
	if err != nil {
		t.Fatalf("legacy v2 evidence cannot load: %v", err)
	}
	cfg := config.Config{
		IPLists: map[string]config.IPListConfig{
			"feed": {URL: "https://example.com/feed", RefreshInterval: time.Hour, RequestTimeout: time.Second},
		},
		Policies: []config.Policy{{Mode: "blocklist", Include: config.Selector{IPLists: []string{"feed"}}}},
	}
	if err := snapshot.ValidateConfig(cfg); err != nil {
		t.Fatalf("legacy v2 evidence does not match declarative config: %v", err)
	}
	if err := cache.Collect([]string{manifestID}); err != nil {
		t.Fatalf("legacy v2 evidence cannot survive collection: %v", err)
	}
	beforeObject, err := os.ReadFile(cache.objectPath(objectID))
	if err != nil {
		t.Fatal(err)
	}
	beforeManifest, err := os.ReadFile(cache.manifestPath(manifestID))
	if err != nil {
		t.Fatal(err)
	}
	if err := cache.Stabilize(manifestID); err != nil {
		t.Fatalf("legacy v2 evidence cannot stabilize: %v", err)
	}
	afterObject, err := os.ReadFile(cache.objectPath(objectID))
	if err != nil {
		t.Fatal(err)
	}
	afterManifest, err := os.ReadFile(cache.manifestPath(manifestID))
	if err != nil {
		t.Fatal(err)
	}
	if !reflect.DeepEqual(beforeObject, afterObject) || !reflect.DeepEqual(beforeManifest, afterManifest) {
		t.Fatal("legacy v2 recovery rewrote immutable evidence")
	}
}

func TestV3TransportMetadataIsStrictAndMutuallyBound(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	selector := policy.Selector{Kind: policy.IPList, Value: "feed"}
	record, err := parseList([]byte("198.51.100.1\n"), "https://example.com/feed", selector)
	if err != nil {
		t.Fatal(err)
	}
	record.Transport = upstream.Binding{
		Type:               upstream.TypeOpenZiti,
		Identity:           "private",
		IdentityGeneration: strings.Repeat("a", 64),
		Service:            "feed-service",
	}
	snapshot, err := cache.Stage([]Record{record})
	if err != nil {
		t.Fatal(err)
	}

	manifestData, err := os.ReadFile(cache.manifestPath(snapshot.ManifestID()))
	if err != nil {
		t.Fatal(err)
	}
	var manifest manifestFile
	if err := decodeCanonical(manifestData, &manifest, maxCacheManifestSize); err != nil {
		t.Fatal(err)
	}
	manifest.Entries[0].Transport.Service = "other-service"
	mutatedManifest, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	mutatedManifestID := digestID(mutatedManifest)
	if err := os.WriteFile(cache.manifestPath(mutatedManifestID), mutatedManifest, cacheFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(mutatedManifestID); err == nil {
		t.Fatal("cache accepted a manifest binding that differed from its object")
	}

	objectIDs, err := cache.manifestObjectIDs(snapshot.ManifestID())
	if err != nil {
		t.Fatal(err)
	}
	objectData, err := os.ReadFile(cache.objectPath(objectIDs[0]))
	if err != nil {
		t.Fatal(err)
	}
	var objectValue map[string]any
	if err := json.Unmarshal(objectData, &objectValue); err != nil {
		t.Fatal(err)
	}
	transportValue, ok := objectValue["transport"].(map[string]any)
	if !ok {
		t.Fatal("v3 object transport metadata was not an object")
	}
	transportValue["secret"] = "credential-material"
	objectValue["transport"] = transportValue
	mutatedObject, err := canonicalJSON(objectValue)
	if err != nil {
		t.Fatal(err)
	}
	mutatedObjectID := digestID(mutatedObject)
	if err := os.WriteFile(cache.objectPath(mutatedObjectID), mutatedObject, cacheFileMode); err != nil {
		t.Fatal(err)
	}
	manifest.Entries[0].Transport = record.Transport
	manifest.Entries[0].Object = mutatedObjectID
	manifestWithExtraObject, err := canonicalJSON(manifest)
	if err != nil {
		t.Fatal(err)
	}
	manifestWithExtraObjectID := digestID(manifestWithExtraObject)
	if err := os.WriteFile(cache.manifestPath(manifestWithExtraObjectID), manifestWithExtraObject, cacheFileMode); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.Load(manifestWithExtraObjectID); err == nil {
		t.Fatal("cache accepted an object with an extra secret field")
	}
}

func TestListSameOriginRedirectPreservesIPv6Zone(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path == "/feed" {
			http.Redirect(w, req, "/next", http.StatusFound)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	// Route the scoped application authority to a real local HTTP endpoint,
	// as a service-bound transport does, without requiring an IPv6 interface.
	transport := &http.Transport{DialContext: func(ctx context.Context, network, _ string) (net.Conn, error) {
		return (&net.Dialer{}).DialContext(ctx, network, server.Listener.Addr().String())
	}}
	defer transport.CloseIdleConnections()
	resolver := NewResolver(nil, &http.Client{Transport: transport})
	req, err := http.NewRequest(http.MethodGet, "http://[fe80::1%25FeedNIC]/feed", nil)
	if err != nil {
		t.Fatal(err)
	}
	req = req.WithContext(markListOrigin(markListRequest(req.Context()), req.URL))
	response, err := resolver.client.Do(req)
	if err != nil {
		t.Fatalf("same-origin relative redirect failed: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("redirect response status = %d", response.StatusCode)
	}
}

func TestResolvedBindingRequiresExactLoadedGenerationAndService(t *testing.T) {
	selector := policy.Selector{Kind: policy.IPList, Value: "feed"}
	cfg := config.Config{
		IPLists: map[string]config.IPListConfig{
			"feed": {
				URL:             "https://example.com/feed",
				RefreshInterval: time.Hour,
				RequestTimeout:  time.Second,
				Transport:       config.TransportConfig{Type: upstream.TypeOpenZiti, Identity: "private", Service: "feed-service"},
			},
		},
		Policies: []config.Policy{{Mode: "blocklist", Include: config.Selector{IPLists: []string{"feed"}}}},
	}
	record, err := parseList([]byte("198.51.100.1\n"), "https://example.com/feed", selector)
	if err != nil {
		t.Fatal(err)
	}
	record.Transport = upstream.Binding{
		Type:               upstream.TypeOpenZiti,
		Identity:           "private",
		IdentityGeneration: strings.Repeat("a", 64),
		Service:            "feed-service",
	}
	expected := map[policy.Selector]upstream.Binding{selector: record.Transport}
	if !recordMatchesResolved(record, cfg, expected) {
		t.Fatal("matching loaded transport binding was rejected")
	}
	for name, binding := range map[string]upstream.Binding{
		"generation": {
			Type: upstream.TypeOpenZiti, Identity: "private",
			IdentityGeneration: strings.Repeat("b", 64), Service: "feed-service",
		},
		"service": {
			Type: upstream.TypeOpenZiti, Identity: "private",
			IdentityGeneration: strings.Repeat("a", 64), Service: "other-service",
		},
		"direct": {Type: upstream.TypeDirect},
	} {
		t.Run(name, func(t *testing.T) {
			if recordMatchesResolved(record, cfg, map[policy.Selector]upstream.Binding{selector: binding}) {
				t.Fatalf("transport crossing accepted for %s", name)
			}
		})
	}
	if !recordMatchesConfig(record, cfg) {
		t.Fatal("offline declarative validation rejected matching route")
	}
	cfg.IPLists["feed"] = config.IPListConfig{
		URL:             "https://example.com/feed",
		RefreshInterval: time.Hour,
		RequestTimeout:  time.Second,
		Transport:       config.TransportConfig{Type: upstream.TypeOpenZiti, Identity: "private", Service: "other-service"},
	}
	if recordMatchesConfig(record, cfg) {
		t.Fatal("offline declarative validation accepted a changed service")
	}
}

func TestResolveChangedTransportCannotFallbackCommittedList(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	selector := policy.Selector{Kind: policy.IPList, Value: "feed"}
	record, err := parseList([]byte("198.51.100.1\n"), "https://example.com/feed", selector)
	if err != nil {
		t.Fatal(err)
	}
	committed, err := cache.Stage([]Record{record})
	if err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Geo: config.GeoConfig{RefreshInterval: time.Hour, RequestTimeout: time.Second},
		IPLists: map[string]config.IPListConfig{
			"feed": {
				URL:             "https://example.com/feed",
				RefreshInterval: time.Hour,
				RequestTimeout:  time.Second,
				Transport: config.TransportConfig{
					Type: upstream.TypeOpenZiti, Identity: "private", Service: "feed-service",
				},
			},
		},
		Policies: []config.Policy{{Mode: "blocklist", Include: config.Selector{IPLists: []string{"feed"}}}},
	}
	resolution, err := NewResolver(cache, nil).Resolve(context.Background(), cfg, committed.ManifestID(), true)
	if err == nil {
		t.Fatal("changed transport unexpectedly used a direct committed fallback")
	}
	if resolution.Snapshot.ManifestID() == committed.ManifestID() {
		t.Fatal("changed transport revived the old committed list snapshot")
	}
}
