package adapter_test

import (
	"bytes"
	"compress/gzip"
	"context"
	"embed"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
)

// Captured official responses and provenance are checked in beside these tests.
// Synthetic mutations below exercise failure boundaries without public requests.
//
//go:embed testdata/country_li.json testdata/asn_3333.json
var fixtures embed.FS

func fixture(t *testing.T, path string) []byte {
	t.Helper()
	body, err := fixtures.ReadFile("testdata/" + path)
	if err != nil {
		t.Fatal(err)
	}
	return body
}

func sourceConfig(countries, asns []string) config.Config {
	return config.Config{
		Version:  1,
		Firewall: config.FirewallConfig{Backend: "nftables", DenyAction: "drop", IPv4: true, IPv6: true},
		Geo:      config.GeoConfig{RequestTimeout: time.Second, RefreshInterval: time.Hour},
		Policies: []config.Policy{{Name: "fixture", Priority: 1, Direction: "ingress", Mode: "blocklist", Traffic: config.TrafficScope{Any: true}, Include: config.Selector{Countries: countries, ASNs: asns}}},
	}
}

type localTransport struct{ destination *url.URL }

func (r localTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.URL.Host, copy.URL.Scheme = r.destination.Host, r.destination.Scheme
	return http.DefaultTransport.RoundTrip(copy)
}

func resolverFor(t *testing.T, handler http.HandlerFunc) (*source.Cache, *source.Resolver) {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	destination, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	cache, err := source.NewCache(filepath.Join(t.TempDir(), "state"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return cache, source.NewResolver(cache, &http.Client{Transport: localTransport{destination: destination}})
}

func TestActualCountryAndASNResponses(t *testing.T) {
	country, asn := fixture(t, "country_li.json"), fixture(t, "asn_3333.json")
	_, resolver := resolverFor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Query().Get("sourceapp") != "perimeterd" {
			http.Error(w, "missing identity", 400)
			return
		}
		switch r.URL.Query().Get("resource") {
		case "LI":
			if r.URL.Path != "/data/country-resource-list/data.json" || r.URL.RawQuery != "resource=LI&sourceapp=perimeterd&v4_format=prefix" {
				http.Error(w, "bad country request", 400)
				return
			}
			_, _ = w.Write(country)
		case "3333":
			if r.URL.Path != "/data/announced-prefixes/data.json" || r.URL.RawQuery != "resource=3333&sourceapp=perimeterd" {
				http.Error(w, "bad ASN request", 400)
				return
			}
			_, _ = w.Write(asn)
		default:
			http.Error(w, "unexpected resource", 400)
		}
	})
	resolved, err := resolver.Resolve(context.Background(), sourceConfig([]string{"LI"}, []string{"AS3333"}), "", false)
	if err != nil {
		t.Fatal(err)
	}
	records := resolved.Snapshot.Records()
	for _, want := range []struct {
		selector   policy.Selector
		endpoint   string
		apiVersion string
		parameters map[string]string
	}{
		{
			selector: policy.Selector{Kind: policy.Country, Value: "LI"},
			endpoint: "https://stat.ripe.net/data/country-resource-list/data.json", apiVersion: "0.2",
			parameters: map[string]string{"resource": "LI", "sourceapp": "perimeterd", "v4_format": "prefix"},
		},
		{
			selector: policy.Selector{Kind: policy.ASN, Value: "AS3333"},
			endpoint: "https://stat.ripe.net/data/announced-prefixes/data.json", apiVersion: "1.2",
			parameters: map[string]string{"resource": "3333", "sourceapp": "perimeterd"},
		},
	} {
		var found bool
		for _, record := range records {
			if record.Selector != want.selector {
				continue
			}
			found = true
			if record.Endpoint != want.endpoint || record.APIVersion != want.apiVersion || len(record.Parameters) != len(want.parameters) {
				t.Fatalf("record metadata for %v = endpoint %q, version %q, parameters %#v", want.selector, record.Endpoint, record.APIVersion, record.Parameters)
			}
			for key, value := range want.parameters {
				if record.Parameters[key] != value {
					t.Fatalf("record parameter %q for %v = %q, want %q", key, want.selector, record.Parameters[key], value)
				}
			}
		}
		if !found {
			t.Fatalf("resolved records omitted %v", want.selector)
		}
	}
	for _, example := range []struct {
		selector policy.Selector
		address  string
	}{
		{policy.Selector{Kind: policy.Country, Value: "LI"}, "5.34.248.1"},
		{policy.Selector{Kind: policy.ASN, Value: "AS3333"}, "193.0.0.1"},
		{policy.Selector{Kind: policy.ASN, Value: "AS3333"}, "2001:67c:2e8::1"},
	} {
		set, ok := resolved.Snapshot.Policy().Lookup(example.selector)
		if !ok || !set.Contains(netip.MustParseAddr(example.address)) {
			t.Fatalf("captured selector %v lost address %s", example.selector, example.address)
		}
	}
}

func TestRequestObserverUsesBoundedSourceAndOutcome(t *testing.T) {
	type observation struct {
		source  string
		success bool
	}

	var successful []observation
	body := fixture(t, "country_li.json")
	_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(body)
	})
	resolver = resolver.WithRequestObserver(func(source string, success bool) {
		successful = append(successful, observation{source: source, success: success})
	})
	if _, err := resolver.Resolve(context.Background(), sourceConfig([]string{"LI"}, nil), "", false); err != nil {
		t.Fatal(err)
	}
	if len(successful) != 1 || successful[0] != (observation{source: "ripestat", success: true}) {
		t.Fatalf("successful request observations = %#v", successful)
	}

	var failed []observation
	_, resolver = resolverFor(t, func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "unavailable", http.StatusBadGateway)
	})
	resolver = resolver.WithRequestObserver(func(source string, success bool) {
		failed = append(failed, observation{source: source, success: success})
	})
	if _, err := resolver.Resolve(context.Background(), sourceConfig([]string{"LI"}, nil), "", false); err == nil {
		t.Fatal("failed source request was accepted")
	}
	if len(failed) != 1 || failed[0] != (observation{source: "ripestat", success: false}) {
		t.Fatalf("failed request observations = %#v", failed)
	}
}

func mutateFixture(t *testing.T, body []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	if err := json.Unmarshal(body, &value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestRejectsUnacceptableCountryEvidence(t *testing.T) {
	valid := fixture(t, "country_li.json")
	cases := []struct {
		name string
		body []byte
	}{
		{"truncated", valid[:len(valid)/2]},
		{"duplicate-status", []byte(strings.Replace(string(valid), `"status":"ok"`, `"status":"error","status":"ok"`, 1))},
		{"case-aliased-status", []byte(strings.Replace(string(valid), `"status":"ok"`, `"status":"error","STATUS":"ok"`, 1))},
		{"unicode-aliased-status", []byte(strings.Replace(string(valid), `"status":"ok"`, `"status":"error","\u017ftatu\u017f":"ok"`, 1))},
		{"case-aliased-prefixes", mutateFixture(t, valid, func(v map[string]any) {
			v["data"].(map[string]any)["resources"].(map[string]any)["IPV4"] = []string{"8.8.8.0/24"}
		})},
		{"status-failed", mutateFixture(t, valid, func(v map[string]any) { v["status"] = "error" })},
		{"wrong-endpoint", mutateFixture(t, valid, func(v map[string]any) { v["data_call_name"] = "announced-prefixes" })},
		{"wrong-version", mutateFixture(t, valid, func(v map[string]any) { v["version"] = "999" })},
		{"identity-mismatch", mutateFixture(t, valid, func(v map[string]any) { v["data"].(map[string]any)["resource"] = "US" })},
		{"missing-family", mutateFixture(t, valid, func(v map[string]any) { delete(v["data"].(map[string]any)["resources"].(map[string]any), "ipv6") })},
		{"wrong-family", mutateFixture(t, valid, func(v map[string]any) {
			v["data"].(map[string]any)["resources"].(map[string]any)["ipv4"] = []string{"2001:db8::/32"}
		})},
		{"invalid-query-time", mutateFixture(t, valid, func(v map[string]any) { v["data"].(map[string]any)["query_time"] = "yesterday" })},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tc.body) })
			if _, err := resolver.Resolve(context.Background(), sourceConfig([]string{"LI"}, nil), "", false); err == nil {
				t.Fatal("unacceptable source evidence was admitted")
			}
		})
	}
}

func TestASNIdentityAndVisibility(t *testing.T) {
	body := []byte(`{"version":"1.2","data_call_name":"announced-prefixes","data_call_status":"supported","status":"ok","status_code":200,"time":"2026-09-14T00:00:00Z","data":{"resource":"AS3333","query_starttime":"2026-09-13T00:00:00","query_endtime":"2026-09-14T00:00:00","prefixes":[{"prefix":"8.8.8.0/24","timelines":[{"starttime":"2026-09-12T00:00:00","endtime":"2026-09-13T00:00:00"}]},{"prefix":"9.9.9.0/24","timelines":[{"starttime":"2026-09-13T00:00:00","endtime":"2026-09-14T00:00:00"}]}]}}`)
	var response atomic.Value
	response.Store(body)
	_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(response.Load().([]byte)) })
	cfg := sourceConfig(nil, []string{"AS3333"})
	resolved, err := resolver.Resolve(context.Background(), cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}
	set, ok := resolved.Snapshot.Policy().Lookup(policy.Selector{Kind: policy.ASN, Value: "AS3333"})
	if !ok || set.Contains(netip.MustParseAddr("8.8.8.8")) || !set.Contains(netip.MustParseAddr("9.9.9.9")) {
		t.Fatalf("incorrect visibility projection: %v", set.Prefixes())
	}
	for _, echo := range []any{nil, "AS3334"} {
		response.Store(mutateFixture(t, body, func(v map[string]any) { v["data"].(map[string]any)["resource"] = echo }))
		if _, err := resolver.Resolve(context.Background(), cfg, "", false); err == nil {
			t.Fatalf("accepted ASN echo %v", echo)
		}
	}
}

func TestRejectsAliasedASNVisibilityFields(t *testing.T) {
	body := mutateFixture(t, fixture(t, "asn_3333.json"), func(v map[string]any) {
		first := v["data"].(map[string]any)["prefixes"].([]any)[0].(map[string]any)
		timeline := first["timelines"].([]any)[0].(map[string]any)
		timeline["ENDTIME"] = timeline["endtime"]
	})
	_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	if _, err := resolver.Resolve(context.Background(), sourceConfig(nil, []string{"AS3333"}), "", false); err == nil {
		t.Fatal("ambiguous ASN visibility evidence was admitted")
	}
}

func TestUnknownProviderMetadataDoesNotOverrideSourceFields(t *testing.T) {
	body := mutateFixture(t, []byte(countryBody("8.8.8.0/24")), func(v map[string]any) {
		v["provider_metadata"] = map[string]any{
			"STATUS": "error",
			"nested": map[string]any{"status": "error"},
		}
	})
	_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) })
	resolved, err := resolver.Resolve(context.Background(), sourceConfig([]string{"US"}, nil), "", false)
	if err != nil {
		t.Fatal(err)
	}
	set, ok := resolved.Snapshot.Policy().Lookup(policy.Selector{Kind: policy.Country, Value: "US"})
	if !ok || !set.Contains(netip.MustParseAddr("8.8.8.8")) {
		t.Fatal("unrelated metadata changed resolved source prefixes")
	}
}

func countryBody(address string) string {
	return fmt.Sprintf(`{"version":"0.2","data_call_name":"country-resource-list","data_call_status":"supported","status":"ok","status_code":200,"time":"2026-09-14T00:00:00Z","data":{"query_time":"2026-09-13T00:00:00","resources":{"ipv4":[%q],"ipv6":[]}}}`, address)
}

func emptyCountryBody() string {
	return `{"version":"0.2","data_call_name":"country-resource-list","data_call_status":"supported","status":"ok","status_code":200,"time":"2026-09-14T00:00:00Z","data":{"query_time":"2026-09-13T00:00:00","resources":{"ipv4":[],"ipv6":[]}}}`
}

func TestFallbackUsesCommittedSnapshotWhenFetchedPolicyIsEmpty(t *testing.T) {
	for _, scenario := range []string{"empty-selector", "empty-after-exclusion"} {
		t.Run(scenario, func(t *testing.T) {
			var refreshed atomic.Bool
			_, resolver := resolverFor(t, func(w http.ResponseWriter, r *http.Request) {
				body := countryBody("8.8.8.0/24")
				if r.URL.Query().Get("resource") == "CA" && !refreshed.Load() {
					body = countryBody("9.9.9.0/24")
				}
				if scenario == "empty-selector" && refreshed.Load() {
					body = emptyCountryBody()
				}
				_, _ = io.WriteString(w, body)
			})
			cfg := sourceConfig([]string{"US"}, nil)
			if scenario == "empty-after-exclusion" {
				cfg.Policies[0].Exclude.Countries = []string{"CA"}
			}
			initial, err := resolver.Resolve(context.Background(), cfg, "", false)
			if err != nil {
				t.Fatal(err)
			}
			initialAge := initial.Snapshot.OldestRetrieved()

			refreshed.Store(true)
			cfg.Geo.RefreshInterval = time.Nanosecond
			fallback, err := resolver.Resolve(context.Background(), cfg, initial.Snapshot.ManifestID(), true)
			if err != nil || fallback.RefreshError == nil {
				t.Fatalf("empty fetched policy did not fall back: %+v %v", fallback, err)
			}
			if fallback.Snapshot.ManifestID() != initial.Snapshot.ManifestID() {
				t.Fatalf("fallback manifest = %q, want committed %q", fallback.Snapshot.ManifestID(), initial.Snapshot.ManifestID())
			}
			if !fallback.Snapshot.OldestRetrieved().Equal(initialAge) {
				t.Fatalf("fallback retrieval age = %v, want %v", fallback.Snapshot.OldestRetrieved(), initialAge)
			}
			if _, err := resolver.Resolve(context.Background(), cfg, initial.Snapshot.ManifestID(), false); err == nil {
				t.Fatal("scheduled refresh accepted an unusable fetched policy")
			}
		})
	}
}

func TestRejectsChangedConfigThatInvalidatesCommittedFallback(t *testing.T) {
	_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, countryBody("8.8.8.0/24"))
	})
	cfg := sourceConfig([]string{"US"}, nil)
	initial, err := resolver.Resolve(context.Background(), cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}

	changed := sourceConfig([]string{"US"}, nil)
	changed.Policies[0].Exclude.Countries = []string{"US"}
	if _, err := resolver.Resolve(context.Background(), changed, initial.Snapshot.ManifestID(), true); err == nil {
		t.Fatalf("same-selector invalid config was accepted: %v", err)
	}

	changed.Geo.RefreshInterval = time.Nanosecond
	if _, err := resolver.Resolve(context.Background(), changed, initial.Snapshot.ManifestID(), true); err == nil {
		t.Fatalf("invalid changed config was accepted during refresh: %v", err)
	}
}

func TestFallbackUsesWholeCommittedSnapshotAndPreservesAge(t *testing.T) {
	var failing atomic.Bool
	_, resolver := resolverFor(t, func(w http.ResponseWriter, r *http.Request) {
		resource := r.URL.Query().Get("resource")
		if failing.Load() && resource != "US" {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		address := "9.9.9.0/24"
		if resource == "US" {
			address = "8.8.8.0/24"
			if failing.Load() {
				address = "1.1.1.0/24"
			}
		}
		_, _ = io.WriteString(w, countryBody(address))
	})
	cfg := sourceConfig([]string{"US", "CA"}, nil)
	initial, err := resolver.Resolve(context.Background(), cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}
	failing.Store(true)
	fresh, err := resolver.Resolve(context.Background(), cfg, initial.Snapshot.ManifestID(), false)
	if err != nil || fresh.Snapshot.ManifestID() != initial.Snapshot.ManifestID() {
		t.Fatalf("fresh reuse: %+v %v", fresh, err)
	}
	cfg.Geo.RefreshInterval = time.Nanosecond
	fallback, err := resolver.Resolve(context.Background(), cfg, initial.Snapshot.ManifestID(), true)
	if err != nil || fallback.RefreshError == nil || fallback.Snapshot.ManifestID() != initial.Snapshot.ManifestID() {
		t.Fatalf("whole fallback: %+v %v", fallback, err)
	}
	if _, err := resolver.Resolve(context.Background(), cfg, initial.Snapshot.ManifestID(), false); err == nil {
		t.Fatal("scheduled refresh hid partial-source failure")
	}
	subset := sourceConfig([]string{"CA"}, nil)
	subset.Geo.RefreshInterval = time.Nanosecond
	smaller, err := resolver.Resolve(context.Background(), subset, initial.Snapshot.ManifestID(), true)
	if err != nil || smaller.RefreshError == nil {
		t.Fatalf("subset fallback: %+v %v", smaller, err)
	}
	if len(smaller.Snapshot.Records()) != 1 || smaller.Snapshot.Records()[0].Selector.Value != "CA" {
		t.Fatal("fallback retained unreferenced selectors")
	}
	for _, record := range initial.Snapshot.Records() {
		if record.Selector.Value == "CA" && !smaller.Snapshot.OldestRetrieved().Equal(record.RetrievedAt) {
			t.Fatal("subset fallback reset source age")
		}
	}
	subset.Policies[0].Include.Countries = append(subset.Policies[0].Include.Countries, "DE")
	if _, err := resolver.Resolve(context.Background(), subset, initial.Snapshot.ManifestID(), true); err == nil {
		t.Fatal("stale fallback invented newly introduced selector")
	}
}

func TestRequestTimeoutAndDecodedSizeLimit(t *testing.T) {
	t.Run("timeout", func(t *testing.T) {
		_, resolver := resolverFor(t, func(_ http.ResponseWriter, r *http.Request) { <-r.Context().Done() })
		cfg := sourceConfig([]string{"US"}, nil)
		cfg.Geo.RequestTimeout = 20 * time.Millisecond
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if _, err := resolver.Resolve(ctx, cfg, "", false); err == nil {
			t.Fatal("source timeout was accepted")
		}
	})
	t.Run("decoded-gzip-limit", func(t *testing.T) {
		var compressed bytes.Buffer
		writer := gzip.NewWriter(&compressed)
		_, _ = writer.Write(bytes.Repeat([]byte(" "), (32<<20)+1))
		if err := writer.Close(); err != nil {
			t.Fatal(err)
		}
		_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("Content-Encoding", "gzip")
			_, _ = w.Write(compressed.Bytes())
		})
		if _, err := resolver.Resolve(context.Background(), sourceConfig([]string{"US"}, nil), "", false); err == nil || !strings.Contains(err.Error(), "limit") {
			t.Fatalf("decoded oversized response error: %v", err)
		}
	})
}

func TestResolverBoundsConcurrentRequests(t *testing.T) {
	var active, maximum atomic.Int32
	_, resolver := resolverFor(t, func(w http.ResponseWriter, r *http.Request) {
		count := active.Add(1)
		defer active.Add(-1)
		for old := maximum.Load(); count > old; old = maximum.Load() {
			if maximum.CompareAndSwap(old, count) {
				break
			}
		}
		select {
		case <-time.After(10 * time.Millisecond):
		case <-r.Context().Done():
			return
		}
		_, _ = io.WriteString(w, countryBody("8.8.8.0/24"))
	})
	cfg := sourceConfig([]string{"LI", "US", "CA", "DE", "FR", "GB", "CH", "AT"}, nil)
	if _, err := resolver.Resolve(context.Background(), cfg, "", false); err != nil {
		t.Fatal(err)
	}
	if maximum.Load() > 4 {
		t.Fatalf("exceeded four simultaneous requests: %d", maximum.Load())
	}
}
