package adapter_test

import (
	"io"
	"net/http"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func providerSourceConfig(ids ...string) config.Config {
	cfg := sourceConfig(nil, nil)
	cfg.Providers = config.ProvidersConfig{RefreshInterval: time.Hour, RequestTimeout: time.Second}
	cfg.Policies[0].Include.Providers = ids
	return cfg
}

func TestDynamicProvidersResolveOnlyRequiredCDNFiles(t *testing.T) {
	const mainPath = "/gh/rezmoss/cloud-provider-ip-addresses@main/future-vendor/future-vendor_ips_merged.txt"
	const carvePath = "/gh/rezmoss/cloud-provider-ip-addresses@main/new_vendor_123/new_vendor_123_ips_merged.txt"
	var mu sync.Mutex
	requests := map[string]int{}
	_, resolver := resolverFor(t, func(w http.ResponseWriter, r *http.Request) {
		key := r.Host + r.URL.RequestURI()
		mu.Lock()
		requests[key]++
		mu.Unlock()
		if r.Method != http.MethodGet {
			http.Error(w, "content GET required", http.StatusMethodNotAllowed)
			return
		}
		switch key {
		case "cdn.jsdelivr.net" + mainPath:
			_, _ = io.WriteString(w, "8.8.8.42/24\n2001:4860:4860::8888\n8.8.8.8\n")
		case "cdn.jsdelivr.net" + carvePath:
			_, _ = io.WriteString(w, "8.8.8.8\n")
		case "lists.example.test/custom":
			_, _ = io.WriteString(w, "9.9.9.9\n")
		default:
			http.NotFound(w, r)
		}
	})
	cfg := providerSourceConfig("future-vendor", "future-vendor")
	cfg.Policies[0].Include.IPLists = []string{"future-vendor"}
	cfg.Policies[0].Exclude.Providers = []string{"new_vendor_123"}
	cfg.IPLists = map[string]config.IPListConfig{"future-vendor": {URL: "https://lists.example.test/custom", RefreshInterval: time.Hour, RequestTimeout: time.Second}}
	cfg.Policies = append(cfg.Policies, config.Policy{Name: "disabled", Priority: 2, Direction: "ingress", Mode: "disabled", Traffic: config.TrafficScope{Any: true}, Include: config.Selector{Providers: []string{"not_published_yet"}}})
	first, err := resolver.Resolve(t.Context(), cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}
	for selector, want := range map[policy.Selector][]string{
		{Kind: policy.Provider, Value: "future-vendor"}:  {"8.8.8.0/24", "2001:4860:4860::8888/128"},
		{Kind: policy.Provider, Value: "new_vendor_123"}: {"8.8.8.8/32"},
		{Kind: policy.IPList, Value: "future-vendor"}:    {"9.9.9.9/32"},
	} {
		set, ok := first.Snapshot.Policy().Lookup(selector)
		var got []string
		for _, prefix := range set.Prefixes() {
			got = append(got, prefix.String())
		}
		if !ok || !reflect.DeepEqual(got, want) {
			t.Fatalf("wrong data for independent source %v: %v, want %v", selector, got, want)
		}
	}
	second, err := resolver.Resolve(t.Context(), cfg, first.Snapshot.ManifestID(), false)
	if err != nil || second.Snapshot.ManifestID() != first.Snapshot.ManifestID() {
		t.Fatalf("fresh provider snapshot could not be reused: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	wantRequests := map[string]int{"cdn.jsdelivr.net" + mainPath: 1, "cdn.jsdelivr.net" + carvePath: 1, "lists.example.test/custom": 1}
	if !reflect.DeepEqual(requests, wantRequests) {
		t.Fatalf("unexpected discovery, disabled, duplicate, or fresh-source request: %v", requests)
	}
}

func TestMissingProviderFailsCandidateButCanAppearLater(t *testing.T) {
	var available atomic.Bool
	_, resolver := resolverFor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Host != "cdn.jsdelivr.net" || r.URL.Path != "/gh/rezmoss/cloud-provider-ip-addresses@main/unreleased_vendor/unreleased_vendor_ips_merged.txt" || !available.Load() {
			http.NotFound(w, r)
			return
		}
		_, _ = io.WriteString(w, "8.8.8.8\n")
	})
	cfg := providerSourceConfig("unreleased_vendor")
	if result, err := resolver.Resolve(t.Context(), cfg, "", true); err == nil || result.Snapshot.ManifestID() != "" {
		t.Fatalf("unknown provider was silently accepted: %v", err)
	}
	available.Store(true)
	first, err := resolver.Resolve(t.Context(), cfg, "", false)
	if err != nil {
		t.Fatalf("new provider remained negatively cached: %v", err)
	}
	// An unavailable exclusion is especially dangerous: treating it as empty
	// would broaden the effective block instead of rejecting the candidate.
	cfg.Policies[0].Exclude.Providers = []string{"missing_exclusion"}
	if result, err := resolver.Resolve(t.Context(), cfg, first.Snapshot.ManifestID(), true); err == nil || result.Snapshot.ManifestID() != "" {
		t.Fatalf("unknown exclusion borrowed incomplete fallback: %v", err)
	}
}

func TestProviderFailureRetainsCompleteMixedSnapshot(t *testing.T) {
	for _, failure := range []string{"404", "empty", "malformed"} {
		t.Run(failure, func(t *testing.T) {
			var failing atomic.Bool
			_, resolver := resolverFor(t, func(w http.ResponseWriter, r *http.Request) {
				switch r.Host {
				case "cdn.jsdelivr.net":
					if failing.Load() {
						switch failure {
						case "404":
							http.NotFound(w, r)
						case "empty":
							_, _ = io.WriteString(w, "# no addresses\n")
						case "malformed":
							_, _ = io.WriteString(w, "1.1.1.1\nmalformed-tail\n")
						}
						return
					}
					_, _ = io.WriteString(w, "8.8.8.8\n")
				case "lists.example.test":
					if failing.Load() {
						_, _ = io.WriteString(w, "2.2.2.2\n")
					} else {
						_, _ = io.WriteString(w, "9.9.9.9\n")
					}
				default:
					http.NotFound(w, r)
				}
			})
			cfg := providerSourceConfig("future_vendor")
			cfg.Providers.RefreshInterval = time.Nanosecond
			cfg.IPLists = map[string]config.IPListConfig{"peer": {URL: "https://lists.example.test/peer", RefreshInterval: time.Nanosecond, RequestTimeout: time.Second}}
			cfg.Policies[0].Include.IPLists = []string{"peer"}
			first, err := resolver.Resolve(t.Context(), cfg, "", false)
			if err != nil {
				t.Fatal(err)
			}
			failing.Store(true)
			if result, err := resolver.Resolve(t.Context(), cfg, first.Snapshot.ManifestID(), false); err == nil || result.Snapshot.ManifestID() != "" {
				t.Fatalf("invalid provider published a partial refresh: %v", err)
			}
			fallback, err := resolver.Resolve(t.Context(), cfg, first.Snapshot.ManifestID(), true)
			if err != nil || fallback.RefreshError == nil || fallback.Snapshot.ManifestID() != first.Snapshot.ManifestID() || !fallback.Snapshot.OldestRetrieved().Equal(first.Snapshot.OldestRetrieved()) {
				t.Fatalf("complete mixed fallback changed on failure: %+v, %v", fallback, err)
			}
		})
	}
}
