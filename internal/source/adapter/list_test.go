package adapter_test

import (
	"compress/gzip"
	"context"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func listSourceConfig(url string, countries, lists []string) config.Config {
	return config.Config{
		Version:  1,
		Firewall: config.FirewallConfig{Backend: "nftables", DenyAction: "drop", IPv4: true, IPv6: true},
		Geo:      config.GeoConfig{RequestTimeout: time.Second, RefreshInterval: time.Hour},
		IPLists: map[string]config.IPListConfig{
			"feed": {URL: url, RefreshInterval: time.Hour, RequestTimeout: time.Second},
		},
		Policies: []config.Policy{{Name: "fixture", Priority: 1, Direction: "ingress", Mode: "blocklist", Traffic: config.TrafficScope{Any: true}, Include: config.Selector{Countries: countries, IPLists: lists}}},
	}
}

func TestCustomListMalformedTailDoesNotPublishPartialSnapshot(t *testing.T) {
	body := "192.0.2.1\n"
	_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, body)
	})
	cfg := listSourceConfig("http://feed.invalid/list", nil, []string{"feed"})
	initial, err := resolver.Resolve(context.Background(), cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}
	body = "192.0.2.1\nnot-an-address\n"
	cfg.IPLists["feed"] = config.IPListConfig{URL: "http://feed.invalid/list", RefreshInterval: time.Nanosecond, RequestTimeout: time.Second}
	fallback, err := resolver.Resolve(context.Background(), cfg, initial.Snapshot.ManifestID(), true)
	if err != nil || fallback.RefreshError == nil {
		t.Fatalf("malformed list did not use stale complete snapshot: %+v %v", fallback, err)
	}
	if fallback.Snapshot.ManifestID() != initial.Snapshot.ManifestID() {
		t.Fatalf("malformed list changed manifest to %q", fallback.Snapshot.ManifestID())
	}
}

func TestCustomListChangedURLCannotUseOldFallback(t *testing.T) {
	_, resolver := resolverFor(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/new" {
			http.Error(w, "offline", http.StatusServiceUnavailable)
			return
		}
		_, _ = io.WriteString(w, "198.51.100.1\n")
	})
	cfg := listSourceConfig("http://feed.invalid/old", nil, []string{"feed"})
	initial, err := resolver.Resolve(context.Background(), cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}
	cfg.IPLists["feed"] = config.IPListConfig{URL: "http://feed.invalid/new", RefreshInterval: time.Hour, RequestTimeout: time.Second}
	if _, err := resolver.Resolve(context.Background(), cfg, initial.Snapshot.ManifestID(), true); err == nil {
		t.Fatal("changed list URL reused old-source fallback")
	}
}

func TestCustomListAndRIPEstatPublishCompleteMixedSnapshot(t *testing.T) {
	_, resolver := resolverFor(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/list":
			_, _ = io.WriteString(w, " 192.0.2.1\n2001:db8::1\n")
		case strings.HasSuffix(r.URL.Path, "/country-resource-list/data.json"):
			_, _ = io.WriteString(w, countryBody("198.51.100.0/24"))
		default:
			http.NotFound(w, r)
		}
	})
	cfg := listSourceConfig("http://feed.invalid/list", []string{"US"}, []string{"feed"})
	resolved, err := resolver.Resolve(context.Background(), cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}
	records := resolved.Snapshot.Records()
	if len(records) != 2 {
		t.Fatalf("mixed snapshot records = %d, want 2", len(records))
	}
	seen := map[policy.Selector]bool{}
	for _, record := range records {
		seen[record.Selector] = true
	}
	if !seen[policy.Selector{Kind: policy.Country, Value: "US"}] || !seen[policy.Selector{Kind: policy.IPList, Value: "feed"}] {
		t.Fatalf("mixed snapshot selectors = %#v", seen)
	}
}

func TestCustomListAllowsTenRedirectsButRejectsEleven(t *testing.T) {
	for _, limit := range []int{10, 11} {
		t.Run(fmt.Sprintf("redirects-%d", limit), func(t *testing.T) {
			_, resolver := resolverFor(t, func(w http.ResponseWriter, r *http.Request) {
				depth, err := strconv.Atoi(strings.TrimPrefix(r.URL.Path, "/"))
				if err != nil {
					http.Error(w, "bad redirect path", http.StatusBadRequest)
					return
				}
				if depth < limit {
					http.Redirect(w, r, fmt.Sprintf("/%d", depth+1), http.StatusFound)
					return
				}
				_, _ = io.WriteString(w, "192.0.2.1\n")
			})
			cfg := listSourceConfig("http://feed.invalid/0", nil, []string{"feed"})
			_, err := resolver.Resolve(context.Background(), cfg, "", false)
			if limit == 10 && err != nil {
				t.Fatalf("ten redirects failed: %v", err)
			}
			if limit == 11 && err == nil {
				t.Fatal("eleven redirects unexpectedly succeeded")
			}
		})
	}
}

func csvSourceConfig() config.CSVConfig {
	return config.CSVConfig{Delimiter: ";", Header: true, IPColumn: 1, Filter: config.CSVFilterConfig{Column: 3, Op: ">=", Value: 1}}
}

func TestCSVParsingOptionChangesInvalidateFreshAndStaleEvidence(t *testing.T) {
	for name, mutate := range map[string]func(*config.CSVConfig){
		"column":           func(c *config.CSVConfig) { c.IPColumn = 2 },
		"delimiter":        func(c *config.CSVConfig) { c.Delimiter = "," },
		"header":           func(c *config.CSVConfig) { c.Header = false },
		"filter-column":    func(c *config.CSVConfig) { c.Filter.Column = 2 },
		"filter-presence":  func(c *config.CSVConfig) { c.Filter = config.CSVFilterConfig{} },
		"filter-operator":  func(c *config.CSVConfig) { c.Filter.Op = ">" },
		"filter-threshold": func(c *config.CSVConfig) { c.Filter.Value = 0.5 },
		"text":             func(c *config.CSVConfig) { *c = config.CSVConfig{} },
	} {
		for _, stale := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/stale=%t", name, stale), func(t *testing.T) {
				offline := false
				_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) {
					if offline {
						http.Error(w, "offline", http.StatusServiceUnavailable)
						return
					}
					_, _ = io.WriteString(w, "ip;unused;confidence\n192.0.2.1;2;2\n")
				})
				cfg := listSourceConfig("http://feed.invalid/list", nil, []string{"feed"})
				list := cfg.IPLists["feed"]
				list.CSV = csvSourceConfig()
				cfg.IPLists["feed"] = list
				initial, err := resolver.Resolve(context.Background(), cfg, "", false)
				if err != nil {
					t.Fatal(err)
				}
				offline = true
				mutate(&list.CSV)
				if stale {
					list.RefreshInterval = time.Nanosecond
				}
				cfg.IPLists["feed"] = list
				if err := initial.Snapshot.ValidateConfig(cfg); err == nil {
					t.Fatal("changed interpretation admitted committed source evidence")
				}
				result, err := resolver.Resolve(context.Background(), cfg, initial.Snapshot.ManifestID(), true)
				if err == nil || result.Snapshot.ManifestID() != "" {
					t.Fatal("changed interpretation reused fresh evidence or stale fallback")
				}
			})
		}
	}
}

func TestCSVTimingChangesAndEquivalentDefaultsRetainReuse(t *testing.T) {
	requests := 0
	_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) {
		requests++
		_, _ = io.WriteString(w, "192.0.2.1,1\n")
	})
	cfg := listSourceConfig("http://feed.invalid/list", nil, []string{"feed"})
	list := cfg.IPLists["feed"]
	list.CSV = config.CSVConfig{IPColumn: 1, Filter: config.CSVFilterConfig{Column: 2, Op: ">=", Value: 0}}
	cfg.IPLists["feed"] = list
	initial, err := resolver.Resolve(context.Background(), cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}
	list.RefreshInterval, list.RequestTimeout = 2*time.Hour, 2*time.Second
	list.CSV.Delimiter = ","
	cfg.IPLists["feed"] = list
	result, err := resolver.Resolve(context.Background(), cfg, initial.Snapshot.ManifestID(), true)
	if err != nil || result.RefreshError != nil || result.Snapshot.ManifestID() != initial.Snapshot.ManifestID() || requests != 1 {
		t.Fatalf("timing/default-only change lost reuse: %+v %v requests=%d", result, err, requests)
	}
}

func TestCSVMixedTransactionIsAtomicAndFallbackRequiresExactIdentity(t *testing.T) {
	broken := false
	_, resolver := resolverFor(t, func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/list":
			if broken {
				_, _ = io.WriteString(w, "ip;unused;confidence\n192.0.2.2;AS1;2\n192.0.2.3;AS2;not-a-number\n")
			} else {
				_, _ = io.WriteString(w, "ip;unused;confidence\n192.0.2.1;AS1;2\n")
			}
		case strings.HasSuffix(r.URL.Path, "/country-resource-list/data.json"):
			if broken {
				_, _ = io.WriteString(w, countryBody("203.0.113.0/24"))
			} else {
				_, _ = io.WriteString(w, countryBody("198.51.100.0/24"))
			}
		default:
			http.NotFound(w, r)
		}
	})
	cfg := listSourceConfig("http://feed.invalid/list", []string{"US"}, []string{"feed"})
	list := cfg.IPLists["feed"]
	list.CSV = csvSourceConfig()
	cfg.IPLists["feed"] = list
	initial, err := resolver.Resolve(context.Background(), cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}
	broken = true
	cfg.Geo.RefreshInterval = time.Nanosecond
	list.RefreshInterval = time.Nanosecond
	cfg.IPLists["feed"] = list
	if result, err := resolver.Resolve(context.Background(), cfg, "", false); err == nil || result.Snapshot.ManifestID() != "" {
		t.Fatal("malformed CSV published a partial mixed snapshot")
	}
	if result, err := resolver.Resolve(context.Background(), cfg, initial.Snapshot.ManifestID(), false); err == nil || result.Snapshot.ManifestID() != "" {
		t.Fatal("refresh without fallback published a partial mixed snapshot")
	}
	fallback, err := resolver.Resolve(context.Background(), cfg, initial.Snapshot.ManifestID(), true)
	if err != nil || fallback.RefreshError == nil || fallback.Snapshot.ManifestID() != initial.Snapshot.ManifestID() {
		t.Fatalf("failed mixed refresh did not retain exact complete reference: %+v %v", fallback, err)
	}
	list.CSV.Filter.Value = 0.5
	cfg.IPLists["feed"] = list
	if result, err := resolver.Resolve(context.Background(), cfg, initial.Snapshot.ManifestID(), true); err == nil || result.Snapshot.ManifestID() != "" {
		t.Fatal("changed CSV identity revived mixed committed fallback")
	}
}

func TestCSVValidatesDisabledAddressFamily(t *testing.T) {
	_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "192.0.2.1,1\n2001:db8::invalid,0\n")
	})
	cfg := listSourceConfig("http://feed.invalid/list", nil, []string{"feed"})
	cfg.Firewall.IPv6 = false
	list := cfg.IPLists["feed"]
	list.CSV = config.CSVConfig{IPColumn: 1, Filter: config.CSVFilterConfig{Column: 2, Op: ">=", Value: 1}}
	cfg.IPLists["feed"] = list
	if result, err := resolver.Resolve(context.Background(), cfg, "", false); err == nil || result.Snapshot.ManifestID() != "" {
		t.Fatal("invalid filtered-out disabled family published a snapshot")
	}
}

func TestCSVRedirectGzipAndIdenticalPrefixesKeepDistinctIdentity(t *testing.T) {
	requests := 0
	_, resolver := resolverFor(t, func(w http.ResponseWriter, r *http.Request) {
		requests++
		if r.Header.Get("Accept") != "text/csv, text/plain" {
			t.Errorf("CSV request did not advertise CSV: %v", r.Header)
		}
		if r.URL.Path == "/list" {
			http.Redirect(w, r, "/data", http.StatusFound)
			return
		}
		// Content type is deliberately unrelated: configuration alone chooses CSV.
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Encoding", "gzip")
		writer := gzip.NewWriter(w)
		_, _ = io.WriteString(writer, "ip;unused;confidence\n192.0.2.1;AS1;2\n")
		if err := writer.Close(); err != nil {
			t.Error(err)
		}
	})
	cfg := listSourceConfig("http://feed.invalid/list", nil, []string{"feed"})
	list := cfg.IPLists["feed"]
	list.CSV = csvSourceConfig()
	cfg.IPLists["feed"] = list
	initial, err := resolver.Resolve(context.Background(), cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}
	list.CSV.Filter.Value = 0.5
	cfg.IPLists["feed"] = list
	changed, err := resolver.Resolve(context.Background(), cfg, initial.Snapshot.ManifestID(), true)
	if err != nil {
		t.Fatal(err)
	}
	if requests != 4 || changed.RefreshError != nil || changed.Snapshot.ManifestID() == initial.Snapshot.ManifestID() {
		t.Fatalf("changed threshold did not fetch distinct evidence: requests=%d, result=%+v", requests, changed)
	}
	old, current := initial.Snapshot.Records()[0], changed.Snapshot.Records()[0]
	if len(old.IPv4) != 1 || len(current.IPv4) != 1 || old.IPv4[0] != current.IPv4[0] || old.Parameters["filter_value"] != "1" || current.Parameters["filter_value"] != "0.5" {
		t.Fatalf("identical prefix sets lost distinct filter identity: old=%+v current=%+v", old, current)
	}
	if err := changed.Snapshot.ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}
}
