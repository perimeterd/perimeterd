package adapter_test

import (
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
