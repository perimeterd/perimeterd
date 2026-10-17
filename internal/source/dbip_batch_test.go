package source

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/config/catalog"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestDBIPBatchReuseAdditionRemovalAndStaleFallback(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	var calls atomic.Int64
	fail := false
	body := dbipGzip(t, dbipTestCSV)
	resolver := NewResolver(cache, &http.Client{Transport: dbipRoundTrip(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		status := 200
		if fail {
			status = 403
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
	})})
	cfg := dbipTestConfig()
	first, err := resolver.Resolve(context.Background(), cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || len(first.Attempted) != 2 {
		t.Fatalf("calls=%d attempted=%v", calls.Load(), first.Attempted)
	}
	if err := first.Snapshot.ValidateConfig(cfg); err != nil {
		t.Fatal(err)
	}
	records := first.Snapshot.Records()
	if records[0].Release != records[1].Release || records[0].Parameters["sha256"] != records[1].Parameters["sha256"] || !records[0].RetrievedAt.Equal(records[1].RetrievedAt) {
		t.Fatal("incoherent batch")
	}
	reused, err := resolver.Resolve(context.Background(), cfg, first.Snapshot.ManifestID(), false)
	if err != nil || calls.Load() != 1 || reused.Snapshot.ManifestID() != first.Snapshot.ManifestID() {
		t.Fatalf("reuse err=%v calls=%d", err, calls.Load())
	}
	cfg.Policies[0].Include.Countries = []string{"SK"}
	removed, err := resolver.Resolve(context.Background(), cfg, first.Snapshot.ManifestID(), false)
	if err != nil || calls.Load() != 1 || len(removed.Snapshot.Records()) != 1 {
		t.Fatalf("removal err=%v calls=%d", err, calls.Load())
	}
	cfg.Policies[0].Include.Countries = []string{"SK", "CZ", "US"}
	body = dbipGzip(t, dbipTestCSV+"2001:db8::4,2001:db8::7,US\n")
	added, err := resolver.Resolve(context.Background(), cfg, removed.Snapshot.ManifestID(), false)
	if err != nil || calls.Load() != 2 || len(added.Attempted) != 3 {
		t.Fatalf("addition err=%v calls=%d attempted=%v", err, calls.Load(), added.Attempted)
	}
	for _, record := range added.Snapshot.Records() {
		if record.Parameters["sha256"] == records[0].Parameters["sha256"] {
			t.Fatal("addition retained old artifact")
		}
	}
	// Same month and identical country memberships still get a new provenance
	// object when complete decoded bytes change (here a harmless CSV quoting).
	prior := added.Snapshot
	cfg.Geo.RefreshInterval = time.Nanosecond
	body = dbipGzip(t, "\"192.0.2.0\",192.0.2.3,SK\n192.0.2.4,192.0.2.7,CZ\n2001:db8::,2001:db8::3,SK\n2001:db8::4,2001:db8::7,US\n")
	changed, err := resolver.Resolve(context.Background(), cfg, prior.ManifestID(), false)
	if err != nil {
		t.Fatal(err)
	}
	if changed.Snapshot.ManifestID() == prior.ManifestID() || changed.Snapshot.Records()[0].Parameters["sha256"] == prior.Records()[0].Parameters["sha256"] {
		t.Fatal("same-month changed bytes lost provenance")
	}
	if !slices.Equal(changed.Snapshot.Records()[0].IPv4, prior.Records()[0].IPv4) {
		t.Fatal("quoting changed membership")
	}
	fail = true
	fallback, err := resolver.Resolve(context.Background(), cfg, changed.Snapshot.ManifestID(), true)
	if err != nil || fallback.RefreshError == nil || fallback.Snapshot.ManifestID() != changed.Snapshot.ManifestID() || len(fallback.Attempted) != 3 {
		t.Fatalf("fallback err=%v refresh=%v", err, fallback.RefreshError)
	}
	cfg.Policies[0].Include.Countries = append(cfg.Policies[0].Include.Countries, "LI")
	if _, err := resolver.Resolve(context.Background(), cfg, changed.Snapshot.ManifestID(), true); err == nil {
		t.Fatal("missing country permitted stale fallback")
	}
	cfg.Policies[0].Include.Countries = []string{"SK", "CZ", "US"}
	cfg.Geo.CountryProvider = config.CountryProviderRIPEstat
	if _, err := resolver.Resolve(context.Background(), cfg, changed.Snapshot.ManifestID(), true); err == nil {
		t.Fatal("provider switch permitted stale fallback")
	}
}

func TestDBIPBatchRejectsClockRollbackAndKeepsCommittedSnapshot(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	body := dbipGzip(t, dbipTestCSV)
	resolver := NewResolver(cache, &http.Client{Transport: dbipRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
	})})
	cfg := dbipTestConfig()
	cfg.Geo.RefreshInterval = time.Nanosecond
	future := resolver.WithClock(func() time.Time { return time.Date(2027, 1, 15, 0, 0, 0, 0, time.UTC) })
	committed, err := future.Resolve(context.Background(), cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}
	rollback := resolver.WithClock(func() time.Time { return time.Date(2026, 12, 15, 0, 0, 0, 0, time.UTC) })
	if _, err := rollback.Resolve(context.Background(), cfg, committed.Snapshot.ManifestID(), false); err == nil {
		t.Fatal("release downgrade accepted")
	}
	stale, err := rollback.Resolve(context.Background(), cfg, committed.Snapshot.ManifestID(), true)
	if err != nil || stale.RefreshError == nil || stale.Snapshot.ManifestID() != committed.Snapshot.ManifestID() {
		t.Fatalf("rollback fallback err=%v", err)
	}
}

func TestDBIPExpandedCountriesShareOneDownload(t *testing.T) {
	members, _ := catalog.Countries("european-union")
	for _, include := range []config.Selector{{Groups: []string{"european-union"}, ExpandedCountries: members}, {RIRs: []string{"RIPE"}}} {
		cache, _ := openCacheTest(t, nil)
		calls := 0
		body := dbipGzip(t, dbipTestCSV)
		resolver := NewResolver(cache, &http.Client{Transport: dbipRoundTrip(func(*http.Request) (*http.Response, error) {
			calls++
			return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
		})})
		cfg := dbipTestConfig()
		cfg.Policies[0].Include = include
		required, err := policy.RequiredSelectors(cfg)
		if err != nil {
			t.Fatal(err)
		}
		result, err := resolver.Resolve(context.Background(), cfg, "", false)
		if err != nil {
			t.Fatal(err)
		}
		if calls != 1 || len(result.Attempted) != len(required) || len(result.Snapshot.Records()) != len(required) {
			t.Fatalf("calls=%d attempted=%d required=%d", calls, len(result.Attempted), len(required))
		}
	}
}

func TestDBIPASNOnlyAndDisabledCountriesDoNotDownload(t *testing.T) {
	for _, disabled := range []bool{false, true} {
		cache, _ := openCacheTest(t, nil)
		resolver := NewResolver(cache, &http.Client{Transport: dbipRoundTrip(func(req *http.Request) (*http.Response, error) {
			if req.URL.Host == "download.db-ip.com" {
				t.Error("unexpected DB-IP request")
			}
			return &http.Response{StatusCode: 403, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(nil))}, nil
		})})
		cfg := dbipTestConfig()
		if disabled {
			cfg.Policies[0].Mode = "disabled"
		} else {
			cfg.Policies[0].Include = config.Selector{ASNs: []string{"AS3333"}}
		}
		_, _ = resolver.Resolve(context.Background(), cfg, "", false)
	}
}

func TestDBIPMixedTransactionFailureAndEmptyPolicyKeepCommittedManifest(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	body := dbipGzip(t, dbipTestCSV)
	resolver := NewResolver(cache, &http.Client{Transport: dbipRoundTrip(func(req *http.Request) (*http.Response, error) {
		status := 200
		response := body
		switch req.URL.Host {
		case "stat.ripe.net":
			status = 403
		case "list.example":
			response = []byte("198.51.100.0/24\n")
		}
		return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(response))}, nil
	})})
	cfg := dbipTestConfig()
	committed, err := resolver.Resolve(context.Background(), cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}
	cfg.Geo.RefreshInterval = time.Nanosecond
	cfg.IPLists = map[string]config.IPListConfig{"feed": {URL: "https://list.example/feed", RefreshInterval: time.Hour, RequestTimeout: time.Second}}
	cfg.Policies[0].Include.ASNs = []string{"AS3333"}
	cfg.Policies[0].Include.IPLists = []string{"feed"}
	if result, err := resolver.Resolve(context.Background(), cfg, committed.Snapshot.ManifestID(), true); err == nil || result.Snapshot.ManifestID() != "" {
		t.Fatal("mixed-source failure published a partial snapshot")
	}
	loaded, err := cache.Load(committed.Snapshot.ManifestID())
	if err != nil || loaded.ManifestID() != committed.Snapshot.ManifestID() {
		t.Fatalf("committed manifest lost: %v", err)
	}
	cfg.Policies[0].Include = config.Selector{Countries: []string{"US"}}
	if _, err := resolver.Resolve(context.Background(), cfg, committed.Snapshot.ManifestID(), false); err == nil {
		t.Fatal("valid absent-country evidence bypassed empty-policy compiler guard")
	}
}

func TestDBIPResolverRejectsBlankCSVWithoutRetry(t *testing.T) {
	for _, test := range []struct {
		name, newline string
	}{
		{"LF", "\n"},
		{"CRLF", "\r\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cache, _ := openCacheTest(t, nil)
			body := dbipGzip(t, strings.ReplaceAll(dbipTestCSV, "\n", test.newline)+test.newline)
			var calls atomic.Int32
			resolver := NewResolver(cache, &http.Client{Transport: dbipRoundTrip(func(*http.Request) (*http.Response, error) {
				calls.Add(1)
				return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
			})})
			if _, err := resolver.Resolve(context.Background(), dbipTestConfig(), "", false); err == nil {
				t.Fatal("accepted a blank CSV record")
			}
			if got := calls.Load(); got != 1 {
				t.Fatalf("requests=%d, want 1 for deterministic CSV validation failure", got)
			}
		})
	}
}

func TestDBIPResolverRetriesTruncatedStream(t *testing.T) {
	cache, _ := openCacheTest(t, nil)
	incomplete := dbipGzip(t, "198.51.100.0,198.51.100.3,SK\n")
	incomplete = incomplete[:len(incomplete)-2]
	complete := dbipGzip(t, dbipTestCSV)
	var calls atomic.Int32
	resolver := NewResolver(cache, &http.Client{Transport: dbipRoundTrip(func(*http.Request) (*http.Response, error) {
		body := complete
		if calls.Add(1) == 1 {
			body = incomplete
		}
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body))}, nil
	})})
	result, err := resolver.Resolve(context.Background(), dbipTestConfig(), "", false)
	if err != nil {
		t.Fatal(err)
	}
	if got := calls.Load(); got != 2 {
		t.Fatalf("requests=%d, want 2 after an interrupted artifact stream", got)
	}
	got := make(map[policy.Selector][]netip.Prefix)
	for _, record := range result.Snapshot.Records() {
		got[record.Selector] = record.IPv4
	}
	want := map[policy.Selector][]netip.Prefix{
		{Kind: policy.Country, Value: "SK"}: {netip.MustParsePrefix("192.0.2.0/30")},
		{Kind: policy.Country, Value: "CZ"}: {netip.MustParsePrefix("192.0.2.4/30")},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("IPv4 records=%v, want successful complete artifact records %v", got, want)
	}
}
