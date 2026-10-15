package adapter_test

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestTransientHTTPFailureRecoversCompleteSnapshot(t *testing.T) {
	for _, status := range []int{408, 500, 502, 503, 504} {
		t.Run(http.StatusText(status), func(t *testing.T) {
			var requests atomic.Int32
			_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) {
				if requests.Add(1) == 1 {
					http.Error(w, "temporary failure", status)
					return
				}
				_, _ = io.WriteString(w, countryBody("8.8.8.42/24"))
			})
			result, err := resolver.Resolve(t.Context(), sourceConfig([]string{"BE"}, nil), "", false)
			if err != nil {
				t.Fatal(err)
			}
			set, ok := result.Snapshot.Policy().Lookup(policy.Selector{Kind: policy.Country, Value: "BE"})
			if requests.Load() != 2 || !ok || !set.Contains(netip.MustParseAddr("8.8.8.1")) || set.Contains(netip.MustParseAddr("9.9.9.1")) {
				t.Fatalf("transient HTTP failure lost complete policy: requests=%d set=%v", requests.Load(), set)
			}
		})
	}
}

func TestRequestTimeoutAndInterruptedReadRecover(t *testing.T) {
	for _, failure := range []string{"timeout", "truncated-body", "closed-connection"} {
		t.Run(failure, func(t *testing.T) {
			var requests atomic.Int32
			_, resolver := resolverFor(t, func(w http.ResponseWriter, r *http.Request) {
				if requests.Add(1) == 1 {
					switch failure {
					case "timeout":
						<-r.Context().Done()
					case "truncated-body":
						w.Header().Set("Content-Length", "4096")
						_, _ = io.WriteString(w, countryBody("1.1.1.0/24"))
					case "closed-connection":
						connection, _, err := w.(http.Hijacker).Hijack()
						if err != nil {
							t.Error(err)
							return
						}
						_ = connection.Close()
					}
					return
				}
				_, _ = io.WriteString(w, countryBody("8.8.8.0/24"))
			})
			cfg := sourceConfig([]string{"BE"}, nil)
			cfg.Geo.RequestTimeout = 100 * time.Millisecond
			result, err := resolver.Resolve(t.Context(), cfg, "", false)
			if err != nil {
				t.Fatal(err)
			}
			set, ok := result.Snapshot.Policy().Lookup(policy.Selector{Kind: policy.Country, Value: "BE"})
			if requests.Load() != 2 || !ok || !set.Contains(netip.MustParseAddr("8.8.8.1")) || set.Contains(netip.MustParseAddr("1.1.1.1")) {
				t.Fatalf("retry admitted incomplete or stale prefixes: requests=%d set=%v", requests.Load(), set)
			}
		})
	}
}

func TestPersistentTransientFailureHasFiniteAttempts(t *testing.T) {
	var requests atomic.Int32
	_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) {
		requests.Add(1)
		http.Error(w, "still unavailable", http.StatusServiceUnavailable)
	})
	result, err := resolver.Resolve(t.Context(), sourceConfig([]string{"BE"}, nil), "", false)
	if err == nil || requests.Load() != 3 || result.Snapshot.ManifestID() != "" {
		t.Fatalf("failed selector escaped retry bound or published a snapshot: requests=%d manifest=%q err=%v", requests.Load(), result.Snapshot.ManifestID(), err)
	}
}

func TestPermanentSourceFailuresAreNotRetried(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int
		body   string
	}{
		{name: "bad-request", status: 400},
		{name: "unauthorized", status: 401},
		{name: "forbidden", status: 403},
		{name: "not-found", status: 404},
		{name: "rate-limited", status: 429},
		{name: "not-implemented", status: 501},
		{name: "invalid-json", status: 200, body: `{"data":`},
		{name: "invalid-data", status: 200, body: countryBody("not-a-prefix")},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var requests atomic.Int32
			_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) {
				requests.Add(1)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			result, err := resolver.Resolve(t.Context(), sourceConfig([]string{"BE"}, nil), "", false)
			if err == nil || requests.Load() != 1 || result.Snapshot.ManifestID() != "" {
				t.Fatalf("permanent failure retried or published: requests=%d manifest=%q err=%v", requests.Load(), result.Snapshot.ManifestID(), err)
			}
		})
	}
}

func TestRetryStopsOnCallerCancellationOrDeadline(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline"} {
		t.Run(mode, func(t *testing.T) {
			var requests atomic.Int32
			first := make(chan struct{})
			_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) {
				if requests.Add(1) == 1 {
					defer close(first)
				}
				http.Error(w, "temporary failure", http.StatusServiceUnavailable)
			})
			ctx, cancel := context.WithCancel(t.Context())
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(t.Context(), 500*time.Millisecond)
			}
			defer cancel()
			finished := make(chan error, 1)
			go func() {
				_, err := resolver.Resolve(ctx, sourceConfig([]string{"BE"}, nil), "", false)
				finished <- err
			}()
			<-first
			if mode == "cancel" {
				cancel()
			}
			select {
			case err := <-finished:
				want := context.Canceled
				if mode == "deadline" {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) || requests.Load() != 1 {
					t.Fatalf("caller cancellation did not stop retry: requests=%d err=%v", requests.Load(), err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("caller cancellation did not interrupt retry wait")
			}
		})
	}
}

func TestTextSourcesRetryTransientHTTPFailure(t *testing.T) {
	for _, kind := range []policy.SelectorKind{policy.IPList, policy.Provider} {
		t.Run(string(kind), func(t *testing.T) {
			var requests atomic.Int32
			_, resolver := resolverFor(t, func(w http.ResponseWriter, _ *http.Request) {
				if requests.Add(1) == 1 {
					http.Error(w, "temporarily unavailable", http.StatusBadGateway)
					return
				}
				_, _ = io.WriteString(w, "8.8.8.42/24\n2001:4860:4860::8888\n")
			})
			cfg := listSourceConfig("https://feed.example.test/list", nil, []string{"feed"})
			selector := policy.Selector{Kind: policy.IPList, Value: "feed"}
			if kind == policy.Provider {
				cfg = providerSourceConfig("future-vendor")
				selector = policy.Selector{Kind: policy.Provider, Value: "future-vendor"}
			}
			result, err := resolver.Resolve(t.Context(), cfg, "", false)
			if err != nil {
				t.Fatal(err)
			}
			set, ok := result.Snapshot.Policy().Lookup(selector)
			if requests.Load() != 2 || !ok || !set.Contains(netip.MustParseAddr("8.8.8.1")) || !set.Contains(netip.MustParseAddr("2001:4860:4860::8888")) {
				t.Fatalf("text source did not recover complete policy: requests=%d selector=%v set=%v", requests.Load(), selector, set)
			}
		})
	}
}
