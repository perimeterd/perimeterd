package app

import (
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
)

func TestRunIPListRefreshDoesNotFetchFreshPeers(t *testing.T) {
	var fast, slow, unused atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/fast":
			if fast.Add(1) == 1 {
				_, _ = io.WriteString(w, "1.1.1.1\n")
			} else {
				_, _ = io.WriteString(w, "2.2.2.2\n")
			}
		case "/slow":
			slow.Add(1)
			_, _ = io.WriteString(w, "8.8.8.8\n")
		default:
			unused.Add(1)
			http.Error(w, "unused source", http.StatusNotFound)
		}
	}))
	defer server.Close()
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	listen := runAddress(t)
	text := fmt.Sprintf(`version: 1
metrics:
  listen: %q
firewall:
  backend: nftables
geo:
  refresh_interval: 24h
ip_lists:
  fast:
    url: %s/fast
    refresh_interval: 500ms
  slow:
    url: %s/slow
    refresh_interval: 24h
  unused:
    url: %s/unused
    refresh_interval: 1ns
policies:
  - name: country
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["any"]
    include:
      ip_lists: [fast, slow]
  - name: disabled
    priority: 20
    direction: ingress
    mode: disabled
    traffic: ["any"]
    include:
      ip_lists: [unused]
`, listen, server.URL, server.URL, server.URL)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &sourceObservingBackend{policies: make(chan string, 32)}
	cancel, _, ready, done := startRun(t, path, filepath.Join(dir, "state"), backend, nil)
	defer awaitRunStop(t, cancel, done)
	awaitRunReady(t, ready)
	awaitSourcePolicy(t, backend.policies, "1.1.1.1/32")
	awaitSourcePolicy(t, backend.policies, "2.2.2.2/32")
	if slow.Load() != 1 || unused.Load() != 0 {
		t.Fatalf("refresh fetched fresh or disabled lists: slow=%d unused=%d", slow.Load(), unused.Load())
	}
	response := mustGet(t, "http://"+listen+"/metrics")
	defer func() { _ = response.Body.Close() }()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `perimeterd_prefix_snapshot_timestamp_seconds{source="ip_list"}`) || strings.Contains(string(body), `source="ripestat"`) {
		t.Fatalf("list-only runtime reported wrong source freshness: %s", body)
	}
}

func TestSourceRetryBarrierPreservesIndependentDeadlines(t *testing.T) {
	now := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	fast := policy.Selector{Kind: policy.IPList, Value: "fast"}
	slow := policy.Selector{Kind: policy.IPList, Value: "slow"}
	runtime := &sourceRuntime{deadlines: map[policy.Selector]sourceDeadline{
		fast: {retrieved: now.Add(-time.Minute), interval: time.Minute, due: now},
		slow: {retrieved: now.Add(-59 * time.Minute), interval: time.Hour, due: now.Add(time.Minute)},
	}}
	if got := runtime.nextRefresh(now); !got.Equal(now) {
		t.Fatalf("initial refresh deadline = %v, want %v", got, now)
	}
	runtime.attempted([]policy.Selector{fast}, now)
	if got := runtime.nextRefresh(now.Add(time.Second)); !got.Equal(now.Add(time.Minute)) {
		t.Fatalf("failed refresh busy-looped or delayed fresh peer: %v", got)
	}
	// Both are now stale. A complete failed attempt must honor the slower
	// source's retry interval, not fetch it again at every fast-list tick.
	runtime.attempted([]policy.Selector{fast, slow}, now.Add(time.Minute))
	if got := runtime.nextRefresh(now.Add(2 * time.Minute)); !got.Equal(now.Add(61 * time.Minute)) {
		t.Fatalf("failed slow source retried at fast-list interval: %v", got)
	}
	// Disabling the blocking source after commit must restore the remaining
	// overdue source immediately, not leave a timer tied to the removed list.
	delete(runtime.deadlines, slow)
	if got := runtime.nextRefresh(now.Add(2 * time.Minute)); got.After(now.Add(2 * time.Minute)) {
		t.Fatalf("removed list continued delaying refresh: %v", got)
	}
}

func TestSourceFailureDoesNotDelayPeerExpiringDuringFetch(t *testing.T) {
	start := time.Date(2026, 9, 20, 0, 0, 0, 0, time.UTC)
	fast := policy.Selector{Kind: policy.IPList, Value: "fast"}
	slow := policy.Selector{Kind: policy.IPList, Value: "slow"}
	runtime := &sourceRuntime{deadlines: map[policy.Selector]sourceDeadline{
		fast: {retrieved: start.Add(-time.Second), interval: time.Second, due: start},
		slow: {retrieved: start.Add(-24*time.Hour + time.Second), interval: 24 * time.Hour, due: start.Add(time.Second)},
	}}
	// The slow source was reused while fresh. It expires during a two-second
	// failed request for fast, so it must not inherit a 24-hour retry barrier.
	completed := start.Add(2 * time.Second)
	runtime.attempted([]policy.Selector{fast}, completed)
	if got := runtime.nextRefresh(completed); !got.Equal(completed.Add(time.Second)) {
		t.Fatalf("unattempted peer delayed complete refresh: %v", got)
	}
}

func TestCandidateOwnsIPListIdentity(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, "8.8.8.8\n")
	}))
	defer server.Close()
	cfg, err := config.Parse([]byte(fmt.Sprintf(`version: 1
firewall:
  backend: nftables
ip_lists:
  service:
    url: %s
policies:
  - name: service
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["any"]
    include:
      ip_lists: [service]
`, server.URL)))
	if err != nil {
		t.Fatal(err)
	}
	engine, store := newTestEngine(t, &recordingBackend{}, nil)
	defer engine.Close()
	resolution, err := source.NewResolver(store.Prefixes(), server.Client()).Resolve(t.Context(), cfg, "", false)
	if err != nil {
		t.Fatal(err)
	}
	epoch, err := engine.Admit()
	if err != nil {
		t.Fatal(err)
	}
	candidate, err := NewCandidate(epoch, "policy.yaml", cfg, resolution.Snapshot)
	if err != nil {
		t.Fatal(err)
	}
	// Mutating caller-owned definitions and references must not alter the
	// candidate subsequently admitted to the durable writer.
	list := cfg.IPLists["service"]
	list.URL = server.URL + "/different"
	cfg.IPLists["service"] = list
	cfg.Policies[0].Include.IPLists[0] = "missing"
	outcome, err := engine.Apply(t.Context(), candidate)
	if err != nil || !outcome.Committed {
		t.Fatalf("caller mutation changed candidate identity: committed=%v error=%v", outcome.Committed, err)
	}
	if _, err := store.Read(); err != nil {
		t.Fatalf("committed candidate cannot recover after caller mutation: %v", err)
	}
}
