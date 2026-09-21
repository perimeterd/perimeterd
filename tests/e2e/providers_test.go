//go:build linux && e2e

package e2e

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"os"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/app"
	"github.com/perimeterd/perimeterd/internal/state"
)

const (
	providerInitialID      = "fixture_alpha"
	providerCarveID        = "fixture_carve"
	providerMissingID      = "missing_provider"
	providerSupplement     = "/supplement"
	providerInitialBody    = "# initial provider snapshot\n8.20.0.0/24\n8.21.0.0/24\n2600:20::/64\n2600:21::/64\n"
	providerReplacement    = "# replacement provider snapshot\n8.22.0.0/24\n2600:22::/64\n"
	providerCarveBody      = "# subtract the original provider range\n8.20.0.0/24\n2600:20::/64\n"
	providerSupplementBody = "# mixed-source supplement\n8.22.0.0/24\n2600:22::/64\n"
)

const providerCDNPrefix = "https://cdn.jsdelivr.net/gh/rezmoss/cloud-provider-ip-addresses@main/"

type providerFixtureTransport struct {
	fixture *customListServer
	host    string
	mu      sync.Mutex
	seen    []string
}

func newProviderFixtureTransport(t *testing.T, fixture *customListServer) *providerFixtureTransport {
	t.Helper()
	u, err := url.Parse(fixture.server.URL)
	if err != nil {
		t.Fatalf("parse provider fixture URL: %v", err)
	}
	return &providerFixtureTransport{fixture: fixture, host: u.Host}
}

func (f *providerFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Host != f.host && request.URL.Host != "cdn.jsdelivr.net" {
		return nil, fmt.Errorf("unexpected source host %q", request.URL.Host)
	}
	if request.URL.Host == f.host {
		return http.DefaultTransport.RoundTrip(request)
	}

	if request.URL.Scheme != "https" || request.URL.RawQuery != "" || request.Method != http.MethodGet {
		return nil, fmt.Errorf("provider request is not a fixed GET URL: %s", request.URL)
	}
	if !strings.HasPrefix(request.URL.String(), providerCDNPrefix) {
		return nil, fmt.Errorf("provider request escaped fixed jsDelivr prefix: %s", request.URL)
	}
	relative := strings.TrimPrefix(request.URL.String(), providerCDNPrefix)
	parts := strings.Split(relative, "/")
	if len(parts) != 2 || parts[0] == "" || parts[1] != parts[0]+"_ips_merged.txt" {
		return nil, fmt.Errorf("provider request has unexpected path: %s", request.URL)
	}
	id := parts[0]
	f.mu.Lock()
	f.seen = append(f.seen, request.URL.String())
	f.mu.Unlock()

	target, err := url.Parse(f.fixture.URL("/provider/" + id))
	if err != nil {
		return nil, fmt.Errorf("parse provider fixture target: %w", err)
	}
	forwarded := request.Clone(request.Context())
	forwarded.URL = target
	forwarded.Host = target.Host
	return http.DefaultTransport.RoundTrip(forwarded)
}

func (f *providerFixtureTransport) URLs() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.seen...)
}

type providerRuntime struct {
	cancel  context.CancelFunc
	signals chan os.Signal
	done    <-chan error
	once    sync.Once
	stopErr error
}

func startProviderRuntime(t *testing.T, configPath string, client *http.Client) *providerRuntime {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 8)
	done := make(chan error, 1)
	ready := make(chan string, 4)
	go func() {
		done <- app.Run(ctx, app.Options{
			ConfigPath:   configPath,
			StateDir:     "/var/lib/perimeterd",
			LockPath:     "/run/perimeterd/owner.lock",
			SourceClient: client,
			Signals:      signals,
			Stderr:       os.Stderr,
			Notify: func(message string) error {
				ready <- message
				return nil
			},
			StartupTimeout: 30 * time.Second,
		})
	}()
	deadline := time.NewTimer(45 * time.Second)
	defer deadline.Stop()
	for {
		select {
		case message := <-ready:
			if strings.Contains(message, "READY=1") {
				runtime := &providerRuntime{cancel: cancel, signals: signals, done: done}
				t.Cleanup(func() { runtime.stop(t) })
				return runtime
			}
		case err := <-done:
			if err == nil {
				t.Fatalf("provider runtime exited before readiness")
			}
			t.Fatalf("provider runtime startup: %v", err)
		case <-deadline.C:
			t.Fatalf("provider runtime did not become ready")
		}
	}
}

func (r *providerRuntime) reload(t *testing.T) {
	t.Helper()
	select {
	case r.signals <- syscall.SIGHUP:
	case <-time.After(5 * time.Second):
		t.Fatal("provider runtime did not accept reload signal")
	}
}

func (r *providerRuntime) stop(t *testing.T) {
	t.Helper()
	r.once.Do(func() {
		r.cancel()
		r.stopErr = <-r.done
	})
	if r.stopErr != nil {
		t.Fatalf("provider runtime stop: %v", r.stopErr)
	}
}

func runProviderExpectFailure(t *testing.T, configPath string, client *http.Client) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	signals := make(chan os.Signal, 8)
	done := make(chan error, 1)
	go func() {
		done <- app.Run(ctx, app.Options{
			ConfigPath:     configPath,
			StateDir:       "/var/lib/perimeterd",
			LockPath:       "/run/perimeterd/owner.lock",
			SourceClient:   client,
			Signals:        signals,
			Stderr:         os.Stderr,
			Notify:         func(string) error { return nil },
			StartupTimeout: 10 * time.Second,
		})
	}()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("unknown provider unexpectedly activated")
		}
		return err
	case <-ctx.Done():
		t.Fatalf("unknown provider did not fail startup: %v", ctx.Err())
		return ctx.Err()
	}
}

func providerConfigPath(t *testing.T, fixture *customListServer) string {
	t.Helper()
	return fixture.URL(providerSupplement)
}

func writeProviderConfig(t *testing.T, path, backend, table, supplementURL, providerID string, policies bool) {
	t.Helper()
	var yaml strings.Builder
	yaml.WriteString("version: 1\n")
	yaml.WriteString("logging:\n  level: error\n  format: text\n")
	yaml.WriteString("metrics:\n  listen: \"\"\n")
	yaml.WriteString("global:\n  allowlist: []\n  blocklist: []\n")
	if backend == "nftables" {
		fmt.Fprintf(&yaml, "firewall:\n  backend: nftables\n  deny_action: reject\n  ipv4: true\n  ipv6: true\n  nftables:\n    table: %q\n    priority: -10\n", table)
	} else {
		yaml.WriteString(`firewall:
  backend: iptables
  deny_action: reject
  ipv4: true
  ipv6: true
  iptables:
    attachments:
      - chain: INPUT
        direction: ingress
      - chain: OUTPUT
        direction: egress
`)
	}
	yaml.WriteString("geo:\n  refresh_interval: 24h\n  request_timeout: 1s\n  refresh_jitter: 1s\n")
	yaml.WriteString("providers:\n  refresh_interval: 200ms\n  request_timeout: 2s\n")
	fmt.Fprintf(&yaml, `ip_lists:
  supplement:
    url: %q
    refresh_interval: 24h
    request_timeout: 2s
`, supplementURL)
	yaml.WriteString("groups: {}\n")
	if !policies {
		yaml.WriteString("policies: []\n")
	} else {
		fmt.Fprintf(&yaml, `policies:
  - name: provider-allow-ingress
    priority: 10
    direction: ingress
    mode: allowlist
    traffic: ["18480/tcp"]
    include:
      providers: [%q]
  - name: provider-mixed-block
    priority: 20
    direction: ingress
    mode: blocklist
    traffic: ["18482/tcp"]
    include:
      providers: [%q]
      ip_lists: [supplement]
    exclude:
      providers: [%q]
  - name: provider-allow-egress
    priority: 30
    direction: egress
    mode: allowlist
    traffic: ["18481/tcp"]
    include:
      providers: [%q]
  - name: provider-mixed-allow-egress
    priority: 40
    direction: egress
    mode: allowlist
    traffic: ["18483/tcp"]
    include:
      providers: [%q]
      ip_lists: [supplement]
    exclude:
      providers: [%q]
`, providerID, providerID, providerCarveID, providerID, providerID, providerCarveID)
	}
	yaml.WriteString("crowdsec:\n  enabled: false\n")
	if err := os.WriteFile(path, []byte(yaml.String()), 0o600); err != nil {
		t.Fatalf("write provider config: %v", err)
	}
}

func waitProviderOwnership(t *testing.T, backend, table string) {
	t.Helper()
	if backend == "nftables" {
		waitForNFTTable(t, table)
		return
	}
	waitForIPTablesOwned(t, "v4", "v6")
}

func waitNoProviderOwnership(t *testing.T, backend, table string) {
	t.Helper()
	if backend == "nftables" {
		waitNoNFTTable(t, table)
		return
	}
	waitNoIPTablesOwned(t, "v4", "v6")
}

func providerPacketInitial(t *testing.T, peer *peerNamespace) {
	t.Helper()
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18480", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18480", "success", "tcp")
	probeIngress(t, peer, "tcp4", "8.22.0.1:18480", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:22::1]:18480", "reject", "tcp")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18481", "success", "tcp")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18483", "reject", "tcp")
	probeEgress(t, peer, "tcp6", "["+fixtureIPv6Peer+"]:18483", "reject", "tcp")
	probeEgress(t, peer, "tcp4", "8.21.0.2:18483", "success", "tcp")
	probeEgress(t, peer, "tcp6", "[2600:21::2]:18483", "success", "tcp")
	probeEgress(t, peer, "tcp4", "8.22.0.2:18483", "success", "tcp")
	probeEgress(t, peer, "tcp6", "[2600:22::2]:18483", "success", "tcp")
	probeEgress(t, peer, "tcp6", "["+fixtureIPv6Peer+"]:18481", "success", "tcp")
	probeEgress(t, peer, "tcp4", "8.22.0.2:18481", "reject", "tcp")
	probeEgress(t, peer, "tcp6", "[2600:22::2]:18481", "reject", "tcp")
	// Alpha covers 8.20 and 8.21; carve removes 8.20, while supplement adds 8.22.
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18482", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18482", "success", "tcp")
	probeIngress(t, peer, "tcp4", "8.21.0.1:18482", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:21::1]:18482", "reject", "tcp")
	probeIngress(t, peer, "tcp4", "8.22.0.1:18482", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:22::1]:18482", "reject", "tcp")
}

func providerPacketReplacement(t *testing.T, peer *peerNamespace) {
	t.Helper()
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18480", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18480", "reject", "tcp")
	probeIngress(t, peer, "tcp4", "8.22.0.1:18480", "success", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:22::1]:18480", "success", "tcp")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18481", "reject", "tcp")
	probeEgress(t, peer, "tcp6", "["+fixtureIPv6Peer+"]:18481", "reject", "tcp")
	probeEgress(t, peer, "tcp4", "8.22.0.2:18481", "success", "tcp")
	probeEgress(t, peer, "tcp6", "[2600:22::2]:18481", "success", "tcp")
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18482", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18482", "success", "tcp")
	probeIngress(t, peer, "tcp4", "8.22.0.1:18482", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:22::1]:18482", "reject", "tcp")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18483", "reject", "tcp")
	probeEgress(t, peer, "tcp6", "["+fixtureIPv6Peer+"]:18483", "reject", "tcp")
	probeEgress(t, peer, "tcp4", "8.22.0.2:18483", "success", "tcp")
	probeEgress(t, peer, "tcp6", "[2600:22::2]:18483", "success", "tcp")
}

func activeProviderRevision(t *testing.T) *state.Revision {
	t.Helper()
	store, err := state.Open("/var/lib/perimeterd", nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if view.Active == nil {
		t.Fatal("provider runtime has no selected revision")
	}
	return view.Active
}

func assertProviderRefreshStops(t *testing.T, fixture *customListServer, path string) {
	t.Helper()
	last := fixture.Requests(path)
	quietSince := time.Now()
	deadline := time.Now().Add(5 * time.Second)
	for time.Since(quietSince) < 750*time.Millisecond {
		if time.Now().After(deadline) {
			t.Fatal("unreferenced provider continued refreshing")
		}
		time.Sleep(50 * time.Millisecond)
		if current := fixture.Requests(path); current != last {
			last = current
			quietSince = time.Now()
		}
	}
}

func TestE2EProviders(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, scenario := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(scenario, func(t *testing.T) { runIsolated(t, "TestE2EProviders", scenario) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	addCustomListAddresses(t, peer)

	scenario := os.Getenv(e2eScenario)
	backend := scenario
	if strings.HasPrefix(scenario, "iptables-") {
		installIPTablesTools(t, strings.TrimPrefix(scenario, "iptables-"))
		backend = "iptables"
	}
	table := fmt.Sprintf("pde2e_providers_%d", os.Getpid())
	configPath := tempConfig(t, "providers")
	fixture := newCustomListServer(t)
	fixture.Set(providerSupplement, http.StatusOK, providerSupplementBody)
	fixture.Set("/provider/"+providerInitialID, http.StatusOK, providerInitialBody)
	fixture.Set("/provider/"+providerCarveID, http.StatusOK, providerCarveBody)
	fixture.Set("/provider/"+providerMissingID, http.StatusNotFound, "missing provider\n")
	transport := newProviderFixtureTransport(t, fixture)
	client := &http.Client{Transport: transport}

	// A valid-looking unknown ID is fetched dynamically and fails before any
	// native target is applied.
	writeProviderConfig(t, configPath, backend, table, providerConfigPath(t, fixture), providerMissingID, true)
	if err := runProviderExpectFailure(t, configPath, client); err == nil {
		t.Fatal("unknown provider startup unexpectedly succeeded")
	}
	waitNoProviderOwnership(t, backend, table)
	waitCustomListRequests(t, fixture, "/provider/"+providerMissingID, 1)

	writeProviderConfig(t, configPath, backend, table, providerConfigPath(t, fixture), providerInitialID, true)
	runtime := startProviderRuntime(t, configPath, client)
	waitProviderOwnership(t, backend, table)
	waitCustomListRequests(t, fixture, "/provider/"+providerInitialID, 1)
	waitCustomListRequests(t, fixture, "/provider/"+providerCarveID, 1)
	waitCustomListRequests(t, fixture, providerSupplement, 1)
	providerPacketInitial(t, peer)

	// A missing ID on reload is rejected without replacing active enforcement.
	beforeEpoch := activeProviderRevision(t).Epoch
	writeProviderConfig(t, configPath, backend, table, providerConfigPath(t, fixture), providerMissingID, true)
	missingBefore := fixture.Requests("/provider/" + providerMissingID)
	runtime.reload(t)
	waitCustomListRequests(t, fixture, "/provider/"+providerMissingID, missingBefore+1)
	time.Sleep(750 * time.Millisecond)
	if activeProviderRevision(t).Epoch != beforeEpoch {
		t.Fatal("missing provider reload replaced the active configuration")
	}
	providerPacketInitial(t, peer)

	// A complete valid refresh replaces both families and all policy projections.
	replacementBefore := fixture.Requests("/provider/" + providerInitialID)
	fixture.Set("/provider/"+providerInitialID, http.StatusOK, providerReplacement)
	waitCustomListRequests(t, fixture, "/provider/"+providerInitialID, replacementBefore+1)
	time.Sleep(750 * time.Millisecond)
	providerPacketReplacement(t, peer)

	// 404 and malformed responses retain that complete replacement snapshot.
	for _, response := range []struct {
		status int
		body   string
	}{
		{status: http.StatusNotFound, body: "not found\n"},
		{status: http.StatusOK, body: "8.22.0.0/24\nnot-an-address\n"},
	} {
		before := fixture.Requests("/provider/" + providerInitialID)
		fixture.Set("/provider/"+providerInitialID, response.status, response.body)
		waitCustomListRequests(t, fixture, "/provider/"+providerInitialID, before+1)
		time.Sleep(500 * time.Millisecond)
		providerPacketReplacement(t, peer)
	}

	// Restore the file identity without reloading it; startup must fall back to
	// the exact committed provider URL and parser identity.
	writeProviderConfig(t, configPath, backend, table, providerConfigPath(t, fixture), providerInitialID, true)
	runtime.stop(t)
	fixture.Set("/provider/"+providerInitialID, http.StatusNotFound, "restart outage\n")
	runtime = startProviderRuntime(t, configPath, client)
	waitProviderOwnership(t, backend, table)
	providerPacketReplacement(t, peer)

	// Removing the last policy reference removes enforcement and stops refreshes.
	writeProviderConfig(t, configPath, backend, table, providerConfigPath(t, fixture), providerInitialID, false)
	runtime.reload(t)
	waitNoProviderOwnership(t, backend, table)
	assertProviderRefreshStops(t, fixture, "/provider/"+providerInitialID)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18480", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18480", "success", "tcp")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18481", "success", "tcp")
	probeEgress(t, peer, "tcp6", "["+fixtureIPv6Peer+"]:18481", "success", "tcp")
	runtime.stop(t)

	for _, requestURL := range transport.URLs() {
		if !strings.HasPrefix(requestURL, providerCDNPrefix) {
			t.Fatalf("provider fixture observed non-canonical URL %q", requestURL)
		}
	}
}
