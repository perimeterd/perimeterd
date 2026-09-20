//go:build linux && e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"testing"
	"time"
)

type customListResponse struct {
	status int
	body   string
	count  int
}

type customListServer struct {
	server *httptest.Server
	mu     sync.Mutex
	paths  map[string]*customListResponse
}

func newCustomListServer(t *testing.T) *customListServer {
	t.Helper()
	fixture := &customListServer{paths: make(map[string]*customListResponse)}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, request *http.Request) {
		fixture.mu.Lock()
		response, ok := fixture.paths[request.URL.Path]
		if !ok {
			response = &customListResponse{status: http.StatusNotFound}
			fixture.paths[request.URL.Path] = response
		}
		response.count++
		status, body := response.status, response.body
		fixture.mu.Unlock()
		w.WriteHeader(status)
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(fixture.server.Close)
	return fixture
}

func (s *customListServer) URL(path string) string {
	return s.server.URL + path
}

func (s *customListServer) Set(path string, status int, body string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	response, ok := s.paths[path]
	if !ok {
		response = new(customListResponse)
		s.paths[path] = response
	}
	response.status = status
	response.body = body
}

func (s *customListServer) Requests(path string) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	response, ok := s.paths[path]
	if !ok {
		return 0
	}
	return response.count
}

func waitCustomListRequests(t *testing.T, fixture *customListServer, path string, minimum int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if fixture.Requests(path) >= minimum {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("custom list %s did not receive request %d (received %d)", path, minimum, fixture.Requests(path))
}

func activeCustomListEndpoint(t *testing.T, listName string) string {
	t.Helper()
	activeBytes, err := os.ReadFile("/var/lib/perimeterd/active.json")
	if err != nil {
		t.Fatalf("read active record: %v", err)
	}
	var activeEnvelope struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(activeBytes, &activeEnvelope); err != nil {
		t.Fatalf("decode active record: %v", err)
	}
	var active struct {
		ID string `json:"id"`
	}
	if err := json.Unmarshal(activeEnvelope.Payload, &active); err != nil {
		t.Fatalf("decode active record payload: %v", err)
	}
	revisionBytes, err := os.ReadFile("/var/lib/perimeterd/revisions/" + active.ID + ".json")
	if err != nil {
		t.Fatalf("read active revision: %v", err)
	}
	var revisionEnvelope struct {
		Payload json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(revisionBytes, &revisionEnvelope); err != nil {
		t.Fatalf("decode active revision: %v", err)
	}
	var revision struct {
		Manifest string `json:"manifest"`
	}
	if err := json.Unmarshal(revisionEnvelope.Payload, &revision); err != nil {
		t.Fatalf("decode active revision payload: %v", err)
	}
	manifestBytes, err := os.ReadFile("/var/lib/perimeterd/prefixes/manifests/" + revision.Manifest + ".json")
	if err != nil {
		t.Fatalf("read active manifest: %v", err)
	}
	var manifest struct {
		Entries []struct {
			Selector struct {
				Kind  string `json:"kind"`
				Value string `json:"value"`
			} `json:"selector"`
			Endpoint string `json:"endpoint"`
		} `json:"selectors"`
	}
	if err := json.Unmarshal(manifestBytes, &manifest); err != nil {
		t.Fatalf("decode active manifest: %v", err)
	}
	for _, entry := range manifest.Entries {
		if entry.Selector.Kind == "ip_list" && entry.Selector.Value == listName {
			return entry.Endpoint
		}
	}
	t.Fatalf("active manifest has no %s custom list", listName)
	return ""
}

func writeCustomListConfig(t *testing.T, path, backend, table, mainURL, carveURL, refreshInterval string, policies bool) {
	t.Helper()
	var yaml strings.Builder
	yaml.WriteString("version: 1\n")
	yaml.WriteString("logging:\n  level: error\n  format: text\n")
	yaml.WriteString("metrics:\n  listen: \"\"\n")
	yaml.WriteString("global:\n  allowlist: []\n  blocklist: []\n")
	if backend == "nftables" {
		fmt.Fprintf(&yaml, "firewall:\n  backend: nftables\n  deny_action: drop\n  ipv4: true\n  ipv6: true\n  nftables:\n    table: %q\n    priority: -10\n", table)
	} else {
		yaml.WriteString(`firewall:
  backend: iptables
  deny_action: drop
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
	fmt.Fprintf(&yaml, `ip_lists:
  main:
    url: %q
    refresh_interval: %s
    request_timeout: 2s
  carve:
    url: %q
    refresh_interval: %s
    request_timeout: 2s
`, mainURL, refreshInterval, carveURL, refreshInterval)
	yaml.WriteString("groups: {}\n")
	if !policies {
		yaml.WriteString("policies: []\n")
	} else {
		yaml.WriteString(`policies:
  - name: list-exclude-ingress
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["18480/tcp"]
    include:
      ip_lists: [main]
    exclude:
      ip_lists: [carve]
  - name: list-only-ingress
    priority: 20
    direction: ingress
    mode: blocklist
    traffic: ["18482/tcp"]
    include:
      ip_lists: [main]
  - name: list-allow-egress
    priority: 30
    direction: egress
    mode: allowlist
    traffic: ["18481/tcp"]
    include:
      ip_lists: [main]
`)
	}
	yaml.WriteString("crowdsec:\n  enabled: false\n")
	if err := os.WriteFile(path, []byte(yaml.String()), 0o600); err != nil {
		t.Fatalf("write custom list config: %v", err)
	}
}

func addCustomListAddresses(t *testing.T, peer *peerNamespace) {
	t.Helper()
	for _, address := range []struct {
		host string
		peer string
	}{
		{host: "8.21.0.1/24", peer: "8.21.0.2/24"},
		{host: "8.22.0.1/24", peer: "8.22.0.2/24"},
	} {
		command(t, 10*time.Second, "ip", "addr", "add", address.host, "dev", "e2h0")
		peer.run(t, "ip", "addr", "add", address.peer, "dev", "e2p0")
	}
	for _, address := range []struct {
		host string
		peer string
	}{
		{host: "2600:21::1/64", peer: "2600:21::2/64"},
		{host: "2600:22::1/64", peer: "2600:22::2/64"},
	} {
		command(t, 10*time.Second, "ip", "-6", "addr", "add", address.host, "dev", "e2h0", "nodad")
		peer.run(t, "ip", "-6", "addr", "add", address.peer, "dev", "e2p0", "nodad")
	}
}

func exerciseInitialCustomList(t *testing.T, peer *peerNamespace) {
	t.Helper()
	// The carve list removes the peer's base address from the blocklist, while
	// another listed address remains denied. The same source is also an
	// egress allowlist, covering both families and both selector positions.
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18480", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18480", "success", "tcp")
	probeIngress(t, peer, "tcp4", "8.21.0.1:18480", "drop", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:21::1]:18480", "drop", "tcp")
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18482", "drop", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18482", "drop", "tcp")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18481", "success", "tcp")
	probeEgress(t, peer, "tcp6", "["+fixtureIPv6Peer+"]:18481", "success", "tcp")
	probeEgress(t, peer, "tcp4", "8.21.0.2:18481", "success", "tcp")
	probeEgress(t, peer, "tcp6", "[2600:21::2]:18481", "success", "tcp")
}

func assertReplacementBlockRetained(t *testing.T, peer *peerNamespace) {
	t.Helper()
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18482", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18482", "success", "tcp")
	probeIngress(t, peer, "tcp4", "8.22.0.1:18482", "drop", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:22::1]:18482", "drop", "tcp")
}

func exerciseReplacementCustomList(t *testing.T, peer *peerNamespace) {
	t.Helper()
	// A complete replacement removes the old prefixes and installs the new
	// dual-stack set. New flows therefore follow the new snapshot immediately.
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18480", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18480", "success", "tcp")
	probeIngress(t, peer, "tcp4", "8.21.0.1:18480", "success", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:21::1]:18480", "success", "tcp")
	probeIngress(t, peer, "tcp4", "8.22.0.1:18480", "drop", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:22::1]:18480", "drop", "tcp")
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18482", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18482", "success", "tcp")
	probeIngress(t, peer, "tcp4", "8.22.0.1:18482", "drop", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:22::1]:18482", "drop", "tcp")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18481", "drop", "tcp")
	probeEgress(t, peer, "tcp6", "["+fixtureIPv6Peer+"]:18481", "drop", "tcp")
	probeEgress(t, peer, "tcp4", "8.22.0.2:18481", "success", "tcp")
	probeEgress(t, peer, "tcp6", "[2600:22::2]:18481", "success", "tcp")
}

func TestE2ECustomIPLists(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, scenario := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(scenario, func(t *testing.T) { runIsolated(t, "TestE2ECustomIPLists", scenario) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	addCustomListAddresses(t, peer)

	mainBody := "# initial dual-stack source\r\n 8.20.0.42/24\r\n8.21.0.0/24\r\n2600:20::42/64\r\n2600:21::/64\r\n"
	carveBody := "# one excluded address per family\n8.20.0.2\n2600:20::2/128\n"
	replacementBody := "# replacement dual-stack source\n8.22.0.42/24\n2600:22::42/64\n"
	fixture := newCustomListServer(t)
	fixture.Set("/main", http.StatusOK, mainBody)
	fixture.Set("/carve", http.StatusOK, carveBody)
	changed := newCustomListServer(t)
	changed.Set("/main", http.StatusServiceUnavailable, "temporarily unavailable\n")

	scenario := os.Getenv(e2eScenario)
	backend := scenario
	if strings.HasPrefix(scenario, "iptables-") {
		installIPTablesTools(t, strings.TrimPrefix(scenario, "iptables-"))
		backend = "iptables"
	}
	table := fmt.Sprintf("pde2e_lists_%d", os.Getpid())
	configPath := tempConfig(t, "custom-lists")
	writeCustomListConfig(t, configPath, backend, table, fixture.URL("/main"), fixture.URL("/carve"), "200ms", true)
	var daemon *daemonProcess
	if backend == "nftables" {
		daemon = startDaemon(t, configPath, table)
	} else {
		daemon = startIPTablesDaemon(t, configPath, "v4", "v6")
	}
	waitCustomListRequests(t, fixture, "/main", 1)
	waitCustomListRequests(t, fixture, "/carve", 1)
	exerciseInitialCustomList(t, peer)

	// A valid refresh is a complete source replacement, not an incremental
	// merge. The short interval keeps this deterministic without a live feed.
	mainRequests := fixture.Requests("/main")
	fixture.Set("/main", http.StatusOK, replacementBody)
	waitCustomListRequests(t, fixture, "/main", mainRequests+1)
	time.Sleep(2 * time.Second)
	exerciseReplacementCustomList(t, peer)

	// Malformed, empty, and unavailable responses must not replace the last
	// committed snapshot or interrupt its packet enforcement.
	for _, response := range []struct {
		status int
		body   string
	}{
		{status: http.StatusOK, body: "8.22.0.0/24\nnot-an-address\n"},
		{status: http.StatusOK, body: "# comment only\r\n\t\r\n"},
		{status: http.StatusBadGateway, body: "upstream outage\n"},
	} {
		before := fixture.Requests("/main")
		fixture.Set("/main", response.status, response.body)
		waitCustomListRequests(t, fixture, "/main", before+1)
		time.Sleep(750 * time.Millisecond)
		assertReplacementBlockRetained(t, peer)
	}

	// Stop the old schedule before testing URL identity. A failed reload for a
	// changed URL cannot borrow the old same-name object.
	fixture.Set("/main", http.StatusOK, replacementBody)
	writeCustomListConfig(t, configPath, backend, table, fixture.URL("/main"), fixture.URL("/carve"), "24h", true)
	daemon.reload(t)
	time.Sleep(750 * time.Millisecond)
	oldRequests := fixture.Requests("/main")
	writeCustomListConfig(t, configPath, backend, table, changed.URL("/main"), fixture.URL("/carve"), "24h", true)
	daemon.reload(t)
	waitCustomListRequests(t, changed, "/main", 1)
	time.Sleep(750 * time.Millisecond)
	if got := fixture.Requests("/main"); got != oldRequests {
		t.Fatalf("changed-URL reload unexpectedly fetched old URL: before=%d after=%d", oldRequests, got)
	}
	if endpoint := activeCustomListEndpoint(t, "main"); endpoint != fixture.URL("/main") {
		t.Fatalf("changed-URL reload replaced the active source identity: %q", endpoint)
	}
	assertReplacementBlockRetained(t, peer)

	// Restore the original identity, then make it due and unavailable. Startup
	// must use the complete committed fallback, retaining both families.
	writeCustomListConfig(t, configPath, backend, table, fixture.URL("/main"), fixture.URL("/carve"), "24h", true)
	daemon.reload(t)
	time.Sleep(750 * time.Millisecond)
	fixture.Set("/main", http.StatusServiceUnavailable, "restart outage\n")
	writeCustomListConfig(t, configPath, backend, table, fixture.URL("/main"), fixture.URL("/carve"), "200ms", true)
	daemon.reload(t)
	waitCustomListRequests(t, fixture, "/main", fixture.Requests("/main")+1)
	time.Sleep(750 * time.Millisecond)
	assertReplacementBlockRetained(t, peer)
	daemon.stop(t)
	if backend == "nftables" {
		daemon = startDaemon(t, configPath, table)
	} else {
		daemon = startIPTablesDaemon(t, configPath, "v4", "v6")
	}
	assertReplacementBlockRetained(t, peer)

	// Removing the final policy reference removes enforcement and stops future
	// list refreshes, while leaving the definitions and cache evidence intact.
	fixture.Set("/main", http.StatusOK, replacementBody)
	writeCustomListConfig(t, configPath, backend, table, fixture.URL("/main"), fixture.URL("/carve"), "200ms", false)
	daemon.reload(t)
	if backend == "nftables" {
		waitNoNFTTable(t, table)
	} else {
		waitNoIPTablesOwned(t, "v4", "v6")
	}
	beforeRemovalRequests := fixture.Requests("/main")
	time.Sleep(750 * time.Millisecond)
	if got := fixture.Requests("/main"); got != beforeRemovalRequests {
		t.Fatalf("unreferenced list continued refreshing: before=%d after=%d", beforeRemovalRequests, got)
	}
}
