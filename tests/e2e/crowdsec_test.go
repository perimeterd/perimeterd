//go:build linux && e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/state"
)

const crowdFixtureKey = "perimeterd-isolated-crowdsec-key"

type crowdFixtureDecision struct {
	id      int64
	value   string
	expires time.Time
}

type crowdFixture struct {
	mu           sync.Mutex
	decisions    map[int64]crowdFixtureDecision
	pending      map[int64]struct{}
	deleted      []int64
	mode         string
	startups     int
	unauthorized int
	badRequest   bool
}

func newCrowdFixture(t *testing.T) (*crowdFixture, *httptest.Server) {
	t.Helper()
	fixture := &crowdFixture{
		decisions: make(map[int64]crowdFixtureDecision),
		pending:   make(map[int64]struct{}),
	}
	server := httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(server.Close)
	return fixture, server
}

func (f *crowdFixture) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if r.Header.Get("X-Api-Key") != crowdFixtureKey {
		f.unauthorized++
		http.Error(w, "unauthorized", http.StatusUnauthorized)
		return
	}
	query := r.URL.Query()
	startupValues := query["startup"]
	if r.URL.Path != "/v1/decisions/stream" ||
		query.Get("dedup") != "false" || len(query["dedup"]) != 1 ||
		query.Get("scopes") != "ip,range" || len(query["scopes"]) != 1 ||
		len(startupValues) != 1 ||
		(startupValues[0] != "true" && startupValues[0] != "false") {
		f.badRequest = true
		http.Error(w, "unsupported stream request", http.StatusBadRequest)
		return
	}
	startup := startupValues[0] == "true"
	if startup {
		f.startups++
	}
	w.Header().Set("Content-Type", "application/json")
	if f.mode == "malformed" {
		_, _ = w.Write([]byte(`{"new":[],"deleted":[],"new":[]}`))
		return
	}

	now := time.Now()
	capacity := len(f.decisions)
	if !startup {
		capacity = len(f.pending)
	}
	newDecisions := make([]map[string]any, 0, capacity)
	appendDecision := func(decision crowdFixtureDecision) {
		if !decision.expires.After(now) {
			delete(f.decisions, decision.id)
			delete(f.pending, decision.id)
			return
		}
		scope := "ip"
		if strings.Contains(decision.value, "/") {
			scope = "range"
		}
		newDecisions = append(newDecisions, map[string]any{
			"id": decision.id, "type": "ban", "scope": scope, "value": decision.value,
			"until":  decision.expires.UTC().Format(time.RFC3339Nano),
			"origin": "cscli", "scenario": "perimeterd-e2e",
		})
	}
	if startup {
		for _, decision := range f.decisions {
			appendDecision(decision)
		}
	} else {
		for id := range f.pending {
			if decision, ok := f.decisions[id]; ok {
				appendDecision(decision)
			}
		}
	}

	deleted := make([]map[string]any, 0, len(f.deleted))
	if !startup {
		for _, id := range f.deleted {
			deleted = append(deleted, map[string]any{"id": id})
		}
	}
	clear(f.pending)
	f.deleted = nil
	_ = json.NewEncoder(w).Encode(map[string]any{"new": newDecisions, "deleted": deleted})
}

func (f *crowdFixture) set(id int64, value string, lifetime time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.decisions[id] = crowdFixtureDecision{id: id, value: value, expires: time.Now().Add(lifetime)}
	if f.pending == nil {
		f.pending = make(map[int64]struct{})
	}
	f.pending[id] = struct{}{}
}

func (f *crowdFixture) remove(id int64) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if _, ok := f.decisions[id]; !ok {
		return
	}
	delete(f.decisions, id)
	delete(f.pending, id)
	for _, deletedID := range f.deleted {
		if deletedID == id {
			return
		}
	}
	f.deleted = append(f.deleted, id)
}

func (f *crowdFixture) changeMode(mode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode = mode
}

func (f *crowdFixture) counters() (int, int, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.startups, f.unauthorized, f.badRequest
}

func writeCrowdConfig(t *testing.T, path, backend, table, endpoint, key string, enabled bool, allow []string) {
	t.Helper()
	allowJSON, err := json.Marshal(allow)
	if err != nil {
		t.Fatal(err)
	}
	if allow == nil {
		allowJSON = []byte("[]")
	}
	body := fmt.Sprintf(`version: 1
logging:
  level: debug
metrics:
  listen: ""
firewall:
  backend: %s
  deny_action: reject
  ipv4: true
  ipv6: true
  nftables:
    table: %s
    priority: -10
global:
  allowlist: %s
crowdsec:
  enabled: %t
  lapi_url: %q
  api_key_file: %q
  update_frequency: 250ms
`, backend, table, allowJSON, enabled, endpoint, key)
	// #nosec G703 -- path is created by this test beneath its private fixture directory.
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func waitCrowdCondition(t *testing.T, description string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("CrowdSec condition did not converge: %s", description)
}

func waitCrowdPacket(t *testing.T, peer *peerNamespace, network, address, expectation string) {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go echoTCP(listener)
	var last []byte
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		cmd := peer.helper(t, "dial-tcp", network, address, expectation)
		last, err = cmd.CombinedOutput()
		if err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("CrowdSec packet path %s %s did not become %s: %v\n%s", network, address, expectation, err, last)
}

func crowdActive(t *testing.T) *state.Revision {
	t.Helper()
	store, err := state.Open("/var/lib/perimeterd", nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	return view.Active
}

func TestE2ECrowdSec(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, backend := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(backend, func(t *testing.T) { runIsolated(t, "TestE2ECrowdSec", backend) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	backend := os.Getenv(e2eScenario)
	if strings.HasPrefix(backend, "iptables-") {
		installIPTablesTools(t, strings.TrimPrefix(backend, "iptables-"))
		backend = "iptables"
	}
	foreign := fmt.Sprintf("crowd_foreign_%d", os.Getpid())
	createForeignTable(t, foreign)
	fixture, server := newCrowdFixture(t)
	fixture.set(1, fixtureIPv4Peer, 5*time.Minute)
	fixture.set(2, fixtureIPv6Peer, 5*time.Minute)
	fixture.set(3, fixtureLANPeer, 5*time.Minute)
	configPath := tempConfig(t, "crowdsec")
	keyPath := filepath.Join(t.TempDir(), "crowdsec.key")
	if err := os.WriteFile(keyPath, []byte(crowdFixtureKey), 0o600); err != nil {
		t.Fatal(err)
	}
	table := fmt.Sprintf("crowd_owned_%d", os.Getpid())
	writeCrowdConfig(t, configPath, backend, table, server.URL, keyPath, true, nil)
	daemon := startDaemonProcess(t, configPath, "CrowdSec initial projection", func() bool { return activeRevision() != "" })
	// Readiness cannot precede existing decisions becoming effective.
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18680", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18680", "reject", "tcp")
	probeIngress(t, peer, "tcp4", fixtureLANHost+":18680", "success", "tcp")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18681", "success", "tcp")
	initial := crowdActive(t)
	fixture.remove(1)
	waitCrowdPacket(t, peer, "tcp4", fixtureIPv4Host+":18682", "success")
	if current := crowdActive(t); current.ID != initial.ID || current.Target.Generation != initial.Target.Generation {
		t.Fatal("incremental CrowdSec update rebuilt the static generation")
	}

	// The longer covering ID must not survive deletion, even when reconnect
	// returns malformed HTTP200 and no subsequent deletion/expiry event arrives.
	fixture.set(4, "8.20.0.0/24", 12*time.Second)
	fixture.set(5, fixtureIPv4Peer, 5*time.Minute)
	waitCrowdPacket(t, peer, "tcp4", fixtureIPv4Host+":18683", "reject")
	fixture.remove(5)
	// An acknowledged second poll gives the delete batch a chance to finish;
	// local expiry below proves that ID5 did not retain hidden coverage.
	waitCrowdCondition(t, "longer decision deletion delivered", func() bool {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		return len(fixture.deleted) == 0
	})
	fixture.changeMode("malformed")
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18684", "reject", "tcp")
	waitCrowdPacket(t, peer, "tcp4", fixtureIPv4Host+":18685", "success")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18685", "reject", "tcp")
	fixture.remove(2)
	fixture.remove(3)
	fixture.remove(4)
	fixture.changeMode("")
	waitCrowdPacket(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18686", "success")
	waitCrowdCondition(t, "authoritative reconnect", func() bool { count, _, _ := fixture.counters(); return count >= 2 })

	// Both /0 families must lower correctly; built-in local allow and egress
	// remain unaffected. Explicit global allow wins over every CrowdSec ban.
	fixture.set(6, "0.0.0.0/0", 5*time.Minute)
	fixture.set(7, "::/0", 5*time.Minute)
	waitCrowdPacket(t, peer, "tcp4", fixtureIPv4Host+":18687", "reject")
	waitCrowdPacket(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18687", "reject")
	before := activeRevision()
	writeCrowdConfig(t, configPath, backend, table, server.URL, keyPath, true, []string{fixtureIPv4Peer})
	daemon.reload(t)
	waitForIPTablesCommit(t, before)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18688", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18688", "reject", "tcp")

	// Re-reading the same credential path must stage authentication without
	// discarding the old client's retained credential or stream authority.
	before = activeRevision()
	starts, _, _ := fixture.counters()
	if err := os.WriteFile(keyPath, []byte("invalid-replacement-secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	daemon.reload(t)
	waitCrowdCondition(t, "replacement authentication rejected", func() bool { _, failures, _ := fixture.counters(); return failures > 0 })
	waitCrowdCondition(t, "old credential resumed authoritative synchronization", func() bool { count, _, _ := fixture.counters(); return count > starts })
	if activeRevision() != before {
		t.Fatal("failed credential replacement committed configuration")
	}
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18689", "reject", "tcp")
	if strings.Contains(daemon.output.String(), crowdFixtureKey) || strings.Contains(daemon.output.String(), "invalid-replacement-secret") {
		t.Fatal("CrowdSec credential leaked into debug logs")
	}
	if err := os.WriteFile(keyPath, []byte(crowdFixtureKey), 0o600); err != nil {
		t.Fatal(err)
	}

	replacement, replacementServer := newCrowdFixture(t)
	before = activeRevision()
	writeCrowdConfig(t, configPath, backend, table, replacementServer.URL, keyPath, true, nil)
	daemon.reload(t)
	waitForIPTablesCommit(t, before)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18690", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18690", "success", "tcp")
	replacement.set(8, fixtureIPv4Peer, 5*time.Minute)
	waitCrowdPacket(t, peer, "tcp4", fixtureIPv4Host+":18691", "reject")
	before = activeRevision()
	writeCrowdConfig(t, configPath, backend, table, replacementServer.URL, keyPath, false, nil)
	daemon.reload(t)
	waitForIPTablesCommit(t, before)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18692", "success", "tcp")
	if current := crowdActive(t); current.Target != nil {
		t.Fatal("CrowdSec-only disable did not converge to empty enforcement")
	}

	// No running owner is necessary for native expiration. Restart must fetch
	// a new full snapshot, not recover decisions from durable target metadata.
	replacement.set(8, fixtureIPv4Peer, 7*time.Second)
	replacement.set(9, fixtureIPv6Peer, 5*time.Minute)
	before = activeRevision()
	writeCrowdConfig(t, configPath, backend, table, replacementServer.URL, keyPath, true, nil)
	daemon.reload(t)
	waitForIPTablesCommit(t, before)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18693", "reject", "tcp")
	daemon.stop(t)
	waitCrowdPacket(t, peer, "tcp4", fixtureIPv4Host+":18694", "success")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18694", "reject", "tcp")
	replacement.remove(9)
	replacement.set(8, fixtureIPv4Peer, 5*time.Minute)
	daemon = startDaemonProcess(t, configPath, "CrowdSec restart authority", func() bool { return activeRevision() != "" })
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18695", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18695", "success", "tcp")
	daemon.stop(t)
	command(t, 30*time.Second, e2eBinary(t), "cleanup")
	assertForeignTable(t, foreign)
	for _, f := range []*crowdFixture{fixture, replacement} {
		if _, _, bad := f.counters(); bad {
			t.Fatal("CrowdSec adapter violated the stream request contract")
		}
	}
}
