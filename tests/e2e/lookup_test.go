//go:build linux && e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/lookup"
)

const (
	lookupMainList  = "/lookup-main"
	lookupCarveList = "/lookup-carve"
	lookupMainBody  = "# source-backed lookup fixture\n8.20.0.0/24\n8.21.0.0/24\n2600:20::/64\n2600:21::/64\n"
	lookupCarveBody = "# excluded source membership\n8.20.0.2/32\n2600:20::2/128\n"
)

type lookupCommandResult struct {
	response lookup.Response
	exitCode int
	output   []byte
}

func lookupCommand(t *testing.T, address, direction, protocol string, port *uint16) lookupCommandResult {
	t.Helper()
	args := []string{"lookup", address}
	if direction != "" {
		args = append(args, "--direction", direction)
	}
	if protocol != "" {
		args = append(args, "--protocol", protocol)
	}
	if port != nil {
		args = append(args, "--port", fmt.Sprint(*port))
	}
	args = append(args, "--json")
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- the validated E2E binary is launched only by this test harness.
	cmd := exec.CommandContext(ctx, e2eBinary(t), args...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("lookup %s timed out: %v\n%s", address, ctx.Err(), output)
	}
	result := lookupCommandResult{output: output}
	if err == nil {
		result.exitCode = 0
	} else {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			result.exitCode = exitErr.ExitCode()
		} else {
			result.exitCode = -1
		}
	}
	if err := json.Unmarshal(output, &result.response); err != nil {
		t.Fatalf("lookup %s did not return JSON (exit %d): %v\n%s", address, result.exitCode, err, output)
	}
	return result
}

func requireLookupUnknown(t *testing.T, result lookupCommandResult, address string) lookup.Response {
	t.Helper()
	if result.exitCode != 1 {
		t.Fatalf("lookup %s unavailable exit = %d, want 1: %s", address, result.exitCode, result.output)
	}
	if result.response.SchemaVersion != lookup.SchemaVersion || result.response.Verdict != "unknown" || result.response.Error == nil {
		t.Fatalf("lookup %s unavailable response is not explicit unknown: %+v\n%s", address, result.response, result.output)
	}
	return result.response
}

func lookupOutcome(response lookup.Response, verdict, stage string) (lookup.Outcome, bool) {
	for _, outcome := range response.Outcomes {
		if outcome.Verdict == verdict && (stage == "" || outcome.Stage == stage) {
			return outcome, true
		}
	}
	return lookup.Outcome{}, false
}

func lookupEvidence(outcome lookup.Outcome, kind, name string) (lookup.Evidence, bool) {
	for _, evidence := range outcome.Evidence {
		if evidence.Kind == kind && evidence.Name == name {
			return evidence, true
		}
	}
	return lookup.Evidence{}, false
}

func waitForLookup(t *testing.T, address, direction, protocol string, port *uint16, want func(lookup.Response) bool) lookup.Response {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last lookup.Response
	for time.Now().Before(deadline) {
		result := lookupCommand(t, address, direction, protocol, port)
		last = result.response
		if result.exitCode == 0 {
			if result.response.SchemaVersion != lookup.SchemaVersion || result.response.Flow != "new" || result.response.Error != nil {
				t.Fatalf("lookup %s returned malformed complete response: %+v", address, result.response)
			}
			if want(last) {
				return last
			}
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("lookup %s did not converge: %+v", address, last)
	return lookup.Response{}
}

func waitForLookupVerdict(t *testing.T, address, direction, protocol string, port *uint16, verdict string) lookup.Response {
	t.Helper()
	return waitForLookup(t, address, direction, protocol, port, func(response lookup.Response) bool {
		return response.Verdict == verdict
	})
}

func lookupBackendScenario(t *testing.T) string {
	t.Helper()
	backend := os.Getenv(e2eScenario)
	if strings.HasPrefix(backend, "iptables-") {
		installIPTablesTools(t, strings.TrimPrefix(backend, "iptables-"))
		return "iptables"
	}
	if backend == "nftables" {
		return backend
	}
	t.Fatalf("unknown lookup backend scenario %q", backend)
	return ""
}

func startLookupDaemon(t *testing.T, configPath, backend, table string) *daemonProcess {
	t.Helper()
	if backend == "nftables" {
		return startDaemon(t, configPath, table)
	}
	return startDaemonProcess(t, configPath, "lookup iptables policy", func() bool {
		return activeRevision() != ""
	})
}

func addLookupAddresses(t *testing.T, peer *peerNamespace) {
	t.Helper()
	for _, family := range []struct {
		host string
		peer string
	}{
		{host: "8.21.0.1/24", peer: "8.21.0.2/24"},
		{host: "2600:21::1/64", peer: "2600:21::2/64"},
	} {
		if strings.Contains(family.host, ":") {
			command(t, 10*time.Second, "ip", "-6", "addr", "add", family.host, "dev", "e2h0", "nodad")
			peer.run(t, "ip", "-6", "addr", "add", family.peer, "dev", "e2p0", "nodad")
		} else {
			command(t, 10*time.Second, "ip", "addr", "add", family.host, "dev", "e2h0")
			peer.run(t, "ip", "addr", "add", family.peer, "dev", "e2p0")
		}
	}
}

func writeLookupConfig(t *testing.T, path, backend, table, mainURL, carveURL string, ipv4, ipv6 bool, refresh string) {
	t.Helper()
	var firewall string
	if backend == "nftables" {
		firewall = fmt.Sprintf(`firewall:
  backend: nftables
  deny_action: reject
  ipv4: %t
  ipv6: %t
  nftables:
    table: %q
    priority: -10
`, ipv4, ipv6, table)
	} else {
		firewall = fmt.Sprintf(`firewall:
  backend: iptables
  deny_action: reject
  ipv4: %t
  ipv6: %t
  iptables:
    attachments:
      - chain: INPUT
        direction: ingress
      - chain: OUTPUT
        direction: egress
`, ipv4, ipv6)
	}
	body := fmt.Sprintf(`version: 1
logging:
  level: debug
  format: text
metrics:
  listen: ""
global:
  allowlist: ["8.22.0.0/24"]
  blocklist: ["8.23.0.0/24"]
%sgeo:
  refresh_interval: 1s
  request_timeout: 2s
  refresh_jitter: 1ns
ip_lists:
  lookup-main:
    url: %q
    refresh_interval: %s
    request_timeout: 2s
  lookup-carve:
    url: %q
    refresh_interval: %s
    request_timeout: 2s
groups: {}
policies:
  - name: lookup-source-block
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["18480/tcp"]
    include:
      ip_lists: [lookup-main]
    exclude:
      ip_lists: [lookup-carve]
  - name: lookup-source-egress
    priority: 20
    direction: egress
    mode: allowlist
    traffic: ["18481/tcp"]
    include:
      ip_lists: [lookup-main]
crowdsec:
  enabled: false
`, firewall, mainURL, refresh, carveURL, refresh)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write lookup config: %v", err)
	}
}

func TestE2ELookupNative(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, backend := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(backend, func(t *testing.T) { runIsolated(t, "TestE2ELookupNative", backend) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	backend := lookupBackendScenario(t)
	peer := newPeerNamespace(t)
	addLookupAddresses(t, peer)
	fixture := newCustomListServer(t)
	fixture.Set(lookupMainList, 200, lookupMainBody)
	fixture.Set(lookupCarveList, 200, lookupCarveBody)
	configPath := tempConfig(t, "lookup-native")
	table := fmt.Sprintf("pde2e_lookup_%d", os.Getpid())
	writeLookupConfig(t, configPath, backend, table, fixture.URL(lookupMainList), fixture.URL(lookupCarveList), true, true, "1s")
	daemon := startLookupDaemon(t, configPath, backend, table)

	port := new(uint16(18480))
	// The source-backed decision is checked against both real packet families.
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18480", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18480", "success", "tcp")
	probeIngress(t, peer, "tcp4", "8.21.0.1:18480", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:21::1]:18480", "reject", "tcp")

	blocked := waitForLookupVerdict(t, "8.21.0.2", "ingress", "tcp", port, "blocked")
	if outcome, ok := lookupOutcome(blocked, "blocked", "policy"); !ok {
		t.Fatalf("source block has no policy outcome: %+v", blocked.Outcomes)
	} else if evidence, ok := lookupEvidence(outcome, "ip_list", "lookup-main"); !ok || !evidence.Contributing {
		t.Fatalf("source block lacks contributing include evidence: %+v", outcome.Evidence)
	}
	blockedV6 := waitForLookupVerdict(t, "2600:21::2", "ingress", "tcp", port, "blocked")
	if _, ok := lookupOutcome(blockedV6, "blocked", "policy"); !ok {
		t.Fatalf("IPv6 source block has no policy outcome: %+v", blockedV6.Outcomes)
	}
	carved := waitForLookupVerdict(t, "8.20.0.2", "ingress", "tcp", port, "not_blocked")
	if outcome, ok := lookupOutcome(carved, "not_blocked", ""); !ok {
		t.Fatalf("excluded source has no terminal policy outcome: %+v", carved.Outcomes)
	} else if evidence, ok := lookupEvidence(outcome, "ip_list", "lookup-carve"); !ok || !evidence.Contributing || evidence.Role != "exclude" {
		t.Fatalf("excluded source evidence is not marked as a contributing exclusion: %+v", outcome.Evidence)
	}
	globalBlock := waitForLookupVerdict(t, "8.23.0.4", "ingress", "tcp", port, "blocked")
	if _, ok := lookupOutcome(globalBlock, "blocked", "global_block"); !ok {
		t.Fatalf("global block was not identified as global evidence: %+v", globalBlock.Outcomes)
	}
	globalAllow := waitForLookupVerdict(t, "8.22.0.4", "ingress", "tcp", port, "not_blocked")
	if _, ok := lookupOutcome(globalAllow, "not_blocked", "global_allow"); !ok {
		t.Fatalf("global allow was not identified as global evidence: %+v", globalAllow.Outcomes)
	}
	mixed := waitForLookupVerdict(t, "8.20.0.0/23", "ingress", "tcp", port, "mixed")
	if _, blockedOK := lookupOutcome(mixed, "blocked", ""); !blockedOK {
		t.Fatalf("mixed CIDR omitted blocked partition: %+v", mixed.Outcomes)
	}
	if _, allowedOK := lookupOutcome(mixed, "not_blocked", ""); !allowedOK {
		t.Fatalf("mixed CIDR omitted excluded partition: %+v", mixed.Outcomes)
	}
	omitted := waitForLookupVerdict(t, "8.21.0.2", "", "", nil, "mixed")
	if omitted.Query.Direction != "" || omitted.Query.Protocol != "" || omitted.Query.Port != nil {
		t.Fatalf("omitted lookup scope was silently narrowed: %+v", omitted.Query)
	}

	// A source outage/rejected refresh retains the exact applied answer.
	time.Sleep(1200 * time.Millisecond)
	initialRequests := fixture.Requests(lookupMainList)
	fixture.Set(lookupMainList, 500, "upstream unavailable\n")
	daemon.reload(t)
	waitCustomListRequests(t, fixture, lookupMainList, initialRequests+1)
	waitForLookupVerdict(t, "8.21.0.2", "ingress", "tcp", port, "blocked")

	// A malformed reload is rejected without replacing the committed query view.
	writeInvalidConfigMarker(t, configPath, "unsupported-lookup-reload")
	diagnosticOffset := daemonDiagnosticOffset(daemon)
	daemon.reload(t)
	waitForDaemonDiagnostic(t, daemon, []string{"unsupported-lookup-reload"}, diagnosticOffset)
	waitForLookupVerdict(t, "8.21.0.2", "ingress", "tcp", port, "blocked")

	daemon.stop(t)
	requireLookupUnknown(t, lookupCommand(t, "8.21.0.2", "ingress", "tcp", port), "8.21.0.2")
}

func writeLookupCoverageConfig(t *testing.T, path, backend, table, mainURL string, ipv4, ipv6 bool) {
	t.Helper()
	var firewall string
	if backend == "nftables" {
		firewall = fmt.Sprintf(`firewall:
  backend: nftables
  deny_action: reject
  ipv4: %t
  ipv6: %t
  nftables:
    table: %q
    priority: -10
`, ipv4, ipv6, table)
	} else {
		firewall = fmt.Sprintf(`firewall:
  backend: iptables
  deny_action: reject
  ipv4: %t
  ipv6: %t
  iptables:
    attachments:
      - chain: INPUT
        direction: ingress
`, ipv4, ipv6)
	}
	body := fmt.Sprintf(`version: 1
logging:
  level: error
metrics:
  listen: ""
global:
  allowlist: []
  blocklist: []
%sgeo:
  refresh_interval: 24h
  request_timeout: 2s
  refresh_jitter: 1ns
ip_lists:
  lookup-v4-only:
    url: %q
    refresh_interval: 24h
    request_timeout: 2s
groups: {}
policies:
  - name: lookup-empty-v6
    priority: 10
    direction: ingress
    mode: allowlist
    traffic: ["18482/tcp"]
    include:
      ip_lists: [lookup-v4-only]
crowdsec:
  enabled: false
`, firewall, mainURL)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write lookup coverage config: %v", err)
	}
}

func TestE2ELookupCoverage(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, backend := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(backend, func(t *testing.T) { runIsolated(t, "TestE2ELookupCoverage", backend) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	backend := lookupBackendScenario(t)
	peer := newPeerNamespace(t)
	fixture := newCustomListServer(t)
	fixture.Set("/v4-only", 200, "8.20.0.0/24\n")
	configPath := tempConfig(t, "lookup-coverage")
	table := fmt.Sprintf("pde2e_lookup_cov_%d", os.Getpid())
	writeLookupCoverageConfig(t, configPath, backend, table, fixture.URL("/v4-only"), true, true)
	daemon := startLookupDaemon(t, configPath, backend, table)
	port := new(uint16(18482))
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18482", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18482", "reject", "tcp")
	emptyV6 := waitForLookupVerdict(t, fixtureIPv6Peer, "ingress", "tcp", port, "blocked")
	if _, ok := lookupOutcome(emptyV6, "blocked", "policy"); !ok {
		t.Fatalf("empty IPv6 allowlist was not explained by policy: %+v", emptyV6.Outcomes)
	}

	// Disabling a family makes it explicitly unmanaged rather than an implicit allow.
	before := activeRevision()
	writeLookupCoverageConfig(t, configPath, backend, table, fixture.URL("/v4-only"), true, false)
	daemon.reload(t)
	if backend != "nftables" {
		waitForIPTablesCommit(t, before)
	}
	disabled := waitForLookup(t, fixtureIPv6Peer, "ingress", "tcp", port, func(response lookup.Response) bool {
		if response.Verdict != "not_blocked" {
			return false
		}
		for _, outcome := range response.Outcomes {
			if !outcome.Attachment.Managed && outcome.Stage == "not_managed" {
				return true
			}
		}
		return false
	})
	if _, ok := lookupOutcome(disabled, "not_blocked", "not_managed"); !ok {
		t.Fatalf("disabled IPv6 was not reported as unmanaged: %+v", disabled.Outcomes)
	}
	daemon.stop(t)
	requireLookupUnknown(t, lookupCommand(t, fixtureIPv6Peer, "ingress", "tcp", port), fixtureIPv6Peer)
}

func TestE2ELookupCrowdSec(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, backend := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(backend, func(t *testing.T) { runIsolated(t, "TestE2ELookupCrowdSec", backend) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	backend := lookupBackendScenario(t)
	peer := newPeerNamespace(t)
	fixture, server := newCrowdFixture(t)
	fixture.set(41, fixtureIPv4Peer, 5*time.Minute)
	configPath := tempConfig(t, "lookup-crowdsec")
	keyPath := filepath.Join(t.TempDir(), "crowdsec.key")
	if err := os.WriteFile(keyPath, []byte(crowdFixtureKey), 0o600); err != nil {
		t.Fatal(err)
	}
	table := fmt.Sprintf("pde2e_lookup_cs_%d", os.Getpid())
	writeCrowdConfig(t, configPath, backend, table, server.URL, keyPath, true, nil)
	var daemon *daemonProcess
	if backend == "nftables" {
		daemon = startDaemon(t, configPath, table)
	} else {
		daemon = startLookupDaemon(t, configPath, backend, table)
	}
	port := new(uint16(18680))
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18680", "reject", "tcp")
	blocked := waitForLookup(t, fixtureIPv4Peer, "ingress", "tcp", port, func(response lookup.Response) bool {
		return response.Verdict == "blocked"
	})
	outcome, ok := lookupOutcome(blocked, "blocked", "crowdsec")
	if !ok {
		t.Fatalf("CrowdSec decision was not the deciding lookup stage: %+v", blocked.Outcomes)
	}
	var evidence lookup.Evidence
	foundEvidence := false
	for _, candidate := range outcome.Evidence {
		if candidate.Kind == "crowdsec" && candidate.DecisionID == 41 {
			evidence = candidate
			foundEvidence = true
			break
		}
	}
	if !foundEvidence || evidence.DecisionDeadline.IsZero() || evidence.LeaseDeadline.IsZero() {
		t.Fatalf("CrowdSec lookup omitted acknowledged decision/lease evidence: %+v", outcome.Evidence)
	}

	fixture.remove(41)
	waitCrowdPacket(t, peer, "tcp4", fixtureIPv4Host+":18681", "success")
	waitForLookup(t, fixtureIPv4Peer, "ingress", "tcp", port, func(response lookup.Response) bool {
		return response.Verdict == "not_blocked"
	})

	fixture.set(42, fixtureIPv4Peer, 5*time.Second)
	waitCrowdPacket(t, peer, "tcp4", fixtureIPv4Host+":18682", "reject")
	waitForLookup(t, fixtureIPv4Peer, "ingress", "tcp", port, func(response lookup.Response) bool {
		return response.Verdict == "blocked"
	})
	// After the acknowledged native lease expires, the applied projection
	// converges to an empty dynamic view rather than using desired state.
	waitForLookup(t, fixtureIPv4Peer, "ingress", "tcp", port, func(response lookup.Response) bool {
		return response.Verdict == "not_blocked"
	})
	daemon.stop(t)
}
