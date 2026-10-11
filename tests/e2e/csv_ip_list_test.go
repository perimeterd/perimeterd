//go:build linux && e2e

package e2e

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"
)

func writeCSVListConfig(t *testing.T, path, backend, table, url, interval, threshold string) {
	t.Helper()
	writeCustomListConfig(t, path, backend, table, url, url, interval, false)
	// Keep the existing backend fixture configuration and replace only its
	// source definitions and policies with a single confidence-filtered source.
	// #nosec G304 -- path is a private configuration fixture created above.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	start := strings.Index(string(data), "ip_lists:\n")
	end := strings.Index(string(data), "crowdsec:\n")
	body := string(data[:start]) + fmt.Sprintf(`ip_lists:
  main:
    url: %q
    refresh_interval: %s
    request_timeout: 2s
    csv:
      delimiter: ";"
      header: true
      ip_column: 1
      filter:
        column: 3
        op: ">="
        value: %s
policies:
  - name: confidence
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["18482/tcp"]
    include:
      ip_lists: [main]
`, url, interval, threshold) + string(data[end:])
	// #nosec G703 -- path is the same private fixture, not remote input.
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func TestE2ECSVIPLists(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, scenario := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(scenario, func(t *testing.T) {
				t.Logf("%s", runIsolated(t, "TestE2ECSVIPLists", scenario))
			})
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	addCustomListAddresses(t, peer)
	fixture := newCustomListServer(t)
	const valid = "# local confidence fixture\n\nip_address;autonomous_system;confidence\n8.20.0.2;1;1\n8.21.0.2;2;0.5;unused\n2600:20::2;1;1\n2600:21::2;2;0.5\n"
	fixture.Set("/csv", http.StatusOK, valid)
	backend := os.Getenv(e2eScenario)
	if strings.HasPrefix(backend, "iptables-") {
		installIPTablesTools(t, strings.TrimPrefix(backend, "iptables-"))
		backend = "iptables"
	}
	table := fmt.Sprintf("pde2e_csv_%d", os.Getpid())
	path := tempConfig(t, "csv-list")
	writeCSVListConfig(t, path, backend, table, fixture.URL("/csv"), "24h", "1")
	command(t, 10*time.Second, e2eBinary(t), "validate", "--config", path)
	var daemon *daemonProcess
	if backend == "nftables" {
		daemon = startDaemon(t, path, table)
	} else {
		daemon = startIPTablesDaemon(t, path, "v4", "v6")
	}
	assertPackets := func(lower string) {
		t.Helper()
		probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18482", "drop", "tcp")
		probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18482", "drop", "tcp")
		probeIngress(t, peer, "tcp4", "8.21.0.1:18482", lower, "tcp")
		probeIngress(t, peer, "tcp6", "[2600:21::1]:18482", lower, "tcp")
	}
	assertPackets("success")
	t.Log("confidence >= 1 blocks matching IPv4/IPv6; lower confidence passes")

	before := activeRevision()
	writeCSVListConfig(t, path, backend, table, fixture.URL("/csv"), "24h", "0.5")
	output := command(t, 90*time.Second, e2eBinary(t), "reload")
	assertReloadAcknowledgement(t, before, reloadConfigDigest(t, path), output)
	assertPackets("drop")
	t.Log("threshold reload to >= 0.5 blocks formerly excluded addresses")

	// With all evidence fresh, an unavailable changed interpretation must not
	// activate a same-name cached object from the lower threshold.
	fixture.Set("/csv", http.StatusServiceUnavailable, "outage\n")
	before = activeRevision()
	writeCSVListConfig(t, path, backend, table, fixture.URL("/csv"), "24h", "2")
	assertReloadRejected(t, "configuration_error")
	assertReloadPolicyUnchanged(t, before)
	assertPackets("drop")

	fixture.Set("/csv", http.StatusOK, valid)
	writeCSVListConfig(t, path, backend, table, fixture.URL("/csv"), "200ms", "0.5")
	command(t, 90*time.Second, e2eBinary(t), "reload")
	// Failed periodic refreshes may use only the complete committed selection.
	// Include a valid different prefix before the malformed tail to detect
	// accidental publication of partial parser results.
	for _, body := range []string{
		"ip;asn;confidence\n8.22.0.2;3;1\n\"broken tail\n",
		"ip;asn;confidence\n8.22.0.2;3;0\n",
	} {
		offset := daemonDiagnosticOffset(daemon)
		requests := fixture.Requests("/csv")
		fixture.Set("/csv", http.StatusOK, body)
		waitCustomListRequests(t, fixture, "/csv", requests+1)
		waitForDaemonDiagnostic(t, daemon, []string{"ip_list/main"}, offset)
		assertPackets("drop")
		probeIngress(t, peer, "tcp4", "8.22.0.1:18482", "success", "tcp")
	}
	t.Log("malformed tail and zero-match refresh preserve complete committed rules")

	// Restart during an outage proves the persisted CSV interpretation survives
	// exact-reference recovery, rather than being recreated only in memory.
	fixture.Set("/csv", http.StatusServiceUnavailable, "restart outage\n")
	daemon.stop(t)
	if backend == "nftables" {
		daemon = startDaemon(t, path, table)
	} else {
		daemon = startIPTablesDaemon(t, path, "v4", "v6")
	}
	assertPackets("drop")
	daemon.stop(t)
	t.Log("restart outage retains CSV selection from committed evidence")
}
