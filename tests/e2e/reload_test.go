//go:build linux && e2e

package e2e

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"
)

func TestE2EAcknowledgedReload(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, backend := range []string{"nftables", "nft", "legacy"} {
			t.Run(backend, func(t *testing.T) {
				output := runIsolated(t, "TestE2EAcknowledgedReload", backend)
				t.Logf("%s", output)
			})
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	backend := os.Getenv(e2eScenario)
	table := fmt.Sprintf("pdack_%d", os.Getpid())
	path := tempConfig(t, "acknowledged-reload")
	writePolicy := func(block []string) {
		if backend == "nftables" {
			writeConfig(t, path, table, "drop", nil, block, -10)
		} else {
			writeIPTablesConfig(t, path, "drop", nil, block, true, true, defaultIPTablesAttachments())
		}
	}
	if backend != "nftables" {
		installIPTablesTools(t, backend)
		seedIPTablesParents(t)
	}
	writePolicy([]string{"8.8.8.8/32"})
	var daemon *daemonProcess
	if backend == "nftables" {
		daemon = startDaemon(t, path, table)
	} else {
		daemon = startIPTablesDaemon(t, path, "v4", "v6")
	}
	before := activeRevision()
	initialDigest := reloadConfigDigest(t, path)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18580", "success", "tcp")

	// A valid but different candidate must not enter native apply on a mismatch.
	writePolicy([]string{fixtureIPv4Peer + "/32"})
	assertReloadRejected(t, "config_mismatch", "--expect-config-sha256", initialDigest)
	assertReloadPolicyUnchanged(t, before)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18580", "success", "tcp")

	writeInvalidConfig(t, path)
	assertReloadRejected(t, "configuration_error")
	assertReloadPolicyUnchanged(t, before)
	writePolicy([]string{fixtureIPv4Peer + "/32"})
	writeReloadSource(t, path, "http://127.0.0.1:9/reload-unavailable", "1s")
	command(t, 10*time.Second, e2eBinary(t), "validate", "--config", path)
	assertReloadRejected(t, "configuration_error")
	assertReloadPolicyUnchanged(t, before)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18580", "success", "tcp")

	// Exit zero must already mean the selected runtime and kernel enforce B.
	writePolicy([]string{fixtureIPv4Peer + "/32"})
	digest := reloadConfigDigest(t, path)
	output := command(t, 90*time.Second, e2eBinary(t), "reload", "--expect-config-sha256", digest)
	assertReloadAcknowledgement(t, before, digest, output)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18580", "drop", "tcp")
	t.Logf("backend=%s applied=%s", backend, strings.TrimSpace(string(output)))

	// No expected digest still acknowledges this request's bytes, not a prior reload.
	before = activeRevision()
	writePolicy([]string{"8.8.8.8/32"})
	output = command(t, 90*time.Second, e2eBinary(t), "reload")
	assertReloadAcknowledgement(t, before, reloadConfigDigest(t, path), output)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18580", "success", "tcp")

	if backend == "nftables" {
		before = activeRevision()
		entered := make(chan struct{}, 1)
		fixture := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, request *http.Request) {
			entered <- struct{}{}
			<-request.Context().Done()
		}))
		t.Cleanup(fixture.Close)
		writePolicy([]string{fixtureIPv4Peer + "/32"})
		writeReloadSource(t, path, fixture.URL+"/reload-timeout", "180s")
		output, err := commandMayFail(90*time.Second, e2eBinary(t), "reload")
		if err == nil || !strings.Contains(string(output), "unknown") {
			t.Fatalf("timeout falsely acknowledged completion: err=%v output=%s", err, output)
		}
		select {
		case <-entered:
		default:
			t.Fatal("timeout never reached the actual source operation")
		}
		assertReloadPolicyUnchanged(t, before)
		probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18580", "success", "tcp")
		t.Logf("native source timeout: %s", strings.TrimSpace(string(output)))
	}
	daemon.stop(t)
	assertReloadRejected(t, "unknown")
}

func reloadConfigDigest(t *testing.T, path string) string {
	t.Helper()
	// #nosec G304 -- path is an isolated configuration fixture created by this test.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func assertReloadRejected(t *testing.T, code string, args ...string) {
	t.Helper()
	argv := append([]string{e2eBinary(t), "reload"}, args...)
	output, err := commandMayFail(90*time.Second, argv...)
	if err == nil || !strings.Contains(string(output), code) {
		t.Fatalf("reload did not fail closed with %s: err=%v output=%s", code, err, output)
	}
	t.Logf("reload rejected: %s", strings.TrimSpace(string(output)))
}

func assertReloadPolicyUnchanged(t *testing.T, before string) {
	t.Helper()
	if after := activeRevision(); after != before {
		t.Fatalf("rejected reload changed the selected revision: before=%s after=%s", before, after)
	}
}

func assertReloadAcknowledgement(t *testing.T, before, digest string, output []byte) {
	t.Helper()
	after := activeRevision()
	var selected struct {
		Payload struct {
			ID string `json:"id"`
		} `json:"payload"`
	}
	if err := json.Unmarshal([]byte(after), &selected); err != nil {
		t.Fatal(err)
	}
	if after == before || selected.Payload.ID == "" ||
		!strings.Contains(string(output), selected.Payload.ID) || !strings.Contains(string(output), digest) {
		t.Fatalf("acknowledgement does not name this selected revision/digest: selected=%s digest=%s output=%s", after, digest, output)
	}
}

func writeReloadSource(t *testing.T, path, url, timeout string) {
	t.Helper()
	// #nosec G304 -- path is an isolated configuration fixture created by this test.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	body := strings.Replace(string(data), "policies: []", fmt.Sprintf(`ip_lists:
  reload-source:
    url: %q
    request_timeout: %s
policies:
  - name: reload-source
    priority: 100
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      ip_lists: [reload-source]`, url, timeout), 1)
	// #nosec G703 -- path is the same private fixture, not supplied by configuration.
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}
