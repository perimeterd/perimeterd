//go:build linux && e2e

package e2e

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/app"
	"github.com/perimeterd/perimeterd/internal/control"
	"github.com/perimeterd/perimeterd/internal/lookup"
	"github.com/perimeterd/perimeterd/internal/testutil/dbipfixture"
)

const dbipHelper = "PERIMETERD_DBIP_HELPER"

// Only HTTP transport is injected: daemon transactions, parsers, persistence,
// control sockets and native enforcement all use the production implementation.
func TestE2EDBIPDaemonHelper(t *testing.T) {
	if os.Getenv(dbipHelper) != "1" {
		return
	}
	origin, err := url.Parse(os.Getenv("PERIMETERD_DBIP_ORIGIN"))
	if err != nil {
		t.Fatal(err)
	}
	err = app.Run(context.Background(), app.Options{
		ConfigPath:   os.Getenv("PERIMETERD_DBIP_CONFIG"),
		StateDir:     "/var/lib/perimeterd",
		LockPath:     "/run/perimeterd/owner.lock",
		SourceClient: &http.Client{Transport: dbipfixture.Transport{Origin: origin}},
		Stderr:       os.Stderr,
		Checkpoint: func(label string) error {
			if label == os.Getenv("PERIMETERD_DBIP_CRASH") {
				os.Exit(97)
			}
			marker := os.Getenv("PERIMETERD_DBIP_FAIL")
			if marker != "" {
				root, openErr := os.OpenRoot(filepath.Dir(marker))
				if openErr != nil {
					return openErr
				}
				defer func() { _ = root.Close() }()
				data, readErr := root.ReadFile(filepath.Base(marker))
				if readErr == nil && string(data) == label {
					if err := root.Remove(filepath.Base(marker)); err != nil {
						return err
					}
					return errors.New("injected DB-IP candidate publication failure")
				}
			}
			return nil
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(98)
	}
}

func dbipCommand(path, origin, marker, crash string) *exec.Cmd {
	// #nosec G204 G702 -- re-executes the compiled isolated E2E binary.
	cmd := exec.Command(os.Args[0], "-test.run", "^TestE2EDBIPDaemonHelper$", "-test.v")
	cmd.Env = append(os.Environ(), dbipHelper+"=1", "PERIMETERD_DBIP_CONFIG="+path,
		"PERIMETERD_DBIP_ORIGIN="+origin, "PERIMETERD_DBIP_FAIL="+marker, "PERIMETERD_DBIP_CRASH="+crash)
	return cmd
}

type dbipNativeSources struct {
	mu          sync.Mutex
	unavailable bool
	badTail     bool
	badASN      bool
	badList     bool
	emptyUS     bool
	requests    int
	encoded     []byte
}

func newDBIPNativeSources(t *testing.T) (*dbipNativeSources, *httptest.Server) {
	t.Helper()
	encoded, err := dbipfixture.Gzip(dbipfixture.CSV)
	if err != nil {
		t.Fatal(err)
	}
	fixture := &dbipNativeSources{encoded: encoded}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.mu.Lock()
		defer fixture.mu.Unlock()
		if r.URL.Path == "/dbip" {
			fixture.requests++
		}
		if fixture.unavailable {
			http.Error(w, "fixture offline", http.StatusForbidden)
			return
		}
		switch r.URL.Path {
		case "/dbip":
			if r.Header.Get("Accept-Encoding") != "identity" {
				http.Error(w, "explicit artifact encoding required", 400)
				return
			}
			body := fixture.encoded
			if fixture.badTail {
				body, _ = dbipfixture.Gzip(dbipfixture.CSV + "malformed,unselected,tail\n")
			}
			if fixture.emptyUS {
				body, _ = dbipfixture.Gzip(strings.ReplaceAll(dbipfixture.CSV, ",US\n", ",ZZ\n"))
			}
			_, _ = w.Write(body)
		case "/asn":
			if fixture.badASN {
				_, _ = w.Write([]byte(`{"status":"error"}`))
			} else {
				switch r.URL.Query().Get("resource") {
				case "3333":
					_, _ = w.Write([]byte(asnFixtureBody))
				case "3334":
					_, _ = w.Write([]byte(strings.ReplaceAll(asnFixtureBody, "3333", "3334")))
				default:
					http.Error(w, "unconfigured ASN", http.StatusNotFound)
				}
			}
		case "/list":
			if fixture.badList {
				http.Error(w, "list unavailable", http.StatusForbidden)
			} else {
				_, _ = w.Write([]byte("8.20.0.0/24\n2600:20::/64\n"))
			}
		case "/country":
			v4, v6 := []string{}, []string{}
			subnet := map[string]string{"US": "21", "JP": "20", "TW": "22", "IR": "23"}[r.URL.Query().Get("resource")]
			if subnet != "" {
				v4, v6 = []string{"8." + subnet + ".0.0/24"}, []string{"2600:" + subnet + "::/64"}
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"version": "0.2", "data_call_name": "country-resource-list", "data_call_status": "supported", "status": "ok", "status_code": 200, "time": "2026-09-14T00:00:00Z", "data": map[string]any{"query_time": "2026-09-13T00:00:00", "resources": map[string]any{"ipv4": v4, "ipv6": v6}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(server.Close)
	return fixture, server
}

func writeDBIPNativeConfig(t *testing.T, path, backend, table, provider, origin string, mixed bool) {
	t.Helper()
	text := geoConfigYAML(table)
	text = strings.Replace(text, "country_provider: ripestat", "country_provider: "+provider, 1)
	text = strings.Replace(text, "refresh_interval: 1s", "refresh_interval: 24h", 1)
	text = strings.Replace(text, "partners: [US]", "partners: [US, JP]", 1)
	text = strings.Replace(text, "      groups: [partners]", "      groups: [partners]\n    exclude:\n      countries: [JP]", 1)
	if backend == "iptables" {
		text = strings.Replace(text, "backend: nftables", "backend: iptables", 1)
		text = strings.Replace(text, fmt.Sprintf("  nftables:\n    table: %q\n    priority: -10\n", table), "  iptables:\n    attachments:\n      - chain: INPUT\n        direction: ingress\n      - chain: OUTPUT\n        direction: egress\n", 1)
	}
	if mixed {
		text = strings.Replace(text, "groups:\n", fmt.Sprintf("ip_lists:\n  transaction-list:\n    url: %q\ngroups:\n", origin+"/list"), 1)
		text = strings.Replace(text, "      asns: [AS3333]", "      asns: [AS3334]\n      ip_lists: [transaction-list]", 1)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil { // #nosec G703 -- namespace fixture.
		t.Fatal(err)
	}
}

func dbipNativePackets(t *testing.T, peer *peerNamespace, provider string) {
	t.Helper()
	us, jp := "20", "21"
	if provider == "ripestat" {
		us, jp = jp, us
	}
	for _, family := range []string{"4", "6"} {
		host := func(subnet string, port int) string {
			if family == "6" {
				return fmt.Sprintf("[2600:%s::1]:%d", subnet, port)
			}
			return fmt.Sprintf("8.%s.0.1:%d", subnet, port)
		}
		probeIngress(t, peer, "tcp"+family, host(us, 18080), "success", "tcp")
		probeIngress(t, peer, "tcp"+family, host(jp, 18080), "reject", "tcp")
		probeIngress(t, peer, "udp"+family, host(us, 18082), "reject", "udp")
		probeIngress(t, peer, "udp"+family, host(jp, 18082), "success", "udp")
		probeIngress(t, peer, "tcp"+family, host("22", 18088), "reject", "tcp")
		probeIngress(t, peer, "tcp"+family, host("23", 18088), "success", "tcp")
		probeIngress(t, peer, "tcp"+family, host("22", 18089), "reject", "tcp")
		probeIngress(t, peer, "tcp"+family, host("23", 18089), "success", "tcp")
	}
	probeEgress(t, peer, "udp4", fixtureIPv4Peer+":18083", "success", "udp")
	probeEgress(t, peer, "udp6", "["+fixtureIPv6Peer+"]:18083", "success", "udp")
}

func dbipNativeEvidence(t *testing.T, provider string) lookup.Response {
	t.Helper()
	address := "8.20.0.2"
	if provider == "ripestat" {
		address = "8.21.0.2"
	}
	port := uint16(18082)
	response := waitForLookupVerdict(t, address, "ingress", "udp", &port, "blocked")
	outcome, ok := lookupOutcome(response, "blocked", "policy")
	if !ok {
		t.Fatalf("missing policy outcome: %+v", response)
	}
	var evidence lookup.Evidence
	ok = false
	for _, item := range outcome.Evidence {
		if item.Kind == "country" && item.Name == "US" && item.Policy == outcome.Policy && item.Role == "include" && item.Contributing {
			evidence, ok = item, true
			break
		}
	}
	if !ok || !evidence.Contributing || evidence.Provider != provider || (provider == "dbip-lite" && evidence.Release == "") || (provider == "ripestat" && evidence.Release != "") {
		t.Fatalf("wrong committed country provenance: %+v", outcome.Evidence)
	}
	if data, _ := json.Marshal(response); strings.Contains(string(data), "download.db-ip.com") || strings.Contains(string(data), "sha256") {
		t.Fatalf("lookup disclosed private source identity: %s", data)
	}
	output := command(t, 10*time.Second, e2eBinary(t), "lookup", address, "--direction", "ingress", "--protocol", "udp", "--port", "18082")
	if !strings.Contains(string(output), provider) {
		t.Fatalf("human lookup omitted provider: %s", output)
	}
	if len(evidence.Via) == 0 {
		t.Fatalf("country group expansion path missing: %+v", evidence)
	}
	var status control.StatusResult
	statusJSON := command(t, 10*time.Second, e2eBinary(t), "status", "--json")
	if err := json.Unmarshal(statusJSON, &status); err != nil {
		t.Fatal(err)
	}
	if status.SchemaVersion != control.StatusSchemaVersion || status.Applied.Details == nil {
		t.Fatalf("invalid committed status: %s", statusJSON)
	}
	found := false
	for _, summary := range status.Applied.Details.Sources {
		if summary.Provider == provider && summary.Release == evidence.Release && !summary.RetrievedAt.IsZero() {
			found = true
		}
	}
	if !found {
		t.Fatalf("committed source summary omitted country provider: %s", statusJSON)
	}
	if strings.Contains(string(statusJSON), "download.db-ip.com") || strings.Contains(string(statusJSON), "sha256") {
		t.Fatalf("status disclosed source endpoint or parameters: %s", statusJSON)
	}
	statusText := command(t, 10*time.Second, e2eBinary(t), "status")
	if !strings.Contains(string(statusText), provider) {
		t.Fatalf("human status omitted country provider: %s", statusText)
	}
	t.Logf("applied provider=%s release=%s retrieved_at=%s", evidence.Provider, evidence.Release, evidence.RetrievedAt)
	for _, check := range []struct {
		address, protocol, verdict, kind, name, role, source string
		port                                                 uint16
		via, contributing                                    bool
	}{
		{"8.21.0.2", "udp", "not_blocked", "country", "JP", "exclude", provider, 18082, false, false},
		{"2600:21::2", "udp", "not_blocked", "country", "JP", "exclude", provider, 18082, false, false},
		{"8.22.0.2", "tcp", "blocked", "country", "TW", "include", provider, 18088, true, true},
		{"2600:22::2", "tcp", "blocked", "country", "TW", "include", provider, 18088, true, true},
		{"8.20.0.2", "udp", "not_blocked", "asn", "AS3333", "include", "ripestat", 18083, false, true},
		{"2600:20::2", "udp", "not_blocked", "asn", "AS3333", "include", "ripestat", 18083, false, true},
	} {
		if provider == "ripestat" && check.name == "JP" {
			check.address = strings.Replace(check.address, "21", "20", 1)
		}
		direction := "ingress"
		if check.kind == "asn" {
			direction = "egress"
		}
		result := waitForLookupVerdict(t, check.address, direction, check.protocol, &check.port, check.verdict)
		matched := false
		for _, partition := range result.Outcomes {
			for _, item := range partition.Evidence {
				if item.Kind == check.kind && item.Name == check.name && item.Role == check.role && item.Provider == check.source && item.Contributing == check.contributing {
					if check.via && len(item.Via) == 0 {
						t.Fatalf("RIR expansion path missing: %+v", item)
					}
					if check.source == "ripestat" && item.Release != "" {
						t.Fatalf("RIPE evidence fabricated monthly release: %+v", item)
					}
					matched = true
				}
			}
		}
		if !matched {
			t.Fatalf("missing committed %s/%s %s evidence: %+v", check.kind, check.name, check.role, result)
		}
	}
	return response
}

func dbipNativeSourceSummary(t *testing.T) []control.StatusSource {
	t.Helper()
	var status control.StatusResult
	output := command(t, 10*time.Second, e2eBinary(t), "status", "--json")
	if err := json.Unmarshal(output, &status); err != nil || status.Applied.Details == nil {
		t.Fatalf("committed status unavailable: %v: %s", err, output)
	}
	return status.Applied.Details.Sources
}

func dbipNativeSummaryUnchanged(t *testing.T, before []control.StatusSource) {
	t.Helper()
	if after := dbipNativeSourceSummary(t); !reflect.DeepEqual(before, after) {
		t.Fatalf("failed candidate advanced applied source summary: before=%+v after=%+v", before, after)
	}
}

func TestE2EDBIPNative(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, backend := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(backend, func(t *testing.T) { t.Logf("%s", runIsolated(t, "TestE2EDBIPNative", backend)) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	backend := lookupBackendScenario(t)
	if backend == "iptables" {
		seedIPTablesParents(t)
	}
	peer := newPeerNamespace(t)
	addLookupAddresses(t, peer)
	for _, subnet := range []string{"22", "23"} {
		command(t, 10*time.Second, "ip", "addr", "add", "8."+subnet+".0.1/24", "dev", "e2h0")
		peer.run(t, "ip", "addr", "add", "8."+subnet+".0.2/24", "dev", "e2p0")
		command(t, 10*time.Second, "ip", "-6", "addr", "add", "2600:"+subnet+"::1/64", "dev", "e2h0", "nodad")
		peer.run(t, "ip", "-6", "addr", "add", "2600:"+subnet+"::2/64", "dev", "e2p0", "nodad")
	}
	fixture, server := newDBIPNativeSources(t)
	path, table := tempConfig(t, "dbip-native"), fmt.Sprintf("pd_dbip_%d", os.Getpid())
	marker := filepath.Join(t.TempDir(), "publication-failure")
	write := func(provider string, mixed bool) {
		writeDBIPNativeConfig(t, path, backend, table, provider, server.URL, mixed)
	}
	start := func() *daemonProcess {
		return startDaemonCommand(t, dbipCommand(path, server.URL, marker, ""), "DB-IP native provider", func() bool { return activeRevision() != "" }, 2*time.Minute)
	}
	write("ripestat", false)
	command(t, 10*time.Second, e2eBinary(t), "validate", "--config", path)
	daemon := start()
	dbipNativePackets(t, peer, "ripestat")
	dbipNativeEvidence(t, "ripestat")

	// A malformed unselected tail rejects a provider switch with the exact old
	// applied lookup, revision and dual-stack enforcement still authoritative.
	fixture.mu.Lock()
	fixture.badTail = true
	fixture.mu.Unlock()
	write("dbip-lite", false)
	command(t, 10*time.Second, e2eBinary(t), "validate", "--config", path)
	fixture.mu.Lock()
	offlineRequests := fixture.requests
	fixture.mu.Unlock()
	if offlineRequests != 0 {
		t.Fatal("offline DB-IP validation performed a download")
	}
	before := activeRevision()
	oldEvidence := dbipNativeEvidence(t, "ripestat")
	oldSummary := dbipNativeSourceSummary(t)
	assertReloadRejected(t, "configuration_error")
	if activeRevision() != before {
		t.Fatal("failed switch changed active revision")
	}
	unchangedEvidence := dbipNativeEvidence(t, "ripestat")
	unchangedEvidence.ObservedAt = oldEvidence.ObservedAt
	if !reflect.DeepEqual(unchangedEvidence, oldEvidence) {
		t.Fatal("failed switch changed applied evidence")
	}
	dbipNativeSummaryUnchanged(t, oldSummary)
	dbipNativePackets(t, peer, "ripestat")
	fixture.mu.Lock()
	fixture.badTail = false
	fixture.mu.Unlock()
	command(t, 90*time.Second, e2eBinary(t), "reload")
	dbipNativePackets(t, peer, "dbip-lite")
	committedDBIP := dbipNativeEvidence(t, "dbip-lite")
	fixture.mu.Lock()
	requests := fixture.requests
	fixture.mu.Unlock()
	if requests != 2 {
		t.Fatalf("country/RIR leaves used %d artifact requests, want failed+successful single batch", requests)
	}

	// A complete same-provider snapshot survives restart without upstream. Its
	// retrieval metadata is committed provenance, not the attempted refresh time.
	daemon.stop(t)
	data, err := os.ReadFile(path) // #nosec G304 -- private config fixture.
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(strings.Replace(string(data), "refresh_interval: 24h", "refresh_interval: 1s", 1)), 0o600); err != nil {
		t.Fatal(err)
	} // #nosec G703 -- private config fixture.
	time.Sleep(1100 * time.Millisecond)
	fixture.mu.Lock()
	fixture.unavailable = true
	fixture.mu.Unlock()
	daemon = start()
	dbipNativePackets(t, peer, "dbip-lite")
	restartedDBIP := dbipNativeEvidence(t, "dbip-lite")
	for _, initial := range committedDBIP.Outcomes {
		for _, evidence := range initial.Evidence {
			for _, restarted := range restartedDBIP.Outcomes {
				for _, current := range restarted.Evidence {
					if current.Kind == evidence.Kind && current.Name == evidence.Name && (current.Release != evidence.Release || !current.RetrievedAt.Equal(evidence.RetrievedAt)) {
						t.Fatal("unavailable-upstream restart advanced committed source metadata")
					}
				}
			}
		}
	}
	fixture.mu.Lock()
	fixture.unavailable = false
	fixture.mu.Unlock()

	// Admission failures in another required source cannot publish a partial
	// country/ASN/list transaction or advance its applied artifact metadata.
	for _, failure := range []string{"asn", "list"} {
		write("ripestat", false)
		command(t, 90*time.Second, e2eBinary(t), "reload")
		before = activeRevision()
		oldSummary = dbipNativeSourceSummary(t)
		write("dbip-lite", true)
		fixture.mu.Lock()
		fixture.badASN = failure == "asn"
		fixture.badList = failure == "list"
		fixture.mu.Unlock()
		assertReloadRejected(t, "configuration_error")
		if activeRevision() != before {
			t.Fatalf("%s failure published candidate", failure)
		}
		dbipNativePackets(t, peer, "ripestat")
		dbipNativeEvidence(t, "ripestat")
		dbipNativeSummaryUnchanged(t, oldSummary)
		fixture.mu.Lock()
		fixture.badASN = false
		fixture.badList = false
		fixture.mu.Unlock()
	}
	// A valid complete artifact with no US assignments reaches the compiler's
	// empty-effective-allowlist guard rather than becoming an empty native set.
	write("dbip-lite", false)
	before = activeRevision()
	oldSummary = dbipNativeSourceSummary(t)
	fixture.mu.Lock()
	fixture.emptyUS = true
	fixture.mu.Unlock()
	assertReloadRejected(t, "configuration_error")
	if activeRevision() != before {
		t.Fatal("compiler rejection changed authority")
	}
	dbipNativePackets(t, peer, "ripestat")
	dbipNativeEvidence(t, "ripestat")
	dbipNativeSummaryUnchanged(t, oldSummary)
	fixture.mu.Lock()
	fixture.emptyUS = false
	fixture.mu.Unlock()

	// Fail both native post-switch compensation and durable publication paths
	// using production checkpoints, asserting packets and applied provenance.
	for _, checkpoint := range []string{"after-switch", "active:before-file-sync"} {
		write("dbip-lite", false)
		before = activeRevision()
		oldSummary = dbipNativeSourceSummary(t)
		if err := os.WriteFile(marker, []byte(checkpoint), 0o600); err != nil {
			t.Fatal(err)
		}
		assertReloadRejected(t, "apply_failed")
		if activeRevision() != before {
			t.Fatalf("%s failure changed authority", checkpoint)
		}
		dbipNativePackets(t, peer, "ripestat")
		dbipNativeEvidence(t, "ripestat")
		dbipNativeSummaryUnchanged(t, oldSummary)
	}
	write("dbip-lite", false)
	command(t, 90*time.Second, e2eBinary(t), "reload")
	dbipNativePackets(t, peer, "dbip-lite")
	daemon.stop(t)

	// Interrupted RIPE replacement cannot reinterpret committed DB-IP state.
	write("ripestat", false)
	if output, err := dbipCommand(path, server.URL, marker, "after-prepare").CombinedOutput(); !exitStatus(err, 97) {
		t.Fatalf("provider-switch recovery crash: %v\n%s", err, output)
	}
	write("dbip-lite", false)
	fixture.mu.Lock()
	fixture.unavailable = true
	fixture.mu.Unlock()
	daemon = start()
	dbipNativePackets(t, peer, "dbip-lite")
	dbipNativeEvidence(t, "dbip-lite")
	fixture.mu.Lock()
	fixture.unavailable = false
	fixture.mu.Unlock()
	write("ripestat", false)
	command(t, 90*time.Second, e2eBinary(t), "reload")
	dbipNativePackets(t, peer, "ripestat")
	dbipNativeEvidence(t, "ripestat")
	daemon.stop(t)
}
