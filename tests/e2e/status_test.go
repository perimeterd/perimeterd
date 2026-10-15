//go:build linux && e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/control"
	"github.com/perimeterd/perimeterd/internal/policy"
)

// The production daemon runs in a separate process via capacityCommand. Its
// injected country transport refuses external requests; this server handles both
// country fixtures and the real CrowdSec streaming protocol on the same origin.
func newStatusSources(t *testing.T) (*crowdFixture, *httptest.Server) {
	t.Helper()
	crowd := &crowdFixture{
		decisions: make(map[int64]crowdFixtureDecision),
		pending:   make(map[int64]struct{}),
	}
	type resources struct {
		IPv4 []string `json:"ipv4"`
		IPv6 []string `json:"ipv6"`
	}
	countries := map[string]resources{
		// Duplicates are removed; adjacent CIDRs remain distinct logical members.
		"US": {
			IPv4: []string{"8.20.0.0/25", "8.20.0.128/25", "8.20.0.0/25", "8.22.0.0/24"},
			IPv6: []string{"2600:20::/65", "2600:20:0:0:8000::/65", "2600:20::/65", "2600:22::/64"},
		},
		"CA": {
			IPv4: []string{"8.30.0.0/24"},
			IPv6: []string{"2600:30::/64", "2600:32::/64"},
		},
		"DE": {
			IPv4: []string{"8.50.0.0/24", "8.52.0.0/24", "8.54.0.0/24", "8.56.0.0/24"},
			IPv6: []string{"2600:50::/64"},
		},
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/country" {
			crowd.serve(w, r)
			return
		}
		country, ok := countries[r.URL.Query().Get("resource")]
		if !ok {
			http.Error(w, "unexpected country", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": "0.2", "data_call_name": "country-resource-list",
			"data_call_status": "supported", "status": "ok", "status_code": 200,
			"time": "2026-09-14T00:00:00Z",
			"data": map[string]any{"query_time": "2026-09-13T00:00:00", "resources": country},
		})
	}))
	t.Cleanup(server.Close)
	return crowd, server
}

func writeStatusConfig(t *testing.T, path, backend, table, endpoint, key, egressCountry string) {
	t.Helper()
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
    table: %q
    priority: -10
global:
  allowlist: ["8.60.0.0/24", "2600:60::/64"]
  blocklist: ["8.62.0.0/24", "2600:62::/64"]
geo:
  refresh_interval: 1h
  request_timeout: 2s
policies:
  - name: ingress
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["18480/tcp"]
    include:
      countries: [US]
  - name: egress
    priority: 10
    direction: egress
    mode: blocklist
    traffic: ["18480/tcp"]
    include:
      countries: [%s]
  - name: ssh
    priority: 20
    direction: ingress
    mode: blocklist
    traffic: ["22/tcp"]
    include:
      countries: [CA]
crowdsec:
  enabled: true
  lapi_url: %q
  api_key_file: %q
  update_frequency: 250ms
`, backend, table, egressCountry, endpoint, key)
	// #nosec G703 -- path belongs to this isolated test's fixture directory.
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func expectedStatusCompiled(reloaded bool) control.StatusCompiledSets {
	result := control.StatusCompiledSets{
		Sets:   make([]control.StatusCompiledSet, 0, 12),
		Totals: make([]control.StatusCompiledTotal, 0, 2),
	}
	for _, family := range []policy.Family{policy.IPv4, policy.IPv6} {
		name, allow, ssh, egress := "ipv4", uint64(6), uint64(1), uint64(3)
		if family == policy.IPv6 {
			name, allow, ssh = "ipv6", 4, 2
		}
		if reloaded {
			egress = 4
			if family == policy.IPv6 {
				egress = 1
			}
		}
		// Built-in local allow ranges plus one explicit allow prefix per family;
		// the classifier's normative internal set also contributes exactly once.
		rows := []control.StatusCompiledSet{
			{Family: name, ID: "geo/egress", Count: egress},
			{Family: name, ID: "geo/ingress", Count: 3},
			{Family: name, ID: "geo/ssh", Count: ssh},
			{Family: name, ID: "geo_eligible", Count: uint64(len(policy.GeoEligible(family).Prefixes()))},
			{Family: name, ID: "global_allowlist", Count: allow},
			{Family: name, ID: "global_blocklist", Count: 1},
		}
		var total uint64
		for _, row := range rows {
			total += row.Count
		}
		result.Sets = append(result.Sets, rows...)
		result.Totals = append(result.Totals, control.StatusCompiledTotal{Family: name, Count: total})
	}
	return result
}

func assertStatusSources(t *testing.T, details *control.StatusDetails, reloaded bool) {
	t.Helper()
	country4, country6 := uint64(4), uint64(5)
	if reloaded {
		country4, country6 = 8, 6
	}
	want := []control.StatusPrefixCount{
		{Family: "ipv4", Source: "global", Type: "allowlist", Count: 1},
		{Family: "ipv4", Source: "global", Type: "blocklist", Count: 1},
		{Family: "ipv4", Source: "local", Type: "local", Count: 5},
		{Family: "ipv4", Source: "ripestat", Type: "country", Count: country4},
		{Family: "ipv6", Source: "global", Type: "allowlist", Count: 1},
		{Family: "ipv6", Source: "global", Type: "blocklist", Count: 1},
		{Family: "ipv6", Source: "local", Type: "local", Count: 3},
		{Family: "ipv6", Source: "ripestat", Type: "country", Count: country6},
	}
	if !reflect.DeepEqual(details.PrefixCounts, want) {
		t.Fatalf("deduplicated source counts = %+v, want %+v", details.PrefixCounts, want)
	}
}

func assertStatusCLI(t *testing.T, phase string, reloaded bool) control.StatusResult {
	t.Helper()
	output := command(t, 10*time.Second, e2eBinary(t), "status", "--json")
	var status control.StatusResult
	if err := json.Unmarshal(output, &status); err != nil {
		t.Fatalf("parse actual status CLI: %v\n%s", err, output)
	}
	if status.SchemaVersion != control.StatusSchemaVersion || !status.Successful() || status.Applied.State != "applied" || status.Applied.Revision == "" || status.Applied.Details == nil {
		t.Fatalf("status is not an acknowledged healthy applied report: %+v", status)
	}
	details := status.Applied.Details
	want := expectedStatusCompiled(reloaded)
	if !reflect.DeepEqual(details.CompiledSets, want) {
		t.Fatalf("compiled static sets = %+v, want %+v", details.CompiledSets, want)
	}
	assertStatusSources(t, details, reloaded)
	text := string(command(t, 10*time.Second, e2eBinary(t), "status"))
	lines := strings.Split(strings.TrimSpace(text), "\n")
	hasLine := func(want string) {
		t.Helper()
		for _, line := range lines {
			if line == want {
				return
			}
		}
		t.Fatalf("status text missing targeted line %q:\n%s", want, text)
	}
	hasLine("Compiled firewall sets (static target memberships; duplicates across sets included; not a kernel audit):")
	for _, row := range want.Sets {
		hasLine(fmt.Sprintf("  family=%s set=%s count=%d", row.Family, row.ID, row.Count))
	}
	for _, total := range want.Totals {
		hasLine(fmt.Sprintf("  family=%s total_memberships=%d", total.Family, total.Count))
	}
	hasLine("  Dynamic CrowdSec memberships excluded; decision counts reported separately.")
	if strings.Contains(text, "set=crowdsec") {
		t.Fatalf("dynamic CrowdSec misrepresented as a static set:\n%s", text)
	}
	// These are actual CLI responses, not regenerated display strings. The JSON
	// is small (three policies), and text evidence is limited to relevant lines.
	t.Logf("phase=%s actual status --json: %s", phase, strings.TrimSpace(string(output)))
	for _, line := range lines {
		if strings.Contains(line, "Compiled firewall sets") || strings.Contains(line, "family=") || strings.Contains(line, "Dynamic CrowdSec memberships excluded") {
			t.Logf("phase=%s actual status: %s", phase, line)
		}
	}
	return status
}

func waitStatusDecisions(t *testing.T, v4, v6 uint64) control.StatusResult {
	t.Helper()
	var last control.StatusResult
	waitCrowdCondition(t, fmt.Sprintf("status decisions ipv4=%d ipv6=%d", v4, v6), func() bool {
		last = largeCrowdStatus(t)
		if !last.Successful() || last.Applied.Details == nil {
			return false
		}
		crowd := last.Applied.Details.CrowdSec
		return crowd.Enabled && crowd.Validity == "valid" && crowd.Counts != nil && crowd.Counts.IPv4 == v4 && crowd.Counts.IPv6 == v6
	})
	return last
}

func TestE2EStatusCompiledSets(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, backend := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(backend, func(t *testing.T) {
				t.Logf("%s", runIsolated(t, "TestE2EStatusCompiledSets", backend))
			})
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	command(t, 10*time.Second, "ip", "link", "set", "lo", "up")
	backend := lookupBackendScenario(t)
	if backend == "iptables" {
		seedIPTablesParents(t)
	}
	crowd, server := newStatusSources(t)
	// Duplicate decisions for one address prove these are decision counts,
	// unlike normalized compiled static prefix memberships.
	crowd.set(1, "8.40.0.2", time.Hour)
	crowd.set(2, "8.40.0.2", time.Hour)
	crowd.set(3, "2600:40::2", time.Hour)
	key := tempConfig(t, "status-crowd-key")
	if err := os.WriteFile(key, []byte(crowdFixtureKey), 0o600); err != nil {
		t.Fatal(err)
	}
	path := tempConfig(t, "status-compiled")
	table := fmt.Sprintf("pde2e_status_%d", os.Getpid())
	writeStatusConfig(t, path, backend, table, server.URL, key, "US")
	start := func() *daemonProcess {
		return startDaemonCommand(t, capacityCommand(path, server.URL), "compiled status native daemon", func() bool {
			return activeRevision() != ""
		}, 45*time.Second)
	}
	daemon := start()
	waitStatusDecisions(t, 2, 1)
	initial := assertStatusCLI(t, "initial", false)
	port := uint16(18480)
	waitForLookupVerdict(t, "8.40.0.2", "ingress", "tcp", &port, "blocked")

	writeStatusConfig(t, path, backend, table, server.URL, key, "DE")
	reloadOutput := command(t, 90*time.Second, e2eBinary(t), "reload")
	t.Logf("actual reload: %s", strings.TrimSpace(string(reloadOutput)))
	reloaded := assertStatusCLI(t, "reloaded", true)
	if reloaded.Applied.Revision == initial.Applied.Revision {
		t.Fatal("policy selection changed counts without changing acknowledged revision")
	}

	daemon.stop(t)
	daemon = start()
	waitStatusDecisions(t, 2, 1)
	restarted := assertStatusCLI(t, "restarted", true)
	// Startup recovers durable state and may reapply the current configuration;
	// require its published summary to match the new acknowledged durable target,
	// rather than assuming that startup must retain the old revision identifier.
	if revision := capacityReadRevision(t); restarted.Applied.Revision != revision.ID {
		t.Fatalf("restart status revision = %q, durable target = %q", restarted.Applied.Revision, revision.ID)
	}
	if !reflect.DeepEqual(restarted.Applied.Details.CompiledSets, reloaded.Applied.Details.CompiledSets) {
		t.Fatal("restart did not reconstruct the acknowledged compiled summary")
	}

	crowd.remove(1)
	crowd.remove(2)
	crowd.set(4, "2600:40::2", time.Hour)
	updated := waitStatusDecisions(t, 0, 2)
	if updated.Applied.Revision != restarted.Applied.Revision || !reflect.DeepEqual(updated.Applied.Details.CompiledSets, restarted.Applied.Details.CompiledSets) {
		t.Fatal("dynamic-only publication changed static revision or compiled memberships")
	}
	if updated.Applied.Details.CrowdSec.Operation <= restarted.Applied.Details.CrowdSec.Operation {
		t.Fatal("dynamic decisions changed without an acknowledged CrowdSec operation")
	}
	waitForLookupVerdict(t, "8.40.0.2", "ingress", "tcp", &port, "not_blocked")
	assertStatusCLI(t, "dynamic-update", true)
	_, unauthorized, badRequest := crowd.counters()
	if unauthorized != 0 || badRequest {
		t.Fatalf("invalid local LAPI interaction: unauthorized=%d bad_request=%t", unauthorized, badRequest)
	}
	daemon.stop(t)
}
