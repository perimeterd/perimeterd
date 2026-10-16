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
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/app"
	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
	"github.com/perimeterd/perimeterd/internal/state"
	"github.com/perimeterd/perimeterd/internal/testutil/historicalfixture"
)

// This helper uses the production native router, journal and control server.
// Only the HTTP transport and exact crash/error boundary are injected.
func TestE2ESharedPolicyDaemonHelper(t *testing.T) {
	if os.Getenv("PERIMETERD_SHARED_HELPER") != "1" {
		return
	}
	endpoint, err := url.Parse(os.Getenv("PERIMETERD_SHARED_SOURCE"))
	if err != nil {
		t.Fatal(err)
	}
	armed := false
	err = app.Run(context.Background(), app.Options{
		ConfigPath:     os.Getenv("PERIMETERD_SHARED_CONFIG"),
		SourceClient:   &http.Client{Transport: capacityTransport{local: endpoint}},
		Stderr:         os.Stderr,
		StartupTimeout: 20 * time.Second,
		Checkpoint: func(label string) error {
			if label == "after-prepare" {
				armed = true
			}
			if armed && label == "after-switch" {
				failure := os.Getenv("PERIMETERD_SHARED_FAILURE_FILE")
				if failure != "" {
					if _, err := os.Stat(failure); err == nil { // #nosec G703 -- marker belongs to this isolated test's private directory.
						if err := os.Remove(failure); err != nil { // #nosec G703 -- removes only the private failure marker.
							return err
						}
						return errors.New("shared-policy injected reload failure")
					}
				}
			}
			if armed && label == os.Getenv("PERIMETERD_SHARED_CHECKPOINT") {
				if os.Getenv("PERIMETERD_SHARED_ERROR") == "1" {
					return errors.New("shared-policy injected transition failure")
				}
				os.Exit(97)
			}
			return nil
		},
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(98)
	}
}

func sharedPolicyCommand(path, endpoint, checkpoint string, fail bool) *exec.Cmd {
	// #nosec G204 G702 -- re-executes this compiled isolated test harness.
	cmd := exec.Command(os.Args[0], "-test.run", "^TestE2ESharedPolicyDaemonHelper$", "-test.v")
	cmd.Env = append(os.Environ(), "PERIMETERD_SHARED_HELPER=1", "PERIMETERD_SHARED_CONFIG="+path, "PERIMETERD_SHARED_SOURCE="+endpoint, "PERIMETERD_SHARED_CHECKPOINT="+checkpoint)
	if fail {
		cmd.Env = append(cmd.Env, "PERIMETERD_SHARED_ERROR=1")
	}
	return cmd
}

func sharedPolicySources(t *testing.T) *httptest.Server {
	t.Helper()
	records := historicalfixture.Records()
	// US differs only in IPv6, testing independent family equivalence classes.
	records = append(records, policy.ResolvedSelector{Selector: policy.Selector{Kind: policy.Country, Value: "US"}, IPv4: records[0].IPv4, IPv6: append(records[0].IPv6, records[1].IPv6...)})
	countries := map[string][]byte{}
	for _, record := range records {
		v4, v6 := []string{}, []string{}
		for _, prefix := range record.IPv4 {
			v4 = append(v4, prefix.String())
		}
		for _, prefix := range record.IPv6 {
			v6 = append(v6, prefix.String())
		}
		body, err := json.Marshal(map[string]any{"version": "0.2", "data_call_name": "country-resource-list", "data_call_status": "supported", "status": "ok", "status_code": 200, "time": "2026-09-14T00:00:00Z", "data": map[string]any{"query_time": "2026-09-13T00:00:00", "resources": map[string]any{"ipv4": v4, "ipv6": v6}}})
		if err != nil {
			t.Fatal(err)
		}
		countries[record.Selector.Value] = body
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/country" {
			body, ok := countries[r.URL.Query().Get("resource")]
			if !ok {
				w.WriteHeader(http.StatusBadRequest)
				return
			}
			_, _ = w.Write(body)
			return
		}
		if r.URL.Path == "/v1/decisions/stream" && r.Header.Get("X-Api-Key") == crowdFixtureKey {
			_, _ = w.Write([]byte(`{"new":[],"deleted":[]}`))
			return
		}
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(server.Close)
	return server
}

func sharedPolicyWrite(t *testing.T, path, backend, endpoint, key, egress string, remove bool) config.Config {
	t.Helper()
	text := fmt.Sprintf(`version: 1
metrics:
  listen: ""
firewall:
  backend: %s
  deny_action: drop
  ipv4: true
  ipv6: true
  nftables:
    table: perimeterd
    priority: -10
  iptables:
    attachments:
      - chain: INPUT
        direction: ingress
      - chain: OUTPUT
        direction: egress
crowdsec:
  enabled: true
  lapi_url: %q
  api_key_file: %q
policies:
  - name: ssh
    direction: ingress
    priority: 10
    mode: allowlist
    traffic: ['22']
    include:
      countries: [SK]
  - name: ingress
    direction: ingress
    priority: 100
    mode: allowlist
    traffic: [any]
    include:
      countries: [CZ]
`, backend, endpoint, key)
	if !remove {
		text += fmt.Sprintf(`  - name: egress
    direction: egress
    priority: 100
    mode: allowlist
    traffic: [any]
    include:
      countries: [%s]
`, egress)
	}
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil { // #nosec G703 -- private namespace policy fixture.
		t.Fatal(err)
	}
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func sharedPolicySeed(t *testing.T, cfg config.Config, path string) (*state.Store, *state.Revision) {
	t.Helper()
	store, err := state.Open("/var/lib/perimeterd", nil)
	if err != nil {
		t.Fatal(err)
	}
	records := []source.Record{}
	now := time.Now().UTC()
	for _, record := range historicalfixture.Records() {
		records = append(records, source.Record{Selector: record.Selector, Endpoint: "https://stat.ripe.net/data/country-resource-list/data.json", APIVersion: "0.2", Parameters: map[string]string{"resource": record.Selector.Value, "sourceapp": "perimeterd", "v4_format": "prefix"}, QueryStart: now, QueryEnd: now, RetrievedAt: now, IPv4: record.IPv4, IPv6: record.IPv6})
	}
	snapshot, err := store.Prefixes().Stage(records)
	if err != nil {
		t.Fatal(err)
	}
	target, err := historicalfixture.Target(cfg.Firewall.Backend, store.Owner())
	if err != nil {
		t.Fatal(err)
	}
	revision := &state.Revision{Version: 2, ID: target.Generation, Epoch: 1, Manifest: snapshot.ManifestID(), ConfigPath: path, Config: cfg, Target: target}
	if err := store.Prepare(nil, revision); err != nil {
		t.Fatal(err)
	}
	var native firewall.Backend = firewall.NewNFT()
	if target.Backend() == "iptables" {
		native = firewall.NewIPTables(nil)
	}
	if err := native.Preflight(context.Background(), nil, target, nil); err != nil {
		t.Fatal(err)
	}
	if err := native.Apply(context.Background(), nil, target, nil); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(revision); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(); err != nil {
		t.Fatal(err)
	}
	return store, revision
}

// Count the real isolated inventory, not hypothetical compiler object savings.
// Exact counts detect old generation orphans, including unreferenced ipsets.
func sharedPolicyNative(t *testing.T, target *firewall.Target) {
	t.Helper()
	want := 0
	for _, family := range target.Families {
		want += len(family.Sets)
	}
	if target.Backend() == "nftables" {
		data := command(t, 10*time.Second, "nft", "-j", "list", "table", "inet", target.Table)
		var inventory struct {
			Objects []map[string]json.RawMessage `json:"nftables"`
		}
		if err := json.Unmarshal(data, &inventory); err != nil {
			t.Fatal(err)
		}
		sets := map[string]bool{}
		chains, counters := 0, 0
		for _, object := range inventory.Objects {
			if _, ok := object["chain"]; ok {
				chains++
			}
			if _, ok := object["counter"]; ok {
				counters++
			}
			if raw, ok := object["set"]; ok {
				var set struct {
					Name string `json:"name"`
				}
				if err := json.Unmarshal(raw, &set); err != nil {
					t.Fatal(err)
				}
				sets[set.Name] = true
			}
		}
		if len(sets) != want {
			t.Fatalf("native nft sets=%d want=%d: %s", len(sets), want, data)
		}
		// Two generation and two stable entry chains per family, two hooks,
		// and the stable ownership witness. Counter identities remain distinct.
		if chains != 4*len(target.Families)+3 || counters != len(target.Counters) {
			t.Fatalf("orphan nft objects: chains=%d counters=%d", chains, counters)
		}
		for name := range sets {
			if !strings.Contains(string(data), `"@`+name+`"`) {
				// nft JSON serializes named references as either @name or a set object.
				if !strings.Contains(string(data), `"set":"`+name+`"`) && !strings.Contains(strings.ReplaceAll(string(data), " ", ""), `"right":"@`+name+`"`) {
					t.Fatalf("unreferenced native set %s", name)
				}
			}
		}
	} else {
		names := strings.Fields(string(command(t, 10*time.Second, "ipset", "list", "-name")))
		if len(names) != want {
			t.Fatalf("native ipsets=%d want=%d: %v", len(names), want, names)
		}
		for _, family := range []string{"v4", "v6"} {
			saved, err := iptablesSaveMayFail(family)
			if err != nil {
				t.Fatal(err)
			}
			chains := 0
			for _, line := range strings.Split(string(saved), "\n") {
				if strings.HasPrefix(line, ":pdc") {
					chains++
				}
			}
			// These fixtures have two unfiltered attachment profiles: one
			// generation and one stable entry chain for each direction.
			if chains != 4 {
				t.Fatalf("orphan %s iptables chains: %d\n%s", family, chains, saved)
			}
			for _, name := range names {
				if strings.HasPrefix(name, "pd"+family) && !strings.Contains(string(saved), "--match-set "+name+" ") {
					t.Fatalf("orphan native set %s", name)
				}
			}
		}
	}
}

func sharedPolicyStatus(t *testing.T, geo4, geo6 int, representative string) *state.Revision {
	t.Helper()
	status := largeCrowdStatus(t)
	if !status.Daemon.Healthy || status.Applied.Details == nil {
		t.Fatalf("shared status unhealthy: %#v", status)
	}
	revision := capacityReadRevision(t)
	want := map[string][]string{}
	counts := map[policy.Family]int{}
	wantCounts := map[string]uint64{}
	wantTotals := map[string]uint64{}
	for _, family := range revision.Target.Families {
		for _, set := range family.Sets {
			if strings.HasPrefix(set.ID, "geo/") {
				counts[family.Family]++
			}
			key := fmt.Sprintf("ipv%d/%s", family.Family, set.ID)
			if set.Kind != policy.StaticSet {
				continue
			}
			wantCounts[key] = uint64(len(set.Prefixes))
			wantTotals[fmt.Sprintf("ipv%d", family.Family)] += uint64(len(set.Prefixes))
			consumers := map[string]bool{}
			for _, path := range family.Paths {
				for _, rule := range path.Rules {
					if rule.Match.SetID == set.ID && rule.Policy != "" {
						consumers[rule.Policy] = true
					}
				}
			}
			want[key] = []string{}
			for consumer := range consumers {
				want[key] = append(want[key], consumer)
			}
			sort.Strings(want[key])
		}
	}
	if counts[policy.IPv4] != geo4 || counts[policy.IPv6] != geo6 {
		t.Fatalf("geo objects=%v want=%d/%d", counts, geo4, geo6)
	}
	got := map[string][]string{}
	for _, row := range status.Applied.Details.CompiledSets.Sets {
		key := row.Family + "/" + row.ID
		got[key] = row.Policies
		if count, ok := wantCounts[key]; !ok || count != row.Count {
			t.Fatalf("static membership count for %s = %d want %d", key, row.Count, count)
		}
	}
	for _, total := range status.Applied.Details.CompiledSets.Totals {
		if total.Count != wantTotals[total.Family] {
			t.Fatalf("shared family total %s = %d want %d", total.Family, total.Count, wantTotals[total.Family])
		}
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("native acknowledged consumers=%v want=%v", got, want)
	}
	if representative != "" {
		for _, family := range []string{"ipv4", "ipv6"} {
			if !reflect.DeepEqual(got[family+"/geo/"+representative], []string{"egress", "ingress"}) {
				t.Fatalf("missing shared consumers: %v", got)
			}
		}
	}
	text := string(command(t, 10*time.Second, e2eBinary(t), "status"))
	if !strings.Contains(text, "shared sets counted once") || !strings.Contains(text, "policies=") {
		t.Fatalf("human shared status missing consumers: %s", text)
	}
	sharedPolicyNative(t, revision.Target)
	return revision
}

func sharedPolicyPackets(t *testing.T, peer *peerNamespace, egress4, egress6 string, removed bool) {
	t.Helper()
	for _, network := range []string{"tcp4", "tcp6"} {
		host, remote, missHost, missRemote := "8.20.0.1", "8.20.0.2", "8.21.0.1", "8.21.0.2"
		allow := egress4
		if network == "tcp6" {
			host, remote, missHost, missRemote, allow = "[2600:20::1]", "[2600:20::2]", "[2600:21::1]", "[2600:21::2]", egress6
		}
		probeIngress(t, peer, network, host+":18980", "success", "tcp")
		probeIngress(t, peer, network, missHost+":18980", "drop", "tcp")
		probeIngress(t, peer, network, host+":22", "drop", "tcp")
		probeIngress(t, peer, network, missHost+":22", "success", "tcp")
		other := "drop"
		if allow == "both" || removed {
			other = "success"
		}
		if allow == "both" {
			allow = "success"
		}
		probeEgress(t, peer, network, remote+":18981", allow, "tcp")
		probeEgress(t, peer, network, missRemote+":18981", other, "tcp")
		unknownHost, unknownRemote := "8.22.0.1", "8.22.0.2"
		if network == "tcp6" {
			unknownHost, unknownRemote = "[2600:22::1]", "[2600:22::2]"
		}
		probeIngress(t, peer, network, unknownHost+":18980", "drop", "tcp")
		unknownEgress := "drop"
		if removed {
			unknownEgress = "success"
		}
		probeEgress(t, peer, network, unknownRemote+":18981", unknownEgress, "tcp")
	}
}

func TestE2ESharedPolicyLifecycle(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, backend := range []string{"nftables", "nft", "legacy"} {
			t.Run(backend, func(t *testing.T) { t.Logf("%s", runIsolated(t, "TestE2ESharedPolicyLifecycle", backend)) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	backend := os.Getenv(e2eScenario)
	if backend != "nftables" {
		installIPTablesTools(t, backend)
		seedIPTablesParents(t)
		backend = "iptables"
	}
	peer := newPeerNamespace(t)
	command(t, 10*time.Second, "ip", "addr", "add", "8.21.0.1/24", "dev", "e2h0")
	peer.run(t, "ip", "addr", "add", "8.21.0.2/24", "dev", "e2p0")
	command(t, 10*time.Second, "ip", "-6", "addr", "add", "2600:21::1/64", "dev", "e2h0", "nodad")
	peer.run(t, "ip", "-6", "addr", "add", "2600:21::2/64", "dev", "e2p0", "nodad")
	command(t, 10*time.Second, "ip", "addr", "add", "8.22.0.1/24", "dev", "e2h0")
	peer.run(t, "ip", "addr", "add", "8.22.0.2/24", "dev", "e2p0")
	command(t, 10*time.Second, "ip", "-6", "addr", "add", "2600:22::1/64", "dev", "e2h0", "nodad")
	peer.run(t, "ip", "-6", "addr", "add", "2600:22::2/64", "dev", "e2p0", "nodad")
	server := sharedPolicySources(t)
	key, path := tempConfig(t, "shared-key"), tempConfig(t, "shared-policy")
	if err := os.WriteFile(key, []byte(crowdFixtureKey), 0o600); err != nil {
		t.Fatal(err)
	}
	write := func(country string, remove bool) config.Config {
		return sharedPolicyWrite(t, path, backend, server.URL, key, country, remove)
	}
	cfg := write("CZ", false)
	store, historical := sharedPolicySeed(t, cfg, path)
	revisionPath := filepath.Join("/var/lib/perimeterd/revisions", historical.ID+".json")
	recorded, err := os.ReadFile(revisionPath) // #nosec G304 -- private immutable historical revision fixture.
	if err != nil {
		t.Fatal(err)
	}
	sharedPolicyNative(t, historical.Target)
	sharedPolicyPackets(t, peer, "success", "success", false)
	// A same-ID prepared journal must restore the actual recorded duplicate sets.
	if err := store.Prepare(historical, historical); err != nil {
		t.Fatal(err)
	}
	writeInvalidConfig(t, path)
	if output, err := sharedPolicyCommand(path, server.URL, "", false).CombinedOutput(); !exitStatus(err, 98) {
		t.Fatalf("historical same-ID recovery: %v\n%s", err, output)
	}
	sharedPolicyNative(t, historical.Target)
	write("CZ", false)
	// Failed migration compensates to the recorded historical representation.
	if output, err := sharedPolicyCommand(path, server.URL, "after-switch", true).CombinedOutput(); !exitStatus(err, 98) {
		t.Fatalf("migration rollback: %v\n%s", err, output)
	}
	sharedPolicyNative(t, historical.Target)
	sharedPolicyPackets(t, peer, "success", "success", false)
	checkpoints := []string{"after-prepare", "after-switch"}
	if backend == "iptables" {
		checkpoints = append(checkpoints, "iptables-after-switch-v4")
	}
	for _, checkpoint := range checkpoints {
		write("CZ", false)
		if output, err := sharedPolicyCommand(path, server.URL, checkpoint, false).CombinedOutput(); !exitStatus(err, 97) {
			t.Fatalf("migration crash at %s: %v\n%s", checkpoint, err, output)
		}
		writeInvalidConfig(t, path)
		if output, err := sharedPolicyCommand(path, server.URL, "", false).CombinedOutput(); !exitStatus(err, 98) {
			t.Fatalf("migration recovery at %s: %v\n%s", checkpoint, err, output)
		}
		sharedPolicyNative(t, historical.Target)
		sharedPolicyPackets(t, peer, "success", "success", false)
		if current, err := os.ReadFile(revisionPath); err != nil || string(current) != string(recorded) { // #nosec G304 -- private immutable historical revision fixture.
			t.Fatalf("recovery rewrote historical durable revision: %v", err)
		}
	}
	write("CZ", false)
	// A durable commit interrupted before retirement retains the shared target.
	if output, err := sharedPolicyCommand(path, server.URL, "after-commit", false).CombinedOutput(); !exitStatus(err, 97) {
		t.Fatalf("committed migration crash: %v\n%s", err, output)
	}
	failureFile := filepath.Join(t.TempDir(), "reload-failure")
	t.Setenv("PERIMETERD_SHARED_FAILURE_FILE", failureFile)
	start := func() *daemonProcess {
		return startDaemonCommand(t, sharedPolicyCommand(path, server.URL, "", false), "shared policy native daemon", func() bool { return activeRevision() != "" }, 45*time.Second)
	}
	daemon := start()
	sharedPolicyStatus(t, 2, 2, "egress")
	sharedPolicyPackets(t, peer, "success", "success", false)
	// Retirement may remove the obsolete record, but must never rewrite it.
	if current, err := os.ReadFile(revisionPath); err == nil && string(current) != string(recorded) || err != nil && !os.IsNotExist(err) { // #nosec G304 -- private immutable historical revision fixture.
		t.Fatalf("migration rewrote historical durable revision: %v", err)
	}
	beforeFailure := waitStatusDecisions(t, 0, 0)
	write("CZ, SK", false)
	if err := os.WriteFile(failureFile, []byte("fail once"), 0o600); err != nil {
		t.Fatal(err)
	}
	if output, err := commandMayFail(45*time.Second, e2eBinary(t), "reload"); err == nil {
		t.Fatalf("injected post-switch reload succeeded: %s", output)
	}
	// Failed replacement restarts the retained CrowdSec cursor. Its native
	// reconciliation briefly fences queries, especially across iptables families.
	afterFailure := waitStatusDecisions(t, 0, 0)
	if afterFailure.Applied.Details == nil || afterFailure.Applied.Revision != beforeFailure.Applied.Revision || !reflect.DeepEqual(afterFailure.Applied.Details.CompiledSets, beforeFailure.Applied.Details.CompiledSets) || !reflect.DeepEqual(afterFailure.Applied.Details.PrefixCounts, beforeFailure.Applied.Details.PrefixCounts) {
		t.Fatalf("failed split changed acknowledged status: before=%#v after=%#v", beforeFailure.Applied, afterFailure.Applied)
	}
	sharedPolicyStatus(t, 2, 2, "egress")
	sharedPolicyPackets(t, peer, "success", "success", false)
	write("CZ", false)
	// Reload acknowledgement already guarantees status and native publication.
	for _, step := range []struct {
		country                string
		geo4, geo6             int
		v4, v6, representative string
	}{
		{"CZ, SK", 3, 3, "both", "both", ""},
		{"CZ", 2, 2, "success", "success", "egress"},
		{"US", 2, 3, "success", "both", ""}, // IPv4 shares, IPv6 materializes a distinct union.
		{"CZ", 2, 2, "success", "success", "egress"},
	} {
		write(step.country, false)
		command(t, 45*time.Second, e2eBinary(t), "reload")
		sharedPolicyStatus(t, step.geo4, step.geo6, step.representative)
		sharedPolicyPackets(t, peer, step.v4, step.v6, false)
	}
	// Removing lexicographic representative egress must not delete ingress data.
	write("CZ", true)
	command(t, 45*time.Second, e2eBinary(t), "reload")
	sharedPolicyStatus(t, 2, 2, "")
	sharedPolicyPackets(t, peer, "success", "success", true)
	write("CZ", false)
	command(t, 45*time.Second, e2eBinary(t), "reload")
	beforeReload := sharedPolicyStatus(t, 2, 2, "egress")
	command(t, 45*time.Second, e2eBinary(t), "reload")
	current := sharedPolicyStatus(t, 2, 2, "egress")
	if !reflect.DeepEqual(current.Target.Families, beforeReload.Target.Families) {
		t.Fatal("unchanged reload changed shared policy membership or rules")
	}
	if current.Target.Backend() == "nftables" && current.Target.Generation != beforeReload.Target.Generation {
		t.Fatal("unchanged nft reload replaced shared native generation")
	}
	// iptables retains its existing replacement-authority container contract.
	if current.Target.Backend() == "iptables" && current.Target.DynamicGeneration == beforeReload.Target.DynamicGeneration {
		t.Fatal("iptables reload reused the replaced CrowdSec authority container")
	}
	daemon.stop(t)
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Prepare(view.Active, view.Active); err != nil {
		t.Fatal(err)
	}
	daemon = start()
	sharedPolicyStatus(t, 2, 2, "egress")
	sharedPolicyPackets(t, peer, "success", "success", false)
	daemon.stop(t)
}
