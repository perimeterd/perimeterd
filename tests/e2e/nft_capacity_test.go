//go:build linux && e2e

package e2e

import (
	"bufio"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/app"
	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
	"github.com/perimeterd/perimeterd/internal/state"
	"github.com/perimeterd/perimeterd/internal/testutil/capacityfixture"
	"github.com/perimeterd/perimeterd/internal/testutil/crowdsecfixture"
)

const capacityHelper = "PERIMETERD_CAPACITY_HELPER"

// capacityTransport redirects only the fixed country source. LAPI requests use
// the configured loopback server. No live source or production endpoint is used.
type capacityTransport struct{ local *url.URL }

func (c capacityTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if strings.Contains(request.URL.Path, "country-resource-list") {
		forwarded := request.Clone(request.Context())
		endpoint := *c.local
		endpoint.Path = "/country"
		endpoint.RawQuery = request.URL.RawQuery
		forwarded.URL, forwarded.Host = &endpoint, endpoint.Host
		return http.DefaultTransport.RoundTrip(forwarded)
	}
	if request.URL.Host != c.local.Host {
		return nil, errors.New("capacity fixture refuses external source")
	}
	return http.DefaultTransport.RoundTrip(request)
}

// This separate process runs the production daemon entrypoint and native backend.
// The only injection is source transport, the same public seam as other E2Es.
func TestE2ECapacityDaemonHelper(t *testing.T) {
	if os.Getenv(capacityHelper) != "1" {
		return
	}
	endpoint, err := url.Parse(os.Getenv("PERIMETERD_CAPACITY_SOURCE"))
	if err != nil {
		t.Fatal(err)
	}
	stateDir := os.Getenv("PERIMETERD_CAPACITY_STATE")
	if stateDir == "" {
		stateDir = "/var/lib/perimeterd"
	}
	lockPath := os.Getenv("PERIMETERD_CAPACITY_LOCK")
	if lockPath == "" {
		lockPath = "/run/perimeterd/owner.lock"
	}
	checkpoint := os.Getenv("PERIMETERD_CAPACITY_CRASH")
	err = app.Run(context.Background(), app.Options{
		ConfigPath:   os.Getenv("PERIMETERD_CAPACITY_CONFIG"),
		StateDir:     stateDir,
		LockPath:     lockPath,
		SourceClient: &http.Client{Transport: capacityTransport{local: endpoint}},
		Stderr:       os.Stderr,
		Checkpoint: func(label string) error {
			if checkpoint != "" && checkpoint == label {
				os.Exit(97)
			}
			if label == "after-switch" {
				if marker := os.Getenv("PERIMETERD_CAPACITY_FAIL_FILE"); marker != "" {
					if _, err := os.Stat(marker); err == nil { // #nosec G703 -- marker is created by this private namespace fixture.
						if err := os.Remove(marker); err != nil { // #nosec G703 -- removes only that fixture-owned marker.
							return err
						}
						return errors.New("injected capacity reload failure after native switch")
					}
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

type capacitySources struct {
	mu          sync.Mutex
	countries   [2]map[string][]byte
	refresh     bool
	deletePeers bool
	deleted     bool
	bytes       int64
	until       time.Time
}

func newCapacitySources(t *testing.T) (*capacitySources, *httptest.Server) {
	t.Helper()
	f := &capacitySources{until: time.Now().Add(2 * time.Hour)}
	for variant := range 2 {
		f.countries[variant] = make(map[string][]byte)
		for _, record := range capacityfixture.Records(variant == 1) {
			v4, v6 := make([]string, 0, len(record.IPv4)), make([]string, 0, len(record.IPv6))
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
			f.countries[variant][record.Selector.Value] = body
		}
	}
	server := httptest.NewServer(http.HandlerFunc(f.serve))
	t.Cleanup(server.Close)
	return f, server
}

func (f *capacitySources) serve(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	f.mu.Lock()
	if r.URL.Path == "/country" {
		variant := 0
		if f.refresh {
			variant = 1
		}
		body, ok := f.countries[variant][r.URL.Query().Get("resource")]
		f.mu.Unlock()
		if !ok {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write(body)
		return
	}
	if r.URL.Path != "/v1/decisions/stream" || r.Header.Get("X-Api-Key") != crowdFixtureKey {
		f.mu.Unlock()
		w.WriteHeader(http.StatusForbidden)
		return
	}
	deletePeers := f.deletePeers
	if r.URL.Query().Get("startup") == "true" {
		f.deleted = deletePeers
		f.mu.Unlock()
		buffer := bufio.NewWriterSize(w, 32<<10)
		snapshot := crowdsecfixture.Snapshot{Count: crowdsecfixture.LargeCount, Until: f.until, IPv4: "8.22.0.2", IPv6: "2600:22::2"}
		// Snapshot remains a genuine >98MB full stream on every restart. The
		// later deletion delta changes dynamic authority independently of geo.
		n, err := io.Copy(buffer, snapshot.Reader())
		if err != nil {
			return
		}
		if err := buffer.Flush(); err != nil {
			return
		}
		f.mu.Lock()
		f.bytes = n
		f.deleted = false
		f.mu.Unlock()
		return
	}
	if deletePeers && !f.deleted {
		f.deleted = true
		f.mu.Unlock()
		_, _ = io.WriteString(w, `{"new":[],"deleted":[{"id":1},{"id":2}]}`)
		return
	}
	f.mu.Unlock()
	_, _ = io.WriteString(w, `{"new":[],"deleted":[]}`)
}

func capacityCommand(configPath, sourceURL string, extra ...string) *exec.Cmd {
	// #nosec G204 G702 -- this isolated harness re-executes its own compiled test binary.
	cmd := exec.Command(os.Args[0], "-test.run", "^TestE2ECapacityDaemonHelper$", "-test.v")
	cmd.Env = append(os.Environ(), capacityHelper+"=1", "PERIMETERD_CAPACITY_CONFIG="+configPath, "PERIMETERD_CAPACITY_SOURCE="+sourceURL)
	cmd.Env = append(cmd.Env, extra...)
	return cmd
}

func capacityReadRevision(t *testing.T) *state.Revision {
	t.Helper()
	var active struct {
		Payload struct {
			ID string `json:"id"`
		} `json:"payload"`
	}
	if err := json.Unmarshal([]byte(activeRevision()), &active); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join("/var/lib/perimeterd/revisions", active.Payload.ID+".json"))
	if err != nil {
		t.Fatal(err)
	}
	var revision struct {
		Payload state.Revision `json:"payload"`
	}
	if err := json.Unmarshal(data, &revision); err != nil {
		t.Fatal(err)
	}
	return &revision.Payload
}

func capacityAssertState(t *testing.T, ssh bool) *state.Revision {
	t.Helper()
	var revision *state.Revision
	deadline := time.Now().Add(3 * time.Minute)
	for {
		status := largeCrowdStatus(t)
		if status.Daemon.Healthy && status.Applied.Revision != "" {
			revision = capacityReadRevision(t)
			if status.Applied.Revision == revision.ID {
				break
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("no acknowledged production revision: %+v", status)
		}
		time.Sleep(200 * time.Millisecond)
	}
	wantPolicies := 2
	if ssh {
		wantPolicies = 3
	}
	if len(revision.Config.Policies) != wantPolicies {
		t.Fatalf("persisted policies=%d, want %d", len(revision.Config.Policies), wantPolicies)
	}
	total, counts := capacityfixture.Memberships(revision.Target.Families)
	if err := capacityfixture.ValidateShared(revision.Target.Families, ssh); err != nil {
		t.Fatal(err)
	}
	capacityAssertStatusAndNative(t, revision, false)
	t.Logf("applied=%s static-generation=%s dynamic-generation=%s memberships=%d per-set=%v", revision.ID, revision.Target.Generation, revision.Target.DynamicGeneration, total, counts)
	return revision
}

func capacityMeasure(t *testing.T, daemon *daemonProcess, table, phase string, started time.Time) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// #nosec G204 -- table comes from the fixed local fixture in verified private namespaces.
	cmd := exec.CommandContext(ctx, "nft", "-j", "list", "table", "inet", table)
	inventory, err := cmd.Output()
	if err != nil {
		t.Fatal(err)
	}
	usage := cmd.ProcessState.SysUsage().(*syscall.Rusage)
	var envelope struct {
		Nftables []struct {
			Set *struct {
				Flags []string          `json:"flags"`
				Elem  []json.RawMessage `json:"elem"`
			} `json:"set"`
		} `json:"nftables"`
	}
	if err := json.Unmarshal(inventory, &envelope); err != nil {
		t.Fatal(err)
	}
	projection := 0
	for _, object := range envelope.Nftables {
		if object.Set != nil {
			for _, flag := range object.Set.Flags {
				if flag == "timeout" {
					projection += len(object.Set.Elem)
				}
			}
		}
	}
	t.Logf("phase=%s wall=%s native-inventory-bytes=%d actual-native-dynamic-elements=%d inspection-user=%s inspection-system=%s inspection-maxrss-kib=%d", phase, time.Since(started), len(inventory), projection, cmd.ProcessState.UserTime(), cmd.ProcessState.SystemTime(), usage.Maxrss)
	t.Log("inspection child rusage maxrss may include inherited pre-exec fixture-generator RSS; daemon VmHWM below is sampled after exec")
	if daemon != nil {
		data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", daemon.cmd.Process.Pid))
		if err != nil {
			t.Fatal(err)
		}
		for _, line := range strings.Split(string(data), "\n") {
			if strings.HasPrefix(line, "VmHWM:") {
				t.Logf("phase=%s daemon-only-%s (fixture generator is separate parent process)", phase, line)
			}
		}
		data, err = os.ReadFile(fmt.Sprintf("/proc/%d/stat", daemon.cmd.Process.Pid))
		if err != nil {
			t.Fatal(err)
		}
		fields := strings.Fields(string(data))
		if len(fields) > 14 {
			t.Logf("phase=%s daemon-user-ticks=%s daemon-system-ticks=%s", phase, fields[13], fields[14])
		}
	}
}

func capacityPackets(t *testing.T, peer *peerNamespace, ssh, banned, udpSSH bool) {
	t.Helper()
	for _, network := range []string{"tcp4", "tcp6"} {
		for _, subnet := range []string{"20", "21", "22", "23"} {
			host := "8." + subnet + ".0.1"
			remote := "8." + subnet + ".0.2"
			if network == "tcp6" {
				host = "[2600:" + subnet + "::1]"
				remote = "[2600:" + subnet + "::2]"
			}
			allow := "success"
			if subnet == "23" || (banned && subnet == "22") {
				allow = "drop"
			}
			sshAllow := allow
			if ssh && subnet == "22" {
				sshAllow = "drop"
			}
			probeIngress(t, peer, network, host+":22", sshAllow, "tcp")
			udpAllow := allow
			if udpSSH && subnet == "22" {
				udpAllow = "drop"
			}
			probeIngress(t, peer, strings.Replace(network, "tcp", "udp", 1), host+":22", udpAllow, "udp")
			probeIngress(t, peer, network, host+":18880", allow, "tcp")
			// CrowdSec only guards ingress; egress still follows the broader group.
			egress := "success"
			if subnet == "23" {
				egress = "drop"
			}
			probeEgress(t, peer, network, remote+":18881", egress, "tcp")
		}
	}
	probeIngress(t, peer, "tcp4", fixtureLANHost+":18882", "success", "tcp")
}

func TestE2ENFTProductionCapacity(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		t.Logf("%s", runIsolated(t, "TestE2ENFTProductionCapacity", "nftables"))
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	// Production-sized immutable revisions and over-budget evidence need more
	// than the default small-fixture tmpfs, still finite and private.
	if err := syscall.Mount("", "/var/lib", "", syscall.MS_REMOUNT, "size=1536m"); err != nil {
		t.Fatal(err)
	}
	peer := newPeerNamespace(t)
	for _, subnet := range []string{"21", "22", "23"} {
		command(t, 10*time.Second, "ip", "addr", "add", "8."+subnet+".0.1/24", "dev", "e2h0")
		peer.run(t, "ip", "addr", "add", "8."+subnet+".0.2/24", "dev", "e2p0")
		command(t, 10*time.Second, "ip", "-6", "addr", "add", "2600:"+subnet+"::1/64", "dev", "e2h0", "nodad")
		peer.run(t, "ip", "-6", "addr", "add", "2600:"+subnet+"::2/64", "dev", "e2p0", "nodad")
	}
	generatorStarted := time.Now()
	fixture, server := newCapacitySources(t)
	t.Logf("fixture-generation-wall=%s (fixture memory belongs to test parent, not daemon)", time.Since(generatorStarted))
	var generatorUsage syscall.Rusage
	if err := syscall.Getrusage(syscall.RUSAGE_SELF, &generatorUsage); err != nil {
		t.Fatal(err)
	}
	t.Logf("fixture-generator-maxrss-kib=%d user=%v system=%v", generatorUsage.Maxrss, generatorUsage.Utime, generatorUsage.Stime)
	configPath := tempConfig(t, "production-capacity")
	key := filepath.Join(t.TempDir(), "fixture.key")
	if err := os.WriteFile(key, []byte(crowdFixtureKey), 0o600); err != nil {
		t.Fatal(err)
	}
	table := fmt.Sprintf("production_capacity_%d", os.Getpid())
	write := func(ssh bool) {
		text := strings.Replace(capacityfixture.YAML(table, server.URL, key, ssh), "refresh_interval: 1h", "refresh_interval: 1m\n  refresh_jitter: 1ns", 1)
		if err := os.WriteFile(configPath, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	failFile := filepath.Join(t.TempDir(), "fail-after-switch")
	start := func(extra ...string) *daemonProcess {
		extra = append(extra, "PERIMETERD_CAPACITY_FAIL_FILE="+failFile)
		daemon := startDaemonCommand(t, capacityCommand(configPath, server.URL, extra...), "production capacity daemon", func() bool { return activeRevision() != "" }, 3*time.Minute)
		fixture.mu.Lock()
		deleted := fixture.deletePeers
		fixture.mu.Unlock()
		if deleted {
			waitCrowdPacket(t, peer, "tcp4", "8.22.0.1:18884", "success")
			waitCrowdPacket(t, peer, "tcp6", "[2600:22::1]:18884", "success")
		}
		return daemon
	}
	started := time.Now()
	write(true)
	historical := capacityStageHistorical(t, configPath, server.URL, peer)
	capacityMeasure(t, nil, table, "recorded-unshared-recovery", started)
	daemon := start()
	migrated := capacityAssertState(t, true)
	if migrated.Target.Generation == historical.Target.Generation {
		t.Fatal("normal startup did not migrate the recorded unshared generation")
	}
	capacityMeasure(t, daemon, table, "recorded-unshared-to-shared", started)
	capacityPackets(t, peer, true, true, true)
	write(false)
	previousInitial := activeRevision()
	initialOutput := command(t, 180*time.Second, e2eBinary(t), "reload")
	assertReloadAcknowledgement(t, previousInitial, reloadConfigDigest(t, configPath), initialOutput)
	initial := capacityAssertState(t, false)
	fixture.mu.Lock()
	size := fixture.bytes
	fixture.mu.Unlock()
	if size != 107_938_931 {
		t.Fatalf("large full LAPI stream changed: %d bytes, want 107938931", size)
	}
	status := capacityReadyStatus(t)
	counts := *status.Applied.Details.CrowdSec.Counts
	if counts.IPv4 != crowdsecfixture.LargeCount-2 || counts.IPv6 != 1 {
		t.Fatalf("unique live decision counts=%+v", counts)
	}
	t.Logf("full-LAPI-bytes=%d unique-live-IDs=%d IPv4-IDs=%d IPv6-IDs=%d (not a native prefix count)", size, counts.IPv4+counts.IPv6, counts.IPv4, counts.IPv6)
	capacityMeasure(t, daemon, table, "initial", started)
	t.Logf("exact shared geo savings=%d memberships (historical pair=%d shared=%d; unrelated=%d)", capacityfixture.GeoMemberships, 2*capacityfixture.GeoMemberships, capacityfixture.GeoMemberships, capacityfixture.UnrelatedMemberships)
	capacityPackets(t, peer, false, true, false)

	started = time.Now()
	before := activeRevision()
	write(true)
	output := command(t, 180*time.Second, e2eBinary(t), "reload", "--expect-config-sha256", reloadConfigDigest(t, configPath))
	assertReloadAcknowledgement(t, before, reloadConfigDigest(t, configPath), output)
	withSSH := capacityAssertState(t, true)
	if withSSH.Target.Generation == initial.Target.Generation {
		t.Fatal("SSH reload did not create distinct static generation")
	}
	capacityMeasure(t, daemon, table, "add-ssh", started)
	capacityPackets(t, peer, true, true, true)

	// Change only egress's effective membership, leaving ingress and SSH intact.
	started = time.Now()
	beforeSplitStatus := capacityReadyStatus(t)
	baseText, err := os.ReadFile(configPath) // #nosec G304 -- private namespace policy fixture.
	if err != nil {
		t.Fatal(err)
	}
	splitText := string(baseText)
	marker := "  - name: egress\n"
	position := strings.Index(splitText, marker)
	if position < 0 {
		t.Fatal("missing egress policy")
	}
	splitText = splitText[:position] + strings.Replace(splitText[position:], "    traffic: [any]", "    exclude:\n      countries: [CZ]\n    traffic: [any]", 1)
	if err := os.WriteFile(configPath, []byte(splitText), 0o600); err != nil { // #nosec G703 -- private namespace policy fixture.
		t.Fatal(err)
	}
	before = activeRevision()
	output = command(t, 180*time.Second, e2eBinary(t), "reload")
	assertReloadAcknowledgement(t, before, reloadConfigDigest(t, configPath), output)
	split := capacityReadRevision(t)
	capacityAssertSplit(t, split)
	splitStatus := capacityReadyStatus(t)
	if !reflect.DeepEqual(splitStatus.Applied.Details.PrefixCounts, beforeSplitStatus.Applied.Details.PrefixCounts) ||
		!reflect.DeepEqual(splitStatus.Applied.Details.CrowdSec.Counts, beforeSplitStatus.Applied.Details.CrowdSec.Counts) {
		t.Fatal("geo sharing split changed source or live decision accounting")
	}
	capacityMeasure(t, daemon, table, "split-egress-only", started)
	for _, network := range []string{"tcp4", "tcp6"} {
		host, remote := "8.20.0.1:18885", "8.20.0.2:18886"
		if network == "tcp6" {
			host, remote = "[2600:20::1]:18885", "[2600:20::2]:18886"
		}
		probeIngress(t, peer, network, host, "success", "tcp")
		probeEgress(t, peer, network, remote, "drop", "tcp")
	}
	started = time.Now()
	if err := os.WriteFile(configPath, baseText, 0o600); err != nil { // #nosec G703 -- restores the private namespace policy fixture.
		t.Fatal(err)
	}
	before = activeRevision()
	output = command(t, 180*time.Second, e2eBinary(t), "reload")
	assertReloadAcknowledgement(t, before, reloadConfigDigest(t, configPath), output)
	withSSH = capacityAssertState(t, true)
	capacityMeasure(t, daemon, table, "merge-egress", started)
	capacityPackets(t, peer, true, true, true)

	// A failure after the actual native switch must roll back the previous
	// acknowledged shared representation, including its live CrowdSec leases.
	beforeRollback := capacityReadRevision(t)
	if err := os.WriteFile(configPath, []byte(splitText), 0o600); err != nil { // #nosec G703 -- private namespace rollback fixture.
		t.Fatal(err)
	}
	if err := os.WriteFile(failFile, []byte("fail"), 0o600); err != nil {
		t.Fatal(err)
	}
	rollbackCmd := exec.Command(e2eBinary(t), "reload") // #nosec G204 -- trusted fixture CLI with fixed arguments.
	if output, err := rollbackCmd.CombinedOutput(); err == nil {
		t.Fatalf("post-switch failed reload was acknowledged: %s", output)
	}
	afterRollback := capacityAssertState(t, true)
	if afterRollback.ID != beforeRollback.ID || !reflect.DeepEqual(afterRollback.Target, beforeRollback.Target) {
		t.Fatal("failed reload changed acknowledged shared target")
	}
	capacityPackets(t, peer, true, true, true)
	capacityMeasure(t, daemon, table, "post-switch-rollback", time.Now())
	if err := os.WriteFile(configPath, baseText, 0o600); err != nil { // #nosec G703 -- restores the private namespace policy fixture.
		t.Fatal(err)
	}

	started = time.Now()
	before = activeRevision()
	output = command(t, 180*time.Second, e2eBinary(t), "reload")
	assertReloadAcknowledgement(t, before, reloadConfigDigest(t, configPath), output)
	unchanged := capacityAssertState(t, true)
	if unchanged.Target.Generation != withSSH.Target.Generation {
		t.Fatal("unchanged reload replaced static generation")
	}
	capacityMeasure(t, daemon, table, "unchanged", started)

	started = time.Now()
	fixture.mu.Lock()
	fixture.refresh = true
	fixture.mu.Unlock()
	deadline := time.Now().Add(3 * time.Minute)
	var refreshed *state.Revision
	for time.Now().Before(deadline) {
		refreshed = capacityReadRevision(t)
		if refreshed.Target.Generation != unchanged.Target.Generation {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	if refreshed == nil || refreshed.Target.Generation == unchanged.Target.Generation {
		t.Fatal("country refresh never acknowledged a distinct static generation")
	}
	capacityAssertState(t, true)
	capacityMeasure(t, daemon, table, "country-refresh", started)

	fixture.mu.Lock()
	fixture.deletePeers = true
	fixture.mu.Unlock()
	waitCrowdPacket(t, peer, "tcp4", "8.22.0.1:18883", "success")
	waitCrowdPacket(t, peer, "tcp6", "[2600:22::1]:18883", "success")
	afterDynamic := capacityAssertState(t, true)
	if afterDynamic.Target.Generation != refreshed.Target.Generation {
		t.Fatal("independent dynamic change replaced static generation")
	}
	capacityPackets(t, peer, true, false, true)
	capacityMeasure(t, daemon, table, "dynamic-delete", time.Now())
	daemon.stop(t)

	// A normal restart creates its own exact same-ID prepared journal before
	// applying the active target. Crash at the durable journal publication.
	crash := capacityCommand(configPath, server.URL, "PERIMETERD_CAPACITY_CRASH=journal:after-dir-sync")
	if output, err := crash.CombinedOutput(); !exitStatus(err, 97) {
		t.Fatalf("same-ID recovery crash: %v\n%s", err, output)
	}
	store, err := state.Open("/var/lib/perimeterd", nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if view.Journal == nil || view.Journal.Phase != "prepared" || view.Journal.Previous != view.Active.ID || view.Journal.Candidate != view.Active.ID || view.Journal.PreviousManifest != view.Journal.CandidateManifest || len(view.Journal.Revisions) != 1 {
		t.Fatalf("not exact production journal: %+v", view.Journal)
	}
	started = time.Now()
	daemon = start()
	capacityAssertState(t, true)
	capacityPackets(t, peer, true, false, true)
	capacityMeasure(t, daemon, table, "same-ID-recovery", started)
	daemon.stop(t)

	// A genuine changed static target is interrupted after durable preparation;
	// recovery must retain acknowledged three-policy authority, never two-policy.
	// #nosec G304 -- configPath is created by tempConfig inside the isolated fixture.
	text, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	// #nosec G703 -- only the fixture-owned configuration is changed.
	if err := os.WriteFile(configPath, []byte(strings.Replace(string(text), "deny_action: drop", "deny_action: reject", 1)), 0o600); err != nil {
		t.Fatal(err)
	}
	crash = capacityCommand(configPath, server.URL, "PERIMETERD_CAPACITY_CRASH=after-prepare")
	if output, err := crash.CombinedOutput(); !exitStatus(err, 97) {
		t.Fatalf("distinct preparation crash: %v\n%s", err, output)
	}
	view, err = store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if view.Journal == nil || view.Journal.Previous == view.Journal.Candidate || view.Revisions[view.Journal.Previous].Target.Generation == view.Revisions[view.Journal.Candidate].Target.Generation {
		t.Fatal("interrupted target did not retain distinct static generations")
	}
	// #nosec G703 -- restore the same fixture-owned configuration, never a host path.
	if err := os.WriteFile(configPath, text, 0o600); err != nil {
		t.Fatal(err)
	}
	daemon = start()
	capacityAssertState(t, true)
	capacityPackets(t, peer, true, false, true)
	daemon.stop(t)

	capacityNativeFailureCases(t, configPath, server.URL, start)
	capacityOverBudgetStartup(t, server.URL)
}

func capacityNativeFailureCases(t *testing.T, configPath, sourceURL string, start func(...string) *daemonProcess) {
	t.Helper()
	native, err := exec.LookPath("nft")
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	mode := filepath.Join(dir, "mode")
	wrapper := fmt.Sprintf("#!/bin/sh\nif [ -f %q ]; then\n mode=$(cat %q)\n if [ \"$mode\" = once ]; then rm -f %q; fi\n echo 'SECRET-HOSTILE-NATIVE-DIAGNOSTIC' >&2\n exit 1\nfi\nexec %q \"$@\"\n", mode, mode, mode, native)
	// #nosec G306 -- private fault-injection wrapper must be executable; content is local.
	if err := os.WriteFile(filepath.Join(dir, "nft"), []byte(wrapper), 0o700); err != nil {
		t.Fatal(err)
	}
	path := "PATH=" + dir + ":" + os.Getenv("PATH")
	if err := os.WriteFile(mode, []byte("once"), 0o600); err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	daemon := start(path)
	capacityAssertState(t, true)
	if strings.Contains(daemon.output.String(), "SECRET-HOSTILE-NATIVE-DIAGNOSTIC") {
		t.Fatal("early recovery leaked native diagnostic")
	}
	t.Logf("transient native failure recovered in %s", time.Since(started))
	daemon.stop(t)
	if err := os.WriteFile(mode, []byte("always"), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := capacityCommand(configPath, sourceURL, path)
	output := new(lockedBuffer)
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) && !strings.Contains(output.String(), "recover") {
		time.Sleep(20 * time.Millisecond)
	}
	if !strings.Contains(output.String(), "recover") {
		_ = cmd.Process.Kill()
		err := <-done
		t.Fatalf("first recovery failure was not visible: %v: %s", err, output.String())
	}
	started = time.Now()
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-done:
		t.Logf("recovery process stopped: %v", err)
		if time.Since(started) > 3*time.Second {
			t.Fatal("stop during retry was not prompt")
		}
	case <-time.After(5 * time.Second):
		_ = cmd.Process.Kill()
		err := <-done
		t.Fatalf("stop during recovery did not cancel retry: %v", err)
	}
	if strings.Contains(output.String(), "SECRET-HOSTILE-NATIVE-DIAGNOSTIC") {
		t.Fatal("stop recovery leaked native diagnostic")
	}
	store, err := state.Open("/var/lib/perimeterd", nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil || view.Active == nil || view.Journal == nil || len(view.Active.Config.Policies) != 3 {
		t.Fatalf("stop during recovery lost acknowledged state/journal: %v", err)
	}
}

func capacityOverBudgetStartup(t *testing.T, sourceURL string) {
	t.Helper()
	// Keep the durable revision below the record ceiling: geography is stored
	// once in the compiled target, not duplicated in literal configuration.
	// Short, sparse addresses fit the source-object limit but their nft prefix
	// expressions exceed native input capacity after compilation.
	const count = 900_000
	cfg, err := config.Parse([]byte(`version: 1
firewall:
  backend: nftables
  ipv4: false
  ipv6: true
  nftables:
    table: capacity_overbudget
policies:
  - name: oversized
    direction: ingress
    priority: 10
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
`))
	if err != nil {
		t.Fatal(err)
	}
	prefixes := make([]netip.Prefix, count)
	for index := range count {
		var address [16]byte
		address[1] = 1
		binary.BigEndian.PutUint32(address[12:], uint32(index)*2)
		prefixes[index] = netip.PrefixFrom(netip.AddrFrom16(address), 128)
	}
	dir := "/var/lib/capacity-overbudget"
	store, err := state.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	snapshot, err := store.Prefixes().Stage([]source.Record{{
		Selector:   policy.Selector{Kind: policy.Country, Value: "US"},
		Endpoint:   "https://stat.ripe.net/data/country-resource-list/data.json",
		APIVersion: "0.2",
		Parameters: map[string]string{"resource": "US", "sourceapp": "perimeterd", "v4_format": "prefix"},
		QueryStart: now, QueryEnd: now, RetrievedAt: now, IPv6: prefixes,
	}})
	if err != nil {
		t.Fatal(err)
	}
	model, err := policy.Compile(cfg, snapshot.Policy())
	if err != nil {
		t.Fatal(err)
	}
	target, err := firewall.BuildTarget(store.Owner(), capacityfixture.InitialID, cfg, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	var capacity *firewall.CapacityError
	admissionErr := firewall.NewNFT().Preflight(context.Background(), target, target, nil)
	if !errors.As(admissionErr, &capacity) || capacity.RequiredBytes <= capacity.LimitBytes {
		t.Fatalf("over-budget fixture must reach numeric native capacity rejection, got %v", admissionErr)
	}
	revision := &state.Revision{Version: 2, ID: capacityfixture.InitialID, Epoch: 1, Manifest: snapshot.ManifestID(), ConfigPath: "/unused/not-read-before-recovery", Config: cfg, Target: target}
	if err := store.Prepare(nil, revision); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(revision); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(); err != nil {
		t.Fatal(err)
	}
	if err := store.Prepare(revision, revision); err != nil {
		t.Fatal(err)
	}
	journalPath := filepath.Join(dir, "journal.json")
	// #nosec G304 -- journalPath belongs to the private over-budget fixture state.
	before, err := os.ReadFile(journalPath)
	if err != nil {
		t.Fatal(err)
	}
	started := time.Now()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := capacityCommand(revision.ConfigPath, sourceURL, "PERIMETERD_CAPACITY_STATE="+dir)
	// Bind the safety deadline without replacing recovery's own startup policy.
	// #nosec G204 -- reuse the compiled test helper and its fixed argument vector.
	cmd = exec.CommandContext(ctx, cmd.Path, cmd.Args[1:]...)
	cmd.Env = append(os.Environ(), capacityHelper+"=1", "PERIMETERD_CAPACITY_CONFIG="+revision.ConfigPath, "PERIMETERD_CAPACITY_SOURCE="+sourceURL, "PERIMETERD_CAPACITY_STATE="+dir)
	// Any native command is a failure: admission must stop before inspection
	// and mutation, not merely fail because a native subprocess was unavailable.
	toolDir := t.TempDir()
	nativeMarker := filepath.Join(toolDir, "native-called")
	wrapper := fmt.Sprintf("#!/bin/sh\nprintf called > %q\nexit 99\n", nativeMarker)
	// #nosec G306 -- private marker script must be executable; no external script content.
	if err := os.WriteFile(filepath.Join(toolDir, "nft"), []byte(wrapper), 0o700); err != nil {
		t.Fatal(err)
	}
	cmd.Env = append(cmd.Env, "PATH="+toolDir+":"+os.Getenv("PATH"))
	notifyPath := filepath.Join(t.TempDir(), "failure.sock")
	notify, listenErr := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifyPath, Net: "unixgram"})
	if listenErr != nil {
		t.Fatal(listenErr)
	}
	defer func() { _ = notify.Close() }()
	cmd.Env = append(cmd.Env, "NOTIFY_SOCKET="+notifyPath)
	output, err := cmd.CombinedOutput()
	if err == nil || ctx.Err() != nil {
		t.Fatalf("over-budget recovery did not fail promptly: %v\n%s", err, output)
	}
	if !strings.Contains(string(output), "capacity") ||
		!strings.Contains(string(output), fmt.Sprint(capacity.RequiredBytes)) ||
		!strings.Contains(string(output), fmt.Sprint(capacity.LimitBytes)) {
		t.Fatalf("missing numeric capacity diagnosis: %s", output)
	}
	if strings.Contains(string(output), "1::") || strings.Contains(string(output), "SECRET-") {
		t.Fatal("unsafe capacity diagnostic")
	}
	_ = notify.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var messages []string
	for {
		var packet [4096]byte
		n, _, err := notify.ReadFromUnix(packet[:])
		if err != nil {
			break
		}
		message := string(packet[:n])
		if strings.Contains(message, "READY=1") {
			t.Fatal("over-budget recovery sent premature READY")
		}
		if strings.Contains(message, "1::") || strings.Contains(message, "SECRET-") {
			t.Fatal("unsafe startup notification")
		}
		messages = append(messages, message)
	}
	if len(messages) == 0 {
		t.Fatal("over-budget startup emitted no systemd progress notification")
	}
	t.Logf("over-budget notification messages=%q (private socket, not a real systemd manager)", messages)
	_ = notify.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
	var packet [4096]byte
	if n, _, err := notify.ReadFromUnix(packet[:]); err == nil {
		t.Fatalf("startup notification continued after process exit: %s", packet[:n])
	}
	if _, err := os.Stat(nativeMarker); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("over-budget startup invoked native command before rejecting: %v", err)
	}
	// #nosec G304 -- read back that same private journal to prove it was preserved.
	after, readErr := os.ReadFile(journalPath)
	if readErr != nil || sha256.Sum256(before) != sha256.Sum256(after) {
		t.Fatal("over-budget recovery changed prepared journal")
	}
	view, err := store.Read()
	if err != nil || view.Journal == nil || view.Active == nil || view.Active.ID != revision.ID ||
		view.Journal.Previous != revision.ID || view.Journal.Candidate != revision.ID ||
		view.Journal.Phase != "prepared" || len(view.Journal.Revisions) != 1 {
		t.Fatalf("over-budget durable state damaged: %v", err)
	}
	t.Logf("over-budget initial recovery rejected safely in %s; prepared journal checksum intact", time.Since(started))
}
