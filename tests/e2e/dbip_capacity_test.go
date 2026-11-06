//go:build linux && e2e

package e2e

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/control"
	"github.com/perimeterd/perimeterd/internal/crowdsec"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/state"
	"github.com/perimeterd/perimeterd/internal/testutil/capacityfixture"
)

const dbipCapacityLifetime = 2 * time.Hour

func dbipCapacityWait(t *testing.T, description string, ready func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Minute)
	for time.Now().Before(deadline) {
		if ready() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", description)
}

func dbipCapacityStatus(t *testing.T) control.StatusResult {
	t.Helper()
	var status control.StatusResult
	dbipCapacityWait(t, "coherent acknowledged capacity authority", func() bool {
		status = largeCrowdStatus(t)
		return status.Successful() && status.Applied.Details != nil &&
			status.Applied.Details.CrowdSec.Counts != nil
	})
	return status
}

type dbipCapacitySources struct {
	mu             sync.Mutex
	countries      *capacitySources
	refresh        bool
	count, offset  int
	deletePeers    bool
	serial, served int
	until          time.Time
	rejectStartup  bool
	rejectedBytes  int64
}

func newDBIPCapacitySources(t *testing.T) (*dbipCapacitySources, *httptest.Server) {
	t.Helper()
	countries, _ := newCapacitySourcesFor(t, capacityfixture.DBIPRecords)
	fixture := &dbipCapacitySources{countries: countries, count: capacityfixture.DBIPProjectedBans, serial: 1, until: time.Now().Add(12 * time.Hour).Truncate(time.Second)}
	server := httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(server.Close)
	return fixture, server
}

func (f *dbipCapacitySources) serve(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	reject := r.URL.Path == "/v1/decisions/stream" && r.URL.Query().Get("startup") == "true" && f.rejectStartup
	if reject {
		f.rejectStartup = false
	}
	refresh, count, offset, deleted, serial, served, until := f.refresh, f.count, f.offset, f.deletePeers, f.serial, f.served, f.until
	f.mu.Unlock()
	if r.URL.Path == "/country" {
		f.countries.mu.Lock()
		f.countries.refresh = refresh
		f.countries.mu.Unlock()
		f.countries.serve(w, r)
		return
	}
	if r.URL.Path == "/dbip" {
		path := os.Getenv("PERIMETERD_CAPACITY_DBIP_FILE")
		if refresh {
			path = os.Getenv("PERIMETERD_CAPACITY_DBIP_REFRESH_FILE")
		}
		root, err := os.OpenRoot(filepath.Dir(path))
		if err != nil {
			http.Error(w, "artifact unavailable", http.StatusInternalServerError)
			return
		}
		defer func() { _ = root.Close() }()
		file, err := root.Open(filepath.Base(path))
		if err != nil {
			http.Error(w, "artifact unavailable", http.StatusInternalServerError)
			return
		}
		defer func() { _ = file.Close() }()
		w.Header().Set("Content-Type", "application/gzip")
		_, _ = io.Copy(w, file)
		return
	}
	if r.URL.Path != "/v1/decisions/stream" || r.Header.Get("X-Api-Key") != crowdFixtureKey {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if reject {
		// Only the staged authority receives this full snapshot. Ordinary polls
		// and the resumed old client still receive their admissible authority.
		batch := dbipCapacityOversized(until)
		counter := &dbipCapacityWriter{Writer: bufio.NewWriterSize(w, 32<<10)}
		if err := capacityfixture.WriteDBIPSnapshot(counter, batch); err != nil {
			return
		}
		if err := counter.Writer.(*bufio.Writer).Flush(); err != nil {
			return
		}
		f.mu.Lock()
		f.rejectedBytes = counter.bytes
		f.mu.Unlock()
		return
	}
	if serial == served && r.URL.Query().Get("startup") != "true" {
		_, _ = io.WriteString(w, `{"new":[],"deleted":[]}`)
		return
	}
	batch := capacityfixture.DBIPBatch(count, offset, until)
	if deleted {
		batch.New = batch.New[2:]
		batch.Deleted = []int64{1, 2}
	}
	buffer := bufio.NewWriterSize(w, 32<<10)
	if err := capacityfixture.WriteDBIPSnapshot(buffer, batch); err != nil {
		return
	}
	if err := buffer.Flush(); err != nil {
		return
	}
	f.mu.Lock()
	f.served = serial
	f.mu.Unlock()
}

type dbipCapacityWriter struct {
	io.Writer
	bytes int64
}

func (w *dbipCapacityWriter) Write(data []byte) (int, error) {
	n, err := w.Writer.Write(data)
	w.bytes += int64(n)
	return n, err
}

func dbipCapacityOversized(until time.Time) crowdsec.Batch {
	// An exception at the parent's second address splits each /64 into 65
	// disjoint timed prefixes. Long IPv6 spellings also exercise real native
	// encoding, without requiring a source response beyond its 256 MiB fence.
	const pairs = 65536
	batch := crowdsec.Batch{Startup: true, New: make([]crowdsec.Decision, 2*pairs)}
	for i := range pairs {
		address := [16]byte{0x26, 0x00, 0xab, 0xcd, 0xab, 0xcd, byte(i >> 8), byte(i)}
		parent := netip.PrefixFrom(netip.AddrFrom16(address), 64)
		batch.New[2*i] = crowdsec.Decision{ID: int64(2*i + 1), Prefix: parent, Deadline: until}
		batch.New[2*i+1] = crowdsec.Decision{ID: int64(2*i + 2), Prefix: netip.PrefixFrom(parent.Addr().Next(), 128), Deadline: until.Add(time.Hour)}
	}
	return batch
}

func (f *dbipCapacitySources) projection(t *testing.T) []policy.TimedPrefix {
	t.Helper()
	started := time.Now()
	f.mu.Lock()
	batch := capacityfixture.DBIPBatch(f.count, f.offset, f.until)
	if f.deletePeers {
		batch.New = batch.New[2:]
	}
	f.mu.Unlock()
	store := crowdsec.NewStore("http://fixture.invalid/", 1)
	if err := store.Apply(batch, 1, time.Now()); err != nil {
		t.Fatal(err)
	}
	projection := store.Projection(time.Now())
	recordE2EPhase(t, e2ePhaseRecord{Profile: "dbip-euro-atlantic", Phase: "projection-oracle", Event: "comparison", Outcome: "success", ProjectedMemberships: len(projection), DurationNS: time.Since(started).Nanoseconds()})
	return projection
}

func dbipCapacityRejection(t *testing.T, output string, backend string) *firewall.CapacityError {
	t.Helper()
	// These numeric fields are rendered by CapacityError.Error through the
	// actual daemon reload path, not a synthetic backend or direct preflight.
	pattern := regexp.MustCompile(`(nftables|iptables) backend: (nft-table|ipsets) (input|inventory|output) capacity exceeded: required ([0-9]+) bytes, limit ([0-9]+) bytes`)
	for line := range strings.SplitSeq(output, "\n") {
		var record struct {
			Message string `json:"msg"`
			Error   string `json:"error"`
		}
		if json.Unmarshal([]byte(line), &record) != nil || record.Message != "reload failed" {
			continue
		}
		match := pattern.FindStringSubmatch(record.Error)
		if match == nil || match[1] != backend {
			continue
		}
		required, err := strconv.ParseInt(match[4], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		limit, err := strconv.ParseInt(match[5], 10, 64)
		if err != nil {
			t.Fatal(err)
		}
		if required <= limit || (limit != 64<<20 && limit != 256<<20 && limit != 384<<20) {
			t.Fatalf("invalid native capacity diagnostic: %s", record.Error)
		}
		return &firewall.CapacityError{Backend: match[1], Resource: match[2], Scope: match[3], RequiredBytes: required, LimitBytes: limit}
	}
	return nil
}

func beginDBIPPhase(t *testing.T, backend, phase string) time.Time {
	t.Helper()
	started := time.Now()
	recordE2EPhase(t, e2ePhaseRecord{Backend: backend, Profile: "dbip-euro-atlantic", Phase: phase, Event: "phase_start", Timestamp: started})
	return started
}

func dbipCapacityState(t *testing.T, live bool, wantDynamic int, phase string) (*state.Revision, *nativePhaseSnapshot) {
	t.Helper()
	if wantDynamic < 0 {
		t.Fatal("negative expected projection")
		return nil, nil
	}
	waitStarted := time.Now()
	want := uint64(wantDynamic)
	var revision *state.Revision
	var acknowledged control.StatusResult
	dbipCapacityWait(t, "DB-IP acknowledged static and dynamic revision", func() bool {
		status := largeCrowdStatus(t)
		if !status.Successful() || status.Applied.Details == nil || status.Applied.Details.CrowdSec.Counts == nil {
			return false
		}
		counts := status.Applied.Details.CrowdSec.Counts
		if counts.IPv4+counts.IPv6 != want {
			return false
		}
		if _, err := os.Stat("/var/lib/perimeterd/journal.json"); !errors.Is(err, os.ErrNotExist) {
			if err != nil {
				t.Fatal(err)
			}
			return false
		}
		revision = capacityReadRevision(t)
		acknowledged = status
		return status.Applied.Revision == revision.ID
	})
	total, counts := capacityfixture.Memberships(revision.Target.Families)
	recordE2EPhase(t, e2ePhaseRecord{Backend: revision.Target.Backend(), Profile: "dbip-euro-atlantic", Phase: phase, Event: "acknowledged", Outcome: "success", StaticMemberships: total, ProjectedMemberships: wantDynamic, StaticGeneration: revision.Target.Generation, DynamicGeneration: revision.Target.DynamicGeneration, DurationNS: time.Since(waitStarted).Nanoseconds()})
	if !live {
		if err := capacityfixture.ValidateDBIP(revision.Target.Families); err != nil {
			t.Fatal(err)
		}
	}
	snapshot := captureNativePhase(t, revision.Target, phase, true)
	comparisonStarted := time.Now()
	assertSnapshotProjectionCount(t, snapshot, wantDynamic)
	expected := 0
	for _, family := range revision.Target.Families {
		expected += len(family.Sets)
	}
	if revision.Target.Backend() == "iptables" {
		expected++ // The deliberately foreign set.
		if len(snapshot.sets) != expected {
			t.Fatalf("obsolete generations or resize spares remain: sets=%d want=%d", len(snapshot.sets), expected)
		}
	} else {
		actual, err := snapshotNativeReferences(snapshot, revision.Target, false)
		if err != nil || actual != expected {
			t.Fatalf("native references/orphan sets: sets=%d want=%d (%v)", actual, expected, err)
		}
	}
	afterCapture := dbipCapacityStatus(t)
	if afterCapture.Applied.Revision != revision.ID || afterCapture.Applied.ConfigEpoch != acknowledged.Applied.ConfigEpoch ||
		afterCapture.Applied.Details.CrowdSec.Epoch != acknowledged.Applied.Details.CrowdSec.Epoch ||
		afterCapture.Applied.Details.CrowdSec.Operation != acknowledged.Applied.Details.CrowdSec.Operation {
		t.Fatalf("authority changed during native phase observation; snapshot cannot be reused: revision=%s/%s config-epoch=%d/%d crowd-epoch=%d/%d operation=%d/%d",
			revision.ID, afterCapture.Applied.Revision, acknowledged.Applied.ConfigEpoch, afterCapture.Applied.ConfigEpoch,
			acknowledged.Applied.Details.CrowdSec.Epoch, afterCapture.Applied.Details.CrowdSec.Epoch,
			acknowledged.Applied.Details.CrowdSec.Operation, afterCapture.Applied.Details.CrowdSec.Operation)
	}
	recordE2EPhase(t, e2ePhaseRecord{Backend: revision.Target.Backend(), Profile: "dbip-euro-atlantic", Phase: phase, Event: "comparison", Outcome: "success", StaticMemberships: total, ProjectedMemberships: wantDynamic, DurationNS: time.Since(comparisonStarted).Nanoseconds()})
	t.Logf("revision=%s static-generation=%s dynamic-generation=%s unique-static-memberships=%d per-set=%v projected-dynamic=%d", revision.ID, revision.Target.Generation, revision.Target.DynamicGeneration, total, counts, wantDynamic)
	return revision, snapshot
}

func dbipCapacityMeasure(t *testing.T, daemon *daemonProcess, target *firewall.Target, phase string, started time.Time, snapshot *nativePhaseSnapshot) {
	t.Helper()
	defer snapshot.release()
	measureNativePhase(t, daemon, target, phase, started, snapshot)
	store, err := state.Open("/var/lib/perimeterd", nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	staticIDs, dynamicIDs := make(map[string]bool), make(map[string]bool)
	for _, revision := range view.Revisions {
		staticIDs[revision.Target.Generation] = true
		if revision.Target.DynamicGeneration != "" {
			dynamicIDs[revision.Target.DynamicGeneration] = true
		}
	}
	total, _ := capacityfixture.Memberships(target.Families)
	recordE2EPhase(t, e2ePhaseRecord{Backend: target.Backend(), Profile: "dbip-euro-atlantic", Phase: phase, Event: "phase_end", Outcome: "success", StaticMemberships: total, StaticGeneration: target.Generation, DynamicGeneration: target.DynamicGeneration, StaticGenerations: len(staticIDs), DynamicGenerations: len(dynamicIDs), WallNS: time.Since(started).Nanoseconds()})
	t.Logf("phase=%s retained-revisions=%d static-generations=%d dynamic-generations=%d journal=%+v wall=%s", phase, len(view.Revisions), len(staticIDs), len(dynamicIDs), view.Journal, time.Since(started))
}

func dbipCapacityPackets(t *testing.T, peer *peerNamespace, banned bool, phase string) {
	t.Helper()
	started := time.Now()
	defer func() {
		outcome := "success"
		if t.Failed() {
			outcome = "failure"
		}
		recordE2EPhase(t, e2ePhaseRecord{Backend: os.Getenv(e2eScenario), Profile: "dbip-euro-atlantic", Phase: phase, Event: "packets", Outcome: outcome, DurationNS: time.Since(started).Nanoseconds()})
	}()
	capacityPackets(t, peer, true, banned, false)
	for _, network := range []string{"udp4", "udp6"} {
		for _, subnet := range []string{"20", "22", "23"} {
			host, remote := "8."+subnet+".0.1", "8."+subnet+".0.2"
			if network == "udp6" {
				host, remote = "[2600:"+subnet+"::1]", "[2600:"+subnet+"::2]"
			}
			ingress, egress := "success", "success"
			if subnet == "23" {
				ingress, egress = "drop", "drop"
			}
			if banned && subnet == "22" {
				ingress = "drop"
			}
			probeIngress(t, peer, network, host+":18880", ingress, "udp")
			probeEgress(t, peer, network, remote+":18881", egress, "udp")
		}
	}
}

// TestE2EDBIPCapacity uses the existing daemon helper, native tool-family
// installers, peer probes and namespace harness. No live request is permitted.
// Optional local DB-IP artifacts exercise the production DB-IP parser instead
// of deterministic country envelopes; packet assertions remain deterministic.
func TestE2EDBIPCapacity(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, backend := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(backend, func(t *testing.T) {
				runIsolatedFor(t, "TestE2EDBIPCapacity", backend, dbipCapacityLifetime)
			})
		}
		return
	}
	requireIsolatedChild(t)
	setupStarted := time.Now()
	prepareMounts(t)
	if err := syscall.Mount("", "/var/lib", "", syscall.MS_REMOUNT, "size=3072m"); err != nil {
		t.Fatal(err)
	}
	backend := os.Getenv(e2eScenario)
	phase := "fixture-setup"
	if strings.HasPrefix(backend, "iptables-") {
		installIPTablesTools(t, strings.TrimPrefix(backend, "iptables-"))
		backend = "iptables"
		seedIPTablesParents(t)
		addIPTablesForeignRules(t)
		command(t, 10*time.Second, "ipset", "create", "capacity_foreign", "hash:net")
		command(t, 10*time.Second, "ipset", "add", "capacity_foreign", "203.0.113.99")
		for _, tool := range []string{"iptables", "ip6tables"} {
			command(t, 10*time.Second, tool, "-N", "DOCKER-USER")
			command(t, 10*time.Second, tool, "-A", "FORWARD", "-j", "DOCKER-USER")
		}
	}
	for _, tool := range []string{"nft", "ipset", "iptables", "ip6tables"} {
		output, err := commandMayFail(10*time.Second, tool, "--version")
		t.Logf("tool=%s version=%s error=%v", tool, strings.TrimSpace(string(output)), err)
	}
	t.Logf("kernel=%s requested-backend=%s", strings.TrimSpace(string(command(t, 10*time.Second, "uname", "-r"))), os.Getenv(e2eScenario))
	if backend == "nftables" {
		command(t, 10*time.Second, "nft", "add", "table", "inet", "capacity_foreign")
	}
	foreign := func(snapshot *nativePhaseSnapshot) {
		if backend == "iptables" {
			if snapshot == nil {
				assertIPTablesForeign(t, "v4")
				assertIPTablesForeign(t, "v6")
			} else {
				assertSnapshotForeignIPTables(t, snapshot, "v4")
				assertSnapshotForeignIPTables(t, snapshot, "v6")
			}
			command(t, 10*time.Second, "ipset", "test", "capacity_foreign", "203.0.113.99")
		} else {
			command(t, 10*time.Second, "nft", "list", "table", "inet", "capacity_foreign")
		}
	}
	peer := newPeerNamespaceFor(t, dbipCapacityLifetime+time.Minute)
	for _, subnet := range []string{"21", "22", "23"} {
		command(t, 10*time.Second, "ip", "addr", "add", "8."+subnet+".0.1/24", "dev", "e2h0")
		peer.run(t, "ip", "addr", "add", "8."+subnet+".0.2/24", "dev", "e2p0")
		command(t, 10*time.Second, "ip", "-6", "addr", "add", "2600:"+subnet+"::1/64", "dev", "e2h0", "nodad")
		peer.run(t, "ip", "-6", "addr", "add", "2600:"+subnet+"::2/64", "dev", "e2p0", "nodad")
	}
	fixture, server := newDBIPCapacitySources(t)
	live := os.Getenv("PERIMETERD_CAPACITY_DBIP_FILE") != ""
	if live && os.Getenv("PERIMETERD_CAPACITY_DBIP_REFRESH_FILE") == "" {
		t.Fatal("live artifact requires controlled refresh artifact")
	}
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte(crowdFixtureKey), 0o600); err != nil {
		t.Fatal(err)
	}
	path := tempConfig(t, "dbip-capacity")
	table := fmt.Sprintf("dbip_capacity_%d", os.Getpid())
	configRoot, err := os.OpenRoot(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = configRoot.Close() })
	refreshInterval := "1h"
	write := func(bidirectional bool, action string) {
		text := capacityfixture.DBIPYAML(table, server.URL, key, backend, bidirectional)
		text = strings.Replace(text, "refresh_interval: 1h", "refresh_interval: "+refreshInterval+"\n  refresh_jitter: 1ns", 1)
		text = strings.Replace(text, "deny_action: drop", "deny_action: "+action, 1)
		if live {
			text = strings.Replace(text, "country_provider: ripestat", "country_provider: dbip-lite", 1)
		}
		if err := configRoot.WriteFile(filepath.Base(path), []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	var daemon *daemonProcess
	start := func() *daemonProcess {
		actionStarted := time.Now()
		recordE2EPhase(t, e2ePhaseRecord{Backend: backend, Profile: "dbip-euro-atlantic", Phase: phase, Event: "action_start"})
		process := startDaemonCommand(t, capacityCommand(path, server.URL), "DB-IP capacity daemon", func() bool { return activeRevision() != "" }, 15*time.Minute)
		recordE2EPhase(t, e2ePhaseRecord{Backend: backend, Profile: "dbip-euro-atlantic", Phase: phase, Event: "process_ready", Outcome: "success", DurationNS: time.Since(actionStarted).Nanoseconds()})
		return process
	}
	reload := func() {
		actionStarted := time.Now()
		recordE2EPhase(t, e2ePhaseRecord{Backend: backend, Profile: "dbip-euro-atlantic", Phase: phase, Event: "action_start"})
		before := largeCrowdStatus(t)
		if !before.Successful() {
			dbipCapacityWait(t, "coherent pre-reload configuration epoch", func() bool {
				before = largeCrowdStatus(t)
				return before.Successful()
			})
		}
		daemon.reload(t)
		dbipCapacityWait(t, "acknowledged asynchronous reload and completed journal", func() bool {
			select {
			case <-daemon.done:
				t.Fatalf("daemon exited during reload: %v\n%s", daemon.waitErr(), daemon.output.String())
			default:
			}
			status := largeCrowdStatus(t)
			if !status.Successful() || status.Applied.ConfigEpoch <= before.Applied.ConfigEpoch || status.Applied.Revision == before.Applied.Revision {
				return false
			}
			if _, err := os.Stat("/var/lib/perimeterd/journal.json"); !errors.Is(err, os.ErrNotExist) {
				if err != nil {
					t.Fatal(err)
				}
				return false
			}
			return true
		})
		recordE2EPhase(t, e2ePhaseRecord{Backend: backend, Profile: "dbip-euro-atlantic", Phase: phase, Event: "action_acknowledged", Outcome: "success", DurationNS: time.Since(actionStarted).Nanoseconds()})
	}
	recordE2EPhase(t, e2ePhaseRecord{Backend: backend, Profile: "dbip-euro-atlantic", Phase: phase, Event: "setup", Outcome: "success", DurationNS: time.Since(setupStarted).Nanoseconds()})
	phase = "incident-first-start"
	started := beginDBIPPhase(t, backend, phase)
	write(false, "drop")
	daemon = start()
	initial, snapshot := dbipCapacityState(t, live, capacityfixture.DBIPProjectedBans, phase)
	if !live {
		// No OUTPUT hook in incident case: outside-group egress is not filtered.
		if backend == "iptables" {
			probeEgress(t, peer, "tcp4", "8.23.0.2:18881", "success", "tcp")
		}
		probeIngress(t, peer, "tcp4", "8.22.0.1:22", "drop", "tcp")
		probeIngress(t, peer, "udp4", "8.20.0.1:22", "success", "udp")
	}
	dbipCapacityMeasure(t, daemon, initial.Target, phase, started, snapshot)
	phase = "explicit-bidirectional"
	started = beginDBIPPhase(t, backend, phase)
	write(true, "drop")
	reload()
	current, snapshot := dbipCapacityState(t, live, capacityfixture.DBIPProjectedBans, phase)
	if !live {
		dbipCapacityPackets(t, peer, true, phase)
	}
	dbipCapacityMeasure(t, daemon, current.Target, phase, started, snapshot)
	phase = "unchanged-policy-authority-reload"
	started = beginDBIPPhase(t, backend, phase)
	reload()
	unchanged, snapshot := dbipCapacityState(t, live, capacityfixture.DBIPProjectedBans, phase)
	if backend == "nftables" {
		if unchanged.Target.Generation != current.Target.Generation || unchanged.Target.DynamicGeneration != current.Target.DynamicGeneration {
			t.Fatal("unchanged nft reload replaced shared identities")
		}
	} else {
		// Explicit iptables reload synchronizes a fresh LAPI authority in a
		// distinct container. Its static paths bind that container, so both
		// generations change; ordinary source refresh retains dynamic identity.
		if unchanged.Target.Generation == current.Target.Generation || unchanged.Target.DynamicGeneration == current.Target.DynamicGeneration {
			t.Fatal("iptables reload reused obsolete LAPI authority identity")
		}
	}
	dbipCapacityMeasure(t, daemon, unchanged.Target, phase, started, snapshot)
	phase = "changed-country-refresh"
	started = beginDBIPPhase(t, backend, phase)
	fixture.mu.Lock()
	fixture.refresh = true
	fixture.mu.Unlock()
	// Configure one accelerated refresh window with an actual alternate
	// country artifact, then observe an ordinary scheduled return transition.
	// Explicit reload authority replacement is not the source-refresh proof.
	refreshInterval = "1m"
	write(true, "drop")
	reload()
	beforeRefresh := capacityReadRevision(t)
	fixture.mu.Lock()
	fixture.refresh = false
	fixture.mu.Unlock()
	lastObserved := activeRevision()
	var refreshed *state.Revision
	dbipCapacityWait(t, "changed-country distinct generation", func() bool {
		active := activeRevision()
		if active == lastObserved {
			return false
		}
		lastObserved = active
		observed := capacityReadRevision(t)
		if observed.Target.Generation == beforeRefresh.Target.Generation {
			return false
		}
		refreshed = observed
		return true
	})
	if refreshed.Target.DynamicGeneration != beforeRefresh.Target.DynamicGeneration {
		t.Fatal("country refresh replaced live dynamic identity")
	}
	if reflect.DeepEqual(beforeRefresh.Target.Families, refreshed.Target.Families) {
		t.Fatal("source refresh changed identity without changed memberships")
	}
	t.Logf("phase=scheduled-country-transition old-static=%s new-static=%s retained-dynamic=%s", beforeRefresh.Target.Generation, refreshed.Target.Generation, refreshed.Target.DynamicGeneration)
	// Restore normal cadence before slower inventory/packet measurements and
	// ban/recovery work, rather than running competing minute-by-minute applies.
	refreshInterval = "1h"
	write(true, "drop")
	reload()
	current, snapshot = dbipCapacityState(t, live, capacityfixture.DBIPProjectedBans, phase)
	if !live {
		dbipCapacityPackets(t, peer, true, phase)
	}
	dbipCapacityMeasure(t, daemon, current.Target, phase, started, snapshot)
	// Delete peer bans, replace sparse memberships in place, and renew deadlines.
	phase = "in-place-delete-replace-renew"
	started = beginDBIPPhase(t, backend, phase)
	fixture.mu.Lock()
	fixture.deletePeers = true
	fixture.offset = 1000
	fixture.until = fixture.until.Add(time.Hour)
	fixture.serial++
	fixture.mu.Unlock()
	current, snapshot = dbipCapacityState(t, live, capacityfixture.DBIPProjectedBans-2, phase)
	assertNativeProjection(t, current.Target, fixture.projection(t), started, snapshot)
	if !live {
		dbipCapacityPackets(t, peer, false, phase)
	}
	dbipCapacityMeasure(t, daemon, current.Target, phase, started, snapshot)
	// Doubling each family's projection crosses the original ipset maxelem and
	// therefore requires a populated resize spare, not just an in-place delta.
	phase = "growth-resize-spare-retired"
	started = beginDBIPPhase(t, backend, phase)
	retainedUpdatedAfter := started
	fixture.mu.Lock()
	fixture.count = 300000
	fixture.deletePeers = false
	fixture.serial++
	fixture.mu.Unlock()
	current, snapshot = dbipCapacityState(t, live, 300000, phase)
	if !live {
		dbipCapacityPackets(t, peer, true, phase)
	}
	foreign(snapshot)
	dbipCapacityMeasure(t, daemon, current.Target, phase, started, snapshot)
	// Existing native capacity cases retain direct preflight coverage. Here the
	// running daemon must resolve, stage and reject a real LAPI authority.
	phase = "rejected-candidate-preserved"
	started = beginDBIPPhase(t, backend, phase)
	beforeRejected := dbipCapacityStatus(t)
	previousAuthority := beforeRejected.Applied.Details.CrowdSec
	previousProjection := fixture.projection(t)
	// Dynamic decisions are not persisted in revisions. This unchanged-config
	// reload has the same static durable shape; reserve an extra KiB for
	// advancing fixed-width identity/epoch metadata.
	payload, err := json.Marshal(current)
	if err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(map[string]any{"version": 2, "checksum": strings.Repeat("0", 64), "payload": json.RawMessage(payload)})
	if err != nil {
		t.Fatal(err)
	}
	if len(record)+1024 >= 32<<20 {
		t.Fatalf("candidate durable envelope lacks metadata headroom: %d bytes", len(record))
	}
	logOffset := len(daemon.output.String())
	fixture.mu.Lock()
	fixture.rejectStartup = true
	fixture.rejectedBytes = 0
	fixture.mu.Unlock()
	write(true, "drop")
	rejectionStarted := time.Now()
	recordE2EPhase(t, e2ePhaseRecord{Backend: backend, Profile: "dbip-euro-atlantic", Phase: phase, Event: "action_start"})
	daemon.reload(t)
	var capacity *firewall.CapacityError
	dbipCapacityWait(t, "daemon numeric native capacity rejection", func() bool {
		select {
		case <-daemon.done:
			t.Fatalf("daemon exited during rejected reload: %v\n%s", daemon.waitErr(), daemon.output.String())
		default:
		}
		capacity = dbipCapacityRejection(t, daemon.output.String()[logOffset:], backend)
		return capacity != nil
	})
	recordE2EPhase(t, e2ePhaseRecord{Backend: backend, Profile: "dbip-euro-atlantic", Phase: phase, Event: "action_rejected", Outcome: "success", DurationNS: time.Since(rejectionStarted).Nanoseconds()})
	fixture.mu.Lock()
	responseBytes := fixture.rejectedBytes
	fixture.mu.Unlock()
	if responseBytes <= 0 || responseBytes >= 256<<20 {
		t.Fatalf("oversized native candidate did not fit the real source fence: bytes=%d", responseBytes)
	}
	// Rejection restarts the retained authenticated client with a full sync.
	// Its native apply can outlast an inventory read; await the fresh, valid
	// authority epoch before opening the immutable post-rejection observation.
	resumeStarted := time.Now()
	dbipCapacityWait(t, "retained CrowdSec full synchronization acknowledgement", func() bool {
		status := largeCrowdStatus(t)
		return status.Successful() && status.Applied.Details != nil &&
			status.Applied.Details.CrowdSec.Epoch > previousAuthority.Epoch &&
			status.Applied.Details.CrowdSec.Validity == "valid"
	})
	recordE2EPhase(t, e2ePhaseRecord{Backend: backend, Profile: "dbip-euro-atlantic", Phase: phase, Event: "source_acknowledged", Outcome: "success", DurationNS: time.Since(resumeStarted).Nanoseconds()})
	preserved, snapshot := dbipCapacityState(t, live, 300000, phase)
	afterRejected := dbipCapacityStatus(t)
	authority := afterRejected.Applied.Details.CrowdSec
	if preserved.ID != current.ID || !reflect.DeepEqual(preserved.Target, current.Target) ||
		afterRejected.Applied.ConfigEpoch != beforeRejected.Applied.ConfigEpoch ||
		authority.Epoch <= previousAuthority.Epoch || authority.Validity != "valid" {
		t.Fatalf("rejected candidate changed durable or acknowledged authority: revision=%s/%s target-equal=%t config-epoch=%d/%d crowd-before=%+v crowd-after=%+v", current.ID, preserved.ID, reflect.DeepEqual(preserved.Target, current.Target), beforeRejected.Applied.ConfigEpoch, afterRejected.Applied.ConfigEpoch, previousAuthority, authority)
	}
	rejectionStore, err := state.Open("/var/lib/perimeterd", nil)
	if err != nil {
		t.Fatal(err)
	}
	rejectedView, err := rejectionStore.Read()
	if err != nil || rejectedView.Journal != nil || rejectedView.Active == nil || rejectedView.Active.ID != current.ID {
		t.Fatalf("rejection left unsafe durable authority/journal: %+v (%v)", rejectedView, err)
	}
	assertNativeProjection(t, current.Target, previousProjection, retainedUpdatedAfter, snapshot)
	t.Logf("phase=over-budget-daemon-candidate backend=%s resource=%s scope=%s required=%d limit=%d source-bytes=%d source-decisions=%d projected-prefixes=%d durable-envelope-bytes=%d retained-revision=%s retained-crowd-epoch=%d", capacity.Backend, capacity.Resource, capacity.Scope, capacity.RequiredBytes, capacity.LimitBytes, responseBytes, 2*65536, 65*65536, len(record), preserved.ID, authority.Epoch)
	recordE2EPhase(t, e2ePhaseRecord{Backend: backend, Profile: "dbip-euro-atlantic", Phase: phase, Event: "capacity_rejected", Outcome: "success", Resource: capacity.Resource, CapacityScope: capacity.Scope, RequiredBytes: capacity.RequiredBytes, LimitBytes: capacity.LimitBytes, ProjectedMemberships: 65 * 65536, StaticGeneration: current.Target.Generation, DynamicGeneration: current.Target.DynamicGeneration})
	foreign(snapshot)
	if !live {
		dbipCapacityPackets(t, peer, true, phase)
	}
	dbipCapacityMeasure(t, daemon, current.Target, phase, started, snapshot)
	phase = "later-admissible-source-and-config"
	started = beginDBIPPhase(t, backend, phase)
	fixture.mu.Lock()
	fixture.offset += 1000
	fixture.until = fixture.until.Add(time.Hour)
	fixture.serial++
	fixture.mu.Unlock()
	write(true, "drop")
	reload()
	current, snapshot = dbipCapacityState(t, live, 300000, phase)
	admitted := dbipCapacityStatus(t)
	if admitted.Applied.Details.CrowdSec.Epoch <= authority.Epoch || admitted.Applied.Revision == preserved.ID {
		t.Fatalf("later changed source authority was not acknowledged: %+v", admitted.Applied)
	}
	assertNativeProjection(t, current.Target, fixture.projection(t), started, snapshot)
	if !live {
		dbipCapacityPackets(t, peer, true, phase)
	}
	dbipCapacityMeasure(t, daemon, current.Target, phase, started, snapshot)
	daemon.stop(t)
	phase = "clean-restart"
	started = beginDBIPPhase(t, backend, phase)
	daemon = start()
	current, snapshot = dbipCapacityState(t, live, 300000, phase)
	dbipCapacityMeasure(t, daemon, current.Target, phase, started, snapshot)
	daemon.stop(t)
	// Exercise durable same-ID preparation and native partially switched state,
	// then distinct-generation preparation and partial family switching.
	partial := "after-switch"
	if backend == "iptables" {
		partial = "iptables-after-switch-v4"
	}
	for _, distinct := range []bool{false, true} {
		prepared := "journal:after-dir-sync"
		if distinct {
			prepared = "after-prepare"
		}
		for _, checkpoint := range []string{prepared, partial} {
			phase = fmt.Sprintf("interrupted-distinct-%t-%s", distinct, strings.ReplaceAll(checkpoint, ":", "-"))
			started = beginDBIPPhase(t, backend, phase)
			if distinct {
				write(true, "reject")
			}
			crashCheckpoint := checkpoint
			journalPhase := ""
			if !distinct && backend == "nftables" && checkpoint == partial {
				// Recover does not emit normal apply's after-switch hook. Its
				// durable switched-phase checkpoint follows the same-ID native
				// apply and still precedes recovery commit/retirement.
				crashCheckpoint = "journal:after-dir-sync"
				journalPhase = "switched"
			}
			extra := []string{"PERIMETERD_CAPACITY_CRASH=" + crashCheckpoint, "PERIMETERD_CAPACITY_CRASH_PHASE=" + journalPhase}
			if distinct {
				extra = append(extra, "PERIMETERD_CAPACITY_CRASH_DISTINCT=1")
			}
			cmd := capacityCommand(path, server.URL, extra...)
			if output, err := cmd.CombinedOutput(); !exitStatus(err, 97) {
				t.Fatalf("recovery interruption distinct=%t checkpoint=%s: %v\n%s", distinct, checkpoint, err, output)
			}
			store, err := state.Open("/var/lib/perimeterd", nil)
			if err != nil {
				t.Fatal(err)
			}
			view, err := store.Read()
			if err != nil || view.Journal == nil {
				t.Fatalf("missing interrupted journal: %v", err)
			}
			previous, candidate := view.Revisions[view.Journal.Previous], view.Revisions[view.Journal.Candidate]
			if previous == nil || candidate == nil {
				t.Fatal("journal lost target evidence")
			}
			different := previous.Target.Generation != candidate.Target.Generation
			if different != distinct {
				t.Fatalf("recovery identity mismatch: distinct=%t previous=%s candidate=%s", distinct, previous.Target.Generation, candidate.Target.Generation)
			}
			// Preflight admits an unrecorded candidate and must reject these
			// already-materialized names. Measure complete coexistence below;
			// actual recovery validates both durable targets before mutation.
			t.Logf("phase=interrupted distinct-request=%t checkpoint=%s native-checkpoint=%s journal-phase=%s previous=%s candidate=%s", distinct, checkpoint, crashCheckpoint, view.Journal.Phase, view.Journal.Previous, view.Journal.Candidate)
			snapshot = captureNativePhase(t, candidate.Target, phase, true)
			dbipCapacityMeasure(t, nil, candidate.Target, phase, started, snapshot)
			phase = fmt.Sprintf("recovered-distinct-%t-%s", distinct, strings.ReplaceAll(checkpoint, ":", "-"))
			started = beginDBIPPhase(t, backend, phase)
			write(true, "drop")
			daemon = start()
			current, snapshot = dbipCapacityState(t, live, 300000, phase)
			if !live {
				dbipCapacityPackets(t, peer, true, phase)
			}
			foreign(snapshot)
			dbipCapacityMeasure(t, daemon, current.Target, phase, started, snapshot)
			daemon.stop(t)
		}
	}
	cleanupStarted := time.Now()
	cleanupOutput := command(t, 15*time.Minute, e2eBinary(t), "cleanup")
	store, err := state.Open("/var/lib/perimeterd", nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil || view.Active != nil || view.Journal != nil {
		t.Fatalf("cleanup retained active authority or journal: %+v (%v)", view, err)
	}
	foreign(nil)
	if backend == "iptables" {
		waitNoIPTablesOwned(t, "v4", "v6")
		if names := strings.Fields(string(command(t, 10*time.Second, "ipset", "list", "-name"))); len(names) != 1 || names[0] != "capacity_foreign" {
			t.Fatalf("owned ipsets remained after cleanup: %v", names)
		}
	} else if output, err := nftTableMayFail(current.Target.Table); err == nil {
		t.Fatalf("owned table remained after cleanup: %s", output)
	}
	t.Logf("phase=owned-cleanup complete; active=nil journal=nil foreign objects retained wall=%s output=%s", time.Since(cleanupStarted), strings.TrimSpace(string(cleanupOutput)))
}
