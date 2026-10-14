//go:build linux && e2e

package e2e

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/control"
	"github.com/perimeterd/perimeterd/internal/testutil/crowdsecfixture"
)

type largeCrowdFixture struct {
	mu     sync.Mutex
	mode   string
	served bool
	bytes  int64
}

func (f *largeCrowdFixture) set(mode string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.mode, f.served = mode, false
}

func (f *largeCrowdFixture) serve(w http.ResponseWriter, r *http.Request) {
	if r.Header.Get("X-Api-Key") != crowdFixtureKey || r.URL.Path != "/v1/decisions/stream" || r.URL.Query().Get("scopes") != "ip,range" || r.URL.Query().Get("dedup") != "false" {
		w.WriteHeader(http.StatusForbidden)
		return
	}
	f.mu.Lock()
	mode, served := f.mode, f.served
	f.served = true
	f.mu.Unlock()
	w.Header().Set("Content-Type", "application/json")
	if mode == "http" || ((mode == "overflow" || mode == "truncated") && served) {
		w.WriteHeader(http.StatusUnauthorized)
		_, _ = io.WriteString(w, "SECRET-HOSTILE-BODY")
		return
	}
	if mode == "large" && !served {
		snapshot := crowdsecfixture.Snapshot{Count: crowdsecfixture.LargeCount, Until: time.Now().Add(time.Hour), IPv4: fixtureIPv4Peer, IPv6: fixtureIPv6Peer}
		buffer := bufio.NewWriterSize(w, 32<<10)
		n, err := io.Copy(buffer, snapshot.Reader())
		if err != nil {
			return
		}
		if err := buffer.Flush(); err != nil {
			return
		}
		f.mu.Lock()
		f.bytes = n
		f.mu.Unlock()
		return
	}
	if mode == "truncated" || mode == "overflow" {
		// Both complete decision members precede the corruption: accepting a
		// parsed prefix would ban the previously unblocked public test peer.
		_, _ = fmt.Fprint(w, `{"deleted":[{"id":1}],"new":[{"id":900000,"type":"ban","scope":"ip","value":"8.23.0.2","duration":"1h"}]`)
		if mode == "overflow" {
			_, _ = io.WriteString(w, "}")
			chunk := strings.Repeat(" ", 32<<10)
			for sent := 0; sent <= 256<<20; sent += len(chunk) {
				if _, err := io.WriteString(w, chunk); err != nil {
					return
				}
			}
		}
		return
	}
	if mode == "resync" && r.URL.Query().Get("startup") == "true" {
		_, _ = fmt.Fprintf(w, `{"new":[{"id":2,"type":"ban","scope":"ip","value":%q,"duration":"1h"}],"deleted":[]}`, fixtureIPv6Peer)
		return
	}
	_, _ = io.WriteString(w, `{"new":[],"deleted":[]}`)
}

func largeCrowdStatus(t *testing.T) control.StatusResult {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- the validated isolated E2E binary is controlled by this harness.
	output, err := exec.CommandContext(ctx, e2eBinary(t), "status", "--json").CombinedOutput()
	var status control.StatusResult
	if json.Unmarshal(output, &status) != nil {
		t.Fatalf("status failed: %v\n%s", err, output)
	}
	return status
}

func TestE2ECrowdSecLargeSnapshot(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		t.Logf("%s", runIsolated(t, "TestE2ECrowdSecLargeSnapshot", "nftables"))
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	command(t, 10*time.Second, "ip", "addr", "add", "8.23.0.1/24", "dev", "e2h0")
	peer.run(t, "ip", "addr", "add", "8.23.0.2/24", "dev", "e2p0")
	fixture := &largeCrowdFixture{mode: "large"}
	server := httptest.NewServer(http.HandlerFunc(fixture.serve))
	t.Cleanup(server.Close)
	configPath := tempConfig(t, "crowdsec-large")
	keyPath := filepath.Join(t.TempDir(), "crowdsec.key")
	if err := os.WriteFile(keyPath, []byte(crowdFixtureKey), 0o600); err != nil {
		t.Fatal(err)
	}
	writeCrowdConfig(t, configPath, "nftables", fmt.Sprintf("crowd_large_%d", os.Getpid()), server.URL, keyPath, true, nil)
	started := time.Now()
	daemon := startDaemonProcess(t, configPath, "large CrowdSec snapshot", func() bool { return activeRevision() != "" })
	fixture.mu.Lock()
	size := fixture.bytes
	fixture.mu.Unlock()
	if size < 100<<20 {
		t.Fatalf("large daemon fixture only %d bytes", size)
	}
	t.Logf("actual daemon large startup bytes=%d elapsed=%s", size, time.Since(started))
	initial := largeCrowdStatus(t)
	if initial.Applied.Details == nil || initial.Applied.Details.CrowdSec.Counts == nil {
		t.Fatalf("no acknowledged CrowdSec counts: %+v", initial)
	}
	counts := *initial.Applied.Details.CrowdSec.Counts
	if counts.IPv4 != crowdsecfixture.LargeCount-2 || counts.IPv6 != 1 {
		t.Fatalf("large startup counts: %+v", counts)
	}
	if result := lookupCommand(t, fixtureIPv4Peer, "ingress", "tcp", nil); result.response.Verdict != "blocked" {
		t.Fatalf("large stream lookup: %s", result.output)
	}
	if processStatus, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", daemon.cmd.Process.Pid)); err == nil {
		for _, line := range strings.Split(string(processStatus), "\n") {
			if strings.HasPrefix(line, "VmHWM:") {
				t.Logf("daemon-only peak RSS after large startup: %s (generator runs in test process)", line)
			}
		}
	}
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18780", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18780", "reject", "tcp")
	for index, mode := range []string{"truncated", "overflow"} {
		beforeLog := len(daemon.output.String())
		fixture.set(mode)
		category := "malformed"
		if mode == "overflow" {
			category = "268435456"
		}
		waitCrowdCondition(t, mode+" poll rejected", func() bool { return strings.Contains(daemon.output.String()[beforeLog:], category) })
		current := largeCrowdStatus(t)
		if current.Applied.Revision != initial.Applied.Revision || current.Applied.Details == nil || current.Applied.Details.CrowdSec.Operation != initial.Applied.Details.CrowdSec.Operation {
			t.Fatalf("failed %s stream changed acknowledged state: %+v", mode, current)
		}
		probeIngress(t, peer, "tcp4", fixtureIPv4Host+fmt.Sprintf(":%d", 18781+index), "reject", "tcp")
		probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]"+fmt.Sprintf(":%d", 18781+index), "reject", "tcp")
		probeIngress(t, peer, "tcp4", "8.23.0.1"+fmt.Sprintf(":%d", 18781+index), "success", "tcp")
	}
	fixture.set("resync")
	waitCrowdPacket(t, peer, "tcp4", fixtureIPv4Host+":18784", "success")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18784", "reject", "tcp")
	resynced := largeCrowdStatus(t)
	if resynced.Applied.Details == nil || resynced.Applied.Details.CrowdSec.Counts == nil || *resynced.Applied.Details.CrowdSec.Counts != (control.StatusDecisionCounts{IPv6: 1}) {
		t.Fatalf("valid resync did not replace failed state: %+v", resynced)
	}
	daemon.stop(t)
	for _, mode := range []string{"http", "overflow"} {
		fixture.set(mode)
		ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
		// #nosec G204 -- the validated isolated E2E binary is controlled by this harness.
		output, err := exec.CommandContext(ctx, e2eBinary(t), "run", "--config", configPath).CombinedOutput()
		cancel()
		category := "HTTP 401"
		if mode == "overflow" {
			category = "268435456"
		}
		if err == nil || ctx.Err() == context.DeadlineExceeded || !strings.Contains(string(output), category) || strings.Contains(string(output), "SECRET-HOSTILE-BODY") || strings.Contains(string(output), crowdFixtureKey) || strings.Contains(string(output), server.URL) {
			t.Fatalf("unsafe or unhelpful %s startup diagnostic: %v\n%s", mode, err, output)
		}
		t.Logf("%s startup rejected with sanitized category %s", mode, category)
	}
}
