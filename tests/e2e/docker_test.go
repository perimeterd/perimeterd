//go:build linux && e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"regexp"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/app"
	"github.com/perimeterd/perimeterd/internal/firewall"
)

const dockerE2EEnv = "PERIMETERD_DOCKER_E2E"

// TestE2EDockerCoexistence exercises the iptables integration point Docker
// documents for third-party policy engines. The daemon and Docker both run in
// the isolated child, so every assertion below observes packets through real
// Docker-generated NAT/filter rules.
func TestE2EDockerCoexistence(t *testing.T) {
	if os.Getenv(dockerE2EEnv) != "1" {
		t.Skip("PERIMETERD_DOCKER_E2E=1 is required")
	}
	if os.Getenv(e2eChildEnv) != "1" {
		for _, variant := range []string{"nft", "legacy"} {
			t.Run(variant, func(t *testing.T) {
				t.Logf("%s", runIsolated(t, "TestE2EDockerCoexistence", variant))
			})
		}
		return
	}

	requireIsolatedChild(t)
	prepareMounts(t)
	variant := os.Getenv(e2eScenario)
	installIPTablesTools(t, variant)
	fixture := newDockerFixture(t)
	peer := fixture.peer

	// Confirm the fixture's two independent published ports and both address
	// families before perimeterd is present. These are the success controls for
	// Docker's own DNAT and the dual-stack bridge.
	for _, probe := range []struct {
		network string
		address string
	}{
		{"tcp4", fixtureIPv4Host + ":18080"},
		{"tcp4", fixtureIPv4Host + ":18081"},
		{"tcp6", "[" + fixtureIPv6Host + "]:18080"},
		{"tcp6", "[" + fixtureIPv6Host + "]:18081"},
	} {
		fixture.peerProbe(t, probe.network, probe.address, "success")
	}

	containerIPs := dockerContainerIPs(t, fixture)
	configPath := tempConfig(t, "docker-coexistence")
	dockerOnlyBaseline := dockerForeignSnapshot(t)
	writeDockerCoexistenceConfig(t, configPath, "reject", true, containerIPs, "DOCKER-USER")
	geo := &geoFixtureTransport{started: time.Now(), validFor: 20 * time.Minute}
	daemon := startDockerPolicyDaemon(t, configPath, geo)

	// TW is deliberately mapped by the offline source fixture to 8.22/2600:22;
	// the peer is 8.20/2600:20. An ingress allowlist therefore denies only the
	// requested original host port and returns all other traffic to Docker.
	fixture.peerProbe(t, "tcp4", fixtureIPv4Host+":18080", "reject")
	fixture.peerProbe(t, "tcp6", "["+fixtureIPv6Host+"]:18080", "reject")
	fixture.peerProbe(t, "tcp4", fixtureIPv4Host+":18081", "success")
	fixture.peerProbe(t, "tcp6", "["+fixtureIPv6Host+"]:18081", "success")
	if got := dockerForeignSnapshot(t); !bytes.Equal(got, dockerOnlyBaseline) {
		t.Fatalf("Docker rules changed during perimeterd apply:\n%s", got)
	}

	// A policy that would reject the container's source addresses if the
	// attachment were incorrectly treated as ingress proves that egress is not
	// accidentally classified by the e2h0-only DOCKER-USER hook.
	for _, listener := range []struct {
		network string
		address string
	}{
		{"tcp4", fixtureIPv4Peer + ":18080"},
		{"tcp6", "[" + fixtureIPv6Peer + "]:18080"},
	} {
		probeDockerEgress(t, fixture, peer, listener.network, listener.address)
	}
	for _, address := range []string{fixtureIPv4Peer, fixtureIPv6Peer} {
		response := waitForLookupVerdict(t, address, "ingress", "tcp", new(uint16(18080)), "blocked")
		outcome, ok := lookupOutcome(response, "blocked", "policy")
		if !ok || outcome.Attachment.PortBasis != "original_destination" {
			t.Fatalf("Docker original-destination lookup for %s omitted managed policy/port basis: %+v", address, response.Outcomes)
		}
	}

	// Put a foreign reject after the managed jump; the 18081 mapping must then
	// fail, proving that perimeterd's RETURN cannot bypass downstream authority.
	for _, family := range []string{"iptables", "ip6tables"} {
		insertForeignDockerDeny(t, family)
		assertDockerUserOrdering(t, family)
	}
	fixture.peerProbe(t, "tcp4", fixtureIPv4Host+":18081", "reject")
	fixture.peerProbe(t, "tcp6", "["+fixtureIPv6Host+"]:18081", "reject")
	for _, address := range []string{fixtureIPv4Peer, fixtureIPv6Peer} {
		response := waitForLookupVerdict(t, address, "ingress", "tcp", new(uint16(18081)), "not_blocked")
		if len(response.Outcomes) != 1 || response.Outcomes[0].Attachment.PortBasis != "original_destination" {
			t.Fatalf("foreign Docker denial was attributed to perimeterd for %s: %+v", address, response.Outcomes)
		}
	}
	baseline := dockerForeignSnapshot(t)
	before := activeIPTablesRevision()
	writeDockerCoexistenceConfig(t, configPath, "reject", false, containerIPs, "DOCKER-USER")
	daemon.reload(t)
	waitForIPTablesCommit(t, before)
	// With original_destination=false, Docker's translated destination is 8080,
	// so the 18080 policy does not match and the published mapping succeeds.
	fixture.peerProbe(t, "tcp4", fixtureIPv4Host+":18080", "success")
	fixture.peerProbe(t, "tcp6", "["+fixtureIPv6Host+"]:18080", "success")
	for _, address := range []string{fixtureIPv4Peer, fixtureIPv6Peer} {
		response := waitForLookupVerdict(t, address, "ingress", "tcp", new(uint16(8080)), "not_blocked")
		if len(response.Outcomes) != 1 || response.Outcomes[0].Attachment.PortBasis != "current_destination" {
			t.Fatalf("Docker current-destination lookup for %s retained original-port denial: %+v", address, response.Outcomes)
		}
	}
	if got := dockerForeignSnapshot(t); !bytes.Equal(got, baseline) {
		t.Fatalf("Docker/foreign rules changed across original-destination reload:\n%s", got)
	}
	assertDockerUserOrdering(t, "iptables")
	assertDockerUserOrdering(t, "ip6tables")

	before = activeIPTablesRevision()
	writeDockerCoexistenceConfig(t, configPath, "reject", true, containerIPs, "DOCKER-USER")
	daemon.reload(t)
	waitForIPTablesCommit(t, before)
	fixture.peerProbe(t, "tcp4", fixtureIPv4Host+":18080", "reject")
	fixture.peerProbe(t, "tcp6", "["+fixtureIPv6Host+"]:18080", "reject")
	for _, address := range []string{fixtureIPv4Peer, fixtureIPv6Peer} {
		response := waitForLookupVerdict(t, address, "ingress", "tcp", new(uint16(18080)), "blocked")
		if outcome, ok := lookupOutcome(response, "blocked", "policy"); !ok || outcome.Attachment.PortBasis != "original_destination" {
			t.Fatalf("rejected Docker reload changed lookup authority for %s: %+v", address, response.Outcomes)
		}
	}
	if got := dockerForeignSnapshot(t); !bytes.Equal(got, baseline) {
		t.Fatalf("Docker/foreign rules changed across policy reload:\n%s", got)
	}

	assertDockerUserOrdering(t, "iptables")
	assertDockerUserOrdering(t, "ip6tables")
	// A candidate with a missing parent must fail closed: the active revision and
	// enforcement remain untouched, and no Docker-owned chain is removed.
	active := activeIPTablesRevision()
	writeDockerCoexistenceConfig(t, configPath, "reject", true, containerIPs, "DOCKER-USER-NOT-PRESENT")
	daemon.reload(t)
	daemon.waitReloadFailure(t, active)
	fixture.peerProbe(t, "tcp4", fixtureIPv4Host+":18080", "reject")
	fixture.peerProbe(t, "tcp6", "["+fixtureIPv6Host+"]:18080", "reject")

	daemon.stop(t)
	for _, address := range []string{fixtureIPv4Peer, fixtureIPv6Peer} {
		requireLookupUnknown(t, lookupCommand(t, address, "ingress", "tcp", new(uint16(18080))), address)
	}
	if got := dockerForeignSnapshot(t); !bytes.Equal(got, baseline) {
		t.Fatalf("Docker/foreign rules changed across daemon stop:\n%s", got)
	}
	fixture.peerProbe(t, "tcp4", fixtureIPv4Host+":18080", "reject")
	fixture.peerProbe(t, "tcp6", "["+fixtureIPv6Host+"]:18080", "reject")
	command(t, 30*time.Second, e2eBinary(t), "cleanup")
	waitNoIPTablesOwned(t, "v4", "v6")
	if got := dockerForeignSnapshot(t); !bytes.Equal(got, baseline) {
		t.Fatalf("Docker/foreign rules changed across owned cleanup:\n%s", got)
	}
	fixture.peerProbe(t, "tcp4", fixtureIPv4Host+":18080", "success")
	fixture.peerProbe(t, "tcp6", "["+fixtureIPv6Host+"]:18080", "success")
	fixture.peerProbe(t, "tcp4", fixtureIPv4Host+":18081", "reject")
	fixture.peerProbe(t, "tcp6", "["+fixtureIPv6Host+"]:18081", "reject")
}

type dockerPreflightObserver struct {
	firewall.Backend
	rejected chan error
}

func (b *dockerPreflightObserver) Preflight(ctx context.Context, previous, candidate *firewall.Target, dynamic *firewall.DynamicState) error {
	err := b.Backend.Preflight(ctx, previous, candidate, dynamic)
	if err != nil {
		b.rejected <- err
	}
	return err
}

type dockerDaemon struct {
	cancel   context.CancelFunc
	signals  chan os.Signal
	done     chan error
	rejected <-chan error
	output   *lockedBuffer
	stopped  bool
}

func startDockerPolicyDaemon(t *testing.T, configPath string, geo *geoFixtureTransport) *dockerDaemon {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 2)
	done := make(chan error, 1)
	ready := make(chan struct{}, 1)
	output := new(lockedBuffer)
	backend := &dockerPreflightObserver{Backend: firewall.NewNative(nil), rejected: make(chan error, 1)}
	d := &dockerDaemon{cancel: cancel, signals: signals, done: done, rejected: backend.rejected, output: output}
	go func() {
		done <- app.Run(ctx, app.Options{
			ConfigPath:   configPath,
			StateDir:     "/var/lib/perimeterd",
			LockPath:     "/run/perimeterd/owner.lock",
			SourceClient: &http.Client{Transport: geo},
			Backend:      backend,
			Signals:      signals,
			Stderr:       output,
			Notify: func(status string) error {
				if strings.Contains(status, "READY=1") {
					select {
					case ready <- struct{}{}:
					default:
					}
				}
				return nil
			},
			StartupTimeout: 2 * time.Minute,
		})
	}()
	t.Cleanup(func() { d.stop(t) })
	select {
	case <-ready:
	case err := <-done:
		d.stopped = true
		t.Fatalf("perimeterd exited during startup: %v\n%s", err, output.String())
	case <-time.After(2 * time.Minute):
		t.Fatalf("perimeterd readiness timed out\n%s", output.String())
	}
	waitForIPTablesOwned(t, "v4", "v6")
	return d
}

func (d *dockerDaemon) reload(t *testing.T) {
	t.Helper()
	if d.stopped {
		t.Fatal("reload after daemon stop")
	}
	d.signals <- syscall.SIGHUP
}

func (d *dockerDaemon) waitReloadFailure(t *testing.T, active string) {
	t.Helper()
	select {
	case err := <-d.rejected:
		t.Logf("candidate rejected without replacing active policy: %v", err)
		if got := activeIPTablesRevision(); got != active {
			t.Fatalf("failed reload changed active revision: before=%q after=%q", active, got)
		}
	case err := <-d.done:
		d.stopped = true
		t.Fatalf("perimeterd exited during failed reload: %v\n%s", err, d.output.String())
	case <-time.After(30 * time.Second):
		t.Fatalf("missing-parent preflight did not reject candidate\n%s", d.output.String())
	}
}

func (d *dockerDaemon) stop(t *testing.T) {
	t.Helper()
	if d.stopped {
		return
	}
	d.stopped = true
	d.cancel()
	select {
	case err := <-d.done:
		if err != nil && !errors.Is(err, context.Canceled) {
			t.Fatalf("perimeterd stop: %v", err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("perimeterd did not stop")
	}
}

func probeDockerEgress(t *testing.T, fixture *dockerFixture, peer *peerNamespace, network, address string) {
	t.Helper()
	cmd := peer.helper(t, "listen-tcp", network, address, "success")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("peer listener stdout: %v", err)
	}
	stderr := new(lockedBuffer)
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start peer listener: %v", err)
	}
	defer func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	}()
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		ready <- scanner.Scan() && scanner.Text() == "READY"
	}()
	select {
	case ok := <-ready:
		if !ok {
			t.Fatalf("peer listener did not become ready: %s", stderr.String())
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("peer listener readiness timed out: %s", stderr.String())
	}
	fixture.containerProbe(t, network, address, "success")
}

func dockerContainerIPs(t *testing.T, fixture *dockerFixture) []string {
	t.Helper()
	output := fixture.command(t, "inspect", "--format", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{.GlobalIPv6Address}}{{end}}", fixture.containerName)
	values := strings.Fields(string(output))
	if len(values) < 2 {
		t.Fatalf("Docker inspect returned no dual-stack container addresses: %q", output)
	}
	return []string{values[0] + "/32", values[1] + "/128"}
}

func writeDockerCoexistenceConfig(t *testing.T, path, action string, originalDestination bool, block []string, chain string) {
	t.Helper()
	var yaml strings.Builder
	yaml.WriteString("version: 1\nlogging:\n  level: warn\n  format: text\nmetrics:\n  listen: \"\"\nglobal:\n  allowlist: []\n  blocklist:\n")
	for _, prefix := range block {
		fmt.Fprintf(&yaml, "    - %q\n", prefix)
	}
	fmt.Fprintf(&yaml, "firewall:\n  backend: iptables\n  deny_action: %s\n  ipv4: true\n  ipv6: true\n  iptables:\n    attachments:\n      - chain: %q\n        direction: ingress\n        input_interfaces: [\"e2h0\"]\n", action, chain)
	if originalDestination {
		yaml.WriteString("        original_destination: true\n")
	}
	yaml.WriteString("geo:\n  refresh_interval: 24h\n  request_timeout: 2s\n  refresh_jitter: 1s\ngroups: {}\npolicies:\n  - name: docker-ingress\n    priority: 10\n    direction: ingress\n    mode: allowlist\n    traffic: [\"18080/tcp\"]\n    include:\n      countries: [TW]\ncrowdsec:\n  enabled: false\n")
	if err := os.WriteFile(path, []byte(yaml.String()), 0o600); err != nil {
		t.Fatalf("write Docker config: %v", err)
	}
}

func insertForeignDockerDeny(t *testing.T, commandName string) {
	t.Helper()
	lines := strings.Split(string(command(t, 10*time.Second, commandName, "-S", "DOCKER-USER")), "\n")
	position := 0
	for _, line := range lines {
		if !strings.HasPrefix(line, "-A DOCKER-USER ") {
			continue
		}
		position++
		if strings.Contains(line, "perimeterd owner=") {
			position++
			break
		}
	}
	if position == 0 {
		t.Fatalf("managed perimeterd jump missing from %s DOCKER-USER chain:\n%s", commandName, strings.Join(lines, "\n"))
	}
	command(t, 10*time.Second, commandName, "-I", "DOCKER-USER", strconv.Itoa(position), "-p", "tcp", "-m", "conntrack", "--ctorigdstport", "18081", "-m", "comment", "--comment", "docker-e2e-foreign", "-j", "REJECT", "--reject-with", "tcp-reset")
}

func assertDockerUserOrdering(t *testing.T, commandName string) {
	t.Helper()
	lines := strings.Split(string(command(t, 10*time.Second, commandName, "-S", "DOCKER-USER")), "\n")
	owned, ret, foreign := 0, 0, 0
	position := 0
	for _, line := range lines {
		if !strings.HasPrefix(line, "-A DOCKER-USER ") {
			continue
		}
		position++
		if strings.Contains(line, "perimeterd owner=") {
			owned = position
		}
		if strings.Contains(line, "docker-e2e-foreign") {
			foreign = position
		}
		if strings.HasSuffix(line, "-j RETURN") {
			ret = position
		}
	}
	if owned == 0 || foreign == 0 || owned >= foreign || ret != 0 && owned >= ret {
		t.Fatalf("DOCKER-USER ordering is unsafe in %s: owned=%d foreign=%d return=%d\n%s", commandName, owned, foreign, ret, strings.Join(lines, "\n"))
	}
}

var dockerCounterPattern = regexp.MustCompile(`\[[0-9]+:[0-9]+\]`)

func dockerForeignSnapshot(t *testing.T) []byte {
	t.Helper()
	var snapshot strings.Builder
	for _, family := range []string{"v4", "v6"} {
		data, err := iptablesSaveMayFail(family)
		if err != nil {
			t.Fatalf("snapshot %s iptables: %v", family, err)
		}
		lines := strings.Split(string(data), "\n")
		ownedChains := make(map[string]bool)
		for _, line := range lines {
			if !strings.Contains(line, "perimeterd owner=") {
				continue
			}
			fields := strings.Fields(line)
			for index, field := range fields {
				if field == "-A" && index+1 < len(fields) && fields[index+1] != "DOCKER-USER" {
					ownedChains[fields[index+1]] = true
					break
				}
			}
		}
		for _, line := range lines {
			if line == "" || strings.HasPrefix(line, "#") || strings.Contains(line, "perimeterd owner=") {
				continue
			}
			if strings.HasPrefix(line, ":") && ownedChains[strings.Fields(line)[0][1:]] {
				continue
			}
			snapshot.WriteString(dockerCounterPattern.ReplaceAllString(line, "[0:0]"))
			snapshot.WriteByte('\n')
		}
		snapshot.WriteString("# family ")
		snapshot.WriteString(family)
		snapshot.WriteByte('\n')
	}
	return []byte(snapshot.String())
}
