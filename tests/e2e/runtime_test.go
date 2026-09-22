//go:build linux && e2e

package e2e

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"testing"
	"time"
)

func TestE2ERuntime(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		runIsolated(t, "TestE2ERuntime", "runtime")
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	table := fmt.Sprintf("pde2e_%d", os.Getpid())
	foreign := table + "_foreign"
	configPath := tempConfig(t, "runtime")
	collision := table + "_collision"
	createForeignTable(t, collision)
	createForeignTable(t, foreign)
	writeConfig(t, configPath, table, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureLANPeer + "/32", fixtureIPv6Peer + "/128"}, -10)
	daemon := startDaemon(t, configPath, table)
	assertLockCollision(t, configPath)

	// Both families and both directions are real packets through the daemon's
	// nftables hooks. Public fixture addresses avoid the immutable LAN allowlist.
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18080", "drop", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18080", "drop", "tcp")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18081", "drop", "tcp")
	probeEgress(t, peer, "tcp6", "["+fixtureIPv6Peer+"]:18081", "drop", "tcp")
	probeIngress(t, peer, "udp4", fixtureIPv4Host+":18082", "drop", "udp")
	probeIngress(t, peer, "udp6", "["+fixtureIPv6Host+"]:18082", "drop", "udp")
	probeEgress(t, peer, "udp4", fixtureIPv4Peer+":18083", "drop", "udp")
	// Immutable built-in LAN ranges remain reachable even when listed in the
	// direct global blocklist.
	probeIngress(t, peer, "tcp4", fixtureLANHost+":18085", "success", "tcp")
	probeEgress(t, peer, "tcp4", fixtureLANPeer+":18086", "success", "tcp")
	probeEgress(t, peer, "udp6", "["+fixtureIPv6Peer+"]:18083", "drop", "udp")

	// Removing one configured family retires only that family's path. The
	// remaining IPv4 block stays active while IPv6 traffic returns normally.
	writeConfigFamilies(t, configPath, table, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10, true, false)
	before := activeRevision()
	daemon.reload(t)
	waitForActiveRevisionChange(t, before, configPath)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18080", "drop", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18080", "success", "tcp")
	probeEgress(t, peer, "tcp6", "["+fixtureIPv6Peer+"]:18081", "success", "tcp")
	writeConfig(t, configPath, table, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	before = activeRevision()
	daemon.reload(t)
	waitForActiveRevisionChange(t, before, configPath)

	beforeCounters := nftCounters(t, table)
	if len(beforeCounters) == 0 {
		t.Fatal("nftables target has no named accounting counters")
	}

	// Explicit global allows take precedence over the same global blocks.
	writeConfig(t, configPath, table, "drop", []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	before = activeRevision()
	daemon.reload(t)
	waitForActiveRevisionChange(t, before, configPath)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18080", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18080", "success", "tcp")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18081", "success", "tcp")
	probeEgress(t, peer, "tcp6", "["+fixtureIPv6Peer+"]:18081", "success", "tcp")

	// Native nftables /0 sets retain allow-before-block precedence.
	writeConfig(t, configPath, table, "drop", []string{"0.0.0.0/0", "::/0"}, []string{"0.0.0.0/0", "::/0"}, -10)
	before = activeRevision()
	daemon.reload(t)
	waitForActiveRevisionChange(t, before, configPath)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18080", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18080", "success", "tcp")

	// A connection established before a reload remains usable after a new-flow
	// block is selected, proving the ESTABLISHED guard precedes denial.
	listenerCmd, ready := startPeerListener(t, peer, "tcp4", fixtureIPv4Peer+":18084")
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("peer established-flow listener did not become ready")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("peer established-flow listener timed out")
	}
	conn, err := net.DialTimeout("tcp4", fixtureIPv4Peer+":18084", 2*time.Second)
	if err != nil {
		t.Fatalf("establish egress flow: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("a")); err != nil {
		t.Fatalf("initial established write: %v", err)
	}
	var response [1]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		t.Fatalf("initial established response: %v", err)
	}
	writeConfig(t, configPath, table, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	before = activeRevision()
	daemon.reload(t)
	waitForActiveRevisionChange(t, before, configPath)
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("b")); err != nil {
		t.Fatalf("established flow was interrupted by reload: %v", err)
	}
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		t.Fatalf("established response after reload: %v", err)
	}
	_ = conn.Close()
	_ = listenerCmd.Process.Kill()
	_ = listenerCmd.Wait()
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18084", "drop", "tcp")

	// Reject is observable as a prompt connection failure, unlike DROP's
	// timeout. A malformed HUP must preserve this active enforcement.
	writeConfig(t, configPath, table, "reject", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	before = activeRevision()
	daemon.reload(t)
	waitForActiveRevisionChange(t, before, configPath)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18080", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18080", "reject", "tcp")
	probeIngress(t, peer, "udp4", fixtureIPv4Host+":18082", "reject", "udp")
	probeIngress(t, peer, "udp6", "["+fixtureIPv6Host+"]:18082", "reject", "udp")
	probeEgress(t, peer, "udp4", fixtureIPv4Peer+":18083", "reject", "udp")
	probeEgress(t, peer, "udp6", "["+fixtureIPv6Peer+"]:18083", "reject", "udp")
	writeInvalidConfigMarker(t, configPath, "unsupported-native-reload")
	diagnosticOffset := daemonDiagnosticOffset(daemon)
	daemon.reload(t)
	waitForDaemonDiagnostic(t, daemon, []string{"unsupported-native-reload"}, diagnosticOffset)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18080", "reject", "tcp")

	// Priority-only reload replaces only hook chains. The stable counters remain
	// present and retain their values while the generated path is unchanged.
	writeConfig(t, configPath, table, "reject", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -9)
	before = activeRevision()
	daemon.reload(t)
	waitForActiveRevisionChange(t, before, configPath)
	priorities := nftHookPriorities(t, table)
	foundPriority := false
	for _, priority := range priorities {
		if priority == -9 {
			foundPriority = true
			break
		}
	}
	if !foundPriority {
		t.Fatalf("nftables hook priority did not switch to -9: %#v", priorities)
	}
	afterCounters := nftCounters(t, table)
	sharedCounter := false
	for name, before := range beforeCounters {
		if after, ok := afterCounters[name]; ok {
			sharedCounter = true
			if after < before {
				t.Fatalf("stable counter %q reset across reload: before=%d after=%d", name, before, after)
			}
		}
	}
	if !sharedCounter {
		t.Fatalf("no stable named counters survived reload: before=%v after=%v", beforeCounters, afterCounters)
	}

	// An unrecorded same-name table is a hard collision. Reload failure must
	// preserve the active target and the foreign table byte-for-byte.
	writeConfig(t, configPath, collision, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -9)
	diagnosticOffset = daemonDiagnosticOffset(daemon)
	daemon.reload(t)
	waitForDaemonDiagnostic(t, daemon, []string{"foreign_child"}, diagnosticOffset)
	if _, err := nftTableMayFail(table); err != nil {
		t.Fatalf("collision reload removed active table: %v", err)
	}
	assertForeignTable(t, collision)

	// Table migration builds a second owned table before retiring the first.
	migrated := table + "_m"
	writeConfig(t, configPath, migrated, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -9)
	daemon.reload(t)
	waitForNFTTable(t, migrated)
	waitNoNFTTable(t, table)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18080", "drop", "tcp")

	// The canonical empty model unhooks and removes all owned artifacts.
	writeConfig(t, configPath, migrated, "drop", nil, nil, -9)
	daemon.reload(t)
	waitNoNFTTable(t, migrated)
	assertForeignTable(t, foreign)
	assertForeignTable(t, collision)

	// Reinstall a non-empty target so normal SIGTERM can prove that a committed
	// target survives shutdown independently of explicit cleanup.
	writeConfig(t, configPath, migrated, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -9)
	daemon.reload(t)
	waitForNFTTable(t, migrated)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18080", "drop", "tcp")

	// Normal TERM deliberately leaves the committed target active.
	daemon.stop(t)
	if _, err := nftTableMayFail(migrated); err != nil {
		t.Fatalf("normal stop removed active nftables table: %v", err)
	}

	// Reboot-style self-recovery: retain durable target metadata and owned
	// objects, remove only table rules, and require startup to restore actual
	// packet enforcement before the process can serve.
	flushOwnedTableRules(t, migrated)
	daemon = startDaemon(t, configPath, migrated)
	waitCrowdPacket(t, peer, "tcp4", fixtureIPv4Host+":18080", "drop")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18081", "drop", "tcp")
	daemon.stop(t)

	command(t, 30*time.Second, e2eBinary(t), "cleanup")
	waitNoNFTTable(t, migrated)
	assertForeignTable(t, foreign)
	assertForeignTable(t, collision)
}

func TestE2ELiteralTableName(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		runIsolated(t, "TestE2ELiteralTableName", "literal-table")
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	sentinel := "sentinel"
	foreign := "foreign"
	owned := "sentinel; delete table inet foreign"
	configPath := tempConfig(t, "literal-table")
	createForeignTable(t, sentinel)
	createForeignTable(t, foreign)
	writeConfig(t, configPath, owned, "drop", nil, []string{fixtureIPv4Peer + "/32"}, -10)
	daemon := startDaemon(t, configPath, owned)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18280", "drop", "tcp")
	daemon.stop(t)
	command(t, 30*time.Second, e2eBinary(t), "cleanup")
	waitNoNFTTable(t, owned)
	assertForeignTable(t, sentinel)
	assertForeignTable(t, foreign)
}

func waitForNFTTable(t *testing.T, table string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := nftTableMayFail(table); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("nftables table %q did not appear", table)
}

func TestE2EDeletionAssertionRejectsInspectionFailure(t *testing.T) {
	const helperEnv = "PERIMETERD_E2E_INSPECTION_FAILURE"
	if os.Getenv(helperEnv) == "1" {
		t.Setenv("PATH", t.TempDir())
		waitNoNFTTable(t, "uninspectable-table")
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	// #nosec G204 G702 -- invokes this test executable with a fixed helper selector.
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run", "^TestE2EDeletionAssertionRejectsInspectionFailure$")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("inspection failure did not fail promptly: %v\n%s", ctx.Err(), output)
	}
	var exitErr *exec.ExitError
	if !errors.As(err, &exitErr) || exitErr.ExitCode() != 1 {
		t.Fatalf("expected a failed deletion assertion, got %v\n%s", err, output)
	}
}

func TestE2EInspectionRequiresRulesetEnvelope(t *testing.T) {
	if _, _, err := selectNFTTable([]byte(`{}`), "absent"); err == nil {
		t.Fatal("missing ruleset envelope was accepted as absence")
	}
	if _, found, err := selectNFTTable([]byte(`{"nftables":[]}`), "absent"); err != nil || found {
		t.Fatalf("valid empty ruleset was not accepted as absence: found=%v, err=%v", found, err)
	}
}
