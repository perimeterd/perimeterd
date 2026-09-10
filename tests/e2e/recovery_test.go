//go:build linux && e2e

package e2e

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestE2ERecovery(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		runIsolated(t, "TestE2ERecovery", "recovery")
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	table := fmt.Sprintf("pde2er_%d", os.Getpid())
	configPath := tempConfig(t, "recovery")
	writeConfig(t, configPath, table, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	daemon := startDaemon(t, configPath, table)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18180", "drop", "tcp")
	daemon.stop(t)

	// A one-shot after-switch error rolls a DROP->REJECT candidate back to the
	// real active target. The next normal reconciliation then succeeds without
	// orphaning candidate-only counters.
	baselineCounters := nftCounters(t, table)
	writeConfig(t, configPath, table, "reject", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	failedReload := startAppErrorHelper(t, configPath, "after-switch")
	if err := failedReload.Run(); !exitStatus(err, 98) {
		t.Fatalf("one-shot after-switch rollback returned %v", err)
	}
	afterRollbackCounters := nftCounters(t, table)
	if len(afterRollbackCounters) != len(baselineCounters) {
		t.Fatalf("rollback left candidate-only counters: before=%v after=%v", baselineCounters, afterRollbackCounters)
	}
	for name := range baselineCounters {
		if _, ok := afterRollbackCounters[name]; !ok {
			t.Fatalf("rollback removed stable counter %q", name)
		}
	}
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18180", "drop", "tcp")
	daemon = startDaemon(t, configPath, table)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18180", "reject", "tcp")
	daemon.stop(t)

	// A crash before durable active publication leaves the committed old target
	// authoritative. Recovery runs before the now-invalid YAML is read.
	writeConfig(t, configPath, table, "drop", []string{fixtureIPv4Peer + "/32"}, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	crash := startAppHelper(t, configPath, "active:before-file-sync", false)
	if err := crash.Run(); !exitStatus(err, 97) {
		t.Fatalf("pre-commit crash helper returned %v", err)
	}
	writeInvalidConfig(t, configPath)
	if err := runRunExpectFailure(t, configPath); err == nil {
		t.Fatal("run unexpectedly accepted invalid YAML after pre-commit crash")
	}
	// The recovered old target remains in force even though startup then rejects
	// the current configuration.
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18180", "reject", "tcp")

	// The rename boundary is also crash-safe: before rename restores the old
	// complete record and leaves no partially written active file.
	writeConfig(t, configPath, table, "drop", []string{fixtureIPv4Peer + "/32"}, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	crash = startAppHelper(t, configPath, "active:before-rename", false)
	if err := crash.Run(); !exitStatus(err, 97) {
		t.Fatalf("before-rename crash helper returned %v", err)
	}
	writeInvalidConfig(t, configPath)
	if err := runRunExpectFailure(t, configPath); err == nil {
		t.Fatal("run unexpectedly accepted invalid YAML after before-rename crash")
	}
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18180", "reject", "tcp")

	// After rename, recovery accepts either complete observed record, then
	// stabilizes it before returning; no truncated active record is tolerated.
	writeConfig(t, configPath, table, "drop", []string{fixtureIPv4Peer + "/32"}, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	crash = startAppHelper(t, configPath, "active:after-rename", false)
	if err := crash.Run(); !exitStatus(err, 97) {
		t.Fatalf("after-rename crash helper returned %v", err)
	}
	writeInvalidConfig(t, configPath)
	if err := runRunExpectFailure(t, configPath); err == nil {
		t.Fatal("run unexpectedly accepted invalid YAML after after-rename crash")
	}
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18180", "success", "tcp")

	// A crash after the active record's directory barrier makes the candidate
	// authoritative. Invalid current YAML must not roll it back.
	writeConfig(t, configPath, table, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	crash = startAppHelper(t, configPath, "active:after-dir-sync", false)
	if err := crash.Run(); !exitStatus(err, 97) {
		t.Fatalf("post-commit crash helper returned %v", err)
	}
	writeInvalidConfig(t, configPath)
	if err := runRunExpectFailure(t, configPath); err == nil {
		t.Fatal("run unexpectedly accepted invalid YAML after post-commit crash")
	}
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18180", "drop", "tcp")

	// A backend error after the netlink switch and during compensation leaves
	// journal evidence and fences ordinary work. A subsequent normal start uses
	// persisted metadata to recover rather than trusting YAML.
	writeConfig(t, configPath, table, "drop", []string{fixtureIPv4Peer + "/32"}, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	failed := startAppHelper(t, configPath, "after-switch", true)
	if err := failed.Run(); !exitStatus(err, 98) {
		t.Fatalf("injected recovery-failure helper returned %v", err)
	}
	if _, err := os.Stat(filepath.Join("/var/lib/perimeterd", "journal.json")); err != nil {
		t.Fatalf("failed recovery discarded journal evidence: %v", err)
	}
	writeConfig(t, configPath, table, "drop", []string{fixtureIPv4Peer + "/32"}, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	daemon = startDaemon(t, configPath, table)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18180", "success", "tcp")
	daemon.stop(t)

	// Recovery must inspect hook metadata, not just a stable name/comment. A
	// same-owned chain with the wrong hook is fenced and preserved.
	corruptOwnedBaseChain(t, table)
	fenced := startAppHelper(t, configPath, "unreachable-checkpoint", false)
	if err := fenced.Run(); !exitStatus(err, 98) {
		t.Fatalf("recovery did not remain fenced at its startup deadline: %v", err)
	}
	if _, err := nftTableMayFail(table); err != nil {
		t.Fatalf("recovery removed evidence after hook mismatch: %v", err)
	}
	if err := runCleanupExpectFailure(t); err == nil {
		t.Fatal("cleanup accepted a malformed owned base chain")
	}
	if _, err := nftTableMayFail(table); err != nil {
		t.Fatalf("cleanup removed malformed table: %v", err)
	}
}

func runRunExpectFailure(t *testing.T, configPath string) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	// #nosec G204 -- runs the locally built CLI against a private namespace fixture.
	cmd := exec.CommandContext(ctx, e2eBinary(t), "run", "--config", configPath)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("invalid configuration run timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		return fmt.Errorf("%w\n%s", err, output)
	}
	return nil
}

func runCleanupExpectFailure(t *testing.T) error {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	// #nosec G204 -- runs the locally built CLI against private namespace state.
	cmd := exec.CommandContext(ctx, e2eBinary(t), "cleanup")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("cleanup with malformed ownership timed out: %v\n%s", ctx.Err(), output)
	}
	if err != nil {
		return fmt.Errorf("%w\n%s", err, output)
	}
	return nil
}

func exitStatus(err error, status int) bool {
	if err == nil {
		return false
	}
	exitErr, ok := err.(*exec.ExitError)
	return ok && exitErr.ExitCode() == status
}
