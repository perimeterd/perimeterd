//go:build linux && e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func newE2EOutputForTest(t *testing.T, progress func(e2ePhaseRecord)) *e2eChildOutput {
	t.Helper()
	file, err := os.CreateTemp(t.TempDir(), "evidence-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = file.Close() })
	return &e2eChildOutput{spool: file, progress: progress}
}

func encodedE2EPhase(t *testing.T) []byte {
	t.Helper()
	data, err := json.Marshal(e2ePhaseRecord{Backend: "nftables", Scenario: "output-check", Phase: "ready", Event: "action_start", Timestamp: time.Now().UTC()})
	if err != nil {
		t.Fatal(err)
	}
	return append(append([]byte(e2ePhasePrefix), data...), '\n')
}

func TestE2EOutputBoundedTailAndCompleteEvidence(t *testing.T) {
	output := newE2EOutputForTest(t, nil)
	data := append([]byte("complete-semantic-evidence-start\n"), bytes.Repeat([]byte("x"), 3*e2eDiagnosticLimit)...)
	data = append(data, []byte("\nuseful failure at end\n")...)
	writer := e2eChildStream{output: output}
	for offset := 0; offset < len(data); {
		end := min(offset+317, len(data))
		if _, err := writer.Write(data[offset:end]); err != nil {
			t.Fatal(err)
		}
		offset = end
	}
	if len(output.tail) != e2eDiagnosticLimit || !bytes.HasSuffix(output.tail, []byte("useful failure at end\n")) {
		t.Fatal("bounded diagnostic tail lost failure evidence")
	}
	if bytes.Contains(output.tail, []byte("complete-semantic-evidence-start")) {
		t.Fatal("diagnostic tail was not bounded")
	}
	got, err := output.evidence()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, data) {
		t.Fatal("semantic output was truncated or changed")
	}
}

func TestE2EOutputSafeRecordsAndStreams(t *testing.T) {
	var records []e2ePhaseRecord
	output := newE2EOutputForTest(t, func(record e2ePhaseRecord) { records = append(records, record) })
	stdout := e2eChildStream{output: output, stream: 0}
	stderr := e2eChildStream{output: output, stream: 1}
	line := encodedE2EPhase(t)
	// A stderr fragment must not splice into the stdout phase line.
	if _, err := stdout.Write(line[:12]); err != nil {
		t.Fatal(err)
	}
	if _, err := stderr.Write([]byte("=== RUN nested\n--- FAIL: nested\nsecret raw payload\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := stdout.Write(line[12:]); err != nil {
		t.Fatal(err)
	}
	invalid := []string{
		e2ePhasePrefix + `{"event":"ready","timestamp":"2026-11-05T00:00:00Z","credentials":"secret"}` + "\n",
		e2ePhasePrefix + `{"event":"ready","timestamp":"2026-11-05T00:00:00Z","phase":"Bearer secret"}` + "\n",
		e2ePhasePrefix + `{"event":"ready","timestamp":"2026-11-05T00:00:00Z","capture_bytes":-1}` + "\n",
		e2ePhasePrefix + `{"event":"measurement","timestamp":"2026-11-05T00:00:00Z","source_decisions":-1}` + "\n",
		e2ePhasePrefix + `{"event":"ready","timestamp":"2026-11-05T00:00:00Z"} {}` + "\n",
		strings.Repeat("x", e2ePhaseLineLimit+1) + string(line),
	}
	for _, data := range invalid {
		if _, err := stdout.Write([]byte(data)); err != nil {
			t.Fatal(err)
		}
	}
	if len(records) != 1 || records[0].Phase != "ready" {
		t.Fatalf("unsafe or fragmented records forwarded: %+v", records)
	}
	// Both streams use the same synchronization but preserve all evidence.
	var group sync.WaitGroup
	for _, writer := range []e2eChildStream{stdout, stderr} {
		group.Add(1)
		go func(writer e2eChildStream) {
			defer group.Done()
			for range 100 {
				if _, err := writer.Write([]byte("diagnostic\n")); err != nil {
					return
				}
			}
		}(writer)
	}
	group.Wait()
	data, err := output.evidence()
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Count(data, []byte("diagnostic\n")) != 200 {
		t.Fatal("concurrent stream output was lost")
	}
}

// This helper is an ordinary subprocess, not a namespace simulation. The parent
// also runs a real runIsolatedFor smoke test to cover unshare and descendant exit.
func TestE2EOutputSubprocessHelper(t *testing.T) {
	mode := os.Getenv("PERIMETERD_E2E_OUTPUT_HELPER")
	if mode == "" {
		return
	}
	if _, err := fmt.Fprintln(os.Stdout, "child waiting for release"); err != nil {
		t.Fatal(err)
	}
	recordE2EPhase(t, e2ePhaseRecord{Scenario: "output-check", Phase: "ready", Event: "action_start"})
	if mode == "failure" {
		if _, err := fmt.Fprint(os.Stdout, strings.Repeat("x", 2*e2eDiagnosticLimit)); err != nil {
			t.Fatal(err)
		}
		if _, err := fmt.Fprintln(os.Stdout, "intentional child failure tail"); err != nil {
			t.Fatal(err)
		}
		os.Exit(7)
	}
	var release [1]byte
	if _, err := io.ReadFull(os.Stdin, release[:]); err != nil {
		os.Exit(8)
	}
	fmt.Fprintln(os.Stderr, "child released")
	os.Exit(0)
}

func TestE2EOutputLiveProgressAndCancellation(t *testing.T) {
	for _, mode := range []string{"release", "cancel", "timeout", "failure"} {
		t.Run(mode, func(t *testing.T) {
			timeout := 10 * time.Second
			if mode == "timeout" {
				timeout = 3 * time.Second
			}
			ctx, cancel := context.WithTimeout(context.Background(), timeout)
			defer cancel()
			progress := make(chan e2ePhaseRecord, 1)
			output := newE2EOutputForTest(t, func(record e2ePhaseRecord) { progress <- record })
			// #nosec G204 G702 -- controlled re-execution of this test executable.
			cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestE2EOutputSubprocessHelper$")
			cmd.Env = append(os.Environ(), "PERIMETERD_E2E_OUTPUT_HELPER="+mode, e2eChildEnv+"=1")
			cmd.Stdout = e2eChildStream{output: output, stream: 0}
			cmd.Stderr = e2eChildStream{output: output, stream: 1}
			input, err := cmd.StdinPipe()
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = input.Close() }()
			if err := cmd.Start(); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() { done <- cmd.Wait() }()
			select {
			case <-progress:
			case <-ctx.Done():
				t.Fatal("child progress was not visible before completion")
			}
			if mode != "failure" {
				select {
				case err := <-done:
					t.Fatalf("child exited before release/cancellation: %v", err)
				default:
				}
			}
			switch mode {
			case "release":
				if _, err := input.Write([]byte{1}); err != nil {
					t.Fatal(err)
				}
			case "cancel":
				cancel()
			}
			select {
			case err := <-done:
				if mode == "release" && err != nil {
					t.Fatalf("released child: %v", err)
				}
				if mode != "release" && err == nil {
					t.Fatal("failed/canceled child lost exit status")
				}
				if mode == "timeout" && ctx.Err() != context.DeadlineExceeded {
					t.Fatalf("timeout lost context deadline: %v", ctx.Err())
				}
			case <-time.After(10 * time.Second):
				t.Fatal("child did not terminate")
			}
			data, err := output.evidence()
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Contains(data, []byte(e2ePhasePrefix)) {
				t.Fatal("complete evidence lost live record")
			}
			if (mode == "timeout" || mode == "cancel") && !bytes.Contains(output.tail, []byte("child waiting for release")) {
				t.Fatal("canceled child lost useful diagnostic tail")
			}
			if mode == "failure" && (len(output.tail) != e2eDiagnosticLimit || !bytes.Contains(output.tail, []byte("intentional child failure tail")) || len(data) <= 2*e2eDiagnosticLimit) {
				t.Fatal("failure did not retain bounded diagnostics and complete evidence independently")
			}
		})
	}
}

func TestE2EPhaseArtifacts(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "phases")
	data := bytes.TrimSpace(encodedE2EPhase(t)[len(e2ePhasePrefix):])
	for range 2 {
		if err := persistE2EPhase(dir, data); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, fmt.Sprintf("phases-%d.jsonl", os.Getpid()))
	// #nosec G304 -- phase file is constructed beneath this test's private temporary directory.
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, bytes.Repeat(append(bytes.Clone(data), '\n'), 2)) {
		t.Fatal("phase records were not appended immediately")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o644 {
		t.Fatalf("artifacts unreadable after sudo: %v", info.Mode())
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(t.TempDir(), "not-an-artifact"), path); err != nil {
		t.Fatal(err)
	}
	if persistE2EPhase(dir, data) == nil {
		t.Fatal("artifact writer followed a symbolic link")
	}
}

func TestE2EOutputNamespaceSmoke(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		runIsolated(t, "TestE2EOutputNamespaceSmoke", "output-smoke")
		return
	}
	requireIsolatedChild(t)
	recordE2EPhase(t, e2ePhaseRecord{Phase: "isolated-child-ready", Event: "action_start"})
}
