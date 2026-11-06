//go:build linux && e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestE2EOutputNamespaceDescendant(t *testing.T) {
	path := os.Getenv("PERIMETERD_E2E_CANCEL_SOCKET")
	if path == "" {
		return
	}
	// #nosec G704 -- fixed Unix-domain transport to the parent-owned temporary socket; no network URL.
	connection, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	if _, err := io.WriteString(connection, "ready"); err != nil {
		t.Fatal(err)
	}
	var data [1]byte
	_, _ = connection.Read(data[:])
}

func TestE2EOutputNamespaceTimeoutHelper(t *testing.T) {
	if os.Getenv("PERIMETERD_E2E_CANCEL_SOCKET") == "" {
		return
	}
	if os.Getenv(e2eChildEnv) != "1" {
		runIsolatedFor(t, "TestE2EOutputNamespaceTimeoutHelper", "output-cancellation", 5*time.Second)
		return
	}
	requireIsolatedChild(t)
	// #nosec G204 G702 -- fixed helper in this test executable, within checked namespaces.
	cmd := exec.Command(os.Args[0], "-test.run=^TestE2EOutputNamespaceDescendant$")
	cmd.Env = os.Environ()
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	recordE2EPhase(t, e2ePhaseRecord{Phase: "descendant-started", Event: "action_start"})
	if err := cmd.Wait(); err != nil {
		t.Fatal(err)
	}
}

func TestE2EOutputNamespaceCancellation(t *testing.T) {
	path := filepath.Join(t.TempDir(), "cancel.sock")
	listener, err := net.ListenUnix("unix", &net.UnixAddr{Name: path, Net: "unix"})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	if err := listener.SetDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Second)
	defer cancel()
	// #nosec G204 G702 -- controlled helper re-execution; its expected failed namespace is not CI evidence.
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestE2EOutputNamespaceTimeoutHelper$")
	cmd.Env = append(os.Environ(), "PERIMETERD_E2E_CANCEL_SOCKET="+path, e2eChildEnv+"=", e2ePhaseDirEnv+"=")
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	output := new(lockedBuffer)
	cmd.Stdout, cmd.Stderr = output, output
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL) })
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	connection, err := listener.AcceptUnix()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = connection.Close() }()
	if err := connection.SetReadDeadline(time.Now().Add(15 * time.Second)); err != nil {
		t.Fatal(err)
	}
	ready := make([]byte, len("ready"))
	if _, err := io.ReadFull(connection, ready); err != nil || string(ready) != "ready" {
		t.Fatalf("descendant did not establish liveness: %v", err)
	}
	var data [1]byte
	if n, err := connection.Read(data[:]); n != 0 || err != io.EOF {
		t.Fatalf("namespace timeout left descendant connection alive: n=%d err=%v", n, err)
	}
	select {
	case err := <-done:
		if err == nil || ctx.Err() != nil {
			t.Fatalf("namespace deadline did not terminate wrapper and descendants: %v (%v)", err, ctx.Err())
		}
	case <-ctx.Done():
		t.Fatal("namespace cancellation did not drain child output")
	}
	found := false
	for line := range strings.SplitSeq(output.String(), "\n") {
		if !strings.HasPrefix(line, e2ePhasePrefix) {
			continue
		}
		var record e2ePhaseRecord
		if json.Unmarshal(bytes.TrimPrefix([]byte(line), []byte(e2ePhasePrefix)), &record) == nil && record.Event == "namespace_end" && record.Outcome == "timeout" {
			found = true
		}
	}
	if !found {
		t.Fatal("namespace timeout lost structured failure result")
	}
}
