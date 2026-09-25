//go:build linux && e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
)

type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type daemonProcess struct {
	cmd          *exec.Cmd
	output       *lockedBuffer
	done         chan struct{}
	mu           sync.Mutex
	err          error
	expectedExit bool
	redactOutput func([]byte) string
}

func (d *daemonProcess) markExpectedExit() {
	d.mu.Lock()
	d.expectedExit = true
	d.mu.Unlock()
}

func (d *daemonProcess) isExpectedExit() bool {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.expectedExit
}

func (d *daemonProcess) diagnosticOutput() string {
	value := []byte(d.output.String())
	if d.redactOutput != nil {
		return d.redactOutput(value)
	}
	return string(value)
}

func (d *daemonProcess) successfulExit(t *testing.T) {
	t.Helper()
	if d.isExpectedExit() {
		return
	}
	if err := d.waitErr(); err != nil {
		t.Errorf("perimeterd exited unsuccessfully: %v\n%s", err, d.diagnosticOutput())
	}
}

func startDaemon(t *testing.T, configPath, table string) *daemonProcess {
	t.Helper()
	return startDaemonProcess(t, configPath, fmt.Sprintf("nft table %q", table), func() bool {
		_, err := nftTableMayFail(table)
		return err == nil
	})
}

func startDaemonProcess(t *testing.T, configPath, readinessDescription string, enforcementReady func() bool) *daemonProcess {
	t.Helper()
	binary := e2eBinary(t)
	output := new(lockedBuffer)
	notifyPath := filepath.Join(t.TempDir(), "ready.sock")
	notify, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifyPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen for %s readiness: %v", readinessDescription, err)
	}
	t.Cleanup(func() {
		_ = notify.Close()
		_ = os.Remove(notifyPath)
	})
	// #nosec G204 -- the validated E2E binary is launched only by this test harness.
	cmd := exec.Command(binary, "run", "--config", configPath)
	cmd.Env = append(os.Environ(), "NOTIFY_SOCKET="+notifyPath)
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start perimeterd for %s: %v", readinessDescription, err)
	}
	d := &daemonProcess{cmd: cmd, output: output, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		d.mu.Lock()
		d.err = err
		d.mu.Unlock()
		close(d.done)
	}()
	t.Cleanup(func() { d.stop(t) })
	deadline := time.Now().Add(45 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		select {
		case <-d.done:
			t.Fatalf("perimeterd exited during startup for %s: %v\n%s", readinessDescription, d.waitErr(), d.output.String())
		default:
		}
		if !ready {
			_ = notify.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			var packet [4096]byte
			n, _, readErr := notify.ReadFromUnix(packet[:])
			if readErr != nil {
				if netErr, ok := readErr.(net.Error); !ok || !netErr.Timeout() {
					t.Fatalf("read %s readiness: %v\n%s", readinessDescription, readErr, d.output.String())
				}
				continue
			}
			ready = bytes.Contains(packet[:n], []byte("READY=1"))
			continue
		}
		if enforcementReady() {
			_ = notify.Close()
			_ = os.Remove(notifyPath)
			return d
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("perimeterd did not become ready for %s\n%s", readinessDescription, d.output.String())
	return nil
}

func (d *daemonProcess) waitErr() error {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.err
}

func (d *daemonProcess) stop(t *testing.T) {
	t.Helper()
	select {
	case <-d.done:
		d.successfulExit(t)
		return
	default:
	}
	if err := d.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("signal perimeterd: %v", err)
	}
	select {
	case <-d.done:
		d.successfulExit(t)
	case <-time.After(20 * time.Second):
		// A forced kill is an explicit failure of normal shutdown. Callers
		// that intentionally kill a daemon must use kill instead.
		_ = d.cmd.Process.Kill()
		<-d.done
		t.Errorf("perimeterd did not stop after SIGTERM\n%s", d.diagnosticOutput())
	}
}

func (d *daemonProcess) kill(t *testing.T) {
	t.Helper()
	d.markExpectedExit()
	select {
	case <-d.done:
		return
	default:
	}
	if err := d.cmd.Process.Kill(); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("kill perimeterd: %v", err)
	}
	select {
	case <-d.done:
	case <-time.After(5 * time.Second):
		t.Errorf("perimeterd did not exit after kill\n%s", d.diagnosticOutput())
	}
}

func waitForActiveRevisionChange(t *testing.T, before, configPath string) string {
	t.Helper()
	expected, err := config.Load(configPath)
	if err != nil {
		t.Fatalf("load expected configuration: %v", err)
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		marker := activeRevision()
		var active struct {
			Payload struct {
				ID string `json:"id"`
			} `json:"payload"`
		}
		if marker != "" && marker != before && json.Unmarshal([]byte(marker), &active) == nil &&
			len(active.Payload.ID) == 32 && strings.Trim(active.Payload.ID, "0123456789abcdef") == "" {
			// The active ID is constrained to 32 lowercase hexadecimal characters.
			data, readErr := os.ReadFile(filepath.Join("/var/lib/perimeterd/revisions", active.Payload.ID+".json"))
			var revision struct {
				Payload struct {
					Config config.Config `json:"config"`
				} `json:"payload"`
			}
			if readErr == nil && json.Unmarshal(data, &revision) == nil {
				selectedJSON, marshalErr := json.Marshal(revision.Payload.Config)
				if marshalErr == nil && bytes.Equal(expectedJSON, selectedJSON) {
					return marker
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("active revision did not select the reloaded configuration")
	return ""
}

func TestDaemonStopReportsFailedExit(t *testing.T) {
	const (
		helperEnv = "PERIMETERD_E2E_DAEMON_STOP_FAILURE"
		marker    = "DAEMON_STOP_FAILURE_CHECK_COMPLETED"
	)
	if os.Getenv(helperEnv) == "1" {
		cmd := exec.Command("/bin/sh", "-c", "exit 23") // #nosec G204 -- fixed helper command used only by this regression.
		output := new(lockedBuffer)
		cmd.Stdout, cmd.Stderr = output, output
		if err := cmd.Start(); err != nil {
			t.Fatalf("start failed-exit helper: %v", err)
		}
		d := &daemonProcess{cmd: cmd, output: output, done: make(chan struct{})}
		go func() {
			err := cmd.Wait()
			d.mu.Lock()
			d.err = err
			d.mu.Unlock()
			close(d.done)
		}()
		<-d.done
		d.stop(t)
		if _, err := fmt.Fprintln(os.Stdout, marker); err != nil {
			t.Fatalf("write shutdown-check result: %v", err)
		}
		return
	}
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("resolve test executable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- invokes this test executable with a fixed regression selector.
	cmd := exec.CommandContext(ctx, self, "-test.run", "^TestDaemonStopReportsFailedExit$")
	cmd.Env = append(os.Environ(), helperEnv+"=1")
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("shutdown regression helper timed out: %v", ctx.Err())
	}
	exitErr, ok := err.(*exec.ExitError)
	if !ok || exitErr.ExitCode() != 1 {
		t.Fatalf("shutdown regression helper did not fail with expected test status: err=%v output=%s", err, output)
	}
	if !bytes.Contains(output, []byte(marker)) {
		t.Fatalf("shutdown regression helper did not complete the stop check: %s", output)
	}
}

func daemonDiagnosticOffset(daemon *daemonProcess) int {
	return len(daemon.output.String())
}

func waitForDaemonDiagnostic(t *testing.T, daemon *daemonProcess, markers []string, offset int) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		output := daemon.output.String()
		if offset <= len(output) {
			for line := range strings.SplitSeq(output[offset:], "\n") {
				matched := true
				for _, marker := range markers {
					if !strings.Contains(line, marker) {
						matched = false
						break
					}
				}
				if matched {
					return
				}
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("daemon did not report reload candidate markers %q:\n%s", markers, daemon.diagnosticOutput())
}

func (d *daemonProcess) reload(t *testing.T) {
	t.Helper()
	if err := d.cmd.Process.Signal(syscall.SIGHUP); err != nil {
		t.Fatalf("signal perimeterd reload: %v", err)
	}
}

func e2eBinary(t *testing.T) string {
	t.Helper()
	path := os.Getenv(e2eBinaryEnv)
	if path == "" {
		t.Fatal("E2E_BINARY is required")
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		t.Fatalf("resolve E2E_BINARY: %v", err)
	}
	if _, err := exec.LookPath(absolute); err != nil {
		t.Fatalf("E2E_BINARY is not executable: %v", err)
	}
	return absolute
}

func writeConfig(t *testing.T, path, table, action string, allow, block []string, priority int) {
	writeConfigFamilies(t, path, table, action, allow, block, priority, true, true)
}

func writeConfigFamilies(t *testing.T, path, table, action string, allow, block []string, priority int, ipv4, ipv6 bool) {
	t.Helper()
	var yaml strings.Builder
	yaml.WriteString("version: 1\n")
	yaml.WriteString("logging:\n  level: debug\n  format: text\n")
	yaml.WriteString("metrics:\n  listen: \"\"\n")
	yaml.WriteString("global:\n")
	if len(allow) == 0 {
		yaml.WriteString("  allowlist: []\n")
	} else {
		yaml.WriteString("  allowlist:\n")
		for _, value := range allow {
			fmt.Fprintf(&yaml, "    - %q\n", value)
		}
	}
	if len(block) == 0 {
		yaml.WriteString("  blocklist: []\n")
	} else {
		yaml.WriteString("  blocklist:\n")
		for _, value := range block {
			fmt.Fprintf(&yaml, "    - %q\n", value)
		}
	}
	fmt.Fprintf(&yaml, "firewall:\n  backend: nftables\n  deny_action: %s\n  ipv4: %t\n  ipv6: %t\n  nftables:\n    table: %q\n    priority: %d\n", action, ipv4, ipv6, table, priority)
	yaml.WriteString("geo:\n  refresh_interval: 24h\n  request_timeout: 1s\n  refresh_jitter: 1s\n")
	yaml.WriteString("groups: {}\npolicies: []\ncrowdsec:\n  enabled: false\n")
	if err := os.WriteFile(path, []byte(yaml.String()), 0o600); err != nil {
		t.Fatalf("write config: %v", err)
	}
}

func writeInvalidConfig(t *testing.T, path string) {
	t.Helper()
	writeInvalidConfigMarker(t, path, "unsupported")
}

func writeInvalidConfigMarker(t *testing.T, path, marker string) {
	t.Helper()
	body := fmt.Sprintf("version: 1\nfirewall:\n  backend: %s\n", marker)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("write invalid config: %v", err)
	}
}

func tempConfig(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join(t.TempDir(), name+".yaml")
}

func assertLockCollision(t *testing.T, configPath string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	// #nosec G204 -- e2eBinary validates the fixture executable; arguments are not shell-expanded.
	cmd := exec.CommandContext(ctx, e2eBinary(t), "run", "--config", configPath)
	cmd.Stdout = io.Discard
	cmd.Stderr = io.Discard
	if err := cmd.Run(); err == nil {
		t.Fatal("second perimeterd run acquired the lifecycle lock")
	}
	if ctx.Err() != nil {
		t.Fatalf("second perimeterd run did not fail promptly: %v", ctx.Err())
	}
}
