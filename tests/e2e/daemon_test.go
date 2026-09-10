//go:build linux && e2e

package e2e

import (
	"bytes"
	"context"
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
	cmd    *exec.Cmd
	output *lockedBuffer
	done   chan struct{}
	mu     sync.Mutex
	err    error
}

func startDaemon(t *testing.T, configPath, table string) *daemonProcess {
	t.Helper()
	binary := e2eBinary(t)
	output := new(lockedBuffer)
	notifyPath := filepath.Join(t.TempDir(), "ready.sock")
	notify, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifyPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen for daemon readiness: %v", err)
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
		t.Fatalf("start perimeterd: %v", err)
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
			t.Fatalf("perimeterd exited during startup: %v\n%s", d.waitErr(), d.output.String())
		default:
		}
		if !ready {
			_ = notify.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			var packet [4096]byte
			n, _, readErr := notify.ReadFromUnix(packet[:])
			if readErr != nil {
				if netErr, ok := readErr.(net.Error); !ok || !netErr.Timeout() {
					t.Fatalf("read perimeterd readiness: %v\n%s", readErr, d.output.String())
				}
				continue
			}
			ready = bytes.Contains(packet[:n], []byte("READY=1"))
			continue
		}
		if _, err := nftTableMayFail(table); err == nil {
			_ = notify.Close()
			_ = os.Remove(notifyPath)
			return d
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("perimeterd did not become ready for table %q\n%s", table, d.output.String())
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
		return
	default:
	}
	if err := d.cmd.Process.Signal(syscall.SIGTERM); err != nil && !errors.Is(err, os.ErrProcessDone) {
		t.Errorf("signal perimeterd: %v", err)
	}
	select {
	case <-d.done:
	case <-time.After(20 * time.Second):
		_ = d.cmd.Process.Kill()
		<-d.done
		t.Errorf("perimeterd did not stop after SIGTERM\n%s", d.output.String())
	}
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
	info, err := os.Stat(absolute)
	if err != nil {
		t.Fatalf("stat E2E_BINARY: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("E2E_BINARY is not executable: %s", absolute)
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
	yaml.WriteString("logging:\n  level: error\n  format: text\n")
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
	if err := os.WriteFile(path, []byte("version: 1\nfirewall:\n  backend: unsupported\n"), 0o600); err != nil {
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
	// #nosec G204 -- the validated E2E binary is launched only by this test harness.
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
