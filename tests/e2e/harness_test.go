//go:build linux && e2e

package e2e

import (
	"bufio"
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
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/app"
	"github.com/perimeterd/perimeterd/internal/firewall"
)

const (
	e2eEnabledEnv      = "PERIMETERD_E2E"
	e2eChildEnv        = "PERIMETERD_E2E_CHILD"
	e2eScenario        = "PERIMETERD_E2E_SCENARIO"
	e2eBinaryEnv       = "E2E_BINARY"
	e2eHelperEnv       = "PERIMETERD_E2E_APP_HELPER"
	e2eCheckpoint      = "PERIMETERD_E2E_CHECKPOINT"
	e2eFailApply       = "PERIMETERD_E2E_FAIL_APPLY"
	e2eCheckpointError = "PERIMETERD_E2E_CHECKPOINT_ERROR"
)

const (
	fixtureIPv4Host = "8.20.0.1"
	fixtureIPv4Peer = "8.20.0.2"
	fixtureIPv6Host = "2600:20::1"
	fixtureIPv6Peer = "2600:20::2"
	fixtureLANHost  = "192.168.20.1"
	fixtureLANPeer  = "192.168.20.2"
)

func TestMain(m *testing.M) {
	if os.Getenv(e2eEnabledEnv) != "1" && os.Getenv(e2eChildEnv) != "1" {
		fmt.Fprintln(os.Stderr, "PERIMETERD_E2E=1 is required; refusing to run the privileged E2E suite")
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// runIsolated re-executes one test in a fresh user, mount, network, and PID namespace.
// The outer process never invokes a firewall tool; all such calls happen after
// the child verifies that its namespace differs from the caller's namespace.
func runIsolated(t *testing.T, testName, scenario string) {
	t.Helper()
	parentNet, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("read parent network namespace: %v", err)
	}
	parentMount, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatalf("read parent mount namespace: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	// #nosec G204 G702 -- the namespace wrapper and test executable are controlled by this test-only harness.
	cmd := exec.CommandContext(ctx, "unshare", "--kill-child", "--user", "--map-root-user", "--mount", "--mount-proc", "--net", "--pid", "--fork", os.Args[0], "-test.run", "^"+testName+"$", "-test.v")
	cmd.Env = append(os.Environ(),
		e2eEnabledEnv+"=1",
		e2eChildEnv+"=1",
		e2eScenario+"="+scenario,
		"PERIMETERD_E2E_PARENT_NETNS="+parentNet,
		"PERIMETERD_E2E_PARENT_MNTNS="+parentMount,
	)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			t.Fatalf("isolated %s timed out: %v\n%s", scenario, ctx.Err(), output.String())
		}
		t.Fatalf("isolated %s failed: %v\n%s", scenario, err, output.String())
	}
}

func requireIsolatedChild(t *testing.T) {
	t.Helper()
	if os.Getenv(e2eChildEnv) != "1" {
		t.Fatal("test must execute in an isolated child")
	}
	parentNet := os.Getenv("PERIMETERD_E2E_PARENT_NETNS")
	parentMount := os.Getenv("PERIMETERD_E2E_PARENT_MNTNS")
	if parentNet == "" || parentMount == "" {
		t.Fatal("isolated child is missing parent namespace identity")
	}
	currentNet, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("read child network namespace: %v", err)
	}
	if currentNet == parentNet {
		t.Fatalf("child network namespace equals parent (%s); refusing firewall mutation", currentNet)
	}
	currentMount, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatalf("read child mount namespace: %v", err)
	}
	if currentMount == parentMount {
		t.Fatalf("child mount namespace equals parent (%s); refusing filesystem mutation", currentMount)
	}
	if os.Getpid() != 1 {
		t.Fatal("fixture must be PID namespace init so exit terminates all descendants")
	}
	if os.Geteuid() != 0 {
		t.Fatalf("child is not namespace root (uid %d)", os.Geteuid())
	}
}

func prepareMounts(t *testing.T) {
	t.Helper()
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		t.Fatalf("make mount namespace private: %v", err)
	}
	for _, dir := range []string{"/run", "/var/lib"} {
		if err := syscall.Mount("tmpfs", dir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0755,size=64m"); err != nil {
			t.Fatalf("mount private tmpfs on %s: %v", dir, err)
		}
	}
	if err := os.MkdirAll("/run/perimeterd", 0o700); err != nil {
		t.Fatalf("create private runtime directory: %v", err)
	}
	if err := os.MkdirAll("/var/lib/perimeterd", 0o700); err != nil {
		t.Fatalf("create private state directory: %v", err)
	}
}

func command(t *testing.T, timeout time.Duration, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// #nosec G204 -- command and arguments are fixed by this privileged test harness.
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			t.Fatalf("%s timed out: %v\n%s", strings.Join(args, " "), ctx.Err(), output)
		}
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return output
}

func commandMayFail(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// #nosec G204 -- command and arguments are fixed by this privileged test harness.
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return output, ctx.Err()
	}
	return output, err
}

func commandInput(t *testing.T, timeout time.Duration, input []byte, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// #nosec G204 -- command and arguments are fixed by this privileged test harness.
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			t.Fatalf("%s timed out: %v", strings.Join(args, " "), ctx.Err())
		}
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return output
}

type peerNamespace struct {
	pid  int
	proc *exec.Cmd
}

func newPeerNamespace(t *testing.T) *peerNamespace {
	t.Helper()
	// Local OUTPUT rejections deliver their ICMP errors through loopback.
	// A fresh network namespace starts with lo down.
	command(t, 10*time.Second, "ip", "link", "set", "lo", "up")
	parentNet, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	proc := exec.Command("unshare", "--net", "--kill-child", "--fork", "sleep", "600")
	if err := proc.Start(); err != nil {
		t.Fatalf("start peer network namespace: %v", err)
	}
	peer := &peerNamespace{pid: proc.Process.Pid, proc: proc}
	t.Cleanup(func() {
		if proc.Process != nil {
			_ = proc.Process.Kill()
		}
		_ = proc.Wait()
	})
	deadline := time.Now().Add(5 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		if network, err := os.Readlink(fmt.Sprintf("/proc/%d/ns/net", peer.pid)); err == nil && network != parentNet {
			ready = true
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if !ready {
		t.Fatal("peer did not enter a separate network namespace")
	}
	peer.run(t, "ip", "link", "set", "lo", "up")
	command(t, 10*time.Second, "ip", "link", "add", "e2h0", "type", "veth", "peer", "name", "e2p0")
	command(t, 10*time.Second, "ip", "link", "set", "e2p0", "netns", strconv.Itoa(peer.pid))
	command(t, 10*time.Second, "ip", "addr", "add", fixtureIPv4Host+"/24", "dev", "e2h0")
	command(t, 10*time.Second, "ip", "addr", "add", fixtureLANHost+"/24", "dev", "e2h0")
	command(t, 10*time.Second, "ip", "-6", "addr", "add", fixtureIPv6Host+"/64", "dev", "e2h0", "nodad")
	command(t, 10*time.Second, "ip", "link", "set", "e2h0", "up")
	peer.run(t, "ip", "addr", "add", fixtureIPv4Peer+"/24", "dev", "e2p0")
	peer.run(t, "ip", "addr", "add", fixtureLANPeer+"/24", "dev", "e2p0")
	peer.run(t, "ip", "-6", "addr", "add", fixtureIPv6Peer+"/64", "dev", "e2p0", "nodad")
	peer.run(t, "ip", "link", "set", "e2p0", "up")
	return peer
}

func (p *peerNamespace) run(t *testing.T, args ...string) []byte {
	t.Helper()
	full := append([]string{"nsenter", "-t", strconv.Itoa(p.pid), "-n", "--"}, args...)
	return command(t, 10*time.Second, full...)
}

func (p *peerNamespace) helper(t *testing.T, mode, network, address, expectation string) *exec.Cmd {
	t.Helper()
	// #nosec G204 G702 -- enters the harness-owned peer namespace and runs this test executable.
	cmd := exec.Command("nsenter", "-t", strconv.Itoa(p.pid), "-n", "--", os.Args[0], "-test.run", "^TestE2EPeer$")
	cmd.Env = append(os.Environ(),
		e2eEnabledEnv+"=1",
		e2eChildEnv+"=1",
		"PERIMETERD_E2E_PEER_MODE="+mode,
		"PERIMETERD_E2E_PEER_NETWORK="+network,
		"PERIMETERD_E2E_PEER_ADDRESS="+address,
		"PERIMETERD_E2E_PEER_EXPECT="+expectation,
	)
	return cmd
}

func TestE2EPeer(t *testing.T) {
	mode := os.Getenv("PERIMETERD_E2E_PEER_MODE")
	if mode == "" {
		return
	}
	network := os.Getenv("PERIMETERD_E2E_PEER_NETWORK")
	address := os.Getenv("PERIMETERD_E2E_PEER_ADDRESS")
	expectation := os.Getenv("PERIMETERD_E2E_PEER_EXPECT")
	timeout := 1500 * time.Millisecond
	switch mode {
	case "dial-tcp":
		peerDialTCP(t, network, address, expectation, timeout)
	case "dial-udp":
		peerDialUDP(t, network, address, expectation, timeout)
	case "listen-tcp":
		peerListenTCP(t, network, address)
	case "listen-udp":
		peerListenUDP(t, network, address)
	default:
		t.Fatalf("unknown peer helper mode %q", mode)
	}
}

func peerDialTCP(t *testing.T, network, address, expectation string, timeout time.Duration) {
	t.Helper()
	started := time.Now()
	// #nosec G704 -- the peer helper dials only fixed fixture addresses in the isolated E2E namespace.
	conn, err := net.DialTimeout(network, address, timeout)
	if err == nil {
		defer func() { _ = conn.Close() }()
		if expectation != "success" {
			t.Fatalf("unexpected successful TCP connection for %s", expectation)
		}
		if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
			t.Fatal(err)
		}
		if _, err := conn.Write([]byte("e")); err != nil {
			t.Fatalf("TCP write: %v", err)
		}
		var response [1]byte
		if _, err := io.ReadFull(conn, response[:]); err != nil {
			t.Fatalf("TCP response: %v", err)
		}
		return
	}
	if expectation == "success" {
		t.Fatalf("TCP connection failed: %v", err)
	}
	if expectation == "reject" && time.Since(started) > 700*time.Millisecond {
		t.Fatalf("reject did not fail promptly: %v", err)
	}
	if expectation == "drop" && time.Since(started) < 700*time.Millisecond {
		t.Fatalf("drop failed too quickly: %v", err)
	}
}

func peerDialUDP(t *testing.T, network, address, expectation string, timeout time.Duration) {
	t.Helper()
	started := time.Now()
	// #nosec G704 -- the peer helper dials only fixed fixture addresses in the isolated E2E namespace.
	conn, err := net.DialTimeout(network, address, timeout)
	if err != nil {
		t.Fatalf("UDP fixture connection setup failed: %v", err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(timeout)); err != nil {
		t.Fatal(err)
	}
	_, writeErr := conn.Write([]byte("e"))
	if writeErr != nil && expectation == "success" {
		t.Fatalf("UDP write: %v", writeErr)
	}
	// OUTPUT DROP and REJECT can both return EPERM from send. Only REJECT
	// additionally queues an ICMP error on this connected socket; DROP leaves
	// the receive waiting until its deadline. Do not classify the send alone.
	if writeErr != nil && !errors.Is(writeErr, syscall.EPERM) {
		t.Fatalf("UDP fixture send failed: %v", writeErr)
	}
	var response [1]byte
	_, readErr := conn.Read(response[:])
	if expectation == "success" && readErr != nil {
		t.Fatalf("UDP response: %v", readErr)
	}
	if expectation != "success" {
		if readErr == nil {
			t.Fatalf("unexpected UDP response for %s", expectation)
		}
		var networkErr net.Error
		timedOut := errors.As(readErr, &networkErr) && networkErr.Timeout()
		if expectation == "reject" && (timedOut || time.Since(started) > 700*time.Millisecond) {
			t.Fatalf("UDP reject did not produce a prompt ICMP error: %v", readErr)
		}
		if expectation == "drop" && !timedOut {
			t.Fatalf("UDP drop produced an error instead of timing out: %v", readErr)
		}
	}
}

func peerListenTCP(t *testing.T, network, address string) {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatalf("peer TCP listen: %v", err)
	}
	defer func() { _ = listener.Close() }()
	fmt.Println("READY")
	conn, err := listener.Accept()
	if err != nil {
		t.Fatalf("peer TCP accept: %v", err)
	}
	defer func() { _ = conn.Close() }()
	buf := make([]byte, 1)
	for {
		if _, err := io.ReadFull(conn, buf); err != nil {
			return
		}
		if _, err := conn.Write(buf); err != nil {
			return
		}
	}
}

func peerListenUDP(t *testing.T, network, address string) {
	t.Helper()
	conn, err := net.ListenUDP(network, mustUDPAddr(t, network, address))
	if err != nil {
		t.Fatalf("peer UDP listen: %v", err)
	}
	defer func() { _ = conn.Close() }()
	fmt.Println("READY")
	buf := make([]byte, 1)
	n, remote, err := conn.ReadFromUDP(buf)
	if err != nil {
		t.Fatalf("peer UDP read: %v", err)
	}
	if _, err := conn.WriteToUDP(buf[:n], remote); err != nil {
		t.Fatalf("peer UDP write: %v", err)
	}
}

func mustUDPAddr(t *testing.T, network, address string) *net.UDPAddr {
	t.Helper()
	addr, err := net.ResolveUDPAddr(network, address)
	if err != nil {
		t.Fatalf("resolve UDP address %q: %v", address, err)
	}
	return addr
}

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

func probeIngress(t *testing.T, peer *peerNamespace, network, hostAddress, expectation string, protocol string) {
	t.Helper()
	var listener net.Listener
	if protocol == "tcp" {
		var err error
		listener, err = net.Listen(network, hostAddress)
		if err != nil {
			t.Fatalf("listen ingress %s: %v", hostAddress, err)
		}
		defer func() { _ = listener.Close() }()
		go echoTCP(listener)
	} else {
		udp, err := net.ListenUDP(network, mustUDPAddr(t, network, hostAddress))
		if err != nil {
			t.Fatalf("listen ingress UDP %s: %v", hostAddress, err)
		}
		defer func() { _ = udp.Close() }()
		go echoUDP(udp)
	}
	cmd := peer.helper(t, "dial-"+protocol, network, hostAddress, expectation)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		t.Fatalf("ingress %s/%s (%s): %v\n%s", network, protocol, expectation, err, output.String())
	}
}

func probeEgress(t *testing.T, peer *peerNamespace, network, peerAddress, expectation, protocol string) {
	t.Helper()
	cmd := peer.helper(t, "listen-"+protocol, network, peerAddress, expectation)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("peer listener stdout: %v", err)
	}
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatalf("start peer listener: %v", err)
	}
	defer func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
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
	if protocol == "tcp" {
		peerDialTCP(t, network, peerAddress, expectation, 1500*time.Millisecond)
	} else {
		peerDialUDP(t, network, peerAddress, expectation, 1500*time.Millisecond)
	}
}

func echoTCP(listener net.Listener) {
	for {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		go func() {
			defer func() { _ = conn.Close() }()
			buf := make([]byte, 1)
			for {
				if _, err := io.ReadFull(conn, buf); err != nil {
					return
				}
				if _, err := conn.Write(buf); err != nil {
					return
				}
			}
		}()
	}
}

func echoUDP(conn *net.UDPConn) {
	buf := make([]byte, 1)
	for {
		n, addr, err := conn.ReadFromUDP(buf)
		if err != nil {
			return
		}
		if _, err := conn.WriteToUDP(buf[:n], addr); err != nil {
			return
		}
	}
}

func startPeerListener(t *testing.T, peer *peerNamespace, network, address string) (*exec.Cmd, <-chan bool) {
	t.Helper()
	cmd := peer.helper(t, "listen-tcp", network, address, "success")
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		t.Fatalf("peer listener stdout: %v", err)
	}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start peer listener: %v", err)
	}
	ready := make(chan bool, 1)
	go func() {
		scanner := bufio.NewScanner(stdout)
		ready <- scanner.Scan() && scanner.Text() == "READY"
	}()
	t.Cleanup(func() {
		if cmd.Process != nil {
			_ = cmd.Process.Kill()
		}
		_ = cmd.Wait()
	})
	return cmd, ready
}

func nftTable(t *testing.T, table string) []byte {
	t.Helper()
	output, err := nftTableMayFail(table)
	if err != nil {
		t.Fatalf("list nft table %q: %v", table, err)
	}
	return output
}

var errNFTTableNotFound = errors.New("nft table not found")

func nftTableMayFail(table string) ([]byte, error) {
	output, err := commandMayFail(5*time.Second, "nft", "-j", "list", "ruleset")
	if err != nil {
		return output, err
	}
	filtered, found, err := selectNFTTable(output, table)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %q", errNFTTableNotFound, table)
	}
	return filtered, nil
}

func selectNFTTable(data []byte, table string) ([]byte, bool, error) {
	var envelope struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, false, fmt.Errorf("decode nft ruleset: %w", err)
	}
	if envelope.Nftables == nil {
		return nil, false, errors.New("nft ruleset is missing its object array")
	}
	selected := make([]map[string]json.RawMessage, 0)
	for _, item := range envelope.Nftables {
		for kind, raw := range item {
			var object map[string]any
			if err := json.Unmarshal(raw, &object); err != nil {
				return nil, false, fmt.Errorf("decode nft %s: %w", kind, err)
			}
			name, _ := object["name"].(string)
			parent, _ := object["table"].(string)
			if (kind == "table" && name == table) || parent == table {
				selected = append(selected, item)
				break
			}
		}
	}
	if len(selected) == 0 {
		return nil, false, nil
	}
	filtered, err := json.Marshal(struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}{Nftables: selected})
	if err != nil {
		return nil, false, fmt.Errorf("encode nft table: %w", err)
	}
	return filtered, true, nil
}

func waitNoNFTTable(t *testing.T, table string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, err := nftTableMayFail(table)
		if errors.Is(err, errNFTTableNotFound) {
			return
		}
		if err != nil {
			t.Fatalf("inspect nft table %q before confirming deletion: %v", table, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("nft table %q still exists", table)
}

func createForeignTable(t *testing.T, table string) {
	t.Helper()
	batch := fmt.Sprintf(`{"nftables":[{"add":{"table":{"family":"inet","name":"%s"}}},{"add":{"chain":{"family":"inet","table":"%s","name":"foreign_child","type":"filter","hook":"input","prio":300,"policy":"accept","comment":"foreign-owner"}}}]}`, table, table)
	commandInput(t, 10*time.Second, []byte(batch), "nft", "-j", "-f", "-")
}

func flushOwnedTableRules(t *testing.T, table string) {
	t.Helper()
	batch := fmt.Sprintf(`{"nftables":[{"flush":{"table":{"family":"inet","name":"%s"}}}]}`, table)
	commandInput(t, 10*time.Second, []byte(batch), "nft", "-j", "-f", "-")
}

func objectJSON(t *testing.T, table string) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(nftTable(t, table), &value); err != nil {
		t.Fatalf("decode nft JSON: %v", err)
	}
	return value
}

type nftChainMetadata struct {
	Family  string
	Table   string
	Name    string
	Type    string
	Hook    string
	Policy  string
	Comment string
	Prio    int64
}

func ownedBaseChain(t *testing.T, table string) nftChainMetadata {
	t.Helper()
	var found nftChainMetadata
	walkJSON(objectJSON(t, table), func(object map[string]any) {
		if found.Name != "" {
			return
		}
		chain, ok := object["chain"].(map[string]any)
		if !ok {
			return
		}
		hook, _ := chain["hook"].(string)
		name, _ := chain["name"].(string)
		comment, _ := chain["comment"].(string)
		if name == "" || comment == "" || (hook != "input" && hook != "output") {
			return
		}
		prio, ok := chain["prio"].(float64)
		chainType, _ := chain["type"].(string)
		policy, _ := chain["policy"].(string)
		if !ok {
			return
		}
		if chainType == "" {
			chainType = "filter"
		}
		if policy == "" {
			policy = "accept"
		}
		found = nftChainMetadata{
			Family: "inet", Table: table, Name: name, Type: chainType,
			Hook: hook, Policy: policy, Comment: comment, Prio: int64(prio),
		}
	})
	if found.Name == "" {
		t.Fatalf("owned nftables base chain not found in %q", table)
	}
	return found
}

func corruptOwnedBaseChain(t *testing.T, table string) {
	t.Helper()
	original := ownedBaseChain(t, table)
	corrupt := original
	corrupt.Hook = "forward"
	batch := map[string]any{
		"nftables": []any{
			map[string]any{"flush": map[string]any{"chain": map[string]any{"family": original.Family, "table": original.Table, "name": original.Name}}},
			map[string]any{"delete": map[string]any{"chain": map[string]any{"family": original.Family, "table": original.Table, "name": original.Name}}},
			map[string]any{"add": map[string]any{"chain": map[string]any{
				"family": corrupt.Family, "table": corrupt.Table, "name": corrupt.Name,
				"type": corrupt.Type, "hook": corrupt.Hook, "prio": corrupt.Prio,
				"policy": corrupt.Policy, "comment": corrupt.Comment,
			}}},
		},
	}
	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal corrupt nft batch: %v", err)
	}
	commandInput(t, 10*time.Second, data, "nft", "-j", "-f", "-")
}

func walkJSON(value any, visit func(map[string]any)) {
	switch typed := value.(type) {
	case map[string]any:
		visit(typed)
		for _, child := range typed {
			walkJSON(child, visit)
		}
	case []any:
		for _, child := range typed {
			walkJSON(child, visit)
		}
	}
}

func nftCounters(t *testing.T, table string) map[string]uint64 {
	t.Helper()
	counters := make(map[string]uint64)
	walkJSON(objectJSON(t, table), func(object map[string]any) {
		counter, ok := object["counter"].(map[string]any)
		if !ok {
			return
		}
		name, _ := counter["name"].(string)
		packets, ok := counter["packets"].(float64)
		if name != "" && ok {
			counters[name] = uint64(packets)
		}
	})
	return counters
}

func nftHookPriorities(t *testing.T, table string) map[string]int64 {
	t.Helper()
	priorities := make(map[string]int64)
	walkJSON(objectJSON(t, table), func(object map[string]any) {
		chain, ok := object["chain"].(map[string]any)
		if !ok {
			return
		}
		name, _ := chain["name"].(string)
		prio, ok := chain["prio"].(float64)
		if name != "" && ok {
			priorities[name] = int64(prio)
		}
	})
	return priorities
}

func assertForeignTable(t *testing.T, table string) {
	t.Helper()
	output, err := nftTableMayFail(table)
	if err != nil {
		t.Fatalf("foreign nft table %q was removed: %v", table, err)
	}
	if !bytes.Contains(output, []byte("foreign_child")) {
		t.Fatalf("foreign nft child was removed: %s", output)
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

func startAppHelper(t *testing.T, configPath, checkpoint string, failApply bool) *exec.Cmd {
	t.Helper()
	// #nosec G204 G702 -- runs this test executable with a fixed helper selector.
	cmd := exec.Command(os.Args[0], "-test.run", "^TestE2EAppHelper$", "-test.v")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		e2eEnabledEnv+"=1",
		e2eChildEnv+"=1",
		e2eHelperEnv+"=1",
		"PERIMETERD_E2E_CONFIG="+configPath,
		e2eCheckpoint+"="+checkpoint,
	)
	if failApply {
		cmd.Env = append(cmd.Env, e2eFailApply+"=1")
	}
	return cmd
}

func startAppErrorHelper(t *testing.T, configPath, checkpoint string) *exec.Cmd {
	t.Helper()
	cmd := startAppHelper(t, configPath, checkpoint, false)
	cmd.Env = append(cmd.Env, e2eCheckpointError+"=1")
	return cmd
}

// TestE2EAppHelper runs app.Run with test-only programmatic injection hooks.
// It is never part of the production CLI and is only used to terminate a
// helper at an exact durability boundary in the isolated namespace.
func TestE2EAppHelper(t *testing.T) {
	if os.Getenv(e2eHelperEnv) != "1" {
		return
	}
	configPath := os.Getenv("PERIMETERD_E2E_CONFIG")
	checkpoint := os.Getenv(e2eCheckpoint)
	if configPath == "" || checkpoint == "" {
		t.Fatal("app helper requires config and checkpoint")
	}
	armed := false
	check := func(label string) error {
		// Startup restoration republishes the old active record too. Inject
		// only after the new candidate has durably prepared its transaction.
		if label == "after-prepare" {
			armed = true
		}
		if armed && label == checkpoint {
			if os.Getenv(e2eCheckpointError) == "1" {
				return errors.New("e2e checkpoint failure")
			}
			os.Exit(97)
		}
		return nil
	}
	backend := firewall.Backend(firewall.NewNFT())
	if os.Getenv(e2eFailApply) == "1" {
		backend = &failAfterApplyBackend{Backend: backend, armed: &armed}
	}
	startupTimeout := 30 * time.Second
	if os.Getenv(e2eFailApply) == "1" {
		startupTimeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	err := app.Run(ctx, app.Options{ConfigPath: configPath, Stderr: os.Stderr, Backend: backend, Checkpoint: check, StartupTimeout: startupTimeout})
	if err != nil {
		os.Exit(98)
	}
}

type failAfterApplyBackend struct {
	firewall.Backend
	armed *bool
}

func (b *failAfterApplyBackend) Apply(ctx context.Context, previous, candidate *firewall.Target) error {
	if err := b.Backend.Apply(ctx, previous, candidate); err != nil {
		return err
	}
	if *b.armed {
		return errors.New("e2e injected post-apply failure")
	}
	return nil
}
