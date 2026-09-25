//go:build linux && e2e

package e2e

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"os/exec"
	"strconv"
	"syscall"
	"testing"
	"time"
)

const (
	fixtureIPv4Host = "8.20.0.1"
	fixtureIPv4Peer = "8.20.0.2"
	fixtureIPv6Host = "2600:20::1"
	fixtureIPv6Peer = "2600:20::2"
	fixtureLANHost  = "192.168.20.1"
	fixtureLANPeer  = "192.168.20.2"
)

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
	if expectation == "drop" {
		var networkErr net.Error
		if !errors.As(err, &networkErr) || !networkErr.Timeout() {
			t.Fatalf("TCP DROP produced an error instead of a timeout: %v", err)
		}
	}
	if expectation == "reject" {
		// Both native backends reject TCP with a reset, which refuses the
		// connect rather than timing it out or reporting a routing failure.
		if !errors.Is(err, syscall.ECONNREFUSED) {
			t.Fatalf("TCP REJECT did not refuse the connection: %v", err)
		}
		if time.Since(started) > 700*time.Millisecond {
			t.Fatalf("TCP REJECT did not fail promptly: %v", err)
		}
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

func probeIngress(t *testing.T, peer *peerNamespace, network, hostAddress, expectation string, protocol string) {
	t.Helper()
	probeIngressAddresses(t, peer, network, hostAddress, hostAddress, expectation, protocol)
}

func probeIngressAddresses(t *testing.T, peer *peerNamespace, network, hostAddress, dialAddress, expectation, protocol string) {
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
	cmd := peer.helper(t, "dial-"+protocol, network, dialAddress, expectation)
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
