package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/firewall"
)

func TestStartupNotifierDeliversBoundedExtensionAndErrors(t *testing.T) {
	messages := make(chan string, 1)
	notifier := newStartupNotifier(func(message string) error {
		messages <- message
		return errors.New("delivery failed")
	}, time.Now().Add(5*time.Second))
	select {
	case message := <-messages:
		if !strings.Contains(message, "EXTEND_TIMEOUT_USEC=") {
			t.Fatalf("startup message %q has no timeout extension", message)
		}
		if !strings.Contains(message, "STATUS=starting") {
			t.Fatalf("startup message %q has no status", message)
		}
	case <-time.After(time.Second):
		t.Fatal("startup notifier did not deliver immediately")
	}
	if err := notifier.Stop(); err == nil || !strings.Contains(err.Error(), "delivery failed") {
		t.Fatalf("Stop error = %v, want delivery failure", err)
	}
}

func TestSystemdNotifyUsesUnixDatagram(t *testing.T) {
	path := t.TempDir() + "/notify.sock"
	address := &net.UnixAddr{Name: path, Net: "unixgram"}
	listener, err := net.ListenUnixgram("unixgram", address)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	t.Setenv("NOTIFY_SOCKET", path)
	if err := systemdNotify()("READY=1"); err != nil {
		t.Fatalf("systemdNotify: %v", err)
	}
	_ = listener.SetReadDeadline(time.Now().Add(time.Second))
	buffer := make([]byte, 128)
	n, _, err := listener.ReadFromUnix(buffer)
	if err != nil {
		t.Fatal(err)
	}
	if got := string(buffer[:n]); got != "READY=1" {
		t.Fatalf("notification = %q, want READY=1", got)
	}
}

func TestMetricsHealthEndpointAndBindPromotion(t *testing.T) {
	var health atomic.Bool
	health.Store(true)
	metrics, err := bindMetrics("127.0.0.1:0", health.Load, nil)
	if err != nil {
		t.Fatal(err)
	}
	metrics.serve()
	t.Cleanup(func() { _ = metrics.closeImmediate() })
	response := mustGet(t, "http://"+metrics.ln.Addr().String()+"/metrics")
	if response.StatusCode != http.StatusOK {
		_ = response.Body.Close()
		t.Fatalf("metrics status = %d, want 200", response.StatusCode)
	}
	_ = response.Body.Close()
	health.Store(false)
	response = mustGet(t, "http://"+metrics.ln.Addr().String()+"/metrics")
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), "perimeterd_enforcement_health 0") {
		t.Fatalf("metrics body = %q", body)
	}

	other, err := bindMetrics("127.0.0.1:0", health.Load, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = other.closeImmediate() })
	other.serve()
	unknown := mustGet(t, "http://"+other.ln.Addr().String()+"/unknown")
	_ = unknown.Body.Close()
	if unknown.StatusCode != http.StatusNotFound {
		t.Fatalf("unknown path status = %d, want 404", unknown.StatusCode)
	}
}

func TestMetricsCloseAfterServeIgnoresExpectedClosedListener(t *testing.T) {
	var health atomic.Bool
	health.Store(true)
	metrics, err := bindMetrics("127.0.0.1:0", health.Load, nil)
	if err != nil {
		t.Fatal(err)
	}
	metrics.serve()
	if err := metrics.close(context.Background()); err != nil {
		t.Fatalf("close after serve: %v", err)
	}
}

func TestMetricsClosesRequestsWithWithheldBodies(t *testing.T) {
	metrics, err := bindMetrics("127.0.0.1:0", func() bool { return true }, nil)
	if err != nil {
		t.Fatal(err)
	}
	// Scale the configured deadline, retaining zero if the server regresses
	// to an unbounded read. No assertion depends on the production duration.
	metrics.server.ReadTimeout /= 100
	metrics.serve()
	t.Cleanup(func() { _ = metrics.closeImmediate() })
	// #nosec G704 -- the destination is this test's loopback listener.
	conn, err := net.DialTimeout("tcp", metrics.ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET /metrics HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("server did not close the incomplete request before client deadline: %v", err)
	}
}

func TestMetricsForcedRetirementClosesActiveRequests(t *testing.T) {
	metrics, err := bindMetrics("127.0.0.1:0", func() bool { return true }, nil)
	if err != nil {
		t.Fatal(err)
	}
	active := make(chan struct{}, 1)
	metrics.server.ConnState = func(_ net.Conn, state http.ConnState) {
		if state == http.StateActive {
			select {
			case active <- struct{}{}:
			default:
			}
		}
	}
	metrics.serve()
	t.Cleanup(func() { _ = metrics.closeImmediate() })
	// #nosec G704 -- the destination is this test's loopback listener.
	conn, err := net.DialTimeout("tcp", metrics.ln.Addr().String(), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "GET /metrics HTTP/1.1\r\nHost: localhost\r\nContent-Length: 1\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	select {
	case <-active:
	case <-time.After(time.Second):
		t.Fatal("request did not become active")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Millisecond)
	defer cancel()
	if err := metrics.close(ctx); err != nil {
		t.Fatalf("successful forced retirement reported a resource failure: %v", err)
	}
	if _, err := io.Copy(io.Discard, conn); err != nil {
		t.Fatalf("retired listener left the active request open: %v", err)
	}
}

func mustGet(t *testing.T, url string) *http.Response {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		// #nosec G107 -- URL comes only from this test's loopback listener.
		response, err := http.Get(url)
		if err == nil {
			return response
		}
		if time.Now().After(deadline) {
			t.Fatalf("GET %s: %v", url, err)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

type runBackend struct {
	*recordingBackend
	applied chan struct{}
}

func (b *runBackend) Apply(ctx context.Context, previous, candidate *firewall.Target) error {
	err := b.recordingBackend.Apply(ctx, previous, candidate)
	b.applied <- struct{}{}
	return err
}

func runAddress(t *testing.T) string {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	address := listener.Addr().String()
	if err := listener.Close(); err != nil {
		t.Fatal(err)
	}
	return address
}

func writeRunConfig(t *testing.T, path, listen, block string) {
	t.Helper()
	text := fmt.Sprintf(`version: 1
metrics:
  listen: %s
firewall:
  backend: nftables
global:
  blocklist: [%s]
`, listen, block)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func startRun(t *testing.T, configPath, stateDir string, backend firewall.Backend, checkpoint func(string) error) (context.CancelFunc, chan os.Signal, chan string, <-chan error) {
	return startRunWithClient(t, configPath, stateDir, backend, nil, checkpoint)
}

func startRunWithClient(t *testing.T, configPath, stateDir string, backend firewall.Backend, client *http.Client, checkpoint func(string) error) (context.CancelFunc, chan os.Signal, chan string, <-chan error) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	signals := make(chan os.Signal, 8)
	ready := make(chan string, 8)
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			ConfigPath:   configPath,
			StateDir:     stateDir,
			LockPath:     filepath.Join(stateDir, "run", "owner.lock"),
			Backend:      backend,
			SourceClient: client,
			Signals:      signals,
			Stderr:       io.Discard,
			Checkpoint:   checkpoint,
			Notify: func(message string) error {
				ready <- message
				return nil
			},
			StartupTimeout: 20 * time.Second,
		})
	}()
	return cancel, signals, ready, done
}

func awaitRunReady(t *testing.T, ready <-chan string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case message := <-ready:
			if strings.Contains(message, "READY=1") {
				return
			}
		case <-deadline:
			t.Fatal("runtime did not become ready")
		}
	}
}

func awaitRunApply(t *testing.T, applied <-chan struct{}) {
	t.Helper()
	select {
	case <-applied:
	case <-time.After(5 * time.Second):
		t.Fatal("backend apply did not complete")
	}
}

func awaitRunStop(t *testing.T, cancel context.CancelFunc, done <-chan error) {
	t.Helper()
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runtime stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runtime did not stop")
	}
}

func waitRunPort(t *testing.T, address string, busy bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		listener, err := net.Listen("tcp", address)
		isBusy := err != nil
		if listener != nil {
			_ = listener.Close()
		}
		if isBusy == busy {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("port %s busy = %v, want %v", address, isBusy, busy)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func assertRunHealth(t *testing.T, address string, want int) {
	t.Helper()
	response := mustGet(t, "http://"+address+"/metrics")
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("metrics status = %d, want 200", response.StatusCode)
	}
	needle := fmt.Sprintf("perimeterd_enforcement_health %d", want)
	if !strings.Contains(string(body), needle) {
		t.Fatalf("metrics body = %q, want %q", body, needle)
	}
}

func TestRunUncertainReloadRetainsAndDiscardsStagedListener(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "policy.yaml")
	activeAddress := runAddress(t)
	stagedAddress := runAddress(t)
	writeRunConfig(t, configPath, activeAddress, "198.51.100.0/24")
	backend := &runBackend{recordingBackend: &recordingBackend{}, applied: make(chan struct{}, 16)}
	cancel, signals, ready, done := startRun(t, configPath, filepath.Join(dir, "state"), backend, nil)
	defer func() {
		if cancel != nil {
			awaitRunStop(t, cancel, done)
		}
	}()
	awaitRunReady(t, ready)
	awaitRunApply(t, backend.applied)
	assertRunHealth(t, activeAddress, 1)

	writeRunConfig(t, configPath, stagedAddress, "203.0.113.0/24")
	backend.mu.Lock()
	backend.applyErr = errors.New("uncertain reload")
	backend.applyFailures = 3
	backend.mutateBeforeFailure = true
	backend.mu.Unlock()
	signals <- syscall.SIGHUP
	for range 3 {
		awaitRunApply(t, backend.applied)
	}
	waitRunPort(t, stagedAddress, true)
	assertRunHealth(t, activeAddress, 0)
	if got := backend.selection(); got == "" {
		t.Fatal("uncertain reload lost the active firewall selection")
	}

	waitRunPort(t, stagedAddress, false)
	assertRunHealth(t, activeAddress, 1)
}

func TestRunSameAddressReloadKeepsListenerBound(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "policy.yaml")
	activeAddress := runAddress(t)
	writeRunConfig(t, configPath, activeAddress, "198.51.100.0/24")
	reachedPrepare := make(chan struct{}, 1)
	releasePrepare := make(chan struct{})
	release := sync.OnceFunc(func() { close(releasePrepare) })
	blockPrepare := false
	checkpoint := func(phase string) error {
		if phase == "after-prepare" && blockPrepare {
			select {
			case reachedPrepare <- struct{}{}:
			default:
			}
			<-releasePrepare
		}
		return nil
	}
	backend := &runBackend{recordingBackend: &recordingBackend{}, applied: make(chan struct{}, 16)}
	cancel, signals, ready, done := startRun(t, configPath, filepath.Join(dir, "state"), backend, checkpoint)
	defer func() {
		release()
		if cancel != nil {
			awaitRunStop(t, cancel, done)
		}
	}()
	awaitRunReady(t, ready)
	awaitRunApply(t, backend.applied)
	assertRunHealth(t, activeAddress, 1)

	writeRunConfig(t, configPath, activeAddress, "203.0.113.0/24")
	blockPrepare = true
	signals <- syscall.SIGHUP
	select {
	case <-reachedPrepare:
	case <-time.After(5 * time.Second):
		t.Fatal("same-address reload did not reach durable preparation")
	}
	waitRunPort(t, activeAddress, true)
	release()
	awaitRunApply(t, backend.applied)
	assertRunHealth(t, activeAddress, 1)
}

func TestRunPendingReloadShutdownReleasesBothListeners(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "policy.yaml")
	activeAddress := runAddress(t)
	stagedAddress := runAddress(t)
	writeRunConfig(t, configPath, activeAddress, "198.51.100.0/24")
	backend := &runBackend{recordingBackend: &recordingBackend{}, applied: make(chan struct{}, 32)}
	cancel, signals, ready, done := startRun(t, configPath, filepath.Join(dir, "state"), backend, nil)
	defer func() {
		if cancel != nil {
			awaitRunStop(t, cancel, done)
		}
	}()
	awaitRunReady(t, ready)
	awaitRunApply(t, backend.applied)

	writeRunConfig(t, configPath, stagedAddress, "203.0.113.0/24")
	backend.mu.Lock()
	backend.applyErr = errors.New("persistent uncertainty")
	backend.applyFailures = 100
	backend.mutateBeforeFailure = true
	backend.mu.Unlock()
	signals <- syscall.SIGHUP
	for range 3 {
		awaitRunApply(t, backend.applied)
	}
	waitRunPort(t, stagedAddress, true)
	assertRunHealth(t, activeAddress, 0)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("runtime stop: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("runtime did not stop")
	}
	cancel = nil
	waitRunPort(t, stagedAddress, false)
	waitRunPort(t, activeAddress, false)
}

func TestRunUncertainReloadRetainsAndPublishesMatchingRevision(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "policy.yaml")
	activeAddress := runAddress(t)
	stagedAddress := runAddress(t)
	writeRunConfig(t, configPath, activeAddress, "198.51.100.0/24")
	recoveryFailed := make(chan struct{}, 1)
	failCommit := false
	failCommitStabilize := false
	failRecoveryStabilize := false
	checkpoint := func(phase string) error {
		switch phase {
		case "active:after-dir-sync":
			if failCommit {
				failCommit = false
				failCommitStabilize = true
				failRecoveryStabilize = true
				return errors.New("ambiguous active publication")
			}
		case "stabilize:before-file-sync":
			if failCommitStabilize {
				failCommitStabilize = false
				return errors.New("commit durability unavailable")
			}
			if failRecoveryStabilize {
				failRecoveryStabilize = false
				select {
				case recoveryFailed <- struct{}{}:
				default:
				}
				return errors.New("recovery durability unavailable")
			}
		}
		return nil
	}
	backend := &runBackend{recordingBackend: &recordingBackend{}, applied: make(chan struct{}, 16)}
	cancel, signals, ready, done := startRun(t, configPath, filepath.Join(dir, "state"), backend, checkpoint)
	defer func() {
		if cancel != nil {
			awaitRunStop(t, cancel, done)
		}
	}()
	awaitRunReady(t, ready)
	awaitRunApply(t, backend.applied)

	writeRunConfig(t, configPath, stagedAddress, "203.0.113.0/24")
	failCommit = true
	signals <- syscall.SIGHUP
	select {
	case <-recoveryFailed:
	case <-time.After(5 * time.Second):
		t.Fatal("uncertain reload did not enter recovery")
	}
	waitRunPort(t, stagedAddress, true)
	assertRunHealth(t, activeAddress, 0)
	waitRunPort(t, activeAddress, false)
	assertRunHealth(t, stagedAddress, 1)
}

func TestRunCommittedDegradedReloadPublishesUnhealthyListener(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "policy.yaml")
	activeAddress := runAddress(t)
	stagedAddress := runAddress(t)
	writeRunConfig(t, configPath, activeAddress, "198.51.100.0/24")
	backend := &runBackend{recordingBackend: &recordingBackend{}, applied: make(chan struct{}, 16)}
	cancel, signals, ready, done := startRun(t, configPath, filepath.Join(dir, "state"), backend, nil)
	defer func() {
		if cancel != nil {
			awaitRunStop(t, cancel, done)
		}
	}()
	awaitRunReady(t, ready)
	awaitRunApply(t, backend.applied)

	writeRunConfig(t, configPath, stagedAddress, "203.0.113.0/24")
	backend.mu.Lock()
	backend.retireErr = errors.New("retirement unavailable")
	backend.mu.Unlock()
	signals <- syscall.SIGHUP
	awaitRunApply(t, backend.applied)
	waitRunPort(t, stagedAddress, true)
	waitRunPort(t, activeAddress, false)
	assertRunHealth(t, stagedAddress, 0)
}

func writeGeoRunConfig(t *testing.T, path, listen, refresh string) {
	t.Helper()
	text := fmt.Sprintf(`version: 1
metrics:
  listen: %s
firewall:
  backend: nftables
geo:
  refresh_interval: %s
  refresh_jitter: 1ns
  request_timeout: 3s
policies:
  - name: country
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["443/tcp"]
    include:
      countries: [CZ]
`, listen, refresh)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
}

func runMetricTimestamp(t *testing.T, address string) int64 {
	t.Helper()
	response := mustGet(t, "http://"+address+"/metrics")
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(body), "\n") {
		if !strings.HasPrefix(line, "perimeterd_prefix_snapshot_timestamp_seconds{") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) != 2 {
			t.Fatalf("malformed timestamp metric line %q", line)
		}
		value, err := strconv.ParseInt(fields[1], 10, 64)
		if err != nil {
			t.Fatalf("timestamp metric %q: %v", line, err)
		}
		return value
	}
	t.Fatalf("metrics body has no source timestamp: %q", body)
	return 0
}

func waitRunTimestampAfter(t *testing.T, address string, previous int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for {
		current := runMetricTimestamp(t, address)
		if current > previous {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("source timestamp = %d, want after %d", current, previous)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestRunSameAddressPublicationSelectsSourceTimestamp(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "policy.yaml")
	activeAddress := runAddress(t)
	var sourceAddress atomic.Value
	sourceAddress.Store("8.8.8.8/32")
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/data/country-resource-list/data.json" ||
			request.URL.Query().Get("resource") != "CZ" ||
			request.URL.Query().Get("sourceapp") != "perimeterd" {
			http.Error(writer, "unexpected source request", http.StatusBadRequest)
			return
		}
		writer.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(writer, `{"status":"ok","status_code":200,"data_call_name":"country-resource-list","data_call_status":"supported","version":"0.2","time":"2026-09-14T00:00:00","data":{"query_time":"2026-09-13T00:00:00","resources":{"ipv4":[%q],"ipv6":[]}}}`, sourceAddress.Load().(string))
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	writeGeoRunConfig(t, configPath, activeAddress, "1h")
	backend := &sourceObservingBackend{policies: make(chan string, 16)}
	client := &http.Client{Transport: fixtureSourceTransport{target: target, base: http.DefaultTransport}}
	cancel, signals, ready, done := startRunWithClient(t, configPath, filepath.Join(dir, "state"), backend, client, nil)
	defer func() {
		if cancel != nil {
			awaitRunStop(t, cancel, done)
		}
	}()
	awaitRunReady(t, ready)
	awaitSourcePolicy(t, backend.policies, "8.8.8.8/32")
	previous := runMetricTimestamp(t, activeAddress)

	time.Sleep(1100 * time.Millisecond)
	sourceAddress.Store("9.9.9.9/32")
	writeGeoRunConfig(t, configPath, activeAddress, "1s")
	signals <- syscall.SIGHUP
	awaitSourcePolicy(t, backend.policies, "9.9.9.9/32")
	waitRunTimestampAfter(t, activeAddress, previous)
}

func TestRunStartupWithholdsReadinessUntilRecovery(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "policy.yaml")
	stagedAddress := runAddress(t)
	writeRunConfig(t, configPath, stagedAddress, "198.51.100.0/24")
	recoveryFailed := make(chan struct{}, 1)
	failCommit := true
	failCommitStabilize := false
	failRecoveryStabilize := false
	blockRecovery := false
	allowRecovery := make(chan struct{})
	releaseRecovery := sync.OnceFunc(func() { close(allowRecovery) })
	checkpoint := func(phase string) error {
		switch phase {
		case "active:after-dir-sync":
			if failCommit {
				failCommit = false
				failCommitStabilize = true
				failRecoveryStabilize = true
				return errors.New("ambiguous startup publication")
			}
		case "stabilize:before-file-sync":
			if failCommitStabilize {
				failCommitStabilize = false
				return errors.New("startup durability unavailable")
			}
			if failRecoveryStabilize {
				failRecoveryStabilize = false
				blockRecovery = true
				select {
				case recoveryFailed <- struct{}{}:
				default:
				}
				return errors.New("startup recovery durability unavailable")
			}
			if blockRecovery {
				<-allowRecovery
			}
		}
		return nil
	}
	backend := &runBackend{recordingBackend: &recordingBackend{}, applied: make(chan struct{}, 16)}
	cancel, _, ready, done := startRun(t, configPath, filepath.Join(dir, "state"), backend, checkpoint)
	defer func() {
		releaseRecovery()
		if cancel != nil {
			awaitRunStop(t, cancel, done)
		}
	}()
	select {
	case <-recoveryFailed:
	case <-time.After(5 * time.Second):
		t.Fatal("startup did not enter recovery")
	}
	waitRunPort(t, stagedAddress, true)
checkReadiness:
	for {
		select {
		case message := <-ready:
			if strings.Contains(message, "READY=1") {
				t.Fatal("startup reported readiness before recovery")
			}
		default:
			break checkReadiness
		}
	}
	releaseRecovery()
	awaitRunReady(t, ready)
	assertRunHealth(t, stagedAddress, 1)
}
