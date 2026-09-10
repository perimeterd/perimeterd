package app

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"
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
	metrics, err := bindMetrics("127.0.0.1:0", health.Load)
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

	other, err := bindMetrics("127.0.0.1:0", health.Load)
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
	metrics, err := bindMetrics("127.0.0.1:0", health.Load)
	if err != nil {
		t.Fatal(err)
	}
	metrics.serve()
	if err := metrics.close(context.Background()); err != nil {
		t.Fatalf("close after serve: %v", err)
	}
}

func TestMetricsClosesRequestsWithWithheldBodies(t *testing.T) {
	metrics, err := bindMetrics("127.0.0.1:0", func() bool { return true })
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
	metrics, err := bindMetrics("127.0.0.1:0", func() bool { return true })
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
