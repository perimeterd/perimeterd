package control

import (
	"context"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func testServer(t *testing.T, handler ReloadHandler) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), "lookup.sock")
	server, err := Listen(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "lookup available") }), ReloadHTTPHandler(handler))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	return path
}

func applied() ReloadResult {
	return ReloadResult{SchemaVersion: 1, Outcome: "applied", Revision: "revision", ConfigSHA256: strings.Repeat("a", 64)}
}

func TestReloadUnixBeyondLookupDeadline(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	path := testServer(t, func(ctx context.Context, _ ReloadRequest) ReloadResult {
		close(entered)
		select {
		case <-release:
			return applied()
		case <-ctx.Done():
			return Failure("unknown", "timeout", "canceled")
		}
	})
	result := make(chan ReloadResult, 1)
	go func() { result <- ReloadPath(context.Background(), path, ReloadRequest{}) }()
	<-entered
	// This one real-duration regression protects endpoint-aware socket deadlines.
	timer := time.NewTimer(Timeout + 200*time.Millisecond)
	defer timer.Stop()
	<-timer.C
	close(release)
	if got := <-result; got.Outcome != "applied" {
		t.Fatalf("long reload = %#v", got)
	}
}

func TestReloadIndependentCapacityAndCancellation(t *testing.T) {
	entered := make(chan struct{}, 2)
	var calls atomic.Int32
	path := testServer(t, func(ctx context.Context, _ ReloadRequest) ReloadResult {
		calls.Add(1)
		entered <- struct{}{}
		<-ctx.Done()
		return Failure("unknown", "timeout", "canceled")
	})
	ctx, cancel := context.WithCancel(context.Background())
	results := make(chan ReloadResult, 2)
	for range 2 {
		go func() { results <- ReloadPath(ctx, path, ReloadRequest{}) }()
	}
	<-entered
	<-entered
	if got := ReloadPath(context.Background(), path, ReloadRequest{}); got.Code != "busy" {
		t.Fatalf("third waiter = %#v", got)
	}
	client, closeClient := UnixClient(path, time.Second)
	defer closeClient()
	response, err := client.Post("http://perimeterd/v1/lookup", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	_ = response.Body.Close()
	if response.StatusCode != 200 {
		t.Fatal(response.StatusCode)
	}
	cancel()
	<-results
	<-results
	if calls.Load() != 2 {
		t.Fatalf("calls=%d", calls.Load())
	}
}

func TestReloadStrictRequests(t *testing.T) {
	var calls atomic.Int32
	path := testServer(t, func(context.Context, ReloadRequest) ReloadResult { calls.Add(1); return applied() })
	client, closeClient := UnixClient(path, time.Second)
	defer closeClient()
	for _, body := range []string{`null`, `{}`, `{"unknown":1}`, `{"expect_config_sha256":""}`, `{"expect_config_sha256":null}`, `{"expect_config_sha256":"bad"}`, `{} {}`, `{"expect_config_sha256":"a","expect_config_sha256":"a"}`, `{"EXPECT_CONFIG_SHA256":"a"}`, strings.Repeat(" ", reloadMaxBytes+1)} {
		response, err := client.Post("http://perimeterd"+ReloadEndpoint, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		_ = response.Body.Close()
		want := 400
		if body == `{}` {
			want = 200
		}
		if response.StatusCode != want {
			t.Fatalf("body=%q status=%d", body, response.StatusCode)
		}
	}
	if calls.Load() != 1 {
		t.Fatalf("invalid requests reached handler: %d", calls.Load())
	}
}

func TestReloadClientFailsClosedWithoutRetry(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		status     int
	}{
		{"old", "404 page not found", 404},
		{"malformed", "{", 200},
		{"schema", `{"schema_version":2,"outcome":"applied","revision":"r","config_sha256":"` + strings.Repeat("a", 64) + `"}`, 200},
		{"missing", `{"schema_version":1,"outcome":"applied"}`, 200},
		{"digest", `{"schema_version":1,"outcome":"applied","revision":"r","config_sha256":"` + strings.Repeat("b", 64) + `"}`, 200},
		{"status", `{"schema_version":1,"outcome":"applied","revision":"r","config_sha256":"` + strings.Repeat("a", 64) + `"}`, 503},
		{"redirect", "{}", 307},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "socket")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			var calls atomic.Int32
			server := &http.Server{ReadHeaderTimeout: time.Second, Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				calls.Add(1)
				w.Header().Set("Location", "http://perimeterd"+ReloadEndpoint)
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})}
			go func() { _ = server.Serve(listener) }()
			defer func() { _ = server.Close() }()
			result := ReloadPath(context.Background(), path, ReloadRequest{ExpectConfigSHA256: strings.Repeat("a", 64)})
			if result.Outcome != "unknown" || calls.Load() != 1 {
				t.Fatalf("result=%#v calls=%d", result, calls.Load())
			}
		})
	}
	if got := ReloadPath(context.Background(), filepath.Join(t.TempDir(), "absent"), ReloadRequest{}); got.Outcome != "unknown" {
		t.Fatal(got)
	}
}

func TestReloadTimeoutAndShutdownCancelWaiter(t *testing.T) {
	canceled := make(chan struct{})
	path := testServer(t, func(ctx context.Context, _ ReloadRequest) ReloadResult {
		<-ctx.Done()
		close(canceled)
		return Failure("unknown", "timeout", "canceled")
	})
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	result := ReloadPath(ctx, path, ReloadRequest{})
	if result.Outcome != "unknown" || !strings.Contains(result.Message, "unknown") {
		t.Fatal(result)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("waiter leaked")
	}
}

func TestReloadResponseSizeBound(t *testing.T) {
	path := testServer(t, func(context.Context, ReloadRequest) ReloadResult {
		result := applied()
		result.Revision = strings.Repeat("x", reloadMaxBytes)
		return result
	})
	if got := ReloadPath(context.Background(), path, ReloadRequest{}); got.Outcome != "unknown" || got.Code != "invalid_result" {
		t.Fatal(got)
	}
}
