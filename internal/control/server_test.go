package control

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/state"
)

func TestSocketActiveRefusalAndLifecycleLockIndependence(t *testing.T) {
	dir := t.TempDir()
	// #nosec G302 -- this private runtime directory requires owner-only traversal.
	if err := os.Chmod(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "lookup.sock")
	lock, err := state.AcquireLock(filepath.Join(dir, "owner.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	server, err := Listen(path, http.NotFoundHandler(), ReloadHTTPHandler(func(context.Context, ReloadRequest) ReloadResult { return applied() }))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(context.Background()) }()
	if _, err := Listen(path, http.NotFoundHandler(), http.NotFoundHandler()); err == nil {
		t.Fatal("replaced active socket")
	}
	if got := ReloadPath(context.Background(), path, ReloadRequest{}); got.Outcome != "applied" {
		t.Fatal(got)
	}
}

func TestSocketInodeCleanupAndListenerFailure(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lookup.sock")
	server, err := Listen(path, http.NotFoundHandler(), http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	if err := server.listener.Close(); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-server.Errors():
		if err == nil {
			t.Fatal("missing listener error")
		}
	case <-time.After(time.Second):
		t.Fatal("listener failure not reported")
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket retained %v", err)
	}
}

func TestReloadSlowUploadRetainsShortReadBound(t *testing.T) {
	reached := make(chan struct{}, 1)
	path := testServer(t, func(context.Context, ReloadRequest) ReloadResult { reached <- struct{}{}; return applied() })
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	_ = conn.SetDeadline(time.Now().Add(Timeout + 2*time.Second))
	_, err = io.WriteString(conn, "POST /v1/reload HTTP/1.1\r\nHost: perimeterd\r\nContent-Length: 2\r\n\r\n{")
	if err != nil {
		t.Fatal(err)
	}
	response, err := http.ReadResponse(bufio.NewReader(conn), nil)
	if err != nil {
		t.Fatalf("short read bound failed: %v", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusBadRequest {
		t.Fatal(response.StatusCode)
	}
	select {
	case <-reached:
		t.Fatal("incomplete upload admitted")
	default:
	}
}

func TestLookupEvaluationRetainsShortContextBound(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lookup.sock")
	server, err := Listen(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ctx, cancel := context.WithTimeout(r.Context(), Timeout)
		defer cancel()
		<-ctx.Done()
		w.WriteHeader(http.StatusServiceUnavailable)
	}), http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(context.Background()) }()
	client, closeClient := UnixClient(path, Timeout+2*time.Second)
	defer closeClient()
	ctx, cancel := context.WithTimeout(context.Background(), Timeout+2*time.Second)
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, "http://perimeterd/v1/lookup", nil)
	response, err := client.Do(req)
	// Write deadline and handler context expire together; either a non-success
	// response or closed connection proves lookup did not inherit 80 seconds.
	if err == nil {
		defer func() { _ = response.Body.Close() }()
		if response.StatusCode == 200 {
			t.Fatal("lookup falsely succeeded")
		}
	}
	if ctx.Err() != nil {
		t.Fatal("lookup outlived its short route deadline")
	}
}
