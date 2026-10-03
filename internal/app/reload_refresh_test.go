package app

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"

	"github.com/perimeterd/perimeterd/internal/control"
)

func TestBackgroundRefreshCannotCompleteReloadWaiter(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	stateDir := filepath.Join(dir, "state")
	address := runAddress(t)
	var sourceAddress atomic.Value
	sourceAddress.Store("8.8.8.8/32")
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = fmt.Fprintf(w, `{"status":"ok","status_code":200,"data_call_name":"country-resource-list","data_call_status":"supported","version":"0.2","time":"2026-09-14T00:00:00","data":{"query_time":"2026-09-13T00:00:00","resources":{"ipv4":[%q],"ipv6":[]}}}`, sourceAddress.Load().(string))
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	writeGeoRunConfig(t, path, address, "1s")
	entered := make(chan struct{})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	backend := &sourceObservingBackend{policies: make(chan string, 16)}
	client := &http.Client{Transport: fixtureSourceTransport{target: target, base: http.DefaultTransport}}
	cancel, _, ready, done := startRunWithClient(t, path, stateDir, backend, client, func(phase string) error {
		if phase == "reload:after-read" {
			close(entered)
			<-release
		}
		return nil
	})
	defer func() { unblock(); awaitRunStop(t, cancel, done) }()
	awaitRunReady(t, ready)
	awaitSourcePolicy(t, backend.policies, "8.8.8.8/32")
	result := make(chan control.ReloadResult, 1)
	go func() {
		result <- control.ReloadPath(context.Background(), filepath.Join(stateDir, "run", "lookup.sock"), control.ReloadRequest{})
	}()
	awaitReloadBoundary(t, "reload:after-read", entered, result)
	sourceAddress.Store("9.9.9.9/32")
	// The real refresh timer drives this barrier; no race-guessing sleep.
	awaitSourcePolicy(t, backend.policies, "9.9.9.9/32")
	assertPending(t, result)
	unblock()
	if got := <-result; got.Outcome != "applied" {
		t.Fatal(got)
	}
}

func TestDigestMismatchSkipsSourcesAndSourceFailureKeepsPolicy(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	stateDir := filepath.Join(dir, "state")
	address := runAddress(t)
	var calls atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		http.Error(w, "unavailable", http.StatusServiceUnavailable)
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	writeRunConfig(t, path, address, "8.8.8.8/32")
	backend := &runBackend{recordingBackend: &recordingBackend{}, applied: make(chan struct{}, 16)}
	client := &http.Client{Transport: fixtureSourceTransport{target: target, base: http.DefaultTransport}}
	cancel, _, ready, done := startRunWithClient(t, path, stateDir, backend, client, nil)
	defer awaitRunStop(t, cancel, done)
	awaitRunReady(t, ready)
	awaitRunApply(t, backend.applied)
	previous := backend.selection()
	writeGeoRunConfig(t, path, address, "1h")
	socket := filepath.Join(stateDir, "run", "lookup.sock")
	got := control.ReloadPath(context.Background(), socket, control.ReloadRequest{ExpectConfigSHA256: "0000000000000000000000000000000000000000000000000000000000000000"})
	if got.Code != "config_mismatch" || calls.Load() != 0 || backend.selection() != previous {
		t.Fatalf("mismatch=%#v source calls=%d", got, calls.Load())
	}
	got = control.ReloadPath(context.Background(), socket, control.ReloadRequest{})
	if got.Outcome != "rejected" || got.Code != "configuration_error" || calls.Load() == 0 || backend.selection() != previous {
		t.Fatalf("source failure=%#v source calls=%d", got, calls.Load())
	}
}
