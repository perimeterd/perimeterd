package app

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/control"
	"github.com/perimeterd/perimeterd/internal/state"
)

type reloadFixture struct {
	path, stateDir, socket, address string
	backend                         *runBackend
	cancel                          context.CancelFunc
	signals                         chan os.Signal
	done                            <-chan error
}

func startReloadFixture(t *testing.T, checkpoint func(string) error) *reloadFixture {
	t.Helper()
	dir, err := os.MkdirTemp("", "pd-reload-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	f := &reloadFixture{path: filepath.Join(dir, "policy.yaml"), stateDir: filepath.Join(dir, "state"), address: runAddress(t), backend: &runBackend{recordingBackend: &recordingBackend{}, applied: make(chan struct{}, 32)}}
	f.socket = filepath.Join(f.stateDir, "run", "lookup.sock")
	writeRunConfig(t, f.path, f.address, "8.8.8.8/32")
	var ready chan string
	f.cancel, f.signals, ready, f.done = startRun(t, f.path, f.stateDir, f.backend, checkpoint)
	awaitRunReady(t, ready)
	awaitRunApply(t, f.backend.applied)
	t.Cleanup(func() {
		if f.cancel != nil {
			awaitRunStop(t, f.cancel, f.done)
		}
	})
	return f
}

func (f *reloadFixture) request(ctx context.Context) control.ReloadResult {
	return control.ReloadPath(ctx, f.socket, control.ReloadRequest{})
}

func fileDigest(t *testing.T, path string) string {
	t.Helper()
	// #nosec G304 -- path is an isolated configuration fixture created by this test.
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return fmt.Sprintf("%x", sha256.Sum256(data))
}

func reloadAsync(f *reloadFixture, ctx context.Context) <-chan control.ReloadResult {
	result := make(chan control.ReloadResult, 1)
	go func() { result <- f.request(ctx) }()
	return result
}

func awaitBoundary(t *testing.T, c <-chan struct{}) {
	t.Helper()
	select {
	case <-c:
	case <-time.After(5 * time.Second):
		t.Fatal("boundary not reached")
	}
}

func assertPending(t *testing.T, c <-chan control.ReloadResult) {
	t.Helper()
	select {
	case r := <-c:
		t.Fatalf("premature completion %#v", r)
	default:
	}
}

func TestAcknowledgedReloadWaitsForNativeApplyAndPublication(t *testing.T) {
	var armed atomic.Bool
	prepare := make(chan struct{})
	publish := make(chan struct{})
	releaseApply := make(chan struct{})
	releasePublish := make(chan struct{})
	releaseA := sync.OnceFunc(func() { close(releaseApply) })
	releaseP := sync.OnceFunc(func() { close(releasePublish) })
	defer releaseA()
	defer releaseP()
	f := startReloadFixture(t, func(phase string) error {
		if !armed.Load() {
			return nil
		}
		switch phase {
		case "after-prepare":
			close(prepare)
			<-releaseApply
		case "runtime:before-publish":
			close(publish)
			<-releasePublish
		}
		return nil
	})
	writeRunConfig(t, f.path, f.address, "9.9.9.9/32")
	digest := fileDigest(t, f.path)
	armed.Store(true)
	result := reloadAsync(f, context.Background())
	awaitBoundary(t, prepare)
	assertPending(t, result)
	releaseA()
	awaitBoundary(t, publish)
	assertPending(t, result)
	releaseP()
	got := <-result
	if got.Outcome != "applied" || got.ConfigSHA256 != digest || got.Revision == "" || f.backend.selection() != got.Revision {
		t.Fatalf("completion=%#v selection=%s", got, f.backend.selection())
	}
	store, err := state.Open(f.stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil || view.Active == nil || view.Active.ID != got.Revision {
		t.Fatalf("durable publication=%v %v", view.Active, err)
	}
	if len(view.Active.Config.Global.Blocklist) != 1 || view.Active.Config.Global.Blocklist[0].String() != "9.9.9.9/32" {
		t.Fatal("acknowledged revision did not select requested policy")
	}
}

func TestAcknowledgedReloadRejectsMalformedSecretAndDigestMismatch(t *testing.T) {
	f := startReloadFixture(t, nil)
	previous := f.backend.selection()
	// #nosec G101 -- synthetic credential-shaped marker verifies diagnostic redaction.
	secret := "DO_NOT_ECHO_API_SECRET_123"
	if err := os.WriteFile(f.path, []byte("version: ["+secret+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	got := f.request(context.Background())
	if got.Outcome != "rejected" || got.Code != "configuration_error" || strings.Contains(got.Message, secret) || got.ConfigSHA256 != fileDigest(t, f.path) {
		t.Fatal(got)
	}
	writeRunConfig(t, f.path, f.address, "9.9.9.9/32")
	got = control.ReloadPath(context.Background(), f.socket, control.ReloadRequest{ExpectConfigSHA256: strings.Repeat("0", 64)})
	if got.Code != "config_mismatch" || got.ConfigSHA256 != fileDigest(t, f.path) || f.backend.selection() != previous {
		t.Fatal(got)
	}
	select {
	case <-f.backend.applied:
		t.Fatal("rejected candidate applied")
	default:
	}
}

func TestAcknowledgedReloadParsesSameReadBytesAfterReplacement(t *testing.T) {
	read := make(chan struct{})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	f := startReloadFixture(t, func(phase string) error {
		if phase == "reload:after-read" {
			close(read)
			<-release
		}
		return nil
	})
	writeRunConfig(t, f.path, f.address, "9.9.9.9/32")
	digest := fileDigest(t, f.path)
	result := reloadAsync(f, context.Background())
	awaitBoundary(t, read)
	if err := os.WriteFile(f.path, []byte("invalid: ["), 0o600); err != nil {
		t.Fatal(err)
	}
	unblock()
	if got := <-result; got.Outcome != "applied" || got.ConfigSHA256 != digest {
		t.Fatal(got)
	}
	store, err := state.Open(f.stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil || view.Active == nil || len(view.Active.Config.Global.Blocklist) != 1 || view.Active.Config.Global.Blocklist[0].String() != "9.9.9.9/32" {
		t.Fatalf("replacement changed parsed candidate: %v %v", view.Active, err)
	}
}

func TestAcknowledgedReloadSupersessionAndSIGHUP(t *testing.T) {
	for _, signal := range []bool{false, true} {
		t.Run(fmt.Sprint(signal), func(t *testing.T) {
			entered := make(chan struct{}, 2)
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			f := startReloadFixture(t, func(phase string) error {
				if phase == "reload:after-read" {
					entered <- struct{}{}
					<-release
				}
				return nil
			})
			first := reloadAsync(f, context.Background())
			awaitBoundary(t, entered)
			var second <-chan control.ReloadResult
			if signal {
				f.signals <- syscall.SIGHUP
			} else {
				second = reloadAsync(f, context.Background())
			}
			awaitBoundary(t, entered)
			if got := <-first; got.Outcome != "rejected" || got.Code != "superseded" {
				t.Fatal(got)
			}
			unblock()
			if second != nil {
				if got := <-second; got.Outcome != "applied" {
					t.Fatal(got)
				}
			} else {
				awaitRunApply(t, f.backend.applied)
			}
		})
	}
}

func TestAcknowledgedReloadCancellationBeforeApplyAndDuringApply(t *testing.T) {
	for _, phase := range []string{"reload:after-read", "after-prepare"} {
		t.Run(phase, func(t *testing.T) {
			entered := make(chan struct{})
			release := make(chan struct{})
			unblock := sync.OnceFunc(func() { close(release) })
			defer unblock()
			var armed atomic.Bool
			f := startReloadFixture(t, func(p string) error {
				if armed.Load() && p == phase {
					close(entered)
					<-release
				}
				return nil
			})
			previous := f.backend.selection()
			armed.Store(true)
			writeRunConfig(t, f.path, f.address, "9.9.9.9/32")
			ctx, cancel := context.WithCancel(context.Background())
			result := reloadAsync(f, ctx)
			awaitBoundary(t, entered)
			cancel()
			if got := <-result; got.Outcome != "unknown" {
				t.Fatal(got)
			}
			unblock()
			if phase == "after-prepare" {
				awaitRunApply(t, f.backend.applied)
				if f.backend.selection() == previous {
					t.Fatal("request context interrupted native transaction")
				}
			}
			// Closing drains the late result and its session/listener owners.
			awaitRunStop(t, f.cancel, f.done)
			f.cancel = nil
			if phase == "reload:after-read" && f.backend.selection() != previous {
				t.Fatal("canceled staging mutated backend")
			}
		})
	}
}

func TestAcknowledgedReloadCommittedDegradedAndPublicationFailure(t *testing.T) {
	for _, phase := range []string{"after-retire", "runtime:before-publish"} {
		t.Run(phase, func(t *testing.T) {
			var armed atomic.Bool
			f := startReloadFixture(t, func(p string) error {
				if armed.Load() && p == phase {
					return errors.New("injected completion failure")
				}
				return nil
			})
			if phase == "after-retire" {
				f.backend.mu.Lock()
				f.backend.retireErr = errors.New("native cleanup failed")
				f.backend.mu.Unlock()
			}
			armed.Store(true)
			writeRunConfig(t, f.path, f.address, "9.9.9.9/32")
			got := f.request(context.Background())
			if got.Outcome != "degraded" || got.Revision == "" || got.ConfigSHA256 != fileDigest(t, f.path) {
				t.Fatal(got)
			}
			if phase == "runtime:before-publish" {
				select {
				case err := <-f.done:
					if err == nil {
						t.Fatal("publication failure did not stop daemon")
					}
					f.cancel = nil
				case <-time.After(5 * time.Second):
					t.Fatal("fatal publication failed to stop")
				}
			}
		})
	}
}

func TestReloadBridgeStartupCancellationAndShutdown(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	bridge := newReloadBridge(ctx.Done())
	if got := bridge.handle(context.Background(), control.ReloadRequest{}); got.Code != "not_ready" {
		t.Fatal(got)
	}
	bridge.ready.Store(true)
	canceled, stop := context.WithCancel(context.Background())
	stop()
	if got := bridge.handle(canceled, control.ReloadRequest{}); got.Outcome != "unknown" {
		t.Fatal(got)
	}
	select {
	case <-bridge.requests:
		t.Fatal("expired startup request queued")
	default:
	}
	result := make(chan control.ReloadResult, 1)
	go func() { result <- bridge.handle(context.Background(), control.ReloadRequest{}) }()
	cancel()
	if got := <-result; got.Outcome == "applied" {
		t.Fatal(got)
	}
}

func TestAcknowledgedReloadUncertainApplyAndBusyRecovery(t *testing.T) {
	var armed atomic.Bool
	var stabilize atomic.Int32
	f := startReloadFixture(t, func(phase string) error {
		if !armed.Load() {
			return nil
		}
		if phase == "active:after-dir-sync" {
			return errors.New("directory durability unavailable")
		}
		if phase == "stabilize:before-file-sync" {
			stabilize.Add(1)
			return errors.New("commit acknowledgement unavailable")
		}
		return nil
	})
	armed.Store(true)
	writeRunConfig(t, f.path, f.address, "9.9.9.9/32")
	got := f.request(context.Background())
	if got.Outcome != "unknown" || got.ConfigSHA256 != fileDigest(t, f.path) {
		t.Fatal(got)
	}
	if got := f.request(context.Background()); got.Outcome != "rejected" || got.Code != "busy" {
		t.Fatal(got)
	}
	armed.Store(false)
}

func TestAcknowledgedReloadShutdownDrainsLateStaging(t *testing.T) {
	entered := make(chan struct{})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	f := startReloadFixture(t, func(phase string) error {
		if phase == "reload:after-read" {
			close(entered)
			<-release
		}
		return nil
	})
	result := reloadAsync(f, context.Background())
	awaitBoundary(t, entered)
	f.cancel()
	if got := <-result; got.Outcome == "applied" {
		t.Fatal(got)
	}
	unblock()
	awaitRunStop(t, f.cancel, f.done)
	f.cancel = nil
	if _, err := os.Lstat(f.socket); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("socket retained after shutdown: %v", err)
	}
}

func TestStartupUnixReloadFailsWithoutDeferredExecution(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	stateDir := filepath.Join(dir, "state")
	writeRunConfig(t, path, runAddress(t), "8.8.8.8/32")
	reached := make(chan struct{})
	release := make(chan struct{})
	unblock := sync.OnceFunc(func() { close(release) })
	defer unblock()
	backend := &runBackend{recordingBackend: &recordingBackend{}, applied: make(chan struct{}, 16)}
	cancel, _, ready, done := startRun(t, path, stateDir, backend, func(phase string) error {
		if phase == "after-prepare" {
			close(reached)
			<-release
		}
		return nil
	})
	stopped := false
	defer func() {
		unblock()
		if !stopped {
			awaitRunStop(t, cancel, done)
		}
	}()
	awaitBoundary(t, reached)
	got := control.ReloadPath(context.Background(), filepath.Join(stateDir, "run", "lookup.sock"), control.ReloadRequest{})
	if got.Outcome != "rejected" || got.Code != "not_ready" {
		t.Fatal(got)
	}
	unblock()
	awaitRunReady(t, ready)
	awaitRunApply(t, backend.applied)
	// Shutdown drains every producer; a queued startup reload would execute a
	// second native transaction (or hit the once-only startup barrier).
	cancel()
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("startup request was deferred")
	}
	select {
	case <-backend.applied:
		t.Fatal("startup request executed later")
	default:
	}
}
