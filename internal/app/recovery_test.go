package app

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"testing/synctest"
	"time"

	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/state"
)

func recoveryFixture(t *testing.T) (string, *state.Store, *state.Revision) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	store, err := state.Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := NewEngine(store, &recordingBackend{}, nil)
	defer engine.Close()
	if _, err := engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	outcome, err := engine.Apply(context.Background(), admitCandidate(t, engine, parseEngineConfig(t, "203.0.113.0/24")))
	if err != nil || !outcome.Committed {
		t.Fatalf("initial apply: %+v, %v", outcome, err)
	}
	return dir, store, outcome.Active
}

func TestRecoverySameRevisionAndCleanRestart(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(fmt.Sprintf("prepared=%t", prepared), func(t *testing.T) {
			_, store, active := recoveryFixture(t)
			if prepared {
				if err := store.Prepare(active, active); err != nil {
					t.Fatal(err)
				}
				view, err := store.Read()
				if err != nil || view.Journal == nil {
					t.Fatalf("prepared view: %+v, %v", view, err)
				}
				journal := view.Journal
				if journal.Phase != "prepared" || journal.Previous != active.ID || journal.Candidate != active.ID || len(journal.Revisions) != 1 || journal.PreviousManifest != journal.CandidateManifest {
					t.Fatalf("incorrect same-revision fixture: %+v", journal)
				}
			}
			backend := &recordingBackend{}
			engine := NewEngine(store, backend, nil)
			defer engine.Close()
			recovered, err := recoverUntilReady(context.Background(), engine, nil)
			if err != nil || recovered == nil || recovered.ID != active.ID || backend.selection() != active.Target.Generation || !engine.Healthy() {
				t.Fatalf("recovery: %+v, %v, selected=%s", recovered, err, backend.selection())
			}
			view, err := store.Read()
			if err != nil || view.Journal != nil || view.Active.ID != active.ID {
				t.Fatalf("final state: %+v, %v", view, err)
			}
		})
	}
}

func TestRecoveryPermanentCapacityPreservesJournal(t *testing.T) {
	for _, prepared := range []bool{false, true} {
		t.Run(fmt.Sprintf("prepared=%t", prepared), func(t *testing.T) {
			_, store, active := recoveryFixture(t)
			if prepared {
				if err := store.Prepare(active, active); err != nil {
					t.Fatal(err)
				}
			}
			capacity := &firewall.CapacityError{RequiredBytes: 200, LimitBytes: 100}
			backend := &recordingBackend{applyErr: capacity, applyFailures: 2}
			engine := NewEngine(store, backend, nil)
			defer engine.Close()
			failures := 0
			_, err := recoverUntilReady(context.Background(), engine, func(err error, attempt int, delay time.Duration) {
				failures++
				if attempt != 1 || delay != 0 {
					t.Fatalf("permanent failure retried: attempt=%d delay=%s", attempt, delay)
				}
			})
			if !errors.Is(err, capacity) || failures != 1 || backend.applyFailures != 1 {
				t.Fatalf("permanent recovery: failures=%d remaining=%d err=%v", failures, backend.applyFailures, err)
			}
			view, err := store.Read()
			if err != nil || view.Active == nil || view.Active.ID != active.ID || view.Journal == nil || view.Journal.Phase != "prepared" || view.Journal.Candidate != active.ID {
				t.Fatalf("failure changed durable authority: %+v, %v", view, err)
			}
		})
	}
}

func TestRecoveryTransientRetryAndContext(t *testing.T) {
	for _, mode := range []string{"success", "deadline", "cancel"} {
		t.Run(mode, func(t *testing.T) {
			synctest.Test(t, func(t *testing.T) {
				_, store, active := recoveryFixture(t)
				root := errors.New("untrusted native diagnostic")
				backend := &recordingBackend{applyErr: root, applyFailures: 1}
				engine := NewEngine(store, backend, nil)
				defer engine.Close()
				ctx, cancel := context.WithTimeout(context.Background(), 500*time.Millisecond)
				if mode != "deadline" {
					cancel()
					ctx, cancel = context.WithCancel(context.Background())
				}
				defer cancel()
				failures := 0
				recovered, err := recoverUntilReady(ctx, engine, func(_ error, attempt int, delay time.Duration) {
					failures++
					if attempt != 1 || delay != time.Second {
						t.Fatalf("retry: attempt=%d delay=%s", attempt, delay)
					}
					if mode == "cancel" {
						cancel()
					}
				})
				if failures != 1 {
					t.Fatalf("failures=%d", failures)
				}
				if mode == "success" {
					if err != nil || recovered == nil || recovered.ID != active.ID {
						t.Fatalf("transient recovery: %+v, %v", recovered, err)
					}
				} else {
					want := context.Canceled
					if mode == "deadline" {
						want = context.DeadlineExceeded
					}
					if !errors.Is(err, want) || !errors.Is(err, root) {
						t.Fatalf("lost context or root cause: %v", err)
					}
				}
			})
		})
	}
}

type childTimeoutBackend struct {
	*recordingBackend
	calls     int
	childErr  error
	parentErr error
}

func (b *childTimeoutBackend) Apply(ctx context.Context, previous, candidate *firewall.Target, dynamic *firewall.DynamicState) error {
	b.calls++
	if b.calls == 1 {
		child, cancel := context.WithTimeout(ctx, time.Millisecond)
		defer cancel()
		<-child.Done()
		b.childErr, b.parentErr = child.Err(), ctx.Err()
		return fmt.Errorf("native operation: %w", b.childErr)
	}
	return b.recordingBackend.Apply(ctx, previous, candidate, dynamic)
}

func TestRunRecoveryRetriesChildTimeout(t *testing.T) {
	dir, store, active := recoveryFixture(t)
	if err := store.Prepare(active, active); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "policy.yaml")
	writeRunConfig(t, path, runAddress(t), "8.8.8.8/32")
	backend := &childTimeoutBackend{recordingBackend: &recordingBackend{}}
	signals := make(chan os.Signal, 1)
	var ready bool
	var logs bytes.Buffer
	err := Run(context.Background(), Options{
		ConfigPath: path, StateDir: dir,
		LockPath: filepath.Join(dir, "run", "owner.lock"), Backend: backend,
		StartupTimeout: time.Minute, Stderr: &logs, Signals: signals,
		Notify: func(message string) error {
			if strings.Contains(message, "READY=1") {
				ready = true
				signals <- os.Interrupt
			}
			return nil
		},
	})
	if err != nil || !ready {
		t.Fatalf("startup did not recover from child timeout: ready=%t err=%v logs=%s", ready, err, logs.String())
	}
	if !errors.Is(backend.childErr, context.DeadlineExceeded) || backend.parentErr != nil {
		t.Fatalf("timeout was not confined to child: child=%v parent=%v", backend.childErr, backend.parentErr)
	}
	// Initial recovery times out, its retry succeeds, then current YAML applies.
	if backend.calls != 3 {
		t.Fatalf("native apply calls=%d, want failed recovery, successful recovery, and initial apply", backend.calls)
	}
	view, err := store.Read()
	if err != nil || view.Journal != nil || view.Active == nil || backend.selection() != view.Active.Target.Generation {
		t.Fatalf("recovered startup left inconsistent authority: %+v err=%v selected=%s", view, err, backend.selection())
	}
}

func TestRunBootstrapRecoveryFailureIsSafeAndStopsNotifier(t *testing.T) {
	dir, store, active := recoveryFixture(t)
	if err := store.Prepare(active, active); err != nil {
		t.Fatal(err)
	}
	// #nosec G101 -- deliberate dummy URL credentials exercise diagnostic secrecy.
	secret := "https://user:secret@example.invalid/private"
	root := errors.New(secret)
	backend := &recordingBackend{applyErr: root, persistentApplyErr: true}
	var logs bytes.Buffer
	var mu sync.Mutex
	var messages []string
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	err := Run(ctx, Options{
		ConfigPath: filepath.Join(dir, "does-not-exist.yaml"), StateDir: dir,
		LockPath: filepath.Join(dir, "run", "owner.lock"), Backend: backend,
		Stderr: &logs, Signals: make(chan os.Signal),
		Notify: func(message string) error {
			mu.Lock()
			defer mu.Unlock()
			messages = append(messages, message)
			if strings.Contains(message, "recovery retry pending") {
				// The first failure must already be logged before any retry wait.
				if logs.Len() == 0 {
					t.Error("first recovery failure was not logged immediately")
				}
				cancel()
			}
			return nil
		},
	})
	if !errors.Is(err, context.Canceled) || !errors.Is(err, root) {
		t.Fatalf("Run error: %v", err)
	}
	mu.Lock()
	defer mu.Unlock()
	joined := strings.Join(messages, "\n")
	if strings.Contains(logs.String(), secret) || strings.Contains(joined, secret) || strings.Contains(err.Error(), secret) || strings.Contains(joined, "READY=1") {
		t.Fatalf("unsafe or premature startup output: logs=%s notifications=%s", logs.String(), joined)
	}
	if len(messages) == 0 || !strings.HasPrefix(messages[len(messages)-1], "STATUS=startup failed:") {
		t.Fatalf("missing final failed status: %v", messages)
	}
}

func TestRecoveryClassificationThroughJoinedErrors(t *testing.T) {
	capacity := &firewall.CapacityError{RequiredBytes: 2, LimitBytes: 1}
	if recoveryRetryable(fmt.Errorf("outer: %w", errors.Join(errors.New("temporary"), capacity))) {
		t.Fatal("joined permanent capacity error was retried")
	}
	for _, transient := range []error{errors.New("unknown native error"), context.Canceled, context.DeadlineExceeded} {
		if !recoveryRetryable(fmt.Errorf("native operation: %w", transient)) {
			t.Fatalf("child-operation failure must remain retryable: %v", transient)
		}
	}
	for _, permanent := range []error{exec.ErrNotFound, os.ErrPermission, os.ErrNotExist} {
		if recoveryRetryable(fmt.Errorf("native operation: %w", permanent)) {
			t.Fatalf("deterministic native failure was retried: %v", permanent)
		}
	}
	if got := recoveryContextError(context.Canceled, context.Canceled); got != context.Canceled {
		t.Fatalf("context error wrapped repeatedly: %v", got)
	}
}

func TestRecoveryDistinctPreparedTransitionRestoresAcknowledgedTarget(t *testing.T) {
	_, store, active := recoveryFixture(t)
	engine := NewEngine(store, &recordingBackend{}, nil)
	defer engine.Close()
	if _, err := engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	candidate := admitCandidate(t, engine, parseEngineConfig(t, "198.51.100.0/24"))
	id, err := transactionID()
	if err != nil {
		t.Fatal(err)
	}
	target, err := firewall.BuildTarget(store.Owner(), id, candidate.cfg, candidate.model, active.Target)
	if err != nil {
		t.Fatal(err)
	}
	pending := &state.Revision{Version: 2, ID: id, Epoch: candidate.epoch, ConfigPath: candidate.path, Config: candidate.cfg, Target: target}
	if target.Generation == active.Target.Generation {
		t.Fatal("fixture did not create a distinct static generation")
	}
	if err := store.Prepare(active, pending); err != nil {
		t.Fatal(err)
	}
	backend := &recordingBackend{selected: target.Generation}
	restarted := NewEngine(store, backend, nil)
	defer restarted.Close()
	recovered, err := recoverUntilReady(context.Background(), restarted, nil)
	if err != nil || recovered == nil || recovered.ID != active.ID || backend.selection() != active.Target.Generation {
		t.Fatalf("interrupted transition recovery: %+v, %v, selected=%s", recovered, err, backend.selection())
	}
	view, err := store.Read()
	if err != nil || view.Journal != nil || view.Active.ID != active.ID {
		t.Fatalf("recovery lost acknowledged authority: %+v, %v", view, err)
	}
}

func TestRunPermanentRecoveryFailsBeforeReadingYAML(t *testing.T) {
	dir, store, active := recoveryFixture(t)
	if err := store.Prepare(active, active); err != nil {
		t.Fatal(err)
	}
	capacity := &firewall.CapacityError{RequiredBytes: 200, LimitBytes: 100}
	backend := &recordingBackend{applyErr: capacity, applyFailures: 2}
	var logs bytes.Buffer
	err := Run(context.Background(), Options{
		ConfigPath: filepath.Join(dir, "missing.yaml"), StateDir: dir,
		LockPath: filepath.Join(dir, "run", "owner.lock"), Backend: backend,
		Stderr: &logs, Signals: make(chan os.Signal), Notify: func(string) error { return nil },
	})
	if !errors.Is(err, capacity) || backend.applyFailures != 1 {
		t.Fatalf("startup did not stop at first capacity failure: %v, remaining=%d", err, backend.applyFailures)
	}
	if !strings.Contains(logs.String(), `"required_bytes":200`) || !strings.Contains(logs.String(), `"limit_bytes":100`) {
		t.Fatalf("early capacity log lacks actionable dimensions: %s", logs.String())
	}
	view, err := store.Read()
	if err != nil || view.Active == nil || view.Active.ID != active.ID || view.Journal == nil || view.Journal.Phase != "prepared" {
		t.Fatalf("failed startup changed durable state: %+v, %v", view, err)
	}
}
