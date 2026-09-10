package app

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"testing"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/state"
)

type recordingBackend struct {
	mu sync.Mutex

	selected            string
	applyErr            error
	applyFailures       int
	persistentApplyErr  bool
	mutateBeforeFailure bool
	retireErr           error
	cleanupErr          error
	applies             int
	retire              int
}

func (b *recordingBackend) Preflight(context.Context, *firewall.Target, *firewall.Target) error {
	return nil
}

func (b *recordingBackend) Apply(_ context.Context, previous, candidate *firewall.Target) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.applies++
	if b.applyFailures > 0 {
		b.applyFailures--
		if b.mutateBeforeFailure {
			b.selectTarget(candidate)
		}
		if b.applyErr == nil {
			return errors.New("injected backend apply failure")
		}
		return b.applyErr
	}
	if b.persistentApplyErr && b.applyErr != nil {
		if b.mutateBeforeFailure {
			b.selectTarget(candidate)
		}
		return b.applyErr
	}
	b.selectTarget(candidate)
	return nil
}

func (b *recordingBackend) selectTarget(candidate *firewall.Target) {
	if candidate == nil {
		b.selected = ""
	} else {
		b.selected = candidate.Generation
	}
}

func (b *recordingBackend) Retire(context.Context, *firewall.Target, *firewall.Target) error {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.retire++
	return b.retireErr
}

func (b *recordingBackend) Cleanup(context.Context, []*firewall.Target) error {
	return b.cleanupErr
}

func (b *recordingBackend) selection() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.selected
}

func parseEngineConfig(t *testing.T, block string) config.Config {
	t.Helper()
	text := `version: 1
firewall:
  backend: nftables
  deny_action: drop
  ipv4: true
  ipv6: true
  nftables:
    table: perimeterd-test
    priority: -10
global:
  blocklist: [` + block + `]
`
	cfg, err := config.Parse([]byte(text))
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	return cfg
}

func newTestEngine(t *testing.T, backend firewall.Backend, checkpoint func(string) error) (*Engine, *state.Store) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	store, err := state.Open(dir, checkpoint)
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	engine := NewEngine(store, backend, checkpoint)
	if _, err := engine.Recover(context.Background()); err != nil {
		t.Fatalf("recover empty state: %v", err)
	}
	return engine, store
}

func admitCandidate(t *testing.T, engine *Engine, cfg config.Config) Candidate {
	t.Helper()
	epoch, err := engine.Admit()
	if err != nil {
		t.Fatalf("admit: %v", err)
	}
	candidate, err := NewCandidate(epoch, "invalid-current-yaml.yaml", cfg)
	if err != nil {
		t.Fatalf("new candidate: %v", err)
	}
	return candidate
}

func TestEngineNewInvalidAdmissionSupersedesOlderCandidate(t *testing.T) {
	backend := &recordingBackend{}
	engine, _ := newTestEngine(t, backend, nil)
	defer engine.Close()
	old := admitCandidate(t, engine, parseEngineConfig(t, "8.8.8.0/24"))

	newEpoch, err := engine.Admit()
	if err != nil {
		t.Fatalf("admit newer request: %v", err)
	}
	if _, err := NewCandidate(newEpoch, "new-invalid.yaml", config.Config{}); err == nil {
		t.Fatal("invalid newer candidate unexpectedly compiled")
	}

	if _, err := engine.Apply(context.Background(), old); err == nil {
		t.Fatal("superseded candidate was applied")
	}
	if got := backend.selection(); got != "" {
		t.Fatalf("superseded candidate changed selection to %q", got)
	}
}

func TestEnginePostCommitRetirementFailureKeepsCandidateAndDegrades(t *testing.T) {
	backend := &recordingBackend{retireErr: errors.New("retirement unavailable")}
	engine, store := newTestEngine(t, backend, nil)
	defer engine.Close()

	candidate := admitCandidate(t, engine, parseEngineConfig(t, "9.9.9.0/24"))
	outcome, err := engine.Apply(context.Background(), candidate)
	if err == nil {
		t.Fatal("retirement failure was hidden")
	}
	if !outcome.Committed || !outcome.Degraded {
		t.Fatalf("post-commit retirement failure outcome = %#v, err=%v", outcome, err)
	}
	if outcome.Active == nil || outcome.Active.Target == nil {
		t.Fatalf("committed candidate was not retained: %#v", outcome.Active)
	}
	if got := backend.selection(); got != outcome.Active.Target.Generation {
		t.Fatalf("kernel selection %q differs from committed target %q", got, outcome.Active.Target.Generation)
	}
	if engine.Healthy() {
		t.Fatal("engine remained healthy after required retirement failed")
	}
	view, err := store.Read()
	if err != nil {
		t.Fatalf("read durable state: %v", err)
	}
	if view.Active == nil || view.Active.ID != outcome.Active.ID {
		t.Fatalf("durable active revision = %#v, want committed %s", view.Active, outcome.Active.ID)
	}

	if _, err := engine.Admit(); err == nil {
		t.Fatal("degraded engine admitted an ordinary mutation")
	}
	if got := backend.selection(); got != outcome.Active.Target.Generation {
		t.Fatalf("ordinary mutation changed degraded selection to %q", got)
	}
}

func TestEngineObservedActiveIDAfterCommitBarrierFailureRetiresForward(t *testing.T) {
	var once sync.Once
	checkpoint := func(name string) error {
		if name != "active:after-rename" {
			return nil
		}

		var err error
		once.Do(func() { err = errors.New("ambiguous active publication") })
		return err
	}
	backend := &recordingBackend{}
	engine, store := newTestEngine(t, backend, checkpoint)
	defer engine.Close()

	candidate := admitCandidate(t, engine, parseEngineConfig(t, "192.0.2.128/25"))
	outcome, err := engine.Apply(context.Background(), candidate)
	if err == nil {
		t.Fatal("ambiguous active publication was hidden")
	}
	if !outcome.Committed || outcome.Degraded || outcome.Active == nil {
		t.Fatalf("observed candidate was not committed forward: %#v, err=%v", outcome, err)
	}
	view, readErr := store.Read()
	if readErr != nil {
		t.Fatalf("read state after observed active publication: %v", readErr)
	}
	if view.Active == nil || view.Active.ID != outcome.Active.ID {
		t.Fatalf("active revision = %#v, want %s", view.Active, outcome.Active.ID)
	}
	if got := backend.selection(); got != outcome.Active.Target.Generation {
		t.Fatalf("selected target %q, want candidate generation %q", got, outcome.Active.Target.Generation)
	}
}

func TestEnginePersistentDirectoryBarrierFailureFencesMutation(t *testing.T) {
	armed := false
	checkpoint := func(name string) error {
		if name == "active:after-dir-sync" {
			armed = true
			return errors.New("directory durability unavailable")
		}
		if name == "stabilize:before-file-sync" && armed {
			return errors.New("directory durability remains unavailable")
		}
		return nil
	}
	backend := &recordingBackend{}
	engine, store := newTestEngine(t, backend, checkpoint)
	defer engine.Close()

	candidate := admitCandidate(t, engine, parseEngineConfig(t, "198.51.100.128/25"))
	outcome, err := engine.Apply(context.Background(), candidate)
	if err == nil {
		t.Fatal("persistent directory barrier failure was hidden")
	}
	if !outcome.Degraded || engine.Healthy() {
		t.Fatalf("uncertain publication did not fence health: %#v", outcome)
	}
	if _, err := engine.Admit(); err == nil {
		t.Fatal("fenced engine admitted ordinary mutation")
	}
	view, readErr := store.Read()
	if readErr != nil {
		t.Fatalf("read retained uncertainty evidence: %v", readErr)
	}
	if view.Journal == nil {
		t.Fatal("uncertain publication discarded recovery journal")
	}
	if view.Active == nil || view.Active.Target == nil {
		t.Fatalf("uncertain publication discarded observed active target: %#v", view.Active)
	}

	if got := backend.selection(); got != view.Active.Target.Generation {
		t.Fatalf("kernel selection %q differs from observed active generation %q", got, view.Active.Target.Generation)
	}
}

func TestEngineRebootsIntoObservedCandidateAfterUncertainCommit(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	armed := false
	checkpoint := func(name string) error {
		if name == "active:after-dir-sync" {
			armed = true
			return errors.New("directory durability unavailable")
		}
		if name == "stabilize:before-file-sync" && armed {
			return errors.New("directory durability remains unavailable")
		}
		return nil
	}
	store, err := state.Open(dir, checkpoint)
	if err != nil {
		t.Fatalf("open state: %v", err)
	}
	backend := &recordingBackend{}
	engine := NewEngine(store, backend, checkpoint)
	if _, err := engine.Recover(context.Background()); err != nil {
		t.Fatalf("recover empty state: %v", err)
	}
	candidate := admitCandidate(t, engine, parseEngineConfig(t, "203.0.113.128/25"))
	if _, err := engine.Apply(context.Background(), candidate); err == nil {
		t.Fatal("uncertain commit unexpectedly succeeded")
	}
	observed, err := store.Read()
	if err != nil || observed.Active == nil || observed.Journal == nil {
		t.Fatalf("uncertain state = %#v, err=%v", observed, err)
	}
	engine.Close()

	recoveredStore, err := state.Open(dir, nil)
	if err != nil {
		t.Fatalf("reopen persisted state: %v", err)
	}
	recoveredBackend := &recordingBackend{}
	recovered := NewEngine(recoveredStore, recoveredBackend, nil)
	defer recovered.Close()
	active, err := recovered.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover observed candidate after restart: %v", err)
	}
	if active == nil || active.ID != observed.Active.ID {
		t.Fatalf("recovered active = %#v, want %s", active, observed.Active.ID)
	}
	if got := recoveredBackend.selection(); got != observed.Active.Target.Generation {
		t.Fatalf("recovered target %q, want %q", got, observed.Active.Target.Generation)
	}
	final, err := recoveredStore.Read()
	if err != nil {
		t.Fatalf("read stabilized state: %v", err)
	}
	if final.Journal != nil {
		t.Fatalf("recovery left journal: %#v", final.Journal)
	}
}

func TestEngineBackendFailureRollsBackPreviousSelection(t *testing.T) {
	backend := &recordingBackend{}
	engine, store := newTestEngine(t, backend, nil)
	defer engine.Close()

	first := admitCandidate(t, engine, parseEngineConfig(t, "198.51.100.0/24"))
	firstOutcome, err := engine.Apply(context.Background(), first)
	if err != nil || !firstOutcome.Committed || firstOutcome.Active == nil {
		t.Fatalf("initial apply = %#v, err=%v", firstOutcome, err)
	}
	backend.applyErr = errors.New("switch failed")
	backend.applyFailures = 1

	second := admitCandidate(t, engine, parseEngineConfig(t, "203.0.113.0/24"))
	secondOutcome, err := engine.Apply(context.Background(), second)
	if err == nil {
		t.Fatal("backend switch failure was hidden")
	}
	if secondOutcome.Committed || secondOutcome.Degraded {
		t.Fatalf("rollback failure classification = %#v, err=%v", secondOutcome, err)
	}
	if got := backend.selection(); got != firstOutcome.Active.Target.Generation {
		t.Fatalf("rollback selected %q, want prior generation %q", got, firstOutcome.Active.Target.Generation)
	}
	view, err := store.Read()
	if err != nil {
		t.Fatalf("read active state after rollback: %v", err)
	}
	if view.Active == nil || view.Active.ID != firstOutcome.Active.ID {
		t.Fatalf("active revision after rollback = %#v, want %s", view.Active, firstOutcome.Active.ID)
	}
}

func TestEnginePersistentBackendFailureFencesAfterRollbackFailure(t *testing.T) {
	backend := &recordingBackend{}
	engine, store := newTestEngine(t, backend, nil)
	defer engine.Close()

	first := admitCandidate(t, engine, parseEngineConfig(t, "198.51.100.0/24"))
	firstOutcome, err := engine.Apply(context.Background(), first)
	if err != nil || !firstOutcome.Committed || firstOutcome.Active == nil {
		t.Fatalf("initial apply = %#v, err=%v", firstOutcome, err)
	}
	backend.applyErr = errors.New("persistent backend failure")
	backend.persistentApplyErr = true

	second := admitCandidate(t, engine, parseEngineConfig(t, "203.0.113.0/24"))
	outcome, err := engine.Apply(context.Background(), second)
	if err == nil {
		t.Fatal("persistent backend failure was hidden")
	}
	if outcome.Committed || !outcome.Degraded || engine.Healthy() {
		t.Fatalf("persistent backend failure did not fence engine: %#v", outcome)
	}
	if got := backend.selection(); got != firstOutcome.Active.Target.Generation {
		t.Fatalf("persistent failure changed selection to %q", got)
	}
	view, readErr := store.Read()
	if readErr != nil {
		t.Fatalf("read fenced state: %v", readErr)
	}
	if view.Active == nil || view.Active.ID != firstOutcome.Active.ID {
		t.Fatalf("active revision after persistent failure = %#v", view.Active)
	}
	if view.Journal == nil {
		t.Fatal("persistent rollback failure discarded journal evidence")
	}
	if _, err := engine.Admit(); err == nil {
		t.Fatal("fenced engine admitted ordinary mutation")
	}
}

func TestEngineLostApplyAckRestoresEmptySelection(t *testing.T) {
	backend := &recordingBackend{
		applyErr:            errors.New("lost apply acknowledgement"),
		applyFailures:       1,
		mutateBeforeFailure: true,
	}
	engine, store := newTestEngine(t, backend, nil)
	defer engine.Close()

	candidate := admitCandidate(t, engine, parseEngineConfig(t, "192.0.2.64/26"))
	outcome, err := engine.Apply(context.Background(), candidate)
	if err == nil {
		t.Fatal("lost backend acknowledgement was hidden")
	}
	if outcome.Committed || outcome.Degraded {
		t.Fatalf("lost acknowledgement did not restore first-install state: %#v", outcome)
	}
	if got := backend.selection(); got != "" {
		t.Fatalf("rollback left candidate selected after lost acknowledgement: %q", got)
	}
	view, readErr := store.Read()
	if readErr != nil {
		t.Fatalf("read state after lost acknowledgement rollback: %v", readErr)
	}
	if view.Active != nil || view.Journal != nil {
		t.Fatalf("rollback left durable first-install evidence: %#v", view)
	}
}

func TestEngineLostApplyAckRestoresActiveBeforeEmptyCandidate(t *testing.T) {
	backend := &recordingBackend{}
	engine, store := newTestEngine(t, backend, nil)
	defer engine.Close()

	first := admitCandidate(t, engine, parseEngineConfig(t, "198.51.100.0/24"))
	firstOutcome, err := engine.Apply(context.Background(), first)
	if err != nil || !firstOutcome.Committed || firstOutcome.Active == nil {
		t.Fatalf("initial apply = %#v, err=%v", firstOutcome, err)
	}

	backend.applyErr = errors.New("lost empty-switch acknowledgement")
	backend.applyFailures = 1
	backend.mutateBeforeFailure = true
	empty := admitCandidate(t, engine, parseEngineConfig(t, ""))
	outcome, err := engine.Apply(context.Background(), empty)
	if err == nil {
		t.Fatal("lost empty-switch acknowledgement was hidden")
	}
	if outcome.Committed || outcome.Degraded {
		t.Fatalf("active-to-empty rollback was not healthy: %#v", outcome)
	}
	if got := backend.selection(); got != firstOutcome.Active.Target.Generation {
		t.Fatalf("rollback left active target unselected: got %q, want %q", got, firstOutcome.Active.Target.Generation)
	}
	view, readErr := store.Read()
	if readErr != nil {
		t.Fatalf("read active-to-empty rollback state: %v", readErr)
	}
	if view.Active == nil || view.Active.ID != firstOutcome.Active.ID || view.Journal != nil {
		t.Fatalf("active-to-empty rollback durable state = %#v", view)
	}
}

func TestEngineCloseFencesLateCandidate(t *testing.T) {
	engine, _ := newTestEngine(t, &recordingBackend{}, nil)
	candidate := admitCandidate(t, engine, parseEngineConfig(t, "8.8.4.0/24"))
	engine.Close()
	if _, err := engine.Apply(context.Background(), candidate); err == nil {
		t.Fatal("late candidate applied after engine close")
	}
	if _, err := engine.Admit(); err == nil {
		t.Fatal("new work admitted after engine close")
	}
}

func TestEngineCheckpointAfterSwitchRestoresFirstInstall(t *testing.T) {
	var once sync.Once
	checkpoint := func(name string) error {
		if name != "after-switch" {
			return nil
		}
		var err error
		once.Do(func() { err = errors.New("simulated switch checkpoint crash") })
		return err
	}
	backend := &recordingBackend{}
	engine, store := newTestEngine(t, backend, checkpoint)
	defer engine.Close()

	candidate := admitCandidate(t, engine, parseEngineConfig(t, "8.8.8.8/32"))
	outcome, err := engine.Apply(context.Background(), candidate)
	if err == nil {
		t.Fatal("checkpoint failure was ignored")
	}
	if outcome.Committed {
		t.Fatalf("pre-commit checkpoint failure reported committed: %#v", outcome)
	}
	if got := backend.selection(); got != "" {
		t.Fatalf("first-install rollback retained selection %q", got)
	}
	view, readErr := store.Read()
	if readErr != nil {
		t.Fatalf("read state after rollback: %v", readErr)
	}
	if view.Active != nil {
		t.Fatalf("first install published active revision after rollback: %#v", view.Active)
	}
}

func TestEngineRecoveryUsesPersistedTargetWithoutCurrentYAML(t *testing.T) {
	backend := &recordingBackend{}
	engine, store := newTestEngine(t, backend, nil)
	candidate := admitCandidate(t, engine, parseEngineConfig(t, "203.0.113.0/24"))
	outcome, err := engine.Apply(context.Background(), candidate)
	if err != nil || !outcome.Committed || outcome.Active == nil {
		t.Fatalf("initial apply = %#v, err=%v", outcome, err)
	}
	engine.Close()

	recoveredBackend := &recordingBackend{}
	recovered := NewEngine(store, recoveredBackend, nil)
	defer recovered.Close()
	active, err := recovered.Recover(context.Background())
	if err != nil {
		t.Fatalf("recover persisted target with invalid current YAML path: %v", err)
	}
	if active == nil || active.ID != outcome.Active.ID {
		t.Fatalf("recovered active = %#v, want %s", active, outcome.Active.ID)
	}
	if got := recoveredBackend.selection(); got != outcome.Active.Target.Generation {
		t.Fatalf("recovery selected %q, want persisted generation %q", got, outcome.Active.Target.Generation)
	}
}

func TestEngineRejectsCanceledApplyBeforeMutation(t *testing.T) {
	backend := &recordingBackend{}
	engine, _ := newTestEngine(t, backend, nil)
	defer engine.Close()
	candidate := admitCandidate(t, engine, parseEngineConfig(t, "192.0.2.0/24"))
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.Apply(ctx, candidate); err == nil {
		t.Fatal("canceled apply unexpectedly mutated")
	}
	if got := backend.selection(); got != "" {
		t.Fatalf("canceled apply selected %q", got)
	}
}
