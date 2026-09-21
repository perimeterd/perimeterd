package app

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/lookup"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/state"
)

var (
	errEngineClosed   = errors.New("perimeterd engine is closed")
	errEngineDegraded = errors.New("perimeterd enforcement is degraded; recovery is required")
	errStaleCandidate = errors.New("candidate was superseded by a newer admission")
)

// Outcome reports the durable identity selected by an apply attempt. Committed
// remains true when post-commit retirement fails: the new active revision is
// authoritative even while enforcement is degraded.
type Outcome struct {
	Transaction string
	Committed   bool
	Degraded    bool
	Active      *state.Revision
}

// Engine serializes admission, durable state transitions, and backend calls.
// The lifecycle owner must hold the state lock for the whole engine lifetime.
type Engine struct {
	mu         sync.Mutex
	applyMu    sync.Mutex
	crowd      *crowdRuntime
	store      *state.Store
	backend    firewall.Backend
	checkpoint func(string) error

	admitted        uint64
	activeEpoch     uint64
	refreshSequence uint64
	closing         atomic.Bool
	healthy         atomic.Bool

	// queryView is published only after a complete native/durable transition.
	// Queries load it without taking mu or applyMu and evaluate its immutable
	// contents outside the writer. queryVersion fences a view even when safe
	// compensation restores the same pointer.
	queryView     atomic.Pointer[lookupView]
	queryVersion  atomic.Uint64
	queryFallback *lookupView
	queryBase     *lookupView
	stagedQuery   *lookup.Static
}

// NewEngine constructs a fenced engine. Recovery must be called before normal
// admissions; health is therefore initially false.
func NewEngine(store *state.Store, backend firewall.Backend, checkpoint func(string) error) *Engine {
	engine := &Engine{store: store, backend: backend, checkpoint: checkpoint}
	engine.crowd = newCrowdRuntime(engine)
	if backend == nil {
		engine.backend = firewall.NewNative(func(family policy.Family, generation string) error {
			if err := store.RecordFamilySelection(family, generation); err != nil {
				return err
			}
			token := "v4"
			if family == policy.IPv6 {
				token = "v6"
			}
			return engine.check("iptables-after-switch-" + token)
		})
	}
	return engine
}

func (e *Engine) applyBackendLocked(ctx context.Context, previous, candidate *firewall.Target, dynamic *firewall.DynamicState) error {
	if (previous != nil && previous.DynamicGeneration != "") || (candidate != nil && candidate.DynamicGeneration != "") {
		if _, err := e.crowd.nextOperationLocked(); err != nil {
			return err
		}
	}
	return e.backend.Apply(ctx, previous, candidate, dynamic)
}

// Admit reserves a monotonically increasing request epoch. Admission itself is
// serialized with commit, so a newer request fences older work even when the
// newer request later fails validation or compilation.
func (e *Engine) Admit() (uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.closing.Load() {
		return 0, errEngineClosed
	}
	if e.degraded() {
		return 0, errEngineDegraded
	}
	if e.admitted == ^uint64(0) {
		return 0, errors.New("candidate admission epoch exhausted")
	}
	e.admitted++
	return e.admitted, nil
}

// AdmitRefresh reserves a sequence for the active configuration independently
// of reload admission. A rejected reload cannot fence its active refreshes.
func (e *Engine) AdmitRefresh(epoch uint64) (uint64, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := e.startErrorLocked(context.Background()); err != nil {
		return 0, err
	}
	if epoch == 0 || epoch != e.activeEpoch {
		return 0, errStaleCandidate
	}
	if e.refreshSequence == ^uint64(0) {
		return 0, errors.New("refresh sequence exhausted")
	}
	e.refreshSequence++
	return e.refreshSequence, nil
}

// current checks result freshness before exposing failures or binding resources.
// Apply repeats the check while holding the mutation fence.
func (e *Engine) current(candidate Candidate) bool {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.currentLocked(candidate)
}

func (e *Engine) currentLocked(candidate Candidate) bool {
	if candidate.epoch == 0 {
		return false
	}
	if candidate.refresh != 0 {
		return candidate.epoch == e.activeEpoch && candidate.refresh == e.refreshSequence
	}
	return candidate.epoch == e.admitted
}

// Apply admits a fully staged candidate to the backend and durable store. All
// mutations occur only after a read-only preflight and durable preparation.
func (e *Engine) Apply(ctx context.Context, candidate Candidate) (Outcome, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	selected, stageErr := e.crowd.stageForApply(ctx, candidate)
	e.mu.Lock()
	defer func() {
		e.stagedQuery = nil
		e.mu.Unlock()
	}()
	e.crowd.grantAt = time.Time{}
	e.crowd.grantDone = time.Time{}
	if stageErr != nil {
		outcome := Outcome{Degraded: e.degraded()}
		e.crowd.finishApplyLocked(outcome, selected)
		if outcome.Degraded {
			e.abortLookupLocked()
		} else {
			e.restoreLookupLocked()
		}
		return outcome, stageErr
	}
	if candidate.refresh != 0 {
		// A reconnect may have replaced the source epoch between staging and
		// acquisition of the writer fence. Refresh always uses live authority.
		selected = e.crowd.active
	}
	outcome, err := e.applyLocked(ctx, candidate, selected)
	e.crowd.finishApplyLocked(outcome, selected)
	if outcome.Committed && outcome.Active != nil {
		e.adoptActiveEpochLocked(outcome.Active)
		if outcome.Degraded {
			e.abortLookupLocked()
		} else if publishErr := e.publishCandidateLookupLocked(candidate, outcome.Active); publishErr != nil {
			e.abortLookupLocked()
			e.healthy.Store(false)
			outcome.Degraded = true
			err = errors.Join(err, publishErr)
		}
	} else if outcome.Degraded {
		e.abortLookupLocked()
	} else {
		e.restoreLookupLocked()
	}
	return outcome, err
}

func (e *Engine) applyLocked(ctx context.Context, candidate Candidate, selected *crowdState) (Outcome, error) {
	if err := e.startErrorLocked(ctx); err != nil {
		return Outcome{Degraded: e.degraded()}, err
	}
	if !e.currentLocked(candidate) {
		return Outcome{}, errStaleCandidate
	}
	if e.store == nil || e.backend == nil {
		return Outcome{}, errors.New("engine requires a state store and firewall backend")
	}

	view, err := e.store.Read()
	if err != nil {
		return e.failLocked(err)
	}
	if view.Journal != nil {
		return e.failLocked(errors.New("pending durable transaction requires recovery"))
	}
	previous := view.Active
	transaction, err := transactionID()
	if err != nil {
		return Outcome{}, err
	}
	var previousTarget *firewall.Target
	if previous != nil {
		previousTarget = previous.Target
	}
	candidateTarget, err := firewall.BuildTarget(e.store.Owner(), transaction, candidate.cfg, candidate.model, previousTarget)
	if err != nil {
		return Outcome{Active: previous, Degraded: e.degraded()}, err
	}
	static, err := lookup.NewStatic(candidate.cfg, candidateTarget, candidate.snapshot)
	if err != nil {
		return Outcome{Active: previous, Degraded: e.degraded()}, fmt.Errorf("build lookup state: %w", err)
	}
	e.stagedQuery = static
	var admission, activation *firewall.DynamicState
	if candidate.cfg.CrowdSec.Enabled {
		if selected == nil || selected.store == nil {
			return Outcome{Active: previous}, errors.New("CrowdSec activation was not synchronized")
		}
		if selected != e.crowd.active {
			candidateTarget.DynamicGeneration = transaction
			candidateTarget.Generation = transaction
		}
		admission = &firewall.DynamicState{Prefixes: selected.store.Projection(time.Now())}
		if previousTarget == nil || candidateTarget.DynamicGeneration != previousTarget.DynamicGeneration {
			activation = admission
		}
	}
	// Capacity admission includes retained authority; activation replaces it only
	// for a new container. Static refresh must not renew a shared generation.
	if err := firewall.ValidateTarget(candidateTarget); err != nil {
		return Outcome{Active: previous, Degraded: e.degraded()}, err
	}
	if err := e.backend.Preflight(ctx, previousTarget, candidateTarget, admission); err != nil {
		return Outcome{Active: previous, Degraded: e.degraded()}, err
	}
	candidateRevision := &state.Revision{
		Version:         1,
		ID:              transaction,
		Epoch:           candidate.epoch,
		ConfigPath:      candidate.path,
		Config:          cloneConfig(candidate.cfg),
		Target:          candidateTarget,
		Manifest:        candidate.snapshot.ManifestID(),
		RefreshSequence: candidate.refresh,
	}
	e.crowd.transaction = transaction
	e.crowd.staged = selected
	if err := e.store.Prepare(previous, candidateRevision); err != nil {
		return e.failLocked(err)
	}
	if err := e.check("after-prepare"); err != nil {
		return e.rollbackLocked(ctx, previous, candidateRevision, candidateTarget, previousTarget, err)
	}
	if activation != nil {
		e.crowd.grantAt = time.Now()
	}
	e.invalidateLookupLocked()
	if err := e.applyBackendLocked(ctx, previousTarget, candidateTarget, activation); err != nil {
		return e.rollbackLocked(ctx, previous, candidateRevision, candidateTarget, previousTarget, err)
	}
	if activation != nil {
		e.crowd.grantDone = time.Now()
	}
	if err := e.check("after-switch"); err != nil {
		return e.rollbackLocked(ctx, previous, candidateRevision, candidateTarget, previousTarget, err)
	}

	if err := e.store.MarkPhase("switched"); err != nil {
		return e.rollbackLocked(ctx, previous, candidateRevision, candidateTarget, previousTarget, err)
	}
	if err := e.store.Commit(candidateRevision); err != nil {
		return e.resolveCommitErrorLocked(ctx, previous, candidateRevision, candidateTarget, previousTarget, err)
	}
	if err := e.check("after-commit"); err != nil {
		return e.resolveCommittedLocked(ctx, previous, candidateRevision, candidateTarget, previousTarget, err)
	}
	if err := e.store.MarkPhase("committed"); err != nil {
		return e.resolveCommittedLocked(ctx, previous, candidateRevision, candidateTarget, previousTarget, err)
	}
	if err := e.check("before-retire"); err != nil {
		return e.resolveCommittedLocked(ctx, previous, candidateRevision, candidateTarget, previousTarget, err)
	}
	if err := e.backend.Retire(ctx, previousTarget, candidateTarget); err != nil {
		return e.committedFailureLocked(candidateRevision, err)
	}
	if err := e.store.Finish(); err != nil {
		return e.committedFailureLocked(candidateRevision, err)
	}
	active, err := e.readActiveLocked()
	if err != nil {
		return e.committedFailureLocked(candidateRevision, err)
	}
	e.healthy.Store(true)
	return Outcome{Transaction: transaction, Committed: true, Active: active}, nil
}

func (e *Engine) rollbackLocked(ctx context.Context, previous, candidate *state.Revision, candidateTarget, previousTarget *firewall.Target, original error) (Outcome, error) {
	if ctx.Err() != nil {
		e.healthy.Store(false)
		return Outcome{Transaction: candidate.ID, Active: previous, Degraded: true}, original
	}
	if err := e.applyBackendLocked(ctx, candidateTarget, previousTarget, nil); err != nil {
		e.healthy.Store(false)
		return Outcome{Transaction: candidate.ID, Active: previous, Degraded: true}, errors.Join(original, fmt.Errorf("restore previous firewall target: %w", err))
	}
	if err := e.backend.Retire(ctx, candidateTarget, previousTarget); err != nil {
		e.healthy.Store(false)
		return Outcome{Transaction: candidate.ID, Active: previous, Degraded: true}, errors.Join(original, fmt.Errorf("retire failed candidate: %w", err))
	}
	if err := e.store.Stabilize(); err != nil {
		e.healthy.Store(false)
		return Outcome{Transaction: candidate.ID, Active: previous, Degraded: true}, errors.Join(original, fmt.Errorf("stabilize restored transaction: %w", err))
	}
	if err := e.store.Finish(); err != nil {
		e.healthy.Store(false)
		return Outcome{Transaction: candidate.ID, Active: previous, Degraded: true}, errors.Join(original, fmt.Errorf("finish failed transaction: %w", err))
	}
	e.healthy.Store(true)
	return Outcome{Transaction: candidate.ID, Active: previous}, original
}

func (e *Engine) resolveCommitErrorLocked(ctx context.Context, previous, candidate *state.Revision, candidateTarget, previousTarget *firewall.Target, original error) (Outcome, error) {
	if err := e.store.Stabilize(); err != nil {
		e.healthy.Store(false)
		return Outcome{Transaction: candidate.ID, Active: previous, Degraded: true}, errors.Join(original, fmt.Errorf("stabilize uncertain commit: %w", err))
	}
	active, err := e.readActiveLocked()
	if err != nil {
		e.healthy.Store(false)
		return Outcome{Transaction: candidate.ID, Degraded: true}, errors.Join(original, err)
	}
	if active != nil && active.ID == candidate.ID {
		return e.resolveCommittedLocked(ctx, previous, candidate, candidateTarget, previousTarget, original)
	}
	return e.rollbackLocked(ctx, previous, candidate, candidateTarget, previousTarget, original)
}

func (e *Engine) resolveCommittedLocked(ctx context.Context, previous, candidate *state.Revision, candidateTarget, previousTarget *firewall.Target, cause error) (Outcome, error) {
	if err := e.store.Stabilize(); err != nil {
		e.healthy.Store(false)
		return Outcome{Transaction: candidate.ID, Committed: true, Active: candidate, Degraded: true}, errors.Join(cause, fmt.Errorf("stabilize committed revision: %w", err))
	}
	if err := e.store.MarkPhase("committed"); err != nil {
		e.healthy.Store(false)
		return Outcome{Transaction: candidate.ID, Committed: true, Active: candidate, Degraded: true}, errors.Join(cause, err)
	}
	if err := e.backend.Retire(ctx, previousTarget, candidateTarget); err != nil {
		return e.committedFailureLocked(candidate, errors.Join(cause, err))
	}
	if err := e.store.Finish(); err != nil {
		return e.committedFailureLocked(candidate, errors.Join(cause, err))
	}
	e.healthy.Store(true)
	active, err := e.readActiveLocked()
	if err != nil {
		return e.committedFailureLocked(candidate, errors.Join(cause, err))
	}
	return Outcome{Transaction: candidate.ID, Committed: true, Active: active}, cause
}

func (e *Engine) committedFailureLocked(candidate *state.Revision, err error) (Outcome, error) {
	e.healthy.Store(false)
	active := candidate
	if view, readErr := e.store.Read(); readErr == nil && view.Active != nil {
		active = view.Active
	}
	return Outcome{Transaction: candidate.ID, Committed: true, Active: active, Degraded: true}, err
}

func (e *Engine) failLocked(err error) (Outcome, error) {
	e.abortLookupLocked()
	e.healthy.Store(false)
	return Outcome{Degraded: true}, err
}

// Recover resolves persisted transactions before configuration is read. It
// uses only the observed active record, journal, and complete target metadata.
func (e *Engine) Recover(ctx context.Context) (*state.Revision, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	revision, err := e.recoverLocked(ctx)
	if err == nil {
		err = e.crowd.recoverLocked(ctx, revision)
	}
	if err == nil {
		err = e.publishRecoveredLookupLocked(revision)
	}
	if err != nil {
		e.abortLookupLocked()
		e.healthy.Store(false)
	}
	return revision, err
}

func (e *Engine) recoverLocked(ctx context.Context) (*state.Revision, error) {
	e.invalidateLookupLocked()
	if e.closing.Load() {
		return nil, errEngineClosed
	}
	if e.store == nil || e.backend == nil {
		return nil, errors.New("engine requires a state store and firewall backend")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	view, err := e.store.Read()
	if err != nil {
		return nil, e.recoveryFailureLocked(err)
	}
	if err := e.store.Stabilize(); err != nil {
		return nil, e.recoveryFailureLocked(err)
	}
	view, err = e.store.Read()
	if err != nil {
		return nil, e.recoveryFailureLocked(err)
	}
	if view.Journal == nil {
		if view.Active == nil {
			e.healthy.Store(true)
			e.adoptActiveEpochLocked(nil)
			return nil, nil
		}
		if err := e.store.Prepare(view.Active, view.Active); err != nil {
			return nil, e.recoveryFailureLocked(err)
		}
		if err := e.applyBackendLocked(ctx, targetOf(view.Active), targetOf(view.Active), nil); err != nil {
			return nil, e.recoveryFailureLocked(err)
		}
		if err := e.store.MarkPhase("switched"); err != nil {
			return nil, e.recoveryFailureLocked(err)
		}
		if err := e.store.Commit(view.Active); err != nil {
			return nil, e.recoveryFailureLocked(err)
		}
		if err := e.store.MarkPhase("committed"); err != nil {
			return nil, e.recoveryFailureLocked(err)
		}
		if err := e.backend.Retire(ctx, targetOf(view.Active), targetOf(view.Active)); err != nil {
			return nil, e.recoveryFailureLocked(err)
		}
		if err := e.store.Finish(); err != nil {
			return nil, e.recoveryFailureLocked(err)
		}
		e.healthy.Store(true)
		e.adoptActiveEpochLocked(view.Active)
		return view.Active, nil
	}
	journal := view.Journal
	if journal.Operation == "cleanup" {
		if err := e.cleanupViewLocked(ctx, view); err != nil {
			return nil, e.recoveryFailureLocked(err)
		}
		e.healthy.Store(true)
		e.adoptActiveEpochLocked(nil)
		return nil, nil
	}
	if journal.Operation != "apply" {
		return nil, e.recoveryFailureLocked(fmt.Errorf("unsupported journal operation %q", journal.Operation))
	}
	if journal.ID != journal.Candidate {
		return nil, e.recoveryFailureLocked(errors.New("apply journal identity does not match candidate revision"))
	}
	previous, err := revisionRef(view, journal.Previous)
	if err != nil {
		return nil, e.recoveryFailureLocked(err)
	}
	candidate, err := revisionRef(view, journal.Candidate)
	if err != nil {
		return nil, e.recoveryFailureLocked(err)
	}
	if candidate == nil {
		return nil, e.recoveryFailureLocked(errors.New("apply journal has no candidate revision"))
	}
	prevTarget, candidateTarget := targetOf(previous), targetOf(candidate)
	if view.Active != nil && view.Active.ID == journal.ID {
		if err := e.applyBackendLocked(ctx, prevTarget, candidateTarget, nil); err != nil {
			return nil, e.recoveryFailureLocked(err)
		}
		if err := e.store.Commit(candidate); err != nil {
			return nil, e.recoveryFailureLocked(err)
		}
		if err := e.store.MarkPhase("committed"); err != nil {
			return nil, e.recoveryFailureLocked(err)
		}
		if err := e.backend.Retire(ctx, prevTarget, candidateTarget); err != nil {
			return nil, e.recoveryFailureLocked(err)
		}
		if err := e.store.Finish(); err != nil {
			return nil, e.recoveryFailureLocked(err)
		}
		e.healthy.Store(true)
		e.adoptActiveEpochLocked(candidate)
		return candidate, nil
	}
	if err := e.applyBackendLocked(ctx, candidateTarget, prevTarget, nil); err != nil {
		return nil, e.recoveryFailureLocked(err)
	}
	if err := e.backend.Retire(ctx, candidateTarget, prevTarget); err != nil {
		return nil, e.recoveryFailureLocked(err)
	}
	if err := e.store.Finish(); err != nil {
		return nil, e.recoveryFailureLocked(err)
	}
	e.healthy.Store(true)
	e.adoptActiveEpochLocked(previous)
	return previous, nil
}

func (e *Engine) cleanupViewLocked(ctx context.Context, view state.View) error {
	targets := targetsForView(view)
	if err := e.backend.Cleanup(ctx, targets); err != nil {
		return err
	}
	if err := e.store.RemoveActive(); err != nil {
		return err
	}
	return e.store.Finish()
}

// Cleanup removes only targets referenced by durable metadata. It first writes
// a cleanup intent so interruption cannot turn an incomplete removal into an
// apparently clean state.
func (e *Engine) Cleanup(ctx context.Context) error {
	if ctx == nil {
		ctx = context.Background()
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return err
	}
	if e.closing.Load() {
		return errEngineClosed
	}
	if e.store == nil || e.backend == nil {
		return errors.New("engine requires a state store and firewall backend")
	}
	view, err := e.store.Read()
	if err != nil {
		return e.recoveryFailureLocked(err)
	}
	if view.Journal == nil && view.Active == nil {
		e.abortLookupLocked()
		e.crowd.activateLocked(nil)
		e.healthy.Store(true)
		if err := e.publishEmptyLookupLocked(); err != nil {
			e.abortLookupLocked()
			e.healthy.Store(false)
			return err
		}
		return nil
	}
	e.invalidateLookupLocked()
	id, err := transactionID()
	if err != nil {
		e.abortLookupLocked()
		return err
	}
	if err := e.store.BeginCleanup(view, id); err != nil {
		return e.recoveryFailureLocked(err)
	}
	view, err = e.store.Read()
	if err != nil {
		return e.recoveryFailureLocked(err)
	}
	if err := e.cleanupViewLocked(ctx, view); err != nil {
		return e.recoveryFailureLocked(err)
	}
	e.crowd.activateLocked(nil)
	e.healthy.Store(true)
	if err := e.publishEmptyLookupLocked(); err != nil {
		e.abortLookupLocked()
		e.healthy.Store(false)
		return err
	}
	return nil
}

// Healthy reports the current enforcement health without waiting for the
// serialized writer.
func (e *Engine) Healthy() bool {
	return e.healthy.Load() && e.crowd.enforced.Load()
}

// Close fences all future admissions and waits for any in-flight writer call
// before the lifecycle lock can be released by the service.
func (e *Engine) Close() {
	e.closing.Store(true)
	e.crowd.cancel()
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	e.mu.Lock()
	e.abortLookupLocked()
	e.crowd.closeLocked()
	e.healthy.Store(false)
	e.mu.Unlock()
	e.crowd.workers.Wait()
}

func (e *Engine) startErrorLocked(ctx context.Context) error {
	if e.closing.Load() {
		return errEngineClosed
	}
	if e.degraded() {
		return errEngineDegraded
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	return nil
}

func (e *Engine) degraded() bool {
	return !e.Healthy()
}

func (e *Engine) recoveryFailureLocked(err error) error {
	e.abortLookupLocked()
	e.healthy.Store(false)
	return err
}

func (e *Engine) check(phase string) error {
	if e.checkpoint == nil {
		return nil
	}
	return e.checkpoint(phase)
}

func (e *Engine) readActiveLocked() (*state.Revision, error) {
	view, err := e.store.Read()
	if err != nil {
		return nil, err
	}
	return view.Active, nil
}

func targetOf(revision *state.Revision) *firewall.Target {
	if revision == nil {
		return nil
	}
	return revision.Target
}

func (e *Engine) adoptActiveEpochLocked(revision *state.Revision) {
	if revision == nil {
		e.activeEpoch = 0
		e.refreshSequence = 0
		return
	}
	if revision.Epoch != e.activeEpoch {
		e.refreshSequence = revision.RefreshSequence
	} else if revision.RefreshSequence > e.refreshSequence {
		e.refreshSequence = revision.RefreshSequence
	}
	e.activeEpoch = revision.Epoch
	if revision.Epoch > e.admitted {
		e.admitted = revision.Epoch
	}
}

func revisionRef(view state.View, id string) (*state.Revision, error) {
	if id == "" {
		return nil, nil
	}
	revision, ok := view.Revisions[id]
	if !ok || revision == nil {
		return nil, fmt.Errorf("journal references missing revision %q", id)
	}
	return revision, nil
}

func targetsForView(view state.View) []*firewall.Target {
	ids := make(map[string]struct{}, len(view.Revisions)+1)
	if view.Active != nil {
		ids[view.Active.ID] = struct{}{}
	}
	if view.Journal != nil {
		if view.Journal.Previous != "" {
			ids[view.Journal.Previous] = struct{}{}
		}
		if view.Journal.Candidate != "" {
			ids[view.Journal.Candidate] = struct{}{}
		}
		for _, id := range view.Journal.Revisions {
			if id != "" {
				ids[id] = struct{}{}
			}
		}
	}
	ordered := make([]string, 0, len(ids))
	for id := range ids {
		ordered = append(ordered, id)
	}
	sort.Strings(ordered)
	result := make([]*firewall.Target, 0, len(ordered))
	for _, id := range ordered {
		revision := view.Revisions[id]
		if revision != nil && revision.Target != nil {
			result = append(result, revision.Target)
		}
	}
	return result
}

func transactionID() (string, error) {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		return "", fmt.Errorf("generate transaction identity: %w", err)
	}
	return hex.EncodeToString(bytes[:]), nil
}
