package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/lookup"
	"github.com/perimeterd/perimeterd/internal/source"
	"github.com/perimeterd/perimeterd/internal/state"
)

// lookupView owns immutable snapshots of the acknowledged dynamic write and
// may be evaluated without taking the engine writer fence.
type lookupView struct {
	static      *lookup.Static
	dynamic     lookup.Dynamic
	revision    string
	configEpoch uint64
	manifest    string
	token       uint64
}

// Lookup normalizes and evaluates one read-only query against the last
// completely acknowledged applied view. It never takes mu/applyMu and does no
// source, durable-store, credential, native, or reconciliation work.
func (e *Engine) Lookup(ctx context.Context, request lookup.Request) lookup.Response {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized, err := lookup.Normalize(request)
	if err != nil {
		return lookup.Unknown(request, "invalid_request", err.Error())
	}
	if err := ctx.Err(); err != nil {
		return lookup.Unknown(normalized, "deadline", err.Error())
	}
	if e.closing.Load() {
		return lookup.Unknown(normalized, "unavailable", "perimeterd is shutting down")
	}
	view := e.queryView.Load()
	version := e.queryVersion.Load()
	if view == nil || view.token != version {
		return lookup.Unknown(normalized, "unavailable", "no coherent applied view is available")
	}
	response := lookup.Evaluate(ctx, view.static, view.dynamic, normalized, time.Now())
	if err := ctx.Err(); err != nil {
		return lookup.Unknown(normalized, "deadline", err.Error())
	}
	if e.queryVersion.Load() != version || e.queryView.Load() != view {
		return lookup.Unknown(normalized, "stale_view", "applied state changed during evaluation")
	}
	response.Query = normalized
	response.Revision = view.revision
	response.ConfigEpoch = view.configEpoch
	response.Manifest = view.manifest
	response.DynamicEpoch = view.dynamic.Epoch
	response.DynamicOperation = view.dynamic.Operation
	return response
}

func (e *Engine) invalidateLookupLocked() {
	if current := e.queryView.Load(); current != nil {
		e.queryFallback = current
	}
	e.queryVersion.Add(1)
	e.queryView.Store(nil)
}

func (e *Engine) abortLookupLocked() {
	e.queryVersion.Add(1)
	e.queryView.Store(nil)
	e.queryFallback = nil
}

func (e *Engine) restoreLookupLocked() {
	fallback := e.queryFallback
	if fallback == nil {
		return
	}
	e.publishLookupLocked(fallback.static, fallback.dynamic, fallback.revision, fallback.manifest, fallback.configEpoch)
}

func (e *Engine) publishLookupLocked(static *lookup.Static, dynamic lookup.Dynamic, revision, manifest string, configEpoch uint64) {
	token := e.queryVersion.Add(1)
	view := &lookupView{
		static:      static,
		dynamic:     dynamic,
		revision:    revision,
		configEpoch: configEpoch,
		manifest:    manifest,
		token:       token,
	}
	e.queryBase = view
	e.queryView.Store(view)
	e.queryFallback = nil
}

func dynamicFromCrowdState(s *crowdState) lookup.Dynamic {
	if s == nil {
		return lookup.Dynamic{}
	}
	return lookup.Dynamic{
		Epoch:      s.epoch,
		Operation:  s.leaseOperation,
		Prefixes:   s.leasePrefixes,
		Decisions:  s.leaseDecisions,
		ValidUntil: s.leaseValidUntil,
	}
}

func (e *Engine) publishDynamicLookupLocked(s *crowdState, revision, manifest string) {
	current := e.queryView.Load()
	if current == nil {
		current = e.queryFallback
	}
	if current == nil {
		current = e.queryBase
	}
	if current == nil || s == nil {
		return
	}
	if current.revision != revision || current.manifest != manifest {
		return
	}
	e.publishLookupLocked(current.static, dynamicFromCrowdState(s), current.revision, current.manifest, current.configEpoch)
}

func (e *Engine) publishCandidateLookupLocked(candidate Candidate, revision *state.Revision) error {
	if revision == nil {
		return e.publishEmptyLookupLocked()
	}
	static := e.stagedQuery
	if static == nil {
		var err error
		static, err = lookup.NewStatic(candidate.cfg, revision.Target, candidate.snapshot)
		if err != nil {
			return fmt.Errorf("build candidate lookup state: %w", err)
		}
	}
	var dynamic lookup.Dynamic
	if candidate.cfg.CrowdSec.Enabled {
		if e.crowd.active == nil {
			return errors.New("CrowdSec applied view has no acknowledged client epoch")
		}
		dynamic = dynamicFromCrowdState(e.crowd.active)
	}
	e.publishLookupLocked(static, dynamic, revision.ID, revision.Manifest, revision.Epoch)
	return nil
}

func (e *Engine) publishRecoveredLookupLocked(revision *state.Revision) error {
	if revision == nil {
		return e.publishEmptyLookupLocked()
	}
	if revision.Config.CrowdSec.Enabled && e.crowd.active == nil {
		// A process restart must synchronize and successfully apply CrowdSec
		// before its old static revision becomes query authority.
		return nil
	}
	var snapshot source.Snapshot
	if revision.Manifest != "" {
		var err error
		snapshot, err = e.store.Prefixes().Load(revision.Manifest)
		if err != nil {
			return fmt.Errorf("load committed lookup manifest: %w", err)
		}
	}
	static, err := lookup.NewStatic(revision.Config, revision.Target, snapshot)
	if err != nil {
		return fmt.Errorf("build recovered lookup state: %w", err)
	}
	e.publishLookupLocked(static, dynamicFromCrowdState(e.crowd.active), revision.ID, revision.Manifest, revision.Epoch)
	return nil
}

func (e *Engine) publishEmptyLookupLocked() error {
	static, err := lookup.NewStatic(config.Config{}, nil, source.Snapshot{})
	if err != nil {
		return fmt.Errorf("build empty lookup state: %w", err)
	}
	e.publishLookupLocked(static, lookup.Dynamic{}, "", "", 0)
	return nil
}
