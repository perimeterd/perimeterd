package app

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/source"
	"github.com/perimeterd/perimeterd/internal/state"
)

// sourceRuntime belongs to the event loop. Only the timestamp is read by HTTP
// handlers; workers receive immutable configuration and manifest identities.
type sourceRuntime struct {
	cache         *source.Cache
	resolver      *source.Resolver
	active        *state.Revision
	timestamp     atomic.Int64
	timer         *time.Timer
	reloadCancel  context.CancelFunc
	refreshCancel context.CancelFunc
}

func newSourceRuntime(cache *source.Cache, client *http.Client) *sourceRuntime {
	return &sourceRuntime{cache: cache, resolver: source.NewResolver(cache, client)}
}

func (s *sourceRuntime) selectRevision(revision *state.Revision) error {
	var snapshot source.Snapshot
	if revision != nil && revision.Manifest != "" {
		var err error
		snapshot, err = s.cache.Load(revision.Manifest)
		if err != nil {
			return fmt.Errorf("load committed source snapshot: %w", err)
		}
	}
	if s.active == nil || revision == nil || s.active.Epoch != revision.Epoch {
		if s.refreshCancel != nil {
			s.refreshCancel()
			s.refreshCancel = nil
		}
	}
	s.active = revision
	stamp := int64(0)
	if oldest := snapshot.OldestRetrieved(); !oldest.IsZero() {
		stamp = oldest.Unix()
	}
	s.timestamp.Store(stamp)
	s.schedule()
	return nil
}

func (s *sourceRuntime) schedule() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
	if s.active == nil || s.active.Manifest == "" {
		return
	}
	geo := s.active.Config.Geo
	const maximum = time.Duration(1<<63 - 1)
	var jitter time.Duration
	if geo.RefreshJitter == maximum {
		jitter = time.Duration(rand.Int64()) // #nosec G404 -- non-security scheduling jitter.
	} else {
		jitter = rand.N(geo.RefreshJitter + 1) // #nosec G404 -- non-security scheduling jitter.
	}
	delay := geo.RefreshInterval
	if jitter > maximum-delay {
		delay = maximum
	} else {
		delay += jitter
	}
	s.timer = time.NewTimer(delay)
}

func (s *sourceRuntime) events() <-chan time.Time {
	if s.timer == nil {
		return nil
	}
	return s.timer.C
}

func (s *sourceRuntime) manifest() string {
	if s.active == nil {
		return ""
	}
	return s.active.Manifest
}

func (s *sourceRuntime) age() time.Duration {
	stamp := s.timestamp.Load()
	if stamp == 0 {
		return 0
	}
	return max(0, time.Since(time.Unix(stamp, 0)))
}

func (s *sourceRuntime) close() {
	if s.timer != nil {
		s.timer.Stop()
	}
	if s.reloadCancel != nil {
		s.reloadCancel()
	}
	if s.refreshCancel != nil {
		s.refreshCancel()
	}
}

// collectPrefixes runs only while the lifecycle owner has no staging workers:
// after startup recovery or explicit cleanup. Uncommitted work cannot race GC.
func collectPrefixes(store *state.Store) error {
	view, err := store.Read()
	if err != nil {
		return err
	}
	manifests := make([]string, 0, len(view.Revisions))
	for _, revision := range view.Revisions {
		if revision.Manifest != "" {
			manifests = append(manifests, revision.Manifest)
		}
	}
	return store.Prefixes().Collect(manifests)
}

func stageSource(ctx context.Context, opts Options, resolver *source.Resolver, epoch, refresh uint64, cfg config.Config, committed string) stageResult {
	result := stageResult{candidate: Candidate{epoch: epoch, refresh: refresh}, cfg: cfg}
	resolved, err := resolver.Resolve(ctx, cfg, committed, refresh == 0)
	if err != nil {
		result.err = fmt.Errorf("resolve source snapshot: %w", err)
		return result
	}
	candidate, err := NewCandidate(epoch, opts.ConfigPath, cfg, resolved.Snapshot)
	if err != nil {
		result.err = fmt.Errorf("compile configuration: %w", err)
		return result
	}
	candidate.refresh = refresh
	result.candidate = candidate
	result.refreshErr = resolved.RefreshError
	result.logger = newLogger(cfg, opts.Stderr)
	result.err = ctx.Err()
	return result
}
