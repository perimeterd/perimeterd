package app

import (
	"context"
	"fmt"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
	"github.com/perimeterd/perimeterd/internal/state"
	"github.com/perimeterd/perimeterd/internal/upstream"
)

// sourceRuntime belongs to the event loop. Only timestamps are read by HTTP
// handlers; workers receive immutable configuration and manifest identities.
type sourceRuntime struct {
	cache           *source.Cache
	resolver        *source.Resolver
	active          *state.Revision
	session         *upstream.Session
	timestamps      atomic.Pointer[sourceTimestamps]
	deadlines       map[policy.Selector]sourceDeadline
	timer           *time.Timer
	reloadCancel    context.CancelFunc
	reloadEpoch     uint64
	refreshCancel   context.CancelFunc
	refreshSequence uint64
}

type sourceTimestamps struct {
	ripe     int64
	ipList   int64
	provider int64
}

type sourceDeadline struct {
	endpoint  string
	transport upstream.Binding
	retrieved time.Time
	interval  time.Duration
	jitter    time.Duration
	due       time.Time
	retry     time.Time
}

func newSourceRuntime(cache *source.Cache, client *http.Client) *sourceRuntime {
	return &sourceRuntime{cache: cache, resolver: source.NewResolver(cache, client)}
}

func (s *sourceRuntime) selectRevision(revision *state.Revision, nextSession *upstream.Session) error {
	var snapshot source.Snapshot
	if revision != nil && revision.Manifest != "" {
		var err error
		snapshot, err = s.cache.Load(revision.Manifest)
		if err != nil {
			return fmt.Errorf("load committed source snapshot: %w", err)
		}
	}
	oldSession := s.session
	if nextSession == nil && s.active != nil && revision != nil &&
		(s.active == revision || (s.active.ID != "" && s.active.ID == revision.ID)) {
		// Recovery of the same committed revision keeps its captured route
		// generation. A nil selection means "preserve" at this boundary, not
		// "drop" the session that is still owned by the active source.
		nextSession = oldSession
	}
	deadlines := make(map[policy.Selector]sourceDeadline)
	timestamps := &sourceTimestamps{}
	if revision != nil {
		for _, record := range snapshot.Records() {
			spec, err := source.DescribeSelector(revision.Config, record.Selector)
			if err != nil {
				return fmt.Errorf("describe committed source: %w", err)
			}
			interval, jitter := spec.RefreshInterval, spec.RefreshJitter
			stamp := &timestamps.ripe
			switch record.Selector.Kind {
			case policy.IPList:
				stamp = &timestamps.ipList
			case policy.Provider:
				stamp = &timestamps.provider
			}
			if unix := record.RetrievedAt.Unix(); *stamp == 0 || unix < *stamp {
				*stamp = unix
			}
			deadline, exists := s.deadlines[record.Selector]
			if !exists || deadline.endpoint != record.Endpoint || deadline.transport != record.Transport || !deadline.retrieved.Equal(record.RetrievedAt) || deadline.interval != interval || deadline.jitter != jitter {
				deadline = sourceDeadline{
					endpoint: record.Endpoint, transport: record.Transport, retrieved: record.RetrievedAt,
					interval: interval, jitter: jitter,
					due: record.RetrievedAt.Add(refreshDelay(interval, jitter)),
				}
			}
			deadlines[record.Selector] = deadline
		}
	}
	if s.active == nil || revision == nil || s.active.Epoch != revision.Epoch {
		if s.refreshCancel != nil {
			s.refreshCancel()
			s.refreshCancel = nil
			s.refreshSequence = 0
		}
	}
	s.active = revision
	s.session = nextSession
	s.deadlines = deadlines
	s.timestamps.Store(timestamps)
	s.schedule()
	if oldSession != nil && oldSession != nextSession {
		oldSession.Close()
	}
	return nil
}

func (s *sourceRuntime) retainSession() *upstream.Session {
	if s == nil || s.session == nil {
		return nil
	}
	return s.session.Retain()
}

func (s *sourceRuntime) schedule() {
	s.stopTimer()
	if next := s.nextRefresh(time.Now()); !next.IsZero() {
		s.timer = time.NewTimer(max(0, time.Until(next)))
	}
}

func (s *sourceRuntime) stopTimer() {
	if s.timer != nil {
		s.timer.Stop()
		s.timer = nil
	}
}

// A complete candidate cannot publish while any stale selector is in retry
// cooldown. Preserve other deadlines, but wait for that barrier rather than
// refetching a failed source early or combining partial success with stale data.
func (s *sourceRuntime) nextRefresh(now time.Time) time.Time {
	var next, barrier time.Time
	for _, deadline := range s.deadlines {
		if next.IsZero() || deadline.due.Before(next) {
			next = deadline.due
		}
		if !deadline.retrieved.Add(deadline.interval).After(now) && deadline.retry.After(barrier) {
			barrier = deadline.retry
		}
	}
	if !next.IsZero() && barrier.After(next) {
		return barrier
	}
	return next
}

// Retry only selectors chosen by the resolver, not fresh peers that happened
// to expire while its HTTP requests were in flight.
func (s *sourceRuntime) attempted(selectors []policy.Selector, now time.Time) {
	for _, selector := range selectors {
		if deadline, ok := s.deadlines[selector]; ok {
			deadline.retry = now.Add(refreshDelay(deadline.interval, deadline.jitter))
			s.deadlines[selector] = deadline
		}
	}
}

func refreshDelay(interval, maximumJitter time.Duration) time.Duration {
	const maximum = time.Duration(1<<63 - 1)
	var jitter time.Duration
	if maximumJitter == maximum {
		jitter = time.Duration(rand.Int64()) // #nosec G404 -- non-security scheduling jitter.
	} else if maximumJitter > 0 {
		jitter = rand.N(maximumJitter + 1) // #nosec G404 -- non-security scheduling jitter.
	}
	delay := interval
	if jitter > maximum-delay {
		delay = maximum
	} else {
		delay += jitter
	}
	return delay
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
	timestamps := s.snapshotTimestamps()
	stamp := timestamps.ripe
	if stamp == 0 || (timestamps.ipList != 0 && timestamps.ipList < stamp) {
		stamp = timestamps.ipList
	}
	if stamp == 0 || (timestamps.provider != 0 && timestamps.provider < stamp) {
		stamp = timestamps.provider
	}
	if stamp == 0 {
		return 0
	}
	return max(0, time.Since(time.Unix(stamp, 0)))
}

func (s *sourceRuntime) snapshotTimestamps() sourceTimestamps {
	if timestamps := s.timestamps.Load(); timestamps != nil {
		return *timestamps
	}
	return sourceTimestamps{}
}

func (s *sourceRuntime) close() {
	s.stopTimer()
	if s.reloadCancel != nil {
		s.reloadCancel()
		s.reloadCancel = nil
		s.reloadEpoch = 0
	}
	if s.refreshCancel != nil {
		s.refreshCancel()
		s.refreshCancel = nil
		s.refreshSequence = 0
	}
	if s.session != nil {
		session := s.session
		s.session = nil
		session.Close()
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

// stageSource takes ownership of session, including on resolution failure. The
// returned staging owner must be consumed by applyStaged or explicitly closed.
func stageSource(ctx context.Context, opts Options, resolver *source.Resolver, epoch, refresh uint64, cfg config.Config, committed string, session *upstream.Session) stageResult {
	staged := &stagedCandidate{Candidate: Candidate{epoch: epoch, refresh: refresh}, session: session}
	result := stageResult{candidate: staged}
	resolved, err := resolver.Resolve(ctx, cfg, committed, refresh == 0)
	result.attempted = resolved.Attempted
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
	staged.Candidate = candidate
	result.refreshErr = resolved.RefreshError
	result.logger = newLogger(cfg, opts.Stderr)
	result.err = ctx.Err()
	return result
}
