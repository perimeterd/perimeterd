package app

import (
	"context"
	"errors"
	"math/rand/v2"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	crowd "github.com/perimeterd/perimeterd/internal/crowdsec"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/state"
	"github.com/perimeterd/perimeterd/internal/upstream"
)

const (
	crowdRetryMin        = time.Second
	crowdRetryMax        = time.Minute
	crowdShutdownTimeout = 5 * time.Second
)

func crowdRetryWait(delay time.Duration) time.Duration {
	half := delay / 2
	return half + rand.N(delay-half+1) // #nosec G404 -- scheduling jitter has no cryptographic or authentication role.
}

func crowdBackoff(delay time.Duration) time.Duration {
	return min(delay*2, crowdRetryMax)
}

// Every mutable field below is protected by Engine.mu. Network polls run outside
// that fence; only the acknowledged active epoch may deliver incremental batches.
// Epoch retirement cancels workers, but never joins them while holding the fence.
type crowdState struct {
	client       *crowd.Client
	store        *crowd.Store
	cfg          config.CrowdSecConfig
	epoch        uint64
	sequence     uint64
	pollCancel   context.CancelFunc
	pollDone     chan struct{}
	expiryCancel context.CancelFunc
	wake         chan struct{}
	renewAt      time.Time
	backoff      time.Duration
	successes    int

	// These fields are immutable acknowledged native evidence until the next
	// successful dynamic write. They are deliberately separate from store's
	// desired decision set.
	leasePrefixes   []policy.TimedPrefix
	leaseDecisions  []crowd.Decision
	leaseValidUntil time.Time
	leaseOperation  uint64
}

type crowdRuntime struct {
	engine      *Engine
	transport   http.RoundTripper
	ctx         context.Context
	cancel      context.CancelFunc
	workers     sync.WaitGroup
	retiring    sync.WaitGroup
	nextEpoch   uint64
	operation   uint64
	watermark   uint64
	connected   atomic.Bool
	enforced    atomic.Bool
	active      *crowdState
	staged      *crowdState
	transaction string
	grantAt     time.Time
	grantDone   time.Time
	dirty       bool
	retryAt     time.Time
	retryDelay  time.Duration
}

func newCrowdRuntime(engine *Engine) *crowdRuntime {
	ctx, cancel := context.WithCancel(context.Background())
	c := &crowdRuntime{engine: engine, ctx: ctx, cancel: cancel, transport: http.DefaultTransport}
	c.enforced.Store(true)
	return c
}

// ConfigureCrowdSecTransport installs the optional HTTP transport before activation.
func (e *Engine) ConfigureCrowdSecTransport(client *http.Client) {
	e.mu.Lock()
	defer e.mu.Unlock()
	if client != nil && client.Transport != nil {
		e.crowd.transport = client.Transport
	}
}

// CrowdSecConnected reports the last acknowledged active client's connection state.
func (e *Engine) CrowdSecConnected() bool { return e.crowd.connected.Load() }

func (c *crowdRuntime) nextEpochLocked() (uint64, error) {
	if c.nextEpoch == ^uint64(0) {
		return 0, errors.New("CrowdSec client epoch exhausted")
	}
	c.nextEpoch++
	return c.nextEpoch, nil
}

func (c *crowdRuntime) nextOperationLocked() (uint64, error) {
	if c.operation == ^uint64(0) {
		return 0, errors.New("CrowdSec operation sequence exhausted")
	}
	c.operation++
	return c.operation, nil
}

// stageForApply is serialized by Engine.applyMu, not Engine.mu. Retain the old
// authenticated client until selection is certain, including same-path rotation.
func (c *crowdRuntime) stageForApply(ctx context.Context, candidate Candidate) (*crowdState, error) {
	e := c.engine
	e.mu.Lock()
	if err := e.startErrorLocked(ctx); err != nil {
		e.mu.Unlock()
		return nil, err
	}
	if !e.currentLocked(candidate) {
		e.mu.Unlock()
		return nil, errStaleCandidate
	}
	if candidate.refresh != 0 && c.active != nil && candidate.cfg.CrowdSec.Enabled {
		active := c.active
		e.mu.Unlock()
		return active, nil
	}
	old := c.active
	var done chan struct{}
	if old != nil && old.pollCancel != nil {
		old.pollCancel()
		done = old.pollDone
		old.pollCancel = nil
	}
	transport := c.transport
	e.mu.Unlock()
	if done != nil {
		<-done
	}
	if !candidate.cfg.CrowdSec.Enabled {
		return nil, nil
	}
	if candidate.cfg.CrowdSec.Transport.Type == upstream.TypeOpenZiti {
		if candidate.session == nil {
			return nil, errors.New("CrowdSec OpenZiti transport requires a loaded session")
		}
		var err error
		transport, err = candidate.session.Transport(candidate.cfg.CrowdSec.Transport, candidate.cfg.CrowdSec.LAPIURL)
		if err != nil {
			return nil, err
		}
	}
	client, err := crowd.NewClient(candidate.cfg.CrowdSec, transport)
	if err != nil {
		if candidate.cfg.CrowdSec.Transport.Type == upstream.TypeOpenZiti {
			if closer, ok := transport.(interface{ CloseIdleConnections() }); ok {
				closer.CloseIdleConnections()
			}
		}
		return nil, err
	}
	pollCtx, cancel := context.WithCancel(ctx)
	stop := context.AfterFunc(c.ctx, cancel)
	defer func() { stop(); cancel() }()
	batch, err := client.Poll(pollCtx, true)
	if err != nil {
		client.Close()
		return nil, err
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	epoch, err := c.nextEpochLocked()
	if err != nil {
		c.retireClient(client)
		return nil, err
	}
	staged, err := synchronizedCrowd(client, candidate.cfg.CrowdSec, epoch, batch)
	if err != nil {
		c.retireClient(client)
		return nil, err
	}
	c.staged = staged
	return staged, nil
}

func synchronizedCrowd(client *crowd.Client, cfg config.CrowdSecConfig, epoch uint64, batch crowd.Batch) (*crowdState, error) {
	if !batch.Startup {
		return nil, errors.New("CrowdSec synchronization was not authoritative")
	}
	store := crowd.NewStore(client.Endpoint(), epoch)
	if err := store.Apply(batch, 1, time.Now()); err != nil {
		return nil, err
	}
	return &crowdState{client: client, store: store, cfg: cfg, epoch: epoch, sequence: 1, wake: make(chan struct{}, 1)}, nil
}

func (c *crowdRuntime) stopStateLocked(s *crowdState, closeClient bool) {
	if s == nil {
		return
	}
	if s.pollCancel != nil {
		s.pollCancel()
		s.pollCancel = nil
	}
	if s.expiryCancel != nil {
		s.expiryCancel()
		s.expiryCancel = nil
	}
	if closeClient {
		c.retireClient(s.client)
	}
}

func (c *crowdRuntime) retireClient(client *crowd.Client) {
	if client == nil {
		return
	}
	c.retiring.Add(1)
	go func() {
		defer c.retiring.Done()
		client.Close()
	}()
}

func (c *crowdRuntime) activateLocked(s *crowdState) {
	if c.active == s {
		return
	}
	old := c.active
	c.stopStateLocked(old, old != nil && (s == nil || old.client != s.client))
	c.active = s
	c.connected.Store(s != nil)
	c.dirty = false
	c.retryAt = time.Time{}
	c.retryDelay = 0
	c.enforced.Store(true)
	if s != nil {
		c.startPollLocked(s, false)
		c.startExpiryLocked(s)
	}
}

func (c *crowdRuntime) discardLocked() {
	if c.staged != nil && c.staged != c.active {
		c.retireClient(c.staged.client)
	}
	c.staged = nil
	c.transaction = ""
	if c.active != nil && c.active.pollCancel == nil && !c.engine.closing.Load() {
		// A replacement may have advanced the server cursor even if it failed.
		// Resynchronize with the retained credential, never reread the key file.
		c.connected.Store(false)
		c.startPollLocked(c.active, true)
	}
}

func (c *crowdRuntime) finishApplyLocked(outcome Outcome, selected *crowdState) {
	if outcome.Committed {
		c.activateLocked(selected)
		c.watermark = c.operation
		if selected != nil && !c.grantAt.IsZero() && !c.grantDone.IsZero() {
			var target *firewall.Target
			if outcome.Active != nil {
				target = outcome.Active.Target
			}
			c.recordLeasesLocked(selected, selected.store.Projection(c.grantAt), c.grantAt, c.grantDone, c.operation, target)
		}
	}
	if c.transaction != "" {
		view, err := c.engine.store.Read()
		if err != nil || view.Journal != nil {
			return
		}
	}
	c.discardLocked()
}

// recoverLocked runs after static recovery has selected and stabilized a revision.
// A retained staged store is selected only by its durable transaction identity.
func (c *crowdRuntime) recoverLocked(ctx context.Context, revision *state.Revision) error {
	if c.transaction != "" && revision != nil && revision.ID == c.transaction {
		if c.staged != nil {
			if err := c.reconcileLocked(ctx, c.staged, true); err != nil {
				return err
			}
		}
		c.activateLocked(c.staged)
		c.staged = nil
		c.transaction = ""
		return nil
	}
	c.discardLocked()
	if c.active == nil {
		return nil // A process restart still requires startup synchronization.
	}
	if revision == nil || revision.Target == nil || !revision.Config.CrowdSec.Enabled {
		c.activateLocked(nil)
		return nil
	}
	return c.reconcileLocked(ctx, c.active, false)
}

func (c *crowdRuntime) signalLocked(s *crowdState) {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (c *crowdRuntime) recordLeasesLocked(s *crowdState, projection []policy.TimedPrefix, start, finish time.Time, operation uint64, target *firewall.Target) {
	if start.IsZero() {
		start = finish
	}
	if finish.IsZero() || finish.Before(start) {
		finish = start
	}
	unit := time.Second
	s.renewAt = time.Time{}
	prefixes := make([]policy.TimedPrefix, 0, len(projection))
	s.leaseValidUntil = time.Time{}
	s.leaseOperation = operation
	for _, value := range projection {
		if target != nil && !targetHasFamily(target, value) {
			continue
		}
		_, next := firewall.LeaseGrant(value.Deadline, start, unit)
		grant, _ := firewall.LeaseGrant(value.Deadline, finish, unit)
		if !next.IsZero() && (s.renewAt.IsZero() || next.Before(s.renewAt)) {
			s.renewAt = next
		}
		if grant <= 0 {
			// A projection that crosses native lease granularity is not
			// evidence of an absent ban: the backend omits it. Fence the
			// whole publication at completion until a fresh write settles.
			if s.leaseValidUntil.IsZero() || finish.Before(s.leaseValidUntil) {
				s.leaseValidUntil = finish
			}
			continue
		}
		expiry := start.Add(grant)
		if !expiry.After(finish) {
			if s.leaseValidUntil.IsZero() || finish.Before(s.leaseValidUntil) {
				s.leaseValidUntil = finish
			}
			continue
		}
		prefixes = append(prefixes, policy.TimedPrefix{Prefix: value.Prefix, Deadline: expiry})
		if s.leaseValidUntil.IsZero() || expiry.Before(s.leaseValidUntil) {
			s.leaseValidUntil = expiry
		}
	}
	s.leasePrefixes = prefixes
	s.leaseDecisions = s.store.Decisions()
	c.signalLocked(s)
}

func targetHasFamily(target *firewall.Target, value policy.TimedPrefix) bool {
	if target == nil {
		return true
	}
	want := policy.IPv6
	if value.Prefix.Addr().Is4() {
		want = policy.IPv4
	}
	for _, family := range target.Families {
		if family.Family == want {
			return true
		}
	}
	return false
}

func (c *crowdRuntime) failedWriteLocked(now time.Time) {
	c.engine.abortLookupLocked()
	c.enforced.Store(false)
	c.dirty = true
	if c.retryDelay == 0 {
		c.retryDelay = crowdRetryMin
	}
	c.retryAt = now.Add(crowdRetryWait(c.retryDelay))
	c.retryDelay = crowdBackoff(c.retryDelay)
	// The active worker may be parked without a timer when its store is empty.
	// Reconnect activation failures must make the new retry deadline observable.
	if c.active != nil {
		c.signalLocked(c.active)
	}
}

// A dispatch is constructed and admitted under the same writer fence. Retries
// construct a new operation from the latest store, never replay an old payload.
// Target selection and transaction checks share one freshly validated durable
// view; no view is carried across dispatches or failure retries.
func (c *crowdRuntime) reconcileLocked(ctx context.Context, s *crowdState, activation bool) error {
	if c.engine.closing.Load() {
		return errEngineClosed
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if !activation && c.active != s {
		return errStaleCandidate
	}
	view, err := c.engine.store.Read()
	if err != nil {
		c.failedWriteLocked(time.Now())
		return err
	}
	if view.Journal != nil || !c.engine.healthy.Load() {
		c.failedWriteLocked(time.Now())
		return errEngineDegraded
	}
	if view.Active == nil || view.Active.Target == nil || view.Active.Target.DynamicGeneration == "" {
		c.failedWriteLocked(time.Now())
		return errors.New("CrowdSec active container is unavailable")
	}
	target := view.Active.Target
	now := time.Now()
	s.store.Expire(now)
	epoch, revision := s.epoch, s.store.Revision()
	projection := s.store.Projection(now)
	op, err := c.nextOperationLocked()
	if err != nil {
		c.failedWriteLocked(now)
		return err
	}
	if (!activation && (c.active == nil || epoch != c.active.epoch)) || revision != s.store.Revision() || op <= c.watermark {
		return errStaleCandidate
	}
	writeStart := time.Now()
	c.engine.invalidateLookupLocked()
	if err := c.engine.backend.UpdateDynamic(ctx, target, projection); err != nil {
		c.failedWriteLocked(time.Now())
		return err
	}
	writeFinish := time.Now()
	c.watermark = op
	c.dirty = false
	c.retryAt = time.Time{}
	c.retryDelay = 0
	c.enforced.Store(true)
	c.recordLeasesLocked(s, projection, writeStart, writeFinish, op, target)
	c.engine.publishDynamicLookupLocked(s, view.Active.ID, view.Active.Manifest)
	return nil
}

func (c *crowdRuntime) startPollLocked(s *crowdState, full bool) {
	ctx, cancel := context.WithCancel(c.ctx)
	done := make(chan struct{})
	s.pollCancel, s.pollDone = cancel, done
	c.workers.Add(1)
	go func() { defer c.workers.Done(); defer close(done); c.pollLoop(ctx, s, full) }()
}

func waitCrowd(ctx context.Context, delay time.Duration) bool {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

func (c *crowdRuntime) pollLoop(ctx context.Context, s *crowdState, full bool) {
	backoff, successes := s.backoff, s.successes
	if backoff == 0 {
		backoff = crowdRetryMin
	}
	for {
		if !full && !waitCrowd(ctx, s.cfg.UpdateFrequency) {
			return
		}
		batch, err := s.client.Poll(ctx, full)
		if ctx.Err() != nil {
			return
		}
		c.engine.mu.Lock()
		if c.active != s || ctx.Err() != nil || c.engine.closing.Load() {
			c.engine.mu.Unlock()
			return
		}
		if err != nil {
			c.connected.Store(false)
			successes = 0
			full = true
		} else if full {
			// The same authenticated client owns the cursor, but each full
			// synchronization gets a distinct authority epoch and store.
			var epoch uint64
			epoch, err = c.nextEpochLocked()
			var next *crowdState
			if err == nil {
				next, err = synchronizedCrowd(s.client, s.cfg, epoch, batch)
			}
			if err == nil && c.dirty {
				err = errEngineDegraded
			}
			if err == nil {
				err = c.reconcileLocked(ctx, next, true)
				if err != nil {
					_ = c.reconcileLocked(ctx, s, false)
				}
			}
			if err == nil {
				next.backoff, next.successes = backoff, successes+1
				c.activateLocked(next)
				c.engine.mu.Unlock()
				return
			}
		} else {
			if s.sequence == ^uint64(0) {
				err = errors.New("CrowdSec source sequence exhausted")
			} else {
				s.sequence++
				before := s.store.Revision()
				err = s.store.Apply(batch, s.sequence, time.Now())
				if err == nil {
					c.connected.Store(true)
					if before != s.store.Revision() {
						c.signalLocked(s)
						if !c.dirty {
							_ = c.reconcileLocked(ctx, s, false)
						}
					}
				}
			}
			if err != nil {
				full = true
				c.connected.Store(false)
			}
		}
		c.engine.mu.Unlock()
		if err != nil {
			successes = 0
			if !waitCrowd(ctx, crowdRetryWait(backoff)) {
				return
			}
			backoff = crowdBackoff(backoff)
		} else {
			successes++
			if successes >= 2 {
				backoff = crowdRetryMin
			}
		}
	}
}

func (c *crowdRuntime) startExpiryLocked(s *crowdState) {
	ctx, cancel := context.WithCancel(c.ctx)
	s.expiryCancel = cancel
	c.workers.Add(1)
	go func() { defer c.workers.Done(); c.expiryLoop(ctx, s) }()
}

func (c *crowdRuntime) expiryLoop(ctx context.Context, s *crowdState) {
	for {
		c.engine.mu.Lock()
		if c.active != s || ctx.Err() != nil || c.engine.closing.Load() {
			c.engine.mu.Unlock()
			return
		}
		next := s.store.NextExpiry()
		if c.dirty {
			if next.IsZero() || c.retryAt.Before(next) {
				next = c.retryAt
			}
		} else if !s.renewAt.IsZero() && (next.IsZero() || s.renewAt.Before(next)) {
			next = s.renewAt
		}
		c.engine.mu.Unlock()
		var timer *time.Timer
		var tick <-chan time.Time
		if !next.IsZero() {
			timer = time.NewTimer(max(time.Until(next), 0))
			tick = timer.C
		}
		select {
		case <-ctx.Done():
			if timer != nil {
				timer.Stop()
			}
			return
		case <-s.wake:
			if timer != nil {
				timer.Stop()
			}
			continue
		case <-tick:
		}
		c.engine.mu.Lock()
		c.maintainLocked(ctx, s, time.Now())
		c.engine.mu.Unlock()
	}
}

func (c *crowdRuntime) maintainLocked(ctx context.Context, s *crowdState, now time.Time) {
	if c.active != s || ctx.Err() != nil || c.engine.closing.Load() {
		return
	}
	expired := s.store.Expire(now)
	if c.dirty {
		if now.Before(c.retryAt) {
			return
		}
	} else if !expired && (s.renewAt.IsZero() || now.Before(s.renewAt)) {
		return
	}
	_ = c.reconcileLocked(ctx, s, false)
}

func (c *crowdRuntime) closeLocked() {
	c.connected.Store(false)
	c.stopStateLocked(c.active, true)
	if c.staged != nil && c.staged != c.active {
		c.retireClient(c.staged.client)
	}
	c.active, c.staged = nil, nil
}

func waitGroupBounded(group *sync.WaitGroup, timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		group.Wait()
		close(done)
	}()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-done:
	case <-timer.C:
	}
}
