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
)

const (
	crowdRetryMin = time.Second
	crowdRetryMax = time.Minute
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
}

type crowdRuntime struct {
	engine      *Engine
	transport   http.RoundTripper
	ctx         context.Context
	cancel      context.CancelFunc
	workers     sync.WaitGroup
	nextEpoch   uint64
	operation   uint64
	watermark   uint64
	connected   atomic.Bool
	enforced    atomic.Bool
	active      *crowdState
	staged      *crowdState
	transaction string
	grantAt     time.Time
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
	client, err := crowd.NewClient(candidate.cfg.CrowdSec, transport)
	if err != nil {
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
		client.Close()
		return nil, err
	}
	staged, err := synchronizedCrowd(client, candidate.cfg.CrowdSec, epoch, batch)
	if err != nil {
		client.Close()
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
		s.client.Close()
	}
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
		c.staged.client.Close()
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
		if selected != nil && !c.grantAt.IsZero() {
			c.recordLeasesLocked(selected, selected.store.Projection(c.grantAt), c.grantAt)
		}
		c.watermark = c.operation
		c.staged = nil
		c.transaction = ""
		return
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
			if err := c.writeLocked(ctx, c.staged, revision.Target, true); err != nil {
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
	return c.writeLocked(ctx, c.active, revision.Target, false)
}

func (c *crowdRuntime) signalLocked(s *crowdState) {
	select {
	case s.wake <- struct{}{}:
	default:
	}
}

func (c *crowdRuntime) recordLeasesLocked(s *crowdState, projection []policy.TimedPrefix, at time.Time) {
	s.renewAt = time.Time{}
	for _, value := range projection {
		_, next := firewall.LeaseGrant(value.Deadline, at, time.Second)
		if !next.IsZero() && (s.renewAt.IsZero() || next.Before(s.renewAt)) {
			s.renewAt = next
		}
	}
	c.signalLocked(s)
}

func (c *crowdRuntime) failedWriteLocked(now time.Time) {
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
func (c *crowdRuntime) writeLocked(ctx context.Context, s *crowdState, target *firewall.Target, activation bool) error {
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
	if err := c.engine.backend.UpdateDynamic(ctx, target, projection); err != nil {
		c.failedWriteLocked(time.Now())
		return err
	}
	c.watermark = op
	c.dirty = false
	c.retryAt = time.Time{}
	c.retryDelay = 0
	c.enforced.Store(true)
	c.recordLeasesLocked(s, projection, now)
	return nil
}

func (c *crowdRuntime) targetLocked() (*firewall.Target, error) {
	view, err := c.engine.store.Read()
	if err != nil {
		return nil, err
	}
	if view.Active == nil || view.Active.Target == nil || view.Active.Target.DynamicGeneration == "" {
		return nil, errors.New("CrowdSec active container is unavailable")
	}
	return view.Active.Target, nil
}

func (c *crowdRuntime) reconcileLocked(ctx context.Context, s *crowdState) error {
	target, err := c.targetLocked()
	if err != nil {
		c.failedWriteLocked(time.Now())
		return err
	}
	return c.writeLocked(ctx, s, target, false)
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
				var target *firewall.Target
				target, err = c.targetLocked()
				if err == nil {
					err = c.writeLocked(ctx, next, target, true)
					if err != nil {
						_ = c.writeLocked(ctx, s, target, false)
					}
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
							_ = c.reconcileLocked(ctx, s)
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
	_ = c.reconcileLocked(ctx, s)
}

func (c *crowdRuntime) closeLocked() {
	c.connected.Store(false)
	c.stopStateLocked(c.active, true)
	if c.staged != nil && c.staged != c.active {
		c.staged.client.Close()
	}
	c.active, c.staged = nil, nil
}
