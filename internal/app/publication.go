package app

import (
	"context"
	"errors"
	"log/slog"
	"sync/atomic"
	"time"

	metricspkg "github.com/perimeterd/perimeterd/internal/metrics"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/state"
	"github.com/perimeterd/perimeterd/internal/upstream"
)

const (
	metricsCloseTimeout         = 5 * time.Second
	nativeCounterSampleInterval = 15 * time.Second
)

// runtimePublication owns the listener and logger that describe the active
// runtime. A reservation is kept here from binding through durable recovery so
// an uncertain apply cannot leak or accidentally publish its resources.
type runtimePublication struct {
	engine        *Engine
	source        *sourceRuntime
	logger        *slog.Logger
	collector     *metricspkg.Collector
	health        atomic.Bool
	active        *metricsServer
	reservation   *runtimeReservation
	counterCancel context.CancelFunc
	counterDone   chan struct{}
	closed        bool
}

type runtimeReservation struct {
	transaction string
	staged      *metricsServer
	replace     bool
	logger      *slog.Logger
	refreshErr  error
	attempted   []policy.Selector
	session     *upstream.Session
	prefixes    []metricspkg.PrefixCount
}

func newRuntimePublication(engine *Engine, source *sourceRuntime, logger *slog.Logger, collector *metricspkg.Collector) *runtimePublication {
	publication := &runtimePublication{engine: engine, source: source, logger: logger, collector: collector}
	publication.health.Store(true)
	return publication
}

func (p *runtimePublication) metricsHealthy() bool {
	return p.engine.Healthy() && p.health.Load()
}

func (p *runtimePublication) reserve(result stageResult, ctx context.Context) error {
	if p.reservation != nil {
		return errors.New("runtime publication already has a reservation")
	}
	replace := p.active == nil || p.active.listen != result.candidate.cfg.Metrics.Listen
	var staged *metricsServer
	if replace {
		var err error
		staged, err = bindMetricsWithCollector(result.candidate.cfg.Metrics.Listen, p.metricsHealthy, p.source.snapshotTimestamps, p.collector)
		if err != nil {
			return err
		}
		if staged != nil {
			staged.crowdConnected = p.engine.CrowdSecConnected
		}
	}
	// Application consumes the staging owner; publication holds an independent
	// handle until the revision is selected or discarded.
	session, err := result.candidate.retainSession()
	if err != nil {
		if staged != nil {
			_ = staged.closeImmediate()
		}
		return err
	}
	p.reservation = &runtimeReservation{
		staged:     staged,
		replace:    replace,
		logger:     result.logger,
		refreshErr: result.refreshErr,
		attempted:  result.attempted,
		session:    session,
		prefixes:   prefixCounts(result.candidate.Candidate),
	}
	if p.active == nil && staged != nil {
		p.engine.enableCounterTelemetry(ctx)
	}
	return nil
}

func (p *runtimePublication) retain(transaction string) error {
	if p.reservation == nil {
		return errors.New("runtime publication has no reservation to retain")
	}
	p.reservation.transaction = transaction
	return nil
}

func (p *runtimePublication) pending() bool {
	return p.reservation != nil && p.reservation.transaction != ""
}

func (p *runtimePublication) publish(revision *state.Revision) error {
	reservation := p.reservation
	if reservation == nil {
		return errors.New("runtime publication has no reservation")
	}
	p.reservation = nil
	return p.publishReservation(revision, reservation)
}

func (p *runtimePublication) recover(revision *state.Revision) error {
	reservation := p.reservation
	if reservation == nil {
		return p.source.selectRevision(revision, nil)
	}
	p.reservation = nil
	if reservation.transaction == "" || revision == nil || revision.ID != reservation.transaction {
		_ = closeReservation(reservation)
		if p.active == nil {
			p.stopCounterSampler()
			p.engine.disableCounterTelemetry()
		}
		return p.source.selectRevision(revision, nil)
	}
	return p.publishReservation(revision, reservation)
}

func (p *runtimePublication) publishReservation(revision *state.Revision, reservation *runtimeReservation) error {
	if err := p.source.selectRevision(revision, reservation.session); err != nil {
		closeErr := closeReservation(reservation)
		if p.active == nil {
			p.stopCounterSampler()
			p.engine.disableCounterTelemetry()
		}
		return errors.Join(err, closeErr)
	}
	reservation.session = nil
	p.logger = reservation.logger
	if p.collector != nil {
		p.collector.SetPrefixes(reservation.prefixes)
	}
	if reservation.refreshErr != nil {
		p.source.attempted(reservation.attempted, time.Now())
		p.source.schedule()
		p.logger.Warn("using committed source snapshot after refresh failure", "error", reservation.refreshErr, "snapshot_age", p.source.age())
	}
	if !reservation.replace {
		return nil
	}
	if reservation.staged != nil {
		reservation.staged.serve()
	}
	old := p.active
	p.active = reservation.staged
	retireFailed := false
	if old != nil {
		ctx, cancel := context.WithTimeout(context.Background(), metricsCloseTimeout)
		err := old.close(ctx)
		cancel()
		if err != nil {
			retireFailed = true
			p.health.Store(false)
			p.logger.Warn("retiring metrics listener failed", "error", err)
		}
	}
	if p.active == nil {
		p.stopCounterSampler()
		p.engine.disableCounterTelemetry()
	} else {
		p.startCounterSampler()
	}
	if !retireFailed {
		p.health.Store(true)
	}
	return nil
}

func (p *runtimePublication) discard() error {
	reservation := p.reservation
	p.reservation = nil
	err := closeReservation(reservation)
	if p.active == nil {
		p.stopCounterSampler()
		p.engine.disableCounterTelemetry()
	}
	return err
}

func (p *runtimePublication) startCounterSampler() {
	if p.collector == nil || p.active == nil || !p.engine.supportsNativeCounterTelemetry() || p.counterCancel != nil {
		return
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	p.counterCancel, p.counterDone = cancel, done
	go func() {
		defer close(done)
		ticker := time.NewTicker(nativeCounterSampleInterval)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			default:
			}
			p.engine.sampleNativeCounters(ctx)
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
			}
		}
	}()
}

func (p *runtimePublication) stopCounterSampler() {
	if p.counterCancel == nil {
		return
	}
	p.counterCancel()
	<-p.counterDone
	p.counterCancel = nil
	p.counterDone = nil
}

func (p *runtimePublication) metricsErrors() <-chan error {
	if p.active == nil {
		return nil
	}
	return p.active.errCh
}

func (p *runtimePublication) close() error {
	if p.closed {
		return nil
	}
	p.closed = true
	p.stopCounterSampler()
	p.engine.disableCounterTelemetry()
	reservation := p.reservation
	p.reservation = nil
	reservationErr := closeReservation(reservation)
	active := p.active
	p.active = nil
	if active == nil {
		return reservationErr
	}
	ctx, cancel := context.WithTimeout(context.Background(), metricsCloseTimeout)
	defer cancel()
	return errors.Join(reservationErr, active.close(ctx))
}

func closeReservation(reservation *runtimeReservation) error {
	if reservation == nil {
		return nil
	}
	var err error
	if reservation.staged != nil {
		err = reservation.staged.closeImmediate()
	}
	if reservation.session != nil {
		reservation.session.Close()
		reservation.session = nil
	}
	return err
}
