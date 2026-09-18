// Package app coordinates perimeterd's process lifecycle and serialized engine.
package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/source"
	"github.com/perimeterd/perimeterd/internal/state"
)

const (
	defaultConfigPath     = "/etc/perimeterd/perimeterd.yaml"
	defaultStateDir       = "/var/lib/perimeterd"
	defaultLockPath       = "/run/perimeterd/owner.lock"
	defaultStartupTimeout = 75 * time.Minute
)

// Options controls the daemon's process lifecycle. Backend, SourceClient,
// Checkpoint, Signals, and Notify are programmatic injection points; they are
// not configuration or command-line overrides.
type Options struct {
	ConfigPath     string
	StateDir       string
	LockPath       string
	Stderr         io.Writer
	Backend        firewall.Backend
	SourceClient   *http.Client
	Checkpoint     func(string) error
	Signals        <-chan os.Signal
	Notify         func(string) error
	StartupTimeout time.Duration
}

func normalizeOptions(opts Options) Options {
	if opts.ConfigPath == "" {
		opts.ConfigPath = defaultConfigPath
	}
	if opts.StateDir == "" {
		opts.StateDir = defaultStateDir
	}
	if opts.LockPath == "" {
		opts.LockPath = defaultLockPath
	}
	if opts.Stderr == nil {
		opts.Stderr = os.Stderr
	}
	if opts.StartupTimeout <= 0 || opts.StartupTimeout > defaultStartupTimeout {
		opts.StartupTimeout = defaultStartupTimeout
	}
	if opts.Notify == nil {
		opts.Notify = systemdNotify()
	}
	return opts
}

// Run acquires lifecycle ownership, recovers durable state before reading YAML,
// applies the initial candidate, and remains in the foreground until context
// cancellation or SIGTERM/SIGINT. SIGHUP stages a complete reload.
func Run(ctx context.Context, options Options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	opts := normalizeOptions(options)
	runCtx, cancelRun := context.WithCancel(ctx)
	defer cancelRun()
	signalInput, stopSignals := runtimeSignals(opts.Signals)
	signalEvents := make(chan os.Signal, 8)
	signalStop := make(chan struct{})
	signalDone := make(chan struct{})
	go bridgeSignals(signalInput, signalEvents, cancelRun, signalStop, signalDone)
	defer func() {
		close(signalStop)
		stopSignals()
		<-signalDone
	}()
	startupCtx, cancelStartup := context.WithTimeout(runCtx, opts.StartupTimeout)
	defer cancelStartup()
	deadline, _ := startupCtx.Deadline()
	notifier := newStartupNotifier(opts.Notify, deadline)
	notifyStopped := false
	stopNotifier := func() error {
		if notifyStopped {
			return nil
		}
		notifyStopped = true
		return notifier.Stop()
	}
	defer func() { _ = stopNotifier() }()
	if err := startupCtx.Err(); err != nil {
		return errors.Join(err, stopNotifier())
	}

	lock, err := state.AcquireLock(opts.LockPath)
	if err != nil {
		return errors.Join(err, stopNotifier())
	}
	defer func() { _ = lock.Close() }()
	if err := startupCtx.Err(); err != nil {
		return errors.Join(err, stopNotifier())
	}

	store, err := state.Open(opts.StateDir, opts.Checkpoint)
	if err != nil {
		return errors.Join(err, stopNotifier())
	}
	engine := NewEngine(store, opts.Backend, opts.Checkpoint)
	engine.ConfigureCrowdSecTransport(opts.SourceClient)
	defer engine.Close()

	recovered, err := recoverUntilReady(startupCtx, engine, nil)
	if err != nil {
		return errors.Join(err, stopNotifier())
	}
	if err := startupCtx.Err(); err != nil {
		return errors.Join(err, stopNotifier())
	}
	if err := collectPrefixes(store); err != nil {
		return errors.Join(fmt.Errorf("collect unused prefix cache: %w", err), stopNotifier())
	}
	sources := newSourceRuntime(store.Prefixes(), opts.SourceClient)
	defer sources.close()
	if err := sources.selectRevision(recovered); err != nil {
		return errors.Join(err, stopNotifier())
	}

	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return errors.Join(fmt.Errorf("load configuration: %w", err), stopNotifier())
	}
	if err := firewall.ValidateConfig(cfg); err != nil {
		return errors.Join(fmt.Errorf("runtime configuration: %w", err), stopNotifier())
	}
	if err := startupCtx.Err(); err != nil {
		return errors.Join(err, stopNotifier())
	}
	publication := newRuntimePublication(engine, sources, newLogger(cfg, opts.Stderr))
	defer func() { _ = publication.close() }()

	epoch, err := engine.Admit()
	if err != nil {
		return errors.Join(err, stopNotifier())
	}
	initial := stageSource(startupCtx, opts, sources.resolver, epoch, 0, cfg, sources.manifest())
	if initial.err != nil {
		return errors.Join(initial.err, stopNotifier())
	}
	if err := publication.reserve(initial); err != nil {
		return errors.Join(err, stopNotifier())
	}
	if err := startupCtx.Err(); err != nil {
		_ = publication.discard()
		return errors.Join(err, stopNotifier())
	}
	outcome, applyErr := engine.Apply(startupCtx, initial.candidate)
	if outcome.Degraded {
		if err := publication.retain(outcome.Transaction); err != nil {
			_ = publication.discard()
			return errors.Join(applyErr, err, stopNotifier())
		}
		expected := "startup recovery did not retain candidate"
		if outcome.Committed {
			expected = "startup recovery did not retain committed candidate"
		}
		recovered, recoverErr := recoverUntilReady(startupCtx, engine, func(recoverErr error) {
			publication.logger.Warn("firewall recovery failed", "error", recoverErr)
		})
		if recoverErr != nil {
			_ = publication.discard()
			return errors.Join(applyErr, recoverErr, stopNotifier())
		}
		if recovered == nil || recovered.ID != outcome.Transaction {
			_ = publication.discard()
			return errors.Join(applyErr, errors.New(expected), stopNotifier())
		}
		outcome.Active = recovered
		if err := publication.recover(outcome.Active); err != nil {
			_ = publication.discard()
			return errors.Join(applyErr, err, stopNotifier())
		}
	} else if !outcome.Committed {
		_ = publication.discard()
		if applyErr != nil {
			return errors.Join(fmt.Errorf("apply configuration: %w", applyErr), stopNotifier())
		}
		return errors.Join(errors.New("configuration apply produced no committed revision"), stopNotifier())
	} else if err := publication.publish(outcome.Active); err != nil {
		_ = publication.discard()
		return errors.Join(applyErr, err, stopNotifier())
	}
	if err := notifier.Stop(); err != nil {
		notifyStopped = true
		return err
	}
	notifyStopped = true
	if err := startupCtx.Err(); err != nil {
		return err
	}
	if err := opts.Notify("READY=1\nSTATUS=perimeterd running"); err != nil {
		return fmt.Errorf("send readiness notification: %w", err)
	}

	producerCtx, cancelProducers := context.WithCancel(runCtx)
	defer cancelProducers()
	results := make(chan stageResult, 8)
	var producers sync.WaitGroup
	recovering := false
	recoveryBackoff := time.Second
	var recoveryTimer *time.Timer
	scheduleRecovery := func() {
		if recovering {
			return
		}
		recovering = true
		recoveryBackoff = time.Second
		recoveryTimer = time.NewTimer(0)
	}
	stopService := func() error {
		cancelProducers()
		sources.close()
		producers.Wait()
		if recoveryTimer != nil {
			recoveryTimer.Stop()
			recoveryTimer = nil
		}
		if err := publication.close(); err != nil {
			publication.logger.Error("closing metrics listener failed", "error", err)
			return err
		}
		return nil
	}
	for {
		var recoveryC <-chan time.Time
		if recoveryTimer != nil {
			recoveryC = recoveryTimer.C
		}
		select {
		case <-runCtx.Done():
			return stopService()
		case <-sources.events():
			sources.schedule()
			if recovering || sources.active == nil || sources.refreshCancel != nil {
				continue
			}
			revision := sources.active
			sequence, admitErr := engine.AdmitRefresh(revision.Epoch)
			if admitErr != nil {
				publication.logger.Warn("source refresh admission failed", "error", admitErr)
				continue
			}
			refreshCtx, cancel := context.WithCancel(producerCtx)
			sources.refreshCancel = cancel
			producers.Add(1)
			go func() {
				defer producers.Done()
				result := stageSource(refreshCtx, opts, sources.resolver, revision.Epoch, sequence, revision.Config, revision.Manifest)
				select {
				case results <- result:
				case <-producerCtx.Done():
				}
			}()
		case sig, ok := <-signalEvents:
			if !ok {
				return stopService()
			}
			switch sig {
			case syscall.SIGTERM, syscall.SIGINT:
				return stopService()
			case syscall.SIGHUP:
				requestEpoch, admitErr := engine.Admit()
				if admitErr != nil {
					publication.logger.Warn("reload admission failed", "error", admitErr)
					continue
				}
				if sources.reloadCancel != nil {
					sources.reloadCancel()
				}
				reloadCtx, cancel := context.WithCancel(producerCtx)
				sources.reloadCancel = cancel
				committed := sources.manifest()
				producers.Add(1)
				go func(epoch uint64) {
					defer producers.Done()
					result := stageCandidate(reloadCtx, opts, sources.resolver, epoch, committed)
					select {
					case results <- result:
					case <-producerCtx.Done():
					}
				}(requestEpoch)
			}
		case metricsErr := <-publication.metricsErrors():
			if metricsErr != nil {
				publication.health.Store(false)
				publication.logger.Error("metrics listener failed", "error", metricsErr)
				return errors.Join(metricsErr, stopService())
			}
		case result := <-results:
			if !engine.current(result.candidate) {
				continue
			}
			if result.candidate.refresh != 0 && sources.refreshCancel != nil {
				sources.refreshCancel()
				sources.refreshCancel = nil
			}
			if result.err != nil {
				publication.logger.Warn("candidate resolution failed", "error", result.err, "refresh", result.candidate.refresh != 0, "snapshot_age", sources.age())
				continue
			}
			if recovering || publication.pending() {
				continue
			}
			if err := publication.reserve(result); err != nil {
				publication.logger.Warn("reload failed", "error", err)
				continue
			}
			outcome, applyErr := engine.Apply(runCtx, result.candidate)
			if applyErr != nil && !outcome.Committed {
				if outcome.Degraded && outcome.Transaction != "" {
					if err := publication.retain(outcome.Transaction); err != nil {
						_ = publication.discard()
						publication.logger.Warn("reload failed", "error", err)
						continue
					}
					scheduleRecovery()
				} else {
					_ = publication.discard()
					publication.logger.Warn("reload failed", "error", applyErr)
					if !engine.Healthy() {
						scheduleRecovery()
					}
				}
				continue
			}
			if !outcome.Committed {
				_ = publication.discard()
				publication.logger.Warn("reload produced no committed revision")
				continue
			}
			if err := publication.publish(outcome.Active); err != nil {
				return errors.Join(err, stopService())
			}
			if outcome.Degraded || !engine.Healthy() {
				scheduleRecovery()
			}
		case <-recoveryC:
			recoveryTimer = nil
			recovered, recoverErr := engine.Recover(runCtx)
			if recoverErr != nil {
				publication.logger.Warn("firewall recovery failed", "error", recoverErr)
				if runCtx.Err() == nil {
					recoveryTimer = time.NewTimer(recoveryBackoff)
					if recoveryBackoff < 30*time.Second {
						recoveryBackoff *= 2
						if recoveryBackoff > 30*time.Second {
							recoveryBackoff = 30 * time.Second
						}
					}
				}
				continue
			}
			if err := publication.recover(recovered); err != nil {
				return errors.Join(err, stopService())
			}
			recovering = false
			publication.logger.Info("firewall recovery completed")
		}
	}
}

// Cleanup removes only recorded owned artifacts and never reads the current
// YAML configuration. It uses the same lifecycle lock as Run.
func Cleanup(ctx context.Context, options Options) error {
	if ctx == nil {
		ctx = context.Background()
	}
	opts := normalizeOptions(options)
	lock, err := state.AcquireLock(opts.LockPath)
	if err != nil {
		return err
	}
	defer func() { _ = lock.Close() }()
	store, err := state.Open(opts.StateDir, opts.Checkpoint)
	if err != nil {
		return err
	}
	engine := NewEngine(store, opts.Backend, opts.Checkpoint)
	defer engine.Close()
	if err := engine.Cleanup(ctx); err != nil {
		return err
	}
	return collectPrefixes(store)
}

type stageResult struct {
	candidate  Candidate
	cfg        config.Config
	logger     *slog.Logger
	err        error
	refreshErr error
}

func stageCandidate(ctx context.Context, opts Options, resolver *source.Resolver, epoch uint64, committed string) stageResult {
	cfg, err := config.Load(opts.ConfigPath)
	if err != nil {
		return stageResult{candidate: Candidate{epoch: epoch}, err: fmt.Errorf("load configuration: %w", err)}
	}
	if err := firewall.ValidateConfig(cfg); err != nil {
		return stageResult{candidate: Candidate{epoch: epoch}, err: fmt.Errorf("runtime configuration: %w", err)}
	}
	return stageSource(ctx, opts, resolver, epoch, 0, cfg, committed)
}

func recoverUntilReady(ctx context.Context, engine *Engine, failed func(error)) (*state.Revision, error) {
	backoff := time.Second
	for {
		recovered, err := engine.Recover(ctx)
		if err == nil {
			return recovered, nil
		}
		if failed != nil {
			failed(err)
		}
		if ctx.Err() != nil {
			return nil, errors.Join(err, ctx.Err())
		}
		timer := time.NewTimer(backoff)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				<-timer.C
			}
			return nil, errors.Join(err, ctx.Err())
		case <-timer.C:
		}
		if backoff < 30*time.Second {
			backoff *= 2
			if backoff > 30*time.Second {
				backoff = 30 * time.Second
			}
		}
	}
}

func bridgeSignals(input <-chan os.Signal, output chan<- os.Signal, cancel context.CancelFunc, stop <-chan struct{}, done chan<- struct{}) {
	defer close(done)
	defer close(output)
	for {
		select {
		case <-stop:
			return
		case sig, ok := <-input:
			if !ok {
				return
			}
			if sig == syscall.SIGTERM || sig == syscall.SIGINT {
				cancel()
			}
			select {
			case output <- sig:
			case <-stop:
				return
			default:
				// Signal delivery is edge-triggered; a full buffer is a
				// coalescing point while startup work is running.
			}
		}
	}
}

func runtimeSignals(provided <-chan os.Signal) (<-chan os.Signal, func()) {
	if provided != nil {
		return provided, func() {}
	}
	ch := make(chan os.Signal, 8)
	signal.Notify(ch, syscall.SIGHUP, syscall.SIGTERM, syscall.SIGINT)
	return ch, func() { signal.Stop(ch) }
}

func newLogger(cfg config.Config, output io.Writer) *slog.Logger {
	level := slog.LevelInfo
	switch cfg.Logging.Level {
	case "debug":
		level = slog.LevelDebug
	case "warn":
		level = slog.LevelWarn
	case "error":
		level = slog.LevelError
	}
	opts := &slog.HandlerOptions{Level: level}
	if cfg.Logging.Format == "text" {
		return slog.New(slog.NewTextHandler(output, opts))
	}
	return slog.New(slog.NewJSONHandler(output, opts))
}
