package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	crowd "github.com/perimeterd/perimeterd/internal/crowdsec"
	"github.com/perimeterd/perimeterd/internal/firewall"
	metricspkg "github.com/perimeterd/perimeterd/internal/metrics"
	"github.com/perimeterd/perimeterd/internal/policy"
)

type crowdWriteEvent struct {
	projection []policy.TimedPrefix
	err        error
}

type crowdBackend struct {
	recordingBackend
	dynamicMu   sync.Mutex
	containers  map[string][]policy.TimedPrefix
	current     string
	writes      int
	failWrites  int
	engine      *Engine
	writeEvents chan crowdWriteEvent
}

func (b *crowdBackend) Apply(ctx context.Context, previous, candidate *firewall.Target, dynamic *firewall.DynamicState) error {
	if err := b.recordingBackend.Apply(ctx, previous, candidate, dynamic); err != nil {
		return err
	}
	b.dynamicMu.Lock()
	defer b.dynamicMu.Unlock()
	if candidate == nil {
		b.current = ""
		return nil
	}
	b.current = candidate.DynamicGeneration
	if dynamic != nil {
		b.containers[b.current] = append([]policy.TimedPrefix(nil), dynamic.Prefixes...)
	}
	return nil
}

func (b *crowdBackend) UpdateDynamic(_ context.Context, target *firewall.Target, projection []policy.TimedPrefix) error {
	b.dynamicMu.Lock()
	b.writes++
	b.containers[target.DynamicGeneration] = append([]policy.TimedPrefix(nil), projection...)
	var err error
	if b.failWrites > 0 {
		b.failWrites--
		err = errors.New("injected partial dynamic apply")
	}
	event := crowdWriteEvent{
		projection: append([]policy.TimedPrefix(nil), projection...),
		err:        err,
	}
	b.dynamicMu.Unlock()
	b.writeEvents <- event
	return err
}

func (b *crowdBackend) writeCount() int {
	b.dynamicMu.Lock()
	defer b.dynamicMu.Unlock()
	return b.writes
}

func (b *crowdBackend) selectedProjection() []policy.TimedPrefix {
	b.dynamicMu.Lock()
	defer b.dynamicMu.Unlock()
	return append([]policy.TimedPrefix(nil), b.containers[b.current]...)
}

func waitCrowdWrite(t *testing.T, backend *crowdBackend, timeout time.Duration, want func(crowdWriteEvent) bool) crowdWriteEvent {
	t.Helper()
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	for {
		select {
		case event := <-backend.writeEvents:
			backend.engine.mu.Lock()
			matched := want(event)
			backend.engine.mu.Unlock()
			if matched {
				return event
			}
		case <-timer.C:
			t.Fatal("timed out waiting for CrowdSec backend write")
			return crowdWriteEvent{}
		}
	}
}

func crowdEngineFixture(t *testing.T, checkpoint func(string) error) (*Engine, *crowdBackend, config.Config) {
	t.Helper()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Api-Key") != "retained-key" {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		if r.URL.Query().Get("startup") != "true" {
			_, _ = w.Write([]byte(`{"new":[],"deleted":[]}`))
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"new": []any{map[string]any{"id": 1, "type": "ban", "scope": "ip", "value": "198.51.100.9", "until": time.Now().Add(49 * time.Hour).UTC().Format(time.RFC3339Nano)}}, "deleted": nil})
	}))
	t.Cleanup(server.Close)
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte("retained-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := parseEngineConfig(t, "203.0.113.1")
	cfg.CrowdSec = config.CrowdSecConfig{Enabled: true, LAPIURL: server.URL, APIKeyFile: key, UpdateFrequency: time.Hour}
	backend := &crowdBackend{
		containers:  make(map[string][]policy.TimedPrefix),
		writeEvents: make(chan crowdWriteEvent, 32),
	}
	engine, _ := newTestEngine(t, backend, checkpoint)
	backend.engine = engine
	t.Cleanup(engine.Close)
	outcome, err := engine.Apply(context.Background(), admitCandidate(t, engine, cfg))
	if err != nil || !outcome.Committed {
		t.Fatalf("startup apply: %#v, %v", outcome, err)
	}
	return engine, backend, cfg
}

func TestCrowdDecisionMetricsExpireWhileEngineDegraded(t *testing.T) {
	engine, backend, _ := crowdEngineFixture(t, nil)
	engine.mu.Lock()
	defer engine.mu.Unlock()
	collector := metricspkg.New("test", "commit", "time")
	engine.telemetry = collector
	now := time.Now()
	engine.crowd.publishDecisionCountsLocked(now)
	scrape := func() string {
		response := httptest.NewRecorder()
		collector.Handler(nil, nil, nil).ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/metrics", nil))
		return response.Body.String()
	}
	if body := scrape(); !strings.Contains(body, `perimeterd_crowdsec_decisions{family="ipv4"} 1`) {
		t.Fatalf("active decision is absent before expiry: %s", body)
	}
	engine.healthy.Store(false)
	writes := backend.writeCount()
	engine.crowd.maintainLocked(context.Background(), engine.crowd.active, now.Add(50*time.Hour))
	if body := scrape(); !strings.Contains(body, `perimeterd_crowdsec_decisions{family="ipv4"} 0`) {
		t.Fatalf("expired decision remains exposed during degraded recovery: %s", body)
	}
	if backend.writeCount() != writes {
		t.Fatal("expiry bypassed degraded writer admission")
	}
}

func TestCrowdReloadFailureRetainsCredentialAndAuthority(t *testing.T) {
	engine, backend, cfg := crowdEngineFixture(t, nil)
	engine.mu.Lock()
	oldEpoch := engine.crowd.active.epoch
	engine.mu.Unlock()
	if err := os.WriteFile(cfg.CrowdSec.APIKeyFile, []byte("rejected-rotation"), 0o600); err != nil {
		t.Fatal(err)
	}
	outcome, err := engine.Apply(context.Background(), admitCandidate(t, engine, cfg))
	if err == nil || outcome.Committed {
		t.Fatalf("invalid same-path rotation accepted: %#v, %v", outcome, err)
	}
	event := waitCrowdWrite(t, backend, 3*time.Second, func(event crowdWriteEvent) bool {
		return event.err == nil && len(event.projection) == 1 &&
			event.projection[0].Prefix == netip.MustParsePrefix("198.51.100.9/32")
	})
	engine.mu.Lock()
	resynchronized := engine.crowd.active.epoch > oldEpoch
	engine.mu.Unlock()
	if !resynchronized {
		t.Fatal("retained credential did not complete a replacement full synchronization")
	}
	if len(event.projection) != 1 || event.projection[0].Prefix.String() != "198.51.100.9/32" {
		t.Fatalf("old authority lost: %v", event.projection)
	}
	if projection := backend.selectedProjection(); len(projection) != 1 || projection[0].Prefix.String() != "198.51.100.9/32" {
		t.Fatalf("old authority lost from selected container: %v", projection)
	}
}

func TestCrowdReconnectWriteFailureWakesEmptyStoreRetry(t *testing.T) {
	var reconnect atomic.Bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !reconnect.Load() {
			_, _ = w.Write([]byte(`{"new":[],"deleted":[]}`))
			return
		}
		if r.URL.Query().Get("startup") != "true" {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"new": []any{map[string]any{
			"id": 1, "type": "ban", "scope": "ip", "value": "198.51.100.9", "duration": "1h",
		}}, "deleted": nil})
	}))
	defer server.Close()
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte("test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := parseEngineConfig(t, "203.0.113.1")
	cfg.CrowdSec = config.CrowdSecConfig{Enabled: true, LAPIURL: server.URL, APIKeyFile: key, UpdateFrequency: 10 * time.Millisecond}
	backend := &crowdBackend{
		containers:  make(map[string][]policy.TimedPrefix),
		writeEvents: make(chan crowdWriteEvent, 32),
	}
	engine, _ := newTestEngine(t, backend, nil)
	backend.engine = engine
	defer engine.Close()
	if outcome, err := engine.Apply(context.Background(), admitCandidate(t, engine, cfg)); err != nil || !outcome.Committed {
		t.Fatalf("initial apply: %#v, %v", outcome, err)
	}
	backend.dynamicMu.Lock()
	backend.failWrites = 2
	backend.dynamicMu.Unlock()
	reconnect.Store(true)
	expected := netip.MustParsePrefix("198.51.100.9/32")
	failures := 0
	var final crowdWriteEvent
	waitCrowdWrite(t, backend, 8*time.Second, func(event crowdWriteEvent) bool {
		if event.err != nil {
			failures++
		} else if len(event.projection) == 1 && event.projection[0].Prefix == expected {
			final = event
		}
		return failures >= 2 && len(final.projection) == 1
	})
	event := final
	if writes := backend.writeCount(); writes < 3 {
		t.Fatalf("reconnect did not retry after transient native failures: writes=%d", writes)
	}
	if !engine.Healthy() {
		t.Fatal("successful reconnect left enforcement unhealthy")
	}
	if projection := backend.selectedProjection(); len(projection) != 1 || projection[0].Prefix != expected {
		t.Fatalf("latest authority was not selected after retry: event=%v projection=%v", event.projection, projection)
	}
}

func TestCrowdTransactionSelectionKeepsMatchingAuthority(t *testing.T) {
	for _, phase := range []string{"after-prepare", "after-switch", "after-commit"} {
		t.Run(phase, func(t *testing.T) {
			armed := false
			engine, backend, cfg := crowdEngineFixture(t, func(at string) error {
				if armed && at == phase {
					armed = false
					return errors.New("injected transaction failure")
				}
				return nil
			})
			engine.mu.Lock()
			old := engine.crowd.active
			engine.mu.Unlock()
			cfg.CrowdSec.Enabled = false
			candidate := admitCandidate(t, engine, cfg)
			armed = true
			outcome, err := engine.Apply(context.Background(), candidate)
			if err == nil {
				t.Fatal("checkpoint did not fail")
			}
			engine.mu.Lock()
			active := engine.crowd.active
			engine.mu.Unlock()
			if phase == "after-commit" {
				if !outcome.Committed || active != nil || len(backend.selectedProjection()) != 0 {
					t.Fatalf("committed disable retained authority: %#v", outcome)
				}
			} else if outcome.Committed || active != old || len(backend.selectedProjection()) != 1 {
				t.Fatalf("rollback did not retain old authority: %#v", outcome)
			}
		})
	}
}

func TestCrowdRenewalAndFailedApplyUseCurrentStore(t *testing.T) {
	engine, backend, _ := crowdEngineFixture(t, nil)
	engine.mu.Lock()
	c := engine.crowd
	s := c.active
	due := s.renewAt
	if due.IsZero() || time.Until(due) < 11*time.Hour || time.Until(due) > 12*time.Hour {
		engine.mu.Unlock()
		t.Fatalf("renewal not scheduled at half lease: %v", due)
	}
	originalDeadline := s.store.Projection(time.Now())[0].Deadline
	pollDone := s.pollDone
	c.stopStateLocked(s, false)
	engine.mu.Unlock()
	if pollDone != nil {
		<-pollDone
	}
	c.workers.Wait()

	baseline := backend.writeCount()
	engine.mu.Lock()
	c.maintainLocked(context.Background(), s, due.Add(-time.Nanosecond))
	engine.mu.Unlock()
	if writes := backend.writeCount(); writes != baseline {
		t.Fatalf("lease renewed before its half-grant boundary: writes=%d baseline=%d", writes, baseline)
	}

	baseline = backend.writeCount()
	engine.mu.Lock()
	c.maintainLocked(context.Background(), s, due)
	engine.mu.Unlock()
	renewal := waitCrowdWrite(t, backend, 3*time.Second, func(event crowdWriteEvent) bool {
		return event.err == nil
	})
	if writes := backend.writeCount(); writes != baseline+1 {
		t.Fatalf("unchanged desired state did not receive one fresh acknowledged write: writes=%d baseline=%d", writes, baseline)
	}
	if len(renewal.projection) != 1 || !renewal.projection[0].Deadline.Equal(originalDeadline) {
		t.Fatalf("renewal rebased source expiry: %v", renewal.projection)
	}

	backend.dynamicMu.Lock()
	backend.failWrites = 1
	backend.dynamicMu.Unlock()
	baseline = backend.writeCount()
	engine.mu.Lock()
	err := c.reconcileLocked(context.Background(), s, false)
	engine.mu.Unlock()
	failed := waitCrowdWrite(t, backend, 3*time.Second, func(event crowdWriteEvent) bool {
		return event.err != nil
	})
	if err == nil {
		t.Fatal("partial write unexpectedly succeeded")
	}
	if writes := backend.writeCount(); writes != baseline+1 {
		t.Fatalf("failed native operation did not reach backend exactly once: writes=%d baseline=%d", writes, baseline)
	}
	if failed.err == nil || engine.Healthy() {
		t.Fatalf("failed native operation was acknowledged: event=%v healthy=%v", failed, engine.Healthy())
	}

	latest := netip.MustParsePrefix("203.0.113.128/25")
	engine.mu.Lock()
	s.sequence++
	if err := s.store.Apply(crowd.Batch{Deleted: []int64{1}, New: []crowd.Decision{{ID: 2, Prefix: latest, Deadline: originalDeadline}}}, s.sequence, time.Now()); err != nil {
		engine.mu.Unlock()
		t.Fatal(err)
	}
	engine.mu.Unlock()
	baseline = backend.writeCount()
	engine.mu.Lock()
	err = c.reconcileLocked(context.Background(), s, false)
	engine.mu.Unlock()
	retry := waitCrowdWrite(t, backend, 3*time.Second, func(event crowdWriteEvent) bool {
		return event.err == nil && len(event.projection) == 1 && event.projection[0].Prefix == latest
	})
	if err != nil {
		t.Fatal(err)
	}
	if writes := backend.writeCount(); writes != baseline+1 {
		t.Fatalf("latest authority retry made unexpected backend writes: writes=%d baseline=%d", writes, baseline)
	}
	if len(retry.projection) != 1 || retry.projection[0].Prefix != latest || !engine.Healthy() {
		t.Fatalf("retry replayed stale desired state: event=%v healthy=%v", retry.projection, engine.Healthy())
	}

	stale := &crowdState{epoch: s.epoch - 1, store: s.store}
	baseline = backend.writeCount()
	engine.mu.Lock()
	err = c.reconcileLocked(context.Background(), stale, false)
	engine.mu.Unlock()
	if !errors.Is(err, errStaleCandidate) || backend.writeCount() != baseline {
		t.Fatal("retired epoch reached backend")
	}
}

func TestCrowdUncertainCommitRetainsStagedAuthorityUntilRecovery(t *testing.T) {
	armed := false
	engine, backend, cfg := crowdEngineFixture(t, func(phase string) error {
		if armed && (phase == "active:after-dir-sync" || phase == "stabilize:before-file-sync") {
			return errors.New("injected durable publication uncertainty")
		}
		return nil
	})
	engine.mu.Lock()
	old := engine.crowd.active
	engine.mu.Unlock()
	candidate := admitCandidate(t, engine, cfg)
	armed = true
	outcome, err := engine.Apply(context.Background(), candidate)
	if err == nil || !outcome.Degraded || engine.Healthy() {
		t.Fatalf("uncertain commit was published: %#v, %v", outcome, err)
	}
	engine.mu.Lock()
	staged := engine.crowd.staged
	if staged == nil || staged == old || engine.crowd.active != old {
		engine.mu.Unlock()
		t.Fatal("uncertain transaction lost either authority store")
	}
	writes := backend.writeCount()
	engine.crowd.maintainLocked(context.Background(), old, old.renewAt)
	if backend.writeCount() != writes {
		engine.mu.Unlock()
		t.Fatal("renewal crossed a pending static transaction")
	}
	engine.mu.Unlock()
	armed = false
	if _, err := engine.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	engine.mu.Lock()
	selected := engine.crowd.active
	engine.mu.Unlock()
	if selected != staged || !engine.Healthy() || len(backend.selectedProjection()) != 1 {
		t.Fatal("recovery did not publish the durably selected CrowdSec epoch")
	}
}
