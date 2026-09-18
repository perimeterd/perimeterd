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
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	crowd "github.com/perimeterd/perimeterd/internal/crowdsec"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
)

type crowdBackend struct {
	recordingBackend
	dynamicMu  sync.Mutex
	containers map[string][]policy.TimedPrefix
	current    string
	writes     int
	failWrites int
}

func (b *crowdBackend) Apply(ctx context.Context, previous, candidate *firewall.Target) error {
	if err := b.recordingBackend.Apply(ctx, previous, candidate); err != nil {
		return err
	}
	b.dynamicMu.Lock()
	defer b.dynamicMu.Unlock()
	if candidate == nil {
		b.current = ""
		return nil
	}
	b.current = candidate.DynamicGeneration
	if candidate.Dynamic != nil {
		b.containers[b.current] = append([]policy.TimedPrefix(nil), candidate.Dynamic.Prefixes...)
	}
	return nil
}

func (b *crowdBackend) UpdateDynamic(_ context.Context, target *firewall.Target, projection []policy.TimedPrefix) error {
	b.dynamicMu.Lock()
	defer b.dynamicMu.Unlock()
	b.writes++
	b.containers[target.DynamicGeneration] = append([]policy.TimedPrefix(nil), projection...)
	if b.failWrites > 0 {
		b.failWrites--
		return errors.New("injected partial dynamic apply")
	}
	return nil
}

func (b *crowdBackend) selectedProjection() []policy.TimedPrefix {
	b.dynamicMu.Lock()
	defer b.dynamicMu.Unlock()
	return append([]policy.TimedPrefix(nil), b.containers[b.current]...)
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
	backend := &crowdBackend{containers: make(map[string][]policy.TimedPrefix)}
	engine, _ := newTestEngine(t, backend, checkpoint)
	t.Cleanup(engine.Close)
	outcome, err := engine.Apply(context.Background(), admitCandidate(t, engine, cfg))
	if err != nil || !outcome.Committed {
		t.Fatalf("startup apply: %#v, %v", outcome, err)
	}
	return engine, backend, cfg
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
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		engine.mu.Lock()
		resynchronized := engine.crowd.active.epoch > oldEpoch
		engine.mu.Unlock()
		if resynchronized {
			projection := backend.selectedProjection()
			if len(projection) != 1 || projection[0].Prefix.String() != "198.51.100.9/32" {
				t.Fatalf("old authority lost: %v", projection)
			}
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatal("retained credential did not complete a replacement full synchronization")
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
	backend := &crowdBackend{containers: make(map[string][]policy.TimedPrefix)}
	engine, _ := newTestEngine(t, backend, nil)
	defer engine.Close()
	if outcome, err := engine.Apply(context.Background(), admitCandidate(t, engine, cfg)); err != nil || !outcome.Committed {
		t.Fatalf("initial apply: %#v, %v", outcome, err)
	}
	// The empty store has no expiry or lease-renewal timer. Consume the
	// activation wake before failing a later reconnect and its compensation.
	deadline := time.Now().Add(3 * time.Second)
	for {
		engine.mu.Lock()
		pending := len(engine.crowd.active.wake)
		engine.mu.Unlock()
		if pending == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("empty-store worker did not consume its activation wake")
		}
		time.Sleep(time.Millisecond)
	}
	backend.dynamicMu.Lock()
	backend.failWrites = 2
	backend.dynamicMu.Unlock()
	reconnect.Store(true)
	expected := netip.MustParsePrefix("198.51.100.9/32")
	deadline = time.Now().Add(8 * time.Second)
	for time.Now().Before(deadline) {
		backend.dynamicMu.Lock()
		retried := backend.writes > 2
		backend.dynamicMu.Unlock()
		projection := backend.selectedProjection()
		if retried && engine.Healthy() && len(projection) == 1 && projection[0].Prefix == expected {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	backend.dynamicMu.Lock()
	writes := backend.writes
	backend.dynamicMu.Unlock()
	t.Fatalf("reconnect did not recover after transient native failures: writes=%d healthy=%v projection=%v", writes, engine.Healthy(), backend.selectedProjection())
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
	defer engine.mu.Unlock()
	c := engine.crowd
	s := c.active
	revision, watermark := s.store.Revision(), c.watermark
	due := s.renewAt
	if due.IsZero() || time.Until(due) < 11*time.Hour || time.Until(due) > 12*time.Hour {
		t.Fatalf("renewal not scheduled at half lease: %v", due)
	}
	originalDeadline := s.store.Projection(time.Now())[0].Deadline
	c.maintainLocked(context.Background(), s, due.Add(-time.Nanosecond))
	if c.watermark != watermark {
		t.Fatal("lease renewed before its half-grant boundary")
	}
	c.maintainLocked(context.Background(), s, due)
	if s.store.Revision() != revision || c.watermark <= watermark {
		t.Fatal("unchanged desired revision did not receive a fresh acknowledged operation")
	}
	if got := backend.selectedProjection()[0].Deadline; !got.Equal(originalDeadline) {
		t.Fatal("renewal rebased source expiry")
	}

	backend.failWrites = 1
	watermark = c.watermark
	if err := c.reconcileLocked(context.Background(), s); err == nil {
		t.Fatal("partial write unexpectedly succeeded")
	}
	if c.watermark != watermark || engine.Healthy() {
		t.Fatal("failed native operation was acknowledged")
	}
	s.sequence++
	latest := netip.MustParsePrefix("203.0.113.128/25")
	if err := s.store.Apply(crowd.Batch{Deleted: []int64{1}, New: []crowd.Decision{{ID: 2, Prefix: latest, Deadline: originalDeadline}}}, s.sequence, time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := c.reconcileLocked(context.Background(), s); err != nil {
		t.Fatal(err)
	}
	projection := backend.selectedProjection()
	if len(projection) != 1 || projection[0].Prefix != latest || !engine.Healthy() {
		t.Fatalf("retry replayed stale desired state: %v", projection)
	}
	stale := &crowdState{epoch: s.epoch - 1, store: s.store}
	writes := backend.writes
	target, err := c.targetLocked()
	if err != nil {
		t.Fatal(err)
	}
	if err := c.writeLocked(context.Background(), stale, target, false); !errors.Is(err, errStaleCandidate) || backend.writes != writes {
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
	writes := backend.writes
	engine.crowd.maintainLocked(context.Background(), old, old.renewAt)
	if backend.writes != writes {
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
