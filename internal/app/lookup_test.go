package app

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/lookup"
)

type blockingLookupBackend struct {
	recordingBackend
	entered chan struct{}
	release chan struct{}
	once    sync.Once
}

func (b *blockingLookupBackend) Apply(ctx context.Context, previous, candidate *firewall.Target, dynamic *firewall.DynamicState) error {
	b.once.Do(func() { close(b.entered) })
	select {
	case <-b.release:
	case <-ctx.Done():
		return ctx.Err()
	}
	return b.recordingBackend.Apply(ctx, previous, candidate, dynamic)
}

func TestEngineLookupPublishesConfirmedEmptyState(t *testing.T) {
	engine, _ := newTestEngine(t, &recordingBackend{}, nil)
	defer engine.Close()

	response := engine.Lookup(context.Background(), lookup.Request{Address: "192.0.2.1"})
	if response.Verdict != "not_blocked" || response.Error != nil || len(response.Outcomes) == 0 || response.Outcomes[0].Stage != "not_managed" {
		t.Fatalf("empty lookup = %#v, want complete not_blocked with not_managed outcome", response)
	}
}

func TestEngineLookupDoesNotWaitBehindNativeApply(t *testing.T) {
	backend := &blockingLookupBackend{entered: make(chan struct{}), release: make(chan struct{})}
	engine, _ := newTestEngine(t, backend, nil)
	defer engine.Close()

	candidate := admitCandidate(t, engine, parseEngineConfig(t, "192.0.2.0/24"))
	applyCtx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan Outcome, 1)
	go func() {
		outcome, _ := engine.Apply(applyCtx, candidate)
		result <- outcome
	}()
	select {
	case <-backend.entered:
	case <-time.After(time.Second):
		t.Fatal("native apply did not start")
	}
	response := engine.Lookup(context.Background(), lookup.Request{Address: "192.0.2.1"})
	if response.Verdict != "unknown" {
		t.Fatalf("lookup during native apply = %#v, want unknown", response)
	}
	close(backend.release)
	select {
	case outcome := <-result:
		if !outcome.Committed {
			t.Fatalf("blocked native apply did not commit: %#v", outcome)
		}
	case <-time.After(time.Second):
		t.Fatal("native apply did not finish after release")
	}
}

func TestEngineLookupRetriesDynamicPublicationFromStaticBase(t *testing.T) {
	engine, _ := newTestEngine(t, &recordingBackend{}, nil)
	defer engine.Close()

	candidate := admitCandidate(t, engine, parseEngineConfig(t, "192.0.2.0/24"))
	outcome, err := engine.Apply(context.Background(), candidate)
	if err != nil || !outcome.Committed {
		t.Fatalf("initial apply = %#v, err=%v", outcome, err)
	}
	before := engine.Lookup(context.Background(), lookup.Request{Address: "192.0.2.1"})
	if before.Verdict != "blocked" {
		t.Fatalf("initial lookup = %#v, want blocked", before)
	}

	engine.mu.Lock()
	engine.abortLookupLocked()
	engine.publishDynamicLookupLocked(&crowdState{epoch: 9, leaseOperation: 4}, before.Revision, before.Manifest)
	engine.mu.Unlock()
	after := engine.Lookup(context.Background(), lookup.Request{Address: "192.0.2.1"})
	if after.Verdict != "blocked" || after.Revision != before.Revision || after.DynamicEpoch != 9 || after.DynamicOperation != 4 {
		t.Fatalf("retried dynamic publication = %#v, want old static revision with new dynamic identity", after)
	}
}

func TestEngineLookupDoesNotRepublishStaticBaseAcrossRevisionChange(t *testing.T) {
	engine, _ := newTestEngine(t, &recordingBackend{}, nil)
	defer engine.Close()

	candidate := admitCandidate(t, engine, parseEngineConfig(t, "192.0.2.0/24"))
	outcome, err := engine.Apply(context.Background(), candidate)
	if err != nil || !outcome.Committed {
		t.Fatalf("initial apply = %#v, err=%v", outcome, err)
	}

	engine.mu.Lock()
	engine.abortLookupLocked()
	engine.publishDynamicLookupLocked(&crowdState{epoch: 10, leaseOperation: 5}, "different-revision", "")
	engine.mu.Unlock()
	response := engine.Lookup(context.Background(), lookup.Request{Address: "192.0.2.1"})
	if response.Verdict != "unknown" {
		t.Fatalf("lookup across revision mismatch = %#v, want unknown", response)
	}
}

func TestEngineLookupRestoresPreviousViewAfterSafeCompensation(t *testing.T) {
	backend := &recordingBackend{}
	engine, _ := newTestEngine(t, backend, nil)
	defer engine.Close()

	first := admitCandidate(t, engine, parseEngineConfig(t, "192.0.2.0/24"))
	committed, err := engine.Apply(context.Background(), first)
	if err != nil || !committed.Committed {
		t.Fatalf("initial apply = %#v, err=%v", committed, err)
	}
	before := engine.Lookup(context.Background(), lookup.Request{Address: "192.0.2.10"})
	if before.Verdict != "blocked" {
		t.Fatalf("initial lookup = %#v, want blocked", before)
	}

	backend.mu.Lock()
	backend.applyFailures = 1
	backend.applyErr = errors.New("injected apply failure")
	backend.mu.Unlock()
	second := admitCandidate(t, engine, parseEngineConfig(t, "198.51.100.0/24"))
	outcome, err := engine.Apply(context.Background(), second)
	if err == nil || outcome.Committed || outcome.Degraded {
		t.Fatalf("compensated apply = %#v, err=%v", outcome, err)
	}
	after := engine.Lookup(context.Background(), lookup.Request{Address: "192.0.2.10"})
	if after.Verdict != "blocked" || after.Revision != before.Revision {
		t.Fatalf("restored lookup = %#v, want old blocked revision %q", after, before.Revision)
	}
}

func TestEngineLookupIsUnknownAfterUncertainJournalPreparation(t *testing.T) {
	engine, _ := newTestEngine(t, &recordingBackend{}, func(point string) error {
		if point == "journal:after-rename" {
			return errors.New("injected uncertain journal publication")
		}
		return nil
	})
	defer engine.Close()
	candidate := admitCandidate(t, engine, parseEngineConfig(t, "192.0.2.0/24"))
	outcome, err := engine.Apply(context.Background(), candidate)
	if err == nil || !outcome.Degraded {
		t.Fatalf("uncertain preparation = %#v, err=%v", outcome, err)
	}
	response := engine.Lookup(context.Background(), lookup.Request{Address: "192.0.2.1"})
	if response.Verdict != "unknown" || response.Error == nil || len(response.Outcomes) != 0 {
		t.Fatalf("uncertain durable state returned a definitive answer: %#v", response)
	}
}
