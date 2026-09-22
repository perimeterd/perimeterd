package app

import (
	"context"
	"errors"
	"io"
	"testing"

	"github.com/perimeterd/perimeterd/internal/source"
	"github.com/perimeterd/perimeterd/internal/upstream"
)

func TestStagedSessionSurvivesPublicationSelection(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		name := "committed"
		if uncertain {
			name = "recovered after uncertain commit"
		}
		t.Run(name, func(t *testing.T) {
			failCommit := uncertain
			commitUncertain := false
			engine, store := newTestEngine(t, &recordingBackend{}, func(phase string) error {
				if failCommit && phase == "active:after-dir-sync" {
					commitUncertain = true
					return errors.New("active directory durability unavailable")
				}
				if failCommit && commitUncertain && phase == "stabilize:before-file-sync" {
					return errors.New("active commit acknowledgement unavailable")
				}
				return nil
			})
			defer engine.Close()
			manager := upstream.NewManager()
			defer func() {
				if err := manager.Close(context.Background()); err != nil {
					t.Error(err)
				}
			}()
			session, err := manager.Load(context.Background(), nil)
			if err != nil {
				t.Fatal(err)
			}
			cfg := parseEngineConfig(t, "8.8.8.8/32")
			cfg.Metrics.Listen = ""
			epoch, err := engine.Admit()
			if err != nil {
				t.Fatal(err)
			}
			candidate, err := NewCandidate(epoch, "policy.yaml", cfg, source.Snapshot{})
			if err != nil {
				t.Fatal(err)
			}
			staged := &stagedCandidate{Candidate: candidate, session: session}
			defer staged.close()
			sources := newSourceRuntime(store.Prefixes(), nil)
			defer sources.close()
			logger := newLogger(cfg, io.Discard)
			publication := newRuntimePublication(engine, sources, logger)
			defer func() {
				if err := publication.close(); err != nil {
					t.Error(err)
				}
			}()
			if err := publication.reserve(stageResult{candidate: staged, logger: logger}); err != nil {
				t.Fatal(err)
			}
			outcome, applyErr := engine.applyStaged(context.Background(), staged)
			if retained := session.Retain(); retained != nil {
				retained.Close()
				t.Fatal("application did not consume its staging session")
			}
			if uncertain {
				if applyErr == nil || !outcome.Degraded || outcome.Transaction == "" {
					t.Fatalf("expected uncertain apply: %+v, %v", outcome, applyErr)
				}
				if err := publication.retain(outcome.Transaction); err != nil {
					t.Fatal(err)
				}
				failCommit = false
				active, err := engine.Recover(context.Background())
				if err != nil || active == nil || active.ID != outcome.Transaction {
					t.Fatalf("recover selected candidate: %+v, %v", active, err)
				}
				if err := publication.recover(active); err != nil {
					t.Fatal(err)
				}
			} else {
				if applyErr != nil || !outcome.Committed {
					t.Fatalf("apply candidate: %+v, %v", outcome, applyErr)
				}
				if err := publication.publish(outcome.Active); err != nil {
					t.Fatal(err)
				}
			}
			selected := sources.retainSession()
			if selected == nil {
				t.Fatal("selected source lost its independently owned session")
			}
			selected.Close()
		})
	}
}

func TestRejectedStagedApplyReleasesSession(t *testing.T) {
	engine, _ := newTestEngine(t, &recordingBackend{}, nil)
	defer engine.Close()
	manager := upstream.NewManager()
	defer func() {
		if err := manager.Close(context.Background()); err != nil {
			t.Error(err)
		}
	}()
	session, err := manager.Load(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	candidate := &stagedCandidate{session: session}
	defer candidate.close()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := engine.applyStaged(ctx, candidate); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled staging was not rejected: %v", err)
	}
	if retained := session.Retain(); retained != nil {
		retained.Close()
		t.Fatal("rejected apply retained its staging session")
	}
}
