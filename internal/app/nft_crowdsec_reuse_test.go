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
	"sync/atomic"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestSynchronizedNFTReloadReusesOnlyIdenticalAuthority(t *testing.T) {
	for _, name := range []string{"unchanged", "rollback", "rotated-key", "iptables"} {
		t.Run(name, func(t *testing.T) {
			var startups atomic.Int32
			until := time.Now().UTC().Add(time.Hour).Truncate(time.Second)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Query().Get("startup") != "true" {
					_, _ = w.Write([]byte(`{"new":[],"deleted":[]}`))
					return
				}
				request := startups.Add(1)
				if request > 2 {
					// A rejected candidate resumes the retained client with a full
					// sync. Keep it in flight while checking rollback's native state.
					<-r.Context().Done()
					return
				}
				prefix := "198.51.100.9"
				if request == 2 {
					prefix = "198.51.100.10"
				}
				_ = json.NewEncoder(w).Encode(map[string]any{"new": []any{map[string]any{"id": request, "type": "ban", "scope": "ip", "value": prefix, "until": until.Format(time.RFC3339)}}, "deleted": nil})
			}))
			t.Cleanup(server.Close)
			key := filepath.Join(t.TempDir(), "key")
			if err := os.WriteFile(key, []byte("key-a"), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg := parseEngineConfig(t, "203.0.113.1")
			if name == "iptables" {
				cfg.Firewall.Backend = "iptables"
			}
			cfg.CrowdSec = config.CrowdSecConfig{Enabled: true, LAPIURL: server.URL, APIKeyFile: key, UpdateFrequency: time.Hour}
			var armed atomic.Bool
			injected := errors.New("injected post-switch failure")
			backend := &crowdBackend{containers: make(map[string][]policy.TimedPrefix), writeEvents: make(chan crowdWriteEvent, 32)}
			engine, store := newTestEngine(t, backend, func(phase string) error {
				if phase == "after-switch" && armed.CompareAndSwap(true, false) {
					return injected
				}
				return nil
			})
			backend.engine = engine
			t.Cleanup(engine.Close)
			initial, err := engine.Apply(t.Context(), admitCandidate(t, engine, cfg))
			if err != nil || !initial.Committed {
				t.Fatalf("initial authority: %+v %v", initial, err)
			}
			if name == "rotated-key" {
				if err := os.WriteFile(key, []byte("key-b"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			armed.Store(name == "rollback")
			outcome, err := engine.Apply(context.Background(), admitCandidate(t, engine, cfg))
			if name == "rollback" {
				if !errors.Is(err, injected) || outcome.Committed {
					t.Fatalf("shared-container rollback: %+v %v", outcome, err)
				}
				projection := backend.selectedProjection()
				if len(projection) != 1 || projection[0].Prefix != netip.MustParsePrefix("198.51.100.9/32") || !projection[0].Deadline.Equal(until) {
					t.Fatalf("rollback did not restore previous absolute authority: %v", projection)
				}
				view, err := store.Read()
				if err != nil || view.Active.ID != initial.Active.ID || view.Journal != nil {
					t.Fatalf("rollback changed acknowledged revision: %+v %v", view, err)
				}
				return
			}
			if err != nil || !outcome.Committed || startups.Load() != 2 {
				t.Fatalf("reload omitted authoritative synchronization: %+v %v requests=%d", outcome, err, startups.Load())
			}
			if name == "unchanged" {
				if outcome.Active.Target.Generation != initial.Active.Target.Generation || outcome.Active.Target.DynamicGeneration != initial.Active.Target.DynamicGeneration {
					t.Fatal("unchanged direct nft authority needlessly replaced native identities")
				}
			} else if outcome.Active.Target.DynamicGeneration == initial.Active.Target.DynamicGeneration {
				t.Fatalf("credential replacement or non-nft behavior changed: %s", name)
			}
			projection := backend.selectedProjection()
			if len(projection) != 1 || projection[0].Prefix != netip.MustParsePrefix("198.51.100.10/32") || !projection[0].Deadline.Equal(until) {
				t.Fatalf("full synchronization did not atomically replace authority: %v", projection)
			}
		})
	}
}
