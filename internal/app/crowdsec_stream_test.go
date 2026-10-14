package app

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

type crowdDiagnosticWriter chan string

func (w crowdDiagnosticWriter) Write(p []byte) (int, error) {
	select {
	case w <- string(p):
	default:
	}
	return len(p), nil
}

func TestCrowdMalformedStreamCannotSelectPartialAuthority(t *testing.T) {
	const valid = `{"new":[{"id":1,"type":"ban","scope":"ip","value":"198.51.100.9","duration":"49h"}],"deleted":[]}`
	const malformed = `{"deleted":[{"id":1}],"new":[{"id":2,"type":"ban","scope":"ip","value":"198.51.100.10","duration":"49h","scenario":"SECRET-DECISION"}]` // No closing envelope.
	var body atomic.Value
	body.Store(malformed)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, body.Load().(string))
	}))
	defer server.Close()
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte("SECRET-API-KEY"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := parseEngineConfig(t, "203.0.113.1")
	cfg.CrowdSec = config.CrowdSecConfig{Enabled: true, LAPIURL: server.URL, APIKeyFile: key, UpdateFrequency: time.Hour}
	backend := &crowdBackend{containers: make(map[string][]policy.TimedPrefix), writeEvents: make(chan crowdWriteEvent, 32)}
	engine, store := newTestEngine(t, backend, nil)
	defer engine.Close()
	backend.engine = engine
	messages := make(crowdDiagnosticWriter, 16)
	engine.crowd.logger = slog.New(slog.NewTextHandler(messages, nil))
	outcome, err := engine.Apply(context.Background(), admitCandidate(t, engine, cfg))
	if err == nil || outcome.Committed || engine.crowd.active != nil || len(backend.selectedProjection()) != 0 {
		t.Fatalf("failed initial snapshot selected authority: %#v, %v", outcome, err)
	}
	view, readErr := store.Read()
	if readErr != nil || view.Active != nil {
		t.Fatalf("failed initial sync committed state: %+v, %v", view, readErr)
	}
	if !strings.Contains(err.Error(), "malformed") || strings.Contains(err.Error(), "SECRET") {
		t.Fatalf("initial sync diagnostic lost safe category: %v", err)
	}
	body.Store(valid)
	outcome, err = engine.Apply(context.Background(), admitCandidate(t, engine, cfg))
	if err != nil || !outcome.Committed {
		t.Fatalf("complete startup failed: %#v, %v", outcome, err)
	}
	engine.mu.Lock()
	epoch := engine.crowd.active.epoch
	operation := engine.crowd.active.leaseOperation
	engine.mu.Unlock()
	body.Store(malformed)
	failed, err := engine.Apply(context.Background(), admitCandidate(t, engine, cfg))
	if err == nil || failed.Committed || strings.Contains(err.Error(), "SECRET") || !strings.Contains(err.Error(), "malformed") {
		t.Fatalf("malformed reload not safely rejected: %#v, %v", failed, err)
	}
	// Rejected reload resumes the old client's full sync. Its failed poll must
	// log the category but cannot apply the deletion or new decision prefix.
	select {
	case message := <-messages:
		if !strings.Contains(message, "malformed") || strings.Contains(message, "SECRET") || strings.Contains(message, server.URL) {
			t.Fatalf("background diagnostic is unsafe or useless: %s", message)
		}
	case <-time.After(3 * time.Second):
		t.Fatal("failed background synchronization did not report its category")
	}
	engine.mu.Lock()
	active := engine.crowd.active
	unchanged := active != nil && active.epoch == epoch && active.leaseOperation == operation
	engine.mu.Unlock()
	projection := backend.selectedProjection()
	view, readErr = store.Read()
	if !unchanged || len(projection) != 1 || projection[0].Prefix != netip.MustParsePrefix("198.51.100.9/32") ||
		readErr != nil || view.Active == nil || view.Active.ID != outcome.Active.ID {
		t.Fatalf("failed stream replaced acknowledged state: epoch=%t projection=%v view=%+v err=%v", unchanged, projection, view, readErr)
	}
}
