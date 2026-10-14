//go:build crowdsec

package crowdsec_test

import (
	"bufio"
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/crowdsec"
	"github.com/perimeterd/perimeterd/internal/testutil/crowdsecfixture"
)

func TestLargeLAPISnapshot(t *testing.T) {
	const key = "perimeterd-generated-large-stream-key"
	until := time.Now().Add(time.Hour).UTC().Truncate(time.Second)
	snapshot := crowdsecfixture.Snapshot{Count: crowdsecfixture.LargeCount, Until: until}
	var bytesSent atomic.Int64
	var requests atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		request := requests.Add(1)
		startup := "true"
		if request > 1 {
			startup = "false"
		}
		if r.URL.Path != "/prefix/v1/decisions/stream" || r.URL.Query().Get("startup") != startup || r.URL.Query().Get("scopes") != "ip,range" || r.URL.Query().Get("dedup") != "false" || r.Header.Get("X-Api-Key") != key {
			t.Error("unexpected authenticated stream request")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		fixture := snapshot
		if request > 1 {
			fixture.Count = 4
		}
		w.Header().Set("Content-Type", "application/json")
		buffer := bufio.NewWriterSize(w, 32<<10)
		n, err := io.Copy(buffer, fixture.Reader())
		if err == nil {
			err = buffer.Flush()
		}
		if err != nil {
			t.Errorf("write generated snapshot: %v", err)
		}
		bytesSent.Store(n)
	}))
	defer server.Close()
	keyPath := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(keyPath, []byte(key), 0o600); err != nil {
		t.Fatal(err)
	}
	client, err := crowdsec.NewClient(config.CrowdSecConfig{Enabled: true, LAPIURL: server.URL + "/prefix/", APIKeyFile: keyPath}, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	started := time.Now()
	batch, err := client.Poll(ctx, true)
	elapsed := time.Since(started)
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("large startup stream: %v", err)
	}
	if size := bytesSent.Load(); size < 100<<20 || size < 98_499_095 {
		t.Fatalf("fixture only %d bytes", size)
	}
	if !batch.Startup || len(batch.New) != snapshot.Count-1 || len(batch.Deleted) != 1 || batch.Deleted[0] != snapshot.DeletedID() {
		t.Fatalf("wrong batch: startup=%t new=%d deleted=%v", batch.Startup, len(batch.New), batch.Deleted)
	}
	for index, want := range []string{"198.51.100.77/32", "2001:db8::77/128", "198.51.100.0/24"} {
		decision := batch.New[index]
		if decision.ID != int64(index+1) || decision.Prefix != netip.MustParsePrefix(want) || !decision.Deadline.Equal(until) {
			t.Fatalf("normalized decision %d = %+v, want %s until %s", index, decision, want, until)
		}
	}
	if batch.New[3].ID != 5 || batch.New[len(batch.New)-1].ID != int64(snapshot.Count) {
		t.Fatal("expired ID 4 or final active ID mishandled")
	}
	t.Logf("generated snapshot bytes=%d elapsed=%s allocations=%d allocated-bytes=%d (includes HTTP server/generator; no retained envelope)", bytesSent.Load(), elapsed, after.Mallocs-before.Mallocs, after.TotalAlloc-before.TotalAlloc)
	if status, readErr := os.ReadFile("/proc/self/status"); readErr == nil {
		for _, line := range strings.Split(string(status), "\n") {
			if strings.HasPrefix(line, "VmHWM:") {
				t.Logf("process-wide peak RSS: %s", line)
			}
		}
	}
	delta, err := client.Poll(ctx, false)
	if err != nil {
		t.Fatal(err)
	}
	if delta.Startup || len(delta.New) != 4 || delta.New[3].ID != 4 || delta.New[3].Deadline.After(time.Now()) || len(delta.Deleted) != 1 {
		t.Fatalf("incremental expiration semantics: %+v", delta)
	}
}
