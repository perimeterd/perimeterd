package crowdsec

import (
	"context"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/testutil/crowdsecfixture"
)

const (
	benchmarkBaselineDecisions = 1
	benchmarkLargeDecisions    = 250_000
	benchmarkCombinedDecisions = 100_000
)

type benchmarkRoundTripper struct {
	snapshot crowdsecfixture.Snapshot
}

func (t benchmarkRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(t.snapshot.Reader()),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func benchmarkClient(b *testing.B, snapshot crowdsecfixture.Snapshot) *Client {
	b.Helper()
	keyPath := b.TempDir() + "/lapi-key"
	if err := os.WriteFile(keyPath, []byte("benchmark-key"), 0o600); err != nil {
		b.Fatal(err)
	}
	client, err := NewClient(config.CrowdSecConfig{Enabled: true, LAPIURL: "http://lapi.example", APIKeyFile: keyPath}, benchmarkRoundTripper{snapshot: snapshot})
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(client.Close)
	return client
}

func reportPeakRSS(b *testing.B) {
	b.Helper()
	data, err := os.ReadFile("/proc/self/status")
	if err != nil {
		return
	}
	for _, line := range strings.Split(string(data), "\n") {
		if !strings.HasPrefix(line, "VmHWM:") {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) >= 2 {
			value, parseErr := strconv.ParseInt(fields[1], 10, 64)
			if parseErr == nil {
				b.ReportMetric(float64(value*1024), "peak-rss-bytes")
			}
		}
		return
	}
}

func BenchmarkLAPISnapshotAdmission(b *testing.B) {
	for _, profile := range []struct {
		name  string
		count int
	}{
		{name: "baseline", count: benchmarkBaselineDecisions},
		{name: "large-250k", count: benchmarkLargeDecisions},
		{name: "large-100MiB", count: crowdsecfixture.LargeCount},
	} {
		b.Run(profile.name, func(b *testing.B) {
			snapshot := crowdsecfixture.Snapshot{Count: profile.count, Until: time.Now().Add(24 * time.Hour)}
			size, err := io.Copy(io.Discard, snapshot.Reader())
			if err != nil {
				b.Fatal(err)
			}
			client := benchmarkClient(b, snapshot)
			// Generator CPU and small per-record allocations are included; no
			// serialized fixture is retained. VmHWM is process-wide, not a delta.
			b.ReportAllocs()
			b.ResetTimer()
			for range b.N {
				batch, err := client.Poll(context.Background(), true)
				if err != nil {
					b.Fatalf("snapshot admission: %v", err)
				}
				want := profile.count
				if want >= 4 {
					want-- // ID 4 is already expired.
				}
				if len(batch.New) != want || len(batch.Deleted) != 1 {
					b.Fatalf("admitted %d new/%d deleted decisions, want %d/1", len(batch.New), len(batch.Deleted), want)
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(size), "input-bytes/op")
			b.ReportMetric(float64(profile.count), "decisions/op")
			b.ReportMetric(1, "admitted/op")
			reportPeakRSS(b)
		})
	}
}

func benchmarkBatch(count int, deadline time.Time) Batch {
	decisions := make([]Decision, count)
	for index := range decisions {
		address := netip.AddrFrom4([4]byte{100, byte(index >> 16), byte(index >> 8), byte(index)})
		decisions[index] = Decision{ID: int64(index + 1), Prefix: netip.PrefixFrom(address, 32), Deadline: deadline}
	}
	return Batch{Startup: true, New: decisions}
}

// BenchmarkAuthorityProjection measures only source authority admission and
// timed projection. Native reconciliation is measured by the app benchmark and
// by the opt-in isolated native harness; this benchmark never executes tools.
func BenchmarkAuthorityProjection(b *testing.B) {
	for _, profile := range []struct {
		name  string
		count int
	}{
		{name: "baseline", count: benchmarkBaselineDecisions},
		{name: "large-100k", count: benchmarkCombinedDecisions},
	} {
		b.Run(profile.name, func(b *testing.B) {
			batch := benchmarkBatch(profile.count, time.Now().Add(time.Hour))
			b.ReportAllocs()
			b.ResetTimer()
			projected := 0
			for range b.N {
				store := NewStore("benchmark", 1)
				if err := store.Apply(batch, 1, time.Now()); err != nil {
					b.Fatal(err)
				}
				projected += len(store.Projection(time.Now()))
			}
			b.StopTimer()
			b.ReportMetric(float64(profile.count), "decisions/op")
			b.ReportMetric(float64(projected)/float64(b.N), "projected-prefixes/op")
			reportPeakRSS(b)
		})
	}
}

// BenchmarkCrowdSecReconnectRenewalRefresh measures authority-only reconnect,
// unchanged renewal projection, and a source refresh. Native activation and
// dynamic reconciliation are intentionally outside this control-plane bench.
func BenchmarkCrowdSecReconnectRenewalRefresh(b *testing.B) {
	for _, profile := range []struct {
		name  string
		count int
	}{
		{name: "baseline", count: benchmarkBaselineDecisions},
		{name: "large-100k", count: benchmarkCombinedDecisions},
	} {
		b.Run(profile.name, func(b *testing.B) {
			deadline := time.Now().Add(time.Hour)
			startup := benchmarkBatch(profile.count, deadline)
			refresh := benchmarkBatch(profile.count, deadline.Add(time.Minute))
			refresh.Startup = false
			b.ReportAllocs()
			b.ResetTimer()
			cold, renewal, refreshed := 0, 0, 0
			for index := range b.N {
				// Cold reconnect admits the authoritative startup snapshot.
				reconnected := NewStore("benchmark", uint64(index+1))
				if err := reconnected.Apply(startup, 1, time.Now()); err != nil {
					b.Fatal(err)
				}
				cold += len(reconnected.Projection(time.Now()))
				// Renewal preserves the exact source decisions and deadlines.
				renewal += len(reconnected.Projection(time.Now()))
				// A refresh changes source deadlines and reprojects the authority.
				if err := reconnected.Apply(refresh, 2, time.Now()); err != nil {
					b.Fatal(err)
				}
				refreshed += len(reconnected.Projection(time.Now()))
			}
			b.StopTimer()
			b.ReportMetric(float64(profile.count), "decisions/op")
			iterations := float64(b.N)
			b.ReportMetric(float64(cold)/iterations, "cold-reconnect-prefixes/op")
			b.ReportMetric(float64(renewal)/iterations, "renewal-prefixes/op")
			b.ReportMetric(float64(refreshed)/iterations, "refresh-prefixes/op")
			reportPeakRSS(b)
		})
	}
}
