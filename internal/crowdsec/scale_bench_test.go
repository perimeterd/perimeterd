package crowdsec

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
)

const (
	benchmarkBaselineDecisions = 1
	benchmarkLargeDecisions    = 250_000
	benchmarkCombinedDecisions = 100_000
)

// benchmarkDecision matches the fields emitted by models.Decision in the
// pinned CrowdSec SDK. No benchmark-only fields are added: the serialized
// input size must represent the real LAPI decision envelope.
type benchmarkDecision struct {
	Duration  string `json:"duration"`
	ID        int64  `json:"id"`
	Origin    string `json:"origin"`
	Scenario  string `json:"scenario"`
	Scope     string `json:"scope"`
	Simulated bool   `json:"simulated"`
	Type      string `json:"type"`
	Until     string `json:"until"`
	UUID      string `json:"uuid"`
	Value     string `json:"value"`
}

// benchmarkLAPIWire models the complete decision metadata emitted by a LAPI
// stream. The metadata is deliberately retained here: measuring a compact
// hand-written decision object would understate the stream safety boundary.
func benchmarkLAPIWire(count int) []byte {
	var out bytes.Buffer
	out.Grow(count*256 + 32)
	out.WriteString(`{"new":[`)
	until := time.Now().Add(24 * time.Hour).UTC().Format(time.RFC3339)
	for index := range count {
		if index != 0 {
			out.WriteByte(',')
		}
		address := netip.AddrFrom4([4]byte{198, byte(index >> 16), byte(index >> 8), byte(index)})
		decision := benchmarkDecision{
			Duration: "24h", ID: int64(index + 1), Origin: "cscli",
			Scenario: "crowdsecurity/http-probing", Scope: "Ip", Type: "ban", Until: until,
			UUID: fmt.Sprintf("00000000-0000-4000-8000-%012x", index+1), Value: address.String(),
		}
		encoded, err := json.Marshal(decision)
		if err != nil {
			panic(err)
		}
		out.Write(encoded)
	}
	out.WriteString(`],"deleted":[]}`)
	return out.Bytes()
}

type benchmarkRoundTripper struct {
	body []byte
}

func (t benchmarkRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	return &http.Response{
		StatusCode: http.StatusOK,
		Status:     "200 OK",
		Body:       io.NopCloser(bytes.NewReader(t.body)),
		Header:     make(http.Header),
		Request:    req,
	}, nil
}

func benchmarkClient(b *testing.B, body []byte) *Client {
	b.Helper()
	keyPath := b.TempDir() + "/lapi-key"
	if err := os.WriteFile(keyPath, []byte("benchmark-key"), 0o600); err != nil {
		b.Fatal(err)
	}
	client, err := NewClient(config.CrowdSecConfig{Enabled: true, LAPIURL: "http://lapi.example", APIKeyFile: keyPath}, benchmarkRoundTripper{body: body})
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
	} {
		b.Run(profile.name, func(b *testing.B) {
			body := benchmarkLAPIWire(profile.count)
			client := benchmarkClient(b, body)
			// Poll deliberately redacts SDK/transport errors. Observe the real
			// response gate so capacity rejection cannot hide an unrelated error.
			var admissionErr error
			httpClient := client.bouncer.APIClient.GetClient()
			transport := httpClient.Transport
			httpClient.Transport = roundTripFunc(func(request *http.Request) (*http.Response, error) {
				response, err := transport.RoundTrip(request)
				admissionErr = err
				return response, err
			})
			b.ReportAllocs()
			b.ResetTimer()
			admitted, rejected := 0, 0
			for range b.N {
				batch, err := client.Poll(context.Background(), true)
				if err != nil {
					if len(body) <= bodyLimit || admissionErr == nil || admissionErr.Error() != "crowdsec response body exceeded safety limits" {
						b.Fatalf("snapshot admission: %v (response gate: %v)", err, admissionErr)
					}
					rejected++
					continue
				}
				if len(batch.New) != profile.count {
					b.Fatalf("admitted %d decisions, want %d", len(batch.New), profile.count)
				}
				admitted++
			}
			b.StopTimer()
			b.ReportMetric(float64(len(body)), "input-bytes/op")
			b.ReportMetric(float64(profile.count), "decisions/op")
			iterations := float64(b.N)
			b.ReportMetric(float64(admitted)/iterations, "admitted/op")
			b.ReportMetric(float64(rejected)/iterations, "capacity-rejected/op")
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
