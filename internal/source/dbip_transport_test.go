package source

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

type dbipRoundTrip func(*http.Request) (*http.Response, error)

func (fn dbipRoundTrip) RoundTrip(req *http.Request) (*http.Response, error) { return fn(req) }
func dbipGzip(t *testing.T, body string) []byte {
	t.Helper()
	var b bytes.Buffer
	z := gzip.NewWriter(&b)
	if _, err := z.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := z.Close(); err != nil {
		t.Fatal(err)
	}
	return b.Bytes()
}

func dbipTestConfig() config.Config {
	return config.Config{Version: 1, Geo: config.GeoConfig{CountryProvider: config.CountryProviderDBIPLite, RequestTimeout: time.Second, RefreshInterval: time.Hour}, Firewall: config.FirewallConfig{Backend: "nftables", DenyAction: "drop", IPv4: true, IPv6: true}, Policies: []config.Policy{{Name: "test", Priority: 1, Direction: "ingress", Mode: "blocklist", Traffic: config.TrafficScope{Any: true}, Include: config.Selector{Countries: []string{"SK", "CZ"}}}}}
}

var dbipTestSelectors = []policy.Selector{{Kind: policy.Country, Value: "SK"}, {Kind: policy.Country, Value: "CZ"}}

const dbipTestCSV = "192.0.2.0,192.0.2.3,SK\n192.0.2.4,192.0.2.7,CZ\n2001:db8::,2001:db8::3,SK\n"

func TestDBIPTransportEnvelopesAndIntegrity(t *testing.T) {
	zipped := dbipGzip(t, dbipTestCSV)
	badChecksum := bytes.Clone(zipped)
	badChecksum[len(badChecksum)-8] ^= 1
	for _, test := range []struct {
		name             string
		body             []byte
		coding           string
		uncompressed, ok bool
	}{
		{"artifact", zipped, "", false, true},
		{"identity", zipped, "identity", false, true},
		{"gzip-coding", zipped, "gzip", false, true},
		{"transport-decoded", []byte(dbipTestCSV), "", true, true},
		{"remaining-artifact", zipped, "", true, true},
		{"raw-csv", []byte(dbipTestCSV), "", false, false},
		{"unsupported", zipped, "br", false, false},
		{"checksum", badChecksum, "", false, false},
		{"truncated", zipped[:len(zipped)-2], "", false, false},
		{"garbage", append(bytes.Clone(zipped), 'x'), "", false, false},
		{"extra-member", append(bytes.Clone(zipped), zipped...), "", false, false},
		{"nested", dbipGzip(t, string(zipped)), "gzip", false, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			closed := false
			resolver := NewResolver(nil, &http.Client{Transport: dbipRoundTrip(func(req *http.Request) (*http.Response, error) {
				if req.Header.Get("Accept-Encoding") != "identity" {
					t.Error("missing identity coding")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{"Content-Encoding": []string{test.coding}}, Uncompressed: test.uncompressed, Body: &dbipCloseReader{Reader: bytes.NewReader(test.body), closed: &closed}}, nil
			})})
			_, err := resolver.fetchDBIPAttempt(context.Background(), dbipTestConfig(), dbipTestSelectors, "2026-01")
			if (err == nil) != test.ok {
				t.Fatalf("error=%v, want valid=%v", err, test.ok)
			}
			if !closed {
				t.Error("body not closed")
			}
		})
	}
}

type dbipCloseReader struct {
	io.Reader
	closed *bool
}

func (r *dbipCloseReader) Close() error { *r.closed = true; return nil }

func TestDBIPMonthlyFallbackAndRetryBudget(t *testing.T) {
	zipped := dbipGzip(t, dbipTestCSV)
	for _, test := range []struct {
		name     string
		statuses []int
		months   []string
		ok       bool
	}{
		{"january-lag", []int{404, 200}, []string{"2026-01", "2025-12"}, true},
		{"only-one-previous", []int{404, 404}, []string{"2026-01", "2025-12"}, false},
		{"permanent", []int{403}, []string{"2026-01"}, false},
		{"partial", []int{206}, []string{"2026-01"}, false},
		{"transient", []int{503, 503, 200}, []string{"2026-01", "2026-01", "2026-01"}, true},
		{"exhausted", []int{503, 503, 503}, []string{"2026-01", "2026-01", "2026-01"}, false},
	} {
		t.Run(test.name, func(t *testing.T) {
			calls := 0
			observed := 0
			clockCalls := 0
			resolver := NewResolver(nil, &http.Client{Transport: dbipRoundTrip(func(req *http.Request) (*http.Response, error) {
				if calls >= len(test.statuses) {
					t.Fatalf("extra request %s", req.URL)
				}
				if req.URL.String() != dbipEndpoint(test.months[calls]) {
					t.Fatalf("request %s", req.URL)
				}
				status := test.statuses[calls]
				calls++
				return &http.Response{StatusCode: status, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(zipped))}, nil
			})}).WithClock(func() time.Time { clockCalls++; return time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC) }).WithRequestObserver(func(kind string, success bool) {
				observed++
				if kind != dbipSourceKind || success != test.ok {
					t.Errorf("observer=%s/%v", kind, success)
				}
			})
			records, err := resolver.fetchDBIP(context.Background(), dbipTestConfig(), dbipTestSelectors)
			if (err == nil) != test.ok || calls != len(test.statuses) || observed != 1 {
				t.Fatalf("err=%v calls=%d observed=%d", err, calls, observed)
			}
			if test.ok {
				for _, record := range records {
					if record.Release != test.months[len(test.months)-1] {
						t.Fatalf("release %s", record.Release)
					}
				}
				if clockCalls != 2 {
					t.Fatalf("clock calls=%d", clockCalls)
				}
			}
		})
	}
}

func TestDBIPSlotAdmissionTimeoutAndCancellation(t *testing.T) {
	var calls atomic.Int32
	resolver := NewResolver(nil, &http.Client{Transport: dbipRoundTrip(func(*http.Request) (*http.Response, error) {
		calls.Add(1)
		return nil, errors.New("unexpected request")
	})})
	for range maxConcurrent {
		resolver.slots <- struct{}{}
	}
	cfg := dbipTestConfig()
	cfg.Geo.RequestTimeout = time.Millisecond
	if _, err := resolver.fetchDBIPAttempt(context.Background(), cfg, dbipTestSelectors, "2026-01"); err == nil {
		t.Fatal("slot timeout ignored")
	}
	if calls.Load() != 0 {
		t.Fatal("request bypassed admission")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := resolver.fetchDBIP(ctx, cfg, dbipTestSelectors); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation=%v", err)
	}
}

func TestDBIPNoMonthFallbackOnInvalidDataOrSize(t *testing.T) {
	for name, body := range map[string][]byte{"invalid-csv": dbipGzip(t, "bad\n"), "invalid-gzip": []byte("not gzip"), "size": nil} {
		t.Run(name, func(t *testing.T) {
			calls := 0
			resolver := NewResolver(nil, &http.Client{Transport: dbipRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				length := int64(len(body))
				if name == "size" {
					length = dbipEncodedLimit + 1
				}
				return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: length, Body: io.NopCloser(bytes.NewReader(body))}, nil
			})})
			if _, err := resolver.fetchDBIP(context.Background(), dbipTestConfig(), dbipTestSelectors); err == nil {
				t.Fatal("accepted invalid data")
			}
			if calls != 1 {
				t.Fatalf("requests=%d", calls)
			}
		})
	}
}

func TestDBIPRejectsRedirectTrustBoundary(t *testing.T) {
	for _, target := range []string{"http://download.db-ip.com/free/other.gz", "https://other.example/free/db.gz"} {
		t.Run(target, func(t *testing.T) {
			calls := 0
			resolver := NewResolver(nil, &http.Client{Transport: dbipRoundTrip(func(*http.Request) (*http.Response, error) {
				calls++
				return &http.Response{StatusCode: 302, Header: http.Header{"Location": []string{target}}, Body: io.NopCloser(strings.NewReader(""))}, nil
			})})
			if _, err := resolver.fetchDBIP(context.Background(), dbipTestConfig(), dbipTestSelectors); err == nil {
				t.Fatal("accepted redirect")
			}
			if calls != 1 {
				t.Fatalf("redirect followed %d times", calls)
			}
		})
	}
}

func TestDBIPSelectsMonthInUTC(t *testing.T) {
	resolver := NewResolver(nil, &http.Client{Transport: dbipRoundTrip(func(req *http.Request) (*http.Response, error) {
		if req.URL.String() != dbipEndpoint("2026-02") {
			t.Fatalf("selected %s", req.URL)
		}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(dbipGzip(t, dbipTestCSV)))}, nil
	})}).WithClock(func() time.Time { return time.Date(2026, 1, 31, 23, 30, 0, 0, time.FixedZone("west", -3600)) })
	if _, err := resolver.fetchDBIP(context.Background(), dbipTestConfig(), dbipTestSelectors); err != nil {
		t.Fatal(err)
	}
}

// Produce more than 32MiB of valid decoded data without retaining a global
// fixture or prefix set. Every singleton is sorted and belongs to unused US.
type dbipLargeCSV struct {
	index, count int
	pending      []byte
	storage      [83]byte
}

func (r *dbipLargeCSV) Read(p []byte) (int, error) {
	if len(r.pending) == 0 {
		if r.index == r.count {
			return 0, io.EOF
		}
		r.pending = fmt.Appendf(r.storage[:0], "2001:0db8:0000:0000:0000:0000:%04x:%04x,2001:0db8:0000:0000:0000:0000:%04x:%04x,US\n", r.index>>16, r.index&65535, r.index>>16, r.index&65535)
		r.index++
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}

func TestDBIPAlreadyDecodedCSVUsesDecodedBudget(t *testing.T) {
	const rows = 420_000
	resolver := NewResolver(nil, &http.Client{Transport: dbipRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), Uncompressed: true, ContentLength: rows * 83, Body: io.NopCloser(&dbipLargeCSV{count: rows})}, nil
	})})
	cfg := dbipTestConfig()
	cfg.Geo.RequestTimeout = 30 * time.Second
	records, err := resolver.fetchDBIPAttempt(context.Background(), cfg, dbipTestSelectors, "2026-01")
	if err != nil {
		t.Fatal(err)
	}
	if len(records) != 2 || len(records[dbipTestSelectors[0]].IPv4) != 0 || len(records[dbipTestSelectors[0]].IPv6) != 0 {
		t.Fatal("unused data retained")
	}
}

func TestDBIPEncodedLimitWhileStreamingUnknownLength(t *testing.T) {
	file, err := os.CreateTemp(t.TempDir(), "artifact-*.gz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = file.Close() }()
	zipper, err := gzip.NewWriterLevel(file, gzip.NoCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.Copy(zipper, &dbipLargeCSV{count: 420_000}); err != nil {
		t.Fatal(err)
	}
	if err := zipper.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		t.Fatal(err)
	}
	resolver := NewResolver(nil, &http.Client{Transport: dbipRoundTrip(func(*http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 200, Header: make(http.Header), ContentLength: -1, Body: file}, nil
	})})
	cfg := dbipTestConfig()
	cfg.Geo.RequestTimeout = 30 * time.Second
	_, err = resolver.fetchDBIPAttempt(context.Background(), cfg, dbipTestSelectors, "2026-01")
	if err == nil {
		t.Fatal("accepted encoded artifact above 32MiB")
	}
	var retryable *retryableFetchError
	if errors.As(err, &retryable) {
		t.Fatalf("size rejection became retryable: %v", err)
	}
}

type dbipCancelReader struct {
	reader    io.Reader
	remaining int
	cancel    context.CancelFunc
}

func (r *dbipCancelReader) Read(p []byte) (int, error) {
	n, err := r.reader.Read(p)
	r.remaining--
	if r.remaining == 0 {
		r.cancel()
	}
	return n, err
}

func TestDBIPCancellationDuringParsingClosesBodyWithoutProvenance(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	closed := false
	resolver := NewResolver(nil, &http.Client{Transport: dbipRoundTrip(func(*http.Request) (*http.Response, error) {
		stream := &dbipCancelReader{reader: &dbipLargeCSV{count: 1000}, remaining: 100, cancel: cancel}
		return &http.Response{StatusCode: 200, Header: make(http.Header), Uncompressed: true, Body: &dbipCloseReader{Reader: stream, closed: &closed}}, nil
	})}).WithClock(func() time.Time {
		t.Error("retrieval timestamp captured before complete validation")
		return time.Now()
	})
	records, err := resolver.fetchDBIPAttempt(ctx, dbipTestConfig(), dbipTestSelectors, "2026-01")
	if !errors.Is(err, context.Canceled) || records != nil || !closed {
		t.Fatalf("records=%v error=%v closed=%v", records, err, closed)
	}
}
