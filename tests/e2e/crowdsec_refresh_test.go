//go:build linux && e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/app"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/state"
)

// Observe completed native preflights so the test can distinguish a rejected
// refresh from one that has merely not reached the writer yet.
type refreshCapacityBackend struct {
	firewall.Backend
	initial           chan *firewall.Target
	initialProjection chan []policy.TimedPrefix
	refresh           chan refreshCapacityResult
}

type refreshCapacityResult struct {
	candidate *firewall.Target
	err       error
}

func (b *refreshCapacityBackend) Preflight(ctx context.Context, previous, candidate *firewall.Target, dynamic *firewall.DynamicState) error {
	err := b.Backend.Preflight(ctx, previous, candidate, dynamic)
	if previous != nil {
		select {
		case b.refresh <- refreshCapacityResult{candidate: candidate, err: err}:
		default:
		}
	}
	return err
}

func (b *refreshCapacityBackend) Apply(ctx context.Context, previous, candidate *firewall.Target, dynamic *firewall.DynamicState) error {
	err := b.Backend.Apply(ctx, previous, candidate, dynamic)
	if err == nil && previous == nil && candidate != nil {
		select {
		case b.initial <- candidate:
		default:
		}
		if dynamic != nil {
			projection := append([]policy.TimedPrefix(nil), dynamic.Prefixes...)
			select {
			case b.initialProjection <- projection:
			default:
			}
		}
	}
	return err
}

type refreshCapacitySources struct {
	initial, enlarged, decisions []byte
	grow                         <-chan struct{}
	geoRequests                  atomic.Uint32
}

func (s *refreshCapacitySources) RoundTrip(request *http.Request) (*http.Response, error) {
	body := s.initial
	if request.URL.Host == "lapi.example" {
		body = []byte(`{"new":[],"deleted":[]}`)
		if request.URL.Query().Get("startup") == "true" {
			body = s.decisions
		}
	} else if s.geoRequests.Add(1) > 1 {
		select {
		case <-s.grow:
		case <-request.Context().Done():
			return nil, request.Context().Err()
		}
		body = s.enlarged
	}
	return &http.Response{StatusCode: http.StatusOK, Status: "200 OK", Header: make(http.Header), Body: io.NopCloser(bytes.NewReader(body)), ContentLength: int64(len(body)), Request: request}, nil
}

func TestE2ECrowdSecGeoRefreshCapacity(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		t.Logf("%s", runIsolated(t, "TestE2ECrowdSecGeoRefreshCapacity", "nftables"))
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	makePrefix := func(index uint32, dynamic bool, bits int) netip.Prefix {
		address := [16]byte{0x20, 0x01, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd, 0xab, 0xcd}
		if dynamic {
			address[1] = 0x02
		}
		binary.BigEndian.PutUint32(address[12:], 0xa0000000+index)
		return netip.PrefixFrom(netip.AddrFrom16(address), bits)
	}
	countryBody := func(prefixes []string) []byte {
		encoded, err := json.Marshal(prefixes)
		if err != nil {
			t.Fatal(err)
		}
		return []byte(strings.Replace(countryFixtureBody, `["2600:20::/64"]`, string(encoded), 1))
	}
	// The enlarged source still fits the 32 MiB source/cache/durable bounds,
	// and its static-only native input fits 64 MiB. Together with the 200,000
	// timed prefixes, however, the encoded candidate exceeds 64 MiB before any
	// mutation. Rejecting that combination must leave the old bans renewable.
	const staticPrefixes = 700000
	prefixes := make([]string, staticPrefixes)
	for index := range prefixes {
		prefixes[index] = makePrefix(uint32(index)*4, false, 127).String()
	}
	type decision struct {
		ID       int64  `json:"id"`
		Type     string `json:"type"`
		Scope    string `json:"scope"`
		Value    string `json:"value"`
		Duration string `json:"duration"`
	}
	// 100,000 source decisions produce 200,000 disjoint timed prefixes. Their
	// 25h/49h authority needs renewal beyond the 24h native lease cap.
	decisions := make([]decision, 100000)
	for index := uint32(0); index < 50000; index++ {
		decisions[2*index] = decision{int64(2*index + 1), "ban", "range", makePrefix(index*32, true, 124).String(), "25h"}
		decisions[2*index+1] = decision{int64(2*index + 2), "ban", "range", makePrefix(index*32+2, true, 127).String(), "49h"}
	}
	decisions[0].Value = netip.PrefixFrom(netip.MustParseAddr(fixtureIPv6Peer), 124).Masked().String()
	decisions[1].Value = netip.PrefixFrom(netip.MustParseAddr(fixtureIPv6Peer), 127).Masked().String()
	wire, err := json.Marshal(map[string]any{"new": decisions, "deleted": nil})
	if err != nil {
		t.Fatal(err)
	}
	grow := make(chan struct{})
	fixture := &refreshCapacitySources{initial: countryBody(prefixes[:1]), enlarged: countryBody(prefixes), decisions: wire, grow: grow}
	if len(fixture.enlarged) >= 32<<20 || len(wire) >= 32<<20 {
		t.Fatalf("fixture exceeds source bound: country=%d decisions=%d", len(fixture.enlarged), len(wire))
	}
	backend := &refreshCapacityBackend{Backend: firewall.NewNative(nil), initial: make(chan *firewall.Target, 1), initialProjection: make(chan []policy.TimedPrefix, 1), refresh: make(chan refreshCapacityResult, 1)}
	key := filepath.Join(t.TempDir(), "key")
	if err := os.WriteFile(key, []byte("test-key"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := tempConfig(t, "crowdsec-refresh-capacity")
	configText := fmt.Sprintf(`version: 1
logging:
  level: error
metrics:
  listen: ""
firewall:
  backend: nftables
  ipv4: false
  ipv6: true
  deny_action: reject
  nftables:
    table: crowd_refresh_capacity
geo:
  country_provider: ripestat
  refresh_interval: 1s
  request_timeout: 1m
  refresh_jitter: 1ns
crowdsec:
  enabled: true
  lapi_url: http://lapi.example
  api_key_file: %q
  update_frequency: 1h
policies:
  - name: country
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [any]
    include:
      countries: [US]
`, key)
	if err := os.WriteFile(configPath, []byte(configText), 0o600); err != nil {
		t.Fatal(err)
	}
	ready := make(chan struct{}, 1)
	options := app.Options{ConfigPath: configPath, StateDir: "/var/lib/perimeterd", LockPath: "/run/perimeterd/owner.lock", Backend: backend, SourceClient: &http.Client{Transport: fixture}, Stderr: io.Discard, StartupTimeout: 3 * time.Minute, Notify: func(message string) error {
		if strings.Contains(message, "READY=1") {
			select {
			case ready <- struct{}{}:
			default:
			}
		}
		return nil
	}}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()
	done := make(chan error, 1)
	go func() { done <- app.Run(ctx, options) }()
	stopped := false
	defer func() {
		if !stopped {
			cancel()
			select {
			case err := <-done:
				if err != nil {
					t.Errorf("stop runtime: %v", err)
				}
			case <-time.After(40 * time.Second):
				t.Error("runtime did not stop")
			}
		}
	}()
	select {
	case <-ready:
	case err := <-done:
		stopped = true
		t.Fatalf("startup stopped: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	var initial *firewall.Target
	var initialProjection []policy.TimedPrefix
	select {
	case initial = <-backend.initial:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	select {
	case initialProjection = <-backend.initialProjection:
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	if len(initialProjection) != 200000 {
		t.Fatalf("initial effective projection has %d prefixes, want 200000", len(initialProjection))
	}
	close(grow)
	var rejected *firewall.Target
	select {
	case result := <-backend.refresh:
		var capacity *firewall.CapacityError
		if !errors.As(result.err, &capacity) || capacity.Backend != "nftables" ||
			capacity.Resource != "nft-table" || capacity.Scope != "input" ||
			capacity.LimitBytes != 64<<20 || capacity.RequiredBytes <= capacity.LimitBytes ||
			capacity.StaticGenerations != 2 || capacity.DynamicGenerations != 1 {
			t.Fatalf("refresh did not reject combined encoded candidate capacity: %+v (%v)", capacity, result.err)
		}
		rejected = result.candidate
		t.Logf("rejected static-prefixes=%d projected-prefixes=%d resource=%s scope=%s required-bytes=%d limit-bytes=%d static-generations=%d dynamic-generations=%d",
			staticPrefixes, len(initialProjection), capacity.Resource, capacity.Scope, capacity.RequiredBytes, capacity.LimitBytes, capacity.StaticGenerations, capacity.DynamicGenerations)
	case err := <-done:
		stopped = true
		t.Fatalf("runtime stopped during refresh: %v", err)
	case <-ctx.Done():
		t.Fatal(ctx.Err())
	}
	cancel()
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(40 * time.Second):
		t.Fatal("runtime did not stop after rejected refresh")
	}
	// With the writer stopped, verify the durable selection and renew the exact
	// source projection captured at initial activation, without rebasing deadlines.
	lock, err := state.AcquireLock(options.LockPath)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	store, err := state.Open(options.StateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if view.Journal != nil || view.Active == nil || view.Active.Target.Generation != initial.Generation {
		t.Fatal("rejected refresh changed durable authority")
	}
	if rejected == nil || rejected.Generation == initial.Generation || rejected.DynamicGeneration != initial.DynamicGeneration {
		t.Fatal("refresh did not preserve shared dynamic authority for a distinct static candidate")
	}
	var memberships int
	for _, family := range rejected.Families {
		for _, set := range family.Sets {
			if set.ID == "geo/country" {
				memberships += len(set.Prefixes)
			}
		}
	}
	if memberships != staticPrefixes {
		t.Fatalf("rejected candidate has %d country memberships, want %d", memberships, staticPrefixes)
	}
	// Rule out the independent durable bound: this is the same revision shape
	// and envelope as the active selection, with the enlarged target substituted.
	revision := *view.Active
	revision.ID = rejected.Generation
	revision.Target = rejected
	revision.Epoch++
	revision.RefreshSequence++
	payload, err := json.Marshal(revision)
	if err != nil {
		t.Fatal(err)
	}
	record, err := json.Marshal(map[string]any{"version": 2, "checksum": strings.Repeat("0", 64), "payload": json.RawMessage(payload)})
	if err != nil {
		t.Fatal(err)
	}
	if len(record) >= 32<<20 {
		t.Fatalf("enlarged candidate would fail durable capacity independently: %d bytes", len(record))
	}
	t.Logf("admissible country-source-bytes=%d decisions-source-bytes=%d candidate-durable-bytes=%d", len(fixture.enlarged), len(wire), len(record))
	// A real, read-only preflight without the projected bans must still fit.
	// This proves the input rejection above is combined static/dynamic pressure,
	// not an independently oversized source target or retained native inventory.
	staticCtx, staticCancel := context.WithTimeout(context.Background(), time.Minute)
	defer staticCancel()
	if err := backend.Backend.Preflight(staticCtx, initial, rejected, nil); err != nil {
		t.Fatalf("static refresh alone is not admissible: %v", err)
	}
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18796", "reject", "tcp")
	renewCtx, renewCancel := context.WithTimeout(context.Background(), time.Minute)
	defer renewCancel()
	if err := backend.UpdateDynamic(renewCtx, view.Active.Target, initialProjection); err != nil {
		t.Fatalf("preserved CrowdSec authority cannot be renewed: %v", err)
	}
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18797", "reject", "tcp")
	if err := lock.Close(); err != nil {
		t.Fatal(err)
	}
	if err := app.Cleanup(context.Background(), options); err != nil {
		t.Fatalf("cleanup after rejected refresh: %v", err)
	}
}
