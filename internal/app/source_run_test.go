package app

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/state"
)

type fixtureSourceTransport struct {
	target *url.URL
	base   http.RoundTripper
}

func (r fixtureSourceTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	copy := request.Clone(request.Context())
	copy.URL.Scheme = r.target.Scheme
	copy.URL.Host = r.target.Host
	return r.base.RoundTrip(copy)
}

type sourceObservingBackend struct {
	recordingBackend
	policies chan string
}

func (b *sourceObservingBackend) Apply(ctx context.Context, previous, candidate *firewall.Target, dynamic *firewall.DynamicState) error {
	if err := b.recordingBackend.Apply(ctx, previous, candidate, dynamic); err != nil {
		return err
	}
	selected := ""
	if candidate != nil {
		for _, family := range candidate.Families {
			if family.Family != policy.IPv4 {
				continue
			}
			for _, set := range family.Sets {
				if set.ID == "geo/country" && len(set.Prefixes) != 0 {
					selected = set.Prefixes[0].String()
				}
			}
		}
	}
	select {
	case b.policies <- selected:
	case <-ctx.Done():
		return ctx.Err()
	}
	return nil
}

func TestRunSourceRefreshSurvivesMalformedDataAndRejectedReload(t *testing.T) {
	var address atomic.Value
	address.Store("8.8.8.8/32")
	failedResponses := make(chan struct{}, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/data/country-resource-list/data.json" || r.URL.Query().Get("resource") != "CZ" || r.URL.Query().Get("sourceapp") != "perimeterd" {
			http.Error(w, "unexpected source request", http.StatusBadRequest)
			return
		}
		value := address.Load().(string)
		if value == "malformed" {
			// The aliased success must not admit this different prefix over the
			// last committed policy, despite otherwise complete response data.
			_, _ = io.WriteString(w, `{"status":"error","STATUS":"ok","status_code":200,"data_call_name":"country-resource-list","data_call_status":"supported","version":"0.2","time":"2026-09-14T00:00:00","data":{"query_time":"2026-09-13T00:00:00","resources":{"ipv4":["1.1.1.1/32"],"ipv6":[]}}}`)
			select {
			case failedResponses <- struct{}{}:
			default:
			}
			return
		}
		if value == "9.9.9.9/32" {
			// A valid refresh slower than its scheduling interval must finish
			// rather than being canceled by the next timer tick.
			select {
			case <-time.After(1500 * time.Millisecond):
			case <-r.Context().Done():
				return
			}
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = fmt.Fprintf(w, `{"status":"ok","status_code":200,"data_call_name":"country-resource-list","data_call_status":"supported","version":"0.2","time":"2026-09-14T00:00:00","data":{"query_time":"2026-09-13T00:00:00","resources":{"ipv4":[%q],"ipv6":[]}}}`, value)
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	configPath := filepath.Join(dir, "policy.yaml")
	text := `version: 1
metrics:
  listen: ""
firewall:
  backend: nftables
geo:
  refresh_interval: 1s
  refresh_jitter: 1ns
  request_timeout: 3s
policies:
  - name: country
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["443/tcp"]
    include:
      countries: [CZ]
`
	if err := os.WriteFile(configPath, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &sourceObservingBackend{policies: make(chan string, 32)}
	signals := make(chan os.Signal, 1)
	ready := make(chan struct{}, 1)
	commits := make(chan struct{}, 8)
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, Options{
			ConfigPath:   configPath,
			StateDir:     filepath.Join(dir, "state"),
			LockPath:     filepath.Join(dir, "run", "owner.lock"),
			Backend:      backend,
			SourceClient: &http.Client{Transport: fixtureSourceTransport{target: target, base: http.DefaultTransport}},
			Signals:      signals,
			Stderr:       io.Discard,
			Checkpoint: func(phase string) error {
				if phase == "after-commit" {
					commits <- struct{}{}
				}
				return nil
			},
			Notify: func(message string) error {
				if strings.Contains(message, "READY=1") {
					ready <- struct{}{}
				}
				return nil
			},
		})
	}()
	stopped := false
	defer func() {
		cancel()
		if !stopped {
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Error("source runtime did not stop")
			}
		}
	}()
	select {
	case <-ready:
		<-commits
	case err := <-done:
		stopped = true
		t.Fatalf("source startup failed: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("source startup did not become ready")
	}
	awaitSourcePolicy(t, backend.policies, "8.8.8.8/32")
	address.Store("malformed")
	// Two failed scheduled requests ensure a complete failure cycle has passed.
	// No partial/empty source result may replace the last committed packet policy.
	for range 2 {
		select {
		case <-failedResponses:
		case applied := <-backend.policies:
			t.Fatalf("malformed source changed packet policy to %q", applied)
		case <-time.After(5 * time.Second):
			t.Fatal("source refresh did not retry on the normal schedule")
		}
	}
	if err := os.WriteFile(configPath, []byte("invalid: yaml\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	signals <- syscall.SIGHUP
	address.Store("9.9.9.9/32")
	awaitSourcePolicy(t, backend.policies, "9.9.9.9/32")
	select {
	case <-commits:
	case <-time.After(5 * time.Second):
		t.Fatal("refreshed packet policy was not durably committed")
	}
	cancel()
	select {
	case err := <-done:
		stopped = true
		if err != nil {
			t.Fatalf("stop refreshed source runtime: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("source runtime did not stop")
	}
	store, err := state.Open(filepath.Join(dir, "state"), nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil || view.Active == nil || view.Active.Manifest == "" || view.Active.RefreshSequence == 0 {
		t.Fatalf("refresh did not durably select its complete snapshot: %+v, %v", view.Active, err)
	}
	snapshot, err := store.Prefixes().Load(view.Active.Manifest)
	if err != nil {
		t.Fatal(err)
	}
	prefixes, ok := snapshot.Policy().Lookup(policy.Selector{Kind: policy.Country, Value: "CZ"})
	if !ok || len(prefixes.Prefixes()) != 1 || prefixes.Prefixes()[0].String() != "9.9.9.9/32" {
		t.Fatalf("durable snapshot disagrees with refreshed packet policy: %v", prefixes.Prefixes())
	}
}

func awaitSourcePolicy(t *testing.T, applied <-chan string, want string) {
	t.Helper()
	select {
	case got := <-applied:
		if got != want {
			t.Fatalf("packet policy = %q, want %q", got, want)
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("packet policy did not advance to %q", want)
	}
}
