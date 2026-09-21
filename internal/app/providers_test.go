package app

import (
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

	"github.com/perimeterd/perimeterd/internal/state"
)

func TestRunProviderRefreshSurvivesUnknownReload(t *testing.T) {
	var address atomic.Value
	address.Store("1.1.1.1")
	var stableRequests, unexpectedRequests atomic.Int64
	missing := make(chan struct{}, 8)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/gh/rezmoss/cloud-provider-ip-addresses@main/future_vendor_123/future_vendor_123_ips_merged.txt":
			_, _ = fmt.Fprintln(w, address.Load().(string))
		case "/gh/rezmoss/cloud-provider-ip-addresses@main/missing_vendor_123/missing_vendor_123_ips_merged.txt":
			http.NotFound(w, r)
			select {
			case missing <- struct{}{}:
			default:
			}
		case "/stable":
			stableRequests.Add(1)
			_, _ = io.WriteString(w, "9.9.9.9\n")
		default:
			unexpectedRequests.Add(1)
			http.NotFound(w, r)
		}
	}))
	defer server.Close()
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	path := filepath.Join(dir, "policy.yaml")
	listen := runAddress(t)
	text := fmt.Sprintf(`version: 1
firewall:
  backend: nftables
metrics:
  listen: %q
geo:
  refresh_interval: 24h
providers:
  refresh_interval: 300ms
  request_timeout: 1s
ip_lists:
  stable:
    url: %s/stable
    refresh_interval: 24h
policies:
  - name: country
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["any"]
    include:
      providers: [future_vendor_123]
      ip_lists: [stable]
  - name: disabled
    priority: 20
    direction: ingress
    mode: disabled
    traffic: ["any"]
    include:
      providers: [disabled_vendor_123]
`, listen, server.URL)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatal(err)
	}
	backend := &sourceObservingBackend{policies: make(chan string, 32)}
	client := &http.Client{Transport: fixtureSourceTransport{target: target, base: http.DefaultTransport}}
	stateDir := filepath.Join(dir, "state")
	cancel, signals, ready, done := startRunWithClient(t, path, stateDir, backend, client, nil)
	stopped := false
	defer func() {
		if !stopped {
			awaitRunStop(t, cancel, done)
		}
	}()
	awaitRunReady(t, ready)
	awaitProviderPrefix(t, backend.policies, "1.1.1.1/32")
	address.Store("2.2.2.2")
	awaitProviderPrefix(t, backend.policies, "2.2.2.2/32")
	if stableRequests.Load() != 1 || unexpectedRequests.Load() != 0 {
		t.Fatalf("provider timer fetched fresh or disabled peers: stable=%d unexpected=%d", stableRequests.Load(), unexpectedRequests.Load())
	}
	response := mustGet(t, "http://"+listen+"/metrics")
	body, err := io.ReadAll(response.Body)
	_ = response.Body.Close()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(body), `perimeterd_prefix_snapshot_timestamp_seconds{source="provider"}`) || !strings.Contains(string(body), `source="ip_list"`) || strings.Contains(string(body), `source="ripestat"`) {
		t.Fatalf("mixed provider/custom-list freshness was mislabeled: %s", body)
	}
	// Offline syntax accepts a new ID, but a 404 must reject activation without
	// replacing the prior configuration or disabling its refresh timer.
	reload := strings.Replace(text, "providers: [future_vendor_123]", "providers: [future_vendor_123, missing_vendor_123]", 1)
	if err := os.WriteFile(path, []byte(reload), 0o600); err != nil {
		t.Fatal(err)
	}
	signals <- syscall.SIGHUP
	select {
	case <-missing:
	case <-time.After(5 * time.Second):
		t.Fatal("new provider was not dynamically resolved")
	}
	address.Store("3.3.3.3")
	awaitProviderPrefix(t, backend.policies, "3.3.3.3/32")
	awaitRunStop(t, cancel, done)
	stopped = true
	store, err := state.Open(stateDir, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil || view.Active == nil {
		t.Fatalf("provider revision did not recover: active=%v error=%v", view.Active, err)
	}
	selected := view.Active.Config.Policies[0].Include.Providers
	if len(selected) != 1 || selected[0] != "future_vendor_123" {
		t.Fatalf("missing provider was committed despite resolution failure: %v", selected)
	}
}

func awaitProviderPrefix(t *testing.T, applied <-chan string, want string) {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-applied:
			if got == want {
				return
			}
		case <-deadline:
			t.Fatalf("provider policy did not advance to %q", want)
		}
	}
}
