//go:build linux && e2e

package e2e

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/app"
)

const (
	fixtureExcludedIPv4Host = "192.0.2.20"
	fixtureExcludedIPv4Peer = "192.0.2.21"
	fixtureOtherIPv4Host    = "8.21.0.1"
	fixtureOtherIPv4Peer    = "8.21.0.2"
	fixtureOtherIPv6Host    = "2600:21::1"
	fixtureOtherIPv6Peer    = "2600:21::2"
)

type geoFixtureTransport struct {
	started   time.Time
	validFor  time.Duration
	country   atomic.Bool
	asn       atomic.Bool
	malformed atomic.Bool
}

func (f *geoFixtureTransport) RoundTrip(request *http.Request) (*http.Response, error) {
	if request.URL.Query().Get("sourceapp") != "perimeterd" {
		return nil, fmt.Errorf("RIPEstat request omitted sourceapp=perimeterd")
	}
	resource := request.URL.Query().Get("resource")
	body := countryFixtureBody
	if strings.Contains(request.URL.Path, "announced-prefixes") {
		if resource != "3333" {
			return nil, fmt.Errorf("unexpected ASN resource %q", resource)
		}
		f.asn.Store(true)
		body = asnFixtureBody
	} else if strings.Contains(request.URL.Path, "country-resource-list") {
		if resource == "" {
			return nil, fmt.Errorf("country request omitted resource")
		}
		f.country.Store(true)
		switch resource {
		case "TW":
			body = strings.ReplaceAll(strings.ReplaceAll(body, "8.20.0.0/24", "8.22.0.0/24"), "2600:20::/64", "2600:22::/64")
		case "IR":
			body = strings.ReplaceAll(strings.ReplaceAll(body, "8.20.0.0/24", "8.23.0.0/24"), "2600:20::/64", "2600:23::/64")
		case "JP":
			body = strings.ReplaceAll(body, `["2600:20::/64"]`, `[]`)
		}
	} else {
		return nil, fmt.Errorf("unexpected RIPEstat endpoint %q", request.URL.Path)
	}
	if time.Since(f.started) >= f.validFor {
		f.malformed.Store(true)
		body = `{"status":"error"}`
	}
	return &http.Response{
		StatusCode:    http.StatusOK,
		Status:        "200 OK",
		Header:        make(http.Header),
		Body:          io.NopCloser(strings.NewReader(body)),
		ContentLength: int64(len(body)),
		Request:       request,
	}, nil
}

const countryFixtureBody = `{"version":"0.2","data_call_name":"country-resource-list","data_call_status":"supported","status":"ok","status_code":200,"time":"2026-09-14T00:00:00Z","data":{"query_time":"2026-09-13T00:00:00","resources":{"ipv4":["8.20.0.0/24","192.0.2.0/24"],"ipv6":["2600:20::/64"]}}}`

const asnFixtureBody = `{"version":"1.2","data_call_name":"announced-prefixes","data_call_status":"supported","status":"ok","status_code":200,"time":"2026-09-14T00:00:00Z","data":{"resource":"3333","query_starttime":"2026-09-13T00:00:00","query_endtime":"2026-09-14T00:00:00","prefixes":[{"prefix":"8.20.0.0/24","timelines":[{"starttime":"2026-09-13T00:00:00","endtime":"2026-09-14T00:00:00"}]},{"prefix":"2600:20::/64","timelines":[{"starttime":"2026-09-13T00:00:00","endtime":"2026-09-14T00:00:00"}]}]}}`

func writeGeoConfig(t *testing.T, path, table string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(geoConfigYAML(table)), 0o600); err != nil {
		t.Fatalf("write geo config: %v", err)
	}
}

func geoConfigYAML(table string) string {
	return fmt.Sprintf(`version: 1
logging:
  level: error
  format: text
metrics:
  listen: ""
global:
  allowlist: []
  blocklist: []
firewall:
  backend: nftables
  deny_action: reject
  ipv4: true
  ipv6: true
  nftables:
    table: %q
    priority: -10
geo:
  refresh_interval: 1s
  request_timeout: 1s
  refresh_jitter: 1ns
groups:
  partners: [US]
policies:
  - name: country-ingress
    priority: 10
    direction: ingress
    mode: allowlist
    traffic: ["18080/tcp"]
    include:
      countries: [US]
  - name: later-overlapping-block
    priority: 15
    direction: ingress
    mode: blocklist
    traffic: ["18080/tcp"]
    include:
      countries: [US]
  - name: partners-ingress
    priority: 20
    direction: ingress
    mode: blocklist
    traffic: ["18082/udp"]
    include:
      groups: [partners]
  - name: empty-family-ingress
    priority: 30
    direction: ingress
    mode: allowlist
    traffic: ["18086/tcp"]
    include:
      countries: [JP]
  - name: subtraction-ingress
    priority: 40
    direction: ingress
    mode: blocklist
    traffic: ["18087/tcp"]
    include:
      countries: [US]
    exclude:
      countries: [JP]
  - name: %s
    priority: 50
    direction: ingress
    mode: blocklist
    traffic: ["18088/tcp"]
    include:
      rirs: [APNIC]
  - name: %s
    priority: 60
    direction: ingress
    mode: allowlist
    traffic: ["18089/tcp"]
    include:
      rirs: [RIPE]
  - name: rir-egress
    priority: 10
    direction: egress
    mode: blocklist
    traffic: ["18081/tcp"]
    include:
      rirs: [RIPE]
  - name: asn-egress
    priority: 20
    direction: egress
    mode: allowlist
    traffic: ["18083/udp"]
    include:
      asns: [AS3333]
crowdsec:
  enabled: false
`, table, strings.Repeat("a", 200), strings.Repeat("a", 199)+"b")
}

func TestE2EGeo(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		runIsolated(t, "TestE2EGeo", "geo")
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	command(t, 10*time.Second, "ip", "addr", "add", fixtureExcludedIPv4Host+"/24", "dev", "e2h0")
	peer.run(t, "ip", "addr", "add", fixtureExcludedIPv4Peer+"/24", "dev", "e2p0")
	command(t, 10*time.Second, "ip", "addr", "add", fixtureOtherIPv4Host+"/24", "dev", "e2h0")
	peer.run(t, "ip", "addr", "add", fixtureOtherIPv4Peer+"/24", "dev", "e2p0")
	command(t, 10*time.Second, "ip", "-6", "addr", "add", fixtureOtherIPv6Host+"/64", "dev", "e2h0", "nodad")
	peer.run(t, "ip", "-6", "addr", "add", fixtureOtherIPv6Peer+"/64", "dev", "e2p0", "nodad")
	for _, subnet := range []string{"22", "23"} {
		command(t, 10*time.Second, "ip", "addr", "add", "8."+subnet+".0.1/24", "dev", "e2h0")
		peer.run(t, "ip", "addr", "add", "8."+subnet+".0.2/24", "dev", "e2p0")
		command(t, 10*time.Second, "ip", "-6", "addr", "add", "2600:"+subnet+"::1/64", "dev", "e2h0", "nodad")
		peer.run(t, "ip", "-6", "addr", "add", "2600:"+subnet+"::2/64", "dev", "e2p0", "nodad")
	}

	table := fmt.Sprintf("pde2e_geo_%d", os.Getpid())
	configPath := tempConfig(t, "geo")
	writeGeoConfig(t, configPath, table)
	fixture := &geoFixtureTransport{started: time.Now(), validFor: 8 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- app.Run(ctx, app.Options{
			ConfigPath:     configPath,
			StateDir:       "/var/lib/perimeterd",
			LockPath:       "/run/perimeterd/owner.lock",
			SourceClient:   &http.Client{Transport: fixture},
			Stderr:         io.Discard,
			Notify:         func(string) error { return nil },
			StartupTimeout: 2 * time.Minute,
		})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("perimeterd did not stop")
		}
	}()
	waitForNFTTable(t, table)
	if !fixture.country.Load() || !fixture.asn.Load() {
		t.Fatalf("source fixture did not receive country and ASN requests: country=%t asn=%t", fixture.country.Load(), fixture.asn.Load())
	}
	exerciseGeoPackets(t, peer, fixture)
}

func exerciseGeoPackets(t *testing.T, peer *peerNamespace, fixture *geoFixtureTransport) {
	t.Helper()

	// Country and group policies share a fixture prefix but have disjoint
	// transport scopes. RIR and ASN exercise egress with the opposite actions.
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18080", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18080", "success", "tcp")
	probeIngress(t, peer, "udp4", fixtureIPv4Host+":18082", "reject", "udp")
	probeIngress(t, peer, "udp6", "["+fixtureIPv6Host+"]:18082", "reject", "udp")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18081", "reject", "tcp")
	probeEgress(t, peer, "tcp6", "["+fixtureIPv6Peer+"]:18081", "reject", "tcp")
	probeEgress(t, peer, "udp4", fixtureIPv4Peer+":18083", "success", "udp")
	probeEgress(t, peer, "udp6", "["+fixtureIPv6Peer+"]:18083", "success", "udp")
	probeIngress(t, peer, "tcp4", fixtureOtherIPv4Host+":18080", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureOtherIPv6Host+"]:18080", "reject", "tcp")
	probeEgress(t, peer, "udp4", fixtureOtherIPv4Peer+":18083", "reject", "udp")
	probeEgress(t, peer, "udp6", "["+fixtureOtherIPv6Peer+"]:18083", "reject", "udp")
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18086", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18086", "reject", "tcp")
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18087", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18087", "reject", "tcp")

	// Distinct TW/APNIC and IR/RIPE prefixes prevent a geographic approximation
	// from passing. The two 200-character policy names differ only at the end;
	// their native sets must stay distinct and fit nftables identifier limits.
	probeIngress(t, peer, "tcp4", "8.22.0.1:18088", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:22::1]:18088", "reject", "tcp")
	probeIngress(t, peer, "tcp4", "8.23.0.1:18088", "success", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:23::1]:18088", "success", "tcp")
	probeIngress(t, peer, "tcp4", "8.22.0.1:18089", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:22::1]:18089", "reject", "tcp")
	probeIngress(t, peer, "tcp4", "8.23.0.1:18089", "success", "tcp")
	probeIngress(t, peer, "tcp6", "[2600:23::1]:18089", "success", "tcp")

	// TEST-NET is outside the geo-eligible classifier and outside the immutable
	// local allowlist, so it must bypass every geo policy in both directions.
	probeIngress(t, peer, "udp4", fixtureExcludedIPv4Host+":18082", "success", "udp")
	probeEgress(t, peer, "tcp4", fixtureExcludedIPv4Peer+":18081", "success", "tcp")

	// The scheduled refresh now receives malformed responses. The committed
	// source manifest and nftables target remain active rather than becoming an
	// empty or partial policy.
	time.Sleep(10 * time.Second)
	if !fixture.malformed.Load() {
		t.Fatal("scheduled refresh did not exercise malformed fixture response")
	}
	probeIngress(t, peer, "udp4", fixtureIPv4Host+":18082", "reject", "udp")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18081", "reject", "tcp")
}
