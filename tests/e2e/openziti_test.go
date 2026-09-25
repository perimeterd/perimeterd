//go:build linux && e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

const (
	openZitiEnabledEnv     = "PERIMETERD_OPENZITI_E2E"
	openZitiBinaryEnv      = "ZITI_TEST_BINARY"
	openZitiVersion        = "2.0.4"
	openZitiRouterName     = "router-instance-1"
	openZitiAdminUser      = "admin"
	openZitiAdminPass      = "perimeterd-openziti-admin"
	openZitiService        = "perimeterd-private-feed"
	openZitiAltService     = "perimeterd-private-feed-alt"
	openZitiTLSService     = "perimeterd-private-tls"
	openZitiDeniedSvc      = "perimeterd-private-denied"
	openZitiCrowdVersion   = "1.8.1"
	openZitiCrowdBindirEnv = "CROWDSEC_TEST_BINDIR"
)

// TestE2EOpenZiti is intentionally opt-in. A missing explicitly requested
// prerequisite is a failure; an ordinary E2E invocation never needs Ziti.
func TestE2EOpenZiti(t *testing.T) {
	if os.Getenv(openZitiEnabledEnv) != "1" {
		t.Skip("PERIMETERD_OPENZITI_E2E=1 is required")
	}
	if strings.TrimSpace(os.Getenv(openZitiCrowdBindirEnv)) == "" {
		t.Fatalf("%s is required when %s=1; the real CrowdSec LAPI gate is not optional", openZitiCrowdBindirEnv, openZitiEnabledEnv)
	}
	if os.Getenv(e2eChildEnv) != "1" {
		for _, backend := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(backend, func(t *testing.T) {
				runIsolated(t, "TestE2EOpenZiti", backend)
			})
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)

	backend := openZitiBackendScenario(t)
	ziti := openZitiRequireBinary(t)
	if os.Getenv(e2eBinaryEnv) == "" {
		t.Fatal("E2E_BINARY is required when PERIMETERD_OPENZITI_E2E=1")
	}

	peer := newPeerNamespace(t)
	fixture := openZitiProvision(t, ziti)
	defer fixture.Close(t)

	// The offline validator is the direct-only/no-file/no-network control. The
	// referenced path is deliberately absent; validate must not open it or
	// contact a controller merely because a profile is present but unused.
	openZitiCheckDirectOnly(t, fixture.home)

	port := openZitiFreePort(t)
	lookupPort := uint16(port) // #nosec G115 -- port was assigned by a kernel TCP listener.
	configPath := tempConfig(t, "openziti")
	identityPath := fixture.identityPath
	directURL := fixture.direct.URL("/feed?stage=direct")
	openZitiWriteConfig(t, configPath, fixture.feedURL("/redirect?stage=initial"), identityPath, openZitiService, port, true, backend, directURL)
	tlsCA := openZitiWriteTLSCA(t, fixture.tls)
	restoreTLS := openZitiSetEnv(t, "SSL_CERT_FILE", tlsCA)
	for _, host := range []string{"feed.private.invalid", "other.private.invalid", "lapi.private.invalid"} {
		if addresses, err := net.LookupHost(host); err == nil && len(addresses) > 0 {
			t.Fatalf("DNS tripwire failed: %s resolves to %v; private application traffic could escape the overlay", host, addresses)
		}
	}

	// A hostile proxy must not capture a Ziti application request. The source
	// hostname has no DNS record and the service terminator is the only route.
	// Loopback remains in NO_PROXY so the independent direct source can still
	// prove coexistence without weakening the private Ziti source boundary.
	restoreTripwires := openZitiSetNetworkTripwires(t)
	daemon := openZitiStartDaemon(t, configPath, backend, fixture.table)
	restoreTripwires()

	openZitiWaitStage(t, fixture, "initial", 2)
	openZitiWaitHTTPStage(t, fixture.direct, "direct", 1)
	// The source itself supplies both families. This proves a real private
	// service fetch was published into native enforcement, not a fake dialer.
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":"+fmt.Sprint(port), "reject", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:"+fmt.Sprint(port), "reject", "tcp")
	for _, address := range []string{fixtureIPv4Peer, fixtureIPv6Peer} {
		deadline := time.Now().Add(5 * time.Second)
		for {
			result := lookupCommand(t, address, "ingress", "tcp", &lookupPort)
			if result.response.Verdict == "blocked" {
				break
			}
			// A scheduled refresh can temporarily fence the applied view.
			// Retry unknown, but never accept a contradictory concrete verdict.
			if result.response.Verdict != "unknown" || time.Now().After(deadline) {
				t.Fatalf("OpenZiti lookup did not explain the committed block: %s", result.output)
			}
			time.Sleep(50 * time.Millisecond)
		}
	}

	// Same-origin redirect remains inside the configured source origin and is
	// served by the same exact Ziti service. The handler counts both requests.
	if got := fixture.feed.StageRequests("initial"); got < 2 {
		t.Fatalf("same-origin redirect did not complete through Ziti: %d requests", got)
	}
	openZitiWriteConfig(t, configPath, fixture.feedURL("/feed?stage=denied"), identityPath, openZitiDeniedSvc, port, true, backend, directURL)
	diagnosticOffset := daemonDiagnosticOffset(daemon)
	daemon.reload(t)
	waitForDaemonDiagnostic(t, daemon, []string{"ip_list/private", "refresh=false"}, diagnosticOffset)
	openZitiWaitNoHTTPStage(t, fixture.feed, "denied")
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":"+fmt.Sprint(port), "reject", "tcp")

	// A changed service with a valid authorization is a new source identity and
	// must fetch before it can be selected.
	openZitiWriteConfig(t, configPath, fixture.feedURL("/feed?stage=alt"), identityPath, openZitiAltService, port, true, backend, directURL)
	beforeRevision := activeRevision()
	daemon.reload(t)
	openZitiWaitStage(t, fixture, "alt", 1)
	waitForActiveRevisionChange(t, beforeRevision, configPath)
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:"+fmt.Sprint(port), "reject", "tcp")

	// Cross-origin redirects are rejected before a second application origin is
	// contacted; the prior exact-identity snapshot remains active.
	openZitiWriteConfig(t, configPath, fixture.feedURL("/cross?stage=cross"), identityPath, openZitiAltService, port, true, backend, directURL)
	diagnosticOffset = daemonDiagnosticOffset(daemon)
	daemon.reload(t)
	openZitiWaitStage(t, fixture, "cross", 1)
	waitForDaemonDiagnostic(t, daemon, []string{"ip_list/private", "refresh=false"}, diagnosticOffset)
	if got := fixture.feed.StageRequests("cross-target"); got != 0 {
		t.Fatalf("cross-origin redirect contacted a second application origin: %d requests", got)
	}
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":"+fmt.Sprint(port), "reject", "tcp")

	// Trust the test server's application certificate explicitly and use a
	// hostname covered by that certificate. Ziti's controller CA is not an
	// application CA, so changing only the URL hostname must fail verification.
	openZitiWriteConfigWithTLS(t, configPath, fixture.feedURL("/feed?stage=tls-clear"), identityPath, openZitiTLSService, port, fixture.tls.Listener.Addr().(*net.TCPAddr).Port, backend, directURL, "tls.example.com", "tls-valid")
	beforeRevision = activeRevision()
	daemon.reload(t)
	openZitiWaitHTTPStage(t, fixture.feed, "tls-valid", 1)
	waitForActiveRevisionChange(t, beforeRevision, configPath)
	if got := fixture.feed.StageRequests("tls-invalid"); got != 0 {
		t.Fatalf("invalid TLS stage unexpectedly reached the application: %d requests", got)
	}
	openZitiWriteConfigWithTLS(t, configPath, fixture.feedURL("/feed?stage=tls-clear"), identityPath, openZitiTLSService, port, fixture.tls.Listener.Addr().(*net.TCPAddr).Port, backend, directURL, "tls.private.invalid", "tls-invalid")
	diagnosticOffset = daemonDiagnosticOffset(daemon)
	daemon.reload(t)
	waitForDaemonDiagnostic(t, daemon, []string{"ip_list/tls", "refresh=false"}, diagnosticOffset)
	openZitiWaitNoHTTPStage(t, fixture.feed, "tls-invalid")
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":"+fmt.Sprint(port), "reject", "tcp")
	restoreTLS()

	// Replace the enrolled identity at the same path, revoke the old identity,
	// and reload. The new generation must be captured and used for a fresh fetch.
	openZitiRotateIdentity(t, fixture, identityPath)
	openZitiWriteConfig(t, configPath, fixture.feedURL("/feed?stage=rotated"), identityPath, openZitiAltService, port, true, backend, directURL)
	beforeRevision = activeRevision()
	daemon.reload(t)
	openZitiWaitStage(t, fixture, "rotated", 1)
	waitForActiveRevisionChange(t, beforeRevision, configPath)

	// A canceled/terminated real perimeterd process must drain within the
	// bounded lifecycle timeout. The SDK cleanup limitation is intentionally
	// exercised through its caller shutdown path, not goroutine inspection.
	stopStart := time.Now()
	daemon.stop(t)
	if elapsed := time.Since(stopStart); elapsed > 20*time.Second {
		t.Fatalf("bounded OpenZiti shutdown exceeded 20s: %s", elapsed)
	}

	t.Run("CrowdSecLAPI", func(t *testing.T) {
		openZitiCrowdSecLifecycle(t, fixture, peer, backend)
	})
}

func openZitiCrowdSecLifecycle(t *testing.T, fixture *openZitiFixture, peer *peerNamespace, backend string) {
	t.Helper()
	rawBindir := strings.TrimSpace(os.Getenv(openZitiCrowdBindirEnv))
	if rawBindir == "" {
		t.Fatalf("%s is required when %s=1; provide a directory containing crowdsec and cscli", openZitiCrowdBindirEnv, openZitiEnabledEnv)
	}
	bindir, err := filepath.Abs(rawBindir)
	if err != nil {
		t.Fatalf("resolve %s: %v", openZitiCrowdBindirEnv, err)
	}
	crowdsec := filepath.Join(bindir, "crowdsec")
	cscli := filepath.Join(bindir, "cscli")
	for _, path := range []string{crowdsec, cscli} {
		if _, err := exec.LookPath(path); err != nil {
			t.Fatalf("%s requires an executable at %s: %v", openZitiCrowdBindirEnv, path, err)
		}
	}
	versionCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	versionOutput, versionErr := exec.CommandContext(versionCtx, crowdsec, "-version").CombinedOutput() // #nosec G204 G702 -- explicit operator-selected pinned fixture binary prerequisite.
	if versionErr != nil || !bytes.Contains(versionOutput, []byte(openZitiCrowdVersion)) {
		t.Fatalf("%s must provide CrowdSec v%s: %v", openZitiCrowdBindirEnv, openZitiCrowdVersion, versionErr)
	}
	first := openZitiStartLAPI(t, crowdsec, cscli)
	second := openZitiStartLAPI(t, crowdsec, cscli)
	for index, lapi := range []*openZitiLAPI{first, second} {
		service := fmt.Sprintf("perimeterd-private-lapi-%d", index)
		openZitiCreateService(t, fixture, service, lapi.port, fixture.routerName)
		openZitiCLI(t, fixture, "edge", "create", "service-policy", service+"-dial", "Dial",
			"--service-roles", "@"+service, "--identity-roles", "@perimeterd-feed-client-rotated")
	}
	openZitiCrowdSecCLI(t, cscli, first.config, "decisions", "add", "--ip", fixtureIPv4Peer, "--duration", "1m", "--reason", "perimeterd-e2e")
	openZitiCrowdSecCLI(t, cscli, second.config, "decisions", "add", "--ip", fixtureIPv6Peer, "--duration", "20s", "--reason", "perimeterd-e2e")

	// Consume the replacement server's initial delta. A replacement client
	// must request a full snapshot, not reuse the old endpoint's stream cursor.
	warm, err := http.NewRequest(http.MethodGet, fmt.Sprintf("http://127.0.0.1:%d/v1/decisions/stream?startup=true", second.port), nil)
	if err != nil {
		t.Fatal(err)
	}
	warm.Header.Set("X-Api-Key", openZitiBouncerKey)
	response, err := (&http.Client{Timeout: 3 * time.Second}).Do(warm)
	if err != nil {
		t.Fatal(err)
	}
	_, _ = io.Copy(io.Discard, response.Body)
	_ = response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("replacement LAPI stream bootstrap returned %d", response.StatusCode)
	}

	configPath := filepath.Join(t.TempDir(), "perimeterd.yaml")
	table := fmt.Sprintf("pde2e_ziti_crowd_%d", os.Getpid())
	feedURL := fixture.feedURL("/feed?stage=crowd-shared")
	openZitiWriteCrowdPerimeterdConfig(t, configPath, fixture.identityPath, first.keyPath, first.port, backend, "perimeterd-private-lapi-0", feedURL)
	restoreTripwires := openZitiSetNetworkTripwires(t)
	daemon := openZitiStartDaemon(t, configPath, backend, table)
	restoreTripwires()
	openZitiWaitStage(t, fixture, "crowd-shared", 1)
	port := fmt.Sprint(openZitiFreePort(t))
	v4 := net.JoinHostPort(fixtureIPv4Host, port)
	v6 := net.JoinHostPort(fixtureIPv6Host, port)
	waitCrowdPacket(t, peer, "tcp4", v4, "reject")
	waitCrowdPacket(t, peer, "tcp6", v6, "success")

	// URL, API key, identity, and list route remain identical. Only the LAPI
	// service changes, selecting a different real authority behind the overlay.
	openZitiWriteCrowdPerimeterdConfig(t, configPath, fixture.identityPath, first.keyPath, first.port, backend, "perimeterd-private-lapi-1", feedURL)
	daemon.reload(t)
	waitCrowdPacket(t, peer, "tcp4", v4, "success")
	waitCrowdPacket(t, peer, "tcp6", v6, "reject")
	second.process.stop(t)
	// No LAPI can deliver an expiry delta now. The daemon/kernel must expire
	// the last authoritative decision rather than renewing it during outage.
	waitCrowdPacket(t, peer, "tcp6", v6, "success")
	daemon.stop(t)
}
