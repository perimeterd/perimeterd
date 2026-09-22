//go:build linux && e2e

package e2e

import (
	"bytes"
	"context"
	"encoding/pem"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
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
	daemon.reload(t)
	time.Sleep(2 * time.Second)
	if got := fixture.feed.StageRequests("denied"); got != 0 {
		t.Fatalf("denied Ziti service unexpectedly reached the application: %d requests", got)
	}
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":"+fmt.Sprint(port), "reject", "tcp")

	// A changed service with a valid authorization is a new source identity and
	// must fetch before it can be selected.
	openZitiWriteConfig(t, configPath, fixture.feedURL("/feed?stage=alt"), identityPath, openZitiAltService, port, true, backend, directURL)
	daemon.reload(t)
	openZitiWaitStage(t, fixture, "alt", 1)
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:"+fmt.Sprint(port), "reject", "tcp")

	// Cross-origin redirects are rejected before a second application origin is
	// contacted; the prior exact-identity snapshot remains active.
	openZitiWriteConfig(t, configPath, fixture.feedURL("/cross?stage=cross"), identityPath, openZitiAltService, port, true, backend, directURL)
	daemon.reload(t)
	openZitiWaitStage(t, fixture, "cross", 1)
	if got := fixture.feed.StageRequests("cross-target"); got != 0 {
		t.Fatalf("cross-origin redirect contacted a second application origin: %d requests", got)
	}
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":"+fmt.Sprint(port), "reject", "tcp")

	// Trust the test server's application certificate explicitly and use a
	// hostname covered by that certificate. Ziti's controller CA is not an
	// application CA, so changing only the URL hostname must fail verification.
	openZitiWriteConfigWithTLS(t, configPath, fixture.feedURL("/feed?stage=tls-clear"), identityPath, openZitiTLSService, port, fixture.tls.Listener.Addr().(*net.TCPAddr).Port, backend, directURL, "tls.example.com", "tls-valid")
	daemon.reload(t)
	openZitiWaitHTTPStage(t, fixture.feed, "tls-valid", 1)
	if got := fixture.feed.StageRequests("tls-invalid"); got != 0 {
		t.Fatalf("invalid TLS stage unexpectedly reached the application: %d requests", got)
	}
	openZitiWriteConfigWithTLS(t, configPath, fixture.feedURL("/feed?stage=tls-clear"), identityPath, openZitiTLSService, port, fixture.tls.Listener.Addr().(*net.TCPAddr).Port, backend, directURL, "tls.private.invalid", "tls-invalid")
	daemon.reload(t)
	time.Sleep(2 * time.Second)
	if got := fixture.feed.StageRequests("tls-invalid"); got != 0 {
		t.Fatalf("wrong application TLS hostname reached the application: %d requests", got)
	}
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":"+fmt.Sprint(port), "reject", "tcp")
	restoreTLS()

	// Replace the enrolled identity at the same path, revoke the old identity,
	// and reload. The new generation must be captured and used for a fresh fetch.
	openZitiRotateIdentity(t, fixture, identityPath)
	openZitiWriteConfig(t, configPath, fixture.feedURL("/feed?stage=rotated"), identityPath, openZitiAltService, port, true, backend, directURL)
	daemon.reload(t)
	openZitiWaitStage(t, fixture, "rotated", 1)

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

type openZitiFixture struct {
	ziti         string
	home         string
	ctrlPort     int
	routerPort   int
	routerName   string
	identityPath string
	feed         *openZitiHTTPFixture
	direct       *openZitiHTTPFixture
	tls          *httptest.Server
	table        string
}

func (f *openZitiFixture) Close(t *testing.T) {
	t.Helper()
	if f.tls != nil {
		f.tls.Close()
	}
	if f.feed != nil {
		f.feed.Close()
	}
	if f.direct != nil {
		f.direct.Close()
	}
}

func (f *openZitiFixture) feedURL(path string) string { return f.feed.URL(path) }

func openZitiProvision(t *testing.T, ziti string) *openZitiFixture {
	t.Helper()
	root := t.TempDir()
	home := filepath.Join(root, "ziti-home")
	if err := os.MkdirAll(home, 0o700); err != nil {
		t.Fatal(err)
	}
	feed := openZitiNewHTTPFixture(t)
	direct := openZitiNewDirectHTTPFixture(t)
	fixture := &openZitiFixture{
		ziti:       ziti,
		home:       home,
		ctrlPort:   openZitiFreePort(t),
		routerPort: openZitiFreePort(t),
		routerName: openZitiRouterName,
		feed:       feed,
		direct:     direct,
		table:      fmt.Sprintf("pde2e_ziti_%d", os.Getpid()),
	}

	// edge quickstart is the published v2.0.4 controller/router fixture. It
	// owns the child controller and router processes in this process group.
	quickstart := exec.Command(ziti, "edge", "quickstart", "--home", home, // #nosec G204 -- explicitly selected pinned fixture binary, isolated namespaces, no shell.
		"--ctrl-address", "127.0.0.1", "--ctrl-port", fmt.Sprint(fixture.ctrlPort),
		"--router-address", "127.0.0.1", "--router-port", fmt.Sprint(fixture.routerPort),
		"--username", openZitiAdminUser, "--password", openZitiAdminPass)
	if err := os.MkdirAll(filepath.Join(home, "cli"), 0o700); err != nil {
		t.Fatal(err)
	}
	quickstart.Env = append(os.Environ(), "HOME="+home, "ZITI_HOME="+home, "ZITI_CONFIG_DIR="+filepath.Join(home, "cli"))
	quickstart.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	output := &lockedBuffer{}
	quickstart.Stdout, quickstart.Stderr = output, output
	if err := quickstart.Start(); err != nil {
		t.Fatalf("start ziti edge quickstart v%s: %v", openZitiVersion, err)
	}
	fixtureProcess := &openZitiProcess{cmd: quickstart, done: make(chan struct{}), output: output}
	go fixtureProcess.wait()
	t.Cleanup(func() { fixtureProcess.stop(t) })
	openZitiWaitPort(t, fixtureProcess, fixture.ctrlPort)
	openZitiWaitPort(t, fixtureProcess, fixture.routerPort)

	openZitiCLI(t, fixture, "edge", "login", fmt.Sprintf("127.0.0.1:%d", fixture.ctrlPort), "-u", openZitiAdminUser, "-p", openZitiAdminPass, "-y")
	openZitiCreateService(t, fixture, openZitiService, feed.ListenerPort(), fixture.routerName)
	openZitiCreateService(t, fixture, openZitiAltService, feed.ListenerPort(), fixture.routerName)
	openZitiCreateService(t, fixture, openZitiDeniedSvc, feed.ListenerPort(), fixture.routerName)

	tls := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.feed.RecordStage(r.URL.Query().Get("stage"))
		if !strings.HasPrefix(r.Host, "tls.") {
			http.Error(w, "wrong application hostname", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, fixture.feed.Body())
	}))
	fixture.tls = tls
	openZitiCreateService(t, fixture, openZitiTLSService, tls.Listener.Addr().(*net.TCPAddr).Port, fixture.routerName)

	jwt := filepath.Join(root, "client.jwt")
	identity := filepath.Join(root, "client.json")
	openZitiCLI(t, fixture, "edge", "create", "identity", "perimeterd-feed-client", "--jwt-output-file", jwt)
	openZitiCLI(t, fixture, "edge", "enroll", "--jwt", jwt, "--out", identity)
	if err := os.Chmod(identity, 0o600); err != nil {
		t.Fatal(err)
	}
	fixture.identityPath = identity

	// The denied service intentionally has no matching Dial policy. The
	// remaining services are authorized to this one enrolled client identity.
	openZitiCreateDialPolicy(t, fixture, openZitiService, "perimeterd-feed-client")
	openZitiCreateDialPolicy(t, fixture, openZitiAltService, "perimeterd-feed-client")
	openZitiCreateDialPolicy(t, fixture, openZitiTLSService, "perimeterd-feed-client")
	return fixture
}

func openZitiCreateService(t *testing.T, fixture *openZitiFixture, service string, port int, router string) {
	t.Helper()
	config := service + "-host"
	body := fmt.Sprintf(`{"protocol":"tcp","address":"127.0.0.1","port":%d}`, port)
	openZitiCLI(t, fixture, "edge", "create", "config", config, "host.v1", body)
	openZitiCLI(t, fixture, "edge", "create", "service", service, "--configs", config)
	openZitiCLI(t, fixture, "edge", "create", "service-policy", service+"-bind", "Bind", "--service-roles", "@"+service, "--identity-roles", "@"+router)
}

func openZitiCreateDialPolicy(t *testing.T, fixture *openZitiFixture, service, identity string) {
	t.Helper()
	openZitiCLI(t, fixture, "edge", "create", "service-policy", service+"-dial", "Dial", "--service-roles", "@"+service, "--identity-roles", "@"+identity)
}

func openZitiRotateIdentity(t *testing.T, fixture *openZitiFixture, destination string) {
	t.Helper()
	// The original identity is deleted after the replacement is enrolled. This
	// turns stale-file reuse into a real authorization failure.
	root := filepath.Dir(destination)
	jwt := filepath.Join(root, "rotated.jwt")
	rotated := filepath.Join(root, "rotated.json")
	openZitiCLI(t, fixture, "edge", "create", "identity", "perimeterd-feed-client-rotated", "--jwt-output-file", jwt)
	openZitiCLI(t, fixture, "edge", "enroll", "--jwt", jwt, "--out", rotated)
	if err := os.Chmod(rotated, 0o600); err != nil {
		t.Fatal(err)
	}
	openZitiCLI(t, fixture, "edge", "create", "service-policy", openZitiAltService+"-rotated-dial", "Dial", "--service-roles", "@"+openZitiAltService, "--identity-roles", "@perimeterd-feed-client-rotated")
	if err := os.Remove(destination); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(rotated, destination); err != nil {
		t.Fatal(err)
	}
	openZitiCLI(t, fixture, "edge", "delete", "service-policy", openZitiAltService+"-dial")
	openZitiCLI(t, fixture, "edge", "delete", "identity", "perimeterd-feed-client")
}

func openZitiFirewallConfig(backend, table string) string {
	if backend == "nftables" {
		return fmt.Sprintf(`firewall:
  backend: nftables
  deny_action: reject
  ipv4: true
  ipv6: true
  nftables:
    table: %q
    priority: -10
`, table)
	}
	return `firewall:
  backend: iptables
  deny_action: reject
  ipv4: true
  ipv6: true
  iptables:
    attachments:
      - chain: INPUT
        direction: ingress
      - chain: OUTPUT
        direction: egress
`
}

func openZitiWriteConfig(t *testing.T, path, sourceURL, identityPath, service string, port int, includePolicy bool, backend, directURL string) {
	t.Helper()
	policy := "policies: []\n"
	if includePolicy {
		policy = fmt.Sprintf(`policies:
  - name: ziti-private
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [%q]
    include:
      ip_lists: [private, direct]
`, fmt.Sprintf("%d/tcp", port))
	}
	body := fmt.Sprintf(`version: 1
logging:
  level: debug
  format: text
metrics:
  listen: ""
%s
global:
  allowlist: []
  blocklist: []
openziti:
  identities:
    private:
      identity_file: %q
ip_lists:
  private:
    url: %q
    refresh_interval: 500ms
    request_timeout: 3s
    transport:
      type: openziti
      identity: private
      service: %q
  direct:
    url: %q
    refresh_interval: 500ms
    request_timeout: 3s
groups: {}
%s
crowdsec:
  enabled: false
`, openZitiFirewallConfig(backend, fmt.Sprintf("pde2e_ziti_%d", os.Getpid())), identityPath, sourceURL, service, directURL, policy)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func openZitiWriteConfigWithTLS(t *testing.T, path, sourceURL, identityPath, service string, clearPort, tlsPort int, backend, directURL, tlsHost, tlsStage string) {
	t.Helper()
	// A separate list makes the TLS candidate part of the same complete source
	// transaction while the known-good clear-text evidence is retained.
	body := fmt.Sprintf(`version: 1
logging:
  level: debug
  format: text
metrics:
  listen: ""
%s
global:
  allowlist: []
  blocklist: []
openziti:
  identities:
    private:
      identity_file: %q
ip_lists:
  private:
    url: %q
    refresh_interval: 500ms
    request_timeout: 3s
    transport:
      type: openziti
      identity: private
      service: %q
  direct:
    url: %q
    refresh_interval: 500ms
    request_timeout: 3s
  tls:
    url: %q
    refresh_interval: 500ms
    request_timeout: 3s
    transport:
      type: openziti
      identity: private
      service: %q
groups: {}
policies:
  - name: ziti-private
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: [%q]
    include:
      ip_lists: [private, direct, tls]
crowdsec:
  enabled: false
`, openZitiFirewallConfig(backend, fmt.Sprintf("pde2e_ziti_%d", os.Getpid())), identityPath, sourceURL, openZitiAltService, directURL, "https://"+tlsHost+":"+fmt.Sprint(tlsPort)+"/feed?stage="+tlsStage, openZitiTLSService, fmt.Sprintf("%d/tcp", clearPort))
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func openZitiCheckDirectOnly(t *testing.T, home string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "direct.yaml")
	cliDir := filepath.Join(home, "cli")
	if err := os.MkdirAll(cliDir, 0o700); err != nil {
		t.Fatal(err)
	}
	body := `version: 1
firewall: {backend: nftables}
openziti:
  identities:
    unused:
      identity_file: /definitely/not/a/runtime/credential.json
ip_lists: {}
groups: {}
policies: []
crowdsec:
  enabled: false
`
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, e2eBinary(t), "validate", "--config", path) // #nosec G204 -- repository-built binary with a test-owned configuration.
	cmd.Env = append(os.Environ(), "HOME="+home, "ZITI_HOME="+home, "ZITI_CONFIG_DIR="+cliDir)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("direct-only validation touched an unused identity or failed: %v (%s)", err, openZitiRedact(output))
	}
}

func openZitiBackendScenario(t *testing.T) string {
	t.Helper()
	switch scenario := os.Getenv(e2eScenario); scenario {
	case "nftables":
		return scenario
	case "iptables-legacy":
		installIPTablesTools(t, "legacy")
		return "iptables"
	case "iptables-nft":
		installIPTablesTools(t, "nft")
		return "iptables"
	default:
		t.Fatalf("unknown OpenZiti backend scenario %q", scenario)
		return ""
	}
}

func openZitiStartDaemon(t *testing.T, configPath, backend, table string) *daemonProcess {
	t.Helper()
	var daemon *daemonProcess
	if backend == "nftables" {
		daemon = startDaemon(t, configPath, table)
	} else {
		daemon = startDaemonProcess(t, configPath, "OpenZiti iptables policy", func() bool {
			return activeIPTablesRevision() != ""
		})
	}
	t.Cleanup(func() {
		daemon.stop(t)
		if err := daemon.waitErr(); err != nil {
			t.Errorf("OpenZiti perimeterd exited unsuccessfully: %v\n%s", err, openZitiRedact([]byte(daemon.output.String())))
		}
	})
	return daemon
}

func openZitiSetEnv(t *testing.T, key, value string) func() {
	t.Helper()
	old, present := os.LookupEnv(key)
	if err := os.Setenv(key, value); err != nil {
		t.Fatalf("set %s: %v", key, err)
	}
	return func() {
		if present {
			_ = os.Setenv(key, old)
		} else {
			_ = os.Unsetenv(key)
		}
	}
}

func openZitiSetNetworkTripwires(t *testing.T) func() {
	t.Helper()
	keys := []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "all_proxy", "no_proxy"}
	old := make(map[string]string, len(keys))
	present := make(map[string]bool, len(keys))
	for _, key := range keys {
		old[key], present[key] = os.LookupEnv(key)
	}
	for _, key := range []string{"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "http_proxy", "https_proxy", "all_proxy"} {
		if err := os.Setenv(key, "http://127.0.0.1:1"); err != nil {
			t.Fatalf("set proxy tripwire %s: %v", key, err)
		}
	}
	if err := os.Setenv("NO_PROXY", "127.0.0.1,localhost,[::1]"); err != nil {
		t.Fatalf("set NO_PROXY tripwire: %v", err)
	}
	if err := os.Setenv("no_proxy", "127.0.0.1,localhost,[::1]"); err != nil {
		t.Fatalf("set no_proxy tripwire: %v", err)
	}
	return func() {
		for _, key := range keys {
			if present[key] {
				_ = os.Setenv(key, old[key])
			} else {
				_ = os.Unsetenv(key)
			}
		}
	}
}

func openZitiWriteTLSCA(t *testing.T, server *httptest.Server) string {
	t.Helper()
	certificate := server.Certificate()
	if certificate == nil {
		t.Fatal("TLS fixture did not expose its application certificate")
	}
	path := filepath.Join(t.TempDir(), "application-ca.pem")
	data := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	return path
}

type openZitiHTTPFixture struct {
	server *httptest.Server
	mu     sync.Mutex
	stages map[string]int
	body   string
	host   string
}

func openZitiNewHTTPFixture(t *testing.T) *openZitiHTTPFixture {
	t.Helper()
	return openZitiNewHTTPFixtureForHost(t, "feed.private.invalid")
}

func openZitiNewDirectHTTPFixture(t *testing.T) *openZitiHTTPFixture {
	t.Helper()
	return openZitiNewHTTPFixtureForHost(t, "")
}

func openZitiNewHTTPFixtureForHost(t *testing.T, host string) *openZitiHTTPFixture {
	t.Helper()
	fixture := &openZitiHTTPFixture{
		stages: make(map[string]int),
		body:   fixtureIPv4Peer + "/32\n" + fixtureIPv6Peer + "/128\n",
		host:   host,
	}
	fixture.server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fixture.RecordStage(r.URL.Query().Get("stage"))
		if fixture.host != "" && !strings.HasPrefix(r.Host, fixture.host) {
			// The URL host is part of the application contract; reject direct
			// requests that rewrite it to localhost or the service name.
			http.Error(w, "wrong host", http.StatusBadRequest)
			return
		}
		if fixture.host != "" && r.URL.Path == "/cross" {
			http.Redirect(w, r, "http://other.private.invalid/feed?stage=cross-target", http.StatusFound)
			return
		}
		if fixture.host != "" && r.URL.Path == "/redirect" {
			http.Redirect(w, r, "/feed?"+r.URL.RawQuery, http.StatusFound) // #nosec G710 -- fixture keeps redirects relative and copies only the query used to identify the test stage.
			return
		}
		if r.URL.Path != "/feed" {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, fixture.body)
	}))
	t.Cleanup(fixture.Close)
	return fixture
}

func (f *openZitiHTTPFixture) URL(path string) string {
	if f.host == "" {
		return f.server.URL + path
	}
	return "http://" + f.host + ":" + f.ListenerPortString() + path
}

func (f *openZitiHTTPFixture) ListenerPort() int          { return f.server.Listener.Addr().(*net.TCPAddr).Port }
func (f *openZitiHTTPFixture) ListenerPortString() string { return fmt.Sprint(f.ListenerPort()) }
func (f *openZitiHTTPFixture) Body() string               { return f.body }
func (f *openZitiHTTPFixture) Close() {
	if f.server != nil {
		f.server.Close()
	}
}

func (f *openZitiHTTPFixture) RecordStage(stage string) {
	f.mu.Lock()
	f.stages[stage]++
	f.mu.Unlock()
}

func (f *openZitiHTTPFixture) StageRequests(stage string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.stages[stage]
}

func openZitiWaitStage(t *testing.T, fixture *openZitiFixture, stage string, count int) {
	t.Helper()
	openZitiWaitHTTPStage(t, fixture.feed, stage, count)
}

func openZitiWaitHTTPStage(t *testing.T, fixture *openZitiHTTPFixture, stage string, count int) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		if fixture.StageRequests(stage) >= count {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("source stage %q did not receive request %d (got %d)", stage, count, fixture.StageRequests(stage))
}

func openZitiRequireBinary(t *testing.T) string {
	t.Helper()
	path := os.Getenv(openZitiBinaryEnv)
	if path == "" {
		t.Fatal("ZITI_TEST_BINARY is required when PERIMETERD_OPENZITI_E2E=1 (OpenZiti CLI v2.0.4)")
	}
	path, err := filepath.Abs(path)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat ZITI_TEST_BINARY: %v", err)
	}
	if info.Mode()&0o111 == 0 {
		t.Fatalf("ZITI_TEST_BINARY is not executable: %s", path)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	stateDir := t.TempDir()
	cliDir := filepath.Join(stateDir, "cli")
	if err := os.MkdirAll(cliDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, path, "version") // #nosec G204 G702 -- explicit operator-selected fixture binary prerequisite, fixed arguments.
	cmd.Env = append(os.Environ(), "HOME="+stateDir, "ZITI_HOME="+stateDir, "ZITI_CONFIG_DIR="+cliDir)
	out, err := cmd.CombinedOutput()
	if err != nil || !regexp.MustCompile(`(?:v|Version\s+)?2\.0\.4\b`).Match(out) {
		t.Fatalf("ZITI_TEST_BINARY must be OpenZiti v%s: %v", openZitiVersion, err)
	}
	return path
}

func openZitiCLI(t *testing.T, fixture *openZitiFixture, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, fixture.ziti, args...) // #nosec G204 G702 -- pinned fixture CLI with test-owned argv, no shell.
	cmd.Env = append(os.Environ(), "HOME="+fixture.home, "ZITI_HOME="+fixture.home, "ZITI_CONFIG_DIR="+filepath.Join(fixture.home, "cli"))
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("ziti %s failed: %v (%s)", openZitiSafeArgs(args...), err, openZitiRedact(out))
	}
	return out
}

func openZitiSafeArgs(args ...string) string {
	text := strings.Join(args, " ")
	text = strings.ReplaceAll(text, openZitiAdminPass, "<redacted>")
	text = strings.ReplaceAll(text, "perimeterd-real-crowdsec-openziti-key", "<redacted>")
	return text
}

func openZitiFreePort(t *testing.T) int {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	port := listener.Addr().(*net.TCPAddr).Port
	_ = listener.Close()
	return port
}

type openZitiProcess struct {
	cmd    *exec.Cmd
	done   chan struct{}
	mu     sync.Mutex
	err    error
	output *lockedBuffer
}

func (p *openZitiProcess) wait() {
	err := p.cmd.Wait()
	p.mu.Lock()
	p.err = err
	p.mu.Unlock()
	close(p.done)
}

func (p *openZitiProcess) stop(t *testing.T) {
	t.Helper()
	select {
	case <-p.done:
		return
	default:
	}
	if p.cmd.Process != nil {
		_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM)
	}
	select {
	case <-p.done:
	case <-time.After(15 * time.Second):
		if p.cmd.Process != nil {
			_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
		}
		<-p.done
		t.Errorf("OpenZiti process did not stop within 15s")
	}
}

func openZitiWaitPort(t *testing.T, process *openZitiProcess, port int) {
	t.Helper()
	deadline := time.Now().Add(60 * time.Second)
	for time.Now().Before(deadline) {
		select {
		case <-process.done:
			process.mu.Lock()
			err := process.err
			process.mu.Unlock()
			t.Fatalf("fixture exited before port %d was ready: %v\n%s", port, err, openZitiRedact([]byte(process.output.String())))
		default:
		}
		conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
		if err == nil {
			_ = conn.Close()
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("fixture did not expose port %d\n%s", port, openZitiRedact([]byte(process.output.String())))
}

func openZitiRedact(value []byte) string {
	text := string(value)
	if strings.Contains(text, "PRIVATE KEY") {
		return "output suppressed: private key material"
	}
	for _, token := range []string{"password", "token", "jwt", "authorization", "key"} {
		text = regexp.MustCompile(`(?i)`+regexp.QuoteMeta(token)+`[^\n]*`).ReplaceAllString(text, token+"=<redacted>")
	}
	if len(text) > 12000 {
		text = text[len(text)-12000:]
	}
	return text
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
		info, statErr := os.Stat(path)
		if statErr != nil {
			t.Fatalf("%s must contain %s: %v", openZitiCrowdBindirEnv, path, statErr)
		}
		if info.Mode()&0o111 == 0 {
			t.Fatalf("CrowdSec prerequisite is not executable: %s", path)
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
	openZitiWaitCrowdPacket(t, peer, "tcp4", v4, "reject")
	openZitiWaitCrowdPacket(t, peer, "tcp6", v6, "success")

	// URL, API key, identity, and list route remain identical. Only the LAPI
	// service changes, selecting a different real authority behind the overlay.
	openZitiWriteCrowdPerimeterdConfig(t, configPath, fixture.identityPath, first.keyPath, first.port, backend, "perimeterd-private-lapi-1", feedURL)
	daemon.reload(t)
	openZitiWaitCrowdPacket(t, peer, "tcp4", v4, "success")
	openZitiWaitCrowdPacket(t, peer, "tcp6", v6, "reject")
	second.process.stop(t)
	// No LAPI can deliver an expiry delta now. The daemon/kernel must expire
	// the last authoritative decision rather than renewing it during outage.
	openZitiWaitCrowdPacket(t, peer, "tcp6", v6, "success")
	daemon.stop(t)
}

const openZitiBouncerKey = "perimeterd-real-crowdsec-openziti-key" // #nosec G101 -- isolated fixture credential, never used outside test namespaces.

type openZitiLAPI struct {
	process *openZitiProcess
	config  string
	keyPath string
	port    int
}

func openZitiStartLAPI(t *testing.T, crowdsec, cscli string) *openZitiLAPI {
	t.Helper()
	root := t.TempDir()
	port := openZitiFreePort(t)
	configPath, credentialsPath := openZitiWriteCrowdSecFixture(t, root, port)
	cmd := exec.Command(crowdsec, "-c", configPath, "-no-capi", "-no-cs", "-info") // #nosec G204 G702 -- explicit operator-selected pinned LAPI fixture, isolated namespaces, no shell.
	cmd.Env = append(os.Environ(), "HOME="+root, "XDG_CONFIG_HOME="+root)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	output := &lockedBuffer{}
	cmd.Stdout, cmd.Stderr = output, output
	process := &openZitiProcess{cmd: cmd, done: make(chan struct{}), output: output}
	if err := cmd.Start(); err != nil {
		t.Fatalf("start real CrowdSec v1.8.1 LAPI: %v", err)
	}
	go process.wait()
	t.Cleanup(func() { process.stop(t) })
	openZitiWaitPort(t, process, port)
	openZitiCrowdSecCLI(t, cscli, configPath, "machines", "add", "--auto", "--file", credentialsPath)
	openZitiCrowdSecCLI(t, cscli, configPath, "bouncers", "add", "perimeterd-openziti", "--key", openZitiBouncerKey)
	keyPath := filepath.Join(root, "bouncer.key")
	if err := os.WriteFile(keyPath, []byte(openZitiBouncerKey), 0o600); err != nil {
		t.Fatal(err)
	}
	return &openZitiLAPI{process: process, config: configPath, keyPath: keyPath, port: port}
}

func openZitiWriteCrowdSecFixture(t *testing.T, root string, port int) (string, string) {
	t.Helper()
	configDir := filepath.Join(root, "config")
	dataDir := filepath.Join(root, "data")
	for _, path := range []string{configDir, dataDir, filepath.Join(root, "hub"), filepath.Join(root, "notifications"), filepath.Join(root, "plugins"), filepath.Join(root, "acquis.d")} {
		if err := os.MkdirAll(path, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, content := range map[string]string{
		"acquis.yaml":     "# intentionally empty: decisions are inserted through the real LAPI\n",
		"profiles.yaml":   "name: perimeterd-e2e\nfilters: [\"true\"]\ndecisions:\n - type: ban\n   duration: 1m\n",
		"simulation.yaml": "",
		"console.yaml":    "",
	} {
		if err := os.WriteFile(filepath.Join(configDir, name), []byte(content), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	credentialsPath := filepath.Join(configDir, "local_api_credentials.yaml")
	if err := os.WriteFile(credentialsPath, []byte(fmt.Sprintf("url: http://127.0.0.1:%d\n", port)), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(configDir, "config.yaml")
	config := fmt.Sprintf(`common:
  daemonize: false
  log_media: stdout
  log_level: info
config_paths:
  config_dir: %q
  data_dir: %q
  simulation_path: %q
  hub_dir: %q
  index_path: %q
  notification_dir: %q
  plugin_dir: %q
crowdsec_service:
  acquisition_path: %q
  acquisition_dir: %q
  parser_routines: 1
cscli:
  output: raw
db_config:
  type: sqlite
  db_path: %q
api:
  client:
    insecure_skip_verify: false
    credentials_path: %q
  server:
    log_level: info
    listen_uri: 127.0.0.1:%d
    profiles_path: %q
    console_path: %q
    trusted_ips:
      - 127.0.0.1
      - "::1"
prometheus:
  enabled: false
`, configDir, dataDir, filepath.Join(configDir, "simulation.yaml"), filepath.Join(root, "hub"), filepath.Join(root, "hub", ".index.json"), filepath.Join(root, "notifications"), filepath.Join(root, "plugins"), filepath.Join(configDir, "acquis.yaml"), filepath.Join(configDir, "acquis.d"), filepath.Join(dataDir, "crowdsec.db"), credentialsPath, port, filepath.Join(configDir, "profiles.yaml"), filepath.Join(configDir, "console.yaml"))
	if err := os.WriteFile(configPath, []byte(config), 0o600); err != nil {
		t.Fatal(err)
	}
	return configPath, credentialsPath
}

func openZitiWriteCrowdPerimeterdConfig(t *testing.T, path, identityPath, keyPath string, lapiPort int, backend, service, feedURL string) {
	t.Helper()
	body := fmt.Sprintf(`version: 1
logging:
  level: debug
  format: text
metrics:
  listen: ""
%s
global:
  allowlist: []
  blocklist: []
openziti:
  identities:
    lapi:
      identity_file: %q
ip_lists:
  shared:
    url: %q
    refresh_interval: 1h
    transport:
      type: openziti
      identity: lapi
      service: perimeterd-private-feed-alt
crowdsec:
  enabled: true
  lapi_url: %q
  api_key_file: %q
  update_frequency: 500ms
  transport:
    type: openziti
    identity: lapi
    service: %q
policies:
  - name: shared-identity-list
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["53/udp"]
    include:
      ip_lists: [shared]
groups: {}
`, openZitiFirewallConfig(backend, fmt.Sprintf("pde2e_ziti_crowd_%d", os.Getpid())), identityPath, feedURL, "http://lapi.private.invalid:"+fmt.Sprint(lapiPort), keyPath, service)
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatal(err)
	}
}

func openZitiCrowdSecCLI(t *testing.T, binary, config string, args ...string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	full := append([]string{"-c", config}, args...)
	cmd := exec.CommandContext(ctx, binary, full...) // #nosec G204 G702 -- explicit operator-selected pinned fixture CLI with test-owned argv, no shell.
	cmd.Env = append(os.Environ(), "HOME="+filepath.Dir(config))
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("CrowdSec command %s failed: %v (%s)", openZitiSafeArgs(args...), err, openZitiRedact(output))
	}
}

func openZitiWaitCrowdPacket(t *testing.T, peer *peerNamespace, network, address, expectation string) {
	t.Helper()
	listener, err := net.Listen(network, address)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = listener.Close() }()
	go echoTCP(listener)
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		cmd := peer.helper(t, "dial-tcp", network, address, expectation)
		if err := cmd.Run(); err == nil {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("CrowdSec native packet expectation %s did not converge", expectation)
}
