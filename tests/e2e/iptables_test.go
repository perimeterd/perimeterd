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
	"sync"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/app"
	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/state"
)

type iptablesTools struct {
	mode   string
	marker string
	log    string
}

func installIPTablesTools(t *testing.T, variant string) iptablesTools {
	t.Helper()
	if variant != "nft" && variant != "legacy" {
		t.Fatalf("unsupported iptables test variant %q", variant)
	}
	originalPath := os.Getenv("PATH")
	reals := make(map[string]string)
	baseNames := []string{"iptables", "ip6tables", "iptables-save", "ip6tables-save", "iptables-restore", "ip6tables-restore"}
	for _, name := range baseNames {
		variantName := strings.Replace(name, "tables", "tables-"+variant, 1)
		real, err := exec.LookPath(variantName)
		if err != nil {
			t.Fatalf("required %s tool %q is unavailable: %v", variant, variantName, err)
		}
		reals[name] = real
	}
	if real, err := exec.LookPath("ipset"); err != nil {
		t.Fatalf("required ipset tool is unavailable: %v", err)
	} else {
		reals["ipset"] = real
	}

	dir := t.TempDir()
	tools := iptablesTools{
		mode:   filepath.Join(dir, "failure-mode"),
		marker: filepath.Join(dir, "failure-marker"),
		log:    filepath.Join(dir, "commands.log"),
	}
	if err := os.WriteFile(tools.mode, nil, 0o600); err != nil {
		t.Fatalf("create iptables failure mode: %v", err)
	}
	for name, real := range reals {
		wrapper := filepath.Join(dir, name)
		content := iptablesWrapperScript(real, tools)
		// #nosec G306 -- executable fixture in t.TempDir, accessible only to its owner.
		if err := os.WriteFile(wrapper, []byte(content), 0o700); err != nil {
			t.Fatalf("write %s wrapper: %v", name, err)
		}
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+originalPath)
	verifyIPTablesVariant(t, variant)
	return tools
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'"
}

func iptablesWrapperScript(real string, tools iptablesTools) string {
	return fmt.Sprintf(`#!/bin/sh
set -eu
name=${0##*/}
real=%s
log=%s
modefile=%s
marker=%s
printf '%%s %%s\n' "$name" "$*" >> "$log"
if [ "${1:-}" = "--version" ]; then exec "$real" "$@"; fi
mode=$(/bin/cat "$modefile")
case "$name" in
  iptables-restore|ip6tables-restore)
    tmp=$(/usr/bin/mktemp)
    trap '/bin/rm -f "$tmp"' EXIT
    /bin/cat > "$tmp"
    payload=$(/bin/cat "$tmp")
    commit=0
    case "$payload" in *"/dispatch"*) commit=1 ;; esac
    fail=0
    case "$mode" in
      all|retire) /usr/bin/touch "$marker.$mode"; fail=1 ;;
      precommit)
        if [ ! -e "$marker.precommit" ]; then
          /usr/bin/touch "$marker.precommit"; fail=1
        fi ;;
      v6-second)
        if [ "$name" = ip6tables-restore ] && [ "$commit" = 1 ] && [ ! -e "$marker.v6-second" ]; then
          /usr/bin/touch "$marker.v6-second"; fail=1
        fi ;;
      v6-second-comp)
        if [ "$commit" = 1 ]; then
          if [ -e "$marker.v6-second-comp-1" ]; then
            /usr/bin/touch "$marker.v6-second-comp-2"; fail=1
          elif [ "$name" = ip6tables-restore ]; then
            /usr/bin/touch "$marker.v6-second-comp-1"; fail=1
          fi
        fi ;;
    esac
    if [ "$fail" = 1 ]; then exit 42; fi
    "$real" "$@" < "$tmp"
    printf '%%s done\n' "$name" >> "$log"
    ;;
  *) exec "$real" "$@" ;;
esac
`, shellQuote(real), shellQuote(tools.log), shellQuote(tools.mode), shellQuote(tools.marker))
}

func verifyIPTablesVariant(t *testing.T, variant string) {
	t.Helper()
	want := "legacy"
	if variant == "nft" {
		want = "nf_tables"
	}
	for _, commandName := range []string{"iptables", "ip6tables"} {
		output := strings.ToLower(string(command(t, 10*time.Second, commandName, "--version")))
		if !strings.Contains(output, want) {
			t.Fatalf("%s selected %s variant, got %q", commandName, variant, output)
		}
	}
	if output := command(t, 10*time.Second, "ipset", "--version"); len(output) == 0 {
		t.Fatal("ipset --version returned no output")
	}
}

func writeFailureMode(t *testing.T, tools iptablesTools, mode string) {
	t.Helper()
	if err := os.WriteFile(tools.mode, []byte(mode), 0o600); err != nil {
		t.Fatalf("write iptables failure mode %q: %v", mode, err)
	}
	for _, suffix := range []string{"all", "precommit", "retire", "v6-second", "v6-second-comp-1", "v6-second-comp-2"} {
		_ = os.Remove(tools.marker + "." + suffix)
	}
}

func waitForFailureMarker(t *testing.T, tools iptablesTools, suffix string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(tools.marker + suffix); err == nil {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	data, _ := os.ReadFile(tools.log)
	t.Fatalf("iptables failure marker %q did not appear; command log:\n%s", suffix, data)
}

func activeIPTablesRevision() string {
	data, _ := os.ReadFile("/var/lib/perimeterd/active.json")
	return string(data)
}

func waitForIPTablesCommit(t *testing.T, before string) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		_, err := os.Stat("/var/lib/perimeterd/journal.json")
		active := activeIPTablesRevision()
		if os.IsNotExist(err) && active != "" && active != before {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("iptables transaction did not finish its durable commit")
}

func iptablesSaveMayFail(family string) ([]byte, error) {
	commandName := "iptables-save"
	if family == "v6" {
		commandName = "ip6tables-save"
	}
	return commandMayFail(10*time.Second, commandName, "--counters")
}

func iptablesOwned(t *testing.T, family string) bool {
	t.Helper()
	data, err := iptablesSaveMayFail(family)
	if err != nil {
		t.Fatalf("inspect %s iptables ownership: %v", family, err)
	}
	return strings.Contains(string(data), "perimeterd owner=")
}

func waitForIPTablesOwned(t *testing.T, families ...string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		ok := true
		for _, family := range families {
			if !iptablesOwned(t, family) {
				ok = false
				break
			}
		}
		if ok {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("iptables owned target did not appear for families %v", families)
}

func waitNoIPTablesOwned(t *testing.T, families ...string) {
	t.Helper()
	deadline := time.Now().Add(45 * time.Second)
	for time.Now().Before(deadline) {
		owned := false
		for _, family := range families {
			if iptablesOwned(t, family) {
				owned = true
				break
			}
		}
		if !owned {
			return
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("iptables owned target remained for families %v", families)
}

func assertIPTablesForeign(t *testing.T, family string) {
	t.Helper()
	data, err := iptablesSaveMayFail(family)
	if err != nil {
		t.Fatalf("inspect %s foreign state: %v", family, err)
	}
	if !strings.Contains(string(data), "e2e-foreign") {
		t.Fatalf("%s foreign parent rule was not preserved:\n%s", family, data)
	}
	commandName := "iptables"
	if family == "v6" {
		commandName = "ip6tables"
	}
	for _, chain := range []string{"E2EI", "E2EO"} {
		command(t, 10*time.Second, commandName, "-C", chain, "-m", "comment", "--comment", "e2e-foreign\ncomment", "-j", "RETURN")
	}
}

func seedIPTablesParents(t *testing.T) {
	t.Helper()
	for _, commandName := range []string{"iptables", "ip6tables"} {
		command(t, 10*time.Second, commandName, "-N", "E2EI")
		command(t, 10*time.Second, commandName, "-N", "E2EO")
		command(t, 10*time.Second, commandName, "-A", "INPUT", "-i", "e2h0", "-j", "E2EI")
		command(t, 10*time.Second, commandName, "-A", "OUTPUT", "-o", "e2h0", "-j", "E2EO")
	}
}

func addIPTablesForeignRules(t *testing.T) {
	t.Helper()
	for _, commandName := range []string{"iptables", "ip6tables"} {
		command(t, 10*time.Second, commandName, "-A", "OUTPUT")
		command(t, 10*time.Second, commandName, "-A", "E2EI", "-m", "comment", "--comment", "e2e-foreign\ncomment", "-j", "RETURN")
		command(t, 10*time.Second, commandName, "-A", "E2EO", "-m", "comment", "--comment", "e2e-foreign\ncomment", "-j", "RETURN")
	}
}

func writeIPTablesConfig(t *testing.T, path, action string, allow, block []string, ipv4, ipv6 bool, attachments []config.Attachment) {
	t.Helper()
	var yaml strings.Builder
	yaml.WriteString("version: 1\n")
	yaml.WriteString("logging:\n  level: error\n  format: text\n")
	yaml.WriteString("metrics:\n  listen: \"127.0.0.1:19095\"\n")
	yaml.WriteString("global:\n")
	writePrefixesYAML(&yaml, "allowlist", allow)
	writePrefixesYAML(&yaml, "blocklist", block)
	fmt.Fprintf(&yaml, "firewall:\n  backend: iptables\n  deny_action: %s\n  ipv4: %t\n  ipv6: %t\n  iptables:\n", action, ipv4, ipv6)
	if len(attachments) == 0 {
		yaml.WriteString("    attachments: []\n")
	} else {
		yaml.WriteString("    attachments:\n")
	}
	for _, attachment := range attachments {
		fmt.Fprintf(&yaml, "      - chain: %q\n        direction: %q\n", attachment.Chain, attachment.Direction)
		if len(attachment.InputInterfaces) > 0 {
			yaml.WriteString("        input_interfaces: [")
			for i, iface := range attachment.InputInterfaces {
				if i > 0 {
					yaml.WriteString(", ")
				}
				fmt.Fprintf(&yaml, "%q", iface)
			}
			yaml.WriteString("]\n")
		}
		if len(attachment.OutputInterfaces) > 0 {
			yaml.WriteString("        output_interfaces: [")
			for i, iface := range attachment.OutputInterfaces {
				if i > 0 {
					yaml.WriteString(", ")
				}
				fmt.Fprintf(&yaml, "%q", iface)
			}
			yaml.WriteString("]\n")
		}
		if attachment.OriginalDestination {
			yaml.WriteString("        original_destination: true\n")
		}
	}
	yaml.WriteString("geo:\n  refresh_interval: 24h\n  request_timeout: 1s\n  refresh_jitter: 1s\n")
	yaml.WriteString("groups: {}\npolicies: []\ncrowdsec:\n  enabled: false\n")
	if err := os.WriteFile(path, []byte(yaml.String()), 0o600); err != nil {
		t.Fatalf("write iptables config: %v", err)
	}
}

func writePrefixesYAML(yaml *strings.Builder, name string, values []string) {
	if len(values) == 0 {
		fmt.Fprintf(yaml, "  %s: []\n", name)
		return
	}
	fmt.Fprintf(yaml, "  %s:\n", name)
	for _, value := range values {
		fmt.Fprintf(yaml, "    - %q\n", value)
	}
}

func startIPTablesDaemon(t *testing.T, configPath string, families ...string) *daemonProcess {
	t.Helper()
	binary := e2eBinary(t)
	output := new(lockedBuffer)
	notifyPath := filepath.Join(t.TempDir(), "ready.sock")
	notify, err := net.ListenUnixgram("unixgram", &net.UnixAddr{Name: notifyPath, Net: "unixgram"})
	if err != nil {
		t.Fatalf("listen for iptables daemon readiness: %v", err)
	}
	t.Cleanup(func() {
		_ = notify.Close()
		_ = os.Remove(notifyPath)
	})
	// #nosec G204 -- the validated E2E binary is launched only by this harness.
	cmd := exec.Command(binary, "run", "--config", configPath)
	cmd.Env = append(os.Environ(), "NOTIFY_SOCKET="+notifyPath)
	cmd.Stdout = output
	cmd.Stderr = output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start iptables perimeterd: %v", err)
	}
	d := &daemonProcess{cmd: cmd, output: output, done: make(chan struct{})}
	go func() {
		err := cmd.Wait()
		d.mu.Lock()
		d.err = err
		d.mu.Unlock()
		close(d.done)
	}()
	t.Cleanup(func() { d.stop(t) })
	deadline := time.Now().Add(45 * time.Second)
	ready := false
	for time.Now().Before(deadline) {
		select {
		case <-d.done:
			t.Fatalf("iptables perimeterd exited during startup: %v\n%s", d.waitErr(), d.output.String())
		default:
		}
		if !ready {
			_ = notify.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			var packet [4096]byte
			n, _, readErr := notify.ReadFromUnix(packet[:])
			if readErr != nil {
				if netErr, ok := readErr.(net.Error); !ok || !netErr.Timeout() {
					t.Fatalf("read iptables readiness: %v\n%s", readErr, d.output.String())
				}
				continue
			}
			ready = bytes.Contains(packet[:n], []byte("READY=1"))
			continue
		}
		if len(families) == 0 {
			return d
		}
		owned := true
		for _, family := range families {
			if !iptablesOwned(t, family) {
				owned = false
				break
			}
		}
		if owned {
			_ = notify.Close()
			_ = os.Remove(notifyPath)
			return d
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("iptables perimeterd did not become ready for families %v\n%s", families, d.output.String())
	return nil
}

func defaultIPTablesAttachments() []config.Attachment {
	return []config.Attachment{{Chain: "INPUT", Direction: "ingress"}, {Chain: "OUTPUT", Direction: "egress"}}
}

func customIPTablesAttachments() []config.Attachment {
	return []config.Attachment{
		{Chain: "E2EI", Direction: "ingress", InputInterfaces: []string{"unused0", "e2h0", "e2h+"}},
		{Chain: "E2EO", Direction: "egress", OutputInterfaces: []string{"unused0", "e2h0", "e2h+"}},
	}
}

func TestE2EIPTables(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, variant := range []string{"nft", "legacy"} {
			t.Run(variant, func(t *testing.T) { runIsolated(t, "TestE2EIPTables", variant) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	installIPTablesTools(t, os.Getenv(e2eScenario))
	peer := newPeerNamespace(t)
	seedIPTablesParents(t)
	addIPTablesForeignRules(t)
	command(t, 10*time.Second, "ipset", "create", "e2e_foreign", "hash:ip", "comment")
	command(t, 10*time.Second, "ipset", "add", "e2e_foreign", "8.21.2.3", "comment", "foreign entry")
	configPath := tempConfig(t, "iptables")
	writeIPTablesConfig(t, configPath, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128", fixtureLANPeer + "/32"}, true, true, customIPTablesAttachments())
	daemon := startIPTablesDaemon(t, configPath, "v4", "v6")

	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18380", "drop", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18380", "drop", "tcp")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18381", "drop", "tcp")
	probeEgress(t, peer, "tcp6", "["+fixtureIPv6Peer+"]:18381", "drop", "tcp")
	probeIngress(t, peer, "udp4", fixtureIPv4Host+":18382", "drop", "udp")
	probeIngress(t, peer, "udp6", "["+fixtureIPv6Host+"]:18382", "drop", "udp")
	probeEgress(t, peer, "udp4", fixtureIPv4Peer+":18383", "drop", "udp")
	probeEgress(t, peer, "udp6", "["+fixtureIPv6Peer+"]:18383", "drop", "udp")
	probeIngress(t, peer, "tcp4", fixtureLANHost+":18384", "success", "tcp")
	probeEgress(t, peer, "tcp4", fixtureLANPeer+":18384", "success", "tcp")
	processedBefore := iptablesProcessedPackets(t, "entry_v4_ingress/processed")

	// Global allow entries are deliberately identical /0 entries in both
	// families. They must precede the matching blocks without accepting other
	// traffic implicitly.
	writeIPTablesConfig(t, configPath, "drop", []string{"0.0.0.0/0", "::/0"}, []string{"0.0.0.0/0", "::/0"}, true, true, customIPTablesAttachments())
	before := activeIPTablesRevision()
	daemon.reload(t)
	waitForIPTablesCommit(t, before)
	if after := iptablesProcessedPackets(t, "entry_v4_ingress/processed"); after < processedBefore {
		t.Fatalf("reload reset stable processed counter: %d -> %d", processedBefore, after)
	}
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18380", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18380", "success", "tcp")
	probeEgress(t, peer, "udp4", fixtureIPv4Peer+":18383", "success", "udp")
	probeEgress(t, peer, "udp6", "["+fixtureIPv6Peer+"]:18383", "success", "udp")
	processedBefore = iptablesProcessedPackets(t, "entry_v4_ingress/processed")
	probeIngress(t, peer, "udp4", fixtureIPv4Host+":18385", "success", "udp")
	if after := iptablesProcessedPackets(t, "entry_v4_ingress/processed"); after != processedBefore+1 {
		t.Fatalf("overlapping interface matches processed one packet more than once: %d -> %d", processedBefore, after)
	}
	// RETURN must leave the parent's later verdict in control.
	command(t, 10*time.Second, "iptables", "-I", "E2EO", "2", "-p", "tcp", "--dport", "18386", "-j", "REJECT", "--reject-with", "tcp-reset")
	probeEgress(t, peer, "tcp4", fixtureIPv4Peer+":18386", "reject", "tcp")
	command(t, 10*time.Second, "iptables", "-D", "E2EO", "-p", "tcp", "--dport", "18386", "-j", "REJECT", "--reject-with", "tcp-reset")
	listener, ready := startPeerListener(t, peer, "tcp4", fixtureIPv4Peer+":18387")
	select {
	case ok := <-ready:
		if !ok {
			t.Fatal("established-flow listener failed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("established-flow listener timed out")
	}
	conn, err := net.DialTimeout("tcp4", fixtureIPv4Peer+":18387", time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close(); _ = listener.Process.Kill(); _ = listener.Wait() }()
	exchangeIPTablesByte(t, conn)

	writeIPTablesConfig(t, configPath, "reject", nil, []string{"0.0.0.0/0", "::/0"}, true, true, customIPTablesAttachments())
	before = activeIPTablesRevision()
	daemon.reload(t)
	waitForIPTablesCommit(t, before)
	exchangeIPTablesByte(t, conn)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18380", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18380", "reject", "tcp")
	probeEgress(t, peer, "udp4", fixtureIPv4Peer+":18383", "reject", "udp")
	probeEgress(t, peer, "udp6", "["+fixtureIPv6Peer+"]:18383", "reject", "udp")

	// Disabling one family retires only that family. An entirely disabled
	// model is the canonical empty target and unhooks both families.
	writeIPTablesConfig(t, configPath, "reject", nil, []string{"0.0.0.0/0"}, true, false, customIPTablesAttachments())
	before = activeIPTablesRevision()
	daemon.reload(t)
	waitForIPTablesCommit(t, before)
	waitForIPTablesOwned(t, "v4")
	waitNoIPTablesOwned(t, "v6")
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18380", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18380", "success", "tcp")

	writeIPTablesConfig(t, configPath, "reject", nil, nil, false, false, customIPTablesAttachments())
	before = activeIPTablesRevision()
	daemon.reload(t)
	waitForIPTablesCommit(t, before)
	waitNoIPTablesOwned(t, "v4", "v6")
	assertIPTablesForeign(t, "v4")
	assertIPTablesForeign(t, "v6")

	writeIPTablesConfig(t, configPath, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, true, true, customIPTablesAttachments())
	before = activeIPTablesRevision()
	daemon.reload(t)
	waitForIPTablesCommit(t, before)
	waitForIPTablesOwned(t, "v4", "v6")

	// TERM retains the committed native target. Explicit cleanup removes only
	// owned chains and leaves both configured parents and foreign rules.
	daemon.stop(t)
	if !iptablesOwned(t, "v4") || !iptablesOwned(t, "v6") {
		t.Fatal("normal daemon shutdown removed the committed iptables target")
	}
	// A foreign reference into an owned chain fences cleanup rather than
	// broadening the deletion boundary to the administrator's rule.
	saved, err := iptablesSaveMayFail("v4")
	if err != nil {
		t.Fatal(err)
	}
	var ownedChain string
	for _, line := range strings.Split(string(saved), "\n") {
		if strings.HasPrefix(line, ":pdc") {
			ownedChain = strings.TrimPrefix(strings.Fields(line)[0], ":")
			break
		}
	}
	if ownedChain == "" {
		t.Fatal("missing owned chain")
	}
	command(t, 10*time.Second, "iptables", "-A", "E2EI", "-j", ownedChain)
	if err := runCleanupExpectFailure(t); err == nil {
		t.Fatal("cleanup accepted foreign reference")
	}
	if !iptablesOwned(t, "v4") {
		t.Fatal("failed cleanup removed owned evidence")
	}
	command(t, 10*time.Second, "iptables", "-D", "E2EI", "-j", ownedChain)
	command(t, 30*time.Second, e2eBinary(t), "cleanup")
	waitNoIPTablesOwned(t, "v4", "v6")
	assertIPTablesForeign(t, "v4")
	assertIPTablesForeign(t, "v6")
	command(t, 10*time.Second, "ipset", "test", "e2e_foreign", "8.21.2.3")
}

func TestE2EIPTablesEmptyAttachment(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, variant := range []string{"nft", "legacy"} {
			t.Run(variant, func(t *testing.T) { runIsolated(t, "TestE2EIPTablesEmptyAttachment", variant) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	installIPTablesTools(t, os.Getenv(e2eScenario))
	newPeerNamespace(t)
	seedIPTablesParents(t)
	addIPTablesForeignRules(t)
	configPath := tempConfig(t, "empty-attachment")
	writeIPTablesConfig(t, configPath, "drop", nil, []string{fixtureIPv4Peer + "/32"}, true, true, []config.Attachment{})
	if err := runRunExpectFailure(t, configPath); err == nil {
		t.Fatal("iptables configuration with empty attachments unexpectedly committed")
	}
	if iptablesOwned(t, "v4") || iptablesOwned(t, "v6") {
		t.Fatal("empty attachment validation mutated native firewall state")
	}
	assertIPTablesForeign(t, "v4")
	assertIPTablesForeign(t, "v6")
	writeIPTablesConfig(t, configPath, "drop", nil, nil, false, false, []config.Attachment{})
	path := os.Getenv("PATH")
	t.Setenv("PATH", t.TempDir())
	daemon := startIPTablesDaemon(t, configPath)
	daemon.stop(t)
	command(t, 30*time.Second, e2eBinary(t), "cleanup")
	t.Setenv("PATH", path)
	waitNoIPTablesOwned(t, "v4", "v6")
}

func TestE2EIPTablesFailures(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, variant := range []string{"nft", "legacy"} {
			t.Run(variant, func(t *testing.T) { runIsolated(t, "TestE2EIPTablesFailures", variant) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	tools := installIPTablesTools(t, os.Getenv(e2eScenario))
	peer := newPeerNamespace(t)
	configPath := tempConfig(t, "iptables-failure")
	writeIPTablesConfig(t, configPath, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, true, true, defaultIPTablesAttachments())
	daemon := startIPTablesDaemon(t, configPath, "v4", "v6")

	// The second-family commit fails after the real v4 switch. A one-shot
	// wrapper failure lets the engine compensate both families and preserve the
	// old DROP target.
	writeIPTablesConfig(t, configPath, "reject", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, true, true, defaultIPTablesAttachments())
	writeFailureMode(t, tools, "v6-second")
	daemon.reload(t)
	waitForFailureMarker(t, tools, ".v6-second")
	waitForIPTablesCommit(t, "")
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18480", "drop", "tcp")
	writeFailureMode(t, tools, "")
	writeIPTablesConfig(t, configPath, "reject", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, true, true, defaultIPTablesAttachments())
	before := activeIPTablesRevision()
	daemon.reload(t)
	waitForIPTablesCommit(t, before)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18480", "reject", "tcp")

	// Fail the same second-family commit and its compensating restore. The
	// journal is intentionally retained; after TERM, startup Recover repairs the
	// old target once the wrapper is disarmed.
	writeIPTablesConfig(t, configPath, "drop", []string{"0.0.0.0/0", "::/0"}, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, true, true, defaultIPTablesAttachments())
	writeFailureMode(t, tools, "v6-second-comp")
	daemon.reload(t)
	waitForFailureMarker(t, tools, ".v6-second-comp-1")
	waitForFailureMarker(t, tools, ".v6-second-comp-2")
	waitForIPTablesHealth(t, false)
	selected := activeIPTablesRevision()
	daemon.reload(t)
	for range 3 {
		time.Sleep(300 * time.Millisecond)
		waitForIPTablesHealth(t, false)
	}
	if activeIPTablesRevision() != selected {
		t.Fatal("unrecovered writer committed another candidate")
	}
	journal := filepath.Join("/var/lib/perimeterd", "journal.json")
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if _, err := os.Stat(journal); err == nil {
			break
		}
		time.Sleep(50 * time.Millisecond)
	}
	if _, err := os.Stat(journal); err != nil {
		t.Fatalf("failed compensation discarded journal: %v", err)
	}
	daemon.stop(t)
	writeFailureMode(t, tools, "")
	writeIPTablesConfig(t, configPath, "reject", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, true, true, defaultIPTablesAttachments())
	daemon = startIPTablesDaemon(t, configPath, "v4", "v6")
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18480", "reject", "tcp")
	daemon.stop(t)
	command(t, 30*time.Second, e2eBinary(t), "cleanup")
	waitNoIPTablesOwned(t, "v4", "v6")
}

func TestE2EIPTablesMigration(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, variant := range []string{"nft", "legacy"} {
			t.Run(variant, func(t *testing.T) { runIsolated(t, "TestE2EIPTablesMigration", variant) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	tools := installIPTablesTools(t, os.Getenv(e2eScenario))
	peer := newPeerNamespace(t)
	table := fmt.Sprintf("pde2e_migrate_%d", os.Getpid())
	configPath := tempConfig(t, "migration")
	writeConfig(t, configPath, table, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	daemon := startDaemon(t, configPath, table)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18580", "drop", "tcp")

	// A pre-commit iptables restore failure leaves the nftables target selected.
	writeIPTablesConfig(t, configPath, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, true, true, defaultIPTablesAttachments())
	writeFailureMode(t, tools, "precommit")
	daemon.reload(t)
	waitForFailureMarker(t, tools, ".precommit")
	time.Sleep(2 * time.Second)
	if _, err := nftTableMayFail(table); err != nil {
		t.Fatalf("pre-commit migration failure removed nft target: %v", err)
	}
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18580", "drop", "tcp")
	writeFailureMode(t, tools, "")

	// Successful nftables -> iptables migration and reverse migration each
	// retain packet semantics while retiring only the old backend's artifacts.
	daemon.reload(t)
	waitForIPTablesOwned(t, "v4", "v6")
	waitNoNFTTable(t, table)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18580", "drop", "tcp")

	writeConfig(t, configPath, table+"_reverse", "reject", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	daemon.reload(t)
	waitForNFTTable(t, table+"_reverse")
	waitNoIPTablesOwned(t, "v4", "v6")
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18580", "reject", "tcp")

	// Retirement of the old iptables target occurs after nftables commit. The
	// injected failure therefore leaves the new target authoritative and the
	// old target recoverable for the next startup.
	before := activeIPTablesRevision()
	writeIPTablesConfig(t, configPath, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, true, true, defaultIPTablesAttachments())
	daemon.reload(t)
	// Staged objects appear before selection and durable commit. Do not let
	// the next failure injection interrupt this migration's installation.
	waitForIPTablesCommit(t, before)
	waitForIPTablesOwned(t, "v4", "v6")
	writeFailureMode(t, tools, "retire")
	writeConfig(t, configPath, table+"_reverse2", "reject", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, -10)
	daemon.reload(t)
	waitForFailureMarker(t, tools, ".retire")
	waitForNFTTable(t, table+"_reverse2")
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18580", "reject", "tcp")
	if !iptablesOwned(t, "v4") {
		t.Fatal("post-commit retirement failure unexpectedly removed old iptables target")
	}
	daemon.stop(t)
	writeFailureMode(t, tools, "")
	daemon = startDaemon(t, configPath, table+"_reverse2")
	waitNoIPTablesOwned(t, "v4", "v6")
	daemon.stop(t)
	command(t, 30*time.Second, e2eBinary(t), "cleanup")
	waitNoNFTTable(t, table+"_reverse2")
}

func writeIPTablesGeoConfig(t *testing.T, path string) {
	t.Helper()
	// Keep the source fixture and policy matrix in one place: geo_test.go is the
	// canonical fixture, while this conversion changes only the backend stanza.
	text := geoConfigYAML("unused-nft-table")
	text = strings.Replace(text, "  backend: nftables\n", "  backend: iptables\n", 1)
	old := "  nftables:\n    table: \"unused-nft-table\"\n    priority: -10\n"
	new := "  iptables:\n    attachments:\n      - chain: INPUT\n        direction: ingress\n        original_destination: true\n      - chain: OUTPUT\n        direction: egress\n"
	if !strings.Contains(text, old) {
		t.Fatal("geo fixture nftables stanza changed unexpectedly")
	}
	text = strings.Replace(text, old, new, 1)
	if err := os.WriteFile(path, []byte(text), 0o600); err != nil {
		t.Fatalf("write iptables geo config: %v", err)
	}
}

func TestE2EIPTablesGeo(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, variant := range []string{"nft", "legacy"} {
			t.Run(variant, func(t *testing.T) { runIsolated(t, "TestE2EIPTablesGeo", variant) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	installIPTablesTools(t, os.Getenv(e2eScenario))
	peer := newPeerNamespace(t)
	for _, pair := range []struct{ host, peer string }{
		{fixtureExcludedIPv4Host, fixtureExcludedIPv4Peer},
		{fixtureOtherIPv4Host, fixtureOtherIPv4Peer},
	} {
		command(t, 10*time.Second, "ip", "addr", "add", pair.host+"/24", "dev", "e2h0")
		peer.run(t, "ip", "addr", "add", pair.peer+"/24", "dev", "e2p0")
	}
	command(t, 10*time.Second, "ip", "-6", "addr", "add", fixtureOtherIPv6Host+"/64", "dev", "e2h0", "nodad")
	peer.run(t, "ip", "-6", "addr", "add", fixtureOtherIPv6Peer+"/64", "dev", "e2p0", "nodad")
	for _, subnet := range []string{"22", "23"} {
		command(t, 10*time.Second, "ip", "addr", "add", "8."+subnet+".0.1/24", "dev", "e2h0")
		peer.run(t, "ip", "addr", "add", "8."+subnet+".0.2/24", "dev", "e2p0")
		command(t, 10*time.Second, "ip", "-6", "addr", "add", "2600:"+subnet+"::1/64", "dev", "e2h0", "nodad")
		peer.run(t, "ip", "-6", "addr", "add", "2600:"+subnet+"::2/64", "dev", "e2p0", "nodad")
	}

	configPath := tempConfig(t, "iptables-geo")
	writeIPTablesGeoConfig(t, configPath)
	fixture := &geoFixtureTransport{started: time.Now(), validFor: 8 * time.Second}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	done := make(chan error, 1)
	ready := make(chan struct{})
	var readyOnce sync.Once
	go func() {
		done <- app.Run(ctx, app.Options{
			ConfigPath:   configPath,
			StateDir:     "/var/lib/perimeterd",
			LockPath:     "/run/perimeterd/owner.lock",
			SourceClient: &http.Client{Transport: fixture},
			Stderr:       os.Stderr,
			Notify: func(message string) error {
				if strings.Contains(message, "READY=1") {
					readyOnce.Do(func() { close(ready) })
				}
				return nil
			},
			StartupTimeout: 2 * time.Minute,
		})
	}()
	defer func() {
		cancel()
		select {
		case <-done:
		case <-time.After(20 * time.Second):
			t.Error("iptables geo daemon did not stop")
		}
	}()
	select {
	case <-ready:
	case <-time.After(45 * time.Second):
		t.Fatal("iptables geo daemon did not become ready")
	}
	waitForIPTablesOwned(t, "v4", "v6")
	if !fixture.country.Load() || !fixture.asn.Load() {
		t.Fatalf("source fixture did not receive country and ASN requests: country=%t asn=%t", fixture.country.Load(), fixture.asn.Load())
	}
	exerciseGeoPackets(t, peer, fixture)
	// A listening translated destination makes a missing original-port match
	// observable as a successful exchange, not an unrelated closed-port error.
	for _, tool := range []string{"iptables", "ip6tables"} {
		command(t, 10*time.Second, tool, "-t", "nat", "-A", "PREROUTING", "-i", "e2h0", "-p", "udp", "--dport", "18082", "-j", "REDIRECT", "--to-ports", "18882")
	}
	probeIngressAddresses(t, peer, "udp4", fixtureIPv4Host+":18882", fixtureIPv4Host+":18082", "reject", "udp")
	probeIngressAddresses(t, peer, "udp6", "["+fixtureIPv6Host+"]:18882", "["+fixtureIPv6Host+"]:18082", "reject", "udp")
}

func waitForIPTablesHealth(t *testing.T, healthy bool) {
	t.Helper()
	want := "perimeterd_enforcement_health 0\n"
	if healthy {
		want = "perimeterd_enforcement_health 1\n"
	}
	client := &http.Client{Timeout: time.Second}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		response, err := client.Get("http://127.0.0.1:19095/metrics")
		if err == nil {
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			if readErr == nil && strings.Contains(string(body), want) {
				return
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("enforcement health did not become %t", healthy)
}

func TestE2EIPTablesRecovery(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, variant := range []string{"nft", "legacy"} {
			t.Run(variant, func(t *testing.T) { runIsolated(t, "TestE2EIPTablesRecovery", variant) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	installIPTablesTools(t, os.Getenv(e2eScenario))
	peer := newPeerNamespace(t)
	path := tempConfig(t, "iptables-crash")
	block := []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}
	writeIPTablesConfig(t, path, "drop", nil, block, true, true, defaultIPTablesAttachments())
	daemon := startIPTablesDaemon(t, path, "v4", "v6")
	daemon.stop(t)
	for _, checkpoint := range []string{"iptables-after-switch-v4", "active:after-dir-sync"} {
		writeIPTablesConfig(t, path, "reject", nil, block, true, true, defaultIPTablesAttachments())
		crash := startAppHelper(t, path, checkpoint, false)
		crash.Env = append(crash.Env, "PERIMETERD_E2E_BACKEND=iptables")
		if err := crash.Run(); !exitStatus(err, 97) {
			t.Fatalf("%s crash returned %v", checkpoint, err)
		}
		probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18680", "reject", "tcp")
		v6 := "reject"
		if checkpoint == "iptables-after-switch-v4" {
			v6 = "drop"
		}
		probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18680", v6, "tcp")
		writeInvalidConfig(t, path)
		if err := runRunExpectFailure(t, path); err == nil {
			t.Fatal("invalid YAML accepted after recovery")
		}
		want := "reject"
		if checkpoint == "iptables-after-switch-v4" {
			want = "drop"
		}
		probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18680", want, "tcp")
		probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18680", want, "tcp")
		waitForIPTablesCommit(t, "")
	}
	command(t, 30*time.Second, e2eBinary(t), "cleanup")
	waitNoIPTablesOwned(t, "v4", "v6")
}

func iptablesProcessedPackets(t *testing.T, role string) uint64 {
	t.Helper()
	data, err := iptablesSaveMayFail("v4")
	if err != nil {
		t.Fatal(err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		if strings.Contains(line, "role="+role+"\"") {
			var packets, bytes uint64
			if _, err := fmt.Sscanf(line, "[%d:%d]", &packets, &bytes); err != nil {
				t.Fatal(err)
			}
			return packets
		}
	}
	t.Fatalf("missing processed counter %s", role)
	return 0
}

func exchangeIPTablesByte(t *testing.T, conn net.Conn) {
	t.Helper()
	if err := conn.SetDeadline(time.Now().Add(2 * time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.Write([]byte("x")); err != nil {
		t.Fatal(err)
	}
	var response [1]byte
	if _, err := io.ReadFull(conn, response[:]); err != nil {
		t.Fatal(err)
	}
	if response[0] != 'x' {
		t.Fatal("established echo changed")
	}
}

func TestE2EIPTablesMissingParentCleanup(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, variant := range []string{"nft", "legacy"} {
			t.Run(variant, func(t *testing.T) { runIsolated(t, "TestE2EIPTablesMissingParentCleanup", variant) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	installIPTablesTools(t, os.Getenv(e2eScenario))
	peer := newPeerNamespace(t)
	block := []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}
	for _, operation := range []string{"cleanup", "empty-reload", "migration"} {
		t.Run(operation, func(t *testing.T) {
			seedIPTablesParents(t)
			path := tempConfig(t, "missing-parent")
			writeIPTablesConfig(t, path, "drop", nil, block, true, true, customIPTablesAttachments())
			daemon := startIPTablesDaemon(t, path, "v4", "v6")
			if operation == "cleanup" {
				daemon.stop(t)
			}
			for _, tool := range []string{"iptables", "ip6tables"} {
				// The parent administrator removes its own hooks and chains,
				// leaving the daemon's generation objects unreferenced.
				command(t, 10*time.Second, tool, "-D", "INPUT", "-i", "e2h0", "-j", "E2EI")
				command(t, 10*time.Second, tool, "-D", "OUTPUT", "-o", "e2h0", "-j", "E2EO")
				for _, parent := range []string{"E2EI", "E2EO"} {
					command(t, 10*time.Second, tool, "-F", parent)
					command(t, 10*time.Second, tool, "-X", parent)
				}
			}
			for _, family := range []string{"v4", "v6"} {
				if !iptablesOwned(t, family) {
					t.Fatal("fixture did not retain owned generation rules")
				}
			}
			if operation != "cleanup" {
				before := activeIPTablesRevision()
				if operation == "migration" {
					writeConfig(t, path, "pde2e_missing_parent", "reject", nil, block, -10)
				} else {
					writeIPTablesConfig(t, path, "drop", nil, nil, true, true, customIPTablesAttachments())
				}
				daemon.reload(t)
				waitForIPTablesCommit(t, before)
				if operation == "migration" {
					probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18780", "reject", "tcp")
					probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18780", "reject", "tcp")
				}
				daemon.stop(t)
			}
			command(t, 30*time.Second, e2eBinary(t), "cleanup")
			for _, family := range []string{"v4", "v6"} {
				data, err := iptablesSaveMayFail(family)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(data), ":pdc") || strings.Contains(string(data), "perimeterd owner=") || strings.Contains(string(data), ":E2EI ") || strings.Contains(string(data), ":E2EO ") {
					t.Fatalf("cleanup retained ownership or recreated foreign parents:\n%s", data)
				}
			}
			sets := command(t, 10*time.Second, "ipset", "save")
			if strings.Contains(string(sets), "pdv4s") || strings.Contains(string(sets), "pdv6s") {
				t.Fatalf("cleanup retained owned sets:\n%s", sets)
			}
			// Forward admission still requires the desired custom parents.
			writeIPTablesConfig(t, path, "drop", nil, block, true, true, customIPTablesAttachments())
			if err := runRunExpectFailure(t, path); err == nil {
				t.Fatal("forward reconciliation accepted absent custom parents")
			}
			command(t, 30*time.Second, e2eBinary(t), "cleanup")
		})
	}
}

func TestE2EIPTablesIPSetComments(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, variant := range []string{"nft", "legacy"} {
			t.Run(variant, func(t *testing.T) { runIsolated(t, "TestE2EIPTablesIPSetComments", variant) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	installIPTablesTools(t, os.Getenv(e2eScenario))
	// Native ipset save does not escape the final backslash. This first set
	// must not prevent preflight, and its comment must not absorb owned sets
	// subsequently created between the two foreign sets.
	command(t, 10*time.Second, "ipset", "create", "foreign_before", "hash:net", "comment")
	command(t, 10*time.Second, "ipset", "add", "foreign_before", "203.0.113.1", "comment", "trailing\\")
	path := tempConfig(t, "ipset-comments")
	writeIPTablesConfig(t, path, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, true, true, defaultIPTablesAttachments())
	daemon := startIPTablesDaemon(t, path, "v4", "v6")
	command(t, 10*time.Second, "ipset", "create", "foreign_after", "hash:net", "comment")
	command(t, 10*time.Second, "ipset", "add", "foreign_after", "203.0.113.1", "comment", "trailing\\")
	before := string(command(t, 10*time.Second, "ipset", "save"))
	if !strings.Contains(before, "pdv4s") || !strings.Contains(before, "pdv6s") {
		t.Fatal("fixture did not create both families' owned sets")
	}
	daemon.stop(t)
	command(t, 30*time.Second, e2eBinary(t), "cleanup")
	waitNoIPTablesOwned(t, "v4", "v6")
	after := string(command(t, 10*time.Second, "ipset", "save"))
	if strings.Contains(after, "pdv4s") || strings.Contains(after, "pdv6s") {
		t.Fatalf("successful cleanup left owned sets behind:\n%s", after)
	}
	for _, name := range []string{"foreign_before", "foreign_after"} {
		command(t, 10*time.Second, "ipset", "test", name, "203.0.113.1")
		saved := string(command(t, 10*time.Second, "ipset", "save", name))
		if !strings.Contains(saved, `comment "trailing\"`) {
			t.Fatalf("cleanup changed foreign comment in %s:\n%s", name, saved)
		}
	}
}

func TestE2EIPTablesForeignSetNames(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, variant := range []string{"nft", "legacy"} {
			t.Run(variant, func(t *testing.T) { runIsolated(t, "TestE2EIPTablesForeignSetNames", variant) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	installIPTablesTools(t, os.Getenv(e2eScenario))
	peer := newPeerNamespace(t)
	foreign := map[string][]byte{}
	for _, name := range []string{"foreign one", "foreign two", "\"quoted", "line\nname", "back\\slash", "owner's", strings.Repeat("x", 31)} {
		command(t, 10*time.Second, "ipset", "create", name, "hash:net", "comment")
		command(t, 10*time.Second, "ipset", "add", name, "203.0.113.1", "comment", "foreign\\")
		foreign[name] = command(t, 10*time.Second, "ipset", "save", name)
	}
	path := tempConfig(t, "foreign-set-names")
	block := []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}
	writeIPTablesConfig(t, path, "drop", nil, block, true, true, defaultIPTablesAttachments())
	daemon := startIPTablesDaemon(t, path, "v4", "v6")
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18890", "drop", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18890", "drop", "tcp")
	before := activeIPTablesRevision()
	writeIPTablesConfig(t, path, "reject", nil, block, true, true, defaultIPTablesAttachments())
	daemon.reload(t)
	waitForIPTablesCommit(t, before)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18890", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18890", "reject", "tcp")
	daemon.stop(t)
	var ownedSet string
	for _, name := range strings.Split(string(command(t, 10*time.Second, "ipset", "list", "-name")), "\n") {
		if strings.HasPrefix(name, "pdv4s") {
			ownedSet = name
			break
		}
	}
	if ownedSet == "" {
		t.Fatal("fixture did not retain an owned IPv4 set")
	}
	// Scope set data narrowly, but continue inspecting all rules: a foreign
	// reference into a recorded set must still fence cleanup before mutation.
	command(t, 10*time.Second, "iptables", "-A", "INPUT", "-m", "set", "--match-set", ownedSet, "src", "-j", "RETURN")
	if err := runCleanupExpectFailure(t); err == nil {
		t.Fatal("cleanup ignored a foreign reference to an owned set")
	}
	if !iptablesOwned(t, "v4") || !iptablesOwned(t, "v6") {
		t.Fatal("rejected cleanup removed ownership before validating references")
	}
	command(t, 10*time.Second, "iptables", "-D", "INPUT", "-m", "set", "--match-set", ownedSet, "src", "-j", "RETURN")
	command(t, 30*time.Second, e2eBinary(t), "cleanup")
	waitNoIPTablesOwned(t, "v4", "v6")
	names := string(command(t, 10*time.Second, "ipset", "list", "-name"))
	if strings.Contains(names, "pdv4s") || strings.Contains(names, "pdv6s") {
		t.Fatalf("cleanup left recorded sets behind:\n%s", names)
	}
	for name, saved := range foreign {
		command(t, 10*time.Second, "ipset", "test", name, "203.0.113.1")
		if after := command(t, 10*time.Second, "ipset", "save", name); !bytes.Equal(after, saved) {
			t.Fatalf("foreign set %q changed:\nbefore: %s\nafter: %s", name, saved, after)
		}
	}
}

func TestE2EIPTablesOptionOperands(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, variant := range []string{"nft", "legacy"} {
			t.Run(variant, func(t *testing.T) { runIsolated(t, "TestE2EIPTablesOptionOperands", variant) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	installIPTablesTools(t, os.Getenv(e2eScenario))
	tools := []string{"iptables", "ip6tables"}
	for _, tool := range tools {
		command(t, 10*time.Second, tool, "-A", "INPUT", "-m", "comment", "--comment", "-j", "-j", "RETURN")
	}
	path := tempConfig(t, "option-operands")
	writeIPTablesConfig(t, path, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, true, true, defaultIPTablesAttachments())
	daemon := startIPTablesDaemon(t, path, "v4", "v6")
	daemon.stop(t)
	store, err := state.Open("/var/lib/perimeterd", nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if view.Active == nil || view.Active.Target == nil {
		t.Fatal("missing committed target")
	}
	target := view.Active.Target
	backend := firewall.NewIPTables(nil)
	for _, tool := range tools {
		var ownedChain string
		for _, line := range strings.Split(string(command(t, 10*time.Second, tool, "-S", "INPUT")), "\n") {
			if strings.Contains(line, "perimeterd owner=") {
				fields := strings.Fields(line)
				ownedChain = fields[len(fields)-1]
				break
			}
		}
		if !strings.HasPrefix(ownedChain, "pdc") {
			t.Fatal("missing recorded entry jump")
		}
		command(t, 10*time.Second, tool, "-A", "INPUT", "-m", "comment", "--comment", "-j", "-j", ownedChain)
		before := map[string][]byte{}
		for _, inspect := range tools {
			before[inspect] = command(t, 10*time.Second, inspect, "-S")
		}
		active := activeIPTablesRevision()
		if err := backend.Preflight(context.Background(), target, target); err == nil {
			t.Fatal("preflight accepted a hidden foreign jump into an owned chain")
		}
		if err := backend.Apply(context.Background(), target, target); err == nil {
			t.Fatal("apply accepted a hidden foreign jump into an owned chain")
		}
		if err := runCleanupExpectFailure(t); err == nil {
			t.Fatal("cleanup accepted a hidden foreign jump into an owned chain")
		}
		for _, inspect := range tools {
			if after := command(t, 10*time.Second, inspect, "-S"); !bytes.Equal(after, before[inspect]) {
				t.Fatalf("rejected operations changed %s rules:\nbefore: %s\nafter: %s", inspect, before[inspect], after)
			}
		}
		if activeIPTablesRevision() != active {
			t.Fatal("rejected operations changed the committed revision")
		}
		command(t, 10*time.Second, tool, "-D", "INPUT", "-m", "comment", "--comment", "-j", "-j", ownedChain)
	}
	daemon = startIPTablesDaemon(t, path, "v4", "v6")
	daemon.stop(t)
	command(t, 30*time.Second, e2eBinary(t), "cleanup")
	waitNoIPTablesOwned(t, "v4", "v6")
	for _, tool := range tools {
		command(t, 10*time.Second, tool, "-C", "INPUT", "-m", "comment", "--comment", "-j", "-j", "RETURN")
	}
}

func TestE2EIPTablesSetReferences(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, variant := range []string{"nft", "legacy"} {
			t.Run(variant, func(t *testing.T) { runIsolated(t, "TestE2EIPTablesSetReferences", variant) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	installIPTablesTools(t, os.Getenv(e2eScenario))
	path := tempConfig(t, "set-references")
	writeIPTablesConfig(t, path, "drop", nil, []string{fixtureIPv4Peer + "/32", fixtureIPv6Peer + "/128"}, true, true, defaultIPTablesAttachments())
	daemon := startIPTablesDaemon(t, path, "v4", "v6")
	daemon.stop(t)
	store, err := state.Open("/var/lib/perimeterd", nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if view.Active == nil || view.Active.Target == nil {
		t.Fatal("missing committed target")
	}
	target := view.Active.Target
	backend := firewall.NewIPTables(nil)
	other := "legacy"
	if os.Getenv(e2eScenario) == "legacy" {
		other = "nft"
	}
	command(t, 10*time.Second, "ipset", "create", "foreign-list", "list:set")
	names := strings.Split(string(command(t, 10*time.Second, "ipset", "list", "-name")), "\n")
	for _, family := range []string{"v4", "v6"} {
		var ownedSet string
		for _, name := range names {
			if strings.HasPrefix(name, "pd"+family+"s") {
				ownedSet = name
				break
			}
		}
		if ownedSet == "" {
			t.Fatalf("missing owned %s set", family)
		}
		assertFenced := func() {
			t.Helper()
			before := map[string][]byte{}
			for _, tool := range []string{"iptables", "ip6tables"} {
				before[tool] = command(t, 10*time.Second, tool, "-S")
			}
			saved := command(t, 10*time.Second, "ipset", "save", ownedSet)
			active := activeIPTablesRevision()
			if err := backend.Preflight(context.Background(), target, target); err == nil {
				t.Fatal("preflight accepted an unaccounted native set reference")
			}
			if err := backend.Apply(context.Background(), target, target); err == nil {
				t.Fatal("apply accepted an unaccounted native set reference")
			}
			if err := runCleanupExpectFailure(t); err == nil {
				t.Fatal("cleanup accepted an unaccounted native set reference")
			}
			for tool, rules := range before {
				if after := command(t, 10*time.Second, tool, "-S"); !bytes.Equal(after, rules) {
					t.Fatalf("fenced operations changed %s rules", tool)
				}
			}
			if after := command(t, 10*time.Second, "ipset", "save", ownedSet); !bytes.Equal(after, saved) {
				t.Fatal("fenced operations changed owned set contents")
			}
			if activeIPTablesRevision() != active {
				t.Fatal("fenced operations changed the committed revision")
			}
		}
		command(t, 10*time.Second, "ipset", "add", "foreign-list", ownedSet)
		assertFenced()
		command(t, 10*time.Second, "ipset", "test", "foreign-list", ownedSet)
		command(t, 10*time.Second, "ipset", "del", "foreign-list", ownedSet)
		tool := "iptables-" + other
		if family == "v6" {
			tool = "ip6tables-" + other
		}
		command(t, 10*time.Second, tool, "-A", "OUTPUT", "-m", "set", "--match-set", ownedSet, "dst", "-j", "RETURN")
		assertFenced()
		command(t, 10*time.Second, tool, "-D", "OUTPUT", "-m", "set", "--match-set", ownedSet, "dst", "-j", "RETURN")
	}
	daemon = startIPTablesDaemon(t, path, "v4", "v6")
	daemon.stop(t)
	command(t, 30*time.Second, e2eBinary(t), "cleanup")
	waitNoIPTablesOwned(t, "v4", "v6")
	command(t, 10*time.Second, "ipset", "list", "foreign-list")
}
