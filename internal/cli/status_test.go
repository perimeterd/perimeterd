package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/control"
)

func statusFixture() control.StatusResult {
	return control.StatusResult{
		SchemaVersion: control.StatusSchemaVersion,
		ObservedAt:    time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC),
		Daemon:        control.StatusDaemon{Version: "v1.2.3", UptimeSeconds: 123, Healthy: true},
		Applied: control.StatusApplied{
			State: "applied", Revision: strings.Repeat("a", 64), ConfigEpoch: 7, Manifest: strings.Repeat("b", 64),
			Details: &control.StatusDetails{
				Sources: []control.StatusSource{{Provider: "dbip-lite", Release: "2026-10", RetrievedAt: time.Date(2026, 10, 13, 11, 0, 0, 0, time.UTC)}},
				Firewall: control.StatusFirewall{
					Backend: "iptables", Families: []string{"ipv4", "ipv6"}, DenyAction: "drop",
					Attachments: []control.StatusAttachment{{Chain: "DOCKER-USER", Direction: "ingress", InputInterfaces: []string{"eth0"}, OutputInterfaces: []string{"br0"}, OriginalDestination: true}},
				},
				Policies: []control.StatusPolicy{
					{Name: "web", Priority: 20, Direction: "ingress", Mode: "blocklist", Traffic: control.StatusTraffic{TCP: []control.StatusPortRange{{Start: 80, End: 80}, {Start: 8000, End: 8080}}, UDP: []control.StatusPortRange{{Start: 53, End: 53}}, ICMP: true, ICMPv6: true}},
					{Name: "fallback", Priority: 30, Direction: "ingress", Mode: "allowlist", Traffic: control.StatusTraffic{Any: true}},
				},
				PrefixCounts: []control.StatusPrefixCount{
					{Family: "ipv4", Source: "list:web", Type: "deny", Count: 10},
					{Family: "ipv6", Source: "list:web", Type: "deny", Count: 4},
				},
				CompiledSets: control.StatusCompiledSets{
					Sets: []control.StatusCompiledSet{
						{Family: "ipv4", ID: "geo/egress", Policies: []string{"egress", "ingress"}, Count: 10},
						{Family: "ipv4", ID: "geo/ssh", Policies: []string{"ssh"}, Count: 3},
						{Family: "ipv4", ID: "global_allowlist", Policies: []string{}, Count: 0},
						{Family: "ipv6", ID: "geo/egress", Policies: []string{"egress", "ingress"}, Count: 4},
						{Family: "ipv6", ID: "geo/ssh", Policies: []string{"ssh"}, Count: 1},
					},
					Totals: []control.StatusCompiledTotal{{Family: "ipv4", Count: 13}, {Family: "ipv6", Count: 5}},
				},
				CrowdSec: control.StatusCrowdSec{Enabled: true, Epoch: 3, Operation: 8, Validity: "valid", ValidUntil: time.Date(2026, 10, 13, 13, 0, 0, 0, time.UTC), Counts: &control.StatusDecisionCounts{IPv4: 11, IPv6: 2}},
			},
		},
	}
}

func TestStatusHumanReadableUptime(t *testing.T) {
	for _, tc := range []struct {
		seconds uint64
		want    string
	}{
		{0, "0s"},
		{1, "1s"},
		{59, "59s"},
		{60, "1m"},
		{61, "1m1s"},
		{1260, "21m"},
		{3599, "59m59s"},
		{3600, "1h"},
		{3661, "1h1m1s"},
		{86399, "23h59m59s"},
		{86400, "1d"},
		{90061, "1d1h1m1s"},
		{172801, "2d1s"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			result := statusFixture()
			result.Daemon.UptimeSeconds = tc.seconds
			var out bytes.Buffer
			if err := writeStatus(&out, result); err != nil {
				t.Fatal(err)
			}
			line, _, _ := strings.Cut(out.String(), "\n")
			if !strings.Contains(line, " uptime="+tc.want+" ") {
				t.Fatalf("uptime %d: got %q, want uptime=%s", tc.seconds, line, tc.want)
			}
		})
	}
}

func TestStatusReportsHealthAndStateFailuresOnStdout(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private command requires root")
	}
	for _, tc := range []struct {
		name     string
		change   func(*control.StatusResult)
		wantCode int
		want     string
		noCounts bool
	}{
		{"disabled", func(s *control.StatusResult) {
			s.Applied.Details.CrowdSec = control.StatusCrowdSec{Validity: "disabled"}
		}, 0, "CrowdSec: disabled", true},
		{"empty", func(s *control.StatusResult) { s.Applied = control.StatusApplied{State: "empty"} }, 0, "state=empty", true},
		{"degraded", func(s *control.StatusResult) { s.Daemon.Healthy = false }, 1, "WARNING: daemon health is degraded", false},
		{"unavailable", func(s *control.StatusResult) {
			s.Applied = control.StatusApplied{State: "unavailable", Reason: "acknowledgement missing"}
		}, 1, "WARNING: last-applied state is unavailable: acknowledgement missing", true},
		{"stale", func(s *control.StatusResult) {
			s.Applied.Details.CrowdSec.Validity = "stale"
			s.Applied.Details.CrowdSec.Counts = nil
		}, 1, "WARNING: CrowdSec acknowledged state is stale; decision counts unavailable", true},
		{"unknown", func(s *control.StatusResult) {
			s.Applied.Details.CrowdSec.Validity = "unknown"
			s.Applied.Details.CrowdSec.Counts = nil
		}, 1, "WARNING: CrowdSec acknowledged state is unknown; decision counts unavailable", true},
		{"valid empty dynamic state", func(s *control.StatusResult) {
			s.Applied.Details.CrowdSec.ValidUntil = time.Time{}
			s.Applied.Details.CrowdSec.Counts = &control.StatusDecisionCounts{}
		}, 0, "validity=valid deadline=none", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := statusFixture()
			tc.change(&result)
			var stdout, stderr bytes.Buffer
			code := statusCommand(nil, &stdout, &stderr, func(context.Context) (control.StatusResult, error) { return result, nil })
			if code != tc.wantCode || stderr.Len() != 0 || !strings.Contains(stdout.String(), tc.want) {
				t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
			}
			if tc.noCounts && strings.Contains(stdout.String(), "Unexpired acknowledged decisions") {
				t.Fatalf("non-valid CrowdSec report exposed counts: %s", stdout.String())
			}
			if result.Applied.Details == nil && strings.Contains(stdout.String(), "Compiled firewall sets") {
				t.Fatalf("unapplied status invented a compiled target: %s", stdout.String())
			}
		})
	}
}

func TestStatusJSONIncludesFullReportEvenOnFailure(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private command requires root")
	}
	for _, healthy := range []bool{true, false} {
		result := statusFixture()
		result.Daemon.Healthy = healthy
		var stdout, stderr bytes.Buffer
		code := statusCommand([]string{"--json"}, &stdout, &stderr, func(context.Context) (control.StatusResult, error) { return result, nil })
		want := 1
		if healthy {
			want = 0
		}
		if code != want || stderr.Len() != 0 {
			t.Fatalf("exit=%d stderr=%q", code, stderr.String())
		}
		var got control.StatusResult
		if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
			t.Fatal(err)
		}
		if got.SchemaVersion != control.StatusSchemaVersion || got.ObservedAt != result.ObservedAt || got.Applied.Revision != result.Applied.Revision || got.Applied.Manifest != result.Applied.Manifest || got.Daemon.Healthy != healthy || got.Applied.Details.CrowdSec.Counts.IPv4 != 11 || !reflect.DeepEqual(got.Applied.Details.CompiledSets, result.Applied.Details.CompiledSets) {
			t.Fatalf("incomplete JSON report: %s", stdout.String())
		}
	}
}

func TestStatusUsageAndOfflineHelp(t *testing.T) {
	for _, args := range [][]string{{"--socket", "/tmp/private.sock"}, {"--config", "missing.yaml"}, {"--watch"}, {"extra"}, {"--json=invalid"}} {
		var stdout, stderr bytes.Buffer
		code := statusCommand(args, &stdout, &stderr, func(context.Context) (control.StatusResult, error) {
			t.Fatal("usage contacted daemon")
			return control.StatusResult{}, nil
		})
		if code != 2 || stdout.Len() != 0 || stderr.Len() == 0 {
			t.Fatalf("args=%v exit=%d stdout=%q stderr=%q", args, code, stdout.String(), stderr.String())
		}
	}
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"status", "--help"}, &stdout, &stderr); code != 0 || stdout.Len() == 0 || stderr.Len() != 0 {
		t.Fatalf("help exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	stdout.Reset()
	if code := Run([]string{"--help"}, &stdout, &stderr); code != 0 || !strings.Contains(stdout.String(), "perimeterd status") {
		t.Fatalf("status not discoverable: exit=%d stdout=%q", code, stdout.String())
	}
}

func TestStatusHelpOutputFailure(t *testing.T) {
	var stderr bytes.Buffer
	if code := Run([]string{"status", "--help"}, failingWriter{}, &stderr); code != 1 || !strings.Contains(stderr.String(), io.ErrClosedPipe.Error()) {
		t.Fatalf("exit=%d stderr=%q", code, stderr.String())
	}
}

func TestStatusOperationalAndOutputErrors(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private command requires root")
	}
	var stdout, stderr bytes.Buffer
	if code := statusCommand(nil, &stdout, &stderr, func(context.Context) (control.StatusResult, error) {
		return control.StatusResult{}, errors.New("daemon unavailable")
	}); code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "daemon unavailable") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
	for _, args := range [][]string{nil, {"--json"}} {
		stderr.Reset()
		if code := statusCommand(args, failingWriter{}, &stderr, func(context.Context) (control.StatusResult, error) { return statusFixture(), nil }); code != 1 || !strings.Contains(stderr.String(), io.ErrClosedPipe.Error()) {
			t.Fatalf("args=%v exit=%d stderr=%q", args, code, stderr.String())
		}
	}
}

func TestStatusUnavailableDaemonHasNoDiskFallback(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private command requires root")
	}
	path := filepath.Join(t.TempDir(), "absent.sock")
	var stdout, stderr bytes.Buffer
	code := statusCommand(nil, &stdout, &stderr, func(ctx context.Context) (control.StatusResult, error) { return control.StatusPath(ctx, path) })
	if code != 1 || stdout.Len() != 0 || stderr.Len() == 0 {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestStatusRequiresRootBeforeContactingDaemon(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root cannot exercise non-root guard")
	}
	var stdout, stderr bytes.Buffer
	code := statusCommand(nil, &stdout, &stderr, func(context.Context) (control.StatusResult, error) {
		t.Fatal("non-root contacted daemon")
		return control.StatusResult{}, nil
	})
	if code != 1 || stdout.Len() != 0 || !strings.Contains(stderr.String(), "requires root privileges") {
		t.Fatalf("exit=%d stdout=%q stderr=%q", code, stdout.String(), stderr.String())
	}
}

func TestStatusCompiledTextMatchesJSON(t *testing.T) {
	result := statusFixture()
	before, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	var jsonReport control.StatusResult
	if err := json.Unmarshal(before, &jsonReport); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	if err := writeStatus(&out, result); err != nil {
		t.Fatal(err)
	}
	text := out.String()
	sourcePos := strings.Index(text, "Loaded source prefix elements")
	compiledPos := strings.Index(text, "Compiled firewall sets")
	crowdsecPos := strings.Index(text, "CrowdSec: acknowledged_epoch")
	if sourcePos < 0 || compiledPos <= sourcePos || crowdsecPos <= compiledPos {
		t.Fatalf("source/compiled/CrowdSec sections out of order: %s", text)
	}
	last := compiledPos
	for _, family := range []string{"ipv4", "ipv6"} {
		for _, id := range []string{"geo/egress", "geo/ingress", "geo/ssh", "global_allowlist"} {
			for _, set := range jsonReport.Applied.Details.CompiledSets.Sets {
				if set.Family != family || set.ID != id {
					continue
				}
				policies := strings.Join(set.Policies, ",")
				if policies == "" {
					policies = "-"
				}
				line := fmt.Sprintf("  family=%s set=%s policies=%s count=%d\n", family, id, policies, set.Count)
				pos := strings.Index(text, line)
				if pos <= last || strings.Count(text, line) != 1 {
					t.Fatalf("missing, duplicated or unordered compiled row %q: %s", line, text)
				}
				last = pos
			}
		}
		for _, total := range jsonReport.Applied.Details.CompiledSets.Totals {
			if total.Family != family {
				continue
			}
			line := fmt.Sprintf("  family=%s total_memberships=%d\n", family, total.Count)
			pos := strings.Index(text, line)
			if pos <= last || strings.Count(text, line) != 1 {
				t.Fatalf("missing, duplicated or unordered total %q: %s", line, text)
			}
			last = pos
		}
	}
	compiledText := text[compiledPos:crowdsecPos]
	if !strings.Contains(compiledText, "static target memberships; shared sets counted once; not a kernel audit") ||
		!strings.Contains(compiledText, "Dynamic CrowdSec memberships excluded; decision counts reported separately.") ||
		strings.Contains(compiledText, "set=crowdsec") {
		t.Fatalf("static/dynamic membership semantics unclear: %s", compiledText)
	}
	for _, count := range jsonReport.Applied.Details.PrefixCounts {
		line := fmt.Sprintf("family=%s source=%s type=%s count=%d", count.Family, count.Source, count.Type, count.Count)
		if !strings.Contains(text[sourcePos:compiledPos], line) {
			t.Fatalf("source count changed: missing %q", line)
		}
	}
	if !strings.Contains(text[crowdsecPos:], "ipv4=11 ipv6=2") {
		t.Fatalf("live decision counts changed: %s", text[crowdsecPos:])
	}
	after, err := json.Marshal(result)
	if err != nil || !bytes.Equal(before, after) {
		t.Fatalf("text rendering mutated status summary: %s, %v", after, err)
	}
}

func TestStatusCompiledZeroTotalAndDisabledFamily(t *testing.T) {
	result := statusFixture()
	result.Applied.Details.Firewall.Families = []string{"ipv6"}
	result.Applied.Details.CompiledSets = control.StatusCompiledSets{
		Sets:   []control.StatusCompiledSet{},
		Totals: []control.StatusCompiledTotal{{Family: "ipv6", Count: 0}},
	}
	var out bytes.Buffer
	if err := writeStatus(&out, result); err != nil {
		t.Fatal(err)
	}
	_, compiled, found := strings.Cut(out.String(), "Compiled firewall sets")
	if !found {
		t.Fatal("missing compiled section")
	}
	compiled, _, _ = strings.Cut(compiled, "CrowdSec: acknowledged_epoch")
	if !strings.Contains(compiled, "family=ipv6 total_memberships=0\n") || strings.Contains(compiled, "family=ipv4") || strings.Contains(compiled, " set=") {
		t.Fatalf("zero total or absent family rendered incorrectly: %s", compiled)
	}
	encoded, err := json.Marshal(result)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(encoded, []byte(`"compiled_sets":{"sets":[],"totals":[{"family":"ipv6","count":0}]}`)) {
		t.Fatalf("zero total or empty collection missing from JSON: %s", encoded)
	}
}
