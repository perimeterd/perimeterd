package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/control"
)

func statusFixture() control.StatusResult {
	return control.StatusResult{
		SchemaVersion: 1,
		ObservedAt:    time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC),
		Daemon:        control.StatusDaemon{Version: "v1.2.3", UptimeSeconds: 123, Healthy: true},
		Applied: control.StatusApplied{
			State: "applied", Revision: strings.Repeat("a", 64), ConfigEpoch: 7, Manifest: strings.Repeat("b", 64),
			Details: &control.StatusDetails{
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
		if got.SchemaVersion != 1 || got.ObservedAt != result.ObservedAt || got.Applied.Revision != result.Applied.Revision || got.Applied.Manifest != result.Applied.Manifest || got.Daemon.Healthy != healthy || got.Applied.Details.CrowdSec.Counts.IPv4 != 11 {
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
