package cli

import (
	"bytes"
	"context"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perimeterd/perimeterd/internal/control"
)

func TestReloadUsageAndOfflineHelp(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"reload", "--help"}, 0},
		{[]string{"reload", "--expect-config-sha256", ""}, 2},
		{[]string{"reload", "--expect-config-sha256", "xyz"}, 2},
		{[]string{"reload", "--expect-config-sha256", strings.Repeat("a", 64), "--expect-config-sha256", strings.Repeat("a", 64)}, 2},
		{[]string{"reload", "extra"}, 2},
		{[]string{"reload", "--json"}, 2},
	} {
		var out, err bytes.Buffer
		if got := Run(tc.args, &out, &err); got != tc.want {
			t.Fatalf("args=%v exit=%d stderr=%s", tc.args, got, err.String())
		}
	}
}

func TestReloadCLIResultAndNormalizedDigest(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private command requires root")
	}
	for _, outcome := range []string{"applied", "rejected", "degraded", "unknown"} {
		var out, err bytes.Buffer
		called := 0
		code := reloadCommand([]string{"--expect-config-sha256", strings.Repeat("A", 64)}, &out, &err, func(_ context.Context, input control.ReloadRequest) control.ReloadResult {
			called++
			if input.ExpectConfigSHA256 != strings.Repeat("a", 64) {
				t.Fatal(input)
			}
			if outcome == "applied" {
				return control.ReloadResult{SchemaVersion: 1, Outcome: outcome, Revision: "committed", ConfigSHA256: input.ExpectConfigSHA256}
			}
			return control.Failure(outcome, "apply_failed", "actionable detail")
		})
		want := 1
		if outcome == "applied" {
			want = 0
			if !strings.Contains(out.String(), "committed") || !strings.Contains(out.String(), strings.Repeat("a", 64)) {
				t.Fatal(out.String())
			}
		}
		if code != want || called != 1 {
			t.Fatalf("outcome=%s code=%d calls=%d", outcome, code, called)
		}
		if outcome != "applied" && (!strings.Contains(err.String(), outcome+"/apply_failed") || out.Len() != 0) {
			t.Fatal(err.String())
		}
	}
}

func TestReloadCLIUsesActualUnixAcknowledgement(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("private command requires root")
	}
	path := filepath.Join(t.TempDir(), "lookup.sock")
	digest := strings.Repeat("a", 64)
	server, err := control.Listen(path, http.NotFoundHandler(), control.ReloadHTTPHandler(func(_ context.Context, request control.ReloadRequest) control.ReloadResult {
		if request.ExpectConfigSHA256 != digest {
			t.Errorf("wire digest=%s", request.ExpectConfigSHA256)
		}
		return control.ReloadResult{SchemaVersion: 1, Outcome: "applied", Revision: "committed", ConfigSHA256: digest}
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(context.Background()) }()
	var out, stderr bytes.Buffer
	code := reloadCommand([]string{"--expect-config-sha256", digest}, &out, &stderr, func(ctx context.Context, request control.ReloadRequest) control.ReloadResult {
		return control.ReloadPath(ctx, path, request)
	})
	if code != 0 || !strings.Contains(out.String(), digest) || !strings.Contains(out.String(), "committed") {
		t.Fatalf("exit=%d stdout=%s stderr=%s", code, out.String(), stderr.String())
	}
}
