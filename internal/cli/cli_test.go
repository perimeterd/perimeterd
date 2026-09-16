package cli

import (
	"bytes"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, io.ErrClosedPipe
}

func TestRunFailsWhenVersionOutputCannotBeDelivered(t *testing.T) {
	var stderr bytes.Buffer
	if code := Run([]string{"version"}, failingWriter{}, &stderr); code == 0 {
		t.Fatal("Run(version) reported success despite an output failure")
	}
}

func TestRunFailsWhenCommandHelpCannotBeDelivered(t *testing.T) {
	var stderr bytes.Buffer
	if code := Run([]string{"run", "--help"}, failingWriter{}, &stderr); code != 2 {
		t.Fatalf("Run(run --help) exit code = %d, want 2 for an output failure", code)
	}
	if got := stderr.String(); !strings.Contains(got, io.ErrClosedPipe.Error()) {
		t.Fatalf("stderr = %q, want help output write failure", got)
	}
}

func TestRunVersion(t *testing.T) {
	oldVersion, oldCommit, oldBuildTime := Version, Commit, BuildTime
	t.Cleanup(func() {
		Version, Commit, BuildTime = oldVersion, oldCommit, oldBuildTime
	})
	Version, Commit, BuildTime = "v1.2.3", "abc123", "2026-09-09T12:00:00Z"

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("Run(version) exit code = %d, want 0; stderr = %q", code, stderr.String())
	}
	for _, want := range []string{"v1.2.3", "abc123", "2026-09-09T12:00:00Z"} {
		if !strings.Contains(stdout.String(), want) {
			t.Errorf("version output %q does not contain metadata %q", stdout.String(), want)
		}
	}
	if stderr.Len() != 0 {
		t.Errorf("version wrote to stderr: %q", stderr.String())
	}
}

func TestRunValidateOfflineWithUnavailableCrowdSecAndMissingCredential(t *testing.T) {
	path := filepath.Join(t.TempDir(), "perimeterd.yaml")
	missingCredential := filepath.Join(t.TempDir(), "does-not-exist")
	config := []byte("version: 1\nfirewall:\n  backend: nftables\ncrowdsec:\n  enabled: true\n  lapi_url: http://127.0.0.1:1\n  api_key_file: " + missingCredential + "\n")
	if err := os.WriteFile(path, config, 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"validate", "--config", path}, &stdout, &stderr); code != 0 {
		t.Fatalf("Run(validate) exit code = %d, want 0; stdout = %q; stderr = %q", code, stdout.String(), stderr.String())
	}
	if stdout.Len() == 0 {
		t.Error("successful validation wrote no success output")
	}
	if stderr.Len() != 0 {
		t.Errorf("successful validation wrote to stderr: %q", stderr.String())
	}
}

func TestRunValidateRejectsInvalidConfig(t *testing.T) {
	path := filepath.Join(t.TempDir(), "invalid.yaml")
	if err := os.WriteFile(path, []byte("version: 2\nfirewall:\n  backend: nftables\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var stdout, stderr bytes.Buffer
	if code := Run([]string{"validate", "--config", path}, &stdout, &stderr); code == 0 {
		t.Fatal("Run(validate) accepted an invalid configuration")
	}
	if stdout.Len() != 0 {
		t.Errorf("invalid validation wrote to stdout: %q", stdout.String())
	}
	if stderr.Len() == 0 {
		t.Error("invalid validation wrote no actionable stderr output")
	}
}

func TestRunRejectsUnsupportedAndMalformedCommands(t *testing.T) {
	tests := []struct {
		name string
		args []string
	}{
		{name: "unknown command", args: []string{"not-a-command"}},
		{name: "run positional", args: []string{"run", "extra"}},
		{name: "run unsupported flag", args: []string{"run", "--state-dir", "/tmp/state"}},
		{name: "cleanup unsupported flag", args: []string{"cleanup", "--config", "config.yaml"}},
		{name: "validate positional", args: []string{"validate", "extra"}},
		{name: "version positional", args: []string{"version", "extra"}},
		{name: "unknown validate flag", args: []string{"validate", "--nope"}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(test.args, &stdout, &stderr); code == 0 {
				t.Fatalf("Run(%v) exit code = 0, want failure", test.args)
			}
			if stdout.Len() != 0 {
				t.Errorf("failure wrote to stdout: %q", stdout.String())
			}
			if stderr.Len() == 0 {
				t.Error("failure wrote no actionable stderr output")
			}
		})
	}
}

func TestRunRuntimeHelpUsesStdoutWithoutStartingDaemon(t *testing.T) {
	tests := []struct {
		args []string
		want string
	}{
		{args: []string{"run", "--help"}, want: "Usage: perimeterd run [--config PATH]"},
		{args: []string{"cleanup", "--help"}, want: "Usage: perimeterd cleanup"},
	}
	for _, test := range tests {
		t.Run(test.args[0], func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(test.args, &stdout, &stderr); code != 0 {
				t.Fatalf("Run(%v) exit code = %d; stderr = %q", test.args, code, stderr.String())
			}
			if !strings.Contains(stdout.String(), test.want) {
				t.Errorf("help output = %q, want %q", stdout.String(), test.want)
			}
			if stderr.Len() != 0 {
				t.Errorf("help wrote to stderr: %q", stderr.String())
			}
		})
	}
}

func TestRunRuntimeCommandsRequireRootBeforeOpeningConfig(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root cannot exercise the non-root guard without starting the real daemon")
	}
	for _, args := range [][]string{
		{"run", "--config", filepath.Join(t.TempDir(), "missing.yaml")},
		{"cleanup"},
	} {
		t.Run(args[0], func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if code := Run(args, &stdout, &stderr); code == 0 {
				t.Fatalf("Run(%v) exit code = 0, want privilege failure", args)
			}
			if !strings.Contains(stderr.String(), "requires root privileges") {
				t.Errorf("stderr = %q, want root privilege error", stderr.String())
			}
			if stdout.Len() != 0 {
				t.Errorf("privilege failure wrote to stdout: %q", stdout.String())
			}
		})
	}
}

func TestRunHelpUsesStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"validate", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("Run(validate --help) exit code = %d, want 0", code)
	}
	if !strings.Contains(stdout.String(), "Usage: perimeterd validate") {
		t.Errorf("help output = %q", stdout.String())
	}
	if stderr.Len() != 0 {
		t.Errorf("help wrote to stderr: %q", stderr.String())
	}
}
