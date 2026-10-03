package cli

import (
	"context"
	"fmt"
	"io"

	"github.com/perimeterd/perimeterd/internal/control"
)

func runReload(args []string, stdout, stderr io.Writer) int {
	return reloadCommand(args, stdout, stderr, control.Reload)
}

func reloadCommand(args []string, stdout, stderr io.Writer, call func(context.Context, control.ReloadRequest) control.ReloadResult) int {
	flags := newCommandFlags("reload")
	expected := ""
	seen := false
	flags.fs.Func("expect-config-sha256", "SHA-256 of exact expected configuration bytes", func(value string) error {
		if seen {
			return fmt.Errorf("--expect-config-sha256 cannot be repeated")
		}
		seen = true
		var err error
		expected, err = control.NormalizeDigest(value)
		return err
	})
	flags.fs.Usage = func() {
		_, _ = flags.output.WriteString("Usage: perimeterd reload [--expect-config-sha256 HEX]\n")
		flags.fs.PrintDefaults()
	}
	if handled, exitCode := flags.parse(args, stdout, stderr); handled {
		return exitCode
	}
	if err := requireRoot("reload"); err != nil {
		_, _ = fmt.Fprintf(stderr, "perimeterd: %s\n", err)
		return 1
	}
	result := call(context.Background(), control.ReloadRequest{ExpectConfigSHA256: expected})
	if result.Outcome != "applied" {
		_, _ = fmt.Fprintf(stderr, "perimeterd: reload %s/%s: %s\n", result.Outcome, result.Code, result.Message)
		return 1
	}
	if _, err := fmt.Fprintf(stdout, "configuration applied: revision=%s config_sha256=%s\n", result.Revision, result.ConfigSHA256); err != nil {
		_, _ = fmt.Fprintf(stderr, "perimeterd: write reload acknowledgement: %s\n", err)
		return 1
	}
	return 0
}
