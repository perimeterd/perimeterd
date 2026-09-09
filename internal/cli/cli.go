// Package cli implements perimeterd's command-line interface.
package cli

import (
	"bytes"
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/perimeterd/perimeterd/internal/config"
)

const defaultConfigPath = "/etc/perimeterd/perimeterd.yaml"

// Version, Commit, and BuildTime are replaced by release builds through ldflags.
// Their development values remain useful when running an untagged local build.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// Run dispatches one perimeterd command and returns a process exit status.
// Validation is deliberately limited to config.Load: it does not read
// credentials, resolve selectors, contact services, or mutate firewall state.
func Run(args []string, stdout, stderr io.Writer) int {
	if stdout == nil {
		stdout = io.Discard
	}
	if stderr == nil {
		stderr = io.Discard
	}

	if len(args) == 0 {
		// The invocation already failed, and stderr has no fallback stream.
		_ = writeUsage(stderr)
		return 2
	}
	if args[0] == "-h" || args[0] == "--help" || args[0] == "help" {
		if len(args) != 1 {
			return usageError(stderr, "help does not accept arguments")
		}
		if err := writeUsage(stdout); err != nil {
			return commandError(stderr, fmt.Errorf("write help output: %w", err))
		}
		return 0
	}

	switch args[0] {
	case "version":
		return runVersion(args[1:], stdout, stderr)
	case "validate":
		return runValidate(args[1:], stdout, stderr)
	default:
		return usageError(stderr, fmt.Sprintf("unsupported command %q (available commands: version, validate)", args[0]))
	}
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	var parseOutput bytes.Buffer
	fs := flag.NewFlagSet("perimeterd version", flag.ContinueOnError)
	fs.SetOutput(&parseOutput)
	fs.Usage = func() {
		// bytes.Buffer writes cannot fail.
		_, _ = parseOutput.WriteString("Usage: perimeterd version\n")
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, copyErr := io.Copy(stdout, &parseOutput); copyErr != nil {
				return commandError(stderr, fmt.Errorf("write version help output: %w", copyErr))
			}
			return 0
		}
		// Parsing already failed, and stderr has no fallback stream.
		_, _ = io.Copy(stderr, &parseOutput)
		return 2
	}
	if fs.NArg() != 0 {
		return usageError(stderr, fmt.Sprintf("version does not accept positional arguments: %s", strings.Join(fs.Args(), " ")))
	}

	if _, err := fmt.Fprintf(stdout, "version: %s\ncommit: %s\nbuild time: %s\n", Version, Commit, BuildTime); err != nil {
		return commandError(stderr, fmt.Errorf("write version output: %w", err))
	}
	return 0
}

func runValidate(args []string, stdout, stderr io.Writer) int {
	var parseOutput bytes.Buffer
	fs := flag.NewFlagSet("perimeterd validate", flag.ContinueOnError)
	fs.SetOutput(&parseOutput)
	configPath := fs.String("config", defaultConfigPath, "path to the YAML configuration file")
	fs.Usage = func() {
		// bytes.Buffer writes cannot fail.
		_, _ = parseOutput.WriteString("Usage: perimeterd validate [--config PATH]\n")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, copyErr := io.Copy(stdout, &parseOutput); copyErr != nil {
				return commandError(stderr, fmt.Errorf("write validate help output: %w", copyErr))
			}
			return 0
		}
		// Parsing already failed, and stderr has no fallback stream.
		_, _ = io.Copy(stderr, &parseOutput)
		return 2
	}
	if fs.NArg() != 0 {
		return usageError(stderr, fmt.Sprintf("validate does not accept positional arguments: %s", strings.Join(fs.Args(), " ")))
	}

	if _, err := config.Load(*configPath); err != nil {
		return commandError(stderr, fmt.Errorf("validate %q: %w", *configPath, err))
	}
	if _, err := fmt.Fprintf(stdout, "configuration %q is valid (local validation only; no network or firewall access)\n", *configPath); err != nil {
		return commandError(stderr, fmt.Errorf("write validation output: %w", err))
	}
	return 0
}

const usageText = `Usage:
  perimeterd version
  perimeterd validate [--config PATH]

Commands:
  version   print version, commit, and build time
  validate  parse and locally validate a YAML configuration

Use "perimeterd <command> --help" for command-specific options.
`

func writeUsage(w io.Writer) error {
	_, err := io.WriteString(w, usageText)
	return err
}

func usageError(w io.Writer, message string) int {
	return commandError(w, fmt.Errorf("%s", message))
}

func commandError(w io.Writer, err error) int {
	// The command already failed, and stderr has no fallback stream.
	_, _ = fmt.Fprintf(w, "perimeterd: %s\n", err)
	return 2
}
