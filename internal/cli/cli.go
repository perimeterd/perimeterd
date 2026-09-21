// Package cli implements perimeterd's command-line interface.
package cli

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/perimeterd/perimeterd/internal/app"
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
// The validate command is deliberately limited to config.Load: it does not
// read credentials, resolve selectors, contact services, or mutate firewall
// state.
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
	case "run":
		return runDaemon(args[1:], stdout, stderr)
	case "cleanup":
		return runCleanup(args[1:], stdout, stderr)
	case "lookup":
		return runLookup(args[1:], stdout, stderr)
	default:
		return usageError(stderr, fmt.Sprintf("unsupported command %q (available commands: version, validate, run, cleanup, lookup)", args[0]))
	}
}

type commandFlags struct {
	command string
	fs      *flag.FlagSet
	output  bytes.Buffer
}

func newCommandFlags(command string) *commandFlags {
	flags := &commandFlags{
		command: command,
		fs:      flag.NewFlagSet("perimeterd "+command, flag.ContinueOnError),
	}
	flags.fs.SetOutput(&flags.output)
	return flags
}

// parse handles the common result paths for command flag sets. A handled
// result includes help, parse errors, and rejected positional arguments.
func (f *commandFlags) parse(args []string, stdout, stderr io.Writer) (handled bool, exitCode int) {
	if err := f.fs.Parse(args); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			if _, copyErr := io.Copy(stdout, &f.output); copyErr != nil {
				return true, commandError(stderr, fmt.Errorf("write %s help output: %w", f.command, copyErr))
			}
			return true, 0
		}
		// Parsing already failed, and stderr has no fallback stream.
		_, _ = io.Copy(stderr, &f.output)
		return true, 2
	}
	if f.fs.NArg() != 0 {
		return true, usageError(stderr, fmt.Sprintf("%s does not accept positional arguments: %s", f.command, strings.Join(f.fs.Args(), " ")))
	}
	return false, 0
}

func runDaemon(args []string, stdout, stderr io.Writer) int {
	flags := newCommandFlags("run")
	configPath := flags.fs.String("config", defaultConfigPath, "path to the YAML configuration file")
	flags.fs.Usage = func() {
		_, _ = flags.output.WriteString("Usage: perimeterd run [--config PATH]\n")
		flags.fs.PrintDefaults()
	}
	if handled, exitCode := flags.parse(args, stdout, stderr); handled {
		return exitCode
	}
	if err := requireRoot("run"); err != nil {
		return commandError(stderr, err)
	}
	if err := app.Run(context.Background(), app.Options{
		ConfigPath: *configPath,
		Stderr:     stderr,
	}); err != nil {
		return commandError(stderr, fmt.Errorf("run: %w", err))
	}
	return 0
}

func runCleanup(args []string, stdout, stderr io.Writer) int {
	flags := newCommandFlags("cleanup")
	flags.fs.Usage = func() {
		_, _ = flags.output.WriteString("Usage: perimeterd cleanup\n")
	}
	if handled, exitCode := flags.parse(args, stdout, stderr); handled {
		return exitCode
	}
	if err := requireRoot("cleanup"); err != nil {
		return commandError(stderr, err)
	}
	if err := app.Cleanup(context.Background(), app.Options{Stderr: stderr}); err != nil {
		return commandError(stderr, fmt.Errorf("cleanup: %w", err))
	}
	return 0
}

func requireRoot(command string) error {
	if os.Geteuid() != 0 {
		return fmt.Errorf("%s requires root privileges", command)
	}
	return nil
}

func runVersion(args []string, stdout, stderr io.Writer) int {
	flags := newCommandFlags("version")
	flags.fs.Usage = func() {
		// bytes.Buffer writes cannot fail.
		_, _ = flags.output.WriteString("Usage: perimeterd version\n")
	}
	if handled, exitCode := flags.parse(args, stdout, stderr); handled {
		return exitCode
	}

	if _, err := fmt.Fprintf(stdout, "version: %s\ncommit: %s\nbuild time: %s\n", Version, Commit, BuildTime); err != nil {
		return commandError(stderr, fmt.Errorf("write version output: %w", err))
	}
	return 0
}

func runValidate(args []string, stdout, stderr io.Writer) int {
	flags := newCommandFlags("validate")
	configPath := flags.fs.String("config", defaultConfigPath, "path to the YAML configuration file")
	flags.fs.Usage = func() {
		// bytes.Buffer writes cannot fail.
		_, _ = flags.output.WriteString("Usage: perimeterd validate [--config PATH]\n")
		flags.fs.PrintDefaults()
	}
	if handled, exitCode := flags.parse(args, stdout, stderr); handled {
		return exitCode
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
  perimeterd run [--config PATH]
  perimeterd cleanup
  perimeterd lookup IP_OR_CIDR [flags]
  perimeterd version
  perimeterd validate [--config PATH]

Commands:
  run       recover state, apply configuration, and serve until stopped (root only)
  cleanup   remove recorded owned firewall state (root only)
  lookup    explain applied policy through the running daemon
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
