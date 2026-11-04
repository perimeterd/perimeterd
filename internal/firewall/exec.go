package firewall

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"strings"
)

// executeNative shares process I/O bounds, not backend timeout or transaction
// policy. Callers select fixed native tools and their own input/output limits.
func executeNative(ctx context.Context, command string, args []string, input []byte, inputLimit, outputLimit int) ([]byte, error) {
	if len(input) > inputLimit {
		return nil, &CapacityError{Resource: "native-io", Scope: "input", RequiredBytes: int64(len(input)), LimitBytes: int64(inputLimit)}
	}
	// #nosec G204 -- callers select fixed native firewall tools; configuration is passed as arguments or stdin, never shell code.
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdin = bytes.NewReader(input)
	stdout, stderr := boundedBuffer{limit: outputLimit}, boundedBuffer{limit: outputLimit}
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	runErr := cmd.Run()
	if ctx.Err() != nil {
		return nil, ctx.Err()
	}
	if stdout.overflow != nil {
		return nil, stdout.overflow
	}
	if stderr.overflow != nil {
		return nil, stderr.overflow
	}
	if runErr != nil {
		if message := strings.TrimSpace(stderr.String()); message != "" {
			return nil, fmt.Errorf("%s %s: %w: %s", command, strings.Join(args, " "), runErr, message)
		}
		return nil, fmt.Errorf("%s %s: %w", command, strings.Join(args, " "), runErr)
	}
	return stdout.Bytes(), nil
}

// required is the observed lower bound when capture stopped, not the complete
// size of native output that was discarded after interruption.
type nativeOutputLimitError struct {
	required int64
	limit    int
}

func (e *nativeOutputLimitError) Error() string {
	return fmt.Sprintf("command output exceeds %d bytes", e.limit)
}
func (*nativeOutputLimitError) RecoveryRetryable() bool { return false }

func (e *nativeOutputLimitError) Unwrap() error {
	return &CapacityError{Resource: "native-io", Scope: "output", RequiredBytes: e.required, LimitBytes: int64(e.limit)}
}

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow *nativeOutputLimitError
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	if len(value) > b.limit-b.buffer.Len() {
		b.overflow = &nativeOutputLimitError{required: int64(b.buffer.Len()) + int64(len(value)), limit: b.limit}
		return 0, b.overflow
	}
	return b.buffer.Write(value)
}

// Do not embed bytes.Buffer: its promoted ReadFrom bypasses Write when
// os/exec copies a pipe through io.Copy.
func (b *boundedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *boundedBuffer) String() string { return b.buffer.String() }
