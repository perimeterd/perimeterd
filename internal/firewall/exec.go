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
		return nil, fmt.Errorf("%s input exceeds %d bytes", command, inputLimit)
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

type nativeOutputLimitError struct{ required, limit int }

func (e *nativeOutputLimitError) Error() string {
	return fmt.Sprintf("command output exceeds %d bytes", e.limit)
}
func (*nativeOutputLimitError) RecoveryRetryable() bool { return false }

type boundedBuffer struct {
	buffer   bytes.Buffer
	limit    int
	overflow *nativeOutputLimitError
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	if len(value) > b.limit-b.buffer.Len() {
		b.overflow = &nativeOutputLimitError{required: b.buffer.Len() + len(value), limit: b.limit}
		return 0, b.overflow
	}
	return b.buffer.Write(value)
}

// Do not embed bytes.Buffer: its promoted ReadFrom bypasses Write when
// os/exec copies a pipe through io.Copy.
func (b *boundedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *boundedBuffer) String() string { return b.buffer.String() }
