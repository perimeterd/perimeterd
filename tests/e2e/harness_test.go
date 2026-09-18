//go:build linux && e2e

package e2e

import (
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"testing"
	"time"
)

const (
	e2eEnabledEnv      = "PERIMETERD_E2E"
	e2eChildEnv        = "PERIMETERD_E2E_CHILD"
	e2eScenario        = "PERIMETERD_E2E_SCENARIO"
	e2eBinaryEnv       = "E2E_BINARY"
	e2eHelperEnv       = "PERIMETERD_E2E_APP_HELPER"
	e2eCheckpoint      = "PERIMETERD_E2E_CHECKPOINT"
	e2eFailApply       = "PERIMETERD_E2E_FAIL_APPLY"
	e2eCheckpointError = "PERIMETERD_E2E_CHECKPOINT_ERROR"
)

func TestMain(m *testing.M) {
	if os.Getenv(e2eEnabledEnv) != "1" && os.Getenv(e2eChildEnv) != "1" {
		fmt.Fprintln(os.Stderr, "PERIMETERD_E2E=1 is required; refusing to run the privileged E2E suite")
		os.Exit(2)
	}
	os.Exit(m.Run())
}

// runIsolated re-executes one test in fresh mount, network, and PID namespaces.
// Unprivileged callers also create a user namespace to obtain namespace root.
// The outer process never invokes a firewall tool; all such calls happen after
// the child verifies that its namespace differs from the caller's namespace.
func runIsolated(t *testing.T, testName, scenario string) {
	t.Helper()
	parentNet, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("read parent network namespace: %v", err)
	}
	parentMount, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatalf("read parent mount namespace: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	args := []string{"--kill-child", "--mount", "--mount-proc", "--net", "--pid", "--fork"}
	// Root already has the required privileges. A new user namespace would lose
	// its ability to traverse private workspace directories owned by another UID.
	if os.Geteuid() != 0 {
		args = append(args, "--user", "--map-root-user")
	}
	args = append(args, os.Args[0], "-test.run", "^"+testName+"$", "-test.v")
	// #nosec G204 G702 -- the namespace wrapper and test executable are controlled by this test-only harness.
	cmd := exec.CommandContext(ctx, "unshare", args...)
	cmd.Env = append(os.Environ(),
		e2eEnabledEnv+"=1",
		e2eChildEnv+"=1",
		e2eScenario+"="+scenario,
		"PERIMETERD_E2E_PARENT_NETNS="+parentNet,
		"PERIMETERD_E2E_PARENT_MNTNS="+parentMount,
	)
	var output bytes.Buffer
	cmd.Stdout = &output
	cmd.Stderr = &output
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			t.Fatalf("isolated %s timed out: %v\n%s", scenario, ctx.Err(), output.String())
		}
		t.Fatalf("isolated %s failed: %v\n%s", scenario, err, output.String())
	}
}

func requireIsolatedChild(t *testing.T) {
	t.Helper()
	if os.Getenv(e2eChildEnv) != "1" {
		t.Fatal("test must execute in an isolated child")
	}
	parentNet := os.Getenv("PERIMETERD_E2E_PARENT_NETNS")
	parentMount := os.Getenv("PERIMETERD_E2E_PARENT_MNTNS")
	if parentNet == "" || parentMount == "" {
		t.Fatal("isolated child is missing parent namespace identity")
	}
	currentNet, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatalf("read child network namespace: %v", err)
	}
	if currentNet == parentNet {
		t.Fatalf("child network namespace equals parent (%s); refusing firewall mutation", currentNet)
	}
	currentMount, err := os.Readlink("/proc/self/ns/mnt")
	if err != nil {
		t.Fatalf("read child mount namespace: %v", err)
	}
	if currentMount == parentMount {
		t.Fatalf("child mount namespace equals parent (%s); refusing filesystem mutation", currentMount)
	}
	if os.Getpid() != 1 {
		t.Fatal("fixture must be PID namespace init so exit terminates all descendants")
	}
	if os.Geteuid() != 0 {
		t.Fatalf("child is not namespace root (uid %d)", os.Geteuid())
	}
}

func prepareMounts(t *testing.T) {
	t.Helper()
	if err := syscall.Mount("", "/", "", syscall.MS_REC|syscall.MS_PRIVATE, ""); err != nil {
		t.Fatalf("make mount namespace private: %v", err)
	}
	for _, dir := range []string{"/run", "/var/lib"} {
		if err := syscall.Mount("tmpfs", dir, "tmpfs", syscall.MS_NOSUID|syscall.MS_NODEV, "mode=0755,size=64m"); err != nil {
			t.Fatalf("mount private tmpfs on %s: %v", dir, err)
		}
	}
	if err := os.MkdirAll("/run/perimeterd", 0o700); err != nil {
		t.Fatalf("create private runtime directory: %v", err)
	}
	if err := os.MkdirAll("/var/lib/perimeterd", 0o700); err != nil {
		t.Fatalf("create private state directory: %v", err)
	}
}

func command(t *testing.T, timeout time.Duration, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// #nosec G204 G702 -- privileged fixtures choose the executable; native identifiers are argv values, never shell input.
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			t.Fatalf("%s timed out: %v\n%s", strings.Join(args, " "), ctx.Err(), output)
		}
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return output
}

func commandMayFail(timeout time.Duration, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// #nosec G204 -- command and arguments are fixed by this privileged test harness.
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		return output, ctx.Err()
	}
	return output, err
}

func commandInput(t *testing.T, timeout time.Duration, input []byte, args ...string) []byte {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	// #nosec G204 -- command and arguments are fixed by this privileged test harness.
	cmd := exec.CommandContext(ctx, args[0], args[1:]...)
	cmd.Stdin = bytes.NewReader(input)
	output, err := cmd.CombinedOutput()
	if err != nil {
		if ctx.Err() != nil {
			t.Fatalf("%s timed out: %v", strings.Join(args, " "), ctx.Err())
		}
		t.Fatalf("%s: %v\n%s", strings.Join(args, " "), err, output)
	}
	return output
}
