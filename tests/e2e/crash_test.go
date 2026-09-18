//go:build linux && e2e

package e2e

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/app"
	"github.com/perimeterd/perimeterd/internal/firewall"
)

func startAppHelper(t *testing.T, configPath, checkpoint string, failApply bool) *exec.Cmd {
	t.Helper()
	// #nosec G204 G702 -- runs this test executable with a fixed helper selector.
	cmd := exec.Command(os.Args[0], "-test.run", "^TestE2EAppHelper$", "-test.v")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Env = append(os.Environ(),
		e2eEnabledEnv+"=1",
		e2eChildEnv+"=1",
		e2eHelperEnv+"=1",
		"PERIMETERD_E2E_CONFIG="+configPath,
		e2eCheckpoint+"="+checkpoint,
	)
	if failApply {
		cmd.Env = append(cmd.Env, e2eFailApply+"=1")
	}
	return cmd
}

func startAppErrorHelper(t *testing.T, configPath, checkpoint string) *exec.Cmd {
	t.Helper()
	cmd := startAppHelper(t, configPath, checkpoint, false)
	cmd.Env = append(cmd.Env, e2eCheckpointError+"=1")
	return cmd
}

// TestE2EAppHelper runs app.Run with test-only programmatic injection hooks.
// It is never part of the production CLI and is only used to terminate a
// helper at an exact durability boundary in the isolated namespace.
func TestE2EAppHelper(t *testing.T) {
	if os.Getenv(e2eHelperEnv) != "1" {
		return
	}
	configPath := os.Getenv("PERIMETERD_E2E_CONFIG")
	checkpoint := os.Getenv(e2eCheckpoint)
	if configPath == "" || checkpoint == "" {
		t.Fatal("app helper requires config and checkpoint")
	}
	armed := false
	check := func(label string) error {
		// Startup restoration republishes the old active record too. Inject
		// only after the new candidate has durably prepared its transaction.
		if label == "after-prepare" {
			armed = true
		}
		if armed && label == checkpoint {
			if os.Getenv(e2eCheckpointError) == "1" {
				return errors.New("e2e checkpoint failure")
			}
			os.Exit(97)
		}
		return nil
	}
	var backend firewall.Backend
	if os.Getenv("PERIMETERD_E2E_BACKEND") == "iptables" {
		// Let app.Run bind its family-progress callback to the native router.
		// A nil injected backend selects the production default (NewNative).
	} else {
		backend = firewall.NewNFT()
	}
	startupTimeout := 30 * time.Second
	if os.Getenv(e2eFailApply) == "1" {
		backend = &failAfterApplyBackend{Backend: backend, armed: &armed}
		startupTimeout = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), startupTimeout)
	defer cancel()
	err := app.Run(ctx, app.Options{ConfigPath: configPath, Stderr: os.Stderr, Backend: backend, Checkpoint: check, StartupTimeout: startupTimeout})
	if err != nil {
		os.Exit(98)
	}
}

type failAfterApplyBackend struct {
	firewall.Backend
	armed *bool
}

func (b *failAfterApplyBackend) Apply(ctx context.Context, previous, candidate *firewall.Target, dynamic *firewall.DynamicState) error {
	if err := b.Backend.Apply(ctx, previous, candidate, dynamic); err != nil {
		return err
	}
	if *b.armed {
		return errors.New("e2e injected post-apply failure")
	}
	return nil
}
