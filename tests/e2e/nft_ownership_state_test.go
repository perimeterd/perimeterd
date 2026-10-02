//go:build linux && e2e

package e2e

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/app"
	"github.com/perimeterd/perimeterd/internal/state"
)

func TestE2ENFTMissingWitnessRefused(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		t.Logf("%s", runIsolated(t, "TestE2ENFTMissingWitnessRefused", "missing-witness"))
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	table := fmt.Sprintf("pdmissing_%d", os.Getpid())
	path := tempConfig(t, "missing-witness")
	writeConfig(t, path, table, "drop", nil, []string{"8.8.8.8/32"}, -10)
	daemon := startDaemon(t, path, table)
	daemon.stop(t)
	command(t, 10*time.Second, "nft", "flush", "table", "inet", table)
	before := nftTable(t, table)
	if err := runCleanupExpectFailure(t); err == nil {
		t.Fatal("cleanup adopted an existing table whose witness vanished")
	}
	if !bytes.Equal(before, nftTable(t, table)) {
		t.Fatal("failed cleanup mutated missing-witness table")
	}
	// Direct recovery has a bounded operation rather than the daemon retry loop.
	lock, err := state.AcquireLock("/run/perimeterd/owner.lock")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = lock.Close() }()
	store, err := state.Open("/var/lib/perimeterd", nil)
	if err != nil {
		t.Fatal(err)
	}
	engine := app.NewEngine(store, nil, nil)
	defer engine.Close()
	if _, err := engine.Recover(context.Background()); err == nil {
		t.Fatal("recovery silently repaired a missing witness")
	}
	if !bytes.Equal(before, nftTable(t, table)) {
		t.Fatal("failed recovery mutated missing-witness table")
	}
	t.Logf("missing committed witness refused by cleanup and recovery; inventory: %s", before)
}

func TestE2EOldStateRecordVersionRefused(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		t.Logf("%s", runIsolated(t, "TestE2EOldStateRecordVersionRefused", "old-state-record"))
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	table := fmt.Sprintf("pdversion_%d", os.Getpid())
	path := tempConfig(t, "old-state-record")
	writeConfig(t, path, table, "drop", nil, []string{"8.8.8.8/32"}, -10)
	daemon := startDaemon(t, path, table)
	daemon.stop(t)
	root, err := os.OpenRoot("/var/lib/perimeterd")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	for _, cleaned := range []bool{false, true} {
		if cleaned {
			command(t, 30*time.Second, e2eBinary(t), "cleanup")
			waitNoNFTTable(t, table)
		}
		current, err := root.ReadFile("owner.json")
		if err != nil {
			t.Fatal(err)
		}
		var envelope struct {
			Version  int             `json:"version"`
			Checksum string          `json:"checksum"`
			Payload  json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(current, &envelope); err != nil {
			t.Fatal(err)
		}
		digest := sha256.Sum256(envelope.Payload)
		if envelope.Version != 2 || envelope.Checksum != hex.EncodeToString(digest[:]) {
			t.Fatal("current owner envelope has unexpected version or invalid payload checksum")
		}
		// records.go hashes only payload bytes: changing the outer version does
		// not corrupt the checksum or introduce a second rejection reason.
		envelope.Version = 1
		old, err := json.Marshal(envelope)
		if err != nil {
			t.Fatal(err)
		}
		var reread struct {
			Checksum string          `json:"checksum"`
			Payload  json.RawMessage `json:"payload"`
		}
		if err := json.Unmarshal(old, &reread); err != nil {
			t.Fatal(err)
		}
		oldDigest := sha256.Sum256(reread.Payload)
		if !bytes.Equal(envelope.Payload, reread.Payload) || reread.Checksum != hex.EncodeToString(oldDigest[:]) {
			t.Fatal("version-1 fixture changed the checksummed payload")
		}
		if err := root.WriteFile("owner.json", old, 0o600); err != nil {
			t.Fatal(err)
		}
		beforeState := stateDigests(t)
		beforeNative := command(t, 10*time.Second, "nft", "-j", "list", "ruleset")
		for _, args := range [][]string{{"run", "--config", path}, {"cleanup"}} {
			output, err := commandMayFail(15*time.Second, append([]string{e2eBinary(t)}, args...)...)
			var exitErr *exec.ExitError
			if !errors.As(err, &exitErr) || exitErr.ExitCode() <= 0 ||
				!strings.Contains(string(output), "record version 1 is unsupported") {
				t.Fatalf("daemon did not explicitly refuse old state: cleaned=%t args=%v err=%v output=%s", cleaned, args, err, output)
			}
			if !reflect.DeepEqual(beforeState, stateDigests(t)) || !bytes.Equal(beforeNative, command(t, 10*time.Second, "nft", "-j", "list", "ruleset")) {
				t.Fatal("rejected old-state reader changed durable bytes or native rules")
			}
		}
		if err := root.WriteFile("owner.json", current, 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func stateDigests(t *testing.T) map[string][sha256.Size]byte {
	t.Helper()
	root, err := os.OpenRoot("/var/lib/perimeterd")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = root.Close() }()
	out := make(map[string][sha256.Size]byte)
	if err := fs.WalkDir(root.FS(), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			return nil
		}
		data, err := root.ReadFile(path)
		if err != nil {
			return err
		}
		out[path] = sha256.Sum256(data)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return out
}

// Avoid comparing nft's incidental handles when asserting the canonical rule.
func witnessRule(t *testing.T, table string) map[string]any {
	t.Helper()
	var found map[string]any
	walkJSON(objectJSON(t, table), func(object map[string]any) {
		if rule, ok := object["rule"].(map[string]any); ok {
			comment, _ := rule["comment"].(string)
			if strings.HasSuffix(comment, " role=table_witness_v1") {
				if found != nil {
					t.Fatal("duplicate native ownership witness rule")
				}
				found = rule
			}
		}
	})
	if found == nil {
		t.Fatal("native ownership witness rule is absent")
	}
	expression, err := json.Marshal(found["expr"])
	if err != nil || string(expression) != `[{"return":null}]` {
		t.Fatalf("native witness expression changed: %s %v", expression, err)
	}
	return found
}
