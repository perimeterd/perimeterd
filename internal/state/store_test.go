package state

import (
	"bytes"
	"encoding/json"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func storeTestConfig(t *testing.T) config.Config {
	t.Helper()
	cfg, err := config.Parse([]byte(`version: 1
firewall:
  backend: nftables
  deny_action: drop
  ipv4: true
  ipv6: true
  nftables:
    table: perimeterd-store-test
    priority: -10
global:
  blocklist: [198.51.100.0/24]
`))
	if err != nil {
		t.Fatalf("parse store test config: %v", err)
	}
	return cfg
}

func storeTestRevision(t *testing.T, store *Store, id string) *Revision {
	t.Helper()
	cfg := storeTestConfig(t)
	model, err := policy.Compile(cfg, policy.Snapshot{})
	if err != nil {
		t.Fatalf("compile store test config: %v", err)
	}
	target, err := firewall.BuildTarget(store.Owner(), id, cfg, model, nil)
	if err != nil {
		t.Fatalf("build store test target: %v", err)
	}
	return &Revision{Version: 1, ID: id, Epoch: 1, ConfigPath: "/does/not/exist.yaml", Config: cfg, Target: target}
}

func openTestStore(t *testing.T, checkpoint func(string) error) (*Store, string) {
	t.Helper()
	dir := filepath.Join(t.TempDir(), "state")
	store, err := Open(dir, checkpoint)
	if err != nil {
		t.Fatalf("open test store: %v", err)
	}
	return store, dir
}

func mutateJSONFile(t *testing.T, path string, mutate func(map[string]any)) {
	t.Helper()
	data, err := os.ReadFile(path) // #nosec G304 -- path is a state fixture beneath t.TempDir.
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	var value map[string]any
	if err := json.Unmarshal(data, &value); err != nil {
		t.Fatalf("decode %s for test mutation: %v", path, err)
	}
	mutate(value)
	encoded, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, encoded, info.Mode().Perm()); err != nil {
		t.Fatalf("rewrite %s: %v", path, err)
	}
}

func persistStoreRevision(t *testing.T, store *Store, id string) *Revision {
	t.Helper()
	revision := storeTestRevision(t, store, id)
	if err := store.Prepare(nil, revision); err != nil {
		t.Fatalf("prepare revision: %v", err)
	}
	if err := store.Commit(revision); err != nil {
		t.Fatalf("commit revision: %v", err)
	}
	return revision
}

func TestStoreRejectsMalformedVersionedMetadataAndBrokenReferences(t *testing.T) {
	const id = "0123456789abcdef0123456789abcdef"

	t.Run("unknown envelope field", func(t *testing.T) {
		_, dir := openTestStore(t, nil)
		mutateJSONFile(t, filepath.Join(dir, "owner.json"), func(value map[string]any) { value["unexpected"] = true })
		if _, err := Open(dir, nil); err == nil {
			t.Fatal("opened owner metadata containing an unknown field")
		}
	})

	t.Run("duplicate JSON key", func(t *testing.T) {
		_, dir := openTestStore(t, nil)
		owner, err := os.ReadFile(filepath.Join(dir, "owner.json")) // #nosec G304 -- dir is a private test store beneath t.TempDir.
		if err != nil {
			t.Fatal(err)
		}
		duplicate := bytes.Replace(owner, []byte(`"version":1,`), []byte(`"version":1,"version":1,`), 1)
		if bytes.Equal(owner, duplicate) {
			t.Fatal("owner fixture did not contain its version field")
		}
		if err := os.WriteFile(filepath.Join(dir, "owner.json"), duplicate, 0o600); err != nil { // #nosec G703 -- dir comes from t.TempDir and the owner filename is fixed.
			t.Fatal(err)
		}
		if _, err := Open(dir, nil); err == nil {
			t.Fatal("opened owner metadata containing a duplicate JSON key")
		}
	})
	t.Run("trailing JSON", func(t *testing.T) {
		_, dir := openTestStore(t, nil)
		path := filepath.Join(dir, "owner.json")
		owner, err := os.ReadFile(path) // #nosec G304 -- path is a private test store beneath t.TempDir.
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, append(owner, []byte(`{}`)...), 0o600); err != nil { // #nosec G703 -- path is a fixed owner record inside t.TempDir.
			t.Fatal(err)
		}
		if _, err := Open(dir, nil); err == nil {
			t.Fatal("opened owner metadata with trailing JSON")
		}
	})

	t.Run("checksum mismatch", func(t *testing.T) {
		store, dir := openTestStore(t, nil)
		mutateJSONFile(t, filepath.Join(dir, "owner.json"), func(value map[string]any) { value["checksum"] = strings.Repeat("0", 64) })
		if _, err := Open(dir, nil); err == nil {
			t.Fatal("opened owner metadata with a checksum mismatch")
		}
		_ = store
	})

	t.Run("missing immutable revision", func(t *testing.T) {
		store, dir := openTestStore(t, nil)
		revision := persistStoreRevision(t, store, id)
		if err := os.Remove(filepath.Join(dir, "revisions", revision.ID+".json")); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Read(); err == nil {
			t.Fatal("read succeeded after deleting referenced immutable revision")
		}
	})
	t.Run("unknown payload field", func(t *testing.T) {
		store, dir := openTestStore(t, nil)
		revision := persistStoreRevision(t, store, id)
		raw, err := os.ReadFile(filepath.Join(dir, "revisions", revision.ID+".json")) // #nosec G304 -- revision is a private test fixture.
		if err != nil {
			t.Fatal(err)
		}
		var record envelope
		if err := json.Unmarshal(raw, &record); err != nil {
			t.Fatal(err)
		}
		var payload map[string]any
		if err := json.Unmarshal(record.Payload, &payload); err != nil {
			t.Fatal(err)
		}
		payload["unexpected"] = true
		encoded, err := encodeRecord(payload)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "revisions", revision.ID+".json"), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Read(); err == nil {
			t.Fatal("read accepted an unknown immutable revision payload field")
		}
	})

	t.Run("active reference mismatch", func(t *testing.T) {
		store, dir := openTestStore(t, nil)
		persistStoreRevision(t, store, id)
		encoded, err := encodeRecord(activeRecord{ID: strings.Repeat("f", 32)})
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "active.json"), encoded, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := store.Read(); err == nil {
			t.Fatal("read accepted active reference to an unrelated revision")
		}
	})
}

func TestStorePrepareCheckpointFailuresRetainConservativeEvidence(t *testing.T) {
	checkpoints := []string{
		"revision:before-file-sync",
		"revision:before-rename",
		"revision:after-rename",
		"revision:after-dir-sync",
		"journal:before-file-sync",
		"journal:before-rename",
		"journal:after-rename",
		"journal:after-dir-sync",
	}
	for _, checkpoint := range checkpoints {
		t.Run(checkpoint, func(t *testing.T) {
			var fired bool
			store, dir := openTestStore(t, func(name string) error {
				if name == checkpoint && !fired {
					fired = true
					return errors.New("injected durability uncertainty")
				}
				return nil
			})
			revision := storeTestRevision(t, store, "0123456789abcdef0123456789abcdef")
			if err := store.Prepare(nil, revision); err == nil {
				t.Fatal("prepare succeeded through injected durability failure")
			}
			// Failed barriers never publish an active selection. A later reader must
			// either see the old complete state or retain evidence for recovery.
			view, readErr := store.Read()
			if readErr == nil && view.Active != nil {
				t.Fatalf("failed prepare published active revision %#v", view.Active)
			}
			if _, statErr := os.Stat(filepath.Join(dir, "owner.json")); statErr != nil {
				t.Fatalf("owner evidence disappeared after %s: %v", checkpoint, statErr)
			}
		})
	}
}

func TestStoreActivePublicationBarriersExposeOnlyCompleteObservedRecords(t *testing.T) {
	for _, checkpoint := range []string{
		"active:before-file-sync",
		"active:before-rename",
		"active:after-rename",
		"active:after-dir-sync",
	} {
		t.Run(checkpoint, func(t *testing.T) {
			fired := false
			store, _ := openTestStore(t, func(name string) error {
				if name == checkpoint && !fired {
					fired = true
					return errors.New("injected active publication uncertainty")
				}
				return nil
			})
			revision := storeTestRevision(t, store, "33333333333333333333333333333333")
			if err := store.Prepare(nil, revision); err != nil {
				t.Fatalf("prepare: %v", err)
			}
			if err := store.Commit(revision); err == nil {
				t.Fatal("commit succeeded through injected active publication barrier")
			}
			view, err := store.Read()
			if err != nil {
				t.Fatalf("read complete records after %s: %v", checkpoint, err)
			}
			if view.Active != nil && view.Active.ID != revision.ID {
				t.Fatalf("observed active revision %s, want nil or candidate %s", view.Active.ID, revision.ID)
			}
		})
	}
}

func TestStoreCleanupIntentRetainsUnionUntilFinish(t *testing.T) {
	store, dir := openTestStore(t, nil)
	const id = "11111111111111111111111111111111"
	revision := persistStoreRevision(t, store, id)
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.BeginCleanup(view, "22222222222222222222222222222222"); err != nil {
		t.Fatalf("begin cleanup: %v", err)
	}
	cleanup, err := store.Read()
	if err != nil {
		t.Fatalf("read cleanup intent: %v", err)
	}
	if cleanup.Journal == nil || cleanup.Journal.Operation != "cleanup" {
		t.Fatalf("cleanup journal = %#v", cleanup.Journal)
	}
	if !contains(cleanup.Journal.Revisions, revision.ID) {
		t.Fatalf("cleanup intent dropped active revision %s: %#v", revision.ID, cleanup.Journal.Revisions)
	}
	if err := store.RemoveActive(); err != nil {
		t.Fatalf("remove active: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, "active.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("active record after removal: %v", err)
	}
	if err := store.Finish(); err != nil {
		t.Fatalf("finish cleanup: %v", err)
	}
	if _, err := store.Read(); err != nil {
		t.Fatalf("read empty state after cleanup finish: %v", err)
	}
}

func contains(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func TestStoreRejectsOversizedOrCorruptRevisionWithoutChangingPermissions(t *testing.T) {
	store, dir := openTestStore(t, nil)
	const id = "22222222222222222222222222222222"
	revision := persistStoreRevision(t, store, id)
	path := filepath.Join(dir, "revisions", revision.ID+".json")
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- path is a state fixture beneath t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, append(data, []byte(strings.Repeat("x", maxRecordBytes))...), info.Mode().Perm()); err != nil { // #nosec G703 -- path is a fixed revision record inside t.TempDir.
		t.Fatal(err)
	}
	if _, err := store.Read(); err == nil {
		t.Fatal("read accepted oversized immutable revision")
	}
	if got := info.Mode().Perm(); got != 0o600 {
		t.Fatalf("test fixture revision mode = %o, want 600", got)
	}
}

func TestOversizedCandidatePreservesRecoverableActiveRevision(t *testing.T) {
	store, dir := openTestStore(t, nil)
	previous := persistStoreRevision(t, store, strings.Repeat("1", 32))
	if err := store.Finish(); err != nil {
		t.Fatal(err)
	}
	candidate := storeTestRevision(t, store, strings.Repeat("2", 32))
	// Unused groups remain part of the durable configuration even though they
	// do not enlarge the compiled firewall target.
	candidate.Config.Groups = map[string][]string{strings.Repeat("a", maxRecordBytes): {"DE"}}
	if err := store.Prepare(previous, candidate); err == nil {
		t.Fatal("prepared a revision that the reader cannot load")
	}
	if _, err := os.Stat(store.revisionPath(candidate.ID)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("oversized revision was published: %v", err)
	}
	reopened, err := Open(dir, nil)
	if err != nil {
		t.Fatalf("reopen after rejecting oversized candidate: %v", err)
	}
	view, err := reopened.Read()
	if err != nil {
		t.Fatal(err)
	}
	if view.Journal != nil || view.Active == nil || view.Active.ID != previous.ID {
		t.Fatal("oversized candidate changed active state or left a pending transaction")
	}
	replacement := storeTestRevision(t, reopened, strings.Repeat("3", 32))
	if err := reopened.Prepare(view.Active, replacement); err != nil {
		t.Fatalf("prepare replacement after rejection: %v", err)
	}
	if err := reopened.Commit(replacement); err != nil {
		t.Fatalf("commit replacement after rejection: %v", err)
	}
}

func TestReadRejectsManifestWithoutOwningRevision(t *testing.T) {
	store, dir := openTestStore(t, nil)
	candidate := storeTestRevision(t, store, strings.Repeat("1", 32))
	if err := store.Prepare(nil, candidate); err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	view.Journal.PreviousManifest = strings.Repeat("a", 64)
	if err := store.publish("journal", filepath.Join(dir, "journal.json"), view.Journal); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(); err == nil {
		t.Fatal("recovery admitted a manifest reference without its owning revision")
	}
}

func iptablesStoreRevision(t *testing.T, store *Store, id, block string) *Revision {
	t.Helper()
	cfg := storeTestConfig(t)
	cfg.Firewall.Backend = "iptables"
	cfg.Global.Blocklist = []netip.Prefix{netip.MustParsePrefix(block)}
	model, err := policy.Compile(cfg, policy.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	target, err := firewall.BuildTarget(store.Owner(), id, cfg, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	return &Revision{Version: 1, ID: id, Epoch: 1, ConfigPath: "/missing.yaml", Config: cfg, Target: target}
}

func TestFamilyProgressSurvivesRestartWithoutCommittingCandidate(t *testing.T) {
	store, dir := openTestStore(t, nil)
	previous := iptablesStoreRevision(t, store, strings.Repeat("1", 32), "8.8.8.0/24")
	if err := store.Prepare(nil, previous); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(previous); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(); err != nil {
		t.Fatal(err)
	}
	candidate := iptablesStoreRevision(t, store, strings.Repeat("2", 32), "9.9.9.0/24")
	if err := store.Prepare(previous, candidate); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordFamilySelection(policy.IPv4, candidate.Target.Generation); err != nil {
		t.Fatal(err)
	}
	if err := store.RecordFamilySelection(policy.IPv6, previous.Target.Generation); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := reopened.Read()
	if err != nil {
		t.Fatal(err)
	}
	if view.Active == nil || view.Active.ID != previous.ID || view.Journal == nil {
		t.Fatal("partial family selection replaced durable commit authority")
	}
	selections := make(map[policy.Family]string)
	for _, selection := range view.Journal.FamilySelections {
		selections[selection.Family] = selection.Generation
	}
	if selections[policy.IPv4] != candidate.Target.Generation || selections[policy.IPv6] != previous.Target.Generation {
		t.Fatalf("mixed-family progress lost on restart: %v", selections)
	}
	if err := reopened.RecordFamilySelection(policy.IPv4, previous.Target.Generation); err != nil {
		t.Fatal(err)
	}
	if err := reopened.RecordFamilySelection(policy.IPv6, strings.Repeat("f", 32)); err == nil {
		t.Fatal("unrecorded generation admitted as recovery authority")
	}
	view, err = reopened.Read()
	if err != nil {
		t.Fatal(err)
	}
	for _, selection := range view.Journal.FamilySelections {
		if selection.Generation != previous.Target.Generation {
			t.Fatalf("compensation progress was not preserved: %+v", selection)
		}
	}
}

func TestReadRejectsUnrecordedFamilySelection(t *testing.T) {
	store, dir := openTestStore(t, nil)
	candidate := iptablesStoreRevision(t, store, strings.Repeat("1", 32), "8.8.8.0/24")
	if err := store.Prepare(nil, candidate); err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	view.Journal.FamilySelections = []FamilySelection{{Family: policy.IPv4, Generation: strings.Repeat("f", 32)}}
	if err := store.publish("journal", filepath.Join(dir, "journal.json"), view.Journal); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Read(); err == nil {
		t.Fatal("recovery accepted an unrecorded selected generation")
	}
}
