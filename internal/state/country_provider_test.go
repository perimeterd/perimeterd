package state

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
)

// copyPreDBIPState uses byte-authentic files produced by the original HEAD
// implementation, not by a current serializer. Provenance and raw hashes live
// beside the fixture so future serializer changes cannot silently regenerate it.
func copyPreDBIPState(t *testing.T) (string, map[string][]byte) {
	t.Helper()
	provenance, err := os.ReadFile("testdata/pre-dbip-provenance.json")
	if err != nil {
		t.Fatal(err)
	}
	var identity struct {
		OriginalCommit string            `json:"original_commit"`
		SHA256         map[string]string `json:"sha256"`
	}
	if err := json.Unmarshal(provenance, &identity); err != nil {
		t.Fatal(err)
	}
	if identity.OriginalCommit != "41e77771d544517f28719e6e2ef3ca39f6e1ad2a" || len(identity.SHA256) != 5 {
		t.Fatal("missing original serializer provenance")
	}
	dir := filepath.Join(t.TempDir(), "state")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	fixtures, err := os.OpenRoot("testdata/pre-dbip")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = fixtures.Close() })
	destination, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = destination.Close() })
	originals := make(map[string][]byte)
	err = fs.WalkDir(fixtures.FS(), ".", func(rel string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() {
			return destination.MkdirAll(rel, 0o700)
		}
		data, err := fixtures.ReadFile(rel)
		if err != nil {
			return err
		}
		digest := sha256.Sum256(data)
		if hex.EncodeToString(digest[:]) != identity.SHA256[filepath.ToSlash(rel)] {
			t.Fatalf("original fixture checksum changed: %s", rel)
		}
		originals[rel] = data
		return destination.WriteFile(rel, data, 0o600)
	})
	if err != nil {
		t.Fatal(err)
	}
	return dir, originals
}

func assertHistoricalBytes(t *testing.T, dir string, originals map[string][]byte) {
	t.Helper()
	for path, original := range originals {
		current, err := os.ReadFile(filepath.Join(dir, path)) // #nosec G304 -- private copied fixture.
		if err != nil || !bytes.Equal(current, original) {
			t.Fatalf("historical immutable bytes changed for %s: %v", path, err)
		}
	}
}

func TestPreDBIPCommittedRevisionByteIdentityAndRecovery(t *testing.T) {
	dir, originals := copyPreDBIPState(t)
	store, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil || view.Active == nil {
		t.Fatalf("load original committed state: %+v, %v", view, err)
	}
	old := view.Active
	if old.Version != 2 || old.Config.Geo.CountryProvider != "" || old.Config.Geo.EffectiveCountryProvider() != config.CountryProviderRIPEstat {
		t.Fatalf("historical interpretation changed: %+v", old)
	}
	encoded, err := encodeRecord(*old)
	if err != nil || !bytes.Equal(encoded, originals[filepath.Join("revisions", old.ID+".json")]) {
		t.Fatalf("new serializer changed original revision bytes: %v", err)
	}
	// The restart path must also validate/cache-load and retain an interrupted
	// same-revision recovery journal without interpreting old YAML defaults.
	if err := store.Prepare(old, old); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	recovered, err := restarted.Read()
	if err != nil || recovered.Active == nil || recovered.Journal == nil || recovered.Active.ID != old.ID || recovered.Active.Config.Geo.EffectiveCountryProvider() != config.CountryProviderRIPEstat {
		t.Fatalf("historical recovery authority: %+v, %v", recovered, err)
	}
	if err := restarted.Finish(); err != nil {
		t.Fatal(err)
	}
	assertHistoricalBytes(t, dir, originals)
}

func TestPreDBIPProviderSwitchRejectsRIPEEvidenceAndPreservesAuthority(t *testing.T) {
	dir, originals := copyPreDBIPState(t)
	store, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	old := view.Active
	candidate := *old
	candidate.ID, candidate.Epoch = strings.Repeat("2", 32), 2
	candidate.Config.Geo.CountryProvider = config.CountryProviderDBIPLite
	if err := store.Prepare(old, &candidate); err == nil || !strings.Contains(err.Error(), "source identity") {
		t.Fatalf("DB-IP activation accepted historical RIPE evidence: %v", err)
	}
	for _, provider := range []string{"unknown", "RIPEstat", "DBIP-LITE"} {
		candidate.Config.Geo.CountryProvider = provider
		if err := store.Prepare(old, &candidate); err == nil || !strings.Contains(err.Error(), "country provider") {
			t.Fatalf("durable invalid provider %q accepted: %v", provider, err)
		}
	}
	restarted, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	after, err := restarted.Read()
	if err != nil || after.Active == nil || after.Active.ID != old.ID || after.Active.Config.Geo.EffectiveCountryProvider() != config.CountryProviderRIPEstat || after.Journal != nil {
		t.Fatalf("failed provider switch moved authority: %+v, %v", after, err)
	}
	assertHistoricalBytes(t, dir, originals)
}

func TestPreDBIPLoadRejectsProviderReinterpretation(t *testing.T) {
	dir, originals := copyPreDBIPState(t)
	const id = "11111111111111111111111111111111"
	path := filepath.Join("revisions", id+".json")
	var revision Revision
	if err := decodeRecord(originals[path], &revision); err != nil {
		t.Fatal(err)
	}
	revision.Config.Geo.CountryProvider = config.CountryProviderDBIPLite
	forged, err := encodeRecord(revision)
	if err != nil {
		t.Fatal(err)
	}
	// A valid envelope checksum cannot authorize a provider switch using an
	// unchanged RIPE manifest. Load must perform source/config validation too.
	if err := os.WriteFile(filepath.Join(dir, path), forged, 0o600); err != nil { // #nosec G304 -- private fixture tree.
		t.Fatal(err)
	}
	if _, err := Open(dir, nil); err == nil || !strings.Contains(err.Error(), "source identity") {
		t.Fatalf("load reinterpreted historical RIPE evidence as DB-IP: %v", err)
	}
	current, err := os.ReadFile(filepath.Join(dir, path)) // #nosec G304 -- private fixture tree.
	if err != nil || !bytes.Equal(current, forged) {
		t.Fatalf("rejected load rewrote revision: %v", err)
	}
}

func TestDBIPRevisionPublicationAndReloadValidation(t *testing.T) {
	dir, _ := copyPreDBIPState(t)
	store, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	old := view.Active
	cfg := old.Config
	cfg.Geo.CountryProvider = config.CountryProviderDBIPLite
	snapshot, err := store.Prefixes().Stage([]source.Record{{
		Selector:   policy.Selector{Kind: policy.Country, Value: "SK"},
		SourceKind: "dbip-lite", APIVersion: "dbip-country-csv-1", Release: "2026-10",
		Endpoint:    "https://download.db-ip.com/free/dbip-country-lite-2026-10.csv.gz",
		Parameters:  map[string]string{"resource": "SK", "sha256": strings.Repeat("a", 64)},
		RetrievedAt: time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC),
		IPv4:        []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")},
		IPv6:        []netip.Prefix{netip.MustParsePrefix("2001:db8::/32")},
	}})
	if err != nil {
		t.Fatal(err)
	}
	model, err := policy.Compile(cfg, snapshot.Policy())
	if err != nil {
		t.Fatal(err)
	}
	id := strings.Repeat("2", 32)
	target, err := firewall.BuildTarget(store.Owner(), id, cfg, model, old.Target)
	if err != nil {
		t.Fatal(err)
	}
	candidate := &Revision{Version: 2, ID: id, Epoch: 2, Manifest: snapshot.ManifestID(), ConfigPath: old.ConfigPath, Config: cfg, Target: target}
	if err := store.Prepare(old, candidate); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(candidate); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(); err != nil {
		t.Fatal(err)
	}
	restarted, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	active, err := restarted.Read()
	if err != nil || active.Active == nil || active.Active.ID != id || active.Active.Version != 2 || active.Active.Config.Geo.EffectiveCountryProvider() != config.CountryProviderDBIPLite {
		t.Fatalf("DB-IP committed revision recovery: %+v, %v", active, err)
	}
	// Reverse reinterpretation is forbidden too, on both publication and load.
	ripe := *active.Active
	ripe.Config.Geo.CountryProvider = config.CountryProviderRIPEstat
	if err := restarted.Prepare(active.Active, &ripe); err == nil || !strings.Contains(err.Error(), "source identity") {
		t.Fatalf("DB-IP evidence covered RIPE config: %v", err)
	}
	forged, err := encodeRecord(ripe)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "revisions", id+".json"), forged, 0o600); err != nil { // #nosec G304 -- private fixture tree.
		t.Fatal(err)
	}
	if _, err := Open(dir, nil); err == nil || !strings.Contains(err.Error(), "source identity") {
		t.Fatalf("load accepted DB-IP evidence as RIPE: %v", err)
	}
}
