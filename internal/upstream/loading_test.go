package upstream

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/perimeterd/perimeterd/internal/config"
)

func TestLoadRejectsOversizedReferencedCredential(t *testing.T) {
	dir := t.TempDir()
	identityPath := writeIdentityFile(t, dir)
	identityData, err := os.ReadFile(identityPath) // #nosec G304 -- helper creates this credential under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(identityData, &document); err != nil {
		t.Fatal(err)
	}
	oversizedKey := filepath.Join(dir, "oversized-key.pem")
	if err := os.WriteFile(oversizedKey, make([]byte, maxCredentialBytes+1), 0o600); err != nil {
		t.Fatal(err)
	}
	identityMap, ok := document["id"].(map[string]any)
	if !ok {
		t.Fatal("identity fixture has no id map")
	}
	identityMap["key"] = "file:" + oversizedKey
	identityData, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(identityPath, identityData, 0o600); err != nil {
		t.Fatal(err)
	}

	cfg := config.Config{
		OpenZiti: config.OpenZitiConfig{Identities: map[string]config.OpenZitiIdentityConfig{
			"private": {IdentityFile: identityPath},
		}},
		IPLists: map[string]config.IPListConfig{
			"private": {Transport: config.TransportConfig{Type: TypeOpenZiti, Identity: "private", Service: "source"}},
		},
		Policies: []config.Policy{{Mode: "enforce", Include: config.Selector{IPLists: []string{"private"}}}},
	}
	if _, err := NewManager().Load(context.Background(), cfg); err == nil {
		t.Fatal("oversized credential was accepted")
	}
}

func TestLoadRejectsUnsafeCredentialFiles(t *testing.T) {
	for _, kind := range []string{"readable identity", "writable directory", "identity symlink", "directory symlink", "fifo", "readable key"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			path := writeIdentityFile(t, dir)
			switch kind {
			case "readable identity":
				if err := os.Chmod(path, 0o644); err != nil { // #nosec G302 -- intentionally unsafe fixture must be rejected.
					t.Fatal(err)
				}
			case "writable directory":
				if err := os.Chmod(dir, 0o777); err != nil { // #nosec G302 -- intentionally unsafe fixture must be rejected.
					t.Fatal(err)
				}
			case "identity symlink":
				link := filepath.Join(dir, "link.json")
				if err := os.Symlink(path, link); err != nil {
					t.Fatal(err)
				}
				path = link
			case "directory symlink":
				link := filepath.Join(t.TempDir(), "link")
				if err := os.Symlink(dir, link); err != nil {
					t.Fatal(err)
				}
				path = filepath.Join(link, "identity.json")
			case "fifo":
				path = filepath.Join(dir, "fifo")
				if err := syscall.Mkfifo(path, 0o600); err != nil {
					t.Fatal(err)
				}
			case "readable key":
				data, err := os.ReadFile(path) // #nosec G304 -- path is the credential fixture under t.TempDir.
				if err != nil {
					t.Fatal(err)
				}
				var document map[string]any
				if err := json.Unmarshal(data, &document); err != nil {
					t.Fatal(err)
				}
				id := document["id"].(map[string]any)
				key := strings.TrimPrefix(id["key"].(string), "pem:")
				if err := os.WriteFile(filepath.Join(dir, "key.pem"), []byte(key), 0o644); err != nil { // #nosec G306 -- intentionally readable test key must be rejected.
					t.Fatal(err)
				}
				id["key"] = "file:key.pem"
				data, err = json.Marshal(document)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(path, data, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := captureIdentity("private", path); err == nil {
				t.Fatal("unsafe credential path was accepted")
			}
		})
	}
}

func TestRelativePEMFilesPreserveIdentityGeneration(t *testing.T) {
	dir := t.TempDir()
	path := writeIdentityFile(t, dir)
	original, err := captureIdentity("private", path)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path) // #nosec G304 -- helper creates this credential under t.TempDir.
	if err != nil {
		t.Fatal(err)
	}
	var document map[string]any
	if err := json.Unmarshal(data, &document); err != nil {
		t.Fatal(err)
	}
	id := document["id"].(map[string]any)
	for _, field := range []string{"key", "cert"} {
		mode := os.FileMode(0o600)
		if field == "cert" {
			mode = 0o644
		}
		name := field + ".pem"
		if err := os.WriteFile(filepath.Join(dir, name), []byte(strings.TrimPrefix(id[field].(string), "pem:")), mode); err != nil {
			t.Fatal(err)
		}
		id[field] = "file:" + name
	}
	data, err = json.Marshal(document)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	referenced, err := captureIdentity("private", path)
	if err != nil {
		t.Fatal(err)
	}
	if original.binding != referenced.binding {
		t.Fatal("moving the same credential material into relative PEM files changed its identity")
	}
}
