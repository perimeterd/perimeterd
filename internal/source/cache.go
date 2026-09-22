// Package source contains source resolution and its immutable selector cache.
package source

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/sys/unix"

	"github.com/perimeterd/perimeterd/internal/policy"
)

const (
	cacheSchemaVersion   = 3
	cacheIDLength        = sha256.Size * 2
	maxCacheObjectBytes  = 32 << 20
	maxCacheManifestSize = 16 << 20
	cacheDirMode         = 0o700
	cacheFileMode        = 0o600
)

const (
	legacyCacheSchemaVersionV1 = 1
	legacyCacheSchemaVersionV2 = 2
)

const legacyCacheSchemaVersion = legacyCacheSchemaVersionV1

// Cache is an immutable content-addressed store of selector objects and
// complete manifests. It never selects an object by scanning the cache.
type Cache struct {
	root       string
	objects    string
	manifests  string
	checkpoint func(string) error
}

// Snapshot is an immutable, complete source result selected by one manifest.
type Snapshot struct {
	manifest string
	policy   policy.Snapshot
	records  []Record
	oldest   time.Time
}

// ManifestID returns the content identifier of this snapshot's complete
// manifest. The zero snapshot has no manifest.
func (s Snapshot) ManifestID() string { return s.manifest }

// Policy returns the immutable compiler input represented by this snapshot.
func (s Snapshot) Policy() policy.Snapshot { return s.policy }

// OldestRetrieved returns the oldest selector retrieval timestamp, or the zero
// time for an empty snapshot.
func (s Snapshot) OldestRetrieved() time.Time { return s.oldest }

// Records returns independent copies of every selector result in the snapshot.
func (s Snapshot) Records() []Record {
	if s.records == nil {
		return nil
	}
	out := make([]Record, len(s.records))
	for i, record := range s.records {
		out[i] = cloneRecord(record)
	}
	return out
}

// NewCache creates or opens the prefixes cache beneath stateDir.
func NewCache(stateDir string, checkpoint func(string) error) (*Cache, error) {
	if stateDir == "" {
		return nil, errors.New("source cache: empty state directory")
	}
	root := filepath.Join(stateDir, "prefixes")
	objects := filepath.Join(root, "objects")
	manifests := filepath.Join(root, "manifests")
	for _, directory := range []string{stateDir, root, objects, manifests} {
		if err := ensureCacheDirectory(directory); err != nil {
			return nil, fmt.Errorf("source cache directory %s: %w", directory, err)
		}
	}
	return &Cache{root: root, objects: objects, manifests: manifests, checkpoint: checkpoint}, nil
}

// Stage validates and durably stages one complete candidate snapshot. A
// candidate is publishable only after all selector objects and its manifest are
// installed. The zero-record candidate is the canonical zero snapshot.
func (c *Cache) Stage(records []Record) (Snapshot, error) {
	if c == nil {
		return Snapshot{}, errors.New("source cache: nil cache")
	}
	if len(records) == 0 {
		return Snapshot{}, nil
	}
	if len(records) > maxSelectors {
		return Snapshot{}, errors.New("source cache: too many selectors")
	}
	canonical, err := canonicalRecords(records)
	if err != nil {
		return Snapshot{}, err
	}
	entries := make([]manifestEntry, 0, len(canonical))
	for index, record := range canonical {
		if (record.SourceKind == listSourceKind || record.SourceKind == providerSourceKind) && len(record.IPv4) == 0 && len(record.IPv6) == 0 {
			if record.SourceKind == providerSourceKind {
				return Snapshot{}, errors.New("provider selector contains no prefixes")
			}
			return Snapshot{}, errors.New("custom list selector contains no prefixes")
		}
		object := objectFromRecord(record)
		objectBytes, err := canonicalJSON(object)
		if err != nil {
			return Snapshot{}, fmt.Errorf("selector %d object: %w", index, err)
		}
		if len(objectBytes) > maxCacheObjectBytes {
			return Snapshot{}, errors.New("source cache: selector object exceeds size limit")
		}
		objectID := digestID(objectBytes)
		if err := c.installImmutable(c.objectPath(objectID), objectBytes, "object"); err != nil {
			return Snapshot{}, fmt.Errorf("selector %d object: %w", index, err)
		}
		entries = append(entries, manifestEntryFromRecord(record, objectID))
	}
	source := "ripestat"
	for _, record := range canonical {
		if record.SourceKind == listSourceKind || record.SourceKind == providerSourceKind {
			source = "static"
			break
		}
	}
	manifest := manifestFile{SchemaVersion: cacheSchemaVersion, Source: source, Entries: entries}
	manifestBytes, err := canonicalJSON(manifest)
	if err != nil {
		return Snapshot{}, fmt.Errorf("manifest: %w", err)
	}
	if len(manifestBytes) > maxCacheManifestSize {
		return Snapshot{}, errors.New("source cache: manifest exceeds size limit")
	}
	manifestID := digestID(manifestBytes)
	if err := c.installImmutable(c.manifestPath(manifestID), manifestBytes, "manifest"); err != nil {
		return Snapshot{}, fmt.Errorf("manifest: %w", err)
	}
	return c.Load(manifestID)
}

// Load validates and materializes exactly the manifest named by id and all of
// its referenced selector objects.
func (c *Cache) Load(id string) (Snapshot, error) {
	if c == nil {
		return Snapshot{}, errors.New("source cache: nil cache")
	}
	if err := validateCacheID(id, "manifest"); err != nil {
		return Snapshot{}, err
	}
	manifest, err := c.readManifest(id)
	if err != nil {
		return Snapshot{}, fmt.Errorf("manifest %s: %w", id, err)
	}
	records := make([]Record, 0, len(manifest.Entries))
	resolved := make([]policy.ResolvedSelector, 0, len(manifest.Entries))
	for index, entry := range manifest.Entries {
		record, err := c.loadObject(entry, manifest.SchemaVersion)
		if err != nil {
			return Snapshot{}, fmt.Errorf("manifest %s selector %d: %w", id, index, err)
		}
		records = append(records, record)
		resolved = append(resolved, policy.ResolvedSelector{Selector: record.Selector, IPv4: record.IPv4, IPv6: record.IPv6})
	}
	compiled, err := policy.NewSnapshot(resolved)
	if err != nil {
		return Snapshot{}, fmt.Errorf("manifest %s snapshot: %w", id, err)
	}
	return makeSnapshot(id, compiled, records), nil
}

func (c *Cache) readManifest(id string) (manifestFile, error) {
	if err := validateCacheID(id, "manifest"); err != nil {
		return manifestFile{}, err
	}
	data, err := c.readBounded(c.manifestPath(id), maxCacheManifestSize)
	if err != nil {
		return manifestFile{}, err
	}
	if digestID(data) != id {
		return manifestFile{}, errors.New("content hash mismatch")
	}
	manifest, err := decodeManifest(data)
	if err != nil {
		return manifestFile{}, err
	}
	return manifest, nil
}

// Stabilize validates the named complete manifest and fsyncs every referenced
// object, the manifest, and both cache directories before recovery or apply.
func (c *Cache) Stabilize(id string) error {
	if c == nil {
		return errors.New("source cache: nil cache")
	}
	snapshot, err := c.Load(id)
	if err != nil {
		return err
	}
	if err := c.checkpointCall("prefixes:before-file-sync"); err != nil {
		return err
	}
	if err := syncCacheRegular(c.manifestPath(snapshot.ManifestID())); err != nil {
		return fmt.Errorf("manifest sync: %w", err)
	}
	objectIDs, err := c.manifestObjectIDs(snapshot.ManifestID())
	if err != nil {
		return err
	}
	for _, object := range objectIDs {
		if err := syncCacheRegular(c.objectPath(object)); err != nil {
			return fmt.Errorf("object %s sync: %w", object, err)
		}
	}
	if err := c.checkpointCall("prefixes:before-dir-sync"); err != nil {
		return err
	}
	if err := syncCacheDirectory(c.manifests); err != nil {
		return fmt.Errorf("manifests sync: %w", err)
	}
	if err := syncCacheDirectory(c.objects); err != nil {
		return fmt.Errorf("objects sync: %w", err)
	}
	if err := syncCacheDirectory(c.root); err != nil {
		return err
	}
	if err := syncCacheDirectory(filepath.Dir(c.root)); err != nil {
		return err
	}
	return nil
}

// Collect removes cache objects and manifests not reachable from liveIDs.
// Callers must invoke this only before starting producers or during explicit
// cleanup; Stage intentionally never calls Collect.
func (c *Cache) Collect(liveIDs []string) error {
	if c == nil {
		return errors.New("source cache: nil cache")
	}
	liveManifests := make(map[string]struct{}, len(liveIDs))
	liveObjects := make(map[string]struct{})
	for _, id := range liveIDs {
		if err := validateCacheID(id, "live manifest"); err != nil {
			return err
		}
		if _, err := c.Load(id); err != nil {
			return fmt.Errorf("live manifest %s: %w", id, err)
		}
		liveManifests[id] = struct{}{}
		objectIDs, err := c.manifestObjectIDs(id)
		if err != nil {
			return err
		}
		for _, object := range objectIDs {
			liveObjects[object] = struct{}{}
		}
	}
	if err := c.collectDirectory(c.manifests, liveManifests); err != nil {
		return err
	}
	if err := c.collectDirectory(c.objects, liveObjects); err != nil {
		return err
	}
	return nil
}

func (c *Cache) manifestObjectIDs(id string) ([]string, error) {
	manifest, err := c.readManifest(id)
	if err != nil {
		return nil, err
	}
	ids := make([]string, len(manifest.Entries))
	for i, entry := range manifest.Entries {
		ids[i] = entry.Object
	}
	return ids, nil
}

func (c *Cache) loadObject(entry manifestEntry, schemaVersion int) (Record, error) {
	data, err := c.readBounded(c.objectPath(entry.Object), maxCacheObjectBytes)
	if err != nil {
		return Record{}, fmt.Errorf("object %s: %w", entry.Object, err)
	}
	if digestID(data) != entry.Object {
		return Record{}, fmt.Errorf("object %s: content hash mismatch", entry.Object)
	}
	if err := validateBindingFields(data, schemaVersion, "object"); err != nil {
		return Record{}, fmt.Errorf("object %s: %w", entry.Object, err)
	}
	var object objectFile
	if err := decodeCanonical(data, &object, maxCacheObjectBytes); err != nil {
		return Record{}, fmt.Errorf("object %s: %w", entry.Object, err)
	}
	if object.SchemaVersion != schemaVersion {
		return Record{}, errors.New("manifest and selector object schema versions differ")
	}
	record, err := validateObject(object)
	if err != nil {
		return Record{}, fmt.Errorf("object %s: %w", entry.Object, err)
	}
	if object.Selector != entry.Selector || object.SourceKind != entry.SourceKind || object.SourceName != entry.SourceName || object.Endpoint != entry.Endpoint || object.APIVersion != entry.APIVersion || !maps.Equal(object.Parameters, entry.Parameters) || object.QueryStart != entry.QueryStart || object.QueryEnd != entry.QueryEnd || object.RetrievedAt != entry.RetrievedAt || object.Transport != entry.Transport {
		return Record{}, errors.New("manifest metadata does not match selector object")
	}
	return record, nil
}

func recordFromObject(object objectFile) (Record, error) {
	selector := policy.Selector{Kind: policy.SelectorKind(object.Selector.Kind), Value: object.Selector.Value}
	ipv4, err := parsePrefixes(object.IPv4)
	if err != nil {
		return Record{}, err
	}
	ipv6, err := parsePrefixes(object.IPv6)
	if err != nil {
		return Record{}, err
	}
	return Record{Selector: selector, SourceKind: object.SourceKind, SourceName: object.SourceName, Endpoint: object.Endpoint, APIVersion: object.APIVersion, Parameters: cloneParameters(object.Parameters), QueryStart: parseStoredTime(object.QueryStart), QueryEnd: parseStoredTime(object.QueryEnd), RetrievedAt: parseCanonicalTime(object.RetrievedAt), IPv4: ipv4, IPv6: ipv6, Transport: object.Transport}, nil
}

func validateCacheID(value, label string) error {
	if len(value) != cacheIDLength {
		return fmt.Errorf("source cache: %s identity must be %d lowercase hex characters", label, cacheIDLength)
	}
	for _, char := range value {
		if (char < '0' || char > '9') && (char < 'a' || char > 'f') {
			return fmt.Errorf("source cache: %s identity is not lowercase hexadecimal", label)
		}
	}
	return nil
}

func (c *Cache) objectPath(id string) string   { return filepath.Join(c.objects, id+".json") }
func (c *Cache) manifestPath(id string) string { return filepath.Join(c.manifests, id+".json") }

func (c *Cache) readBounded(path string, limit int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() || info.Mode().Perm() != cacheFileMode {
		return nil, errors.New("unsafe cache file")
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return nil, errors.New("cache file owner mismatch")
	}
	file, err := os.OpenFile(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) // #nosec G304 -- path is an internal content-addressed cache path; O_NOFOLLOW blocks symlink traversal.
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	data, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, errors.New("cache file is oversized")
	}
	return data, nil
}

func (c *Cache) installImmutable(path string, data []byte, kind string) error {
	if err := ensureCacheDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	if existing, err := c.readBounded(path, int64(len(data))); err == nil {
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("immutable %s already differs", kind)
		}
		if err := syncCacheRegular(path); err != nil {
			return err
		}
		return syncCacheDirectory(filepath.Dir(path))
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	temp, err := os.CreateTemp(filepath.Dir(path), ".cache-tmp-")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer func() { _ = os.Remove(tempPath) }()
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := c.checkpointCall(kind + ":before-file-sync"); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := c.checkpointCall(kind + ":before-rename"); err != nil {
		return err
	}
	if err := unix.Renameat2(unix.AT_FDCWD, tempPath, unix.AT_FDCWD, path, unix.RENAME_NOREPLACE); err != nil {
		if !errors.Is(err, os.ErrExist) {
			return err
		}
		existing, readErr := c.readBounded(path, int64(len(data)))
		if readErr != nil {
			return readErr
		}
		if !bytes.Equal(existing, data) {
			return fmt.Errorf("immutable %s already differs", kind)
		}
		if err := syncCacheRegular(path); err != nil {
			return err
		}
		return syncCacheDirectory(filepath.Dir(path))
	}
	if err := c.checkpointCall(kind + ":after-rename"); err != nil {
		return err
	}
	if err := syncCacheDirectory(filepath.Dir(path)); err != nil {
		return err
	}
	return c.checkpointCall(kind + ":after-dir-sync")
}

func (c *Cache) checkpointCall(name string) error {
	if c.checkpoint == nil {
		return nil
	}
	return c.checkpoint(name)
}

func ensureCacheDirectory(path string) error {
	if err := os.MkdirAll(path, cacheDirMode); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() || info.Mode().Perm() != cacheDirMode {
		return fmt.Errorf("unsafe cache directory %q", path)
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int64(stat.Uid) != int64(os.Geteuid()) {
		return fmt.Errorf("unsafe cache directory %q", path)
	}
	return syncCacheDirectory(filepath.Dir(path))
}

func syncCacheRegular(path string) (err error) {
	file, err := os.OpenFile(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) // #nosec G304 -- path is an internal cache file.
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	return file.Sync()
}

func syncCacheDirectory(path string) (err error) {
	file, err := os.OpenFile(path, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0) // #nosec G304 -- path is an internal cache directory.
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := file.Close(); err == nil && closeErr != nil {
			err = closeErr
		}
	}()
	return file.Sync()
}

func (c *Cache) collectDirectory(directory string, live map[string]struct{}) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		name := entry.Name()
		if !strings.HasPrefix(name, ".cache-tmp-") {
			if filepath.Ext(name) != ".json" {
				continue
			}
			id := strings.TrimSuffix(name, ".json")
			if _, ok := live[id]; ok {
				continue
			}
			if err := validateCacheID(id, "cache entry"); err != nil {
				continue
			}
		}
		path := filepath.Join(directory, name)
		info, err := os.Lstat(path)
		if err != nil {
			return err
		}
		stat, ok := info.Sys().(*syscall.Stat_t)
		if !info.Mode().IsRegular() || !ok || int64(stat.Uid) != int64(os.Geteuid()) {
			return fmt.Errorf("unsafe orphan cache entry %q", path)
		}
		if err := os.Remove(path); err != nil {
			return err
		}
	}
	return syncCacheDirectory(directory)
}
