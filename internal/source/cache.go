// Package source contains source resolution and its immutable selector cache.
package source

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"maps"
	"net/netip"
	"os"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"syscall"
	"time"
	"unicode/utf16"
	"unicode/utf8"

	"golang.org/x/sys/unix"

	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/prefix"
)

const (
	cacheSchemaVersion   = 2
	cacheIDLength        = sha256.Size * 2
	maxCacheObjectBytes  = 32 << 20
	maxCacheManifestSize = 16 << 20
	cacheDirMode         = 0o700
	cacheFileMode        = 0o600
)

const legacyCacheSchemaVersion = 1

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
		if record.SourceKind == listSourceKind && len(record.IPv4) == 0 && len(record.IPv6) == 0 {
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
		if record.SourceKind == listSourceKind {
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
	data, err := c.readBounded(c.manifestPath(id), maxCacheManifestSize)
	if err != nil {
		return Snapshot{}, fmt.Errorf("manifest %s: %w", id, err)
	}
	if digestID(data) != id {
		return Snapshot{}, fmt.Errorf("manifest %s: content hash mismatch", id)
	}
	var manifest manifestFile
	if err := decodeCanonical(data, &manifest, maxCacheManifestSize); err != nil {
		return Snapshot{}, fmt.Errorf("manifest %s: %w", id, err)
	}
	if err := validateManifest(manifest); err != nil {
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
	data, err := c.readBounded(c.manifestPath(id), maxCacheManifestSize)
	if err != nil {
		return nil, err
	}
	var manifest manifestFile
	if err := decodeCanonical(data, &manifest, maxCacheManifestSize); err != nil {
		return nil, err
	}
	if err := validateManifest(manifest); err != nil {
		return nil, err
	}
	ids := make([]string, len(manifest.Entries))
	for i, entry := range manifest.Entries {
		ids[i] = entry.Object
	}
	return ids, nil
}

type selectorWire struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

type objectFile struct {
	SchemaVersion int               `json:"schema_version"`
	Selector      selectorWire      `json:"selector"`
	SourceKind    string            `json:"source_kind,omitempty"`
	SourceName    string            `json:"source_name,omitempty"`
	Endpoint      string            `json:"endpoint"`
	APIVersion    string            `json:"api_version"`
	Parameters    map[string]string `json:"parameters"`
	QueryStart    string            `json:"query_start"`
	QueryEnd      string            `json:"query_end"`
	RetrievedAt   string            `json:"retrieved_at"`
	ContentID     string            `json:"content_id"`
	IPv4          []string          `json:"ipv4"`
	IPv6          []string          `json:"ipv6"`
}
type manifestEntry struct {
	Selector    selectorWire      `json:"selector"`
	Object      string            `json:"object"`
	SourceKind  string            `json:"source_kind,omitempty"`
	SourceName  string            `json:"source_name,omitempty"`
	Endpoint    string            `json:"endpoint"`
	APIVersion  string            `json:"api_version"`
	Parameters  map[string]string `json:"parameters"`
	QueryStart  string            `json:"query_start"`
	QueryEnd    string            `json:"query_end"`
	RetrievedAt string            `json:"retrieved_at"`
}

type manifestFile struct {
	SchemaVersion int             `json:"schema_version"`
	Source        string          `json:"source"`
	Entries       []manifestEntry `json:"selectors"`
}

func objectFromRecord(record Record) objectFile {
	return objectFile{
		SchemaVersion: cacheSchemaVersion,
		Selector:      selectorWire{Kind: string(record.Selector.Kind), Value: record.Selector.Value},
		SourceKind:    record.SourceKind,
		SourceName:    record.SourceName,
		Endpoint:      record.Endpoint,
		APIVersion:    record.APIVersion,
		Parameters:    cloneParameters(record.Parameters),
		QueryStart:    storedTime(record.QueryStart), QueryEnd: storedTime(record.QueryEnd), RetrievedAt: canonicalTime(record.RetrievedAt),
		ContentID: prefixContentID(record.IPv4, record.IPv6),
		IPv4:      prefixStrings(record.IPv4), IPv6: prefixStrings(record.IPv6),
	}
}

func manifestEntryFromRecord(record Record, object string) manifestEntry {
	return manifestEntry{
		Selector: selectorWire{Kind: string(record.Selector.Kind), Value: record.Selector.Value},
		Object:   object, SourceKind: record.SourceKind, SourceName: record.SourceName,
		Endpoint: record.Endpoint, APIVersion: record.APIVersion,
		Parameters: cloneParameters(record.Parameters),
		QueryStart: storedTime(record.QueryStart), QueryEnd: storedTime(record.QueryEnd),
		RetrievedAt: canonicalTime(record.RetrievedAt),
	}
}

func (c *Cache) loadObject(entry manifestEntry, schemaVersion int) (Record, error) {
	data, err := c.readBounded(c.objectPath(entry.Object), maxCacheObjectBytes)
	if err != nil {
		return Record{}, fmt.Errorf("object %s: %w", entry.Object, err)
	}
	if digestID(data) != entry.Object {
		return Record{}, fmt.Errorf("object %s: content hash mismatch", entry.Object)
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
	if object.Selector != entry.Selector || object.SourceKind != entry.SourceKind || object.SourceName != entry.SourceName || object.Endpoint != entry.Endpoint || object.APIVersion != entry.APIVersion || !maps.Equal(object.Parameters, entry.Parameters) || object.QueryStart != entry.QueryStart || object.QueryEnd != entry.QueryEnd || object.RetrievedAt != entry.RetrievedAt {
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
	return Record{Selector: selector, SourceKind: object.SourceKind, SourceName: object.SourceName, Endpoint: object.Endpoint, APIVersion: object.APIVersion, Parameters: cloneParameters(object.Parameters), QueryStart: parseStoredTime(object.QueryStart), QueryEnd: parseStoredTime(object.QueryEnd), RetrievedAt: parseCanonicalTime(object.RetrievedAt), IPv4: ipv4, IPv6: ipv6}, nil
}

func (c *Cache) objectForRecord(record Record) (string, error) {
	objectBytes, err := canonicalJSON(objectFromRecord(record))
	if err != nil {
		return "", err
	}
	return digestID(objectBytes), nil
}

func makeSnapshot(id string, compiled policy.Snapshot, records []Record) Snapshot {
	out := Snapshot{manifest: id, policy: compiled, records: make([]Record, len(records))}
	for i, record := range records {
		out.records[i] = cloneRecord(record)
		if out.oldest.IsZero() || record.RetrievedAt.Before(out.oldest) {
			out.oldest = record.RetrievedAt
		}
	}
	return out
}

func canonicalRecords(records []Record) ([]Record, error) {
	out := make([]Record, len(records))
	seen := make(map[policy.Selector]struct{}, len(records))
	for i, record := range records {
		canonical, err := canonicalRecord(record)
		if err != nil {
			return nil, fmt.Errorf("record %d: %w", i, err)
		}
		if _, exists := seen[canonical.Selector]; exists {
			return nil, fmt.Errorf("record %d: duplicate selector %s/%s", i, canonical.Selector.Kind, canonical.Selector.Value)
		}
		seen[canonical.Selector] = struct{}{}
		out[i] = canonical
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Selector.Less(out[j].Selector) })
	return out, nil
}

func canonicalRecord(record Record) (Record, error) {
	selector, err := policy.CanonicalSelector(record.Selector.Kind, record.Selector.Value)
	if err != nil {
		return Record{}, err
	}
	sourceKind := record.SourceKind
	if sourceKind == "" {
		sourceKind = ripeSourceKind
	}
	if sourceKind == listSourceKind {
		if selector.Kind != policy.IPList || record.SourceName != selector.Value {
			return Record{}, errors.New("custom list identity does not match selector")
		}
		endpoint, err := normalizeListURL(record.Endpoint)
		if err != nil || endpoint != record.Endpoint {
			return Record{}, errors.New("custom list URL is not canonical")
		}
		if record.APIVersion != listFormatVersion {
			return Record{}, errors.New("unsupported custom list parser version")
		}
		if len(record.Parameters) != 0 {
			return Record{}, errors.New("custom list request metadata is not empty")
		}
		if !record.QueryStart.IsZero() || !record.QueryEnd.IsZero() {
			return Record{}, errors.New("custom list query timestamps are not allowed")
		}
		retrievedAt, err := canonicalTimestamp(record.RetrievedAt, "retrieved_at")
		if err != nil {
			return Record{}, err
		}
		v4, err := normalizeFamily(record.IPv4, true)
		if err != nil {
			return Record{}, fmt.Errorf("IPv4: %w", err)
		}
		v6, err := normalizeFamily(record.IPv6, false)
		if err != nil {
			return Record{}, fmt.Errorf("IPv6: %w", err)
		}
		return Record{Selector: selector, SourceKind: listSourceKind, SourceName: record.SourceName, Endpoint: endpoint, APIVersion: record.APIVersion, Parameters: map[string]string{}, RetrievedAt: retrievedAt, IPv4: v4, IPv6: v6}, nil
	}
	if sourceKind != ripeSourceKind || record.SourceName != "" {
		return Record{}, errors.New("unsupported source identity")
	}
	expectedEndpoint := countryEndpoint
	expectedParams := map[string]string{"resource": selector.Value, "sourceapp": "perimeterd", "v4_format": "prefix"}
	if selector.Kind == policy.ASN {
		expectedEndpoint = asnEndpoint
		expectedParams = map[string]string{"resource": selector.Value[2:], "sourceapp": "perimeterd"}
	} else if selector.Kind != policy.Country {
		return Record{}, errors.New("cache selector must be an expanded country or ASN")
	}
	if record.Endpoint != expectedEndpoint || record.APIVersion != endpointVersions[expectedEndpoint] {
		return Record{}, errors.New("unsupported selector endpoint or API version")
	}
	parameters := cloneParameters(record.Parameters)
	if !maps.Equal(parameters, expectedParams) {
		return Record{}, errors.New("selector request parameters do not match its identity")
	}
	queryStart, err := canonicalTimestamp(record.QueryStart, "query_start")
	if err != nil {
		return Record{}, err
	}
	queryEnd, err := canonicalTimestamp(record.QueryEnd, "query_end")
	if err != nil {
		return Record{}, err
	}
	retrievedAt, err := canonicalTimestamp(record.RetrievedAt, "retrieved_at")
	if err != nil {
		return Record{}, err
	}
	if queryEnd.Before(queryStart) {
		return Record{}, errors.New("query_end precedes query_start")
	}
	if selector.Kind == policy.Country && !queryStart.Equal(queryEnd) {
		return Record{}, errors.New("country query must name a single instant")
	}
	if queryEnd.After(retrievedAt) {
		return Record{}, errors.New("query end is later than retrieval")
	}
	v4, err := normalizeFamily(record.IPv4, true)
	if err != nil {
		return Record{}, fmt.Errorf("IPv4: %w", err)
	}
	v6, err := normalizeFamily(record.IPv6, false)
	if err != nil {
		return Record{}, fmt.Errorf("IPv6: %w", err)
	}
	return Record{Selector: selector, Endpoint: record.Endpoint, APIVersion: record.APIVersion, Parameters: parameters, QueryStart: queryStart, QueryEnd: queryEnd, RetrievedAt: retrievedAt, IPv4: v4, IPv6: v6}, nil
}

func normalizeFamily(values []netip.Prefix, ipv4 bool) ([]netip.Prefix, error) {
	for i, value := range values {
		if !value.IsValid() {
			return nil, fmt.Errorf("prefix %d is malformed", i)
		}
		if value.Addr().Is4() != ipv4 {
			return nil, fmt.Errorf("prefix %d has wrong address family", i)
		}
	}
	return prefix.Normalize(values)
}

func validateManifest(manifest manifestFile) error {
	if manifest.SchemaVersion != legacyCacheSchemaVersion && manifest.SchemaVersion != cacheSchemaVersion {
		return fmt.Errorf("unsupported schema version %d", manifest.SchemaVersion)
	}
	if manifest.SchemaVersion == legacyCacheSchemaVersion && manifest.Source != ripeSourceKind {
		return fmt.Errorf("unsupported source %q", manifest.Source)
	}
	if manifest.SchemaVersion == cacheSchemaVersion && manifest.Source != ripeSourceKind && manifest.Source != "static" {
		return fmt.Errorf("unsupported source %q", manifest.Source)
	}
	if len(manifest.Entries) == 0 || len(manifest.Entries) > maxSelectors {
		return errors.New("manifest selector count is invalid")
	}
	for i, entry := range manifest.Entries {
		if manifest.SchemaVersion == legacyCacheSchemaVersion && (entry.SourceKind != "" || entry.SourceName != "") {
			return errors.New("legacy manifest contains custom source metadata")
		}
		if err := validateManifestEntry(entry, i); err != nil {
			return err
		}
		selector := manifestSelector(entry)
		if i > 0 && !manifestSelector(manifest.Entries[i-1]).Less(selector) {
			return errors.New("manifest selectors are not strictly sorted")
		}
	}
	return nil
}

func validateManifestEntry(entry manifestEntry, index int) error {
	selector, err := policy.CanonicalSelector(policy.SelectorKind(entry.Selector.Kind), entry.Selector.Value)
	if err != nil {
		return fmt.Errorf("selector %d: %w", index, err)
	}
	if selector.Kind != policy.SelectorKind(entry.Selector.Kind) || selector.Value != entry.Selector.Value {
		return fmt.Errorf("selector %d is not canonical", index)
	}
	if err := validateCacheID(entry.Object, "object"); err != nil {
		return fmt.Errorf("selector %d: %w", index, err)
	}
	if entry.Parameters == nil {
		return fmt.Errorf("selector %d metadata parameters are null", index)
	}
	start := parseStoredTime(entry.QueryStart)
	end := parseStoredTime(entry.QueryEnd)
	retrieved := parseCanonicalTime(entry.RetrievedAt)
	record := Record{Selector: selector, SourceKind: entry.SourceKind, SourceName: entry.SourceName, Endpoint: entry.Endpoint, APIVersion: entry.APIVersion, Parameters: entry.Parameters, QueryStart: start, QueryEnd: end, RetrievedAt: retrieved}
	if _, err := canonicalRecord(record); err != nil {
		return fmt.Errorf("selector %d metadata: %w", index, err)
	}
	if storedTime(start) != entry.QueryStart || storedTime(end) != entry.QueryEnd || canonicalTime(retrieved) != entry.RetrievedAt {
		return fmt.Errorf("selector %d metadata timestamps are not canonical UTC values", index)
	}
	return nil
}

func validateObject(object objectFile) (Record, error) {
	if object.SchemaVersion != legacyCacheSchemaVersion && object.SchemaVersion != cacheSchemaVersion {
		return Record{}, fmt.Errorf("unsupported schema version %d", object.SchemaVersion)
	}
	if object.SchemaVersion == legacyCacheSchemaVersion && (object.SourceKind != "" || object.SourceName != "") {
		return Record{}, errors.New("legacy object contains custom source metadata")
	}
	if object.Parameters == nil || object.IPv4 == nil || object.IPv6 == nil {
		return Record{}, errors.New("object contains null parameters or family array")
	}
	if object.SourceKind == listSourceKind && len(object.IPv4) == 0 && len(object.IPv6) == 0 {
		return Record{}, errors.New("custom list object contains no prefixes")
	}
	record, err := recordFromObject(object)
	if err != nil {
		return Record{}, err
	}
	if storedTime(record.QueryStart) != object.QueryStart || storedTime(record.QueryEnd) != object.QueryEnd || canonicalTime(record.RetrievedAt) != object.RetrievedAt {
		return Record{}, errors.New("timestamps are not canonical UTC values")
	}
	canonical, err := canonicalRecord(record)
	if err != nil {
		return Record{}, err
	}
	if object.ContentID != prefixContentID(canonical.IPv4, canonical.IPv6) {
		return Record{}, errors.New("normalized prefix content hash mismatch")
	}
	if !reflect.DeepEqual(prefixStrings(canonical.IPv4), object.IPv4) || !reflect.DeepEqual(prefixStrings(canonical.IPv6), object.IPv6) {
		return Record{}, errors.New("prefix arrays are not canonical")
	}
	return canonical, nil
}

func manifestSelector(entry manifestEntry) policy.Selector {
	return policy.Selector{Kind: policy.SelectorKind(entry.Selector.Kind), Value: entry.Selector.Value}
}

func prefixStrings(values []netip.Prefix) []string {
	out := make([]string, len(values))
	for i, value := range values {
		out[i] = value.String()
	}
	return out
}

func parsePrefixes(values []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, len(values))
	for i, value := range values {
		parsed, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("prefix %d is malformed: %w", i, err)
		}
		out[i] = parsed
	}
	return out, nil
}

func prefixContentID(ipv4, ipv6 []netip.Prefix) string {
	// Canonical address strings contain no JSON escapes, and these arrays
	// contain no values for which json.Marshal can fail.
	data, _ := json.Marshal([2][]string{prefixStrings(ipv4), prefixStrings(ipv6)})
	return digestID(data)
}

func canonicalTimestamp(value time.Time, field string) (time.Time, error) {
	if value.IsZero() {
		return time.Time{}, fmt.Errorf("%s is required", field)
	}
	return value.UTC(), nil
}

func canonicalTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }
func storedTime(value time.Time) string {
	if value.IsZero() {
		return ""
	}
	return canonicalTime(value)
}

func parseStoredTime(value string) time.Time {
	if value == "" {
		return time.Time{}
	}
	return parseCanonicalTime(value)
}

func parseCanonicalTime(value string) time.Time {
	parsed, _ := time.Parse(time.RFC3339Nano, value)
	return parsed.UTC()
}

func cloneParameters(values map[string]string) map[string]string {
	if values == nil {
		return map[string]string{}
	}
	return maps.Clone(values)
}

func cloneRecord(record Record) Record {
	record.Parameters = cloneParameters(record.Parameters)
	record.IPv4 = append([]netip.Prefix(nil), record.IPv4...)
	record.IPv6 = append([]netip.Prefix(nil), record.IPv6...)
	return record
}

func digestID(data []byte) string {
	digest := sha256.Sum256(data)
	return hex.EncodeToString(digest[:])
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

// canonicalJSON emits RFC 8785-compatible canonical UTF-8 for the JSON values
// used by cache schemas. Cache schemas contain only strings, booleans, arrays,
// objects, and integral schema versions.
func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	parsed, err := parseCanonicalValue(decoder)
	if err != nil {
		return nil, err
	}
	if err := ensureCanonicalEOF(decoder); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := writeCanonicalValue(&out, parsed); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func decodeCanonical(data []byte, target any, limit int64) error {
	if int64(len(data)) > limit || len(data) == 0 {
		return errors.New("cache record size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := parseCanonicalValue(decoder)
	if err != nil {
		return fmt.Errorf("malformed JSON: %w", err)
	}
	if err := ensureCanonicalEOF(decoder); err != nil {
		return err
	}
	// Schema decoding below enforces the known fields after canonical parsing.
	decoder2 := json.NewDecoder(bytes.NewReader(data))
	decoder2.DisallowUnknownFields()
	if err := decoder2.Decode(target); err != nil {
		return fmt.Errorf("malformed payload: %w", err)
	}
	if err := ensureCanonicalEOF(decoder2); err != nil {
		return err
	}
	// Re-encoding through the canonical value rejects non-canonical bytes while
	// still allowing the decoder to enforce schema field names below.
	var canonicalBytes bytes.Buffer
	if err := writeCanonicalValue(&canonicalBytes, value); err != nil {
		return err
	}
	if !bytes.Equal(canonicalBytes.Bytes(), data) {
		return errors.New("cache record is not canonical JSON")
	}
	return nil
}

func parseCanonicalValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("duplicate object key %q", key)
				}
				child, err := parseCanonicalValue(decoder)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("unterminated object")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				child, err := parseCanonicalValue(decoder)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("unterminated array")
			}
			return array, nil
		default:
			return nil, errors.New("unexpected delimiter")
		}
	case json.Number:
		if strings.ContainsAny(string(value), ".eE") {
			return nil, errors.New("non-integral number in cache record")
		}
		return value, nil
	default:
		return value, nil
	}
}

func ensureCanonicalEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON data")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func writeCanonicalValue(out *bytes.Buffer, value any) error {
	switch value := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if value {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		if !utf8.ValidString(value) {
			return errors.New("invalid UTF-8 string")
		}
		writeCanonicalString(out, value)
	case json.Number:
		out.WriteString(string(value))
	case []any:
		out.WriteByte('[')
		for i, child := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonicalValue(out, child); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeCanonicalString(out, key)
			out.WriteByte(':')
			if err := writeCanonicalValue(out, value[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON value %T", value)
	}
	return nil
}

func utf16Less(a, b string) bool {
	aa, bb := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(aa) && i < len(bb); i++ {
		if aa[i] != bb[i] {
			return aa[i] < bb[i]
		}
	}
	return len(aa) < len(bb)
}

func writeCanonicalString(out *bytes.Buffer, value string) {
	out.WriteByte('"')
	for _, char := range []byte(value) {
		switch char {
		case '\\', '"':
			out.WriteByte('\\')
			out.WriteByte(char)
		case '\b':
			out.WriteString("\\b")
		case '\f':
			out.WriteString("\\f")
		case '\n':
			out.WriteString("\\n")
		case '\r':
			out.WriteString("\\r")
		case '\t':
			out.WriteString("\\t")
		default:
			if char < 0x20 {
				fmt.Fprintf(out, "\\u00%02x", char)
			} else {
				out.WriteByte(char)
			}
		}
	}
	out.WriteByte('"')
}
