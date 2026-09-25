// Package source contains source cache wire types, canonicalization, and codec helpers.
package source

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"maps"
	"net/netip"
	"reflect"
	"sort"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/prefix"
	"github.com/perimeterd/perimeterd/internal/upstream"
)

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
	Transport     upstream.Binding  `json:"transport"`
}
type manifestFile struct {
	SchemaVersion int             `json:"schema_version"`
	Entries       []manifestEntry `json:"selectors"`
	Source        string          `json:"source"`
}

func decodeManifest(data []byte) (manifestFile, error) {
	if err := validateManifestBindingFields(data); err != nil {
		return manifestFile{}, err
	}
	var manifest manifestFile
	if err := decodeCanonical(data, &manifest, maxCacheManifestSize); err != nil {
		return manifestFile{}, err
	}
	if err := validateManifest(manifest); err != nil {
		return manifestFile{}, err
	}
	return manifest, nil
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
	Transport   upstream.Binding  `json:"transport"`
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
		Transport: persistedBinding(record.Transport),
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
		Transport:   persistedBinding(record.Transport),
	}
}

func persistedBinding(binding upstream.Binding) upstream.Binding {
	if binding.Type == "" {
		return upstream.Binding{Type: upstream.TypeDirect}
	}
	return binding
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

type ripeRequestDescription struct {
	endpoint   string
	apiVersion string
	parameters map[string]string
}

func ripeRequestFor(selector policy.Selector) (ripeRequestDescription, error) {
	var endpoint string
	var parameters map[string]string
	switch selector.Kind {
	case policy.Country:
		endpoint = countryEndpoint
		parameters = map[string]string{
			"resource": selector.Value, "sourceapp": "perimeterd", "v4_format": "prefix",
		}
	case policy.ASN:
		endpoint = asnEndpoint
		parameters = map[string]string{
			"resource": selector.Value[2:], "sourceapp": "perimeterd",
		}
	default:
		return ripeRequestDescription{}, errors.New("cache selector must be an expanded country or ASN")
	}
	return ripeRequestDescription{
		endpoint: endpoint, apiVersion: endpointVersions[endpoint], parameters: parameters,
	}, nil
}

func canonicalRecord(record Record) (Record, error) {
	selector, err := policy.CanonicalSelector(record.Selector.Kind, record.Selector.Value)
	if err != nil {
		return Record{}, err
	}
	transport, err := canonicalBinding(record.Transport)
	if err != nil {
		return Record{}, err
	}
	sourceKind := record.SourceKind
	if sourceKind == "" {
		sourceKind = ripeSourceKind
	}
	if sourceKind == listSourceKind || sourceKind == providerSourceKind {
		expectedKind, label := policy.IPList, "custom list"
		if sourceKind == providerSourceKind {
			expectedKind, label = policy.Provider, "provider"
			if transport.Type != "" {
				return Record{}, errors.New("provider transport must be direct")
			}
		}
		if selector.Kind != expectedKind || record.SourceName != selector.Value {
			return Record{}, fmt.Errorf("%s identity does not match selector", label)
		}
		endpoint, err := normalizeListURL(record.Endpoint)
		if err != nil || endpoint != record.Endpoint {
			return Record{}, fmt.Errorf("%s URL is not canonical", label)
		}
		if sourceKind == providerSourceKind {
			expectedEndpoint, err := providerEndpoint(selector.Value)
			if err != nil || endpoint != expectedEndpoint {
				return Record{}, errors.New("provider URL does not match selector")
			}
		}
		if record.APIVersion != listFormatVersion {
			return Record{}, fmt.Errorf("unsupported %s parser version", label)
		}
		if len(record.Parameters) != 0 {
			return Record{}, fmt.Errorf("%s request metadata is not empty", label)
		}
		if !record.QueryStart.IsZero() || !record.QueryEnd.IsZero() {
			return Record{}, fmt.Errorf("%s query timestamps are not allowed", label)
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
		return Record{
			Selector: selector, SourceKind: sourceKind, SourceName: record.SourceName,
			Endpoint: endpoint, APIVersion: record.APIVersion,
			Parameters: map[string]string{}, RetrievedAt: retrievedAt,
			IPv4: v4, IPv6: v6, Transport: transport,
		}, nil
	}
	if sourceKind != ripeSourceKind || record.SourceName != "" {
		return Record{}, errors.New("unsupported source identity")
	}
	if transport.Type != "" {
		return Record{}, errors.New("RIPEstat transport must be direct")
	}
	request, err := ripeRequestFor(selector)
	if err != nil {
		return Record{}, err
	}
	if record.Endpoint != request.endpoint || record.APIVersion != request.apiVersion {
		return Record{}, errors.New("unsupported selector endpoint or API version")
	}
	parameters := cloneParameters(record.Parameters)
	if !maps.Equal(parameters, request.parameters) {
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
	return Record{Selector: selector, Endpoint: record.Endpoint, APIVersion: record.APIVersion, Parameters: parameters, QueryStart: queryStart, QueryEnd: queryEnd, RetrievedAt: retrievedAt, IPv4: v4, IPv6: v6, Transport: transport}, nil
}

func canonicalBinding(binding upstream.Binding) (upstream.Binding, error) {
	if binding.Type == "" {
		if binding.Identity != "" || binding.IdentityGeneration != "" || binding.Service != "" {
			return upstream.Binding{}, errors.New("direct transport binding contains identity fields")
		}
		return upstream.Binding{}, nil
	}
	if binding.Type == upstream.TypeDirect {
		if binding.Identity != "" || binding.IdentityGeneration != "" || binding.Service != "" {
			return upstream.Binding{}, errors.New("direct transport binding contains identity fields")
		}
		return upstream.Binding{}, nil
	}
	if binding.Type != upstream.TypeOpenZiti {
		return upstream.Binding{}, fmt.Errorf("unsupported transport binding type %q", binding.Type)
	}
	if err := binding.Validate(); err != nil {
		return upstream.Binding{}, fmt.Errorf("invalid transport binding: %w", err)
	}
	return binding, nil
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

func validateManifestBindingFields(data []byte) error {
	var envelope struct {
		SchemaVersion int               `json:"schema_version"`
		Entries       []json.RawMessage `json:"selectors"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return fmt.Errorf("manifest binding metadata is malformed: %w", err)
	}
	for index, entry := range envelope.Entries {
		if err := validateBindingFields(entry, envelope.SchemaVersion, fmt.Sprintf("selector %d", index)); err != nil {
			return err
		}
	}
	return nil
}

func validateBindingFields(data []byte, schemaVersion int, label string) error {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("%s binding metadata is malformed: %w", label, err)
	}
	raw, present := fields["transport"]
	if schemaVersion <= legacyCacheSchemaVersionV2 {
		if present {
			return fmt.Errorf("%s contains transport metadata from a newer schema", label)
		}
		return nil
	}
	if !present || bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return fmt.Errorf("%s transport binding is missing", label)
	}
	var bindingFields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &bindingFields); err != nil {
		return fmt.Errorf("%s transport binding is malformed: %w", label, err)
	}
	for name, value := range bindingFields {
		switch name {
		case "type", "identity", "identity_generation", "service":
		default:
			return fmt.Errorf("%s transport binding contains unknown field %q", label, name)
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return fmt.Errorf("%s transport binding field %q is null", label, name)
		}
	}
	var binding upstream.Binding
	if err := json.Unmarshal(raw, &binding); err != nil {
		return fmt.Errorf("%s transport binding is malformed: %w", label, err)
	}
	if err := binding.Validate(); err != nil {
		return fmt.Errorf("%s transport binding is invalid: %w", label, err)
	}
	switch binding.Type {
	case upstream.TypeDirect:
		if len(bindingFields) != 1 {
			return fmt.Errorf("%s direct transport binding has non-canonical fields", label)
		}
	case upstream.TypeOpenZiti:
		if len(bindingFields) != 4 {
			return fmt.Errorf("%s openziti transport binding has non-canonical fields", label)
		}
	default:
		return fmt.Errorf("%s transport binding has unsupported type %q", label, binding.Type)
	}
	return nil
}

func validateManifest(manifest manifestFile) error {
	if manifest.SchemaVersion < legacyCacheSchemaVersionV1 || manifest.SchemaVersion > cacheSchemaVersion {
		return fmt.Errorf("unsupported schema version %d", manifest.SchemaVersion)
	}
	if manifest.SchemaVersion <= legacyCacheSchemaVersionV2 && manifest.Source != ripeSourceKind && (manifest.SchemaVersion != legacyCacheSchemaVersionV2 || manifest.Source != "static") {
		return fmt.Errorf("unsupported source %q", manifest.Source)
	}
	if manifest.SchemaVersion == cacheSchemaVersion && manifest.Source != ripeSourceKind && manifest.Source != "static" {
		return fmt.Errorf("unsupported source %q", manifest.Source)
	}
	if len(manifest.Entries) == 0 || len(manifest.Entries) > maxSelectors {
		return errors.New("manifest selector count is invalid")
	}
	for i, entry := range manifest.Entries {
		if manifest.SchemaVersion == legacyCacheSchemaVersionV1 && (entry.SourceKind != "" || entry.SourceName != "") {
			return errors.New("legacy manifest contains custom source metadata")
		}
		if manifest.SchemaVersion == cacheSchemaVersion && entry.Transport.Type == "" {
			return fmt.Errorf("selector %d transport binding is missing", i)
		}
		if err := validateManifestEntry(entry, manifest.SchemaVersion, i); err != nil {
			return err
		}
		selector := manifestSelector(entry)
		if i > 0 && !manifestSelector(manifest.Entries[i-1]).Less(selector) {
			return errors.New("manifest selectors are not strictly sorted")
		}
	}
	return nil
}

func validateManifestEntry(entry manifestEntry, schemaVersion, index int) error {
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
	transport := entry.Transport
	if schemaVersion <= legacyCacheSchemaVersionV2 {
		if transport.Type != "" || transport.Identity != "" || transport.IdentityGeneration != "" || transport.Service != "" {
			return fmt.Errorf("legacy selector contains transport binding")
		}
		transport = upstream.Binding{}
	}
	start := parseStoredTime(entry.QueryStart)
	end := parseStoredTime(entry.QueryEnd)
	retrieved := parseCanonicalTime(entry.RetrievedAt)
	record := Record{Selector: selector, SourceKind: entry.SourceKind, SourceName: entry.SourceName, Endpoint: entry.Endpoint, APIVersion: entry.APIVersion, Parameters: entry.Parameters, QueryStart: start, QueryEnd: end, RetrievedAt: retrieved, Transport: transport}
	if _, err := canonicalRecord(record); err != nil {
		return fmt.Errorf("selector %d metadata: %w", index, err)
	}
	if storedTime(start) != entry.QueryStart || storedTime(end) != entry.QueryEnd || canonicalTime(retrieved) != entry.RetrievedAt {
		return fmt.Errorf("selector %d metadata timestamps are not canonical UTC values", index)
	}
	return nil
}

func validateObject(object objectFile) (Record, error) {
	if object.SchemaVersion < legacyCacheSchemaVersionV1 || object.SchemaVersion > cacheSchemaVersion {
		return Record{}, fmt.Errorf("unsupported schema version %d", object.SchemaVersion)
	}
	if object.SchemaVersion == legacyCacheSchemaVersionV1 && (object.SourceKind != "" || object.SourceName != "") {
		return Record{}, errors.New("legacy object contains custom source metadata")
	}
	if object.SchemaVersion == cacheSchemaVersion && object.Transport.Type == "" {
		return Record{}, errors.New("object transport binding is missing")
	}
	if object.Parameters == nil || object.IPv4 == nil || object.IPv6 == nil {
		return Record{}, errors.New("object contains null parameters or family array")
	}
	if object.SchemaVersion <= legacyCacheSchemaVersionV2 {
		if object.Transport.Type != "" || object.Transport.Identity != "" || object.Transport.IdentityGeneration != "" || object.Transport.Service != "" {
			return Record{}, errors.New("legacy object contains transport binding")
		}
		object.Transport = upstream.Binding{}
	}
	record, err := recordFromObject(object)
	if err != nil {
		return Record{}, err
	}
	if (object.SourceKind == listSourceKind || object.SourceKind == providerSourceKind) && len(object.IPv4) == 0 && len(object.IPv6) == 0 {
		if object.SourceKind == providerSourceKind {
			return Record{}, errors.New("provider object contains no prefixes")
		}
		return Record{}, errors.New("custom list object contains no prefixes")
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
