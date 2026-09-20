package source

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func (r *Resolver) resolve(ctx context.Context, cfg config.Config, committedManifest string, allowStale bool) (resolution Resolution, resolveErr error) {
	var attempted []policy.Selector
	defer func() {
		if attempted != nil {
			resolution.Attempted = append([]policy.Selector(nil), attempted...)
		}
	}()
	if err := ctx.Err(); err != nil {
		return Resolution{}, err
	}
	if cfg.Geo.RefreshInterval <= 0 || cfg.Geo.RequestTimeout <= 0 {
		return Resolution{}, errors.New("source: refresh interval and request timeout must be positive")
	}
	required, err := policy.RequiredSelectors(cfg)
	if err != nil {
		return Resolution{}, err
	}
	if len(required) > maxSelectors {
		return Resolution{}, fmt.Errorf("source: %d selectors exceed maximum %d", len(required), maxSelectors)
	}
	if len(required) == 0 {
		return Resolution{}, nil
	}
	if r.cache == nil {
		return Resolution{}, errors.New("source: cache is required for non-empty resolution")
	}
	for _, selector := range required {
		if _, _, err := selectorTiming(cfg, selector); err != nil {
			return Resolution{}, err
		}
	}

	var committed Snapshot
	if committedManifest != "" {
		committed, err = r.cache.Load(committedManifest)
		if err != nil {
			return Resolution{}, fmt.Errorf("source: committed manifest: %w", err)
		}
	}
	committedBySelector := recordsBySelector(committed.Records())
	committedCovers := true
	for _, selector := range required {
		record, ok := committedBySelector[selector]
		if !ok || !recordMatchesConfig(record, cfg) {
			committedCovers = false
			break
		}
	}

	candidate := make(map[policy.Selector]Record, len(required))
	stale := make([]policy.Selector, 0, len(required))
	for _, selector := range required {
		record, ok := committedBySelector[selector]
		if !ok || !recordMatchesConfig(record, cfg) {
			stale = append(stale, selector)
			continue
		}
		interval, _, _ := selectorTiming(cfg, selector)
		if recordFresh(record, interval) {
			candidate[selector] = record
		} else {
			stale = append(stale, selector)
		}
	}

	refreshFailure := func(refreshErr error) (Resolution, error) {
		if err := ctx.Err(); err != nil {
			return Resolution{}, err
		}
		if !allowStale || !committedCovers {
			return Resolution{}, refreshErr
		}
		if len(committedBySelector) == len(required) {
			_, validationErr := policy.Compile(cfg, committed.Policy())
			if err := ctx.Err(); err != nil {
				return Resolution{}, err
			}
			if validationErr != nil {
				return Resolution{}, errors.Join(refreshErr, fmt.Errorf("source: validate stale committed snapshot: %w", validationErr))
			}
			return Resolution{Snapshot: committed, RefreshError: refreshErr}, nil
		}
		fallback, stageErr := r.stage(cfg, recordsForSelectors(committedBySelector, required))
		if err := ctx.Err(); err != nil {
			return Resolution{}, err
		}
		if stageErr != nil {
			return Resolution{}, errors.Join(refreshErr, fmt.Errorf("source: stage stale committed subset: %w", stageErr))
		}
		return Resolution{Snapshot: fallback, RefreshError: refreshErr}, nil
	}

	if len(stale) == 0 {
		if len(committedBySelector) == len(required) && committedManifest != "" {
			_, validationErr := policy.Compile(cfg, committed.Policy())
			if err := ctx.Err(); err != nil {
				return Resolution{}, err
			}
			if validationErr != nil {
				return Resolution{}, fmt.Errorf("source: validate reused snapshot: %w", validationErr)
			}
			return Resolution{Snapshot: committed}, nil
		}
		snapshot, stageErr := r.stage(cfg, recordsForSelectors(candidate, required))
		if stageErr != nil {
			return Resolution{}, fmt.Errorf("source: stage reused snapshot: %w", stageErr)
		}
		return Resolution{Snapshot: snapshot}, nil
	}

	attempted = append([]policy.Selector(nil), stale...)
	fetched, fetchErr := r.fetchAll(ctx, cfg, stale)
	if fetchErr != nil {
		return refreshFailure(fetchErr)
	}
	for selector, record := range fetched {
		candidate[selector] = record
	}
	if len(candidate) != len(required) {
		return refreshFailure(errors.New("source: refresh completed without every required selector"))
	}
	snapshot, stageErr := r.stage(cfg, recordsForSelectors(candidate, required))
	if stageErr != nil {
		return refreshFailure(fmt.Errorf("source: stage refreshed snapshot: %w", stageErr))
	}
	return Resolution{Snapshot: snapshot}, nil
}

func (r *Resolver) stage(cfg config.Config, records []Record) (Snapshot, error) {
	snapshot, err := r.cache.Stage(records)
	if err != nil {
		return Snapshot{}, err
	}
	if _, err := policy.Compile(cfg, snapshot.Policy()); err != nil {
		return Snapshot{}, fmt.Errorf("compiled policy: %w", err)
	}
	return snapshot, nil
}

func recordsBySelector(records []Record) map[policy.Selector]Record {
	result := make(map[policy.Selector]Record, len(records))
	for _, record := range records {
		result[record.Selector] = record
	}
	return result
}

func recordsForSelectors(records map[policy.Selector]Record, selectors []policy.Selector) []Record {
	result := make([]Record, 0, len(selectors))
	for _, selector := range selectors {
		if record, ok := records[selector]; ok {
			result = append(result, record)
		}
	}
	return result
}

func recordFresh(record Record, interval time.Duration) bool {
	if record.RetrievedAt.IsZero() || interval <= 0 {
		return false
	}
	age := time.Since(record.RetrievedAt)
	return age >= 0 && age < interval
}

func selectorTiming(cfg config.Config, selector policy.Selector) (time.Duration, time.Duration, error) {
	if selector.Kind != policy.IPList {
		return cfg.Geo.RefreshInterval, cfg.Geo.RequestTimeout, nil
	}
	list, ok := cfg.IPLists[selector.Value]
	if !ok {
		return 0, 0, fmt.Errorf("source: custom list %q is not configured", selector.Value)
	}
	if list.RefreshInterval <= 0 || list.RequestTimeout <= 0 {
		return 0, 0, fmt.Errorf("source: custom list %q has invalid timing", selector.Value)
	}
	return list.RefreshInterval, list.RequestTimeout, nil
}

func recordMatchesConfig(record Record, cfg config.Config) bool {
	switch record.Selector.Kind {
	case policy.IPList:
		list, ok := cfg.IPLists[record.Selector.Value]
		if !ok {
			return false
		}
		endpoint, err := normalizeListURL(list.URL)
		return err == nil && record.SourceKind == listSourceKind && record.SourceName == record.Selector.Value && record.Endpoint == endpoint && record.APIVersion == listFormatVersion
	case policy.Country, policy.ASN:
		if record.SourceKind != "" && record.SourceKind != ripeSourceKind {
			return false
		}
		expected := countryEndpoint
		version := endpointVersions[countryEndpoint]
		if record.Selector.Kind == policy.ASN {
			expected = asnEndpoint
			version = endpointVersions[asnEndpoint]
		}
		return record.Endpoint == expected && record.APIVersion == version
	default:
		return false
	}
}

type listRequestMarker struct{}

func markListRequest(ctx context.Context) context.Context {
	return context.WithValue(ctx, listRequestMarker{}, true)
}

func isListRequest(req *http.Request) bool {
	if req == nil {
		return false
	}
	marked, _ := req.Context().Value(listRequestMarker{}).(bool)
	return marked
}

func validateListURL(value *url.URL) error {
	if value == nil {
		return errors.New("invalid custom list URL")
	}
	_, err := normalizeListURL(value.String())
	return err
}

func normalizeListURL(raw string) (string, error) {
	return config.NormalizeIPListURL(raw)
}

func classifyListRequestError(err error) error {
	var wrapped *url.Error
	if errors.As(err, &wrapped) {
		err = wrapped.Err
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return errors.New("request timed out")
	}
	if errors.Is(err, context.Canceled) {
		return errors.New("request canceled")
	}
	message := strings.ToLower(err.Error())
	switch {
	case strings.Contains(message, "downgrade"):
		return errors.New("redirect downgrade rejected")
	case strings.Contains(message, "too many redirects"):
		return errors.New("too many redirects")
	case strings.Contains(message, "certificate"), strings.Contains(message, "tls"):
		return errors.New("TLS verification failed")
	default:
		return errors.New("request failed")
	}
}

type fetchResult struct {
	selector policy.Selector
	record   Record
	err      error
}

func (r *Resolver) fetchAll(ctx context.Context, cfg config.Config, selectors []policy.Selector) (map[policy.Selector]Record, error) {
	requestCtx, cancel := context.WithCancel(ctx)
	defer cancel()
	jobs := make(chan policy.Selector)
	results := make(chan fetchResult, len(selectors))
	workers := len(selectors)
	if workers > maxConcurrent {
		workers = maxConcurrent
	}
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			for {
				select {
				case <-requestCtx.Done():
					return
				case selector, ok := <-jobs:
					if !ok {
						return
					}
					record, err := r.fetchOne(requestCtx, cfg, selector)
					select {
					case results <- fetchResult{selector: selector, record: record, err: err}:
					case <-requestCtx.Done():
					}
					if err != nil {
						cancel()
					}
				}
			}
		}()
	}
	go func() {
		defer close(jobs)
		for _, selector := range selectors {
			select {
			case jobs <- selector:
			case <-requestCtx.Done():
				return
			}
		}
	}()
	go func() {
		wait.Wait()
		close(results)
	}()

	fetched := make(map[policy.Selector]Record, len(selectors))
	var firstErr error
	for result := range results {
		if result.err != nil && firstErr == nil {
			firstErr = fmt.Errorf("source: selector %s/%s: %w", result.selector.Kind, result.selector.Value, result.err)
			cancel()
			continue
		}
		if result.err == nil {
			fetched[result.selector] = result.record
		}
	}
	if firstErr != nil {
		return nil, firstErr
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(fetched) != len(selectors) {
		return nil, errors.New("source: refresh canceled before all selectors completed")
	}
	return fetched, nil
}

func (r *Resolver) fetchOne(parent context.Context, cfg config.Config, selector policy.Selector) (Record, error) {
	_, timeout, err := selectorTiming(cfg, selector)
	if err != nil {
		return Record{}, err
	}
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	case <-ctx.Done():
		return Record{}, ctx.Err()
	}

	list := selector.Kind == policy.IPList
	values := url.Values{"sourceapp": {"perimeterd"}}
	endpoint := countryEndpoint
	if list {
		configured, ok := cfg.IPLists[selector.Value]
		if !ok {
			return Record{}, fmt.Errorf("custom list %q is not configured", selector.Value)
		}
		endpoint, err = normalizeListURL(configured.URL)
		if err != nil {
			return Record{}, fmt.Errorf("custom list %q has invalid URL", selector.Value)
		}
	} else {
		switch selector.Kind {
		case policy.Country:
			values.Set("resource", selector.Value)
			values.Set("v4_format", "prefix")
		case policy.ASN:
			endpoint = asnEndpoint
			values.Set("resource", selector.Value[2:])
		default:
			return Record{}, fmt.Errorf("unsupported source selector kind %q", selector.Kind)
		}
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		if list {
			return Record{}, errors.New("invalid custom list URL")
		}
		return Record{}, err
	}
	if list {
		ctx = markListRequest(ctx)
	} else {
		u.RawQuery = values.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		if list {
			return Record{}, errors.New("create request failed")
		}
		return Record{}, fmt.Errorf("create request: %w", err)
	}
	if list {
		req.Header.Set("Accept", "text/plain")
	} else {
		req.Header.Set("Accept", "application/json")
	}
	resp, err := r.client.Do(req)
	if err != nil {
		if list {
			return Record{}, classifyListRequestError(err)
		}
		return Record{}, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if list {
		if resp.StatusCode != http.StatusOK {
			return Record{}, fmt.Errorf("HTTP status %d", resp.StatusCode)
		}
	} else if resp.StatusCode < http.StatusOK || resp.StatusCode >= http.StatusMultipleChoices {
		return Record{}, fmt.Errorf("HTTP status %d", resp.StatusCode)
	}
	var decoded io.Reader = resp.Body
	if encoding := resp.Header.Get("Content-Encoding"); encoding != "" && !resp.Uncompressed {
		if !strings.EqualFold(encoding, "gzip") {
			return Record{}, fmt.Errorf("unsupported content encoding %q", encoding)
		}
		reader, err := gzip.NewReader(resp.Body)
		if err != nil {
			return Record{}, fmt.Errorf("decode gzip response: %w", err)
		}
		defer func() { _ = reader.Close() }()
		decoded = reader
	}
	body, err := io.ReadAll(io.LimitReader(decoded, maxBodyBytes+1))
	if err != nil {
		return Record{}, fmt.Errorf("read response: %w", err)
	}
	if len(body) > maxBodyBytes {
		return Record{}, fmt.Errorf("response exceeds %d-byte limit", maxBodyBytes)
	}
	if list {
		return parseList(body, endpoint, selector)
	}
	params := make(map[string]string, len(values))
	for key, list := range values {
		if len(list) != 1 {
			return Record{}, fmt.Errorf("request parameter %q has unexpected multiplicity", key)
		}
		params[key] = list[0]
	}
	if selector.Kind == policy.Country {
		return parseCountry(body, endpoint, params, selector)
	}
	return parseASN(body, endpoint, params, selector)
}

func parseList(body []byte, endpoint string, selector policy.Selector) (Record, error) {
	if !utf8.Valid(body) {
		return Record{}, fmt.Errorf("custom list %q line data is not valid UTF-8", selector.Value)
	}
	ipv4 := make([]netip.Prefix, 0)
	ipv6 := make([]netip.Prefix, 0)
	found := false
	lineNumber := 0
	offset := 0
	for raw := range strings.SplitSeq(string(body), "\n") {
		lineNumber++
		line := raw
		if strings.HasSuffix(line, "\r") && offset+len(raw) < len(body) {
			line = strings.TrimSuffix(line, "\r")
		}
		offset += len(raw) + 1
		line = strings.Trim(line, " \t")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		found = true
		prefix, err := netip.ParsePrefix(line)
		if err != nil {
			address, addressErr := netip.ParseAddr(line)
			if addressErr != nil || address.Zone() != "" {
				return Record{}, fmt.Errorf("custom list %q line %d is not one IP address or CIDR", selector.Value, lineNumber)
			}
			bits := 128
			if address.Is4() {
				bits = 32
			}
			prefix = netip.PrefixFrom(address, bits)
		}
		if prefix.Addr().Is4() {
			ipv4 = append(ipv4, prefix)
		} else if prefix.Addr().Is6() && prefix.Addr().Zone() == "" {
			ipv6 = append(ipv6, prefix)
		} else {
			return Record{}, fmt.Errorf("custom list %q line %d contains an unsupported address", selector.Value, lineNumber)
		}
	}
	if !found {
		return Record{}, fmt.Errorf("custom list %q is empty", selector.Value)
	}
	normalized4, err := normalizeFamily(ipv4, true)
	if err != nil {
		return Record{}, fmt.Errorf("custom list %q IPv4: %w", selector.Value, err)
	}
	normalized6, err := normalizeFamily(ipv6, false)
	if err != nil {
		return Record{}, fmt.Errorf("custom list %q IPv6: %w", selector.Value, err)
	}
	normalizedEndpoint, err := normalizeListURL(endpoint)
	if err != nil {
		return Record{}, fmt.Errorf("custom list %q has invalid endpoint", selector.Value)
	}
	return Record{Selector: selector, SourceKind: listSourceKind, SourceName: selector.Value, Endpoint: normalizedEndpoint, APIVersion: listFormatVersion, Parameters: map[string]string{}, RetrievedAt: time.Now().UTC(), IPv4: normalized4, IPv6: normalized6}, nil
}

type envelope struct {
	Version      string          `json:"version"`
	DataCallName string          `json:"data_call_name"`
	DataCallStat string          `json:"data_call_status"`
	Status       string          `json:"status"`
	StatusCode   int             `json:"status_code"`
	Time         string          `json:"time"`
	Data         json.RawMessage `json:"data"`
}

func decodeEnvelope(body []byte, version, call string) (envelope, error) {
	validator := json.NewDecoder(bytes.NewReader(body))
	if err := validateResponseValue(validator); err != nil {
		return envelope{}, fmt.Errorf("invalid response JSON: %w", err)
	}
	if err := ensureCanonicalEOF(validator); err != nil {
		return envelope{}, err
	}
	var value envelope
	decoder := json.NewDecoder(bytes.NewReader(body))
	if err := decoder.Decode(&value); err != nil {
		return envelope{}, fmt.Errorf("decode JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return envelope{}, errors.New("response contains trailing JSON")
		}
		return envelope{}, fmt.Errorf("decode trailing JSON: %w", err)
	}
	if value.Version != version {
		return envelope{}, fmt.Errorf("%s API version %q, want %q", call, value.Version, version)
	}
	if value.DataCallName != call {
		return envelope{}, fmt.Errorf("RIPEstat endpoint identity %q, want %q", value.DataCallName, call)
	}
	if value.DataCallStat != "supported" {
		return envelope{}, fmt.Errorf("RIPEstat endpoint status %q", value.DataCallStat)
	}
	if value.Status != "ok" || value.StatusCode != http.StatusOK {
		return envelope{}, fmt.Errorf("RIPEstat API status %q/%d", value.Status, value.StatusCode)
	}
	if _, err := parseRipeTime(value.Time); err != nil {
		return envelope{}, fmt.Errorf("invalid response time: %w", err)
	}
	if len(value.Data) == 0 || bytes.Equal(bytes.TrimSpace(value.Data), []byte("null")) {
		return envelope{}, errors.New("response data is missing")
	}
	return value, nil
}

type countryData struct {
	Resource  json.RawMessage `json:"resource"`
	QueryTime string          `json:"query_time"`
	Resources *struct {
		IPv4 *[]string `json:"ipv4"`
		IPv6 *[]string `json:"ipv6"`
	} `json:"resources"`
}

func parseCountry(body []byte, endpoint string, params map[string]string, selector policy.Selector) (Record, error) {
	envelope, err := decodeEnvelope(body, endpointVersions[countryEndpoint], "country-resource-list")
	if err != nil {
		return Record{}, err
	}
	var data countryData
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		return Record{}, fmt.Errorf("country data: %w", err)
	}
	if len(data.Resource) != 0 {
		var echoed string
		if err := json.Unmarshal(data.Resource, &echoed); err != nil {
			return Record{}, errors.New("country data.resource must be a string")
		}
		if strings.ToUpper(echoed) != selector.Value {
			return Record{}, fmt.Errorf("country resource echo %q does not match %q", echoed, selector.Value)
		}
	}
	if data.Resources == nil || data.Resources.IPv4 == nil || data.Resources.IPv6 == nil {
		return Record{}, errors.New("country resources must contain ipv4 and ipv6 arrays")
	}
	queryTime, err := parseRipeTime(data.QueryTime)
	if err != nil {
		return Record{}, fmt.Errorf("country query_time: %w", err)
	}
	ipv4, err := normalizeStrings(*data.Resources.IPv4, true)
	if err != nil {
		return Record{}, fmt.Errorf("country IPv4: %w", err)
	}
	ipv6, err := normalizeStrings(*data.Resources.IPv6, false)
	if err != nil {
		return Record{}, fmt.Errorf("country IPv6: %w", err)
	}
	return Record{Selector: selector, Endpoint: endpoint, APIVersion: envelope.Version, Parameters: params, QueryStart: queryTime, QueryEnd: queryTime, RetrievedAt: time.Now().UTC(), IPv4: ipv4, IPv6: ipv6}, nil
}

type asnData struct {
	Resource       json.RawMessage `json:"resource"`
	Prefixes       *[]asnPrefix    `json:"prefixes"`
	QueryStartTime string          `json:"query_starttime"`
	QueryEndTime   string          `json:"query_endtime"`
}

type asnPrefix struct {
	Prefix    string         `json:"prefix"`
	Timelines *[]asnTimeline `json:"timelines"`
}

type asnTimeline struct {
	StartTime string `json:"starttime"`
	EndTime   string `json:"endtime"`
}

func parseASN(body []byte, endpoint string, params map[string]string, selector policy.Selector) (Record, error) {
	envelope, err := decodeEnvelope(body, endpointVersions[asnEndpoint], "announced-prefixes")
	if err != nil {
		return Record{}, err
	}
	var data asnData
	if err := json.Unmarshal(envelope.Data, &data); err != nil {
		return Record{}, fmt.Errorf("ASN data: %w", err)
	}
	var echoed string
	if err := json.Unmarshal(data.Resource, &echoed); err != nil {
		return Record{}, errors.New("ASN data.resource must be a string")
	}
	want := selector.Value[2:]
	normalized, valid := normalizeASN(echoed)
	if !valid || normalized != want {
		return Record{}, fmt.Errorf("ASN resource echo %q does not match %q", echoed, want)
	}
	if data.Prefixes == nil {
		return Record{}, errors.New("ASN prefixes array is missing")
	}
	queryStart, err := parseRipeTime(data.QueryStartTime)
	if err != nil {
		return Record{}, fmt.Errorf("ASN query_starttime: %w", err)
	}
	queryEnd, err := parseRipeTime(data.QueryEndTime)
	if err != nil {
		return Record{}, fmt.Errorf("ASN query_endtime: %w", err)
	}
	if queryEnd.Before(queryStart) {
		return Record{}, errors.New("ASN query_endtime precedes query_starttime")
	}
	v4 := make([]netip.Prefix, 0, len(*data.Prefixes))
	v6 := make([]netip.Prefix, 0, len(*data.Prefixes))
	for i, item := range *data.Prefixes {
		parsed, err := netip.ParsePrefix(item.Prefix)
		if err != nil {
			return Record{}, fmt.Errorf("ASN prefix %d: %w", i, err)
		}
		if item.Timelines == nil {
			return Record{}, fmt.Errorf("ASN prefix %d timelines array is missing", i)
		}
		visible := false
		for j, timeline := range *item.Timelines {
			start, err := parseRipeTime(timeline.StartTime)
			if err != nil {
				return Record{}, fmt.Errorf("ASN prefix %d timeline %d starttime: %w", i, j, err)
			}
			end, err := parseRipeTime(timeline.EndTime)
			if err != nil {
				return Record{}, fmt.Errorf("ASN prefix %d timeline %d endtime: %w", i, j, err)
			}
			if end.Before(start) {
				return Record{}, fmt.Errorf("ASN prefix %d timeline %d ends before it starts", i, j)
			}
			if !start.After(queryEnd) && !end.Before(queryEnd) {
				visible = true
			}
		}
		if !visible {
			continue
		}
		if parsed.Addr().Is4() {
			v4 = append(v4, parsed)
		} else if parsed.Addr().Is6() {
			v6 = append(v6, parsed)
		} else {
			return Record{}, fmt.Errorf("ASN prefix %d has unsupported family", i)
		}
	}
	ipv4, err := normalizeFamily(v4, true)
	if err != nil {
		return Record{}, fmt.Errorf("ASN IPv4: %w", err)
	}
	ipv6, err := normalizeFamily(v6, false)
	if err != nil {
		return Record{}, fmt.Errorf("ASN IPv6: %w", err)
	}
	return Record{Selector: selector, Endpoint: endpoint, APIVersion: envelope.Version, Parameters: params, QueryStart: queryStart, QueryEnd: queryEnd, RetrievedAt: time.Now().UTC(), IPv4: ipv4, IPv6: ipv6}, nil
}

func normalizeStrings(values []string, ipv4 bool) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for i, value := range values {
		parsed, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("prefix %d %q: %w", i, value, err)
		}
		if parsed.Addr().Is4() != ipv4 {
			return nil, fmt.Errorf("prefix %d %q has wrong address family", i, value)
		}
		prefixes = append(prefixes, parsed)
	}
	return normalizeFamily(prefixes, ipv4)
}

func normalizeASN(value string) (string, bool) {
	digits := strings.TrimPrefix(strings.ToUpper(value), "AS")
	if digits == "" {
		return "", false
	}
	for _, digit := range digits {
		if digit < '0' || digit > '9' {
			return "", false
		}
	}
	number, err := strconv.ParseUint(digits, 10, 32)
	return strconv.FormatUint(number, 10), err == nil
}

func parseRipeTime(value string) (time.Time, error) {
	if value == "" {
		return time.Time{}, errors.New("time is empty")
	}
	for _, layout := range []string{time.RFC3339Nano, "2006-01-02T15:04:05.999999", "2006-01-02T15:04:05"} {
		if parsed, err := time.Parse(layout, value); err == nil {
			return parsed.UTC(), nil
		}
	}
	return time.Time{}, fmt.Errorf("unsupported timestamp %q", value)
}

// Validate every JSON value without allocating a second copy of prefix arrays.
// Fields equivalent under encoding/json's case-folding rules are ambiguous,
// even when the typed decoder would pick the last one. Other metadata is allowed.
func validateResponseValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		keys := make(map[string]struct{})
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return err
			}
			name, ok := key.(string)
			if !ok {
				return errors.New("invalid object key")
			}
			name = foldResponseKey(name)
			if _, exists := keys[name]; exists {
				return fmt.Errorf("duplicate field %q", name)
			}
			keys[name] = struct{}{}
			if err := validateResponseValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("unterminated object")
		}
	case json.Delim('['):
		for decoder.More() {
			if err := validateResponseValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("unterminated array")
		}
	}
	return nil
}

// foldResponseKey gives EqualFold-equivalent keys the same spelling, including
// non-ASCII aliases such as long s. Already-lowercase ASCII keys reuse their
// original strings rather than allocating another copy.
func foldResponseKey(name string) string {
	return strings.Map(func(r rune) rune {
		if r > unicode.MaxASCII {
			for {
				next := unicode.SimpleFold(r)
				if next <= r {
					r = next
					break
				}
				r = next
			}
		}
		if 'A' <= r && r <= 'Z' {
			return r + ('a' - 'A')
		}
		return r
	}, name)
}
