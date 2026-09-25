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
	"github.com/perimeterd/perimeterd/internal/upstream"
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
	expectedBindings := make(map[policy.Selector]upstream.Binding)
	for _, selector := range required {
		if selector.Kind != policy.IPList {
			continue
		}
		spec, specErr := DescribeSelector(cfg, selector)
		if specErr != nil {
			return Resolution{}, specErr
		}
		binding, bindingErr := r.bindingForRoute(spec.Transport)
		if bindingErr != nil {
			return Resolution{}, fmt.Errorf("source: custom list %q transport: %w", selector.Value, bindingErr)
		}
		expectedBindings[selector] = binding
	}
	committedBySelector := recordsBySelector(committed.Records())
	committedCovers := true
	for _, selector := range required {
		record, ok := committedBySelector[selector]
		if !ok || !recordMatchesResolved(record, cfg, expectedBindings) {
			committedCovers = false
			break
		}
	}

	candidate := make(map[policy.Selector]Record, len(required))
	stale := make([]policy.Selector, 0, len(required))
	for _, selector := range required {
		record, ok := committedBySelector[selector]
		if !ok || !recordMatchesResolved(record, cfg, expectedBindings) {
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
	var refreshInterval, requestTimeout time.Duration
	switch selector.Kind {
	case policy.IPList:
		list, ok := cfg.IPLists[selector.Value]
		if !ok {
			return 0, 0, fmt.Errorf("source: custom list %q is not configured", selector.Value)
		}
		refreshInterval, requestTimeout = list.RefreshInterval, list.RequestTimeout
	case policy.Provider:
		refreshInterval, requestTimeout = cfg.Providers.RefreshInterval, cfg.Providers.RequestTimeout
	default:
		refreshInterval, requestTimeout = cfg.Geo.RefreshInterval, cfg.Geo.RequestTimeout
	}
	if err := validateSelectorTiming(selector, refreshInterval, requestTimeout); err != nil {
		return 0, 0, err
	}
	spec, err := DescribeSelector(cfg, selector)
	if err != nil {
		return 0, 0, err
	}
	return spec.RefreshInterval, spec.RequestTimeout, nil
}

func validSelectorTiming(selector policy.Selector, spec SelectorSpec) error {
	return validateSelectorTiming(selector, spec.RefreshInterval, spec.RequestTimeout)
}

func validateSelectorTiming(selector policy.Selector, refreshInterval, requestTimeout time.Duration) error {
	if refreshInterval > 0 && requestTimeout > 0 {
		return nil
	}
	switch selector.Kind {
	case policy.IPList:
		return fmt.Errorf("source: custom list %q has invalid timing", selector.Value)
	case policy.Provider:
		return errors.New("source: provider refresh interval and request timeout must be positive")
	default:
		return errors.New("source: refresh interval and request timeout must be positive")
	}
}

func recordMatchesConfig(record Record, cfg config.Config) bool {
	spec, err := DescribeSelector(cfg, record.Selector)
	if err != nil {
		return false
	}
	switch record.Selector.Kind {
	case policy.IPList:
		return record.SourceKind == spec.SourceKind &&
			record.SourceName == spec.SourceName &&
			record.Endpoint == spec.Endpoint &&
			record.APIVersion == spec.APIVersion &&
			bindingMatchesConfig(record.Transport, spec.Transport)
	case policy.Provider:
		return record.SourceKind == spec.SourceKind &&
			record.SourceName == spec.SourceName &&
			record.Endpoint == spec.Endpoint &&
			record.APIVersion == spec.APIVersion &&
			isDirectBinding(record.Transport)
	case policy.Country, policy.ASN:
		if record.SourceKind != "" && record.SourceKind != spec.SourceKind {
			return false
		}
		return record.Endpoint == spec.Endpoint && record.APIVersion == spec.APIVersion && isDirectBinding(record.Transport)
	default:
		return false
	}
}

func recordMatchesResolved(record Record, cfg config.Config, expected map[policy.Selector]upstream.Binding) bool {
	if !recordMatchesConfig(record, cfg) {
		return false
	}
	if record.Selector.Kind != policy.IPList {
		return true
	}
	binding, ok := expected[record.Selector]
	return ok && record.Transport == binding
}

func isDirectBinding(binding upstream.Binding) bool {
	return binding.Type == "" || binding.Type == upstream.TypeDirect
}

func bindingMatchesConfig(binding upstream.Binding, route config.TransportConfig) bool {
	if route.Type == "" || route.Type == upstream.TypeDirect {
		direct := upstream.Binding{Type: upstream.TypeDirect}
		return isDirectBinding(binding) && direct.MatchesConfig(route)
	}
	return binding.MatchesConfig(route)
}

type (
	listOriginMarker  struct{}
	listRequestMarker struct{}
)

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

func markListOrigin(ctx context.Context, value *url.URL) context.Context {
	if value == nil {
		return ctx
	}
	origin := url.URL{Scheme: value.Scheme, Host: value.Host}
	return context.WithValue(ctx, listOriginMarker{}, origin.String())
}

func sameURLOrigin(a, b *url.URL) bool {
	if a == nil || b == nil {
		return false
	}
	if !strings.EqualFold(a.Scheme, b.Scheme) {
		return false
	}
	hostA, hostB := strings.ToLower(a.Hostname()), strings.ToLower(b.Hostname())
	if hostA != hostB {
		return false
	}
	portA, portB := a.Port(), b.Port()
	if portA == "" {
		portA = defaultOriginPort(a.Scheme)
	}
	if portB == "" {
		portB = defaultOriginPort(b.Scheme)
	}
	return portA == portB
}

func defaultOriginPort(scheme string) string {
	if strings.EqualFold(scheme, "https") {
		return "443"
	}
	return "80"
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
	case strings.Contains(message, "origin changed"):
		return errors.New("redirect origin changed")
	case strings.Contains(message, "too many redirects"):
		return errors.New("too many redirects")
	case strings.Contains(message, "certificate"), strings.Contains(message, "tls"):
		return errors.New("TLS verification failed")
	default:
		return errors.New("request failed")
	}
}

type idleConnectionCloser interface {
	CloseIdleConnections()
}

func closeIdleConnections(transport http.RoundTripper) {
	if closer, ok := transport.(idleConnectionCloser); ok {
		closer.CloseIdleConnections()
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
	requestSource := selectorMetricSource(selector.Kind)
	success := false
	if r.observeRequest != nil {
		defer func() { r.observeRequest(requestSource, success) }()
	}
	spec, err := DescribeSelector(cfg, selector)
	if err != nil {
		return Record{}, err
	}
	if err := validSelectorTiming(selector, spec); err != nil {
		return Record{}, err
	}
	timeout := spec.RequestTimeout
	ctx, cancel := context.WithTimeout(parent, timeout)
	defer cancel()
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	case <-ctx.Done():
		return Record{}, ctx.Err()
	}

	text := selector.Kind == policy.IPList || selector.Kind == policy.Provider
	endpoint := spec.Endpoint
	sourceLabel := ""
	var values url.Values
	var requestDescription ripeRequestDescription
	route := spec.Transport
	var binding upstream.Binding
	switch selector.Kind {
	case policy.IPList:
		sourceLabel = fmt.Sprintf("custom list %q", selector.Value)
		binding, err = r.bindingForRoute(route)
		if err != nil {
			return Record{}, fmt.Errorf("custom list %q transport: %w", selector.Value, err)
		}
	case policy.Provider:
		sourceLabel = fmt.Sprintf("provider %q", selector.Value)
	case policy.Country, policy.ASN:
		requestDescription, err = ripeRequestFor(selector)
		if err != nil {
			return Record{}, err
		}
		endpoint = requestDescription.endpoint
		values = make(url.Values, len(requestDescription.parameters))
		for key, value := range requestDescription.parameters {
			values.Set(key, value)
		}
	default:
		return Record{}, fmt.Errorf("unsupported source selector kind %q", selector.Kind)
	}
	u, err := url.Parse(endpoint)
	if err != nil {
		if text {
			return Record{}, fmt.Errorf("%s has invalid URL", sourceLabel)
		}
		return Record{}, err
	}
	client := r.client
	if text {
		ctx = markListRequest(ctx)
		if selector.Kind == policy.IPList && route.Type == upstream.TypeOpenZiti {
			ctx = markListOrigin(ctx, u)
			transport, transportErr := r.session.Transport(route, endpoint)
			if transportErr != nil {
				return Record{}, fmt.Errorf("%s transport: %w", sourceLabel, transportErr)
			}
			defer closeIdleConnections(transport)
			owned := *r.client
			owned.Transport = transport
			client = &owned
		}
	} else {
		u.RawQuery = values.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		if text {
			return Record{}, fmt.Errorf("%s: create request failed", sourceLabel)
		}
		return Record{}, fmt.Errorf("create request: %w", err)
	}
	if text {
		req.Header.Set("Accept", "text/plain")
	} else {
		req.Header.Set("Accept", "application/json")
	}
	resp, err := client.Do(req)
	if err != nil {
		if text {
			requestErr := classifyListRequestError(err)
			if selector.Kind == policy.Provider {
				return Record{}, fmt.Errorf("%s request: %w", sourceLabel, requestErr)
			}
			return Record{}, requestErr
		}
		return Record{}, fmt.Errorf("request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if text {
		if resp.StatusCode != http.StatusOK {
			if selector.Kind == policy.Provider {
				return Record{}, fmt.Errorf("%s: HTTP status %d", sourceLabel, resp.StatusCode)
			}
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
	var record Record
	if text {
		record, err = parseTextList(body, endpoint, selector)
	} else if selector.Kind == policy.Country {
		record, err = parseCountry(body, endpoint, requestDescription.apiVersion, requestDescription.parameters, selector)
	} else {
		record, err = parseASN(body, endpoint, requestDescription.apiVersion, requestDescription.parameters, selector)
	}
	if err != nil {
		return Record{}, err
	}
	record.Transport = binding
	success = true
	return record, nil
}

func selectorMetricSource(kind policy.SelectorKind) string {
	switch kind {
	case policy.Country, policy.ASN:
		return ripeSourceKind
	case policy.IPList:
		return listSourceKind
	case policy.Provider:
		return providerSourceKind
	default:
		return "unknown"
	}
}

func parseList(body []byte, endpoint string, selector policy.Selector) (Record, error) {
	return parseTextList(body, endpoint, selector)
}

func parseTextList(body []byte, endpoint string, selector policy.Selector) (Record, error) {
	sourceKind := listSourceKind
	sourceLabel := "custom list"
	if selector.Kind == policy.Provider {
		sourceKind = providerSourceKind
		sourceLabel = "provider"
	}
	description := fmt.Sprintf("%s %q", sourceLabel, selector.Value)
	if !utf8.Valid(body) {
		return Record{}, fmt.Errorf("%s line data is not valid UTF-8", description)
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
				return Record{}, fmt.Errorf("%s line %d is not one IP address or CIDR", description, lineNumber)
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
			return Record{}, fmt.Errorf("%s line %d contains an unsupported address", description, lineNumber)
		}
	}
	if !found {
		return Record{}, fmt.Errorf("%s is empty", description)
	}
	normalized4, err := normalizeFamily(ipv4, true)
	if err != nil {
		return Record{}, fmt.Errorf("%s IPv4: %w", description, err)
	}
	normalized6, err := normalizeFamily(ipv6, false)
	if err != nil {
		return Record{}, fmt.Errorf("%s IPv6: %w", description, err)
	}
	normalizedEndpoint, err := normalizeListURL(endpoint)
	if err != nil {
		return Record{}, fmt.Errorf("%s has invalid endpoint", description)
	}
	return Record{
		Selector: selector, SourceKind: sourceKind, SourceName: selector.Value,
		Endpoint: normalizedEndpoint, APIVersion: listFormatVersion,
		Parameters: map[string]string{}, RetrievedAt: time.Now().UTC(),
		IPv4: normalized4, IPv6: normalized6,
	}, nil
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

func parseCountry(body []byte, endpoint, apiVersion string, params map[string]string, selector policy.Selector) (Record, error) {
	envelope, err := decodeEnvelope(body, apiVersion, "country-resource-list")
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

func parseASN(body []byte, endpoint, apiVersion string, params map[string]string, selector policy.Selector) (Record, error) {
	envelope, err := decodeEnvelope(body, apiVersion, "announced-prefixes")
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
