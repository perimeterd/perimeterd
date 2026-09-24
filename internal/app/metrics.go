package app

import (
	"context"
	"net/netip"
	"sort"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/firewall"
	metricspkg "github.com/perimeterd/perimeterd/internal/metrics"
	"github.com/perimeterd/perimeterd/internal/policy"
)

type nativeCounterTelemetry interface {
	SnapshotCounters(context.Context, *firewall.Target) (map[string]firewall.CounterSnapshot, error)
	SetCounterRetirementHook(firewall.CounterRetirementHook)
}

func (e *Engine) supportsNativeCounterTelemetry() bool {
	if e == nil {
		return false
	}
	_, ok := e.backend.(nativeCounterTelemetry)
	return ok
}

var builtinLocalPrefixes = config.BuiltinLocalRanges()

func prefixCounts(candidate Candidate) []metricspkg.PrefixCount {
	type key struct{ family, source, kind string }
	type prefixEntry struct {
		family, source, kind string
		prefix               netip.Prefix
	}
	counts := make(map[key]float64)
	seen := make(map[prefixEntry]struct{})
	add := func(prefix netip.Prefix, source, kind string) {
		if !prefix.IsValid() {
			return
		}
		prefix = prefix.Masked()
		family := "ipv6"
		if prefix.Addr().Is4() {
			family = "ipv4"
		}
		if (family == "ipv4" && !candidate.cfg.Firewall.IPv4) || (family == "ipv6" && !candidate.cfg.Firewall.IPv6) {
			return
		}
		identity := prefixEntry{family: family, source: source, kind: kind, prefix: prefix}
		if _, exists := seen[identity]; exists {
			return
		}
		seen[identity] = struct{}{}
		counts[key{family: family, source: source, kind: kind}]++
	}
	for _, prefix := range builtinLocalPrefixes {
		add(prefix, "local", "local")
	}
	for _, prefix := range candidate.cfg.Global.Allowlist {
		if _, local := localPrefixSet[prefix]; !local {
			add(prefix, "global", "allowlist")
		}
	}
	for _, prefix := range candidate.cfg.Global.Blocklist {
		add(prefix, "global", "blocklist")
	}
	for _, record := range candidate.snapshot.Records() {
		source, kind := selectorMetricLabels(record.Selector.Kind)
		for _, prefix := range record.IPv4 {
			add(prefix, source, kind)
		}
		for _, prefix := range record.IPv6 {
			add(prefix, source, kind)
		}
	}
	result := make([]metricspkg.PrefixCount, 0, len(counts))
	for key, count := range counts {
		result = append(result, metricspkg.PrefixCount{Family: key.family, Source: key.source, Type: key.kind, Count: count})
	}
	sort.Slice(result, func(i, j int) bool {
		if result[i].Family != result[j].Family {
			return result[i].Family < result[j].Family
		}
		if result[i].Source != result[j].Source {
			return result[i].Source < result[j].Source
		}
		return result[i].Type < result[j].Type
	})
	return result
}

var localPrefixSet = func() map[netip.Prefix]struct{} {
	values := make(map[netip.Prefix]struct{}, len(builtinLocalPrefixes))
	for _, value := range builtinLocalPrefixes {
		values[value] = struct{}{}
	}
	return values
}()

func selectorMetricLabels(kind policy.SelectorKind) (source, valueType string) {
	switch kind {
	case policy.Country:
		return "ripestat", "country"
	case policy.ASN:
		return "ripestat", "asn"
	case policy.IPList:
		return "ip_list", "ip_list"
	case policy.Provider:
		return "provider", "provider"
	default:
		return "", ""
	}
}

func firewallFamily(value policy.Family) string {
	switch value {
	case policy.IPv4:
		return "ipv4"
	case policy.IPv6:
		return "ipv6"
	default:
		return "unknown"
	}
}

func currentCounterSamples(target *firewall.Target, values map[string]firewall.CounterSnapshot) []metricspkg.CounterSample {
	if target == nil {
		return nil
	}
	samples := make([]metricspkg.CounterSample, 0, len(values))
	for _, value := range values {
		backend := value.Backend
		if backend == "" {
			backend = target.Backend()
		}
		samples = append(samples, metricspkg.CounterSample{
			Backend:          backend,
			Generation:       value.Generation,
			Rule:             value.Rule,
			Family:           firewallFamily(value.Family),
			Direction:        string(value.Direction),
			Reason:           string(value.Reason),
			Action:           string(value.Action),
			ProcessedPackets: value.ProcessedPackets,
			ProcessedBytes:   value.ProcessedBytes,
			DeniedPackets:    value.DeniedPackets,
			DeniedBytes:      value.DeniedBytes,
			Current:          value.Generation == target.Generation,
		})
	}
	return samples
}

func retiredCounterSamples(values []firewall.CounterSnapshot) []metricspkg.CounterSample {
	samples := make([]metricspkg.CounterSample, 0, len(values))
	for _, value := range values {
		if value.Rule == "" {
			continue
		}
		samples = append(samples, metricspkg.CounterSample{
			Backend:          value.Backend,
			Generation:       value.Generation,
			Rule:             value.Rule,
			Family:           firewallFamily(value.Family),
			Direction:        string(value.Direction),
			Reason:           string(value.Reason),
			Action:           string(value.Action),
			ProcessedPackets: value.ProcessedPackets,
			ProcessedBytes:   value.ProcessedBytes,
			DeniedPackets:    value.DeniedPackets,
			DeniedBytes:      value.DeniedBytes,
		})
	}
	return samples
}

func retiredCounterBackend(values []firewall.CounterSnapshot) string {
	for _, value := range values {
		if value.Backend != "" {
			return value.Backend
		}
	}
	return "unknown"
}

func (e *Engine) enableCounterTelemetry(ctx context.Context) {
	if ctx == nil {
		ctx = context.Background()
	}
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.telemetry == nil {
		return
	}
	backend, ok := e.backend.(nativeCounterTelemetry)
	if !ok {
		return
	}
	e.counterTelemetryEnabled = true
	e.telemetry.BeginCounterCollection()
	backend.SetCounterRetirementHook(func(values []firewall.CounterSnapshot, err error) {
		kind := retiredCounterBackend(values)
		if err != nil {
			e.telemetry.CounterReadFailed(kind)
			return
		}
		e.telemetry.CounterRetired(kind, retiredCounterSamples(values), time.Now())
	})
	e.sampleNativeCountersLocked(ctx)
}

func (e *Engine) disableCounterTelemetry() {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.counterTelemetryEnabled = false
	if backend, ok := e.backend.(nativeCounterTelemetry); ok {
		backend.SetCounterRetirementHook(nil)
	}
}

func (e *Engine) sampleNativeCounters(ctx context.Context) {
	e.applyMu.Lock()
	defer e.applyMu.Unlock()
	e.mu.Lock()
	defer e.mu.Unlock()
	e.sampleNativeCountersLocked(ctx)
}

func (e *Engine) sampleNativeCountersLocked(ctx context.Context) {
	if !e.counterTelemetryEnabled || e.telemetry == nil {
		return
	}
	view, err := e.store.Read()
	if err != nil {
		e.telemetry.CounterReadFailed("unknown")
		return
	}
	// Pending recovery may still own objects outside the selected target. A
	// partial snapshot would discard their baselines before retirement retries.
	if view.Journal != nil || view.Active == nil || view.Active.Target == nil {
		return
	}
	e.observeNativeCountersLocked(ctx, view.Active.Target)
}

func (e *Engine) observeNativeCountersLocked(ctx context.Context, target *firewall.Target) {
	if !e.counterTelemetryEnabled || e.telemetry == nil || target == nil {
		return
	}
	backend, ok := e.backend.(nativeCounterTelemetry)
	if !ok {
		return
	}
	values, err := backend.SnapshotCounters(ctx, target)
	if err != nil {
		e.telemetry.CounterReadFailed(target.Backend())
		return
	}
	samples := currentCounterSamples(target, values)
	at := time.Now()
	e.telemetry.CounterSnapshot(target.Backend(), samples, at)
}
