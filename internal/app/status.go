package app

import (
	"context"
	"errors"
	"math"
	"slices"
	"sort"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/control"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/lookup"
	"github.com/perimeterd/perimeterd/internal/policy"
)

// Status reads the same acknowledgement-fenced view as Lookup. It performs no
// native, source, credential or durable-store work and never takes writer locks.
func (e *Engine) Status(ctx context.Context) control.StatusResult {
	if ctx == nil {
		ctx = context.Background()
	}
	now := time.Now()
	result := control.StatusResult{
		SchemaVersion: control.StatusSchemaVersion, ObservedAt: now.UTC(),
		Daemon:  control.StatusDaemon{Version: e.version, Healthy: e.Healthy() && e.runtimeHealthy.Load()},
		Applied: control.StatusApplied{State: "unavailable", Reason: "no coherent applied view is available"},
	}
	if elapsed := now.Sub(e.startedAt); elapsed > 0 {
		result.Daemon.UptimeSeconds = uint64(elapsed / time.Second)
	}
	if e.closing.Load() {
		result.Daemon.Healthy = false
		result.Applied.Reason = "perimeterd is shutting down"
		return result
	}
	if err := ctx.Err(); err != nil {
		result.Applied.Reason = err.Error()
		return result
	}
	view := e.queryView.Load()
	version := e.queryVersion.Load()
	if view == nil || view.token != version {
		return result
	}
	applied := control.StatusApplied{State: "empty"}
	if view.status != nil {
		details := cloneStatusDetails(view.status)
		details.CrowdSec = statusCrowdSec(ctx, details, view.dynamic, now)
		applied = control.StatusApplied{State: "applied", Revision: view.revision, ConfigEpoch: view.configEpoch, Manifest: view.manifest, Details: details}
	}
	if err := ctx.Err(); err != nil {
		result.Applied.Reason = err.Error()
		return result
	}
	if e.closing.Load() || e.queryVersion.Load() != version || e.queryView.Load() != view {
		result.Applied.Reason = "applied state changed during status evaluation"
		return result
	}
	result.Applied = applied
	result.Daemon.Healthy = e.Healthy() && e.runtimeHealthy.Load()
	return result
}

func buildStatusDetails(candidate Candidate, target *firewall.Target) (*control.StatusDetails, error) {
	if target == nil {
		return nil, nil
	}
	cfg := candidate.cfg
	setCapacity := 0
	for _, family := range target.Families {
		setCapacity += len(family.Sets)
	}
	details := &control.StatusDetails{
		Firewall:     control.StatusFirewall{Backend: target.Backend(), DenyAction: cfg.Firewall.DenyAction, Families: make([]string, 0, len(target.Families))},
		Policies:     make([]control.StatusPolicy, 0, len(cfg.Policies)),
		PrefixCounts: make([]control.StatusPrefixCount, 0, len(candidate.prefixes)),
		CompiledSets: control.StatusCompiledSets{
			Sets:   make([]control.StatusCompiledSet, 0, setCapacity),
			Totals: make([]control.StatusCompiledTotal, 0, len(target.Families)),
		},
		CrowdSec: control.StatusCrowdSec{Enabled: cfg.CrowdSec.Enabled, Validity: "disabled"},
	}
	for _, family := range target.Families {
		name := firewallFamily(family.Family)
		details.Firewall.Families = append(details.Firewall.Families, name)
		var total uint64
		for _, set := range family.Sets {
			if set.Kind != policy.StaticSet {
				continue
			}
			count := uint64(len(set.Prefixes))
			if count > math.MaxUint64-total {
				return nil, errors.New("compiled firewall set memberships overflow")
			}
			details.CompiledSets.Sets = append(details.CompiledSets.Sets, control.StatusCompiledSet{Family: name, ID: set.ID, Count: count})
			total += count
		}
		details.CompiledSets.Totals = append(details.CompiledSets.Totals, control.StatusCompiledTotal{Family: name, Count: total})
	}
	sort.Strings(details.Firewall.Families)
	sort.Slice(details.CompiledSets.Sets, func(i, j int) bool {
		a, b := details.CompiledSets.Sets[i], details.CompiledSets.Sets[j]
		if a.Family != b.Family {
			return a.Family < b.Family
		}
		return a.ID < b.ID
	})
	sort.Slice(details.CompiledSets.Totals, func(i, j int) bool {
		return details.CompiledSets.Totals[i].Family < details.CompiledSets.Totals[j].Family
	})
	if target.IPTables != nil {
		for _, attachment := range target.IPTables.Attachments {
			details.Firewall.Attachments = append(details.Firewall.Attachments, control.StatusAttachment{
				Chain: attachment.Chain, Direction: attachment.Direction,
				InputInterfaces: slices.Clone(attachment.InputInterfaces), OutputInterfaces: slices.Clone(attachment.OutputInterfaces),
				OriginalDestination: attachment.OriginalDestination,
			})
		}
	}
	for _, p := range cfg.Policies {
		details.Policies = append(details.Policies, control.StatusPolicy{
			Name: p.Name, Priority: p.Priority, Direction: p.Direction, Mode: p.Mode,
			Traffic: control.StatusTraffic{Any: p.Traffic.Any, TCP: statusPorts(p.Traffic.TCP), UDP: statusPorts(p.Traffic.UDP), ICMP: p.Traffic.ICMP, ICMPv6: p.Traffic.ICMPv6},
		})
	}
	sort.Slice(details.Policies, func(i, j int) bool {
		a, b := details.Policies[i], details.Policies[j]
		if a.Direction != b.Direction {
			return a.Direction < b.Direction
		}
		if a.Priority != b.Priority {
			return a.Priority < b.Priority
		}
		return a.Name < b.Name
	})
	for _, count := range candidate.prefixes {
		details.PrefixCounts = append(details.PrefixCounts, control.StatusPrefixCount{Family: count.Family, Source: count.Source, Type: count.Type, Count: uint64(count.Count)})
	}
	return details, nil
}

func statusPorts(ports []config.PortRange) []control.StatusPortRange {
	if len(ports) == 0 {
		return nil
	}
	result := make([]control.StatusPortRange, len(ports))
	for i, p := range ports {
		result[i] = control.StatusPortRange{Start: p.Start, End: p.End}
	}
	return result
}

// Returned metadata is owned by the caller; mutating it cannot corrupt the
// published snapshot used by concurrent queries.
func cloneStatusDetails(value *control.StatusDetails) *control.StatusDetails {
	result := *value
	result.Firewall.Families = slices.Clone(value.Firewall.Families)
	result.Firewall.Attachments = slices.Clone(value.Firewall.Attachments)
	for i := range result.Firewall.Attachments {
		result.Firewall.Attachments[i].InputInterfaces = slices.Clone(value.Firewall.Attachments[i].InputInterfaces)
		result.Firewall.Attachments[i].OutputInterfaces = slices.Clone(value.Firewall.Attachments[i].OutputInterfaces)
	}
	result.Policies = slices.Clone(value.Policies)
	for i := range result.Policies {
		result.Policies[i].Traffic.TCP = slices.Clone(value.Policies[i].Traffic.TCP)
		result.Policies[i].Traffic.UDP = slices.Clone(value.Policies[i].Traffic.UDP)
	}
	result.PrefixCounts = slices.Clone(value.PrefixCounts)
	result.CompiledSets.Sets = slices.Clone(value.CompiledSets.Sets)
	result.CompiledSets.Totals = slices.Clone(value.CompiledSets.Totals)
	return &result
}

func statusCrowdSec(ctx context.Context, details *control.StatusDetails, dynamic lookup.Dynamic, now time.Time) control.StatusCrowdSec {
	result := control.StatusCrowdSec{Enabled: details.CrowdSec.Enabled, Validity: "disabled"}
	if !result.Enabled {
		return result
	}
	result.Validity = "unknown"
	if dynamic.Epoch == 0 || dynamic.Operation == 0 {
		return result
	}
	result.Epoch, result.Operation, result.ValidUntil = dynamic.Epoch, dynamic.Operation, dynamic.ValidUntil
	if !dynamic.ValidUntil.IsZero() && !dynamic.ValidUntil.After(now) {
		result.Validity = "stale"
		return result
	}
	counts := &control.StatusDecisionCounts{}
	ipv4 := slices.Contains(details.Firewall.Families, "ipv4")
	ipv6 := slices.Contains(details.Firewall.Families, "ipv6")
	for i, decision := range dynamic.Decisions {
		if i%256 == 0 && ctx.Err() != nil {
			return result
		}
		if !decision.Deadline.After(now) {
			continue
		}
		if decision.Prefix.Addr().Is4() {
			if ipv4 {
				counts.IPv4++
			}
		} else if ipv6 {
			counts.IPv6++
		}
	}
	result.Validity, result.Counts = "valid", counts
	return result
}
