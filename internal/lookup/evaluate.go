package lookup

import (
	"context"
	"fmt"
	"net/netip"
	"slices"
	"sort"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/crowdsec"
	"github.com/perimeterd/perimeterd/internal/policy"
)

type trafficScope struct {
	protocol string
	ports    *Ports
}

// Evaluate computes a complete, backend-neutral answer from immutable static
// state and acknowledged dynamic evidence. It performs no I/O and never emits
// a partial answer: cancellation, stale lease evidence, or a work limit yields
// an explicit unknown response.
func Evaluate(ctx context.Context, static *Static, dynamic Dynamic, request Request, now time.Time) Response {
	normalized, err := Normalize(request)
	if err != nil {
		return Unknown(request, "invalid_input", err.Error())
	}
	if now.IsZero() {
		now = time.Now()
	}
	if static == nil {
		return Unknown(normalized, "enforcement_unavailable", "lookup state is unavailable")
	}
	if err := validateDynamic(dynamic); err != nil {
		return Unknown(normalized, "enforcement_unavailable", err.Error())
	}
	if static.crowdsec && !dynamic.ValidUntil.IsZero() && !dynamic.ValidUntil.After(now) {
		return Unknown(normalized, "enforcement_unavailable", "acknowledged CrowdSec lease view has expired")
	}

	query, _ := netip.ParsePrefix(normalized.Address)
	family := policy.IPv6
	if query.Addr().Is4() {
		family = policy.IPv4
	}
	addresses, ok := partitionPrefixes(ctx, query, static.familyBoundaries(family), dynamic.Prefixes, dynamic.Decisions)
	if !ok {
		if err := contextErr(ctx); err != nil {
			return Unknown(normalized, "enforcement_unavailable", err.Error())
		}
		return Unknown(normalized, "limit_exceeded", "address partition exceeds lookup work limit")
	}
	scopes := trafficScopes(static, family, normalized)
	if len(scopes) == 0 {
		return Unknown(normalized, "invalid_input", "request has no traffic scope")
	}
	directions := []policy.Direction{policy.Ingress, policy.Egress}
	if normalized.Direction != "" {
		directions = []policy.Direction{normalized.Direction}
	}

	result := Response{SchemaVersion: SchemaVersion, Query: normalized, Flow: "new", ObservedAt: now}
	result.Manifest = static.manifest
	records := 0
	for _, address := range addresses {
		if err := contextErr(ctx); err != nil {
			return Unknown(normalized, "enforcement_unavailable", err.Error())
		}
		for _, direction := range directions {
			attachments := static.attachmentsFor(direction)
			for _, scope := range scopes {
				if err := contextErr(ctx); err != nil {
					return Unknown(normalized, "enforcement_unavailable", err.Error())
				}
				if len(attachments) == 0 {
					if records >= MaxRecords {
						return Unknown(normalized, "limit_exceeded", "lookup outcomes and evidence exceed the record limit")
					}
					result.Outcomes = append(result.Outcomes, makeNotManaged(address, direction, scope, "no managed attachment"))
					records++
					continue
				}
				plan, managedFamily := static.family(family)
				for _, attachment := range attachments {
					if !managedFamily {
						if records >= MaxRecords {
							return Unknown(normalized, "limit_exceeded", "lookup outcomes and evidence exceed the record limit")
						}
						result.Outcomes = append(result.Outcomes, makeNotManagedWith(address, direction, scope, attachment, "address family is not managed"))
						records++
						continue
					}
					if static.crowdsec && uncertainDynamic(dynamic, address, now) {
						return Unknown(normalized, "enforcement_unavailable", "acknowledged dynamic lease coverage is uncertain")
					}
					outcome := evaluateScope(ctx, static, plan, dynamic, address, direction, scope, attachment, now, MaxRecords-records-1)
					if outcome == nil {
						if err := contextErr(ctx); err != nil {
							return Unknown(normalized, "enforcement_unavailable", err.Error())
						}
						return Unknown(normalized, "limit_exceeded", "lookup outcomes and evidence exceed the record limit")
					}
					if records+1+len(outcome.Evidence) > MaxRecords {
						return Unknown(normalized, "limit_exceeded", "lookup outcomes and evidence exceed the record limit")
					}
					result.Outcomes = append(result.Outcomes, *outcome)
					records += 1 + len(outcome.Evidence)
				}
			}
		}
	}
	result.Outcomes = coalesceOutcomes(ctx, result.Outcomes)
	if err := contextErr(ctx); err != nil {
		return Unknown(normalized, "enforcement_unavailable", err.Error())
	}
	blocked, clear := false, false
	for _, outcome := range result.Outcomes {
		if outcome.Verdict == "blocked" {
			blocked = true
		} else {
			clear = true
		}
	}
	switch {
	case blocked && clear:
		result.Verdict = "mixed"
	case blocked:
		result.Verdict = "blocked"
	default:
		result.Verdict = "not_blocked"
	}
	return result
}

func contextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}

func validateDynamic(dynamic Dynamic) error {
	for _, value := range dynamic.Prefixes {
		if !validPrefix(value.Prefix) || value.Deadline.IsZero() {
			return fmt.Errorf("dynamic projection contains invalid prefix evidence")
		}
	}
	for _, value := range dynamic.Decisions {
		if value.ID <= 0 || !validPrefix(value.Prefix) || value.Deadline.IsZero() {
			return fmt.Errorf("dynamic decision evidence is invalid")
		}
	}
	return nil
}

func validPrefix(value netip.Prefix) bool {
	return value.IsValid() && value == value.Masked() && value.Addr().Zone() == ""
}

func sameFamily(value netip.Prefix, family policy.Family) bool {
	return family == policy.IPv4 && value.Addr().Is4() || family == policy.IPv6 && value.Addr().Is6()
}

func uncertainDynamic(dynamic Dynamic, address netip.Prefix, now time.Time) bool {
	for _, value := range dynamic.Prefixes {
		if value.Deadline.After(now) || !overlaps(value.Prefix, address) {
			continue
		}
		return true
	}
	for _, value := range dynamic.Decisions {
		if value.Deadline.After(now) || !overlaps(value.Prefix, address) {
			continue
		}
		return true
	}
	return false
}

func partitionPrefixes(ctx context.Context, query netip.Prefix, boundaries []netip.Prefix, timed []policy.TimedPrefix, decisions []crowdsec.Decision) ([]netip.Prefix, bool) {
	if contextErr(ctx) != nil {
		return nil, false
	}
	if query.Bits() == query.Addr().BitLen() {
		return []netip.Prefix{query}, true
	}
	start := sort.Search(len(boundaries), func(index int) bool {
		return boundaries[index].Addr().Compare(query.Addr()) >= 0
	})
	boundaries = boundaries[start:]
	end := sort.Search(len(boundaries), func(index int) bool {
		return !query.Contains(boundaries[index].Addr())
	})
	boundaries = boundaries[:end]
	if len(boundaries) > MaxRecords*8 {
		return nil, false
	}
	owned := false
	add := func(value netip.Prefix) bool {
		if contextErr(ctx) != nil {
			return false
		}
		if value.Bits() <= query.Bits() || !query.Contains(value.Addr()) {
			return true
		}
		if len(boundaries) >= MaxRecords*8 {
			return false
		}
		if !owned {
			boundaries = slices.Clone(boundaries)
			owned = true
		}
		boundaries = append(boundaries, value)
		return true
	}
	for _, value := range timed {
		if !add(value.Prefix) {
			return nil, false
		}
	}
	for _, value := range decisions {
		if !add(value.Prefix) {
			return nil, false
		}
	}
	if owned {
		sort.Slice(boundaries, func(i, j int) bool {
			if order := boundaries[i].Addr().Compare(boundaries[j].Addr()); order != 0 {
				return order < 0
			}
			return boundaries[i].Bits() < boundaries[j].Bits()
		})
		boundaries = slices.Compact(boundaries)
	}
	work := []netip.Prefix{query}
	for index := 0; index < len(work); index++ {
		if contextErr(ctx) != nil {
			return nil, false
		}
		node := work[index]
		first := sort.Search(len(boundaries), func(index int) bool {
			return boundaries[index].Addr().Compare(node.Addr()) >= 0
		})
		split := false
		for _, boundary := range boundaries[first:] {
			if !node.Contains(boundary.Addr()) {
				break
			}
			if boundary.Bits() > node.Bits() {
				split = true
				break
			}
		}
		if !split {
			continue
		}
		left, right, _ := splitPrefix(node)
		work[index] = left
		work = append(work, right)
		if len(work) > MaxRecords*8 {
			return nil, false
		}
		index--
	}
	sort.Slice(work, func(i, j int) bool {
		return work[i].Addr().Compare(work[j].Addr()) < 0
	})
	return work, true
}

func splitPrefix(value netip.Prefix) (netip.Prefix, netip.Prefix, bool) {
	bits := value.Bits()
	width := value.Addr().BitLen()
	if bits >= width {
		return netip.Prefix{}, netip.Prefix{}, false
	}
	left := netip.PrefixFrom(value.Addr(), bits+1).Masked()
	if value.Addr().Is4() {
		bytes := left.Addr().As4()
		bytes[bits/8] |= byte(1 << (7 - bits%8))
		return left, netip.PrefixFrom(netip.AddrFrom4(bytes), bits+1).Masked(), true
	}
	bytes := left.Addr().As16()
	bytes[bits/8] |= byte(1 << (7 - bits%8))
	return left, netip.PrefixFrom(netip.AddrFrom16(bytes), bits+1).Masked(), true
}

func overlaps(left, right netip.Prefix) bool {
	return left.IsValid() && right.IsValid() && left.Addr().BitLen() == right.Addr().BitLen() && (left.Contains(right.Addr()) || right.Contains(left.Addr()))
}

func trafficScopes(static *Static, family policy.Family, request Request) []trafficScope {
	protocols := []string{"tcp", "udp", "icmp", "other"}
	if request.Protocol != "" {
		protocols = []string{request.Protocol}
	}
	result := make([]trafficScope, 0, len(protocols)*4)
	plan, _ := static.family(family)
	for _, protocol := range protocols {
		if request.Port != nil {
			result = append(result, trafficScope{protocol: protocol, ports: &Ports{Start: *request.Port, End: *request.Port}})
			continue
		}
		if protocol != "tcp" && protocol != "udp" {
			result = append(result, trafficScope{protocol: protocol})
			continue
		}
		boundaries := []uint16{0}
		for _, path := range plan.Paths {
			for _, rule := range path.Rules {
				if rule.Match.Traffic.Any {
					continue
				}
				ranges := rule.Match.Traffic.TCP
				if protocol == "udp" {
					ranges = rule.Match.Traffic.UDP
				}
				for _, span := range ranges {
					boundaries = append(boundaries, span.Start)
					if span.End < 65535 {
						boundaries = append(boundaries, span.End+1)
					}
				}
			}
		}
		slices.Sort(boundaries)
		unique := slices.Compact(boundaries)
		for index, start := range unique {
			end := uint16(65535)
			if index+1 < len(unique) {
				end = unique[index+1] - 1
			}
			result = append(result, trafficScope{protocol: protocol, ports: &Ports{Start: start, End: end}})
		}
	}
	return result
}

func (s *Static) attachmentsFor(direction policy.Direction) []Attachment {
	if s.nft {
		hook := "input"
		if direction == policy.Egress {
			hook = "output"
		}
		return []Attachment{{Name: fmt.Sprintf("inet/%s/%s", s.table, hook), Managed: true, PortBasis: "current_destination"}}
	}
	values := s.attachments[direction]
	result := make([]Attachment, len(values))
	for i, value := range values {
		result[i] = Attachment{Name: value.Chain, Managed: true, PortBasis: portBasis(value), InputInterfaces: append([]string(nil), value.InputInterfaces...), OutputInterfaces: append([]string(nil), value.OutputInterfaces...)}
	}
	return result
}

func portBasis(value config.Attachment) string {
	if value.OriginalDestination {
		return "original_destination"
	}
	return "current_destination"
}

func makeNotManaged(address netip.Prefix, direction policy.Direction, scope trafficScope, reason string) Outcome {
	return makeNotManagedWith(address, direction, scope, Attachment{PortBasis: "current_destination"}, reason)
}

func makeNotManagedWith(address netip.Prefix, direction policy.Direction, scope trafficScope, attachment Attachment, reason string) Outcome {
	attachment.Managed = false
	return Outcome{Prefix: address, Direction: direction, Protocol: scope.protocol, Ports: clonePorts(scope.ports), Attachment: attachment, Verdict: "not_blocked", Action: policy.Return, Stage: "not_managed", Reason: reason}
}

func clonePorts(value *Ports) *Ports {
	if value == nil {
		return nil
	}
	copy := *value
	return &copy
}

func evaluateScope(ctx context.Context, static *Static, plan policy.FamilyPlan, dynamic Dynamic, address netip.Prefix, direction policy.Direction, scope trafficScope, attachment Attachment, now time.Time, evidenceLimit int) *Outcome {
	var path *policy.Path
	for i := range plan.Paths {
		if plan.Paths[i].Direction == direction {
			path = &plan.Paths[i]
			break
		}
	}
	if path == nil {
		outcome := makeNotManagedWith(address, direction, scope, attachment, "direction is not managed")
		return &outcome
	}
	for _, rule := range path.Rules {
		if contextErr(ctx) != nil {
			return nil
		}
		if rule.Match.Flow == policy.EstablishedRelated || rule.Match.Flow == policy.NotNew {
			continue
		}
		if !ruleMatches(static, plan, *path, rule, address, dynamic, scope, now) {
			continue
		}
		outcome := Outcome{Prefix: address, Direction: direction, Protocol: scope.protocol, Ports: clonePorts(scope.ports), Attachment: attachment, Action: rule.Action, Policy: rule.Policy}
		if rule.Policy != "" {
			outcome.Priority = int(static.priorities[rule.Policy])
		}
		if rule.Action == policy.Drop || rule.Action == policy.Reject {
			outcome.Verdict = "blocked"
		} else {
			outcome.Verdict = "not_blocked"
		}
		outcome.Stage, outcome.Reason = classifyRule(rule, static)
		evidence, ok := explain(ctx, static, rule, address, dynamic, outcome.Stage, evidenceLimit)
		if !ok {
			return nil
		}
		outcome.Evidence = evidence
		return &outcome
	}
	return nil
}

func ruleMatches(static *Static, plan policy.FamilyPlan, path policy.Path, rule policy.Rule, address netip.Prefix, dynamic Dynamic, scope trafficScope, now time.Time) bool {
	if !scopeMatches(rule.Match.Traffic, plan.Family, scope) {
		return false
	}
	if rule.Match.SetID == "" {
		return true
	}
	member := false
	if rule.Match.SetID == "crowdsec" {
		for _, value := range dynamic.Prefixes {
			if value.Deadline.After(now) && value.Prefix.Contains(address.Addr()) {
				member = true
				break
			}
		}
	} else {
		_, member = containingPrefix(static.setIndex[plan.Family][rule.Match.SetID], address.Addr())
	}
	if rule.Match.NegateSet {
		return !member
	}
	return member
}

func scopeMatches(value policy.Scope, family policy.Family, scope trafficScope) bool {
	if value.Any {
		return true
	}
	switch scope.protocol {
	case "tcp":
		return portMatches(value.TCP, scope.ports)
	case "udp":
		return portMatches(value.UDP, scope.ports)
	case "icmp":
		return value.ICMP && (family == policy.IPv4 || family == policy.IPv6)
	default:
		return false
	}
}

func portMatches(values []policy.PortRange, ports *Ports) bool {
	if ports == nil {
		return len(values) != 0
	}
	for _, value := range values {
		if ports.Start >= value.Start && ports.End <= value.End {
			return true
		}
	}
	return false
}

func classifyRule(rule policy.Rule, static *Static) (string, string) {
	switch rule.Match.SetID {
	case "global_allowlist":
		return "global_allow", "global_allowlist"
	case "global_blocklist":
		return "global_block", "global_blocklist"
	case "crowdsec":
		return "crowdsec", "crowdsec"
	case "geo_eligible":
		return "classifier", "not_geo_eligible"
	}
	if rule.Policy != "" {
		if rule.Action == policy.Drop || rule.Action == policy.Reject {
			if static.policies[rule.Policy].Mode == "allowlist" {
				return "policy", "allowlist_absence"
			}
			return "policy", "geo_policy"
		}
		if static.policies[rule.Policy].Mode == "allowlist" && rule.Match.SetID != "" {
			return "policy", "allowlist_match"
		}
		if static.policies[rule.Policy].Mode == "blocklist" && rule.Match.SetID == "" {
			return "policy", "blocklist_miss"
		}
		return "policy", "policy_pass"
	}
	return "pass", "no_matching_policy"
}

type outcomeGroup struct {
	prototype Outcome
	prefixes  []netip.Prefix
}

func coalesceOutcomes(ctx context.Context, values []Outcome) []Outcome {
	groups := make([]outcomeGroup, 0, len(values))
	for _, value := range values {
		if contextErr(ctx) != nil {
			return nil
		}
		found := -1
		for index := range groups {
			if outcomeSame(groups[index].prototype, value) {
				found = index
				break
			}
		}
		if found < 0 {
			groups = append(groups, outcomeGroup{prototype: value, prefixes: []netip.Prefix{value.Prefix}})
		} else {
			groups[found].prefixes = append(groups[found].prefixes, value.Prefix)
		}
	}
	result := make([]Outcome, 0, len(values))
	for _, group := range groups {
		for _, value := range mergePrefixes(group.prefixes) {
			outcome := group.prototype
			outcome.Prefix = value
			result = append(result, outcome)
		}
	}
	sort.Slice(result, func(i, j int) bool { return outcomeLess(result[i], result[j]) })
	return result
}

func outcomeSame(left, right Outcome) bool {
	if left.Direction != right.Direction || left.Protocol != right.Protocol || left.Verdict != right.Verdict || left.Action != right.Action || left.Stage != right.Stage || left.Policy != right.Policy || left.Priority != right.Priority || left.Reason != right.Reason || !attachmentEqual(left.Attachment, right.Attachment) {
		return false
	}
	if (left.Ports == nil) != (right.Ports == nil) {
		return false
	}
	if left.Ports != nil && *left.Ports != *right.Ports {
		return false
	}
	if len(left.Evidence) != len(right.Evidence) {
		return false
	}
	for index := range left.Evidence {
		if !evidenceEqual(left.Evidence[index], right.Evidence[index]) {
			return false
		}
	}
	return true
}

func attachmentEqual(left, right Attachment) bool {
	if left.Name != right.Name || left.Managed != right.Managed || left.PortBasis != right.PortBasis || len(left.InputInterfaces) != len(right.InputInterfaces) || len(left.OutputInterfaces) != len(right.OutputInterfaces) {
		return false
	}
	for index := range left.InputInterfaces {
		if left.InputInterfaces[index] != right.InputInterfaces[index] {
			return false
		}
	}
	for index := range left.OutputInterfaces {
		if left.OutputInterfaces[index] != right.OutputInterfaces[index] {
			return false
		}
	}
	return true
}

func evidenceEqual(left, right Evidence) bool {
	if left.Kind != right.Kind || left.Name != right.Name || left.Policy != right.Policy || left.Role != right.Role || left.Prefix != right.Prefix || left.Contributing != right.Contributing || left.DecisionID != right.DecisionID || !left.RetrievedAt.Equal(right.RetrievedAt) || !left.DecisionDeadline.Equal(right.DecisionDeadline) || !left.LeaseDeadline.Equal(right.LeaseDeadline) || len(left.Via) != len(right.Via) {
		return false
	}
	for index := range left.Via {
		if left.Via[index] != right.Via[index] {
			return false
		}
	}
	return true
}

func mergePrefixes(values []netip.Prefix) []netip.Prefix {
	sort.Slice(values, func(i, j int) bool {
		if order := values[i].Addr().Compare(values[j].Addr()); order != 0 {
			return order < 0
		}
		return values[i].Bits() < values[j].Bits()
	})
	out := values[:0]
	for _, value := range values {
		if len(out) > 0 && out[len(out)-1].Contains(value.Addr()) && out[len(out)-1].Bits() <= value.Bits() {
			continue
		}
		out = append(out, value)
		for len(out) >= 2 {
			left, right := out[len(out)-2], out[len(out)-1]
			if left.Bits() == 0 || left.Bits() != right.Bits() {
				break
			}
			parent := netip.PrefixFrom(left.Addr(), left.Bits()-1).Masked()
			if netip.PrefixFrom(right.Addr(), right.Bits()-1).Masked() != parent {
				break
			}
			out[len(out)-2] = parent
			out = out[:len(out)-1]
		}
	}
	return out
}

func outcomeLess(left, right Outcome) bool {
	if order := left.Prefix.Addr().Compare(right.Prefix.Addr()); order != 0 {
		return order < 0
	}
	if left.Prefix.Bits() != right.Prefix.Bits() {
		return left.Prefix.Bits() < right.Prefix.Bits()
	}
	if left.Direction != right.Direction {
		return left.Direction < right.Direction
	}
	if left.Protocol != right.Protocol {
		return left.Protocol < right.Protocol
	}
	if (left.Ports == nil) != (right.Ports == nil) {
		return left.Ports == nil
	}
	if left.Ports != nil && *left.Ports != *right.Ports {
		if left.Ports.Start != right.Ports.Start {
			return left.Ports.Start < right.Ports.Start
		}
		return left.Ports.End < right.Ports.End
	}
	if left.Attachment.Name != right.Attachment.Name {
		return left.Attachment.Name < right.Attachment.Name
	}
	if left.Attachment.PortBasis != right.Attachment.PortBasis {
		return left.Attachment.PortBasis < right.Attachment.PortBasis
	}
	if left.Attachment.Managed != right.Attachment.Managed {
		return !left.Attachment.Managed
	}
	if len(left.Attachment.InputInterfaces) != len(right.Attachment.InputInterfaces) {
		return len(left.Attachment.InputInterfaces) < len(right.Attachment.InputInterfaces)
	}
	for index := range left.Attachment.InputInterfaces {
		if left.Attachment.InputInterfaces[index] != right.Attachment.InputInterfaces[index] {
			return left.Attachment.InputInterfaces[index] < right.Attachment.InputInterfaces[index]
		}
	}
	if len(left.Attachment.OutputInterfaces) != len(right.Attachment.OutputInterfaces) {
		return len(left.Attachment.OutputInterfaces) < len(right.Attachment.OutputInterfaces)
	}
	for index := range left.Attachment.OutputInterfaces {
		if left.Attachment.OutputInterfaces[index] != right.Attachment.OutputInterfaces[index] {
			return left.Attachment.OutputInterfaces[index] < right.Attachment.OutputInterfaces[index]
		}
	}
	if left.Verdict != right.Verdict {
		return left.Verdict < right.Verdict
	}
	if left.Stage != right.Stage {
		return left.Stage < right.Stage
	}
	if left.Policy != right.Policy {
		return left.Policy < right.Policy
	}
	if left.Priority != right.Priority {
		return left.Priority < right.Priority
	}
	if left.Reason != right.Reason {
		return left.Reason < right.Reason
	}
	if len(left.Evidence) != len(right.Evidence) {
		return len(left.Evidence) < len(right.Evidence)
	}
	for index := range left.Evidence {
		if evidenceLess(left.Evidence[index], right.Evidence[index]) {
			return true
		}
		if evidenceLess(right.Evidence[index], left.Evidence[index]) {
			return false
		}
	}
	return false
}
