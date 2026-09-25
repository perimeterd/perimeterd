package firewall

import (
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

const (
	stableToken     = "stable"
	tableRole       = "table"
	maxNFTNameBytes = 255
)

// BuildTarget lowers a compiled policy state into an owned immutable target.
// The returned target never aliases cfg, model, or previous.
func BuildTarget(owner, id string, cfg config.Config, model policy.State, previous *Target) (*Target, error) {
	if err := ValidateConfig(cfg); err != nil {
		return nil, err
	}
	if !validTargetID(owner) {
		return nil, fmt.Errorf("firewall target: owner must be 32 lowercase hexadecimal characters")
	}
	if !validTargetID(id) {
		return nil, fmt.Errorf("firewall target: generation must be 32 lowercase hexadecimal characters")
	}
	if model.Empty() {
		return nil, nil
	}
	families := model.Families()
	dynamicGeneration := ""
	if cfg.CrowdSec.Enabled {
		dynamicGeneration = id
		table := cfg.Firewall.Nftables.Table
		if cfg.Firewall.Backend == "iptables" {
			table = "filter"
		}
		if previous != nil && previous.Owner == owner && previous.Backend() == cfg.Firewall.Backend &&
			previous.Table == table && previous.DynamicGeneration != "" {
			dynamicGeneration = previous.DynamicGeneration
		}
	}
	candidate := &Target{
		Owner: owner, Table: cfg.Firewall.Nftables.Table, Priority: cfg.Firewall.Nftables.Priority,
		Generation: id, DynamicGeneration: dynamicGeneration, Families: families,
	}
	if cfg.Firewall.Backend == "iptables" {
		candidate.Table = "filter"
		candidate.Priority = 0
		candidate.IPTables = &IPTablesTarget{Attachments: cloneIPTablesAttachments(cfg.Firewall.IPTables.Attachments)}
	}
	if previous != nil && previous.Owner == candidate.Owner && previous.Backend() == candidate.Backend() &&
		previous.Table == candidate.Table && previous.DynamicGeneration == candidate.DynamicGeneration && sameFamilies(previous.Families, candidate.Families) &&
		reflect.DeepEqual(previous.IPTables, candidate.IPTables) {
		candidate.Generation = previous.Generation
	}
	candidate.Counters = desiredCounters(candidate, previous)
	if err := ValidateTarget(candidate); err != nil {
		return nil, err
	}
	return candidate, nil
}

func cloneIPTablesAttachments(values []config.Attachment) []config.Attachment {
	if values == nil {
		return nil
	}
	out := make([]config.Attachment, len(values))
	for i, value := range values {
		out[i] = value
		out[i].InputInterfaces = append([]string(nil), value.InputInterfaces...)
		out[i].OutputInterfaces = append([]string(nil), value.OutputInterfaces...)
	}
	return out
}

func sameFamilies(a, b []policy.FamilyPlan) bool {
	return reflect.DeepEqual(a, b)
}

func desiredCounters(target *Target, previous *Target) []CounterSpec {
	roles := make(map[string]CounterSpec)
	for _, family := range target.Families {
		for _, path := range family.Paths {
			role := path.Processed
			name := counterName(target.Owner, family.Family, path.Direction, role)
			roles[name] = CounterSpec{Name: name, Family: family.Family, Direction: path.Direction, Role: role}
			for _, rule := range path.Rules {
				if rule.Counter.Kind != policy.Denied {
					continue
				}
				name = counterName(target.Owner, family.Family, path.Direction, rule.Counter)
				roles[name] = CounterSpec{Name: name, Family: family.Family, Direction: path.Direction, Role: rule.Counter}
			}
		}
	}
	if previous != nil && previous.Backend() == target.Backend() && previous.Table == target.Table {
		for _, counter := range previous.Counters {
			if validRole(counter.Role) && validFamily(counter.Family) && validDirection(counter.Direction) &&
				counter.Name == counterName(target.Owner, counter.Family, counter.Direction, counter.Role) {
				roles[counter.Name] = counter
			}
		}
	}
	out := make([]CounterSpec, 0, len(roles))
	for _, counter := range roles {
		out = append(out, counter)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}

func counterName(owner string, family policy.Family, direction policy.Direction, role policy.CounterRole) string {
	parts := []string{"pd", owner, "counter", familyToken(family), string(direction), string(role.Kind)}
	if role.Kind == policy.Denied {
		parts = append(parts, string(role.Reason), string(role.Action))
	}
	return strings.Join(parts, "_")
}

func familyToken(value policy.Family) string {
	if value == policy.IPv4 {
		return "v4"
	}
	return "v6"
}

func artifactName(owner, generation, role string) string {
	return "pd_" + owner + "_" + generation + "_" + sanitizeRole(role)
}

func sanitizeRole(value string) string {
	value = strings.NewReplacer("/", "_", " ", "_", ".", "_").Replace(value)
	return value
}

func ownershipComment(owner, generation, role string, stable bool) string {
	if stable {
		return "perimeterd owner=" + owner + " role=" + role
	}
	return "perimeterd owner=" + owner + " generation=" + generation + " role=" + role
}

func tableComment(owner string) string { return ownershipComment(owner, stableToken, tableRole, true) }

func baseChainName(target *Target, direction policy.Direction) string {
	return artifactName(target.Owner, stableToken, "base_"+string(direction))
}

func entryChainName(target *Target, family policy.Family, direction policy.Direction) string {
	return artifactName(target.Owner, stableToken, "entry_"+familyToken(family)+"_"+string(direction))
}

func generationChainName(target *Target, family policy.Family, direction policy.Direction) string {
	return artifactName(target.Owner, target.Generation, "path_"+familyToken(family)+"_"+string(direction))
}

func dynamicSetName(target *Target, family policy.Family) string {
	return artifactName(target.Owner, target.DynamicGeneration, "dynamic_"+familyToken(family))
}

func setName(target *Target, family policy.Family, setID string) string {
	if setID == "crowdsec" && target.DynamicGeneration != "" {
		return dynamicSetName(target, family)
	}
	prefix := artifactName(target.Owner, target.Generation, "set_"+familyToken(family)+"_")
	readable := sanitizeRole(setID)
	// geo/eligible and the fixed geo_eligible set are distinct logical sets;
	// retain a readable name while keeping their native identifiers distinct.
	if setID == "geo/eligible" {
		readable = "geo_policy_eligible"
	}
	name := prefix + readable
	if len(name) <= maxNFTNameBytes {
		return name
	}

	// Policy names are intentionally not bounded by nftables' identifier limit.
	// Keep a readable prefix, then append a digest of the complete logical set
	// ID so names differing only after the native limit remain distinct.
	digest := sha256.Sum256([]byte(setID))
	suffix := "_h" + hex.EncodeToString(digest[:])
	// Validated owner/generation IDs fix the prefix length, leaving room for
	// both a readable ASCII prefix and the complete digest.
	available := maxNFTNameBytes - len(prefix) - len(suffix)
	return prefix + readable[:available] + suffix
}

func chainRole(family policy.Family, direction policy.Direction) string {
	return "path_" + familyToken(family) + "_" + string(direction)
}

func entryRole(family policy.Family, direction policy.Direction) string {
	return "entry_" + familyToken(family) + "_" + string(direction)
}

func baseRole(direction policy.Direction) string { return "base_" + string(direction) }

// nftCommand is intentionally a small typed subset of the libnftables JSON
// schema. map values are only built from validated model data below.
type nftCommand struct {
	Add    any `json:"add,omitempty"`
	Create any `json:"create,omitempty"`
	Delete any `json:"delete,omitempty"`
	Flush  any `json:"flush,omitempty"`
}

type nftBatch struct {
	Nftables []nftCommand `json:"nftables"`
}

func jsonEquivalent(actual, expected any) bool {
	actualJSON, err := json.Marshal(actual)
	if err != nil {
		return false
	}
	expectedJSON, err := json.Marshal(expected)
	if err != nil {
		return false
	}
	var actualValue, expectedValue any
	if err := json.Unmarshal(actualJSON, &actualValue); err != nil {
		return false
	}
	if err := json.Unmarshal(expectedJSON, &expectedValue); err != nil {
		return false
	}
	return reflect.DeepEqual(actualValue, expectedValue)
}

func chainRulesComplete(inventory *nftInventory, chain string, expected []map[string]any) bool {
	if inventory == nil {
		return false
	}
	index := 0
	for _, observed := range inventory.rules {
		if observed.Chain != chain {
			continue
		}
		if index >= len(expected) {
			return false
		}
		rule := expected[index]
		comment, ok := rule["comment"].(string)
		if !ok || comment == "" || observed.Comment != comment {
			return false
		}
		if !jsonEquivalent(observed.Expr, rule["expr"]) {
			return false
		}
		index++
	}
	return index == len(expected)
}

func generationRulesComplete(inventory *nftInventory, target *Target) bool {
	for _, family := range target.Families {
		for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
			if !chainRulesComplete(inventory, generationChainName(target, family.Family, direction), familyPathRules(target, family, direction)) {
				return false
			}
		}
	}
	return true
}

func entryRulesComplete(inventory *nftInventory, target *Target) bool {
	for _, family := range target.Families {
		for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
			if !chainRulesComplete(inventory, entryChainName(target, family.Family, direction), entryRules(target, family.Family, direction)) {
				return false
			}
		}
	}
	return true
}

func baseRulesComplete(inventory *nftInventory, target *Target) bool {
	for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
		if !chainRulesComplete(inventory, baseChainName(target, direction), baseRules(target, direction)) {
			return false
		}
	}
	return true
}

type addressInterval struct {
	start netip.Addr
	end   netip.Addr
}

func prefixInterval(prefix netip.Prefix) addressInterval {
	prefix = prefix.Masked()
	start := prefix.Addr()
	end := start
	bits := prefix.Bits()
	if start.Is4() {
		octets := start.As4()
		value := binary.BigEndian.Uint32(octets[:])
		if hostBits := 32 - bits; hostBits > 0 {
			value |= ^uint32(0) >> bits
			var bytes [4]byte
			binary.BigEndian.PutUint32(bytes[:], value)
			end = netip.AddrFrom4(bytes)
		}
		return addressInterval{start: start, end: end}
	}
	bytes := start.As16()
	hostBits := 128 - bits
	for index := len(bytes) - 1; index >= 0 && hostBits > 0; index-- {
		width := hostBits
		if width > 8 {
			width = 8
		}
		bytes[index] |= byte((1 << width) - 1)
		hostBits -= width
	}
	return addressInterval{start: start, end: netip.AddrFrom16(bytes)}
}

func mergeIntervals(intervals []addressInterval) []addressInterval {
	if len(intervals) < 2 {
		return intervals
	}
	sort.Slice(intervals, func(i, j int) bool {
		if comparison := intervals[i].start.Compare(intervals[j].start); comparison != 0 {
			return comparison < 0
		}
		return intervals[i].end.Compare(intervals[j].end) < 0
	})
	merged := intervals[:1]
	for _, current := range intervals[1:] {
		previous := &merged[len(merged)-1]
		overlaps := current.start.Compare(previous.end) <= 0
		adjacent := false
		if next := previous.end.Next(); next.IsValid() {
			adjacent = current.start == next
		}
		if overlaps || adjacent {
			if current.end.Compare(previous.end) > 0 {
				previous.end = current.end
			}
			continue
		}
		merged = append(merged, current)
	}
	return merged
}

func parseObservedAddress(raw json.RawMessage, family policy.Family) (netip.Addr, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err != nil {
		return netip.Addr{}, err
	}
	address, err := netip.ParseAddr(text)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, fmt.Errorf("invalid address %q", text)
	}
	if (family == policy.IPv4 && !address.Is4()) || (family == policy.IPv6 && !address.Is6()) {
		return netip.Addr{}, fmt.Errorf("address %q has wrong family", text)
	}
	return address, nil
}

func parseObservedInterval(raw json.RawMessage, family policy.Family) (addressInterval, error) {
	if address, err := parseObservedAddress(raw, family); err == nil {
		return addressInterval{start: address, end: address}, nil
	}
	var object map[string]json.RawMessage
	if err := json.Unmarshal(raw, &object); err != nil || len(object) != 1 {
		return addressInterval{}, errors.New("unsupported set element")
	}
	if prefixRaw, ok := object["prefix"]; ok {
		var fields map[string]json.RawMessage
		if err := json.Unmarshal(prefixRaw, &fields); err != nil || len(fields) != 2 {
			return addressInterval{}, errors.New("malformed prefix element")
		}
		addr, ok := fields["addr"]
		if !ok {
			return addressInterval{}, errors.New("prefix element missing address")
		}
		address, err := parseObservedAddress(addr, family)
		if err != nil {
			return addressInterval{}, err
		}
		var bits int
		if err := json.Unmarshal(fields["len"], &bits); err != nil {
			return addressInterval{}, errors.New("prefix element has invalid length")
		}
		maxBits := address.BitLen()
		if bits < 0 || bits > maxBits {
			return addressInterval{}, errors.New("prefix element has invalid length")
		}
		return prefixInterval(netip.PrefixFrom(address, bits)), nil
	}
	if rangeRaw, ok := object["range"]; ok {
		var fields []json.RawMessage
		if err := json.Unmarshal(rangeRaw, &fields); err != nil || len(fields) != 2 {
			return addressInterval{}, errors.New("malformed range element")
		}
		start, err := parseObservedAddress(fields[0], family)
		if err != nil {
			return addressInterval{}, err
		}
		end, err := parseObservedAddress(fields[1], family)
		if err != nil {
			return addressInterval{}, err
		}
		if start.Compare(end) > 0 {
			return addressInterval{}, errors.New("range element is reversed")
		}
		return addressInterval{start: start, end: end}, nil
	}
	return addressInterval{}, errors.New("unsupported set element")
}

func setElementsComplete(observed nftObject, family policy.Family, expected []netip.Prefix) bool {
	if len(observed.Elem) == 0 {
		return len(expected) == 0
	}
	var rawElements []json.RawMessage
	if err := json.Unmarshal(observed.Elem, &rawElements); err != nil || rawElements == nil {
		return false
	}
	if len(expected) == 0 {
		return len(rawElements) == 0
	}
	if len(rawElements) == 0 {
		return false
	}
	actual := make([]addressInterval, 0, len(rawElements))
	for _, raw := range rawElements {
		interval, err := parseObservedInterval(raw, family)
		if err != nil {
			return false
		}
		actual = append(actual, interval)
	}
	desired := make([]addressInterval, 0, len(expected))
	for _, prefix := range expected {
		desired = append(desired, prefixInterval(prefix))
	}
	actual, desired = mergeIntervals(actual), mergeIntervals(desired)
	if len(actual) != len(desired) {
		return false
	}
	for index := range actual {
		if actual[index].start != desired[index].start || actual[index].end != desired[index].end {
			return false
		}
	}
	return true
}

func commandBatch(target *Target, inventory *nftInventory, dynamic *DynamicState) (nftBatch, error) {
	if err := ValidateTarget(target); err != nil {
		return nftBatch{}, err
	}
	if err := validateDynamicState(target, dynamic); err != nil {
		return nftBatch{}, err
	}
	var batch nftBatch
	if inventory == nil || !inventory.present {
		batch.Nftables = append(batch.Nftables, nftCommand{Create: map[string]any{"table": map[string]any{
			"family": "inet", "name": target.Table, "comment": tableComment(target.Owner),
		}}})
	}
	// Counters, static sets and generated chains are immutable per generation.
	for _, counter := range target.Counters {
		if inventory != nil && inventory.hasCounter(counter.Name) {
			continue
		}
		batch.Nftables = append(batch.Nftables, nftCommand{Add: map[string]any{"counter": map[string]any{
			"family": "inet", "table": target.Table, "name": counter.Name,
			"comment": ownershipComment(target.Owner, stableToken, "counter/"+counter.Name, true),
		}}})
	}
	now := time.Now()
	for _, family := range target.Families {
		for _, set := range family.Sets {
			name := setName(target, family.Family, set.ID)
			if set.Kind == policy.DynamicCrowdSecSet {
				if inventory != nil && inventory.hasSet(name) {
					if dynamic != nil {
						commands, err := dynamicSetCommands(target, family.Family, inventory.sets[name], dynamic.Prefixes, now)
						if err != nil {
							return nftBatch{}, err
						}
						batch.Nftables = append(batch.Nftables, commands...)
					}
					continue
				}
				definition := dynamicSetDefinition(target, family.Family, name)
				batch.Nftables = append(batch.Nftables, nftCommand{Add: map[string]any{"set": definition}})
				if dynamic != nil {
					commands, err := dynamicSetCommands(target, family.Family, nftObject{}, dynamic.Prefixes, now)
					if err != nil {
						return nftBatch{}, err
					}
					batch.Nftables = append(batch.Nftables, commands...)
				}
				continue
			}
			elems := make([]any, 0, len(set.Prefixes))
			for _, prefix := range set.Prefixes {
				elems = append(elems, prefixExpression(prefix))
			}
			if inventory != nil && inventory.hasSet(name) {
				if !setElementsComplete(inventory.sets[name], family.Family, set.Prefixes) {
					return nftBatch{}, fmt.Errorf("nft backend: set %q has missing or unexpected elements", name)
				}
				continue
			}
			typeName := "ipv4_addr"
			if family.Family == policy.IPv6 {
				typeName = "ipv6_addr"
			}
			definition := map[string]any{
				"family": "inet", "table": target.Table, "name": name,
				"type": typeName, "flags": []string{"constant", "interval"}, "auto-merge": true,
			}
			// Empty static sets are still materialized. Geo allowlists use an
			// explicitly empty family to deny every globally routable address;
			// omitting the set would make the generated reference invalid.
			if len(elems) != 0 {
				definition["elem"] = elems
			}
			batch.Nftables = append(batch.Nftables, nftCommand{Add: map[string]any{"set": definition}})
		}
	}
	keepGeneration := generationRulesComplete(inventory, target)
	for _, family := range target.Families {
		for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
			name := generationChainName(target, family.Family, direction)
			if inventory != nil && inventory.hasChain(name) {
				if !keepGeneration {
					batch.Nftables = append(batch.Nftables, nftCommand{Flush: map[string]any{"chain": objectRef(target.Table, name)}})
				}
			} else {
				batch.Nftables = append(batch.Nftables, nftCommand{Add: map[string]any{"chain": map[string]any{
					"family": "inet", "table": target.Table, "name": name,
					"comment": ownershipComment(target.Owner, target.Generation, chainRole(family.Family, direction), false),
				}}})
			}
			if inventory == nil || !inventory.hasChain(name) || !keepGeneration {
				for _, rule := range familyPathRules(target, family, direction) {
					batch.Nftables = append(batch.Nftables, nftCommand{Add: map[string]any{"rule": rule}})
				}
			}
		}
	}
	keepEntry := entryRulesComplete(inventory, target)
	for _, family := range target.Families {
		for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
			name := entryChainName(target, family.Family, direction)
			exists := inventory != nil && inventory.hasChain(name)
			if !exists {
				batch.Nftables = append(batch.Nftables, nftCommand{Add: map[string]any{"chain": map[string]any{
					"family": "inet", "table": target.Table, "name": name,
					"comment": ownershipComment(target.Owner, stableToken, entryRole(family.Family, direction), true),
				}}})
			} else if !keepEntry {
				batch.Nftables = append(batch.Nftables, nftCommand{Flush: map[string]any{"chain": objectRef(target.Table, name)}})
			}
			if !exists || !keepEntry {
				for _, rule := range entryRules(target, family.Family, direction) {
					batch.Nftables = append(batch.Nftables, nftCommand{Add: map[string]any{"rule": rule}})
				}
			}
		}
	}
	keepFamilies := baseRulesComplete(inventory, target)
	for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
		name := baseChainName(target, direction)
		var chain *nftObject
		if inventory != nil {
			chain = inventory.chain(name)
		}
		if chain == nil {
			batch.Nftables = append(batch.Nftables, nftCommand{Add: map[string]any{"chain": baseChain(target, direction)}})
			for _, rule := range baseRules(target, direction) {
				batch.Nftables = append(batch.Nftables, nftCommand{Add: map[string]any{"rule": rule}})
			}
		} else if chain.Prio != target.Priority {
			batch.Nftables = append(batch.Nftables,
				nftCommand{Flush: map[string]any{"chain": objectRef(target.Table, name)}},
				nftCommand{Delete: map[string]any{"chain": objectRef(target.Table, name)}},
				nftCommand{Add: map[string]any{"chain": baseChain(target, direction)}},
			)
			for _, rule := range baseRules(target, direction) {
				batch.Nftables = append(batch.Nftables, nftCommand{Add: map[string]any{"rule": rule}})
			}
		} else if !keepFamilies {
			batch.Nftables = append(batch.Nftables, nftCommand{Flush: map[string]any{"chain": objectRef(target.Table, name)}})
			for _, rule := range baseRules(target, direction) {
				batch.Nftables = append(batch.Nftables, nftCommand{Add: map[string]any{"rule": rule}})
			}
		}
	}
	return batch, nil
}

func objectRef(table, name string) map[string]any {
	return map[string]any{"family": "inet", "table": table, "name": name}
}

func baseChain(target *Target, direction policy.Direction) map[string]any {
	hook := "input"
	if direction == policy.Egress {
		hook = "output"
	}
	return map[string]any{"family": "inet", "table": target.Table, "name": baseChainName(target, direction), "type": "filter", "hook": hook, "prio": target.Priority, "policy": "accept", "comment": ownershipComment(target.Owner, stableToken, baseRole(direction), true)}
}

func baseRules(target *Target, direction policy.Direction) []map[string]any {
	result := make([]map[string]any, 0, len(target.Families))
	for _, family := range target.Families {
		proto := "ipv4"
		if family.Family == policy.IPv6 {
			proto = "ipv6"
		}
		result = append(result, map[string]any{"family": "inet", "table": target.Table, "chain": baseChainName(target, direction), "comment": ownershipComment(target.Owner, stableToken, "dispatch/"+familyToken(family.Family)+"/"+string(direction), true), "expr": []any{
			map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "nfproto"}}, "right": proto}},
			map[string]any{"jump": map[string]any{"target": entryChainName(target, family.Family, direction)}},
		}})
	}
	return result
}

func entryRules(target *Target, family policy.Family, direction policy.Direction) []map[string]any {
	chain := entryChainName(target, family, direction)
	role := entryRole(family, direction)
	counter := counterName(target.Owner, family, direction, policy.CounterRole{Kind: policy.Processed})
	return []map[string]any{
		{"family": "inet", "table": target.Table, "chain": chain, "comment": ownershipComment(target.Owner, stableToken, role+"/processed", true), "expr": []any{map[string]any{"counter": counter}}},
		{"family": "inet", "table": target.Table, "chain": chain, "comment": ownershipComment(target.Owner, stableToken, role+"/established", true), "expr": []any{map[string]any{"match": map[string]any{"op": "in", "left": map[string]any{"ct": map[string]any{"key": "state"}}, "right": map[string]any{"set": []any{"established", "related"}}}}, map[string]any{"return": nil}}},
		{"family": "inet", "table": target.Table, "chain": chain, "comment": ownershipComment(target.Owner, stableToken, role+"/not-new", true), "expr": []any{map[string]any{"match": map[string]any{"op": "!=", "left": map[string]any{"ct": map[string]any{"key": "state"}}, "right": "new"}}, map[string]any{"return": nil}}},
		{"family": "inet", "table": target.Table, "chain": chain, "comment": ownershipComment(target.Owner, target.Generation, role+"/dispatch", false), "expr": []any{map[string]any{"jump": map[string]any{"target": generationChainName(target, family, direction)}}}},
	}
}

func familyPathRules(target *Target, family policy.FamilyPlan, direction policy.Direction) []map[string]any {
	var path policy.Path
	for _, candidate := range family.Paths {
		if candidate.Direction == direction {
			path = candidate
			break
		}
	}
	chain := generationChainName(target, family.Family, direction)
	setIDs := make(map[string]string)
	for _, set := range family.Sets {
		setIDs[set.ID] = setName(target, family.Family, set.ID)
	}
	result := make([]map[string]any, 0)
	index := 0
	for _, logical := range path.Rules {
		if logical.Match.Flow != "" {
			continue
		}
		var variants [][]any
		if logical.Action == policy.Reject && logical.Match.Traffic.Any {
			variants = rejectVariants()
		} else {
			variants = trafficVariants(logical.Match.Traffic, family.Family)
		}
		for _, expr := range variants {
			exprs := make([]any, 0, 4)
			if logical.Match.SetID != "" {
				set := setIDs[logical.Match.SetID]
				remote := "saddr"
				if direction == policy.Egress {
					remote = "daddr"
				}
				proto := "ip"
				if family.Family == policy.IPv6 {
					proto = "ip6"
				}
				op := "=="
				if logical.Match.NegateSet {
					op = "!="
				}
				exprs = append(exprs, map[string]any{"match": map[string]any{"op": op, "left": map[string]any{"payload": map[string]any{"protocol": proto, "field": remote}}, "right": "@" + set}})
			}
			exprs = append(exprs, expr...)
			if logical.Counter.Kind == policy.Denied {
				exprs = append(exprs, map[string]any{"counter": counterName(target.Owner, family.Family, direction, logical.Counter)})
			}
			exprs = append(exprs, verdictExpression(logical.Action, family.Family, expr...))
			result = append(result, map[string]any{"family": "inet", "table": target.Table, "chain": chain, "comment": ownershipComment(target.Owner, target.Generation, chainRole(family.Family, direction)+"/rule/"+strconv.Itoa(index), false), "expr": exprs})
			index++
		}
	}
	return result
}

func trafficVariants(scope policy.Scope, family policy.Family) [][]any {
	if scope.Any {
		return [][]any{{}}
	}
	result := make([][]any, 0, len(scope.TCP)+len(scope.UDP)+1)
	for _, port := range scope.TCP {
		result = append(result, []any{matchPort("tcp", port)})
	}
	for _, port := range scope.UDP {
		result = append(result, []any{matchPort("udp", port)})
	}
	if scope.ICMP {
		proto := "icmp"
		if family == policy.IPv6 {
			proto = "icmpv6"
		}
		result = append(result, []any{map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "l4proto"}}, "right": proto}}})
	}
	return result
}

func rejectVariants() [][]any {
	return [][]any{
		{map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"meta": map[string]any{"key": "l4proto"}}, "right": "tcp"}}},
		{map[string]any{"match": map[string]any{"op": "!=", "left": map[string]any{"meta": map[string]any{"key": "l4proto"}}, "right": "tcp"}}},
	}
}

func matchPort(proto string, value policy.PortRange) map[string]any {
	var right any = value.Start
	if value.Start != value.End {
		right = map[string]any{"range": []any{value.Start, value.End}}
	}
	return map[string]any{"match": map[string]any{"op": "==", "left": map[string]any{"payload": map[string]any{"protocol": proto, "field": "dport"}}, "right": right}}
}

func verdictExpression(action policy.Action, family policy.Family, variants ...any) map[string]any {
	switch action {
	case policy.Return:
		return map[string]any{"return": nil}
	case policy.Drop:
		return map[string]any{"drop": nil}
	case policy.Reject:
		for _, value := range variants {
			object, ok := value.(map[string]any)
			if !ok {
				continue
			}
			match, ok := object["match"].(map[string]any)
			if !ok {
				continue
			}
			left, ok := match["left"].(map[string]any)
			if !ok {
				continue
			}
			if payload, ok := left["payload"].(map[string]any); ok && payload["protocol"] == "tcp" {
				return map[string]any{"reject": map[string]any{"type": "tcp reset"}}
			}
			if meta, ok := left["meta"].(map[string]any); ok && match["op"] == "==" && meta["key"] == "l4proto" && match["right"] == "tcp" {
				return map[string]any{"reject": map[string]any{"type": "tcp reset"}}
			}
		}
		kind := "icmp"
		if family == policy.IPv6 {
			kind = "icmpv6"
		}
		return map[string]any{"reject": map[string]any{"type": kind, "expr": "admin-prohibited"}}
	default:
		return map[string]any{"return": nil}
	}
}

func prefixExpression(value netip.Prefix) map[string]any {
	return map[string]any{"prefix": map[string]any{"addr": value.Addr().String(), "len": value.Bits()}}
}
