package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"slices"
	"strconv"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
)

const (
	maxNFTOutput          = 64 << 20
	maxNFTInput           = 32 << 20
	maxNFTInventoryBudget = 48 << 20
)

type nftExecutor func(context.Context, []string, []byte) ([]byte, error)

// NFT is the native nftables backend. It only invokes nft with typed JSON and
// never parses human-oriented command output.
type NFT struct {
	exec nftExecutor
}

// NewNFT returns a backend using the host nft executable. Tests in this
// package may inject a bounded executor without changing production behavior.
func NewNFT() *NFT { return &NFT{exec: nativeNFTExecutor} }

func nativeNFTExecutor(ctx context.Context, args []string, input []byte) ([]byte, error) {
	return executeNative(ctx, "nft", args, input, maxNFTInput, maxNFTOutput)
}

func validateNFTTarget(target *Target) error {
	if target != nil && target.IPTables != nil {
		return errors.New("nft backend: iptables target is not supported")
	}
	return ValidateTarget(target)
}

// validateNFTCapacity bounds the complete recoverable state, not just an
// incremental switch. Native JSON adds handles, counter values and whitespace;
// allow twice the encoded full installation plus 1 KiB per object for that
// expansion, with another 16 MiB of capture headroom. Prefixes can become host
// strings or merged ranges, neither larger than this allowance. Sum both full
// generations in each table because they coexist until durable retirement.
// The projection is used only for candidate admission/capacity accounting.
func validateNFTCapacity(previous, candidate *Target, dynamic *DynamicState) error {
	budgets := make(map[string]int)
	for index, target := range []*Target{previous, candidate} {
		if target == nil {
			continue
		}
		if err := validateNFTTarget(target); err != nil {
			return err
		}
		var projection *DynamicState
		if index == 1 {
			projection = dynamic
		}
		batch, err := commandBatch(target, nil, projection)
		if err != nil {
			return err
		}
		data, err := json.Marshal(batch)
		if err != nil {
			return fmt.Errorf("nft backend: encode capacity estimate: %w", err)
		}
		if len(data) > maxNFTInput {
			return errors.New("nft backend: complete target exceeds input limit")
		}
		budgets[target.Table] += nftInspectionBudget(len(data), len(batch.Nftables))
		if budgets[target.Table] > maxNFTInventoryBudget {
			return errors.New("nft backend: retained generations exceed inspection capacity")
		}
	}
	return nil
}

func nftInspectionBudget(encodedBytes, commands int) int {
	return 2*encodedBytes + 1024*commands + 4096
}

type nftObject struct {
	Kind       string
	Family     string
	Table      string
	Name       string
	Chain      string
	Comment    string
	Type       string
	Hook       string
	Policy     string
	Prio       int32
	HasPrio    bool
	Expr       []json.RawMessage
	Elem       json.RawMessage
	Flags      []string
	Timeout    json.RawMessage
	HasTimeout bool
}

type baseDefinition struct {
	typeName string
	hook     string
	policy   string
	priority int32
}

type nftInventory struct {
	present   bool
	sizeBytes int
	table     nftObject
	chains    map[string]nftObject
	sets      map[string]nftObject
	counters  map[string]nftObject
	rules     []nftObject
}

func newNFTInventory() *nftInventory {
	return &nftInventory{chains: make(map[string]nftObject), sets: make(map[string]nftObject), counters: make(map[string]nftObject)}
}

func (n *nftInventory) hasTable(target *Target) bool {
	return n != nil && n.present && n.table.Comment == tableComment(target.Owner)
}

func (n *nftInventory) hasChain(name string) bool {
	_, ok := n.chains[name]
	return ok
}

func (n *nftInventory) chain(name string) *nftObject {
	value, ok := n.chains[name]
	if !ok {
		return nil
	}
	return &value
}

func (n *nftInventory) hasSet(name string) bool {
	_, ok := n.sets[name]
	return ok
}

func (n *nftInventory) hasCounter(name string) bool {
	_, ok := n.counters[name]
	return ok
}

func (n *NFT) run(ctx context.Context, args []string, input []byte) ([]byte, error) {
	if n == nil || n.exec == nil {
		return nil, errors.New("nft backend is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	commandCtx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return n.exec(commandCtx, args, input)
}

func (n *NFT) listTables(ctx context.Context) ([]nftObject, error) {
	data, err := n.run(ctx, []string{"-j", "list", "tables"}, nil)
	if err != nil {
		return nil, err
	}
	return decodeNFTObjects(data)
}

func (n *NFT) listTable(ctx context.Context, table string) ([]nftObject, int, error) {
	request := map[string]any{"nftables": []any{
		map[string]any{"list": map[string]any{"table": map[string]any{"family": "inet", "name": table}}},
	}}
	input, err := json.Marshal(request)
	if err != nil {
		return nil, 0, fmt.Errorf("nft backend: encode list-table request: %w", err)
	}
	data, err := n.run(ctx, []string{"-j", "-f", "-"}, input)
	if err != nil {
		return nil, 0, err
	}
	objects, err := decodeNFTObjects(data)
	return objects, len(data), err
}

func (n *NFT) inspect(ctx context.Context, table string, targets ...*Target) (*nftInventory, error) {
	if table == "" {
		return nil, errors.New("nft backend: empty table")
	}
	tables, err := n.listTables(ctx)
	if err != nil {
		return nil, err
	}
	inventory := newNFTInventory()
	for _, object := range tables {
		if object.Kind == "table" && object.Family == "inet" && object.Name == table {
			inventory.present = true
			inventory.table = object
			break
		}
	}
	if !inventory.present {
		return inventory, nil
	}
	objects, sizeBytes, err := n.listTable(ctx, table)
	if err != nil {
		return nil, err
	}
	inventory.sizeBytes = sizeBytes
	for _, object := range objects {
		switch object.Kind {
		case "table":
			if object.Family == "inet" && object.Name == table {
				inventory.table = object
			}
		case "chain":
			if object.Family != "inet" || object.Table != table || object.Name == "" {
				return nil, errors.New("nft backend: malformed chain inventory")
			}
			inventory.chains[object.Name] = object
		case "set":
			if object.Family != "inet" || object.Table != table || object.Name == "" {
				return nil, errors.New("nft backend: malformed set inventory")
			}
			inventory.sets[object.Name] = object
		case "counter":
			if object.Family != "inet" || object.Table != table || object.Name == "" {
				return nil, errors.New("nft backend: malformed counter inventory")
			}
			inventory.counters[object.Name] = object
		case "rule":
			if object.Family != "inet" || object.Table != table || object.Chain == "" {
				return nil, errors.New("nft backend: malformed rule inventory")
			}
			inventory.rules = append(inventory.rules, object)
		case "element":
			// Elements are included in set output on supported nft versions;
			// accepting a typed element object keeps inspection forward-compatible.
		default:
			return nil, fmt.Errorf("nft backend: unsupported object %q in table inventory", object.Kind)
		}
	}
	if err := validateInventory(inventory, targets...); err != nil {
		return nil, err
	}
	return inventory, nil
}

func decodeNFTObjects(data []byte) ([]nftObject, error) {
	if len(data) == 0 || len(data) > maxNFTOutput {
		return nil, errors.New("nft backend: empty or oversized JSON output")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var envelopeMap map[string]json.RawMessage
	if err := decoder.Decode(&envelopeMap); err != nil {
		return nil, fmt.Errorf("nft backend: decode JSON: %w", err)
	}
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return nil, errors.New("nft backend: trailing JSON")
	}
	raw, ok := envelopeMap["nftables"]
	if !ok || len(envelopeMap) != 1 {
		return nil, errors.New("nft backend: missing or unknown top-level property")
	}
	var envelope []map[string]json.RawMessage
	if err := json.Unmarshal(raw, &envelope); err != nil {
		return nil, fmt.Errorf("nft backend: nftables is not an array: %w", err)
	}
	objects := make([]nftObject, 0, len(envelope))
	for _, item := range envelope {
		if len(item) == 0 {
			return nil, errors.New("nft backend: empty JSON object")
		}
		if raw, ok := item["metainfo"]; ok {
			if len(item) != 1 || len(raw) == 0 {
				return nil, errors.New("nft backend: malformed metainfo")
			}
			continue
		}
		if len(item) != 1 {
			return nil, errors.New("nft backend: ambiguous JSON object")
		}
		for kind, raw := range item {
			object, err := decodeNFTObject(kind, raw)
			if err != nil {
				return nil, err
			}
			objects = append(objects, object)
		}
	}
	return objects, nil
}

func decodeNFTObject(kind string, raw json.RawMessage) (nftObject, error) {
	var object nftObject
	object.Kind = kind
	var common struct {
		Family  string            `json:"family"`
		Table   string            `json:"table"`
		Name    string            `json:"name"`
		Chain   string            `json:"chain"`
		Comment string            `json:"comment"`
		Type    string            `json:"type"`
		Hook    string            `json:"hook"`
		Policy  string            `json:"policy"`
		Prio    json.Number       `json:"prio"`
		Expr    []json.RawMessage `json:"expr"`
		Elem    json.RawMessage   `json:"elem"`
		Flags   []string          `json:"flags"`
		Timeout json.RawMessage   `json:"timeout"`
	}
	switch kind {
	case "table", "chain", "set", "counter", "rule", "element":
	default:
		return object, fmt.Errorf("nft backend: unsupported JSON object %q", kind)
	}
	if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return object, fmt.Errorf("nft backend: null %s object", kind)
	}
	if err := json.Unmarshal(raw, &common); err != nil {
		return object, fmt.Errorf("nft backend: malformed %s: %w", kind, err)
	}
	object.Family, object.Table, object.Name, object.Chain = common.Family, common.Table, common.Name, common.Chain
	object.Comment, object.Type, object.Hook, object.Policy, object.Expr, object.Elem = common.Comment, common.Type, common.Hook, common.Policy, common.Expr, common.Elem
	object.Flags, object.Timeout = common.Flags, common.Timeout
	object.HasTimeout = common.Timeout != nil
	if common.Prio != "" {
		value, err := strconv.ParseInt(string(common.Prio), 10, 32)
		if err != nil {
			return object, fmt.Errorf("nft backend: malformed chain priority: %w", err)
		}
		object.Prio, object.HasPrio = int32(value), true
	}
	return object, nil
}

type nftDynamicElement struct {
	interval addressInterval
	ttl      time.Duration
}

func dynamicSetDefinition(target *Target, family policy.Family, name string) map[string]any {
	typeName := "ipv4_addr"
	if family == policy.IPv6 {
		typeName = "ipv6_addr"
	}
	return map[string]any{
		"family": "inet", "table": target.Table, "name": name,
		"type": typeName, "flags": []string{"interval", "timeout"},
	}
}

func dynamicSetMetadataComplete(object nftObject, family policy.Family) bool {
	typeName := "ipv4_addr"
	if family == policy.IPv6 {
		typeName = "ipv6_addr"
	}
	if object.Comment != "" || object.Type != typeName || len(object.Flags) != 2 ||
		!slices.Contains(object.Flags, "interval") || !slices.Contains(object.Flags, "timeout") {
		return false
	}
	if object.HasTimeout {
		// Dynamic leases carry their authority on each element. A set-level
		// timeout would silently expire or make elements permanent.
		return false
	}
	return true
}

func parseDynamicElement(raw json.RawMessage, family policy.Family) (nftDynamicElement, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(raw, &fields); err != nil || fields == nil || len(fields) != 1 {
		return nftDynamicElement{}, errors.New("nft backend: dynamic element is not an object")
	}
	elemRaw, ok := fields["elem"]
	if !ok {
		return nftDynamicElement{}, errors.New("nft backend: dynamic element is missing elem")
	}
	var fieldsInner map[string]json.RawMessage
	if err := json.Unmarshal(elemRaw, &fieldsInner); err != nil || fieldsInner == nil {
		return nftDynamicElement{}, errors.New("nft backend: dynamic element payload is malformed")
	}
	for key := range fieldsInner {
		if key != "val" && key != "timeout" && key != "expires" {
			return nftDynamicElement{}, fmt.Errorf("nft backend: unknown dynamic element field %q", key)
		}
	}
	valueRaw, hasValue := fieldsInner["val"]
	timeoutRaw, hasTimeout := fieldsInner["timeout"]
	expiresRaw, hasExpires := fieldsInner["expires"]
	if !hasValue || !hasTimeout || !hasExpires {
		return nftDynamicElement{}, errors.New("nft backend: dynamic element is missing timeout or expiry")
	}
	parseSeconds := func(raw json.RawMessage, label string, allowZero bool) (time.Duration, error) {
		var number json.Number
		if err := json.Unmarshal(raw, &number); err != nil {
			return 0, fmt.Errorf("nft backend: dynamic element %s is not numeric", label)
		}
		seconds, err := strconv.ParseInt(string(number), 10, 64)
		if err != nil || (!allowZero && seconds <= 0) || (allowZero && seconds < 0) || seconds > int64(24*time.Hour/time.Second) {
			return 0, fmt.Errorf("nft backend: dynamic element %s is invalid", label)
		}
		return time.Duration(seconds) * time.Second, nil
	}
	timeout, err := parseSeconds(timeoutRaw, "timeout", false)
	if err != nil {
		return nftDynamicElement{}, err
	}
	ttl, err := parseSeconds(expiresRaw, "expiry", true)
	if err != nil {
		return nftDynamicElement{}, err
	}
	if ttl > timeout {
		return nftDynamicElement{}, errors.New("nft backend: dynamic element expiry exceeds timeout")
	}
	interval, err := parseObservedInterval(valueRaw, family)
	if err != nil {
		return nftDynamicElement{}, fmt.Errorf("nft backend: malformed dynamic element: %w", err)
	}
	return nftDynamicElement{interval: interval, ttl: ttl}, nil
}

func dynamicSetCommands(target *Target, family policy.Family, observed nftObject, desired []policy.TimedPrefix, now time.Time) ([]nftCommand, error) {
	if err := ValidateDynamic(desired); err != nil {
		return nil, err
	}
	observedByInterval := make(map[addressInterval]time.Duration)
	if len(observed.Elem) != 0 {
		var rawElements []json.RawMessage
		if err := json.Unmarshal(observed.Elem, &rawElements); err != nil || rawElements == nil {
			return nil, errors.New("nft backend: dynamic set elements are malformed")
		}
		for _, raw := range rawElements {
			element, err := parseDynamicElement(raw, family)
			if err != nil {
				return nil, err
			}
			if _, exists := observedByInterval[element.interval]; exists {
				return nil, errors.New("nft backend: dynamic set contains duplicate elements")
			}
			observedByInterval[element.interval] = element.ttl
		}
	}
	var additions []any
	changed := false
	for _, desiredValue := range desired {
		if (family == policy.IPv4 && !desiredValue.Prefix.Addr().Is4()) || (family == policy.IPv6 && !desiredValue.Prefix.Addr().Is6()) {
			continue
		}
		grant, _ := LeaseGrant(desiredValue.Deadline, now, time.Second)
		if grant <= 0 {
			continue
		}
		if ttl, exists := observedByInterval[prefixInterval(desiredValue.Prefix)]; !exists || ttl != grant {
			changed = true
		}
		var value any = desiredValue.Prefix.Addr().String()
		if desiredValue.Prefix.Bits() != desiredValue.Prefix.Addr().BitLen() {
			value = prefixExpression(desiredValue.Prefix)
		}
		additions = append(additions, map[string]any{"elem": map[string]any{"val": value, "timeout": int64(grant / time.Second)}})
	}
	if !changed && len(additions) == len(observedByInterval) {
		return nil, nil
	}
	// A flush plus one grouped add commits atomically with no empty-set window.
	// Per-element deletion makes large interval-set renewals prohibitively slow,
	// and races kernel expiry. Flush only contents, retaining identity and rules.
	commands := make([]nftCommand, 0, 2)
	if len(observedByInterval) != 0 {
		commands = append(commands, nftCommand{Flush: map[string]any{"set": objectRef(target.Table, dynamicSetName(target, family))}})
	}
	if len(additions) != 0 {
		commands = append(commands, nftCommand{Add: map[string]any{"element": map[string]any{
			"family": "inet", "table": target.Table, "name": dynamicSetName(target, family), "elem": additions,
		}}})
	}
	return commands, nil
}

func validateInventory(inventory *nftInventory, targets ...*Target) error {
	if inventory == nil || !inventory.present {
		return nil
	}
	valid := make(map[string]struct{})
	chainComments := make(map[string]string)
	baseDefs := make(map[string][]baseDefinition)
	setTypes := make(map[string]string)
	dynamicSets := make(map[string]policy.Family)
	counterComments := make(map[string]string)
	ruleChains := make(map[string]string)
	var owner string
	for _, target := range targets {
		if target == nil {
			continue
		}
		if err := ValidateTarget(target); err != nil {
			return err
		}
		if owner == "" {
			owner = target.Owner
		} else if owner != target.Owner {
			return errors.New("nft backend: ownership owner mismatch")
		}
		if target.Table != inventory.table.Name {
			continue
		}
		valid["table"] = struct{}{}
		for _, value := range []policy.Direction{policy.Ingress, policy.Egress} {
			base := baseChainName(target, value)
			valid["chain/"+base] = struct{}{}
			chainComments[base] = ownershipComment(target.Owner, stableToken, baseRole(value), true)
			hook := "input"
			if value == policy.Egress {
				hook = "output"
			}
			baseDefs[base] = append(baseDefs[base], baseDefinition{typeName: "filter", hook: hook, policy: "accept", priority: target.Priority})
		}
		for _, family := range target.Families {
			for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
				entry := entryChainName(target, family.Family, direction)
				path := generationChainName(target, family.Family, direction)
				valid["chain/"+entry], valid["chain/"+path] = struct{}{}, struct{}{}
				chainComments[entry] = ownershipComment(target.Owner, stableToken, entryRole(family.Family, direction), true)
				chainComments[path] = ownershipComment(target.Owner, target.Generation, chainRole(family.Family, direction), false)
				for _, rule := range entryRules(target, family.Family, direction) {
					comment := rule["comment"].(string)
					ruleChains[comment] = entry
				}
				for _, rule := range familyPathRules(target, family, direction) {
					comment := rule["comment"].(string)
					ruleChains[comment] = path
				}
			}
			for _, set := range family.Sets {
				name := setName(target, family.Family, set.ID)
				valid["set/"+name] = struct{}{}
				if set.Kind == policy.DynamicCrowdSecSet {
					dynamicSets[name] = family.Family
				} else {
					// nft JSON does not round-trip set comments. Ownership is the
					// recorded owner/generation-qualified name inside the marked
					// table, with immutable contents and shape checked exactly.
					if observed, exists := inventory.sets[name]; exists && !setElementsComplete(observed, family.Family, set.Prefixes) {
						return fmt.Errorf("nft backend: set %q has missing or unexpected elements", name)
					}
				}
				if family.Family == policy.IPv4 {
					setTypes[name] = "ipv4_addr"
				} else {
					setTypes[name] = "ipv6_addr"
				}
			}
		}
		for _, counter := range target.Counters {
			valid["counter/"+counter.Name] = struct{}{}
			counterComments[counter.Name] = ownershipComment(target.Owner, stableToken, "counter/"+counter.Name, true)
		}
		for _, rule := range baseRules(target, policy.Ingress) {
			comment := rule["comment"].(string)
			ruleChains[comment] = baseChainName(target, policy.Ingress)
		}
		for _, rule := range baseRules(target, policy.Egress) {
			comment := rule["comment"].(string)
			ruleChains[comment] = baseChainName(target, policy.Egress)
		}
	}
	if owner != "" && inventory.table.Comment != tableComment(owner) {
		return errors.New("nft backend: table ownership collision")
	}
	for name, set := range inventory.sets {
		if _, ok := valid["set/"+name]; !ok {
			return fmt.Errorf("nft backend: unknown or foreign set %q", name)
		}
		if family, dynamic := dynamicSets[name]; dynamic {
			if !dynamicSetMetadataComplete(set, family) {
				return fmt.Errorf("nft backend: dynamic set %q has unexpected metadata", name)
			}
			if len(set.Elem) != 0 {
				var elements []json.RawMessage
				if err := json.Unmarshal(set.Elem, &elements); err != nil || elements == nil {
					return fmt.Errorf("nft backend: dynamic set %q has malformed elements", name)
				}
				for _, raw := range elements {
					if _, err := parseDynamicElement(raw, family); err != nil {
						return fmt.Errorf("nft backend: dynamic set %q: %w", name, err)
					}
				}
			}
			continue
		}
		if set.Comment != "" || len(set.Flags) != 2 || !slices.Contains(set.Flags, "constant") || !slices.Contains(set.Flags, "interval") {
			return fmt.Errorf("nft backend: set %q has unexpected metadata or flags", name)
		}
		if expected, ok := setTypes[name]; !ok || set.Type != expected {
			return fmt.Errorf("nft backend: set %q has unexpected datatype", name)
		}
	}
	for name, chain := range inventory.chains {
		if _, ok := valid["chain/"+name]; !ok {
			return fmt.Errorf("nft backend: unknown or foreign chain %q", name)
		}
		if expected, ok := chainComments[name]; !ok || chain.Comment != expected {
			return fmt.Errorf("nft backend: chain %q has foreign ownership marker", name)
		}
		if definitions, ok := baseDefs[name]; ok {
			matches := false
			for _, definition := range definitions {
				if chain.Type == definition.typeName && chain.Hook == definition.hook && chain.Policy == definition.policy && chain.HasPrio && chain.Prio == definition.priority {
					matches = true
					break
				}
			}
			if !matches {
				return fmt.Errorf("nft backend: base chain %q has unexpected hook definition", name)
			}
		} else if chain.Type != "" || chain.Hook != "" || chain.Policy != "" || chain.HasPrio {
			return fmt.Errorf("nft backend: regular chain %q is unexpectedly hooked", name)
		}
	}
	for name, counter := range inventory.counters {
		if _, ok := valid["counter/"+name]; !ok {
			return fmt.Errorf("nft backend: unknown or foreign counter %q", name)
		}
		if expected, ok := counterComments[name]; !ok || counter.Comment != expected {
			return fmt.Errorf("nft backend: counter %q has foreign ownership marker", name)
		}
	}
	for _, rule := range inventory.rules {
		if expected, ok := ruleChains[rule.Comment]; !ok || expected != rule.Chain {
			return fmt.Errorf("nft backend: unknown or foreign rule in chain %q", rule.Chain)
		}
	}
	return nil
}

func (n *NFT) probe(ctx context.Context) error {
	_, err := n.listTables(ctx)
	return err
}

// Preflight validates the typed target and inspects existing ownership before
// callers publish durable intent or mutate the kernel.
func (n *NFT) Preflight(ctx context.Context, previous, candidate *Target, dynamic *DynamicState) error {
	if err := validateDynamicState(candidate, dynamic); err != nil {
		return err
	}
	if previous == nil && candidate == nil {
		return n.probe(ctx)
	}
	if err := validateNFTCapacity(previous, candidate, dynamic); err != nil {
		return err
	}
	if err := n.probe(ctx); err != nil {
		return err
	}
	// A new table is never adopted merely because it carries our marker (or
	// happens to be empty). Only an already-recorded previous table is
	// authorized during preflight. Apply is deliberately more permissive for
	// a persisted candidate during recovery.
	if candidate != nil && (previous == nil || candidate.Table != previous.Table) {
		inventory, err := n.inspect(ctx, candidate.Table)
		if err != nil {
			return err
		}
		if inventory.present {
			return fmt.Errorf("nft backend: candidate table %q already exists without recorded authorization", candidate.Table)
		}
	}
	seen := make(map[string]struct{})
	for _, target := range []*Target{previous, candidate} {
		if target == nil {
			continue
		}
		if _, ok := seen[target.Table]; ok {
			continue
		}
		seen[target.Table] = struct{}{}
		if _, err := n.inspect(ctx, target.Table, previous, candidate); err != nil {
			return err
		}
	}
	return nil
}

// Apply switches dispatch to candidate, or removes only previous owned base
// chains when candidate is nil. All mutations for one switch use one JSON batch.
func (n *NFT) Apply(ctx context.Context, previous, candidate *Target, dynamic *DynamicState) error {
	if err := validateDynamicState(candidate, dynamic); err != nil {
		return err
	}
	if previous == nil && candidate == nil {
		return n.probe(ctx)
	}
	if err := validateNFTCapacity(previous, candidate, dynamic); err != nil {
		return err
	}
	if candidate == nil {
		if previous == nil {
			return nil
		}
		inventory, err := n.inspect(ctx, previous.Table, previous)
		if err != nil {
			return err
		}
		if !inventory.present {
			return nil
		}
		var batch nftBatch
		for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
			name := baseChainName(previous, direction)
			if inventory.hasChain(name) {
				batch.Nftables = append(batch.Nftables, nftCommand{Flush: map[string]any{"chain": objectRef(previous.Table, name)}}, nftCommand{Delete: map[string]any{"chain": objectRef(previous.Table, name)}})
			}
		}
		return n.applyBatch(ctx, batch)
	}
	inventory, err := n.inspect(ctx, candidate.Table, previous, candidate)
	if err != nil {
		return err
	}
	batch, err := commandBatch(candidate, inventory, dynamic)
	if err != nil {
		return err
	}
	return n.applyBatch(ctx, batch)
}

func encodeNFTBatch(batch nftBatch) ([]byte, error) {
	data, err := json.Marshal(batch)
	if err != nil {
		return nil, fmt.Errorf("nft backend: encode batch: %w", err)
	}
	if len(data) > maxNFTInput {
		return nil, errors.New("nft backend: batch exceeds input limit")
	}
	return data, nil
}

func (n *NFT) applyBatch(ctx context.Context, batch nftBatch) error {
	if len(batch.Nftables) == 0 {
		return nil
	}
	data, err := encodeNFTBatch(batch)
	if err != nil {
		return err
	}
	_, err = n.run(ctx, []string{"-j", "-f", "-"}, data)
	return err
}

// UpdateDynamic reconciles only the exact dynamic containers recorded by
// target. Static sets, generations, chains, and dispatch hooks are not part of
// this transaction.
func (n *NFT) UpdateDynamic(ctx context.Context, target *Target, desired []policy.TimedPrefix) error {
	if target == nil {
		return errors.New("nft backend: dynamic update requires a target")
	}
	if err := validateNFTTarget(target); err != nil {
		return err
	}
	if target.DynamicGeneration == "" {
		return errors.New("nft backend: dynamic update requires a dynamic generation")
	}
	if err := ValidateDynamic(desired); err != nil {
		return err
	}
	inventory, err := n.inspect(ctx, target.Table, target)
	if err != nil {
		return err
	}
	if !inventory.present {
		return errors.New("nft backend: dynamic table is absent")
	}
	now := time.Now()
	var batch nftBatch
	retainedBytes := inventory.sizeBytes
	for _, familyPlan := range target.Families {
		for _, set := range familyPlan.Sets {
			if set.Kind != policy.DynamicCrowdSecSet {
				continue
			}
			name := setName(target, familyPlan.Family, set.ID)
			observed, exists := inventory.sets[name]
			if !exists {
				batch.Nftables = append(batch.Nftables, nftCommand{Add: map[string]any{"set": dynamicSetDefinition(target, familyPlan.Family, name)}})
			}
			commands, err := dynamicSetCommands(target, familyPlan.Family, observed, desired, now)
			if err != nil {
				return err
			}
			if len(commands) != 0 {
				// A changed set is atomically replaced. Retain all other native
				// contents, but do not count its old and new elements together.
				retainedBytes -= len(observed.Elem)
			}
			batch.Nftables = append(batch.Nftables, commands...)
		}
	}
	if len(batch.Nftables) == 0 {
		return nil
	}
	data, err := encodeNFTBatch(batch)
	if err != nil {
		return err
	}
	if retainedBytes+nftInspectionBudget(len(data), len(batch.Nftables)) > maxNFTInventoryBudget {
		return errors.New("nft backend: combined static and dynamic contents exceed inspection capacity")
	}
	_, err = n.run(ctx, []string{"-j", "-f", "-"}, data)
	return err
}

// Retire removes only recorded objects no longer referenced by candidate. A
// migrated table is deleted only after its complete ownership inventory was
// validated.
func (n *NFT) Retire(ctx context.Context, previous, candidate *Target) error {
	for _, target := range []*Target{previous, candidate} {
		if err := validateNFTTarget(target); err != nil {
			return err
		}
	}
	// A nil candidate is the committed empty-state retirement. A nil previous
	// means a first installation has no obsolete ownership and must be kept.
	if previous == nil && candidate == nil {
		return nil
	}
	if previous == nil {
		return nil
	}
	if candidate == nil {
		return n.retireSingle(ctx, previous)
	}
	if previous.Table != candidate.Table {
		inventory, err := n.inspect(ctx, previous.Table, previous)
		if err != nil {
			return err
		}
		if !inventory.present {
			return nil
		}
		return n.applyBatch(ctx, nftBatch{Nftables: []nftCommand{{Delete: map[string]any{"table": map[string]any{"family": "inet", "name": previous.Table}}}}})
	}
	inventory, err := n.inspect(ctx, previous.Table, previous, candidate)
	if err != nil {
		return err
	}
	if !inventory.present {
		return nil
	}
	var batch nftBatch
	candidateChains, candidateSets := make(map[string]struct{}), make(map[string]struct{})
	for _, family := range candidate.Families {
		for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
			candidateChains[entryChainName(candidate, family.Family, direction)] = struct{}{}
			candidateChains[generationChainName(candidate, family.Family, direction)] = struct{}{}
		}
		for _, set := range family.Sets {
			candidateSets[setName(candidate, family.Family, set.ID)] = struct{}{}
		}
	}
	candidateCounters := make(map[string]struct{}, len(candidate.Counters))
	for _, counter := range candidate.Counters {
		candidateCounters[counter.Name] = struct{}{}
	}
	// First detach and remove obsolete stable entries. Their jumps are the
	// references that otherwise keep old generation chains busy (EBUSY).
	for _, family := range previous.Families {
		for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
			name := entryChainName(previous, family.Family, direction)
			if _, keep := candidateChains[name]; keep {
				continue
			}
			if inventory.hasChain(name) {
				batch.Nftables = append(batch.Nftables,
					nftCommand{Flush: map[string]any{"chain": objectRef(previous.Table, name)}},
					nftCommand{Delete: map[string]any{"chain": objectRef(previous.Table, name)}},
				)
			}
		}
	}
	// Generation chains can now be deleted without a stable entry reference.
	for _, family := range previous.Families {
		for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
			name := generationChainName(previous, family.Family, direction)
			if _, keep := candidateChains[name]; keep {
				continue
			}
			if inventory.hasChain(name) {
				batch.Nftables = append(batch.Nftables,
					nftCommand{Flush: map[string]any{"chain": objectRef(previous.Table, name)}},
					nftCommand{Delete: map[string]any{"chain": objectRef(previous.Table, name)}},
				)
			}
		}
	}
	for _, family := range previous.Families {
		for _, set := range family.Sets {
			name := setName(previous, family.Family, set.ID)
			if _, keep := candidateSets[name]; keep {
				continue
			}
			if inventory.hasSet(name) {
				batch.Nftables = append(batch.Nftables, nftCommand{Delete: map[string]any{"set": objectRef(previous.Table, name)}})
			}
		}
	}
	for _, counter := range previous.Counters {
		if _, keep := candidateCounters[counter.Name]; keep {
			continue
		}
		if inventory.hasCounter(counter.Name) {
			batch.Nftables = append(batch.Nftables, nftCommand{Delete: map[string]any{"counter": objectRef(previous.Table, counter.Name)}})
		}
	}
	return n.applyBatch(ctx, batch)
}

func (n *NFT) retireSingle(ctx context.Context, target *Target) error {
	if target == nil {
		return nil
	}
	inventory, err := n.inspect(ctx, target.Table, target)
	if err != nil {
		return err
	}
	if !inventory.present {
		return nil
	}
	return n.applyBatch(ctx, nftBatch{Nftables: []nftCommand{{Delete: map[string]any{"table": map[string]any{"family": "inet", "name": target.Table}}}}})
}

// Cleanup removes recorded owned tables only after validating every observed
// child against the complete union of recorded targets.
func (n *NFT) Cleanup(ctx context.Context, targets []*Target) error {
	if len(targets) == 0 {
		return nil
	}
	byTable := make(map[string][]*Target)
	for _, target := range targets {
		if target == nil {
			continue
		}
		if err := validateNFTTarget(target); err != nil {
			return err
		}
		byTable[target.Table] = append(byTable[target.Table], target)
	}
	var batch nftBatch
	for table, values := range byTable {
		inventory, err := n.inspect(ctx, table, values...)
		if err != nil {
			return err
		}
		if !inventory.present {
			continue
		}
		batch.Nftables = append(batch.Nftables, nftCommand{Delete: map[string]any{"table": map[string]any{"family": "inet", "name": table}}})
	}
	return n.applyBatch(ctx, batch)
}
