package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
)

const (
	maxNFTOutput          = 64 << 20
	maxNFTInput           = 8 << 20
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
	if len(input) > maxNFTInput {
		return nil, fmt.Errorf("nft input exceeds %d bytes", maxNFTInput)
	}
	// #nosec G204 -- executable is fixed to nft; configured identifiers are marshaled as JSON, never raw nft DSL.
	cmd := exec.CommandContext(ctx, "nft", args...)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr boundedBuffer
	stdout.limit, stderr.limit = maxNFTOutput, maxNFTOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		message := strings.TrimSpace(stderr.String())
		if message != "" {
			return nil, fmt.Errorf("nft %s: %w: %s", strings.Join(args, " "), err, message)
		}
		return nil, fmt.Errorf("nft %s: %w", strings.Join(args, " "), err)
	}
	return stdout.Bytes(), nil
}

type boundedBuffer struct {
	buffer bytes.Buffer
	limit  int
}

func (b *boundedBuffer) Write(value []byte) (int, error) {
	if len(value) > b.limit-b.buffer.Len() {
		return 0, fmt.Errorf("nft output exceeds %d bytes", b.limit)
	}
	return b.buffer.Write(value)
}

// Do not embed bytes.Buffer: its promoted ReadFrom bypasses Write when
// os/exec copies a pipe through io.Copy.
func (b *boundedBuffer) Bytes() []byte  { return b.buffer.Bytes() }
func (b *boundedBuffer) String() string { return b.buffer.String() }

// validateNFTCapacity bounds the complete recoverable state, not just an
// incremental switch. Native JSON adds handles, counter values and whitespace;
// allow twice the encoded full installation plus 1 KiB per object for that
// expansion, with another 16 MiB of capture headroom. Prefixes can become host
// strings or merged ranges, neither larger than this allowance. Sum both full
// generations in each table because they coexist until durable retirement.
func validateNFTCapacity(targets ...*Target) error {
	budgets := make(map[string]int)
	for _, target := range targets {
		if target == nil {
			continue
		}
		batch, err := commandBatch(target, nil, nil)
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
		budgets[target.Table] += 2*len(data) + 1024*len(batch.Nftables) + 4096
		if budgets[target.Table] > maxNFTInventoryBudget {
			return errors.New("nft backend: retained generations exceed inspection capacity")
		}
	}
	return nil
}

type nftObject struct {
	Kind    string
	Family  string
	Table   string
	Name    string
	Chain   string
	Comment string
	Type    string
	Hook    string
	Policy  string
	Prio    int32
	HasPrio bool
	Expr    []json.RawMessage
	Elem    json.RawMessage
	Flags   []string
}

type baseDefinition struct {
	typeName string
	hook     string
	policy   string
	priority int32
}

type nftInventory struct {
	present  bool
	table    nftObject
	chains   map[string]nftObject
	sets     map[string]nftObject
	counters map[string]nftObject
	rules    []nftObject
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

func (n *NFT) listTable(ctx context.Context, table string) ([]nftObject, error) {
	request := map[string]any{"nftables": []any{
		map[string]any{"list": map[string]any{"table": map[string]any{"family": "inet", "name": table}}},
	}}
	input, err := json.Marshal(request)
	if err != nil {
		return nil, fmt.Errorf("nft backend: encode list-table request: %w", err)
	}
	data, err := n.run(ctx, []string{"-j", "-f", "-"}, input)
	if err != nil {
		return nil, err
	}
	return decodeNFTObjects(data)
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
	objects, err := n.listTable(ctx, table)
	if err != nil {
		return nil, err
	}
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
	object.Flags = common.Flags
	if common.Prio != "" {
		value, err := strconv.ParseInt(string(common.Prio), 10, 32)
		if err != nil {
			return object, fmt.Errorf("nft backend: malformed chain priority: %w", err)
		}
		object.Prio, object.HasPrio = int32(value), true
	}
	return object, nil
}

func validateInventory(inventory *nftInventory, targets ...*Target) error {
	if inventory == nil || !inventory.present {
		return nil
	}
	valid := make(map[string]struct{})
	chainComments := make(map[string]string)
	baseDefs := make(map[string][]baseDefinition)
	setTypes := make(map[string]string)
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
				// nft JSON does not round-trip set comments. Ownership is the
				// recorded owner/generation-qualified name inside the marked
				// table, with immutable contents and shape checked exactly.
				if observed, exists := inventory.sets[name]; exists && !setElementsComplete(observed, family.Family, set.Prefixes) {
					return fmt.Errorf("nft backend: set %q has missing or unexpected elements", name)
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
	for name, set := range inventory.sets {
		if _, ok := valid["set/"+name]; !ok {
			return fmt.Errorf("nft backend: unknown or foreign set %q", name)
		}
		if set.Comment != "" || len(set.Flags) != 2 || !slices.Contains(set.Flags, "constant") || !slices.Contains(set.Flags, "interval") {
			return fmt.Errorf("nft backend: set %q has unexpected metadata or flags", name)
		}
		if expected, ok := setTypes[name]; !ok || set.Type != expected {
			return fmt.Errorf("nft backend: set %q has unexpected datatype", name)
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
func (n *NFT) Preflight(ctx context.Context, previous, candidate *Target) error {
	if previous == nil && candidate == nil {
		return n.probe(ctx)
	}
	if err := validateNFTCapacity(previous, candidate); err != nil {
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
func (n *NFT) Apply(ctx context.Context, previous, candidate *Target) error {
	if previous == nil && candidate == nil {
		return n.probe(ctx)
	}
	if err := validateNFTCapacity(previous, candidate); err != nil {
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
	batch, err := commandBatch(candidate, inventory, previous)
	if err != nil {
		return err
	}
	return n.applyBatch(ctx, batch)
}

func (n *NFT) applyBatch(ctx context.Context, batch nftBatch) error {
	if len(batch.Nftables) == 0 {
		return nil
	}
	data, err := json.Marshal(batch)
	if err != nil {
		return fmt.Errorf("nft backend: encode batch: %w", err)
	}
	if len(data) > maxNFTInput {
		return errors.New("nft backend: batch exceeds input limit")
	}
	_, err = n.run(ctx, []string{"-j", "-f", "-"}, data)
	return err
}

// Retire removes only recorded objects no longer referenced by candidate. A
// migrated table is deleted only after its complete ownership inventory was
// validated.
func (n *NFT) Retire(ctx context.Context, previous, candidate *Target) error {
	for _, target := range []*Target{previous, candidate} {
		if err := ValidateTarget(target); err != nil {
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
		if err := ValidateTarget(target); err != nil {
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
