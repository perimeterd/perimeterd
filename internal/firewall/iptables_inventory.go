package firewall

import (
	"context"
	"errors"
	"fmt"
	"iter"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
)

// iptChainKey keeps kernel namespaces explicit throughout parsing, ownership
// validation, and mutation. Table always retains its native name.
type iptChainKey struct {
	Family policy.Family
	Table  string
	Chain  string
}

func (k iptChainKey) String() string {
	return fmt.Sprintf("%s/%s/%s", familyName(k.Family), k.Table, k.Chain)
}

func (k iptChainKey) withChain(name string) iptChainKey {
	k.Chain = name
	return k
}

type iptObservedRule struct {
	iptChainKey
	Args       []string
	Packets    uint64
	Bytes      uint64
	References []iptRuleReference
}

type iptReferenceKind uint8

const (
	iptJumpReference iptReferenceKind = iota
	iptSetReference
	iptCommentReference
)

type iptRuleReference struct {
	Kind  iptReferenceKind
	Value string
}

func (r iptObservedRule) references(kind iptReferenceKind) iter.Seq[string] {
	return func(yield func(string) bool) {
		for _, reference := range r.References {
			if reference.Kind == kind && !yield(reference.Value) {
				return
			}
		}
	}
}

type (
	iptObservedChain struct {
		iptChainKey
		Rules []iptObservedRule
	}
	iptObservedSet struct {
		Name, Type, Family string
		Options            []string
		Entries            []string
		Timeouts           map[string]uint64
		Extended           bool
		UnknownOptions     bool
		References         uint64
		InspectionBytes    int
	}
)

type iptInventory struct {
	Chains     map[iptChainKey]iptObservedChain
	Sets       map[string]iptObservedSet
	Rules      []iptObservedRule
	TableBytes map[policy.Family]int
	SetBytes   int
}

func newIPTInventory() *iptInventory {
	return &iptInventory{Chains: make(map[iptChainKey]iptObservedChain), Sets: make(map[string]iptObservedSet), TableBytes: make(map[policy.Family]int)}
}

func familyName(family policy.Family) string {
	if family == policy.IPv4 {
		return "v4"
	}
	return "v6"
}

func familySetName(family policy.Family) string {
	if family == policy.IPv4 {
		return "inet"
	}
	return "inet6"
}

func chainKey(family policy.Family, name string) iptChainKey {
	return iptChainKey{Family: family, Table: "filter", Chain: name}
}

func (i *IPTables) inspect(ctx context.Context, expectedSets map[string]iptSet) (*iptInventory, error) {
	result := newIPTInventory()
	for _, family := range []policy.Family{policy.IPv4, policy.IPv6} {
		output, err := i.run(ctx, familyTool(family, "-save"), []string{"--counters"}, nil)
		if err != nil {
			return nil, err
		}
		result.TableBytes[family] = len(output)
		parsed, err := parseIPTablesSave(family, output)
		if err != nil {
			return nil, fmt.Errorf("%s save: %w", familyName(family), err)
		}
		for key, chain := range parsed.Chains {
			result.Chains[key] = chain
		}
		result.Rules = append(result.Rules, parsed.Rules...)
	}
	if err := i.inspectSets(ctx, expectedSets, result); err != nil {
		return nil, err
	}
	return result, nil
}

func (i *IPTables) inspectSets(ctx context.Context, expected map[string]iptSet, inventory *iptInventory) error {
	if len(expected) == 0 {
		return ctx.Err()
	}
	for name, set := range expected {
		// Generated set names occupy all 31 bytes available in the kernel.
		// A foreign name containing a newline cannot forge such a complete
		// census line: the name plus newline would exceed that native limit.
		if len(name) != maxIPTSetNameBytes || name != set.Name {
			return errors.New("invalid recorded ipset identity")
		}
		if err := validateIPTablesIdentifier(name, "set", maxIPTSetNameBytes, false); err != nil {
			return err
		}
	}
	// Discover only exact identities, without interpreting foreign names or
	// definitions. Native global save does not quote arbitrary set names.
	names, err := i.run(ctx, "ipset", []string{"list", "-name"}, nil)
	if err != nil {
		return err
	}
	for line := range strings.Lines(string(names)) {
		name := strings.TrimSuffix(line, "\n")
		if _, wanted := expected[name]; !wanted {
			continue
		}
		if _, duplicate := inventory.Sets[name]; duplicate {
			return errors.New("duplicate recorded ipset in name census")
		}
		output, err := i.run(ctx, "ipset", []string{"save", name}, nil)
		if err != nil {
			// A disappeared set or any command failure remains an error, not
			// permission to adopt, overwrite, or forget recorded ownership.
			return err
		}
		if len(output) > maxIPTablesOutput-inventory.SetBytes {
			return errors.New("recorded ipsets exceed inspection limit")
		}
		sets, err := parseIPSetSave(output)
		if err != nil {
			return err
		}
		observed, exists := sets[name]
		if !exists || len(sets) != 1 {
			return errors.New("ipset query returned an unexpected identity")
		}
		header, err := i.run(ctx, "ipset", []string{"list", name, "-output", "xml", "-terse"}, nil)
		if err != nil {
			return err
		}
		if len(header) > maxIPTablesOutput-inventory.SetBytes-len(output) {
			return errors.New("recorded ipsets exceed inspection limit")
		}
		observed.References, err = parseIPSetReferences(header, name)
		if err != nil {
			return err
		}
		observed.InspectionBytes = len(output) + len(header)
		inventory.SetBytes += observed.InspectionBytes
		inventory.Sets[name] = observed
	}
	return nil
}

func targetFamilies(target *Target) (map[policy.Family]iptFamilyModel, error) {
	result := make(map[policy.Family]iptFamilyModel)
	if target == nil {
		return result, nil
	}
	if target.IPTables == nil {
		return nil, errors.New("target does not select iptables")
	}
	if err := ValidateTarget(target); err != nil {
		return nil, err
	}
	for _, family := range target.Families {
		model, err := buildIPTFamily(target, family.Family)
		if err != nil {
			return nil, err
		}
		result[family.Family] = model
	}
	return result, nil
}

type iptExpected struct {
	chains  map[iptChainKey][]iptChain
	sets    map[string]iptSet
	parents map[iptChainKey][]iptRule
	owners  map[string]bool
	models  map[*Target]map[policy.Family]iptFamilyModel
	rules   map[iptChainKey]map[string]bool
}

func expectedIPT(targets ...*Target) (*iptExpected, error) {
	result := &iptExpected{chains: make(map[iptChainKey][]iptChain), sets: make(map[string]iptSet), parents: make(map[iptChainKey][]iptRule), owners: make(map[string]bool), models: make(map[*Target]map[policy.Family]iptFamilyModel), rules: make(map[iptChainKey]map[string]bool)}
	for _, target := range targets {
		if target == nil {
			continue
		}
		if _, exists := result.models[target]; exists {
			continue
		}
		result.owners[target.Owner] = true
		models, err := targetFamilies(target)
		if err != nil {
			return nil, err
		}
		result.models[target] = models
		for family, model := range models {
			for _, chains := range [][]iptChain{model.Staging, model.Active} {
				for _, chain := range chains {
					key := chainKey(family, chain.Name)
					result.chains[key] = append(result.chains[key], chain)
					for _, rule := range chain.Rules {
						result.addRule(key, rule.Args)
					}
				}
			}
			for _, set := range model.Sets {
				if old, exists := result.sets[set.Name]; exists && (old.Family != set.Family || old.Dynamic != set.Dynamic || (!set.Dynamic && !slices.Equal(old.Prefixes, set.Prefixes))) {
					return nil, errors.New("conflicting recorded ipset definitions")
				}
				result.sets[set.Name] = set
				if set.Dynamic {
					spare := set
					spare.Name = iptDynamicSpareName(set.Name)
					result.sets[spare.Name] = spare
				}
			}
			for _, attachment := range model.Attachments {
				key := chainKey(family, attachment.Parent)
				result.parents[key] = append(result.parents[key], attachment.Rule)
				result.addRule(key, attachment.Rule.Args)
			}
		}
	}
	return result, nil
}

func (e *iptExpected) addRule(chain iptChainKey, args []string) {
	if e.rules[chain] == nil {
		e.rules[chain] = make(map[string]bool)
	}
	e.rules[chain][iptRuleKey(args)] = true
}

func matchesIPTExpected(rule iptObservedRule, expected *iptExpected) bool {
	rules := expected.rules[rule.iptChainKey]
	return len(rules) != 0 && rules[iptRuleKey(rule.Args)]
}

func validateIPTInventory(inventory *iptInventory, expected *iptExpected) error {
	references := make(map[string]uint64, len(expected.sets))
	for _, rule := range inventory.Rules {
		known := matchesIPTExpected(rule, expected)
		if _, owned := expected.chains[rule.iptChainKey]; owned && !known {
			return fmt.Errorf("owned chain %s contains an unexpected rule", rule.Chain)
		}
		for name := range rule.references(iptJumpReference) {
			if _, owned := expected.chains[rule.withChain(name)]; owned && !known {
				return errors.New("unrecorded reference to owned chain")
			}
		}
		for name := range rule.references(iptSetReference) {
			if _, owned := expected.sets[name]; owned {
				if !known {
					return errors.New("unrecorded reference to owned set")
				}
				references[name]++
			}
		}
		for comment := range rule.references(iptCommentReference) {
			for owner := range expected.owners {
				if strings.Contains(comment, "owner="+owner) && !known {
					return errors.New("unrecorded owned rule marker")
				}
			}
		}
	}
	for name, want := range expected.sets {
		observed, exists := inventory.Sets[name]
		if !exists {
			continue
		}
		if observed.References != references[name] {
			return fmt.Errorf("owned set %s has inconsistent native references: kernel=%d recorded=%d", name, observed.References, references[name])
		}
		if observed.Type != "hash:net" || observed.Family != familySetName(want.Family) {
			return fmt.Errorf("unexpected owned set shape: %s", name)
		}
		if !want.Dynamic {
			if observed.Extended {
				return fmt.Errorf("unexpected owned set shape: %s", name)
			}
			for n := 0; n < len(observed.Options); n += 2 {
				if n+1 == len(observed.Options) || !slices.Contains([]string{"family", "hashsize", "maxelem", "bucketsize", "initval"}, observed.Options[n]) {
					return fmt.Errorf("unexpected owned set option: %s", name)
				}
			}
		} else {
			hasDefaultTimeout := false
			for n := 0; n < len(observed.Options); n += 2 {
				if n+1 == len(observed.Options) || !slices.Contains([]string{"family", "hashsize", "maxelem", "bucketsize", "initval", "timeout"}, observed.Options[n]) {
					return fmt.Errorf("unexpected owned set option: %s", name)
				}
				if observed.Options[n] == "timeout" {
					timeout, err := strconv.ParseUint(observed.Options[n+1], 10, 64)
					if err != nil || timeout != uint64(maximumLease/time.Second) {
						return fmt.Errorf("dynamic set has an unsafe default timeout: %s", name)
					}
					hasDefaultTimeout = true
				}
			}
			if !hasDefaultTimeout {
				return fmt.Errorf("dynamic set has no finite default timeout: %s", name)
			}
			if _, err := ipsetCapacity(observed); err != nil {
				return fmt.Errorf("dynamic set %s: %w", name, err)
			}
			if observed.UnknownOptions {
				return fmt.Errorf("unexpected dynamic set entry metadata: %s", name)
			}
			for _, entry := range observed.Entries {
				if timeout, exists := observed.Timeouts[entry]; !exists || timeout == 0 ||
					timeout > uint64(maximumLease/time.Second) {
					return fmt.Errorf("dynamic set entry has no finite timeout: %s", name)
				}
				prefix, err := netip.ParsePrefix(entry)
				if err != nil || (want.Family == policy.IPv4 && !prefix.Addr().Is4()) ||
					(want.Family == policy.IPv6 && !prefix.Addr().Is6()) {
					return fmt.Errorf("unexpected dynamic set element: %s", name)
				}
			}
			continue
		}
		prefixes := make(map[string]bool, len(want.Prefixes))
		for _, prefix := range want.Prefixes {
			prefixes[prefix.String()] = true
		}
		for _, entry := range observed.Entries {
			if !prefixes[entry] {
				return fmt.Errorf("unexpected owned set element: %s", name)
			}
			delete(prefixes, entry)
		}
		// An interrupted restore can leave an authorized, unreferenced staging
		// set incomplete. Stage can finish it and cleanup can discard it.
		if len(prefixes) != 0 && observed.References != 0 {
			return fmt.Errorf("owned set is missing expected elements: %s", name)
		}
	}
	return nil
}

func observedAttachment(inventory *iptInventory, family policy.Family, attachment iptAttachment) bool {
	for _, rule := range inventory.Chains[chainKey(family, attachment.Parent)].Rules {
		if sameIPTRule(rule.Args, attachment.Rule.Args) {
			return true
		}
	}
	return false
}

func hasIPTAttachment(attachments []iptAttachment, want iptAttachment) bool {
	for _, value := range attachments {
		if value.Parent == want.Parent && sameIPTRule(value.Rule.Args, want.Rule.Args) {
			return true
		}
	}
	return false
}

func referencedSet(inventory *iptInventory, name string) bool {
	for _, rule := range inventory.Rules {
		for reference := range rule.references(iptSetReference) {
			if reference == name {
				return true
			}
		}
	}
	return false
}

func referencedChain(inventory *iptInventory, family policy.Family, name string) bool {
	for _, rule := range inventory.Rules {
		if rule.Family != family || rule.Table != "filter" {
			continue
		}
		for reference := range rule.references(iptJumpReference) {
			if reference == name {
				return true
			}
		}
	}
	return false
}

func sameObservedChain(observed iptObservedChain, want iptChain) bool {
	if len(observed.Rules) != len(want.Rules) {
		return false
	}
	for n := range want.Rules {
		if !sameIPTRule(observed.Rules[n].Args, want.Rules[n].Args) {
			return false
		}
	}
	return true
}

// inspectTargets validates ownership without requiring attachment parents to
// exist. Teardown must also work after a parent administrator removes its chain.
func (i *IPTables) inspectTargets(ctx context.Context, expected *iptExpected) (*iptInventory, error) {
	if err := i.probe(ctx); err != nil {
		return nil, err
	}
	inventory, err := i.inspect(ctx, expected.sets)
	if err != nil {
		return nil, err
	}
	if err := validateIPTInventory(inventory, expected); err != nil {
		return nil, err
	}
	return inventory, nil
}

func (i *IPTables) preflightTargets(ctx context.Context, expected *iptExpected, candidate *Target) (*iptInventory, error) {
	inventory, err := i.inspectTargets(ctx, expected)
	if err != nil {
		return nil, err
	}
	// Only attachments being installed require parents. Previous-only
	// attachments may already be absent during removal or migration recovery.
	for family, model := range expected.models[candidate] {
		for _, attachment := range model.Attachments {
			key := chainKey(family, attachment.Parent)
			if _, exists := inventory.Chains[key]; !exists && !slices.Contains([]string{"INPUT", "OUTPUT", "FORWARD"}, attachment.Parent) {
				return nil, fmt.Errorf("configured parent chain does not exist: %s", key)
			}
			// Built-in chains exist logically even when an nf_tables compatibility
			// table has not yet been materialized. Restore creates only these defaults.
		}
	}
	return inventory, nil
}

func ipsetInspectionSize(set iptSet) int {
	size := 1024 // Save definition plus the terse XML header.
	entryOverhead := len(set.Name) + 6
	var buffer [64]byte
	if set.Dynamic {
		entryOverhead += len(" timeout ") + len(strconv.AppendUint(buffer[:0], uint64(maximumLease/time.Second), 10))
	}
	for _, prefix := range set.Prefixes {
		size += entryOverhead + len(prefix.AppendTo(buffer[:0]))
	}
	return size
}

// Leave capture headroom for counters and native formatting. Budget the full
// rule inventories and recorded sets so staging cannot prevent later inspection.
func validateIPTCapacity(inventory *iptInventory, expected *iptExpected) error {
	const budget = 48 << 20
	setBytes := inventory.SetBytes
	tableBytes := map[policy.Family]int{policy.IPv4: inventory.TableBytes[policy.IPv4], policy.IPv6: inventory.TableBytes[policy.IPv6]}
	chainSize := func(chain iptChain) int {
		size := len(chain.Name) + 64
		for _, rule := range chain.Rules {
			size += len(chain.Name) + 128
			for _, arg := range rule.Args {
				size += len(arg) + 3
			}
		}
		return size
	}
	for name, set := range expected.sets {
		observed, exists := inventory.Sets[name]
		current := observed.InspectionBytes
		if set.Dynamic {
			spare := iptDynamicSpareName(name)
			if name == spare {
				continue // Accounted together with the live set.
			}
			current += inventory.Sets[spare].InspectionBytes
			if !set.DynamicProjection {
				if !exists {
					setBytes += ipsetInspectionSize(set)
				}
				continue
			}
		}
		planned := ipsetInspectionSize(set)
		if set.Dynamic && exists {
			capacity, err := ipsetCapacity(observed)
			if err != nil {
				return err
			}
			if len(set.Prefixes) > capacity {
				// Only resizing holds old live contents alongside a populated
				// spare. An existing spare is destroyed before either operation.
				planned += observed.InspectionBytes
			}
		}
		// In-place updates delete obsolete entries before adding replacements.
		// Static partial staging likewise fills one set, not a second copy.
		setBytes += max(0, planned-current)
	}
	for key, chains := range expected.chains {
		size := 0
		for _, chain := range chains {
			size = max(size, chainSize(chain))
		}
		tableBytes[key.Family] += size
	}
	for _, models := range expected.models {
		for _, model := range models {
			rules := 4096
			for _, chains := range [][]iptChain{model.Staging, model.Active} {
				for _, chain := range chains {
					rules += chainSize(chain)
				}
			}
			for _, attachment := range model.Attachments {
				rules += chainSize(iptChain{Name: attachment.Parent, Rules: []iptRule{attachment.Rule}})
			}
			if rules > maxIPTablesInput {
				return errors.New("iptables complete family exceeds input budget")
			}
		}
	}
	if setBytes > budget || tableBytes[policy.IPv4] > budget || tableBytes[policy.IPv6] > budget {
		return errors.New("iptables retained generations exceed inspection budget")
	}
	return nil
}
