package firewall

import (
	"context"
	"errors"
	"fmt"
	"math"
	"net/netip"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
)

const (
	maxIPTablesInput  = 16 << 20
	maxIPTablesOutput = 64 << 20
	maxIPTablesTime   = 30 * time.Second
)

type iptablesExecutor func(context.Context, string, []string, []byte) ([]byte, error)

// IPTables stages immutable generations before selecting them independently in
// IPv4 and IPv6. The durable journal, not observed rules, authorizes recovery.
type IPTables struct {
	exec     iptablesExecutor
	progress FamilyProgress
	mu       sync.Mutex
	variant  string
}

// NewIPTables uses a matched native tool family from PATH and reports selections
// after successful family switches, including compensation and unhooking.
func NewIPTables(progress FamilyProgress) *IPTables {
	return &IPTables{exec: nativeIPTablesExecutor, progress: progress}
}

func nativeIPTablesExecutor(ctx context.Context, command string, args []string, input []byte) ([]byte, error) {
	return executeNative(ctx, command, args, input, maxIPTablesInput, maxIPTablesOutput)
}

func (i *IPTables) run(ctx context.Context, command string, args []string, input []byte) ([]byte, error) {
	if i == nil || i.exec == nil {
		return nil, errors.New("iptables backend is not initialized")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if len(input) > maxIPTablesInput {
		return nil, errors.New("iptables input exceeds limit")
	}
	callCtx, cancel := context.WithTimeout(ctx, maxIPTablesTime)
	defer cancel()
	return i.exec(callCtx, command, args, input)
}

func parseIPTablesVariant(value []byte) (string, error) {
	text := string(value)
	nft, legacy := strings.Contains(text, "(nf_tables)"), strings.Contains(text, "(legacy)")
	if nft == legacy {
		return "", errors.New("version does not identify exactly one implementation")
	}
	if nft {
		return "nf_tables", nil
	}
	return "legacy", nil
}

func (i *IPTables) probe(ctx context.Context) error {
	var variant string
	for _, command := range []string{"iptables", "ip6tables", "iptables-save", "ip6tables-save", "iptables-restore", "ip6tables-restore"} {
		output, err := i.run(ctx, command, []string{"--version"}, nil)
		if err != nil {
			return err
		}
		kind, err := parseIPTablesVariant(output)
		if err != nil {
			return fmt.Errorf("%s: %w", command, err)
		}
		if variant != "" && kind != variant {
			return errors.New("iptables tools use different implementations")
		}
		variant = kind
	}
	if _, err := i.run(ctx, "ipset", []string{"--version"}, nil); err != nil {
		return err
	}
	i.mu.Lock()
	defer i.mu.Unlock()
	if i.variant != "" && i.variant != variant {
		return errors.New("iptables implementation changed during ownership")
	}
	i.variant = variant
	return nil
}

func familyTool(family policy.Family, suffix string) string {
	if family == policy.IPv4 {
		return "iptables" + suffix
	}
	return "ip6tables" + suffix
}

func (i *IPTables) restore(ctx context.Context, family policy.Family, lines []string) error {
	if len(lines) == 0 {
		return ctx.Err()
	}
	input := []byte("*filter\n" + strings.Join(lines, "\n") + "\nCOMMIT\n")
	_, err := i.run(ctx, familyTool(family, "-restore"), []string{"--wait", "--noflush"}, input)
	return err
}

// Preflight checks tool compatibility, ownership, parents, and recovery capacity
// before the writer publishes durable intent.
func (i *IPTables) Preflight(ctx context.Context, previous, candidate *Target, dynamic *DynamicState) error {
	if err := validateDynamicState(candidate, dynamic); err != nil {
		return err
	}
	if previous == nil && candidate == nil {
		return ctx.Err()
	}
	expected, err := expectedIPTWithProjection(dynamic, previous, candidate)
	if err != nil {
		return err
	}
	inventory, err := i.preflightTargets(ctx, expected, candidate)
	if err != nil {
		return err
	}
	if err := validateIPTCapacity(inventory, expected); err != nil {
		return err
	}
	// Before Prepare, candidate-only names have no durable authorization.
	if candidate != nil {
		old, err := expectedIPTWithProjection(nil, previous)
		if err != nil {
			return err
		}
		next, err := expectedIPTWithProjection(dynamic, candidate)
		if err != nil {
			return err
		}
		for key := range next.chains {
			if _, authorized := old.chains[key]; !authorized {
				if _, exists := inventory.Chains[key]; exists {
					return fmt.Errorf("unrecorded candidate chain collision: %s", key)
				}
			}
		}
		for name := range next.sets {
			if _, authorized := old.sets[name]; !authorized {
				if _, exists := inventory.Sets[name]; exists {
					return fmt.Errorf("unrecorded candidate set collision: %s", name)
				}
			}
		}
	}
	return nil
}

func observedSetEntries(set iptObservedSet) map[string]struct{} {
	result := make(map[string]struct{}, len(set.Entries))
	for _, entry := range set.Entries {
		result[entry] = struct{}{}
	}
	return result
}

func ipsetCapacity(set iptObservedSet) (int, error) {
	capacity := 0
	for n := 0; n+1 < len(set.Options); n += 2 {
		if set.Options[n] != "maxelem" {
			continue
		}
		if capacity != 0 {
			return 0, errors.New("duplicate ipset capacity")
		}
		value, err := strconv.Atoi(set.Options[n+1])
		if err != nil || value <= 0 {
			return 0, errors.New("invalid ipset capacity")
		}
		capacity = value
	}
	if capacity == 0 {
		return 0, errors.New("missing ipset capacity")
	}
	return capacity, nil
}

func dynamicIPSetCapacity(needed int) int {
	capacity := 65536
	for capacity < needed && capacity <= math.MaxInt/2 {
		capacity *= 2
	}
	return max(capacity, needed)
}

// A bounded restore may stop at any line. The spare name is authorized by the
// same recorded dynamic generation, so retries and cleanup recognize it both
// before and after swap. Live references always keep pointing at the live name.
func appendDynamicIPSet(input *strings.Builder, set iptSet, inventory *iptInventory, desired map[string]uint64) error {
	observed, exists := inventory.Sets[set.Name]
	capacity := 0
	if exists {
		var err error
		capacity, err = ipsetCapacity(observed)
		if err != nil {
			return err
		}
	}
	spare := iptDynamicSpareName(set.Name)
	if _, exists := inventory.Sets[spare]; exists {
		fmt.Fprintf(input, "destroy %s\n", spare)
	}
	resize := exists && len(desired) > capacity
	destination := set.Name
	if resize {
		destination = spare
	}
	if !exists || resize {
		fmt.Fprintf(input, "create %s hash:net family %s maxelem %d timeout %d\n",
			destination, familySetName(set.Family), dynamicIPSetCapacity(len(desired)), int(maximumLease/time.Second))
	}
	if !resize {
		for _, entry := range observed.Entries {
			if _, keep := desired[entry]; !keep {
				fmt.Fprintf(input, "del %s %s -exist\n", set.Name, entry)
			}
		}
	}
	entries := make([]string, 0, len(desired))
	for entry := range desired {
		entries = append(entries, entry)
	}
	slices.Sort(entries)
	for _, entry := range entries {
		grant := desired[entry]
		if !resize && observed.Timeouts[entry] == grant {
			continue
		}
		fmt.Fprintf(input, "add %s %s timeout %d -exist\n", destination, entry, grant)
	}
	if resize {
		fmt.Fprintf(input, "swap %s %s\ndestroy %s\n", spare, set.Name, spare)
	}
	return nil
}

// ipset restore is already non-transactional. Bound each invocation while
// preserving command order, including population before a resize swap.
func (i *IPTables) restoreSets(ctx context.Context, input string) error {
	for input != "" {
		size := min(len(input), maxIPTablesInput)
		if size < len(input) {
			size = strings.LastIndexByte(input[:size], '\n') + 1
			if size == 0 {
				return errors.New("ipset command exceeds input limit")
			}
		}
		if _, err := i.run(ctx, "ipset", []string{"restore"}, []byte(input[:size])); err != nil {
			return err
		}
		input = input[size:]
	}
	return nil
}

func (i *IPTables) stage(ctx context.Context, models map[policy.Family]iptFamilyModel, inventory *iptInventory) error {
	var setInput strings.Builder
	now := time.Now()
	for _, family := range []policy.Family{policy.IPv4, policy.IPv6} {
		model := models[family]
		for _, set := range model.Sets {
			observed, exists := inventory.Sets[set.Name]
			// A nil projection means recovery/refresh: never alter live leases.
			if set.Dynamic && !set.DynamicProjection {
				if !exists {
					fmt.Fprintf(&setInput, "create %s hash:net family %s maxelem %d timeout %d\n", set.Name, familySetName(family), 65536, int(maximumLease/time.Second))
				}
				continue
			}
			desired := make(map[string]uint64, len(set.Prefixes))
			for n, prefix := range set.Prefixes {
				if !set.Dynamic {
					desired[prefix.String()] = 0
					continue
				}
				grant, _ := LeaseGrant(set.Timed[n].Deadline, now, time.Second)
				if grant > 0 {
					desired[prefix.String()] = uint64(grant / time.Second)
				}
			}
			if set.Dynamic {
				if err := appendDynamicIPSet(&setInput, set, inventory, desired); err != nil {
					return err
				}
				continue
			}
			if exists && len(observed.Entries) == len(desired) {
				same := true
				for _, entry := range observed.Entries {
					if _, wanted := desired[entry]; !wanted {
						same = false
						break
					}
				}
				if same {
					continue
				}
			}
			if exists && referencedSet(inventory, set.Name) {
				return fmt.Errorf("refusing to mutate referenced generation set %s", set.Name)
			}
			if !exists {
				fmt.Fprintf(&setInput, "create %s hash:net family %s maxelem %d\n", set.Name, familySetName(family), max(65536, len(desired)))
			}
			observedEntries := observedSetEntries(observed)
			for _, entry := range observed.Entries {
				if _, keep := desired[entry]; !keep {
					fmt.Fprintf(&setInput, "del %s %s\n", set.Name, entry)
				}
			}
			for _, prefix := range set.Prefixes {
				entry := prefix.String()
				if _, exists := observedEntries[entry]; !exists {
					fmt.Fprintf(&setInput, "add %s %s\n", set.Name, entry)
				}
			}
		}
	}
	if err := i.restoreSets(ctx, setInput.String()); err != nil {
		return err
	}
	for _, family := range []policy.Family{policy.IPv4, policy.IPv6} {
		var lines []string
		for _, chain := range models[family].Staging {
			observed, exists := inventory.Chains[chainKey(family, chain.Name)]
			if exists && sameObservedChain(observed, chain) {
				continue
			}
			if exists && referencedChain(inventory, family, chain.Name) {
				return fmt.Errorf("refusing to mutate referenced generation chain %s", chain.Name)
			}
			if !exists {
				lines = append(lines, ":"+chain.Name+" - [0:0]")
			} else {
				lines = append(lines, "-F "+chain.Name)
			}
			for _, rule := range chain.Rules {
				line, err := renderIPTRule(chain.Name, rule)
				if err != nil {
					return err
				}
				lines = append(lines, line)
			}
		}
		if err := i.restore(ctx, family, lines); err != nil {
			return err
		}
	}
	return nil
}

func (i *IPTables) commitFamily(ctx context.Context, family policy.Family, old, next iptFamilyModel, inventory *iptInventory) error {
	var declarations, changes []string
	for _, chain := range next.Active {
		observed, exists := inventory.Chains[chainKey(family, chain.Name)]
		if !exists {
			declarations = append(declarations, ":"+chain.Name+" - [0:0]")
		}
		replace := exists && len(observed.Rules) == len(chain.Rules)
		if exists && !replace {
			changes = append(changes, "-F "+chain.Name)
		}
		for n, rule := range chain.Rules {
			if replace && sameIPTRule(observed.Rules[n].Args, rule.Args) {
				continue
			}
			line, err := renderIPTRule(chain.Name, rule)
			if err != nil {
				return err
			}
			if replace {
				line = "-R " + chain.Name + " " + strconv.Itoa(n+1) + strings.TrimPrefix(line, "-A "+chain.Name)
			}
			changes = append(changes, line)
		}
	}
	for _, attachment := range old.Attachments {
		if hasIPTAttachment(next.Attachments, attachment) || !observedAttachment(inventory, family, attachment) {
			continue
		}
		line, err := renderIPTRule(attachment.Parent, attachment.Rule)
		if err != nil {
			return err
		}
		changes = append(changes, "-D"+strings.TrimPrefix(line, "-A"))
	}
	for _, attachment := range next.Attachments {
		if observedAttachment(inventory, family, attachment) {
			continue
		}
		line, err := renderIPTRule(attachment.Parent, attachment.Rule)
		if err != nil {
			return err
		}
		// Ownership precedes existing parent verdicts, without modifying them.
		changes = append(changes, "-I "+attachment.Parent+" 1"+strings.TrimPrefix(line, "-A "+attachment.Parent))
	}
	return i.restore(ctx, family, append(declarations, changes...))
}

func (i *IPTables) selectFamily(ctx context.Context, family policy.Family, previous, candidate *Target, expected *iptExpected) error {
	inventory, err := i.inspect(ctx, expected.sets)
	if err != nil {
		return err
	}
	if err := validateIPTInventory(inventory, expected); err != nil {
		return err
	}
	old, next := expected.models[previous], expected.models[candidate]
	if err := i.commitFamily(ctx, family, old[family], next[family], inventory); err != nil {
		return err
	}
	if i.progress != nil {
		generation := ""
		if _, exists := next[family]; exists {
			generation = candidate.Generation
		}
		if err := i.progress(family, generation); err != nil {
			return err
		}
	}
	return nil
}

// UpdateDynamic reconciles only the recorded CrowdSec hash:net containers.
// Static sets and packet paths are intentionally absent from the mutation
// plan, so a partially applied restore converges on the next invocation.
func (i *IPTables) UpdateDynamic(ctx context.Context, target *Target, prefixes []policy.TimedPrefix) error {
	if err := ValidateTarget(target); err != nil {
		return err
	}
	if target == nil || target.IPTables == nil {
		return errors.New("iptables dynamic update requires an iptables target")
	}
	if target.DynamicGeneration == "" {
		return errors.New("iptables dynamic update requires a dynamic generation")
	}
	if err := ValidateDynamic(prefixes); err != nil {
		return err
	}
	expected, err := expectedIPTWithProjection(nil, target)
	if err != nil {
		return err
	}
	inventory, err := i.inspectTargets(ctx, expected)
	if err != nil {
		return err
	}
	now := time.Now()
	var input strings.Builder
	for _, family := range []policy.Family{policy.IPv4, policy.IPv6} {
		model := expected.models[target][family]
		for _, set := range model.Sets {
			if !set.Dynamic {
				continue
			}
			desiredTimed := loweredIPTTimedPrefixes(prefixes, family)
			set.DynamicProjection = true
			set.Prefixes = make([]netip.Prefix, 0, len(desiredTimed))
			desired := make(map[string]uint64, len(desiredTimed))
			for _, value := range desiredTimed {
				grant, _ := LeaseGrant(value.Deadline, now, time.Second)
				if grant > 0 {
					set.Prefixes = append(set.Prefixes, value.Prefix)
					desired[value.Prefix.String()] = uint64(grant / time.Second)
				}
			}
			expected.sets[set.Name] = set
			spare := set
			spare.Name = iptDynamicSpareName(set.Name)
			expected.sets[spare.Name] = spare
			if err := appendDynamicIPSet(&input, set, inventory, desired); err != nil {
				return err
			}
		}
	}
	if err := validateIPTCapacity(inventory, expected); err != nil {
		return err
	}
	return i.restoreSets(ctx, input.String())
}

// Apply selects the candidate, preserving dynamic leases unless authority is supplied.
func (i *IPTables) Apply(ctx context.Context, previous, candidate *Target, dynamic *DynamicState) error {
	if err := validateDynamicState(candidate, dynamic); err != nil {
		return err
	}
	if previous == nil && candidate == nil {
		return ctx.Err()
	}
	expected, err := expectedIPTWithProjection(dynamic, previous, candidate)
	if err != nil {
		return err
	}
	inventory, err := i.preflightTargets(ctx, expected, candidate)
	if err != nil {
		return err
	}
	if err := validateIPTCapacity(inventory, expected); err != nil {
		return err
	}
	if err := i.stage(ctx, expected.models[candidate], inventory); err != nil {
		return err
	}
	old, next := expected.models[previous], expected.models[candidate]
	var attempted []policy.Family
	for _, family := range []policy.Family{policy.IPv4, policy.IPv6} {
		_, was := old[family]
		_, want := next[family]
		if !was && !want {
			continue
		}
		attempted = append(attempted, family)
		if err := i.selectFamily(ctx, family, previous, candidate, expected); err != nil {
			// An interrupted command may have committed. Include the attempted family,
			// not only commands whose successful exit was observed.
			compensationCtx, cancel := context.WithTimeout(context.Background(), maxIPTablesTime)
			result := err
			for n := len(attempted) - 1; n >= 0; n-- {
				if undoErr := i.selectFamily(compensationCtx, attempted[n], candidate, previous, expected); undoErr != nil {
					result = errors.Join(result, fmt.Errorf("compensation: %w", undoErr))
				}
			}
			cancel()
			return result
		}
	}
	return nil
}

func (i *IPTables) remove(ctx context.Context, remove, keep []*Target) error {
	all := append(append([]*Target(nil), remove...), keep...)
	expected, err := expectedIPTWithProjection(nil, all...)
	if err != nil {
		return err
	}
	inventory, err := i.inspectTargets(ctx, expected)
	if err != nil {
		return err
	}
	obsolete, err := expectedIPTWithProjection(nil, remove...)
	if err != nil {
		return err
	}
	retained, err := expectedIPTWithProjection(nil, keep...)
	if err != nil {
		return err
	}
	for key := range retained.chains {
		delete(obsolete.chains, key)
	}
	for name := range retained.sets {
		delete(obsolete.sets, name)
	}
	for key, rules := range obsolete.parents {
		kept := rules[:0]
		for _, rule := range rules {
			found := false
			for _, retain := range retained.parents[key] {
				if sameIPTRule(rule.Args, retain.Args) {
					found = true
					break
				}
			}
			if !found {
				kept = append(kept, rule)
			}
		}
		obsolete.parents[key] = kept
	}
	for _, family := range []policy.Family{policy.IPv4, policy.IPv6} {
		var lines []string
		// Use the observed list, deleting each exact recorded hook once, including
		// duplicates left by an interrupted older writer.
		for _, rule := range inventory.Rules {
			if rule.Family != family || rule.Table != "filter" {
				continue
			}
			for _, owned := range obsolete.parents[rule.iptChainKey] {
				if sameIPTRule(rule.Args, owned.Args) {
					line, err := renderIPTRule(rule.Chain, owned)
					if err != nil {
						return err
					}
					lines = append(lines, "-D"+strings.TrimPrefix(line, "-A"))
					break
				}
			}
		}
		var names []string
		for key := range obsolete.chains {
			observed, exists := inventory.Chains[key]
			if exists && observed.Family == family && observed.Table == "filter" {
				names = append(names, observed.Chain)
			}
		}
		slices.Sort(names)
		for _, rule := range inventory.Rules {
			referencesObsolete := false
			for name := range rule.references(iptJumpReference) {
				if slices.Contains(names, name) {
					referencesObsolete = true
					break
				}
			}
			if rule.Family != family || rule.Table != "filter" || !referencesObsolete || slices.Contains(names, rule.Chain) {
				continue
			}
			authorized := false
			for _, owned := range obsolete.parents[rule.iptChainKey] {
				if sameIPTRule(rule.Args, owned.Args) {
					authorized = true
					break
				}
			}
			if !authorized {
				return errors.New("retained rule references obsolete chain")
			}
		}
		// Flush all selected owned chains before deleting any: helpers and entry
		// chains reference generation chains. This remains one family transaction.
		for _, name := range names {
			lines = append(lines, "-F "+name)
		}
		for _, name := range names {
			lines = append(lines, "-X "+name)
		}
		if err := i.restore(ctx, family, lines); err != nil {
			return err
		}
		if len(lines) != 0 && i.progress != nil {
			kept := false
			for key := range retained.chains {
				if key.Family == family && key.Table == "filter" {
					kept = true
					break
				}
			}
			if !kept {
				if err := i.progress(family, ""); err != nil {
					return err
				}
			}
		}
	}
	// The kernel refuses referenced sets. Never flush them to make deletion work.
	names := make([]string, 0, len(obsolete.sets))
	for name := range obsolete.sets {
		if _, exists := inventory.Sets[name]; exists {
			names = append(names, name)
		}
	}
	slices.Sort(names)
	for _, name := range names {
		observed := inventory.Sets[name]
		var accounted uint64
		for _, rule := range inventory.Rules {
			count := uint64(0)
			for reference := range rule.references(iptSetReference) {
				if reference == name {
					count++
				}
			}
			if count == 0 {
				continue
			}
			if !obsolete.rules[rule.iptChainKey][iptRuleKey(rule.Args)] {
				return fmt.Errorf("refusing to destroy referenced ipset %s", name)
			}
			accounted += count
		}
		if observed.References != accounted {
			return fmt.Errorf("ipset %s has unaccounted native references", name)
		}
		if _, err := i.run(ctx, "ipset", []string{"destroy", name}, nil); err != nil {
			return err
		}
	}
	return nil
}

// Retire removes prior ownership not retained by the committed candidate.
func (i *IPTables) Retire(ctx context.Context, previous, candidate *Target) error {
	if previous == nil {
		return ctx.Err()
	}
	return i.remove(ctx, []*Target{previous}, []*Target{candidate})
}

// Cleanup removes only objects authorized by the complete recorded target union.
func (i *IPTables) Cleanup(ctx context.Context, targets []*Target) error {
	if len(targets) == 0 {
		return ctx.Err()
	}
	return i.remove(ctx, targets, nil)
}

var _ Backend = (*IPTables)(nil)
