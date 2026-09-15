package firewall

import (
	"bytes"
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/netip"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode"

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
	if len(input) > maxIPTablesInput {
		return nil, errors.New("iptables input exceeds limit")
	}
	// #nosec G204 -- callers select fixed native tools; policy data is passed on stdin.
	cmd := exec.CommandContext(ctx, command, args...)
	cmd.Stdin = bytes.NewReader(input)
	var stdout, stderr boundedBuffer
	stdout.limit, stderr.limit = maxIPTablesOutput, maxIPTablesOutput
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, fmt.Errorf("%s %s: %w: %s", command, strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return stdout.Bytes(), nil
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

type iptObservedRule struct {
	Table      string
	Chain      string
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
		Table, Name string
		Rules       []iptObservedRule
	}
	iptObservedSet struct {
		Name, Type, Family string
		Options            []string
		Entries            []string
		Extended           bool
		References         uint64
	}
)

type iptInventory struct {
	Chains     map[string]iptObservedChain
	Sets       map[string]iptObservedSet
	Rules      []iptObservedRule
	TableBytes map[policy.Family]int
	SetBytes   int
}

func newIPTInventory() *iptInventory {
	return &iptInventory{Chains: make(map[string]iptObservedChain), Sets: make(map[string]iptObservedSet), TableBytes: make(map[policy.Family]int)}
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
func chainKey(family policy.Family, name string) string { return familyName(family) + ":" + name }
func familyTool(family policy.Family, suffix string) string {
	if family == policy.IPv4 {
		return "iptables" + suffix
	}
	return "ip6tables" + suffix
}

func parseIPTablesSave(data []byte) (*iptInventory, error) {
	if len(data) > maxIPTablesOutput {
		return nil, errors.New("oversized iptables save")
	}
	result := newIPTInventory()
	table := ""
	for lineNo, raw := range iptSaveRecords(string(data)) {
		line := strings.TrimSpace(raw)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "*") {
			if table != "" {
				return nil, errors.New("missing COMMIT")
			}
			table = strings.TrimPrefix(line, "*")
			if table == "" {
				return nil, errors.New("empty table")
			}
			continue
		}
		if table == "" {
			return nil, fmt.Errorf("line %d outside table", lineNo+1)
		}
		if line == "COMMIT" {
			table = ""
			continue
		}
		if strings.HasPrefix(line, ":") {
			fields := strings.Fields(line[1:])
			if len(fields) != 3 {
				return nil, errors.New("malformed chain declaration")
			}
			key := table + ":" + fields[0]
			if _, exists := result.Chains[key]; exists {
				return nil, errors.New("duplicate chain")
			}
			result.Chains[key] = iptObservedChain{Table: table, Name: fields[0]}
			continue
		}
		var packets, byteCount uint64
		if strings.HasPrefix(line, "[") {
			end := strings.IndexByte(line, ']')
			if end < 0 {
				return nil, errors.New("malformed rule counter")
			}
			pair := strings.Split(line[1:end], ":")
			if len(pair) != 2 {
				return nil, errors.New("malformed rule counter")
			}
			var err error
			packets, err = strconv.ParseUint(pair[0], 10, 64)
			if err != nil {
				return nil, err
			}
			byteCount, err = strconv.ParseUint(pair[1], 10, 64)
			if err != nil {
				return nil, err
			}
			line = strings.TrimSpace(line[end+1:])
		}
		tokens, literals, err := splitIPTLine(line)
		if err != nil {
			return nil, err
		}
		if len(tokens) < 2 || tokens[0] != "-A" {
			return nil, fmt.Errorf("unsupported save line %d", lineNo+1)
		}
		key := table + ":" + tokens[1]
		chain, exists := result.Chains[key]
		if !exists {
			return nil, errors.New("rule references undeclared chain")
		}
		rule := iptObservedRule{Table: table, Chain: tokens[1], Args: tokens[2:], Packets: packets, Bytes: byteCount}
		rule.References = iptRuleReferences(tokens[2:], literals[2:])
		chain.Rules = append(chain.Rules, rule)
		result.Chains[key] = chain
		result.Rules = append(result.Rules, rule)
	}
	if table != "" {
		return nil, errors.New("missing COMMIT")
	}
	return result, nil
}

// ipsetSaveRecords parses ipset's save grammar, not shell or iptables escaping.
// Double-quoted fields may span lines, but backslashes and apostrophes are
// literal. Keeping record and field parsing together prevents quoted comments
// from consuming following set definitions.
func ipsetSaveRecords(data string) iter.Seq2[[]string, error] {
	return func(yield func([]string, error) bool) {
		var fields []string
		var token strings.Builder
		inToken, quoted, closed, comment := false, false, false, false
		flushToken := func() {
			if inToken {
				if fields == nil {
					fields = make([]string, 0, 8)
				}
				fields = append(fields, token.String())
				token.Reset()
				inToken = false
			}
			closed = false
		}
		for _, char := range data {
			if char == '\n' && !quoted {
				flushToken()
				if len(fields) != 0 && !yield(fields, nil) {
					return
				}
				fields = nil
				comment = false
				continue
			}
			if comment {
				continue
			}
			if quoted {
				if char == '"' {
					quoted, closed = false, true
				} else {
					token.WriteRune(char)
				}
				continue
			}
			if unicode.IsSpace(char) {
				flushToken()
				continue
			}
			if closed {
				yield(nil, errors.New("ipset save: missing delimiter after quoted field"))
				return
			}
			if !inToken && len(fields) == 0 && char == '#' {
				comment = true
				continue
			}
			if !inToken && char == '"' {
				inToken, quoted = true, true
				continue
			}
			token.WriteRune(char)
			inToken = true
		}
		if quoted {
			yield(nil, errors.New("ipset save: unterminated quote"))
			return
		}
		flushToken()
		if len(fields) != 0 {
			yield(fields, nil)
		}
	}
}

func parseIPSetSave(data []byte) (map[string]iptObservedSet, error) {
	if len(data) > maxIPTablesOutput {
		return nil, errors.New("oversized ipset save")
	}
	result := make(map[string]iptObservedSet)
	for fields, err := range ipsetSaveRecords(string(data)) {
		if err != nil {
			return nil, err
		}
		if len(fields) < 3 {
			return nil, errors.New("malformed ipset save")
		}
		switch fields[0] {
		case "create":
			if _, exists := result[fields[1]]; exists {
				return nil, errors.New("duplicate set")
			}
			set := iptObservedSet{Name: fields[1], Type: fields[2], Family: "inet", Options: fields[3:]}
			for n := 3; n+1 < len(fields); n++ {
				if fields[n] == "family" {
					set.Family = fields[n+1]
				}
			}
			result[set.Name] = set
		case "add":
			set, exists := result[fields[1]]
			if !exists {
				return nil, errors.New("element references undeclared set")
			}
			entry := fields[2]
			if set.Type == "hash:net" {
				prefix, err := netip.ParsePrefix(entry)
				if err != nil {
					addr, addrErr := netip.ParseAddr(entry)
					if addrErr != nil {
						return nil, err
					}
					prefix = netip.PrefixFrom(addr, addr.BitLen())
				}
				entry = prefix.Masked().String()
			}
			set.Entries = append(set.Entries, entry)
			set.Extended = set.Extended || len(fields) != 3
			result[set.Name] = set
		default:
			return nil, errors.New("unsupported ipset save directive")
		}
	}
	return result, nil
}

// Native reference counts include users outside the selected xtables inventory,
// including list:set membership and rules from the other tool implementation.
func parseIPSetReferences(data []byte, name string) (uint64, error) {
	var document struct {
		XMLName xml.Name `xml:"ipsets"`
		Sets    []struct {
			Name    string `xml:"name,attr"`
			Headers []struct {
				References []string `xml:"references"`
			} `xml:"header"`
		} `xml:"ipset"`
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&document); err != nil {
		return 0, fmt.Errorf("ipset reference metadata: %w", err)
	}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("ipset reference metadata: %w", err)
		}
		if text, ok := token.(xml.CharData); !ok || len(bytes.TrimSpace(text)) != 0 {
			return 0, errors.New("ipset reference metadata has trailing content")
		}
	}
	if len(document.Sets) != 1 || document.Sets[0].Name != name ||
		len(document.Sets[0].Headers) != 1 || len(document.Sets[0].Headers[0].References) != 1 {
		return 0, errors.New("ipset query returned incomplete or ambiguous reference metadata")
	}
	count, err := strconv.ParseUint(document.Sets[0].Headers[0].References[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("ipset reference count: %w", err)
	}
	return count, nil
}

func (i *IPTables) inspect(ctx context.Context, expectedSets map[string]iptSet) (*iptInventory, error) {
	result := newIPTInventory()
	for _, family := range []policy.Family{policy.IPv4, policy.IPv6} {
		output, err := i.run(ctx, familyTool(family, "-save"), []string{"--counters"}, nil)
		if err != nil {
			return nil, err
		}
		result.TableBytes[family] = len(output)
		parsed, err := parseIPTablesSave(output)
		if err != nil {
			return nil, fmt.Errorf("%s save: %w", familyName(family), err)
		}
		for _, chain := range parsed.Chains {
			table := familyName(family)
			if chain.Table != "filter" {
				table += "\x00" + chain.Table
			}
			chain.Table = table
			for n := range chain.Rules {
				chain.Rules[n].Table = table
			}
			result.Chains[table+":"+chain.Name] = chain
		}
		for _, rule := range parsed.Rules {
			if rule.Table == "filter" {
				rule.Table = familyName(family)
			} else {
				rule.Table = familyName(family) + "\x00" + rule.Table
			}
			result.Rules = append(result.Rules, rule)
		}
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
		inventory.SetBytes += len(output) + len(header)
		inventory.Sets[name] = observed
	}
	return nil
}

// Extract all ownership-relevant options, never just the first apparent flag.
// Save quotes/escapes identify data even when it spells an option. Known
// operands are consumed together. An unknown extension has unknown arity, so
// its remaining unquoted tokens are inspected conservatively: ambiguity must
// not hide a real reference by consuming it as another option's operand.
func iptRuleReferences(args []string, literals []bool) []iptRuleReference {
	var references []iptRuleReference
	opaque := false
	for n := 0; n < len(args); n++ {
		if literals[n] {
			continue
		}
		count := 1
		var kind iptReferenceKind
		reference := false
		switch args[n] {
		case "-j", "--jump", "-g", "--goto":
			kind, reference = iptJumpReference, true
		case "--comment":
			kind, reference = iptCommentReference, true
		case "--match-set", "--add-set", "--del-set":
			kind, reference, count = iptSetReference, true, 2
		case "-m", "--match", "-p", "--protocol", "-s", "--source", "-d", "--destination",
			"-i", "--in-interface", "-o", "--out-interface",
			"--ctstate", "--dport", "--sport", "--ctorigdstport", "--reject-with":
		case "--tcp-flags", "-c", "--set-counters":
			count = 2
		case "!", "-f", "--fragment":
			count = 0
		default:
			opaque = true
			continue
		}
		if reference && n+1 < len(args) {
			references = append(references, iptRuleReference{Kind: kind, Value: args[n+1]})
		}
		if !opaque {
			n += count
		}
	}
	return references
}

// save canonicalizes extension ordering and adds implicit protocol modules.
// Normalize only equivalent spellings; retain every other token, including
// unknown extensions, so an ownership comment cannot authorize a foreign rule.
func canonicalIPTRule(args []string) []string {
	result := make([]string, 0, len(args))
	negate := false
	for n := 0; n < len(args); n++ {
		key := args[n]
		if key == "!" {
			negate = true
			continue
		}
		if key == "-m" && n+1 < len(args) && slices.Contains([]string{"tcp", "udp", "conntrack", "set", "comment"}, args[n+1]) && !negate {
			n++
			continue
		}
		count := 1
		if key == "--match-set" {
			count = 2
		}
		if n+count >= len(args) {
			count = len(args) - n - 1
		}
		values := append([]string(nil), args[n+1:n+1+count]...)
		if key == "--ctstate" && len(values) == 1 {
			states := strings.Split(values[0], ",")
			slices.Sort(states)
			values[0] = strings.Join(states, ",")
		}
		if key == "-p" && len(values) == 1 && values[0] == "icmpv6" {
			values[0] = "ipv6-icmp"
		}
		result = append(result, strconv.FormatBool(negate)+"\x00"+key+"\x00"+strings.Join(values, "\x00"))
		negate = false
		n += count
	}
	if negate {
		result = append(result, "!")
	}
	slices.Sort(result)
	return result
}

func sameIPTRule(a, b []string) bool { return slices.Equal(canonicalIPTRule(a), canonicalIPTRule(b)) }

func renderIPTRule(chain string, rule iptRule) (string, error) {
	if err := validateIPTablesIdentifier(chain, "chain", maxIPTChainNameBytes, false); err != nil {
		return "", err
	}
	tokens := make([]string, len(rule.Args))
	for n, token := range rule.Args {
		if token == "" || strings.ContainsAny(token, "\x00\r\n") {
			return "", errors.New("unsafe restore token")
		}
		tokens[n] = token
		if strings.ContainsAny(token, " \t\"'\\") || n > 0 && rule.Args[n-1] == "--comment" {
			tokens[n] = iptQuote(token)
		}
	}
	return "-A " + chain + " " + strings.Join(tokens, " "), nil
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
	chains  map[string][]iptChain
	sets    map[string]iptSet
	parents map[string][]iptRule
	owners  map[string]bool
	models  map[*Target]map[policy.Family]iptFamilyModel
	rules   map[string]map[string]bool
}

func expectedIPT(targets ...*Target) (*iptExpected, error) {
	result := &iptExpected{chains: make(map[string][]iptChain), sets: make(map[string]iptSet), parents: make(map[string][]iptRule), owners: make(map[string]bool), models: make(map[*Target]map[policy.Family]iptFamilyModel), rules: make(map[string]map[string]bool)}
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
				if old, exists := result.sets[set.Name]; exists && (old.Family != set.Family || !slices.Equal(old.Prefixes, set.Prefixes)) {
					return nil, errors.New("conflicting recorded ipset definitions")
				}
				result.sets[set.Name] = set
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

func iptRuleKey(args []string) string {
	var result strings.Builder
	for _, token := range canonicalIPTRule(args) {
		result.WriteString(strconv.Itoa(len(token)))
		result.WriteByte(':')
		result.WriteString(token)
	}
	return result.String()
}

func (e *iptExpected) addRule(chain string, args []string) {
	if e.rules[chain] == nil {
		e.rules[chain] = make(map[string]bool)
	}
	e.rules[chain][iptRuleKey(args)] = true
}

func matchesIPTExpected(rule iptObservedRule, expected *iptExpected) bool {
	rules := expected.rules[rule.Table+":"+rule.Chain]
	return len(rules) != 0 && rules[iptRuleKey(rule.Args)]
}

func validateIPTInventory(inventory *iptInventory, expected *iptExpected) error {
	references := make(map[string]uint64, len(expected.sets))
	for _, rule := range inventory.Rules {
		known := matchesIPTExpected(rule, expected)
		if _, owned := expected.chains[rule.Table+":"+rule.Chain]; owned && !known {
			return fmt.Errorf("owned chain %s contains an unexpected rule", rule.Chain)
		}
		for name := range rule.references(iptJumpReference) {
			if _, owned := expected.chains[rule.Table+":"+name]; owned && !known {
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
		if observed.Type != "hash:net" || observed.Family != familySetName(want.Family) || observed.Extended {
			return fmt.Errorf("unexpected owned set shape: %s", name)
		}
		for n := 0; n < len(observed.Options); n += 2 {
			if n+1 == len(observed.Options) || !slices.Contains([]string{"family", "hashsize", "maxelem", "bucketsize", "initval"}, observed.Options[n]) {
				return fmt.Errorf("unexpected owned set option: %s", name)
			}
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
		if rule.Table != familyName(family) {
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

func (i *IPTables) restore(ctx context.Context, family policy.Family, lines []string) error {
	if len(lines) == 0 {
		return ctx.Err()
	}
	input := []byte("*filter\n" + strings.Join(lines, "\n") + "\nCOMMIT\n")
	_, err := i.run(ctx, familyTool(family, "-restore"), []string{"--wait", "--noflush"}, input)
	return err
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

// Preflight checks tool compatibility, ownership, parents, and recovery capacity
// before the writer publishes durable intent.
func (i *IPTables) Preflight(ctx context.Context, previous, candidate *Target) error {
	if previous == nil && candidate == nil {
		return ctx.Err()
	}
	expected, err := expectedIPT(previous, candidate)
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
		old, err := expectedIPT(previous)
		if err != nil {
			return err
		}
		next, err := expectedIPT(candidate)
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

func (i *IPTables) stage(ctx context.Context, models map[policy.Family]iptFamilyModel, inventory *iptInventory) error {
	var setInput strings.Builder
	for _, family := range []policy.Family{policy.IPv4, policy.IPv6} {
		model := models[family]
		for _, set := range model.Sets {
			observed, exists := inventory.Sets[set.Name]
			if exists && len(observed.Entries) == len(set.Prefixes) {
				continue
			}
			if exists && referencedSet(inventory, set.Name) {
				return fmt.Errorf("refusing to mutate referenced generation set %s", set.Name)
			}
			if !exists {
				fmt.Fprintf(&setInput, "create %s hash:net family %s maxelem %d\n", set.Name, familySetName(family), max(65536, len(set.Prefixes)))
			}
			seen := make(map[string]bool, len(observed.Entries))
			for _, entry := range observed.Entries {
				seen[entry] = true
			}
			for _, prefix := range set.Prefixes {
				if !seen[prefix.String()] {
					fmt.Fprintf(&setInput, "add %s %s\n", set.Name, prefix)
				}
			}
		}
	}
	if setInput.Len() != 0 {
		if _, err := i.run(ctx, "ipset", []string{"restore"}, []byte(setInput.String())); err != nil {
			return err
		}
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

// Apply stages both families before switching either one. Failed or uncertain
// switches trigger bounded compensation independent of caller cancellation.
func (i *IPTables) Apply(ctx context.Context, previous, candidate *Target) error {
	if previous == nil && candidate == nil {
		return ctx.Err()
	}
	expected, err := expectedIPT(previous, candidate)
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
	expected, err := expectedIPT(all...)
	if err != nil {
		return err
	}
	inventory, err := i.inspectTargets(ctx, expected)
	if err != nil {
		return err
	}
	obsolete, err := expectedIPT(remove...)
	if err != nil {
		return err
	}
	retained, err := expectedIPT(keep...)
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
			if rule.Table != familyName(family) {
				continue
			}
			for _, owned := range obsolete.parents[rule.Table+":"+rule.Chain] {
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
			if exists && observed.Table == familyName(family) {
				names = append(names, observed.Name)
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
			if rule.Table != familyName(family) || !referencesObsolete || slices.Contains(names, rule.Chain) {
				continue
			}
			authorized := false
			for _, owned := range obsolete.parents[rule.Table+":"+rule.Chain] {
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
				if strings.HasPrefix(key, familyName(family)+":") {
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

// Leave capture headroom for counters and native formatting. Budget the full
// rule inventories and recorded sets so staging cannot prevent later inspection.
func validateIPTCapacity(inventory *iptInventory, expected *iptExpected) error {
	const budget = 48 << 20
	setBytes := inventory.SetBytes
	tableBytes := map[policy.Family]int{policy.IPv4: inventory.TableBytes[policy.IPv4], policy.IPv6: inventory.TableBytes[policy.IPv6]}
	setSize := func(set iptSet) int {
		size := 1024 // Save definition plus the terse XML header.
		var buffer [64]byte
		for _, prefix := range set.Prefixes {
			size += len(set.Name) + len(prefix.AppendTo(buffer[:0])) + 6
		}
		return size
	}
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
		if !exists || len(observed.Entries) != len(set.Prefixes) {
			setBytes += setSize(set)
		}
	}
	for key, chains := range expected.chains {
		size := 0
		for _, chain := range chains {
			size = max(size, chainSize(chain))
		}
		family := policy.IPv4
		if strings.HasPrefix(key, "v6:") {
			family = policy.IPv6
		}
		tableBytes[family] += size
	}
	for _, models := range expected.models {
		inputSets := 0
		for _, model := range models {
			for _, set := range model.Sets {
				inputSets += setSize(set)
			}
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
		if inputSets > maxIPTablesInput {
			return errors.New("ipset complete target exceeds input budget")
		}
	}
	if setBytes > budget || tableBytes[policy.IPv4] > budget || tableBytes[policy.IPv6] > budget {
		return errors.New("iptables retained generations exceed inspection budget")
	}
	return nil
}
