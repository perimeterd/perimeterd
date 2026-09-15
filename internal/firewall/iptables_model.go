package firewall

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"iter"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"unicode"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

const (
	maxIPTChainNameBytes = 28
	maxIPTSetNameBytes   = 31
	iptNameDigestBytes   = 12
	iptSetDigestBytes    = 13
)

// iptRule is an iptables-restore rule without its -A chain prefix. Arguments
// are kept as tokens; the backend quotes tokens while writing restore input.
type iptRule struct {
	Args []string
}

type iptChain struct {
	Name  string
	Rules []iptRule
}

type iptSet struct {
	Name     string
	Family   policy.Family
	Prefixes []netip.Prefix
}

type iptAttachment struct {
	Parent string
	Rule   iptRule
}

type iptFamilyModel struct {
	Family      policy.Family
	Sets        []iptSet
	Staging     []iptChain
	Active      []iptChain
	Attachments []iptAttachment
}

// iptSetName returns a native name whose complete logical identity is hashed.
// ipset limits names to 31 bytes, so readable names cannot safely contain an
// arbitrary owner, generation, and policy identifier. The caller validates
// collisions among all names in a generated model before mutation.
func iptSetName(target *Target, family policy.Family, setID string) string {
	owner, generation := "", ""
	if target != nil {
		owner, generation = target.Owner, target.Generation
	}
	identity := strings.Join([]string{"set", owner, generation, familyToken(family), setID}, "\x00")
	digest := sha256.Sum256([]byte(identity))
	return "pd" + familyToken(family) + "s" + hex.EncodeToString(digest[:iptSetDigestBytes])
}

func iptChainName(identity string) string {
	digest := sha256.Sum256([]byte(identity))
	return "pdc" + hex.EncodeToString(digest[:iptNameDigestBytes])
}

func iptGenerationChainName(target *Target, family policy.Family, direction policy.Direction, originalDestination bool) string {
	owner, generation := "", ""
	if target != nil {
		owner, generation = target.Owner, target.Generation
	}
	return iptChainName(strings.Join([]string{"staging", owner, generation, familyToken(family), string(direction), strconv.FormatBool(originalDestination)}, "\x00"))
}

func iptEntryChainName(target *Target, family policy.Family, attachment config.Attachment) string {
	owner := ""
	if target != nil {
		owner = target.Owner
	}
	return iptChainName(strings.Join([]string{"entry", owner, familyToken(family), attachmentIdentity(attachment)}, "\x00"))
}

func iptFilterChainName(target *Target, family policy.Family, attachment config.Attachment) string {
	owner := ""
	if target != nil {
		owner = target.Owner
	}
	return iptChainName(strings.Join([]string{"filter", owner, familyToken(family), attachmentIdentity(attachment)}, "\x00"))
}

func attachmentIdentity(attachment config.Attachment) string {
	return strings.Join([]string{
		attachment.Chain,
		attachment.Direction,
		strings.Join(attachment.InputInterfaces, "\x01"),
		strings.Join(attachment.OutputInterfaces, "\x01"),
		strconv.FormatBool(attachment.OriginalDestination),
	}, "\x00")
}

func safeAttachmentIdentity(attachment config.Attachment) string {
	digest := sha256.Sum256([]byte(attachmentIdentity(attachment)))
	return attachment.Chain + "_" + attachment.Direction + "_h" + hex.EncodeToString(digest[:8])
}

func iptCommentArgs(args []string, comment string) []string {
	result := make([]string, 0, len(args)+4)
	result = append(result, args...)
	result = append(result, "-m", "comment", "--comment", comment)
	return result
}

func iptOwnedRule(args []string, owner, generation, role string, stable bool) iptRule {
	return iptRule{Args: iptCommentArgs(args, ownershipComment(owner, generation, role, stable))}
}

// iptQuote emits a single restore token. Restore's parser uses backslash
// escapes inside double quotes; controls are escaped so arbitrary ownership
// values cannot terminate or span a token.
func iptQuote(value string) string {
	var builder strings.Builder
	builder.Grow(len(value) + 2)
	builder.WriteByte('"')
	for _, char := range value {
		switch char {
		case '\\':
			builder.WriteString(`\\`)
		case '"':
			builder.WriteString(`\"`)
		case '\n':
			builder.WriteString(`\n`)
		case '\r':
			builder.WriteString(`\r`)
		case '\t':
			builder.WriteString(`\t`)
		case 0:
			builder.WriteString(`\0`)
		default:
			builder.WriteRune(char)
		}
	}
	builder.WriteByte('"')
	return builder.String()
}

// iptSaveRecords yields zero-based physical line numbers and complete logical
// records without copying them. Native save output can contain literal newlines
// in quoted comments; header comments, in contrast, always end at a newline.
func iptSaveRecords(data string) iter.Seq2[int, string] {
	return func(yield func(int, string) bool) {
		start, startLine, line := 0, 0, 0
		var quote rune
		escaped, comment, started := false, false, false
		for pos, char := range data {
			if char == '\n' {
				line++
				if comment || quote == 0 && !escaped {
					if !yield(startLine, data[start:pos]) {
						return
					}
					start, startLine = pos+1, line
					comment, started = false, false
					continue
				}
			}
			if comment {
				continue
			}
			if escaped {
				escaped = false
				continue
			}
			if quote != 0 {
				if char == quote {
					quote = 0
				} else if char == '\\' && quote == '"' {
					escaped = true
				}
				continue
			}
			if !started {
				if unicode.IsSpace(char) {
					continue
				}
				if char == '#' {
					comment = true
					continue
				}
				started = true
			}
			switch char {
			case '\\':
				escaped = true
			case '"', '\'':
				quote = char
			}
		}
		if start < len(data) {
			yield(startLine, data[start:])
		}
	}
}

// splitIPTLine tokenizes one logical machine-oriented save/restore record. It accepts
// adjacent quoted and unquoted fragments, as the native tools do, and rejects
// malformed quoting instead of silently changing a rule.
// The parallel boolean slice marks quoted/escaped data tokens, which must not
// become option flags when inspecting opaque extension arguments.
func splitIPTLine(line string) ([]string, []bool, error) {
	tokens := make([]string, 0, 8)
	literals := make([]bool, 0, 8)
	literal := false
	var token strings.Builder
	inToken := false
	quote := rune(0)
	escaped := false
	for _, char := range line {
		if escaped {
			switch char {
			case 'n':
				token.WriteByte('\n')
			case 'r':
				token.WriteByte('\r')
			case 't':
				token.WriteByte('\t')
			case '0':
				token.WriteByte(0)
			default:
				token.WriteRune(char)
			}
			inToken = true
			escaped = false
			continue
		}
		if quote != 0 {
			if char == '\\' && quote == '"' {
				escaped = true
				continue
			}
			if char == quote {
				quote = 0
				inToken = true
				continue
			}
			token.WriteRune(char)
			inToken = true
			continue
		}
		switch {
		case char == '\\':
			escaped = true
			literal = true
			inToken = true
		case char == '"' || char == '\'':
			quote = char
			literal = true
			inToken = true
		case unicode.IsSpace(char):
			if inToken {
				tokens = append(tokens, token.String())
				literals = append(literals, literal)
				literal = false
				token.Reset()
				inToken = false
			}
		default:
			token.WriteRune(char)
			inToken = true
		}
	}
	if escaped {
		return nil, nil, fmt.Errorf("iptables line: trailing escape")
	}
	if quote != 0 {
		return nil, nil, fmt.Errorf("iptables line: unterminated quote")
	}
	if inToken {
		tokens = append(tokens, token.String())
		literals = append(literals, literal)
	}
	return tokens, literals, nil
}

func validateIPTablesIdentifier(value, field string, max int, allowPlus bool) error {
	if value == "" {
		return fmt.Errorf("firewall target: %s must not be empty", field)
	}
	if len([]byte(value)) > max {
		return fmt.Errorf("firewall target: %s exceeds %d bytes", field, max)
	}
	for _, char := range value {
		if char == 0 || unicode.IsSpace(char) || char == '\'' || char == '"' || char == '\\' {
			return fmt.Errorf("firewall target: %s contains an invalid character", field)
		}
		if allowPlus && char == '+' {
			continue
		}
		if (char < 'a' || char > 'z') && (char < 'A' || char > 'Z') &&
			(char < '0' || char > '9') && char != '-' && char != '_' && char != '.' && char != ':' {
			return fmt.Errorf("firewall target: %s contains an invalid character", field)
		}
	}
	return nil
}

func validateIPTablesTarget(target *Target) error {
	if target == nil || target.IPTables == nil {
		return nil
	}
	attachments := target.IPTables.Attachments
	if len(attachments) == 0 {
		return fmt.Errorf("firewall target: iptables requires at least one attachment for a non-empty target")
	}
	seenAttachments := make(map[string]struct{}, len(attachments))
	for index, attachment := range attachments {
		field := fmt.Sprintf("iptables attachment %d", index)
		if err := validateIPTablesIdentifier(attachment.Chain, field+" chain", maxIPTChainNameBytes, false); err != nil {
			return err
		}
		if attachment.Direction != string(policy.Ingress) && attachment.Direction != string(policy.Egress) {
			return fmt.Errorf("firewall target: %s has invalid direction %q", field, attachment.Direction)
		}
		for interfaceIndex, name := range attachment.InputInterfaces {
			if err := validateIPTablesIdentifier(name, fmt.Sprintf("%s input interface %d", field, interfaceIndex), 15, true); err != nil {
				return err
			}
		}
		for interfaceIndex, name := range attachment.OutputInterfaces {
			if err := validateIPTablesIdentifier(name, fmt.Sprintf("%s output interface %d", field, interfaceIndex), 15, true); err != nil {
				return err
			}
		}
		if attachment.Chain != "INPUT" && attachment.Chain != "OUTPUT" {
			if attachment.Direction == string(policy.Ingress) && len(attachment.InputInterfaces) == 0 {
				return fmt.Errorf("firewall target: %s requires an input interface for custom ingress parent", field)
			}
			if attachment.Direction == string(policy.Egress) && len(attachment.OutputInterfaces) == 0 {
				return fmt.Errorf("firewall target: %s requires an output interface for custom egress parent", field)
			}
		}
		key := attachmentIdentity(attachment)
		if _, exists := seenAttachments[key]; exists {
			return fmt.Errorf("firewall target: duplicate iptables attachment %q", attachment.Chain)
		}
		seenAttachments[key] = struct{}{}
	}

	seenNative := make(map[string]string)
	for _, attachment := range attachments {
		seenNative[attachment.Chain] = "parent/" + attachment.Chain
	}
	addNative := func(name, identity string, limit int) error {
		if len([]byte(name)) > limit || name == "" {
			return fmt.Errorf("firewall target: generated iptables name %q exceeds native limit", name)
		}
		if previous, exists := seenNative[name]; exists && previous != identity {
			return fmt.Errorf("firewall target: iptables native name %q collides between %s and %s", name, previous, identity)
		}
		seenNative[name] = identity
		return nil
	}
	for _, family := range target.Families {
		if !validFamily(family.Family) {
			continue
		}
		for _, set := range family.Sets {
			if set.Kind != policy.StaticSet {
				continue
			}
			if err := addNative(iptSetName(target, family.Family, set.ID), "set/"+familyToken(family.Family)+"/"+set.ID, maxIPTSetNameBytes); err != nil {
				return err
			}
		}
		for _, attachment := range attachments {
			if attachment.Direction != string(policy.Ingress) && attachment.Direction != string(policy.Egress) {
				continue
			}
			entry := iptEntryChainName(target, family.Family, attachment)
			if err := addNative(entry, "entry/"+familyToken(family.Family)+"/"+attachmentIdentity(attachment), maxIPTChainNameBytes); err != nil {
				return err
			}
			if len(attachment.InputInterfaces) != 0 || len(attachment.OutputInterfaces) != 0 {
				filter := iptFilterChainName(target, family.Family, attachment)
				if err := addNative(filter, "filter/"+familyToken(family.Family)+"/"+attachmentIdentity(attachment), maxIPTChainNameBytes); err != nil {
					return err
				}
			}
			staging := iptGenerationChainName(target, family.Family, attachmentDirection(attachment), attachment.OriginalDestination)
			if err := addNative(staging, "staging/"+familyToken(family.Family)+"/"+string(attachment.Direction)+"/"+strconv.FormatBool(attachment.OriginalDestination), maxIPTChainNameBytes); err != nil {
				return err
			}
		}
	}
	return nil
}

func attachmentDirection(attachment config.Attachment) policy.Direction {
	if attachment.Direction == string(policy.Egress) {
		return policy.Egress
	}
	return policy.Ingress
}

func loweredIPTPrefixes(values []netip.Prefix, family policy.Family) ([]netip.Prefix, error) {
	seen := make(map[netip.Prefix]struct{}, len(values))
	result := make([]netip.Prefix, 0, len(values))
	appendPrefix := func(prefix netip.Prefix) {
		prefix = prefix.Masked()
		if _, exists := seen[prefix]; exists {
			return
		}
		seen[prefix] = struct{}{}
		result = append(result, prefix)
	}
	for _, prefix := range values {
		if !prefix.IsValid() {
			return nil, fmt.Errorf("invalid prefix %q", prefix)
		}
		if family == policy.IPv4 && !prefix.Addr().Is4() {
			return nil, fmt.Errorf("IPv4 set contains %s", prefix)
		}
		if family == policy.IPv6 && !prefix.Addr().Is6() {
			return nil, fmt.Errorf("IPv6 set contains %s", prefix)
		}
		if prefix.Bits() == 0 {
			if family == policy.IPv4 {
				appendPrefix(netip.MustParsePrefix("0.0.0.0/1"))
				appendPrefix(netip.MustParsePrefix("128.0.0.0/1"))
			} else {
				appendPrefix(netip.MustParsePrefix("::/1"))
				appendPrefix(netip.MustParsePrefix("8000::/1"))
			}
			continue
		}
		appendPrefix(prefix)
	}
	sort.Slice(result, func(i, j int) bool {
		if compare := result[i].Addr().Compare(result[j].Addr()); compare != 0 {
			return compare < 0
		}
		return result[i].Bits() < result[j].Bits()
	})
	return result, nil
}

func findFamilyPlan(target *Target, family policy.Family) (policy.FamilyPlan, bool) {
	for _, plan := range target.Families {
		if plan.Family == family {
			return plan, true
		}
	}
	return policy.FamilyPlan{}, false
}

func findPath(plan policy.FamilyPlan, direction policy.Direction) (policy.Path, bool) {
	for _, path := range plan.Paths {
		if path.Direction == direction {
			return path, true
		}
	}
	return policy.Path{}, false
}

func buildIPTFamily(target *Target, family policy.Family) (iptFamilyModel, error) {
	model := iptFamilyModel{Family: family}
	if target == nil {
		return model, fmt.Errorf("iptables model: nil target")
	}
	if !validFamily(family) {
		return model, fmt.Errorf("iptables model: unsupported family %d", family)
	}
	if err := validateIPTablesTarget(target); err != nil {
		return model, err
	}
	if target.IPTables == nil {
		return model, fmt.Errorf("iptables model: target has no iptables attachment configuration")
	}
	plan, exists := findFamilyPlan(target, family)
	if !exists {
		return model, nil
	}

	sets := append([]policy.PrefixSet(nil), plan.Sets...)
	sort.SliceStable(sets, func(i, j int) bool { return sets[i].ID < sets[j].ID })
	setNames := make(map[string]string, len(sets))
	for _, set := range sets {
		if set.Kind != policy.StaticSet {
			return model, fmt.Errorf("iptables model: set %q is not static", set.ID)
		}
		prefixes, err := loweredIPTPrefixes(set.Prefixes, family)
		if err != nil {
			return model, fmt.Errorf("iptables model: set %q: %w", set.ID, err)
		}
		name := iptSetName(target, family, set.ID)
		if previous, collision := setNames[set.ID]; collision && previous != name {
			return model, fmt.Errorf("iptables model: set %q maps to conflicting native names %q and %q", set.ID, previous, name)
		}
		setNames[set.ID] = name
		model.Sets = append(model.Sets, iptSet{Name: name, Family: family, Prefixes: prefixes})
	}

	profiles := make(map[policy.Direction]map[bool]struct{}, 2)
	for _, attachment := range target.IPTables.Attachments {
		direction := attachmentDirection(attachment)
		if profiles[direction] == nil {
			profiles[direction] = make(map[bool]struct{})
		}
		profiles[direction][attachment.OriginalDestination] = struct{}{}
	}
	for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
		path, ok := findPath(plan, direction)
		if !ok {
			return model, fmt.Errorf("iptables model: family %d is missing %s path", family, direction)
		}
		for originalDestination := range profiles[direction] {
			name := iptGenerationChainName(target, family, direction, originalDestination)
			rules, err := buildIPTPathRules(target, family, path, setNames, originalDestination)
			if err != nil {
				return model, err
			}
			model.Staging = append(model.Staging, iptChain{Name: name, Rules: rules})
		}
	}
	sort.Slice(model.Staging, func(i, j int) bool { return model.Staging[i].Name < model.Staging[j].Name })

	for _, attachment := range target.IPTables.Attachments {
		direction := attachmentDirection(attachment)
		if _, ok := findPath(plan, direction); !ok {
			return model, fmt.Errorf("iptables model: family %d is missing %s path", family, direction)
		}
		entryName := iptEntryChainName(target, family, attachment)
		stagingName := iptGenerationChainName(target, family, direction, attachment.OriginalDestination)
		entryRules := buildIPTEntryRules(target, family, direction, stagingName)
		model.Active = append(model.Active, iptChain{Name: entryName, Rules: entryRules})
		jumpTarget := entryName
		if len(attachment.InputInterfaces) != 0 || len(attachment.OutputInterfaces) != 0 {
			filterName := iptFilterChainName(target, family, attachment)
			filterRules := buildIPTInterfaceRules(target, family, attachment, entryName)
			model.Active = append(model.Active, iptChain{Name: filterName, Rules: filterRules})
			jumpTarget = filterName
		}
		commentRole := "attachment/" + familyToken(family) + "/" + safeAttachmentIdentity(attachment)
		model.Attachments = append(model.Attachments, iptAttachment{
			Parent: attachment.Chain,
			Rule:   iptOwnedRule([]string{"-j", jumpTarget}, target.Owner, stableToken, commentRole, true),
		})
	}
	return model, nil
}

func buildIPTEntryRules(target *Target, family policy.Family, direction policy.Direction, staging string) []iptRule {
	role := entryRole(family, direction)
	return []iptRule{
		iptOwnedRule(nil, target.Owner, stableToken, role+"/processed", true),
		iptOwnedRule([]string{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN"}, target.Owner, stableToken, role+"/established", true),
		iptOwnedRule([]string{"-m", "conntrack", "!", "--ctstate", "NEW", "-j", "RETURN"}, target.Owner, stableToken, role+"/not-new", true),
		iptOwnedRule([]string{"-j", staging}, target.Owner, target.Generation, role+"/dispatch", false),
	}
}

func buildIPTInterfaceRules(target *Target, family policy.Family, attachment config.Attachment, entry string) []iptRule {
	inputs := attachment.InputInterfaces
	outputs := attachment.OutputInterfaces
	if len(inputs) == 0 {
		inputs = []string{""}
	}
	if len(outputs) == 0 {
		outputs = []string{""}
	}
	result := make([]iptRule, 0, len(inputs)*len(outputs))
	index := 0
	for _, input := range inputs {
		for _, output := range outputs {
			args := make([]string, 0, 8)
			if input != "" {
				args = append(args, "-i", input)
			}
			if output != "" {
				args = append(args, "-o", output)
			}
			args = append(args, "-g", entry)
			role := "filter/" + familyToken(family) + "/" + safeAttachmentIdentity(attachment) + "/" + strconv.Itoa(index)
			result = append(result, iptOwnedRule(args, target.Owner, stableToken, role, true))
			index++
		}
	}
	return result
}

func iptTrafficVariants(scope policy.Scope, family policy.Family, originalDestination bool, action policy.Action) [][]string {
	if scope.Any {
		if action != policy.Reject {
			return [][]string{{}}
		}
		return [][]string{{"-p", "tcp", "-j", "REJECT", "--reject-with", "tcp-reset"}, {"!", "-p", "tcp", "-j", "REJECT", "--reject-with", iptAdminReject(family)}}
	}
	result := make([][]string, 0, len(scope.TCP)+len(scope.UDP)+1)
	for _, port := range scope.TCP {
		result = append(result, append([]string{"-p", "tcp"}, iptPortArgs(port, originalDestination)...))
	}
	for _, port := range scope.UDP {
		result = append(result, append([]string{"-p", "udp"}, iptPortArgs(port, originalDestination)...))
	}
	if scope.ICMP {
		protocol := "icmp"
		if family == policy.IPv6 {
			protocol = "icmpv6"
		}
		result = append(result, []string{"-p", protocol})
	}
	for index := range result {
		if action != policy.Reject {
			continue
		}
		isTCP := len(result[index]) >= 2 && result[index][0] == "-p" && result[index][1] == "tcp"
		if isTCP {
			result[index] = append(result[index], "-j", "REJECT", "--reject-with", "tcp-reset")
		} else {
			result[index] = append(result[index], "-j", "REJECT", "--reject-with", iptAdminReject(family))
		}
	}
	return result
}

func iptAdminReject(family policy.Family) string {
	if family == policy.IPv6 {
		return "icmp6-adm-prohibited"
	}
	return "icmp-admin-prohibited"
}

func iptPortArgs(port policy.PortRange, originalDestination bool) []string {
	value := strconv.FormatUint(uint64(port.Start), 10)
	if port.Start != port.End {
		value += ":" + strconv.FormatUint(uint64(port.End), 10)
	}
	if originalDestination {
		return []string{"-m", "conntrack", "--ctorigdstport", value}
	}
	return []string{"--dport", value}
}

func iptActionArgs(action policy.Action) []string {
	switch action {
	case policy.Return:
		return []string{"-j", "RETURN"}
	case policy.Drop:
		return []string{"-j", "DROP"}
	case policy.Reject:
		// Reject variants append their complete target in iptTrafficVariants.
		return nil
	default:
		return nil
	}
}

func buildIPTPathRules(target *Target, family policy.Family, path policy.Path, setNames map[string]string, originalDestination bool) ([]iptRule, error) {
	if path.Remote != policy.SourceAddress && path.Remote != policy.DestinationAddress {
		return nil, fmt.Errorf("iptables model: %s path has invalid remote field %q", path.Direction, path.Remote)
	}
	result := make([]iptRule, 0, len(path.Rules))
	role := chainRole(family, path.Direction)
	index := 0
	for _, logical := range path.Rules {
		switch logical.Action {
		case policy.Return, policy.Drop, policy.Reject:
		default:
			return nil, fmt.Errorf("iptables model: unsupported rule action %q", logical.Action)
		}
		if !validTrafficScope(logical.Match.Traffic) {
			return nil, fmt.Errorf("iptables model: rule %d has an invalid traffic scope", index)
		}
		if logical.Match.Flow != "" {
			if logical.Match.Flow != policy.EstablishedRelated && logical.Match.Flow != policy.NotNew {
				return nil, fmt.Errorf("iptables model: unsupported flow guard %q", logical.Match.Flow)
			}
			if !logical.Match.Traffic.Any || logical.Match.SetID != "" || logical.Policy != "" {
				return nil, fmt.Errorf("iptables model: flow guard has unexpected match metadata")
			}
			continue
		}
		if logical.Match.NegateSet && logical.Match.SetID != "geo_eligible" {
			return nil, fmt.Errorf("iptables model: unsupported negated set %q", logical.Match.SetID)
		}
		setArgs := make([]string, 0, 5)
		if logical.Match.SetID != "" {
			name, ok := setNames[logical.Match.SetID]
			if !ok {
				return nil, fmt.Errorf("iptables model: rule references unknown set %q", logical.Match.SetID)
			}
			remote := "src"
			if path.Remote == policy.DestinationAddress {
				remote = "dst"
			}
			setArgs = append(setArgs, "-m", "set")
			if logical.Match.NegateSet {
				setArgs = append(setArgs, "!")
			}
			setArgs = append(setArgs, "--match-set", name, remote)
		}
		variants := iptTrafficVariants(logical.Match.Traffic, family, originalDestination, logical.Action)
		if len(variants) == 0 {
			return nil, fmt.Errorf("iptables model: rule %d has an empty traffic scope", index)
		}
		for _, variant := range variants {
			args := append(append([]string(nil), setArgs...), variant...)
			if logical.Action != policy.Reject || !containsJump(args, "REJECT") {
				args = append(args, iptActionArgs(logical.Action)...)
			}
			commentRole := role + "/rule/" + strconv.Itoa(index)
			if logical.Counter.Kind == policy.Denied {
				commentRole += "/denied/" + string(logical.Counter.Reason) + "/" + string(logical.Counter.Action)
			}
			result = append(result, iptOwnedRule(args, target.Owner, target.Generation, commentRole, false))
			index++
		}
	}
	return result, nil
}

func containsJump(args []string, target string) bool {
	for index := 0; index+1 < len(args); index++ {
		if args[index] == "-j" && args[index+1] == target {
			return true
		}
	}
	return false
}
