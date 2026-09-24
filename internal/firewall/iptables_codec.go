package firewall

import (
	"errors"
	"fmt"
	"iter"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"github.com/perimeterd/perimeterd/internal/policy"
)

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

func parseIPTablesSave(family policy.Family, data []byte) (*iptInventory, error) {
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
			key := iptChainKey{Family: family, Table: table, Chain: fields[0]}
			if _, exists := result.Chains[key]; exists {
				return nil, errors.New("duplicate chain")
			}
			result.Chains[key] = iptObservedChain{iptChainKey: key}
			continue
		}
		var packets, byteCount uint64
		hasCounters := false
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
			hasCounters = true
			line = strings.TrimSpace(line[end+1:])
		}
		tokens, literals, err := splitIPTLine(line)
		if err != nil {
			return nil, err
		}
		if len(tokens) < 2 || tokens[0] != "-A" {
			return nil, fmt.Errorf("unsupported save line %d", lineNo+1)
		}
		key := iptChainKey{Family: family, Table: table, Chain: tokens[1]}
		chain, exists := result.Chains[key]
		if !exists {
			return nil, errors.New("rule references undeclared chain")
		}
		rule := iptObservedRule{iptChainKey: key, Args: tokens[2:], Packets: packets, Bytes: byteCount, HasCounters: hasCounters}
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

func iptRuleKey(args []string) string {
	var result strings.Builder
	for _, token := range canonicalIPTRule(args) {
		result.WriteString(strconv.Itoa(len(token)))
		result.WriteByte(':')
		result.WriteString(token)
	}
	return result.String()
}
