package firewall

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/perimeterd/perimeterd/internal/policy"
)

// SnapshotCounters reads machine-oriented save output and selects only rules
// exactly generated for the supplied perimeterd target.
func (i *IPTables) SnapshotCounters(ctx context.Context, target *Target) (map[string]CounterSnapshot, error) {
	if target == nil || target.IPTables == nil {
		return nil, errors.New("iptables backend: counter snapshot requires an iptables target")
	}
	if err := ValidateTarget(target); err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	expected, err := expectedIPTWithProjection(nil, target)
	if err != nil {
		return nil, err
	}
	inventory := newIPTInventory()
	var outputBytes int
	for _, familyPlan := range target.Families {
		family := familyPlan.Family
		output, err := i.run(ctx, familyTool(family, "-save"), []string{"--counters"}, nil)
		if err != nil {
			return nil, fmt.Errorf("%s counter snapshot: %w", familyName(family), err)
		}
		if len(output) > maxIPTablesOutput-outputBytes {
			return nil, errors.New("iptables counter snapshot exceeds output limit")
		}
		outputBytes += len(output)
		parsed, err := parseIPTablesSave(family, output)
		if err != nil {
			return nil, fmt.Errorf("%s counter snapshot: %w", familyName(family), err)
		}
		for key, chain := range parsed.Chains {
			inventory.Chains[key] = chain
		}
		inventory.Rules = append(inventory.Rules, parsed.Rules...)
	}
	return iptCounterSnapshots(target, expected.models[target], inventory)
}

// SetCounterRetirementHook installs the observer called before native counter removal.
func (i *IPTables) SetCounterRetirementHook(hook CounterRetirementHook) {
	if i == nil {
		return
	}
	if i.retirement == nil {
		i.retirement = &counterRetirementReporter{}
	}
	i.retirement.set(hook)
}

func (i *IPTables) setCounterRetirementReporter(reporter *counterRetirementReporter) {
	i.retirement = reporter
}

type iptCounterExpectation struct {
	family    policy.Family
	direction policy.Direction
	role      policy.CounterRole
}

func iptCounterSnapshots(target *Target, models map[policy.Family]iptFamilyModel, inventory *iptInventory) (map[string]CounterSnapshot, error) {
	expected := make(map[iptChainKey]map[string]iptCounterExpectation)
	for family, model := range models {
		for _, chain := range model.Active {
			for _, rule := range chain.Rules {
				direction, role, ok := iptCounterRole(target, family, rule.Args, false)
				if !ok {
					continue
				}
				if err := addIPTCounterExpectation(expected, chainKey(family, chain.Name), rule.Args, iptCounterExpectation{family: family, direction: direction, role: role}); err != nil {
					return nil, err
				}
			}
		}
		for _, chain := range model.Staging {
			for _, rule := range chain.Rules {
				direction, role, ok := iptCounterRole(target, family, rule.Args, true)
				if !ok {
					continue
				}
				if err := addIPTCounterExpectation(expected, chainKey(family, chain.Name), rule.Args, iptCounterExpectation{family: family, direction: direction, role: role}); err != nil {
					return nil, err
				}
			}
		}
	}
	result := make(map[string]CounterSnapshot)
	for key, rules := range expected {
		observed, exists := inventory.Chains[key]
		if !exists {
			return nil, fmt.Errorf("iptables backend: owned counter chain %s is absent", key.String())
		}
		found := make(map[string]bool, len(rules))
		for position, rule := range observed.Rules {
			ruleKey := iptRuleKey(rule.Args)
			expectation, wanted := rules[ruleKey]
			if !wanted {
				continue
			}
			if found[ruleKey] {
				return nil, fmt.Errorf("iptables backend: duplicate owned counter rule in %s", key.String())
			}
			if !rule.HasCounters {
				return nil, fmt.Errorf("iptables backend: owned rule in %s has no native counters", key.String())
			}
			ruleID := fmt.Sprintf("%s/%s/%s/%d", familyName(key.Family), key.Table, key.Chain, position)
			value, err := newCounterSnapshot(target, ruleID, expectation.family, expectation.direction, expectation.role, rule.Packets, rule.Bytes)
			if err != nil {
				return nil, err
			}
			if err := addCounterSnapshot(result, value); err != nil {
				return nil, err
			}
			found[ruleKey] = true
		}
		for ruleKey := range rules {
			if !found[ruleKey] {
				return nil, fmt.Errorf("iptables backend: expected owned counter rule is absent from %s", key.String())
			}
		}
	}
	return result, nil
}

func addIPTCounterExpectation(expected map[iptChainKey]map[string]iptCounterExpectation, chain iptChainKey, args []string, value iptCounterExpectation) error {
	key := iptRuleKey(args)
	if expected[chain] == nil {
		expected[chain] = make(map[string]iptCounterExpectation)
	}
	if _, exists := expected[chain][key]; exists {
		return fmt.Errorf("iptables backend: duplicate expected counter rule in %s", chain.String())
	}
	expected[chain][key] = value
	return nil
}

func iptCounterRole(target *Target, family policy.Family, args []string, generationRule bool) (policy.Direction, policy.CounterRole, bool) {
	comment, ok := iptRuleComment(args)
	if !ok {
		return "", policy.CounterRole{}, false
	}
	for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
		if !generationRule {
			want := ownershipComment(target.Owner, stableToken, entryRole(family, direction)+"/processed", true)
			if comment == want {
				return direction, policy.CounterRole{Kind: policy.Processed}, true
			}
			continue
		}
		prefix := ownershipComment(target.Owner, target.Generation, chainRole(family, direction)+"/rule/", false)
		if !strings.HasPrefix(comment, prefix) {
			continue
		}
		marker := "/denied/"
		index := strings.LastIndex(comment, marker)
		if index < len(prefix) {
			continue
		}
		if _, err := strconv.ParseUint(comment[len(prefix):index], 10, 32); err != nil {
			continue
		}
		parts := strings.Split(comment[index+len(marker):], "/")
		if len(parts) != 2 {
			continue
		}
		role := policy.CounterRole{Kind: policy.Denied, Reason: policy.DenyReason(parts[0]), Action: policy.Action(parts[1])}
		if validRole(role) {
			return direction, role, true
		}
	}
	return "", policy.CounterRole{}, false
}

func iptRuleComment(args []string) (string, bool) {
	var comment string
	for index := 0; index+3 < len(args); index++ {
		if args[index] == "-m" && args[index+1] == "comment" && args[index+2] == "--comment" {
			comment = args[index+3]
		}
	}
	return comment, comment != ""
}

var _ CounterSnapshotter = (*IPTables)(nil)
