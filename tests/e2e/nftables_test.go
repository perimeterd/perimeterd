//go:build linux && e2e

package e2e

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"testing"
	"time"
)

func nftTable(t *testing.T, table string) []byte {
	t.Helper()
	output, err := nftTableMayFail(table)
	if err != nil {
		t.Fatalf("list nft table %q: %v", table, err)
	}
	return output
}

var errNFTTableNotFound = errors.New("nft table not found")

func nftTableMayFail(table string) ([]byte, error) {
	output, err := commandMayFail(5*time.Second, "nft", "-j", "list", "ruleset")
	if err != nil {
		return output, err
	}
	filtered, found, err := selectNFTTable(output, table)
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, fmt.Errorf("%w: %q", errNFTTableNotFound, table)
	}
	return filtered, nil
}

func selectNFTTable(data []byte, table string) ([]byte, bool, error) {
	var envelope struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return nil, false, fmt.Errorf("decode nft ruleset: %w", err)
	}
	if envelope.Nftables == nil {
		return nil, false, errors.New("nft ruleset is missing its object array")
	}
	selected := make([]map[string]json.RawMessage, 0)
	for _, item := range envelope.Nftables {
		for kind, raw := range item {
			var object map[string]any
			if err := json.Unmarshal(raw, &object); err != nil {
				return nil, false, fmt.Errorf("decode nft %s: %w", kind, err)
			}
			name, _ := object["name"].(string)
			parent, _ := object["table"].(string)
			if (kind == "table" && name == table) || parent == table {
				selected = append(selected, item)
				break
			}
		}
	}
	if len(selected) == 0 {
		return nil, false, nil
	}
	filtered, err := json.Marshal(struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}{Nftables: selected})
	if err != nil {
		return nil, false, fmt.Errorf("encode nft table: %w", err)
	}
	return filtered, true, nil
}

func waitNoNFTTable(t *testing.T, table string) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		_, err := nftTableMayFail(table)
		if errors.Is(err, errNFTTableNotFound) {
			return
		}
		if err != nil {
			t.Fatalf("inspect nft table %q before confirming deletion: %v", table, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	t.Fatalf("nft table %q still exists", table)
}

func createForeignTable(t *testing.T, table string) {
	t.Helper()
	batch := fmt.Sprintf(`{"nftables":[{"add":{"table":{"family":"inet","name":"%s"}}},{"add":{"chain":{"family":"inet","table":"%s","name":"foreign_child","type":"filter","hook":"input","prio":300,"policy":"accept","comment":"foreign-owner"}}}]}`, table, table)
	commandInput(t, 10*time.Second, []byte(batch), "nft", "-j", "-f", "-")
}

func flushOwnedTableRules(t *testing.T, table string) {
	t.Helper()
	batch := fmt.Sprintf(`{"nftables":[{"flush":{"table":{"family":"inet","name":"%s"}}}]}`, table)
	commandInput(t, 10*time.Second, []byte(batch), "nft", "-j", "-f", "-")
}

func objectJSON(t *testing.T, table string) any {
	t.Helper()
	var value any
	if err := json.Unmarshal(nftTable(t, table), &value); err != nil {
		t.Fatalf("decode nft JSON: %v", err)
	}
	return value
}

type nftChainMetadata struct {
	Family  string
	Table   string
	Name    string
	Type    string
	Hook    string
	Policy  string
	Comment string
	Prio    int64
}

func ownedBaseChain(t *testing.T, table string) nftChainMetadata {
	t.Helper()
	var found nftChainMetadata
	walkJSON(objectJSON(t, table), func(object map[string]any) {
		if found.Name != "" {
			return
		}
		chain, ok := object["chain"].(map[string]any)
		if !ok {
			return
		}
		hook, _ := chain["hook"].(string)
		name, _ := chain["name"].(string)
		comment, _ := chain["comment"].(string)
		if name == "" || comment == "" || (hook != "input" && hook != "output") {
			return
		}
		prio, ok := chain["prio"].(float64)
		chainType, _ := chain["type"].(string)
		policy, _ := chain["policy"].(string)
		if !ok {
			return
		}
		if chainType == "" {
			chainType = "filter"
		}
		if policy == "" {
			policy = "accept"
		}
		found = nftChainMetadata{
			Family: "inet", Table: table, Name: name, Type: chainType,
			Hook: hook, Policy: policy, Comment: comment, Prio: int64(prio),
		}
	})
	if found.Name == "" {
		t.Fatalf("owned nftables base chain not found in %q", table)
	}
	return found
}

func corruptOwnedBaseChain(t *testing.T, table string) {
	t.Helper()
	original := ownedBaseChain(t, table)
	corrupt := original
	corrupt.Hook = "forward"
	batch := map[string]any{
		"nftables": []any{
			map[string]any{"flush": map[string]any{"chain": map[string]any{"family": original.Family, "table": original.Table, "name": original.Name}}},
			map[string]any{"delete": map[string]any{"chain": map[string]any{"family": original.Family, "table": original.Table, "name": original.Name}}},
			map[string]any{"add": map[string]any{"chain": map[string]any{
				"family": corrupt.Family, "table": corrupt.Table, "name": corrupt.Name,
				"type": corrupt.Type, "hook": corrupt.Hook, "prio": corrupt.Prio,
				"policy": corrupt.Policy, "comment": corrupt.Comment,
			}}},
		},
	}
	data, err := json.Marshal(batch)
	if err != nil {
		t.Fatalf("marshal corrupt nft batch: %v", err)
	}
	commandInput(t, 10*time.Second, data, "nft", "-j", "-f", "-")
}

func walkJSON(value any, visit func(map[string]any)) {
	switch typed := value.(type) {
	case map[string]any:
		visit(typed)
		for _, child := range typed {
			walkJSON(child, visit)
		}
	case []any:
		for _, child := range typed {
			walkJSON(child, visit)
		}
	}
}

func nftCounters(t *testing.T, table string) map[string]uint64 {
	t.Helper()
	counters := make(map[string]uint64)
	walkJSON(objectJSON(t, table), func(object map[string]any) {
		counter, ok := object["counter"].(map[string]any)
		if !ok {
			return
		}
		name, _ := counter["name"].(string)
		packets, ok := counter["packets"].(float64)
		if name != "" && ok {
			counters[name] = uint64(packets)
		}
	})
	return counters
}

func nftHookPriorities(t *testing.T, table string) map[string]int64 {
	t.Helper()
	priorities := make(map[string]int64)
	walkJSON(objectJSON(t, table), func(object map[string]any) {
		chain, ok := object["chain"].(map[string]any)
		if !ok {
			return
		}
		name, _ := chain["name"].(string)
		prio, ok := chain["prio"].(float64)
		if name != "" && ok {
			priorities[name] = int64(prio)
		}
	})
	return priorities
}

func assertForeignTable(t *testing.T, table string) {
	t.Helper()
	output, err := nftTableMayFail(table)
	if err != nil {
		t.Fatalf("foreign nft table %q was removed: %v", table, err)
	}
	if !bytes.Contains(output, []byte("foreign_child")) {
		t.Fatalf("foreign nft child was removed: %s", output)
	}
}
