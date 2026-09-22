package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"os"

	"go.yaml.in/yaml/v3"
)

// Parse strictly decodes one YAML document, applies documented defaults, and
// performs all offline semantic validation. It never reads files, resolves
// names, contacts services, or mutates firewall state.
func Parse(data []byte) (Config, error) {
	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&root); err != nil {
		return Config{}, fmt.Errorf("configuration: malformed YAML: %w", err)
	}
	if root.Kind == 0 {
		return Config{}, errors.New("configuration: empty document")
	}
	if err := rejectDuplicateKeys(&root, "configuration"); err != nil {
		return Config{}, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, errors.New("configuration: multiple YAML documents are not allowed")
		}
		return Config{}, fmt.Errorf("configuration: malformed YAML: %w", err)
	}
	rootNode := unwrapDocument(&root)
	if err := checkRootShape(rootNode); err != nil {
		return Config{}, err
	}

	var raw rawConfig
	known := yaml.NewDecoder(bytes.NewReader(data))
	known.KnownFields(true)
	if err := known.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("configuration: %w", err)
	}
	return normalize(raw)
}

// Load reads exactly path and delegates all interpretation to Parse. It does
// not read credential files or perform any other I/O.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is intentionally selected by an authorized operator; no sandbox boundary is promised.
	if err != nil {
		return Config{}, fmt.Errorf("load configuration %q: %w", path, err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("load configuration %q: %w", path, err)
	}
	return cfg, nil
}

type rawConfig struct {
	Version   *int                  `yaml:"version"`
	Logging   *rawLogging           `yaml:"logging"`
	Metrics   *rawMetrics           `yaml:"metrics"`
	Global    *rawGlobal            `yaml:"global"`
	Firewall  *rawFirewall          `yaml:"firewall"`
	Geo       *rawGeo               `yaml:"geo"`
	Providers *rawProviders         `yaml:"providers"`
	OpenZiti  *rawOpenZiti          `yaml:"openziti"`
	IPLists   map[string]*rawIPList `yaml:"ip_lists"`
	Groups    map[string][]string   `yaml:"groups"`
	Policies  []rawPolicy           `yaml:"policies"`
	CrowdSec  *rawCrowdSec          `yaml:"crowdsec"`
}

type rawOpenZiti struct {
	Identities map[string]*rawOpenZitiIdentity `yaml:"identities"`
}

type rawOpenZitiIdentity struct {
	IdentityFile *string `yaml:"identity_file"`
}

type rawTransport struct {
	Type     *string `yaml:"type"`
	Identity *string `yaml:"identity"`
	Service  *string `yaml:"service"`
}

type rawIPList struct {
	URL             *string       `yaml:"url"`
	RefreshInterval *string       `yaml:"refresh_interval"`
	RequestTimeout  *string       `yaml:"request_timeout"`
	Transport       *rawTransport `yaml:"transport"`
}

type rawLogging struct {
	Level  *string `yaml:"level"`
	Format *string `yaml:"format"`
}

type rawMetrics struct {
	Listen *string `yaml:"listen"`
}

type rawGlobal struct {
	Allowlist *[]string `yaml:"allowlist"`
	Blocklist *[]string `yaml:"blocklist"`
}

type rawFirewall struct {
	Backend    *string      `yaml:"backend"`
	DenyAction *string      `yaml:"deny_action"`
	IPv4       *bool        `yaml:"ipv4"`
	IPv6       *bool        `yaml:"ipv6"`
	Nftables   *rawNftables `yaml:"nftables"`
	IPTables   *rawIPTables `yaml:"iptables"`
}

type rawNftables struct {
	Table    *string `yaml:"table"`
	Priority *int64  `yaml:"priority"`
}

type rawIPTables struct {
	Attachments *[]rawAttachment `yaml:"attachments"`
}

type rawAttachment struct {
	Chain               *string   `yaml:"chain"`
	Direction           *string   `yaml:"direction"`
	InputInterfaces     *[]string `yaml:"input_interfaces"`
	OutputInterfaces    *[]string `yaml:"output_interfaces"`
	OriginalDestination *bool     `yaml:"original_destination"`
}

type rawGeo struct {
	RefreshInterval *string `yaml:"refresh_interval"`
	RequestTimeout  *string `yaml:"request_timeout"`
	RefreshJitter   *string `yaml:"refresh_jitter"`
}

type rawProviders struct {
	RefreshInterval *string `yaml:"refresh_interval"`
	RequestTimeout  *string `yaml:"request_timeout"`
}

type rawCrowdSec struct {
	Enabled         *bool         `yaml:"enabled"`
	LAPIURL         *string       `yaml:"lapi_url"`
	APIKeyFile      *string       `yaml:"api_key_file"`
	UpdateFrequency *string       `yaml:"update_frequency"`
	Transport       *rawTransport `yaml:"transport"`
}

type rawPolicy struct {
	Name      *string      `yaml:"name"`
	Priority  *int64       `yaml:"priority"`
	Direction *string      `yaml:"direction"`
	Mode      *string      `yaml:"mode"`
	Traffic   *[]string    `yaml:"traffic"`
	Include   *rawSelector `yaml:"include"`
	Exclude   *rawSelector `yaml:"exclude"`
}

type rawSelector struct {
	Countries *[]string `yaml:"countries"`
	RIRs      *[]string `yaml:"rirs"`
	Groups    *[]string `yaml:"groups"`
	ASNs      *[]string `yaml:"asns"`
	IPLists   *[]string `yaml:"ip_lists"`
	Providers *[]string `yaml:"providers"`
}

type nodeKind uint8

const (
	kindMap nodeKind = iota
	kindSeq
	kindString
	kindInt
	kindBool
)

func unwrapDocument(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		return node.Content[0]
	}
	return node
}

func rejectDuplicateKeys(node *yaml.Node, path string) error {
	if node.Kind == yaml.DocumentNode {
		for _, child := range node.Content {
			if err := rejectDuplicateKeys(child, path); err != nil {
				return err
			}
		}
		return nil
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("%s: mapping keys must be strings", path)
			}
			if _, exists := seen[key.Value]; exists {
				return fmt.Errorf("%s.%s: duplicate key", path, key.Value)
			}
			seen[key.Value] = struct{}{}
			if err := rejectDuplicateKeys(value, path+"."+key.Value); err != nil {
				return err
			}
		}
	} else {
		for _, child := range node.Content {
			if err := rejectDuplicateKeys(child, path); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkRootShape(root *yaml.Node) error {
	if err := expectNode(root, kindMap, "configuration"); err != nil {
		return err
	}
	return checkMappingFields(root, "configuration", map[string]nodeKind{
		"version": kindInt, "logging": kindMap, "metrics": kindMap, "global": kindMap, "firewall": kindMap,
		"geo": kindMap, "providers": kindMap, "openziti": kindMap, "ip_lists": kindMap, "groups": kindMap, "policies": kindSeq, "crowdsec": kindMap,
	}, map[string]func(*yaml.Node, string) error{
		"logging": checkLogging, "metrics": checkMetrics, "global": checkGlobal, "firewall": checkFirewall,
		"geo": checkGeo, "providers": checkProviders, "openziti": checkOpenZiti, "ip_lists": checkIPListsShape, "groups": checkGroupsShape, "policies": checkPoliciesShape, "crowdsec": checkCrowdSec,
	})
}

func checkMappingFields(node *yaml.Node, path string, kinds map[string]nodeKind, nested map[string]func(*yaml.Node, string) error) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		name := key.Value
		expected, ok := kinds[name]
		if !ok {
			continue
		}
		if err := expectNode(value, expected, path+"."+name); err != nil {
			return err
		}
		if fn := nested[name]; fn != nil {
			if err := fn(value, path+"."+name); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkLogging(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"level": kindString, "format": kindString}, nil)
}

func checkMetrics(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"listen": kindString}, nil)
}

func checkGlobal(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"allowlist": kindSeq, "blocklist": kindSeq}, map[string]func(*yaml.Node, string) error{"allowlist": checkStringSequence, "blocklist": checkStringSequence})
}

func checkGeo(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"refresh_interval": kindString, "request_timeout": kindString, "refresh_jitter": kindString}, nil)
}

func checkProviders(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"refresh_interval": kindString, "request_timeout": kindString}, nil)
}

func checkCrowdSec(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"enabled": kindBool, "lapi_url": kindString, "api_key_file": kindString, "update_frequency": kindString, "transport": kindMap}, map[string]func(*yaml.Node, string) error{"transport": checkTransportShape})
}

func checkOpenZiti(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"identities": kindMap}, map[string]func(*yaml.Node, string) error{"identities": checkIdentitiesShape})
}

func checkIdentitiesShape(node *yaml.Node, path string) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("%s: identity names must be strings", path)
		}
		entryPath := path + "." + key.Value
		if err := expectNode(value, kindMap, entryPath); err != nil {
			return err
		}
		if err := checkMappingFields(value, entryPath, map[string]nodeKind{"identity_file": kindString}, nil); err != nil {
			return err
		}
	}
	return nil
}

func checkTransportShape(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"type": kindString, "identity": kindString, "service": kindString}, nil)
}

func checkFirewall(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"backend": kindString, "deny_action": kindString, "ipv4": kindBool, "ipv6": kindBool, "nftables": kindMap, "iptables": kindMap}, map[string]func(*yaml.Node, string) error{"nftables": checkNftables, "iptables": checkIPTables})
}

func checkNftables(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"table": kindString, "priority": kindInt}, nil)
}

func checkIPTables(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"attachments": kindSeq}, map[string]func(*yaml.Node, string) error{"attachments": checkAttachmentsShape})
}

func checkAttachmentsShape(node *yaml.Node, path string) error {
	for i, item := range node.Content {
		if err := expectNode(item, kindMap, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
		if err := checkMappingFields(item, fmt.Sprintf("%s[%d]", path, i), map[string]nodeKind{"chain": kindString, "direction": kindString, "input_interfaces": kindSeq, "output_interfaces": kindSeq, "original_destination": kindBool}, map[string]func(*yaml.Node, string) error{"input_interfaces": checkStringSequence, "output_interfaces": checkStringSequence}); err != nil {
			return err
		}
	}
	return nil
}

func checkIPListsShape(node *yaml.Node, path string) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("%s: list names must be strings", path)
		}
		entryPath := path + "." + key.Value
		if err := expectNode(value, kindMap, entryPath); err != nil {
			return err
		}
		if err := checkMappingFields(value, entryPath, map[string]nodeKind{
			"url": kindString, "refresh_interval": kindString, "request_timeout": kindString, "transport": kindMap,
		}, map[string]func(*yaml.Node, string) error{"transport": checkTransportShape}); err != nil {
			return err
		}
	}
	return nil
}

func checkGroupsShape(node *yaml.Node, path string) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("%s: group names must be strings", path)
		}
		if err := expectNode(value, kindSeq, path+"."+key.Value); err != nil {
			return err
		}
		if err := checkStringSequence(value, path+"."+key.Value); err != nil {
			return err
		}
	}
	return nil
}

func checkPoliciesShape(node *yaml.Node, path string) error {
	for i, item := range node.Content {
		if err := expectNode(item, kindMap, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
		if err := checkPolicyShape(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

func checkPolicyShape(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"name": kindString, "priority": kindInt, "direction": kindString, "mode": kindString, "traffic": kindSeq, "include": kindMap, "exclude": kindMap}, map[string]func(*yaml.Node, string) error{"traffic": checkStringSequence, "include": checkSelectorShape, "exclude": checkSelectorShape})
}

func checkSelectorShape(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"countries": kindSeq, "rirs": kindSeq, "groups": kindSeq, "asns": kindSeq, "ip_lists": kindSeq, "providers": kindSeq}, map[string]func(*yaml.Node, string) error{"countries": checkStringSequence, "rirs": checkStringSequence, "groups": checkStringSequence, "asns": checkStringSequence, "ip_lists": checkStringSequence, "providers": checkStringSequence})
}

func checkStringSequence(node *yaml.Node, path string) error {
	for i, item := range node.Content {
		if err := expectNode(item, kindString, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

func expectNode(node *yaml.Node, expected nodeKind, path string) error {
	ok := false
	switch expected {
	case kindMap:
		ok = node.Kind == yaml.MappingNode && node.Tag == "!!map"
	case kindSeq:
		ok = node.Kind == yaml.SequenceNode && node.Tag == "!!seq"
	case kindString:
		ok = node.Kind == yaml.ScalarNode && node.Tag == "!!str"
	case kindInt:
		ok = node.Kind == yaml.ScalarNode && node.Tag == "!!int"
	case kindBool:
		ok = node.Kind == yaml.ScalarNode && node.Tag == "!!bool"
	}
	if !ok {
		return fmt.Errorf("%s: wrong YAML type", path)
	}
	return nil
}
