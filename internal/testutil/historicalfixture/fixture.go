// Package historicalfixture loads actual pre-sharing compiler output for upgrade tests.
package historicalfixture

import (
	_ "embed"
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
)

//go:embed targets.json
var targets []byte

// Target returns a fresh recorded target, changing only its owner identity.
// The historical generation and separate policy objects are never recompiled.
func Target(backend, owner string) (*firewall.Target, error) {
	var recorded map[string]json.RawMessage
	if err := json.Unmarshal(targets, &recorded); err != nil {
		return nil, err
	}
	data, ok := recorded[backend]
	if !ok {
		return nil, fmt.Errorf("unsupported historical backend %q", backend)
	}
	data = []byte(strings.ReplaceAll(string(data), strings.Repeat("a", 32), owner))
	var target firewall.Target
	if err := json.Unmarshal(data, &target); err != nil {
		return nil, err
	}
	if err := firewall.ValidateTarget(&target); err != nil {
		return nil, err
	}
	return &target, nil
}

// Config describes the exact configuration used by the historical recorder.
func Config(backend, lapi, key string) (config.Config, error) {
	if backend != "nftables" && backend != "iptables" {
		return config.Config{}, fmt.Errorf("unsupported historical backend %q", backend)
	}
	return config.Parse([]byte(fmt.Sprintf(`version: 1
metrics:
  listen: ""
firewall:
  backend: %s
  deny_action: drop
  ipv4: true
  ipv6: true
  nftables:
    table: perimeterd
    priority: -10
  iptables:
    attachments:
      - chain: INPUT
        direction: ingress
      - chain: OUTPUT
        direction: egress
crowdsec:
  enabled: true
  lapi_url: %q
  api_key_file: %q
policies:
  - name: ssh
    direction: ingress
    priority: 10
    mode: allowlist
    traffic: ['22']
    include:
      countries: [SK]
  - name: ingress
    direction: ingress
    priority: 100
    mode: allowlist
    traffic: [any]
    include:
      countries: [CZ]
  - name: egress
    direction: egress
    priority: 100
    mode: allowlist
    traffic: [any]
    include:
      countries: [CZ]
`, backend, lapi, key)))
}

// Records supplies the small, offline country snapshot used by the recorder.
func Records() []policy.ResolvedSelector {
	return []policy.ResolvedSelector{
		{Selector: policy.Selector{Kind: policy.Country, Value: "CZ"}, IPv4: []netip.Prefix{netip.MustParsePrefix("8.20.0.2/32")}, IPv6: []netip.Prefix{netip.MustParsePrefix("2600:20::2/128")}},
		{Selector: policy.Selector{Kind: policy.Country, Value: "SK"}, IPv4: []netip.Prefix{netip.MustParsePrefix("8.21.0.2/32")}, IPv6: []netip.Prefix{netip.MustParsePrefix("2600:21::2/128")}},
	}
}
