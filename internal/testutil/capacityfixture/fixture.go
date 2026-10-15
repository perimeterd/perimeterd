// Package capacityfixture supplies stable, non-coalescing production-shaped
// geography for both native measurements and daemon lifecycle regressions.
package capacityfixture

import (
	"encoding/binary"
	"fmt"
	"net/netip"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/config/catalog"
	"github.com/perimeterd/perimeterd/internal/policy"
)

// Production membership counts and stable test identities are shared by gates.
const (
	IPv4Memberships          = 152419
	IPv6Memberships          = 31565
	MinimumStaticMemberships = 368147
	Owner                    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	InitialID                = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
	SSHID                    = "cccccccccccccccccccccccccccccccc"
	RefreshID                = "dddddddddddddddddddddddddddddddd"
)

// YAML uses the real built-in euro-atlantic group, never a smaller replacement.
// Addresses ending in .2/::2 are packet peers; .1/::1 are their isolated hosts.
func YAML(table, lapi, key string, ssh bool) string {
	text := fmt.Sprintf(`version: 1
logging:
  level: info
metrics:
  listen: ""
firewall:
  backend: nftables
  deny_action: drop
  ipv4: true
  ipv6: true
  nftables:
    table: %q
    priority: -10
geo:
  refresh_interval: 1h
  request_timeout: 30s
crowdsec:
  enabled: true
  lapi_url: %q
  api_key_file: %q
  update_frequency: 10s
policies:
`, table, lapi, key)
	if ssh {
		text += `  - name: ssh
    direction: ingress
    priority: 10
    mode: allowlist
    include:
      countries: [CZ, SK]
    traffic: ['22']
`
	}
	return text + `  - name: ingress
    direction: ingress
    priority: 100
    mode: allowlist
    include:
      groups: [euro-atlantic]
    traffic: [any]
  - name: egress
    direction: egress
    priority: 100
    mode: allowlist
    include:
      groups: [euro-atlantic]
    traffic: [any]
`
}

// Records has exactly the observed geo membership per family. A refresh moves
// every synthetic address, but preserves packet peers. Each host prefix is
// separated by an unused address, resisting compiler and native coalescing.
func Records(refresh bool) []policy.ResolvedSelector {
	countries, _ := catalog.Countries("euro-atlantic")
	records := make([]policy.ResolvedSelector, 0, len(countries))
	for _, country := range countries {
		record := policy.ResolvedSelector{Selector: policy.Selector{Kind: policy.Country, Value: country}}
		switch country {
		case "CZ":
			record.IPv4 = []netip.Prefix{netip.MustParsePrefix("8.20.0.2/32")}
			record.IPv6 = []netip.Prefix{netip.MustParsePrefix("2600:20::2/128")}
		case "SK":
			record.IPv4 = []netip.Prefix{netip.MustParsePrefix("8.21.0.2/32")}
			record.IPv6 = []netip.Prefix{netip.MustParsePrefix("2600:21::2/128")}
		case "US":
			record.IPv4 = make([]netip.Prefix, IPv4Memberships-2)
			record.IPv6 = make([]netip.Prefix, IPv6Memberships-2)
			record.IPv4[0] = netip.MustParsePrefix("8.22.0.2/32")
			record.IPv6[0] = netip.MustParsePrefix("2600:22::2/128")
			offset := uint32(0)
			if refresh {
				offset = 1_000_000
			}
			for index := 1; index < len(record.IPv4); index++ {
				var address [4]byte
				binary.BigEndian.PutUint32(address[:], 0x0b000000+2*(uint32(index)+offset))
				record.IPv4[index] = netip.PrefixFrom(netip.AddrFrom4(address), 32)
			}
			for index := 1; index < len(record.IPv6); index++ {
				var address [16]byte
				address[0], address[1] = 0x26, 0x04
				binary.BigEndian.PutUint64(address[8:], 2*(uint64(index)+uint64(offset)))
				record.IPv6[index] = netip.PrefixFrom(netip.AddrFrom16(address), 128)
			}
		}
		records = append(records, record)
	}
	return records
}

// Compile lowers a deterministic two/three-policy geography without live feeds.
func Compile(table string, ssh, refresh bool) (config.Config, policy.State, error) {
	cfg, err := config.Parse([]byte(YAML(table, "http://127.0.0.1:18080", "/unused/fixture-key", ssh)))
	if err != nil {
		return cfg, policy.State{}, err
	}
	snapshot, err := policy.NewSnapshot(Records(refresh))
	if err != nil {
		return cfg, policy.State{}, err
	}
	model, err := policy.Compile(cfg, snapshot)
	return cfg, model, err
}

// Memberships reports compiled counts, including compiler-owned eligibility and
// global sets rather than assuming that input record counts survived reduction.
func Memberships(families []policy.FamilyPlan) (int, map[string]int) {
	total := 0
	counts := make(map[string]int)
	for _, family := range families {
		for _, set := range family.Sets {
			if set.Kind != policy.StaticSet {
				continue
			}
			counts[fmt.Sprintf("%s/ipv%d", set.ID, family.Family)] = len(set.Prefixes)
			total += len(set.Prefixes)
		}
	}
	return total, counts
}
