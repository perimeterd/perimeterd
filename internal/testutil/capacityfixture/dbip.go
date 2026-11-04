package capacityfixture

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/config/catalog"
	"github.com/perimeterd/perimeterd/internal/policy"
)

// DB-IP-era counts are post-normalization memberships, not source rows.
const (
	DBIPIPv4Memberships    = 400098
	DBIPIPv6Memberships    = 482656
	DBIPSSHIPv4Memberships = 3977
	DBIPSSHIPv6Memberships = 5749
	DBIPStaticMemberships  = 892659
	DBIPProjectedBans      = 150000
)

// DBIPPrefix uses sparse ranges with realistic text lengths. The first 200000
// ranges are stable across refresh so live bans remain within the country set.
func DBIPPrefix(index int, ipv6, refresh bool) netip.Prefix {
	if refresh && index >= 200000 {
		index += 1000000
	}
	if index < 0 || index > 4_000_000 {
		panic("capacity fixture prefix index out of range")
	}
	if !ipv6 {
		var address [4]byte
		binary.BigEndian.PutUint32(address[:], 0x64000000+uint32(index)*8)
		return netip.PrefixFrom(netip.AddrFrom4(address), 30)
	}
	address := [16]byte{0x26, 0x04, 0xab, 0xcd}
	binary.BigEndian.PutUint64(address[8:], uint64(index)*8)
	return netip.PrefixFrom(netip.AddrFrom16(address), 126)
}

// DBIPRecords preserves the measured normalized counts, not just feed rows.
func DBIPRecords(refresh bool) []policy.ResolvedSelector {
	countries, _ := catalog.Countries("euro-atlantic")
	records := make([]policy.ResolvedSelector, 0, len(countries))
	for _, country := range countries {
		record := policy.ResolvedSelector{Selector: policy.Selector{Kind: policy.Country, Value: country}}
		switch country {
		case "CZ":
			record.IPv4 = append(record.IPv4, netip.MustParsePrefix("8.20.0.2/32"))
			record.IPv6 = append(record.IPv6, netip.MustParsePrefix("2600:20::2/128"))
			for i := range DBIPSSHIPv4Memberships - 2 {
				record.IPv4 = append(record.IPv4, DBIPPrefix(i, false, refresh))
			}
			for i := range DBIPSSHIPv6Memberships - 2 {
				record.IPv6 = append(record.IPv6, DBIPPrefix(i, true, refresh))
			}
		case "SK":
			record.IPv4 = []netip.Prefix{netip.MustParsePrefix("8.21.0.2/32")}
			record.IPv6 = []netip.Prefix{netip.MustParsePrefix("2600:21::2/128")}
		case "US":
			record.IPv4 = append(record.IPv4, netip.MustParsePrefix("8.22.0.2/32"))
			record.IPv6 = append(record.IPv6, netip.MustParsePrefix("2600:22::2/128"))
			for i := DBIPSSHIPv4Memberships - 2; i < DBIPIPv4Memberships-3; i++ {
				record.IPv4 = append(record.IPv4, DBIPPrefix(i, false, refresh))
			}
			for i := DBIPSSHIPv6Memberships - 2; i < DBIPIPv6Memberships-3; i++ {
				record.IPv6 = append(record.IPv6, DBIPPrefix(i, true, refresh))
			}
		}
		records = append(records, record)
	}
	return records
}

// DBIPYAML keeps incident ingress-only attachment admission separate from the
// explicitly attached bidirectional packet variant. Port shorthand 22 is TCP.
func DBIPYAML(table, lapi, key, backend string, bidirectional bool) string {
	text := YAML(table, lapi, key, true)
	text = strings.Replace(text, "traffic: ['22/tcp', '22/udp']", "traffic: ['22']", 1)
	text = strings.Replace(text, "geo:\n", "geo:\n  country_provider: ripestat\n", 1)
	attachments := "    attachments:\n      - chain: INPUT\n        direction: ingress\n      - chain: DOCKER-USER\n        direction: ingress\n        input_interfaces: [e2h0]\n        original_destination: true\n"
	if bidirectional {
		attachments += "      - chain: OUTPUT\n        direction: egress\n"
	}
	if backend == "iptables" {
		text = strings.Replace(text, "backend: nftables", "backend: iptables", 1)
		text = strings.Replace(text, fmt.Sprintf("  nftables:\n    table: %q\n    priority: -10\n", table), "  iptables:\n"+attachments, 1)
	}
	return text
}

// CompileDBIP builds the deterministic large profile through the real compiler.
func CompileDBIP(table string, refresh bool) (config.Config, policy.State, error) {
	cfg, err := config.Parse([]byte(DBIPYAML(table, "http://127.0.0.1:18080", "/unused/fixture-key", "nftables", true)))
	if err != nil {
		return cfg, policy.State{}, err
	}
	snapshot, err := policy.NewSnapshot(DBIPRecords(refresh))
	if err != nil {
		return cfg, policy.State{}, err
	}
	model, err := policy.Compile(cfg, snapshot)
	return cfg, model, err
}

// ValidateDBIP checks materialized counts and both shared-set consumers.
func ValidateDBIP(families []policy.FamilyPlan) error {
	total, counts := Memberships(families)
	if total != DBIPStaticMemberships {
		return fmt.Errorf("DB-IP static memberships=%d want=%d: %v", total, DBIPStaticMemberships, counts)
	}
	for _, family := range families {
		geo, ssh := DBIPIPv4Memberships, DBIPSSHIPv4Memberships
		if family.Family == policy.IPv6 {
			geo, ssh = DBIPIPv6Memberships, DBIPSSHIPv6Memberships
		}
		if counts[fmt.Sprintf("geo/egress/ipv%d", family.Family)] != geo || counts[fmt.Sprintf("geo/ssh/ipv%d", family.Family)] != ssh {
			return fmt.Errorf("DB-IP family counts: %v", counts)
		}
		if _, ok := counts[fmt.Sprintf("geo/ingress/ipv%d", family.Family)]; ok {
			return fmt.Errorf("DB-IP duplicated ingress set: %v", counts)
		}
		consumers := map[string]bool{}
		for _, path := range family.Paths {
			for _, rule := range path.Rules {
				if rule.Match.SetID == "geo/egress" {
					consumers[rule.Policy] = true
				}
			}
		}
		if !consumers["ingress"] || !consumers["egress"] {
			return fmt.Errorf("DB-IP sharing consumers: %v", consumers)
		}
	}
	return nil
}
