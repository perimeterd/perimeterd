package policy

import (
	"net/netip"

	"github.com/perimeterd/perimeterd/internal/prefix"
)

// The tables below are the normative IANA special-purpose baseline reviewed on
// 2026-09-07. They are deliberately compiled into the binary: policy
// enforcement never follows network refreshes or netip's evolving classifiers.
var (
	geoIPv4 = buildGeoEligible(
		[]string{"0.0.0.0/0"},
		[]string{
			"0.0.0.0/8",
			"10.0.0.0/8",
			"172.16.0.0/12",
			"192.168.0.0/16",
			"100.64.0.0/10",
			"127.0.0.0/8",
			"169.254.0.0/16",
			"192.0.0.0/24",
			"192.0.2.0/24",
			"198.51.100.0/24",
			"203.0.113.0/24",
			"192.88.99.0/24",
			"198.18.0.0/15",
			"224.0.0.0/4",
			"240.0.0.0/4",
		},
		[]string{"192.0.0.9/32", "192.0.0.10/32"},
	)
	geoIPv6 = buildGeoEligible(
		[]string{"2000::/3", "64:ff9b::/96"},
		[]string{"2001::/23", "2001:db8::/32", "3fff::/20", "2002::/16"},
		[]string{
			"2001:1::1/128",
			"2001:1::2/128",
			"2001:1::3/128",
			"2001:3::/32",
			"2001:4:112::/48",
			"2001:20::/28",
			"2001:30::/28",
		},
	)
)

func geoEligible(family Family) prefix.Set {
	switch family {
	case IPv4:
		return geoIPv4
	case IPv6:
		return geoIPv6
	default:
		return prefix.Set{}
	}
}

func buildGeoEligible(base, excluded, restored []string) prefix.Set {
	baseSet := mustPrefixSet(base)
	excludedSet := mustPrefixSet(excluded)
	restoredSet := mustPrefixSet(restored)
	return prefix.Union(prefix.Difference(baseSet, excludedSet), restoredSet)
}

func mustPrefixSet(values []string) prefix.Set {
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		parsed, err := netip.ParsePrefix(value)
		if err != nil {
			panic("invalid compiled-in geo prefix " + value)
		}
		prefixes = append(prefixes, parsed.Masked())
	}
	set, err := prefix.New(prefixes)
	if err != nil {
		panic("invalid compiled-in geo prefix set")
	}
	return set
}
