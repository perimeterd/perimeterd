package policy

import (
	"net/netip"
	"testing"
)

func TestGeoEligibleIPv4Boundaries(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"0.0.0.0", false},
		{"0.255.255.255", false},
		{"1.0.0.0", true},
		{"9.255.255.255", true},
		{"10.0.0.0", false},
		{"10.255.255.255", false},
		{"11.0.0.0", true},
		{"172.15.255.255", true},
		{"172.16.0.0", false},
		{"172.31.255.255", false},
		{"172.32.0.0", true},
		{"192.167.255.255", true},
		{"192.168.0.0", false},
		{"192.168.255.255", false},
		{"192.169.0.0", true},
		{"100.63.255.255", true},
		{"100.64.0.0", false},
		{"100.127.255.255", false},
		{"100.128.0.0", true},
		{"126.255.255.255", true},
		{"127.0.0.0", false},
		{"127.255.255.255", false},
		{"128.0.0.0", true},
		{"169.253.255.255", true},
		{"169.254.0.0", false},
		{"169.254.255.255", false},
		{"169.255.0.0", true},
		{"191.255.255.255", true},
		{"192.0.0.0", false},
		{"192.0.0.8", false},
		{"192.0.0.9", true},
		{"192.0.0.10", true},
		{"192.0.0.11", false},
		{"192.0.0.255", false},
		{"192.0.1.0", true},
		{"192.0.2.0", false},
		{"192.0.2.255", false},
		{"192.0.3.0", true},
		{"192.88.98.255", true},
		{"192.88.99.0", false},
		{"192.88.99.255", false},
		{"192.89.0.0", true},
		{"198.17.255.255", true},
		{"198.18.0.0", false},
		{"198.19.255.255", false},
		{"198.20.0.0", true},
		{"198.51.99.255", true},
		{"198.51.100.0", false},
		{"198.51.100.255", false},
		{"198.51.101.0", true},
		{"203.0.112.255", true},
		{"203.0.113.0", false},
		{"203.0.113.255", false},
		{"203.0.114.0", true},
		{"223.255.255.255", true},
		{"224.0.0.0", false},
		{"239.255.255.255", false},
		{"240.0.0.0", false},
		{"255.255.255.255", false},
	}
	checkClassifierAddresses(t, IPv4, tests)
}

func TestGeoEligibleIPv6Boundaries(t *testing.T) {
	tests := []struct {
		address string
		want    bool
	}{
		{"::", false},
		{"1fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"2000::", true},
		{"2000:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"2001::", false},
		{"2001:1ff:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"2001:200::", true},
		{"2001:0:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"2001:1::", false},
		{"2001:1::1", true},
		{"2001:1::2", true},
		{"2001:1::3", true},
		{"2001:1::4", false},
		{"2001:2::", false},
		{"2001:3::", true},
		{"2001:3:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"2001:4::", false},
		{"2001:4:112::", true},
		{"2001:4:112:ffff:ffff:ffff:ffff:ffff", true},
		{"2001:4:113::", false},
		{"2001:10::", false},
		{"2001:20::", true},
		{"2001:2f:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"2001:30::", true},
		{"2001:3f:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"2001:40::", false},
		{"2001:db7:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"2001:db8::", false},
		{"2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"2001:db9::", true},
		{"2002::", false},
		{"2002:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"2003::", true},
		{"3ffe:ffff:ffff:ffff:ffff:ffff:ffff:ffff", true},
		{"3fff::", false},
		{"3fff:fff:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"3fff:1000::", true},
		{"4000::", false},
		{"64:ff9a:ffff:ffff:ffff:ffff:ffff:ffff", false},
		{"64:ff9b::", true},
		{"64:ff9b::ffff:ffff", true},
		{"64:ff9c::", false},
	}
	checkClassifierAddresses(t, IPv6, tests)
}

func TestGeoEligibleObservationCannotMutateClassifier(t *testing.T) {
	prefixes := GeoEligible(IPv4).Prefixes()
	if len(prefixes) == 0 {
		t.Fatal("IPv4 classifier unexpectedly empty")
	}
	prefixes[0] = netip.MustParsePrefix("0.0.0.0/0")

	classifier := GeoEligible(IPv4)
	if !classifier.Contains(netip.MustParseAddr("192.0.0.9")) {
		t.Fatal("mutating Prefixes result changed restored IPv4 exception")
	}
	if classifier.Contains(netip.MustParseAddr("10.0.0.1")) {
		t.Fatal("mutating Prefixes result changed private-range exclusion")
	}
	if GeoEligible(Family(99)).Len() != 0 {
		t.Fatal("unsupported family should have an empty classifier")
	}
}

func checkClassifierAddresses(t *testing.T, family Family, tests []struct {
	address string
	want    bool
},
) {
	t.Helper()
	classifier := GeoEligible(family)
	for _, test := range tests {
		address := netip.MustParseAddr(test.address)
		if got := classifier.Contains(address); got != test.want {
			t.Errorf("GeoEligible(%d).Contains(%s) = %t, want %t", family, test.address, got, test.want)
		}
	}
}
