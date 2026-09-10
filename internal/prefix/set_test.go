package prefix

import (
	"net/netip"
	"reflect"
	"strconv"
	"testing"
)

func TestNormalizeCanonicalizesWithoutMutatingInput(t *testing.T) {
	values := []netip.Prefix{
		netip.MustParsePrefix("2001:db8:1::9/48"),
		netip.MustParsePrefix("192.0.2.99/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.0.2.128/25"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	original := append([]netip.Prefix(nil), values...)
	got, err := Normalize(values)
	if err != nil {
		t.Fatal(err)
	}
	want := []netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("2001:db8::/32"),
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("Normalize() = %v, want %v", got, want)
	}
	if !reflect.DeepEqual(values, original) {
		t.Fatalf("Normalize mutated input: got %v, want %v", values, original)
	}
}

func TestNewRejectsInvalidPrefixes(t *testing.T) {
	cases := []netip.Prefix{
		{},
		netip.PrefixFrom(netip.MustParseAddr("192.0.2.1"), 33),
		netip.PrefixFrom(netip.MustParseAddr("2001:db8::1"), 129),
	}
	for _, value := range cases {
		if _, err := New([]netip.Prefix{value}); err == nil {
			t.Errorf("New(%v) accepted invalid prefix", value)
		}
	}
}

func TestDifferenceIPv4AndIPv6Boundaries(t *testing.T) {
	include, err := New([]netip.Prefix{netip.MustParsePrefix("0.0.0.0/0")})
	if err != nil {
		t.Fatal(err)
	}
	exclude, err := New([]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/32"),
		netip.MustParsePrefix("255.255.255.255/32"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := Difference(include, exclude)
	for _, tc := range []struct {
		address string
		want    bool
	}{
		{"0.0.0.0", false},
		{"0.0.0.1", true},
		{"255.255.255.254", true},
		{"255.255.255.255", false},
	} {
		if got.Contains(netip.MustParseAddr(tc.address)) != tc.want {
			t.Errorf("Difference(/0, hosts).Contains(%s) = %v, want %v", tc.address, got.Contains(netip.MustParseAddr(tc.address)), tc.want)
		}
	}

	include6, err := New([]netip.Prefix{netip.MustParsePrefix("::/0")})
	if err != nil {
		t.Fatal(err)
	}
	exclude6, err := New([]netip.Prefix{
		netip.MustParsePrefix("::/128"),
		netip.MustParsePrefix("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got6 := Difference(include6, exclude6)
	for _, tc := range []struct {
		address string
		want    bool
	}{
		{"::", false},
		{"::1", true},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", true},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", false},
	} {
		if got6.Contains(netip.MustParseAddr(tc.address)) != tc.want {
			t.Errorf("Difference(v6 /0, hosts).Contains(%s) = %v, want %v", tc.address, got6.Contains(netip.MustParseAddr(tc.address)), tc.want)
		}
	}
}

func TestDifferenceDoesNotCrossFamilies(t *testing.T) {
	include, err := New([]netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/0"),
		netip.MustParsePrefix("::/0"),
	})
	if err != nil {
		t.Fatal(err)
	}
	exclude, err := New([]netip.Prefix{
		netip.MustParsePrefix("::/0"),
		netip.MustParsePrefix("192.0.2.0/24"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := Difference(include, exclude)
	if got.Contains(netip.MustParseAddr("192.0.2.1")) || got.Contains(netip.MustParseAddr("::1")) {
		t.Fatal("cross-family subtraction retained an excluded address")
	}
	if !got.Contains(netip.MustParseAddr("198.51.100.1")) {
		t.Fatal("IPv4 subtraction was affected by IPv6 exclusion")
	}
}

func TestDifferenceOverlappingExclusionsAndExhaustiveMembership(t *testing.T) {
	include, err := New([]netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.0.3.0/25"),
	})
	if err != nil {
		t.Fatal(err)
	}
	exclude, err := New([]netip.Prefix{
		netip.MustParsePrefix("192.0.2.0/26"),
		netip.MustParsePrefix("192.0.2.32/27"),
		netip.MustParsePrefix("192.0.2.64/26"),
		netip.MustParsePrefix("192.0.2.128/25"),
		netip.MustParsePrefix("192.0.3.64/26"),
	})
	if err != nil {
		t.Fatal(err)
	}
	got := Difference(include, exclude)
	for octet := range 256 {
		address := netip.MustParseAddr("192.0.2." + strconv.Itoa(octet))
		want := include.Contains(address) && !exclude.Contains(address)
		if got.Contains(address) != want {
			t.Fatalf("membership mismatch for %s: got %v, want %v", address, got.Contains(address), want)
		}
	}
	for octet := range 128 {
		address := netip.MustParseAddr("192.0.3." + strconv.Itoa(octet))
		want := include.Contains(address) && !exclude.Contains(address)
		if got.Contains(address) != want {
			t.Fatalf("membership mismatch for %s: got %v, want %v", address, got.Contains(address), want)
		}
	}
}

func TestUnionAndViewsAreIndependent(t *testing.T) {
	input := []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	set, err := New(input)
	if err != nil {
		t.Fatal(err)
	}
	input[0] = netip.MustParsePrefix("203.0.113.0/24")
	if !set.Contains(netip.MustParseAddr("192.0.2.1")) || set.Contains(netip.MustParseAddr("203.0.113.1")) {
		t.Fatal("New retained mutable input storage")
	}

	union := Union(set, mustNew(netip.MustParsePrefix("2001:db8::/32")))
	prefixes := union.Prefixes()
	prefixes[0] = netip.MustParsePrefix("198.51.100.0/24")
	if !union.Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("Prefixes exposed mutable storage")
	}
	v4 := union.IPv4()
	v4Prefixes := v4.Prefixes()
	v4Prefixes[0] = netip.MustParsePrefix("198.51.100.0/24")
	if !union.Contains(netip.MustParseAddr("192.0.2.1")) {
		t.Fatal("IPv4 view aliases source storage")
	}
	if union.IPv6().Len() != 1 || union.IPv4().Len() != 1 {
		t.Fatal("family views have incorrect contents")
	}
}

func mustNew(values ...netip.Prefix) Set {
	set, err := New(values)
	if err != nil {
		panic(err)
	}
	return set
}
