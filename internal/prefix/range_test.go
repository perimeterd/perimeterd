package prefix

import (
	"net/netip"
	"slices"
	"testing"
)

func TestRangeExactMinimalBoundaries(t *testing.T) {
	for _, test := range []struct {
		start, end string
		want       []string
	}{
		{"192.0.2.1", "192.0.2.1", []string{"192.0.2.1/32"}},
		{"0.0.0.0", "255.255.255.255", []string{"0.0.0.0/0"}},
		{"::", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", []string{"::/0"}},
		{"255.255.255.254", "255.255.255.255", []string{"255.255.255.254/31"}},
		{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe", "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff", []string{"ffff:ffff:ffff:ffff:ffff:ffff:ffff:fffe/127"}},
		{"192.0.2.1", "192.0.2.6", []string{"192.0.2.1/32", "192.0.2.2/31", "192.0.2.4/31", "192.0.2.6/32"}},
		{"2001:db8::1", "2001:db8::6", []string{"2001:db8::1/128", "2001:db8::2/127", "2001:db8::4/127", "2001:db8::6/128"}},
	} {
		t.Run(test.start+"-"+test.end, func(t *testing.T) {
			got, err := Range(netip.MustParseAddr(test.start), netip.MustParseAddr(test.end))
			if err != nil {
				t.Fatal(err)
			}
			want := make([]netip.Prefix, 0, len(test.want))
			for _, s := range test.want {
				want = append(want, netip.MustParsePrefix(s))
			}
			if !slices.Equal(got, want) {
				t.Fatalf("got %v want %v", got, want)
			}
		})
	}
}

func TestRangeRejectsAmbiguousAndInvalidIntervals(t *testing.T) {
	for _, pair := range [][2]string{{"192.0.2.2", "192.0.2.1"}, {"192.0.2.1", "::1"}, {"::ffff:192.0.2.1", "::ffff:192.0.2.2"}, {"fe80::1%eth0", "fe80::2%eth0"}} {
		if _, err := Range(netip.MustParseAddr(pair[0]), netip.MustParseAddr(pair[1])); err == nil {
			t.Fatalf("accepted %v", pair)
		}
	}
	if _, err := Range(netip.Addr{}, netip.Addr{}); err == nil {
		t.Fatal("accepted zero address")
	}
}

func TestRangeExactContainmentSmallIntervals(t *testing.T) {
	base := netip.MustParseAddr("192.0.2.0")
	for start := range 32 {
		for end := start; end < 32; end++ {
			a, b := base, base
			for range start {
				a = a.Next()
			}
			for range end {
				b = b.Next()
			}
			got, err := Range(a, b)
			if err != nil {
				t.Fatal(err)
			}
			probe := base
			for n := range 33 {
				count := 0
				for _, p := range got {
					if p.Contains(probe) {
						count++
					}
				}
				want := 0
				if n >= start && n <= end {
					want = 1
				}
				if count != want {
					t.Fatalf("%v-%v includes %v %d times", a, b, probe, count)
				}
				probe = probe.Next()
			}
		}
	}
}
