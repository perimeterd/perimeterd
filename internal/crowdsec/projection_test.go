package crowdsec

import (
	"net/netip"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestProjectionUsesMaximumDeadlineAndCoalescesOnlyEqualDeadlines(t *testing.T) {
	now := time.Now()
	short := now.Add(10 * time.Minute)
	long := now.Add(20 * time.Minute)
	store := NewStore("lapi", 1)
	if err := store.Apply(Batch{Startup: true, New: []Decision{
		{ID: 1, Prefix: netip.MustParsePrefix("10.0.0.0/8"), Deadline: short},
		{ID: 2, Prefix: netip.MustParsePrefix("10.1.0.0/16"), Deadline: long},
		{ID: 3, Prefix: netip.MustParsePrefix("10.2.0.0/16"), Deadline: long},
	}}, 1, now); err != nil {
		t.Fatal(err)
	}
	projection := store.Projection(now)
	for _, value := range projection {
		if value.Prefix.Contains(netip.MustParseAddr("10.1.1.1")) || value.Prefix.Contains(netip.MustParseAddr("10.2.1.1")) {
			if !value.Deadline.Equal(long) {
				t.Fatalf("overlap deadline = %v, want %v", value.Deadline, long)
			}
		}
		if value.Prefix.Contains(netip.MustParseAddr("10.3.1.1")) && !value.Deadline.Equal(short) {
			t.Fatalf("uncovered overlap deadline = %v, want %v", value.Deadline, short)
		}
	}
	if got := deadlineFor(projection, netip.MustParseAddr("10.1.1.1")); !got.Equal(long) {
		t.Fatalf("narrow overlap deadline = %v, want %v", got, long)
	}
	if got := deadlineFor(projection, netip.MustParseAddr("10.3.1.1")); !got.Equal(short) {
		t.Fatalf("broad-only deadline = %v, want %v", got, short)
	}
	for index := 1; index < len(projection); index++ {
		if projection[index-1].Prefix.Overlaps(projection[index].Prefix) {
			t.Fatalf("projection prefixes overlap: %v and %v", projection[index-1].Prefix, projection[index].Prefix)
		}
	}
}

func TestProjectionHandlesFamilyBoundariesAndMaximumAddresses(t *testing.T) {
	now := time.Now()
	deadline := now.Add(time.Hour)
	store := NewStore("lapi", 1)
	if err := store.Apply(Batch{Startup: true, New: []Decision{
		{ID: 1, Prefix: netip.MustParsePrefix("255.255.255.255/32"), Deadline: deadline},
		{ID: 2, Prefix: netip.MustParsePrefix("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff/128"), Deadline: deadline},
		{ID: 3, Prefix: netip.MustParsePrefix("0.0.0.0/0"), Deadline: deadline},
		{ID: 4, Prefix: netip.MustParsePrefix("::/0"), Deadline: deadline},
	}}, 1, now); err != nil {
		t.Fatal(err)
	}
	projection := store.Projection(now)
	if got := deadlineFor(projection, netip.MustParseAddr("255.255.255.255")); !got.Equal(deadline) {
		t.Fatalf("IPv4 maximum missing from projection: %v", got)
	}
	if got := deadlineFor(projection, netip.MustParseAddr("ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")); !got.Equal(deadline) {
		t.Fatalf("IPv6 maximum missing from projection: %v", got)
	}
	if len(projection) != 2 || projection[0].Prefix != netip.MustParsePrefix("0.0.0.0/0") || projection[1].Prefix != netip.MustParsePrefix("::/0") {
		t.Fatalf("full-family projection was not coalesced: %#v", projection)
	}
}

func TestProjectionSplitsIPv4MaximumWhenDeadlinesDiffer(t *testing.T) {
	now := time.Now()
	short := now.Add(time.Minute)
	long := now.Add(2 * time.Minute)
	store := NewStore("lapi", 1)
	if err := store.Apply(Batch{Startup: true, New: []Decision{
		{ID: 1, Prefix: netip.MustParsePrefix("0.0.0.0/0"), Deadline: short},
		{ID: 2, Prefix: netip.MustParsePrefix("255.255.255.255/32"), Deadline: long},
	}}, 1, now); err != nil {
		t.Fatal(err)
	}
	projection := store.Projection(now)
	if got := deadlineFor(projection, netip.MustParseAddr("0.0.0.1")); !got.Equal(short) {
		t.Fatalf("broad deadline = %v, want %v", got, short)
	}
	if got := deadlineFor(projection, netip.MustParseAddr("255.255.255.255")); !got.Equal(long) {
		t.Fatalf("maximum-address deadline = %v, want %v", got, long)
	}
	for _, value := range projection {
		if value.Prefix.Addr().Is6() {
			t.Fatalf("IPv4 projection emitted IPv6 prefix %v", value.Prefix)
		}
	}
}

func TestProjectionRetainsMappedIPv6RangeWithoutIPv4Authority(t *testing.T) {
	now := time.Now()
	short, long := now.Add(time.Hour), now.Add(2*time.Hour)
	store := NewStore("lapi", 1)
	if err := store.Apply(Batch{Startup: true, New: []Decision{
		{ID: 1, Prefix: netip.MustParsePrefix("::/80"), Deadline: short},
		{ID: 2, Prefix: netip.MustParsePrefix("::fffe:0:0/96"), Deadline: long},
	}}, 1, now); err != nil {
		t.Fatal(err)
	}
	projection := store.Projection(now)
	if err := firewall.ValidateDynamic(projection); err != nil {
		t.Fatalf("accepted source ranges produced inadmissible authority: %v", err)
	}
	if got := deadlineFor(projection, netip.MustParseAddr("::ffff:192.0.2.1")); !got.Equal(short) {
		t.Fatalf("mapped IPv6 range changed deadline: %v", got)
	}
	if got := deadlineFor(projection, netip.MustParseAddr("::fffe:0:1")); !got.Equal(long) {
		t.Fatalf("longer overlap changed deadline: %v", got)
	}
	if got := deadlineFor(projection, netip.MustParseAddr("192.0.2.1")); !got.IsZero() {
		t.Fatalf("IPv6 projection created IPv4 authority: %v", got)
	}
}

func deadlineFor(values []policy.TimedPrefix, address netip.Addr) time.Time {
	for _, value := range values {
		if value.Prefix.Contains(address) {
			return value.Deadline
		}
	}
	return time.Time{}
}
