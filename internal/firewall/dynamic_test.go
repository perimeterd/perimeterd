package firewall

import (
	"net/netip"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestLeaseGrantBoundsRetainedDeadline(t *testing.T) {
	now := time.Now()
	deadline := now.Add(49 * time.Hour)
	grant, renew := LeaseGrant(deadline, now, time.Second)
	if grant != 24*time.Hour || !renew.Equal(now.Add(12*time.Hour)) {
		t.Fatalf("initial capped lease = %s, renewal %s", grant, renew.Sub(now))
	}
	grant, renew = LeaseGrant(deadline, now.Add(12*time.Hour), time.Second)
	if grant != 24*time.Hour || !renew.Equal(now.Add(24*time.Hour)) {
		t.Fatalf("renewed capped lease = %s, renewal %s", grant, renew.Sub(now))
	}
	// A delayed retry must use the retained deadline, not restart the source
	// duration. The final lease terminates the renewal obligation.
	grant, renew = LeaseGrant(deadline, now.Add(30*time.Hour+250*time.Millisecond), time.Second)
	if grant != 19*time.Hour-time.Second || !renew.IsZero() {
		t.Fatalf("delayed final lease = %s, renewal %s", grant, renew)
	}
	for _, unit := range []time.Duration{time.Millisecond, time.Second} {
		for _, remaining := range []time.Duration{-unit, 0, unit / 2, unit, 24*time.Hour + unit/2} {
			grant, renew = LeaseGrant(now.Add(remaining), now, unit)
			want := max(remaining/unit*unit, 0)
			if grant != want || !renew.IsZero() {
				t.Errorf("unit=%s remaining=%s grant=%s renewal=%s", unit, remaining, grant, renew)
			}
		}
	}
}

func TestDynamicProjectionRejectsOverlappingAuthority(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	entry := func(value string) policy.TimedPrefix {
		return policy.TimedPrefix{Prefix: netip.MustParsePrefix(value), Deadline: deadline}
	}
	for _, values := range [][]policy.TimedPrefix{
		{entry("8.20.0.0/24"), entry("8.20.0.2/32")},
		{entry("2600:20::/64"), entry("::/0")},
		{entry("8.20.0.2/32"), entry("8.20.0.2/32")},
		{entry("8.20.0.2/24")},
		{{Prefix: netip.MustParsePrefix("8.20.0.2/32")}},
	} {
		if err := ValidateDynamic(values); err == nil {
			t.Fatalf("accepted invalid dynamic authority: %v", values)
		}
	}
	values := []policy.TimedPrefix{entry("2600:20::/64"), entry("8.20.0.2/32"), entry("8.21.0.0/24")}
	if err := ValidateDynamic(values); err != nil {
		t.Fatal(err)
	}
	if values[0].Prefix != netip.MustParsePrefix("2600:20::/64") {
		t.Fatal("validation mutated caller projection order")
	}
}
