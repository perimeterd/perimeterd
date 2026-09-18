package firewall

import (
	"errors"
	"slices"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
)

const maximumLease = 24 * time.Hour

// LeaseGrant rounds down remaining authority to native granularity before
// applying the cross-backend cap. A zero grant must never reach a native tool:
// it means omission, not a permanent ban. Only a truncated lease is renewed.
func LeaseGrant(deadline, now time.Time, unit time.Duration) (grant time.Duration, renewAt time.Time) {
	if unit <= 0 || deadline.IsZero() {
		return 0, time.Time{}
	}
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		return 0, time.Time{}
	}
	rounded := remaining / unit * unit
	if rounded <= maximumLease {
		return rounded, time.Time{}
	}
	return maximumLease, now.Add(maximumLease / 2)
}

// ValidateDynamic checks projection shape before it can authorize a native
// mutation. Expired deadlines are valid here: backends omit them at dispatch.
// A projection may contain either family, including families not enabled on a
// target; each backend filters those rather than broadening its owned scope.
// Mapped IPv6 prefixes can arise while splitting otherwise non-mapped IPv6
// ranges. Keep their 128-bit family; never reinterpret them as IPv4 authority.
func ValidateDynamic(values []policy.TimedPrefix) error {
	for _, value := range values {
		if !value.Prefix.IsValid() || value.Prefix != value.Prefix.Masked() {
			return errors.New("firewall dynamic projection contains an invalid canonical prefix")
		}
		if value.Deadline.IsZero() {
			return errors.New("firewall dynamic projection requires an absolute deadline")
		}
	}
	compare := func(a, b policy.TimedPrefix) int {
		if order := a.Prefix.Addr().Compare(b.Prefix.Addr()); order != 0 {
			return order
		}
		return a.Prefix.Bits() - b.Prefix.Bits()
	}
	ordered := values
	if !slices.IsSortedFunc(values, compare) {
		ordered = slices.Clone(values)
		slices.SortFunc(ordered, compare)
	}
	for index := 1; index < len(ordered); index++ {
		if ordered[index-1].Prefix.Overlaps(ordered[index].Prefix) {
			return errors.New("firewall dynamic projection contains overlapping prefixes")
		}
	}
	return nil
}
