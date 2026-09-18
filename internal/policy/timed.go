package policy

import (
	"net/netip"
	"time"
)

// TimedPrefix is one disjoint portion of a live dynamic projection. Deadline
// retains its monotonic clock while the daemon runs; it is never persisted as
// decision authority or rebased when an enforcement attempt is retried.
type TimedPrefix struct {
	Prefix   netip.Prefix
	Deadline time.Time
}
