package crowdsec

import (
	"fmt"
	"net/netip"
	"slices"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
)

// Decision is one independently expiring CrowdSec decision. ID is retained as
// provenance in the authoritative store even when projection coalesces ranges.
type Decision struct {
	ID       int64
	Prefix   netip.Prefix
	Deadline time.Time
}

// Batch is one validated source update. A startup batch is an authoritative
// replacement; incremental batches delete before adding updates.
type Batch struct {
	Startup bool
	New     []Decision
	Deleted []int64
}

// Store is the in-memory authoritative decision set for one endpoint and
// client epoch. Its methods are called under the application serialization
// fence; it intentionally has no internal mutex.
type Store struct {
	endpoint string
	epoch    uint64
	revision uint64

	decisions map[int64]retainedDecision

	lastSequence uint64
	hasSequence  bool
}

type retainedDecision struct {
	decision Decision
	sequence uint64
}

// NewStore creates an empty authoritative decision store.
func NewStore(endpoint string, epoch uint64) *Store {
	return &Store{endpoint: endpoint, epoch: epoch, decisions: make(map[int64]retainedDecision)}
}

// Endpoint identifies the credential-free source endpoint represented by the store.
func (s *Store) Endpoint() string {
	if s == nil {
		return ""
	}
	return s.endpoint
}

// Epoch identifies the source-client epoch that owns this store.
func (s *Store) Epoch() uint64 {
	if s == nil {
		return 0
	}
	return s.epoch
}

// Revision is the monotonic desired-state revision. It advances for authority,
// provenance, prefix, deadline, or expiry changes, not for unknown deletions.
func (s *Store) Revision() uint64 {
	if s == nil {
		return 0
	}
	return s.revision
}

// Decisions returns a deterministic immutable snapshot of every retained
// decision. The returned slice and its values are independent of the store;
// callers may retain it as acknowledged provenance without observing later
// desired-state changes.
func (s *Store) Decisions() []Decision {
	if s == nil || len(s.decisions) == 0 {
		return nil
	}
	out := make([]Decision, 0, len(s.decisions))
	for _, retained := range s.decisions {
		out = append(out, retained.decision)
	}
	slices.SortFunc(out, func(a, b Decision) int {
		return cmpInt64(a.ID, b.ID)
	})
	return out
}

// CountFamilies reports retained decisions whose absolute deadlines are still
// in the future, without allocating a snapshot slice.
func (s *Store) CountFamilies(now time.Time) (ipv4, ipv6 int) {
	if s == nil {
		return 0, 0
	}
	for _, retained := range s.decisions {
		if !retained.decision.Deadline.After(now) {
			continue
		}
		if retained.decision.Prefix.Addr().Is4() {
			ipv4++
		} else {
			ipv6++
		}
	}
	return ipv4, ipv6
}

func cmpInt64(a, b int64) int {
	if a < b {
		return -1
	}
	if a > b {
		return 1
	}
	return 0
}

// Apply validates and atomically admits one source batch. Sequence values must
// be strictly increasing after the first admitted batch. A failed validation
// leaves both the decision set and the sequence watermark untouched.
func (s *Store) Apply(batch Batch, sequence uint64, now time.Time) error {
	if s == nil {
		return fmt.Errorf("crowdsec store: nil store")
	}
	if sequence == 0 {
		return fmt.Errorf("crowdsec store: batch sequence must be positive")
	}
	if s.hasSequence && sequence <= s.lastSequence {
		return fmt.Errorf("crowdsec store: stale batch sequence %d (last %d)", sequence, s.lastSequence)
	}
	if err := validateBatch(batch); err != nil {
		return err
	}

	changed := batchChanges(s.decisions, batch, sequence, now)
	if changed && s.revision == ^uint64(0) {
		return fmt.Errorf("crowdsec store: desired revision exhausted")
	}
	if s.decisions == nil {
		s.decisions = make(map[int64]retainedDecision, len(batch.New))
	}
	if batch.Startup {
		clear(s.decisions)
	} else {
		for id, retained := range s.decisions {
			if !retained.decision.Deadline.After(now) {
				delete(s.decisions, id)
			}
		}
	}
	for _, id := range batch.Deleted {
		delete(s.decisions, id)
	}
	for _, decision := range batch.New {
		if decision.Deadline.After(now) {
			s.decisions[decision.ID] = retainedDecision{decision: decision, sequence: sequence}
		} else {
			// A response that arrived after the absolute deadline contributes no
			// membership, and also removes a previous value for this ID above.
			delete(s.decisions, decision.ID)
		}
	}

	s.lastSequence = sequence
	s.hasSequence = true
	if changed {
		s.revision++
	}
	return nil
}

func batchChanges(decisions map[int64]retainedDecision, batch Batch, sequence uint64, now time.Time) bool {
	if batch.Startup {
		if len(decisions) != 0 {
			return true
		}
		for _, decision := range batch.New {
			if decision.Deadline.After(now) {
				return true
			}
		}
		return false
	}
	for _, retained := range decisions {
		if !retained.decision.Deadline.After(now) {
			return true
		}
	}
	for _, id := range batch.Deleted {
		if _, exists := decisions[id]; exists {
			return true
		}
	}
	for _, decision := range batch.New {
		if retained, exists := decisions[decision.ID]; exists {
			if retained.sequence != sequence || retained.decision.Prefix != decision.Prefix ||
				!retained.decision.Deadline.Equal(decision.Deadline) {
				return true
			}
			continue
		}
		if decision.Deadline.After(now) {
			return true
		}
	}
	return false
}

// Expire removes every contribution whose absolute deadline is no longer in
// the future. It returns whether the authoritative set changed.
func (s *Store) Expire(now time.Time) bool {
	if s == nil || len(s.decisions) == 0 {
		return false
	}
	if s.revision == ^uint64(0) {
		return false
	}
	changed := false
	for id, retained := range s.decisions {
		if !retained.decision.Deadline.After(now) {
			delete(s.decisions, id)
			changed = true
		}
	}
	if changed {
		s.revision++
	}
	return changed
}

// Projection returns an immutable snapshot of the exact disjoint timed
// projection. It does not mutate the authoritative store; expiry is explicit
// through Expire so a caller can perform it under the same writer fence.
func (s *Store) Projection(now time.Time) []policy.TimedPrefix {
	if s == nil {
		return nil
	}
	return s.projection(now)
}

// NextExpiry returns the earliest retained absolute deadline, or the zero time
// when no decisions remain.
func (s *Store) NextExpiry() time.Time {
	if s == nil || len(s.decisions) == 0 {
		return time.Time{}
	}
	var next time.Time
	for _, retained := range s.decisions {
		if next.IsZero() || retained.decision.Deadline.Before(next) {
			next = retained.decision.Deadline
		}
	}
	return next
}

func validateBatch(batch Batch) error {
	for _, id := range batch.Deleted {
		if id <= 0 {
			return fmt.Errorf("crowdsec store: invalid deleted decision ID %d", id)
		}
	}
	seen := make(map[int64]struct{}, len(batch.New))
	for index, decision := range batch.New {
		if decision.ID <= 0 {
			return fmt.Errorf("crowdsec store: invalid decision ID %d", decision.ID)
		}
		if !decision.Prefix.IsValid() || decision.Prefix != decision.Prefix.Masked() ||
			decision.Prefix.Addr().Zone() != "" || decision.Prefix.Addr().Is4In6() {
			return fmt.Errorf("crowdsec store: new decision %d has invalid prefix", index)
		}
		if decision.Deadline.IsZero() {
			return fmt.Errorf("crowdsec store: new decision %d has zero deadline", index)
		}
		if _, exists := seen[decision.ID]; exists {
			return fmt.Errorf("crowdsec store: duplicate decision ID %d", decision.ID)
		}
		seen[decision.ID] = struct{}{}
	}
	return nil
}
