package firewall

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"

	"github.com/perimeterd/perimeterd/internal/policy"
)

// CounterSnapshot is one owned native counter value. Rule is an opaque
// backend-local identity used to track resets; it is not an operator label.
type CounterSnapshot struct {
	Backend          string
	Generation       string
	Rule             string
	Family           policy.Family
	Direction        policy.Direction
	Reason           policy.DenyReason
	Action           policy.Action
	ProcessedPackets uint64
	ProcessedBytes   uint64
	DeniedPackets    uint64
	DeniedBytes      uint64
	Retired          bool
}

// CounterSnapshotter exposes current cumulative native counters for one target.
// Implementations read only perimeterd-owned counters and never mutate rules.
type CounterSnapshotter interface {
	SnapshotCounters(context.Context, *Target) (map[string]CounterSnapshot, error)
}

// CounterRetirementHook consumes the final snapshot immediately before an old
// generation's native objects are removed. A failed telemetry read is reported
// to the hook but never prevents enforcement retirement.
type CounterRetirementHook func([]CounterSnapshot, error)

type counterRetirementReporter struct {
	mu   sync.RWMutex
	hook CounterRetirementHook
}

func (r *counterRetirementReporter) set(hook CounterRetirementHook) {
	if r == nil {
		return
	}
	r.mu.Lock()
	r.hook = hook
	r.mu.Unlock()
}

func (r *counterRetirementReporter) enabled() bool {
	if r == nil {
		return false
	}
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.hook != nil
}

func (r *counterRetirementReporter) report(target *Target, values map[string]CounterSnapshot, err error) {
	if r == nil || target == nil {
		return
	}
	r.mu.RLock()
	hook := r.hook
	r.mu.RUnlock()
	if hook == nil {
		return
	}
	if err != nil {
		hook([]CounterSnapshot{{Backend: target.Backend(), Generation: target.Generation, Retired: true}}, err)
		return
	}
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	rows := []CounterSnapshot{{Backend: target.Backend(), Generation: target.Generation, Retired: true}}
	for _, key := range keys {
		value := values[key]
		value.Retired = true
		rows = append(rows, value)
	}
	hook(rows, nil)
}

func counterSnapshotKey(generation, rule string) string {
	return generation + "/" + rule
}

func newCounterSnapshot(target *Target, rule string, family policy.Family, direction policy.Direction, role policy.CounterRole, packets, byteCount uint64) (CounterSnapshot, error) {
	if target == nil || rule == "" || !validFamily(family) || !validDirection(direction) || !validRole(role) {
		return CounterSnapshot{}, errors.New("firewall counter snapshot has invalid identity")
	}
	value := CounterSnapshot{
		Backend: target.Backend(), Generation: target.Generation, Rule: rule,
		Family: family, Direction: direction,
	}
	if role.Kind == policy.Processed {
		value.ProcessedPackets, value.ProcessedBytes = packets, byteCount
	} else {
		value.Reason, value.Action = role.Reason, role.Action
		value.DeniedPackets, value.DeniedBytes = packets, byteCount
	}
	return value, nil
}

func addCounterSnapshot(values map[string]CounterSnapshot, value CounterSnapshot) error {
	if len(values) >= maxCounterSnapshotRows {
		return fmt.Errorf("firewall counter snapshot exceeds %d rules", maxCounterSnapshotRows)
	}
	key := counterSnapshotKey(value.Generation, value.Rule)
	if _, exists := values[key]; exists {
		return fmt.Errorf("firewall counter snapshot has duplicate rule identity %q", value.Rule)
	}
	values[key] = value
	return nil
}

const maxCounterSnapshotRows = 1 << 16

var (
	_ CounterSnapshotter = (*NFT)(nil)
	_ CounterSnapshotter = (*IPTables)(nil)
	_ CounterSnapshotter = (*Native)(nil)
)
