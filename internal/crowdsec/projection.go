package crowdsec

import (
	"container/heap"
	"encoding/binary"
	"math/bits"
	"net/netip"
	"sort"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
)

type uint128 struct {
	hi uint64
	lo uint64
}

type projectionBoundary struct {
	value uint128
	top   bool
}

type projectionEvent struct {
	at     projectionBoundary
	index  int
	remove bool
}

type projectionRange struct {
	start    uint128
	end      projectionBoundary
	deadline time.Time
}

type projectionHeapItem struct {
	index    int
	deadline time.Time
}

type projectionDeadlineHeap struct {
	items []projectionHeapItem
}

func (h projectionDeadlineHeap) Len() int { return len(h.items) }
func (h projectionDeadlineHeap) Less(i, j int) bool {
	return h.items[i].deadline.After(h.items[j].deadline)
}
func (h projectionDeadlineHeap) Swap(i, j int) { h.items[i], h.items[j] = h.items[j], h.items[i] }
func (h *projectionDeadlineHeap) Push(value any) {
	h.items = append(h.items, value.(projectionHeapItem))
}

func (h *projectionDeadlineHeap) Pop() any {
	last := len(h.items) - 1
	value := h.items[last]
	h.items = h.items[:last]
	return value
}

func (h *projectionDeadlineHeap) current(active []bool) (projectionHeapItem, bool) {
	for h.Len() != 0 {
		top := h.items[0]
		if active[top.index] {
			return top, true
		}
		heap.Pop(h)
	}
	return projectionHeapItem{}, false
}

func (s *Store) projection(now time.Time) []policy.TimedPrefix {
	if len(s.decisions) == 0 {
		return nil
	}
	decisions := make([]Decision, 0, len(s.decisions))
	for _, retained := range s.decisions {
		decision := retained.decision
		if decision.Deadline.After(now) {
			decisions = append(decisions, decision)
		}
	}
	if len(decisions) == 0 {
		return nil
	}

	result := make([]policy.TimedPrefix, 0, len(decisions))
	result = projectFamily(result, decisions, true, now)
	result = projectFamily(result, decisions, false, now)
	return result
}

func projectFamily(result []policy.TimedPrefix, decisions []Decision, ipv4 bool, now time.Time) []policy.TimedPrefix {
	events := make([]projectionEvent, 0, len(decisions)*2)
	for index, decision := range decisions {
		prefix := decision.Prefix
		if prefix.Addr().Is4() != ipv4 || !decision.Deadline.After(now) {
			continue
		}
		width := 128
		start := addr128(prefix.Masked().Addr())
		if ipv4 {
			width = 32
			start = addr128v4(prefix.Masked().Addr().As4())
		}
		end := prefixEnd(start, prefix.Bits(), width)
		events = append(events,
			projectionEvent{at: projectionBoundary{value: start}, index: index},
			projectionEvent{at: end, index: index, remove: true},
		)
	}
	if len(events) == 0 {
		return result
	}
	sort.Slice(events, func(i, j int) bool {
		return compareBoundary(events[i].at, events[j].at) < 0
	})

	active := make([]bool, len(decisions))
	deadlines := projectionDeadlineHeap{items: make([]projectionHeapItem, 0, len(decisions))}
	var ranges []projectionRange
	for index := 0; index < len(events); {
		nextIndex := index + 1
		for nextIndex < len(events) && compareBoundary(events[index].at, events[nextIndex].at) == 0 {
			nextIndex++
		}
		for eventIndex := index; eventIndex < nextIndex; eventIndex++ {
			event := events[eventIndex]
			if event.remove {
				active[event.index] = false
			}
		}
		for eventIndex := index; eventIndex < nextIndex; eventIndex++ {
			event := events[eventIndex]
			if !event.remove {
				active[event.index] = true
				heap.Push(&deadlines, projectionHeapItem{index: event.index, deadline: decisions[event.index].Deadline})
			}
		}
		if nextIndex == len(events) {
			break
		}
		next := events[nextIndex].at
		best, ok := deadlines.current(active)
		if ok && compareBoundary(events[index].at, next) < 0 {
			start := events[index].at.value
			if len(ranges) != 0 && ranges[len(ranges)-1].end.value == start && !ranges[len(ranges)-1].end.top && ranges[len(ranges)-1].deadline.Equal(best.deadline) {
				ranges[len(ranges)-1].end = next
			} else {
				ranges = append(ranges, projectionRange{start: start, end: next, deadline: best.deadline})
			}
		}
		index = nextIndex
	}

	for _, value := range ranges {
		result = decomposeRange(result, value.start, value.end, value.deadline, ipv4)
	}
	return result
}

func addr128(value netip.Addr) uint128 {
	bytes := value.As16()
	return uint128{
		hi: uint64(bytes[0])<<56 | uint64(bytes[1])<<48 | uint64(bytes[2])<<40 | uint64(bytes[3])<<32 |
			uint64(bytes[4])<<24 | uint64(bytes[5])<<16 | uint64(bytes[6])<<8 | uint64(bytes[7]),
		lo: uint64(bytes[8])<<56 | uint64(bytes[9])<<48 | uint64(bytes[10])<<40 | uint64(bytes[11])<<32 |
			uint64(bytes[12])<<24 | uint64(bytes[13])<<16 | uint64(bytes[14])<<8 | uint64(bytes[15]),
	}
}

func addr128v4(value [4]byte) uint128 {
	return uint128{lo: uint64(value[0])<<24 | uint64(value[1])<<16 | uint64(value[2])<<8 | uint64(value[3])}
}

func prefixEnd(start uint128, prefixBits, width int) projectionBoundary {
	sizeBits := width - prefixBits
	return addPower(start, sizeBits, width)
}

func addPower(start uint128, sizeBits, width int) projectionBoundary {
	if sizeBits == width {
		return projectionBoundary{top: true}
	}
	value := start
	if sizeBits < 64 {
		increment := uint64(1) << uint(sizeBits)
		var carry uint64
		value.lo, carry = bits.Add64(value.lo, increment, 0)
		var overflow uint64
		value.hi, overflow = bits.Add64(value.hi, 0, carry)
		if overflow != 0 || (width < 64 && (value.hi != 0 || value.lo >= uint64(1)<<uint(width))) {
			return projectionBoundary{top: true}
		}
		return projectionBoundary{value: value}
	}
	if sizeBits == 64 {
		var overflow uint64
		value.hi, overflow = bits.Add64(value.hi, 1, 0)
		if overflow != 0 {
			return projectionBoundary{top: true}
		}
		return projectionBoundary{value: value}
	}
	increment := uint64(1) << uint(sizeBits-64)
	var overflow uint64
	value.hi, overflow = bits.Add64(value.hi, increment, 0)
	if overflow != 0 {
		return projectionBoundary{top: true}
	}
	return projectionBoundary{value: value}
}

func compareUint128(left, right uint128) int {
	if left.hi < right.hi {
		return -1
	}
	if left.hi > right.hi {
		return 1
	}
	if left.lo < right.lo {
		return -1
	}
	if left.lo > right.lo {
		return 1
	}
	return 0
}

func compareBoundary(left, right projectionBoundary) int {
	if left.top {
		if right.top {
			return 0
		}
		return 1
	}
	if right.top {
		return -1
	}
	return compareUint128(left.value, right.value)
}

func aligned(start uint128, sizeBits, width int) bool {
	if sizeBits == 0 {
		return true
	}
	if sizeBits == width {
		return start.hi == 0 && start.lo == 0
	}
	if sizeBits < 64 {
		return start.lo&((uint64(1)<<uint(sizeBits))-1) == 0
	}
	if sizeBits == 64 {
		return start.lo == 0
	}
	return start.lo == 0 && start.hi&((uint64(1)<<uint(sizeBits-64))-1) == 0
}

func decomposeRange(result []policy.TimedPrefix, start uint128, end projectionBoundary, deadline time.Time, ipv4 bool) []policy.TimedPrefix {
	width := 128
	if ipv4 {
		width = 32
	}
	for {
		if end.top {
			if start.hi == 0 && start.lo == 0 {
				if width == 128 {
					result = append(result, policy.TimedPrefix{Prefix: netip.MustParsePrefix("::/0"), Deadline: deadline})
				} else {
					result = append(result, policy.TimedPrefix{Prefix: netip.MustParsePrefix("0.0.0.0/0"), Deadline: deadline})
				}
				return result
			}
		} else if compareUint128(start, end.value) >= 0 {
			return result
		}
		chosen := -1
		for sizeBits := width; sizeBits >= 0; sizeBits-- {
			if !aligned(start, sizeBits, width) {
				continue
			}
			candidate := addPower(start, sizeBits, width)
			if compareBoundary(candidate, end) <= 0 {
				chosen = sizeBits
				break
			}
		}
		if chosen < 0 {
			panic("crowdsec: projection range decomposition failed")
		}
		candidate := addPower(start, chosen, width)
		prefixBits := width - chosen
		var prefix netip.Prefix
		if ipv4 {
			var value [8]byte
			binary.BigEndian.PutUint64(value[:], start.lo)
			prefix = netip.PrefixFrom(netip.AddrFrom4([4]byte(value[4:])), prefixBits)
		} else {
			var value [16]byte
			binary.BigEndian.PutUint64(value[:8], start.hi)
			binary.BigEndian.PutUint64(value[8:], start.lo)
			prefix = netip.PrefixFrom(netip.AddrFrom16(value), prefixBits)
		}
		result = append(result, policy.TimedPrefix{Prefix: prefix, Deadline: deadline})
		if candidate.top {
			return result
		}
		start = candidate.value
	}
}
