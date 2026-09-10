// Package prefix provides immutable operations on canonical IP prefixes.
package prefix

import (
	"errors"
	"fmt"
	"net/netip"
	"sort"
)

// Set is an immutable, canonical collection of non-overlapping IP prefixes.
//
// The zero Set is an empty set. Prefixes are sorted by family, network address,
// and prefix length. All methods that expose prefixes return independent copies.
type Set struct {
	prefixes []netip.Prefix
	v6Start  int
}

// Normalize validates prefixes, masks host bits, removes duplicates and
// contained prefixes, and returns an independently owned canonical slice.
func Normalize(values []netip.Prefix) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return []netip.Prefix{}, nil
	}
	canonical := make([]netip.Prefix, len(values))
	for i, value := range values {
		if err := validate(value); err != nil {
			return nil, fmt.Errorf("prefix %d: %w", i, err)
		}
		canonical[i] = value.Masked()
	}
	return canonicalize(canonical), nil
}

// New validates and constructs an immutable prefix set from values.
func New(values []netip.Prefix) (Set, error) {
	canonical, err := Normalize(values)
	if err != nil {
		return Set{}, err
	}
	return fromCanonical(canonical), nil
}

// Union returns the canonical union of all supplied sets.
func Union(sets ...Set) Set {
	if len(sets) == 0 {
		return Set{}
	}
	total := 0
	for _, set := range sets {
		total += len(set.prefixes)
	}
	if total == 0 {
		return Set{}
	}
	merged := make([]netip.Prefix, 0, total)
	for _, set := range sets {
		merged = append(merged, set.prefixes...)
	}
	return fromCanonical(canonicalize(merged))
}

// Difference returns include minus exclude, preserving exact address
// membership independently in IPv4 and IPv6.
func Difference(include, exclude Set) Set {
	if len(include.prefixes) == 0 {
		return Set{}
	}
	if len(exclude.prefixes) == 0 {
		return fromCanonical(append([]netip.Prefix(nil), include.prefixes...))
	}

	result := make([]netip.Prefix, 0, len(include.prefixes))
	processFamily(
		include.prefixes[:include.v6Start],
		exclude.prefixes[:exclude.v6Start],
		&result,
	)
	processFamily(
		include.prefixes[include.v6Start:],
		exclude.prefixes[exclude.v6Start:],
		&result,
	)
	return fromCanonical(result)
}

// Contains reports whether addr belongs to the set.
func (set Set) Contains(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	start, end := 0, set.v6Start
	if addr.Is6() {
		start, end = set.v6Start, len(set.prefixes)
	} else if !addr.Is4() {
		return false
	}
	if start >= end {
		return false
	}
	position := sort.Search(end-start, func(i int) bool {
		return set.prefixes[start+i].Addr().Compare(addr) > 0
	})
	if position == 0 {
		return false
	}
	return set.prefixes[start+position-1].Contains(addr)
}

// Len reports the number of canonical prefixes in the set.
func (set Set) Len() int {
	return len(set.prefixes)
}

// Prefixes returns an independently owned canonical copy of the set prefixes.
func (set Set) Prefixes() []netip.Prefix {
	if len(set.prefixes) == 0 {
		return []netip.Prefix{}
	}
	return append([]netip.Prefix(nil), set.prefixes...)
}

// IPv4 returns an immutable view containing only the set's IPv4 prefixes.
func (set Set) IPv4() Set {
	return Set{prefixes: set.prefixes[:set.v6Start], v6Start: set.v6Start}
}

// IPv6 returns an immutable view containing only the set's IPv6 prefixes.
func (set Set) IPv6() Set {
	return Set{prefixes: set.prefixes[set.v6Start:]}
}

func validate(value netip.Prefix) error {
	addr := value.Addr()
	if !addr.IsValid() {
		return errors.New("invalid address")
	}
	if addr.Zone() != "" {
		return errors.New("scoped address is not allowed")
	}
	bits := value.Bits()
	maxBits := 128
	if addr.Is4() {
		maxBits = 32
	} else if !addr.Is6() {
		return errors.New("invalid address family")
	}
	if bits < 0 || bits > maxBits {
		return fmt.Errorf("invalid prefix length %d", bits)
	}
	return nil
}

func less(a, b netip.Prefix) bool {
	a4, b4 := a.Addr().Is4(), b.Addr().Is4()
	if a4 != b4 {
		return a4
	}
	if comparison := a.Addr().Compare(b.Addr()); comparison != 0 {
		return comparison < 0
	}
	return a.Bits() < b.Bits()
}

func canonicalize(values []netip.Prefix) []netip.Prefix {
	if len(values) == 0 {
		return []netip.Prefix{}
	}
	sort.Slice(values, func(i, j int) bool {
		return less(values[i], values[j])
	})
	out := values[:0]
	for _, candidate := range values {
		if len(out) != 0 && out[len(out)-1].Contains(candidate.Addr()) {
			continue
		}
		out = append(out, candidate)
	}
	return out
}

func fromCanonical(values []netip.Prefix) Set {
	if len(values) == 0 {
		return Set{}
	}
	v6Start := sort.Search(len(values), func(i int) bool {
		return values[i].Addr().Is6()
	})
	return Set{prefixes: values, v6Start: v6Start}
}

func processFamily(includes, excludes []netip.Prefix, result *[]netip.Prefix) {
	exclusionStart := 0
	for _, include := range includes {
		includeStart := include.Addr()
		includeEnd := prefixEnd(include)
		for exclusionStart < len(excludes) && prefixEnd(excludes[exclusionStart]).Compare(includeStart) < 0 {
			exclusionStart++
		}
		exclusionEnd := exclusionStart
		for exclusionEnd < len(excludes) && excludes[exclusionEnd].Addr().Compare(includeEnd) <= 0 {
			exclusionEnd++
		}
		if exclusionStart == exclusionEnd {
			*result = append(*result, include)
			continue
		}
		subtractNode(include, excludes[exclusionStart:exclusionEnd], result)
	}
}

func subtractNode(node netip.Prefix, excludes []netip.Prefix, result *[]netip.Prefix) {
	start, end := overlapRange(node, excludes)
	if start == end {
		*result = append(*result, node)
		return
	}
	if excludes[start].Bits() <= node.Bits() && excludes[start].Contains(node.Addr()) {
		return
	}
	left, right := split(node)
	if !left.IsValid() {
		return
	}
	subtractNode(left, excludes[start:end], result)
	subtractNode(right, excludes[start:end], result)
}

func overlapRange(node netip.Prefix, excludes []netip.Prefix) (int, int) {
	start := node.Addr()
	end := prefixEnd(node)
	first := sort.Search(len(excludes), func(i int) bool {
		return prefixEnd(excludes[i]).Compare(start) >= 0
	})
	last := sort.Search(len(excludes), func(i int) bool {
		return excludes[i].Addr().Compare(end) > 0
	})
	return first, last
}

func split(value netip.Prefix) (netip.Prefix, netip.Prefix) {
	bits := value.Bits()
	maxBits := 128
	if value.Addr().Is4() {
		maxBits = 32
	}
	if bits >= maxBits {
		return netip.Prefix{}, netip.Prefix{}
	}
	if value.Addr().Is4() {
		base := value.Addr().As4()
		mask := byte(1 << (7 - bits%8))
		base[bits/8] &^= mask
		left := netip.PrefixFrom(netip.AddrFrom4(base), bits+1)
		base[bits/8] |= mask
		right := netip.PrefixFrom(netip.AddrFrom4(base), bits+1)
		return left, right
	}
	base := value.Addr().As16()
	mask := byte(1 << (7 - bits%8))
	base[bits/8] &^= mask
	left := netip.PrefixFrom(netip.AddrFrom16(base), bits+1)
	base[bits/8] |= mask
	right := netip.PrefixFrom(netip.AddrFrom16(base), bits+1)
	return left, right
}

func prefixEnd(value netip.Prefix) netip.Addr {
	bits := value.Bits()
	if value.Addr().Is4() {
		address := value.Addr().As4()
		for bit := bits; bit < 32; bit++ {
			address[bit/8] |= 1 << (7 - bit%8)
		}
		return netip.AddrFrom4(address)
	}
	address := value.Addr().As16()
	for bit := bits; bit < 128; bit++ {
		address[bit/8] |= 1 << (7 - bit%8)
	}
	return netip.AddrFrom16(address)
}
