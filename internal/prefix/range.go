package prefix

import (
	"encoding/binary"
	"fmt"
	"math/bits"
	"net/netip"
)

// Range returns the minimal exact CIDR cover of the inclusive address interval.
// It never unmaps addresses or iterates individual addresses.
func Range(start, end netip.Addr) ([]netip.Prefix, error) {
	return AppendRange(nil, start, end)
}

// AppendRange appends an exact minimal cover, reusing the destination storage.
func AppendRange(result []netip.Prefix, start, end netip.Addr) ([]netip.Prefix, error) {
	if !start.IsValid() || !end.IsValid() || start.Zone() != "" || end.Zone() != "" || start.Is4In6() || end.Is4In6() || start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
		return nil, fmt.Errorf("invalid inclusive address range")
	}
	for {
		raw := start.As16()
		trailing := bits.TrailingZeros64(binary.BigEndian.Uint64(raw[8:]))
		if trailing == 64 {
			trailing += bits.TrailingZeros64(binary.BigEndian.Uint64(raw[:8]))
		}
		trailing = min(trailing, start.BitLen())
		length := start.BitLen() - trailing
		// Start with the largest aligned block, shrinking only to fit the end.
		block := netip.PrefixFrom(start, length)
		last := rangeLast(block)
		for last.Compare(end) > 0 {
			length++
			block = netip.PrefixFrom(start, length)
			last = rangeLast(block)
		}
		result = append(result, block)
		if last == end {
			return result, nil
		}
		start = last.Next()
	}
}

func rangeLast(p netip.Prefix) netip.Addr {
	bytes := p.Addr().As16()
	offset := 0
	if p.Addr().Is4() {
		offset = 96
	}
	boundary := offset + p.Bits()
	if boundary%8 != 0 {
		bytes[boundary/8] |= byte(0xff >> uint(boundary%8))
		boundary += 8 - boundary%8
	}
	for index := boundary / 8; index < len(bytes); index++ {
		bytes[index] = 0xff
	}
	if p.Addr().Is4() {
		return netip.AddrFrom4([4]byte(bytes[12:]))
	}
	return netip.AddrFrom16(bytes)
}
