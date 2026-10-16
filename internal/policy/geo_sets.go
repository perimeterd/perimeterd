package policy

import (
	"crypto/sha256"
	"encoding/binary"
	"net/netip"
	"sort"

	"github.com/perimeterd/perimeterd/internal/prefix"
)

// geoSetInterner lives for one family compilation. Hashes select candidates;
// only equality of the complete canonical sequence establishes membership identity.
type geoSetInterner struct {
	sets     []PrefixSet
	buckets  map[[sha256.Size]byte][]int
	policies map[string]int
}

func compileGeoSets(family Family, policies []compiledPolicy) ([]PrefixSet, map[string]string) {
	interner := geoSetInterner{
		buckets:  make(map[[sha256.Size]byte][]int, len(policies)),
		policies: make(map[string]int, len(policies)),
	}
	for _, value := range policies {
		// Family filtering is an immutable view, not a prefix-slice copy.
		sequence := value.includedFamily(family)
		interner.intern(value.policy.Name, sequence, geoFingerprint(family, sequence))
	}
	bindings := make(map[string]string, len(policies))
	for name, index := range interner.policies {
		bindings[name] = interner.sets[index].ID
	}
	// Sorting data objects must not reorder the original policy rules.
	sort.Slice(interner.sets, func(i, j int) bool { return interner.sets[i].ID < interner.sets[j].ID })
	return interner.sets, bindings
}

func (interner *geoSetInterner) intern(name string, sequence prefix.Set, fingerprint [sha256.Size]byte) {
	id := "geo/" + name
	for _, index := range interner.buckets[fingerprint] {
		set := &interner.sets[index]
		if !equalGeoSequence(sequence, set.Prefixes) {
			continue
		}
		if id < set.ID {
			set.ID = id
		}
		interner.policies[name] = index
		return
	}
	index := len(interner.sets)
	// Copy only the first sequence in each equivalence class into retained state.
	interner.sets = append(interner.sets, PrefixSet{ID: id, Kind: StaticSet, Prefixes: sequence.Prefixes()})
	interner.buckets[fingerprint] = append(interner.buckets[fingerprint], index)
	interner.policies[name] = index
}

func equalGeoSequence(sequence prefix.Set, values []netip.Prefix) bool {
	if sequence.Len() != len(values) {
		return false
	}
	i := 0
	for value := range sequence.All() {
		if value != values[i] {
			return false
		}
		i++
	}
	return true
}

func geoFingerprint(family Family, sequence prefix.Set) [sha256.Size]byte {
	hash := sha256.New()
	var header [1 + binary.MaxVarintLen64]byte
	header[0] = byte(family)
	size := binary.PutVarint(header[1:], int64(sequence.Len()))
	_, _ = hash.Write(header[:1+size])
	for value := range sequence.All() {
		// Fixed-width canonical address bytes and a framed prefix length avoid
		// ambiguous concatenation without string or JSON serialization.
		var framed [16 + binary.MaxVarintLen64]byte
		address := value.Addr().As16()
		copy(framed[:16], address[:])
		size := binary.PutVarint(framed[16:], int64(value.Bits()))
		_, _ = hash.Write(framed[:16+size])
	}
	var result [sha256.Size]byte
	hash.Sum(result[:0])
	return result
}
