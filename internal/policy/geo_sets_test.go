package policy

import (
	"crypto/sha256"
	"net/netip"
	"testing"

	"github.com/perimeterd/perimeterd/internal/prefix"
)

func TestGeoInternerConfirmsEqualityWithinHashBucket(t *testing.T) {
	interner := geoSetInterner{
		buckets:  make(map[[sha256.Size]byte][]int),
		policies: make(map[string]int),
	}
	makeSet := func(values ...string) prefix.Set {
		t.Helper()
		prefixes := make([]netip.Prefix, len(values))
		for i, value := range values {
			prefixes[i] = netip.MustParsePrefix(value)
		}
		set, err := prefix.New(prefixes)
		if err != nil {
			t.Fatal(err)
		}
		return set
	}
	// Deliberately force unequal sequences, a proper prefix of another sequence,
	// and empty sequences into the same bucket. No real hash collision is needed.
	collision := [sha256.Size]byte{}
	first := makeSet("8.0.0.0/8", "9.0.0.0/8")
	interner.intern("zulu", first, collision)
	interner.intern("unequal", makeSet("8.0.0.0/8", "11.0.0.0/8"), collision)
	interner.intern("partial", makeSet("8.0.0.0/8"), collision)
	interner.intern("empty-z", makeSet(), collision)
	interner.intern("alpha", first, collision)
	interner.intern("empty-a", makeSet(), collision)
	if len(interner.sets) != 4 {
		t.Fatalf("collision merged unequal sequences: %#v", interner.sets)
	}
	if interner.policies["alpha"] != interner.policies["zulu"] || interner.sets[interner.policies["zulu"]].ID != "geo/alpha" {
		t.Fatalf("equal sequence did not select lexical representative: %#v", interner)
	}
	if interner.policies["empty-a"] != interner.policies["empty-z"] || interner.sets[interner.policies["empty-z"]].ID != "geo/empty-a" {
		t.Fatalf("equal empty sequences did not share: %#v", interner)
	}
}
