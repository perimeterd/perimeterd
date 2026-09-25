package policy

import (
	"net/netip"
	"reflect"
	"testing"
)

func TestStateZeroIsCanonicalEmpty(t *testing.T) {
	var state State
	if !state.Empty() {
		t.Fatal("zero State should be empty")
	}
	if families := state.Families(); families != nil {
		t.Fatalf("zero State Families() = %#v, want nil", families)
	}
	emptyState := State{families: make([]FamilyPlan, 0)}
	if families := emptyState.Families(); families != nil {
		t.Fatalf("empty State Families() = %#v, want nil", families)
	}
}

func TestCloneFamiliesPreservesNilAndEmptySlices(t *testing.T) {
	if got := CloneFamilies(nil); got != nil {
		t.Fatalf("CloneFamilies(nil) = %#v, want nil", got)
	}
	if got := CloneFamilies(make([]FamilyPlan, 0)); got == nil {
		t.Fatal("CloneFamilies(non-nil empty) returned nil")
	}

	values := []FamilyPlan{
		{Sets: make([]PrefixSet, 0), Paths: make([]Path, 0)},
		{Paths: []Path{{Rules: make([]Rule, 0)}}},
		{
			Sets: []PrefixSet{{Prefixes: make([]netip.Prefix, 0)}},
			Paths: []Path{{Rules: []Rule{{
				Match: Match{Traffic: Scope{
					TCP: make([]PortRange, 0),
					UDP: make([]PortRange, 0),
				}},
			}}}},
		},
		{},
	}
	cloned := CloneFamilies(values)
	if cloned[0].Sets == nil || cloned[0].Paths == nil || cloned[1].Paths[0].Rules == nil {
		t.Fatal("CloneFamilies collapsed non-nil empty nested slices")
	}
	if cloned[2].Sets[0].Prefixes == nil ||
		cloned[2].Paths[0].Rules[0].Match.Traffic.TCP == nil ||
		cloned[2].Paths[0].Rules[0].Match.Traffic.UDP == nil {
		t.Fatal("CloneFamilies collapsed non-nil empty leaf slices")
	}
	if cloned[3].Sets != nil || cloned[3].Paths != nil {
		t.Fatalf("CloneFamilies changed absent nested slices: %#v", cloned[3])
	}
}

func TestStateFamiliesDeepCopy(t *testing.T) {
	firstPrefix := netip.MustParsePrefix("192.0.2.0/24")
	secondPrefix := netip.MustParsePrefix("2001:db8::/32")
	newFamilies := func() []FamilyPlan {
		return []FamilyPlan{{
			Family: IPv4,
			Sets:   []PrefixSet{{ID: "geo/example", Kind: StaticSet, Prefixes: []netip.Prefix{firstPrefix}}},
			Paths: []Path{{
				Direction: Ingress,
				Remote:    SourceAddress,
				Processed: CounterRole{Kind: Processed},
				Rules: []Rule{{
					Match: Match{Flow: EstablishedRelated, SetID: "geo/example", Traffic: Scope{
						TCP:  []PortRange{{Start: 22, End: 22}},
						UDP:  []PortRange{{Start: 53, End: 53}},
						ICMP: true,
					}},
					Action:  Return,
					Policy:  "example",
					Counter: CounterRole{Kind: Denied, Reason: GeoPolicy, Action: Reject},
				}},
			}},
		}}
	}

	// Independent fixture instances keep the oracle valid even if Families aliases state.
	state := State{families: newFamilies()}
	want := newFamilies()

	observed := state.Families()
	observed[0].Family = IPv6
	observed[0].Sets[0].ID = "mutated"
	observed[0].Sets[0].Prefixes[0] = secondPrefix
	observed[0].Sets[0].Prefixes = append(observed[0].Sets[0].Prefixes, secondPrefix)
	observed[0].Paths[0].Direction = Egress
	observed[0].Paths[0].Rules[0].Match.SetID = "mutated"
	observed[0].Paths[0].Rules[0].Match.Traffic.TCP[0].Start = 443
	observed[0].Paths[0].Rules[0].Match.Traffic.UDP[0].End = 5353
	observed[0].Paths[0].Rules[0].Match.Traffic.TCP = append(observed[0].Paths[0].Rules[0].Match.Traffic.TCP, PortRange{Start: 80, End: 80})
	observed[0].Paths[0].Rules = append(observed[0].Paths[0].Rules, Rule{Action: Drop})

	if got := state.Families(); !reflect.DeepEqual(got, want) {
		t.Fatalf("mutating Families result changed State:\n got: %#v\nwant: %#v", got, want)
	}
}
