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
	if families := state.Families(); len(families) != 0 {
		t.Fatalf("zero State has %d family plans", len(families))
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
