package historicalfixture_test

import (
	"encoding/json"
	"strings"
	"testing"

	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/testutil/historicalfixture"
)

func TestRecordedTargetsRemainUnsharedAndFresh(t *testing.T) {
	owner := strings.Repeat("c", 32)
	for _, backend := range []string{"nftables", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			first, err := historicalfixture.Target(backend, owner)
			if err != nil {
				t.Fatal(err)
			}
			if err := firewall.ValidateTarget(first); err != nil {
				t.Fatal(err)
			}
			before, err := json.Marshal(first)
			if err != nil {
				t.Fatal(err)
			}
			for _, family := range first.Families {
				sets := map[string]bool{}
				for _, set := range family.Sets {
					sets[set.ID] = true
				}
				if !sets["geo/ingress"] || !sets["geo/egress"] || !sets["geo/ssh"] {
					t.Fatalf("historical objects were canonicalized: %v", sets)
				}
				for _, path := range family.Paths {
					for _, rule := range path.Rules {
						if rule.Policy != "" && strings.HasPrefix(rule.Match.SetID, "geo/") && rule.Match.SetID != "geo/"+rule.Policy {
							t.Fatalf("historical rule binding changed: %#v", rule)
						}
					}
				}
			}
			for _, counter := range first.Counters {
				if !strings.Contains(counter.Name, owner) {
					t.Fatalf("counter owner not replaced: %s", counter.Name)
				}
			}
			first.Families[0].Sets[0].ID = "mutated"
			second, err := historicalfixture.Target(backend, owner)
			if err != nil {
				t.Fatal(err)
			}
			after, err := json.Marshal(second)
			if err != nil {
				t.Fatal(err)
			}
			if string(before) != string(after) {
				t.Fatal("fixture callers share mutable target storage")
			}
			if second.Generation != strings.Repeat("b", 32) || second.DynamicGeneration != second.Generation {
				t.Fatal("historical generations changed")
			}
		})
	}
}
