package capacityfixture

import (
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/crowdsec"
	"github.com/perimeterd/perimeterd/internal/firewall"
)

func TestDBIPProfileNormalizedSharedAndEffective(t *testing.T) {
	var previous *firewall.Target
	for _, refresh := range []bool{false, true} {
		cfg, model, err := CompileDBIP("dbip_capacity", refresh)
		if err != nil {
			t.Fatal(err)
		}
		if err := ValidateDBIP(model.Families()); err != nil {
			t.Fatal(err)
		}
		id := InitialID
		if refresh {
			id = RefreshID
		}
		target, err := firewall.BuildTarget(Owner, id, cfg, model, previous)
		if err != nil {
			t.Fatal(err)
		}
		if previous != nil && previous.Generation == target.Generation {
			t.Fatal("changed source reused static generation")
		}
		previous = target
		for _, traffic := range cfg.Policies[0].Traffic.UDP {
			t.Fatalf("TCP shorthand unexpectedly enabled UDP: %v", traffic)
		}
	}
	now := time.Date(2026, 11, 1, 0, 0, 0, 0, time.UTC)
	store := crowdsec.NewStore("offline-capacity", 1)
	batch := DBIPBatch(DBIPProjectedBans, 0, now.Add(24*time.Hour))
	if err := store.Apply(batch, 1, now); err != nil {
		t.Fatal(err)
	}
	projection := store.Projection(now)
	if len(projection) != DBIPProjectedBans {
		t.Fatalf("effective projection=%d want=%d", len(projection), DBIPProjectedBans)
	}
	counts := [2]int{}
	for _, value := range projection {
		family := 0
		if value.Prefix.Addr().Is6() {
			family = 1
		}
		counts[family]++
	}
	if counts != [2]int{75000, 75000} {
		t.Fatalf("projected families=%v", counts)
	}
}
