package app

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/control"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
)

func TestCommittedSourceSummaryAggregatesOldestRetrievalDeterministically(t *testing.T) {
	engine, store := newTestEngine(t, &recordingBackend{}, nil)
	defer engine.Close()
	cfg, err := config.Parse([]byte(`version: 1
geo:
  country_provider: dbip-lite
firewall:
  backend: nftables
policies:
  - name: mixed
    priority: 10
    direction: ingress
    mode: blocklist
    traffic: ["443/tcp"]
    include:
      countries: [CZ]
      asns: [AS3333, AS4444]
`))
	if err != nil {
		t.Fatal(err)
	}
	countryAt := time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)
	oldest := countryAt.Add(-2 * time.Hour)
	ripe := func(value, resource string, at time.Time) source.Record {
		return source.Record{
			Selector: policy.Selector{Kind: policy.ASN, Value: value}, Endpoint: "https://stat.ripe.net/data/announced-prefixes/data.json", APIVersion: "1.2",
			Parameters: map[string]string{"resource": resource, "sourceapp": "perimeterd"}, QueryStart: at.Add(-time.Hour), QueryEnd: at, RetrievedAt: at,
			IPv4: []netip.Prefix{netip.MustParsePrefix("9.9.9.9/32")}, IPv6: []netip.Prefix{},
		}
	}
	country := dbipAppSnapshot(t, store, "2026-10", countryAt).Records()[0]
	records := []source.Record{ripe("AS4444", "4444", countryAt), country, ripe("AS3333", "3333", oldest)}
	want := []control.StatusSource{{Provider: "dbip-lite", Release: "2026-10", RetrievedAt: countryAt}, {Provider: "ripestat", RetrievedAt: oldest}}
	for _, reverse := range []bool{false, true} {
		if reverse {
			records[0], records[2] = records[2], records[0]
		}
		snapshot, err := store.Prefixes().Stage(records)
		if err != nil {
			t.Fatal(err)
		}
		epoch, err := engine.Admit()
		if err != nil {
			t.Fatal(err)
		}
		candidate, err := NewCandidate(epoch, "mixed.yaml", cfg, snapshot)
		if err != nil {
			t.Fatal(err)
		}
		outcome, err := engine.Apply(context.Background(), candidate)
		if err != nil || !outcome.Committed {
			t.Fatalf("apply: %+v %v", outcome, err)
		}
		got := engine.Status(context.Background()).Applied.Details.Sources
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("reverse=%t summary=%+v want=%+v", reverse, got, want)
		}
	}
}
