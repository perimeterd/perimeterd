package app

import (
	"context"
	"net/netip"
	"reflect"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/control"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
)

func TestStatusCompiledSetsCountPolicyMemberships(t *testing.T) {
	for _, scenario := range []string{"nftables", "iptables", "ipv4-only"} {
		t.Run(scenario, func(t *testing.T) {
			cfg, err := config.Parse([]byte(`version: 1
firewall:
  backend: nftables
global:
  allowlist: [8.100.0.1/24, 8.100.0.0/24, '2600:100::/48']
  blocklist: [8.200.0.0/24, '2600:200::/48']
policies:
  - name: ingress
    priority: 100
    direction: ingress
    mode: allowlist
    traffic: [any]
    include:
      countries: [CZ]
  - name: egress
    priority: 100
    direction: egress
    mode: allowlist
    traffic: [any]
    include:
      countries: [CZ]
  - name: ssh
    priority: 10
    direction: ingress
    mode: allowlist
    traffic: [22/tcp, 22/udp]
    include:
      countries: [SK]
`))
			if err != nil {
				t.Fatal(err)
			}
			if scenario == "iptables" {
				cfg.Firewall.Backend = "iptables"
				cfg.Firewall.IPTables.Attachments = []config.Attachment{{Chain: "INPUT", Direction: "ingress"}, {Chain: "OUTPUT", Direction: "egress"}}
			}
			if scenario == "ipv4-only" {
				cfg.Firewall.IPv6 = false
			}
			engine, store := newTestEngine(t, &recordingBackend{}, nil)
			defer engine.Close()
			now := time.Now().UTC().Truncate(time.Second)
			record := func(country string, v4, v6 []netip.Prefix) source.Record {
				return source.Record{
					Selector: policy.Selector{Kind: policy.Country, Value: country},
					Endpoint: "https://stat.ripe.net/data/country-resource-list/data.json", APIVersion: "0.2",
					Parameters: map[string]string{"resource": country, "v4_format": "prefix", "sourceapp": "perimeterd"},
					QueryStart: now.Add(-time.Hour), QueryEnd: now.Add(-time.Hour), RetrievedAt: now,
					IPv4: v4, IPv6: v6,
				}
			}
			snapshot, err := store.Prefixes().Stage([]source.Record{
				record("CZ", []netip.Prefix{netip.MustParsePrefix("8.20.0.0/24"), netip.MustParsePrefix("8.22.0.0/24")}, []netip.Prefix{netip.MustParsePrefix("2600:20::/48")}),
				record("SK", []netip.Prefix{netip.MustParsePrefix("8.40.0.0/24"), netip.MustParsePrefix("8.42.0.0/24"), netip.MustParsePrefix("8.44.0.0/24")}, []netip.Prefix{}),
			})
			if err != nil {
				t.Fatal(err)
			}
			apply := func() Outcome {
				t.Helper()
				epoch, err := engine.Admit()
				if err != nil {
					t.Fatal(err)
				}
				candidate, err := NewCandidate(epoch, "policy.yaml", cfg, snapshot)
				if err != nil {
					t.Fatal(err)
				}
				outcome, err := engine.Apply(context.Background(), candidate)
				if err != nil || !outcome.Committed {
					t.Fatalf("apply: %+v, %v", outcome, err)
				}
				return outcome
			}
			first := apply()
			want := control.StatusCompiledSets{Sets: []control.StatusCompiledSet{}, Totals: []control.StatusCompiledTotal{}}
			var wantSources []control.StatusPrefixCount
			for _, family := range []policy.Family{policy.IPv4, policy.IPv6} {
				if family == policy.IPv6 && !cfg.Firewall.IPv6 {
					continue
				}
				name := firewallFamily(family)
				var local uint64
				for _, p := range config.BuiltinLocalRanges() {
					if p.Addr().Is4() == (family == policy.IPv4) {
						local++
					}
				}
				geo, ssh, loaded := uint64(2), uint64(3), uint64(5)
				if family == policy.IPv6 {
					geo, ssh, loaded = 1, 0, 1
				}
				eligible := uint64(len(policy.GeoEligible(family).Prefixes()))
				want.Sets = append(want.Sets,
					control.StatusCompiledSet{Family: name, ID: "geo/egress", Count: geo},
					control.StatusCompiledSet{Family: name, ID: "geo/ingress", Count: geo},
					control.StatusCompiledSet{Family: name, ID: "geo/ssh", Count: ssh},
					control.StatusCompiledSet{Family: name, ID: "geo_eligible", Count: eligible},
					control.StatusCompiledSet{Family: name, ID: "global_allowlist", Count: local + 1},
					control.StatusCompiledSet{Family: name, ID: "global_blocklist", Count: 1},
				)
				want.Totals = append(want.Totals, control.StatusCompiledTotal{Family: name, Count: 2*geo + ssh + eligible + local + 2})
				wantSources = append(wantSources,
					control.StatusPrefixCount{Family: name, Source: "global", Type: "allowlist", Count: 1},
					control.StatusPrefixCount{Family: name, Source: "global", Type: "blocklist", Count: 1},
					control.StatusPrefixCount{Family: name, Source: "local", Type: "local", Count: local},
					control.StatusPrefixCount{Family: name, Source: "ripestat", Type: "country", Count: loaded},
				)
			}
			report := engine.Status(context.Background())
			if !report.Successful() || report.Applied.Revision != first.Active.ID || !reflect.DeepEqual(report.Applied.Details.CompiledSets, want) || !reflect.DeepEqual(report.Applied.Details.PrefixCounts, wantSources) {
				t.Fatalf("compiled/source membership mismatch: %+v; want compiled=%+v sources=%+v", report, want, wantSources)
			}
			var sshSelector config.Selector
			for _, p := range cfg.Policies {
				if p.Name == "ssh" {
					sshSelector = p.Include
				}
			}
			for i := range cfg.Policies {
				if cfg.Policies[i].Name == "egress" {
					cfg.Policies[i].Include = cloneSelector(sshSelector)
				}
			}
			second := apply()
			for i := range want.Sets {
				if want.Sets[i].ID == "geo/egress" {
					want.Sets[i].Count = 3
					if want.Sets[i].Family == "ipv6" {
						want.Sets[i].Count = 0
					}
				}
			}
			for i := range want.Totals {
				if want.Totals[i].Family == "ipv4" {
					want.Totals[i].Count++
				} else {
					want.Totals[i].Count--
				}
			}
			report = engine.Status(context.Background())
			if !report.Successful() || report.Applied.Revision == first.Active.ID || report.Applied.Revision != second.Active.ID || !reflect.DeepEqual(report.Applied.Details.CompiledSets, want) || !reflect.DeepEqual(report.Applied.Details.PrefixCounts, wantSources) {
				t.Fatalf("new acknowledged revision did not publish new compiled counts with unchanged sources: %+v", report)
			}
		})
	}
}

func TestStatusCompiledSetsEmptyStaticMemberships(t *testing.T) {
	for _, emptyStatic := range []bool{false, true} {
		t.Run(map[bool]string{false: "dynamic-only", true: "zero-static-set"}[emptyStatic], func(t *testing.T) {
			sets := []policy.PrefixSet{{ID: "crowdsec", Kind: policy.DynamicCrowdSecSet}}
			wantSets := []control.StatusCompiledSet{}
			if emptyStatic {
				sets = append(sets, policy.PrefixSet{ID: "geo/crowdsec-exception", Kind: policy.StaticSet})
				wantSets = append(wantSets, control.StatusCompiledSet{Family: "ipv6", ID: "geo/crowdsec-exception"})
			}
			target := &firewall.Target{Families: []policy.FamilyPlan{{Family: policy.IPv6, Sets: sets}}}
			details, err := buildStatusDetails(Candidate{}, target)
			if err != nil {
				t.Fatal(err)
			}
			got := cloneStatusDetails(details).CompiledSets
			want := control.StatusCompiledSets{Sets: wantSets, Totals: []control.StatusCompiledTotal{{Family: "ipv6"}}}
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("empty static/dynamic distinction: %+v, want %+v", got, want)
			}
		})
	}
}
