package firewall

import (
	"encoding/json"
	"net/netip"
	"reflect"
	"strings"
	"testing"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestSharedPolicyNativeObjectsAndDirection(t *testing.T) {
	for _, backend := range []string{"nftables", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			cfg := config.Config{Version: 1, Firewall: config.FirewallConfig{Backend: backend, DenyAction: "drop", IPv4: true, IPv6: true, Nftables: config.NftablesConfig{Table: "shared", Priority: -10}, IPTables: config.IPTablesConfig{Attachments: []config.Attachment{{Chain: "INPUT", Direction: "ingress"}, {Chain: "OUTPUT", Direction: "egress"}}}}}
			for _, direction := range []string{"ingress", "egress"} {
				cfg.Policies = append(cfg.Policies, config.Policy{Name: direction, Direction: direction, Priority: 100, Mode: "allowlist", Traffic: config.TrafficScope{Any: true}, Include: config.Selector{Countries: []string{"CZ"}}})
			}
			snapshot, err := policy.NewSnapshot([]policy.ResolvedSelector{{Selector: policy.Selector{Kind: policy.Country, Value: "CZ"}, IPv4: []netip.Prefix{netip.MustParsePrefix("8.20.0.2/32")}, IPv6: []netip.Prefix{netip.MustParsePrefix("2600:20::2/128")}}})
			if err != nil {
				t.Fatal(err)
			}
			compiled, err := policy.Compile(cfg, snapshot)
			if err != nil {
				t.Fatal(err)
			}
			target, err := BuildTarget(testOwner, testGenA, cfg, compiled, nil)
			if err != nil {
				t.Fatal(err)
			}
			for _, family := range target.Families {
				geo := 0
				for _, set := range family.Sets {
					if strings.HasPrefix(set.ID, "geo/") {
						geo++
						if set.ID != "geo/egress" {
							t.Fatalf("representative = %s", set.ID)
						}
					}
				}
				if geo != 1 {
					t.Fatalf("family %d materialized %d geo objects", family.Family, geo)
				}
				for _, path := range family.Paths {
					found := false
					for _, rule := range path.Rules {
						if rule.Match.SetID == "geo/egress" {
							found = true
							if rule.Policy != string(path.Direction) {
								t.Fatalf("representative replaced rule policy: %#v", rule)
							}
						}
						if rule.Counter.Kind == policy.Denied && rule.Counter.Reason == policy.GeoPolicy && rule.Policy != string(path.Direction) {
							t.Fatalf("denial identity changed: %#v", rule)
						}
					}
					if !found {
						t.Fatalf("missing shared reference in %s", path.Direction)
					}
				}
				if backend == "nftables" {
					name := setName(target, family.Family, "geo/egress")
					for _, direction := range []policy.Direction{policy.Ingress, policy.Egress} {
						data, err := json.Marshal(familyPathRules(target, family, direction))
						if err != nil {
							t.Fatal(err)
						}
						field := "saddr"
						if direction == policy.Egress {
							field = "daddr"
						}
						if !strings.Contains(string(data), "@"+name) || !strings.Contains(string(data), `"field":"`+field+`"`) {
							t.Fatalf("native %s reference/orientation missing: %s", direction, data)
						}
					}
				} else {
					model, err := buildIPTFamily(target, family.Family, nil)
					if err != nil {
						t.Fatal(err)
					}
					name := iptSetName(target, family.Family, "geo/egress")
					objects := 0
					for _, set := range model.Sets {
						if set.Name == name {
							objects++
						}
					}
					if objects != 1 {
						t.Fatalf("native shared ipsets = %d", objects)
					}
					orientations := map[string]bool{}
					for _, chain := range model.Staging {
						for _, rule := range chain.Rules {
							for index, arg := range rule.Args {
								if arg == "--match-set" && index+2 < len(rule.Args) && rule.Args[index+1] == name {
									orientations[rule.Args[index+2]] = true
								}
							}
						}
					}
					if !reflect.DeepEqual(orientations, map[string]bool{"src": true, "dst": true}) {
						t.Fatalf("shared ipset orientations = %v", orientations)
					}
				}
			}
			if len(target.Counters) != 8 {
				t.Fatalf("expected separate ingress/egress processed and denied counters per family, got %v", target.Counters)
			}
		})
	}
}
