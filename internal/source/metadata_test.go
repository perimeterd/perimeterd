package source

import (
	"testing"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/upstream"
)

func TestRequiredIdentitiesSelectsOnlyActiveSources(t *testing.T) {
	cfg := config.Config{
		OpenZiti: config.OpenZitiConfig{Identities: map[string]config.OpenZitiIdentityConfig{
			"active":   {IdentityFile: "/tmp/active.json"},
			"inactive": {IdentityFile: "/tmp/inactive.json"},
		}},
		IPLists: map[string]config.IPListConfig{
			"active":   {Transport: config.TransportConfig{Type: upstream.TypeOpenZiti, Identity: "active", Service: "feed"}},
			"inactive": {Transport: config.TransportConfig{Type: upstream.TypeOpenZiti, Identity: "inactive", Service: "feed"}},
		},
		Policies: []config.Policy{
			{Mode: "blocklist", Include: config.Selector{IPLists: []string{"active"}}},
			{Mode: "disabled", Include: config.Selector{IPLists: []string{"inactive"}}},
		},
	}
	got, err := RequiredIdentities(cfg)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]config.OpenZitiIdentityConfig{"active": {IdentityFile: "/tmp/active.json"}}
	if len(got) != len(want) || got["active"] != want["active"] {
		t.Fatalf("required identities = %#v, want %#v", got, want)
	}

	cfg.CrowdSec.Enabled = true
	cfg.CrowdSec.Transport = config.TransportConfig{Type: upstream.TypeOpenZiti, Identity: "inactive", Service: "lapi"}
	got, err = RequiredIdentities(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got["inactive"] != (config.OpenZitiIdentityConfig{IdentityFile: "/tmp/inactive.json"}) {
		t.Fatalf("CrowdSec identity selection = %#v", got)
	}
}

func TestRequiredIdentitiesRejectsMissingActiveProfile(t *testing.T) {
	cfg := config.Config{
		IPLists: map[string]config.IPListConfig{
			"private": {Transport: config.TransportConfig{Type: upstream.TypeOpenZiti, Identity: "missing", Service: "feed"}},
		},
		Policies: []config.Policy{{Mode: "allowlist", Include: config.Selector{IPLists: []string{"private"}}}},
	}
	if _, err := RequiredIdentities(cfg); err == nil {
		t.Fatal("missing active OpenZiti profile was accepted")
	}
}
