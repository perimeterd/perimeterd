package source

import (
	"context"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
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

func TestTimingDiagnosticsPreserveSelectorPrecedence(t *testing.T) {
	cases := []struct {
		name      string
		selector  policy.Selector
		fetch     bool
		configure func(*config.Config)
		want      string
	}{
		{
			name:     "missing list during timing selection",
			selector: policy.Selector{Kind: policy.IPList, Value: "missing"},
			want:     `source: custom list "missing" is not configured`,
		},
		{
			name:     "invalid list timing before list URL",
			selector: policy.Selector{Kind: policy.IPList, Value: "feed"},
			configure: func(cfg *config.Config) {
				cfg.IPLists = map[string]config.IPListConfig{"feed": {RefreshInterval: 0, RequestTimeout: time.Second}}
			},
			want: `source: custom list "feed" has invalid timing`,
		},
		{
			name:     "provider timing selection",
			selector: policy.Selector{Kind: policy.Provider, Value: "sample"},
			configure: func(cfg *config.Config) {
				cfg.Providers = config.ProvidersConfig{RequestTimeout: time.Second}
			},
			want: "source: provider refresh interval and request timeout must be positive",
		},
		{
			name:     "RIPE timing selection",
			selector: policy.Selector{Kind: policy.Country, Value: "LI"},
			configure: func(cfg *config.Config) {
				cfg.Geo.RefreshInterval = 0
			},
			want: "source: refresh interval and request timeout must be positive",
		},
		{
			name:     "missing list before fetch timing",
			selector: policy.Selector{Kind: policy.IPList, Value: "missing"},
			fetch:    true,
			want:     `source: custom list "missing" is not configured`,
		},
		{
			name:     "list URL before fetch timing",
			selector: policy.Selector{Kind: policy.IPList, Value: "feed"},
			fetch:    true,
			configure: func(cfg *config.Config) {
				cfg.IPLists = map[string]config.IPListConfig{"feed": {RefreshInterval: 0, RequestTimeout: time.Second}}
			},
			want: `source: custom list "feed" has invalid URL`,
		},
		{
			name:     "provider fetch timing after selector description",
			selector: policy.Selector{Kind: policy.Provider, Value: "sample"},
			fetch:    true,
			configure: func(cfg *config.Config) {
				cfg.Providers = config.ProvidersConfig{RequestTimeout: time.Second}
			},
			want: "source: provider refresh interval and request timeout must be positive",
		},
		{
			name:     "RIPE fetch timing",
			selector: policy.Selector{Kind: policy.Country, Value: "LI"},
			fetch:    true,
			configure: func(cfg *config.Config) {
				cfg.Geo.RefreshInterval = 0
			},
			want: "source: refresh interval and request timeout must be positive",
		},
	}
	resolver := NewResolver(nil, nil)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := config.Config{Geo: config.GeoConfig{RefreshInterval: time.Hour, RequestTimeout: time.Second}}
			if tc.configure != nil {
				tc.configure(&cfg)
			}
			var err error
			if tc.fetch {
				_, err = resolver.fetchOne(context.Background(), cfg, tc.selector)
			} else {
				_, _, err = selectorTiming(cfg, tc.selector)
			}
			if err == nil || err.Error() != tc.want {
				t.Fatalf("timing result error = %v, want %q", err, tc.want)
			}
		})
	}
}
