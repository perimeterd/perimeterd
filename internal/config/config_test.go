package config

import (
	"encoding/json"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"
)

func TestParseDefaultsAndExplicitZeroValues(t *testing.T) {
	cfg, err := Parse([]byte(`version: 1
metrics:
  listen: ""
firewall:
  backend: iptables
  ipv4: false
  ipv6: false
  nftables:
    priority: 0
  iptables: {}
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Version != 1 || cfg.Firewall.Backend != "iptables" {
		t.Fatalf("unexpected identity defaults: %#v", cfg)
	}
	if cfg.Metrics.Listen != "" || cfg.Firewall.IPv4 || cfg.Firewall.IPv6 {
		t.Fatalf("explicit empty/false values were not preserved: %#v", cfg)
	}
	if cfg.Firewall.Nftables.Priority != 0 {
		t.Fatalf("explicit zero priority was not preserved: %d", cfg.Firewall.Nftables.Priority)
	}
	if cfg.Logging.Level != "info" || cfg.Logging.Format != "json" || cfg.Geo.RefreshInterval != 24*time.Hour || cfg.CrowdSec.UpdateFrequency != 10*time.Second {
		t.Fatalf("documented defaults not applied: %#v", cfg)
	}
	if cfg.CrowdSec.APIKeyFile != "" {
		t.Fatalf("api_key_file unexpectedly defaulted: %q", cfg.CrowdSec.APIKeyFile)
	}
}

func TestParseCanonicalPrefixesAndBuiltInAllows(t *testing.T) {
	cfg, err := Parse([]byte(`version: 1
firewall:
  backend: nftables
global:
  allowlist:
    - 198.51.100.99/24
    - 198.51.100.0/24
    - 198.51.100.4/32
  blocklist:
    - 203.0.113.99/24
    - 203.0.113.0/24
`))
	if err != nil {
		t.Fatal(err)
	}
	wantAllow := netip.MustParsePrefix("198.51.100.0/24")
	foundAllow := false
	for _, prefix := range cfg.Global.Allowlist {
		if prefix == wantAllow {
			foundAllow = true
		}
		if prefix == netip.MustParsePrefix("198.51.100.4/32") {
			t.Fatalf("contained allow prefix was retained: %v", prefix)
		}
	}
	if !foundAllow {
		t.Fatalf("canonical configured allow prefix missing: %v", cfg.Global.Allowlist)
	}
	if len(cfg.Global.Blocklist) != 1 || cfg.Global.Blocklist[0] != netip.MustParsePrefix("203.0.113.0/24") {
		t.Fatalf("blocklist was not masked/deduplicated: %v", cfg.Global.Blocklist)
	}
	for _, local := range BuiltinLocalRanges() {
		found := false
		for _, prefix := range cfg.Global.Allowlist {
			if prefix == local {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("built-in local range missing from effective allowlist: %v", local)
		}
	}
}

func TestParseTrafficAndGroupExpansion(t *testing.T) {
	cfg, err := Parse([]byte(`version: 1
groups:
  partners: [US, ca, US]
firewall:
  backend: nftables
policies:
  - name: sample
    priority: 0
    direction: ingress
    mode: blocklist
    traffic: ["100-102/tcp", "101/tcp", "103", "80/udp", "80/udp", "icmp", "icmpv6"]
    include:
      groups: [partners]
      countries: [CA]
`))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Groups["partners"]; strings.Join(got, ",") != "CA,US" {
		t.Fatalf("custom group was not normalized: %v", got)
	}
	policy := cfg.Policies[0]
	if len(policy.Traffic.TCP) != 1 || policy.Traffic.TCP[0] != (PortRange{Start: 100, End: 103}) {
		t.Fatalf("TCP ranges were not merged: %#v", policy.Traffic.TCP)
	}
	if len(policy.Traffic.UDP) != 1 || policy.Traffic.UDP[0] != (PortRange{Start: 80, End: 80}) || !policy.Traffic.ICMP || !policy.Traffic.ICMPv6 {
		t.Fatalf("transport scope was not normalized: %#v", policy.Traffic)
	}
	if got := strings.Join(policy.Include.ExpandedCountries, ","); got != "CA,US" {
		t.Fatalf("group/country expansion was not deterministic: %q", got)
	}
}

func TestParseRejectsStrictAndOfflineBoundaries(t *testing.T) {
	cases := []string{
		"version: 1\nfirewall:\n  backend: nftables\nunknown: true\n",
		"version: 1\nversion: 1\nfirewall:\n  backend: nftables\n",
		"version: 1\n---\nversion: 1\nfirewall:\n  backend: nftables\n",
		"version: 1\nfirewall:\n  backend: nftables\n  ipv4: 1\n",
		"version: 1\nfirewall: {backend: nftables}\npolicies: !!null []\n",
		"version: 1\nfirewall: {backend: nftables}\ngroups: !!null {partners: [CH]}\n",
		"version: 1\nfirewall:\n  backend: nftables\n  nftables:\n    priority: -200\n",
		"version: 1\ncrowdsec:\n  lapi_url: not-a-url\nfirewall:\n  backend: nftables\n",
		"version: 1\nfirewall:\n  backend: nftables\npolicies:\n  - name: bad\n    priority: 1\n    direction: ingress\n    mode: blocklist\n    traffic: [80]\n    include: {}\n",
		"version: 1\nfirewall:\n  backend: nftables\npolicies:\n  - name: a\n    priority: 1\n    direction: ingress\n    mode: disabled\n    traffic: [\"any\"]\n    include:\n      countries: [US]\n  - name: b\n    priority: 1\n    direction: ingress\n    mode: blocklist\n    traffic: [\"any\"]\n    include:\n      countries: [CA]\n",
	}
	for _, input := range cases {
		if _, err := Parse([]byte(input)); err == nil {
			t.Errorf("invalid configuration was accepted:\n%s", input)
		}
	}
}

func TestParseAttachmentNormalizationAndScopedAddressRejection(t *testing.T) {
	scoped := `version: 1
global:
  allowlist: ["192.0.2.1%eth0"]
firewall:
  backend: iptables
`
	if _, err := Parse([]byte(scoped)); err == nil {
		t.Fatal("scoped address was accepted")
	}

	cfg, err := Parse([]byte(`version: 1
firewall:
  backend: iptables
  iptables:
    attachments:
      - chain: FORWARD
        direction: ingress
        input_interfaces: [eth1, eth0, eth0]
        output_interfaces: [veth1, veth1]
      - chain: FORWARD
        direction: ingress
        input_interfaces: [a, b]
        output_interfaces: [c]
      - chain: FORWARD
        direction: ingress
        input_interfaces: [a]
        output_interfaces: [b, c]
`))
	if err != nil {
		t.Fatal(err)
	}
	if len(cfg.Firewall.IPTables.Attachments) != 3 {
		t.Fatalf("attachments unexpectedly collapsed: %#v", cfg.Firewall.IPTables.Attachments)
	}
	first := cfg.Firewall.IPTables.Attachments[0]
	if strings.Join(first.InputInterfaces, ",") != "eth0,eth1" || strings.Join(first.OutputInterfaces, ",") != "veth1" {
		t.Fatalf("attachment interfaces were not sorted/deduplicated: %#v", first)
	}
}

func TestParseAttachmentDefaultsVersusExplicitEmpty(t *testing.T) {
	for _, backend := range []string{"nftables", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			input := "version: 1\nglobal:\n  blocklist: [203.0.113.1]\nfirewall:\n  backend: " + backend + "\n"
			omitted, err := Parse([]byte(input))
			if err != nil {
				t.Fatal(err)
			}
			defaults := omitted.Firewall.IPTables.Attachments
			if len(defaults) != 2 ||
				defaults[0].Chain != "INPUT" || defaults[0].Direction != "ingress" ||
				defaults[1].Chain != "OUTPUT" || defaults[1].Direction != "egress" {
				t.Fatalf("omitted attachments did not retain host defaults: %#v", defaults)
			}

			explicit, err := Parse([]byte(input + "  iptables:\n    attachments: []\n"))
			if err != nil {
				t.Fatal(err)
			}
			if got := explicit.Firewall.IPTables.Attachments; len(got) != 0 {
				t.Fatalf("explicit empty attachments were replaced by defaults: %#v", got)
			}
		})
	}
}

func TestParseIPListsNormalizeAndReferenceValidation(t *testing.T) {
	cfg, err := Parse([]byte(`version: 1
firewall:
  backend: nftables
ip_lists:
  zoom:
    url: HTTPS://EXAMPLE.COM/feed?region=US
    refresh_interval: 6h
    request_timeout: 45s
policies:
  - name: disabled
    priority: 1
    direction: ingress
    mode: disabled
    traffic: ["any"]
    include:
      ip_lists: [zoom, zoom]
`))
	if err != nil {
		t.Fatal(err)
	}
	list := cfg.IPLists["zoom"]
	if list.URL != "https://example.com/feed?region=US" || list.RefreshInterval != 6*time.Hour || list.RequestTimeout != 45*time.Second {
		t.Fatalf("custom list was not normalized: %#v", list)
	}
	if len(cfg.Policies[0].Include.IPLists) != 1 || cfg.Policies[0].Include.IPLists[0] != "zoom" {
		t.Fatalf("list selector was not deduplicated: %#v", cfg.Policies[0].Include.IPLists)
	}

	invalid := []string{
		`version: 1
firewall: {backend: nftables}
ip_lists:
  Zoom:
    url: https://example.com/feed
`,
		`version: 1
firewall: {backend: nftables}
ip_lists:
  zoom:
    url: https://user@example.com/feed
`,
		`version: 1
firewall: {backend: nftables}
ip_lists:
  zoom:
    url: https://example.com/feed#fragment
`,
		`version: 1
firewall: {backend: nftables}
ip_lists:
  zoom:
    url: https://example.com/feed
policies:
  - name: disabled
    priority: 1
    direction: ingress
    mode: disabled
    traffic: ["any"]
    include:
      ip_lists: [missing]
`,
		`version: 1
firewall: {backend: nftables}
ip_lists:
  zoom:
    url: https://example.com/feed
    refresh_interval: 0s
`,
	}
	for _, input := range invalid {
		if _, err := Parse([]byte(input)); err == nil {
			t.Errorf("invalid custom-list configuration was accepted:\n%s", input)
		}
	}
}

func TestIPListURLPreservesIPv6InterfaceZone(t *testing.T) {
	want := "http://[fe80::1%25FeedNIC]/list"
	got, err := NormalizeIPListURL("HTTP://[fe80::1%25FeedNIC]/list")
	if err != nil || got != want {
		t.Fatalf("IPv6 interface identity changed: URL=%q error=%v", got, err)
	}
}

func TestParseProvidersDefaultsAndArbitraryIDs(t *testing.T) {
	base := "version: 1\nfirewall:\n  backend: nftables\n"
	cfg, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Providers.RefreshInterval != 24*time.Hour || cfg.Providers.RequestTimeout != 30*time.Second {
		t.Fatalf("provider defaults = %#v", cfg.Providers)
	}

	cfg, err = Parse([]byte(base + `providers:
  refresh_interval: 6h
  request_timeout: 45s
policies:
  - name: disabled
    priority: 1
    direction: ingress
    mode: disabled
    traffic: [any]
    include:
      providers: [future_feed, alpha_beta, future_feed, "0"]
    exclude:
      providers: [future_feed]
`))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Providers.RefreshInterval != 6*time.Hour || cfg.Providers.RequestTimeout != 45*time.Second {
		t.Fatalf("provider settings = %#v", cfg.Providers)
	}
	got := cfg.Policies[0].Include.Providers
	if strings.Join(got, ",") != "0,alpha_beta,future_feed" {
		t.Fatalf("provider IDs were not sorted/deduplicated: %v", got)
	}
	if got := cfg.Policies[0].Exclude.Providers; len(got) != 1 || got[0] != "future_feed" {
		t.Fatalf("disabled provider exclusion was not normalized: %v", got)
	}
}

func TestParseRejectsUnsafeProviderIDsAndSettings(t *testing.T) {
	base := "version: 1\nfirewall:\n  backend: nftables\npolicies:\n  - name: p\n    priority: 1\n    direction: ingress\n    mode: disabled\n    traffic: [any]\n    include:\n      providers: [%s]\n"
	for _, id := range []string{`""`, `"../escape"`, `"foo/bar"`, `"foo?bar"`, `"Foo"`, `"foo.bar"`, `"foo\nbar"`} {
		if _, err := Parse([]byte(fmt.Sprintf(base, id))); err == nil {
			t.Errorf("unsafe provider ID %s was accepted", id)
		}
	}
	for _, input := range []string{
		"version: 1\nfirewall: {backend: nftables}\nproviders:\n  refresh_interval: 0s\n",
		"version: 1\nfirewall: {backend: nftables}\nproviders:\n  request_timeout: nope\n",
		"version: 1\nfirewall: {backend: nftables}\nproviders:\n  unknown: 1\n",
		"version: 1\nfirewall: {backend: nftables}\nproviders: []\n",
		"version: 1\nfirewall: {backend: nftables}\npolicies:\n  - name: p\n    priority: 1\n    direction: ingress\n    mode: disabled\n    traffic: [any]\n    include:\n      providers: nope\n",
	} {
		if _, err := Parse([]byte(input)); err == nil {
			t.Errorf("invalid provider configuration was accepted:\n%s", input)
		}
	}
}

func TestParseOpenZitiTransportsAndCanonicalDirectDefaults(t *testing.T) {
	input := []byte(`version: 1
openziti:
  identities:
    private-sources:
      identity_file: /does/not/exist/openziti.json
ip_lists:
  public-feed:
    url: https://example.org/public.txt
    transport:
      type: direct
  private-feed:
    url: https://feeds.internal/private.txt
    transport:
      type: openziti
      identity: private-sources
      service: Perimeterd-Private-Feeds
crowdsec:
  transport:
    type: openziti
    identity: private-sources
    service: perimeterd-lapi
firewall:
  backend: nftables
`)
	cfg, err := Parse(input)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.OpenZiti.Identities["private-sources"].IdentityFile; got != "/does/not/exist/openziti.json" {
		t.Fatalf("identity file changed: %q", got)
	}
	if got := cfg.IPLists["public-feed"].Transport; !got.IsZero() {
		t.Fatalf("explicit direct transport was not canonicalized: %#v", got)
	}
	private := cfg.IPLists["private-feed"].Transport
	if private.Type != "openziti" || private.Identity != "private-sources" || private.Service != "Perimeterd-Private-Feeds" {
		t.Fatalf("OpenZiti list transport was not retained: %#v", private)
	}
	if got := cfg.CrowdSec.Transport; got != (TransportConfig{Type: "openziti", Identity: "private-sources", Service: "perimeterd-lapi"}) {
		t.Fatalf("CrowdSec transport was not retained: %#v", got)
	}

	legacy, err := Parse([]byte("version: 1\nfirewall:\n  backend: nftables\n"))
	if err != nil {
		t.Fatal(err)
	}
	explicitDirect, err := Parse([]byte(`version: 1
firewall:
  backend: nftables
ip_lists:
  feed:
    url: https://example.org/feed
    transport: {}
`))
	if err != nil {
		t.Fatal(err)
	}
	legacyWire, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}
	explicitWire, err := json.Marshal(explicitDirect)
	if err != nil {
		t.Fatal(err)
	}
	if string(legacyWire) == "" || string(explicitWire) == "" {
		t.Fatal("empty normalized config wire")
	}
	if strings.Contains(string(legacyWire), "OpenZiti") || strings.Contains(string(explicitWire), "Transport") {
		t.Fatalf("canonical direct defaults leaked into legacy wire: legacy=%s explicit=%s", legacyWire, explicitWire)
	}
}

func TestParseOpenZitiRejectsInvalidDefinitionsOffline(t *testing.T) {
	base := "version: 1\nfirewall: {backend: nftables}\n"
	cases := []string{
		base + "openziti:\n  identities:\n    profile:\n      identity_file: relative.json\n",
		base + "openziti:\n  identities:\n    profile: null\n",
		base + "openziti:\n  identities:\n    profile:\n      identity_file: /tmp/profile.json\nip_lists:\n  feed:\n    url: https://example.org/feed\n    transport:\n      type: openziti\n      identity: missing\n      service: service\n",
		base + "openziti:\n  identities:\n    profile:\n      identity_file: /tmp/profile.json\nip_lists:\n  feed:\n    url: https://example.org/feed\n    transport:\n      identity: profile\n      service: service\n",
		base + "openziti:\n  identities:\n    profile:\n      identity_file: /tmp/profile.json\nip_lists:\n  feed:\n    url: https://example.org/feed\n    transport:\n      type: openziti\n      identity: profile\n      service: '   '\n",
		base + "openziti:\n  identities:\n    profile:\n      identity_file: /tmp/profile.json\nip_lists:\n  feed:\n    url: https://example.org/feed\n    transport:\n      type: unsupported\n      identity: profile\n      service: service\n",
		base + "openziti:\n  identities:\n    profile:\n      identity_file: /tmp/profile.json\ncrowdsec:\n  transport:\n    type: openziti\n    identity: missing\n    service: service\n",
		base + "openziti:\n  identities:\n    profile:\n      identity_file: /tmp/profile.json\nip_lists:\n  feed:\n    url: https://example.org/feed\n    transport:\n      type: direct\n      identity: profile\n",
	}
	for _, input := range cases {
		if _, err := Parse([]byte(input)); err == nil {
			t.Errorf("invalid OpenZiti configuration was accepted:\n%s", input)
		}
	}
}
