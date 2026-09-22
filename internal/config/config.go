// Package config parses and validates perimeterd's version 1 YAML configuration.
package config

import (
	"net/netip"
	"time"
)

// Config is the fully defaulted and locally validated version 1 configuration.
// Prefixes and selector values are normalized deterministically for consumers
// such as the policy compiler.
type Config struct {
	Version   int                     `yaml:"version"`
	Logging   LoggingConfig           `yaml:"logging"`
	Metrics   MetricsConfig           `yaml:"metrics"`
	Global    GlobalConfig            `yaml:"global"`
	Firewall  FirewallConfig          `yaml:"firewall"`
	Geo       GeoConfig               `yaml:"geo"`
	Providers ProvidersConfig         `yaml:"providers"`
	OpenZiti  OpenZitiConfig          `yaml:"openziti,omitempty" json:"OpenZiti,omitzero"`
	IPLists   map[string]IPListConfig `yaml:"ip_lists"`
	Groups    map[string][]string     `yaml:"groups"`
	Policies  []Policy                `yaml:"policies"`
	CrowdSec  CrowdSecConfig          `yaml:"crowdsec"`
}

// OpenZitiConfig contains reusable, pre-enrolled OpenZiti identity profiles.
// Profiles are validated offline but are not loaded until an active transport
// needs one.
type OpenZitiConfig struct {
	Identities map[string]OpenZitiIdentityConfig `yaml:"identities,omitempty" json:"Identities,omitzero"`
}

// OpenZitiIdentityConfig describes one externally enrolled SDK identity.
type OpenZitiIdentityConfig struct {
	IdentityFile string `yaml:"identity_file,omitempty" json:"IdentityFile,omitzero"`
}

// TransportConfig selects the source transport. An empty Type is the
// canonical direct transport; openziti requires a named identity and service.
type TransportConfig struct {
	Type     string `yaml:"type,omitempty" json:"Type,omitzero"`
	Identity string `yaml:"identity,omitempty" json:"Identity,omitzero"`
	Service  string `yaml:"service,omitempty" json:"Service,omitzero"`
}

// IsZero reports whether the transport is the canonical direct default.
func (t TransportConfig) IsZero() bool {
	return t.Type == "" && t.Identity == "" && t.Service == ""
}

// IsZero reports whether no OpenZiti identity profiles are configured.
func (c OpenZitiConfig) IsZero() bool {
	return len(c.Identities) == 0
}

// IPListConfig describes one named HTTP(S) text source and its optional
// per-source transport.
type IPListConfig struct {
	URL             string          `yaml:"url"`
	RefreshInterval time.Duration   `yaml:"refresh_interval"`
	RequestTimeout  time.Duration   `yaml:"request_timeout"`
	Transport       TransportConfig `yaml:"transport,omitempty" json:"Transport,omitzero"`
}

// LoggingConfig controls structured log verbosity and encoding.
type LoggingConfig struct {
	Level  string `yaml:"level"`
	Format string `yaml:"format"`
}

// MetricsConfig controls the optional Prometheus listener.
type MetricsConfig struct {
	Listen string `yaml:"listen"`
}

// GlobalConfig contains direct address allow and block lists. Allowlist is the
// effective list and includes immutable built-in local ranges in addition to
// configured entries.
type GlobalConfig struct {
	Allowlist []netip.Prefix `yaml:"allowlist"`
	Blocklist []netip.Prefix `yaml:"blocklist"`
}

// FirewallConfig selects the backend and packet denial behavior.
type FirewallConfig struct {
	Backend    string         `yaml:"backend"`
	DenyAction string         `yaml:"deny_action"`
	IPv4       bool           `yaml:"ipv4"`
	IPv6       bool           `yaml:"ipv6"`
	Nftables   NftablesConfig `yaml:"nftables"`
	IPTables   IPTablesConfig `yaml:"iptables"`
}

// NftablesConfig contains the nftables table and hook priority.
type NftablesConfig struct {
	Table    string `yaml:"table"`
	Priority int32  `yaml:"priority"`
}

// IPTablesConfig contains normalized parent-chain attachments.
type IPTablesConfig struct {
	Attachments []Attachment `yaml:"attachments"`
}

// Attachment describes one iptables parent-chain integration point.
type Attachment struct {
	Chain               string   `yaml:"chain"`
	Direction           string   `yaml:"direction"`
	InputInterfaces     []string `yaml:"input_interfaces"`
	OutputInterfaces    []string `yaml:"output_interfaces"`
	OriginalDestination bool     `yaml:"original_destination"`
}

// GeoConfig controls static prefix refresh timing.
type GeoConfig struct {
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	RequestTimeout  time.Duration `yaml:"request_timeout"`
	RefreshJitter   time.Duration `yaml:"refresh_jitter"`
}

// ProvidersConfig controls the shared refresh timing for named-provider feeds.
type ProvidersConfig struct {
	RefreshInterval time.Duration `yaml:"refresh_interval"`
	RequestTimeout  time.Duration `yaml:"request_timeout"`
}

// CrowdSecConfig controls the optional CrowdSec LAPI stream.
type CrowdSecConfig struct {
	Enabled         bool            `yaml:"enabled"`
	LAPIURL         string          `yaml:"lapi_url"`
	APIKeyFile      string          `yaml:"api_key_file"`
	UpdateFrequency time.Duration   `yaml:"update_frequency"`
	Transport       TransportConfig `yaml:"transport,omitempty" json:"Transport,omitzero"`
}

// Policy describes one normalized, backend-neutral policy declaration.
type Policy struct {
	Name      string       `yaml:"name"`
	Priority  int64        `yaml:"priority"`
	Direction string       `yaml:"direction"`
	Mode      string       `yaml:"mode"`
	Traffic   TrafficScope `yaml:"traffic"`
	Include   Selector     `yaml:"include"`
	Exclude   Selector     `yaml:"exclude"`
}

// PortRange is an inclusive transport-port interval.
type PortRange struct {
	Start uint16 `yaml:"start"`
	End   uint16 `yaml:"end"`
}

// TrafficScope is the normalized L4 scope of a policy. TCP and UDP ranges are
// sorted and merged independently. ICMP and ICMPv6 cover every type and code.
type TrafficScope struct {
	TCP    []PortRange `yaml:"tcp"`
	UDP    []PortRange `yaml:"udp"`
	ICMP   bool        `yaml:"icmp"`
	ICMPv6 bool        `yaml:"icmpv6"`
	Any    bool        `yaml:"any"`
}

// Selector contains the explicitly selected categories and their deterministic
// local country expansion. ExpandedCountries is the union of Countries and all
// referenced built-in/custom groups; no network resolution occurs here.
type Selector struct {
	Countries         []string `yaml:"countries"`
	RIRs              []string `yaml:"rirs"`
	Groups            []string `yaml:"groups"`
	ASNs              []string `yaml:"asns"`
	IPLists           []string `yaml:"ip_lists"`
	Providers         []string `yaml:"providers"`
	ExpandedCountries []string `yaml:"expanded_countries"`
}
