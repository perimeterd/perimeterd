// Package config parses and validates perimeterd's version 1 YAML configuration.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"go.yaml.in/yaml/v3"

	"github.com/perimeterd/perimeterd/internal/config/catalog"
	"github.com/perimeterd/perimeterd/internal/prefix"
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

// Parse strictly decodes one YAML document, applies documented defaults, and
// performs all offline semantic validation. It never reads files, resolves
// names, contacts services, or mutates firewall state.
func Parse(data []byte) (Config, error) {
	var root yaml.Node
	dec := yaml.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(&root); err != nil {
		return Config{}, fmt.Errorf("configuration: malformed YAML: %w", err)
	}
	if root.Kind == 0 {
		return Config{}, errors.New("configuration: empty document")
	}
	if err := rejectDuplicateKeys(&root, "configuration"); err != nil {
		return Config{}, err
	}
	var extra yaml.Node
	if err := dec.Decode(&extra); err != io.EOF {
		if err == nil {
			return Config{}, errors.New("configuration: multiple YAML documents are not allowed")
		}
		return Config{}, fmt.Errorf("configuration: malformed YAML: %w", err)
	}
	rootNode := unwrapDocument(&root)
	if err := checkRootShape(rootNode); err != nil {
		return Config{}, err
	}

	var raw rawConfig
	known := yaml.NewDecoder(bytes.NewReader(data))
	known.KnownFields(true)
	if err := known.Decode(&raw); err != nil {
		return Config{}, fmt.Errorf("configuration: %w", err)
	}
	return normalize(raw)
}

// Load reads exactly path and delegates all interpretation to Parse. It does
// not read credential files or perform any other I/O.
func Load(path string) (Config, error) {
	data, err := os.ReadFile(path) // #nosec G304 -- path is intentionally selected by an authorized operator; no sandbox boundary is promised.
	if err != nil {
		return Config{}, fmt.Errorf("load configuration %q: %w", path, err)
	}
	cfg, err := Parse(data)
	if err != nil {
		return Config{}, fmt.Errorf("load configuration %q: %w", path, err)
	}
	return cfg, nil
}

type rawConfig struct {
	Version   *int                  `yaml:"version"`
	Logging   *rawLogging           `yaml:"logging"`
	Metrics   *rawMetrics           `yaml:"metrics"`
	Global    *rawGlobal            `yaml:"global"`
	Firewall  *rawFirewall          `yaml:"firewall"`
	Geo       *rawGeo               `yaml:"geo"`
	Providers *rawProviders         `yaml:"providers"`
	OpenZiti  *rawOpenZiti          `yaml:"openziti"`
	IPLists   map[string]*rawIPList `yaml:"ip_lists"`
	Groups    map[string][]string   `yaml:"groups"`
	Policies  []rawPolicy           `yaml:"policies"`
	CrowdSec  *rawCrowdSec          `yaml:"crowdsec"`
}

type rawOpenZiti struct {
	Identities map[string]*rawOpenZitiIdentity `yaml:"identities"`
}

type rawOpenZitiIdentity struct {
	IdentityFile *string `yaml:"identity_file"`
}

type rawTransport struct {
	Type     *string `yaml:"type"`
	Identity *string `yaml:"identity"`
	Service  *string `yaml:"service"`
}

type rawIPList struct {
	URL             *string       `yaml:"url"`
	RefreshInterval *string       `yaml:"refresh_interval"`
	RequestTimeout  *string       `yaml:"request_timeout"`
	Transport       *rawTransport `yaml:"transport"`
}

type rawLogging struct {
	Level  *string `yaml:"level"`
	Format *string `yaml:"format"`
}

type rawMetrics struct {
	Listen *string `yaml:"listen"`
}

type rawGlobal struct {
	Allowlist *[]string `yaml:"allowlist"`
	Blocklist *[]string `yaml:"blocklist"`
}

type rawFirewall struct {
	Backend    *string      `yaml:"backend"`
	DenyAction *string      `yaml:"deny_action"`
	IPv4       *bool        `yaml:"ipv4"`
	IPv6       *bool        `yaml:"ipv6"`
	Nftables   *rawNftables `yaml:"nftables"`
	IPTables   *rawIPTables `yaml:"iptables"`
}

type rawNftables struct {
	Table    *string `yaml:"table"`
	Priority *int64  `yaml:"priority"`
}

type rawIPTables struct {
	Attachments *[]rawAttachment `yaml:"attachments"`
}

type rawAttachment struct {
	Chain               *string   `yaml:"chain"`
	Direction           *string   `yaml:"direction"`
	InputInterfaces     *[]string `yaml:"input_interfaces"`
	OutputInterfaces    *[]string `yaml:"output_interfaces"`
	OriginalDestination *bool     `yaml:"original_destination"`
}

type rawGeo struct {
	RefreshInterval *string `yaml:"refresh_interval"`
	RequestTimeout  *string `yaml:"request_timeout"`
	RefreshJitter   *string `yaml:"refresh_jitter"`
}

type rawProviders struct {
	RefreshInterval *string `yaml:"refresh_interval"`
	RequestTimeout  *string `yaml:"request_timeout"`
}

type rawCrowdSec struct {
	Enabled         *bool         `yaml:"enabled"`
	LAPIURL         *string       `yaml:"lapi_url"`
	APIKeyFile      *string       `yaml:"api_key_file"`
	UpdateFrequency *string       `yaml:"update_frequency"`
	Transport       *rawTransport `yaml:"transport"`
}

type rawPolicy struct {
	Name      *string      `yaml:"name"`
	Priority  *int64       `yaml:"priority"`
	Direction *string      `yaml:"direction"`
	Mode      *string      `yaml:"mode"`
	Traffic   *[]string    `yaml:"traffic"`
	Include   *rawSelector `yaml:"include"`
	Exclude   *rawSelector `yaml:"exclude"`
}

type rawSelector struct {
	Countries *[]string `yaml:"countries"`
	RIRs      *[]string `yaml:"rirs"`
	Groups    *[]string `yaml:"groups"`
	ASNs      *[]string `yaml:"asns"`
	IPLists   *[]string `yaml:"ip_lists"`
	Providers *[]string `yaml:"providers"`
}

func normalize(raw rawConfig) (Config, error) {
	if raw.Version == nil {
		return Config{}, errors.New("version: required")
	}
	if *raw.Version != 1 {
		return Config{}, fmt.Errorf("version: must be exactly 1 (got %d)", *raw.Version)
	}
	if raw.Firewall == nil {
		return Config{}, errors.New("firewall: required mapping")
	}
	if raw.Firewall.Backend == nil || *raw.Firewall.Backend == "" {
		return Config{}, errors.New("firewall.backend: required non-empty value")
	}
	if *raw.Firewall.Backend != "nftables" && *raw.Firewall.Backend != "iptables" {
		return Config{}, fmt.Errorf("firewall.backend: unsupported value %q", *raw.Firewall.Backend)
	}

	cfg := Config{
		Version: 1,
		Logging: LoggingConfig{Level: "info", Format: "json"},
		Metrics: MetricsConfig{Listen: "127.0.0.1:2112"},
		Firewall: FirewallConfig{
			Backend: *raw.Firewall.Backend, DenyAction: "drop", IPv4: true, IPv6: true,
			Nftables: NftablesConfig{Table: "perimeterd", Priority: -10},
			IPTables: IPTablesConfig{Attachments: defaultAttachments()},
		},
		Geo:       GeoConfig{RefreshInterval: 24 * time.Hour, RequestTimeout: 30 * time.Second, RefreshJitter: 10 * time.Minute},
		Providers: ProvidersConfig{RefreshInterval: 24 * time.Hour, RequestTimeout: 30 * time.Second},
		IPLists:   make(map[string]IPListConfig),
		Groups:    make(map[string][]string),
		Policies:  []Policy{},
		CrowdSec:  CrowdSecConfig{Enabled: false, LAPIURL: "http://127.0.0.1:8080", UpdateFrequency: 10 * time.Second},
		OpenZiti:  OpenZitiConfig{Identities: make(map[string]OpenZitiIdentityConfig)},
	}

	if raw.Logging != nil {
		if raw.Logging.Level != nil {
			cfg.Logging.Level = *raw.Logging.Level
		}
		if raw.Logging.Format != nil {
			cfg.Logging.Format = *raw.Logging.Format
		}
	}
	if cfg.Logging.Level != "debug" && cfg.Logging.Level != "info" && cfg.Logging.Level != "warn" && cfg.Logging.Level != "error" {
		return Config{}, fmt.Errorf("logging.level: unsupported value %q", cfg.Logging.Level)
	}
	if cfg.Logging.Format != "json" && cfg.Logging.Format != "text" {
		return Config{}, fmt.Errorf("logging.format: unsupported value %q", cfg.Logging.Format)
	}
	if raw.Metrics != nil && raw.Metrics.Listen != nil {
		cfg.Metrics.Listen = *raw.Metrics.Listen
	}
	if err := validateListen(cfg.Metrics.Listen); err != nil {
		return Config{}, err
	}

	var allow, block []string
	if raw.Global != nil {
		if raw.Global.Allowlist != nil {
			allow = *raw.Global.Allowlist
		}
		if raw.Global.Blocklist != nil {
			block = *raw.Global.Blocklist
		}
	}
	var err error
	if cfg.OpenZiti.Identities, err = normalizeOpenZiti(raw.OpenZiti); err != nil {
		return Config{}, err
	}
	if cfg.Global.Allowlist, err = normalizePrefixes(allow, "global.allowlist"); err != nil {
		return Config{}, err
	}
	if cfg.Global.Blocklist, err = normalizePrefixes(block, "global.blocklist"); err != nil {
		return Config{}, err
	}
	// Built-in local ranges are part of the effective allowlist and cannot be removed.
	locals := builtinLocalRanges()
	allowPrefixes := make([]netip.Prefix, 0, len(cfg.Global.Allowlist)+len(locals))
	allowPrefixes = append(allowPrefixes, cfg.Global.Allowlist...)
	allowPrefixes = append(allowPrefixes, locals...)
	if cfg.Global.Allowlist, err = prefix.Normalize(allowPrefixes); err != nil {
		return Config{}, fmt.Errorf("global.allowlist: %w", err)
	}

	fw := raw.Firewall
	if fw.DenyAction != nil {
		cfg.Firewall.DenyAction = *fw.DenyAction
	}
	if cfg.Firewall.DenyAction != "drop" && cfg.Firewall.DenyAction != "reject" {
		return Config{}, fmt.Errorf("firewall.deny_action: unsupported value %q", cfg.Firewall.DenyAction)
	}
	if fw.IPv4 != nil {
		cfg.Firewall.IPv4 = *fw.IPv4
	}
	if fw.IPv6 != nil {
		cfg.Firewall.IPv6 = *fw.IPv6
	}
	if fw.Nftables != nil {
		if fw.Nftables.Table != nil {
			cfg.Firewall.Nftables.Table = *fw.Nftables.Table
		}
		if fw.Nftables.Priority != nil {
			if *fw.Nftables.Priority < -2147483648 || *fw.Nftables.Priority > 2147483647 {
				return Config{}, errors.New("firewall.nftables.priority: must fit signed 32-bit integer")
			}
			cfg.Firewall.Nftables.Priority = int32(*fw.Nftables.Priority)
		}
	}
	if cfg.Firewall.Nftables.Table == "" {
		return Config{}, errors.New("firewall.nftables.table: must be non-empty")
	}
	if cfg.Firewall.Nftables.Priority <= -200 {
		return Config{}, fmt.Errorf("firewall.nftables.priority: must be greater than -200 (got %d)", cfg.Firewall.Nftables.Priority)
	}
	if fw.IPTables != nil && fw.IPTables.Attachments != nil {
		cfg.Firewall.IPTables.Attachments, err = normalizeAttachments(*fw.IPTables.Attachments)
		if err != nil {
			return Config{}, err
		}
	}

	if raw.Geo != nil {
		if raw.Geo.RefreshInterval != nil {
			cfg.Geo.RefreshInterval, err = positiveDuration(*raw.Geo.RefreshInterval, "geo.refresh_interval")
			if err != nil {
				return Config{}, err
			}
		}
		if raw.Geo.RequestTimeout != nil {
			cfg.Geo.RequestTimeout, err = positiveDuration(*raw.Geo.RequestTimeout, "geo.request_timeout")
			if err != nil {
				return Config{}, err
			}
		}
		if raw.Geo.RefreshJitter != nil {
			cfg.Geo.RefreshJitter, err = positiveDuration(*raw.Geo.RefreshJitter, "geo.refresh_jitter")
			if err != nil {
				return Config{}, err
			}
		}
	}
	if cfg.Geo.RefreshInterval <= 0 {
		return Config{}, errors.New("geo.refresh_interval: must be positive")
	}
	if cfg.Geo.RequestTimeout <= 0 {
		return Config{}, errors.New("geo.request_timeout: must be positive")
	}
	if cfg.Geo.RefreshJitter <= 0 {
		return Config{}, errors.New("geo.refresh_jitter: must be positive")
	}
	if raw.Providers != nil {
		if raw.Providers.RefreshInterval != nil {
			cfg.Providers.RefreshInterval, err = positiveDuration(*raw.Providers.RefreshInterval, "providers.refresh_interval")
			if err != nil {
				return Config{}, err
			}
		}
		if raw.Providers.RequestTimeout != nil {
			cfg.Providers.RequestTimeout, err = positiveDuration(*raw.Providers.RequestTimeout, "providers.request_timeout")
			if err != nil {
				return Config{}, err
			}
		}
	}
	if cfg.Providers.RefreshInterval <= 0 {
		return Config{}, errors.New("providers.refresh_interval: must be positive")
	}
	if cfg.Providers.RequestTimeout <= 0 {
		return Config{}, errors.New("providers.request_timeout: must be positive")
	}

	if raw.CrowdSec != nil {
		if raw.CrowdSec.Enabled != nil {
			cfg.CrowdSec.Enabled = *raw.CrowdSec.Enabled
		}
		if raw.CrowdSec.LAPIURL != nil {
			cfg.CrowdSec.LAPIURL = *raw.CrowdSec.LAPIURL
		}
		if raw.CrowdSec.APIKeyFile != nil {
			cfg.CrowdSec.APIKeyFile = *raw.CrowdSec.APIKeyFile
		}
		if raw.CrowdSec.UpdateFrequency != nil {
			cfg.CrowdSec.UpdateFrequency, err = positiveDuration(*raw.CrowdSec.UpdateFrequency, "crowdsec.update_frequency")
			if err != nil {
				return Config{}, err
			}
		}
		if raw.CrowdSec.Transport != nil {
			cfg.CrowdSec.Transport, err = normalizeTransport(*raw.CrowdSec.Transport, cfg.OpenZiti.Identities, "crowdsec.transport")
			if err != nil {
				return Config{}, err
			}
		}
	}

	if err := validateURL(cfg.CrowdSec.LAPIURL, "crowdsec.lapi_url"); err != nil {
		return Config{}, err
	}
	if cfg.CrowdSec.Enabled && cfg.CrowdSec.APIKeyFile == "" {
		return Config{}, errors.New("crowdsec.api_key_file: required and non-empty when crowdsec.enabled is true")
	}
	if cfg.CrowdSec.UpdateFrequency <= 0 {
		return Config{}, errors.New("crowdsec.update_frequency: must be positive")
	}

	ipLists, err := normalizeIPLists(raw.IPLists, cfg.OpenZiti.Identities)
	if err != nil {
		return Config{}, err
	}
	cfg.IPLists = ipLists

	groups, err := normalizeGroups(raw.Groups)
	if err != nil {
		return Config{}, err
	}
	cfg.Groups = groups
	for _, rp := range raw.Policies {
		p, e := normalizePolicy(rp, groups, ipLists)
		if e != nil {
			return Config{}, e
		}
		cfg.Policies = append(cfg.Policies, p)
	}
	if err := validatePolicyUniqueness(cfg.Policies); err != nil {
		return Config{}, err
	}
	sort.SliceStable(cfg.Policies, func(i, j int) bool {
		if cfg.Policies[i].Direction != cfg.Policies[j].Direction {
			return cfg.Policies[i].Direction < cfg.Policies[j].Direction
		}
		return cfg.Policies[i].Priority < cfg.Policies[j].Priority
	})
	return cfg, nil
}

func defaultAttachments() []Attachment {
	return []Attachment{{Chain: "INPUT", Direction: "ingress"}, {Chain: "OUTPUT", Direction: "egress"}}
}

func normalizePrefixes(values []string, field string) ([]netip.Prefix, error) {
	prefixes := make([]netip.Prefix, 0, len(values))
	for i, value := range values {
		if value == "" {
			return nil, fmt.Errorf("%s[%d]: empty address", field, i)
		}
		if addr, err := netip.ParseAddr(value); err == nil {
			if addr.Zone() != "" {
				return nil, fmt.Errorf("%s[%d]: scoped addresses are not allowed", field, i)
			}
			prefixes = append(prefixes, netip.PrefixFrom(addr, addr.BitLen()).Masked())
			continue
		}
		prefix, err := netip.ParsePrefix(value)
		if err != nil {
			return nil, fmt.Errorf("%s[%d]: invalid address or CIDR", field, i)
		}
		prefixes = append(prefixes, prefix.Masked())
	}
	normalized, err := prefix.Normalize(prefixes)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", field, err)
	}
	return normalized, nil
}

func builtinLocalRanges() []netip.Prefix {
	values := []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8", "169.254.0.0/16", "::1/128", "fe80::/10", "fc00::/7"}
	prefixes := make([]netip.Prefix, 0, len(values))
	for _, value := range values {
		p, _ := netip.ParsePrefix(value)
		prefixes = append(prefixes, p)
	}
	return prefixes
}

func normalizeAttachments(raw []rawAttachment) ([]Attachment, error) {
	out := make([]Attachment, 0, len(raw))
	seen := make(map[string]struct{}, len(raw))
	for i, a := range raw {
		field := fmt.Sprintf("firewall.iptables.attachments[%d]", i)
		if a.Chain == nil || *a.Chain == "" {
			return nil, fmt.Errorf("%s.chain: required non-empty value", field)
		}
		if a.Direction == nil || (*a.Direction != "ingress" && *a.Direction != "egress") {
			return nil, fmt.Errorf("%s.direction: must be ingress or egress", field)
		}
		attachment := Attachment{Chain: *a.Chain, Direction: *a.Direction}
		if a.InputInterfaces != nil {
			attachment.InputInterfaces = normalizeInterfaceList(*a.InputInterfaces)
		}
		if a.OutputInterfaces != nil {
			attachment.OutputInterfaces = normalizeInterfaceList(*a.OutputInterfaces)
		}
		for j, iface := range attachment.InputInterfaces {
			if iface == "" {
				return nil, fmt.Errorf("%s.input_interfaces[%d]: must be non-empty", field, j)
			}
		}
		for j, iface := range attachment.OutputInterfaces {
			if iface == "" {
				return nil, fmt.Errorf("%s.output_interfaces[%d]: must be non-empty", field, j)
			}
		}
		if a.OriginalDestination != nil {
			attachment.OriginalDestination = *a.OriginalDestination
		}
		if attachment.Chain != "INPUT" && attachment.Chain != "OUTPUT" {
			if attachment.Direction == "ingress" && len(attachment.InputInterfaces) == 0 {
				return nil, fmt.Errorf("%s.input_interfaces: non-host ingress attachment requires an input interface", field)
			}
			if attachment.Direction == "egress" && len(attachment.OutputInterfaces) == 0 {
				return nil, fmt.Errorf("%s.output_interfaces: non-host egress attachment requires an output interface", field)
			}
		}
		key := attachment.Chain + "\x00" + attachment.Direction + "\x00" +
			sliceKey(attachment.InputInterfaces) + "\x00" + sliceKey(attachment.OutputInterfaces) +
			"\x00" + strconv.FormatBool(attachment.OriginalDestination)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, attachment)
	}
	return out, nil
}

func normalizeInterfaceList(values []string) []string {
	out := append([]string(nil), values...)
	sort.Strings(out)
	compact := out[:0]
	for _, value := range out {
		if len(compact) == 0 || compact[len(compact)-1] != value {
			compact = append(compact, value)
		}
	}
	return compact
}

func sliceKey(values []string) string {
	var b strings.Builder
	for _, value := range values {
		b.WriteString(strconv.Itoa(len(value)))
		b.WriteByte(':')
		b.WriteString(value)
		b.WriteByte(';')
	}
	return b.String()
}

func normalizeOpenZiti(raw *rawOpenZiti) (map[string]OpenZitiIdentityConfig, error) {
	out := make(map[string]OpenZitiIdentityConfig)
	if raw == nil {
		return out, nil
	}
	out = make(map[string]OpenZitiIdentityConfig, len(raw.Identities))
	for name, value := range raw.Identities {
		field := "openziti.identities." + name
		if err := validateName(name, field); err != nil {
			return nil, err
		}
		if value == nil {
			return nil, fmt.Errorf("%s: required mapping", field)
		}
		if value.IdentityFile == nil || *value.IdentityFile == "" {
			return nil, fmt.Errorf("%s.identity_file: required non-empty value", field)
		}
		if !filepath.IsAbs(*value.IdentityFile) {
			return nil, fmt.Errorf("%s.identity_file: must be an absolute path", field)
		}
		out[name] = OpenZitiIdentityConfig{IdentityFile: *value.IdentityFile}
	}
	return out, nil
}

func normalizeTransport(raw rawTransport, identities map[string]OpenZitiIdentityConfig, field string) (TransportConfig, error) {
	transport := TransportConfig{}
	if raw.Type != nil {
		switch *raw.Type {
		case "", "direct":
			// The empty type is the canonical direct default.
		case "openziti":
			transport.Type = "openziti"
		default:
			return TransportConfig{}, fmt.Errorf("%s.type: unsupported value %q", field, *raw.Type)
		}
	}
	if raw.Identity != nil {
		transport.Identity = *raw.Identity
	}
	if raw.Service != nil {
		transport.Service = *raw.Service
	}
	if transport.Type == "" {
		if raw.Identity != nil || raw.Service != nil {
			return TransportConfig{}, fmt.Errorf("%s: identity and service are forbidden for direct transport", field)
		}
		return TransportConfig{}, nil
	}
	if transport.Identity == "" {
		return TransportConfig{}, fmt.Errorf("%s.identity: required for openziti transport", field)
	}
	if err := validateName(transport.Identity, field+".identity"); err != nil {
		return TransportConfig{}, err
	}
	if _, ok := identities[transport.Identity]; !ok {
		return TransportConfig{}, fmt.Errorf("%s.identity: unknown OpenZiti identity %q", field, transport.Identity)
	}
	if strings.TrimSpace(transport.Service) == "" {
		return TransportConfig{}, fmt.Errorf("%s.service: required non-blank value for openziti transport", field)
	}
	return transport, nil
}

func normalizeIPLists(raw map[string]*rawIPList, identities map[string]OpenZitiIdentityConfig) (map[string]IPListConfig, error) {
	out := make(map[string]IPListConfig, len(raw))
	for name, value := range raw {
		field := "ip_lists." + name
		if err := validateName(name, field); err != nil {
			return nil, err
		}
		if value == nil {
			return nil, fmt.Errorf("%s: required mapping", field)
		}
		if value.URL == nil || *value.URL == "" {
			return nil, fmt.Errorf("%s.url: required non-empty value", field)
		}
		urlValue, err := NormalizeIPListURL(*value.URL)
		if err != nil {
			return nil, fmt.Errorf("%s.url: %w", field, err)
		}
		entry := IPListConfig{
			URL:             urlValue,
			RefreshInterval: 24 * time.Hour,
			RequestTimeout:  30 * time.Second,
		}
		if value.RefreshInterval != nil {
			entry.RefreshInterval, err = positiveDuration(*value.RefreshInterval, field+".refresh_interval")
			if err != nil {
				return nil, err
			}
		}
		if value.RequestTimeout != nil {
			entry.RequestTimeout, err = positiveDuration(*value.RequestTimeout, field+".request_timeout")
			if err != nil {
				return nil, err
			}
		}
		if value.Transport != nil {
			entry.Transport, err = normalizeTransport(*value.Transport, identities, field+".transport")
			if err != nil {
				return nil, err
			}
		}
		out[name] = entry
	}
	return out, nil
}

// NormalizeIPListURL canonicalizes and validates one configured HTTP(S) list
// URL. Scheme and DNS host are lowercased; IPv6 zones, path and query are preserved.
func NormalizeIPListURL(value string) (string, error) {
	if strings.ContainsAny(value, "\r\n") {
		return "", errors.New("invalid URL")
	}
	parsed, err := url.Parse(value)
	if err != nil || parsed.Host == "" || parsed.Hostname() == "" {
		return "", errors.New("must be an absolute http or https URL")
	}
	if parsed.User != nil {
		return "", errors.New("user information is not allowed")
	}
	if strings.Contains(value, "#") {
		return "", errors.New("fragment is not allowed")
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme != "http" && scheme != "https" {
		return "", errors.New("must be an absolute http or https URL")
	}
	parsed.Scheme = scheme
	if !strings.HasPrefix(parsed.Host, "[") {
		parsed.Host = strings.ToLower(parsed.Host)
	}
	return parsed.String(), nil
}

func normalizeGroups(raw map[string][]string) (map[string][]string, error) {
	out := make(map[string][]string, len(raw))
	for name, countries := range raw {
		if err := validateName(name, "groups."+name); err != nil {
			return nil, err
		}
		if _, exists := catalog.Countries(name); exists {
			return nil, fmt.Errorf("groups.%s: custom group shadows built-in group", name)
		}
		if len(countries) == 0 {
			return nil, fmt.Errorf("groups.%s: country list must be non-empty", name)
		}
		seen := make(map[string]struct{}, len(countries))
		for i, country := range countries {
			country = strings.ToUpper(country)
			if !catalog.ValidCountry(country) {
				return nil, fmt.Errorf("groups.%s[%d]: unknown country", name, i)
			}
			seen[country] = struct{}{}
		}
		list := make([]string, 0, len(seen))
		for country := range seen {
			list = append(list, country)
		}
		sort.Strings(list)
		out[name] = list
	}
	return out, nil
}

func normalizePolicy(raw rawPolicy, groups map[string][]string, ipLists map[string]IPListConfig) (Policy, error) {
	if raw.Name == nil || *raw.Name == "" {
		return Policy{}, errors.New("policies[].name: required")
	}
	if err := validateName(*raw.Name, "policies."+*raw.Name+".name"); err != nil {
		return Policy{}, err
	}
	if raw.Priority == nil {
		return Policy{}, fmt.Errorf("policy %s.priority: required", *raw.Name)
	}
	if *raw.Priority < 0 {
		return Policy{}, fmt.Errorf("policy %s.priority: must be non-negative", *raw.Name)
	}
	if raw.Direction == nil || (*raw.Direction != "ingress" && *raw.Direction != "egress") {
		return Policy{}, fmt.Errorf("policy %s.direction: must be ingress or egress", *raw.Name)
	}
	if raw.Mode == nil || (*raw.Mode != "allowlist" && *raw.Mode != "blocklist" && *raw.Mode != "disabled") {
		return Policy{}, fmt.Errorf("policy %s.mode: must be allowlist, blocklist, or disabled", *raw.Name)
	}
	if raw.Traffic == nil || len(*raw.Traffic) == 0 {
		return Policy{}, fmt.Errorf("policy %s.traffic: required non-empty list", *raw.Name)
	}
	traffic, err := normalizeTraffic(*raw.Traffic, *raw.Name)
	if err != nil {
		return Policy{}, err
	}
	if raw.Include == nil {
		return Policy{}, fmt.Errorf("policy %s.include: required mapping", *raw.Name)
	}
	include, includeCount, err := normalizeSelector(*raw.Include, groups, ipLists, "policy "+*raw.Name+".include")
	if err != nil {
		return Policy{}, err
	}
	exclude := Selector{}
	if raw.Exclude != nil {
		exclude, _, err = normalizeSelector(*raw.Exclude, groups, ipLists, "policy "+*raw.Name+".exclude")
		if err != nil {
			return Policy{}, err
		}
	}
	if *raw.Mode != "disabled" && includeCount == 0 {
		return Policy{}, fmt.Errorf("policy %s.include: enabled policy requires a non-empty selector", *raw.Name)
	}
	return Policy{Name: *raw.Name, Priority: *raw.Priority, Direction: *raw.Direction, Mode: *raw.Mode, Traffic: traffic, Include: include, Exclude: exclude}, nil
}

func normalizeSelector(raw rawSelector, groups map[string][]string, ipLists map[string]IPListConfig, field string) (Selector, int, error) {
	selector := Selector{}
	count := 0
	if raw.Countries != nil {
		if len(*raw.Countries) == 0 {
			return Selector{}, 0, fmt.Errorf("%s.countries: must be non-empty when present", field)
		}
		seen := map[string]struct{}{}
		for i, country := range *raw.Countries {
			country = strings.ToUpper(country)
			if !catalog.ValidCountry(country) {
				return Selector{}, 0, fmt.Errorf("%s.countries[%d]: unknown country", field, i)
			}
			seen[country] = struct{}{}
		}
		selector.Countries = sortedKeys(seen)
		count += len(selector.Countries)
	}
	if raw.RIRs != nil {
		if len(*raw.RIRs) == 0 {
			return Selector{}, 0, fmt.Errorf("%s.rirs: must be non-empty when present", field)
		}
		seen := map[string]struct{}{}
		for i, rir := range *raw.RIRs {
			rir = strings.ToUpper(rir)
			if !catalog.ValidRIR(rir) {
				return Selector{}, 0, fmt.Errorf("%s.rirs[%d]: unknown RIR", field, i)
			}
			seen[rir] = struct{}{}
		}
		selector.RIRs = sortedKeys(seen)
		count += len(selector.RIRs)
	}
	if raw.Groups != nil {
		if len(*raw.Groups) == 0 {
			return Selector{}, 0, fmt.Errorf("%s.groups: must be non-empty when present", field)
		}
		seen := map[string]struct{}{}
		for i, name := range *raw.Groups {
			if _, ok := groups[name]; !ok {
				if _, builtin := catalog.Countries(name); !builtin {
					return Selector{}, 0, fmt.Errorf("%s.groups[%d]: unknown group", field, i)
				}
			}
			seen[name] = struct{}{}
		}
		selector.Groups = sortedKeys(seen)
		count += len(selector.Groups)
	}
	if raw.ASNs != nil {
		if len(*raw.ASNs) == 0 {
			return Selector{}, 0, fmt.Errorf("%s.asns: must be non-empty when present", field)
		}
		seen := map[string]struct{}{}
		for i, asn := range *raw.ASNs {
			if !catalog.ValidASN(asn) {
				return Selector{}, 0, fmt.Errorf("%s.asns[%d]: must use canonical AS<number> form", field, i)
			}
			seen[asn] = struct{}{}
		}
		selector.ASNs = sortedKeys(seen)
		count += len(selector.ASNs)
	}
	if raw.IPLists != nil {
		if len(*raw.IPLists) == 0 {
			return Selector{}, 0, fmt.Errorf("%s.ip_lists: must be non-empty when present", field)
		}
		seen := map[string]struct{}{}
		for i, name := range *raw.IPLists {
			if _, ok := ipLists[name]; !ok {
				return Selector{}, 0, fmt.Errorf("%s.ip_lists[%d]: unknown list", field, i)
			}
			seen[name] = struct{}{}
		}
		selector.IPLists = sortedKeys(seen)
		count += len(selector.IPLists)
	}
	if raw.Providers != nil {
		if len(*raw.Providers) == 0 {
			return Selector{}, 0, fmt.Errorf("%s.providers: must be non-empty when present", field)
		}
		seen := make(map[string]struct{}, len(*raw.Providers))
		for i, id := range *raw.Providers {
			if !ValidProviderID(id) {
				return Selector{}, 0, fmt.Errorf("%s.providers[%d]: must use a lowercase provider ID containing only letters, digits, hyphens, or underscores", field, i)
			}
			seen[id] = struct{}{}
		}
		selector.Providers = sortedKeys(seen)
		count += len(selector.Providers)
	}
	countrySet := make(map[string]struct{}, len(selector.Countries))
	for _, country := range selector.Countries {
		countrySet[country] = struct{}{}
	}
	for _, group := range selector.Groups {
		members, ok := groups[group]
		if !ok {
			members, ok = catalog.Countries(group)
		}
		if !ok {
			continue
		}
		for _, country := range members {
			countrySet[strings.ToUpper(country)] = struct{}{}
		}
	}
	selector.ExpandedCountries = sortedKeys(countrySet)
	return selector, count, nil
}

func normalizeTraffic(values []string, policy string) (TrafficScope, error) {
	var scope TrafficScope
	for i, value := range values {
		field := fmt.Sprintf("policy %s.traffic[%d]", policy, i)
		if value == "any" {
			if len(values) != 1 {
				return TrafficScope{}, fmt.Errorf("%s: any must be the only entry", field)
			}
			scope.Any = true
			continue
		}
		if value == "icmp" {
			scope.ICMP = true
			continue
		}
		if value == "icmpv6" {
			scope.ICMPv6 = true
			continue
		}
		transport := "tcp"
		portText := value
		if strings.Contains(value, "/") {
			parts := strings.Split(value, "/")
			if len(parts) != 2 || (parts[1] != "tcp" && parts[1] != "udp") {
				return TrafficScope{}, fmt.Errorf("%s: invalid transport", field)
			}
			transport, portText = parts[1], parts[0]
		}
		start, end, ok := parsePortRange(portText)
		if !ok {
			return TrafficScope{}, fmt.Errorf("%s: expected decimal port 1-65535 or inclusive range", field)
		}
		r := PortRange{Start: start, End: end}
		if transport == "tcp" {
			scope.TCP = append(scope.TCP, r)
		} else {
			scope.UDP = append(scope.UDP, r)
		}
	}
	scope.TCP = mergePortRanges(scope.TCP)
	scope.UDP = mergePortRanges(scope.UDP)
	return scope, nil
}

func parsePortRange(value string) (uint16, uint16, bool) {
	if value == "" {
		return 0, 0, false
	}
	parts := strings.Split(value, "-")
	if len(parts) > 2 || parts[0] == "" {
		return 0, 0, false
	}
	start, err := decimalPort(parts[0])
	if err != nil {
		return 0, 0, false
	}
	end := start
	if len(parts) == 2 {
		if parts[1] == "" {
			return 0, 0, false
		}
		end, err = decimalPort(parts[1])
		if err != nil {
			return 0, 0, false
		}
	}
	if end < start {
		return 0, 0, false
	}
	return start, end, true
}

func decimalPort(value string) (uint16, error) {
	if value == "" {
		return 0, errors.New("empty")
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return 0, errors.New("not decimal")
		}
	}
	n, err := strconv.ParseUint(value, 10, 16)
	if err != nil || n == 0 {
		return 0, errors.New("out of range")
	}
	return uint16(n), nil
}

func mergePortRanges(values []PortRange) []PortRange {
	if len(values) == 0 {
		return []PortRange{}
	}
	out := append([]PortRange(nil), values...)
	sort.Slice(out, func(i, j int) bool {
		if out[i].Start != out[j].Start {
			return out[i].Start < out[j].Start
		}
		return out[i].End < out[j].End
	})
	merged := out[:1]
	for _, next := range out[1:] {
		last := &merged[len(merged)-1]
		if int(next.Start) <= int(last.End)+1 {
			if next.End > last.End {
				last.End = next.End
			}
			continue
		}
		merged = append(merged, next)
	}
	return merged
}

func validatePolicyUniqueness(policies []Policy) error {
	names := make(map[string]struct{}, len(policies))
	priorities := make(map[string]map[int64]string)
	for _, policy := range policies {
		if _, exists := names[policy.Name]; exists {
			return fmt.Errorf("policy %s: duplicate policy name", policy.Name)
		}
		names[policy.Name] = struct{}{}
		byDirection := priorities[policy.Direction]
		if byDirection == nil {
			byDirection = make(map[int64]string)
			priorities[policy.Direction] = byDirection
		}
		if other, exists := byDirection[policy.Priority]; exists {
			return fmt.Errorf("policies %s and %s: duplicate priority %d in %s direction", other, policy.Name, policy.Priority, policy.Direction)
		}
		byDirection[policy.Priority] = policy.Name
	}
	return nil
}

var namePattern = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)

// ValidName reports whether name uses perimeterd's lowercase DNS-label-like
// identifier syntax.
func ValidName(name string) bool {
	return namePattern.MatchString(name)
}

var providerIDPattern = regexp.MustCompile(`^[a-z0-9_-]+$`)

// ValidProviderID reports whether an external named-provider ID is safe to use
// in the fixed source endpoint path. It intentionally does not check membership.
func ValidProviderID(id string) bool {
	return providerIDPattern.MatchString(id)
}

func validateName(name, field string) error {
	if !ValidName(name) {
		return fmt.Errorf("%s: must be a lowercase DNS-label-like name", field)
	}
	return nil
}

func sortedKeys(values map[string]struct{}) []string {
	keys := make([]string, 0, len(values))
	for key := range values {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func positiveDuration(value, field string) (time.Duration, error) {
	d, err := time.ParseDuration(value)
	if err != nil {
		return 0, fmt.Errorf("%s: invalid Go duration", field)
	}
	if d <= 0 {
		return 0, fmt.Errorf("%s: must be positive", field)
	}
	return d, nil
}

func validateListen(value string) error {
	if value == "" {
		return nil
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return fmt.Errorf("metrics.listen: must be host:port")
	}
	if !decimalDigits(port) {
		return fmt.Errorf("metrics.listen: port must be decimal")
	}
	n, err := strconv.Atoi(port)
	if err != nil || n < 0 || n > 65535 {
		return fmt.Errorf("metrics.listen: port out of range")
	}
	if strings.ContainsAny(host, "\r\n") {
		return errors.New("metrics.listen: invalid host")
	}
	return nil
}

func decimalDigits(value string) bool {
	if value == "" {
		return false
	}
	for _, r := range value {
		if r < '0' || r > '9' {
			return false
		}
	}
	return true
}

func validateURL(value, field string) error {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.Hostname() == "" || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("%s: must be an absolute http or https URL", field)
	}
	if strings.ContainsAny(value, "\r\n") {
		return fmt.Errorf("%s: invalid URL", field)
	}
	return nil
}

type nodeKind uint8

const (
	kindMap nodeKind = iota
	kindSeq
	kindString
	kindInt
	kindBool
)

func unwrapDocument(node *yaml.Node) *yaml.Node {
	if node.Kind == yaml.DocumentNode && len(node.Content) == 1 {
		return node.Content[0]
	}
	return node
}

func rejectDuplicateKeys(node *yaml.Node, path string) error {
	if node.Kind == yaml.DocumentNode {
		for _, child := range node.Content {
			if err := rejectDuplicateKeys(child, path); err != nil {
				return err
			}
		}
		return nil
	}
	if node.Kind == yaml.MappingNode {
		seen := make(map[string]struct{}, len(node.Content)/2)
		for i := 0; i+1 < len(node.Content); i += 2 {
			key, value := node.Content[i], node.Content[i+1]
			if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
				return fmt.Errorf("%s: mapping keys must be strings", path)
			}
			if _, exists := seen[key.Value]; exists {
				return fmt.Errorf("%s.%s: duplicate key", path, key.Value)
			}
			seen[key.Value] = struct{}{}
			if err := rejectDuplicateKeys(value, path+"."+key.Value); err != nil {
				return err
			}
		}
	} else {
		for _, child := range node.Content {
			if err := rejectDuplicateKeys(child, path); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkRootShape(root *yaml.Node) error {
	if err := expectNode(root, kindMap, "configuration"); err != nil {
		return err
	}
	return checkMappingFields(root, "configuration", map[string]nodeKind{
		"version": kindInt, "logging": kindMap, "metrics": kindMap, "global": kindMap, "firewall": kindMap,
		"geo": kindMap, "providers": kindMap, "openziti": kindMap, "ip_lists": kindMap, "groups": kindMap, "policies": kindSeq, "crowdsec": kindMap,
	}, map[string]func(*yaml.Node, string) error{
		"logging": checkLogging, "metrics": checkMetrics, "global": checkGlobal, "firewall": checkFirewall,
		"geo": checkGeo, "providers": checkProviders, "openziti": checkOpenZiti, "ip_lists": checkIPListsShape, "groups": checkGroupsShape, "policies": checkPoliciesShape, "crowdsec": checkCrowdSec,
	})
}

func checkMappingFields(node *yaml.Node, path string, kinds map[string]nodeKind, nested map[string]func(*yaml.Node, string) error) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		name := key.Value
		expected, ok := kinds[name]
		if !ok {
			continue
		}
		if err := expectNode(value, expected, path+"."+name); err != nil {
			return err
		}
		if fn := nested[name]; fn != nil {
			if err := fn(value, path+"."+name); err != nil {
				return err
			}
		}
	}
	return nil
}

func checkLogging(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"level": kindString, "format": kindString}, nil)
}

func checkMetrics(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"listen": kindString}, nil)
}

func checkGlobal(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"allowlist": kindSeq, "blocklist": kindSeq}, map[string]func(*yaml.Node, string) error{"allowlist": checkStringSequence, "blocklist": checkStringSequence})
}

func checkGeo(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"refresh_interval": kindString, "request_timeout": kindString, "refresh_jitter": kindString}, nil)
}

func checkProviders(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"refresh_interval": kindString, "request_timeout": kindString}, nil)
}

func checkCrowdSec(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"enabled": kindBool, "lapi_url": kindString, "api_key_file": kindString, "update_frequency": kindString, "transport": kindMap}, map[string]func(*yaml.Node, string) error{"transport": checkTransportShape})
}

func checkOpenZiti(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"identities": kindMap}, map[string]func(*yaml.Node, string) error{"identities": checkIdentitiesShape})
}

func checkIdentitiesShape(node *yaml.Node, path string) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("%s: identity names must be strings", path)
		}
		entryPath := path + "." + key.Value
		if err := expectNode(value, kindMap, entryPath); err != nil {
			return err
		}
		if err := checkMappingFields(value, entryPath, map[string]nodeKind{"identity_file": kindString}, nil); err != nil {
			return err
		}
	}
	return nil
}

func checkTransportShape(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"type": kindString, "identity": kindString, "service": kindString}, nil)
}

func checkFirewall(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"backend": kindString, "deny_action": kindString, "ipv4": kindBool, "ipv6": kindBool, "nftables": kindMap, "iptables": kindMap}, map[string]func(*yaml.Node, string) error{"nftables": checkNftables, "iptables": checkIPTables})
}

func checkNftables(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"table": kindString, "priority": kindInt}, nil)
}

func checkIPTables(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"attachments": kindSeq}, map[string]func(*yaml.Node, string) error{"attachments": checkAttachmentsShape})
}

func checkAttachmentsShape(node *yaml.Node, path string) error {
	for i, item := range node.Content {
		if err := expectNode(item, kindMap, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
		if err := checkMappingFields(item, fmt.Sprintf("%s[%d]", path, i), map[string]nodeKind{"chain": kindString, "direction": kindString, "input_interfaces": kindSeq, "output_interfaces": kindSeq, "original_destination": kindBool}, map[string]func(*yaml.Node, string) error{"input_interfaces": checkStringSequence, "output_interfaces": checkStringSequence}); err != nil {
			return err
		}
	}
	return nil
}

func checkIPListsShape(node *yaml.Node, path string) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("%s: list names must be strings", path)
		}
		entryPath := path + "." + key.Value
		if err := expectNode(value, kindMap, entryPath); err != nil {
			return err
		}
		if err := checkMappingFields(value, entryPath, map[string]nodeKind{
			"url": kindString, "refresh_interval": kindString, "request_timeout": kindString, "transport": kindMap,
		}, map[string]func(*yaml.Node, string) error{"transport": checkTransportShape}); err != nil {
			return err
		}
	}
	return nil
}

func checkGroupsShape(node *yaml.Node, path string) error {
	for i := 0; i+1 < len(node.Content); i += 2 {
		key, value := node.Content[i], node.Content[i+1]
		if key.Kind != yaml.ScalarNode || key.Tag != "!!str" {
			return fmt.Errorf("%s: group names must be strings", path)
		}
		if err := expectNode(value, kindSeq, path+"."+key.Value); err != nil {
			return err
		}
		if err := checkStringSequence(value, path+"."+key.Value); err != nil {
			return err
		}
	}
	return nil
}

func checkPoliciesShape(node *yaml.Node, path string) error {
	for i, item := range node.Content {
		if err := expectNode(item, kindMap, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
		if err := checkPolicyShape(item, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

func checkPolicyShape(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"name": kindString, "priority": kindInt, "direction": kindString, "mode": kindString, "traffic": kindSeq, "include": kindMap, "exclude": kindMap}, map[string]func(*yaml.Node, string) error{"traffic": checkStringSequence, "include": checkSelectorShape, "exclude": checkSelectorShape})
}

func checkSelectorShape(node *yaml.Node, path string) error {
	return checkMappingFields(node, path, map[string]nodeKind{"countries": kindSeq, "rirs": kindSeq, "groups": kindSeq, "asns": kindSeq, "ip_lists": kindSeq, "providers": kindSeq}, map[string]func(*yaml.Node, string) error{"countries": checkStringSequence, "rirs": checkStringSequence, "groups": checkStringSequence, "asns": checkStringSequence, "ip_lists": checkStringSequence, "providers": checkStringSequence})
}

func checkStringSequence(node *yaml.Node, path string) error {
	for i, item := range node.Content {
		if err := expectNode(item, kindString, fmt.Sprintf("%s[%d]", path, i)); err != nil {
			return err
		}
	}
	return nil
}

func expectNode(node *yaml.Node, expected nodeKind, path string) error {
	ok := false
	switch expected {
	case kindMap:
		ok = node.Kind == yaml.MappingNode && node.Tag == "!!map"
	case kindSeq:
		ok = node.Kind == yaml.SequenceNode && node.Tag == "!!seq"
	case kindString:
		ok = node.Kind == yaml.ScalarNode && node.Tag == "!!str"
	case kindInt:
		ok = node.Kind == yaml.ScalarNode && node.Tag == "!!int"
	case kindBool:
		ok = node.Kind == yaml.ScalarNode && node.Tag == "!!bool"
	}
	if !ok {
		return fmt.Errorf("%s: wrong YAML type", path)
	}
	return nil
}
