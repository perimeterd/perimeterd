package control

import (
	"context"
	"time"
)

// StatusEndpoint is the read-only applied-state endpoint.
const StatusEndpoint = "/v1/status"

// StatusResult reports daemon-owned, last-acknowledged state, not a kernel audit.
type StatusResult struct {
	SchemaVersion int           `json:"schema_version"`
	ObservedAt    time.Time     `json:"observed_at"`
	Daemon        StatusDaemon  `json:"daemon"`
	Applied       StatusApplied `json:"applied"`
}

// StatusDaemon describes the running process independently of applied state.
type StatusDaemon struct {
	Version       string `json:"version"`
	UptimeSeconds uint64 `json:"uptime_seconds"`
	Healthy       bool   `json:"healthy"`
}

// StatusApplied distinguishes applied, empty, and unavailable enforcement.
// Details is nil unless State is applied. Reason explains unavailable state.
type StatusApplied struct {
	State       string         `json:"state"`
	Reason      string         `json:"reason,omitempty"`
	Revision    string         `json:"revision,omitempty"`
	ConfigEpoch uint64         `json:"config_epoch,omitempty"`
	Manifest    string         `json:"manifest,omitempty"`
	Details     *StatusDetails `json:"details,omitempty"`
}

// StatusDetails contains only public applied-policy metadata and loaded counts.
type StatusDetails struct {
	Firewall     StatusFirewall      `json:"firewall"`
	Policies     []StatusPolicy      `json:"policies"`
	PrefixCounts []StatusPrefixCount `json:"prefix_counts"`
	CrowdSec     StatusCrowdSec      `json:"crowdsec"`
}

// StatusFirewall identifies the selected backend and managed address families.
type StatusFirewall struct {
	Backend     string             `json:"backend"`
	Families    []string           `json:"families"`
	DenyAction  string             `json:"deny_action"`
	Attachments []StatusAttachment `json:"attachments,omitempty"`
}

// StatusAttachment describes an applied iptables parent-chain boundary.
type StatusAttachment struct {
	Chain               string   `json:"chain"`
	Direction           string   `json:"direction"`
	InputInterfaces     []string `json:"input_interfaces,omitempty"`
	OutputInterfaces    []string `json:"output_interfaces,omitempty"`
	OriginalDestination bool     `json:"original_destination"`
}

// StatusPolicy summarizes a normalized policy without its source definitions.
type StatusPolicy struct {
	Name      string        `json:"name"`
	Priority  int64         `json:"priority"`
	Direction string        `json:"direction"`
	Mode      string        `json:"mode"`
	Traffic   StatusTraffic `json:"traffic"`
}

// StatusTraffic describes a policy's normalized protocol and port scope.
type StatusTraffic struct {
	Any    bool              `json:"any"`
	TCP    []StatusPortRange `json:"tcp,omitempty"`
	UDP    []StatusPortRange `json:"udp,omitempty"`
	ICMP   bool              `json:"icmp"`
	ICMPv6 bool              `json:"icmpv6"`
}

// StatusPortRange is an inclusive transport-port interval.
type StatusPortRange struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

// StatusPrefixCount counts distinct prefix elements within one metric label set.
type StatusPrefixCount struct {
	Family string `json:"family"`
	Source string `json:"source"`
	Type   string `json:"type"`
	Count  uint64 `json:"count"`
}

// StatusCrowdSec omits counts when validity is unknown or stale.
// Counts count unexpired acknowledged decisions, not unique addresses.
type StatusCrowdSec struct {
	Enabled    bool                  `json:"enabled"`
	Epoch      uint64                `json:"epoch,omitempty"`
	Operation  uint64                `json:"operation,omitempty"`
	Validity   string                `json:"validity"`
	ValidUntil time.Time             `json:"valid_until,omitzero"`
	Counts     *StatusDecisionCounts `json:"counts,omitempty"`
}

// StatusDecisionCounts counts unexpired acknowledged decisions by enabled family.
type StatusDecisionCounts struct {
	IPv4 uint64 `json:"ipv4"`
	IPv6 uint64 `json:"ipv6"`
}

// StatusHandler reads a coherent snapshot without changing enforcement.
type StatusHandler func(context.Context) StatusResult

// Successful reports whether status can be used as a healthy coherent report.
func (s StatusResult) Successful() bool {
	if !s.Daemon.Healthy || (s.Applied.State != "applied" && s.Applied.State != "empty") {
		return false
	}
	return s.Applied.Details == nil || !s.Applied.Details.CrowdSec.Enabled || s.Applied.Details.CrowdSec.Validity == "valid"
}
