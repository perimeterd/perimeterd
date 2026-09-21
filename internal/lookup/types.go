// Package lookup implements read-only applied-policy queries and private transport.
package lookup

import (
	"context"
	"net/netip"
	"time"

	"github.com/perimeterd/perimeterd/internal/crowdsec"
	"github.com/perimeterd/perimeterd/internal/policy"
)

const (
	// SocketPath is the production-only local query endpoint.
	SocketPath = "/run/perimeterd/lookup.sock"
	// Endpoint versions the read-only HTTP method on the Unix socket.
	Endpoint = "/v1/lookup"
	// SchemaVersion identifies the complete response envelope.
	SchemaVersion = 1
	// MaxRequestBytes bounds decoded query input.
	MaxRequestBytes = 4 << 10
	// MaxResponseBytes bounds a complete encoded result.
	MaxResponseBytes = 4 << 20
	// MaxRecords bounds combined outcome and evidence records.
	MaxRecords = 4096
	// MaxConcurrent bounds admitted query evaluations.
	MaxConcurrent = 4
	// Timeout bounds one complete query round trip.
	Timeout = 5 * time.Second
)

// Request selects address and new-flow scopes; omitted fields mean all scopes.
type Request struct {
	Address   string           `json:"address"`
	Direction policy.Direction `json:"direction,omitempty"`
	Protocol  string           `json:"protocol,omitempty"`
	Port      *uint16          `json:"port,omitempty"`
}

// Failure is an explicit inability to supply a complete result.
type Failure struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// Response is complete or explicitly unknown; records are never truncated.
type Response struct {
	SchemaVersion    int       `json:"schema_version"`
	Query            Request   `json:"query"`
	Flow             string    `json:"flow"`
	ObservedAt       time.Time `json:"observed_at,omitzero"`
	Revision         string    `json:"revision,omitempty"`
	ConfigEpoch      uint64    `json:"config_epoch,omitempty"`
	Manifest         string    `json:"manifest,omitempty"`
	DynamicEpoch     uint64    `json:"dynamic_epoch,omitempty"`
	DynamicOperation uint64    `json:"dynamic_operation,omitempty"`
	Verdict          string    `json:"verdict"`
	Outcomes         []Outcome `json:"outcomes,omitempty"`
	Error            *Failure  `json:"error,omitempty"`
}

// Ports is an inclusive destination-port interval.
type Ports struct {
	Start uint16 `json:"start"`
	End   uint16 `json:"end"`
}

// Attachment identifies the conditions under which an outcome applies.
type Attachment struct {
	Name             string   `json:"name"`
	Managed          bool     `json:"managed"`
	PortBasis        string   `json:"port_basis"`
	InputInterfaces  []string `json:"input_interfaces,omitempty"`
	OutputInterfaces []string `json:"output_interfaces,omitempty"`
}

// Outcome covers one whole address, flow and managed-path partition.
type Outcome struct {
	Prefix     netip.Prefix     `json:"prefix"`
	Direction  policy.Direction `json:"direction"`
	Protocol   string           `json:"protocol"`
	Ports      *Ports           `json:"ports,omitempty"`
	Attachment Attachment       `json:"attachment"`
	Verdict    string           `json:"verdict"`
	Action     policy.Action    `json:"action"`
	Stage      string           `json:"stage"`
	Policy     string           `json:"policy,omitempty"`
	Priority   int              `json:"priority"`
	Reason     string           `json:"reason"`
	Evidence   []Evidence       `json:"evidence,omitempty"`
}

// Evidence distinguishes source membership from its causal role in an outcome.
type Evidence struct {
	Kind             string       `json:"kind"`
	Name             string       `json:"name"`
	Policy           string       `json:"policy,omitempty"`
	Role             string       `json:"role"`
	Via              []string     `json:"via,omitempty"`
	Prefix           netip.Prefix `json:"prefix"`
	Contributing     bool         `json:"contributing"`
	RetrievedAt      time.Time    `json:"retrieved_at,omitzero"`
	DecisionID       int64        `json:"decision_id,omitempty"`
	DecisionDeadline time.Time    `json:"decision_deadline,omitzero"`
	LeaseDeadline    time.Time    `json:"lease_deadline,omitzero"`
}

// Dynamic owns immutable evidence captured at a successful native write.
// Prefix deadlines are conservative acknowledged native lease deadlines, not
// desired decision deadlines. ValidUntil bounds certainty of the whole view.
type Dynamic struct {
	Epoch      uint64
	Operation  uint64
	Prefixes   []policy.TimedPrefix
	Decisions  []crowdsec.Decision
	ValidUntil time.Time
}

// Handler consumes a normalized request without changing enforcement.
type Handler func(context.Context, Request) Response

// Unknown never carries partial outcomes or a permissive verdict.
func Unknown(request Request, code, message string) Response {
	return Response{SchemaVersion: SchemaVersion, Query: request, Flow: "new", Verdict: "unknown", Error: &Failure{Code: code, Message: message}}
}
