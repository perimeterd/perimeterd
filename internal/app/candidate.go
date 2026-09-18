// Package app coordinates durable firewall revisions and their serialized writer.
package app

import (
	"slices"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
)

// Candidate is an immutable, completely compiled configuration awaiting the
// serialized writer. Its fields are deliberately private: callers can only
// construct one through NewCandidate, and all mutable configuration containers
// are owned by the candidate.
type Candidate struct {
	epoch    uint64
	refresh  uint64
	path     string
	cfg      config.Config
	model    policy.State
	snapshot source.Snapshot
}

// NewCandidate validates and compiles cfg without reading sources or touching
// the kernel. The candidate owns independent copies of cfg and its compiled
// model, so later caller mutations cannot alter the desired revision.
func NewCandidate(epoch uint64, path string, cfg config.Config, snapshot source.Snapshot) (Candidate, error) {
	owned := cloneConfig(cfg)
	if err := firewall.ValidateConfig(owned); err != nil {
		return Candidate{}, err
	}
	model, err := policy.Compile(owned, snapshot.Policy())
	if err != nil {
		return Candidate{}, err
	}
	return Candidate{epoch: epoch, path: path, cfg: owned, model: model, snapshot: snapshot}, nil
}

func cloneConfig(value config.Config) config.Config {
	value.Global.Allowlist = slices.Clone(value.Global.Allowlist)
	value.Global.Blocklist = slices.Clone(value.Global.Blocklist)
	value.Groups = cloneGroups(value.Groups)
	value.Policies = clonePolicies(value.Policies)
	value.Firewall.IPTables.Attachments = cloneAttachments(value.Firewall.IPTables.Attachments)
	return value
}

func cloneGroups(values map[string][]string) map[string][]string {
	if values == nil {
		return nil
	}
	result := make(map[string][]string, len(values))
	for key, entries := range values {
		result[key] = slices.Clone(entries)
	}
	return result
}

func clonePolicies(values []config.Policy) []config.Policy {
	if values == nil {
		return nil
	}
	result := make([]config.Policy, len(values))
	for index, value := range values {
		result[index] = value
		result[index].Traffic.TCP = slices.Clone(value.Traffic.TCP)
		result[index].Traffic.UDP = slices.Clone(value.Traffic.UDP)
		result[index].Include = cloneSelector(value.Include)
		result[index].Exclude = cloneSelector(value.Exclude)
	}
	return result
}

func cloneSelector(value config.Selector) config.Selector {
	value.Countries = slices.Clone(value.Countries)
	value.RIRs = slices.Clone(value.RIRs)
	value.Groups = slices.Clone(value.Groups)
	value.ASNs = slices.Clone(value.ASNs)
	value.ExpandedCountries = slices.Clone(value.ExpandedCountries)
	return value
}

func cloneAttachments(values []config.Attachment) []config.Attachment {
	if values == nil {
		return nil
	}
	result := make([]config.Attachment, len(values))
	for index, value := range values {
		result[index] = value
		result[index].InputInterfaces = slices.Clone(value.InputInterfaces)
		result[index].OutputInterfaces = slices.Clone(value.OutputInterfaces)
	}
	return result
}
