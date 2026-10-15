package control

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
)

const statusMaxBytes = 4 << 20

// StatusHTTPHandler serves bounded, read-only daemon snapshots. Degraded reports
// are successful HTTP exchanges; health and validity remain explicit in JSON.
func StatusHTTPHandler(handle StatusHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != StatusEndpoint {
			http.NotFound(w, r)
			return
		}
		if r.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "status requires GET /v1/status", http.StatusMethodNotAllowed)
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), Timeout)
		defer cancel()
		if handle == nil || ctx.Err() != nil {
			http.Error(w, "status unavailable", http.StatusServiceUnavailable)
			return
		}
		result := handle(ctx)
		if ctx.Err() != nil {
			http.Error(w, "status canceled", http.StatusServiceUnavailable)
			return
		}
		encoded, err := json.Marshal(result)
		if err != nil || len(encoded) > statusMaxBytes || validateStatus(result) != nil {
			http.Error(w, "invalid status report", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(encoded)
	}
}

// Status reads the daemon's acknowledged state through its private socket.
func Status(ctx context.Context) (StatusResult, error) {
	return StatusPath(ctx, SocketPath)
}

// StatusPath reads the same report at an isolated programmatic socket path.
// Transport/protocol errors are separate from valid degraded daemon reports.
func StatusPath(ctx context.Context, path string) (StatusResult, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	client, closeClient := UnixClient(path, Timeout)
	defer closeClient()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://perimeterd"+StatusEndpoint, nil)
	if err != nil {
		return StatusResult{}, fmt.Errorf("control status request: %w", err)
	}
	response, err := client.Do(req)
	if err != nil {
		return StatusResult{}, fmt.Errorf("control status unavailable: %w", err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusOK {
		return StatusResult{}, fmt.Errorf("control status: unexpected HTTP status %d", response.StatusCode)
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, statusMaxBytes+1))
	if err != nil {
		return StatusResult{}, fmt.Errorf("control status response: %w", err)
	}
	if len(data) > statusMaxBytes {
		return StatusResult{}, errors.New("control status response exceeds 4 MiB")
	}
	result, err := decodeStatus(data)
	if err != nil {
		return StatusResult{}, fmt.Errorf("control status protocol: %w", err)
	}
	return result, nil
}

func decodeStatus(data []byte) (StatusResult, error) {
	var result StatusResult
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&result); err != nil {
		return StatusResult{}, err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return StatusResult{}, errors.New("trailing JSON document")
	}
	if err := validateStatus(result); err != nil {
		return StatusResult{}, err
	}
	return result, nil
}

func validateStatus(result StatusResult) error {
	if result.SchemaVersion != StatusSchemaVersion {
		return errors.New("unsupported status schema version")
	}
	if result.ObservedAt.IsZero() || result.Daemon.Version == "" {
		return errors.New("incomplete status observation")
	}
	applied := result.Applied
	switch applied.State {
	case "empty", "unavailable":
		if applied.Details != nil || applied.Revision != "" || applied.ConfigEpoch != 0 || applied.Manifest != "" {
			return errors.New("unapplied status contains applied metadata")
		}
		if (applied.State == "unavailable") != (applied.Reason != "") {
			return errors.New("inconsistent unapplied status reason")
		}
		return nil
	case "applied":
		if applied.Revision == "" || applied.ConfigEpoch == 0 || applied.Details == nil || applied.Reason != "" {
			return errors.New("incomplete applied status")
		}
	default:
		return errors.New("invalid applied status state")
	}
	details := applied.Details
	if (details.Firewall.Backend != "nftables" && details.Firewall.Backend != "iptables") ||
		len(details.Firewall.Families) == 0 || (details.Firewall.DenyAction != "drop" && details.Firewall.DenyAction != "reject") ||
		details.Policies == nil || details.PrefixCounts == nil {
		return errors.New("incomplete applied policy summary")
	}
	if err := validateStatusCompiledSets(details.Firewall.Families, details.CompiledSets); err != nil {
		return err
	}
	crowdsec := applied.Details.CrowdSec
	switch crowdsec.Validity {
	case "disabled":
		if crowdsec.Enabled || crowdsec.Counts != nil || crowdsec.Epoch != 0 || crowdsec.Operation != 0 || !crowdsec.ValidUntil.IsZero() {
			return errors.New("inconsistent disabled CrowdSec status")
		}
	case "valid", "stale", "unknown":
		if !crowdsec.Enabled || (crowdsec.Validity == "valid") != (crowdsec.Counts != nil) {
			return errors.New("inconsistent CrowdSec validity/counts")
		}
		if crowdsec.Validity != "unknown" && (crowdsec.Epoch == 0 || crowdsec.Operation == 0) {
			return errors.New("CrowdSec validity omitted acknowledged operation")
		}
		if crowdsec.Validity == "unknown" && (crowdsec.Epoch != 0 || crowdsec.Operation != 0 || !crowdsec.ValidUntil.IsZero()) {
			return errors.New("unknown CrowdSec status contains acknowledged metadata")
		}
		if crowdsec.Validity == "valid" && !crowdsec.ValidUntil.IsZero() && !result.ObservedAt.Before(crowdsec.ValidUntil) {
			return errors.New("valid CrowdSec status has expired")
		}
	default:
		return errors.New("invalid CrowdSec validity")
	}
	return nil
}

func validateStatusCompiledSets(families []string, compiled StatusCompiledSets) error {
	if compiled.Sets == nil || compiled.Totals == nil {
		return errors.New("missing compiled firewall set collections")
	}
	sums := make(map[string]uint64, len(families))
	for _, family := range families {
		if family != "ipv4" && family != "ipv6" {
			return errors.New("invalid firewall family")
		}
		if _, exists := sums[family]; exists {
			return errors.New("duplicate firewall family")
		}
		sums[family] = 0
	}
	type identity struct {
		family string
		id     string
	}
	seen := make(map[identity]struct{}, len(compiled.Sets))
	for _, set := range compiled.Sets {
		sum, enabled := sums[set.Family]
		if !enabled || set.ID == "" {
			return errors.New("invalid compiled firewall set identity")
		}
		key := identity{family: set.Family, id: set.ID}
		if _, exists := seen[key]; exists {
			return errors.New("duplicate compiled firewall set")
		}
		seen[key] = struct{}{}
		if set.Count > math.MaxUint64-sum {
			return errors.New("compiled firewall set total overflows")
		}
		sums[set.Family] = sum + set.Count
	}
	totals := make(map[string]struct{}, len(compiled.Totals))
	for _, total := range compiled.Totals {
		sum, enabled := sums[total.Family]
		if !enabled || sum != total.Count {
			return errors.New("inconsistent compiled firewall set total")
		}
		if _, exists := totals[total.Family]; exists {
			return errors.New("duplicate compiled firewall family total")
		}
		totals[total.Family] = struct{}{}
	}
	if len(totals) != len(sums) {
		return errors.New("missing compiled firewall family total")
	}
	return nil
}
