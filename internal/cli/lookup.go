package cli

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/perimeterd/perimeterd/internal/lookup"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func runLookup(args []string, stdout, stderr io.Writer) int {
	request, jsonOutput, help, err := parseLookupArgs(args)
	if err != nil {
		if jsonOutput || lookupJSONRequested(args) {
			result := lookup.Unknown(request, "invalid_request", err.Error())
			if encodeErr := json.NewEncoder(stdout).Encode(result); encodeErr != nil {
				_, _ = fmt.Fprintf(stderr, "perimeterd: write lookup output: %s\n", encodeErr)
				return 1
			}
			return 2
		}
		return usageError(stderr, err.Error())
	}
	if help {
		if err := writeLookupUsage(stdout); err != nil {
			return commandError(stderr, fmt.Errorf("write lookup help output: %w", err))
		}
		return 0
	}
	result := lookup.Call(context.Background(), request)
	if jsonOutput {
		if err := json.NewEncoder(stdout).Encode(result); err != nil {
			_, _ = fmt.Fprintf(stderr, "perimeterd: write lookup output: %s\n", err)
			return 1
		}
	} else if err := writeLookupHuman(stdout, result); err != nil {
		_, _ = fmt.Fprintf(stderr, "perimeterd: write lookup output: %s\n", err)
		return 1
	}
	if result.Verdict == "unknown" {
		return 1
	}
	return 0
}

func lookupJSONRequested(args []string) bool {
	for _, arg := range args {
		if arg == "--json" {
			return true
		}
	}
	return false
}

func parseLookupArgs(args []string) (lookup.Request, bool, bool, error) {
	var request lookup.Request
	var input string
	var jsonOutput bool
	var help bool
	var directionSet, protocolSet, portSet bool
	for len(args) > 0 {
		arg := args[0]
		args = args[1:]
		if arg == "--help" || arg == "-h" {
			help = true
			continue
		}
		if arg == "--json" {
			jsonOutput = true
			continue
		}
		name, value, hasValue := strings.Cut(arg, "=")
		if !hasValue && (name == "--direction" || name == "--protocol" || name == "--port") {
			if len(args) == 0 {
				return request, false, help, fmt.Errorf("lookup: %s requires a value", name)
			}
			value = args[0]
			args = args[1:]
		}
		switch name {
		case "--direction":
			if value == "" {
				return request, false, help, errors.New("lookup: --direction requires a non-empty value")
			}
			if directionSet {
				return request, false, help, errors.New("lookup: --direction specified more than once")
			}
			directionSet = true
			request.Direction = policy.Direction(value)
		case "--protocol":
			if value == "" {
				return request, false, help, errors.New("lookup: --protocol requires a non-empty value")
			}
			if protocolSet {
				return request, false, help, errors.New("lookup: --protocol specified more than once")
			}
			protocolSet = true
			request.Protocol = value
		case "--port":
			if portSet {
				return request, false, help, errors.New("lookup: --port specified more than once")
			}
			port, err := strconv.ParseUint(value, 10, 16)
			if err != nil {
				return request, false, help, errors.New("lookup: --port must be an integer from 0 to 65535")
			}
			request.Port = new(uint16(port))
			portSet = true
		default:
			if strings.HasPrefix(arg, "-") {
				return request, false, help, fmt.Errorf("lookup: unknown option %q", arg)
			}
			if input != "" {
				return request, false, help, errors.New("lookup: exactly one IP address or CIDR is required")
			}
			input = arg
		}
	}
	if help {
		return request, jsonOutput, true, nil
	}
	if input == "" {
		return request, jsonOutput, false, errors.New("lookup: exactly one IP address or CIDR is required")
	}
	request.Address = input
	normalized, err := lookup.Normalize(request)
	if err != nil {
		return request, jsonOutput, false, fmt.Errorf("lookup: %w", err)
	}
	return normalized, jsonOutput, false, nil
}

func writeLookupUsage(w io.Writer) error {
	_, err := io.WriteString(w, "Usage: perimeterd lookup IP_OR_CIDR [--direction ingress|egress] [--protocol tcp|udp|icmp|other] [--port 0..65535] [--json]\n")
	return err
}

func writeLookupHuman(w io.Writer, response lookup.Response) error {
	query := response.Query.Address
	if response.Query.Direction != "" {
		query += " direction=" + string(response.Query.Direction)
	} else {
		query += " direction=ingress,egress"
	}
	if response.Query.Protocol != "" {
		query += " protocol=" + response.Query.Protocol
	} else {
		query += " protocol=all"
	}
	if response.Query.Port != nil {
		query += fmt.Sprintf(" port=%d", *response.Query.Port)
	} else {
		query += " port=all"
	}
	if _, err := fmt.Fprintf(w, "Query: %s\n", query); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "Flow: %s\nVerdict: %s\n", response.Flow, response.Verdict); err != nil {
		return err
	}
	if !response.ObservedAt.IsZero() {
		if _, err := fmt.Fprintf(w, "Observed at: %s\n", response.ObservedAt.UTC().Format(time.RFC3339Nano)); err != nil {
			return err
		}
	}
	if response.Revision != "" {
		if _, err := fmt.Fprintf(w, "Revision: %s\n", response.Revision); err != nil {
			return err
		}
	}
	if response.ConfigEpoch != 0 {
		if _, err := fmt.Fprintf(w, "Config epoch: %d\n", response.ConfigEpoch); err != nil {
			return err
		}
	}
	if response.Manifest != "" {
		if _, err := fmt.Fprintf(w, "Manifest: %s\n", response.Manifest); err != nil {
			return err
		}
	}
	if response.DynamicEpoch != 0 || response.DynamicOperation != 0 {
		if _, err := fmt.Fprintf(w, "Dynamic epoch: %d\nDynamic operation: %d\n", response.DynamicEpoch, response.DynamicOperation); err != nil {
			return err
		}
	}
	if response.Error != nil {
		if _, err := fmt.Fprintf(w, "Error: %s: %s\n", response.Error.Code, response.Error.Message); err != nil {
			return err
		}
	}
	for index, outcome := range response.Outcomes {
		if _, err := fmt.Fprintf(w, "Outcome %d:\n  Prefix: %s\n  Direction: %s\n  Protocol: %s\n  Verdict: %s\n  Action: %s\n  Stage: %s\n  Reason: %s\n  Attachment: %s (managed=%t, port basis=%s)\n", index+1, outcome.Prefix, outcome.Direction, outcome.Protocol, outcome.Verdict, outcome.Action, outcome.Stage, outcome.Reason, outcome.Attachment.Name, outcome.Attachment.Managed, outcome.Attachment.PortBasis); err != nil {
			return err
		}
		if outcome.Ports != nil {
			if _, err := fmt.Fprintf(w, "  Ports: %d-%d\n", outcome.Ports.Start, outcome.Ports.End); err != nil {
				return err
			}
		}
		if outcome.Policy != "" {
			if _, err := fmt.Fprintf(w, "  Policy: %s (priority=%d)\n", outcome.Policy, outcome.Priority); err != nil {
				return err
			}
		}
		if len(outcome.Attachment.InputInterfaces) != 0 {
			if _, err := fmt.Fprintf(w, "  Input interfaces: %s\n", strings.Join(outcome.Attachment.InputInterfaces, ", ")); err != nil {
				return err
			}
		}
		if len(outcome.Attachment.OutputInterfaces) != 0 {
			if _, err := fmt.Fprintf(w, "  Output interfaces: %s\n", strings.Join(outcome.Attachment.OutputInterfaces, ", ")); err != nil {
				return err
			}
		}
		for _, evidence := range outcome.Evidence {
			if _, err := fmt.Fprintf(w, "  Evidence: %s %s role=%s contributing=%t prefix=%s", evidence.Kind, evidence.Name, evidence.Role, evidence.Contributing, evidence.Prefix); err != nil {
				return err
			}
			if evidence.Policy != "" {
				if _, err := fmt.Fprintf(w, " policy=%s", evidence.Policy); err != nil {
					return err
				}
			}
			if len(evidence.Via) != 0 {
				if _, err := fmt.Fprintf(w, " via=%s", strings.Join(evidence.Via, ",")); err != nil {
					return err
				}
			}
			if !evidence.RetrievedAt.IsZero() {
				if _, err := fmt.Fprintf(w, " retrieved_at=%s", evidence.RetrievedAt.UTC().Format(time.RFC3339Nano)); err != nil {
					return err
				}
			}
			if evidence.DecisionID != 0 {
				if _, err := fmt.Fprintf(w, " decision_id=%d", evidence.DecisionID); err != nil {
					return err
				}
			}
			if !evidence.DecisionDeadline.IsZero() {
				if _, err := fmt.Fprintf(w, " decision_deadline=%s", evidence.DecisionDeadline.UTC().Format(time.RFC3339Nano)); err != nil {
					return err
				}
			}
			if !evidence.LeaseDeadline.IsZero() {
				if _, err := fmt.Fprintf(w, " lease_deadline=%s", evidence.LeaseDeadline.UTC().Format(time.RFC3339Nano)); err != nil {
					return err
				}
			}
			if _, err := io.WriteString(w, "\n"); err != nil {
				return err
			}
		}
	}
	return nil
}
