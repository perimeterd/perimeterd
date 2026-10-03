package lookup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"net/netip"
	"reflect"
	"strings"
)

// HTTPHandler exposes lookup semantics on the shared private control listener.
func HTTPHandler(handle Handler) http.HandlerFunc {
	active := make(chan struct{}, MaxConcurrent)
	return func(writer http.ResponseWriter, request *http.Request) {
		writer.Header().Set("Content-Type", "application/json")
		writer.Header().Set("Connection", "close")
		if request.Method != http.MethodPost || request.URL.Path != Endpoint {
			writeResponse(writer, http.StatusNotFound, Unknown(Request{}, "invalid_endpoint", "lookup endpoint requires POST /v1/lookup"))
			return
		}
		if request.ContentLength > MaxRequestBytes {
			writeResponse(writer, http.StatusRequestEntityTooLarge, Unknown(Request{}, "request_too_large", "lookup request exceeds 4 KiB"))
			return
		}
		body, err := io.ReadAll(io.LimitReader(request.Body, MaxRequestBytes+1))
		if err != nil {
			writeResponse(writer, http.StatusBadRequest, Unknown(Request{}, "invalid_request", "cannot read lookup request"))
			return
		}
		if len(body) > MaxRequestBytes {
			writeResponse(writer, http.StatusRequestEntityTooLarge, Unknown(Request{}, "request_too_large", "lookup request exceeds 4 KiB"))
			return
		}
		var query Request
		if err := decodeRequest(body, &query); err != nil {
			writeResponse(writer, http.StatusBadRequest, Unknown(query, "invalid_request", err.Error()))
			return
		}
		normalized, err := Normalize(query)
		if err != nil {
			writeResponse(writer, http.StatusBadRequest, Unknown(query, "invalid_request", err.Error()))
			return
		}
		query = normalized
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			writeResponse(writer, http.StatusTooManyRequests, Unknown(query, "busy", "lookup evaluator is busy"))
			return
		}
		ctx, cancel := context.WithTimeout(request.Context(), Timeout)
		defer cancel()
		response := handle(ctx, query)
		if response.SchemaVersion != SchemaVersion || response.Flow != "new" || !reflect.DeepEqual(response.Query, query) {
			response = Unknown(query, "invalid_result", "lookup handler returned inconsistent response metadata")
		}
		if response.Verdict == "" {
			response = Unknown(query, "invalid_result", "lookup handler returned an empty verdict")
		}
		if err := isValidResponse(response); err != nil {
			code := "invalid_result"
			if strings.Contains(err.Error(), "record limit") {
				code = "limit"
			}
			response = Unknown(query, code, err.Error())
		}
		writeResponse(writer, statusForResponse(response), response)
	}
}

func statusForResponse(response Response) int {
	if response.Verdict == "unknown" {
		return http.StatusServiceUnavailable
	}
	return http.StatusOK
}

func writeResponse(writer http.ResponseWriter, status int, response Response) {
	encoded, err := encodeResponse(response)
	if err != nil {
		response = Unknown(response.Query, "response_too_large", "lookup response exceeds 4 MiB")
		encoded, _ = encodeResponse(response)
		status = http.StatusInternalServerError
	}
	writer.Header().Set("Content-Length", fmt.Sprint(len(encoded)))
	writer.WriteHeader(status)
	_, _ = writer.Write(encoded)
}

func encodeResponse(response Response) ([]byte, error) {
	encoded, err := json.Marshal(response)
	if err != nil {
		return nil, err
	}
	if len(encoded) > MaxResponseBytes {
		return nil, errors.New("response exceeds 4 MiB")
	}
	return encoded, nil
}

func decodeStrict(data []byte, destination any) error {
	if len(bytes.TrimSpace(data)) == 0 {
		return errors.New("request must be a JSON object")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	if err := scanJSON(decoder, 0); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON is not allowed")
		}
		return fmt.Errorf("trailing JSON: %w", err)
	}
	decoder = json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	return nil
}

func scanJSON(decoder *json.Decoder, depth int) error {
	if depth > 128 {
		return errors.New("JSON nesting exceeds limit")
	}
	token, err := decoder.Token()
	if err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	switch delimiter := token.(type) {
	case json.Delim:
		switch delimiter {
		case '{':
			keys := make(map[string]struct{})
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return fmt.Errorf("invalid JSON object: %w", err)
				}
				key, ok := keyToken.(string)
				if !ok {
					return errors.New("invalid JSON object key")
				}
				for _, character := range key {
					if character > 127 {
						return errors.New("JSON field names must be ASCII")
					}
				}
				key = strings.ToLower(key)
				if _, exists := keys[key]; exists {
					return fmt.Errorf("duplicate JSON field %q", key)
				}
				keys[key] = struct{}{}
				if err := scanJSON(decoder, depth+1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
		case '[':
			for decoder.More() {
				if err := scanJSON(decoder, depth+1); err != nil {
					return err
				}
			}
			_, err = decoder.Token()
		default:
			return errors.New("invalid JSON delimiter")
		}
		if err != nil {
			return fmt.Errorf("invalid JSON container: %w", err)
		}
	}
	return nil
}

func decodeRequest(data []byte, destination *Request) error {
	if err := decodeStrict(data, destination); err != nil {
		return err
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(data, &fields); err != nil {
		return fmt.Errorf("invalid JSON: %w", err)
	}
	for field := range fields {
		switch field {
		case "address", "direction", "protocol", "port":
		default:
			return fmt.Errorf("unknown JSON field %q", field)
		}
	}
	for _, field := range []string{"direction", "protocol"} {
		raw, ok := fields[field]
		if !ok {
			continue
		}
		var value string
		if err := json.Unmarshal(raw, &value); err != nil || value == "" {
			return fmt.Errorf("%s must be a non-empty string", field)
		}
	}
	if raw, ok := fields["port"]; ok && bytes.Equal(bytes.TrimSpace(raw), []byte("null")) {
		return errors.New("port must be an integer when present")
	}
	return nil
}

func isValidResponse(response Response) error {
	if response.SchemaVersion != SchemaVersion {
		return errors.New("unsupported lookup schema version")
	}
	if response.Flow != "new" {
		return errors.New("unsupported lookup flow")
	}
	switch response.Verdict {
	case "blocked", "not_blocked", "mixed":
		normalized, err := Normalize(response.Query)
		if err != nil || !reflect.DeepEqual(normalized, response.Query) {
			return errors.New("lookup response query is not normalized")
		}
	}
	switch response.Verdict {
	case "blocked", "not_blocked", "mixed":
		if response.Error != nil {
			return errors.New("complete lookup has an error")
		}
		if response.ObservedAt.IsZero() {
			return errors.New("complete lookup omitted observed_at")
		}
		if len(response.Outcomes) == 0 {
			return errors.New("complete lookup omitted outcomes")
		}
	case "unknown":
		if response.Error == nil || response.Error.Code == "" || response.Error.Message == "" {
			return errors.New("unknown lookup lacks an error")
		}
		if len(response.Outcomes) != 0 {
			return errors.New("unknown lookup contains partial outcomes")
		}
		return nil
	default:
		return errors.New("invalid lookup verdict")
	}
	if len(response.Outcomes) > MaxRecords {
		return errors.New("lookup response exceeds record limit")
	}
	blocked, notBlocked := 0, 0
	records := 0
	for _, outcome := range response.Outcomes {
		records += 1 + len(outcome.Evidence)
		if records > MaxRecords {
			return errors.New("lookup response exceeds record limit")
		}
		if !outcome.Prefix.IsValid() {
			return errors.New("lookup outcome has invalid prefix")
		}
		if outcome.Direction != "ingress" && outcome.Direction != "egress" {
			return errors.New("lookup outcome has invalid direction")
		}
		switch outcome.Protocol {
		case "tcp", "udp", "icmp", "other":
		default:
			return errors.New("lookup outcome has invalid protocol")
		}
		switch outcome.Verdict {
		case "blocked":
			if outcome.Action != "drop" && outcome.Action != "reject" {
				return errors.New("blocked outcome has invalid action")
			}
			blocked++
		case "not_blocked":
			if outcome.Action != "return" {
				return errors.New("not_blocked outcome has invalid action")
			}
			notBlocked++
		default:
			return errors.New("lookup outcome has invalid verdict")
		}
		if outcome.Reason == "" || outcome.Stage == "" {
			return errors.New("lookup outcome omitted reason or stage")
		}
		for _, evidence := range outcome.Evidence {
			if !evidence.Prefix.IsValid() || evidence.Kind == "" || evidence.Name == "" || evidence.Role == "" {
				return errors.New("lookup evidence is incomplete")
			}
		}
	}
	switch response.Verdict {
	case "blocked":
		if blocked == 0 || notBlocked != 0 {
			return errors.New("blocked verdict does not cover all outcomes")
		}
	case "not_blocked":
		if notBlocked == 0 || blocked != 0 {
			return errors.New("not_blocked verdict does not cover all outcomes")
		}
	case "mixed":
		if blocked == 0 || notBlocked == 0 {
			return errors.New("mixed verdict lacks both outcome classes")
		}
	}
	return validateCoverage(response)
}

// validateCoverage proves an exact address/port partition for every returned
// attachment and requested direction/protocol. Disjoint rectangle volumes let
// IPv6 /0 be checked without enumerating addresses or all 65,536 ports.
func validateCoverage(response Response) error {
	query, _ := netip.ParsePrefix(response.Query.Address)
	type scopeGroup struct {
		direction  string
		attachment Attachment
		outcomes   []Outcome
	}
	var groups []scopeGroup
	for _, outcome := range response.Outcomes {
		if outcome.Prefix != outcome.Prefix.Masked() || outcome.Prefix.Bits() < query.Bits() || !query.Contains(outcome.Prefix.Addr()) {
			return errors.New("lookup outcome extends outside the query")
		}
		if response.Query.Direction != "" && outcome.Direction != response.Query.Direction ||
			response.Query.Protocol != "" && outcome.Protocol != response.Query.Protocol {
			return errors.New("lookup outcome extends outside the traffic scope")
		}
		if outcome.Protocol == "tcp" || outcome.Protocol == "udp" {
			if outcome.Ports == nil || outcome.Ports.Start > outcome.Ports.End {
				return errors.New("lookup outcome has invalid ports")
			}
			if response.Query.Port != nil && (outcome.Ports.Start != *response.Query.Port || outcome.Ports.End != *response.Query.Port) {
				return errors.New("lookup outcome extends outside the port scope")
			}
		} else if outcome.Ports != nil {
			return errors.New("lookup outcome has ports on a portless protocol")
		}
		if outcome.Attachment.PortBasis != "current_destination" && outcome.Attachment.PortBasis != "original_destination" ||
			outcome.Attachment.Managed && outcome.Attachment.Name == "" {
			return errors.New("lookup outcome has incomplete attachment coverage")
		}
		index := 0
		for index < len(groups) {
			if groups[index].direction == string(outcome.Direction) && attachmentEqual(groups[index].attachment, outcome.Attachment) {
				break
			}
			index++
		}
		if index == len(groups) {
			groups = append(groups, scopeGroup{direction: string(outcome.Direction), attachment: outcome.Attachment})
		}
		for _, previous := range groups[index].outcomes {
			if previous.Protocol == outcome.Protocol && previous.Prefix.Overlaps(outcome.Prefix) &&
				(previous.Ports == nil || previous.Ports.Start <= outcome.Ports.End && outcome.Ports.Start <= previous.Ports.End) {
				return errors.New("lookup outcomes overlap")
			}
		}
		groups[index].outcomes = append(groups[index].outcomes, outcome)
	}
	directions := []string{"ingress", "egress"}
	if response.Query.Direction != "" {
		directions = []string{string(response.Query.Direction)}
	}
	for _, direction := range directions {
		found := false
		for _, group := range groups {
			found = found || group.direction == direction
		}
		if !found {
			return errors.New("lookup response omitted a requested direction")
		}
	}
	protocols := []string{"tcp", "udp", "icmp", "other"}
	if response.Query.Protocol != "" {
		protocols = []string{response.Query.Protocol}
	}
	for _, group := range groups {
		for _, protocol := range protocols {
			width := uint64(1)
			if response.Query.Port == nil && (protocol == "tcp" || protocol == "udp") {
				width = 65536
			}
			var expected, actual, volume big.Int
			expected.SetUint64(width)
			expected.Lsh(&expected, uint(query.Addr().BitLen()-query.Bits()))
			for _, outcome := range group.outcomes {
				if outcome.Protocol != protocol {
					continue
				}
				width = 1
				if outcome.Ports != nil {
					width = uint64(outcome.Ports.End) - uint64(outcome.Ports.Start) + 1
				}
				volume.SetUint64(width)
				volume.Lsh(&volume, uint(outcome.Prefix.Addr().BitLen()-outcome.Prefix.Bits()))
				actual.Add(&actual, &volume)
			}
			if actual.Cmp(&expected) != 0 {
				return errors.New("lookup response omitted requested address or traffic coverage")
			}
		}
	}
	return nil
}
