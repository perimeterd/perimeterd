package control

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// ReloadEndpoint and the wait bounds define the synchronous reload protocol.
const (
	ReloadEndpoint      = "/v1/reload"
	ReloadClientTimeout = 75 * time.Second
	ReloadServerTimeout = 80 * time.Second
	reloadMaxBytes      = 4 << 10
)

type (
	// ReloadRequest optionally correlates admission with exact configuration bytes.
	ReloadRequest struct {
		ExpectConfigSHA256 string `json:"expect_config_sha256,omitempty"`
	}
	// ReloadResult describes this request's completion, not a later active revision.
	ReloadResult struct {
		SchemaVersion int    `json:"schema_version"`
		Outcome       string `json:"outcome"`
		Revision      string `json:"revision,omitempty"`
		ConfigSHA256  string `json:"config_sha256,omitempty"`
		Code          string `json:"code,omitempty"`
		Message       string `json:"message,omitempty"`
	}
)

// ReloadHandler submits a validated request to the daemon's serialized owner.
type ReloadHandler func(context.Context, ReloadRequest) ReloadResult

// Failure constructs a non-success response in the current protocol schema.
func Failure(outcome, code, message string) ReloadResult {
	return ReloadResult{SchemaVersion: 1, Outcome: outcome, Code: code, Message: message}
}

// NormalizeDigest validates a SHA-256 hexadecimal digest and lowercases it.
func NormalizeDigest(value string) (string, error) {
	if len(value) != 64 {
		return "", errors.New("config SHA-256 must contain 64 hexadecimal characters")
	}
	if _, err := hex.DecodeString(value); err != nil {
		return "", errors.New("config SHA-256 must contain 64 hexadecimal characters")
	}
	return strings.ToLower(value), nil
}

func strictJSON(data []byte, destination any) error {
	if len(bytes.TrimSpace(data)) == 0 || bytes.TrimSpace(data)[0] != '{' {
		return errors.New("expected JSON object")
	}
	scanner := json.NewDecoder(bytes.NewReader(data))
	_, _ = scanner.Token()
	seen := make(map[string]bool)
	allowed := map[string]bool{"expect_config_sha256": true}
	if _, ok := destination.(*ReloadResult); ok {
		allowed = map[string]bool{"schema_version": true, "outcome": true, "revision": true, "config_sha256": true, "code": true, "message": true}
	}
	for scanner.More() {
		token, err := scanner.Token()
		key, ok := token.(string)
		if err != nil || !ok || seen[key] || !allowed[key] {
			return errors.New("duplicate or unknown JSON field")
		}
		seen[key] = true
		var value json.RawMessage
		if err := scanner.Decode(&value); err != nil {
			return err
		}
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return errors.New("null JSON field")
		}
	}
	if _, err := scanner.Token(); err != nil {
		return err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return err
	}
	if err := decoder.Decode(new(any)); err != io.EOF {
		return errors.New("trailing JSON document")
	}
	return nil
}

func validateResult(result ReloadResult, expected string) error {
	if result.SchemaVersion != 1 {
		return errors.New("unsupported reload schema version")
	}
	if result.ConfigSHA256 != "" {
		digest, err := NormalizeDigest(result.ConfigSHA256)
		if err != nil || digest != result.ConfigSHA256 {
			return errors.New("invalid actual config SHA-256")
		}
	}
	switch result.Outcome {
	case "applied":
		if result.Revision == "" || result.ConfigSHA256 == "" || result.Code != "" || result.Message != "" {
			return errors.New("incomplete or inconsistent applied reload metadata")
		}
		if expected != "" && expected != result.ConfigSHA256 {
			return errors.New("applied reload config SHA-256 mismatch")
		}
	case "degraded":
		if result.Revision == "" {
			return errors.New("degraded reload omitted committed revision")
		}
		fallthrough
	case "rejected", "unknown":
		if result.Code == "" || result.Message == "" {
			return errors.New("reload failure omitted diagnostic")
		}
	default:
		return errors.New("invalid reload outcome")
	}
	return nil
}

// ReloadHTTPHandler validates bounded requests and independently limits waiters.
func ReloadHTTPHandler(handle ReloadHandler) http.HandlerFunc {
	active := make(chan struct{}, 2)
	return func(w http.ResponseWriter, r *http.Request) {
		send := func(result ReloadResult) {
			encoded, err := json.Marshal(result)
			if err != nil || len(encoded) > reloadMaxBytes {
				result = Failure("unknown", "invalid_result", "reload completion is unknown: response exceeds 4 KiB")
				encoded, _ = json.Marshal(result)
			}
			status := http.StatusServiceUnavailable
			if result.Outcome == "applied" {
				status = http.StatusOK
			}
			if result.Code == "invalid_request" {
				status = http.StatusBadRequest
			}
			if result.Code == "config_mismatch" || result.Code == "superseded" {
				status = http.StatusConflict
			}
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(status)
			_, _ = w.Write(encoded)
		}
		if r.Method != http.MethodPost || r.URL.Path != ReloadEndpoint {
			send(Failure("rejected", "invalid_request", "reload requires POST /v1/reload"))
			return
		}
		body, err := io.ReadAll(io.LimitReader(r.Body, reloadMaxBytes+1))
		var request ReloadRequest
		if err != nil || len(body) > reloadMaxBytes || strictJSON(body, &request) != nil {
			send(Failure("rejected", "invalid_request", "invalid reload request"))
			return
		}
		var fields map[string]json.RawMessage
		_ = json.Unmarshal(body, &fields)
		if _, present := fields["expect_config_sha256"]; present {
			request.ExpectConfigSHA256, err = NormalizeDigest(request.ExpectConfigSHA256)
			if err != nil {
				send(Failure("rejected", "invalid_request", err.Error()))
				return
			}
		}
		select {
		case active <- struct{}{}:
			defer func() { <-active }()
		default:
			send(Failure("rejected", "busy", "reload handler capacity exhausted"))
			return
		}
		ctx, cancel := context.WithTimeout(r.Context(), ReloadServerTimeout)
		defer cancel()
		result := handle(ctx, request)
		if err := validateResult(result, request.ExpectConfigSHA256); err != nil {
			result = Failure("unknown", "invalid_result", err.Error())
		}
		send(result)
	}
}

// Reload requests acknowledged application through the production private socket.
func Reload(ctx context.Context, request ReloadRequest) ReloadResult {
	return ReloadPath(ctx, SocketPath, request)
}

// ReloadPath supports the same operation at an isolated programmatic socket path.
func ReloadPath(ctx context.Context, path string, request ReloadRequest) ReloadResult {
	if ctx == nil {
		ctx = context.Background()
	}
	if request.ExpectConfigSHA256 != "" {
		normalized, err := NormalizeDigest(request.ExpectConfigSHA256)
		if err != nil {
			return Failure("rejected", "invalid_request", err.Error())
		}
		request.ExpectConfigSHA256 = normalized
	}
	ctx, cancel := context.WithTimeout(ctx, ReloadClientTimeout)
	defer cancel()
	client, closeClient := UnixClient(path, ReloadClientTimeout)
	defer closeClient()
	body, _ := json.Marshal(request)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, "http://perimeterd"+ReloadEndpoint, bytes.NewReader(body))
	if err != nil {
		return Failure("unknown", "unavailable", "cannot create reload request")
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		code := "unavailable"
		if ctx.Err() != nil {
			code = "timeout"
		}
		return Failure("unknown", code, "reload completion is unknown: "+err.Error())
	}
	defer func() { _ = response.Body.Close() }()
	encoded, err := io.ReadAll(io.LimitReader(response.Body, reloadMaxBytes+1))
	var result ReloadResult
	if err != nil || len(encoded) > reloadMaxBytes || strictJSON(encoded, &result) != nil {
		return Failure("unknown", "protocol", "reload completion is unknown: invalid daemon response")
	}
	if err := validateResult(result, request.ExpectConfigSHA256); err != nil {
		return Failure("unknown", "protocol", "reload completion is unknown: "+err.Error())
	}
	if (result.Outcome == "applied") != (response.StatusCode == http.StatusOK) || response.StatusCode >= 200 && response.StatusCode < 300 && result.Outcome != "applied" {
		return Failure("unknown", "protocol", fmt.Sprintf("reload completion is unknown: inconsistent HTTP %d", response.StatusCode))
	}
	return result
}
