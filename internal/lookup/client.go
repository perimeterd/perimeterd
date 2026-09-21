package lookup

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"reflect"
)

// Call queries the running daemon over the fixed root-only Unix socket. It
// never falls back to a network or configuration-file evaluation.
func Call(ctx context.Context, request Request) Response {
	return callPath(ctx, SocketPath, request)
}

func callPath(ctx context.Context, path string, request Request) Response {
	if ctx == nil {
		ctx = context.Background()
	}
	normalized, err := Normalize(request)
	if err != nil {
		return Unknown(request, "invalid_request", err.Error())
	}
	request = normalized
	callCtx, cancel := context.WithTimeout(ctx, Timeout)
	defer cancel()
	body, err := json.Marshal(request)
	if err != nil || len(body) > MaxRequestBytes {
		return Unknown(request, "request_too_large", "lookup request exceeds 4 KiB")
	}
	transport := &http.Transport{
		DisableKeepAlives: true,
		DialContext: func(dialCtx context.Context, _, _ string) (net.Conn, error) {
			dialer := &net.Dialer{Timeout: Timeout}
			return dialer.DialContext(dialCtx, "unix", path)
		},
	}
	client := &http.Client{Transport: transport}
	defer transport.CloseIdleConnections()
	req, err := http.NewRequestWithContext(callCtx, http.MethodPost, "http://perimeterd"+Endpoint, bytes.NewReader(body))
	if err != nil {
		return Unknown(request, "runtime", "create lookup request: "+err.Error())
	}
	req.Header.Set("Content-Type", "application/json")
	response, err := client.Do(req)
	if err != nil {
		code := "unavailable"
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			code = "deadline"
		} else if errors.Is(callCtx.Err(), context.Canceled) {
			code = "canceled"
		}
		return Unknown(request, code, "lookup daemon unavailable: "+err.Error())
	}
	defer func() { _ = response.Body.Close() }()
	if response.ContentLength > MaxResponseBytes {
		return Unknown(request, "response_too_large", "lookup response exceeds 4 MiB")
	}
	encoded, err := io.ReadAll(io.LimitReader(response.Body, MaxResponseBytes+1))
	if err != nil {
		code := "runtime"
		if errors.Is(callCtx.Err(), context.DeadlineExceeded) {
			code = "deadline"
		} else if errors.Is(callCtx.Err(), context.Canceled) {
			code = "canceled"
		}
		return Unknown(request, code, "read lookup response: "+err.Error())
	}
	if len(encoded) > MaxResponseBytes {
		return Unknown(request, "response_too_large", "lookup response exceeds 4 MiB")
	}
	var result Response
	if err := decodeStrict(encoded, &result); err != nil {
		return Unknown(request, "protocol", "invalid lookup response: "+err.Error())
	}
	if err := isValidResponse(result); err != nil {
		return Unknown(request, "protocol", err.Error())
	}
	if result.Query.Address == "" {
		return Unknown(request, "protocol", "lookup response omitted query")
	}
	if !reflect.DeepEqual(result.Query, request) {
		return Unknown(request, "protocol", "lookup response query mismatch")
	}
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		if result.Verdict != "unknown" {
			return Unknown(request, "protocol", fmt.Sprintf("lookup daemon returned HTTP %d", response.StatusCode))
		}
	}
	return result
}
