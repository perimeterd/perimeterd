package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func statusReport(state string) StatusResult {
	result := StatusResult{
		SchemaVersion: 1,
		ObservedAt:    time.Date(2026, time.October, 13, 12, 0, 0, 0, time.UTC),
		Daemon:        StatusDaemon{Version: "test", Healthy: true},
		Applied:       StatusApplied{State: state},
	}
	switch state {
	case "unavailable":
		result.Daemon.Healthy = false
		result.Applied.Reason = "acknowledged state unavailable"
	case "applied":
		result.Applied.Revision = "revision"
		result.Applied.ConfigEpoch = 1
		result.Applied.Details = &StatusDetails{
			Firewall:     StatusFirewall{Backend: "iptables", Families: []string{"ipv4", "ipv6"}, DenyAction: "reject", Attachments: []StatusAttachment{{Chain: "FORWARD", Direction: "egress", OutputInterfaces: []string{"eth0"}, OriginalDestination: true}}},
			Policies:     []StatusPolicy{{Name: "web", Priority: -10, Direction: "ingress", Mode: "allowlist", Traffic: StatusTraffic{TCP: []StatusPortRange{{Start: 80, End: 443}}, ICMP: true}}},
			PrefixCounts: []StatusPrefixCount{{Family: "ipv4", Source: "global", Type: "allowlist", Count: 12}},
			CrowdSec:     StatusCrowdSec{Validity: "disabled"},
		}
	}
	return result
}

func statusServer(t *testing.T, handler http.Handler) string {
	t.Helper()
	path := filepath.Join(t.TempDir(), SocketName)
	server, err := Listen(path, http.NotFoundHandler(), http.NotFoundHandler(), handler)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = server.Close(context.Background()) })
	return path
}

func TestStatusUnixReportStates(t *testing.T) {
	for _, state := range []string{"applied", "empty", "unavailable"} {
		t.Run(state, func(t *testing.T) {
			want := statusReport(state)
			path := statusServer(t, StatusHTTPHandler(func(context.Context) StatusResult { return want }))
			got, err := StatusPath(context.Background(), path)
			if err != nil {
				t.Fatalf("status exchange failed: %v", err)
			}
			if got.Successful() != (state != "unavailable") {
				t.Fatalf("unexpected success: %#v", got)
			}
		})
	}
	for _, validity := range []string{"disabled", "valid", "stale", "unknown"} {
		t.Run(validity, func(t *testing.T) {
			want := statusReport("applied")
			cs := &want.Applied.Details.CrowdSec
			cs.Validity = validity
			cs.Enabled = validity != "disabled"
			if validity == "valid" || validity == "stale" {
				cs.Epoch, cs.Operation = 1, 2
			}
			if validity == "valid" {
				// Acknowledged empty writes have zero validity deadline.
				cs.Counts = &StatusDecisionCounts{}
			}
			path := statusServer(t, StatusHTTPHandler(func(context.Context) StatusResult { return want }))
			got, err := StatusPath(context.Background(), path)
			if err != nil {
				t.Fatalf("status exchange failed: %v", err)
			}
			if got.Successful() != (validity == "disabled" || validity == "valid") {
				t.Fatalf("unexpected success: %#v", got)
			}
		})
	}
	want := statusReport("applied")
	want.Daemon.Healthy = false
	got, err := StatusPath(context.Background(), statusServer(t, StatusHTTPHandler(func(context.Context) StatusResult { return want })))
	if err != nil || got.Successful() {
		t.Fatalf("degraded report = %#v, %v", got, err)
	}
}

func TestStatusHandlerRejectsInvalidRequestsAndReports(t *testing.T) {
	var calls atomic.Int32
	handler := StatusHTTPHandler(func(context.Context) StatusResult { calls.Add(1); return statusReport("empty") })
	for _, tc := range []struct {
		method, path string
		code         int
	}{
		{http.MethodPost, StatusEndpoint, http.StatusMethodNotAllowed},
		{http.MethodGet, "/wrong", http.StatusNotFound},
	} {
		response := httptest.NewRecorder()
		handler(response, httptest.NewRequest(tc.method, tc.path, nil))
		if response.Code != tc.code || calls.Load() != 0 {
			t.Fatalf("invalid request: code=%d calls=%d", response.Code, calls.Load())
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	response := httptest.NewRecorder()
	handler(response, httptest.NewRequest(http.MethodGet, StatusEndpoint, nil).WithContext(ctx))
	if response.Code != http.StatusServiceUnavailable || calls.Load() != 0 {
		t.Fatalf("canceled request: code=%d calls=%d", response.Code, calls.Load())
	}
	for _, result := range []StatusResult{{}, {SchemaVersion: 1, ObservedAt: time.Now(), Daemon: StatusDaemon{Version: "test"}, Applied: StatusApplied{State: "unavailable", Reason: strings.Repeat("x", statusMaxBytes)}}} {
		response := httptest.NewRecorder()
		StatusHTTPHandler(func(context.Context) StatusResult { return result })(response, httptest.NewRequest(http.MethodGet, StatusEndpoint, nil))
		if response.Code != http.StatusInternalServerError {
			t.Fatalf("invalid report status = %d", response.Code)
		}
	}
}

func TestStatusRejectsProtocolFailures(t *testing.T) {
	encoded, err := json.Marshal(statusReport("empty"))
	if err != nil {
		t.Fatal(err)
	}
	valid := string(encoded)
	appliedBytes, err := json.Marshal(statusReport("applied"))
	if err != nil {
		t.Fatal(err)
	}
	appliedJSON := string(appliedBytes)
	cases := []struct {
		name, body string
		code       int
	}{
		{"null", "null", 200},
		{"empty", "{}", 200},
		{"malformed", "{", 200},
		{"schema", strings.Replace(valid, `"schema_version":1`, `"schema_version":2`, 1), 200},
		{"unknown", strings.Replace(valid, `"state":"empty"`, `"state":"empty","extra":true`, 1), 200},
		{"trailing", valid + " {}", 200},
		{"state", strings.Replace(valid, `"state":"empty"`, `"state":"invented"`, 1), 200},
		{"invalid_health", strings.Replace(valid, `"healthy":true`, `"healthy":"true"`, 1), 200},
		{"missing_version", strings.Replace(valid, `"version":"test"`, `"version":""`, 1), 200},
		{"missing_observation", strings.Replace(valid, `"observed_at":"2026-10-13T12:00:00Z"`, `"observed_at":null`, 1), 200},
		{"incomplete_applied", strings.Replace(valid, `"state":"empty"`, `"state":"applied"`, 1), 200},
		{"missing_reason", strings.Replace(valid, `"state":"empty"`, `"state":"unavailable"`, 1), 200},
		{"invalid_validity", strings.Replace(appliedJSON, `"validity":"disabled"`, `"validity":"invented"`, 1), 200},
		{"missing_firewall", strings.Replace(appliedJSON, `"backend":"iptables"`, `"backend":""`, 1), 200},
		{"counts_without_validity", strings.Replace(appliedJSON, `"validity":"disabled"`, `"validity":"disabled","counts":{"ipv4":0,"ipv6":0}`, 1), 200},
		{"valid_without_counts", strings.Replace(appliedJSON, `"enabled":false,"validity":"disabled"`, `"enabled":true,"validity":"valid","epoch":1,"operation":1`, 1), 200},
		{"missing_operation", strings.Replace(appliedJSON, `"enabled":false,"validity":"disabled"`, `"enabled":true,"validity":"valid","counts":{}`, 1), 200},
		{"oversize", strings.Repeat(" ", statusMaxBytes+1), 200},
		{"http_error", valid, 503},
		{"redirect", valid, 302},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			path := statusServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Location", "http://perimeterd"+StatusEndpoint)
				w.WriteHeader(tc.code)
				_, _ = io.WriteString(w, tc.body)
			}))
			result, err := StatusPath(context.Background(), path)
			if err == nil || !reflect.DeepEqual(result, StatusResult{}) {
				t.Fatalf("invalid response accepted: %#v, %v", result, err)
			}
		})
	}
}

func TestStatusCancellationAndUnavailable(t *testing.T) {
	if _, err := StatusPath(context.Background(), filepath.Join(t.TempDir(), "missing.sock")); err == nil {
		t.Fatal("unreachable socket succeeded")
	}
	entered := make(chan struct{})
	finished := make(chan struct{})
	path := statusServer(t, StatusHTTPHandler(func(ctx context.Context) StatusResult {
		close(entered)
		<-ctx.Done()
		close(finished)
		return statusReport("empty")
	}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	result := make(chan error, 1)
	go func() { _, err := StatusPath(ctx, path); result <- err }()
	<-entered
	cancel()
	if err := <-result; !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation = %v", err)
	}
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("daemon status handler did not observe cancellation")
	}
	ctx, cancelDeadline := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancelDeadline()
	path = statusServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-r.Context().Done() }))
	if _, err := StatusPath(ctx, path); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline = %v", err)
	}
}

func TestListenRequiresAllHandlers(t *testing.T) {
	handler := http.NotFoundHandler()
	for _, handlers := range [][3]http.Handler{{nil, handler, handler}, {handler, nil, handler}, {handler, handler, nil}} {
		if server, err := Listen(filepath.Join(t.TempDir(), SocketName), handlers[0], handlers[1], handlers[2]); err == nil || server != nil {
			t.Fatalf("nil handler accepted: server=%v err=%v", server, err)
		}
	}
}
