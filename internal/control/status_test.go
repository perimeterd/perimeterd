package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
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
		SchemaVersion: StatusSchemaVersion,
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
			CompiledSets: StatusCompiledSets{
				Sets:   []StatusCompiledSet{{Family: "ipv4", ID: "global_allowlist", Count: 12}},
				Totals: []StatusCompiledTotal{{Family: "ipv4", Count: 12}, {Family: "ipv6", Count: 0}},
			},
			CrowdSec: StatusCrowdSec{Validity: "disabled"},
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
			if !reflect.DeepEqual(got, want) {
				t.Fatalf("status report changed in transit: got=%#v want=%#v", got, want)
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
	for _, result := range []StatusResult{{}, {SchemaVersion: StatusSchemaVersion, ObservedAt: time.Now(), Daemon: StatusDaemon{Version: "test"}, Applied: StatusApplied{State: "unavailable", Reason: strings.Repeat("x", statusMaxBytes)}}} {
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
		{"schema", strings.Replace(valid, `"schema_version":2`, `"schema_version":1`, 1), 200},
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

func TestStatusCompiledSetValidation(t *testing.T) {
	cases := []struct {
		name   string
		change func(*StatusDetails)
		valid  bool
	}{
		{"both families", func(*StatusDetails) {}, true},
		{"zero static sets", func(d *StatusDetails) {
			d.CompiledSets = StatusCompiledSets{Sets: []StatusCompiledSet{}, Totals: []StatusCompiledTotal{{Family: "ipv4"}, {Family: "ipv6"}}}
		}, true},
		{"zero static row", func(d *StatusDetails) {
			d.CompiledSets.Sets = append(d.CompiledSets.Sets, StatusCompiledSet{Family: "ipv6", ID: "geo/ssh"})
		}, true},
		{"same ID different families", func(d *StatusDetails) {
			d.CompiledSets.Sets = append(d.CompiledSets.Sets, StatusCompiledSet{Family: "ipv6", ID: "global_allowlist"})
		}, true},
		{"single family", func(d *StatusDetails) {
			d.Firewall.Families = []string{"ipv4"}
			d.CompiledSets.Totals = d.CompiledSets.Totals[:1]
		}, true},
		{"maximum count", func(d *StatusDetails) {
			d.CompiledSets.Sets[0].Count = math.MaxUint64
			d.CompiledSets.Totals[0].Count = math.MaxUint64
		}, true},
		{"missing sets", func(d *StatusDetails) { d.CompiledSets.Sets = nil }, false},
		{"missing totals", func(d *StatusDetails) { d.CompiledSets.Totals = nil }, false},
		{"invalid enabled family", func(d *StatusDetails) { d.Firewall.Families[0] = "ipv5" }, false},
		{"duplicate enabled family", func(d *StatusDetails) { d.Firewall.Families[1] = "ipv4" }, false},
		{"empty ID", func(d *StatusDetails) { d.CompiledSets.Sets[0].ID = "" }, false},
		{"disabled row family", func(d *StatusDetails) { d.Firewall.Families = []string{"ipv6"} }, false},
		{"invalid row family", func(d *StatusDetails) { d.CompiledSets.Sets[0].Family = "ipv5" }, false},
		{"duplicate row", func(d *StatusDetails) {
			d.CompiledSets.Sets = append(d.CompiledSets.Sets, d.CompiledSets.Sets[0])
			d.CompiledSets.Totals[0].Count *= 2
		}, false},
		{"missing family total", func(d *StatusDetails) { d.CompiledSets.Totals = d.CompiledSets.Totals[:1] }, false},
		{"empty totals", func(d *StatusDetails) { d.CompiledSets.Totals = []StatusCompiledTotal{} }, false},
		{"extra family total", func(d *StatusDetails) {
			d.CompiledSets.Totals = append(d.CompiledSets.Totals, StatusCompiledTotal{Family: "ipv5"})
		}, false},
		{"disabled family total", func(d *StatusDetails) { d.Firewall.Families = []string{"ipv4"} }, false},
		{"duplicate total", func(d *StatusDetails) {
			d.CompiledSets.Totals = append(d.CompiledSets.Totals, d.CompiledSets.Totals[0])
		}, false},
		{"mismatched total", func(d *StatusDetails) { d.CompiledSets.Totals[0].Count++ }, false},
		{"overflow", func(d *StatusDetails) {
			d.CompiledSets.Sets[0].Count = math.MaxUint64
			d.CompiledSets.Sets = append(d.CompiledSets.Sets, StatusCompiledSet{Family: "ipv4", ID: "geo/ingress", Count: 1})
			d.CompiledSets.Totals[0].Count = 0
		}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			report := statusReport("applied")
			tc.change(report.Applied.Details)
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			got, err := decodeStatus(encoded)
			if tc.valid {
				if err != nil || !reflect.DeepEqual(got, report) {
					t.Fatalf("valid compiled summary did not round trip: got=%#v err=%v", got, err)
				}
			} else if err == nil {
				t.Fatalf("invalid compiled summary accepted: %#v", got)
			}
			response := httptest.NewRecorder()
			StatusHTTPHandler(func(context.Context) StatusResult { return report })(response, httptest.NewRequest(http.MethodGet, StatusEndpoint, nil))
			wantCode := http.StatusInternalServerError
			if tc.valid {
				wantCode = http.StatusOK
			}
			if response.Code != wantCode {
				t.Fatalf("handler status=%d want=%d", response.Code, wantCode)
			}
		})
	}
}

func TestStatusRejectsMissingCompiledStructures(t *testing.T) {
	report := statusReport("applied")
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	summary, err := json.Marshal(report.Applied.Details.CompiledSets)
	if err != nil {
		t.Fatal(err)
	}
	original := `"compiled_sets":` + string(summary) + ","
	for _, compiled := range []string{"", `"compiled_sets":null,`, `"compiled_sets":{},`, `"compiled_sets":{"sets":[]},`, `"compiled_sets":{"totals":[]},`, `"compiled_sets":{"sets":null,"totals":[]},`, `"compiled_sets":{"sets":[],"totals":null},`} {
		t.Run(compiled, func(t *testing.T) {
			body := strings.Replace(string(encoded), original, compiled, 1)
			if body == string(encoded) {
				t.Fatal("fixture replacement did not change compiled structure")
			}
			if _, err := decodeStatus([]byte(body)); err == nil {
				t.Fatalf("missing compiled structure accepted: %s", body)
			}
		})
	}
}

func TestStatusRejectsOldSchemaForEveryState(t *testing.T) {
	for _, state := range []string{"applied", "empty", "unavailable"} {
		t.Run(state, func(t *testing.T) {
			report := statusReport(state)
			report.SchemaVersion = 1
			encoded, err := json.Marshal(report)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := decodeStatus(encoded); err == nil || !strings.Contains(err.Error(), "unsupported status schema version") {
				t.Fatalf("old schema did not fail explicitly: %v", err)
			}
		})
	}
}

func TestStatusRejectsMalformedCompiledCounts(t *testing.T) {
	report := statusReport("applied")
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range []string{"-1", "18446744073709551616", "1.5", `"12"`} {
		t.Run(count, func(t *testing.T) {
			for _, field := range []string{`"id":"global_allowlist","count":12`, `"totals":[{"family":"ipv4","count":12`} {
				replacement := strings.Replace(field, `"count":12`, `"count":`+count, 1)
				body := strings.Replace(string(encoded), field, replacement, 1)
				if body == string(encoded) {
					t.Fatal("fixture replacement did not change compiled count")
				}
				if _, err := decodeStatus([]byte(body)); err == nil {
					t.Fatalf("malformed compiled count accepted: %s", body)
				}
			}
		})
	}
}
