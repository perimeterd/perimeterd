package lookup

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestListenRejectsSymlinkSocketWithoutDeletingTarget(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "lookup.sock")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if _, err := Listen(path, func(context.Context, Request) Response { return Unknown(Request{}, "x", "x") }); err == nil {
		t.Fatal("Listen accepted symlink socket path")
	}
	if _, err := os.Stat(target); err != nil {
		t.Fatalf("stale socket check deleted symlink target: %v", err)
	}
}

func TestListenHardensRuntimeDirectoryAndSocket(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "runtime")
	server, err := Listen(filepath.Join(dir, "lookup.sock"), func(_ context.Context, request Request) Response {
		return Response{SchemaVersion: SchemaVersion, Query: request, Flow: "new", Verdict: "not_blocked"}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(context.Background()) }()
	dirInfo, err := os.Stat(dir)
	if err != nil {
		t.Fatal(err)
	}
	if dirInfo.Mode().Perm() != 0o700 {
		t.Fatalf("runtime directory mode = %o, want 700", dirInfo.Mode().Perm())
	}
	socketInfo, err := os.Stat(filepath.Join(dir, "lookup.sock"))
	if err != nil {
		t.Fatal(err)
	}
	if socketInfo.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode = %o, want 600", socketInfo.Mode().Perm())
	}
}

func TestLookupTransportRoundTrip(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lookup.sock")
	server, err := Listen(path, func(_ context.Context, request Request) Response {
		return Response{
			SchemaVersion: SchemaVersion,
			Query:         request,
			Flow:          "new",
			ObservedAt:    time.Now().UTC(),
			Verdict:       "not_blocked",
			Outcomes: []Outcome{{
				Prefix:     netip.MustParsePrefix(request.Address),
				Direction:  "ingress",
				Protocol:   "tcp",
				Ports:      &Ports{Start: 80, End: 80},
				Attachment: Attachment{Name: "test", Managed: true, PortBasis: "current_destination"},
				Verdict:    "not_blocked",
				Action:     "return",
				Stage:      "policy",
				Reason:     "no matching denial",
			}},
		}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(context.Background()) }()
	result := callPath(context.Background(), path, Request{Address: "1.1.1.1", Direction: "ingress", Protocol: "tcp", Port: new(uint16(80))})
	if result.Verdict != "not_blocked" || len(result.Outcomes) != 1 || result.Query.Address != "1.1.1.1/32" {
		t.Fatalf("round-trip result = %#v", result)
	}
}

func TestLookupTransportClosePreservesReplacementPath(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lookup.sock")
	server, err := Listen(path, func(_ context.Context, request Request) Response {
		return Response{SchemaVersion: SchemaVersion, Query: request, Flow: "new", Verdict: "not_blocked"}
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("replacement"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := server.Close(context.Background()); err == nil {
		t.Fatal("Close succeeded after socket path replacement")
	}
	data, err := fs.ReadFile(os.DirFS(dir), "lookup.sock")
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "replacement" {
		t.Fatalf("replacement path contents = %q", data)
	}
}

func TestLookupTransportRejectsDuplicateUnknownAndTrailingJSON(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lookup.sock")
	server, err := Listen(path, func(_ context.Context, request Request) Response {
		return Response{SchemaVersion: SchemaVersion, Query: request, Flow: "new", Verdict: "not_blocked"}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(context.Background()) }()
	client := unixClient(path)
	for _, body := range []string{
		`{"address":"1.1.1.1","address":"1.1.1.1"}`,
		`{"address":"1.1.1.1","unknown":true}`,
		`{"address":"1.1.1.1"}{}`,
		`{"address":"1.1.1.1","direction":""}`,
		`{"Address":"1.1.1.1"}`,
		`{"address":"1.1.1.1","ADDRESS":"1.1.1.1"}`,
	} {
		response, err := client.Post("http://perimeterd"+Endpoint, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		encoded, readErr := io.ReadAll(response.Body)
		_ = response.Body.Close()
		if readErr != nil {
			t.Fatal(readErr)
		}
		if response.StatusCode != http.StatusBadRequest {
			t.Fatalf("body %s status = %d, want 400", body, response.StatusCode)
		}
		var result Response
		if err := json.Unmarshal(encoded, &result); err != nil {
			t.Fatal(err)
		}
		if result.Verdict != "unknown" || result.Error == nil {
			t.Fatalf("body %s response = %#v, want unknown error", body, result)
		}
	}
}

func TestLookupTransportRequestLimit(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lookup.sock")
	server, err := Listen(path, func(_ context.Context, request Request) Response {
		return Response{SchemaVersion: SchemaVersion, Query: request, Flow: "new", Verdict: "not_blocked"}
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(context.Background()) }()
	response, err := unixClient(path).Post("http://perimeterd"+Endpoint, "application/json", strings.NewReader(`{"address":"`+strings.Repeat("1", MaxRequestBytes)+`"}`))
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized request status = %d, want 413", response.StatusCode)
	}
}

func TestLookupTransportCloseCancelsActiveEvaluation(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "lookup.sock")
	started := make(chan struct{})
	canceled := make(chan struct{})
	var once sync.Once
	server, err := Listen(path, func(ctx context.Context, request Request) Response {
		once.Do(func() { close(started) })
		<-ctx.Done()
		close(canceled)
		return Unknown(request, "canceled", "lookup canceled")
	})
	if err != nil {
		t.Fatal(err)
	}
	client := unixClient(path)
	result := make(chan error, 1)
	go func() {
		response, err := client.Post("http://perimeterd"+Endpoint, "application/json", strings.NewReader(`{"address":"1.1.1.1"}`))
		if response != nil {
			_ = response.Body.Close()
		}
		result <- err
	}()
	select {
	case <-started:
	case <-time.After(time.Second):
		t.Fatal("handler did not start")
	}
	if err := server.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	select {
	case <-canceled:
	case <-time.After(time.Second):
		t.Fatal("closing server did not cancel evaluation")
	}
	<-result
}

func unixClient(path string) *http.Client {
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: time.Second}).DialContext(ctx, "unix", path)
	}}
	return &http.Client{Transport: transport}
}

func TestLookupCloseInterruptsIncompleteRequestBody(t *testing.T) {
	path := filepath.Join(t.TempDir(), "lookup.sock")
	server, err := Listen(path, func(_ context.Context, request Request) Response {
		return Unknown(request, "unexpected", "incomplete body reached evaluator")
	})
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = server.Close(context.Background()) }()
	conn, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = conn.Close() }()
	if err := conn.SetDeadline(time.Now().Add(time.Second)); err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(conn, "POST /v1/lookup HTTP/1.1\r\nHost: perimeterd\r\nContent-Length: 2\r\nExpect: 100-continue\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	reader := bufio.NewReader(conn)
	for {
		line, err := reader.ReadString('\n')
		if err != nil {
			t.Fatal(err)
		}
		if line == "\r\n" {
			break
		}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if err := server.Close(ctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("blocked-body shutdown error = %v", err)
	}
	if _, err := reader.ReadByte(); !errors.Is(err, io.EOF) {
		t.Fatalf("incomplete body connection survived shutdown: %v", err)
	}
}

func TestClientRejectsIncompleteAndOverlappingPartitions(t *testing.T) {
	for _, kind := range []string{"direction", "protocol", "address", "port", "overlap"} {
		t.Run(kind, func(t *testing.T) {
			query := Request{Address: "8.0.0.0/24", Direction: "ingress", Protocol: "tcp"}
			outcome := Outcome{
				Prefix: netip.MustParsePrefix(query.Address), Direction: query.Direction, Protocol: query.Protocol,
				Ports:      &Ports{Start: 0, End: 65535},
				Attachment: Attachment{Name: "test", Managed: true, PortBasis: "current_destination"},
				Verdict:    "not_blocked", Action: "return", Stage: "pass", Reason: "no_matching_policy",
			}
			switch kind {
			case "direction":
				query.Direction = ""
			case "protocol":
				query.Protocol = ""
			case "address":
				outcome.Prefix = netip.MustParsePrefix("8.0.0.0/25")
			case "port":
				outcome.Ports.End = 32767
			}
			response := Response{SchemaVersion: SchemaVersion, Query: query, Flow: "new", ObservedAt: time.Now(), Verdict: "not_blocked", Outcomes: []Outcome{outcome}}
			if kind == "overlap" {
				response.Outcomes = append(response.Outcomes, outcome)
			}
			path := filepath.Join(t.TempDir(), "malformed.sock")
			listener, err := net.Listen("unix", path)
			if err != nil {
				t.Fatal(err)
			}
			server := httptest.NewUnstartedServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if err := json.NewEncoder(writer).Encode(response); err != nil {
					t.Error(err)
				}
			}))
			if err := server.Listener.Close(); err != nil {
				t.Fatal(err)
			}
			server.Listener = listener
			server.Start()
			defer server.Close()
			result := callPath(context.Background(), path, query)
			if result.Verdict != "unknown" || result.Error == nil || result.Error.Code != "protocol" || len(result.Outcomes) != 0 {
				t.Fatalf("malformed %s partition accepted: %#v", kind, result)
			}
		})
	}
}
