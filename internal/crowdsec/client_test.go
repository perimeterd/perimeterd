package crowdsec

import (
	"bytes"
	"compress/gzip"
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

func crowdConfig(t *testing.T, endpoint string) config.CrowdSecConfig {
	t.Helper()
	keyFile := t.TempDir() + "/key"
	if err := os.WriteFile(keyFile, []byte("test-api-key\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	return config.CrowdSecConfig{Enabled: true, LAPIURL: endpoint, APIKeyFile: keyFile}
}

func response(status int, body io.Reader, headers http.Header) *http.Response {
	return &http.Response{StatusCode: status, Status: http.StatusText(status), Body: io.NopCloser(body), Header: headers}
}

func TestClientPollInjectsDedupAndExplicitStartup(t *testing.T) {
	var got *http.Request
	body := `{"new":[{"id":42,"type":"ban","scope":"Ip","value":"192.0.2.9","duration":"1h","origin":"cscli","scenario":"s"}],"deleted":[]}`
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req
		return response(http.StatusOK, strings.NewReader(body), nil), nil
	})
	client, err := NewClient(crowdConfig(t, "http://lapi.example/base"), transport)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()

	batch, err := client.Poll(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if got == nil {
		t.Fatal("transport did not receive a request")
	}
	query := got.URL.Query()
	if query.Get("dedup") != "false" || query.Get("startup") != "false" || query.Get("scopes") != "ip,range" {
		t.Fatalf("stream query was not adapted safely: %v", query)
	}
	if got.Header.Get("X-Api-Key") != "test-api-key" {
		t.Fatalf("API key header missing")
	}
	if len(batch.New) != 1 || batch.New[0].ID != 42 || batch.New[0].Prefix != netip.MustParsePrefix("192.0.2.9/32") {
		t.Fatalf("unexpected batch: %#v", batch)
	}
}

func TestClientPollRejectsMalformedEnvelopeShapes(t *testing.T) {
	cases := []string{
		``,
		`{"new":[],"deleted":[]}{"new":[],"deleted":[]}`,
		`{"new":[],"new":[],"deleted":[]}`,
		`{"new":[{"id":1,"type":"ban","scope":"ip","value":"192.0.2.1","duration":"1h"}],"deleted":[],"New":[]}`,
		`{"new":[],"deleted":[],"Deleted":[{"id":1,"type":"ban","scope":"ip","value":"192.0.2.1","duration":"1h"}]}`,
		`{"new":{},"deleted":[]}`,
		`{"new":[]}`,
		`{"new":[],"deleted":[],"unknown":{"unterminated":true}`,
		`{"new":[null],"deleted":[]}`,
		`{"new":[{"id":1,"scope":"Ip","value":"192.0.2.1","duration":"1h"}],"deleted":[]}`,
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
				return response(http.StatusOK, strings.NewReader(body), nil), nil
			})
			client, err := NewClient(crowdConfig(t, "http://lapi.example"), transport)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			if _, err := client.Poll(context.Background(), true); err == nil {
				t.Fatal("malformed envelope was accepted")
			}
		})
	}
}

func TestClientPollValidatesApplicableDecisionsAndKeepsAbsoluteExpiry(t *testing.T) {
	started := time.Now()
	body := `{"new":[` +
		`{"id":1,"type":"captcha","scope":"ip","value":"not-an-ip","duration":"bad"},` +
		`{"id":2,"type":"ban","scope":"ip","value":"192.0.2.1","duration":"bad"},` +
		`{"id":3,"type":"ban","scope":"range","value":"2001:db8::/64","until":"` + started.Add(2*time.Hour).UTC().Format(time.RFC3339Nano) + `"}` +
		`],"deleted":null}`
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(http.StatusOK, strings.NewReader(body), nil), nil
	})
	client, err := NewClient(crowdConfig(t, "http://lapi.example"), transport)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	batch, err := client.Poll(context.Background(), true)
	if err == nil {
		t.Fatal("invalid applicable decision was accepted")
	}
	if len(batch.New) != 0 {
		t.Fatalf("partial batch escaped validation: %#v", batch)
	}

	body = `{"new":[{"id":3,"type":"ban","scope":"range","value":"2001:db8::/64","until":"` + started.Add(2*time.Hour).UTC().Format(time.RFC3339Nano) + `"}],"deleted":null}`
	client2, err := NewClient(crowdConfig(t, "http://lapi.example"), roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return response(http.StatusOK, strings.NewReader(body), nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer client2.Close()
	batch, err = client2.Poll(context.Background(), true)
	if err != nil || len(batch.New) != 1 || !batch.New[0].Prefix.IsValid() {
		t.Fatalf("absolute decision was not accepted: %#v, %v", batch, err)
	}
	// The wire retains the absolute wall instant, not the sender's local
	// monotonic clock reading.
	if !batch.New[0].Deadline.Equal(started.Add(2 * time.Hour).UTC()) {
		t.Fatalf("absolute expiry changed: got %v", batch.New[0].Deadline)
	}
}

func TestClientExpiredMinimumDurationRemovesExistingDecision(t *testing.T) {
	body := `{"new":[{"id":1,"type":"ban","scope":"ip","value":"192.0.2.1","duration":"-2562047h47m16.854775808s"}],"deleted":[]}`
	client, err := NewClient(crowdConfig(t, "http://lapi.example"), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, strings.NewReader(body), nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	now := time.Now()
	store := NewStore(client.Endpoint(), 1)
	if err := store.Apply(Batch{Startup: true, New: []Decision{{ID: 1, Prefix: netip.MustParsePrefix("192.0.2.1/32"), Deadline: now.Add(time.Hour)}}}, 1, now); err != nil {
		t.Fatal(err)
	}
	batch, err := client.Poll(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(batch, 2, time.Now()); err != nil {
		t.Fatal(err)
	}
	if got := store.Projection(time.Now()); len(got) != 0 {
		t.Fatalf("expired update extended existing authority: %v", got)
	}
	batch, err = client.Poll(context.Background(), true)
	if err != nil || len(batch.New) != 0 {
		t.Fatalf("expired startup decision became a new ban: %#v, %v", batch, err)
	}
}

func TestClientCanonicalizesMappedIPv4Authority(t *testing.T) {
	body := `{"new":[
		{"id":1,"type":"ban","scope":"ip","value":"::ffff:198.51.100.77","duration":"40m"},
		{"id":2,"type":"ban","scope":"ip","value":"198.51.100.78","duration":"40m"},
		{"id":3,"type":"ban","scope":"ip","value":"2001:db8::77","duration":"40m"},
		{"id":4,"type":"ban","scope":"range","value":"::ffff:198.51.101.129/120","duration":"40m"},
		{"id":5,"type":"ban","scope":"range","value":"::ffff:198.51.100.0/80","duration":"40m"}
	],"deleted":[]}`
	client, err := NewClient(crowdConfig(t, "http://lapi.example"), roundTripFunc(func(*http.Request) (*http.Response, error) {
		return response(http.StatusOK, strings.NewReader(body), nil), nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	batch, err := client.Poll(context.Background(), true)
	if err != nil {
		t.Fatal(err)
	}
	store := NewStore(client.Endpoint(), 1)
	if err := store.Apply(batch, 1, time.Now()); err != nil {
		t.Fatalf("valid mapped IP rejected the whole source batch: %v", err)
	}
	want := map[netip.Prefix]bool{
		netip.MustParsePrefix("198.51.100.77/32"): true,
		netip.MustParsePrefix("198.51.100.78/32"): true,
		netip.MustParsePrefix("2001:db8::77/128"): true,
		netip.MustParsePrefix("198.51.101.0/24"):  true,
		netip.MustParsePrefix("::/80"):            true,
	}
	projection := store.Projection(time.Now())
	if len(projection) != len(want) {
		t.Fatalf("source authority changed: %v", projection)
	}
	for _, value := range projection {
		if !want[value.Prefix] {
			t.Fatalf("source address changed family or range: %s", value.Prefix)
		}
	}
}

func TestClientPollRejectsScopedAddresses(t *testing.T) {
	for _, address := range []string{"2001:4860:1234::7%eth0", "::ffff:198.51.100.7%eth0"} {
		t.Run(address, func(t *testing.T) {
			body := `{"new":[` +
				`{"id":1,"type":"ban","scope":"ip","value":"198.51.100.8","duration":"1h"},` +
				`{"id":2,"type":"ban","scope":"ip","value":"` + address + `","duration":"1h"}` +
				`],"deleted":[]}`
			client, err := NewClient(crowdConfig(t, "http://lapi.example"), roundTripFunc(func(*http.Request) (*http.Response, error) {
				return response(http.StatusOK, strings.NewReader(body), nil), nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			batch, err := client.Poll(context.Background(), true)
			if err == nil {
				t.Fatal("scoped decision was accepted as unscoped authority")
			}
			if len(batch.New) != 0 || len(batch.Deleted) != 0 {
				t.Fatalf("partial batch escaped validation: %#v", batch)
			}
		})
	}
}

func TestGateResponseBoundsGzipAndNormalizesHeaders(t *testing.T) {
	var compressed bytes.Buffer
	writer := gzip.NewWriter(&compressed)
	if _, err := writer.Write([]byte(`{"new":[],"deleted":[]}`)); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	h := make(http.Header)
	h.Set("Content-Encoding", "gzip")
	resp := response(http.StatusOK, bytes.NewReader(compressed.Bytes()), h)
	if err := gateResponse(resp); err != nil {
		t.Fatal(err)
	}
	if resp.Header.Get("Content-Encoding") != "" || resp.ContentLength <= 0 {
		t.Fatalf("gate did not normalize response metadata: %#v", resp.Header)
	}
	decoded, err := io.ReadAll(resp.Body)
	if err != nil || string(decoded) != `{"new":[],"deleted":[]}` {
		t.Fatalf("unexpected decoded response: %q, %v", decoded, err)
	}
}

func TestClientCloseCancelsPoll(t *testing.T) {
	started := make(chan struct{})
	transport := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		close(started)
		<-req.Context().Done()
		return nil, req.Context().Err()
	})
	client, err := NewClient(crowdConfig(t, "http://lapi.example"), transport)
	if err != nil {
		t.Fatal(err)
	}
	result := make(chan error, 1)
	go func() {
		_, err := client.Poll(context.Background(), true)
		result <- err
	}()
	<-started
	client.Close()
	select {
	case err := <-result:
		if !errors.Is(err, errClientClosed) {
			t.Fatalf("close returned wrong error: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("poll did not observe client closure")
	}
}
