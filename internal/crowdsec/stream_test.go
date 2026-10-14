package crowdsec

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"net/url"
	"strings"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	log "github.com/sirupsen/logrus"
)

const smallStream = `{"new":[{"id":7,"type":"ban","scope":"range","value":"::ffff:198.51.100.129/120","duration":"1h"}],"deleted":[{"id":8}]}`

func gzipStream(t *testing.T, body string) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := gzip.NewWriter(&out)
	if _, err := io.WriteString(writer, body); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

func requireStreamFailure(t *testing.T, err error, kind streamFailure) *streamError {
	t.Helper()
	var failure *streamError
	if !errors.As(err, &failure) || failure.kind != kind {
		t.Fatalf("failure category = %v, want %s", err, kind)
	}
	return failure
}

type chunkReader struct{ io.Reader }

func (r chunkReader) Read(p []byte) (int, error) {
	if len(p) > 3 {
		p = p[:3]
	}
	return r.Reader.Read(p)
}

func TestStreamActualReadLimits(t *testing.T) {
	for _, encoding := range []string{"identity", "gzip"} {
		t.Run(encoding, func(t *testing.T) {
			wire := []byte(smallStream)
			if encoding == "gzip" {
				wire = gzipStream(t, smallStream)
			}
			for _, test := range []struct {
				name   string
				limits streamLimits
				kind   streamFailure
				limit  int64
			}{
				{name: "exact", limits: streamLimits{wire: int64(len(wire)), decoded: int64(len(smallStream))}},
				{name: "wire_one_over", limits: streamLimits{wire: int64(len(wire) - 1), decoded: 4096}, kind: failureWireLimit, limit: int64(len(wire) - 1)},
				{name: "decoded_one_over", limits: streamLimits{wire: 4096, decoded: int64(len(smallStream) - 1)}, kind: failureDecodedLimit, limit: int64(len(smallStream) - 1)},
			} {
				for _, declared := range []int64{-1, 0, 1, 999999} {
					t.Run(fmt.Sprintf("%s/declared_%d", test.name, declared), func(t *testing.T) {
						resp := response(http.StatusOK, chunkReader{bytes.NewReader(wire)}, http.Header{"Content-Encoding": {encoding}})
						resp.ContentLength = declared
						resp.TransferEncoding = []string{"chunked"}
						started := time.Now()
						batch, err := decodeStream(resp, true, started, test.limits)
						if test.kind != "" {
							failure := requireStreamFailure(t, err, test.kind)
							if failure.limit != test.limit || !strings.Contains(err.Error(), fmt.Sprint(test.limit)) {
								t.Fatalf("limit metadata = %#v", failure)
							}
							if batch.Startup || len(batch.New) != 0 || len(batch.Deleted) != 0 {
								t.Fatalf("partial batch escaped: %#v", batch)
							}
							return
						}
						if err != nil {
							t.Fatal(err)
						}
						if !batch.Startup || len(batch.New) != 1 || batch.New[0].ID != 7 ||
							batch.New[0].Prefix != netip.MustParsePrefix("198.51.100.0/24") ||
							!batch.New[0].Deadline.Equal(started.Add(time.Hour-deadlineSlack)) ||
							len(batch.Deleted) != 1 || batch.Deleted[0] != 8 {
							t.Fatalf("normalized exact-limit batch = %#v", batch)
						}
					})
				}
			}
		})
	}
}

type failReader struct{ err error }

func (r failReader) Read([]byte) (int, error) { return 0, r.err }

type terminalErrorReader struct{ data []byte }

func (r *terminalErrorReader) Read(p []byte) (int, error) {
	n := copy(p, r.data)
	r.data = r.data[n:]
	if len(r.data) == 0 {
		return n, errors.New("secret terminal read")
	}
	return n, nil
}

func TestStreamTailAndEncodingIntegrity(t *testing.T) {
	validGzip := gzipStream(t, smallStream)
	badChecksum := bytes.Clone(validGzip)
	badChecksum[len(badChecksum)-8] ^= 1
	for _, test := range []struct {
		name     string
		reader   io.Reader
		encoding string
		limits   streamLimits
		kind     streamFailure
	}{
		{name: "trailing_json", reader: strings.NewReader(smallStream + `null`), kind: failureEnvelope},
		{name: "trailing_malformed", reader: strings.NewReader(smallStream + `!secret`), kind: failureEnvelope},
		{name: "tail_read_failure", reader: io.MultiReader(strings.NewReader(smallStream), failReader{errors.New("secret-read")}), kind: failureTransport},
		{name: "valid_data_with_read_failure", reader: &terminalErrorReader{data: []byte(smallStream)}, kind: failureTransport},
		{name: "wire_whitespace_overflow", reader: strings.NewReader(smallStream + " "), limits: streamLimits{wire: int64(len(smallStream)), decoded: 4096}, kind: failureWireLimit},
		{name: "decoded_whitespace_overflow", reader: strings.NewReader(smallStream + " "), limits: streamLimits{wire: 4096, decoded: int64(len(smallStream))}, kind: failureDecodedLimit},
		{name: "gzip_expansion", reader: bytes.NewReader(gzipStream(t, smallStream+strings.Repeat(" ", 2048))), encoding: "gzip", limits: streamLimits{wire: 4096, decoded: int64(len(smallStream))}, kind: failureDecodedLimit},
		{name: "gzip_checksum", reader: bytes.NewReader(badChecksum), encoding: "gzip", kind: failureGzip},
		{name: "gzip_truncated", reader: bytes.NewReader(validGzip[:len(validGzip)-4]), encoding: "gzip", kind: failureGzip},
		{name: "gzip_header", reader: strings.NewReader("secret-invalid-gzip"), encoding: "gzip", kind: failureGzip},
		{name: "gzip_read_failure", reader: io.MultiReader(bytes.NewReader(validGzip), failReader{errors.New("secret-read")}), encoding: "gzip", kind: failureTransport},
		{name: "gzip_trailing_json", reader: bytes.NewReader(gzipStream(t, smallStream+`{}`)), encoding: "gzip", kind: failureEnvelope},
		{name: "gzip_invalid_suffix", reader: io.MultiReader(bytes.NewReader(validGzip), strings.NewReader("secret-invalid-member")), encoding: "gzip", kind: failureGzip},
		{name: "gzip_truncated_next_member", reader: io.MultiReader(bytes.NewReader(validGzip), bytes.NewReader([]byte{0x1f})), encoding: "gzip", kind: failureGzip},
		{name: "unsupported", reader: strings.NewReader(smallStream), encoding: "secret-encoding", kind: failureEncoding},
		{name: "stacked", reader: bytes.NewReader(validGzip), encoding: "gzip, identity", kind: failureEncoding},
	} {
		t.Run(test.name, func(t *testing.T) {
			if test.limits == (streamLimits{}) {
				test.limits = streamLimits{wire: 4096, decoded: 4096}
			}
			batch, raw := decodeStream(response(http.StatusOK, test.reader, http.Header{"Content-Encoding": {test.encoding}}), true, time.Now(), test.limits)
			err := sanitizeStreamError(raw, nil, false)
			_ = requireStreamFailure(t, err, test.kind)
			if batch.Startup || len(batch.New) != 0 || len(batch.Deleted) != 0 {
				t.Fatalf("invalid tail admitted a prefix: %#v", batch)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("untrusted diagnostics escaped: %v", err)
			}
		})
	}
}

func TestStreamEnvelopeExtensionsAndNulls(t *testing.T) {
	for _, test := range []struct {
		name string
		body string
		kind streamFailure
	}{
		{name: "reordered_null", body: `{"deleted":null,"new":null}`},
		{name: "nested_extensions", body: `{"extra":{"a":[1e99999,{"b":[true,false,null,"value"]}]},"deleted":[],"new":[]}`},
		{name: "depth_exact", body: `{"extra":` + strings.Repeat("[", maxExtensionDepth) + `0` + strings.Repeat("]", maxExtensionDepth) + `,"new":[],"deleted":[]}`},
		{name: "depth_over", body: `{"extra":` + strings.Repeat("[", maxExtensionDepth+1) + `0` + strings.Repeat("]", maxExtensionDepth+1) + `,"new":[],"deleted":[]}`, kind: failureEnvelope},
		{name: "duplicate_deleted", body: `{"new":[],"deleted":[],"deleted":[]}`, kind: failureEnvelope},
		{name: "case_alias", body: `{"new":[],"DELETED":[]}`, kind: failureEnvelope},
		{name: "missing_new", body: `{"deleted":[]}`, kind: failureEnvelope},
		{name: "wrong_deleted_type", body: `{"new":[],"deleted":false}`, kind: failureEnvelope},
		{name: "invalid_deleted_identity", body: `{"new":[],"deleted":[{"id":0}]}`, kind: failureDecision},
		{name: "typed_deleted_error", body: `{"new":[],"deleted":[{"id":1,"duration":123}]}`, kind: failureDecision},
		{name: "typed_new_error", body: `{"new":[{"id":"secret"}],"deleted":[]}`, kind: failureDecision},
		{name: "new_identity_not_inherited", body: `{"new":[{"id":1,"type":"ban","scope":"ip","value":"198.51.100.1","duration":"1h"},{"type":"ban","scope":"ip","value":"198.51.100.2","duration":"1h"}],"deleted":[]}`, kind: failureDecision},
		{name: "deleted_identity_not_inherited", body: `{"new":[],"deleted":[{"id":1},{}]}`, kind: failureDecision},
		{name: "null_not_inherited", body: `{"new":[],"deleted":[{"id":1},null]}`, kind: failureDecision},
		{name: "extension_malformed", body: `{"extra":{"x":[true,]},"new":[],"deleted":[]}`, kind: failureEnvelope},
	} {
		t.Run(test.name, func(t *testing.T) {
			batch, err := decodeStream(response(http.StatusOK, strings.NewReader(test.body), nil), true, time.Now(), streamLimits{wire: 4096, decoded: 4096})
			if test.kind != "" {
				_ = requireStreamFailure(t, err, test.kind)
				if len(batch.New) != 0 || len(batch.Deleted) != 0 || batch.Startup {
					t.Fatalf("malformed envelope escaped: %#v", batch)
				}
				return
			}
			if err != nil || !batch.Startup || len(batch.New) != 0 || len(batch.Deleted) != 0 {
				t.Fatalf("authoritative empty extension envelope = %#v, %v", batch, err)
			}
		})
	}
}

func TestClientStreamSlowTransferDoesNotExtendDuration(t *testing.T) {
	requestStarted := make(chan time.Time, 1)
	release := make(chan struct{})
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestStarted <- time.Now()
		w.WriteHeader(http.StatusOK)
		w.(http.Flusher).Flush()
		<-release
		_, _ = io.WriteString(w, smallStream)
	}))
	defer server.Close()
	client, err := NewClient(crowdConfig(t, server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	type result struct {
		batch Batch
		err   error
	}
	completed := make(chan result, 1)
	before := time.Now()
	go func() { batch, err := client.Poll(context.Background(), true); completed <- result{batch, err} }()
	atServer := <-requestStarted
	// A controlled transfer pause makes a response-time anchor detectably wrong.
	time.Sleep(30 * time.Millisecond)
	close(release)
	got := <-completed
	if got.err != nil || len(got.batch.New) != 1 {
		t.Fatalf("slow stream = %#v, %v", got.batch, got.err)
	}
	deadline := got.batch.New[0].Deadline
	if deadline.Before(before.Add(time.Hour-deadlineSlack)) || deadline.After(atServer.Add(time.Hour-deadlineSlack)) {
		t.Fatalf("duration rebased after request start: %v, start bounds %v..%v", deadline, before, atServer)
	}
}

type observedBody struct {
	io.ReadCloser
	closed atomic.Bool
	reads  atomic.Int32
}

func (b *observedBody) Read(p []byte) (int, error) {
	b.reads.Add(1)
	return b.ReadCloser.Read(p)
}

func (b *observedBody) Close() error { b.closed.Store(true); return b.ReadCloser.Close() }

func TestClientHTTPStatusDoesNotReadErrorBody(t *testing.T) {
	for _, status := range []int{401, 403, 500} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			body := &observedBody{ReadCloser: io.NopCloser(failReader{errors.New("secret hostile unbounded body")})}
			client, err := NewClient(crowdConfig(t, "http://secret-user:secret-password@lapi.example/base?secret-query"), roundTripFunc(func(*http.Request) (*http.Response, error) {
				return &http.Response{StatusCode: status, Status: "secret status text", Body: body, Header: http.Header{"Content-Encoding": {"secret invalid encoding"}}, ContentLength: 1 << 40}, nil
			}))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			batch, err := client.Poll(context.Background(), true)
			failure := requireStreamFailure(t, err, failureHTTP)
			if failure.status != status || !strings.Contains(err.Error(), fmt.Sprint(status)) || strings.Contains(err.Error(), "secret") {
				t.Fatalf("HTTP status or secrecy lost: %v", err)
			}
			if body.reads.Load() != 0 || !body.closed.Load() || len(batch.New) != 0 || batch.Startup {
				t.Fatal("failed HTTP body was read, leaked, or admitted")
			}
		})
	}
}

func TestClientTransportFailureCategoriesAndSecrecy(t *testing.T) {
	var sdkOutput bytes.Buffer
	disableSDKDiagnostics()
	oldOutput := log.StandardLogger().Out
	log.SetOutput(&sdkOutput)
	defer log.SetOutput(oldOutput)
	for _, test := range []struct {
		name string
		err  error
		kind streamFailure
		is   error
	}{
		{name: "dns", err: &net.DNSError{Err: "secret underlying", Name: "secret-host"}, kind: failureDNS},
		{name: "dns_timeout", err: &net.DNSError{Err: "secret underlying", Name: "secret-host", IsTimeout: true}, kind: failureTimeout},
		{name: "connection", err: &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("secret underlying")}, kind: failureConnection},
		{name: "reset_read", err: fmt.Errorf("secret wrapper: %w", syscall.ECONNRESET), kind: failureConnection},
		{name: "tls", err: &tls.CertificateVerificationError{Err: errors.New("secret certificate")}, kind: failureTLS},
		{name: "tls_alert", err: tls.AlertError(40), kind: failureTLS},
		{name: "timeout", err: fmt.Errorf("secret wrapper: %w", context.DeadlineExceeded), kind: failureTimeout, is: context.DeadlineExceeded},
		{name: "canceled", err: fmt.Errorf("secret wrapper: %w", context.Canceled), kind: failureCanceled, is: context.Canceled},
		{name: "unknown", err: errors.New("secret underlying"), kind: failureTransport},
	} {
		t.Run(test.name, func(t *testing.T) {
			client, err := NewClient(crowdConfig(t, "http://secret-user:secret-password@lapi.example/base?secret-query"), roundTripFunc(func(req *http.Request) (*http.Response, error) {
				if req.URL.User != nil || req.URL.Query().Has("secret-query") {
					t.Error("configured secret URL material reached transport")
				}
				return nil, &url.Error{Op: "secret operation", URL: "https://secret-user:secret-password@secret-host?secret-query", Err: test.err}
			}))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			_, err = client.Poll(context.Background(), true)
			_ = requireStreamFailure(t, err, test.kind)
			if test.is != nil && !errors.Is(err, test.is) {
				t.Fatalf("context identity lost: %v", err)
			}
			if strings.Contains(err.Error(), "secret") || strings.Contains(sdkOutput.String(), "secret") || strings.Contains(sdkOutput.String(), "test-api-key") {
				t.Fatalf("secret diagnostic escaped: %v; SDK log %q", err, sdkOutput.String())
			}
		})
	}
}

func TestClientCancellationClosesStreamingBody(t *testing.T) {
	for _, mode := range []string{"cancel", "deadline", "close"} {
		t.Run(mode, func(t *testing.T) {
			started := make(chan struct{})
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				_, _ = io.WriteString(w, `{"new":[`)
				w.(http.Flusher).Flush()
				close(started)
				<-r.Context().Done()
			}))
			defer server.Close()
			transport := http.DefaultTransport.(*http.Transport).Clone()
			transport.DisableCompression = true
			defer transport.CloseIdleConnections()
			bodyReady := make(chan *observedBody, 1)
			client, err := NewClient(crowdConfig(t, server.URL), roundTripFunc(func(req *http.Request) (*http.Response, error) {
				resp, err := transport.RoundTrip(req)
				if err == nil {
					body := &observedBody{ReadCloser: resp.Body}
					resp.Body = body
					bodyReady <- body
				}
				return resp, err
			}))
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			ctx, cancel := context.WithCancel(context.Background())
			if mode == "deadline" {
				cancel()
				ctx, cancel = context.WithTimeout(context.Background(), 100*time.Millisecond)
			}
			defer cancel()
			completed := make(chan error, 1)
			var observed atomic.Int32
			client.SetRequestObserver(func(success bool) {
				if success {
					observed.Add(100)
				} else {
					observed.Add(1)
				}
			})
			go func() { _, err := client.Poll(ctx, true); completed <- err }()
			<-started
			body := <-bodyReady
			switch mode {
			case "cancel":
				cancel()
			case "close":
				client.Close()
			}
			select {
			case err := <-completed:
				want := context.Canceled
				if mode == "close" {
					want = errClientClosed
				}
				if mode == "deadline" {
					want = context.DeadlineExceeded
				}
				if !errors.Is(err, want) || !body.closed.Load() || observed.Load() != 1 {
					t.Fatalf("stream cancellation: %v, closed=%t, observation=%d", err, body.closed.Load(), observed.Load())
				}
			case <-time.After(3 * time.Second):
				t.Fatal("cancellation did not interrupt response read")
			}
		})
	}
}

func TestClientRefusesRedirectsAndVerifiesTLS(t *testing.T) {
	var redirected atomic.Bool
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { redirected.Store(true) }))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Location", target.URL+"/?secret")
		w.WriteHeader(http.StatusFound)
	}))
	defer server.Close()
	client, err := NewClient(crowdConfig(t, server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	_, err = client.Poll(context.Background(), true)
	failure := requireStreamFailure(t, err, failureHTTP)
	if failure.status != http.StatusFound || redirected.Load() {
		t.Fatalf("redirect followed or status lost: %v", err)
	}
	secure := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, smallStream) }))
	defer secure.Close()
	tlsClient, err := NewClient(crowdConfig(t, secure.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tlsClient.Close()
	_, err = tlsClient.Poll(context.Background(), true)
	_ = requireStreamFailure(t, err, failureTLS)
}

func TestClientPollEncodingHeaders(t *testing.T) {
	compressed := gzipStream(t, smallStream)
	for _, encodings := range [][]string{{"identity"}, {"gzip"}, {"gzip", "secret-encoding"}} {
		t.Run(strings.Join(encodings, ","), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				for _, encoding := range encodings {
					w.Header().Add("Content-Encoding", encoding)
				}
				if encodings[0] == "gzip" {
					_, _ = w.Write(compressed)
				} else {
					_, _ = io.WriteString(w, smallStream)
				}
			}))
			defer server.Close()
			client, err := NewClient(crowdConfig(t, server.URL), nil)
			if err != nil {
				t.Fatal(err)
			}
			defer client.Close()
			batch, err := client.Poll(context.Background(), true)
			if len(encodings) > 1 {
				_ = requireStreamFailure(t, err, failureEncoding)
				if strings.Contains(err.Error(), "secret") || len(batch.New) != 0 || batch.Startup {
					t.Fatalf("unsupported repeated encoding was admitted or leaked: %#v %v", batch, err)
				}
				return
			}
			if err != nil || !batch.Startup || len(batch.New) != 1 || batch.New[0].ID != 7 ||
				batch.New[0].Prefix != netip.MustParsePrefix("198.51.100.0/24") ||
				len(batch.Deleted) != 1 || batch.Deleted[0] != 8 {
				t.Fatalf("HTTP encoding changed decisions: %#v %v", batch, err)
			}
		})
	}
}

func TestClientSnapshotExpiryAtCompleteAdmission(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, `{"new":[{"id":1,"type":"ban","scope":"ip","value":"198.51.100.1","duration":"1.1s"}],"deleted":[]}`)
		w.(http.Flusher).Flush()
		// Complete JSON is available early, but admission must await EOF.
		time.Sleep(200 * time.Millisecond)
	}))
	defer server.Close()
	client, err := NewClient(crowdConfig(t, server.URL), nil)
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	batch, err := client.Poll(context.Background(), true)
	if err != nil || !batch.Startup || len(batch.New) != 0 {
		t.Fatalf("snapshot admitted a decision expired during transfer: %#v, %v", batch, err)
	}
	batch, err = client.Poll(context.Background(), false)
	if err != nil || batch.Startup || len(batch.New) != 1 || batch.New[0].ID != 1 || batch.New[0].Deadline.After(time.Now()) {
		t.Fatalf("incremental expired update lost removal semantics: %#v, %v", batch, err)
	}
}

func TestClientWrappedTransportPreservesGzipIntegrityCategory(t *testing.T) {
	compressed := gzipStream(t, smallStream)
	compressed[len(compressed)-8] ^= 1
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Encoding", "gzip")
		_, _ = w.Write(compressed)
	}))
	defer server.Close()
	// Model OpenZiti's opaque transport wrapper: NewClient cannot clone or
	// configure its underlying HTTP transport. Automatic decoding would erase
	// the wire encoding and misclassify a corrupt trailer as an identity read.
	base := http.DefaultTransport.(*http.Transport).Clone()
	base.DisableCompression = false
	defer base.CloseIdleConnections()
	client, err := NewClient(crowdConfig(t, server.URL), roundTripFunc(base.RoundTrip))
	if err != nil {
		t.Fatal(err)
	}
	defer client.Close()
	batch, err := client.Poll(context.Background(), true)
	_ = requireStreamFailure(t, err, failureGzip)
	if batch.Startup || len(batch.New) != 0 || len(batch.Deleted) != 0 {
		t.Fatalf("wrapped transport admitted corrupt gzip: %#v", batch)
	}
}
