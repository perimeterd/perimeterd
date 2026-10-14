package crowdsec

import (
	"compress/gzip"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/models"
)

// maxExtensionDepth bounds open containers within an unknown envelope member.
// Token parsing may allocate one string/number; it never retains an extension
// object or the complete envelope. Decisions are decoded one at a time.
const maxExtensionDepth = 64

type streamLimits struct {
	wire    int64
	decoded int64
}

func (c *Client) pollStream(ctx context.Context, startup bool, started time.Time) (Batch, error) {
	streamURL := *c.streamURL
	// StreamBouncer's default options explicitly disable these two pull flags.
	// Keep that SDK wire contract, including explicit false startup and dedup.
	streamURL.RawQuery = url.Values{
		"startup":         {strconv.FormatBool(startup)},
		"scopes":          {"ip,range"},
		"dedup":           {"false"},
		"community_pull":  {"false"},
		"additional_pull": {"false"},
	}.Encode()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, streamURL.String(), nil)
	if err != nil {
		return Batch{}, err
	}
	req.Header.Set("User-Agent", c.bouncer.APIClient.UserAgent)
	// Wrapped transports (including OpenZiti) hide their *http.Transport.
	// Explicit identity prevents its automatic gzip negotiation/decoding too;
	// a server-supplied gzip body must reach our independent wire/decoded gates.
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := c.bouncer.APIClient.GetClient().Do(req)
	if resp != nil && resp.Body != nil {
		defer func() { _ = resp.Body.Close() }()
	}
	if err != nil {
		return Batch{}, err
	}
	if resp.StatusCode != http.StatusOK {
		// Do not read a server-controlled error body, even to drain it. Status
		// must remain identifiable with hostile, oversized or stalled bodies.
		return Batch{}, &streamError{kind: failureHTTP, status: resp.StatusCode}
	}
	return decodeStream(resp, startup, started, streamLimits{wire: wireLimit, decoded: decodedLimit})
}

// boundedStreamReader measures actual entity bytes, independently of declared
// length. At the boundary a one-byte probe distinguishes exact EOF from overflow.
// The probe is never delivered to the parser or decompressor.
type boundedStreamReader struct {
	reader    io.Reader
	remaining int64
	limit     int64
	kind      streamFailure
	err       error
}

func (r *boundedStreamReader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if r.err != nil {
		return 0, r.err
	}
	if r.remaining == 0 {
		var probe [1]byte
		n, err := r.reader.Read(probe[:])
		if n > 0 {
			r.err = &streamError{kind: r.kind, limit: r.limit}
			return 0, r.err
		}
		if err != nil && err != io.EOF {
			r.err = err
		}
		return 0, err
	}
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	n, err := r.reader.Read(p)
	r.remaining -= int64(n)
	if err != nil && err != io.EOF {
		r.err = err
	}
	return n, err
}

func decodeStream(resp *http.Response, startup bool, started time.Time, limits streamLimits) (Batch, error) {
	if resp.Body == nil {
		return Batch{}, &streamError{kind: failureEnvelope}
	}
	wire := &boundedStreamReader{reader: resp.Body, remaining: limits.wire, limit: limits.wire, kind: failureWireLimit}
	var input io.Reader = wire
	encoding := strings.TrimSpace(strings.ToLower(strings.Join(resp.Header.Values("Content-Encoding"), ",")))
	compressed := encoding == "gzip"
	switch encoding {
	case "", "identity":
	case "gzip":
		reader, err := gzip.NewReader(wire)
		if err != nil {
			if wire.err != nil {
				return Batch{}, wire.err
			}
			return Batch{}, &streamError{kind: failureGzip}
		}
		defer func() { _ = reader.Close() }()
		input = reader
	default:
		return Batch{}, &streamError{kind: failureEncoding}
	}
	decoded := &boundedStreamReader{reader: input, remaining: limits.decoded, limit: limits.decoded, kind: failureDecodedLimit}
	decoder := json.NewDecoder(decoded)
	// Unknown extension numbers need not fit in float64. Keep their existing
	// JSON syntax semantics without materializing a potentially huge value.
	decoder.UseNumber()
	batch, err := decodeEnvelope(decoder, startup, started)
	// Readers retain failures even if json.Decoder had enough buffered bytes
	// to finish a value. A valid prefix must never mask a bad read or trailer.
	if wire.err != nil {
		return Batch{}, wire.err
	}
	if decoded.err != nil {
		if overflow, ok := decoded.err.(*streamError); ok {
			return Batch{}, overflow
		}
		if compressed {
			return Batch{}, &streamError{kind: failureGzip}
		}
		return Batch{}, decoded.err
	}
	if err != nil {
		return Batch{}, err
	}
	if startup {
		// Earlier items may expire while the remaining stream is in flight.
		// Match snapshot admission at completion without rebasing deadlines.
		now := time.Now()
		kept := batch.New[:0]
		for _, decision := range batch.New {
			if decision.Deadline.After(now) {
				kept = append(kept, decision)
			}
		}
		batch.New = kept
	}
	return batch, nil
}

func decodeEnvelope(decoder *json.Decoder, startup bool, started time.Time) (Batch, error) {
	malformed := errMalformedEnvelope
	first, err := decoder.Token()
	if err != nil || first != json.Delim('{') {
		return Batch{}, malformed
	}
	batch := Batch{Startup: startup}
	seenNew, seenDeleted := false, false
	for decoder.More() {
		key, err := decoder.Token()
		if err != nil {
			return Batch{}, malformed
		}
		name, ok := key.(string)
		if !ok {
			return Batch{}, malformed
		}
		switch {
		case strings.EqualFold(name, "new"):
			if name != "new" || seenNew {
				return Batch{}, malformed
			}
			seenNew = true
			if err := decodeDecisions(decoder, &batch, false, started); err != nil {
				return Batch{}, err
			}
		case strings.EqualFold(name, "deleted"):
			if name != "deleted" || seenDeleted {
				return Batch{}, malformed
			}
			seenDeleted = true
			if err := decodeDecisions(decoder, &batch, true, started); err != nil {
				return Batch{}, err
			}
		default:
			if err := skipExtension(decoder); err != nil {
				return Batch{}, malformed
			}
		}
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim('}') || !seenNew || !seenDeleted {
		return Batch{}, malformed
	}
	// Token must consume through EOF, not just through the closing object.
	// This charges whitespace to both limits and validates gzip integrity.
	if _, err := decoder.Token(); err != io.EOF {
		return Batch{}, malformed
	}
	return batch, nil
}

func decodeDecisions(decoder *json.Decoder, batch *Batch, deleted bool, started time.Time) error {
	first, err := decoder.Token()
	if err != nil {
		return &streamError{kind: failureEnvelope}
	}
	if first == nil { // JSON null is an empty array under the stream contract.
		return nil
	}
	if first != json.Delim('[') {
		return &streamError{kind: failureEnvelope}
	}
	var decision models.Decision
	for decoder.More() {
		// Reuse the model, but never inherit omitted fields (or JSON null)
		// from the preceding item.
		decision = models.Decision{}
		if err := decoder.Decode(&decision); err != nil {
			return &streamError{kind: failureDecision}
		}
		if deleted {
			if decision.ID <= 0 {
				return &streamError{kind: failureDecision}
			}
			batch.Deleted = append(batch.Deleted, decision.ID)
			continue
		}
		converted, keep, err := convertDecision(&decision, started, !batch.Startup)
		if err != nil {
			return &streamError{kind: failureDecision}
		}
		if keep {
			batch.New = append(batch.New, converted)
		}
	}
	last, err := decoder.Token()
	if err != nil || last != json.Delim(']') {
		return &streamError{kind: failureEnvelope}
	}
	return nil
}

// skipExtension uses an iterative token walk, never RawMessage or interface{}
// trees. The limit counts containers relative to the unknown member's value.
func skipExtension(decoder *json.Decoder) error {
	depth := 0
	for {
		token, err := decoder.Token()
		if err != nil {
			return err
		}
		if delim, ok := token.(json.Delim); ok {
			switch delim {
			case '{', '[':
				depth++
				if depth > maxExtensionDepth {
					return &streamError{kind: failureEnvelope}
				}
			case '}', ']':
				depth--
			}
		}
		if depth == 0 {
			return nil
		}
	}
}
