package source

import (
	"bufio"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

var errDBIPNotFound = errors.New("DB-IP artifact HTTP 404")

func (r *Resolver) fetchDBIP(ctx context.Context, cfg config.Config, selectors []policy.Selector) (records map[policy.Selector]Record, err error) {
	success := false
	if r.observeRequest != nil {
		defer func() { r.observeRequest(dbipSourceKind, success) }()
	}
	now := r.utcNow()
	month := time.Date(now.Year(), now.Month(), 1, 0, 0, 0, 0, time.UTC)
	for lag := range 2 {
		release := month.Format("2006-01")
		records, err = retryFetch(ctx, func() (map[policy.Selector]Record, error) { return r.fetchDBIPAttempt(ctx, cfg, selectors, release) })
		if err == nil {
			success = true
			return records, nil
		}
		if lag != 0 || !errors.Is(err, errDBIPNotFound) {
			return nil, err
		}
		month = month.AddDate(0, -1, 0)
	}
	return nil, err
}

func (r *Resolver) fetchDBIPAttempt(parent context.Context, cfg config.Config, selectors []policy.Selector, release string) (map[policy.Selector]Record, error) {
	ctx, cancel := context.WithTimeout(parent, cfg.Geo.RequestTimeout)
	defer cancel()
	select {
	case r.slots <- struct{}{}:
		defer func() { <-r.slots }()
	case <-ctx.Done():
		return nil, retryableFetchFailure(ctx.Err(), ctx.Err())
	}
	endpoint := dbipEndpoint(release)
	origin, _ := url.Parse(endpoint)
	// DB-IP shares text-source redirect validation and additionally pins the
	// vendor origin. Redirects can never cross an HTTPS trust boundary.
	ctx = markListOrigin(markListRequest(ctx), origin)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept-Encoding", "identity")
	resp, err := r.client.Do(req)
	if err != nil {
		return nil, retryableFetchFailure(classifyListRequestError(err), err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode == http.StatusNotFound {
		return nil, errDBIPNotFound
	}
	if resp.StatusCode != http.StatusOK {
		err := fmt.Errorf("DB-IP HTTP status %d", resp.StatusCode)
		switch resp.StatusCode {
		case 408, 500, 502, 503, 504:
			return nil, &retryableFetchError{err}
		}
		return nil, err
	}
	encoding := strings.ToLower(strings.TrimSpace(resp.Header.Get("Content-Encoding")))
	if encoding != "" && encoding != "identity" && encoding != "gzip" {
		return nil, fmt.Errorf("unsupported DB-IP content encoding")
	}
	bodyLimit := int64(dbipEncodedLimit)
	// An injected transport may have already removed the encoding. Its wire
	// byte count is unavailable: bound that stream by the decoded limit instead.
	// The normal identity request retains and checks the encoded byte budget.
	if resp.Uncompressed {
		bodyLimit = dbipDecodedLimit
	}
	if resp.ContentLength > bodyLimit {
		return nil, fmt.Errorf("DB-IP response size limit exceeded")
	}
	limited := &io.LimitedReader{R: resp.Body, N: bodyLimit + 1}
	buffered := bufio.NewReader(limited)
	var decoded io.Reader = buffered
	// Accepted envelopes: the ordinary .gz artifact (with no coding, identity,
	// or gzip coding), and a transport's already-uncompressed CSV. If transport
	// decoding leaves the .gz artifact intact we decode it once. Nested gzip,
	// concatenated members, and bytes after the one member are invalid.
	magic, peekErr := buffered.Peek(2)
	compressed := len(magic) == 2 && magic[0] == 0x1f && magic[1] == 0x8b
	if peekErr != nil && peekErr != io.EOF {
		return nil, retryableFetchFailure(peekErr, peekErr)
	}
	var zipper *gzip.Reader
	if compressed {
		if resp.Uncompressed {
			consumed := bodyLimit + 1 - limited.N
			limited.N = dbipEncodedLimit + 1 - consumed
			if resp.ContentLength > dbipEncodedLimit {
				return nil, errors.New("DB-IP encoded size limit exceeded")
			}
		}
		zipper, err = gzip.NewReader(buffered)
		if err != nil {
			return nil, retryableFetchFailure(fmt.Errorf("invalid DB-IP gzip: %w", err), err)
		}
		defer func() { _ = zipper.Close() }()
		zipper.Multistream(false)
		decoded = zipper
	} else if !resp.Uncompressed {
		return nil, errors.New("DB-IP artifact is not gzip")
	}
	records, digest, err := parseDBIP(ctx, decoded, selectors, standardDBIPLimits)
	if err != nil {
		if ctx.Err() != nil {
			return nil, retryableFetchFailure(ctx.Err(), ctx.Err())
		}
		// A bounded reader can surface as truncated gzip; a size rejection must
		// never acquire the transient read marker and repeat an oversized download.
		if limited.N <= 0 {
			return nil, errors.New("DB-IP response size limit exceeded")
		}
		// Preserve shared transient read classification; integrity/CSV validation
		// errors never become publication-lag fallback signals.
		return nil, retryableFetchFailure(err, err)
	}
	if zipper != nil {
		if _, err := buffered.ReadByte(); err != io.EOF {
			return nil, errors.New("DB-IP trailing gzip content")
		}
	}
	if limited.N <= 0 {
		return nil, errors.New("DB-IP encoded size limit exceeded")
	}
	if err := ctx.Err(); err != nil {
		return nil, retryableFetchFailure(err, err)
	}
	retrieved := r.utcNow()
	for selector, record := range records {
		record.SourceKind, record.APIVersion, record.Release = dbipSourceKind, dbipFormatVersion, release
		record.Endpoint, record.RetrievedAt = endpoint, retrieved
		record.Parameters = map[string]string{"resource": selector.Value, "sha256": digest}
		records[selector] = record
	}
	return records, nil
}
