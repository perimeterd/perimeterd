package crowdsec

import (
	"context"
	"errors"
	"io"
	"net/http"
	"net/netip"
	"net/url"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/crowdsecurity/crowdsec/pkg/apiclient"
	"github.com/crowdsecurity/crowdsec/pkg/models"
	csbouncer "github.com/crowdsecurity/go-cs-bouncer"
	log "github.com/sirupsen/logrus"

	"github.com/perimeterd/perimeterd/internal/buildinfo"
	"github.com/perimeterd/perimeterd/internal/config"
)

const (
	requestLimit    = 30 * time.Second
	wireLimit       = 256 << 20
	decodedLimit    = 256 << 20
	credentialLimit = 4 << 10
	deadlineSlack   = time.Second
)

var (
	errClientClosed  = errors.New("crowdsec client is closed")
	errInvalidConfig = errors.New("invalid crowdsec client configuration")
	sdkLogOnce       sync.Once
)

// Client is an authenticated CrowdSec LAPI stream client. A Client has one
// in-flight poll at a time; callers should serialize Poll calls per client.
type Client struct {
	bouncer   *csbouncer.StreamBouncer
	endpoint  string
	transport http.RoundTripper
	streamURL *url.URL

	mu             sync.Mutex
	closed         bool
	close          chan struct{}
	observeRequest func(success bool)
}

// NewClient constructs an authenticated client for cfg. The API key is read
// once from cfg.APIKeyFile and is never included in errors or diagnostics.
// A nil transport uses a cloned secure default transport.
func NewClient(cfg config.CrowdSecConfig, transport http.RoundTripper) (*Client, error) {
	if !cfg.Enabled {
		return nil, errInvalidConfig
	}

	baseURL, endpoint, err := canonicalURL(cfg.LAPIURL)
	if err != nil {
		return nil, errInvalidConfig
	}

	apiKey, err := readAPIKey(cfg.APIKeyFile)
	if err != nil {
		return nil, err
	}

	baseTransport := secureTransport(transport)
	bouncer := &csbouncer.StreamBouncer{
		APIKey:    apiKey,
		APIUrl:    baseURL.String(),
		Scopes:    []string{"ip", "range"},
		UserAgent: buildinfo.UserAgent(),
	}
	if cfg.UpdateFrequency > 0 {
		bouncer.TickerInterval = cfg.UpdateFrequency.String()
	} else {
		bouncer.TickerInterval = "10s"
	}
	disableSDKDiagnostics()
	if err := bouncer.Init(); err != nil {
		return nil, errors.New("crowdsec API client initialization failed")
	}
	if bouncer.APIClient == nil || bouncer.APIClient.GetClient() == nil {
		return nil, errors.New("crowdsec API client initialization failed")
	}
	apiHTTP := bouncer.APIClient.GetClient()
	auth, ok := apiHTTP.Transport.(*apiclient.APIKeyTransport)
	if !ok || auth == nil {
		return nil, errors.New("crowdsec API authentication initialization failed")
	}
	auth.Transport = baseTransport
	streamURL, err := baseURL.Parse("v1/decisions/stream")
	if err != nil {
		return nil, errors.New("crowdsec stream URL initialization failed")
	}
	// Retain SDK API-key authentication, not its full-response decoder.
	apiHTTP.Transport = auth
	apiHTTP.CheckRedirect = func(_ *http.Request, _ []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{
		bouncer:   bouncer,
		endpoint:  endpoint,
		transport: baseTransport,
		streamURL: streamURL,
		close:     make(chan struct{}),
	}, nil
}

// Endpoint returns the canonical LAPI identity with credentials removed.
func (c *Client) Endpoint() string {
	if c == nil {
		return ""
	}
	return c.endpoint
}

// SameAuthentication compares the captured endpoint and key without exposing
// credential material. Callers must separately establish transport identity.
func (c *Client) SameAuthentication(other *Client) bool {
	return c != nil && other != nil && c.bouncer != nil && other.bouncer != nil &&
		c.endpoint == other.endpoint && c.bouncer.APIKey == other.bouncer.APIKey
}

// SetRequestObserver installs an optional callback for completed LAPI polls.
// The observer receives only whether the stream was accepted, never response
// contents or error text.
func (c *Client) SetRequestObserver(observer func(success bool)) {
	if c == nil {
		return
	}
	c.mu.Lock()
	c.observeRequest = observer
	c.mu.Unlock()
}

// Close cancels an in-flight request and releases idle transport connections.
// It is safe to call repeatedly.
func (c *Client) Close() {
	if c == nil {
		return
	}
	c.mu.Lock()
	if !c.closed {
		c.closed = true
		close(c.close)
	}
	c.mu.Unlock()
	if transport, ok := c.transport.(interface{ CloseIdleConnections() }); ok {
		transport.CloseIdleConnections()
	}
}

// Poll fetches one complete stream envelope. startup is sent explicitly on
// every request, including false incremental polls.
func (c *Client) Poll(ctx context.Context, startup bool) (Batch, error) {
	if ctx == nil {
		return Batch{}, errors.New("crowdsec poll requires a context")
	}
	if c == nil {
		return Batch{}, errClientClosed
	}
	c.mu.Lock()
	closed := c.closed
	observer := c.observeRequest
	c.mu.Unlock()
	if closed {
		return Batch{}, errClientClosed
	}

	success := false
	if observer != nil {
		defer func() { observer(success) }()
	}

	started := time.Now()
	requestCtx, cancel := context.WithTimeout(ctx, requestLimit)
	defer cancel()
	requestCtx, stopClose := contextWithClose(requestCtx, c.close)
	defer stopClose()

	batch, err := c.pollStream(requestCtx, startup, started)
	if err != nil || requestCtx.Err() != nil {
		return Batch{}, sanitizeStreamError(err, requestCtx.Err(), c.isClosed())
	}
	success = true
	return batch, nil
}

func (c *Client) isClosed() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.closed
}

func contextWithClose(parent context.Context, closeCh <-chan struct{}) (context.Context, func()) {
	ctx, cancel := context.WithCancel(parent)
	done := make(chan struct{})
	go func() {
		select {
		case <-closeCh:
			cancel()
		case <-done:
		}
	}()
	return ctx, func() {
		close(done)
		cancel()
	}
}

func readAPIKey(path string) (string, error) {
	file, err := os.Open(path) // #nosec G304 -- the credential path is explicit operator configuration.
	if err != nil {
		return "", errors.New("crowdsec API key is unavailable")
	}
	defer func() { _ = file.Close() }()
	key, err := io.ReadAll(io.LimitReader(file, credentialLimit+1))
	if err != nil || len(key) > credentialLimit {
		return "", errors.New("crowdsec API key is unavailable")
	}
	key = []byte(strings.TrimSpace(string(key)))
	if len(key) == 0 {
		return "", errors.New("crowdsec API key is empty")
	}
	if strings.ContainsAny(string(key), "\r\n") {
		return "", errors.New("crowdsec API key contains invalid characters")
	}
	return string(key), nil
}

// CrowdSec's reviewed SDK uses logrus package globals for request and body
// diagnostics. Perimeterd uses slog, so suppress the SDK's process-wide raw
// diagnostics once rather than allowing credentials or decisions to escape.
func disableSDKDiagnostics() {
	sdkLogOnce.Do(func() {
		log.StandardLogger().SetOutput(io.Discard)
		log.StandardLogger().SetLevel(log.PanicLevel)
	})
}

func canonicalURL(raw string) (*url.URL, string, error) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Hostname() == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return nil, "", errInvalidConfig
	}
	u.User = nil
	u.Fragment = ""
	u.RawFragment = ""
	// A base URL's query is not part of the LAPI endpoint and can contain
	// accidental credentials. Stream options are added per request instead.
	u.RawQuery = ""
	if u.Path == "" {
		u.Path = "/"
	} else if !strings.HasSuffix(u.Path, "/") {
		u.Path += "/"
	}
	u.RawPath = ""
	return u, u.String(), nil
}

func secureTransport(transport http.RoundTripper) http.RoundTripper {
	if transport == nil {
		if base, ok := http.DefaultTransport.(*http.Transport); ok {
			clone := base.Clone()
			clone.DisableCompression = true
			return clone
		}
		return http.DefaultTransport
	}
	if base, ok := transport.(*http.Transport); ok {
		clone := base.Clone()
		clone.DisableCompression = true
		return clone
	}
	return transport
}

func convertDecision(decision *models.Decision, requestStart time.Time, retainExpired bool) (Decision, bool, error) {
	if decision == nil {
		return Decision{}, false, errors.New("decision is missing")
	}
	if decision.Type == nil || *decision.Type == "" {
		return Decision{}, false, errors.New("decision type is missing")
	}
	if *decision.Type != "ban" {
		return Decision{}, false, nil
	}
	if decision.Scope == nil || *decision.Scope == "" {
		return Decision{}, false, errors.New("decision scope is missing")
	}
	scope := strings.ToLower(*decision.Scope)
	if scope != "ip" && scope != "range" {
		return Decision{}, false, nil
	}
	if decision.ID <= 0 || decision.Value == nil || *decision.Value == "" {
		return Decision{}, false, errors.New("decision identity or value is invalid")
	}
	prefix, err := parseDecisionPrefix(scope, *decision.Value)
	if err != nil {
		return Decision{}, false, err
	}
	deadline, err := decisionDeadline(decision, requestStart)
	if err != nil {
		return Decision{}, false, err
	}
	if !deadline.After(time.Now()) {
		if retainExpired {
			return Decision{ID: decision.ID, Prefix: prefix, Deadline: deadline}, true, nil
		}
		return Decision{}, false, nil
	}
	return Decision{ID: decision.ID, Prefix: prefix, Deadline: deadline}, true, nil
}

func parseDecisionPrefix(scope, value string) (netip.Prefix, error) {
	if scope == "ip" {
		addr, err := netip.ParseAddr(value)
		if err != nil {
			return netip.Prefix{}, err
		}
		// Both Unmap and PrefixFrom discard zones; reject scoped authority first.
		if addr.Zone() != "" {
			return netip.Prefix{}, errors.New("scoped addresses are not allowed")
		}
		// LAPI accepts mapped IPv4 spellings as IPv4 authority. Canonicalize
		// source IPs here, without reinterpreting IPv6 projection residuals.
		addr = addr.Unmap()
		return netip.PrefixFrom(addr, addr.BitLen()).Masked(), nil
	}
	prefix, err := netip.ParsePrefix(value)
	if err != nil {
		return netip.Prefix{}, err
	}
	prefix = prefix.Masked()
	// Only a network wholly within the mapped /96 is IPv4 authority. Mask
	// first so broader IPv6 ranges that include that space retain their family.
	if prefix.Addr().Is4In6() {
		prefix = netip.PrefixFrom(prefix.Addr().Unmap(), prefix.Bits()-96)
	}
	return prefix, nil
}

func decisionDeadline(decision *models.Decision, requestStart time.Time) (time.Time, error) {
	if decision.Until != "" {
		var until time.Time
		if err := until.UnmarshalText([]byte(decision.Until)); err != nil {
			return time.Time{}, err
		}
		// Add the wall-clock interval to a monotonic request-start instant while
		// retaining the exact absolute wall-clock deadline.
		return requestStart.Add(until.Sub(requestStart)), nil
	}
	if decision.Duration == nil || *decision.Duration == "" {
		return time.Time{}, errors.New("decision expiry is missing")
	}
	duration, err := time.ParseDuration(*decision.Duration)
	if err != nil {
		return time.Time{}, err
	}
	if duration <= 0 {
		// Already expired. Subtracting slack from the minimum duration would
		// wrap into a future deadline and grant an unintended long-lived ban.
		return requestStart, nil
	}
	return requestStart.Add(duration - deadlineSlack), nil
}
