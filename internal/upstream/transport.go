package upstream

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
)

type requestContextKey struct{}

type origin struct {
	scheme string
	host   string
}

// Binding returns the exact captured routing identity for route. Direct is a
// valid result even for a nil or empty session; OpenZiti never falls back to
// direct when its generation is absent.
func (s *Session) Binding(route config.TransportConfig) (Binding, error) {
	routeType := route.Type
	if routeType == "" {
		routeType = TypeDirect
	}
	if routeType == TypeDirect {
		binding := Binding{Type: TypeDirect}
		if route.Identity != "" || route.Service != "" {
			return Binding{}, errors.New("direct transport cannot select identity or service")
		}
		return binding, nil
	}
	if routeType != TypeOpenZiti {
		return Binding{}, fmt.Errorf("unsupported transport type %q", route.Type)
	}
	if strings.TrimSpace(route.Identity) == "" || strings.TrimSpace(route.Service) == "" {
		return Binding{}, errors.New("openziti transport requires identity and service")
	}
	if s == nil {
		return Binding{}, errors.New("openziti transport has no loaded session")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return Binding{}, errors.New("openziti session is closed")
	}
	gen := s.generations[route.Identity]
	if gen == nil {
		return Binding{}, fmt.Errorf("openziti identity %q is not loaded", route.Identity)
	}
	binding := gen.binding
	if binding.Service != "" {
		return Binding{}, errors.New("invalid captured openziti binding")
	}
	binding.Service = route.Service
	if err := binding.Validate(); err != nil {
		return Binding{}, errors.New("invalid captured openziti binding")
	}
	return binding, nil
}

// Transport creates an isolated application RoundTripper bound to one exact
// origin and one Ziti service. It intentionally rejects direct routes so the
// caller can preserve its existing direct HTTP client and redirect policy.
func (s *Session) Transport(route config.TransportConfig, applicationURL string) (http.RoundTripper, error) {
	if route.Type == "" || route.Type == TypeDirect {
		return nil, errors.New("direct transport has no dedicated round tripper")
	}
	if route.Type != TypeOpenZiti {
		return nil, fmt.Errorf("unsupported transport type %q", route.Type)
	}
	if s == nil {
		return nil, errors.New("openziti transport has no loaded session")
	}
	appOrigin, err := parseOrigin(applicationURL)
	if err != nil {
		return nil, err
	}

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return nil, errors.New("openziti session is closed")
	}
	gen := s.generations[route.Identity]
	if gen == nil {
		s.mu.Unlock()
		return nil, fmt.Errorf("openziti identity %q is not loaded", route.Identity)
	}
	if route.Service == "" {
		s.mu.Unlock()
		return nil, errors.New("openziti transport service is required")
	}
	binding := gen.binding
	binding.Service = route.Service
	if err := binding.Validate(); err != nil {
		s.mu.Unlock()
		return nil, errors.New("invalid captured openziti binding")
	}
	s.mu.Unlock()

	transport := &http.Transport{
		Proxy:                 nil,
		DialContext:           nil,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          16,
		MaxIdleConnsPerHost:   4,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	bound := &boundTransport{
		generation: gen,
		service:    route.Service,
		origin:     appOrigin,
		transport:  transport,
	}
	transport.DialContext = bound.dialContext
	gen.transportMu.Lock()
	if gen.transports == nil {
		gen.transportMu.Unlock()
		return nil, errors.New("openziti identity generation is closed")
	}
	gen.transports[transport] = struct{}{}
	gen.transportMu.Unlock()
	return bound, nil
}

type boundTransport struct {
	generation *generation
	service    string
	origin     origin
	transport  *http.Transport
}

// CloseIdleConnections releases this client's pool from generation tracking.
// A later RoundTrip can register it again, as required by the HTTP interface.
func (t *boundTransport) CloseIdleConnections() {
	t.generation.transportMu.Lock()
	delete(t.generation.transports, t.transport)
	t.generation.transportMu.Unlock()
	t.transport.CloseIdleConnections()
}

func (t *boundTransport) dialContext(ctx context.Context, network, address string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, errors.New("unsupported application network")
	}
	if original, ok := ctx.Value(requestContextKey{}).(context.Context); ok && original != nil {
		ctx = original
	}
	return t.generation.dial(ctx, t.service)
}

func (t *boundTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req == nil || req.URL == nil {
		return nil, errors.New("application request has no URL")
	}
	if err := ensureOrigin(req.URL, t.origin); err != nil {
		return nil, err
	}
	if req.Host != "" && req.Host != req.URL.Host {
		return nil, errors.New("application request authority is not allowed")
	}
	if err := req.Context().Err(); err != nil {
		return nil, err
	}
	if !t.generation.acquireOperation() {
		return nil, errors.New("openziti identity generation is closed")
	}
	t.generation.transportMu.Lock()
	if t.generation.transports == nil {
		t.generation.transportMu.Unlock()
		t.generation.release()
		return nil, errors.New("openziti identity generation is closed")
	}
	t.generation.transports[t.transport] = struct{}{}
	t.generation.transportMu.Unlock()
	ctx, cancel := context.WithCancel(req.Context())
	stop := context.AfterFunc(t.generation.ctx, cancel)
	release := func() {
		stop()
		cancel()
		t.generation.release()
	}
	request := req.Clone(context.WithValue(ctx, requestContextKey{}, ctx))
	response, err := t.transport.RoundTrip(request)
	if err != nil {
		release()
		return nil, err
	}
	if response == nil || response.Body == nil {
		release()
		return response, nil
	}
	response.Body = &releaseBody{ReadCloser: response.Body, release: release}
	return response, nil
}

type releaseBody struct {
	io.ReadCloser
	once    sync.Once
	release func()
}

func (b *releaseBody) Close() error {
	err := b.ReadCloser.Close()
	b.once.Do(b.release)
	return err
}

func parseOrigin(value string) (origin, error) {
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" || parsed.User != nil {
		return origin{}, errors.New("application URL must be an absolute HTTP(S) origin")
	}
	if parsed.Scheme != "http" && parsed.Scheme != "https" {
		return origin{}, errors.New("application URL must use HTTP or HTTPS")
	}
	return canonicalOrigin(parsed), nil
}

func canonicalOrigin(parsed *url.URL) origin {
	port := parsed.Port()
	if port == "" {
		if parsed.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return origin{
		scheme: strings.ToLower(parsed.Scheme),
		host:   strings.ToLower(parsed.Hostname()) + ":" + port,
	}
}

func ensureOrigin(value *url.URL, expected origin) error {
	if value.User != nil || (value.Scheme != "http" && value.Scheme != "https") {
		return errors.New("application request origin is not allowed")
	}
	if canonicalOrigin(value) != expected {
		return errors.New("application request origin is not allowed")
	}
	return nil
}
