// Package source resolves static selectors into immutable cached snapshots.
package source

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"net/url"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/upstream"
)

const (
	ripeSourceKind     = "ripestat"
	listSourceKind     = "ip_list"
	providerSourceKind = "provider"
	listFormatVersion  = "1"
)

// providerEndpoint returns the fixed, documented feed URL for one provider
// identifier. Provider identifiers are syntax-validated by configuration and
// policy; the source layer repeats that check before constructing a request so
// this function cannot create an endpoint for an invalid identity.
func providerEndpoint(id string) (string, error) {
	if !config.ValidProviderID(id) {
		return "", fmt.Errorf("invalid provider ID %q", id)
	}
	return "https://cdn.jsdelivr.net/gh/rezmoss/cloud-provider-ip-addresses@main/" + id + "/" + id + "_ips_merged.txt", nil
}

// Record is one complete, validated static selector result. Prefix slices and
// Parameters are owned by the source layer; callers receive defensive copies
// from cache snapshots.
//
// SourceKind and SourceName are populated for custom lists and providers.
// Existing RIPEstat records leave SourceKind empty for on-disk compatibility.
type Record struct {
	Selector    policy.Selector
	SourceKind  string
	SourceName  string
	Endpoint    string
	APIVersion  string
	Parameters  map[string]string
	QueryStart  time.Time
	QueryEnd    time.Time
	RetrievedAt time.Time
	IPv4        []netip.Prefix
	IPv6        []netip.Prefix
	// Transport is the captured declarative and (for OpenZiti) generation
	// identity used to retrieve this record. The zero value is direct.
	Transport upstream.Binding
}

// Resolution is the result of one complete source transaction. RefreshError is
// populated only when the last committed manifest is returned as a stale,
// all-or-nothing fallback; in that case Resolve itself returns a nil error.
type Resolution struct {
	Snapshot     Snapshot
	RefreshError error
	// Attempted lists the complete due/missing transaction selected for fetch,
	// including selectors in a failed or rejected refresh.
	Attempted []policy.Selector
}

// Resolver fetches RIPEstat, provider, and custom-list data and stages complete
// immutable cache manifests.
type Resolver struct {
	cache   *Cache
	client  *http.Client
	slots   chan struct{}
	session *upstream.Session
}

// WithTransports returns an immutable resolver view using the captured
// transport session. Existing cache, direct HTTP client, and concurrency
// limits remain shared with the original resolver.
func (r *Resolver) WithTransports(session *upstream.Session) *Resolver {
	if r == nil {
		return nil
	}
	view := *r
	view.session = session
	return &view
}

// NewResolver constructs a resolver. A nil client uses the standard HTTPS
// client. Redirects are handled only for text-list requests; RIPEstat keeps
// its existing final-response behavior.
func NewResolver(cache *Cache, client *http.Client) *Resolver {
	if client == nil {
		client = http.DefaultClient
	}
	owned := *client
	owned.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if !isListRequest(req) {
			return http.ErrUseLastResponse
		}
		if len(via) > maxRedirects {
			return errors.New("too many redirects")
		}
		if err := validateListURL(req.URL); err != nil {
			return errors.New("invalid redirect target")
		}
		if len(via) > 0 && via[len(via)-1].URL.Scheme == "https" && req.URL.Scheme == "http" {
			return errors.New("redirect downgrade rejected")
		}
		if origin, _ := req.Context().Value(listOriginMarker{}).(string); origin != "" {
			parsed, err := url.Parse(origin)
			if err != nil || !sameURLOrigin(parsed, req.URL) {
				return errors.New("redirect origin changed")
			}
		}
		return nil
	}
	return &Resolver{cache: cache, client: &owned, slots: make(chan struct{}, maxConcurrent)}
}

// Resolve obtains every selector required by enabled policies and stages one
// immutable snapshot. Only a committed manifest is considered for reuse or
// stale fallback; the cache directory is never scanned to discover candidates.
func (r *Resolver) Resolve(ctx context.Context, cfg config.Config, committedManifest string, allowStale bool) (Resolution, error) {
	return r.resolve(ctx, cfg, committedManifest, allowStale)
}

// ValidateConfig reports whether this snapshot is an exact, identity-matching
// source result for cfg. It is intentionally independent of policy compilation
// so callers can use it at recovery and publication boundaries.
func (s Snapshot) ValidateConfig(cfg config.Config) error {
	required, err := policy.RequiredSelectors(cfg)
	if err != nil {
		return err
	}
	if len(s.records) != len(required) {
		return fmt.Errorf("source snapshot selector coverage mismatch")
	}
	for index, selector := range required {
		record := s.records[index]
		if record.Selector != selector {
			return fmt.Errorf("source snapshot selector coverage mismatch")
		}
		if !recordMatchesConfig(record, cfg) {
			return fmt.Errorf("source snapshot identity mismatch for %s/%s", selector.Kind, selector.Value)
		}
	}
	return nil
}

func (r *Resolver) bindingForRoute(route config.TransportConfig) (upstream.Binding, error) {
	if r == nil || r.session == nil {
		if route.Type == "" || route.Type == upstream.TypeDirect {
			return upstream.Binding{}, nil
		}
		return upstream.Binding{}, errors.New("source: OpenZiti transport session is required")
	}
	binding, err := r.session.Binding(route)
	if err != nil {
		return upstream.Binding{}, err
	}
	if binding.Type == upstream.TypeDirect {
		return upstream.Binding{}, nil
	}
	return binding, nil
}

const (
	maxConcurrent = 4
	maxSelectors  = 512
	maxBodyBytes  = 32 << 20
	maxRedirects  = 10

	countryEndpoint = "https://stat.ripe.net/data/country-resource-list/data.json"
	asnEndpoint     = "https://stat.ripe.net/data/announced-prefixes/data.json"
)

var endpointVersions = map[string]string{
	countryEndpoint: "0.2",
	asnEndpoint:     "1.2",
}
