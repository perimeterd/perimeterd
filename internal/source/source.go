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

// SelectorSpec describes the authoritative source metadata for one canonical
// selector. It is intentionally declarative: Transport is the configured
// route, while records additionally capture the loaded transport generation.
type SelectorSpec struct {
	RefreshInterval time.Duration
	RequestTimeout  time.Duration
	RefreshJitter   time.Duration
	Transport       config.TransportConfig
	Endpoint        string
	SourceKind      string
	SourceName      string
	APIVersion      string
}

// DescribeSelector returns the source identity, endpoint, transport, and
// scheduling metadata for selector. Timing values are extracted without
// validating them; resolver fetch paths retain their existing validation
// timing and error semantics.
func DescribeSelector(cfg config.Config, selector policy.Selector) (SelectorSpec, error) {
	switch selector.Kind {
	case policy.IPList:
		list, ok := cfg.IPLists[selector.Value]
		if !ok {
			return SelectorSpec{}, fmt.Errorf("source: custom list %q is not configured", selector.Value)
		}
		endpoint, err := normalizeListURL(list.URL)
		if err != nil {
			return SelectorSpec{}, fmt.Errorf("source: custom list %q has invalid URL", selector.Value)
		}
		return SelectorSpec{
			RefreshInterval: list.RefreshInterval,
			RequestTimeout:  list.RequestTimeout,
			Transport:       list.Transport,
			Endpoint:        endpoint,
			SourceKind:      listSourceKind,
			SourceName:      selector.Value,
			APIVersion:      listFormatVersion,
		}, nil
	case policy.Provider:
		endpoint, err := providerEndpoint(selector.Value)
		if err != nil {
			return SelectorSpec{}, err
		}
		return SelectorSpec{
			RefreshInterval: cfg.Providers.RefreshInterval,
			RequestTimeout:  cfg.Providers.RequestTimeout,
			Endpoint:        endpoint,
			SourceKind:      providerSourceKind,
			SourceName:      selector.Value,
			APIVersion:      listFormatVersion,
		}, nil
	case policy.Country:
		return SelectorSpec{
			RefreshInterval: cfg.Geo.RefreshInterval,
			RequestTimeout:  cfg.Geo.RequestTimeout,
			RefreshJitter:   cfg.Geo.RefreshJitter,
			Endpoint:        countryEndpoint,
			SourceKind:      ripeSourceKind,
			APIVersion:      endpointVersions[countryEndpoint],
		}, nil
	case policy.ASN:
		return SelectorSpec{
			RefreshInterval: cfg.Geo.RefreshInterval,
			RequestTimeout:  cfg.Geo.RequestTimeout,
			RefreshJitter:   cfg.Geo.RefreshJitter,
			Endpoint:        asnEndpoint,
			SourceKind:      ripeSourceKind,
			APIVersion:      endpointVersions[asnEndpoint],
		}, nil
	default:
		return SelectorSpec{}, fmt.Errorf("source: unsupported source selector kind %q", selector.Kind)
	}
}

// RequiredIdentities returns the active OpenZiti identity profiles referenced
// by enabled custom-list policies and by enabled CrowdSec. It performs no
// credential or network I/O.
func RequiredIdentities(cfg config.Config) (map[string]config.OpenZitiIdentityConfig, error) {
	required := make(map[string]config.OpenZitiIdentityConfig)
	add := func(label string, transport config.TransportConfig) error {
		switch transport.Type {
		case "", upstream.TypeDirect:
			return nil
		case upstream.TypeOpenZiti:
			profile, ok := cfg.OpenZiti.Identities[transport.Identity]
			if !ok {
				return fmt.Errorf("source: %s references unknown OpenZiti identity %q", label, transport.Identity)
			}
			required[transport.Identity] = profile
			return nil
		default:
			return fmt.Errorf("source: %s uses unsupported transport %q", label, transport.Type)
		}
	}
	selectors, err := policy.RequiredSelectors(cfg)
	if err != nil {
		return nil, err
	}
	for _, selector := range selectors {
		if selector.Kind != policy.IPList {
			continue
		}
		list, ok := cfg.IPLists[selector.Value]
		if !ok {
			return nil, fmt.Errorf("source: custom list %q is not configured", selector.Value)
		}
		if err := add(fmt.Sprintf("custom list %q", selector.Value), list.Transport); err != nil {
			return nil, err
		}
	}
	if cfg.CrowdSec.Enabled {
		if err := add("enabled CrowdSec", cfg.CrowdSec.Transport); err != nil {
			return nil, err
		}
	}
	return required, nil
}

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
	cache          *Cache
	client         *http.Client
	slots          chan struct{}
	session        *upstream.Session
	observeRequest func(source string, success bool)
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

// WithRequestObserver returns an immutable resolver view that reports each
// selector fetch with a fixed source kind and success outcome. Observer values
// never include selector IDs, URLs, or error text.
func (r *Resolver) WithRequestObserver(observer func(source string, success bool)) *Resolver {
	if r == nil {
		return nil
	}
	view := *r
	view.observeRequest = observer
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
