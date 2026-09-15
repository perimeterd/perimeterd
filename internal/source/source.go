// Package source resolves RIPEstat selectors into immutable cached snapshots.
package source

import (
	"context"
	"net/http"
	"net/netip"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

// Record is one complete, validated RIPEstat selector result. Prefix slices and
// Parameters are owned by the source layer; callers receive defensive copies
// from cache snapshots.
type Record struct {
	Selector    policy.Selector
	Endpoint    string
	APIVersion  string
	Parameters  map[string]string
	QueryStart  time.Time
	QueryEnd    time.Time
	RetrievedAt time.Time
	IPv4        []netip.Prefix
	IPv6        []netip.Prefix
}

// Resolution is the result of one complete source transaction. RefreshError is
// populated only when the last committed manifest is returned as a stale,
// all-or-nothing fallback; in that case Resolve itself returns a nil error.
type Resolution struct {
	Snapshot     Snapshot
	RefreshError error
}

// Resolver fetches RIPEstat data and stages complete immutable cache manifests.
type Resolver struct {
	cache  *Cache
	client *http.Client
	slots  chan struct{}
}

// NewResolver constructs a resolver. A nil client uses the standard HTTPS
// client and is intentionally not configurable through user configuration.
func NewResolver(cache *Cache, client *http.Client) *Resolver {
	if client == nil {
		client = http.DefaultClient
	}
	owned := *client
	owned.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Resolver{cache: cache, client: &owned, slots: make(chan struct{}, maxConcurrent)}
}

// Resolve obtains every selector required by enabled policies and stages one
// immutable snapshot. Only a committed manifest is considered for reuse or
// stale fallback; the cache directory is never scanned to discover candidates.
func (r *Resolver) Resolve(ctx context.Context, cfg config.Config, committedManifest string, allowStale bool) (Resolution, error) {
	return r.resolve(ctx, cfg, committedManifest, allowStale)
}

const (
	maxConcurrent = 4
	maxSelectors  = 512
	maxBodyBytes  = 32 << 20

	countryEndpoint = "https://stat.ripe.net/data/country-resource-list/data.json"
	asnEndpoint     = "https://stat.ripe.net/data/announced-prefixes/data.json"
)

var endpointVersions = map[string]string{
	countryEndpoint: "0.2",
	asnEndpoint:     "1.2",
}
