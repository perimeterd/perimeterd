package upstream

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"strings"

	"github.com/perimeterd/perimeterd/internal/config"
)

const (
	// TypeDirect identifies ordinary host networking.
	TypeDirect = "direct"
	// TypeOpenZiti identifies an identity/service-bound SDK transport.
	TypeOpenZiti = "openziti"
)

// Binding is the non-secret, immutable routing identity of an upstream.
// IdentityGeneration identifies the captured credential generation without
// exposing credential material.
type Binding struct {
	Type               string `json:"type"`
	Identity           string `json:"identity,omitempty"`
	IdentityGeneration string `json:"identity_generation,omitempty"`
	Service            string `json:"service,omitempty"`
}

// Validate checks the canonical, non-secret binding shape.
func (b Binding) Validate() error {
	switch b.Type {
	case TypeDirect:
		if b.Identity != "" || b.IdentityGeneration != "" || b.Service != "" {
			return fmt.Errorf("direct binding cannot contain identity, generation, or service")
		}
	case TypeOpenZiti:
		if strings.TrimSpace(b.Identity) == "" {
			return fmt.Errorf("openziti binding identity is required")
		}
		if strings.TrimSpace(b.Service) == "" {
			return fmt.Errorf("openziti binding service is required")
		}
		if !validGeneration(b.IdentityGeneration) {
			return fmt.Errorf("openziti binding identity generation is malformed")
		}
	default:
		return fmt.Errorf("unsupported binding type %q", b.Type)
	}
	return nil
}

// MatchesConfig compares only declarative route fields and intentionally
// ignores the captured generation.
func (b Binding) MatchesConfig(route config.TransportConfig) bool {
	routeType := route.Type
	if routeType == "" {
		routeType = TypeDirect
	}
	if routeType != b.Type {
		return false
	}
	if routeType == TypeDirect {
		return route.Identity == "" && route.Service == "" && b.Validate() == nil
	}
	return b.Identity == route.Identity && b.Service == route.Service && b.Validate() == nil
}

func validGeneration(value string) bool {
	if len(value) != sha256.Size*2 {
		return false
	}
	if _, err := hex.DecodeString(value); err != nil {
		return false
	}
	return value == strings.ToLower(value)
}
