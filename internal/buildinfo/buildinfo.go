// Package buildinfo owns metadata injected by release and development builds.
package buildinfo

import "strings"

// Version, Commit, and BuildTime are replaced by builds through ldflags.
// Keep these values unchanged for CLI and metrics provenance.
var (
	Version   = "dev"
	Commit    = "unknown"
	BuildTime = "unknown"
)

// UserAgent identifies the actual build to CrowdSec. LAPI v1.8.1 splits the
// identifier on '/' and requires exactly two parts. Restrict the version to
// product-token characters as well, so unusual local metadata cannot introduce
// extra parts, whitespace, or invalid HTTP header bytes. CLI metadata stays raw.
func UserAgent() string {
	version := strings.Map(func(r rune) rune {
		if r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("._+-", r) {
			return r
		}
		return '-'
	}, Version)
	if version == "" {
		version = "dev"
	}
	return "perimeterd/" + version
}
