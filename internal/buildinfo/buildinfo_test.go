package buildinfo

import (
	"regexp"
	"strings"
	"testing"
)

func TestUserAgentUsesBuildVersion(t *testing.T) {
	original := Version
	t.Cleanup(func() { Version = original })
	cases := []struct {
		version string
		want    string
	}{
		{version: "v1.2.3", want: "perimeterd/v1.2.3"},
		{version: "0.0.2-dev.18.g8a1af5acc7cf", want: "perimeterd/0.0.2-dev.18.g8a1af5acc7cf"},
		{version: "1.2.3+local", want: "perimeterd/1.2.3+local"},
		{version: "dev", want: "perimeterd/dev"},
		{version: "", want: "perimeterd/dev"},
		{version: "branch/feature build\r\n雪", want: "perimeterd/branch-feature-build---"},
	}
	product := regexp.MustCompile(`^perimeterd/[A-Za-z0-9._+\-]+$`)
	for _, tc := range cases {
		t.Run(tc.version, func(t *testing.T) {
			Version = tc.version
			got := UserAgent()
			if got != tc.want {
				t.Fatalf("UserAgent() = %q, want %q", got, tc.want)
			}
			// This is the exact shape required by pinned LAPI's middleware.
			if parts := strings.Split(got, "/"); len(parts) != 2 || parts[0] != "perimeterd" || parts[1] == "" {
				t.Fatalf("LAPI cannot identify build from %q", got)
			}
			if !product.MatchString(got) {
				t.Fatalf("User-Agent is not a safe HTTP product token: %q", got)
			}
			if Version != tc.version {
				t.Fatalf("UserAgent changed raw build metadata: %q", Version)
			}
		})
	}
}
