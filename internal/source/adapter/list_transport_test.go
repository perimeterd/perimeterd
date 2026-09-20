package adapter_test

import (
	"bytes"
	"compress/gzip"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
)

func newHTTPListResolver(t *testing.T, client *http.Client) *source.Resolver {
	t.Helper()
	cache, err := source.NewCache(filepath.Join(t.TempDir(), "state"), nil)
	if err != nil {
		t.Fatal(err)
	}
	return source.NewResolver(cache, client)
}

func TestCustomListNormalizesTextAndRejectsInvalidResponses(t *testing.T) {
	for _, tc := range []struct {
		name      string
		body      string
		status    int
		truncated bool
		valid     bool
	}{
		{name: "normalized", body: " # comment\r\n\t8.8.8.42/24 \r\n8.8.8.8\n8.8.8.0/24\n2001:4860::42/32\n2001:4860::1", status: 200, valid: true},
		{name: "empty", status: 200},
		{name: "comments", body: "# only comments\r\n \t\r\n", status: 200},
		{name: "invalid-utf8", body: "8.8.8.8\n#\xff", status: 200},
		{name: "inline-comment", body: "8.8.8.8 # no inline comments\n", status: 200},
		{name: "invalid-disabled-ipv6", body: "8.8.8.8\n2001:db8::/129\n", status: 200},
		{name: "zone", body: "8.8.8.8\nfe80::1%eth0\n", status: 200},
		{name: "unsolicited-304", status: 304},
		{name: "no-content", status: 204},
		{name: "truncated", body: "8.8.8.8\n", status: 200, truncated: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				if tc.truncated {
					w.Header().Set("Content-Length", "100")
				}
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			}))
			defer server.Close()
			cfg := listSourceConfig(server.URL, nil, []string{"feed"})
			cfg.Firewall.IPv6 = false
			result, err := newHTTPListResolver(t, server.Client()).Resolve(t.Context(), cfg, "", false)
			if !tc.valid {
				if err == nil || result.Snapshot.ManifestID() != "" {
					t.Fatalf("invalid complete response was published: %v, %v", result, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			set, _ := result.Snapshot.Policy().Lookup(policy.Selector{Kind: policy.IPList, Value: "feed"})
			var got []string
			for _, prefix := range set.Prefixes() {
				got = append(got, prefix.String())
			}
			if want := []string{"8.8.8.0/24", "2001:4860::/32"}; !reflect.DeepEqual(got, want) {
				t.Fatalf("normalized complete list = %v, want %v", got, want)
			}
		})
	}
}

func TestCustomListTLSVerificationAndRedirectTransport(t *testing.T) {
	var downgraded atomic.Int64
	var upgradeURL atomic.Value
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/upgrade" {
			http.Redirect(w, r, upgradeURL.Load().(string), http.StatusFound)
			return
		}
		downgraded.Add(1)
		_, _ = io.WriteString(w, "8.8.8.8\n")
	}))
	defer plain.Close()
	tlsServer := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/downgrade" {
			http.Redirect(w, r, plain.URL, http.StatusFound)
			return
		}
		_, _ = io.WriteString(w, "8.8.8.8\n")
	}))
	defer tlsServer.Close()
	tlsURL := tlsServer.URL
	upgradeURL.Store(tlsURL)
	cfg := listSourceConfig(tlsURL+"?token=private-query", nil, []string{"feed"})
	if _, err := newHTTPListResolver(t, nil).Resolve(t.Context(), cfg, "", false); err == nil {
		t.Fatal("untrusted TLS certificate accepted")
	} else if strings.Contains(err.Error(), "private-query") || strings.Contains(err.Error(), tlsURL) {
		t.Fatalf("TLS error leaked source URL: %v", err)
	}
	trusted := newHTTPListResolver(t, tlsServer.Client())
	if _, err := trusted.Resolve(t.Context(), cfg, "", false); err != nil {
		t.Fatalf("trusted HTTPS source rejected: %v", err)
	}
	cfg = listSourceConfig(tlsURL+"/downgrade", nil, []string{"feed"})
	if _, err := trusted.Resolve(t.Context(), cfg, "", false); err == nil || downgraded.Load() != 0 {
		t.Fatalf("HTTPS downgrade reached insecure endpoint: %v requests=%d", err, downgraded.Load())
	}
	cfg = listSourceConfig(plain.URL+"/upgrade", nil, []string{"feed"})
	if _, err := trusted.Resolve(t.Context(), cfg, "", false); err != nil {
		t.Fatalf("HTTP to trusted HTTPS upgrade rejected: %v", err)
	}
}

func TestCustomListBoundsDecodedBodyAndRequestDuration(t *testing.T) {
	const limit = 32 << 20
	for _, size := range []int{limit, limit + 1} {
		t.Run(fmt.Sprintf("decoded-bytes-%d", size), func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.Header().Set("Content-Encoding", "gzip")
				compressed := gzip.NewWriter(w)
				defer func() { _ = compressed.Close() }()
				start := "8.8.8.8\n#"
				_, _ = io.WriteString(compressed, start)
				chunk := bytes.Repeat([]byte("x"), 64<<10)
				for remaining := size - len(start); remaining > 0; {
					n := min(remaining, len(chunk))
					if _, err := compressed.Write(chunk[:n]); err != nil {
						return
					}
					remaining -= n
				}
			}))
			defer server.Close()
			cfg := listSourceConfig(server.URL, nil, []string{"feed"})
			list := cfg.IPLists["feed"]
			list.RequestTimeout = 10 * time.Second
			cfg.IPLists["feed"] = list
			result, err := newHTTPListResolver(t, server.Client()).Resolve(t.Context(), cfg, "", false)
			if size == limit && err != nil {
				t.Fatalf("valid response at decoded limit rejected: %v", err)
			}
			if size > limit && (err == nil || result.Snapshot.ManifestID() != "") {
				t.Fatalf("oversized compressed response accepted: %v", err)
			}
		})
	}
	t.Run("request-timeout", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
			<-r.Context().Done()
		}))
		defer server.Close()
		cfg := listSourceConfig(server.URL, nil, []string{"feed"})
		list := cfg.IPLists["feed"]
		list.RequestTimeout = 10 * time.Millisecond
		cfg.IPLists["feed"] = list
		if result, err := newHTTPListResolver(t, server.Client()).Resolve(t.Context(), cfg, "", false); err == nil || result.Snapshot.ManifestID() != "" {
			t.Fatalf("timed-out request published a snapshot: %v", err)
		}
	})
}
