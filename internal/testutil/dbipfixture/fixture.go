// Package dbipfixture supplies synthetic, sorted dual-stack country data for
// native integration tests. It contains no redistributed vendor database rows.
package dbipfixture

import (
	"bytes"
	"compress/gzip"
	"errors"
	"net/http"
	"net/url"
	"strings"
)

// CSV is a complete synthetic artifact, including unselected countries and the
// vendor extensions. Gaps are intentional; no row is a live geolocation claim.
const CSV = "8.20.0.0,8.20.0.255,US\n8.21.0.0,8.21.0.255,JP\n8.22.0.0,8.22.0.255,TW\n8.23.0.0,8.23.0.255,IR\n8.24.0.0,8.24.0.255,XK\n8.25.0.0,8.25.0.255,ZZ\n2600:20::,2600:20::ffff:ffff:ffff:ffff,US\n2600:21::,2600:21::ffff:ffff:ffff:ffff,JP\n2600:22::,2600:22::ffff:ffff:ffff:ffff,TW\n2600:23::,2600:23::ffff:ffff:ffff:ffff,IR\n"

// Gzip encodes an entire artifact, including its checksum/trailer.
func Gzip(csv string) ([]byte, error) {
	var body bytes.Buffer
	writer := gzip.NewWriter(&body)
	if _, err := writer.Write([]byte(csv)); err != nil {
		return nil, err
	}
	if err := writer.Close(); err != nil {
		return nil, err
	}
	return body.Bytes(), nil
}

// Transport redirects only fixed vendor endpoints to an isolated loopback
// fixture server. Production requests still traverse the real source parser.
// Origin must be an httptest HTTP origin; no external network is permitted.
type Transport struct{ Origin *url.URL }

// RoundTrip routes a fixed source request to its loopback test fixture.
func (f Transport) RoundTrip(request *http.Request) (*http.Response, error) {
	if f.Origin == nil || f.Origin.Scheme != "http" || f.Origin.Hostname() != "127.0.0.1" {
		return nil, errors.New("DB-IP fixture requires a loopback HTTP origin")
	}
	path := ""
	switch {
	case request.URL.Scheme == "https" && request.URL.Host == "download.db-ip.com" && strings.HasPrefix(request.URL.Path, "/free/dbip-country-lite-") && strings.HasSuffix(request.URL.Path, ".csv.gz"):
		path = "/dbip"
	case request.URL.Scheme == "https" && request.URL.Host == "stat.ripe.net" && request.URL.Path == "/data/country-resource-list/data.json":
		path = "/country"
	case request.URL.Scheme == "https" && request.URL.Host == "stat.ripe.net" && request.URL.Path == "/data/announced-prefixes/data.json":
		path = "/asn"
	case request.URL.Scheme == "http" && request.URL.Host == f.Origin.Host:
		path = request.URL.Path
	default:
		return nil, errors.New("DB-IP fixture refuses external source")
	}
	forwarded := request.Clone(request.Context())
	endpoint := *f.Origin
	endpoint.Path, endpoint.RawQuery = path, request.URL.RawQuery
	forwarded.URL, forwarded.Host = &endpoint, endpoint.Host
	return http.DefaultTransport.RoundTrip(forwarded)
}
