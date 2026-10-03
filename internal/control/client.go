package control

import (
	"context"
	"net"
	"net/http"
	"time"
)

// UnixClient never follows redirects or reuses connections. POST requests are
// not automatically retried by net/http on these fresh connections.
func UnixClient(path string, timeout time.Duration) (*http.Client, func()) {
	transport := &http.Transport{DisableKeepAlives: true, DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
		return (&net.Dialer{Timeout: timeout}).DialContext(ctx, "unix", path)
	}}
	return &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}, transport.CloseIdleConnections
}
