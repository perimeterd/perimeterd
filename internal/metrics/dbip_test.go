package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestDBIPBoundedCommittedMetrics(t *testing.T) {
	collector := New("test", "commit", "time")
	collector.SourceRequest("dbip-lite", true)
	collector.SourceRequest("dbip-lite/2026-10/SK", false)
	collector.SetPrefixes([]PrefixCount{{Family: "ipv4", Source: "dbip-lite", Type: "country", Count: 2}, {Family: "ipv4", Source: "ripestat", Type: "asn", Count: 3}})
	response := httptest.NewRecorder()
	collector.Handler(nil, func() PrefixTimestamps { return PrefixTimestamps{DBIPLite: 1234567890, RIPestat: 1234567880} }, nil).ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	body := response.Body.String()
	for _, sample := range []struct {
		name   string
		labels map[string]string
		value  string
	}{
		{"perimeterd_source_requests_total", map[string]string{"source": "dbip-lite", "result": "success"}, "1"},
		{"perimeterd_prefixes", map[string]string{"family": "ipv4", "source": "dbip-lite", "type": "country"}, "2"},
		{"perimeterd_prefixes", map[string]string{"family": "ipv4", "source": "ripestat", "type": "asn"}, "3"},
		{"perimeterd_prefix_snapshot_timestamp_seconds", map[string]string{"source": "dbip-lite"}, "1.23456789e+09"},
	} {
		if !hasSample(body, sample.name, sample.labels, sample.value) {
			t.Fatalf("missing sample %+v: %s", sample, body)
		}
	}
	if strings.Contains(body, "2026-10") || strings.Contains(body, "SK") {
		t.Fatalf("unbounded provenance escaped into metrics: %s", body)
	}
}
