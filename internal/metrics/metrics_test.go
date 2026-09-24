package metrics

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func scrapeMetrics(t *testing.T, collector *Collector) string {
	t.Helper()
	response := httptest.NewRecorder()
	collector.Handler(nil, nil, nil).ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
	if response.Code != 200 {
		t.Fatalf("metrics scrape status = %d", response.Code)
	}
	return response.Body.String()
}

func hasSample(body, name string, wantLabels map[string]string, wantValue string) bool {
	for _, line := range strings.Split(body, "\n") {
		prefix := name + "{"
		if !strings.HasPrefix(line, prefix) {
			continue
		}
		end := strings.IndexByte(line[len(prefix):], '}')
		if end < 0 {
			continue
		}
		labels := make(map[string]string)
		for _, raw := range strings.Split(line[len(prefix):len(prefix)+end], ",") {
			key, value, ok := strings.Cut(raw, "=")
			if !ok {
				continue
			}
			labels[key] = strings.Trim(value, "\"")
		}
		if len(labels) != len(wantLabels) {
			continue
		}
		matched := true
		for key, value := range wantLabels {
			if labels[key] != value {
				matched = false
				break
			}
		}
		if matched && strings.TrimSpace(line[len(prefix)+end+1:]) == wantValue {
			return true
		}
	}
	return false
}

func TestCollectorExportsBoundedOutcomeAndSnapshotGauges(t *testing.T) {
	collector := New(strings.Repeat("v", 256), "commit", "build")
	collector.ConfigReload("success")
	collector.ConfigReload("operator-input")
	collector.Reconcile("config", "success", 25*time.Millisecond)
	collector.SourceRequest("ripestat", true)
	collector.SourceRequest("crowdsec", true)
	collector.SourceRequest("country-secret", false)
	collector.BackendApply("nftables", true)
	collector.SetPrefixes([]PrefixCount{
		{Family: "ipv4", Source: "ripestat", Type: "country", Count: 3},
		{Family: "ipv6", Source: "unbounded", Type: "country", Count: 99},
	})
	collector.SetCrowdSecDecisions(4, 2)

	body := scrapeMetrics(t, collector)
	for _, expected := range []string{
		"perimeterd_build_info",
		"version=\"" + strings.Repeat("v", 128) + "\"",
		"perimeterd_reconcile_duration_seconds_count{reason=\"config\"} 1",
	} {
		if !strings.Contains(body, expected) {
			t.Errorf("metrics exposition does not contain %q", expected)
		}
	}
	for _, sample := range []struct {
		name   string
		labels map[string]string
		value  string
	}{
		{"perimeterd_config_reload_total", map[string]string{"result": "success"}, "1"},
		{"perimeterd_config_reload_total", map[string]string{"result": "error"}, "1"},
		{"perimeterd_reconcile_total", map[string]string{"reason": "config", "result": "success"}, "1"},
		{"perimeterd_source_requests_total", map[string]string{"result": "success", "source": "ripestat"}, "1"},
		{"perimeterd_source_requests_total", map[string]string{"result": "error", "source": "unknown"}, "1"},
		{"perimeterd_source_requests_total", map[string]string{"result": "success", "source": "crowdsec"}, "1"},
		{"perimeterd_backend_apply_total", map[string]string{"backend": "nftables", "result": "success"}, "1"},
		{"perimeterd_prefixes", map[string]string{"family": "ipv4", "source": "ripestat", "type": "country"}, "3"},
		{"perimeterd_crowdsec_decisions", map[string]string{"family": "ipv4"}, "4"},
		{"perimeterd_crowdsec_decisions", map[string]string{"family": "ipv6"}, "2"},
	} {
		if !hasSample(body, sample.name, sample.labels, sample.value) {
			t.Errorf("metrics exposition is missing %s with labels %v and value %s", sample.name, sample.labels, sample.value)
		}
	}
	if strings.Contains(body, "country-secret") || strings.Contains(body, "source=\"unbounded\"") {
		t.Fatalf("unbounded source label escaped: %s", body)
	}
}

func TestPrefixScrapesSeeCompletePublishedSnapshot(t *testing.T) {
	collector := New("test", "commit", "time")
	first := []PrefixCount{
		{Family: "ipv4", Source: "local", Type: "local", Count: 3},
		{Family: "ipv6", Source: "global", Type: "allowlist", Count: 3},
		{Family: "ipv4", Source: "ripestat", Type: "country", Count: 3},
	}
	second := []PrefixCount{
		{Family: "ipv4", Source: "local", Type: "local", Count: 5},
		{Family: "ipv6", Source: "global", Type: "allowlist", Count: 5},
		{Family: "ipv4", Source: "ripestat", Type: "country", Count: 5},
	}
	collector.SetPrefixes(first)
	stop := make(chan struct{})
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
				collector.SetPrefixes(second)
				collector.SetPrefixes(first)
			}
		}
	}()
	defer func() {
		close(stop)
		<-done
	}()
	handler := collector.Handler(nil, nil, nil)
	labels := []map[string]string{
		{"family": "ipv4", "source": "local", "type": "local"},
		{"family": "ipv6", "source": "global", "type": "allowlist"},
		{"family": "ipv4", "source": "ripestat", "type": "country"},
	}
	for range 1000 {
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, httptest.NewRequest("GET", "/metrics", nil))
		if response.Code != 200 {
			t.Fatalf("metrics scrape status = %d", response.Code)
		}
		body := response.Body.String()
		if got := strings.Count(body, "perimeterd_prefixes{"); got != len(labels) {
			t.Fatalf("scrape contains %d of %d prefix series: %s", got, len(labels), body)
		}
		consistent := false
		for _, value := range []string{"3", "5"} {
			complete := true
			for _, label := range labels {
				complete = complete && hasSample(body, "perimeterd_prefixes", label, value)
			}
			if complete {
				consistent = true
				break
			}
		}
		if !consistent {
			t.Fatalf("scrape contains a mixed prefix snapshot: %s", body)
		}
	}
}

func TestCounterActivationWaitsForCompleteReadAfterFailure(t *testing.T) {
	collector := New("test", "commit", "time")
	at := func(second int64) time.Time { return time.Unix(second, 0) }
	active := CounterSample{
		Backend: "iptables", Rule: "active", Family: "ipv4", Direction: "ingress",
		ProcessedPackets: 10, Current: true,
	}
	labels := map[string]string{"backend": "iptables", "family": "ipv4", "direction": "ingress"}
	collector.BeginCounterCollection()
	collector.CounterReadFailed("iptables")
	retired := active
	retired.Rule = "retired"
	retired.Current = false
	retired.ProcessedPackets = 900
	collector.CounterRetired("iptables", []CounterSample{retired}, at(101))
	active.ProcessedPackets = 100
	collector.CounterSnapshot("iptables", []CounterSample{active}, at(102))
	body := scrapeMetrics(t, collector)
	if strings.Contains(body, "perimeterd_firewall_processed_packets_total{") {
		t.Fatalf("first successful complete read imported pre-activation traffic: %s", body)
	}
	active.ProcessedPackets = 110
	collector.CounterSnapshot("iptables", []CounterSample{active}, at(103))
	if body = scrapeMetrics(t, collector); !hasSample(body, "perimeterd_firewall_processed_packets_total", labels, "10") {
		t.Fatalf("post-activation delta not counted: %s", body)
	}

	// Collection stops while native counters keep running. A failed priming
	// attempt must neither reuse the old baseline nor count a retired read.
	collector.BeginCounterCollection()
	collector.CounterReadFailed("iptables")
	retired.ProcessedPackets = 10000
	collector.CounterRetired("iptables", []CounterSample{retired}, at(104))
	active.ProcessedPackets = 10110
	collector.CounterSnapshot("iptables", []CounterSample{active}, at(105))
	body = scrapeMetrics(t, collector)
	if !hasSample(body, "perimeterd_firewall_processed_packets_total", labels, "10") {
		t.Fatalf("disabled-window traffic leaked into total: %s", body)
	}
	active.ProcessedPackets = 10115
	collector.CounterSnapshot("iptables", []CounterSample{active}, at(106))
	body = scrapeMetrics(t, collector)
	if !hasSample(body, "perimeterd_firewall_processed_packets_total", labels, "15") {
		t.Fatalf("post-reactivation delta not counted: %s", body)
	}
	if !hasSample(body, "perimeterd_firewall_counter_read_total", map[string]string{"backend": "iptables", "result": "error"}, "2") {
		t.Fatalf("failed activation reads not recorded: %s", body)
	}
}

func TestCounterSnapshotsMergeRetiredAndResetCountersMonotonically(t *testing.T) {
	collector := New("test", "commit", "time")
	at := func(second int64) time.Time { return time.Unix(second, 0) }
	collector.BeginCounterCollection()
	collector.CounterSnapshot("iptables", []CounterSample{{
		Backend: "iptables", Generation: "old", Rule: "old-denial-rule",
		Family: "ipv4", Direction: "ingress", Reason: "geo_policy", Action: "drop",
		ProcessedPackets: 100, ProcessedBytes: 1000, DeniedPackets: 10, DeniedBytes: 100,
		Current: true,
	}}, at(100))
	collector.CounterSnapshot("iptables", []CounterSample{{
		Backend: "iptables", Generation: "old", Rule: "old-denial-rule",
		Family: "ipv4", Direction: "ingress", Reason: "geo_policy", Action: "drop",
		ProcessedPackets: 107, ProcessedBytes: 1070, DeniedPackets: 12, DeniedBytes: 120,
		Current: true,
	}}, at(101))
	collector.CounterRetired("iptables", []CounterSample{{
		Backend: "iptables", Generation: "old", Rule: "old-denial-rule",
		Family: "ipv4", Direction: "ingress", Reason: "geo_policy", Action: "drop",
		ProcessedPackets: 110, ProcessedBytes: 1100, DeniedPackets: 15, DeniedBytes: 150,
	}}, at(102))
	collector.CounterSnapshot("iptables", []CounterSample{{
		Backend: "iptables", Generation: "new", Rule: "new-denial-rule",
		Family: "ipv4", Direction: "ingress", Reason: "geo_policy", Action: "drop",
		ProcessedPackets: 2, ProcessedBytes: 20, DeniedPackets: 2, DeniedBytes: 20,
		Current: true,
	}}, at(103))
	collector.CounterSnapshot("iptables", []CounterSample{{
		Backend: "iptables", Generation: "new", Rule: "new-denial-rule",
		Family: "ipv4", Direction: "ingress", Reason: "geo_policy", Action: "drop",
		ProcessedPackets: 1, ProcessedBytes: 10, DeniedPackets: 1, DeniedBytes: 10,
		Current: true,
	}}, at(104))
	collector.CounterReadFailed("iptables")

	body := scrapeMetrics(t, collector)
	for _, sample := range []struct {
		name   string
		labels map[string]string
		value  string
	}{
		{"perimeterd_firewall_processed_packets_total", map[string]string{"backend": "iptables", "direction": "ingress", "family": "ipv4"}, "13"},
		{"perimeterd_firewall_processed_bytes_total", map[string]string{"backend": "iptables", "direction": "ingress", "family": "ipv4"}, "130"},
		{"perimeterd_firewall_denied_packets_total", map[string]string{"action": "drop", "backend": "iptables", "direction": "ingress", "family": "ipv4", "reason": "geo_policy"}, "8"},
		{"perimeterd_firewall_counter_read_total", map[string]string{"backend": "iptables", "result": "success"}, "5"},
		{"perimeterd_firewall_counter_read_total", map[string]string{"backend": "iptables", "result": "error"}, "1"},
		{"perimeterd_firewall_counter_timestamp_seconds", map[string]string{"backend": "iptables"}, "104"},
	} {
		if !hasSample(body, sample.name, sample.labels, sample.value) {
			t.Errorf("metrics exposition is missing %s with labels %v and value %s", sample.name, sample.labels, sample.value)
		}
	}
	if strings.Contains(body, "old-denial-rule") || strings.Contains(body, "generation=") {
		t.Fatalf("internal counter identities escaped as labels: %s", body)
	}
}

func TestSharedCounterRetirementAddsOnlyPostSnapshotDelta(t *testing.T) {
	collector := New("test", "commit", "time")
	collector.BeginCounterCollection()
	collector.CounterSnapshot("nftables", []CounterSample{{
		Backend: "nftables", Generation: "old", Rule: "table/shared-counter",
		Family: "ipv6", Direction: "egress", ProcessedPackets: 100,
		Current: true,
	}}, time.Unix(100, 0))
	collector.CounterRetired("nftables", []CounterSample{{
		Backend: "nftables", Generation: "old", Rule: "table/shared-counter",
		Family: "ipv6", Direction: "egress", ProcessedPackets: 115,
	}}, time.Unix(101, 0))
	collector.CounterSnapshot("nftables", []CounterSample{{
		Backend: "nftables", Generation: "new", Rule: "table/shared-counter",
		Family: "ipv6", Direction: "egress", ProcessedPackets: 120,
		Current: true,
	}}, time.Unix(102, 0))

	body := scrapeMetrics(t, collector)
	labels := map[string]string{"backend": "nftables", "direction": "egress", "family": "ipv6"}
	if !hasSample(body, "perimeterd_firewall_processed_packets_total", labels, "20") {
		t.Fatalf("shared counter total does not include just the final delta: %s", body)
	}
	if got := strings.Count(body, "perimeterd_firewall_processed_packets_total{"); got != 1 {
		t.Fatalf("shared counter created duplicate time series: count %d", got)
	}
}

func TestCounterMetricsNeverExposeRawIdentitiesOrDenyLabels(t *testing.T) {
	collector := New("test", "commit", "time")
	initial := CounterSample{
		Backend: "provider-secret", Generation: "generation-secret", Rule: "rule-secret",
		Family: "ipv4", Direction: "ingress", Reason: "country-secret", Action: "operator-value",
		ProcessedPackets: 10, DeniedPackets: 7, Current: true,
	}
	collector.BeginCounterCollection()
	collector.CounterSnapshot("provider-secret", []CounterSample{initial}, time.Unix(100, 0))
	initial.ProcessedPackets = 13
	initial.DeniedPackets = 10
	collector.CounterSnapshot("provider-secret", []CounterSample{initial}, time.Unix(101, 0))

	body := scrapeMetrics(t, collector)
	labels := map[string]string{"backend": "unknown", "direction": "ingress", "family": "ipv4"}
	if !hasSample(body, "perimeterd_firewall_processed_packets_total", labels, "3") {
		t.Fatalf("bounded processed sample missing: %s", body)
	}
	for _, secret := range []string{"provider-secret", "generation-secret", "rule-secret", "country-secret", "operator-value"} {
		if strings.Contains(body, secret) {
			t.Fatalf("raw value %q escaped into metrics: %s", secret, body)
		}
	}
	if strings.Contains(body, "perimeterd_firewall_denied_packets_total{") {
		t.Fatalf("unapproved denial labels created a time series: %s", body)
	}
}

func TestRetirementRetryDoesNotCountUnselectedGenerationTwice(t *testing.T) {
	collector := New("test", "commit", "time")
	active := CounterSample{
		Backend: "iptables", Rule: "active", Family: "ipv4", Direction: "ingress",
		ProcessedPackets: 100, Current: true,
	}
	collector.BeginCounterCollection()
	collector.CounterSnapshot("iptables", []CounterSample{active}, time.Unix(100, 0))
	rejected := CounterSample{
		Backend: "iptables", Rule: "rejected-candidate", Family: "ipv4", Direction: "ingress",
		ProcessedPackets: 7,
	}
	// A failed candidate's final read precedes its deletion. If deletion fails,
	// recovery must be able to repeat that read without counting it again.
	collector.CounterRetired("iptables", []CounterSample{rejected}, time.Unix(101, 0))
	collector.CounterRetired("iptables", []CounterSample{rejected}, time.Unix(102, 0))
	active.ProcessedPackets = 105
	collector.CounterSnapshot("iptables", []CounterSample{active}, time.Unix(103, 0))
	body := scrapeMetrics(t, collector)
	labels := map[string]string{"backend": "iptables", "direction": "ingress", "family": "ipv4"}
	if !hasSample(body, "perimeterd_firewall_processed_packets_total", labels, "12") {
		t.Fatalf("retirement retry double-counted the failed candidate: %s", body)
	}
}
