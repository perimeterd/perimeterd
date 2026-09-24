// Package metrics owns bounded, in-memory Prometheus telemetry for perimeterd.
package metrics

import (
	"net/http"
	"strings"
	"sync"
	"sync/atomic"
	"time"
	"unicode/utf8"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// PrefixTimestamps contains the oldest committed retrieval time for each fixed
// static source kind. Zero values are not exposed.
type PrefixTimestamps struct {
	RIPestat int64
	IPList   int64
	Provider int64
}

type timestampCollector struct {
	desc *prometheus.Desc
	read func() PrefixTimestamps
}

func (c timestampCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c timestampCollector) Collect(ch chan<- prometheus.Metric) {
	values := c.read()
	for _, value := range [...]struct {
		source string
		stamp  int64
	}{
		{source: "ripestat", stamp: values.RIPestat},
		{source: "ip_list", stamp: values.IPList},
		{source: "provider", stamp: values.Provider},
	} {
		if value.stamp != 0 {
			ch <- prometheus.MustNewConstMetric(c.desc, prometheus.GaugeValue, float64(value.stamp), value.source)
		}
	}
}

type prefixSnapshot struct {
	metrics []prometheus.Metric
}

type prefixCollector struct {
	desc     *prometheus.Desc
	snapshot atomic.Pointer[prefixSnapshot]
}

func (c *prefixCollector) Describe(ch chan<- *prometheus.Desc) {
	ch <- c.desc
}

func (c *prefixCollector) Collect(ch chan<- prometheus.Metric) {
	if snapshot := c.snapshot.Load(); snapshot != nil {
		for _, metric := range snapshot.metrics {
			ch <- metric
		}
	}
}

// PrefixCount is one bounded family/source/type prefix gauge value.
type PrefixCount struct {
	Family string
	Source string
	Type   string
	Count  float64
}

// CounterSample is one cumulative native counter observation. Rule is stable
// for persistent counters and generation-scoped for reset counters; neither it
// nor Generation is exposed as a Prometheus label.
type CounterSample struct {
	Backend          string
	Generation       string
	Rule             string
	Family           string
	Direction        string
	Reason           string
	Action           string
	ProcessedPackets uint64
	ProcessedBytes   uint64
	DeniedPackets    uint64
	DeniedBytes      uint64
	Current          bool
}

type counterIdentity struct {
	backend string
	rule    string
}

type counterValue struct {
	processedPackets uint64
	processedBytes   uint64
	deniedPackets    uint64
	deniedBytes      uint64
	family           string
	direction        string
	reason           string
	action           string
}

// Collector stores process-lifetime counters and publishes snapshots without
// doing network, filesystem, or firewall work from the HTTP handler.
type Collector struct {
	registry *prometheus.Registry

	buildInfo         *prometheus.GaugeVec
	configReload      *prometheus.CounterVec
	reconcile         *prometheus.CounterVec
	reconcileDuration *prometheus.HistogramVec
	prefixes          *prefixCollector
	sourceRequests    *prometheus.CounterVec
	crowdDecisions    *prometheus.GaugeVec
	backendApply      *prometheus.CounterVec
	processedPackets  *prometheus.CounterVec
	processedBytes    *prometheus.CounterVec
	deniedPackets     *prometheus.CounterVec
	deniedBytes       *prometheus.CounterVec
	counterRead       *prometheus.CounterVec
	counterTimestamp  *prometheus.GaugeVec
	counterMu         sync.Mutex
	pendingBaseline   bool
	baselines         map[counterIdentity]counterValue
	active            map[counterIdentity]struct{}
}

// New constructs the process-lifetime metric set. Build metadata is bounded in
// length before becoming a constant label, so arbitrary ldflags cannot create
// unbounded exposition or memory use.
func New(version, commit, buildTime string) *Collector {
	collector := &Collector{
		registry:  prometheus.NewRegistry(),
		baselines: make(map[counterIdentity]counterValue),
		active:    make(map[counterIdentity]struct{}),
		buildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "perimeterd_build_info",
			Help: "Build metadata for this perimeterd process.",
		}, []string{"version", "commit", "build_time"}),
		configReload: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "perimeterd_config_reload_total",
			Help: "Configuration reload outcomes.",
		}, []string{"result"}),
		reconcile: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "perimeterd_reconcile_total",
			Help: "Serialized reconciliation outcomes.",
		}, []string{"reason", "result"}),
		reconcileDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "perimeterd_reconcile_duration_seconds",
			Help:    "Time spent applying a reconciliation.",
			Buckets: prometheus.DefBuckets,
		}, []string{"reason"}),
		prefixes: &prefixCollector{desc: prometheus.NewDesc(
			"perimeterd_prefixes",
			"Active prefixes by address family and fixed source/type.",
			[]string{"family", "source", "type"}, nil,
		)},
		sourceRequests: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "perimeterd_source_requests_total",
			Help: "Source retrieval outcomes.",
		}, []string{"source", "result"}),
		crowdDecisions: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "perimeterd_crowdsec_decisions",
			Help: "Active unexpired CrowdSec decisions by address family.",
		}, []string{"family"}),
		backendApply: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "perimeterd_backend_apply_total",
			Help: "Firewall backend apply outcomes.",
		}, []string{"backend", "result"}),
		processedPackets: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "perimeterd_firewall_processed_packets_total",
			Help: "Packets traversing a processed firewall path.",
		}, []string{"backend", "family", "direction"}),
		processedBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "perimeterd_firewall_processed_bytes_total",
			Help: "Bytes traversing a processed firewall path.",
		}, []string{"backend", "family", "direction"}),
		deniedPackets: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "perimeterd_firewall_denied_packets_total",
			Help: "Packets reaching an executed terminal firewall denial.",
		}, []string{"backend", "family", "direction", "reason", "action"}),
		deniedBytes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "perimeterd_firewall_denied_bytes_total",
			Help: "Bytes reaching an executed terminal firewall denial.",
		}, []string{"backend", "family", "direction", "reason", "action"}),
		counterRead: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "perimeterd_firewall_counter_read_total",
			Help: "Native firewall counter-read outcomes.",
		}, []string{"backend", "result"}),
		counterTimestamp: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "perimeterd_firewall_counter_timestamp_seconds",
			Help: "Timestamp of the last successful native firewall counter read.",
		}, []string{"backend"}),
	}
	collector.buildInfo.WithLabelValues(
		boundedMetadata(version, "dev", 128),
		boundedMetadata(commit, "unknown", 64),
		boundedMetadata(buildTime, "unknown", 64),
	).Set(1)
	collector.registry.MustRegister(
		collector.buildInfo,
		collector.configReload,
		collector.reconcile,
		collector.reconcileDuration,
		collector.prefixes,
		collector.sourceRequests,
		collector.crowdDecisions,
		collector.backendApply,
		collector.processedPackets,
		collector.processedBytes,
		collector.deniedPackets,
		collector.deniedBytes,
		collector.counterRead,
		collector.counterTimestamp,
	)
	collector.SetCrowdSecDecisions(0, 0)
	return collector
}

// Handler combines the stable metric registry with listener-local gauges. The
// callbacks are restricted to atomic or in-memory state and never read the
// firewall, source network, or filesystem.
func (c *Collector) Handler(health func() bool, timestamps func() PrefixTimestamps, crowdConnected func() bool) http.Handler {
	dynamic := prometheus.NewRegistry()
	if health != nil {
		dynamic.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "perimeterd_enforcement_health",
			Help: "Whether the selected firewall state is healthy.",
		}, func() float64 {
			if health() {
				return 1
			}
			return 0
		}))
	}
	if timestamps != nil {
		dynamic.MustRegister(timestampCollector{
			desc: prometheus.NewDesc(
				"perimeterd_prefix_snapshot_timestamp_seconds",
				"Oldest retrieval time in the committed prefix snapshot by source.",
				[]string{"source"},
				nil,
			),
			read: timestamps,
		})
	}
	if crowdConnected != nil {
		dynamic.MustRegister(prometheus.NewGaugeFunc(prometheus.GaugeOpts{
			Name: "perimeterd_crowdsec_connected",
			Help: "Whether the CrowdSec client has a valid connection.",
		}, func() float64 {
			if crowdConnected() {
				return 1
			}
			return 0
		}))
	}
	return promhttp.HandlerFor(prometheus.Gatherers{c.registry, dynamic}, promhttp.HandlerOpts{})
}

func boundedMetadata(value, fallback string, maximum int) string {
	if value == "" {
		value = fallback
	}
	value = strings.ToValidUTF8(value, "�")
	if len(value) <= maximum {
		return value
	}
	for maximum > 0 && !utf8.Valid([]byte(value[:maximum])) {
		maximum--
	}
	return value[:maximum]
}

// ConfigReload records one completed reload result.
func (c *Collector) ConfigReload(result string) {
	c.configReload.WithLabelValues(outcome(result)).Inc()
}

// Reconcile records an outcome and its apply duration under one fixed reason.
func (c *Collector) Reconcile(reason, result string, duration time.Duration) {
	c.reconcile.WithLabelValues(reconcileReason(reason), outcome(result)).Inc()
	c.reconcileDuration.WithLabelValues(reconcileReason(reason)).Observe(max(0, duration.Seconds()))
}

// SourceRequest records one logical source selector request without source IDs,
// URLs, or error messages as labels.
func (c *Collector) SourceRequest(source string, success bool) {
	result := "error"
	if success {
		result = "success"
	}
	c.sourceRequests.WithLabelValues(sourceKind(source), result).Inc()
}

// BackendApply records a serialized firewall mutation result.
func (c *Collector) BackendApply(backend string, success bool) {
	result := "error"
	if success {
		result = "success"
	}
	c.backendApply.WithLabelValues(backendKind(backend), result).Inc()
}

// SetPrefixes replaces the active prefix gauge series in one publication.
func (c *Collector) SetPrefixes(values []PrefixCount) {
	counts := make(map[[3]string]float64, len(values))
	for _, value := range values {
		family, ok := familyKind(value.Family)
		if !ok || !validPrefixSource(value.Source) || !validPrefixType(value.Type) {
			continue
		}
		counts[[3]string{family, value.Source, value.Type}] = max(0, value.Count)
	}
	snapshot := &prefixSnapshot{metrics: make([]prometheus.Metric, 0, len(counts))}
	for labels, count := range counts {
		snapshot.metrics = append(snapshot.metrics, prometheus.MustNewConstMetric(
			c.prefixes.desc, prometheus.GaugeValue, count, labels[0], labels[1], labels[2],
		))
	}
	c.prefixes.snapshot.Store(snapshot)
}

// SetCrowdSecDecisions updates the active unexpired decision counts.
func (c *Collector) SetCrowdSecDecisions(ipv4, ipv6 int) {
	c.crowdDecisions.WithLabelValues("ipv4").Set(float64(max(0, ipv4)))
	c.crowdDecisions.WithLabelValues("ipv6").Set(float64(max(0, ipv6)))
}

// BeginCounterCollection defers baseline replacement until the first complete
// successful read. Retired reads cannot initialize the selected target.
func (c *Collector) BeginCounterCollection() {
	c.counterMu.Lock()
	c.pendingBaseline = true
	c.counterMu.Unlock()
}

func (c *Collector) primeCounters(grouped map[counterIdentity]counterValue, current map[counterIdentity]bool) {
	clear(c.baselines)
	clear(c.active)
	for identity, sample := range grouped {
		if current[identity] {
			c.baselines[identity] = sample
			c.active[identity] = struct{}{}
		}
	}
	c.pendingBaseline = false
}

// CounterReadFailed records a failed periodic/final native read. It deliberately
// retains every counter value, baseline, and last-success timestamp.
func (c *Collector) CounterReadFailed(backend string) {
	c.counterRead.WithLabelValues(backendKind(backend), "error").Inc()
}

// CounterSnapshot records a successful active snapshot and prunes baselines
// for counters no longer owned by the selected generation.
func (c *Collector) CounterSnapshot(backend string, samples []CounterSample, at time.Time) {
	c.observeCounters(backend, samples, at)
}

// CounterRetired merges a read immediately before retirement. Keep every
// baseline until a successful complete snapshot: native deletion may fail, and
// recovery must be able to repeat the final read without double-counting.
func (c *Collector) CounterRetired(backend string, samples []CounterSample, at time.Time) {
	backend = backendKind(backend)
	c.counterRead.WithLabelValues(backend, "success").Inc()
	c.counterTimestamp.WithLabelValues(backend).Set(unixSeconds(at))
	c.counterMu.Lock()
	if c.pendingBaseline {
		// A retirement read is not a complete selected-target snapshot.
		// Do not import traffic from before the active metrics window.
		c.counterMu.Unlock()
		return
	}
	grouped, _ := groupSamples(samples)
	for identity, sample := range grouped {
		previous, exists := c.baselines[identity]
		if !exists {
			previous = counterValue{}
		}
		c.addCounterDelta(identity, previous, sample)
		c.baselines[identity] = sample
	}
	c.counterMu.Unlock()
}

func (c *Collector) observeCounters(backend string, samples []CounterSample, at time.Time) {
	backend = backendKind(backend)
	c.counterRead.WithLabelValues(backend, "success").Inc()
	c.counterTimestamp.WithLabelValues(backend).Set(unixSeconds(at))
	grouped, current := groupSamples(samples)
	c.counterMu.Lock()
	if c.pendingBaseline {
		c.primeCounters(grouped, current)
		c.counterMu.Unlock()
		return
	}
	clear(c.active)
	for identity := range current {
		if current[identity] {
			c.active[identity] = struct{}{}
		}
	}
	for identity, sample := range grouped {
		previous, exists := c.baselines[identity]
		if !exists {
			previous = counterValue{}
		}
		c.addCounterDelta(identity, previous, sample)
		c.baselines[identity] = sample
	}
	for identity := range c.baselines {
		if _, stillActive := c.active[identity]; !stillActive {
			delete(c.baselines, identity)
		}
	}
	c.counterMu.Unlock()
}

func (c *Collector) addCounterDelta(identity counterIdentity, previous, current counterValue) {
	family, ok := familyKind(current.family)
	if !ok || (current.direction != "ingress" && current.direction != "egress") {
		return
	}
	packets := counterDelta(previous.processedPackets, current.processedPackets)
	bytes := counterDelta(previous.processedBytes, current.processedBytes)
	if packets != 0 {
		c.processedPackets.WithLabelValues(identity.backend, family, current.direction).Add(float64(packets))
	}
	if bytes != 0 {
		c.processedBytes.WithLabelValues(identity.backend, family, current.direction).Add(float64(bytes))
	}
	if !validDenyReason(current.reason) || (current.action != "drop" && current.action != "reject") {
		return
	}
	packets = counterDelta(previous.deniedPackets, current.deniedPackets)
	bytes = counterDelta(previous.deniedBytes, current.deniedBytes)
	if packets != 0 {
		c.deniedPackets.WithLabelValues(identity.backend, family, current.direction, current.reason, current.action).Add(float64(packets))
	}
	if bytes != 0 {
		c.deniedBytes.WithLabelValues(identity.backend, family, current.direction, current.reason, current.action).Add(float64(bytes))
	}
}

func groupSamples(samples []CounterSample) (map[counterIdentity]counterValue, map[counterIdentity]bool) {
	grouped := make(map[counterIdentity]counterValue, len(samples))
	current := make(map[counterIdentity]bool, len(samples))
	for _, sample := range samples {
		backend := backendKind(sample.Backend)
		if sample.Rule == "" {
			continue
		}
		identity := counterIdentity{backend: backend, rule: sample.Rule}
		value := counterValue{
			processedPackets: sample.ProcessedPackets,
			processedBytes:   sample.ProcessedBytes,
			deniedPackets:    sample.DeniedPackets,
			deniedBytes:      sample.DeniedBytes,
			family:           sample.Family,
			direction:        sample.Direction,
			reason:           sample.Reason,
			action:           sample.Action,
		}
		if previous, exists := grouped[identity]; exists {
			value.processedPackets = max(previous.processedPackets, value.processedPackets)
			value.processedBytes = max(previous.processedBytes, value.processedBytes)
			value.deniedPackets = max(previous.deniedPackets, value.deniedPackets)
			value.deniedBytes = max(previous.deniedBytes, value.deniedBytes)
		}
		grouped[identity] = value
		current[identity] = current[identity] || sample.Current
	}
	return grouped, current
}

func counterDelta(previous, current uint64) uint64 {
	if current >= previous {
		return current - previous
	}
	return current
}

func unixSeconds(at time.Time) float64 {
	if at.IsZero() {
		at = time.Now()
	}
	return float64(at.UnixNano()) / float64(time.Second)
}

func outcome(value string) string {
	if value == "success" {
		return "success"
	}
	return "error"
}

func reconcileReason(value string) string {
	switch value {
	case "config", "source_refresh", "crowdsec", "recovery":
		return value
	default:
		return "config"
	}
}

func sourceKind(value string) string {
	switch value {
	case "ripestat", "ip_list", "provider", "crowdsec":
		return value
	default:
		return "unknown"
	}
}

func backendKind(value string) string {
	switch value {
	case "nftables", "iptables":
		return value
	default:
		return "unknown"
	}
}

func familyKind(value string) (string, bool) {
	switch value {
	case "ipv4", "4":
		return "ipv4", true
	case "ipv6", "6":
		return "ipv6", true
	default:
		return "", false
	}
}

func validDenyReason(value string) bool {
	return value == "global_blocklist" || value == "crowdsec" || value == "geo_policy"
}

func validPrefixSource(value string) bool {
	switch value {
	case "local", "global", "ripestat", "ip_list", "provider":
		return true
	default:
		return false
	}
}

func validPrefixType(value string) bool {
	switch value {
	case "local", "allowlist", "blocklist", "country", "asn", "ip_list", "provider":
		return true
	default:
		return false
	}
}
