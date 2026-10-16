package app

import (
	"context"
	"encoding/json"
	"errors"
	"net/netip"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/control"
	"github.com/perimeterd/perimeterd/internal/crowdsec"
	"github.com/perimeterd/perimeterd/internal/lookup"
)

func TestStatusAppliedRecoveryAndCleanup(t *testing.T) {
	backend := &recordingBackend{}
	engine, store := newTestEngine(t, backend, nil)
	defer engine.Close()
	if got := engine.Status(context.Background()); got.Applied.State != "empty" || !got.Successful() {
		t.Fatalf("empty status = %#v", got)
	}
	candidate := admitCandidate(t, engine, parseEngineConfig(t, "192.0.2.0/24"))
	outcome, err := engine.Apply(context.Background(), candidate)
	if err != nil {
		t.Fatal(err)
	}
	report := engine.Status(context.Background())
	if !report.Successful() || report.Applied.Revision != outcome.Active.ID || report.Applied.ConfigEpoch != candidate.epoch || report.Applied.Manifest != outcome.Active.Manifest {
		t.Fatalf("applied = %#v", report)
	}
	details := report.Applied.Details
	if details.Firewall.Backend != "nftables" || details.Firewall.DenyAction != "drop" || !reflect.DeepEqual(details.Firewall.Families, []string{"ipv4", "ipv6"}) || details.CrowdSec.Validity != "disabled" {
		t.Fatalf("details = %#v", details)
	}
	found := false
	for _, count := range details.PrefixCounts {
		if count.Family == "ipv4" && count.Source == "global" && count.Type == "blocklist" {
			found = true
			if count.Count != 1 {
				t.Fatalf("blocklist count = %d", count.Count)
			}
		}
	}
	if !found {
		t.Fatal("missing applied global blocklist count")
	}
	wantCompiled := details.CompiledSets
	wantCompiled.Sets = slices.Clone(wantCompiled.Sets)
	wantCompiled.Totals = slices.Clone(wantCompiled.Totals)
	for i := range wantCompiled.Sets {
		wantCompiled.Sets[i].Policies = slices.Clone(wantCompiled.Sets[i].Policies)
	}
	// Returned metadata cannot corrupt the daemon's shared applied snapshot.
	details.Firewall.Families[0] = "corrupted"
	details.PrefixCounts[0].Count = 99999
	details.CompiledSets.Sets[0].ID = "corrupted"
	details.CompiledSets.Sets[0].Count = 99999
	details.CompiledSets.Totals[0].Count = 99999
	for i := range details.CompiledSets.Sets {
		if len(details.CompiledSets.Sets[i].Policies) > 0 {
			details.CompiledSets.Sets[i].Policies[0] = "corrupted"
		}
	}
	again := engine.Status(context.Background())
	if again.Applied.Details.Firewall.Families[0] != "ipv4" || again.Applied.Details.PrefixCounts[0].Count == 99999 {
		t.Fatal("status output mutated published state")
	}
	if !reflect.DeepEqual(again.Applied.Details.CompiledSets, wantCompiled) {
		t.Fatal("returned compiled set rows or totals mutated published state")
	}
	engine.Close()
	recovered := NewEngine(store, backend, nil)
	defer recovered.Close()
	if got := recovered.Status(context.Background()); got.Applied.State != "unavailable" || got.Applied.Details != nil {
		t.Fatalf("unrecovered = %#v", got)
	}
	if _, err := recovered.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := recovered.Status(context.Background()); !got.Successful() || got.Applied.Revision != report.Applied.Revision || !reflect.DeepEqual(got.Applied.Details, again.Applied.Details) {
		t.Fatalf("recovered = %#v", got)
	}
	if err := recovered.Cleanup(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := recovered.Status(context.Background()); !got.Successful() || got.Applied.State != "empty" || got.Applied.Details != nil || got.Applied.Revision != "" {
		t.Fatalf("cleanup = %#v", got)
	}
}

func TestStatusKeepsAcknowledgedRevisionAfterRejectedApply(t *testing.T) {
	backend := &recordingBackend{}
	engine, _ := newTestEngine(t, backend, nil)
	defer engine.Close()
	if _, err := engine.Apply(context.Background(), admitCandidate(t, engine, parseEngineConfig(t, "192.0.2.0/24"))); err != nil {
		t.Fatal(err)
	}
	before := engine.Status(context.Background())
	backend.mu.Lock()
	backend.applyFailures = 1
	backend.applyErr = errors.New("apply failed")
	backend.mu.Unlock()
	result, err := engine.Apply(context.Background(), admitCandidate(t, engine, parseEngineConfig(t, "198.51.100.0/24, 203.0.113.0/24")))
	if err == nil || result.Committed || result.Degraded {
		t.Fatalf("apply = %#v, %v", result, err)
	}
	after := engine.Status(context.Background())
	if !after.Successful() || !reflect.DeepEqual(before.Applied, after.Applied) {
		t.Fatalf("rejected apply changed report: %#v", after)
	}
}

func TestStatusDoesNotWaitBehindApply(t *testing.T) {
	backend := &blockingLookupBackend{entered: make(chan struct{}), release: make(chan struct{})}
	engine, _ := newTestEngine(t, backend, nil)
	defer engine.Close()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	candidate := admitCandidate(t, engine, parseEngineConfig(t, "192.0.2.0/24"))
	done := make(chan Outcome, 1)
	go func() { result, _ := engine.Apply(ctx, candidate); done <- result }()
	select {
	case <-backend.entered:
	case <-time.After(time.Second):
		t.Fatal("apply did not start")
	}
	report := make(chan control.StatusResult, 1)
	go func() { report <- engine.Status(context.Background()) }()
	select {
	case got := <-report:
		if got.Applied.State != "unavailable" || got.Applied.Details != nil {
			t.Fatalf("during apply = %#v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("status blocked behind writer")
	}
	close(backend.release)
	result := <-done
	got := engine.Status(context.Background())
	if !got.Successful() || got.Applied.Revision != result.Active.ID {
		t.Fatalf("after apply = %#v", got)
	}
}

func TestStatusUncertainPreparationAndShutdownAreUnavailable(t *testing.T) {
	engine, _ := newTestEngine(t, &recordingBackend{}, func(point string) error {
		if point == "journal:after-rename" {
			return errors.New("uncertain write")
		}
		return nil
	})
	defer engine.Close()
	result, err := engine.Apply(context.Background(), admitCandidate(t, engine, parseEngineConfig(t, "192.0.2.0/24")))
	if err == nil || !result.Degraded {
		t.Fatalf("apply = %#v, %v", result, err)
	}
	got := engine.Status(context.Background())
	if got.Successful() || got.Applied.State != "unavailable" || got.Applied.Details != nil {
		t.Fatalf("uncertain = %#v", got)
	}
	engine.Close()
	got = engine.Status(context.Background())
	if got.Daemon.Healthy || got.Applied.State != "unavailable" {
		t.Fatalf("closed = %#v", got)
	}
}

func TestStatusCrowdSecCountsAcknowledgedDecisionBoundaries(t *testing.T) {
	now := time.Date(2026, 10, 13, 12, 0, 0, 0, time.UTC)
	details := &control.StatusDetails{Firewall: control.StatusFirewall{Families: []string{"ipv4"}}, CrowdSec: control.StatusCrowdSec{Enabled: true}}
	dynamic := lookup.Dynamic{Epoch: 7, Operation: 8, ValidUntil: now.Add(time.Minute), Decisions: []crowdsec.Decision{
		{ID: 1, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Deadline: now.Add(time.Second)},
		{ID: 2, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Deadline: now.Add(time.Minute)},
		{ID: 3, Prefix: netip.MustParsePrefix("198.51.100.0/24"), Deadline: now},
		{ID: 4, Prefix: netip.MustParsePrefix("2001:db8::/32"), Deadline: now.Add(time.Minute)},
	}}
	got := statusCrowdSec(context.Background(), details, dynamic, now)
	if got.Validity != "valid" || *got.Counts != (control.StatusDecisionCounts{IPv4: 2}) || got.Operation != 8 {
		t.Fatalf("counts = %#v", got)
	}
	dynamic.ValidUntil = now
	if got := statusCrowdSec(context.Background(), details, dynamic, now); got.Validity != "stale" || got.Counts != nil {
		t.Fatalf("expired validity = %#v", got)
	}
	dynamic.Decisions = nil
	dynamic.ValidUntil = time.Time{}
	if got := statusCrowdSec(context.Background(), details, dynamic, now); got.Validity != "valid" || *got.Counts != (control.StatusDecisionCounts{}) {
		t.Fatalf("acknowledged empty = %#v", got)
	}
	dynamic.Operation = 0
	if got := statusCrowdSec(context.Background(), details, dynamic, now); got.Validity != "unknown" || got.Counts != nil {
		t.Fatalf("unacknowledged = %#v", got)
	}
}

func TestStatusDynamicPublicationPreservesStaticSummary(t *testing.T) {
	engine, _ := newTestEngine(t, &recordingBackend{}, nil)
	defer engine.Close()
	if _, err := engine.Apply(context.Background(), admitCandidate(t, engine, parseEngineConfig(t, "192.0.2.0/24"))); err != nil {
		t.Fatal(err)
	}
	before := engine.Status(context.Background())
	engine.mu.Lock()
	engine.abortLookupLocked()
	engine.publishDynamicLookupLocked(&crowdState{epoch: 9, leaseOperation: 4}, before.Applied.Revision, before.Applied.Manifest)
	engine.mu.Unlock()
	after := engine.Status(context.Background())
	if !reflect.DeepEqual(before.Applied, after.Applied) {
		t.Fatalf("dynamic update lost static state: %#v", after)
	}
	engine.mu.Lock()
	engine.abortLookupLocked()
	engine.publishDynamicLookupLocked(&crowdState{epoch: 10, leaseOperation: 5}, "other", before.Applied.Manifest)
	engine.mu.Unlock()
	if got := engine.Status(context.Background()); got.Applied.State != "unavailable" {
		t.Fatalf("cross-revision update = %#v", got)
	}
}

func TestStatusConcurrentApplyDoesNotMixCountsAndEpochs(t *testing.T) {
	engine, _ := newTestEngine(t, &recordingBackend{}, nil)
	defer engine.Close()
	stop := make(chan struct{})
	failures := make(chan control.StatusResult, 1)
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			select {
			case <-stop:
				return
			default:
			}
			got := engine.Status(context.Background())
			if got.Applied.State != "applied" {
				continue
			}
			want := uint64(1)
			if got.Applied.ConfigEpoch%2 == 0 {
				want = 2
			}
			found := false
			for _, count := range got.Applied.Details.PrefixCounts {
				if count.Family == "ipv4" && count.Source == "global" && count.Type == "blocklist" {
					found = count.Count == want
				}
			}
			compiled := false
			for _, set := range got.Applied.Details.CompiledSets.Sets {
				if set.Family == "ipv4" && set.ID == "global_blocklist" {
					compiled = set.Count == want
				}
			}
			if !compiled {
				failures <- got
				return
			}
			if !found {
				failures <- got
				return
			}
		}
	}()
	defer func() {
		close(stop)
		<-done
		select {
		case got := <-failures:
			t.Errorf("mixed applied generations: %#v", got)
		default:
		}
	}()
	for i := 1; i <= 12; i++ {
		block := "192.0.2.0/24"
		if i%2 == 0 {
			block += ", 198.51.100.0/24"
		}
		if _, err := engine.Apply(context.Background(), admitCandidate(t, engine, parseEngineConfig(t, block))); err != nil {
			t.Fatal(err)
		}
	}
}

func TestStatusPolicyAndAttachmentSummaryDoesNotExposeConfigSecrets(t *testing.T) {
	engine, _ := newTestEngine(t, &recordingBackend{}, nil)
	defer engine.Close()
	cfg := parseEngineConfig(t, "192.0.2.0/24")
	cfg.Firewall.Backend = "iptables"
	cfg.Firewall.IPTables.Attachments = []config.Attachment{{Chain: "INPUT", Direction: "ingress", InputInterfaces: []string{"eth0"}}}
	cfg.CrowdSec.APIKeyFile = "/secret/credential"
	cfg.CrowdSec.LAPIURL = "http://secret-lapi.example"
	cfg.IPLists = map[string]config.IPListConfig{"unused": {URL: "https://secret-source.example", RefreshInterval: time.Hour, RequestTimeout: time.Second}}
	cfg.Policies = []config.Policy{
		{Name: "disabled-web", Priority: 20, Direction: "ingress", Mode: "disabled", Traffic: config.TrafficScope{TCP: []config.PortRange{{Start: 80, End: 443}}}},
		{Name: "disabled-out", Priority: 10, Direction: "egress", Mode: "disabled", Traffic: config.TrafficScope{Any: true}},
	}
	candidate := admitCandidate(t, engine, cfg)
	if _, err := engine.Apply(context.Background(), candidate); err != nil {
		t.Fatal(err)
	}
	got := engine.Status(context.Background())
	if !got.Successful() {
		t.Fatalf("status = %#v", got)
	}
	details := got.Applied.Details
	if details.Firewall.Backend != "iptables" || len(details.Firewall.Attachments) != 1 || details.Firewall.Attachments[0].InputInterfaces[0] != "eth0" {
		t.Fatalf("attachments = %#v", details.Firewall)
	}
	if len(details.Policies) != 2 || details.Policies[0].Name != "disabled-out" || details.Policies[1].Mode != "disabled" || details.Policies[1].Traffic.TCP[0].End != 443 {
		t.Fatalf("policies = %#v", details.Policies)
	}
	encoded, err := json.Marshal(got)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "secret") || strings.Contains(string(encoded), "unused") {
		t.Fatalf("status exposed nonpublic configuration: %s", encoded)
	}
}
