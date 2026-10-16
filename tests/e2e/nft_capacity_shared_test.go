//go:build linux && e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/control"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
	"github.com/perimeterd/perimeterd/internal/state"
	"github.com/perimeterd/perimeterd/internal/testutil/capacityfixture"
	"github.com/perimeterd/perimeterd/internal/testutil/historicalfixture"
)

// The recorded target supplies historical rule/object identity. Only the three
// explicitly known geo fields are expanded from deterministic source data; this
// is not an alternate compiler for obsolete representations.
func capacityStageHistorical(t *testing.T, configPath, sourceURL string, peer *peerNamespace) *state.Revision {
	t.Helper()
	data, err := os.ReadFile(configPath) // #nosec G304 -- fixed private namespace policy fixture.
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Parse(data)
	if err != nil {
		t.Fatal(err)
	}
	store, err := state.Open("/var/lib/perimeterd", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()
	var records []source.Record
	for _, record := range capacityfixture.Records(false) {
		records = append(records, source.Record{Selector: record.Selector, Endpoint: "https://stat.ripe.net/data/country-resource-list/data.json", APIVersion: "0.2", Parameters: map[string]string{"resource": record.Selector.Value, "sourceapp": "perimeterd", "v4_format": "prefix"}, QueryStart: now, QueryEnd: now, RetrievedAt: now, IPv4: record.IPv4, IPv6: record.IPv6})
	}
	snapshot, err := store.Prefixes().Stage(records)
	if err != nil {
		t.Fatal(err)
	}
	model, err := policy.Compile(cfg, snapshot.Policy())
	if err != nil {
		t.Fatal(err)
	}
	target, err := historicalfixture.Target("nftables", store.Owner())
	if err != nil {
		t.Fatal(err)
	}
	target.Table = cfg.Firewall.Nftables.Table
	compiledFamilies := model.Families()
	for fi := range target.Families {
		family := &target.Families[fi]
		for si := range family.Sets {
			set := &family.Sets[si]
			id := set.ID
			if id != "geo/ingress" && id != "geo/egress" && id != "geo/ssh" {
				continue
			}
			if id == "geo/ingress" {
				id = "geo/egress"
			}
			found := false
			for _, compiled := range compiledFamilies {
				if compiled.Family != family.Family {
					continue
				}
				for _, replacement := range compiled.Sets {
					if replacement.ID == id {
						set.Prefixes = append(set.Prefixes[:0], replacement.Prefixes...)
						found = true
					}
				}
			}
			if !found {
				t.Fatalf("missing explicit historical expansion %s", id)
			}
		}
	}
	total, counts := capacityfixture.Memberships(target.Families)
	if total != 2*capacityfixture.GeoMemberships+capacityfixture.UnrelatedMemberships+4 {
		t.Fatalf("historical scale=%d %v", total, counts)
	}
	// The captured historical rule used the original TCP-only port shorthand.
	// Preserve it as recorded; current YAML explicitly enables TCP and UDP.
	historicalConfig := cfg
	historicalConfig.Policies = slices.Clone(cfg.Policies)
	for i := range historicalConfig.Policies {
		if historicalConfig.Policies[i].Name == "ssh" {
			historicalConfig.Policies[i].Traffic.UDP = nil
		}
	}
	revision := &state.Revision{Version: 2, ID: capacityfixture.InitialID, Epoch: 1, Manifest: snapshot.ManifestID(), ConfigPath: configPath, Config: historicalConfig, Target: target}
	if err := store.Prepare(nil, revision); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(revision); err != nil {
		t.Fatal(err)
	}
	if err := store.Finish(); err != nil {
		t.Fatal(err)
	}
	// Startup first recovers the exact recorded target, then prepares a normal
	// shared compilation. Interrupt before switch to retain real old/new state.
	cmd := capacityCommand(configPath, sourceURL, "PERIMETERD_CAPACITY_CRASH=after-prepare")
	if output, err := cmd.CombinedOutput(); !exitStatus(err, 97) {
		t.Fatalf("historical migration interruption: %v\n%s", err, output)
	}
	view, err := store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if view.Journal == nil || view.Journal.Previous != revision.ID || view.Journal.Candidate == revision.ID {
		t.Fatalf("missing distinct historical migration journal: %+v", view.Journal)
	}
	if !reflect.DeepEqual(view.Active.Target, target) {
		t.Fatal("historical target rewritten during recovery")
	}
	if err := capacityfixture.ValidateShared(view.Revisions[view.Journal.Candidate].Target.Families, true); err != nil {
		t.Fatal(err)
	}
	capacityNativeReferences(t, target, true)
	// Recovery has no authoritative live CrowdSec snapshot yet; static DROP and
	// the CZ/SK SSH restriction still govern both families.
	capacityPackets(t, peer, true, false, false)
	// Recover the prepared transition and interrupt a genuine native switch.
	// Both old unshared and new shared generations must now coexist in-kernel.
	cmd = capacityCommand(configPath, sourceURL, "PERIMETERD_CAPACITY_CRASH=after-switch")
	if output, err := cmd.CombinedOutput(); !exitStatus(err, 97) {
		t.Fatalf("historical switched interruption: %v\n%s", err, output)
	}
	view, err = store.Read()
	if err != nil {
		t.Fatal(err)
	}
	if view.Journal == nil || view.Journal.Previous != revision.ID || view.Journal.Candidate == revision.ID {
		t.Fatalf("missing interrupted native old/new transition: %+v", view.Journal)
	}
	capacityNativeReferences(t, target, true)
	capacityNativeReferences(t, view.Revisions[view.Journal.Candidate].Target, false)
	capacityPackets(t, peer, true, true, true)
	t.Logf("recorded historical recovery memberships=%d; prepared old=%s new=%s", total, target.Generation, view.Revisions[view.Journal.Candidate].Target.Generation)
	return revision
}

func capacityReadyStatus(t *testing.T) control.StatusResult {
	t.Helper()
	var status control.StatusResult
	waitCrowdCondition(t, "acknowledged compiled-set status", func() bool {
		status = largeCrowdStatus(t)
		return status.Successful() && status.Applied.Details != nil && status.Applied.Details.CrowdSec.Counts != nil
	})
	return status
}

func capacityAssertStatusAndNative(t *testing.T, revision *state.Revision, split bool) {
	t.Helper()
	status := capacityReadyStatus(t)
	total, counts := capacityfixture.Memberships(revision.Target.Families)
	seen := 0
	for _, row := range status.Applied.Details.CompiledSets.Sets {
		family := 4
		if row.Family == "ipv6" {
			family = 6
		}
		count := row.Count
		if count > uint64(math.MaxInt) {
			t.Fatalf("status membership cannot fit fixture count: %+v", row)
			return
		}
		if int(count) != counts[fmt.Sprintf("%s/ipv%d", row.ID, family)] {
			t.Fatalf("compiled status count mismatch: %+v", row)
		}
		seen += int(count)
		if row.ID == "geo/egress" {
			want := []string{"egress", "ingress"}
			if split {
				want = []string{"egress"}
			}
			if !reflect.DeepEqual(row.Policies, want) {
				t.Fatalf("actual consumer labels=%v want=%v", row.Policies, want)
			}
		}
		if row.ID == "geo/ingress" && !reflect.DeepEqual(row.Policies, []string{"ingress"}) {
			t.Fatalf("split ingress consumer labels=%v", row.Policies)
		}
		if row.ID == "geo/ssh" && !reflect.DeepEqual(row.Policies, []string{"ssh"}) {
			t.Fatalf("SSH consumer labels=%v", row.Policies)
		}
	}
	if seen != total {
		t.Fatalf("compiled status total=%d want=%d", seen, total)
	}
	var text string
	waitCrowdCondition(t, "completed human status publication", func() bool {
		output, err := commandMayFail(10*time.Second, e2eBinary(t), "status")
		text = string(output)
		return err == nil
	})
	if !strings.Contains(text, "shared sets counted once") {
		t.Fatalf("missing sharing semantics: %s", text)
	}
	for _, row := range status.Applied.Details.CompiledSets.Sets {
		policies := strings.Join(row.Policies, ",")
		if policies == "" {
			policies = "-"
		}
		line := fmt.Sprintf("  family=%s set=%s policies=%s count=%d", row.Family, row.ID, policies, row.Count)
		if !strings.Contains(text, line) {
			t.Fatalf("missing actual human status row %q", line)
		}
		t.Logf("actual status: %s", line)
	}
	expectedSets := 0
	for _, family := range revision.Target.Families {
		expectedSets += len(family.Sets)
	}
	if actual := capacityNativeReferences(t, revision.Target, split); actual != expectedSets {
		t.Fatalf("native retained orphan sets: actual=%d active=%d", actual, expectedSets)
	}
}

// Native checks locate actual data objects and follow references from both
// generation paths, rather than assuming a geo ID suffix names its consumer.
func capacityNativeReferences(t *testing.T, target *firewall.Target, separate bool) int {
	t.Helper()
	output := command(t, 60*time.Second, "nft", "-j", "list", "table", "inet", target.Table)
	var envelope struct {
		Nftables []map[string]json.RawMessage `json:"nftables"`
	}
	if err := json.Unmarshal(output, &envelope); err != nil {
		t.Fatal(err)
	}
	sets := map[string]bool{}
	rules := map[string][]byte{}
	for _, object := range envelope.Nftables {
		if data := object["set"]; data != nil {
			var set struct {
				Name string            `json:"name"`
				Elem []json.RawMessage `json:"elem"`
			}
			if err := json.Unmarshal(data, &set); err != nil {
				t.Fatal(err)
			}
			sets[set.Name] = true
		}
		if data := object["rule"]; data != nil {
			var rule struct {
				Chain string `json:"chain"`
			}
			if err := json.Unmarshal(data, &rule); err != nil {
				t.Fatal(err)
			}
			rules[rule.Chain] = append(rules[rule.Chain], data...)
		}
	}
	for _, family := range []string{"v4", "v6"} {
		var ingress, egress string
		for chain, data := range rules {
			if !strings.Contains(chain, target.Generation) || !strings.Contains(chain, "path_"+family+"_") {
				continue
			}
			for name := range sets {
				if !strings.Contains(name, target.Generation) || !strings.Contains(name, "geo_") || strings.Contains(name, "ssh") || strings.Contains(name, "eligible") {
					continue
				}
				if strings.Contains(string(data), "@"+name+"\"") {
					if strings.HasSuffix(chain, "_ingress") {
						ingress = name
					}
					if strings.HasSuffix(chain, "_egress") {
						egress = name
					}
				}
			}
		}
		if ingress == "" || egress == "" || ((ingress != egress) != separate) {
			t.Fatalf("native %s refs ingress=%s egress=%s separate=%t", family, ingress, egress, separate)
		}
		t.Logf("native family=%s ingress-ref=%s egress-ref=%s separate=%t", family, ingress, egress, separate)
	}
	return len(sets)
}

func capacityAssertSplit(t *testing.T, revision *state.Revision) {
	t.Helper()
	total, counts := capacityfixture.Memberships(revision.Target.Families)
	want := 2*capacityfixture.GeoMemberships + capacityfixture.UnrelatedMemberships + 4 - 2
	if total != want {
		t.Fatalf("split total=%d want=%d: %v", total, want, counts)
	}
	for _, family := range []int{4, 6} {
		full := capacityfixture.IPv4Memberships
		if family == 6 {
			full = capacityfixture.IPv6Memberships
		}
		if counts[fmt.Sprintf("geo/ingress/ipv%d", family)] != full ||
			counts[fmt.Sprintf("geo/egress/ipv%d", family)] != full-1 ||
			counts[fmt.Sprintf("geo/ssh/ipv%d", family)] != 2 {
			t.Fatalf("only egress may change on split: %v", counts)
		}
	}
	capacityAssertStatusAndNative(t, revision, true)
}
