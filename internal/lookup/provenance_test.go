package lookup

import (
	"encoding/json"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/source"
)

func TestSourceEvidencePreservesSemanticKindAndProvenance(t *testing.T) {
	prefix := netip.MustParsePrefix("92.180.233.6/32")
	for _, tc := range []struct {
		kind                      policy.SelectorKind
		source, provider, release string
	}{
		{policy.Country, "dbip-lite", "dbip-lite", "2026-10"},
		{policy.Country, "", "ripestat", ""},
		{policy.Country, "ripestat", "ripestat", ""},
		{policy.ASN, "", "ripestat", ""},
	} {
		record := source.Record{Selector: policy.Selector{Kind: tc.kind, Value: "SK"}, SourceKind: tc.source, Release: tc.release, Endpoint: "https://secret.invalid", Parameters: map[string]string{"sha256": "secret-digest"}, RetrievedAt: time.Now().UTC()}
		evidence := sourceEvidence(sourceRef{record: record, via: []string{"group/EU", "rir/ripencc"}}, "policy", "include", prefix, true)
		if evidence.Kind != string(tc.kind) || evidence.Provider != tc.provider || evidence.Release != tc.release || len(evidence.Via) != 2 || !evidence.Contributing {
			t.Fatalf("wrong attribution: %+v", evidence)
		}
		body, err := json.Marshal(evidence)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(body), "secret") || strings.Contains(string(body), "endpoint") || strings.Contains(string(body), "sha256") {
			t.Fatalf("source secrets leaked: %s", body)
		}
	}
}

func TestEvidenceProvenancePreventsOutcomeCoalescing(t *testing.T) {
	base := Evidence{Kind: "country", Name: "SK", Provider: "dbip-lite", Release: "2026-10", Prefix: netip.MustParsePrefix("92.180.233.6/32")}
	for _, changed := range []Evidence{
		func() Evidence { v := base; v.Provider = "ripestat"; return v }(),
		func() Evidence { v := base; v.Release = "2026-09"; return v }(),
	} {
		if evidenceEqual(base, changed) {
			t.Fatal("different provenance compared equal")
		}
		if evidenceLess(base, changed) == evidenceLess(changed, base) {
			t.Fatal("provenance has no strict ordering")
		}
		if outcomeSame(Outcome{Evidence: []Evidence{base}}, Outcome{Evidence: []Evidence{changed}}) {
			t.Fatal("different provenance coalesced")
		}
	}
}
