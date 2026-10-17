package lookup

import (
	"context"
	"encoding/json"
	"net/http"
	"net/netip"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/control"
)

func TestLookupProvenanceProtocolCutover(t *testing.T) {
	for _, version := range []int{1, 2, 3} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			query := Request{Address: "8.8.8.8/32", Direction: "ingress", Protocol: "icmp"}
			result := Response{SchemaVersion: version, Query: query, Flow: "new", ObservedAt: time.Now(), Verdict: "blocked", Outcomes: []Outcome{{Prefix: netip.MustParsePrefix(query.Address), Direction: query.Direction, Protocol: query.Protocol, Attachment: Attachment{Name: "test", Managed: true, PortBasis: "current_destination"}, Verdict: "blocked", Action: "drop", Stage: "policy", Reason: "policy", Evidence: []Evidence{{Kind: "country", Name: "SK", Provider: "dbip-lite", Release: "2026-10", Role: "include", Prefix: netip.MustParsePrefix(query.Address)}}}}}
			path := filepath.Join(t.TempDir(), "control.sock")
			server, err := control.Listen(path, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(result) }), http.NotFoundHandler(), http.NotFoundHandler())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.Close(context.Background()) }()
			got := callPath(context.Background(), path, query)
			if version != SchemaVersion {
				if got.Error == nil || got.Error.Code != "protocol" || !strings.Contains(got.Error.Message, "schema") {
					t.Fatalf("mixed version accepted: %+v", got)
				}
				return
			}
			if got.Error != nil {
				t.Fatal(got.Error)
			}
			if got.Outcomes[0].Evidence[0].Provider != "dbip-lite" || got.Outcomes[0].Evidence[0].Release != "2026-10" {
				t.Fatalf("lost provenance: %+v", got)
			}
			for _, evidence := range []Evidence{
				{Kind: "country", Name: "SK", Provider: "dbip-lite", Release: "2026-13"},
				{Kind: "country", Name: "SK", Provider: "ripestat", Release: "2026-10"},
				{Kind: "country", Name: "SK"},
				{Kind: "asn", Name: "123", Provider: "dbip-lite"},
			} {
				evidence.Prefix = netip.MustParsePrefix(query.Address)
				evidence.Role = "include"
				result.Outcomes[0].Evidence = []Evidence{evidence}
				if err := isValidResponse(result); err == nil {
					t.Fatalf("forged provenance accepted: %+v", evidence)
				}
			}
		})
	}
}
