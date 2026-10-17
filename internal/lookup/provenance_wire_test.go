package lookup

import (
	"context"
	"fmt"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/perimeterd/perimeterd/internal/control"
)

func TestLookupClientValidatesProvenanceJSON(t *testing.T) {
	for _, tc := range []struct {
		name, kind, fields string
		valid              bool
	}{
		{"country omitted provider", "country", "", false},
		{"country null provider", "country", `,"provider":null`, false},
		{"country numeric provider", "country", `,"provider":7`, false},
		{"ASN omitted provider", "asn", "", false},
		{"ASN null provider", "asn", `,"provider":null`, false},
		{"ASN numeric provider", "asn", `,"provider":7`, false},
		{"DBIP missing release", "country", `,"provider":"dbip-lite"`, false},
		{"DBIP null release", "country", `,"provider":"dbip-lite","release":null`, false},
		{"DBIP numeric release", "country", `,"provider":"dbip-lite","release":202610`, false},
		{"DBIP wrong month", "country", `,"provider":"dbip-lite","release":"2026-13"`, false},
		{"RIPE fabricated release", "country", `,"provider":"ripestat","release":"2026-10"`, false},
		{"ASN fabricated release", "asn", `,"provider":"ripestat","release":"2026-10"`, false},
		{"RIPE country optional release absent", "country", `,"provider":"ripestat"`, true},
		{"RIPE ASN optional release absent", "asn", `,"provider":"ripestat"`, true},
		{"DBIP monthly release", "country", `,"provider":"dbip-lite","release":"2026-10"`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			body := fmt.Sprintf(`{"schema_version":2,"query":{"address":"8.8.8.8/32","direction":"ingress","protocol":"icmp"},"flow":"new","observed_at":"2026-10-17T12:00:00Z","verdict":"blocked","outcomes":[{"prefix":"8.8.8.8/32","direction":"ingress","protocol":"icmp","attachment":{"name":"test","managed":true,"port_basis":"current_destination"},"verdict":"blocked","action":"drop","stage":"policy","reason":"policy","evidence":[{"kind":%q,"name":"SK","role":"include","prefix":"8.8.8.8/32","contributing":true%s}]}]}`, tc.kind, tc.fields)
			path := filepath.Join(t.TempDir(), "control.sock")
			server, err := control.Listen(path, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte(body)) }), http.NotFoundHandler(), http.NotFoundHandler())
			if err != nil {
				t.Fatal(err)
			}
			defer func() { _ = server.Close(context.Background()) }()
			result := callPath(context.Background(), path, Request{Address: "8.8.8.8/32", Direction: "ingress", Protocol: "icmp"})
			if tc.valid {
				if result.Error != nil || len(result.Outcomes) != 1 {
					t.Fatalf("valid source JSON rejected: %+v", result)
				}
				return
			}
			if result.Error == nil || result.Error.Code != "protocol" {
				t.Fatalf("malformed source JSON admitted: %+v", result)
			}
		})
	}
}
