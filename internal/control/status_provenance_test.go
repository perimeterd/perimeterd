package control

import (
	"context"
	"encoding/json"
	"net/http"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestStatusCommittedSourceProtocol(t *testing.T) {
	for _, version := range []int{3, 4, 5} {
		t.Run(strconv.Itoa(version), func(t *testing.T) {
			report := statusReport("applied")
			report.SchemaVersion = version
			report.Applied.Details.Sources = []StatusSource{{Provider: "dbip-lite", Release: "2026-10", RetrievedAt: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}, {Provider: "ripestat", RetrievedAt: time.Date(2026, 10, 15, 12, 0, 0, 0, time.UTC)}}
			path := statusServer(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _ = json.NewEncoder(w).Encode(report) }))
			got, err := StatusPath(context.Background(), path)
			if version != StatusSchemaVersion {
				if err == nil || !strings.Contains(err.Error(), "schema") {
					t.Fatalf("mixed schema accepted: %+v %v", got, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if !reflect.DeepEqual(got.Applied.Details.Sources, report.Applied.Details.Sources) {
				t.Fatalf("lost provenance: %+v", got)
			}
			for _, sources := range [][]StatusSource{
				nil,
				{{Provider: "dbip-lite", Release: "2026-13", RetrievedAt: time.Now()}},
				{{Provider: "ripestat", Release: "2026-10", RetrievedAt: time.Now()}},
				{{Provider: "https://secret.invalid", RetrievedAt: time.Now()}},
				{{Provider: "ripestat"}},
				{report.Applied.Details.Sources[0], report.Applied.Details.Sources[0]},
				{report.Applied.Details.Sources[1], report.Applied.Details.Sources[0]},
			} {
				report.Applied.Details.Sources = sources
				if err := validateStatus(report); err == nil {
					t.Fatalf("invalid summary accepted: %+v", sources)
				}
			}
		})
	}
}
