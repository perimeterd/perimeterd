package control

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
	"time"
)

func TestStatusClientRejectsMalformedSourceSummaryJSON(t *testing.T) {
	for _, tc := range []struct {
		name, raw string
		omit      bool
	}{
		{name: "omitted", omit: true},
		{name: "null", raw: `null`},
		{name: "object", raw: `{}`},
		{name: "string", raw: `"dbip-lite"`},
		{name: "missing provider", raw: `[{"release":"2026-10","retrieved_at":"2026-10-16T12:00:00Z"}]`},
		{name: "null provider", raw: `[{"provider":null,"release":"2026-10","retrieved_at":"2026-10-16T12:00:00Z"}]`},
		{name: "numeric provider", raw: `[{"provider":7,"retrieved_at":"2026-10-16T12:00:00Z"}]`},
		{name: "missing retrieval", raw: `[{"provider":"ripestat"}]`},
		{name: "null retrieval", raw: `[{"provider":"ripestat","retrieved_at":null}]`},
		{name: "numeric retrieval", raw: `[{"provider":"ripestat","retrieved_at":7}]`},
		{name: "missing DBIP release", raw: `[{"provider":"dbip-lite","retrieved_at":"2026-10-16T12:00:00Z"}]`},
		{name: "null DBIP release", raw: `[{"provider":"dbip-lite","release":null,"retrieved_at":"2026-10-16T12:00:00Z"}]`},
		{name: "numeric release", raw: `[{"provider":"dbip-lite","release":202610,"retrieved_at":"2026-10-16T12:00:00Z"}]`},
		{name: "RIPE monthly release", raw: `[{"provider":"ripestat","release":"2026-10","retrieved_at":"2026-10-16T12:00:00Z"}]`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			encoded, err := json.Marshal(statusReport("applied"))
			if err != nil {
				t.Fatal(err)
			}
			var envelope map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &envelope); err != nil {
				t.Fatal(err)
			}
			var applied map[string]json.RawMessage
			if err := json.Unmarshal(envelope["applied"], &applied); err != nil {
				t.Fatal(err)
			}
			var details map[string]json.RawMessage
			if err := json.Unmarshal(applied["details"], &details); err != nil {
				t.Fatal(err)
			}
			if tc.omit {
				delete(details, "sources")
			} else {
				details["sources"] = json.RawMessage(tc.raw)
			}
			applied["details"], err = json.Marshal(details)
			if err != nil {
				t.Fatal(err)
			}
			envelope["applied"], err = json.Marshal(applied)
			if err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(envelope)
			if err != nil {
				t.Fatal(err)
			}
			path := statusServer(t, http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(body) }))
			if result, err := StatusPath(context.Background(), path); err == nil {
				t.Fatalf("client admitted malformed source JSON: %+v", result)
			}
		})
	}
}

func TestStatusClientAllowsRIPEWithoutMonthlyRelease(t *testing.T) {
	report := statusReport("applied")
	report.Applied.Details.Sources = []StatusSource{{Provider: "ripestat", RetrievedAt: time.Date(2026, 10, 16, 12, 0, 0, 0, time.UTC)}}
	path := statusServer(t, StatusHTTPHandler(func(context.Context) StatusResult { return report }))
	got, err := StatusPath(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Applied.Details.Sources) != 1 || got.Applied.Details.Sources[0].Release != "" {
		t.Fatalf("fabricated RIPE release: %+v", got)
	}
}
