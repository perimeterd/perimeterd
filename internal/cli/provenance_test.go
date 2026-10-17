package cli

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestStatusRendersCommittedSourceProvenance(t *testing.T) {
	report := statusFixture()
	var body bytes.Buffer
	if err := writeStatus(&body, report); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"Source: provider=dbip-lite release=2026-10 retrieved_at=2026-10-13T11:00:00Z"} {
		if !strings.Contains(body.String(), want) {
			t.Fatalf("missing provenance %q: %s", want, body.String())
		}
	}
	encoded, err := json.Marshal(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`"schema_version":4`, `"provider":"dbip-lite"`, `"release":"2026-10"`, `"retrieved_at":"2026-10-13T11:00:00Z"`} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("missing JSON provenance %q: %s", want, encoded)
		}
	}
	for _, forbidden := range []string{"endpoint", "parameters", "sha256", "download.db-ip.com"} {
		if strings.Contains(body.String(), forbidden) || strings.Contains(string(encoded), forbidden) {
			t.Fatalf("status leaked source definition: %s %s", body.String(), encoded)
		}
	}
}
