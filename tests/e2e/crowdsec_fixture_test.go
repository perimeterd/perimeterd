//go:build linux && e2e

package e2e

import (
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"testing"
	"time"
)

type crowdFixtureWireDecision struct {
	ID       int64  `json:"id"`
	Value    string `json:"value"`
	Until    string `json:"until"`
	Duration string `json:"duration"`
}

type crowdFixtureWireBatch struct {
	New     []crowdFixtureWireDecision `json:"new"`
	Deleted []struct {
		ID int64 `json:"id"`
	} `json:"deleted"`
}

func crowdFixtureRequest(t *testing.T, serverURL, path, startup string) (int, []byte) {
	t.Helper()
	endpoint, err := url.Parse(serverURL)
	if err != nil {
		t.Fatal(err)
	}
	endpoint.Path = path
	query := endpoint.Query()
	query.Set("dedup", "false")
	query.Set("scopes", "ip,range")
	if startup != "" {
		query.Set("startup", startup)
	}
	endpoint.RawQuery = query.Encode()
	request, err := http.NewRequest(http.MethodGet, endpoint.String(), nil)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("X-Api-Key", crowdFixtureKey)
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := response.Body.Close(); err != nil {
			t.Error(err)
		}
	}()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	return response.StatusCode, body
}

func crowdFixturePoll(t *testing.T, serverURL string, startup bool) crowdFixtureWireBatch {
	t.Helper()
	status, body := crowdFixtureRequest(t, serverURL, "/v1/decisions/stream", strconv.FormatBool(startup))
	if status != http.StatusOK {
		t.Fatalf("fixture poll startup=%t returned HTTP %d: %s", startup, status, body)
	}
	var batch crowdFixtureWireBatch
	if err := json.Unmarshal(body, &batch); err != nil {
		t.Fatalf("fixture poll startup=%t returned malformed JSON: %v", startup, err)
	}
	return batch
}

func crowdFixtureNewByID(batch crowdFixtureWireBatch) map[int64]crowdFixtureWireDecision {
	decisions := make(map[int64]crowdFixtureWireDecision, len(batch.New))
	for _, decision := range batch.New {
		decisions[decision.ID] = decision
	}
	return decisions
}

func crowdFixtureDeletedIDs(batch crowdFixtureWireBatch) map[int64]struct{} {
	ids := make(map[int64]struct{}, len(batch.Deleted))
	for _, decision := range batch.Deleted {
		ids[decision.ID] = struct{}{}
	}
	return ids
}

func TestCrowdFixtureIncrementalStream(t *testing.T) {
	fixture, server := newCrowdFixture(t)
	fixture.set(1, "192.0.2.1", time.Hour)

	snapshot := crowdFixturePoll(t, server.URL, true)
	initial := crowdFixtureNewByID(snapshot)
	if len(initial) != 1 || initial[1].Value != "192.0.2.1" {
		t.Fatalf("initial snapshot = %#v, want decision 1", initial)
	}
	if initial[1].Until == "" || initial[1].Duration != "" {
		t.Fatalf("initial snapshot expiry = %#v, want fixed absolute expiry", initial[1])
	}
	initialUntil := initial[1].Until

	if idle := crowdFixturePoll(t, server.URL, false); len(idle.New) != 0 || len(idle.Deleted) != 0 {
		t.Fatalf("idle incremental poll = %#v, want empty arrays", idle)
	}
	resnapshot := crowdFixtureNewByID(crowdFixturePoll(t, server.URL, true))
	if resnapshot[1].Until != initialUntil {
		t.Fatalf("resnapshot expiry = %q, want unchanged absolute expiry %q", resnapshot[1].Until, initialUntil)
	}

	fixture.set(1, "192.0.2.2", time.Hour)
	fixture.set(2, "2001:db8::2", time.Hour)
	updates := crowdFixtureNewByID(crowdFixturePoll(t, server.URL, false))
	if len(updates) != 2 || updates[1].Value != "192.0.2.2" || updates[2].Value != "2001:db8::2" {
		t.Fatalf("incremental updates = %#v, want latest decisions 1 and 2", updates)
	}
	if idle := crowdFixturePoll(t, server.URL, false); len(idle.New) != 0 || len(idle.Deleted) != 0 {
		t.Fatalf("post-update idle poll = %#v, want empty arrays", idle)
	}

	fixture.remove(1)
	deleted := crowdFixtureDeletedIDs(crowdFixturePoll(t, server.URL, false))
	if len(deleted) != 1 {
		t.Fatalf("deletion delta = %#v, want one deletion", deleted)
	}
	if _, ok := deleted[1]; !ok {
		t.Fatalf("deletion delta = %#v, want ID 1", deleted)
	}
	fixture.set(1, "192.0.2.3", time.Hour)
	readded := crowdFixtureNewByID(crowdFixturePoll(t, server.URL, false))
	if len(readded) != 1 || readded[1].Value != "192.0.2.3" {
		t.Fatalf("re-add delta = %#v, want decision 1", readded)
	}
	fixture.remove(1)
	fixture.set(1, "192.0.2.4", time.Hour)
	removedAndReadded := crowdFixturePoll(t, server.URL, false)
	removed := crowdFixtureDeletedIDs(removedAndReadded)
	readded = crowdFixtureNewByID(removedAndReadded)
	if _, ok := removed[1]; !ok || len(readded) != 1 || readded[1].Value != "192.0.2.4" {
		t.Fatalf("remove/re-add delta = new %#v deleted %#v, want both ID 1 changes", readded, removed)
	}

	fixture.set(3, "192.0.2.3", time.Hour)
	if status, _ := crowdFixtureRequest(t, server.URL, "/v1/decisions/stream", "not-a-boolean"); status != http.StatusBadRequest {
		t.Fatalf("malformed request status = %d, want %d", status, http.StatusBadRequest)
	}
	pending := crowdFixtureNewByID(crowdFixturePoll(t, server.URL, false))
	if len(pending) != 1 || pending[3].Value != "192.0.2.3" {
		t.Fatalf("delta after rejected request = %#v, want decision 3", pending)
	}

	fixture.set(4, "2001:db8::4", time.Hour)
	fixture.changeMode("malformed")
	if status, _ := crowdFixtureRequest(t, server.URL, "/v1/decisions/stream", "false"); status != http.StatusOK {
		t.Fatalf("malformed response status = %d, want %d", status, http.StatusOK)
	}
	fixture.changeMode("")
	pending = crowdFixtureNewByID(crowdFixturePoll(t, server.URL, false))
	if len(pending) != 1 || pending[4].Value != "2001:db8::4" {
		t.Fatalf("delta after malformed response = %#v, want decision 4", pending)
	}

	fixture.set(5, "192.0.2.5", time.Hour)
	fixture.remove(2)
	resync := crowdFixtureNewByID(crowdFixturePoll(t, server.URL, true))
	if len(resync) != 4 {
		t.Fatalf("resynchronization snapshot = %#v, want four active decisions", resync)
	}
	for _, id := range []int64{1, 3, 4, 5} {
		if _, ok := resync[id]; !ok {
			t.Fatalf("resynchronization snapshot missing active ID %d: %#v", id, resync)
		}
	}
	if _, ok := resync[2]; ok {
		t.Fatalf("resynchronization snapshot retained deleted ID 2: %#v", resync)
	}
	if idle := crowdFixturePoll(t, server.URL, false); len(idle.New) != 0 || len(idle.Deleted) != 0 {
		t.Fatalf("post-resynchronization poll = %#v, want empty arrays", idle)
	}
}
