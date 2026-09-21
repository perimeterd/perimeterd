package crowdsec

import (
	"net/netip"
	"testing"
	"time"
)

func TestStoreUpdatesAndUnknownDeletionAreIdempotent(t *testing.T) {
	now := time.Now()
	store := NewStore("https://lapi.example", 42)
	first := Decision{ID: 7, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Deadline: now.Add(10 * time.Minute)}
	if err := store.Apply(Batch{Startup: true, New: []Decision{first}}, 1, now); err != nil {
		t.Fatal(err)
	}
	if store.Revision() != 1 {
		t.Fatalf("initial admission revision = %d, want 1", store.Revision())
	}
	before := store.Projection(now)
	if err := store.Apply(Batch{Deleted: []int64{999}}, 2, now); err != nil {
		t.Fatal(err)
	}
	if store.Revision() != 1 {
		t.Fatalf("unknown deletion changed revision to %d", store.Revision())
	}
	if len(store.Projection(now)) != len(before) {
		t.Fatalf("unknown deletion changed projection: before=%v after=%v", before, store.Projection(now))
	}

	replacement := Decision{ID: 7, Prefix: netip.MustParsePrefix("198.51.100.0/24"), Deadline: now.Add(20 * time.Minute)}
	if err := store.Apply(Batch{Deleted: []int64{7}, New: []Decision{replacement}}, 3, now); err != nil {
		t.Fatal(err)
	}
	if store.Revision() != 2 {
		t.Fatalf("same-ID replacement revision = %d, want 2", store.Revision())
	}
	projection := store.Projection(now)
	if len(projection) != 1 || projection[0].Prefix != replacement.Prefix || !projection[0].Deadline.Equal(replacement.Deadline) {
		t.Fatalf("replacement projection = %#v", projection)
	}
	if err := store.Apply(Batch{Deleted: []int64{7}, New: []Decision{{ID: 7, Prefix: replacement.Prefix, Deadline: replacement.Deadline}}}, 4, now); err != nil {
		t.Fatal(err)
	}
	if store.Revision() != 3 {
		t.Fatalf("same-ID replacement with identical data revision = %d, want 3", store.Revision())
	}
}

func TestStartupBatchReplacesPreviousEndpointSnapshot(t *testing.T) {
	now := time.Now()
	store := NewStore("lapi", 1)
	old := Decision{ID: 1, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Deadline: now.Add(time.Hour)}
	if err := store.Apply(Batch{Startup: true, New: []Decision{old}}, 1, now); err != nil {
		t.Fatal(err)
	}
	fresh := Decision{ID: 2, Prefix: netip.MustParsePrefix("198.51.100.0/24"), Deadline: now.Add(time.Hour)}
	if err := store.Apply(Batch{Startup: true, Deleted: []int64{1}, New: []Decision{fresh}}, 2, now); err != nil {
		t.Fatal(err)
	}
	if got := store.Projection(now); len(got) != 1 || got[0].Prefix != fresh.Prefix {
		t.Fatalf("startup snapshot retained prior decisions: %#v", got)
	}
}

func TestStoreRejectsStaleAndInvalidBatchesWithoutMutation(t *testing.T) {
	now := time.Now()
	store := NewStore("lapi", 1)
	decision := Decision{ID: 1, Prefix: netip.MustParsePrefix("203.0.113.0/24"), Deadline: now.Add(time.Hour)}
	if err := store.Apply(Batch{New: []Decision{{ID: 0, Prefix: decision.Prefix, Deadline: decision.Deadline}}}, 0, now); err == nil {
		t.Fatal("zero sequence or decision ID was accepted")
	}
	if err := store.Apply(Batch{Deleted: []int64{0}}, 1, now); err == nil {
		t.Fatal("zero deleted decision ID was accepted")
	}
	if err := store.Apply(Batch{Startup: true, New: []Decision{decision}}, 4, now); err != nil {
		t.Fatal(err)
	}
	if err := store.Apply(Batch{New: []Decision{{ID: 2, Prefix: netip.Prefix{}, Deadline: now.Add(time.Hour)}}}, 5, now); err == nil {
		t.Fatal("invalid batch was accepted")
	}
	if err := store.Apply(Batch{Deleted: []int64{1}}, 4, now); err == nil {
		t.Fatal("stale sequence was accepted")
	}
	projection := store.Projection(now)
	if len(projection) != 1 || projection[0].Prefix != decision.Prefix {
		t.Fatalf("failed batches mutated projection: %#v", projection)
	}
}

func TestStoreLateDecisionAndExpiry(t *testing.T) {
	now := time.Now()
	store := NewStore("lapi", 1)
	if err := store.Apply(Batch{Startup: true, New: []Decision{{ID: 1, Prefix: netip.MustParsePrefix("10.0.0.0/8"), Deadline: now.Add(-time.Second)}}}, 1, now); err != nil {
		t.Fatal(err)
	}
	if projection := store.Projection(now); len(projection) != 0 {
		t.Fatalf("late decision projected as active: %#v", projection)
	}

	short := Decision{ID: 2, Prefix: netip.MustParsePrefix("10.0.0.0/8"), Deadline: now.Add(time.Minute)}
	long := Decision{ID: 3, Prefix: netip.MustParsePrefix("10.1.0.0/16"), Deadline: now.Add(2 * time.Minute)}
	if err := store.Apply(Batch{New: []Decision{short, long}}, 2, now); err != nil {
		t.Fatal(err)
	}
	if !store.Expire(now.Add(90 * time.Second)) {
		t.Fatal("expired broad decision was not removed")
	}
	for _, value := range store.Projection(now.Add(90 * time.Second)) {
		if value.Prefix.Contains(netip.MustParseAddr("10.0.1.1")) {
			if !value.Deadline.Equal(long.Deadline) {
				t.Fatalf("remaining deadline = %v, want %v", value.Deadline, long.Deadline)
			}
		}
	}
	if !store.Expire(now.Add(3*time.Minute)) || len(store.Projection(now.Add(3*time.Minute))) != 0 {
		t.Fatal("final expiry did not clear projection")
	}
}

func TestStoreProjectionIsImmutable(t *testing.T) {
	now := time.Now()
	store := NewStore("lapi", 1)
	decision := Decision{ID: 1, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Deadline: now.Add(time.Hour)}
	if err := store.Apply(Batch{Startup: true, New: []Decision{decision}}, 1, now); err != nil {
		t.Fatal(err)
	}
	projection := store.Projection(now)
	projection[0].Prefix = netip.MustParsePrefix("198.51.100.0/24")
	projection[0].Deadline = now.Add(2 * time.Hour)
	again := store.Projection(now)
	if len(again) != 1 || again[0].Prefix != decision.Prefix || !again[0].Deadline.Equal(decision.Deadline) {
		t.Fatalf("projection mutation leaked into store: %#v", again)
	}
}

func TestStoreDecisionsIsImmutableAndDeterministic(t *testing.T) {
	now := time.Now()
	store := NewStore("lapi", 1)
	decisions := []Decision{
		{ID: 9, Prefix: netip.MustParsePrefix("198.51.100.0/24"), Deadline: now.Add(2 * time.Hour)},
		{ID: 3, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Deadline: now.Add(time.Hour)},
	}
	if err := store.Apply(Batch{Startup: true, New: decisions}, 1, now); err != nil {
		t.Fatal(err)
	}
	got := store.Decisions()
	if len(got) != 2 || got[0].ID != 3 || got[1].ID != 9 {
		t.Fatalf("decisions = %#v, want IDs [3 9]", got)
	}
	got[0].Prefix = netip.MustParsePrefix("203.0.113.0/24")
	if again := store.Decisions(); again[0].Prefix != decisions[1].Prefix {
		t.Fatalf("decision mutation leaked into store: %#v", again)
	}
}

func TestStoreFailsClosedWhenRevisionExhausted(t *testing.T) {
	now := time.Now()
	store := NewStore("lapi", 1)
	store.revision = ^uint64(0)
	if err := store.Apply(Batch{Startup: true, New: []Decision{{ID: 1, Prefix: netip.MustParsePrefix("192.0.2.0/24"), Deadline: now.Add(time.Hour)}}}, 1, now); err == nil {
		t.Fatal("revision exhaustion was accepted")
	}
	if len(store.Projection(now)) != 0 {
		t.Fatal("revision exhaustion mutated authoritative state")
	}
}
