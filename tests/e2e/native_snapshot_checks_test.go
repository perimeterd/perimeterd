//go:build linux && e2e

package e2e

import (
	"net/netip"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestNativePhaseSnapshotObservation(t *testing.T) {
	// A fixed, old observation must remain meaningful even when assertions run
	// later. Reusing the bytes must never restart the remaining-lease clock.
	observed := time.Unix(1_700_000_000, 0)
	for _, backend := range []string{"nftables", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			target := nativeScaleTarget(t, backend, nil)
			desired := []policy.TimedPrefix{
				{Prefix: netip.MustParsePrefix("8.20.0.2/32"), Deadline: observed.Add(time.Hour)},
				{Prefix: netip.MustParsePrefix("2600:20::2/128"), Deadline: observed.Add(time.Hour)},
			}
			snapshot, err := decodeNativePhase(backend, nativeProjectionFixture(target, desired, 3599), observed, observed.Add(time.Second))
			if err != nil {
				t.Fatal(err)
			}
			if err := checkSnapshotProjection(target, desired, snapshot, observed); err != nil {
				t.Fatalf("original observation lost: %v", err)
			}
			changed := append([]policy.TimedPrefix(nil), desired...)
			for i := range changed {
				changed[i].Deadline = changed[i].Deadline.Add(time.Hour)
			}
			if err := checkSnapshotProjection(target, changed, snapshot, observed); err == nil {
				t.Fatal("old capture proved unobserved renewal")
			}
			if err := checkSnapshotProjection(target, desired, snapshot, observed.Add(time.Second)); err == nil {
				t.Fatal("capture preceding a new update was reused")
			}
			snapshot.release()
			if _, _, err := snapshot.projectionCount(); err == nil {
				t.Fatal("released snapshot used for counts")
			}
			if err := checkSnapshotProjection(target, desired, snapshot, observed); err == nil {
				t.Fatal("released snapshot used for exact comparison")
			}
		})
	}
}
