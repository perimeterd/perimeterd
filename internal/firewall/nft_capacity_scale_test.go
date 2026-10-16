//go:build linux

package firewall

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"syscall"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/testutil/capacityfixture"
)

// TestNFTProductionCapacityMeasurement is explicitly opt-in. It bypasses
// admission ONLY to measure generated batches in a verified private namespace;
// production admission is covered by the actual-daemon lifecycle E2E gate.
func TestNFTProductionCapacityMeasurement(t *testing.T) {
	if os.Getenv("PERIMETERD_CAPACITY_MEASURE") != "1" {
		t.Skip("set PERIMETERD_CAPACITY_MEASURE=1 for isolated native measurement")
	}
	parent := os.Getenv("PERIMETERD_CAPACITY_PARENT_NETNS")
	current, err := os.Readlink("/proc/self/ns/net")
	if err != nil {
		t.Fatal(err)
	}
	if parent == "" {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		args := []string{"--net", "--fork", "--kill-child"}
		if os.Geteuid() != 0 {
			args = append(args, "--user", "--map-root-user")
		}
		args = append(args, os.Args[0], "-test.run", "^TestNFTProductionCapacityMeasurement$", "-test.v")
		// #nosec G204 G702 -- fixed namespace wrapper re-executes this test binary only.
		cmd := exec.CommandContext(ctx, "unshare", args...)
		cmd.Env = append(os.Environ(), "PERIMETERD_CAPACITY_PARENT_NETNS="+current)
		output, err := cmd.CombinedOutput()
		if err != nil {
			t.Fatalf("private measurement: %v\n%s", err, output)
		}
		t.Logf("%s", output)
		return
	}
	if current == parent || os.Geteuid() != 0 {
		t.Fatal("refusing mutation outside verified private network namespace")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Minute)
	defer cancel()
	var previous *Target
	var oldEstimate int
	for _, stage := range []struct {
		name, id     string
		ssh, refresh bool
	}{
		{"initial", capacityfixture.InitialID, false, false},
		{"ssh", capacityfixture.SSHID, true, false},
		{"unchanged", "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee", true, false},
		{"refresh", capacityfixture.RefreshID, true, true},
	} {
		started := time.Now()
		var compileBefore syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &compileBefore); err != nil {
			t.Fatal(err)
		}
		cfg, model, err := capacityfixture.Compile("capacity_measure", stage.ssh, stage.refresh)
		if err != nil {
			t.Fatal(err)
		}
		target, err := BuildTarget(capacityfixture.Owner, stage.id, cfg, model, previous)
		if err != nil {
			t.Fatal(err)
		}
		var compileAfter syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &compileAfter); err != nil {
			t.Fatal(err)
		}
		t.Logf("stage=%s compile-target-wall=%s compile-target-user=%s compile-target-system=%s", stage.name, time.Since(started), time.Duration(compileAfter.Utime.Nano()-compileBefore.Utime.Nano()), time.Duration(compileAfter.Stime.Nano()-compileBefore.Stime.Nano()))
		total, counts := capacityfixture.Memberships(target.Families)
		if err := capacityfixture.ValidateShared(target.Families, stage.ssh); err != nil {
			t.Fatalf("coalesced or unshared fixture: %v", err)
		}
		batch, err := commandBatch(target, nil, nil)
		if err != nil {
			t.Fatal(err)
		}
		encoded, err := json.Marshal(batch)
		if err != nil {
			t.Fatal(err)
		}
		estimate := 2*len(encoded) + 1024*len(batch.Nftables) + 4096
		capacity, err := validateNFTCapacity(ctx, previous, target, nil)
		if err != nil {
			t.Fatal(err)
		}
		retained := capacity.tables[target.Table]
		t.Logf("stage=%s estimated-input-bytes=%d unique-inventory-estimate=%d static-generations=%d dynamic-generations=%d", stage.name, capacity.inputs[target], retained.estimate(), len(retained.staticIDs), len(retained.dynamicIDs))
		t.Logf("stage=%s static-memberships=%d per-set=%v generation=%s dynamic-generation=%s generated-bytes=%d old-single-estimate=%d old-pair-estimate=%d generator-wall=%s", stage.name, total, counts, target.Generation, target.DynamicGeneration, len(encoded), estimate, estimate+oldEstimate, time.Since(started))
		t.Logf("stage=%s shared-geo-memberships=%d historical-unshared-geo-memberships=%d exact-geo-savings=%d unrelated-memberships=%d", stage.name, capacityfixture.GeoMemberships, 2*capacityfixture.GeoMemberships, capacityfixture.GeoMemberships, capacityfixture.UnrelatedMemberships)
		if previous != nil {
			// Measuring a full pair intentionally materializes both generations.
			// Shared objects are omitted by the real observed-inventory generator.
			inventory, err := NewNFT().inspect(ctx, target.Table)
			if err != nil {
				t.Fatal(err)
			}
			batch, err = commandBatch(target, inventory, nil)
			if err != nil {
				t.Fatal(err)
			}
			encoded, err = json.Marshal(batch)
			if err != nil {
				t.Fatal(err)
			}
			t.Logf("stage=%s retained-old-static=%s retained-new-static=%s shared-static-identity=%t", stage.name, previous.Generation, target.Generation, previous.Generation == target.Generation)
		}
		started = time.Now()
		var nativeUser, nativeSystem time.Duration
		var nativeMaxRSS int64
		if len(batch.Nftables) != 0 {
			cmd := exec.CommandContext(ctx, "nft", "-j", "-f", "-")
			cmd.Stdin = bytes.NewReader(encoded)
			if output, err := cmd.CombinedOutput(); err != nil {
				t.Fatalf("native %s: %v\n%s", stage.name, err, output)
			}
			nativeUser, nativeSystem = cmd.ProcessState.UserTime(), cmd.ProcessState.SystemTime()
			nativeMaxRSS = cmd.ProcessState.SysUsage().(*syscall.Rusage).Maxrss
		} else {
			// Match the backend: unchanged inventory requires no native mutation.
			encoded = nil
		}
		nativeWall := time.Since(started)
		// #nosec G204 -- table is generated locally and mutation requires a verified private namespace.
		listed := exec.CommandContext(ctx, "nft", "-j", "list", "table", "inet", target.Table)
		inventory, err := listed.Output()
		if err != nil {
			t.Fatal(err)
		}
		var memory runtime.MemStats
		runtime.ReadMemStats(&memory)
		var generator syscall.Rusage
		if err := syscall.Getrusage(syscall.RUSAGE_SELF, &generator); err != nil {
			t.Fatal(err)
		}
		t.Logf("stage=%s generator-maxrss-kib=%d generator-user=%v generator-system=%v", stage.name, generator.Maxrss, generator.Utime, generator.Stime)
		t.Logf("stage=%s mutation-bytes=%d native-inventory-bytes=%d native-wall=%s native-user=%s native-system=%s native-maxrss-kib=%d generator-heap-bytes=%d", stage.name, len(encoded), len(inventory), nativeWall, nativeUser, nativeSystem, nativeMaxRSS, memory.HeapAlloc)
		t.Log("native child rusage maxrss is an upper bound: it may include inherited pre-exec generator RSS, not only nft resident memory")
		if previous != nil {
			observed, err := NewNFT().inspect(ctx, target.Table)
			if err != nil {
				t.Fatal(err)
			}
			for _, retained := range []*Target{previous, target} {
				for _, family := range retained.Families {
					for _, set := range family.Sets {
						if !observed.hasSet(setName(retained, family.Family, set.ID)) {
							t.Fatalf("missing real retained native set: generation=%s family=%d id=%s", retained.Generation, family.Family, set.ID)
						}
					}
				}
			}
			if err := NewNative(nil).Retire(ctx, previous, target); err != nil {
				t.Fatal(fmt.Errorf("retire measured pair: %w", err))
			}
		}
		previous, oldEstimate = target, estimate
	}
}
