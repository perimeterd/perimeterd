//go:build linux && e2e

package e2e

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/firewall"
)

type nativePhaseMember struct {
	interval  nativeProjectionInterval
	remaining int64
}

type nativePhaseSet struct {
	Name    string
	Timed   bool
	Members []nativePhaseMember
}

// UnmarshalJSON keeps no static element tree. Timed members are decoded once
// into the independent test oracle's interval representation.
func (set *nativePhaseSet) UnmarshalJSON(data []byte) error {
	var metadata struct {
		Name  string   `json:"name"`
		Flags []string `json:"flags"`
	}
	if err := json.Unmarshal(data, &metadata); err != nil {
		return err
	}
	set.Name = metadata.Name
	for _, flag := range metadata.Flags {
		set.Timed = set.Timed || flag == "timeout"
	}
	if !set.Timed {
		return nil
	}
	var elements struct {
		Elements []struct {
			Element struct {
				Value   json.RawMessage `json:"val"`
				Timeout int64           `json:"timeout"`
				Expires int64           `json:"expires"`
			} `json:"elem"`
		} `json:"elem"`
	}
	if err := json.Unmarshal(data, &elements); err != nil {
		return err
	}
	set.Members = make([]nativePhaseMember, 0, len(elements.Elements))
	for _, item := range elements.Elements {
		if item.Element.Timeout <= 0 || item.Element.Timeout > 86400 || item.Element.Expires > item.Element.Timeout {
			return fmt.Errorf("invalid nft timeout/expiry in %s", set.Name)
		}
		member, err := nativeProjectionNFTMember(item.Element.Value)
		if err != nil {
			return err
		}
		set.Members = append(set.Members, nativePhaseMember{interval: member, remaining: item.Element.Expires})
	}
	return nil
}

type nativeCapture struct {
	scope             string
	started, finished time.Time
	bytes             int64
	user, system      time.Duration
	maxRSSKiB         int64
}

// nativePhaseSnapshot belongs to one acknowledged phase. It retains only one
// parsed view, never a raw inventory alongside several generic JSON trees.
// release ends ownership; a later mutation always requires a new capture.
type nativePhaseSnapshot struct {
	backend           string
	phase             string
	target            *firewall.Target
	started, finished time.Time // Actual set observation, used for lease checks.
	sets              map[string]*nativePhaseSet
	nftRules          map[string][]byte
	rules             map[string]string
	captures          []nativeCapture
	decode            time.Duration
	released          bool
}

func decodeNativePhase(backend string, data []byte, started, finished time.Time) (*nativePhaseSnapshot, error) {
	snapshot := &nativePhaseSnapshot{backend: backend, started: started, finished: finished, sets: make(map[string]*nativePhaseSet), nftRules: make(map[string][]byte), rules: make(map[string]string)}
	if backend == "nftables" {
		var response struct {
			Objects []struct {
				Set  *nativePhaseSet `json:"set"`
				Rule *struct {
					Chain string          `json:"chain"`
					Expr  json.RawMessage `json:"expr"`
				} `json:"rule"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal(data, &response); err != nil {
			return nil, err
		}
		for _, object := range response.Objects {
			if object.Set != nil {
				if _, duplicate := snapshot.sets[object.Set.Name]; duplicate {
					return nil, fmt.Errorf("duplicate native set %q", object.Set.Name)
				}
				snapshot.sets[object.Set.Name] = object.Set
			}
			if object.Rule != nil {
				snapshot.nftRules[object.Rule.Chain] = append(snapshot.nftRules[object.Rule.Chain], object.Rule.Expr...)
			}
		}
		return snapshot, nil
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	for scanner.Scan() {
		fields := strings.Fields(scanner.Text())
		if len(fields) < 3 {
			continue
		}
		switch fields[0] {
		case "create":
			if _, duplicate := snapshot.sets[fields[1]]; duplicate {
				return nil, fmt.Errorf("duplicate native set %q", fields[1])
			}
			set := &nativePhaseSet{Name: fields[1]}
			for _, field := range fields[3:] {
				set.Timed = set.Timed || field == "timeout"
			}
			snapshot.sets[set.Name] = set
		case "add":
			set := snapshot.sets[fields[1]]
			if set == nil {
				return nil, fmt.Errorf("native member precedes set %q", fields[1])
			}
			if !set.Timed {
				continue
			}
			if len(fields) != 5 || fields[3] != "timeout" {
				return nil, fmt.Errorf("malformed timed ipset member in %s", set.Name)
			}
			seconds, err := strconv.ParseInt(fields[4], 10, 64)
			if err != nil {
				return nil, err
			}
			member, err := nativeProjectionMember(fields[2])
			if err != nil {
				return nil, err
			}
			set.Members = append(set.Members, nativePhaseMember{interval: member, remaining: seconds})
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return snapshot, nil
}

func captureNativePhase(t *testing.T, target *firewall.Target, phase string, withRules bool) *nativePhaseSnapshot {
	t.Helper()
	backend := target.Backend()
	timeout := 3 * time.Minute
	if backend == "iptables" {
		timeout = 30 * time.Second
		if withRules {
			timeout = time.Minute
		}
	}
	var captures []nativeCapture
	capture := func(scope string, args ...string) ([]byte, nativeCapture) {
		recordE2EPhase(t, e2ePhaseRecord{Backend: backend, Profile: "native", Phase: phase, Event: "capture_start", Resource: scope})
		ctx, cancel := context.WithTimeout(t.Context(), timeout)
		defer cancel()
		started := time.Now()
		// #nosec G204 G702 -- complete fixed native inventory commands; target table is one validated fixture argv value.
		cmd := exec.CommandContext(ctx, args[0], args[1:]...)
		data, err := cmd.Output()
		result := nativeCapture{scope: scope, started: started, finished: time.Now(), bytes: int64(len(data))}
		if cmd.ProcessState != nil {
			usage := cmd.ProcessState.SysUsage().(*syscall.Rusage)
			result.user, result.system, result.maxRSSKiB = cmd.ProcessState.UserTime(), cmd.ProcessState.SystemTime(), usage.Maxrss
		}
		outcome := "success"
		if err != nil {
			outcome = "failure"
		}
		recordE2EPhase(t, e2ePhaseRecord{Backend: backend, Profile: "native", Phase: phase, Event: "capture", Resource: scope, Outcome: outcome, CaptureCommands: 1, CaptureBytes: result.bytes, DurationNS: result.finished.Sub(started).Nanoseconds(), ChildUserNS: result.user.Nanoseconds(), ChildSystemNS: result.system.Nanoseconds(), ChildMaxRSSKiB: result.maxRSSKiB})
		if err != nil {
			t.Fatalf("phase=%s complete %s inventory: %v", phase, scope, err)
		}
		captures = append(captures, result)
		return data, result
	}
	var data []byte
	var observed nativeCapture
	if backend == "nftables" {
		data, observed = capture("nft-table", "nft", "-j", "list", "table", "inet", target.Table)
	} else {
		data, observed = capture("ipsets", "ipset", "save")
	}
	decodeStarted := time.Now()
	snapshot, err := decodeNativePhase(backend, data, observed.started, observed.finished)
	if err != nil {
		t.Fatalf("phase=%s decode complete native inventory: %v", phase, err)
	}
	snapshot.decode = time.Since(decodeStarted)
	snapshot.phase = phase
	snapshot.target = target
	recordE2EPhase(t, e2ePhaseRecord{Backend: backend, Profile: "native", Phase: phase, Event: "decode", Outcome: "success", DurationNS: snapshot.decode.Nanoseconds()})
	// End raw-data ownership before any separate family capture.
	data = nil
	if backend == "iptables" && withRules {
		for _, family := range []struct{ name, command string }{{"v4", "iptables-save"}, {"v6", "ip6tables-save"}} {
			output, _ := capture(family.name+"-rules", family.command, "-c")
			snapshot.rules[family.name] = string(output)
		}
	}
	snapshot.captures = captures
	return snapshot
}

func (snapshot *nativePhaseSnapshot) release() {
	snapshot.sets, snapshot.nftRules, snapshot.rules = nil, nil, nil
	snapshot.target = nil
	snapshot.released = true
}

func (snapshot *nativePhaseSnapshot) projectionCount() (int, int, error) {
	if snapshot == nil || snapshot.released {
		return 0, 0, fmt.Errorf("native phase snapshot is no longer owned")
	}
	members, sets := 0, 0
	for _, set := range snapshot.sets {
		if set.Timed {
			sets++
			members += len(set.Members)
		}
	}
	return members, sets, nil
}

func assertSnapshotProjectionCount(t *testing.T, snapshot *nativePhaseSnapshot, want int) {
	t.Helper()
	members, sets, err := snapshot.projectionCount()
	if err != nil || members != want || sets != 2 {
		t.Fatalf("native projection has %d members across %d timed sets, want %d in two live sets (%v)", members, sets, want, err)
	}
}

func snapshotNativeReferences(snapshot *nativePhaseSnapshot, target *firewall.Target, separate bool) (int, error) {
	if snapshot == nil || snapshot.released || snapshot.backend != "nftables" {
		return 0, fmt.Errorf("native reference snapshot is unavailable")
	}
	for _, family := range []string{"v4", "v6"} {
		var ingress, egress string
		for chain, data := range snapshot.nftRules {
			if !strings.Contains(chain, target.Generation) || !strings.Contains(chain, "path_"+family+"_") {
				continue
			}
			for name := range snapshot.sets {
				if !strings.Contains(name, target.Generation) || !strings.Contains(name, "geo_") || strings.Contains(name, "ssh") || strings.Contains(name, "eligible") {
					continue
				}
				if strings.Contains(string(data), "@"+name+"\"") {
					if strings.HasSuffix(chain, "_ingress") {
						ingress = name
					}
					if strings.HasSuffix(chain, "_egress") {
						egress = name
					}
				}
			}
		}
		if ingress == "" || egress == "" || ((ingress != egress) != separate) {
			return 0, fmt.Errorf("native %s refs ingress=%s egress=%s separate=%t", family, ingress, egress, separate)
		}
	}
	return len(snapshot.sets), nil
}

func assertSnapshotForeignIPTables(t *testing.T, snapshot *nativePhaseSnapshot, family string) {
	t.Helper()
	if snapshot == nil || snapshot.released || !strings.Contains(snapshot.rules[family], "e2e-foreign") {
		t.Fatalf("%s foreign rules missing from complete phase inventory", family)
	}
	tool := "iptables"
	if family == "v6" {
		tool = "ip6tables"
	}
	for _, chain := range []string{"E2EI", "E2EO"} {
		command(t, 10*time.Second, tool, "-C", chain, "-m", "comment", "--comment", "e2e-foreign\ncomment", "-j", "RETURN")
	}
}

func measureNativePhase(t *testing.T, daemon *daemonProcess, target *firewall.Target, phase string, started time.Time, snapshot *nativePhaseSnapshot) {
	t.Helper()
	if snapshot == nil || snapshot.released {
		t.Fatal("phase measurement requires its owned snapshot")
	}
	totalBytes := int64(0)
	for _, capture := range snapshot.captures {
		totalBytes += capture.bytes
		t.Logf("phase=%s scope=%s complete-inventory-bytes=%d capture-wall=%s child-user=%s child-system=%s child-maxrss-kib=%d", phase, capture.scope, capture.bytes, capture.finished.Sub(capture.started), capture.user, capture.system, capture.maxRSSKiB)
	}
	t.Logf("phase=%s native-capture-commands=%d native-capture-bytes=%d decode=%s wall=%s", phase, len(snapshot.captures), totalBytes, snapshot.decode, time.Since(started))
	if daemon == nil {
		return
	}
	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/status", daemon.cmd.Process.Pid))
	if err != nil {
		t.Fatal(err)
	}
	for line := range strings.SplitSeq(string(data), "\n") {
		if strings.HasPrefix(line, "VmHWM:") {
			fields := strings.Fields(line)
			peak, err := strconv.ParseInt(fields[1], 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			recordE2EPhase(t, e2ePhaseRecord{Backend: target.Backend(), Profile: "native", Phase: phase, Event: "process_peak", DaemonMaxRSSKiB: peak})
			t.Logf("phase=%s daemon-%s (cumulative process peak; not phase allocation or kernel memory)", phase, line)
		}
	}
	t.Log("inspection child rusage may inherit the fixture parent's pre-exec RSS peak")
}
