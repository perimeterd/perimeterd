//go:build linux && e2e

package e2e

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestE2ECrowdSecNativeLeases(t *testing.T) {
	if os.Getenv(e2eChildEnv) != "1" {
		for _, variant := range []string{"nftables", "iptables-legacy", "iptables-nft"} {
			t.Run(variant, func(t *testing.T) { runIsolated(t, "TestE2ECrowdSecNativeLeases", variant) })
		}
		return
	}
	requireIsolatedChild(t)
	prepareMounts(t)
	peer := newPeerNamespace(t)
	kind := os.Getenv(e2eScenario)
	if strings.HasPrefix(kind, "iptables-") {
		installIPTablesTools(t, strings.TrimPrefix(kind, "iptables-"))
		kind = "iptables"
	}
	cfg, err := config.Parse([]byte(fmt.Sprintf(`version: 1
firewall:
  backend: %s
  deny_action: reject
crowdsec:
  enabled: true
  api_key_file: /unused/native-only-fixture
`, kind)))
	if err != nil {
		t.Fatal(err)
	}
	model, err := policy.Compile(cfg, policy.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	const owner = "11111111111111111111111111111111"
	first, err := firewall.BuildTarget(owner, "22222222222222222222222222222222", cfg, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(49 * time.Hour)
	projection := []policy.TimedPrefix{
		{Prefix: netip.MustParsePrefix(fixtureIPv4Peer + "/32"), Deadline: deadline},
		{Prefix: netip.MustParsePrefix(fixtureIPv6Peer + "/128"), Deadline: deadline},
	}
	backend := firewall.NewNative(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := backend.Preflight(ctx, nil, first, &firewall.DynamicState{Prefixes: projection}); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, nil, first, &firewall.DynamicState{Prefixes: projection}); err != nil {
		t.Fatal(err)
	}
	defer func() {
		if err := backend.Cleanup(context.Background(), []*firewall.Target{first}); err != nil {
			t.Error(err)
		}
	}()
	assertNativeCrowdLease(t, first, 86400)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18780", "reject", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18780", "reject", "tcp")

	// Renew the exact unchanged desired projection; this is not a new source
	// decision or a rebased 49-hour duration. The native grant stays bounded.
	if err := backend.UpdateDynamic(ctx, first, projection); err != nil {
		t.Fatal(err)
	}
	assertNativeCrowdLease(t, first, 86400)
	cfg.Global.Blocklist = []netip.Prefix{netip.MustParsePrefix("192.0.2.0/24")}
	model, err = policy.Compile(cfg, policy.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	refreshed, err := firewall.BuildTarget(owner, "33333333333333333333333333333333", cfg, model, first)
	if err != nil {
		t.Fatal(err)
	}
	if refreshed.DynamicGeneration != first.DynamicGeneration {
		t.Fatal("static refresh replaced the active lease container")
	}
	if err := backend.Preflight(ctx, first, refreshed, nil); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, first, refreshed, nil); err != nil {
		t.Fatal(err)
	}
	if err := backend.Retire(ctx, first, refreshed); err != nil {
		t.Fatal(err)
	}
	first = refreshed
	assertNativeCrowdLease(t, refreshed, 86400)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18781", "reject", "tcp")

	// A shortened decision must replace the longer lease, not retain a larger
	// observed timeout. With no app expiry worker, only the kernel can unblock.
	for index := range projection {
		projection[index].Deadline = time.Now().Add(5 * time.Second)
	}
	if err := backend.UpdateDynamic(ctx, refreshed, projection); err != nil {
		t.Fatal(err)
	}
	assertNativeCrowdLease(t, refreshed, 5)
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18782", "reject", "tcp")
	waitCrowdPacket(t, peer, "tcp4", fixtureIPv4Host+":18783", "success")
	waitCrowdPacket(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18783", "success")
	for index := range projection {
		projection[index].Deadline = time.Now().Add(500 * time.Millisecond)
	}
	if err := backend.UpdateDynamic(ctx, refreshed, projection); err != nil {
		t.Fatal(err)
	}
	probeIngress(t, peer, "tcp4", fixtureIPv4Host+":18784", "success", "tcp")
	probeIngress(t, peer, "tcp6", "["+fixtureIPv6Host+"]:18784", "success", "tcp")
}

func assertNativeCrowdLease(t *testing.T, target *firewall.Target, ceiling int64) {
	t.Helper()
	count := 0
	if target.Backend() == "nftables" {
		data := command(t, 10*time.Second, "nft", "-j", "list", "table", "inet", target.Table)
		var response struct {
			NFTables []struct {
				Set *struct {
					Flags    []string          `json:"flags"`
					Elements []json.RawMessage `json:"elem"`
				} `json:"set"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal(data, &response); err != nil {
			t.Fatal(err)
		}
		for _, object := range response.NFTables {
			if object.Set == nil || !strings.Contains(strings.Join(object.Set.Flags, ","), "timeout") {
				continue
			}
			for _, raw := range object.Set.Elements {
				var item struct {
					Element struct {
						Timeout int64 `json:"timeout"`
						Expires int64 `json:"expires"`
					} `json:"elem"`
				}
				if err := json.Unmarshal(raw, &item); err != nil {
					t.Fatal(err)
				}
				if item.Element.Timeout <= 0 || item.Element.Timeout > ceiling || item.Element.Expires > item.Element.Timeout {
					t.Fatalf("unsafe native nft lease: %+v", item.Element)
				}
				count++
			}
		}
	} else {
		data := command(t, 10*time.Second, "ipset", "save")
		for line := range strings.Lines(string(data)) {
			fields := strings.Fields(line)
			if len(fields) < 3 || fields[0] != "add" || (fields[2] != fixtureIPv4Peer && fields[2] != fixtureIPv6Peer) {
				continue
			}
			if len(fields) != 5 || fields[3] != "timeout" {
				t.Fatalf("native ipset lease is permanent or malformed: %s", line)
			}
			timeout, err := strconv.ParseInt(fields[4], 10, 64)
			if err != nil || timeout <= 0 || timeout > ceiling {
				t.Fatalf("unsafe native ipset lease: %s", line)
			}
			count++
		}
	}
	if count != 2 {
		t.Fatalf("wanted independently leased IPv4 and IPv6 elements, got %d", count)
	}
}

// assertNativeProjection inspects the complete native inventory after an
// acknowledged update. Relative native grants are calculated before encoding
// and executing the write, so expiry validation includes that measured window
// as well as the read window and whole-second rounding. The bounded windows
// cannot hide the fixture's one-hour renewal. Capped authority exposes only
// its finite native grant; the fixture renews below that cap.
func assertNativeProjection(t *testing.T, target *firewall.Target, desired []policy.TimedPrefix, updatedAfter time.Time) {
	t.Helper()
	started := time.Now()
	var data []byte
	if target.Backend() == "nftables" {
		data = command(t, 3*time.Minute, "nft", "-j", "list", "table", "inet", target.Table)
	} else {
		data = command(t, 3*time.Minute, "ipset", "save")
	}
	finished := time.Now()
	if err := checkNativeProjection(target, desired, data, started, finished, updatedAfter); err != nil {
		t.Fatalf("native projection inspection (%s, %d bytes): %v", finished.Sub(started), len(data), err)
	}
}

type nativeProjectionInterval struct {
	first netip.Addr
	last  netip.Addr
}

func nativeProjectionPrefix(prefix netip.Prefix) nativeProjectionInterval {
	prefix = prefix.Masked()
	first := prefix.Addr()
	bits := first.As16()
	start := prefix.Bits()
	if first.Is4() {
		start += 96
	}
	for bit := start; bit < 128; bit++ {
		bits[bit/8] |= 1 << (7 - bit%8)
	}
	last := netip.AddrFrom16(bits)
	if first.Is4() {
		last = last.Unmap()
	}
	return nativeProjectionInterval{first: first, last: last}
}

func nativeProjectionMember(text string) (nativeProjectionInterval, error) {
	if prefix, err := netip.ParsePrefix(text); err == nil {
		return nativeProjectionPrefix(prefix), nil
	}
	address, err := netip.ParseAddr(text)
	if err != nil {
		return nativeProjectionInterval{}, fmt.Errorf("invalid native member %q: %w", text, err)
	}
	return nativeProjectionInterval{first: address, last: address}, nil
}

func nativeProjectionNFTMember(raw json.RawMessage) (nativeProjectionInterval, error) {
	var text string
	if err := json.Unmarshal(raw, &text); err == nil {
		return nativeProjectionMember(text)
	}
	var value struct {
		Prefix *struct {
			Address string `json:"addr"`
			Length  int    `json:"len"`
		} `json:"prefix"`
		Range []string `json:"range"`
	}
	if err := json.Unmarshal(raw, &value); err != nil {
		return nativeProjectionInterval{}, err
	}
	if value.Prefix != nil && len(value.Range) == 0 {
		return nativeProjectionMember(fmt.Sprintf("%s/%d", value.Prefix.Address, value.Prefix.Length))
	}
	if value.Prefix == nil && len(value.Range) == 2 {
		first, err := netip.ParseAddr(value.Range[0])
		if err != nil {
			return nativeProjectionInterval{}, err
		}
		last, err := netip.ParseAddr(value.Range[1])
		if err != nil || first.BitLen() != last.BitLen() || first.Compare(last) > 0 {
			return nativeProjectionInterval{}, fmt.Errorf("invalid native range %s", raw)
		}
		return nativeProjectionInterval{first: first, last: last}, nil
	}
	return nativeProjectionInterval{}, fmt.Errorf("unsupported native member %s", raw)
}

// The names bind the inspected timeout containers to this target, not merely
// any two timed sets in the namespace. Static/unrelated non-timeout sets are
// ignored, while a leftover spare or an unexpected timed set is an error.
func nativeProjectionNames(target *firewall.Target) map[string]bool {
	names := make(map[string]bool, 2)
	for _, family := range []string{"v4", "v6"} {
		name := "pd_" + target.Owner + "_" + target.DynamicGeneration + "_dynamic_" + family
		if target.Backend() != "nftables" {
			digest := sha256.Sum256([]byte(strings.Join([]string{"dynamic", target.Owner, target.DynamicGeneration, family, "crowdsec"}, "\x00")))
			name = fmt.Sprintf("pd%sd%x", family, digest[:13])
		}
		names[name] = family == "v4"
	}
	return names
}

func checkNativeProjection(target *firewall.Target, desired []policy.TimedPrefix, data []byte, started, finished, updatedAfter time.Time) error {
	if finished.Before(started) || finished.Sub(started) > 3*time.Minute {
		return fmt.Errorf("invalid or unbounded native inspection window")
	}
	if updatedAfter.IsZero() || updatedAfter.After(started) || started.Sub(updatedAfter) > 10*time.Minute {
		return fmt.Errorf("invalid or unbounded native update window")
	}
	writeDelay := started.Sub(updatedAfter)
	remaining := make(map[nativeProjectionInterval]time.Time, len(desired))
	for _, value := range desired {
		if !value.Prefix.IsValid() || value.Deadline.IsZero() {
			return fmt.Errorf("invalid desired native member: %+v", value)
		}
		member := nativeProjectionPrefix(value.Prefix)
		if _, exists := remaining[member]; exists {
			return fmt.Errorf("duplicate desired member %s", value.Prefix)
		}
		remaining[member] = value.Deadline
	}
	names := nativeProjectionNames(target)
	seenSets := make(map[string]bool, len(names))
	observe := func(name string, member nativeProjectionInterval, seconds int64) error {
		ipv4, known := names[name]
		if !known || member.first.Is4() != ipv4 {
			return fmt.Errorf("unexpected native set/family %q: %+v", name, member)
		}
		deadline, exists := remaining[member]
		if !exists {
			return fmt.Errorf("unexpected or duplicate native member in %s: %+v", name, member)
		}
		if seconds <= 0 || seconds > 86400 {
			return fmt.Errorf("non-finite or over-cap native lease for %+v: %ds", member, seconds)
		}
		// The relative grant is planned before native execution. Its expiry
		// can advance by at most the measured update-to-acknowledgement window.
		// Native tools also round displayed remaining lifetimes to seconds.
		earliest := started.Add(time.Duration(seconds)*time.Second - 2*time.Second)
		latest := finished.Add(time.Duration(seconds)*time.Second + 2*time.Second)
		if deadline.Sub(updatedAfter) <= 24*time.Hour && (deadline.Add(writeDelay).Before(earliest) || !deadline.Before(latest)) {
			return fmt.Errorf("native lease deadline mismatch for %+v: desired=%s write-window=%s observed=[%s,%s)", member, deadline, writeDelay, earliest, latest)
		}
		delete(remaining, member)
		return nil
	}
	if target.Backend() == "nftables" {
		var response struct {
			NFTables []struct {
				Set *struct {
					Name     string            `json:"name"`
					Flags    []string          `json:"flags"`
					Elements []json.RawMessage `json:"elem"`
				} `json:"set"`
			} `json:"nftables"`
		}
		if err := json.Unmarshal(data, &response); err != nil {
			return err
		}
		for _, row := range response.NFTables {
			if row.Set == nil {
				continue
			}
			set := row.Set
			timed := false
			for _, flag := range set.Flags {
				timed = timed || flag == "timeout"
			}
			if !timed {
				continue
			}
			if _, known := names[set.Name]; !known || seenSets[set.Name] {
				return fmt.Errorf("unexpected or duplicate timed nft set %q", set.Name)
			}
			seenSets[set.Name] = true
			for _, raw := range set.Elements {
				var item struct {
					Element struct {
						Value   json.RawMessage `json:"val"`
						Timeout int64           `json:"timeout"`
						Expires int64           `json:"expires"`
					} `json:"elem"`
				}
				if err := json.Unmarshal(raw, &item); err != nil {
					return err
				}
				if item.Element.Timeout <= 0 || item.Element.Timeout > 86400 || item.Element.Expires > item.Element.Timeout {
					return fmt.Errorf("invalid nft timeout/expiry: %s", raw)
				}
				member, err := nativeProjectionNFTMember(item.Element.Value)
				if err != nil {
					return err
				}
				if err := observe(set.Name, member, item.Element.Expires); err != nil {
					return err
				}
			}
		}
	} else {
		for line := range strings.SplitSeq(string(data), "\n") {
			fields := strings.Fields(line)
			if len(fields) < 3 {
				continue
			}
			if fields[0] == "create" {
				timed := false
				for _, field := range fields[3:] {
					timed = timed || field == "timeout"
				}
				if !timed {
					continue
				}
				if _, known := names[fields[1]]; !known || seenSets[fields[1]] {
					return fmt.Errorf("unexpected or duplicate timed ipset %q", fields[1])
				}
				seenSets[fields[1]] = true
			}
			if fields[0] != "add" || !seenSets[fields[1]] {
				continue
			}
			if len(fields) != 5 || fields[3] != "timeout" {
				return fmt.Errorf("malformed timed ipset member: %s", line)
			}
			seconds, err := strconv.ParseInt(fields[4], 10, 64)
			if err != nil {
				return err
			}
			member, err := nativeProjectionMember(fields[2])
			if err != nil {
				return err
			}
			if err := observe(fields[1], member, seconds); err != nil {
				return err
			}
		}
	}
	if len(seenSets) != len(names) {
		return fmt.Errorf("native timed sets: got %d, want %d", len(seenSets), len(names))
	}
	if len(remaining) != 0 {
		return fmt.Errorf("native projection is missing %d desired members", len(remaining))
	}
	return nil
}

func TestNativeProjectionValidation(t *testing.T) {
	started := time.Date(2026, time.November, 3, 12, 0, 0, 0, time.UTC)
	finished := started.Add(1500 * time.Millisecond)
	oldDeadline := started.Add(12 * time.Hour)
	newDeadline := oldDeadline.Add(time.Hour)
	// Match the reported false positive exactly: deleting the two peers
	// leaves 149998 old members, but does not install 1000 replacements.
	const count = 149998
	old := make([]policy.TimedPrefix, count)
	for index := range old {
		address := netip.AddrFrom4([4]byte{11, byte(index >> 16), byte(index >> 8), byte(index)})
		old[index] = policy.TimedPrefix{Prefix: netip.PrefixFrom(address, 32), Deadline: oldDeadline}
	}
	desired := append([]policy.TimedPrefix(nil), old...)
	for index := range desired {
		desired[index].Deadline = newDeadline
		if index < 1000 {
			desired[index].Prefix = netip.PrefixFrom(netip.AddrFrom4([4]byte{12, 0, byte(index >> 8), byte(index)}), 32)
		}
	}
	for _, backend := range []string{"nftables", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			target := nativeScaleTarget(t, backend, nil)
			for _, scenario := range []struct {
				name   string
				actual []policy.TimedPrefix
				want   string
			}{
				{name: "exact-renewed-projection", actual: desired},
				{name: "same-count-deleted-peers-without-replacements", actual: old, want: "unexpected or duplicate native member"},
				{name: "correct-membership-stale-leases", actual: desired, want: "deadline mismatch"},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					seconds := int64(13*60*60 - 1)
					if scenario.want == "deadline mismatch" {
						seconds = 12*60*60 - 1
					}
					data := nativeProjectionFixture(target, scenario.actual, seconds)
					err := checkNativeProjection(target, desired, data, started, finished, started)
					if scenario.want == "" {
						if err != nil {
							t.Fatal(err)
						}
					} else if err == nil || !strings.Contains(err.Error(), scenario.want) {
						t.Fatalf("wanted %q rejection, got %v", scenario.want, err)
					}
				})
			}
		})
	}
}

// Fixture encoding is deliberately separate from parsing, but every regression
// uses the same parser/comparator as the real native inspection.
func nativeProjectionFixture(target *firewall.Target, actual []policy.TimedPrefix, seconds int64) []byte {
	var output strings.Builder
	if target.Backend() == "nftables" {
		output.WriteString(`{"nftables":[`)
	}
	firstSet := true
	for name, ipv4 := range nativeProjectionNames(target) {
		if target.Backend() == "nftables" {
			if !firstSet {
				output.WriteByte(',')
			}
			fmt.Fprintf(&output, `{"set":{"name":%q,"flags":["interval","timeout"],"elem":[`, name)
		} else {
			fmt.Fprintf(&output, "create %s hash:net timeout 86400\n", name)
		}
		firstSet = false
		firstMember := true
		for _, value := range actual {
			if value.Prefix.Addr().Is4() != ipv4 {
				continue
			}
			if target.Backend() == "nftables" {
				if !firstMember {
					output.WriteByte(',')
				}
				fmt.Fprintf(&output, `{"elem":{"val":%q,"timeout":%d,"expires":%d}}`, value.Prefix.String(), seconds+1, seconds)
			} else {
				fmt.Fprintf(&output, "add %s %s timeout %d\n", name, value.Prefix, seconds)
			}
			firstMember = false
		}
		if target.Backend() == "nftables" {
			output.WriteString(`]}}`)
		}
	}
	if target.Backend() == "nftables" {
		output.WriteString(`]}`)
	}
	return []byte(output.String())
}

func TestNativeProjectionParsing(t *testing.T) {
	now := time.Date(2026, time.November, 3, 12, 0, 0, 0, time.UTC)
	deadline := now.Add(time.Hour)
	desired := []policy.TimedPrefix{
		{Prefix: netip.MustParsePrefix("192.0.2.0/31"), Deadline: deadline},
		{Prefix: netip.MustParsePrefix("2001:db8::/127"), Deadline: deadline},
	}
	for _, backend := range []string{"nftables", "iptables"} {
		t.Run(backend, func(t *testing.T) {
			target := nativeScaleTarget(t, backend, nil)
			valid := nativeProjectionFixture(target, desired, 3599)
			for _, scenario := range []struct {
				name string
				data []byte
				want string
			}{
				{name: "both-families-prefixes", data: valid},
				{name: "missing-member", data: nativeProjectionFixture(target, desired[:1], 3599), want: "missing 1"},
				{name: "duplicate-member", data: nativeProjectionFixture(target, append(append([]policy.TimedPrefix(nil), desired...), desired[0]), 3599), want: "duplicate native member"},
				{name: "permanent-member", data: nativeProjectionFixture(target, desired, 0), want: "non-finite"},
				{name: "over-cap-member", data: nativeProjectionFixture(target, desired, 86401)},
				{name: "shortened-lease-not-applied", data: nativeProjectionFixture(target, desired, 7200), want: "deadline mismatch"},
			} {
				t.Run(scenario.name, func(t *testing.T) {
					err := checkNativeProjection(target, desired, scenario.data, now, now.Add(time.Second), now)
					if scenario.name == "both-families-prefixes" {
						if err != nil {
							t.Fatal(err)
						}
					} else if err == nil || (scenario.want != "" && !strings.Contains(err.Error(), scenario.want)) {
						t.Fatalf("wanted %q rejection, got %v", scenario.want, err)
					}
				})
			}
			static := append([]byte(nil), valid...)
			if backend == "nftables" {
				static = []byte(strings.Replace(string(valid), `{"nftables":[`, `{"nftables":[{"set":{"name":"unrelated-static","elem":["198.51.100.1"]}},`, 1))
			} else {
				static = append(static, []byte("create unrelated-static hash:net\nadd unrelated-static 198.51.100.1\n")...)
			}
			if err := checkNativeProjection(target, desired, static, now, now, now); err != nil {
				t.Fatalf("unrelated static set affected projection: %v", err)
			}
			capped := append([]policy.TimedPrefix(nil), desired...)
			for index := range capped {
				capped[index].Deadline = now.Add(49 * time.Hour)
			}
			if err := checkNativeProjection(target, capped, nativeProjectionFixture(target, capped, 86399), now, now, now); err != nil {
				t.Fatalf("bounded 24h native grant rejected: %v", err)
			}
			if err := checkNativeProjection(target, desired, valid, now, now.Add(3*time.Minute+time.Nanosecond), now); err == nil {
				t.Fatal("unbounded inspection window accepted")
			}
			if err := checkNativeProjection(target, desired, valid, now, now, now.Add(-10*time.Minute-time.Nanosecond)); err == nil {
				t.Fatal("unbounded update window accepted")
			}
			// Relative timeouts can start later than planning; the observed
			// write window bounds that delay without hiding an hour-old lease.
			if err := checkNativeProjection(target, desired, nativeProjectionFixture(target, desired, 3633), now, now.Add(time.Second), now.Add(-time.Minute)); err != nil {
				t.Fatalf("measured native write latency rejected: %v", err)
			}
			if err := checkNativeProjection(target, desired, nativeProjectionFixture(target, desired, 7199), now, now.Add(time.Second), now.Add(-time.Minute)); err == nil {
				t.Fatal("one-minute write window hid a one-hour stale lease")
			}
			// Non-timeout sets have no bearing on dynamic equality, but an
			// unexpected timeout set must not be hidden by correct live sets.
			unexpected := append([]byte(nil), valid...)
			if backend == "nftables" {
				unexpected = []byte(strings.Replace(string(valid), `{"nftables":[`, `{"nftables":[{"set":{"name":"unexpected","flags":["timeout"],"elem":[]}},`, 1))
			} else {
				unexpected = append(unexpected, []byte("create unexpected hash:net timeout 86400\n")...)
			}
			if err := checkNativeProjection(target, desired, unexpected, now, now, now); err == nil || !strings.Contains(err.Error(), "unexpected") {
				t.Fatalf("unexpected timed container accepted: %v", err)
			}
		})
	}
	for _, pair := range []struct {
		value string
		want  string
	}{
		{value: `"192.0.2.1"`, want: "192.0.2.1/32"},
		{value: `"2001:db8::1"`, want: "2001:db8::1/128"},
		{value: `{"prefix":{"addr":"192.0.2.0","len":31}}`, want: "192.0.2.0/31"},
		{value: `{"prefix":{"addr":"2001:db8::","len":127}}`, want: "2001:db8::/127"},
		{value: `{"range":["2001:db8::","2001:db8::1"]}`, want: "2001:db8::/127"},
	} {
		member, err := nativeProjectionNFTMember([]byte(pair.value))
		if err != nil || member != nativeProjectionPrefix(netip.MustParsePrefix(pair.want)) {
			t.Fatalf("parse %s: %+v (%v), want %s", pair.value, member, err, pair.want)
		}
	}
}
