//go:build linux && e2e

package e2e

import (
	"context"
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
	first.Dynamic = &firewall.DynamicState{Prefixes: projection}
	backend := firewall.NewNative(nil)
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	defer cancel()
	if err := backend.Preflight(ctx, nil, first); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, nil, first); err != nil {
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
	if refreshed.Dynamic != nil || refreshed.DynamicGeneration != first.DynamicGeneration {
		t.Fatal("static refresh captured decisions or replaced the active lease container")
	}
	if err := backend.Preflight(ctx, first, refreshed); err != nil {
		t.Fatal(err)
	}
	if err := backend.Apply(ctx, first, refreshed); err != nil {
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
