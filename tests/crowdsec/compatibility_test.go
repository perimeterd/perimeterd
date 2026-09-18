//go:build crowdsec

package crowdsec_test

import (
	"context"
	"fmt"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/crowdsec"
)

const (
	crowdSecImage = "docker.io/crowdsecurity/crowdsec:v1.8.1@sha256:0f2523fa61ef507f15d953045cface490cc880670c62f2755ced17524107f71a"
	crowdSecKey   = "perimeterd-real-lapi-compatibility-key"
)

type lapiHarness struct {
	name     string
	endpoint string
	keyPath  string
	client   *crowdsec.Client
}

func TestRealLAPICompatibility(t *testing.T) {
	h := startLAPI(t)
	defer func() { h.client.Close() }()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	clearDecisions(t, h)
	t.Run("dedup_false_preserves_all_ids_for_one_prefix", func(t *testing.T) {
		const value = "198.51.100.13"
		addDecision(t, h, value, "20m")
		addDecision(t, h, value, "40m")

		batch := poll(t, h.client, ctx, true)
		if len(batch.New) != 2 {
			t.Fatalf("dedup=false stream returned %d decisions for one prefix, want 2", len(batch.New))
		}
		prefix := netip.MustParsePrefix(value + "/32")
		ids := make(map[int64]struct{}, len(batch.New))
		for _, decision := range batch.New {
			if decision.Prefix != prefix {
				t.Fatalf("decision %d has prefix %s, want %s", decision.ID, decision.Prefix, prefix)
			}
			if _, duplicate := ids[decision.ID]; duplicate {
				t.Fatalf("stream repeated decision ID %d", decision.ID)
			}
			ids[decision.ID] = struct{}{}
		}
	})

	t.Run("mapped_ipv4_is_admitted_as_ipv4_authority", func(t *testing.T) {
		clearDecisions(t, h)
		addDecision(t, h, "::ffff:198.51.100.77", "40m")
		addDecision(t, h, "198.51.100.78", "40m")
		addDecision(t, h, "::ffff:198.51.101.129/120", "40m")
		batch := poll(t, h.client, ctx, true)
		store := crowdsec.NewStore(h.endpoint, 1)
		if err := store.Apply(batch, 1, time.Now()); err != nil {
			t.Fatalf("server-accepted mapped IP prevented activation: %v", err)
		}
		projection := store.Projection(time.Now())
		want := map[netip.Prefix]bool{
			netip.MustParsePrefix("198.51.100.77/32"): true,
			netip.MustParsePrefix("198.51.100.78/32"): true,
			netip.MustParsePrefix("198.51.101.0/24"):  true,
		}
		if len(projection) != len(want) {
			t.Fatalf("server bans were lost: %v", projection)
		}
		for _, value := range projection {
			if !want[value.Prefix] {
				t.Fatalf("server ban has the wrong address family or range: %s", value.Prefix)
			}
		}
	})

	t.Run("incremental_polls_do_not_replay_active_snapshot", func(t *testing.T) {
		clearDecisions(t, h)
		addDecision(t, h, "198.51.100.19", "40m")
		addDecision(t, h, "198.51.100.20", "40m")
		initial := poll(t, h.client, ctx, true)
		if len(initial.New) != 2 {
			t.Fatalf("initial incremental fixture returned %d decisions, want 2", len(initial.New))
		}
		unchanged := poll(t, h.client, ctx, false)
		if len(unchanged.New) != 0 {
			t.Fatalf("unchanged stream replayed %d active decisions", len(unchanged.New))
		}
		const value = "198.51.100.18"
		addDecision(t, h, value, "40m")
		added := poll(t, h.client, ctx, false)
		if len(added.New) != 1 || added.New[0].Prefix != netip.MustParsePrefix(value+"/32") {
			t.Fatalf("incremental stream = %#v, want only the newly added decision", added.New)
		}
		unchanged = poll(t, h.client, ctx, false)
		if len(unchanged.New) != 0 {
			t.Fatalf("acknowledged decision replayed in subsequent poll: %#v", unchanged.New)
		}
	})

	clearDecisions(t, h)
	t.Run("deleting_longer_overlap_keeps_shorter_id", func(t *testing.T) {
		const value = "198.51.100.14"
		addDecision(t, h, value, "20m")
		addDecision(t, h, value, "40m")
		batch := poll(t, h.client, ctx, true)
		if len(batch.New) != 2 {
			t.Fatalf("overlapping stream returned %d decisions, want 2", len(batch.New))
		}
		shortID, longID := batch.New[0].ID, batch.New[1].ID
		if batch.New[0].Deadline.After(batch.New[1].Deadline) {
			shortID, longID = batch.New[1].ID, batch.New[0].ID
		}
		deleteDecision(t, h, longID)

		delta := poll(t, h.client, ctx, false)
		if !containsID(delta.Deleted, longID) {
			t.Fatalf("deletion stream omitted longer decision ID %d: %#v", longID, delta.Deleted)
		}
		if containsID(delta.Deleted, shortID) {
			t.Fatalf("deletion stream removed shorter decision ID %d", shortID)
		}

		remaining := poll(t, h.client, ctx, true)
		if len(remaining.New) != 1 || remaining.New[0].ID != shortID {
			t.Fatalf("authoritative snapshot after deleting longer ID = %#v, want only %d", remaining.New, shortID)
		}
	})

	clearDecisions(t, h)
	t.Run("reconnect_uses_authoritative_startup_snapshot", func(t *testing.T) {
		addDecision(t, h, "198.51.100.15", "40m")
		addDecision(t, h, "198.51.100.16", "40m")
		initial := poll(t, h.client, ctx, true)
		if len(initial.New) != 2 {
			t.Fatalf("initial reconnect fixture returned %d decisions, want 2", len(initial.New))
		}
		removed := initial.New[0].ID
		retained := initial.New[1].ID
		deleteDecision(t, h, removed)

		h.client.Close()
		replacement := newClient(t, h.endpoint, h.keyPath)
		h.client = replacement
		reconnected := poll(t, replacement, ctx, true)
		if len(reconnected.New) != 1 || reconnected.New[0].ID != retained {
			t.Fatalf("reconnect snapshot = %#v, want only retained ID %d", reconnected.New, retained)
		}
	})

	clearDecisions(t, h)
	t.Run("empty_startup_is_authoritative", func(t *testing.T) {
		empty := poll(t, h.client, ctx, true)
		if !empty.Startup || len(empty.New) != 0 {
			t.Fatalf("empty authoritative snapshot = %#v", empty)
		}
	})
}

func startLAPI(t *testing.T) *lapiHarness {
	t.Helper()
	runtime := containerRuntime()
	if _, err := exec.LookPath(runtime); err != nil {
		t.Fatalf("real CrowdSec gate requires %s in PATH: %v", runtime, err)
	}

	root := t.TempDir()
	keyPath := filepath.Join(root, "api-key")
	if err := os.WriteFile(keyPath, []byte(crowdSecKey+"\n"), 0o600); err != nil {
		t.Fatalf("write LAPI key: %v", err)
	}
	dataPath := filepath.Join(root, "data")
	if err := os.Mkdir(dataPath, 0o750); err != nil {
		t.Fatalf("create isolated LAPI data directory: %v", err)
	}

	name := fmt.Sprintf("perimeterd-crowdsec-%d-%d", os.Getpid(), time.Now().UnixNano())
	network := name + "-net"
	if output, err := runDocker(context.Background(), "network", "create", network); err != nil {
		t.Fatalf("create isolated CrowdSec network: %v\n%s", err, output)
	}
	t.Cleanup(func() {
		_, _ = runDocker(context.Background(), "network", "rm", network)
	})
	args := []string{
		"run", "--pull=missing", "--detach", "--rm", "--name", name, "--network", network,
		"-p", "127.0.0.1::8080",
		"-e", "BOUNCER_KEY_PERIMETERD=" + crowdSecKey,
		"-e", "CROWDSEC_BYPASS_DB_VOLUME_CHECK=true",
		"-e", "DISABLE_AGENT=true",
		"-e", "DISABLE_ONLINE_API=true",
		"-v", dataPath + ":/var/lib/crowdsec/data:rw,Z",
		crowdSecImage,
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = runDocker(ctx, "rm", "--force", name)
	})
	startContext, startCancel := context.WithTimeout(context.Background(), 5*time.Minute)
	output, err := runDocker(startContext, args...)
	startCancel()
	if err != nil {
		t.Fatalf("start pinned CrowdSec LAPI: %v\n%s", err, output)
	}

	var endpoint string
	portDeadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(portDeadline) {
		output, err := runDocker(context.Background(), "port", name, "8080/tcp")
		if err == nil {
			port := strings.TrimSpace(string(output))
			if host, _, splitErr := net.SplitHostPort(port); splitErr == nil {
				_, portNumber, _ := net.SplitHostPort(port)
				endpoint = "http://" + net.JoinHostPort(host, portNumber)
				break
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	if endpoint == "" {
		logs, _ := runDocker(context.Background(), "logs", name)
		t.Fatalf("CrowdSec LAPI did not publish an isolated port\n%s", logs)
	}

	client := newClient(t, endpoint, keyPath)
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	readyDeadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(readyDeadline) {
		if _, err := client.Poll(ctx, true); err == nil {
			return &lapiHarness{name: name, endpoint: endpoint, keyPath: keyPath, client: client}
		}
		time.Sleep(500 * time.Millisecond)
	}
	logs, _ := runDocker(context.Background(), "logs", name)
	client.Close()
	t.Fatalf("CrowdSec LAPI did not register the bouncer\n%s", logs)
	return nil
}

func newClient(t *testing.T, endpoint, keyPath string) *crowdsec.Client {
	t.Helper()
	client, err := crowdsec.NewClient(config.CrowdSecConfig{
		Enabled:    true,
		LAPIURL:    endpoint,
		APIKeyFile: keyPath,
	}, nil)
	if err != nil {
		t.Fatalf("create CrowdSec client: %v", err)
	}
	return client
}

func poll(t *testing.T, client *crowdsec.Client, ctx context.Context, startup bool) crowdsec.Batch {
	t.Helper()
	batch, err := client.Poll(ctx, startup)
	if err != nil {
		t.Fatalf("poll real LAPI startup=%t: %v", startup, err)
	}
	return batch
}

func clearDecisions(t *testing.T, h *lapiHarness) {
	t.Helper()
	if output, err := runDocker(context.Background(), "exec", h.name, "cscli", "-c", "/etc/crowdsec/config.yaml", "decisions", "delete", "--all"); err != nil {
		t.Fatalf("clear LAPI decisions: %v\n%s", err, output)
	}
	pollContext, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	poll(t, h.client, pollContext, true)
}

func addDecision(t *testing.T, h *lapiHarness, value, duration string) {
	t.Helper()
	scope := "--ip"
	if strings.Contains(value, "/") {
		scope = "--range"
	}
	if output, err := runDocker(context.Background(), "exec", h.name, "cscli", "-c", "/etc/crowdsec/config.yaml", "decisions", "add", scope, value, "--duration", duration, "--reason", "perimeterd-real-lapi"); err != nil {
		t.Fatalf("add real LAPI decision %s/%s: %v\n%s", value, duration, err, output)
	}
}

func deleteDecision(t *testing.T, h *lapiHarness, id int64) {
	t.Helper()
	if output, err := runDocker(context.Background(), "exec", h.name, "cscli", "-c", "/etc/crowdsec/config.yaml", "decisions", "delete", "--id", strconv.FormatInt(id, 10)); err != nil {
		t.Fatalf("delete real LAPI decision %d: %v\n%s", id, err, output)
	}
}

func containsID(values []int64, want int64) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func containerRuntime() string {
	runtime := strings.TrimSpace(os.Getenv("CROWDSEC_CONTAINER_RUNTIME"))
	if runtime == "" {
		return "docker"
	}
	return runtime
}

func runDocker(ctx context.Context, args ...string) ([]byte, error) {
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, 30*time.Second)
		defer cancel()
	}
	// #nosec G204 -- runtime and argv are controlled by this isolated test harness; no shell is used.
	cmd := exec.CommandContext(ctx, containerRuntime(), args...)
	output, err := cmd.Output()
	if exit, ok := err.(*exec.ExitError); ok {
		output = append(output, exit.Stderr...)
	}
	if ctx.Err() != nil {
		return output, ctx.Err()
	}
	return output, err
}
