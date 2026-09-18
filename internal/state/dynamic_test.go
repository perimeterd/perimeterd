package state

import (
	"net/netip"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/firewall"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestRestartRetainsDynamicContainerButNotDecisionAuthority(t *testing.T) {
	store, dir := openTestStore(t, nil)
	cfg := storeTestConfig(t)
	cfg.CrowdSec.Enabled = true
	cfg.CrowdSec.LAPIURL = "http://127.0.0.1:8080/"
	cfg.CrowdSec.APIKeyFile = "/missing/credential"
	model, err := policy.Compile(cfg, policy.Snapshot{})
	if err != nil {
		t.Fatal(err)
	}
	id := "11111111111111111111111111111111"
	target, err := firewall.BuildTarget(store.Owner(), id, cfg, model, nil)
	if err != nil {
		t.Fatal(err)
	}
	target.Dynamic = &firewall.DynamicState{Prefixes: []policy.TimedPrefix{{
		Prefix: netip.MustParsePrefix("8.20.0.2/32"), Deadline: time.Now().Add(48 * time.Hour),
	}}}
	revision := &Revision{Version: 1, ID: id, Epoch: 1, ConfigPath: "/missing/configuration", Config: cfg, Target: target}
	if err := store.Prepare(nil, revision); err != nil {
		t.Fatal(err)
	}
	if err := store.Commit(revision); err != nil {
		t.Fatal(err)
	}
	reopened, err := Open(dir, nil)
	if err != nil {
		t.Fatal(err)
	}
	view, err := reopened.Read()
	if err != nil {
		t.Fatal(err)
	}
	if view.Active == nil || view.Active.Target == nil {
		t.Fatal("restart lost the recorded enforcement target")
	}
	if view.Active.Target.DynamicGeneration != target.DynamicGeneration || view.Active.Target.DynamicGeneration == "" {
		t.Fatal("restart lost ownership of the retained kernel lease containers")
	}
	if view.Active.Target.Dynamic != nil {
		t.Fatal("restart recovered cached CrowdSec decisions instead of requiring authoritative synchronization")
	}
	if view.Active.Config.CrowdSec.APIKeyFile != cfg.CrowdSec.APIKeyFile {
		t.Fatal("restart lost credential location needed for authoritative synchronization")
	}
}
