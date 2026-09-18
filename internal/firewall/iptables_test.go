package firewall

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestNativeIPTablesFailurePreservesCommandError(t *testing.T) {
	_, err := nativeIPTablesExecutor(context.Background(), "perimeterd-command-that-does-not-exist", nil, nil)
	if err == nil || !strings.Contains(err.Error(), "perimeterd-command-that-does-not-exist") {
		t.Fatalf("native command failure lost executable context: %v", err)
	}
}

func TestIPTablesDiscoveryRejectsMixedToolFamilies(t *testing.T) {
	mixed := false
	backend := &IPTables{exec: func(_ context.Context, command string, args []string, _ []byte) ([]byte, error) {
		if len(args) == 1 && args[0] == "--version" {
			if mixed && command == "ip6tables-restore" {
				return []byte("iptables v1.8.10 (legacy)"), nil
			}
			return []byte("iptables v1.8.10 (nf_tables)"), nil
		}
		return nil, errors.New("unexpected probe")
	}}
	if err := backend.probe(context.Background()); err != nil {
		t.Fatal(err)
	}
	mixed = true
	if err := backend.probe(context.Background()); err == nil {
		t.Fatalf("mixed command families were accepted: %v", err)
	}
}

func TestIPTablesSavePreservesCountersAndRejectsMalformedProtocol(t *testing.T) {
	inventory, err := parseIPTablesSave(policy.IPv4, []byte("*filter\n:INPUT ACCEPT [0:0]\n[42:9001] -A INPUT -m comment --comment \"two words\" -j RETURN\n[4:200] -A INPUT\nCOMMIT\n"))
	if err != nil {
		t.Fatal(err)
	}
	rule := inventory.Rules[0]
	if rule.Packets != 42 || rule.Bytes != 9001 || !slices.Equal(slices.Collect(rule.references(iptCommentReference)), []string{"two words"}) {
		t.Fatalf("lost counters or comment: %+v", rule)
	}
	if counterOnly := inventory.Rules[1]; len(counterOnly.Args) != 0 || counterOnly.Packets != 4 || counterOnly.Bytes != 200 {
		t.Fatalf("lost counter-only rule: %+v", counterOnly)
	}
	for _, input := range []string{
		"*filter\n:INPUT ACCEPT [0:0]\n-A INPUT --comment \"unterminated\nCOMMIT\n",
		"*filter\n:INPUT ACCEPT [0:0]\n",
		"*filter\n:INPUT ACCEPT [0:0]\n[bad:0] -A INPUT -j RETURN\nCOMMIT\n",
	} {
		if _, err := parseIPTablesSave(policy.IPv4, []byte(input)); err == nil {
			t.Fatalf("accepted malformed save: %q", input)
		}
	}
}

func TestIPTablesRuleComparisonPreservesMatchSemantics(t *testing.T) {
	model := []string{"-m", "conntrack", "--ctstate", "ESTABLISHED,RELATED", "-j", "RETURN", "-m", "comment", "--comment", "owned"}
	saved := []string{"-m", "conntrack", "--ctstate", "RELATED,ESTABLISHED", "-m", "comment", "--comment", "owned", "-j", "RETURN"}
	if !sameIPTRule(model, saved) {
		t.Fatal("native option ordering changed equivalent rule identity")
	}
	if sameIPTRule(model, append([]string{"!"}, saved...)) || sameIPTRule(model, append(saved, "-m", "addrtype")) {
		t.Fatal("different matching semantics adopted as the recorded rule")
	}
}

func TestIPSetSaveAcceptsForeignTypesAndNormalizesHostPrefixes(t *testing.T) {
	sets, err := parseIPSetSave([]byte("create foreign bitmap:port range 1-65535\nadd foreign 443\ncreate owned hash:net family inet hashsize 1024 maxelem 65536\nadd owned 203.0.113.1\n"))
	if err != nil {
		t.Fatal(err)
	}
	if sets["foreign"].Type != "bitmap:port" || sets["owned"].Entries[0] != "203.0.113.1/32" {
		t.Fatalf("incorrect native inventory: %+v", sets)
	}
}

func TestIPSetSaveRetainsFiniteDynamicTimeouts(t *testing.T) {
	sets, err := parseIPSetSave([]byte("create owned hash:net family inet maxelem 65536 timeout 86400\nadd owned 198.51.100.1 timeout 37\n"))
	if err != nil {
		t.Fatal(err)
	}
	owned := sets["owned"]
	if !owned.Extended || owned.UnknownOptions || owned.Timeouts["198.51.100.1/32"] != 37 {
		t.Fatalf("dynamic timeout metadata was not retained safely: %+v", owned)
	}
}

func TestIPTDynamicZeroPrefixRetainsOneDeadline(t *testing.T) {
	deadline := time.Now().Add(time.Hour)
	values := loweredIPTTimedPrefixes([]policy.TimedPrefix{{Prefix: policyPrefix("0.0.0.0/0"), Deadline: deadline}}, policy.IPv4)
	if len(values) != 2 || values[0].Deadline != deadline || values[1].Deadline != deadline ||
		values[0].Prefix.String() != "0.0.0.0/1" || values[1].Prefix.String() != "128.0.0.0/1" {
		t.Fatalf("zero prefix did not lower with retained deadline: %#v", values)
	}
}

func policyPrefix(value string) netip.Prefix { return netip.MustParsePrefix(value) }

func TestIPTablesInventorySeparatesTableAndParentNames(t *testing.T) {
	backend := &IPTables{exec: func(_ context.Context, command string, _ []string, _ []byte) ([]byte, error) {
		if command == "ipset" {
			return nil, nil
		}
		return []byte("*filter\n:raw:OUTPUT - [0:0]\nCOMMIT\n*raw\n:OUTPUT ACCEPT [0:0]\nCOMMIT\n"), nil
	}}
	inventory, err := backend.inspect(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Chains) != 4 {
		t.Fatalf("different table/parent identities collided: %+v", inventory.Chains)
	}
	parent := inventory.Chains[chainKey(policy.IPv4, "raw:OUTPUT")]
	if parent.Chain != "raw:OUTPUT" || parent.Table != "filter" || parent.Family != policy.IPv4 {
		t.Fatalf("foreign raw table replaced configured filter parent: %+v", parent)
	}
}

func TestIPTablesCapacityPreservesInspectionHeadroom(t *testing.T) {
	inventory := newIPTInventory()
	expected := &iptExpected{
		chains: map[iptChainKey][]iptChain{
			chainKey(policy.IPv4, "pdcandidate"): {{Name: "pdcandidate", Rules: []iptRule{{Args: []string{"-j", "RETURN"}}}}},
		},
		sets: map[string]iptSet{"candidate": {Name: "candidate", Family: policy.IPv4}},
	}
	if err := validateIPTCapacity(inventory, expected); err != nil {
		t.Fatal(err)
	}
	inventory.SetBytes = 48 << 20
	if err := validateIPTCapacity(inventory, expected); err == nil {
		t.Fatal("staging could consume ipset inspection headroom")
	}
	inventory.SetBytes = 0
	inventory.TableBytes[policy.IPv4] = 48 << 20
	if err := validateIPTCapacity(inventory, expected); err == nil {
		t.Fatal("staging could consume rule inspection headroom")
	}
}

func TestIPTablesSavePreservesMultilineQuotedComments(t *testing.T) {
	data := `# generated by "tool's unmatched header quote
*filter
:INPUT ACCEPT [0:0]
[7:42] -A INPUT -m comment --comment "first \"quoted\"
COMMIT
*raw
# embedded header
last\\tail" -j RETURN
[3:12] -A INPUT -j RETURN
COMMIT
# completed '
`
	inventory, err := parseIPTablesSave(policy.IPv4, []byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(inventory.Rules) != 2 {
		t.Fatalf("quoted content changed rule boundaries: %+v", inventory.Rules)
	}
	want := "first \"quoted\"\nCOMMIT\n*raw\n# embedded header\nlast\\tail"
	rule := inventory.Rules[0]
	if !slices.Equal(slices.Collect(rule.references(iptCommentReference)), []string{want}) || rule.Packets != 7 || rule.Bytes != 42 {
		t.Fatalf("multiline comment or counters changed: %+v", rule)
	}
	if inventory.Rules[1].Packets != 3 || !slices.Equal(slices.Collect(inventory.Rules[1].references(iptJumpReference)), []string{"RETURN"}) {
		t.Fatalf("following rule was absorbed into the comment: %+v", inventory.Rules[1])
	}
}

func TestIPSetSavePreservesRecordsAfterMultilineComments(t *testing.T) {
	data := `# generated "
create foreign hash:net family inet comment
add foreign 203.0.113.1 comment "first
create fake hash:net
last"
create other hash:net family inet
add other 198.51.100.1
`
	sets, err := parseIPSetSave([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 2 || !sets["foreign"].Extended || sets["foreign"].Entries[0] != "203.0.113.1/32" || sets["other"].Entries[0] != "198.51.100.1/32" {
		t.Fatalf("quoted comment changed set records: %+v", sets)
	}
	for _, record := range []string{
		"add foreign 203.0.113.1 comment \"unterminated\n",
		"add foreign 203.0.113.1 comment \"closed\"junk\n",
	} {
		if _, err := parseIPSetSave([]byte("create foreign hash:net\n" + record)); err == nil {
			t.Fatalf("malformed quoted record accepted: %q", record)
		}
	}
}

func TestIPSetSaveCommentsCannotHideFollowingSets(t *testing.T) {
	data := `create foreign_a hash:net family inet comment
add foreign_a 203.0.113.1 comment "trailing\"
create owned hash:net family inet
add owned 198.51.100.1
create foreign_b hash:net family inet comment
add foreign_b 203.0.113.1 comment "trailing\"
`
	sets, err := parseIPSetSave([]byte(data))
	if err != nil {
		t.Fatal(err)
	}
	if len(sets) != 3 || len(sets["owned"].Entries) != 1 || sets["owned"].Entries[0] != "198.51.100.1/32" {
		t.Fatalf("foreign comments hid a set or its entries: %+v", sets)
	}
}

func TestIPSetSavePreservesLiteralQuotedFields(t *testing.T) {
	data := "# header with unmatched \" quote\n" +
		"add foreign 203.0.113.1 comment \"C:\\new\\tab\\\nowner's path\\\"\n" +
		"add foreign 203.0.113.2 comment \"\""
	var records [][]string
	for fields, err := range ipsetSaveRecords(data) {
		if err != nil {
			t.Fatal(err)
		}
		records = append(records, fields)
	}
	if len(records) != 2 || len(records[0]) != 5 || records[0][4] != "C:\\new\\tab\\\nowner's path\\" || len(records[1]) != 5 || records[1][4] != "" {
		t.Fatalf("literal fields or record boundaries changed: %#v", records)
	}
}

func TestIPSetInspectionRejectsIncompleteExactQueries(t *testing.T) {
	name := "pdv4s" + strings.Repeat("a", 26)
	other := "pdv4s" + strings.Repeat("b", 26)
	expected := map[string]iptSet{name: {Name: name, Family: policy.IPv4}}
	commandErr := errors.New("native query failed")
	for _, tc := range []struct {
		name   string
		output string
		err    error
	}{
		{name: "command error", err: commandErr},
		{name: "empty response"},
		{name: "wrong identity", output: "create " + other + " hash:net family inet\n"},
		{name: "extra identity", output: "create " + name + " hash:net family inet\ncreate " + other + " hash:net family inet\n"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &IPTables{exec: func(_ context.Context, _ string, args []string, _ []byte) ([]byte, error) {
				if slices.Equal(args, []string{"list", "-name"}) {
					return []byte(name + "\n"), nil
				}
				return []byte(tc.output), tc.err
			}}
			err := backend.inspectSets(context.Background(), expected, newIPTInventory())
			if err == nil {
				t.Fatal("incomplete inspection was accepted as missing ownership")
			}
			if tc.err != nil && !errors.Is(err, commandErr) {
				t.Fatalf("native query failure was lost: %v", err)
			}
		})
	}
}

func TestIPSetInspectionRequiresUnambiguousRecordedNames(t *testing.T) {
	backend := &IPTables{exec: func(context.Context, string, []string, []byte) ([]byte, error) {
		return nil, nil
	}}
	err := backend.inspectSets(context.Background(), map[string]iptSet{
		"short": {Name: "short", Family: policy.IPv4},
	}, newIPTInventory())
	if err == nil {
		t.Fatal("short name could be forged by a foreign newline-containing name")
	}
}

func TestIPTablesPreflightRejectsExactCandidateSetCollision(t *testing.T) {
	target := testTarget(t, testGenA)
	target.Table, target.Priority = "filter", 0
	target.IPTables = &IPTablesTarget{Attachments: []config.Attachment{{Chain: "INPUT", Direction: "ingress"}}}
	expected, err := expectedIPTWithProjection(nil, target)
	if err != nil {
		t.Fatal(err)
	}
	var collision iptSet
	for _, set := range expected.sets {
		collision = set
		break
	}
	var saved strings.Builder
	fmt.Fprintf(&saved, "create %s hash:net family %s\n", collision.Name, familySetName(collision.Family))
	for _, prefix := range collision.Prefixes {
		fmt.Fprintf(&saved, "add %s %s\n", collision.Name, prefix)
	}
	present := false
	backend := &IPTables{exec: func(_ context.Context, command string, args []string, _ []byte) ([]byte, error) {
		if slices.Equal(args, []string{"--version"}) {
			return []byte(command + " v1.8.11 (nf_tables)"), nil
		}
		if command != "ipset" {
			return nil, nil
		}
		if slices.Equal(args, []string{"list", "-name"}) {
			if present {
				return []byte(collision.Name + "\n"), nil
			}
			return nil, nil
		}
		if slices.Equal(args, []string{"save", collision.Name}) {
			return []byte(saved.String()), nil
		}
		if slices.Equal(args, []string{"list", collision.Name, "-output", "xml", "-terse"}) {
			return fmt.Appendf(nil, `<ipsets><ipset name="%s"><header><references>0</references></header></ipset></ipsets>`, collision.Name), nil
		}
		return nil, errors.New("unexpected native query")
	}}
	if err := backend.Preflight(context.Background(), nil, target, nil); err != nil {
		t.Fatal(err)
	}
	present = true
	if err := backend.Preflight(context.Background(), nil, target, nil); err == nil {
		t.Fatal("candidate adopted an existing unrecorded set with matching contents")
	}
}

func TestIPTablesOwnershipInspectionSeparatesOptionsAndOperands(t *testing.T) {
	expected := &iptExpected{
		chains: map[iptChainKey][]iptChain{chainKey(policy.IPv4, "owned"): nil},
		sets:   map[string]iptSet{"owned_set": {}},
		owners: map[string]bool{"recorded": true},
	}
	for _, tc := range []struct {
		name string
		rule string
	}{
		{"comment hides jump", `-m comment --comment "-j" -j owned`},
		{"interface and comment resemble flags", `-i -j -m comment --comment "-g" -g owned`},
		{"later ownership comment", `-m comment --comment "--comment" -m comment --comment "owner=recorded" -j RETURN`},
		{"set match after option-like comment", `-m comment --comment "--match-set" -m set --match-set owned_set src -j RETURN`},
		{"second set target operand", `-j SET --add-set foreign src --del-set owned_set dst`},
		{"opaque extension before marker", `-m opaque --value "--comment" --flag -m comment --comment "owner=recorded" -j RETURN`},
		{"ambiguous opaque operand", `-m opaque --value --comment -j owned`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			inventory, err := parseIPTablesSave(policy.IPv4, []byte("*filter\n:INPUT ACCEPT [0:0]\n-A INPUT "+tc.rule+"\nCOMMIT\n"))
			if err != nil {
				t.Fatal(err)
			}
			if err := validateIPTInventory(inventory, expected); err == nil {
				t.Fatal("unrecorded ownership reference escaped inspection")
			}
		})
	}
}

func TestIPSetInspectionRequiresAccountedNativeReferences(t *testing.T) {
	name := "pdv4s" + strings.Repeat("a", 26)
	expected := &iptExpected{sets: map[string]iptSet{name: {Name: name, Family: policy.IPv4}}}
	document := func(body string) string {
		return `<ipsets><ipset name="` + name + `"><header>` + body + `</header></ipset></ipsets>`
	}
	queryErr := errors.New("native reference query failed")
	for _, tc := range []struct {
		name   string
		output string
		err    error
		allow  bool
	}{
		{name: "unreferenced set", output: document("<references>0</references>"), allow: true},
		{name: "unaccounted reference", output: document("<references>1</references>")},
		{name: "missing count", output: document("")},
		{name: "empty count", output: document("<references/>")},
		{name: "duplicate count", output: document("<references>1</references><references>0</references>")},
		{name: "negative count", output: document("<references>-1</references>")},
		{name: "wrong identity", output: strings.ReplaceAll(document("<references>0</references>"), name, "other")},
		{name: "extra identity", output: `<ipsets><ipset name="` + name + `"><header><references>0</references></header></ipset><ipset name="other"/></ipsets>`},
		{name: "trailing document", output: document("<references>0</references>") + "<ipsets/>"},
		{name: "query failure", err: queryErr},
	} {
		t.Run(tc.name, func(t *testing.T) {
			backend := &IPTables{exec: func(_ context.Context, command string, args []string, _ []byte) ([]byte, error) {
				if slices.Equal(args, []string{"--version"}) {
					return []byte(command + " v1.8.11 (nf_tables)"), nil
				}
				if command != "ipset" {
					return nil, nil
				}
				if slices.Equal(args, []string{"list", "-name"}) {
					return []byte(name + "\n"), nil
				}
				if slices.Equal(args, []string{"save", name}) {
					return []byte("create " + name + " hash:net family inet\n"), nil
				}
				return []byte(tc.output), tc.err
			}}
			_, err := backend.inspectTargets(context.Background(), expected)
			if (err == nil) != tc.allow {
				t.Fatalf("ownership inspection returned %v, allow=%v", err, tc.allow)
			}
			if tc.err != nil && !errors.Is(err, queryErr) {
				t.Fatalf("native query failure was lost: %v", err)
			}
		})
	}
}
