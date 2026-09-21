package cli

import (
	"bytes"
	"net/netip"
	"strings"
	"testing"

	"github.com/perimeterd/perimeterd/internal/lookup"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestParseLookupFlagsBeforeAndAfterInput(t *testing.T) {
	port := uint16(0)
	request, jsonOutput, help, err := parseLookupArgs([]string{"--direction", "ingress", "8.8.8.1/24", "--protocol=tcp", "--port", "0", "--json"})
	if err != nil {
		t.Fatal(err)
	}
	if help || !jsonOutput {
		t.Fatalf("help=%t json=%t, want help=false json=true", help, jsonOutput)
	}
	want := lookup.Request{Address: "8.8.8.0/24", Direction: policy.Ingress, Protocol: "tcp", Port: &port}
	if request.Address != want.Address || request.Direction != want.Direction || request.Protocol != want.Protocol || request.Port == nil || *request.Port != 0 {
		t.Fatalf("request = %#v, want %#v", request, want)
	}
}

func TestParseLookupRejectsUsageAndExplicitEmptyTraffic(t *testing.T) {
	for _, args := range [][]string{
		{"8.8.8.8", "9.9.9.9"},
		{"8.8.8.8", "--port", "443"},
		{"8.8.8.8", "--direction", ""},
		{"8.8.8.8", "--protocol="},
		{"8.8.8.8", "--config", "policy.yaml"},
	} {
		if _, _, help, err := parseLookupArgs(args); help || err == nil {
			t.Fatalf("args %v parsed as help=%t err=%v", args, help, err)
		}
	}
}

func TestLookupHelpDoesNotRequireDaemon(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"lookup", "--help"}, &stdout, &stderr); code != 0 {
		t.Fatalf("lookup help exit code = %d, want 0 (stderr %q)", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "Usage: perimeterd lookup") {
		t.Fatalf("lookup help = %q", stdout.String())
	}
}

func TestLookupJSONUsageErrorIsStructured(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := Run([]string{"lookup", "8.8.8.8", "--direction=", "--json"}, &stdout, &stderr); code != 2 {
		t.Fatalf("lookup invalid JSON usage exit code = %d, want 2", code)
	}
	if !strings.Contains(stdout.String(), `"verdict":"unknown"`) || stderr.Len() != 0 {
		t.Fatalf("JSON usage output = %q stderr = %q", stdout.String(), stderr.String())
	}
}

func TestLookupHumanOutputIncludesEvidenceAndPartitions(t *testing.T) {
	var output bytes.Buffer
	response := lookup.Response{
		SchemaVersion: lookup.SchemaVersion,
		Query:         lookup.Request{Address: "8.8.8.0/24"},
		Flow:          "new",
		Verdict:       "mixed",
		Revision:      "revision",
		Manifest:      "manifest",
		Outcomes: []lookup.Outcome{{
			Prefix:    netip.MustParsePrefix("8.8.8.0/25"),
			Direction: policy.Ingress,
			Protocol:  "tcp",
			Verdict:   "blocked",
			Action:    policy.Drop,
			Stage:     "policy",
			Reason:    "deny",
			Attachment: lookup.Attachment{
				Name:      "external",
				Managed:   true,
				PortBasis: "destination",
			},
			Evidence: []lookup.Evidence{{Kind: "country", Name: "US", Role: "include", Prefix: netip.MustParsePrefix("8.0.0.0/8"), Contributing: true}},
		}},
	}
	if err := writeLookupHuman(&output, response); err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"8.8.8.0/25", "external", "Evidence:", "8.0.0.0/8", "Revision: revision", "Manifest: manifest"} {
		if !strings.Contains(output.String(), want) {
			t.Fatalf("human output missing %q: %s", want, output.String())
		}
	}
}
