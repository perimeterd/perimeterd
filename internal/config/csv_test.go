package config

import (
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"testing"

	"go.yaml.in/yaml/v3"
)

func csvConfigDocument(csv string) []byte {
	return []byte("version: 1\nfirewall: {backend: nftables}\nip_lists:\n  unused:\n    url: https://example.test/list\n    csv: " + csv + "\n")
}

func TestCSVConfigDefaultsAndExamples(t *testing.T) {
	cases := []struct {
		input string
		want  CSVConfig
	}{
		{"{ip_column: 2}", CSVConfig{Delimiter: ",", IPColumn: 2}},
		{`{delimiter: ";", header: true, ip_column: 1}`, CSVConfig{Delimiter: ";", Header: true, IPColumn: 1}},
		{`{delimiter: ";", header: true, ip_column: 1, filter: {column: 3, op: ">=", value: 1}}`, CSVConfig{Delimiter: ";", Header: true, IPColumn: 1, Filter: CSVFilterConfig{Column: 3, Op: ">=", Value: 1}}},
		{`{delimiter: "\t", header: false, ip_column: 1}`, CSVConfig{Delimiter: "\t", IPColumn: 1}},
		{`{delimiter: "界", ip_column: 1}`, CSVConfig{Delimiter: "界", IPColumn: 1}},
	}
	for _, tc := range cases {
		t.Run(tc.input, func(t *testing.T) {
			cfg, err := Parse(csvConfigDocument(tc.input))
			if err != nil {
				t.Fatal(err)
			}
			got := cfg.IPLists["unused"].CSV
			if got != tc.want {
				t.Fatalf("CSV options = %#v, want %#v", got, tc.want)
			}
			parameters, err := got.Parameters()
			if err != nil {
				t.Fatal(err)
			}
			roundTrip, err := CSVConfigFromParameters(parameters)
			if err != nil || roundTrip != got {
				t.Fatalf("persisted options did not round trip: %#v, %v", roundTrip, err)
			}
		})
	}
}

func TestCSVNumericThresholdCanonicalization(t *testing.T) {
	for _, values := range [][]string{{"1", "1.0", "1e0", "0x1"}, {"0", "0.0", "-0", "-0.0"}, {"0.5", "5e-1"}} {
		var first map[string]string
		for _, value := range values {
			cfg, err := Parse(csvConfigDocument(`{ip_column: 1, filter: {column: 3, op: ">=", value: ` + value + `}}`))
			if err != nil {
				t.Fatalf("threshold %s: %v", value, err)
			}
			c := cfg.IPLists["unused"].CSV
			if c.Filter.Value == 0 && math.Signbit(c.Filter.Value) {
				t.Fatalf("threshold %s retained negative zero", value)
			}
			got, err := c.Parameters()
			if err != nil {
				t.Fatal(err)
			}
			if first == nil {
				first = got
			} else if !reflect.DeepEqual(got, first) {
				t.Fatalf("equivalent threshold %s has different identity: %v != %v", value, got, first)
			}
		}
	}
	for _, op := range []string{"==", "!=", "<", "<=", ">", ">="} {
		if _, err := Parse(csvConfigDocument(`{ip_column: 1, filter: {column: 2, op: "` + op + `", value: -0.5}}`)); err != nil {
			t.Fatalf("operator %s rejected: %v", op, err)
		}
	}
}

func TestCSVConfigStrictRejection(t *testing.T) {
	cases := []string{
		"null", "{}", "[]", "true", "csv", "{unknown: 1, ip_column: 1}", "{ip_column: 1, ip_column: 2}",
		"{ip_column: null}", "{ip_column: 0}", "{ip_column: -1}", `{ip_column: "1"}`, "{ip_column: 1.0}", "{ip_column: true}", "{ip_column: 999999999999999999999999999}",
		"{ip_column: 1, header: null}", "{ip_column: 1, header: 1}", `{ip_column: 1, header: "true"}`, "{ip_column: 1, header: []}",
		"{ip_column: 1, delimiter: null}", "{ip_column: 1, delimiter: 1}", `{ip_column: 1, delimiter: ""}`, `{ip_column: 1, delimiter: "ab"}`,
		`{ip_column: 1, delimiter: "#"}`, `{ip_column: 1, delimiter: "\0"}`, `{ip_column: 1, delimiter: "\r"}`, `{ip_column: 1, delimiter: "\n"}`, `{ip_column: 1, delimiter: "\""}`, `{ip_column: 1, delimiter: "\uFFFD"}`,
		"{ip_column: 1, filter: null}", "{ip_column: 1, filter: []}", "{ip_column: 1, filter: {}}",
		`{ip_column: 1, filter: {column: 2, op: ">="}}`, `{ip_column: 1, filter: {op: ">=", value: 0}}`, "{ip_column: 1, filter: {column: 2, value: 0}}",
		`{ip_column: 1, filter: {column: 0, op: "", value: 0}}`, `{ip_column: 1, filter: {column: -1, op: ">=", value: 0}}`,
		`{ip_column: 1, filter: {column: "2", op: ">=", value: 0}}`, `{ip_column: 1, filter: {column: 2.0, op: ">=", value: 0}}`,
		`{ip_column: 1, filter: {column: null, op: ">=", value: 0}}`, `{ip_column: 1, filter: {column: 2, op: null, value: 0}}`,
		`{ip_column: 1, filter: {column: 2, op: 1, value: 0}}`, `{ip_column: 1, filter: {column: 2, op: " >=", value: 0}}`, `{ip_column: 1, filter: {column: 2, op: "=", value: 0}}`,
		`{ip_column: 1, filter: {column: 2, op: ">=", value: null}}`, `{ip_column: 1, filter: {column: 2, op: ">=", value: "0"}}`,
		`{ip_column: 1, filter: {column: 2, op: ">=", value: true}}`, `{ip_column: 1, filter: {column: 2, op: ">=", value: []}}`,
		`{ip_column: 1, filter: {column: 2, op: ">=", value: .nan}}`, `{ip_column: 1, filter: {column: 2, op: ">=", value: .inf}}`, `{ip_column: 1, filter: {column: 2, op: ">=", value: -.inf}}`,
		`{ip_column: 1, filter: {column: 2, op: ">=", value: 0, extra: true}}`, `{ip_column: 1, filter: {column: 2, op: ">=", value: 0, value: 1}}`,
	}
	for _, input := range cases {
		t.Run(input, func(t *testing.T) {
			if _, err := Parse(csvConfigDocument(input)); err == nil {
				t.Fatalf("invalid unused list accepted: %s", input)
			}
		})
	}
	if _, err := Parse(csvConfigDocument("{ip_column: 1, delimiter: \"" + string([]byte{0xff}) + "\"}")); err == nil {
		t.Fatal("invalid UTF-8 delimiter accepted")
	}
}

func TestCSVLegacySerialization(t *testing.T) {
	cfg, err := Parse([]byte("version: 1\nfirewall: {backend: nftables}\nip_lists: {legacy: {url: https://example.test/list}}\n"))
	if err != nil {
		t.Fatal(err)
	}
	entry := cfg.IPLists["legacy"]
	if !entry.CSV.IsZero() {
		t.Fatal("legacy list selected CSV parsing")
	}
	jsonData, err := json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(jsonData, &fields); err != nil {
		t.Fatal(err)
	}
	if len(fields) != 3 || fields["CSV"] != nil || fields["Transport"] != nil {
		t.Fatalf("legacy JSON fields changed: %s", jsonData)
	}
	yamlData, err := yaml.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(yamlData), "csv:") || strings.Contains(string(yamlData), "transport:") {
		t.Fatalf("legacy YAML fields changed: %s", yamlData)
	}
	entry.CSV = CSVConfig{Delimiter: ",", IPColumn: 1}
	jsonData, err = json.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(jsonData), `"CSV"`) || strings.Contains(string(jsonData), `"Filter"`) {
		t.Fatalf("CSV/filter presence not preserved: %s", jsonData)
	}
	yamlData, err = yaml.Marshal(entry)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(yamlData), "csv:") || strings.Contains(string(yamlData), "filter:") {
		t.Fatalf("CSV/filter YAML presence not preserved: %s", yamlData)
	}
}

func TestCSVParametersRejectNoncanonicalEvidence(t *testing.T) {
	base := CSVConfig{IPColumn: 1, Filter: CSVFilterConfig{Column: 3, Op: ">=", Value: 1}}
	parameters, err := base.Parameters()
	if err != nil {
		t.Fatal(err)
	}
	mutations := map[string][]string{
		"delimiter":     {"", "##", "#", string([]byte{0xff})},
		"header":        {"True", "TRUE", "1", "0", ""},
		"ip_column":     {"01", "+1", "0", "-1", "1.0", " 1", "999999999999999999999999999"},
		"filter_column": {"03", "+3", "0", "-1", "3.0"},
		"filter_op":     {"=", " >=", ""},
		"filter_value":  {"1.0", "1e0", "+1", "01", "NaN", "Inf", "-Inf", " 1", "1e999"},
		"unknown":       {""},
	}
	for key, values := range mutations {
		for _, value := range values {
			bad := make(map[string]string, len(parameters)+1)
			for k, v := range parameters {
				bad[k] = v
			}
			bad[key] = value
			if _, err := CSVConfigFromParameters(bad); err == nil {
				t.Errorf("noncanonical %s=%q accepted", key, value)
			}
		}
	}
	for key := range parameters {
		bad := make(map[string]string, len(parameters))
		for k, v := range parameters {
			if k != key {
				bad[k] = v
			}
		}
		if _, err := CSVConfigFromParameters(bad); err == nil {
			t.Errorf("missing %s accepted", key)
		}
	}
	for _, value := range []string{"-0", "-0.0", "0.0", "+0"} {
		bad := map[string]string{"delimiter": ",", "header": "false", "ip_column": "1", "filter_column": "2", "filter_op": "==", "filter_value": value}
		if _, err := CSVConfigFromParameters(bad); err == nil {
			t.Errorf("noncanonical zero %q accepted", value)
		}
	}
	if _, err := (CSVConfig{}).Parameters(); err == nil {
		t.Fatal("text options accepted as CSV")
	}
	for _, c := range []CSVConfig{
		{IPColumn: 1, Delimiter: string([]byte{0xff})},
		{IPColumn: 1, Filter: CSVFilterConfig{Op: ">="}},
		{IPColumn: 1, Filter: CSVFilterConfig{Column: 2}},
		{IPColumn: 1, Filter: CSVFilterConfig{Column: 2, Op: ">=", Value: math.NaN()}},
		{IPColumn: 1, Filter: CSVFilterConfig{Column: 2, Op: ">=", Value: math.Inf(1)}},
	} {
		if _, err := c.Parameters(); err == nil {
			t.Errorf("invalid programmatic CSV accepted: %#v", c)
		}
	}
	zero := CSVConfig{IPColumn: 1, Filter: CSVFilterConfig{Column: 2, Op: "==", Value: math.Copysign(0, -1)}}
	canonical, err := zero.Parameters()
	if err != nil || canonical["filter_value"] != "0" {
		t.Fatalf("programmatic signed zero not canonicalized: %v, %v", canonical, err)
	}
}
