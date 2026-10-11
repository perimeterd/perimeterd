package source

import (
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestCSVFeedShapesAndQuoting(t *testing.T) {
	for _, test := range []struct {
		name, body   string
		options      config.CSVConfig
		want4, want6 []string
	}{
		{"daily", "# generated\n\nip_address;autonomous_system\n198.51.100.1;AS1\n2001:db8::1;AS2;extra\n198.51.100.42/24;AS3\n198.51.100.0/24;AS4\n", config.CSVConfig{Delimiter: ";", Header: true, IPColumn: 1}, []string{"198.51.100.0/24"}, []string{"2001:db8::1/128"}},
		{"blocklist", "# generated\n\nip_address;autonomous_system;confidence\n198.51.100.42/24;AS1;1\n192.0.2.1;AS2;0.9\n2001:db8::42/64;AS3;2;extra\n", config.CSVConfig{Delimiter: ";", Header: true, IPColumn: 1, Filter: config.CSVFilterConfig{Column: 3, Op: ">=", Value: 1}}, []string{"198.51.100.0/24"}, []string{"2001:db8::/64"}},
		{"quoted", "\"label, with \"\"quote\"\"\nand newline\",\" \t192.0.2.1\t \"\r\nignored,2001:db8::1", config.CSVConfig{IPColumn: 2}, []string{"192.0.2.1/32"}, []string{"2001:db8::1/128"}},
		{"tab", "unused\t198.51.100.1\n", config.CSVConfig{Delimiter: "\t", IPColumn: 2}, []string{"198.51.100.1/32"}, []string{}},
		{"quoted-hash", "\"# not a comment\",192.0.2.1\n# ignored\n", config.CSVConfig{IPColumn: 2}, []string{"192.0.2.1/32"}, []string{}},
	} {
		t.Run(test.name, func(t *testing.T) {
			record, err := parseCSVList([]byte(test.body), "https://example.com/feed?secret=hidden", policy.Selector{Kind: policy.IPList, Value: "feed"}, test.options)
			if err != nil {
				t.Fatal(err)
			}
			if got := prefixStrings(record.IPv4); !reflect.DeepEqual(got, test.want4) {
				t.Fatalf("IPv4 = %v, want %v", got, test.want4)
			}
			if got := prefixStrings(record.IPv6); !reflect.DeepEqual(got, test.want6) {
				t.Fatalf("IPv6 = %v, want %v", got, test.want6)
			}
			if record.APIVersion != csvFormatVersion || record.SourceKind != listSourceKind {
				t.Fatalf("incorrect CSV identity: %+v", record)
			}
		})
	}
}

func TestCSVNumericComparisons(t *testing.T) {
	for _, test := range []struct {
		op        string
		threshold float64
		want      []string
	}{
		{"==", 1, []string{"192.0.2.2/32"}},
		{"!=", 1, []string{"192.0.2.1/32", "192.0.2.3/32"}},
		{"<", 1, []string{"192.0.2.1/32"}},
		{"<=", 1, []string{"192.0.2.1/32", "192.0.2.2/32"}},
		{">", 1, []string{"192.0.2.3/32"}},
		{">=", 1, []string{"192.0.2.2/32", "192.0.2.3/32"}},
		{"==", 0, []string{"192.0.2.1/32"}},
		{">", 0.5, []string{"192.0.2.2/32", "192.0.2.3/32"}},
		{">", 2, []string{"192.0.2.3/32"}},
	} {
		t.Run(fmt.Sprintf("%s-%g", test.op, test.threshold), func(t *testing.T) {
			options := config.CSVConfig{IPColumn: 1, Filter: config.CSVFilterConfig{Column: 2, Op: test.op, Value: test.threshold}}
			record, err := parseCSVList([]byte("192.0.2.1,0\n192.0.2.2,1\n192.0.2.3,10\n"), "https://example.com/feed", policy.Selector{Kind: policy.IPList, Value: "feed"}, options)
			if err != nil {
				t.Fatal(err)
			}
			if got := prefixStrings(record.IPv4); !reflect.DeepEqual(got, test.want) {
				t.Fatalf("got %v, want %v", got, test.want)
			}
		})
	}
}

func TestCSVRejectsEntireMalformedResponse(t *testing.T) {
	for _, test := range []struct {
		name, tail string
	}{
		{"missing-ip", "unused\n"},
		{"missing-filter", "unused,192.0.2.2\n"},
		{"empty-number", "unused,192.0.2.2,\n"},
		{"nonnumeric", "unused,192.0.2.2,sensitive-cell\n"},
		{"nan", "unused,192.0.2.2,NaN\n"},
		{"infinity", "unused,192.0.2.2,+Inf\n"},
		{"overflow", "unused,192.0.2.2,1e999\n"},
		{"invalid-filtered-ip", "unused,sensitive-cell,0\n"},
		{"invalid-v6", "unused,2001:db8::xyz,0\n"},
		{"zone", "unused,fe80::1%eth0,0\n"},
		{"hostname", "unused,example.com,0\n"},
		{"range", "unused,192.0.2.1-192.0.2.2,0\n"},
		{"inline-comment", "unused,192.0.2.2 # comment,1\n"},
		{"unicode-space", "unused,\u00a0192.0.2.2,1\n"},
		{"unclosed-quote", "unused,\"192.0.2.2,1\n"},
		{"bare-quote", "un\"used,192.0.2.2,1\n"},
		{"utf8", "unused,192.0.2.2,1\xff\n"},
		{"whitespace-comment", " # not a comment\n"},
		{"whitespace-record", " \t\n"},
	} {
		t.Run(test.name, func(t *testing.T) {
			record, err := parseCSVList([]byte("unused,192.0.2.1,1\n"+test.tail), "https://example.com/feed?secret=hidden", policy.Selector{Kind: policy.IPList, Value: "feed"}, config.CSVConfig{IPColumn: 2, Filter: config.CSVFilterConfig{Column: 3, Op: ">=", Value: 1}})
			if err == nil {
				t.Fatal("accepted malformed tail")
			}
			if len(record.IPv4)+len(record.IPv6) != 0 {
				t.Fatal("returned partial prefixes")
			}
			for _, secret := range []string{"sensitive-cell", "example.com", "secret=hidden"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error leaked input: %v", err)
				}
			}
		})
	}
	for name, body := range map[string]string{"empty": "", "comments": "# comment\n\n", "header-only": "label,ip,number\n", "short-header": "label\n", "no-matches": "label,ip,number\nunused,192.0.2.1,0\n"} {
		t.Run(name, func(t *testing.T) {
			_, err := parseCSVList([]byte(body), "https://example.com/feed", policy.Selector{Kind: policy.IPList, Value: "feed"}, config.CSVConfig{Header: true, IPColumn: 2, Filter: config.CSVFilterConfig{Column: 3, Op: ">=", Value: 1}})
			if err == nil {
				t.Fatal("accepted empty or incomplete CSV")
			}
		})
	}
}
