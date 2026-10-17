package source

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"

	"github.com/perimeterd/perimeterd/internal/policy"
)

func TestDBIPParserWholeArtifactAndEmptyCountries(t *testing.T) {
	body := "\"0.0.0.0\",\"0.0.0.3\",\"SK\"\r\n0.0.0.4,0.0.0.7,XK\r\n0.0.0.8,0.0.0.9,ZZ\r\n2001:db8::,2001:db8::3,CZ\r\n"
	sk := policy.Selector{Kind: policy.Country, Value: "SK"}
	cz := policy.Selector{Kind: policy.Country, Value: "CZ"}
	us := policy.Selector{Kind: policy.Country, Value: "US"}
	records, digest, err := parseDBIP(context.Background(), strings.NewReader(body), []policy.Selector{sk, cz, us}, standardDBIPLimits)
	if err != nil {
		t.Fatal(err)
	}
	hash := sha256.Sum256([]byte(body))
	if digest != hex.EncodeToString(hash[:]) {
		t.Fatalf("digest %s", digest)
	}
	if len(records) != 3 || len(records[sk].IPv4) != 1 || records[sk].IPv4[0].String() != "0.0.0.0/30" || len(records[sk].IPv6) != 0 || len(records[cz].IPv6) != 1 || len(records[us].IPv4) != 0 || len(records[us].IPv6) != 0 {
		t.Fatalf("records %#v", records)
	}
}

func TestDBIPParserRejectsMalformedUnselectedRows(t *testing.T) {
	good := "0.0.0.0,0.0.0.3,SK\n"
	for name, tail := range map[string]string{
		"columns": "0.0.0.4,0.0.0.5,US,extra\n", "missing": "0.0.0.4,0.0.0.5\n", "country": "0.0.0.4,0.0.0.5,AA\n", "lowercase": "0.0.0.4,0.0.0.5,us\n", "whitespace": "0.0.0.4,0.0.0.5,US \n", "addressspace": " 0.0.0.4,0.0.0.5,US\n", "utf8": "0.0.0.4,0.0.0.5,\xff\n", "overlap": "0.0.0.3,0.0.0.5,US\n", "duplicate": good, "reverse": "0.0.0.5,0.0.0.4,US\n", "mixed": "0.0.0.4,::1,US\n", "mapped": "::ffff:192.0.2.1,::ffff:192.0.2.2,US\n", "zone": "fe80::1%a,fe80::2%a,US\n", "familyorder": "::,::1,US\n0.0.0.4,0.0.0.5,US\n", "quote": "\"0.0.0.4,0.0.0.5,US\n", "blank": "\n", "header": "ip_start,ip_end,country\n",
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseDBIP(context.Background(), strings.NewReader(good+tail), []policy.Selector{{Kind: policy.Country, Value: "SK"}}, standardDBIPLimits); err == nil {
				t.Fatal("accepted malformed unselected tail")
			}
		})
	}
	for _, body := range []string{"", "\n"} {
		if _, _, err := parseDBIP(context.Background(), strings.NewReader(body), nil, standardDBIPLimits); err == nil {
			t.Fatal("accepted empty artifact")
		}
	}
}

func TestDBIPParserStreamingLimitsAndCancellation(t *testing.T) {
	body := "0.0.0.1,0.0.0.6,SK\n0.0.0.7,0.0.0.8,CZ\n"
	for name, limits := range map[string]dbipLimits{
		"decoded": {10, 100, 100, 1024}, "rows": {1024, 1, 100, 1024}, "prefixes": {1024, 100, 1, 1024}, "record": {1024, 100, 100, 10},
	} {
		t.Run(name, func(t *testing.T) {
			if _, _, err := parseDBIP(context.Background(), strings.NewReader(body), []policy.Selector{{Kind: policy.Country, Value: "SK"}}, limits); err == nil {
				t.Fatal("accepted over-limit artifact")
			}
		})
	}
	// Quoted records must be bounded before the standard CSV parser allocates.
	if _, _, err := parseDBIP(context.Background(), strings.NewReader("\""+strings.Repeat("x", 2048)), nil, standardDBIPLimits); err == nil {
		t.Fatal("accepted oversized quoted field")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := parseDBIP(ctx, strings.NewReader(body), nil, standardDBIPLimits); err == nil {
		t.Fatal("ignored cancellation")
	}
}
