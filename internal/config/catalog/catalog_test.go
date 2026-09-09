package catalog

import (
	"sort"
	"testing"
)

func TestValidCountryUsesCompleteISOAlpha2Set(t *testing.T) {
	if got, want := len(countryCodes), 249; got != want {
		t.Fatalf("country code count = %d, want %d", got, want)
	}
	for _, code := range countryCodes {
		if !ValidCountry(code) {
			t.Errorf("catalog code %q was not recognized", code)
		}
	}
	for _, code := range []string{"", "us", "ZZ", "AN", "CS", "FX", "SU", "TP", "YU", "ZR", "XK", "TA"} {
		if ValidCountry(code) {
			t.Errorf("invalid or non-canonical code %q was recognized", code)
		}
	}
}

func TestCountriesRegionalBoundaries(t *testing.T) {
	tests := []struct {
		name string
		yes  []string
		no   []string
	}{
		{name: "africa", yes: []string{"EH", "IO", "TF", "YT"}, no: []string{"AQ", "US"}},
		{name: "asia", yes: []string{"AM", "CY", "JP", "TR"}, no: []string{"RU", "TW"}},
		{name: "europe", yes: []string{"AX", "RU", "SJ"}, no: []string{"CY", "TR"}},
		{name: "oceania", yes: []string{"AS", "UM", "WF"}, no: []string{"AQ", "JP"}},
		{name: "northern-america", yes: []string{"BM", "GL", "PM", "US"}, no: []string{"MX"}},
		{name: "latin-america-caribbean", yes: []string{"BV", "GF", "MX", "VI"}, no: []string{"CA"}},
	}
	assertGroupMemberships(t, tests)
}

func TestCountriesInstitutionalMemberships(t *testing.T) {
	tests := []struct {
		name string
		yes  []string
		no   []string
	}{
		{name: "european-union", yes: []string{"BG", "CY", "IE", "RO"}, no: []string{"CH", "NO"}},
		{name: "schengen-area", yes: []string{"BG", "FI", "RO", "SE", "CH"}, no: []string{"CY", "IE"}},
		{name: "nato", yes: []string{"BG", "FI", "RO", "SE", "TR", "US"}, no: []string{"IE", "CH"}},
	}
	assertGroupMemberships(t, tests)
}

func TestEuroAtlanticIsUnionOfInstitutionalGroups(t *testing.T) {
	euroAtlantic, ok := Countries("euro-atlantic")
	if !ok {
		t.Fatal("euro-atlantic group is missing")
	}
	if !sort.StringsAreSorted(euroAtlantic) {
		t.Fatal("euro-atlantic members are not sorted")
	}

	want := make(map[string]struct{})
	for _, group := range []string{"european-union", "schengen-area", "nato"} {
		members, ok := Countries(group)
		if !ok {
			t.Fatalf("source group %q is missing", group)
		}
		for _, code := range members {
			want[code] = struct{}{}
		}
	}
	if len(euroAtlantic) != len(want) {
		t.Fatalf("euro-atlantic size = %d, want union size %d", len(euroAtlantic), len(want))
	}
	for _, code := range euroAtlantic {
		if _, ok := want[code]; !ok {
			t.Errorf("euro-atlantic contains %q outside source union", code)
		}
		delete(want, code)
	}
	for code := range want {
		t.Errorf("euro-atlantic omits source member %q", code)
	}
}

func TestCountriesReturnsIndependentCopy(t *testing.T) {
	first, ok := Countries("europe")
	if !ok || len(first) == 0 {
		t.Fatal("europe group is missing or empty")
	}
	original := first[0]
	first[0] = "ZZ"

	second, ok := Countries("europe")
	if !ok || second[0] != original {
		t.Fatalf("mutating returned group changed registry: got %q, want %q", second[0], original)
	}
	if _, ok := Countries("not-a-built-in"); ok {
		t.Fatal("unknown group was accepted")
	}
}

func assertGroupMemberships(t *testing.T, tests []struct {
	name string
	yes  []string
	no   []string
},
) {
	t.Helper()
	for _, test := range tests {
		members, ok := Countries(test.name)
		if !ok {
			t.Errorf("group %q is missing", test.name)
			continue
		}
		if !sort.StringsAreSorted(members) {
			t.Errorf("group %q members are not sorted", test.name)
		}
		set := make(map[string]struct{}, len(members))
		for _, code := range members {
			set[code] = struct{}{}
			if !ValidCountry(code) {
				t.Errorf("group %q contains invalid code %q", test.name, code)
			}
		}
		for _, code := range test.yes {
			if _, ok := set[code]; !ok {
				t.Errorf("group %q omits expected member %q", test.name, code)
			}
		}
		for _, code := range test.no {
			if _, ok := set[code]; ok {
				t.Errorf("group %q contains excluded member %q", test.name, code)
			}
		}
	}
}
