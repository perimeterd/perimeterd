// Package catalog contains immutable built-in country, group, and selector facts.
package catalog

import (
	"sort"
	"strconv"
)

// The country set is ISO 3166-1 alpha-2 (249 assigned codes), cross-checked
// against ISO 3166-1:2020 (reviewed/confirmed 2025):
// https://www.iso.org/standard/72482.html
// Online country-code browser: https://www.iso.org/obp/ui/#iso:pub:PUB500001:en
//
// Regional memberships are the ISO-alpha2 rows in the UNSD M49 Overview table
// (the UNSD page describes this as the online M49 standard; the last print
// edition was 1999): https://unstats.un.org/unsd/methodology/m49/overview/
// M49 has no row for TW (Taiwan) and leaves AQ (Antarctica) without a region;
// both remain valid ISO codes, but neither is assigned to a regional built-in.
//
// Institutional memberships are release-pinned snapshots: EU countries page
// (27 members, retrieved 2026-09-09):
// https://european-union.europa.eu/principles-countries-history/eu-countries_en
// Schengen area page (29 members, dated 2025-05-27):
// https://home-affairs.ec.europa.eu/policies/schengen/schengen-area_en
// NATO member countries page (32 members, updated 2024-03-11):
// https://www.nato.int/en/about-us/organization/nato-member-countries
// In particular, BG/RO are in Schengen and FI/SE are in NATO.

var countryCodes = [...]string{
	"AD", "AE", "AF", "AG", "AI", "AL", "AM", "AO", "AQ", "AR", "AS", "AT",
	"AU", "AW", "AX", "AZ", "BA", "BB", "BD", "BE", "BF", "BG", "BH", "BI",
	"BJ", "BL", "BM", "BN", "BO", "BQ", "BR", "BS", "BT", "BV", "BW", "BY",
	"BZ", "CA", "CC", "CD", "CF", "CG", "CH", "CI", "CK", "CL", "CM", "CN",
	"CO", "CR", "CU", "CV", "CW", "CX", "CY", "CZ", "DE", "DJ", "DK", "DM",
	"DO", "DZ", "EC", "EE", "EG", "EH", "ER", "ES", "ET", "FI", "FJ", "FK",
	"FM", "FO", "FR", "GA", "GB", "GD", "GE", "GF", "GG", "GH", "GI", "GL",
	"GM", "GN", "GP", "GQ", "GR", "GS", "GT", "GU", "GW", "GY", "HK", "HM",
	"HN", "HR", "HT", "HU", "ID", "IE", "IL", "IM", "IN", "IO", "IQ", "IR",
	"IS", "IT", "JE", "JM", "JO", "JP", "KE", "KG", "KH", "KI", "KM", "KN",
	"KP", "KR", "KW", "KY", "KZ", "LA", "LB", "LC", "LI", "LK", "LR", "LS",
	"LT", "LU", "LV", "LY", "MA", "MC", "MD", "ME", "MF", "MG", "MH", "MK",
	"ML", "MM", "MN", "MO", "MP", "MQ", "MR", "MS", "MT", "MU", "MV", "MW",
	"MX", "MY", "MZ", "NA", "NC", "NE", "NF", "NG", "NI", "NL", "NO", "NP",
	"NR", "NU", "NZ", "OM", "PA", "PE", "PF", "PG", "PH", "PK", "PL", "PM",
	"PN", "PR", "PS", "PT", "PW", "PY", "QA", "RE", "RO", "RS", "RU", "RW",
	"SA", "SB", "SC", "SD", "SE", "SG", "SH", "SI", "SJ", "SK", "SL", "SM",
	"SN", "SO", "SR", "SS", "ST", "SV", "SX", "SY", "SZ", "TC", "TD", "TF",
	"TG", "TH", "TJ", "TK", "TL", "TM", "TN", "TO", "TR", "TT", "TV", "TW",
	"TZ", "UA", "UG", "UM", "US", "UY", "UZ", "VA", "VC", "VE", "VG", "VI",
	"VN", "VU", "WF", "WS", "YE", "YT", "ZA", "ZM", "ZW",
}

var regionalGroups = map[string][]string{
	"africa": {
		"AO", "BF", "BI", "BJ", "BW", "CD", "CF", "CG", "CI", "CM", "CV", "DJ",
		"DZ", "EG", "EH", "ER", "ET", "GA", "GH", "GM", "GN", "GQ", "GW", "IO",
		"KE", "KM", "LR", "LS", "LY", "MA", "MG", "ML", "MR", "MU", "MW", "MZ",
		"NA", "NE", "NG", "RE", "RW", "SC", "SD", "SH", "SL", "SN", "SO", "SS",
		"ST", "SZ", "TD", "TF", "TG", "TN", "TZ", "UG", "YT", "ZA", "ZM", "ZW",
	},
	"asia": {
		"AE", "AF", "AM", "AZ", "BD", "BH", "BN", "BT", "CN", "CY", "GE", "HK",
		"ID", "IL", "IN", "IQ", "IR", "JO", "JP", "KG", "KH", "KP", "KR", "KW",
		"KZ", "LA", "LB", "LK", "MM", "MN", "MO", "MV", "MY", "NP", "OM", "PH",
		"PK", "PS", "QA", "SA", "SG", "SY", "TH", "TJ", "TL", "TM", "TR", "UZ",
		"VN", "YE",
	},
	"europe": {
		"AD", "AL", "AT", "AX", "BA", "BE", "BG", "BY", "CH", "CZ", "DE", "DK",
		"EE", "ES", "FI", "FO", "FR", "GB", "GG", "GI", "GR", "HR", "HU", "IE",
		"IM", "IS", "IT", "JE", "LI", "LT", "LU", "LV", "MC", "MD", "ME", "MK",
		"MT", "NL", "NO", "PL", "PT", "RO", "RS", "RU", "SE", "SI", "SJ", "SK",
		"SM", "UA", "VA",
	},
	"oceania": {
		"AS", "AU", "CC", "CK", "CX", "FJ", "FM", "GU", "HM", "KI", "MH", "MP",
		"NC", "NF", "NR", "NU", "NZ", "PF", "PG", "PN", "PW", "SB", "TK", "TO",
		"TV", "UM", "VU", "WF", "WS",
	},
	"northern-america": {
		"BM", "CA", "GL", "PM", "US",
	},
	"latin-america-caribbean": {
		"AG", "AI", "AR", "AW", "BB", "BL", "BO", "BQ", "BR", "BS", "BV", "BZ",
		"CL", "CO", "CR", "CU", "CW", "DM", "DO", "EC", "FK", "GD", "GF", "GP",
		"GS", "GT", "GY", "HN", "HT", "JM", "KN", "KY", "LC", "MF", "MQ", "MS",
		"MX", "NI", "PA", "PE", "PR", "PY", "SR", "SV", "SX", "TC", "TT", "UY",
		"VC", "VE", "VG", "VI",
	},
}

// rirServiceRegions is the release-pinned ISO country-to-RIR assignment, not
// a geographic grouping. Reviewed 2026-09-15 against the RIPE NCC table:
// https://www.ripe.net/community/internet-governance/internet-technical-community/the-rir-system/list-of-country-codes-and-rirs/
// Cross-checked with the NRO table and individual RIR service-region lists.
// RIR selectors resolve these countries through country-resource-list; they
// never become independent source records.
var rirServiceRegions = map[string][]string{
	"AFRINIC": {
		"AO", "BF", "BI", "BJ", "BW", "CD", "CF", "CG", "CI", "CM", "CV", "DJ",
		"DZ", "EG", "EH", "ER", "ET", "GA", "GH", "GM", "GN", "GQ", "GW", "KE",
		"KM", "LR", "LS", "LY", "MA", "MG", "ML", "MR", "MU", "MW", "MZ", "NA",
		"NE", "NG", "RE", "RW", "SC", "SD", "SL", "SN", "SO", "SS", "ST", "SZ",
		"TD", "TG", "TN", "TZ", "UG", "YT", "ZA", "ZM", "ZW",
	},
	"APNIC": {
		"AF", "AS", "AU", "BD", "BN", "BT", "CC", "CK", "CN", "CX", "FJ", "FM",
		"GU", "HK", "ID", "IN", "IO", "JP", "KH", "KI", "KP", "KR", "LA", "LK",
		"MH", "MM", "MN", "MO", "MP", "MV", "MY", "NC", "NF", "NP", "NR", "NU",
		"NZ", "PF", "PG", "PH", "PK", "PN", "PW", "SB", "SG", "TF", "TH", "TK",
		"TL", "TO", "TV", "TW", "VN", "VU", "WF", "WS",
	},
	"ARIN": {
		"AG", "AI", "AQ", "BB", "BL", "BM", "BS", "BV", "CA", "DM", "GD", "GP",
		"HM", "JM", "KN", "KY", "LC", "MF", "MQ", "MS", "PM", "PR", "SH", "TC",
		"UM", "US", "VC", "VG", "VI",
	},
	"LACNIC": {
		"AR", "AW", "BO", "BQ", "BR", "BZ", "CL", "CO", "CR", "CU", "CW", "DO",
		"EC", "FK", "GF", "GS", "GT", "GY", "HN", "HT", "MX", "NI", "PA", "PE",
		"PY", "SR", "SV", "SX", "TT", "UY", "VE",
	},
	"RIPE": {
		"AD", "AE", "AL", "AM", "AT", "AX", "AZ", "BA", "BE", "BG", "BH", "BY",
		"CH", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FO", "FR", "GB", "GE",
		"GG", "GI", "GL", "GR", "HR", "HU", "IE", "IL", "IM", "IQ", "IR", "IS",
		"IT", "JE", "JO", "KG", "KW", "KZ", "LB", "LI", "LT", "LU", "LV", "MC",
		"MD", "ME", "MK", "MT", "NL", "NO", "OM", "PL", "PS", "PT", "QA", "RO",
		"RS", "RU", "SA", "SE", "SI", "SJ", "SK", "SM", "SY", "TJ", "TM", "TR",
		"UA", "UZ", "VA", "YE",
	},
}

var (
	euMembers       = []string{"AT", "BE", "BG", "CY", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IE", "IT", "LT", "LU", "LV", "MT", "NL", "PL", "PT", "RO", "SE", "SI", "SK"}
	schengenMembers = []string{"AT", "BE", "BG", "CH", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GR", "HR", "HU", "IS", "IT", "LI", "LT", "LU", "LV", "MT", "NL", "NO", "PL", "PT", "RO", "SE", "SI", "SK"}
	natoMembers     = []string{"AL", "BE", "BG", "CA", "CZ", "DE", "DK", "EE", "ES", "FI", "FR", "GB", "GR", "HR", "HU", "IS", "IT", "LT", "LU", "LV", "ME", "MK", "NL", "NO", "PL", "PT", "RO", "SE", "SI", "SK", "TR", "US"}
)

var (
	countries = makeCountrySet()
	groups    = makeGroups()
)

func makeCountrySet() map[string]struct{} {
	set := make(map[string]struct{}, len(countryCodes))
	for _, code := range countryCodes {
		set[code] = struct{}{}
	}
	return set
}

func makeGroups() map[string][]string {
	result := make(map[string][]string, len(regionalGroups)+4)
	for name, members := range regionalGroups {
		result[name] = append([]string(nil), members...)
	}
	result["european-union"] = append([]string(nil), euMembers...)
	result["schengen-area"] = append([]string(nil), schengenMembers...)
	result["nato"] = append([]string(nil), natoMembers...)
	result["euro-atlantic"] = union(euMembers, schengenMembers, natoMembers)
	return result
}

// ValidCountry reports whether code is an assigned ISO 3166-1 alpha-2 code.
// Callers canonicalize input to uppercase before calling this function.
func ValidCountry(code string) bool {
	_, ok := countries[code]
	return ok
}

// ValidRIR reports whether name is a canonical Regional Internet Registry
// service-region name. Callers canonicalize input to uppercase before calling.
func ValidRIR(name string) bool {
	_, ok := rirServiceRegions[name]
	return ok
}

// RIRCountries returns a defensive copy of the canonical country memberships
// for a Regional Internet Registry service region. Unknown RIRs return nil.
func RIRCountries(name string) []string {
	return append([]string(nil), rirServiceRegions[name]...)
}

// ValidASN reports whether value uses canonical AS<number> spelling for an
// unsigned 32-bit autonomous system number. AS0 and AS4294967295 are valid.
func ValidASN(value string) bool {
	if len(value) <= 2 || value[:2] != "AS" {
		return false
	}
	digits := value[2:]
	if digits[0] == '0' && len(digits) > 1 {
		return false
	}
	for _, char := range digits {
		if char < '0' || char > '9' {
			return false
		}
	}
	_, err := strconv.ParseUint(digits, 10, 32)
	return err == nil
}

// Countries returns a copy of the canonical, lexicographically sorted member
// list for a built-in group. Unknown groups return (nil, false).
func Countries(name string) ([]string, bool) {
	members, ok := groups[name]
	if !ok {
		return nil, false
	}
	return append([]string(nil), members...), true
}

func union(groups ...[]string) []string {
	set := make(map[string]struct{})
	for _, members := range groups {
		for _, code := range members {
			set[code] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for code := range set {
		result = append(result, code)
	}
	sort.Strings(result)
	return result
}
