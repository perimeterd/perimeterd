package state

import (
	"reflect"
	"slices"
	"strings"

	"github.com/perimeterd/perimeterd/internal/policy"
)

// sameCompiledFamilies permits only geo-set storage aliases, not different
// policy behavior. Historical unshared targets remain authoritative as recorded;
// validation must not rewrite them or recreate an obsolete compiler.
func sameCompiledFamilies(recorded, compiled []policy.FamilyPlan) bool {
	if len(recorded) != len(compiled) {
		return false
	}
	for i, actual := range recorded {
		want := compiled[i]
		actualMetadata, wantMetadata := actual, want
		actualMetadata.Sets, actualMetadata.Paths = nil, nil
		wantMetadata.Sets, wantMetadata.Paths = nil, nil
		if !reflect.DeepEqual(actualMetadata, wantMetadata) || !sameCompiledFamily(actual, want) {
			return false
		}
	}
	return true
}

func geoSet(set policy.PrefixSet) bool {
	return set.Kind == policy.StaticSet && strings.HasPrefix(set.ID, "geo/")
}

func sameCompiledFamily(actual, want policy.FamilyPlan) bool {
	actualSets := make(map[string]policy.PrefixSet, len(actual.Sets))
	wantSets := make(map[string]policy.PrefixSet, len(want.Sets))
	for _, set := range want.Sets {
		wantSets[set.ID] = set
	}
	actualInternal, wantInternal := 0, 0
	for _, set := range actual.Sets {
		actualSets[set.ID] = set
		if !geoSet(set) {
			if !reflect.DeepEqual(set, wantSets[set.ID]) {
				return false
			}
			actualInternal++
		}
	}
	for _, set := range want.Sets {
		if !geoSet(set) {
			wantInternal++
		}
	}
	if actualInternal != wantInternal || len(actual.Paths) != len(want.Paths) {
		return false
	}
	used := make(map[string]struct{}, len(actual.Sets))
	compared := make(map[[2]string]struct{})
	for i, path := range actual.Paths {
		expected := want.Paths[i]
		pathMetadata, expectedMetadata := path, expected
		pathMetadata.Rules, expectedMetadata.Rules = nil, nil
		if !reflect.DeepEqual(pathMetadata, expectedMetadata) || len(path.Rules) != len(expected.Rules) {
			return false
		}
		for j, rule := range path.Rules {
			expectedRule := expected.Rules[j]
			actualID, wantID := rule.Match.SetID, expectedRule.Match.SetID
			actualSet, wantSet := actualSets[actualID], wantSets[wantID]
			if actualID != wantID {
				if !geoSet(actualSet) || !geoSet(wantSet) {
					return false
				}
				rule.Match.SetID = wantID
			}
			if !reflect.DeepEqual(rule, expectedRule) {
				return false
			}
			if actualID == "" || !geoSet(actualSet) {
				continue
			}
			if !geoSet(wantSet) {
				return false
			}
			used[actualID] = struct{}{}
			pair := [2]string{actualID, wantID}
			if _, ok := compared[pair]; ok {
				continue
			}
			actualPrefixes, wantPrefixes := actualSet.Prefixes, wantSet.Prefixes
			actualSet.ID, actualSet.Prefixes = wantSet.ID, nil
			wantSet.Prefixes = nil
			if !reflect.DeepEqual(actualSet, wantSet) || !slices.Equal(actualPrefixes, wantPrefixes) {
				return false
			}
			compared[pair] = struct{}{}
		}
	}
	for _, set := range actual.Sets {
		if geoSet(set) {
			if _, ok := used[set.ID]; !ok {
				return false
			}
		}
	}
	return true
}
