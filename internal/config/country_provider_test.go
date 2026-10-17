package config

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
)

func TestCountryProviderYAMLDefaultsAndExplicitValues(t *testing.T) {
	const base = "version: 1\nfirewall: {backend: nftables}\n"
	for _, geo := range []string{"", "geo: {}\n", "geo: {refresh_interval: 12h}\n", "geo: {country_provider: dbip-lite}\n", "geo: {country_provider: ripestat}\n"} {
		t.Run(geo, func(t *testing.T) {
			cfg, err := Parse([]byte(base + geo))
			if err != nil {
				t.Fatal(err)
			}
			want := CountryProviderDBIPLite
			if strings.Contains(geo, "ripestat") {
				want = CountryProviderRIPEstat
			}
			if cfg.Geo.CountryProvider != want || cfg.Geo.EffectiveCountryProvider() != want {
				t.Fatalf("provider = %q, effective = %q, want %q", cfg.Geo.CountryProvider, cfg.Geo.EffectiveCountryProvider(), want)
			}
		})
	}
}

func TestCountryProviderYAMLRejectsInvalidValues(t *testing.T) {
	for _, value := range []string{"null", "~", "", `""`, "DBIP-LITE", "DB-IP", "RIPEstat", "ripe", "unknown", "true", "false", "0", "1.5", "[]", "{}", "[dbip-lite]", "{name: dbip-lite}"} {
		t.Run(value, func(t *testing.T) {
			_, err := Parse([]byte("version: 1\nfirewall: {backend: nftables}\ngeo:\n  country_provider: " + value + "\n"))
			if err == nil || !strings.Contains(err.Error(), "country_provider") {
				t.Fatalf("invalid provider %q: %v", value, err)
			}
		})
	}
	for _, geo := range []string{"null", "[]", "false", "dbip-lite"} {
		if _, err := Parse([]byte("version: 1\nfirewall: {backend: nftables}\ngeo: " + geo + "\n")); err == nil {
			t.Fatalf("invalid geo %q accepted", geo)
		}
	}
}

func TestHistoricalGeoJSONPreservesAbsentCountryProvider(t *testing.T) {
	// Exact pre-provider GeoConfig JSON shape, independent of the new serializer.
	const original = `{"RefreshInterval":86400000000000,"RequestTimeout":30000000000,"RefreshJitter":600000000000}`
	var geo GeoConfig
	if err := json.Unmarshal([]byte(original), &geo); err != nil {
		t.Fatal(err)
	}
	if geo.CountryProvider != "" || geo.EffectiveCountryProvider() != CountryProviderRIPEstat {
		t.Fatalf("historical provider reinterpreted: %+v", geo)
	}
	encoded, err := json.Marshal(geo)
	if err != nil || !bytes.Equal(encoded, []byte(original)) {
		t.Fatalf("historical GeoConfig bytes changed: %s, %v", encoded, err)
	}
	for _, provider := range []string{CountryProviderDBIPLite, CountryProviderRIPEstat} {
		geo.CountryProvider = provider
		encoded, err = json.Marshal(geo)
		if err != nil || !bytes.Contains(encoded, []byte(`"CountryProvider":"`+provider+`"`)) {
			t.Fatalf("explicit provider lost: %s, %v", encoded, err)
		}
	}
}
