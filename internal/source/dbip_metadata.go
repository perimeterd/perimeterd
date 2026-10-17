package source

import (
	"errors"
	"fmt"
	"time"

	"github.com/perimeterd/perimeterd/internal/policy"
)

func dbipEndpoint(release string) string {
	return "https://download.db-ip.com/free/dbip-country-lite-" + release + ".csv.gz"
}

// validateDBIPRecord validates provenance independently of prefix membership.
func validateDBIPRecord(record Record) error {
	selector, err := policy.CanonicalSelector(record.Selector.Kind, record.Selector.Value)
	if err != nil || selector != record.Selector || selector.Kind != policy.Country {
		return errors.New("DB-IP selector must be a canonical ISO country")
	}
	if record.SourceKind != dbipSourceKind || record.SourceName != "" || record.APIVersion != dbipFormatVersion {
		return errors.New("unsupported DB-IP source identity or parser version")
	}
	month, err := time.Parse("2006-01", record.Release)
	if err != nil || month.Format("2006-01") != record.Release || month.Year() < 1 {
		return errors.New("DB-IP release must be canonical YYYY-MM")
	}
	if record.Endpoint != dbipEndpoint(record.Release) {
		return errors.New("DB-IP endpoint does not match release")
	}
	if len(record.Parameters) != 2 || record.Parameters["resource"] != selector.Value {
		return errors.New("DB-IP parameters do not match selector identity")
	}
	if err := validateCacheID(record.Parameters["sha256"], "DB-IP artifact sha256"); err != nil {
		return err
	}
	if !record.QueryStart.IsZero() || !record.QueryEnd.IsZero() {
		return errors.New("DB-IP query timestamps are not allowed")
	}
	if record.RetrievedAt.IsZero() {
		return errors.New("DB-IP retrieved_at is required")
	}
	binding, err := canonicalBinding(record.Transport)
	if err != nil || binding.Type != "" {
		return errors.New("DB-IP transport must be direct")
	}
	return nil
}

// validateDBIPBatch also applies to candidate subsets and durable manifests.
func validateDBIPBatch(records []Record) error {
	var first *Record
	var countryProvider string
	for i := range records {
		record := &records[i]
		if record.Selector.Kind == policy.Country {
			provider := record.SourceKind
			if provider == "" {
				provider = ripeSourceKind
			}
			if countryProvider != "" && countryProvider != provider {
				return errors.New("country batch has inconsistent providers")
			}
			countryProvider = provider
		}
		if record.SourceKind != dbipSourceKind {
			continue
		}
		if err := validateDBIPRecord(*record); err != nil {
			return fmt.Errorf("DB-IP record %d: %w", i, err)
		}
		if first == nil {
			first = record
			continue
		}
		if record.Release != first.Release || record.Parameters["sha256"] != first.Parameters["sha256"] || !record.RetrievedAt.Equal(first.RetrievedAt) {
			return errors.New("DB-IP country batch has inconsistent release, artifact digest or retrieval time")
		}
	}
	return nil
}
