package source

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/csv"
	"encoding/hex"
	"fmt"
	"io"
	"net/netip"
	"unicode/utf8"

	"github.com/perimeterd/perimeterd/internal/config/catalog"
	"github.com/perimeterd/perimeterd/internal/policy"
	"github.com/perimeterd/perimeterd/internal/prefix"
)

const (
	dbipEncodedLimit = 32 << 20
	dbipDecodedLimit = 64 << 20
	dbipRowLimit     = 2_000_000
	dbipPrefixLimit  = 4_000_000
	dbipRecordLimit  = 1024
)

type dbipLimits struct{ decoded, rows, prefixes, record int }

var standardDBIPLimits = dbipLimits{dbipDecodedLimit, dbipRowLimit, dbipPrefixLimit, dbipRecordLimit}

// parseDBIP retains only requested ISO countries; every byte and every row is
// nevertheless validated. Records are framed before encoding/csv sees them so
// an unterminated quoted field cannot cause an unbounded allocation.
func parseDBIP(ctx context.Context, input io.Reader, selectors []policy.Selector, limits dbipLimits) (map[policy.Selector]Record, string, error) {
	records := make(map[policy.Selector]Record, len(selectors))
	for _, s := range selectors {
		records[s] = Record{Selector: s}
	}
	hash := sha256.New()
	limited := &io.LimitedReader{R: input, N: int64(limits.decoded) + 1}
	reader := bufio.NewReader(io.TeeReader(limited, hash))
	var previous netip.Addr
	var rows, emitted int
	var storage [dbipRecordLimit]byte
	var frame bytes.Reader
	csvReader := csv.NewReader(&frame)
	csvReader.FieldsPerRecord = 3
	csvReader.ReuseRecord = true
	for {
		if err := ctx.Err(); err != nil {
			return nil, "", err
		}
		record := storage[:0]
		quoted := false
		for {
			b, err := reader.ReadByte()
			if err == io.EOF {
				break
			}
			if err != nil {
				return nil, "", fmt.Errorf("read DB-IP CSV: %w", err)
			}
			if limited.N == 0 {
				return nil, "", fmt.Errorf("DB-IP decoded size limit exceeded")
			}
			if len(record) >= limits.record {
				return nil, "", fmt.Errorf("DB-IP record size limit exceeded")
			}
			record = append(record, b)
			if b == '"' {
				quoted = !quoted
			}
			if b == '\n' && !quoted {
				break
			}
		}
		if len(record) == 0 {
			break
		}
		rows++
		if rows > limits.rows {
			return nil, "", fmt.Errorf("DB-IP row limit exceeded")
		}
		if !utf8.Valid(record) {
			return nil, "", fmt.Errorf("DB-IP row %d is not UTF-8", rows)
		}
		frame.Reset(record)
		fields, err := csvReader.Read()
		if err != nil {
			// This frame is in memory: even EOF is a CSV validation error,
			// not a failure reading the underlying artifact stream.
			return nil, "", fmt.Errorf("DB-IP row %d: %v", rows, err)
		}
		// Framing ended at the first unquoted newline (or EOF); there cannot be
		// a second RFC4180 record in this bounded frame.
		start, err := netip.ParseAddr(fields[0])
		if err != nil {
			return nil, "", fmt.Errorf("DB-IP invalid start address at row %d", rows)
		}
		end, err := netip.ParseAddr(fields[1])
		if err != nil || start.Zone() != "" || end.Zone() != "" || start.Is4In6() || end.Is4In6() || start.BitLen() != end.BitLen() || start.Compare(end) > 0 {
			return nil, "", fmt.Errorf("DB-IP invalid range at row %d", rows)
		}
		if previous.IsValid() && (start.BitLen() < previous.BitLen() || (start.BitLen() == previous.BitLen() && start.Compare(previous) <= 0)) {
			return nil, "", fmt.Errorf("DB-IP overlapping or unsorted row %d", rows)
		}
		previous = end
		country := fields[2]
		if !catalog.ValidCountry(country) && country != "XK" && country != "ZZ" {
			return nil, "", fmt.Errorf("DB-IP invalid country at row %d", rows)
		}
		if country == "XK" || country == "ZZ" {
			continue
		}
		selector := policy.Selector{Kind: policy.Country, Value: country}
		value, selected := records[selector]
		if !selected {
			continue
		}
		target := &value.IPv6
		if start.Is4() {
			target = &value.IPv4
		}
		before := len(*target)
		*target, err = prefix.AppendRange(*target, start, end)
		if err != nil {
			return nil, "", err
		}
		emitted += len(*target) - before
		if emitted > limits.prefixes {
			return nil, "", fmt.Errorf("DB-IP prefix limit exceeded")
		}
		records[selector] = value
	}
	if rows == 0 {
		return nil, "", fmt.Errorf("DB-IP artifact contains no data")
	}
	if err := ctx.Err(); err != nil {
		return nil, "", err
	}
	for selector, record := range records {
		var err error
		record.IPv4, err = prefix.Normalize(record.IPv4)
		if err != nil {
			return nil, "", err
		}
		record.IPv6, err = prefix.Normalize(record.IPv6)
		if err != nil {
			return nil, "", err
		}
		records[selector] = record
	}
	return records, hex.EncodeToString(hash.Sum(nil)), nil
}
