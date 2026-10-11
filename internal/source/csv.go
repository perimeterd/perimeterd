package source

import (
	"bytes"
	"encoding/csv"
	"errors"
	"fmt"
	"io"
	"math"
	"net/netip"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/perimeterd/perimeterd/internal/config"
	"github.com/perimeterd/perimeterd/internal/policy"
)

func parseCSVList(body []byte, endpoint string, selector policy.Selector, options config.CSVConfig) (Record, error) {
	description := fmt.Sprintf("custom list %q", selector.Value)
	parameters, err := options.Parameters()
	if err != nil || options.IsZero() || selector.Kind != policy.IPList {
		return Record{}, fmt.Errorf("%s has invalid CSV options", description)
	}
	if !utf8.Valid(body) {
		return Record{}, fmt.Errorf("%s CSV line data is not valid UTF-8", description)
	}
	reader := csv.NewReader(bytes.NewReader(body))
	reader.Comma, _ = utf8.DecodeRuneInString(parameters["delimiter"])
	reader.Comment = '#'
	reader.FieldsPerRecord = -1
	reader.ReuseRecord = true
	var ipv4, ipv6 []netip.Prefix
	rows, matches := 0, 0
	filter := options.Filter
	for row := 1; ; row++ {
		fields, err := reader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			var parseError *csv.ParseError
			if errors.As(err, &parseError) {
				return Record{}, fmt.Errorf("%s CSV row %d line %d has malformed quoting", description, row, parseError.Line)
			}
			return Record{}, fmt.Errorf("%s CSV row %d cannot be read", description, row)
		}
		line, _ := reader.FieldPos(0)
		if len(fields) < options.IPColumn {
			return Record{}, fmt.Errorf("%s CSV row %d line %d is missing IP column %d", description, row, line, options.IPColumn)
		}
		if filter.Op != "" && len(fields) < filter.Column {
			return Record{}, fmt.Errorf("%s CSV row %d line %d is missing filter column %d", description, row, line, filter.Column)
		}
		if row == 1 && options.Header {
			continue
		}
		rows++
		prefix, err := parseListAddress(strings.Trim(fields[options.IPColumn-1], " \t"))
		if err != nil || (!prefix.Addr().Is4() && !prefix.Addr().Is6()) || prefix.Addr().Zone() != "" {
			return Record{}, fmt.Errorf("%s CSV row %d line %d column %d is not one IP address or CIDR", description, row, line, options.IPColumn)
		}
		if filter.Op != "" {
			value, err := strconv.ParseFloat(strings.Trim(fields[filter.Column-1], " \t"), 64)
			if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
				return Record{}, fmt.Errorf("%s CSV row %d line %d column %d is not a finite number", description, row, line, filter.Column)
			}
			if !csvMatches(value, filter.Op, filter.Value) {
				continue
			}
		}
		matches++
		if prefix.Addr().Is4() {
			ipv4 = append(ipv4, prefix)
		} else {
			ipv6 = append(ipv6, prefix)
		}
	}
	if rows == 0 {
		return Record{}, fmt.Errorf("%s CSV source is empty", description)
	}
	if matches == 0 {
		return Record{}, fmt.Errorf("%s no prefixes matched the CSV filter", description)
	}
	return finishListRecord(ipv4, ipv6, endpoint, selector, listSourceKind, description, csvFormatVersion, parameters)
}

func csvMatches(value float64, op string, threshold float64) bool {
	switch op {
	case "==":
		return value == threshold
	case "!=":
		return value != threshold
	case "<":
		return value < threshold
	case "<=":
		return value <= threshold
	case ">":
		return value > threshold
	case ">=":
		return value >= threshold
	default:
		return false
	}
}
