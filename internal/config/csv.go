package config

import (
	"fmt"
	"math"
	"strconv"
	"unicode/utf8"
)

func normalizeRawCSV(raw rawCSV, path string) (CSVConfig, error) {
	if raw.IPColumn == nil {
		return CSVConfig{}, fmt.Errorf("%s.ip_column: required", path)
	}
	c := CSVConfig{Delimiter: ",", IPColumn: *raw.IPColumn}
	if raw.Delimiter != nil {
		if *raw.Delimiter == "" {
			return CSVConfig{}, fmt.Errorf("%s.delimiter: must contain one valid CSV delimiter rune", path)
		}
		c.Delimiter = *raw.Delimiter
	}
	if raw.Header != nil {
		c.Header = *raw.Header
	}
	if raw.Filter != nil {
		if raw.Filter.Column == nil {
			return CSVConfig{}, fmt.Errorf("%s.filter.column: required", path)
		}
		if raw.Filter.Op == nil {
			return CSVConfig{}, fmt.Errorf("%s.filter.op: required", path)
		}
		if raw.Filter.Value == nil {
			return CSVConfig{}, fmt.Errorf("%s.filter.value: required", path)
		}
		c.Filter = CSVFilterConfig{Column: *raw.Filter.Column, Op: *raw.Filter.Op, Value: *raw.Filter.Value}
	}
	return normalizeCSV(c, path, raw.Filter != nil)
}

// normalizeCSV is the shared semantic validation path for YAML configuration
// and persisted parser parameters. Presence and wire canonicality are checked
// by their respective decoders.
func normalizeCSV(c CSVConfig, path string, filterPresent bool) (CSVConfig, error) {
	if c.Delimiter == "" {
		c.Delimiter = ","
	}
	r, size := utf8.DecodeRuneInString(c.Delimiter)
	if !utf8.ValidString(c.Delimiter) || size != len(c.Delimiter) || r == utf8.RuneError || r == 0 || r == '\r' || r == '\n' || r == '"' || r == '#' {
		return CSVConfig{}, fmt.Errorf("%s.delimiter: must contain one valid CSV delimiter rune", path)
	}
	if c.IPColumn <= 0 {
		return CSVConfig{}, fmt.Errorf("%s.ip_column: must be a positive one-based integer", path)
	}
	if filterPresent {
		if c.Filter.Column <= 0 {
			return CSVConfig{}, fmt.Errorf("%s.filter.column: must be a positive one-based integer", path)
		}
		switch c.Filter.Op {
		case "==", "!=", "<", "<=", ">", ">=":
		default:
			return CSVConfig{}, fmt.Errorf("%s.filter.op: unsupported numeric operator", path)
		}
		if math.IsNaN(c.Filter.Value) || math.IsInf(c.Filter.Value, 0) {
			return CSVConfig{}, fmt.Errorf("%s.filter.value: must be finite", path)
		}
		if c.Filter.Value == 0 {
			c.Filter.Value = 0
		}
	}
	return c, nil
}

// Parameters validates CSV options and returns canonical parser identity
// parameters, including the effective comma and false defaults. The zero CSV
// value denotes text and is not valid CSV input to this method.
func (c CSVConfig) Parameters() (map[string]string, error) {
	c, err := normalizeCSV(c, "csv", !c.Filter.IsZero())
	if err != nil {
		return nil, err
	}
	parameters := map[string]string{
		"delimiter": c.Delimiter,
		"header":    strconv.FormatBool(c.Header),
		"ip_column": strconv.Itoa(c.IPColumn),
	}
	if !c.Filter.IsZero() {
		parameters["filter_column"] = strconv.Itoa(c.Filter.Column)
		parameters["filter_op"] = c.Filter.Op
		parameters["filter_value"] = strconv.FormatFloat(c.Filter.Value, 'g', -1, 64)
	}
	return parameters, nil
}

// CSVConfigFromParameters accepts only exact canonical persisted CSV parser
// parameters. It rejects unknown keys, missing fields and alternate spellings.
func CSVConfigFromParameters(parameters map[string]string) (CSVConfig, error) {
	c := CSVConfig{Delimiter: parameters["delimiter"]}
	var err error
	if c.Header, err = strconv.ParseBool(parameters["header"]); err != nil {
		return CSVConfig{}, fmt.Errorf("csv.header: invalid persisted boolean")
	}
	if c.IPColumn, err = strconv.Atoi(parameters["ip_column"]); err != nil {
		return CSVConfig{}, fmt.Errorf("csv.ip_column: invalid persisted integer")
	}
	_, hasColumn := parameters["filter_column"]
	_, hasOp := parameters["filter_op"]
	_, hasValue := parameters["filter_value"]
	if hasColumn || hasOp || hasValue {
		if !hasColumn || !hasOp || !hasValue {
			return CSVConfig{}, fmt.Errorf("csv.filter: incomplete persisted parameters")
		}
		if c.Filter.Column, err = strconv.Atoi(parameters["filter_column"]); err != nil {
			return CSVConfig{}, fmt.Errorf("csv.filter.column: invalid persisted integer")
		}
		c.Filter.Op = parameters["filter_op"]
		if c.Filter.Value, err = strconv.ParseFloat(parameters["filter_value"], 64); err != nil {
			return CSVConfig{}, fmt.Errorf("csv.filter.value: invalid persisted number")
		}
	}
	c, err = normalizeCSV(c, "csv", hasColumn || hasOp || hasValue)
	if err != nil {
		return CSVConfig{}, err
	}
	canonical, err := c.Parameters()
	if err != nil {
		return CSVConfig{}, err
	}
	if len(parameters) != len(canonical) {
		return CSVConfig{}, fmt.Errorf("csv: unexpected persisted parameter shape")
	}
	for key, value := range canonical {
		if actual, ok := parameters[key]; !ok || actual != value {
			return CSVConfig{}, fmt.Errorf("csv.%s: noncanonical persisted parameter", key)
		}
	}
	return c, nil
}
