package source

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"unicode/utf16"
	"unicode/utf8"
)

// canonicalJSON emits RFC 8785-compatible canonical UTF-8 for the JSON values
// used by cache schemas. Cache schemas contain only strings, booleans, arrays,
// objects, and integral schema versions.
func canonicalJSON(value any) ([]byte, error) {
	raw, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	parsed, err := parseCanonicalValue(decoder)
	if err != nil {
		return nil, err
	}
	if err := ensureCanonicalEOF(decoder); err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := writeCanonicalValue(&out, parsed); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

func decodeCanonical(data []byte, target any, limit int64) error {
	if int64(len(data)) > limit || len(data) == 0 {
		return errors.New("cache record size is invalid")
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	value, err := parseCanonicalValue(decoder)
	if err != nil {
		return fmt.Errorf("malformed JSON: %w", err)
	}
	if err := ensureCanonicalEOF(decoder); err != nil {
		return err
	}
	// Schema decoding below enforces the known fields after canonical parsing.
	decoder2 := json.NewDecoder(bytes.NewReader(data))
	decoder2.DisallowUnknownFields()
	if err := decoder2.Decode(target); err != nil {
		return fmt.Errorf("malformed payload: %w", err)
	}
	if err := ensureCanonicalEOF(decoder2); err != nil {
		return err
	}
	// Re-encoding through the canonical value rejects non-canonical bytes while
	// still allowing the decoder to enforce schema field names below.
	var canonicalBytes bytes.Buffer
	if err := writeCanonicalValue(&canonicalBytes, value); err != nil {
		return err
	}
	if !bytes.Equal(canonicalBytes.Bytes(), data) {
		return errors.New("cache record is not canonical JSON")
	}
	return nil
}

func parseCanonicalValue(decoder *json.Decoder) (any, error) {
	token, err := decoder.Token()
	if err != nil {
		return nil, err
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			object := make(map[string]any)
			for decoder.More() {
				keyToken, err := decoder.Token()
				if err != nil {
					return nil, err
				}
				key, ok := keyToken.(string)
				if !ok {
					return nil, errors.New("object key is not a string")
				}
				if _, exists := object[key]; exists {
					return nil, fmt.Errorf("duplicate object key %q", key)
				}
				child, err := parseCanonicalValue(decoder)
				if err != nil {
					return nil, err
				}
				object[key] = child
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim('}') {
				return nil, errors.New("unterminated object")
			}
			return object, nil
		case '[':
			array := make([]any, 0)
			for decoder.More() {
				child, err := parseCanonicalValue(decoder)
				if err != nil {
					return nil, err
				}
				array = append(array, child)
			}
			end, err := decoder.Token()
			if err != nil || end != json.Delim(']') {
				return nil, errors.New("unterminated array")
			}
			return array, nil
		default:
			return nil, errors.New("unexpected delimiter")
		}
	case json.Number:
		if strings.ContainsAny(string(value), ".eE") {
			return nil, errors.New("non-integral number in cache record")
		}
		return value, nil
	default:
		return value, nil
	}
}

func ensureCanonicalEOF(decoder *json.Decoder) error {
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("trailing JSON data")
		}
		return fmt.Errorf("trailing JSON data: %w", err)
	}
	return nil
}

func writeCanonicalValue(out *bytes.Buffer, value any) error {
	switch value := value.(type) {
	case nil:
		out.WriteString("null")
	case bool:
		if value {
			out.WriteString("true")
		} else {
			out.WriteString("false")
		}
	case string:
		if !utf8.ValidString(value) {
			return errors.New("invalid UTF-8 string")
		}
		writeCanonicalString(out, value)
	case json.Number:
		out.WriteString(string(value))
	case []any:
		out.WriteByte('[')
		for i, child := range value {
			if i > 0 {
				out.WriteByte(',')
			}
			if err := writeCanonicalValue(out, child); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Slice(keys, func(i, j int) bool { return utf16Less(keys[i], keys[j]) })
		out.WriteByte('{')
		for i, key := range keys {
			if i > 0 {
				out.WriteByte(',')
			}
			writeCanonicalString(out, key)
			out.WriteByte(':')
			if err := writeCanonicalValue(out, value[key]); err != nil {
				return err
			}
		}
		out.WriteByte('}')
	default:
		return fmt.Errorf("unsupported JSON value %T", value)
	}
	return nil
}

func utf16Less(a, b string) bool {
	aa, bb := utf16.Encode([]rune(a)), utf16.Encode([]rune(b))
	for i := 0; i < len(aa) && i < len(bb); i++ {
		if aa[i] != bb[i] {
			return aa[i] < bb[i]
		}
	}
	return len(aa) < len(bb)
}

func writeCanonicalString(out *bytes.Buffer, value string) {
	out.WriteByte('"')
	for _, char := range []byte(value) {
		switch char {
		case '\\', '"':
			out.WriteByte('\\')
			out.WriteByte(char)
		case '\b':
			out.WriteString("\\b")
		case '\f':
			out.WriteString("\\f")
		case '\n':
			out.WriteString("\\n")
		case '\r':
			out.WriteString("\\r")
		case '\t':
			out.WriteString("\\t")
		default:
			if char < 0x20 {
				fmt.Fprintf(out, "\\u00%02x", char)
			} else {
				out.WriteByte(char)
			}
		}
	}
	out.WriteByte('"')
}
