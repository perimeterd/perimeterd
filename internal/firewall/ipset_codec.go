package firewall

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"iter"
	"net/netip"
	"strconv"
	"strings"
	"unicode"
)

// ipsetSaveRecords parses ipset's save grammar, not shell or iptables escaping.
// Double-quoted fields may span lines, but backslashes and apostrophes are
// literal. Keeping record and field parsing together prevents quoted comments
// from consuming following set definitions.
func ipsetSaveRecords(data string) iter.Seq2[[]string, error] {
	return func(yield func([]string, error) bool) {
		var fields []string
		var token strings.Builder
		inToken, quoted, closed, comment := false, false, false, false
		flushToken := func() {
			if inToken {
				if fields == nil {
					fields = make([]string, 0, 8)
				}
				fields = append(fields, token.String())
				token.Reset()
				inToken = false
			}
			closed = false
		}
		for _, char := range data {
			if char == '\n' && !quoted {
				flushToken()
				if len(fields) != 0 && !yield(fields, nil) {
					return
				}
				fields = nil
				comment = false
				continue
			}
			if comment {
				continue
			}
			if quoted {
				if char == '"' {
					quoted, closed = false, true
				} else {
					token.WriteRune(char)
				}
				continue
			}
			if unicode.IsSpace(char) {
				flushToken()
				continue
			}
			if closed {
				yield(nil, errors.New("ipset save: missing delimiter after quoted field"))
				return
			}
			if !inToken && len(fields) == 0 && char == '#' {
				comment = true
				continue
			}
			if !inToken && char == '"' {
				inToken, quoted = true, true
				continue
			}
			token.WriteRune(char)
			inToken = true
		}
		if quoted {
			yield(nil, errors.New("ipset save: unterminated quote"))
			return
		}
		flushToken()
		if len(fields) != 0 {
			yield(fields, nil)
		}
	}
}

func parseIPSetSave(data []byte) (map[string]iptObservedSet, error) {
	if len(data) > maxIPTablesOutput {
		return nil, errors.New("oversized ipset save")
	}
	result := make(map[string]iptObservedSet)
	for fields, err := range ipsetSaveRecords(string(data)) {
		if err != nil {
			return nil, err
		}
		if len(fields) < 3 {
			return nil, errors.New("malformed ipset save")
		}
		switch fields[0] {
		case "create":
			if _, exists := result[fields[1]]; exists {
				return nil, errors.New("duplicate set")
			}
			set := iptObservedSet{Name: fields[1], Type: fields[2], Family: "inet", Options: fields[3:]}
			for n := 3; n+1 < len(fields); n++ {
				if fields[n] == "family" {
					set.Family = fields[n+1]
				}
			}
			result[set.Name] = set
		case "add":
			set, exists := result[fields[1]]
			if !exists {
				return nil, errors.New("element references undeclared set")
			}
			entry := fields[2]
			if set.Type == "hash:net" {
				prefix, err := netip.ParsePrefix(entry)
				if err != nil {
					addr, addrErr := netip.ParseAddr(entry)
					if addrErr != nil {
						return nil, err
					}
					prefix = netip.PrefixFrom(addr, addr.BitLen())
				}
				entry = prefix.Masked().String()
			}
			set.Entries = append(set.Entries, entry)
			set.Extended = set.Extended || len(fields) != 3
			for n := 3; n < len(fields); n++ {
				switch fields[n] {
				case "timeout":
					if n+1 >= len(fields) {
						return nil, errors.New("ipset entry timeout is missing")
					}
					if set.Timeouts == nil {
						set.Timeouts = make(map[string]uint64)
					}
					if _, duplicate := set.Timeouts[entry]; duplicate {
						return nil, errors.New("duplicate ipset entry timeout")
					}
					timeout, err := strconv.ParseUint(fields[n+1], 10, 64)
					if err != nil {
						return nil, fmt.Errorf("ipset entry timeout: %w", err)
					}
					set.Timeouts[entry] = timeout
					n++
				case "comment":
					if n+1 >= len(fields) {
						return nil, errors.New("ipset entry comment is missing")
					}
					set.UnknownOptions = true
					n++
				default:
					set.UnknownOptions = true
				}
			}
			result[set.Name] = set
		default:
			return nil, errors.New("unsupported ipset save directive")
		}
	}
	return result, nil
}

// Native reference counts include users outside the selected xtables inventory,
// including list:set membership and rules from the other tool implementation.
func parseIPSetReferences(data []byte, name string) (uint64, error) {
	var document struct {
		XMLName xml.Name `xml:"ipsets"`
		Sets    []struct {
			Name    string `xml:"name,attr"`
			Headers []struct {
				References []string `xml:"references"`
			} `xml:"header"`
		} `xml:"ipset"`
	}
	decoder := xml.NewDecoder(bytes.NewReader(data))
	if err := decoder.Decode(&document); err != nil {
		return 0, fmt.Errorf("ipset reference metadata: %w", err)
	}
	for {
		token, err := decoder.Token()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return 0, fmt.Errorf("ipset reference metadata: %w", err)
		}
		if text, ok := token.(xml.CharData); !ok || len(bytes.TrimSpace(text)) != 0 {
			return 0, errors.New("ipset reference metadata has trailing content")
		}
	}
	if len(document.Sets) != 1 || document.Sets[0].Name != name ||
		len(document.Sets[0].Headers) != 1 || len(document.Sets[0].Headers[0].References) != 1 {
		return 0, errors.New("ipset query returned incomplete or ambiguous reference metadata")
	}
	count, err := strconv.ParseUint(document.Sets[0].Headers[0].References[0], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("ipset reference count: %w", err)
	}
	return count, nil
}
