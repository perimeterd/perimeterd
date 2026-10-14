// Package crowdsecfixture generates deterministic LAPI streams without retaining
// a serialized envelope. It is shared by the scale and isolated daemon gates.
package crowdsecfixture

import (
	"fmt"
	"io"
	"net/netip"
	"time"
)

// LargeCount produces more than 100 MiB of actual decision metadata.
const LargeCount = 400_000

// Snapshot describes a generated stream. Empty IPv4/IPv6 use documentation
// addresses. Consecutive IPv4 addresses share a deadline and coalesce natively.
type Snapshot struct {
	Count int
	Until time.Time
	IPv4  string
	IPv6  string
}

// DeletedID is deliberately outside the active ID range.
func (s Snapshot) DeletedID() int64 { return int64(s.Count + 100) }

// Reader returns a fresh stream. Only one decision's encoded bytes are live in
// the generator at a time. ID 4 has expired; IDs 1 and 3 exercise normalization.
func (s Snapshot) Reader() io.Reader {
	if s.IPv4 == "" {
		s.IPv4 = "198.51.100.77"
	}
	if s.IPv6 == "" {
		s.IPv6 = "2001:db8::77"
	}
	return &reader{snapshot: s}
}

type reader struct {
	snapshot Snapshot
	index    int
	pending  []byte
	buffer   []byte
	done     bool
}

func (r *reader) Read(p []byte) (int, error) {
	if len(p) == 0 {
		return 0, nil
	}
	if len(r.pending) == 0 {
		if r.done {
			return 0, io.EOF
		}
		s := r.snapshot
		r.buffer = r.buffer[:0]
		switch {
		case r.index == 0:
			r.buffer = append(r.buffer, `{"new":[`...)
		case r.index <= s.Count:
			id := r.index
			value := netip.AddrFrom4([4]byte{198, byte((id >> 16) & 255), byte((id >> 8) & 255), byte(id & 255)}).String()
			scope := "Ip"
			switch id {
			case 1:
				value = "::ffff:" + s.IPv4
			case 2:
				value, scope = s.IPv6+"/128", "Range"
			case 3:
				value, scope = "198.51.100.129/24", "Range"
			}
			until := s.Until
			if id == 4 {
				until = until.Add(-48 * time.Hour)
			}
			if id > 1 {
				r.buffer = append(r.buffer, ',')
			}
			r.buffer = fmt.Appendf(r.buffer, `{"duration":"24h0m0s","id":%d,"origin":"CAPI","scenario":"crowdsecurity/http-probing,crowdsecurity/http-sensitive-files","scope":%q,"simulated":false,"type":"ban","until":%q,"uuid":"00000000-0000-4000-8000-%012x","value":%q}`, id, scope, until.UTC().Format(time.RFC3339), id, value)
		default:
			r.buffer = fmt.Appendf(r.buffer, `],"deleted":[{"duration":"0s","id":%d,"origin":"cscli","scenario":"crowdsecurity/ssh-bf","scope":"Ip","simulated":false,"type":"ban","until":%q,"uuid":"00000000-0000-4000-8000-ffffffffffff","value":%q}]}`, s.DeletedID(), s.Until.Add(-48*time.Hour).UTC().Format(time.RFC3339), s.IPv4)
			r.done = true
		}
		r.index++
		r.pending = r.buffer
	}
	n := copy(p, r.pending)
	r.pending = r.pending[n:]
	return n, nil
}
