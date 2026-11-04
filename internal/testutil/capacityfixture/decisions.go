package capacityfixture

import (
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/perimeterd/perimeterd/internal/crowdsec"
)

// DBIPBatch keeps every decision effective and disjoint, within stable country
// memberships. Mixed IP/range decisions exercise both family projection paths.
func DBIPBatch(count, offset int, until time.Time) crowdsec.Batch {
	batch := crowdsec.Batch{Startup: true, New: make([]crowdsec.Decision, count)}
	for i := range count {
		ipv6 := i%2 != 0
		prefix := DBIPPrefix(10000+(i+offset)/2, ipv6, false)
		bits := 32
		if ipv6 {
			bits = 128
		}
		if i%4 >= 2 {
			bits--
		}
		prefix = netip.PrefixFrom(prefix.Addr(), bits)
		if i == 0 {
			prefix = netip.MustParsePrefix("8.22.0.2/32")
		}
		if i == 1 {
			prefix = netip.MustParsePrefix("2600:22::2/128")
		}
		batch.New[i] = crowdsec.Decision{ID: int64(i + 1), Prefix: prefix, Deadline: until}
	}
	return batch
}

// WriteDBIPSnapshot writes the local LAPI envelope through its bounded caller
// buffer. Offset changes membership without changing decision IDs.
func WriteDBIPSnapshot(w io.Writer, batch crowdsec.Batch) error {
	if _, err := io.WriteString(w, `{"new":[`); err != nil {
		return err
	}
	for i, decision := range batch.New {
		if i != 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		scope, value := "Range", decision.Prefix.String()
		if decision.Prefix.Bits() == decision.Prefix.Addr().BitLen() {
			scope, value = "Ip", decision.Prefix.Addr().String()
		}
		if _, err := fmt.Fprintf(w, `{"id":%d,"scope":%q,"value":%q,"type":"ban","origin":"cscli","duration":"24h","until":%q}`, decision.ID, scope, value, decision.Deadline.UTC().Format(time.RFC3339)); err != nil {
			return err
		}
	}
	if _, err := io.WriteString(w, `],"deleted":[`); err != nil {
		return err
	}
	for i, id := range batch.Deleted {
		if i != 0 {
			if _, err := io.WriteString(w, ","); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, `{"id":%d}`, id); err != nil {
			return err
		}
	}
	_, err := io.WriteString(w, `]}`)
	return err
}
