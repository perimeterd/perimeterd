package lookup

import (
	"fmt"
	"net/netip"

	"github.com/perimeterd/perimeterd/internal/policy"
)

// Normalize validates and canonicalizes the operator request. A bare address
// becomes a host prefix; CIDR host bits are masked. Omitted traffic fields are
// deliberately retained as omissions so evaluation can partition them.
func Normalize(value Request) (Request, error) {
	if value.Address == "" {
		return Request{}, fmt.Errorf("address is required")
	}
	var network netip.Prefix
	if parsed, err := netip.ParsePrefix(value.Address); err == nil {
		rawAddress := parsed.Addr()
		if rawAddress.Zone() != "" {
			return Request{}, fmt.Errorf("address: zones are not supported")
		}
		if rawAddress.Is4In6() {
			return Request{}, fmt.Errorf("address: IPv4-mapped IPv6 is not supported")
		}
		network = parsed.Masked()
	} else {
		address, addrErr := netip.ParseAddr(value.Address)
		if addrErr != nil {
			return Request{}, fmt.Errorf("address: invalid IP or CIDR: %w", addrErr)
		}
		if address.Zone() != "" {
			return Request{}, fmt.Errorf("address: zones are not supported")
		}
		if address.Is4In6() {
			return Request{}, fmt.Errorf("address: IPv4-mapped IPv6 is not supported")
		}
		network = netip.PrefixFrom(address, address.BitLen())
	}
	if !network.IsValid() {
		return Request{}, fmt.Errorf("address: invalid IP or CIDR")
	}
	address := network.Addr()
	if address.Zone() != "" {
		return Request{}, fmt.Errorf("address: zones are not supported")
	}
	if address.Is4In6() {
		return Request{}, fmt.Errorf("address: IPv4-mapped IPv6 is not supported")
	}
	value.Address = network.String()

	switch value.Direction {
	case "", policy.Ingress, policy.Egress:
	default:
		return Request{}, fmt.Errorf("direction: unsupported value %q", value.Direction)
	}
	switch value.Protocol {
	case "", "tcp", "udp", "icmp", "other":
	default:
		return Request{}, fmt.Errorf("protocol: unsupported value %q", value.Protocol)
	}
	if value.Port != nil {
		if value.Protocol != "tcp" && value.Protocol != "udp" {
			return Request{}, fmt.Errorf("port requires tcp or udp protocol")
		}
		port := *value.Port
		value.Port = &port
	}
	return value, nil
}
