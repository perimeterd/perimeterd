# perimeterd

> **Status: design phase.** No daemon, packages, or production-ready release exist
> yet. The documents in this repository define the intended first release; they
> are not evidence of an implemented security control.

`perimeterd` is a Linux firewall policy daemon planned in Go. It will compile
country, RIR, group, and ASN selectors into host firewall policy and combine
that static policy with CrowdSec Local API ingress bans. One process will own
all mutations made through either nftables or iptables/ipset.

## First-release contract

| Area | Version 1 commitment | Owning document |
| --- | --- | --- |
| Platform | Linux; Go 1.27; `amd64` and `arm64` | [Development](docs/development.md) |
| Configuration | Strict local YAML; future remote-source boundary | [Configuration](docs/configuration.md), [architecture](docs/architecture.md) |
| Selectors | RIPEstat-derived country, RIR, built-in/custom group, and ASN prefixes; IPv4 and IPv6 | [Data sources](docs/data-sources.md) |
| Policy | Global IP/CIDR allow/block overrides; ingress/egress geo policy with ports, exceptions, and disabled/reset state | [Configuration](docs/configuration.md) |
| Dynamic bans | CrowdSec LAPI stream-mode ingress `ban` decisions | [Data sources](docs/data-sources.md) |
| Packet path | New-flow policy with established-flow symmetry; DROP or REJECT | [Firewall backends](docs/firewall-backends.md) |
| Firewalls | nftables; iptables with ipset; explicit Docker/custom-chain attachment | [Firewall backends](docs/firewall-backends.md) |
| Service | systemd foreground daemon with explicit readiness and cleanup | [Operations](docs/operations.md) |
| Observability | stdout text/JSON logs; Prometheus health and kernel packet/byte accounting | [Operations](docs/operations.md) |
| Quality | Unit and privileged E2E suites; PR/default-branch checks | [Development](docs/development.md) |
| Releases | Signed SemVer tags; static RPM/DEB artifacts for both architectures | [Development](docs/development.md), [operations](docs/operations.md) |

## Documentation

For deployment, read [configuration](docs/configuration.md) and then
[operations](docs/operations.md). For implementation, start with
[architecture](docs/architecture.md), follow its source/backend contracts, and
use [development](docs/development.md) for verification and delivery gates.

Each document owns the contract named below. Other documents summarize and
link to that owner rather than define a second algorithm.

- [Architecture](docs/architecture.md): components, lifecycle ownership, static
  revision admission, durable commit/recovery, and future deployment boundaries.
- [Configuration](docs/configuration.md): canonical YAML schema, defaults,
  validation, policy semantics, and examples.
- [Firewall backends](docs/firewall-backends.md): packet path, ownership,
  backend-specific commit/rollback guarantees, coexistence, and Docker attachments.
- [Data sources](docs/data-sources.md): RIPEstat/cache and CrowdSec wire
  compatibility, decision admission, timed projection, and renewable leases.
- [Operations](docs/operations.md): operator procedures, deployment prerequisites,
  installed layout, systemd, logs, metrics, upgrades, and removal.
- [Development](docs/development.md): proposed source tree, verification coverage
  by contract and layer, quality gates, CI, and releases.

## Design lineage and licensing

The existing [MIT license](LICENSE) is authoritative. The project takes
behavior-level inspiration from
[geoip-shell](https://github.com/friendly-bits/geoip-shell), whose GPL-3.0
source must not be copied into this MIT-licensed repository. The MIT-licensed
[CrowdSec firewall bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer)
and [Go CrowdSec bouncer client](https://github.com/crowdsecurity/go-cs-bouncer)
may be reused subject to dependency review and preservation of required
copyright and license notices.
