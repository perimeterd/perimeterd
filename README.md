# perimeterd

**Block unwanted traffic at your Linux perimeter.**

`perimeterd` adds geographic/ASN policy and IP/CIDR allow/block overrides to an
existing Linux firewall. It filters unwanted ingress and egress traffic; the
parent firewall remains responsible for permitting services and ports.

> **Status: source-backed nftables and iptables/ipset runtime with CrowdSec.**
> Offline validation, the pure policy compiler, direct IP/CIDR rules, RIPEstat
> country/RIR/group/ASN policies, and CrowdSec ingress bans are implemented.
> The runtime includes immutable static caching, durable recovery, renewable
> dynamic leases, backend migration, and isolated packet-path tests. Docker
> integration, packages, and production releases remain planned. This is not
> yet a production-ready security control.

The [implementation plan](docs/implementation-plan.md) is the authoritative
record of completed milestones and remaining work.

## Try the configuration validator

Build with Go 1.27.1; automatic toolchain selection also works with an older Go:

```sh
GOTOOLCHAIN=auto make build
bin/perimeterd version
bin/perimeterd validate --config configs/perimeterd.yaml
```

Validation requires neither root nor network access. It checks local syntax and
semantics, not source availability or kernel enforcement. Root-only `run` and
`cleanup` are available for the [current runtime](docs/operations.md#current-source-build-runtime).
Try enforcement only in a disposable VM or isolated network namespace. See
[development](docs/development.md#local-commands) for verification commands.

## First-release contract

This table describes the complete release target, not a list of currently
available features. The status above and implementation plan distinguish what
is implemented.

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

For the available runtime, start with [current source-build operations](docs/operations.md#current-source-build-runtime).
For implementation work, check the [implementation plan](docs/implementation-plan.md),
then read [architecture](docs/architecture.md) and its source/backend contracts.
Use [development](docs/development.md) for the current repository map and commands;
its version-1 verification and delivery requirements also describe future work.

Each document owns the contract named below. Other documents summarize and
link to that owner rather than define a second algorithm.

- [Implementation plan](docs/implementation-plan.md): completed milestones,
  remaining work, and the next vertical slice.
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
- [Development](docs/development.md): current source tree and executable gates,
  followed by version-1 verification coverage, CI, and release requirements.

## Design lineage and licensing

The existing [MIT license](LICENSE) is authoritative. The project takes
behavior-level inspiration from
[geoip-shell](https://github.com/friendly-bits/geoip-shell), whose GPL-3.0
source must not be copied into this MIT-licensed repository. The MIT-licensed
[CrowdSec firewall bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer)
and [Go CrowdSec bouncer client](https://github.com/crowdsecurity/go-cs-bouncer)
may be reused subject to dependency review and preservation of required
copyright and license notices.
