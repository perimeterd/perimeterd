![Block unwanted traffic at your Linux perimeter](docs/img/social-banner.png)

# perimeterd

`perimeterd` adds geographic/ASN policy, custom and provider IP lists, CrowdSec
ingress bans, and IP/CIDR allow/block overrides to an existing Linux firewall.
It filters unwanted ingress and egress traffic; the parent firewall remains
responsible for permitting services and ports.

> **Pre-release:** source builds and local DEB/RPM packages are available.
> Publication requires the complete operational and release gates.
> **This is not yet a production-ready security control.**

Release qualification is defined by the [verification matrix](docs/development.md#verification-matrix)
and [release workflow](docs/development.md#release-workflow), not by feature completion.

## Try the configuration validator

Use the Go version declared in [`go.mod`](go.mod); automatic toolchain selection
also works with an older Go:

```sh
GOTOOLCHAIN=auto make build
bin/perimeterd version
bin/perimeterd validate --config configs/perimeterd.yaml
```

Validation requires neither root nor network access. It checks local syntax and
semantics, not source availability or kernel enforcement. Root-only `run`,
`cleanup`, and daemon-backed [lookup](docs/operations.md#ipcidr-lookup) are
available for the [runtime capabilities](docs/operations.md#runtime-capabilities).
Try enforcement only in a disposable VM or isolated network namespace. See
[development](docs/development.md#local-commands) for verification commands.

## Capabilities

The runtime targets Linux on `amd64` and `arm64`, with nftables or iptables/ipset,
RIPEstat-derived geographic/ASN policy, custom HTTP(S) text IP lists in policy
include/exclude selectors with per-list refresh intervals, direct provider IDs
resolved dynamically through jsDelivr, and CrowdSec ingress bans. Docker
coexistence, IP/CIDR lookup with source explanations, and
[optional OpenZiti transport](docs/architecture.md#optional-openziti-upstream-transport)
for selected CrowdSec/custom-list upstreams are implemented. Direct HTTP(S)
remains the default, with no Ziti prerequisite. Prometheus observability,
systemd/tmpfiles integration, amd64/arm64 DEB/RPM packaging, and signed release
automation are implemented.

The documents below own the detailed contracts. Source-build commands do not
install services or packages; see the [installed layout](docs/operations.md#installed-layout)
for package contents and [release workflow](docs/development.md#release-workflow)
for publication requirements.

## Documentation

Start with [operations](docs/operations.md#runtime-capabilities) to try
enforcement, or [development](docs/development.md#local-commands) to build and
verify changes.

| Document | Canonical scope |
| --- | --- |
| [Architecture](docs/architecture.md) | Component boundaries, writer ownership, revision admission, commit, recovery, and applied-state lookup |
| [Configuration](docs/configuration.md) | YAML schema, defaults, validation, policy semantics, and examples |
| [Data sources](docs/data-sources.md) | RIPEstat/cache contracts, HTTP(S) text lists, dynamic provider feeds, and CrowdSec wire compatibility, authority, projection, and leases |
| [Firewall backends](docs/firewall-backends.md) | Packet paths, native ownership, commit/rollback guarantees, and attachments |
| [Operations](docs/operations.md) | Source-build procedures, health/metrics, lookup CLI contract, and service/package lifecycle |
| [Development](docs/development.md) | Repository map, commands, verification matrix, measurements, CI, and release requirements |

Each contract has one owner. Other documents summarize it and link to that owner
rather than define a second algorithm.

## Design lineage and licensing

The project is [MIT-licensed](LICENSE). It takes behavior-level inspiration from
[geoip-shell](https://github.com/friendly-bits/geoip-shell), whose GPL-3.0 source
must not be copied into this repository. See
[license discipline](docs/development.md#license-discipline) for dependency reuse
and notice requirements.
