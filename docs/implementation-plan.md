# Implementation plan

This is the authoritative status record for the first release. Completed
milestones summarize delivered behavior; pending milestones retain their
acceptance criteria. Detailed contracts live in the linked reference documents.

The first release includes both native backends, CrowdSec, Docker coexistence,
custom HTTP(S) text IP lists, dynamic named-provider feeds, IP/CIDR lookup with
source explanations, optional embedded OpenZiti transport for LAPI/custom lists,
operational integration, and release gates.
Implemented does not mean production-ready; the remaining gates below still apply.

Use [Status at a glance](#status-at-a-glance) for delivered capabilities and
[Operational and release gates](#10-operational-and-release-gates) for remaining
work. Completed milestones below are delivery summaries, not separate schema,
algorithm, or test specifications.

## Status at a glance

| Area | Status | Next boundary |
| --- | --- | --- |
| Offline validation and pure compiler | Implemented | Maintain strict schema and policy semantics |
| Static nftables runtime | Implemented | Maintain durable recovery and owned-only mutation |
| RIPEstat resolution, cache, and refresh | Implemented for both backends | Maintain complete-snapshot selection and fallback |
| iptables/ipset runtime and backend migration | Implemented | Maintain per-family recovery and ownership fencing |
| CrowdSec | Implemented for both backends | Maintain authoritative synchronization, bounded leases, and pinned LAPI compatibility |
| Coexistence | Implemented for custom attachments and Docker's iptables bridge backend | Maintain explicit interface constraints, ordering, and foreign-state preservation |
| Custom HTTP(S) IP lists | Implemented for both backends | Maintain named include/exclude selectors, bounded fetching, exact cache identity, and per-list refresh/recovery |
| Named provider feeds | Implemented for both backends | Maintain dynamic include/exclude IDs, jsDelivr `@main` resolution without a catalog, exact cache identity, and complete-snapshot publication |
| IP/CIDR lookup and explanation | Implemented for both backends | Maintain coherent applied-state publication, complete CIDR/traffic partitions, source attribution, and private bounded transport |
| Optional OpenZiti upstream transport | Implemented for LAPI and custom lists | Maintain explicit opt-in, immutable identity/service bindings, bounded application lifecycle, and transport-aware recovery without direct fallback; retain the documented unmodified-SDK limitation |
| Operations and delivery | Source-build CLI, logging, readiness, three HTTP gauges, and native accounting implemented | Full metrics exporter, installed service, packaging, architecture coverage, signed releases |

## 1. Foundation and offline configuration validation

**Status:** implemented.

- Go module, pinned tooling, and build metadata.
- `version` and strict offline `validate` commands with defaults and normalization.
- Annotated configuration and local/CI formatting, lint, unit/race, and
  dependency checks.

Validation checks syntax and local semantics without reading credentials,
contacting sources, or mutating the firewall. See
[configuration](configuration.md) and [local commands](development.md#local-commands).

## 2. Pure policy compiler

**Status:** implemented.

The compiler consumes normalized configuration and immutable selector snapshots
without network, filesystem, or kernel I/O. It provides prefix algebra,
allow/block precedence, the pinned geo classifier, ingress/egress traffic scopes,
policy priority, IPv4/IPv6 family boundaries, disabled policies, and accounting
roles.

[Configuration](configuration.md#evaluation-semantics) owns the policy contract;
the [verification matrix](development.md#verification-matrix) owns its regression
requirements.

## 3. First safe kernel-backed vertical slice

**Status:** implemented.

nftables established the lifecycle and persistence boundaries before source-backed
policy or the second backend was added:

- Exclusive lifecycle ownership and one serialized writer.
- Immutable revisions, prepared journals, durable active-state publication,
  startup recovery, and staged reload.
- Retained rules on shutdown and explicit owned-only cleanup.
- Isolated IPv4/IPv6 packet-path and crash-recovery tests.

The [architecture](architecture.md#durable-apply-and-crash-recovery) defines the
commit boundary. The [native gate](development.md#privileged-end-to-end-suite)
verifies enforcement, recovery, and ownership without using the development
host's firewall.

## 4. RIPEstat static source-backed policy

**Status:** implemented for nftables and iptables/ipset.

RIPEstat country and ASN resolution, country-based RIR/group expansion,
content-addressed cache objects and manifests, and refresh/reload feed the same
compiler and writer. Snapshot selection follows the durable revision: incomplete
responses cannot replace committed policy, and failed refreshes retain the
selected snapshot.

[Data sources](data-sources.md) owns provider validation and fallback. Local HTTP
fixtures, durable-publication tests, and isolated native packet tests exercise
the [source requirements](development.md#sources-and-compatibility).

## 5. CrowdSec, second backend, and coexistence

**Status:** implemented.

| Delivered capability | Canonical contract | Verification |
| --- | --- | --- |
| CrowdSec startup/reconnect authority, decision identity, finite leases, expiry, and reload handover | [CrowdSec source contract](data-sources.md#supported-lapi-contract) | [Source and compatibility matrix](development.md#sources-and-compatibility); `make test-crowdsec` |
| iptables-legacy and iptables-nft parity, per-family compensation, ownership fencing, and backend migration | [iptables/ipset backend](firewall-backends.md#iptables-and-ipset) | [Kernel backend matrix](development.md#kernel-backend-and-coexistence); `make test-e2e` |
| Docker `DOCKER-USER` integration, original-destination matching, interface scoping, and foreign-state preservation | [Docker attachment contract](firewall-backends.md#docker-docker-user-attachment) | [Real Docker gate](development.md#real-docker-coexistence-gate); `make test-docker` |

Docker support is limited to its iptables bridge backend, not its native nftables
backend, rootless networking, or Swarm. The known LAPI query-error behavior remains
an accepted upstream risk, not a local polling workaround or release-blocking
fault-injection requirement; see the [supported LAPI contract](data-sources.md#supported-lapi-contract).

## 6. Custom HTTP(S) text IP lists

**Status:** implemented for nftables and iptables/ipset.

Named `ip_lists` provide HTTP(S) URLs, independent refresh intervals and request
timeouts, and include/exclude selectors that compose with country/ASN policy.
Validation remains offline; only enabled references fetch.

Bounded parsing, exact source identity, complete-snapshot publication, and
committed fallback protect refresh and recovery. This milestone introduced
version-2 cache evidence; [step 9](#9-optional-openziti-upstream-transport) extends
new evidence to version 3 without rewriting legacy object identifiers.

The [configuration](configuration.md#custom-ip-lists),
[architecture](architecture.md#custom-ip-list-integration), and
[source contract](data-sources.md#custom-https-ip-lists) own the details.
[Source verification](development.md#sources-and-compatibility) covers local
HTTP/TLS boundaries, mixed-source failures, legacy recovery, independent timing,
and native IPv4/IPv6 lifecycle on all three backend/tool-family variants.

## 7. Dynamic named-provider feeds

**Status:** implemented for nftables and iptables/ipset.

`include.providers` and `exclude.providers` resolve safe provider IDs through
the jsDelivr `@main` merged-file template. There is no compiled-in catalog,
per-provider definition, discovery request, or alternate-mirror fallback.
Offline validation checks syntax; runtime fetching determines existence.

Provider feeds share the bounded text pipeline and complete-snapshot cache.
Missing new IDs prevent activation; later failures can retain exact committed
fallback. Provider timing and freshness reporting remain separate from RIPEstat
and custom lists. Whole-provider sets track mutable `main`; service/region
filters and a common upstream Git revision are not implied.

The [configuration](configuration.md#named-providers),
[architecture](architecture.md#named-provider-integration), and
[source contract](data-sources.md#named-provider-feeds) define the endpoint,
defaults, identity, and scheduling rules. The
[source verification matrix](development.md#sources-and-compatibility) covers
dynamic existence, mixed-source publication, actual CLI use, and native lifecycle
without depending on live CDN data.

## 8. IP/CIDR lookup and source explanation

**Status:** implemented.

The `lookup` CLI queries the daemon's coherent applied state, not a fresh
compilation or an independent native firewall reader. Delivered capabilities:

- Backend-neutral evaluation of complete IPv4/IPv6 CIDRs, directions, and
  optional protocol/port filters, including attachment/interface conditions.
- Writer-owned publication and completion fencing across reload, dynamic updates,
  compensation, uncertain recovery, and confirmed empty managed state.
- Static source attribution and CrowdSec decision/lease evidence without
  query-time source fetching or persistence of live decisions.
- A private bounded Unix-socket API, human/JSON output, stable verdicts and exit
  codes, cancellation, and explicit unknown results when evidence is unavailable.

The [operator contract](operations.md#ipcidr-lookup),
[query architecture](architecture.md#read-only-lookup-and-explanation), and
[provenance contract](data-sources.md#lookup-source-attribution) own the behavior.
The [lookup verification matrix](development.md#lookup-and-explanation) covers
the actual CLI, native packets, Docker port/attachment semantics, and lifecycle
races. This milestone adds no YAML fields or durable schemas.

## 9. Optional OpenZiti upstream transport

**Status:** implemented with unmodified `sdk-golang v1.8.2` and the explicitly
accepted [SDK cancellation limitation](data-sources.md#sdk-cancellation-limitation).

Named enrolled identity profiles and per-list/LAPI bindings opt selected HTTP
clients into exact private-service dialing. Direct-only installations remain
unchanged; no host tunneler, automatic enrollment, global HTTP interception,
RIPEstat/provider interception, or silent direct fallback is introduced.

Immutable credential generations, independent session ownership, and
transport-aware version-3 cache evidence follow publication and recovery.
Legacy version-1/2 direct evidence remains recoverable under its original
identifiers. Same-path rotation takes effect on reload; LAPI route/identity
replacement requires fresh authority rather than merging the old stream.

The [architecture](architecture.md#optional-openziti-upstream-transport),
[schema](configuration.md#optional-openziti-configuration),
[source contract](data-sources.md#openziti-upstream-transport), and
[operator prerequisites](operations.md#openziti-operations) own the details.
Application waits are bounded; that does not imply complete drainage of
SDK-internal discovery/authentication work.

`make test-openziti` provisions pinned real OpenZiti/CrowdSec fixtures and
exercises authorization, private routing, TLS, identity rotation, mixed sources,
LAPI authority and expiry, lookup, and IPv4/IPv6 enforcement on all three
backend/tool-family variants. The
[OpenZiti verification matrix](development.md#optional-openziti-transport)
owns acceptance and fixture requirements.

## 10. Operational and release gates

**Status:** partially implemented.

Source builds provide stdout logging, three Prometheus gauges, native packet/byte
accounting, and bounded systemd readiness notifications. Remaining work:

- Full metrics collection and export.
- Installed systemd/tmpfiles payloads and verified service lifecycle.
- RPM/DEB package lifecycle and remaining architecture coverage.
- Signed release artifacts and release CI.

The [development](development.md#version-1-verification-and-delivery-requirements)
and [operations](operations.md) contracts define acceptance. Add packaging and
release scaffolding only with working artifacts and executable checks.

## Immediate next task

Complete [step 10](#10-operational-and-release-gates): metrics, service/package
lifecycle, remaining architecture coverage, and signed release gates. Maintain
the [verification matrix](development.md#verification-matrix) for delivered
features while adding these operational artifacts.
Track new work as issues using acceptance criteria from the owning documents
rather than maintaining another implementation or test plan.
