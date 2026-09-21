# Implementation plan

This is the authoritative status record for the first release. Completed
milestones summarize delivered behavior; pending milestones retain their
acceptance criteria. Detailed contracts live in the linked reference documents.

The first release includes both native backends, CrowdSec, Docker coexistence,
custom HTTP(S) text IP lists, dynamic named-provider feeds, IP/CIDR lookup with
source explanations, operational integration, and release gates.
Implemented does not mean production-ready; the remaining gates below still apply.

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

| Milestone | Status | Delivered behavior or remaining acceptance |
| --- | --- | --- |
| CrowdSec | Implemented | Authoritative startup synchronization, decision updates/removals, expiry, renewable leases, reload handover, and pinned real-LAPI compatibility |
| iptables/ipset | Implemented | Packet-policy parity, family-by-family commit and compensation, ownership fencing, recovery, and backend migration |
| Coexistence | Implemented | Real Docker-generated `DOCKER-USER` integration, pre-DNAT port matching, preserved container egress, and foreign-state preservation |

**iptables/ipset:** both legacy and nf_tables tool families support direct and
source-backed IPv4/IPv6 policy, `/0` lowering, interface-constrained custom
attachments, original-destination ports, stable native accounting, and owned
cleanup. Isolated tests cover second-family failures, compensation, crashes, and
bidirectional backend migration.

**CrowdSec:** bounded wire validation preserves decision identity and absolute
expiry. The writer admits current authority separately from durable targets;
renewal does not require a desired-state change, and decisions and credential
contents are never persisted as recovery authority. Both backends use finite
leases capped at 24 hours. Tests cover staged reload/reconnect, failed writes,
credential rotation, uncertain commit, packet enforcement, expiry without the
daemon, and cleanup. `make test-crowdsec` runs the digest-pinned v1.8.1 stream
compatibility gate.

**Docker:** `make test-docker` starts a private real Docker Engine in isolated
namespaces and exercises both iptables-nft and iptables-legacy with IPv4 and IPv6.
The gate verifies remapped published ports with and without original-destination
matching, external-interface scoping, downstream foreign denial, rejected
missing-parent reloads, retained enforcement on stop, and owned-only cleanup.
Docker rules and default policies remain unchanged. A separate privileged CI job
pins Docker 29.8.1. The verified scope is Docker's iptables bridge backend, not
Docker's native nftables backend, rootless networking, or Swarm; see the
[Docker attachment contract](firewall-backends.md#docker-docker-user-attachment).

The known LAPI query-error behavior is an accepted temporary upstream risk tracked in
[crowdsecurity/crowdsec#4691](https://github.com/crowdsecurity/crowdsec/issues/4691).
It is not fault-tested or worked around with full-list polling; see
[data sources](data-sources.md#supported-lapi-contract).

## 6. Custom HTTP(S) text IP lists

**Status:** implemented for nftables and iptables/ipset.

Named `ip_lists` definitions provide HTTP(S) URLs, per-list refresh intervals,
and request timeouts. Both include and exclude selectors support list-only and
mixed country/ASN/list policy through the existing union/subtraction compiler.
Validation remains offline; unused lists are not fetched.

The resolver validates complete bounded text responses and stages version-2
immutable objects/manifests with exact list URL/parser identity. Version-1
RIPEstat recovery still loads, stabilizes, and retains its original object IDs.
The shared scheduler preserves independent deadlines and applies retry
cooldowns only to selectors chosen for fetching. URL changes cannot use old
endpoint fallback; malformed or unavailable feeds never publish partial state.

Verification includes local HTTP/TLS fixtures, decoded-size and redirect
boundaries, mixed-source compilation, legacy-cache recovery, and native
dual-stack list lifecycle scenarios on nftables and both iptables tool families.
The runnable example defines an unreferenced Zoom feed without introducing
network access into the default empty policy.

The [configuration contract](configuration.md#custom-ip-lists),
[static source boundary](architecture.md#custom-ip-list-integration), and
[source contract](data-sources.md#custom-https-ip-lists) own the implementation
invariants. Keep the [verification matrix](development.md#verification-matrix)
and existing writer, CrowdSec, ownership, and Docker gates passing.

## 7. Dynamic named-provider feeds

**Status:** implemented for nftables and iptables/ipset.

`include.providers` and `exclude.providers` accept safe provider IDs, including
new IDs and underscores, without compiled-in membership or per-provider source
definitions. Offline validation checks syntax and source-wide positive timing
settings; runtime resolution determines existence by fetching:

```text
https://cdn.jsdelivr.net/gh/rezmoss/cloud-provider-ip-addresses@main/{id}/{id}_ips_merged.txt
```

No catalog, metadata/discovery request, GitHub API, alternate mirror, or
`go-cloudip` dependency is used. Only missing/due enabled references fetch,
with `24h` refresh and `30s` request timeout defaults. Provider records use the
shared bounded text pipeline and version-2 static manifests; existing RIPEstat
and custom-list cache generations remain recoverable.

The existing scheduler, exact attempted-selector retry evidence, and writer
preserve complete-snapshot publication. New missing IDs prevent activation or
reject reload; later 404/invalid responses retain exact committed fallback.
Freshness is reported with the fixed `source="provider"` label, separately from
RIPEstat and custom lists. Provider and custom-list names do not collide.

Verification covers dynamic existence and later appearance, unsafe IDs,
mixed-source compilation/failure retention, durable identity, independent timing,
and new-flow IPv4/IPv6 lifecycle on nftables and both iptables tool families.
The actual CLI is also exercised against an isolated HTTPS CDN fixture, including
unknown-ID startup failure, rejected-reload timer preservation, restart fallback,
and final-reference removal. Tests do not depend on live CDN data.

The [configuration contract](configuration.md#named-providers),
[static source boundary](architecture.md#named-provider-integration), and
[source contract](data-sources.md#named-provider-feeds) own implementation
invariants. Whole-provider sets follow mutable `main`; service/region filters and
a common upstream Git revision are not implied. Keep the
[verification matrix](development.md#verification-matrix) and existing source,
writer, CrowdSec, and Docker gates passing.

## 8. IP/CIDR lookup and source explanation

**Status:** implemented.

The CLI provides `lookup` alongside `run`, `validate`, `cleanup`, and `version`.
The [operator contract](operations.md#ipcidr-lookup),
[applied-state query boundary](architecture.md#read-only-lookup-and-explanation),
and [provenance contract](data-sources.md#lookup-source-attribution) are delivered
without new YAML fields or durable schemas:

1. **Pure query evaluation.** `internal/lookup` evaluates backend-neutral
   compiled rules for complete IPv4/IPv6 CIDRs, both directions, optional
   protocol/port filters, and new flows. It preserves terminal pass,
   global/CrowdSec precedence, classifier, allowlist absence, and explicit
   attachment/interface/port-basis conditions without native inspection.
2. **Coherent applied-state publication.** The existing writer publishes
   immutable selected configuration/manifest references together with
   acknowledged dynamic projection, decision identity, and conservative native
   lease evidence. Mutation and uncertain recovery invalidate definitive
   answers; a completion fence rejects queries racing a newer operation.
   Rejected candidates and safe compensation preserve old authority.
   Confirmed empty managed state remains queryable.
3. **Source explanations.** Matching country/group/RIR/ASN/list/provider
   membership, include/exclude roles, global entries, and the deciding rule
   remain distinct. CrowdSec evidence retains every matching decision ID and
   separates decision deadlines from acknowledged native leases. Queries do
   not fetch sources, persist live decisions, or invent origin/scenario metadata.
4. **Private interface and CLI.** A root-only fixed Unix socket serves strict,
   versioned, bounded requests independently of metrics. `lookup` supplies
   human/JSON output, stable verdicts and exit codes, cancellation, and explicit
   unknown results for unavailable, inconsistent, or over-limit evidence.
   The listener shares ownership/startup/reload/shutdown lifecycle without
   acquiring the writer or lifecycle lock for queries.
5. **Executable acceptance.** Actual CLI and IPv4/IPv6 probes cover nftables,
   iptables-legacy, and iptables-nft. Docker probes verify original/current
   destination-port semantics and foreign downstream denial. Source refresh,
   rejected reload, CrowdSec deletion/expiry, empty state, and socket shutdown
   scenarios are exercised alongside record-limit, malformed/partial-response,
   cancellation, and uncertain-journal regressions.

The [lookup verification matrix](development.md#lookup-and-explanation) owns
the maintained behavioral requirements. Verification includes `make verify`,
`make test-race`, the full privileged native gate, real-LAPI compatibility, and
the pinned private Docker coexistence/security gate. No independent firewall
reader/writer, query-time packet probe, general GeoIP enrichment, or offline
fallback is part of this feature.

## 9. Operational and release gates

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

Complete step 9: full metrics collection and export, installed service/package
lifecycle and architecture coverage, and signed release artifacts with
executable release CI.

Static source-backed policy, custom HTTP(S) lists, dynamic named providers, both
native backends, CrowdSec synchronization and decision lifecycle, Docker
iptables bridge coexistence, and daemon-backed lookup are implemented. Keep
their writer, recovery, packet-path, query, and compatibility gates passing.
Track new work as issues using acceptance criteria from the owning documents
rather than maintaining another implementation or test plan.
