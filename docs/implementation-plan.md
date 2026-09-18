# Implementation plan

This is the authoritative status record for the first release. Completed
milestones summarize delivered behavior; pending milestones retain their
acceptance criteria. Detailed contracts live in the linked reference documents.

The first release includes both native backends, CrowdSec, Docker coexistence,
operational integration, and release gates. Implemented does not mean
production-ready; the remaining gates below still apply.

## Status at a glance

| Area | Status | Next boundary |
| --- | --- | --- |
| Offline validation and pure compiler | Implemented | Maintain strict schema and policy semantics |
| Static nftables runtime | Implemented | Maintain durable recovery and owned-only mutation |
| RIPEstat resolution, cache, and refresh | Implemented for both backends | Maintain complete-snapshot selection and fallback |
| iptables/ipset runtime and backend migration | Implemented | Maintain per-family recovery and ownership fencing |
| CrowdSec | Implemented for both backends | Maintain authoritative synchronization, bounded leases, and pinned LAPI compatibility |
| Coexistence | Custom-chain attachments implemented; Docker milestone pending | Verify Docker-specific integration and ordering |
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

## 4. Complete static source-backed policy

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

| Milestone | Status | Delivered behavior or remaining acceptance |
| --- | --- | --- |
| CrowdSec | Implemented | Authoritative startup synchronization, decision updates/removals, expiry, renewable leases, reload handover, and pinned real-LAPI compatibility |
| iptables/ipset | Implemented | Packet-policy parity, family-by-family commit and compensation, ownership fencing, recovery, and backend migration |
| Coexistence | Custom attachments implemented; Docker pending | Verify Docker-specific attachment ordering and preservation of foreign firewall state |

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

The Docker-specific coexistence milestone remains pending. The known LAPI
query-error behavior is an accepted temporary upstream risk tracked in
[crowdsecurity/crowdsec#4691](https://github.com/crowdsecurity/crowdsec/issues/4691).
It is not fault-tested or worked around with full-list polling; see
[data sources](data-sources.md#supported-lapi-contract).

## 6. Operational and release gates

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

Complete the Docker-specific coexistence milestone in step 5: verify the
[Docker attachment contract](firewall-backends.md#docker-docker-user-attachment),
packet ordering, and preservation of foreign state. Then complete the remaining
operational and release gates in step 6.

Static source-backed policy, both native backends, and CrowdSec synchronization
and decision lifecycle are already implemented. Keep their existing writer,
recovery, packet-path, and compatibility gates passing while adding the remaining
features. Track new work as issues using acceptance criteria from the owning
documents rather than maintaining another implementation or test plan.
