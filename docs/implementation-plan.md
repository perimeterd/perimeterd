# Implementation plan

This is the authoritative status record for the first release. Completed
milestones summarize delivered behavior; pending milestones retain their
acceptance criteria. Detailed contracts live in the linked reference documents.

Both firewall backends, CrowdSec, coexistence, operational behavior, and release
gates remain part of the first-release scope.

## Status at a glance

| Area | Status | Next boundary |
| --- | --- | --- |
| Offline validation and pure compiler | Implemented | Maintain strict schema and policy semantics |
| Static nftables runtime | Implemented | Maintain durable recovery and owned-only mutation |
| RIPEstat resolution, cache, and refresh | Implemented for both backends | Maintain complete-snapshot selection and fallback |
| iptables/ipset runtime and backend migration | Implemented | Maintain per-family recovery and ownership fencing |
| CrowdSec | Planned | Authoritative startup synchronization and decision lifecycle |
| Coexistence | Custom-chain attachments implemented; Docker milestone pending | Verify Docker-specific integration and ordering |
| Operations and delivery | Source-build CLI, logging, readiness, two HTTP gauges, and native accounting implemented | Full metrics exporter, installed service, packaging, architecture coverage, signed releases |

## 1. Foundation and offline configuration validation

**Status:** implemented: the offline validator, version command, example
configuration, and foundation build/verification tooling are available.

Delivered without requiring root access or network access for validation:

- Go module and pinned development tooling.
- `cmd/perimeterd` with command dispatch separate from configuration logic.
- `perimeterd version` with build metadata.
- `perimeterd validate --config …`: strict YAML parsing, defaults,
  normalization, and local semantic validation.
- The full-schema annotated example configuration.
- Local and CI build, formatting, lint, unit/race, and dependency checks.

**Acceptance:** the binary builds; the example validates; invalid configurations
fail with actionable errors; validation neither contacts sources nor touches the
firewall.

Future packages and commands should follow the same rule: create them only with
real behavior. [Planned additions](development.md#planned-additions) are not
empty interfaces, placeholder implementations, or successful no-op commands.

## 2. Pure policy compiler

**Status:** implemented: immutable prefix algebra and selector snapshots feed
the backend-neutral compiler, including the pinned geo classifier, ordered
rules, accounting roles, and boundary/precedence regression coverage.

The backend-neutral compiler consumes normalized selectors and immutable prefix
snapshots. Implemented behavior includes:

- Allow/block precedence and built-in local-range safety.
- Ingress/egress traffic scopes, ports, and policy priority.
- IPv4/IPv6 boundaries and family-empty behavior.
- Disabled policies and the canonical empty desired state.

Source fetching remains outside the compiler; deterministic snapshots provide
compiler inputs in tests.

**Acceptance:** concrete inputs produce the documented policy semantics, with
focused tests for ambiguous boundaries and precedence. Use the existing
[verification matrix](development.md#verification-matrix), not a second test-plan
document.

## 3. First safe kernel-backed vertical slice

**Status:** implemented. This milestone first delivered direct global IP/CIDR
enforcement on nftables with geo modes and CrowdSec disabled. `run` and `cleanup`
share lifetime ownership; immutable revisions and prepared journals precede
kernel mutation, and durable active-state publication controls recovery.

Verified with `make verify`, `make test-race`, and `make test-e2e`. The isolated
native gate covers IPv4/IPv6 TCP/UDP enforcement, allow precedence, parent-path
returns, established flows, rejected reloads, family removal, stable counters,
priority changes, table migration, crash boundaries, recovery fencing, retained
rules on shutdown, and owned-only cleanup. The development host's firewall is
not used for these scenarios.

nftables was implemented first to establish persistence and recovery before
adding source-backed policy or the second backend. The slice delivered:

- Lifecycle ownership and the single serialized writer.
- Durable transaction preparation and active-state publication.
- nftables reconciliation and ownership tracking.
- Startup recovery, reload, shutdown, and explicit cleanup.
- A disposable network-namespace harness with IPv4/IPv6 traffic probes.

**Acceptance:** traffic follows policy; rejected reloads preserve active
enforcement; restart recovers interrupted work; shutdown leaves rules in place;
cleanup removes only owned artifacts.

Kernel state versus durable state remains the high-risk boundary. Continue to
verify interrupted commits and failed recovery in isolated namespaces or a
disposable VM, never against the development host's firewall.

## 4. Complete static source-backed policy

**Status:** implemented for nftables and iptables/ipset. The RIPEstat adapter
resolves countries and ASNs; RIR and built-in/custom groups expand into country
selectors. Immutable content-addressed objects and manifests are bound to
durable revisions, and refresh/reload reuse the serialized writer and recovery.

Local HTTP fixtures cover official wire compatibility, malformed/partial
responses, visibility intervals, request limits, and whole-snapshot fallback.
Commit tests preserve cache/firewall selection across failed and successful
publication. Isolated native packet tests cover all selector kinds, exclusions,
priority, family-empty policies, and retained enforcement after source failure.

The same resolver and cache feed both backends through the pure compiler.

**Acceptance:** country/RIR/group/ASN selectors work end to end; incomplete or
unacceptable source data cannot replace the committed policy; cache publication
remains consistent with revision commit.

Use local fixture servers to make failure scenarios reproducible without depending
on the public service.

## 5. CrowdSec, second backend, and coexistence

These remain separate milestones under one writer and revision lifecycle:

| Milestone | Status | Required proof |
| --- | --- | --- |
| CrowdSec | Planned | Authoritative startup synchronization, decision updates/removals, expiry and renewable kernel leases, reload handover, and pinned real-LAPI compatibility |
| iptables/ipset | Implemented | Equivalent packet-policy behavior, family-by-family commit and compensation, failure recovery, and backend migration |
| Coexistence | Custom attachments implemented; Docker milestone pending | Documented Docker/custom-chain attachments and preservation of foreign firewall state |

**iptables/ipset status:** implemented under the existing serialized writer and
durable revision lifecycle. Native namespace tests exercise both legacy and
nf_tables tool families: direct and source-backed IPv4/IPv6 policy, `/0`
lowering, interface-constrained custom attachments, original-destination ports,
stable processed accounting, and owned-only cleanup. The failure matrix covers
second-family failure, successful and failed compensation, unhealthy enforcement,
crashes between family switches and after commit, and bidirectional migration
with precommit and retirement failures.

CrowdSec and the Docker-specific coexistence milestone remain pending. Keep
both under the same writer and revision lifecycle; dynamic bans must not gain
separate mutation shortcuts.

## 6. Operational and release gates

**Status:** partially implemented. Source builds provide stdout logging,
enforcement health, the committed-prefix timestamp gauge, native packet/byte
accounting, and bounded systemd readiness notifications. The complete Prometheus
exporter, installed systemd/tmpfiles payloads, RPM/DEB lifecycle, remaining
architecture verification, and signed releases are still required.

Package and release workflows must run real checks, not advertise unimplemented
gates.

**Acceptance:** the applicable service, packaging, observability, CI, and release
contracts in [development](development.md) and [operations](operations.md) are
implemented and verified before release.

## Immediate next task

Continue step 5 with CrowdSec authoritative startup synchronization and decision
lifecycle. Keep CrowdSec changes inside the existing serialized writer and durable
revision boundaries.

Static source-backed policy is complete for nftables and iptables/ipset.
CrowdSec, Docker/coexistence, and operational/release integrations retain their
remaining acceptance criteria; do not bypass ownership or transaction boundaries.

Track subsequent milestones as issues with acceptance criteria drawn from the
existing docs. Update the docs when implementation exposes a concrete
contradiction; otherwise, treat them as the baseline and build.
