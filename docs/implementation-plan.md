# Implementation plan

Start with a small working foundation, then build verified vertical slices. The
existing architecture and verification matrix are the baseline; another general
documentation pass is not a prerequisite.

This sequence does not reduce the first-release contract. Both firewall backends,
CrowdSec, coexistence, operational behavior, and release gates remain required.

## 1. Foundation and offline configuration validation

**Status:** implemented: the offline validator, version command, example
configuration, and foundation build/verification tooling are available.

Make the first implementation PR useful without root access or network access:

- Initialize the Go module and pinned development tooling.
- Add `cmd/perimeterd`, separating command dispatch from configuration logic.
- Implement `perimeterd version` with build metadata.
- Implement `perimeterd validate --config …`: strict YAML parsing, documented
  defaults, normalization, and all local semantic validation.
- Add the documented example configuration.
- Wire build, formatting, lint, unit/race tests, and dependency checks into local
  commands and CI.

**Acceptance:** the binary builds; the example validates; invalid configurations
fail with actionable errors; validation neither contacts sources nor touches the
firewall.

Create packages only when they have real behavior. Do not pre-create
[planned additions](development.md#planned-additions) with empty
interfaces, placeholder implementations, or successful no-op commands. Do not
expose `run` or `cleanup` until they work.

## 2. Pure policy compiler

**Status:** implemented: immutable prefix algebra and selector snapshots feed
the backend-neutral compiler, including the pinned geo classifier, ordered
rules, accounting roles, and boundary/precedence regression coverage.

Implement normalized selectors and prefix operations, followed by the
backend-neutral policy model and compiler. Cover:

- Allow/block precedence and built-in local-range safety.
- Ingress/egress traffic scopes, ports, and policy priority.
- IPv4/IPv6 boundaries and family-empty behavior.
- Disabled policies and the canonical empty desired state.

Use deterministic prefix snapshots as compiler inputs. Source fetching stays
outside the compiler.

**Acceptance:** concrete inputs produce the documented policy semantics, with
focused tests for ambiguous boundaries and precedence. Use the existing
[verification matrix](development.md#verification-matrix), not a second test-plan
document.

## 3. First safe kernel-backed vertical slice

**Status:** implemented for direct global IP/CIDR rules with nftables, disabled
geo policy modes, and CrowdSec disabled. `run` and `cleanup` share lifetime
ownership; immutable revisions and prepared journals precede kernel mutation,
and durable active-state publication controls recovery.

Verified with `make verify`, `make test-race`, and `make test-e2e`. The isolated
native gate covers IPv4/IPv6 TCP/UDP enforcement, allow precedence, parent-path
returns, established flows, rejected reloads, family removal, stable counters,
priority changes, table migration, crash boundaries, recovery fencing, retained
rules on shutdown, and owned-only cleanup. The development host's firewall is
not used for these scenarios.

Start with nftables, bringing persistence and recovery into this slice rather
than adding them afterward. This is implementation order, not a reduction of the
first-release commitment to both backends.

An initial slice can enforce direct global IP/CIDR rules with geo policy and
CrowdSec disabled. That exercises real configuration without external data.

Implemented together:

- Lifecycle ownership and the single serialized writer.
- Durable transaction preparation and active-state publication.
- nftables reconciliation and ownership tracking.
- Startup recovery, reload, shutdown, and explicit cleanup.
- A disposable network-namespace harness with IPv4/IPv6 traffic probes.

**Acceptance:** traffic follows policy; rejected reloads preserve active
enforcement; restart recovers interrupted work; shutdown leaves rules in place;
cleanup removes only owned artifacts.

The high-risk boundary is kernel state versus durable state after failure. Prove
that early, including interrupted commits and failed recovery, not just successful
rule installation. Run this in isolated namespaces or a disposable VM, never
against the development host's firewall.

## 4. Complete static source-backed policy

**Status:** implemented for nftables: the RIPEstat adapter resolves countries
and ASNs, with RIR and built-in/custom group expansion into country selectors.
Immutable content-addressed objects and manifests are bound to durable revisions;
scheduled refresh and reload reuse the existing serialized writer and recovery.

Local HTTP fixtures cover official wire compatibility, malformed/partial
responses, visibility intervals, request limits, and whole-snapshot fallback.
Commit tests preserve cache/firewall selection across failed and successful
publication. Isolated native packet tests cover all selector kinds, exclusions,
priority, family-empty policies, and retained enforcement after source failure.

Add the RIPEstat adapter and cache contract, then connect real prefix snapshots to
the compiler and writer.

**Acceptance:** country/RIR/group/ASN selectors work end to end; incomplete or
unacceptable source data cannot replace the committed policy; cache publication
remains consistent with revision commit.

Use local fixture servers to make failure scenarios reproducible without depending
on the public service.

## 5. CrowdSec, second backend, and coexistence

Implement these as separate milestones:

| Milestone | Required proof |
| --- | --- |
| CrowdSec | Authoritative startup synchronization, decision updates/removals, expiry and renewable kernel leases, reload handover, and pinned real-LAPI compatibility |
| iptables/ipset | Equivalent packet-policy behavior, family-by-family commit and compensation, failure recovery, and backend migration |
| Coexistence | Documented Docker/custom-chain attachments and preservation of foreign firewall state |

Keep these paths under the same writer and revision lifecycle. Do not introduce
separate mutation shortcuts for dynamic bans.

## 6. Operational and release gates

Add basic logging and health reporting as the runtime appears; do not postpone
visibility into failures. Complete counters, systemd hardening/readiness, RPM/DEB
lifecycle behavior, architecture coverage, and signed releases once the daemon's
contracts are exercised.

Package and release workflows must run real checks, not advertise unimplemented
gates.

**Acceptance:** the applicable service, packaging, observability, CI, and release
contracts in [development](development.md) and [operations](operations.md) are
implemented and verified before release.

## Immediate next task

Implement step 5 as separate milestones, starting with CrowdSec authoritative
startup synchronization and decision lifecycle. Keep CrowdSec changes inside
the existing serialized writer and durable revision boundaries.

Static source-backed nftables policy is complete. CrowdSec, iptables/ipset,
coexistence, and operational/release integrations retain their remaining
acceptance criteria; do not bypass ownership or transaction boundaries.

Track subsequent milestones as issues with acceptance criteria drawn from the
existing docs. Update the docs when implementation exposes a concrete
contradiction; otherwise, treat them as the baseline and build.
