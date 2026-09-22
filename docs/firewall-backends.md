# Firewall Backends

This document owns packet-path semantics, native objects, ownership fences, and
backend-specific reconciliation. [Configuration](configuration.md) owns fields
and policy evaluation; [architecture](architecture.md) owns admission, durable
publication, recovery, and the cross-target migration algorithm;
[operations](operations.md) owns procedures and observability.

> **Status boundary.** Static source-backed policy, CrowdSec dynamic bans, both
> native backends, target migration, custom attachments, Docker iptables bridge
> coexistence, and native accounting objects are implemented. Aggregated counter
> collection/export remains planned. The Docker support boundary is defined
> [below](#docker-docker-user-attachment).

## Contents

- [Common invariants](#common-invariants)
- [Logical packet path](#logical-packet-path)
- [Packet and byte accounting](#packet-and-byte-accounting)
- [nftables](#nftables)
  - [Same-table priority reload](#same-table-priority-reload)
  - [Static generations and dynamic updates](#static-generations-and-dynamic-updates)
- [iptables and ipset](#iptables-and-ipset)
  - [Per-family commit and rollback](#per-family-commit-and-rollback)
  - [ipset prefix representation](#ipset-prefix-representation)
- [iptables attachment contract](#iptables-attachment-contract)
- [Docker `DOCKER-USER` attachment](#docker-docker-user-attachment)
- [Coexistence](#coexistence)
- [Ownership inspection and reference fences](#ownership-inspection-and-reference-fences)
- [Failure and cleanup behavior](#failure-and-cleanup-behavior)

## Common invariants

Both implemented backends obey these rules:

- Create, change, and remove only perimeterd-owned tables, chains, sets,
  counters, and exact comment-tagged parent jumps. Never flush a global table,
  built-in chain, configured parent chain, or another manager's object.
- Build a complete static generation before selecting it. Generation-suffixed
  static sets are immutable after an active rule references them: populate a new
  generation and switch references instead of changing an active set. A
  validation or staging failure leaves the active generation selected.
- Serialize every reconcile, migration, cleanup, and native counter operation
  through the writer. The [exclusive lifecycle ownership](architecture.md#exclusive-lifecycle-ownership)
  and [durable apply](architecture.md#durable-apply-and-crash-recovery) contracts
  define the lock, journal, active-record commit point, and retained ownership.
- Never retire the previous target before a replacement is applied and durably
  committed. A migration can temporarily leave both targets enforcing and can
  overblock; failed retirement does not roll back a successful committed
  replacement. See [backend and target migration](architecture.md#backend-and-target-migration).
- Keep IPv4 and IPv6 sets distinct. nftables switches both families together
  in one netlink transaction; iptables commits each family independently.

**Dynamic integration.** Stable CrowdSec sets consume the source-owned
[projection and renewable lease contract](data-sources.md#renewable-kernel-leases).
The [ephemeral backend input contract](data-sources.md#ephemeral-backend-inputs)
keeps timed authority out of the serializable `Target`: `Preflight` receives a
projection only for admission, while `Apply(nil)` preserves existing leases and
an explicit empty projection clears them. Static refreshes therefore reuse
dynamic containers without replaying captured bans. Backends do not invent a
ban cap, renewal schedule, or expiry policy; daemon downtime can let leases
expire before the retained source deadline.

The packet path is limited to new flows. `ESTABLISHED,RELATED` returns before
any denial check, and non-`NEW` traffic returns. For a new flow, the effective
order is global allowlist, global blocklist, ingress CrowdSec set, then
geo policies by ascending priority. A non-match and an allowlist match return
or continue to the surrounding firewall; neither emits a global `ACCEPT`.
`drop` maps to DROP. `reject` maps to a TCP reset for TCP and the native
administratively-prohibited ICMP/ICMPv6 response for other protocols. The
configuration document owns the complete precedence and geo classification.

The effective global allowlist contains built-in local ranges. It therefore
protects LAN, loopback, link-local, and IPv6 unique-local traffic from every
perimeterd denial source. Global lists match the remote address (source on
ingress, destination on egress); geo evaluation bypasses remaining
non-global, non-routable space.

**Custom IP lists** compile into the same static policy sets on both
backends. They add no packet-path stage, native fetcher, or source-specific
verdict. “Geo policy” and the existing `geo_policy` accounting role also cover
list-only policies; the classifier, global allow precedence, first matching
traffic scope, `/0` lowering, and new-flow-only behavior remain unchanged. See
[configuration](configuration.md#custom-ip-lists) for the schema.
The [named-provider selectors](configuration.md#named-providers)
use these same static sets and invariants. They add no provider-specific kernel
objects, verdict stage, or source-fetching responsibility to either backend.

## Logical packet path

```text
owned direction entry
  -> ESTABLISHED,RELATED? return
  -> not a NEW flow? return
  -> global allowlist? return/continue
  -> global blocklist? deny
  -> ingress CrowdSec set? deny
  -> remote address not globally routable unicast? return
  -> geo policies in ascending priority: first matching traffic scope decides
  -> no matching scope: return
```

The established-flow return occurs before all denial checks. A return hands
control back to the parent path; another firewall manager can still deny it.

## Packet and byte accounting

Native accounting is installed independently of the metrics listener. nftables
uses named `counter` objects; iptables uses counters attached to ownership-tagged
rules and reads machine-oriented `iptables-save --counters`/
`ip6tables-save --counters`. Counters are owned artifacts and are removed by
migration, explicit cleanup, or reconciliation to the canonical
[empty desired state](configuration.md#empty-desired-state).

A processed counter represents one traversal into a perimeterd-owned direction
path and increments for established, non-new, allowed, non-global, and
unmatched traffic as well as traffic that is denied later. A packet can traverse
multiple valid attachments (for example, both `FORWARD` and `DOCKER-USER`) or
both targets during migration, so processed totals are not globally unique
packets. Perimeterd does not use packet marks or topology-based de-duplication.

A denied counter increments only for the terminal denial decision actually
executed on that traversal. It is classified by `global_blocklist`,
`crowdsec`, or `geo_policy`, and by `drop` or `reject`. Intermediate
match/jump counters and terminal rules that were not executed are not included;
a generated rejection response is not another denied packet.
Backends retain raw native counters for ownership inspection; iptables inventory
reads machine-oriented `iptables-save --counters`/
`ip6tables-save --counters`, while nftables validates counter objects and
ownership. The source build does not aggregate or export the planned
Prometheus counter names and does not run the planned 15-second sampler.
Operators may inspect native counters using the ownership rules below. A future
sampler must preserve generation deltas, monotonic process totals, and
last-good values on failed reads. Counter gaps after a crash, external rule
replacement, or external counter reset are operational telemetry loss, not an
audit result.

## nftables

The nftables backend owns one `inet` table whose configured name defaults to
`perimeterd`. It owns:

- named ingress and egress filter base chains at the configured hook priority
  (default `-10`); names are stable logical anchors, not immutable native
  objects;
- stable entry chains that count processed traversals, apply established/new
  guards, and dispatch to the selected generated path;
- stable named counters for processed traffic and bounded denial reasons;
- generation-suffixed IPv4 and IPv6 sets for global and geo prefixes; and
- stable dynamic IPv4/IPv6 CrowdSec sets with renewable leases.

The priority must be a signed 32-bit value strictly greater than conntrack's
`-200`: the accepted range is `-199` through `2147483647`. Local validation
checks this even when iptables is selected, and every nftables apply validates
the typed value before staging or journal mutation. See
[configuration](configuration.md#nftables-hook-priority).

### Same-table priority reload

Linux stores hook priority in a base-chain definition; it cannot edit the
priority of an existing base chain in place. A priority change therefore
flushes rules only from the verified perimeterd-owned base chains, deletes
those chains, and recreates the same-named chains at the new priority in one
nftables netlink transaction. The recreated chains point to the stable entry
chains. No built-in or foreign chain is flushed.

The durable journal records complete previous and candidate hook definitions,
including family, table, name, type, hook, priority, policy, ownership, and
references. A combined reload switches any changed generated-path references
in the same transaction. A priority-only reload keeps the table, stable entry
chains, counter objects and values, dynamic sets, and selected static
generation in place. If the transaction fails, old hooks and dispatch remain
selected; recovery recreates the recorded prior hooks before commit or retains
candidate hooks after a committed active record. Architecture owns that
precommit/postcommit decision; this section defines the native atomic boundary.

### Static generations and dynamic updates

A static reconcile builds candidate sets and packet-path chains, then switches
the stable dispatch in one atomic netlink transaction. A kernel-rejected batch
leaves the previous selection intact; a lost or ambiguous command result still
requires ownership inspection and recovery. The transaction does not change
static sets referenced by old rules. Ordinary refreshes preserve the table,
base chains, stable entry chains, named counters, and dynamic sets. A configured
priority change is the explicit base-chain replacement exception above.

Do not garbage-collect the old generation in the packet-switch transaction.
Only after durable active-record commit may a later cleanup remove it. Delayed
or failed cleanup retains owned sets/chains for retry and never reverts a
successful enforcement switch.

**Dynamic updates.** CrowdSec projections replace the contents of stable
dynamic sets without rebuilding static generations. Each changed set uses a
flush and grouped element addition in the same atomic netlink transaction:
there is no empty-set enforcement window. Grouping avoids repeated ownership
metadata, and flushing avoids expensive individual interval deletions during
large-list renewal. Timed elements use integer-second native timeouts and
remain bounded after daemon shutdown. This native replacement does not change
the incremental LAPI stream protocol.

Changing the table name is a target migration, not an in-place update: build
and apply the new table, commit it, then retire recorded old ownership. The
old table is never removed first.

## iptables and ipset

The iptables backend integrates with existing parent chains and does not own a
global table. It uses:

- `iptables-restore --wait --noflush` for IPv4 rules;
- `ip6tables-restore --wait --noflush` for IPv6 rules; and
- `ipset restore` for batched set creation and population. It is not the
  packet-switch atomicity boundary.

At startup and before ownership changes it probes `iptables`, `ip6tables`,
`iptables-save`, `ip6tables-save`, `iptables-restore`, `ip6tables-restore`, and
`ipset`. All six iptables-family commands must identify the same `legacy` or
`nf_tables` implementation and matched IPv4/IPv6 tools. A variant change while
ownership exists is rejected. Restore's `--wait` uses the host-wide xtables
lock; `iptables-save` has no wait flag, so reads are serialized with restore
operations through the writer. The source-build process must remain UID 0 for
this interoperability.

It creates stable owned ingress/egress direction chains and generation-
suffixed `hash:net` sets (`family inet` or `inet6`). It first creates and
populates complete staging sets and chains with no active rule referring to
them, then changes only perimeterd-owned chains and exact comment-tagged parent
jumps. It never flushes or rewrites a configured parent chain, and never swaps
the contents of a generation still referenced by old rules.

Static set names are deterministic, exact 31-byte `hash:net` identifiers;
shortening includes backend, family, role, policy identity, and generation and
must be collision-checked against the complete generated model. The full
identity remains in durable metadata.

### Per-family commit and rollback

The IPv4 and IPv6 restores are separate kernel transactions. A successful IPv4
commit followed by an IPv6 failure (or the reverse) can expose a mixed-
generation window that compensation cannot erase. The writer does not publish
the candidate until both families enforce it, and immediately attempts a
compensating restore of every family whose switch was attempted.
A restore command can fail after the kernel has committed its attempted
family switch. Compensation therefore includes every attempted family, not only
those whose successful exit was observed; an ambiguous result is treated as
possibly partially applied and remains fenced until compensation or recovery
establishes ownership.

If compensation succeeds, the previous committed target remains authoritative;
failed candidate ownership stays recorded for cleanup. If compensation fails,
durable state records the phase, actual family generations, and ownership. The
last committed revision remains recorded but is not claimed to describe actual
enforcement: readiness is withheld at startup, live health is degraded, and
ordinary mutations are fenced until recovery or explicit cleanup. There is no
silent fallback to nftables or another iptables variant.

After a successful two-family commit and durable active-record publication,
retirement is cleanup rather than rollback. A cleanup failure retains both
owned generations and retries without undoing the committed enforcement.

### ipset prefix representation

`ipset hash:net` cannot store a zero-length prefix. Lower `/0` at every ipset
insertion boundary while retaining one logical prefix for matching and
allow-before-block precedence:

| Logical prefix | Stored entries |
| --- | --- |
| `0.0.0.0/0` | `0.0.0.0/1` and `128.0.0.0/1` |
| `::/0` | `::/1` and `8000::/1` |

Static global, geo, and dynamic sets use this lowering. Dynamic `/0` is lowered
with the same source lifetime: the pair is one
projected prefix with one absolute deadline and equal remaining lease timeout,
not two fresh full-duration bans. Reconcile both members from the current
projection on partial updates; do not delete a member still required by that
projection. Non-`/0` prefixes retain their shape. nftables represents `/0`
natively with the same logical semantics.

Dynamic ipsets start with at least 65,536 entries and grow geometrically.
`ipset restore` is bounded and non-transactional: a resize populates a
deterministic, generation-owned spare, then issues a kernel `swap` before
destroying the old name. The swap itself is atomic, but an interrupted
restore can leave a partial spare, both names, or a completed swap without
cleanup. Recorded ownership of every possible name is retained; reconciliation
uses the latest projection, never stale decisions. A spare with unrecorded
native references is never modified or removed.

An interrupted static restore may leave an unreferenced, recorded staging set
with only a subset of its expected entries. Recovery may complete that set and
cleanup may remove it. Missing entries in a referenced static set, or
unrecorded entries in either case, still fail ownership validation.

IPv6 overlap projection may produce mapped IPv6 residual prefixes even when
the source inputs are non-mapped. Both backends preserve those residuals as
128-bit IPv6 ranges; they do not grant authority over IPv4 addresses.

## iptables attachment contract

`firewall.iptables.attachments` is the managed integration boundary.
[Configuration](configuration.md#iptables-attachments) owns its schema,
defaults, normalization, and offline validation. At runtime, each normalized
attachment identifies an existing parent chain, a direction, optional
interface constraints, and optional pre-DNAT destination-port matching.

Runtime verifies every parent chain before reconciliation and inserts managed
jumps matching the normalized interface constraints, with an exact perimeterd
ownership comment. Only that comment-tagged jump may be replaced or deleted. A
missing parent is an apply error and leaves the previous state selected.

Omitting the list retains the default host attachments:

```yaml
firewall:
  backend: iptables
  iptables:
    attachments:
      - chain: INPUT
        direction: ingress
      - chain: OUTPUT
        direction: egress
```

An explicit `attachments: []` means no managed jumps; it does not restore the
defaults. With iptables selected, a non-empty desired policy and no managed
attachments is rejected before mutation. The canonical empty desired state may
instead reconcile to no owned artifacts, including counters and allow-only
rules. nftables does not use this list.

Forwarding and custom-chain attachments are opt-in. A forwarding-chain ingress
attachment must constrain `input_interfaces`; an egress attachment must
constrain `output_interfaces`. This prevents a container egress flow from
being interpreted as external ingress merely because both traverse a forwarding
path. These are conservative matching requirements, not topology validation:
perimeterd does not infer traversal uniqueness, inspect forwarding topology, or
insert packet marks for de-duplication.

`original_destination: true` requests conntrack original-destination port
matching for pre-DNAT policy. It has a performance cost and should be enabled
only where published host ports must be distinguished from translated
container ports.

## Docker `DOCKER-USER` attachment

**Verified with Docker Engine 29.8.1:** bridge networking through Docker's
**iptables firewall backend**, using either iptables-nft or iptables-legacy,
with IPv4 and IPv6. This is not Docker's native nftables backend, which does
not provide `DOCKER-USER`. Rootless networking and Swarm are outside this
verified scope.

Select `firewall.backend: iptables` explicitly and use the same tool family as
Docker. Start Docker and create its bridge network before perimeterd; the
`DOCKER-USER` parent must exist in every enabled address family. Perimeterd
inserts its tagged jump before existing rules but never creates or flushes the
Docker-owned chain. Replace the example interfaces with actual external ingress
interfaces; do not include container bridges.

```yaml
firewall:
  backend: iptables
  iptables:
    attachments:
      - chain: INPUT
        direction: ingress
      - chain: OUTPUT
        direction: egress
      - chain: DOCKER-USER
        direction: ingress
        input_interfaces: [eth0, ens3]
        original_destination: true
```

[Docker documents](https://docs.docker.com/engine/network/firewall-iptables/)
that `DOCKER-USER` receives packets after DNAT. With
`original_destination: true`, policy ports match the original published host
port; without it, they match the translated container port. The input-interface
constraint keeps container-originated forwarding out of this ingress attachment.
Allow/no-match returns to Docker and any foreign rules; it does not bypass a
later denial or change Docker's default policies. Overlapping `FORWARD` and
`DOCKER-USER` attachments count separate owned-path traversals; perimeterd does
not de-duplicate them.

A missing candidate parent rejects reconciliation before mutation and retains
the previous active revision and enforcement through its existing parents.
That guarantee cannot preserve a chain another manager has itself deleted.
Keep Docker's chains and perimeterd's tagged jumps intact; there is no Docker
lifecycle watcher or automatic backend selection.

The [isolated Docker gate](development.md#real-docker-coexistence-gate) verifies
remapped host ports, translated-port contrast, container egress, downstream
foreign denial, failed reload preservation, retained enforcement on stop, and
owned cleanup. Snapshots cover Docker/foreign rules and default policies in
all IPv4/IPv6 iptables tables.

## Coexistence

Backend selection is explicit. There is no capability auto-selection, fallback
after apply failure, or conversion between legacy and nf_tables command
families. Operators choose existing parent chains and preserve perimeterd's
exact tagged jumps. nftables operators choose a hook priority in the supported
range and must compose it with other base chains; `-10` is a default, not a
host-topology guarantee.

Allowlist success returns/continues so another manager may still deny. No
package or service action may add jumps, alter default policies, globally flush
netfilter, enable an unconfigured service, or adopt an object from its name
alone. Cleanup is authorized only by durable ownership records.

## Ownership inspection and reference fences

The iptables backend reads machine-oriented save/restore protocols rather than
human `iptables -L` output. It preserves quoted comments as one logical record,
retains escaping state, consumes known option operands (even operands that look
like `-j`), and inspects unknown extension arities conservatively. Every
ownership comment and chain/set reference in the complete rule inventory is
checked; malformed or ambiguous input rejects the operation.

For ipset, a bounded name-only census avoids treating a foreign set's contents
as perimeterd inventory. Contents are queried only for exact recorded or
candidate names. Each exact set's terse XML header is checked: the kernel
reference count must equal references accounted for by the inspected rules.
This detects foreign `list:set` membership and references from the other
xtables implementation. Missing or ambiguous metadata, query failure, count
mismatch, unexpected entries, and exact candidate-name collision all reject
before staging, unhooking, or deletion. A foreign name containing spaces or
newlines cannot forge a complete generated identifier because every generated
identifier occupies all 31 bytes of the kernel name limit.

The nftables backend uses typed JSON inventory. It requires the marked `inet`
table, exact ownership comments and types for chains and counters, complete
expected set elements, and only recorded rules and objects. nft JSON does not
round-trip set comments; set ownership therefore comes from the recorded
owner/generation-qualified name plus exact type, flags, and contents inside the
marked table. Unknown children or foreign references reject the operation
rather than being adopted.

## Failure and cleanup behavior

Architecture owns the complete journal and recovery state machine. The native
boundaries are:

- nftables switches dispatch atomically in one netlink transaction; rejected
  batches leave old references selected, but ambiguous results require recovery;
- iptables stages both families before switching either, then commits each
  family separately and compensates on failure; the mixed window is real and
  failed compensation degrades and fences enforcement; and
- migrations apply the replacement first, may overlap and overblock, commit the
  replacement, then retire only recorded old ownership. Retirement failure
  retains both targets and the committed replacement.

Previous static sets remain immutable while referenced. An attempted switch can
still change enforcement before a failure is reported, as described above.
The canonical empty state removes all owned artifacts, including counters and
allow-only rules; enabled CrowdSec prevents it even with zero current decisions.

Normal shutdown leaves rules active. The lifecycle lock, journal recovery, and
operator cleanup sequence belong to [architecture](architecture.md) and
[operations](operations.md#reload-recover-and-cleanup). Native cleanup still
reads durable active/prepared/retired target metadata, removes tagged parent
jumps before child objects, and never derives scope from current YAML. An
already-absent custom parent does not block removal of remaining recorded
ownership, but a parent must exist for an attachment in the desired policy.
