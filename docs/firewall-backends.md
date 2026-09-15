# Firewall Backends

This document owns packet-path semantics, firewall object ownership, and
backend reconciliation. [Configuration](configuration.md) owns fields and
policy selection; [architecture](architecture.md) owns the writer and revision
lifecycle.

> **Version-1 backend contract.** This specification includes backend and
> coexistence integrations beyond the current runtime. See the
> [implementation plan](implementation-plan.md) for status and
> [current operations](operations.md#current-source-build-runtime) for supported use.

## Common invariants

Both backends obey the same safety contract:

- Create, change, and remove only perimeterd-owned tables, chains, and sets,
  plus parent-chain jumps carrying an exact perimeterd ownership comment.
- Never flush a global table, built-in chain, configured parent chain, or
  another manager's object.
- Build a complete staged static generation before switching traffic to it.
  Generation-suffixed static sets are immutable after creation: never change
  or swap the contents of a set referenced by active rules; switch references
  to a newly populated generation instead. Validation or staging failure leaves
  the active generation selected.
- Serialize static reconciles, CrowdSec deltas, counter reads, migrations, and
  cleanup through the writer. [Architecture](architecture.md#exclusive-lifecycle-ownership)
  owns lifecycle locking; its [durable transaction contract](architecture.md#durable-apply-and-crash-recovery)
  governs journal preparation, active-record commitment, and prior-generation
  retention for every static reconcile, migration, and cleanup.
- Credential/endpoint replacement or CrowdSec disable prepares separate
  dynamic-set references with the candidate, retaining old references and live
  lease state until durable commit. Ordinary static/geo refreshes reuse the
  active dynamic sets, so precommit rollback never depends on restoring bans
  from a stable set overwritten by a replacement client. See
  [staged reload](architecture.md#staged-reload).
- Every dynamic entry, including both members of an ipset `/0` pair, implements
  the source-owned [timed projection and renewable lease contract](data-sources.md#renewable-kernel-leases).
  Backends lower that contract into native entries; they do not define a second
  cap, renewal schedule, or expiry policy. Daemon downtime can let leases expire
  early; the retained source deadline is never extended.
- Keep IPv4 and IPv6 address sets separate.
- Apply only to conntrack `NEW` or equivalent new-flow traffic. Return from
  `ESTABLISHED,RELATED` before any denial rule.
- The nftables hook priority uses the supported range `-199` through
  `2147483647`, a signed 32-bit integer strictly after conntrack priority
  `-200`. Local validation enforces this even when nftables is not selected;
  every apply also checks the typed value before staging or journal mutation.
  Values at or below `-200` cannot bypass the OUTPUT NEW-flow guard. See
  [configuration](configuration.md#nftables-hook-priority).
- Evaluate new traffic in this order: global allowlist, global blocklist,
  ingress CrowdSec set, then geo policies by ascending priority.
- A non-match and an allowlist success return/continue; neither emits a global
  `ACCEPT` verdict.
- Map `deny_action: drop` directly to DROP. Map `reject` to a TCP reset for
  TCP and the backend-native administratively prohibited ICMP or ICMPv6
  response for UDP and other protocols.

The effective global allowlist includes built-in local ranges and therefore
prevents CrowdSec and every other perimeterd denial source from blocking LAN
traffic. Global lists match any valid remote address. Geo policy then bypasses
remaining non-global space. Ingress uses source; egress uses destination. See
[configuration](configuration.md) for the exact policy algorithm.

## Logical packet path

```text
owned direction entry
  -> ESTABLISHED,RELATED? return
  -> not a NEW flow? return
  -> global allowlist match? return
  -> global blocklist match? deny
  -> ingress and CrowdSec set match? deny
  -> remote address not globally routable unicast? return
  -> policy priority 10 traffic scope matches? decide and return/deny
  -> policy priority 20 traffic scope matches? decide and return/deny
  -> ...
  -> no matching scope: return
```

The established return occurs before all denial checks. Global allow then
precedes global block and CrowdSec. This ordering preserves LAN access and
established-flow symmetry for host-originated and accepted inbound traffic.

## Packet and byte accounting

Both backends expose kernel accounting: nftables
[`counter` objects](https://wiki.nftables.org/wiki-nftables/index.php/Counters)
record packets and bytes, while
[`iptables-save --counters`](https://www.man7.org/linux/man-pages/man8/iptables-save.8.html)
exports the counters attached to iptables rules.

The backend-neutral model assigns bounded accounting roles rather than
operator-derived metric labels. Accounting is per traversal of a
perimeterd-owned direction path: each traversal increments that path's
processed packet and byte counters. A packet can traverse more than one valid
attachment (for example, both `FORWARD` and `DOCKER-USER`) or both generations
during target migration, so these counters are not globally unique packets and
may count the same packet more than once. Perimeterd does not use packet marks
or topology-based de-duplication.
Only the terminal perimeterd denial decision actually executed on a traversal
increments its denied packet and byte counters, classified by
`global_blocklist`, `crowdsec`, or `geo_policy` and by DROP or REJECT.
Intermediate match and jump counters, and terminal rules that were not
executed, are never aggregated. A generated rejection response is not another
denied packet.

Each backend returns a typed raw counter snapshot through the writer.
[Operations](operations.md#prometheus-metrics) owns sampling, generation-delta
accumulation, monotonic totals, and failed-periodic-read behavior. When a
reconcile replaces raw counters, it attempts a final read after dispatch
switches away from the retired generation and before removal, then establishes
the replacement baseline. A failed final read records an accounting gap but
does not roll back successful enforcement.

Kernel counters are installed independently of the metrics listener so
enabling or disabling HTTP exposition never changes the packet path. They are
owned artifacts and are removed by target migration, explicit cleanup, or
reconciliation to the canonical empty desired state.
Process or host crashes and external counter or rule changes may lose
accounting; this is operational telemetry rather than an audit ledger.

## nftables

The nftables backend owns one `inet` table whose configured name defaults to
`perimeterd`. Within it:

- named input and output filter base chains hook at the configured priority
  (default `-10`). Their names are stable logical anchors, not immutable
  nftables objects: a priority change replaces all applicable owned base chains
  atomically as described below;
- stable dynamic IPv4 and IPv6 CrowdSec sets carry renewable element leases
  governed by [renewable kernel leases](data-sources.md#renewable-kernel-leases);
- stable named counter objects hold processed and bounded-reason denial
  accounting;
- stable entry chains increment the appropriate processed counter, apply
  established/new-flow guards, and transfer to the active generated path;
- the generated path evaluates global allow/block sets, the stable CrowdSec
  sets, and ordered geo policy, referencing the appropriate named counter
  immediately before each terminal denial; and
- generation-suffixed, interval-capable IPv4 and IPv6 sets hold global and geo
  prefixes.

### Same-table priority reload

A `firewall.nftables.priority` change uses a same-table, journaled base-chain
replacement. Other configuration changes in the same reload remain part of
that one candidate transaction.

**Kernel constraint:** hook priority belongs to the base-chain definition;
Linux cannot change an existing base chain's priority in place.

Before mutation, the durable apply state records the previous and candidate
hook definitions for every owned applicable base chain (family, table, name,
type, hook, priority, policy, and exact target references), together with the
previous and candidate generated state, using the protocol in
[architecture](architecture.md#durable-apply-and-crash-recovery). In one
nftables netlink transaction it flushes rules only from those owned base
chains, deletes them, and recreates the same-named chains at the new priority
with their target references to the stable entry chains. Flushing the owned
rules first permits deletion of nonempty chains; no built-in or unrelated
chain is flushed. Any generated-path or replacement-client reference changes
in the same reload are switched in that transaction too. Old and new base
chains cannot coexist under the same names, so the durable state retains the
previous definitions and complete rule references. Precommit recovery likewise
flushes/deletes only verified candidate-owned base chains and recreates prior
hooks and prior generated-path references in one transaction, never as
separately visible removal and creation.

For a priority-only reload, only the base-chain hook objects are replaced. The
table, stable entry chains and their rule counters, owned counter objects and
values, dynamic sets and their live leases, and selected static generation
remain in place. Combined changes preserve objects not changed by the other
candidate fields and retain all previous referenced generations until commit.
The transaction is atomic: failure leaves the old hooks and dispatch selected.
After successful enforcement, the active record commits the candidate priority
and transaction ID. A crash before that commit restores the previous hooks
from the durable state; a post-commit crash resumes retirement from committed
intent.

### Static generations and dynamic updates

A static reconcile constructs all new generation sets and packet-path chains,
then switches the stable transfer in one netlink transaction. This is the
nftables atomicity boundary: if any operation in that transaction fails, the
visible dispatch and prior generation remain unchanged. The transaction never
changes the contents of a set referenced by the old rules. Ordinary static/geo
refreshes do not recreate the table, base chains, stable entry chains, named
counters, or dynamic sets, preserving totals and live leases. A configured
priority change is the explicit base-chain replacement exception described
above; a priority-only candidate preserves other objects. A staged client
replacement selects its separately prepared dynamic sets in the same
packet-switch transaction; old dynamic references survive until durable
commit.

Do not garbage-collect the old generation in the packet-switch transaction.
Only after durable active-record commit may a later cleanup transaction remove
it. The [recovery contract](architecture.md#startup-recovery) selects restoration
before commit or retirement afterward, including previous hook definitions
for priority reloads. Delayed or failed GC may leave extra owned sets and
chains; retain their ownership for retry or explicit cleanup, never revert a
successful packet switch merely because retirement failed.

CrowdSec additions and deletions use smaller netlink transactions against the
stable dynamic sets. Every changed element follows the renewable lease and
absolute-deadline rules in [data sources](data-sources.md#renewable-kernel-leases).
A failed batch leaves that batch unapplied and is retried
idempotently by the decision store. An nftables failure is reported; it never
silently falls back to iptables.

A table-name change uses [target migration](architecture.md#backend-and-target-migration),
not a same-table update: build the complete new table, commit the replacement,
then retire recorded old ownership. Until retirement, both hook paths may
enforce and temporarily overblock. A failed replacement leaves the old target
selected; it is never removed first.

## iptables and ipset

The iptables backend integrates with existing parent chains instead of owning a
global table. It uses:

- `iptables-restore --wait --noflush` for IPv4 rules;
- `ip6tables-restore --wait --noflush` for IPv6 rules; and
- `ipset restore` for address-set transactions.

It creates stable owned ingress/egress direction chains and stable dynamic
CrowdSec sets. Static global and geo sets are generation-suffixed `hash:net`
sets using `family inet` or `family inet6`. A reconcile first creates and
populates complete staging sets and chains, with no active rule referencing
them, then commits only perimeterd-owned chain and comment-tagged jump
references. It never swaps or rewrites the contents of a generation still
referenced by the old rules. A staging failure therefore leaves active rules
and sets selected.

The IPv4 and IPv6 commits use separate `iptables-restore --wait --noflush` and
`ip6tables-restore --wait --noflush` operations. Each family commit is atomic
only within that family; the two commits are not one transaction. Only after
both families enforce the candidate does the durable active-record transaction
publish it and retire the prior generation, following
[architecture](architecture.md#durable-apply-and-crash-recovery). Prior sets
and chains remain owned until that commit and are removed only by later
cleanup.

### Per-family commit and rollback

If the IPv4 commit succeeds but the IPv6 commit fails (or the reverse), the
successful family temporarily enforces the candidate while the other family
still enforces the previous generation. This mixed-generation window is
unavoidable even when compensation succeeds. The writer does not publish the
candidate as active; it immediately attempts a compensating restore of the
successful family to its previous recorded generation.

When compensation succeeds, the previous generation remains the active
committed state. The failed candidate and any partially staged ownership stay
recorded until cleanup completes, and no candidate content is copied into the
previous generation.

When compensation itself fails, the durable apply state records the phase,
per-family actual generations, and ownership. The last committed revision
remains recorded, but enforcement is unhealthy rather than claimed to match
it. Startup withholds readiness; a live daemon exposes the ongoing health
signal defined in [operations](operations.md). Further mutations are blocked
except recovery or explicit cleanup. Recovery retries the precommit
restoration; it does not silently fall back to another backend.

If staging or either family commit fails before a family switch, active
references remain unchanged. A successful two-family commit retains the
retired generation through the active-record transaction; a later cleanup
failure retains both generations and retries cleanup without rolling back
enforcement. A crash after that transaction but before cleanup resumes cleanup
from the committed ownership record.

### ipset prefix representation

Lower a valid `/0` at every ipset insertion boundary, including static global
and geo sets and stable dynamic CrowdSec sets:

| Logical prefix | Stored `hash:net` entries |
| --- | --- |
| `0.0.0.0/0` | `0.0.0.0/1` and `128.0.0.0/1` |
| `::/0` | `::/1` and `8000::/1` |

**Representation constraint:** [`ipset` `hash:net`](https://ipset.netfilter.org/ipset.man.html)
cannot store a zero-length prefix; the pair represents the same address union.

The pair is one logical projected prefix for matching and allow-before-block
precedence; no policy semantics change. Dynamic inputs are the disjoint timed
projection `P(D)` defined in
[data sources](data-sources.md#overlap-expiry-and-backend-projection), not
individual decision events. The `/0` pair is derived from one projected
absolute deadline; both lowered entries receive the same renewable kernel lease
under [renewable kernel leases](data-sources.md#renewable-kernel-leases), not a
fresh full ban-duration timeout. On any partial update, reconcile both lowered
entries from the current projection and their remaining lease timeouts; do not
blindly delete a member still required by that projection. Non-`/0` projected
prefixes are stored unchanged in shape, and dynamic ones use the same source
lease semantics. nftables can represent `/0` natively with the same logical
semantics.

ipset names have a 31-character limit. Names therefore use deterministic short
backend, family, role, policy-identity, and generation components; the full
identity remains in persisted metadata. Hash shortening must be collision
checked within a generated model.

Inspection and counter sampling use machine-oriented `iptables-save
--counters`, `ip6tables-save --counters`, and ipset protocols. Exact
perimeterd ownership and accounting-role comments identify the stable entry
jumps and terminal denial rules whose counters may be aggregated; perimeterd
never sums intermediate rule counters or parses human-formatted `iptables -L`
output. `iptables-save` has no lock-wait option, so perimeterd serializes reads
with its own `iptables-restore --wait` operations through the writer. Restore's
`--wait` participates in the global xtables lock, which is why the systemd
service remains UID 0; see [operations](operations.md).
`ipset` existence checks use a bounded name-only census and exact comparisons with
the generated 31-byte identifiers. Set contents are then queried individually by
recorded or candidate name. Global `ipset save` is not used as a foreign-object
inventory: names may contain unquoted spaces or newlines. A newline-containing
foreign name cannot forge a complete generated identifier because the kernel's
31-byte name limit leaves no room for additional characters.
Each exact set also has a terse XML header queried with `ipset list NAME -output
xml -terse`. Its kernel reference count must equal the references accounted for
by recorded rules in the inspected inventory. This detects foreign `list:set`
membership and references from the other xtables implementation without parsing
unrelated set contents. Missing or ambiguous reference metadata, query failures,
and count mismatches reject the operation before staging, unhooking, or deletion.
Quoted comments may span physical lines in native save output. Inspection
preserves them as single logical records rather than interpreting their contents
as additional rules or table directives.
Each protocol retains its own quoting rules: iptables uses backslash escapes,
whereas ipset emits backslashes and apostrophes literally inside double-quoted
comments. An ipset comment's trailing backslash must not hide the closing quote
or consume subsequent set definitions.
Rule inspection retains whether tokens were quoted or escaped and consumes known
option operands as data, even when they spell flags such as `-j`. It checks all
ownership comments and chain/set references rather than taking the first apparent
option. Unknown extension arities are inspected conservatively so ambiguous
operands cannot hide a foreign reference.
Full iptables rule inventories are still inspected, so foreign references into
recorded chains or sets remain errors. Exact candidate-name collisions are also
rejected rather than adopted.

## iptables attachment contract

`firewall.iptables.attachments` defines the managed integration boundary. Each
configured entry contains:

| Field | Meaning |
| --- | --- |
| `chain` | Existing parent chain; perimeterd never creates or flushes it |
| `direction` | `ingress` or `egress` remote-address interpretation |
| `input_interfaces` | Optional allowed input-interface matches |
| `output_interfaces` | Optional allowed output-interface matches |
| `original_destination` | Optional pre-DNAT destination-port matching |

The daemon verifies every parent chain before reconciliation. It inserts
exactly one jump per normalized attachment, with its interface match and an
exact ownership comment. Only that comment-tagged jump may later be replaced
or deleted. A missing chain is a reconcile error and preserves the prior
state.

An explicitly empty attachment list is valid local configuration. When iptables
is selected and the desired policy is not the
[canonical empty state](configuration.md#empty-desired-state), startup or reload
must reject a candidate with no managed attachments before firewall mutation.
Do not report active enforcement or assume administrator-managed jumps exist.
A genuinely empty desired state may reconcile to no owned artifacts without
attachments; nftables does not use this list.

The default host attachments are:

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

Forwarded and container traffic is opt-in through additional explicit
attachments. Every forwarding-chain attachment must constrain an input or
output interface appropriate to its direction. This prevents a new container
egress flow traversing the forwarding path from being interpreted as external
ingress.
The [local attachment checks](configuration.md#iptables-attachments) apply this
conservative constraint to every non-host parent, including custom chains.

These are attachment matching requirements, not topology validation. Perimeterd
verifies configured chains and ownership but does not inspect the host's
forwarding topology, infer traversal uniqueness, or reject overlapping paths.
It inserts and reads no packet marks for de-duplication.

## Docker `DOCKER-USER` attachment

A safe published-service ingress attachment names the external host
interfaces:

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

Docker documents that packets reach
[`DOCKER-USER` after DNAT](https://docs.docker.com/engine/network/firewall-iptables/).
Without `original_destination`, destination port policy sees the translated
container port. With it, generated rules use conntrack original-destination
matching so policy ports mean published host ports. That conntrack lookup has
a performance cost and should be enabled only when required.

The input-interface constraint ensures container-originated forwarding does
not enter an ingress policy merely because it shares `DOCKER-USER`. A
`FORWARD` attachment and a `DOCKER-USER` attachment may both be configured for
the same direction and matching interfaces; that overlap is valid and
intentionally covers both owned-path traversals. Depending on topology,
operators may instead or additionally use a constrained explicit egress
attachment; no unconstrained forwarding attachment is valid.

If `DOCKER-USER` is configured but absent, reconciliation fails and retains the
last-known-good state. Start Docker before perimeterd or omit this attachment.
Perimeterd never creates a Docker-owned chain.

## Coexistence

Backend selection is explicit. There is no capability auto-detection, backend
auto-selection, or fallback after an apply error.

For iptables, operators choose the actual parent chains managed by firewalld,
ufw, Docker, or custom policy and must preserve perimeterd's tagged jumps. For
nftables, operators choose a hook priority within the supported signed 32-bit
range that composes with other base chains. The default `-10` is a starting
contract, not a guarantee about a host's other rules. Changing it uses the
same-table priority reload described in [same-table priority
reload](firewall-backends.md#same-table-priority-reload).
Allowlist success always returns/continues, allowing later firewall policy to
deny. Package scripts do not add jumps, change default policies, flush rules,
or enable the service. Backend and target changes follow the canonical
[migration contract](architecture.md#backend-and-target-migration). Its overlap
window may overblock and count a packet on both paths; denied counters still
require an executed terminal decision. Cleanup uses persisted ownership and
removes only identified perimeterd artifacts.

## Failure and cleanup behavior

A reconcile validates parent objects and renders a complete typed model before
mutation. Durable precommit preparation and the active-record commit are the
[architecture](architecture.md#durable-apply-and-crash-recovery) contract. A
validation or staging failure leaves active references unchanged. nftables
preserves that result with its single-transaction atomic boundary;
iptables/ipset may first enter the explicit per-family mixed window described
above and then compensate. The active committed record changes only after
complete enforcement succeeds. The canonical
[empty desired state](configuration.md#empty-desired-state) removes all owned
artifacts, including counters and allow-only rules. CrowdSec-enabled state
does not meet that predicate, even with zero current bans.

Target migration follows the [migration contract](architecture.md#backend-and-target-migration).
A failed replacement apply preserves the old target and compensates for any
partial candidate attachment; failed compensation degrades enforcement. If
old-target cleanup fails after the active-record commit, both recorded targets
may still enforce, enforcement is unhealthy, and retirement is retried without
admitting new mutations. The replacement is not rolled back merely because
retirement is delayed.

If precommit recovery or compensating rollback cannot restore the previous
owned enforcement, including the previous hook definitions for a priority
reload, the durable state retains actual ownership and generations. Startup
withholds readiness and a live daemon exposes unhealthy enforcement; further
mutations are blocked except recovery or explicit cleanup. A committed intent
instead finishes retirement and never causes recovery to select a staging
generation.

Ordinary shutdown leaves rules active. Lifecycle ownership is defined in
[architecture](architecture.md#exclusive-lifecycle-ownership): `run` and
`perimeterd cleanup` take and hold the same exclusive, nonblocking namespace
lock at `/run/perimeterd/owner.lock` for their entire lifetimes. If the lock
is held, cleanup fails without touching firewall state; the lock is never
unlinked or recreated while held. Cleanup reads durable journal and ownership
records for active, prepared, and retired generations on current and prior
migration targets. It removes tagged parent jumps before owned child objects,
attempts cleanup for both supported backends and prior targets, and finishes
committed retirement. It never derives cleanup scope from current YAML or
broadens ownership because an expected object is missing.
Already-absent custom parents do not prevent removal of remaining recorded
ownership, including retirement during migration or a transition to empty policy.
Parent existence is still required for attachments in the desired policy.
