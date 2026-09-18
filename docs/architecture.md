# Architecture

This document owns component boundaries, static revision admission, writer
ownership, and durable recovery. Static policy and CrowdSec integration are
implemented for both native backends; deployment extensions below remain
first-release or future requirements.

The [implementation plan](implementation-plan.md) owns milestone status.
[Operations](operations.md#current-source-build-runtime) describes what can run
from a source build today.

Related contracts have one canonical home:

| Contract | Owner |
| --- | --- |
| YAML, defaults, policy evaluation, and geo classification | [Configuration](configuration.md) |
| RIPEstat/cache and CrowdSec protocol, admission, projection, and leases | [Data sources](data-sources.md) |
| Kernel objects, packet paths, attachment, and backend transactions | [Firewall backends](firewall-backends.md) |
| Operator procedures, service startup protocol, installed layout, and observability | [Operations](operations.md) |
| Verification layers, build, CI, and releases | [Development](development.md) |

## System context and data flow

```mermaid
flowchart LR
    CS[Local config source] --> V[Strict validation]
    V --> R[Selector resolver and RIPEstat cache]
    R --> C[Policy compiler]
    L[CrowdSec LAPI stream] --> D[Dynamic decision store]
    C --> W[Serialized firewall writer]
    D --> W
    W --> B[Selected firewall backend]
    O[Logging and Prometheus metrics] -. observes .-> CS
    O -. observes .-> V
    O -. observes .-> R
    O -. observes .-> C
    O -. observes .-> L
    O -. observes .-> D
    O -. observes .-> W
    O -. observes .-> B
```

`perimeterd` is one foreground process with one serialized firewall writer.
Configuration parsing, network requests, prefix normalization, policy compilation,
and replacement-resource setup happen outside the apply critical section.
Completed static candidates and coalesced CrowdSec decision projections enter
the same writer.

Only the writer invokes backend mutations and native inspection. Backends
perform these operations under that ownership; source adapters never mutate
firewall or active-revision state. Logging and metrics observe the selected
revision but do not make policy decisions.

### Exclusive lifecycle ownership

Version 1 manages the host network namespace only, using the shared host
`/var/lib/perimeterd` state and `/run/perimeterd` runtime directories. Separate
mount views of those directories or multiple instances in that namespace are
unsupported; a different configuration path does not create a separate owner.

Before reading mutable ownership state or invoking a backend, `run` and
`cleanup` acquire the same nonblocking exclusive `flock` on
`/run/perimeterd/owner.lock`. They hold its open file descriptor for their
entire lifetime, including recovery, child commands, and shutdown draining.
A conflict fails immediately with an actionable error. `validate` and
`version` do not need the lock. Direct invocations create the root-owned
runtime directory and lock with modes `0700` and `0600` when absent.

The lock file is never unlinked or replaced: doing so would permit a second
process to lock a different inode. Packaging and systemd preserve the runtime
directory across service stops, as defined in [operations](operations.md).
Children finish before the owner releases the lock. The lifecycle lock does
not replace the shared host xtables lock or coordinate unrelated firewall
managers.

## Conceptual contracts

These are responsibility boundaries, not a prescription for additional Go
interfaces. [Development](development.md#current-repository-layout) maps them
to the current files.

| Boundary | Responsibility | Must not own |
| --- | --- | --- |
| Configuration | Read local YAML, validate and normalize it; admit reload requests through the app | Kernel mutation or remote-source resolution |
| Source resolution | Resolve required selectors into one immutable, validated snapshot and cache manifest | Partial policy publication or backend syntax |
| Policy compilation | Purely compile normalized configuration and snapshots into immutable, backend-neutral rules, sets, and accounting roles | Network, filesystem, or kernel I/O |
| Application engine | Serialize admission, freshness checks, mutation, and transaction decisions | Native packet-filter syntax |
| Durable store | Validate and publish revision/journal records with explicit durability barriers | Choosing which attempted revision should win |
| Native backend | Preflight, apply, retire, and clean up exact owned targets; preserve native accounting objects | Fetching source data or selecting the durable active revision |
| Runtime publication | Publish the selected source snapshot, logger, and listener; retain or discard staged resources according to the selected transaction | Treating an uncertain commit as success |

The current configuration ingress is a local file, reloaded with `SIGHUP`; the
current static provider is RIPEstat. Future configuration or prefix providers
must preserve these boundaries and produce complete candidates rather than
bypass admission or call a backend directly.

Static reconciliation remains separate from the incremental CrowdSec
path: individual decisions must not rebuild global or geo sets. Both paths use
the same writer.

Kernel packet/byte accounting is implemented; periodic collection and Prometheus
export of those counters are planned. The collector must be an observer, not a
policy input: it reads through the writer outside the Prometheus request path,
never mutates rules, and does not change readiness.
[Operations](operations.md#prometheus-metrics) owns the required 15-second cadence,
generation-delta accumulation, monotonic process-lifetime totals, and retention
of the last successful sample on failure.

## Revision lifecycle

### Commands

- `perimeterd validate --config /etc/perimeterd/perimeterd.yaml` performs
  strict schema parsing, defaults, and local semantic validation. It makes no
  network request and performs no firewall mutation.
- `perimeterd run --config /etc/perimeterd/perimeterd.yaml` acquires lifecycle
  ownership and recovers pending transactions before reading or validating the
  current YAML. It then obtains every required fresh or committed cached
  prefix, reconciles, durably commits, and completes required recovery before
  reporting readiness. CrowdSec additionally requires
  authoritative synchronization when enabled. The
  [bounded startup protocol](operations.md#bounded-startup-deadline) applies
  throughout recovery and initialization.
- `perimeterd version` reports build metadata. Population from signed release
  tags belongs to the planned release workflow.
- `perimeterd cleanup` acquires lifecycle ownership and reads persisted active,
  prepared, and retired target metadata plus ownership markers, not the
  possibly invalid current configuration. It removes every recorded owned
  artifact from both supported backends. It is reserved for explicit operator
  action after stopping the service and for final package removal.

### Signals and shutdown

`SIGHUP` stages a complete reload. `SIGTERM` stops watchers, refresh workers,
and the HTTP listener, drains or safely cancels in-flight work, and exits. It
deliberately leaves the last applied static rules active across restart.
CrowdSec retains only the remaining kernel lease on
shutdown: without a running owner, bans may expire before the source decision's
deadline. This is not indefinite fail-closed ban retention. Only explicit
`cleanup` removes all recorded owned artifacts.

### Staged reload

A reload is a candidate revision until every stage succeeds. Static staging,
CrowdSec synchronization, and dynamic-store capture share this lifecycle.

1. Admit a new request epoch, then parse and strictly validate the complete file.
2. Resolve selectors using acceptable cache entries and required network
   fetches, then compile immutable policy state.
3. Bind any replacement metrics listener and fully synchronize a replacement
   CrowdSec client into a separate staged store without retiring active resources.
4. At the writer boundary, reject stale candidates, capture the selected dynamic
   store, and durably prepare the transaction described below.
5. Apply the complete desired firewall state under the selected backend's
   transaction guarantees.
6. Durably commit the active record, then publish the revision and promote its
   staged resources. Retire old clients/listeners and collect retired firewall
   objects only after that commit.

Any failure before mutation closes candidate resources and leaves the active
revision untouched. nftables packet-path switches are atomic; iptables commits
each address family separately and compensates on failure. Successful rollback
restores the previous selection but cannot erase a transient mixed-generation
window. Failed rollback or uncertain persistence enters degraded recovery:
the last committed revision remains recorded, but it is not claimed to describe
actual enforcement. No new candidate or source delta may mutate the firewall
until recovery succeeds. Counter reads and explicit cleanup remain available.
See [firewall backends](firewall-backends.md#failure-and-cleanup-behavior).

Runtime resources follow the durable selection, not merely the last attempted
apply. A committed-but-degraded result publishes the committed revision while
health remains false. An uncertain uncommitted result retains its staged listener
until recovery either selects that transaction or discards it. An unchanged
metrics address reuses the active listener; pending listeners are also released
on shutdown. Startup still withholds readiness until required recovery completes.

Removing a policy or setting its mode to `disabled` is valid. The canonical
[empty desired state](configuration.md#empty-desired-state) predicate includes
global blocks and CrowdSec, not just geo policies. Only that predicate permits
convergence to no owned firewall artifacts; a remaining global block is still
enforced when all geo policies are removed.

## Candidate freshness

The writer serializes admission metadata as well as mutations. Each admitted
reload receives a monotonically increasing request epoch; each successful
configuration commit establishes that epoch as the active configuration
epoch. A newer admitted reload supersedes all older uncommitted reloads, even
if the newer request later fails validation. Admission and the final
freshness check are ordered with commits; a request arriving during a commit
is admitted after that commit, not midway through it.

Every static candidate carries its originating configuration epoch, reload
request epoch when applicable, and a monotonically increasing refresh
sequence within that configuration. Before any mutation, the writer requires:

- a reload to have the newest admitted reload request epoch;
- a refresh to belong to the still-active configuration epoch and to have
  the newest scheduled refresh sequence for that epoch; and
- a candidate's immutable snapshot and compiled model to match those identities.

A failed reload does not stop refreshes for the active configuration. Once a
new configuration commits, no refresh compiled for the old one can apply.
Superseded work is cancelled opportunistically and discarded at the writer
even if cancellation loses a race. Discard closes candidate resources without
changing active state, cache pointers, or failure health.

CrowdSec shares the writer but has its own
[dynamic admission and activation contract](data-sources.md#authoritative-stream-and-decision-identity).
It distinguishes client identity, desired revision, and enforcement operation
sequence so unchanged bans can renew without admitting stale work. That
contract owns store-event ordering, retry/coalescing, staged-client publication,
and lease-timer dispatch; this section defines static candidate admission.

Static refreshes never contain a captured copy of dynamic bans. Activation or
migration selects the client's current store at the writer boundary, with
subsequent events queued behind it. Configuration-driven activation waits for
the same durable commit as the static candidate.

## Durable apply and crash recovery

### Prepared state

All static reconciles, target migrations, and explicit cleanup use a versioned
write-ahead journal under `/var/lib/perimeterd`. Before the first mutation,
write and `fsync` the referenced immutable state, then publish the journal
using the durable record recipe below. No unjournaled target may be created.
The journal records:

- transaction identity, operation, and phase;
- previous and candidate backend, table, attachment and generation identities;
- previous and candidate nftables base-chain hook definitions, including
  priority, type, policy, ownership and rule references, when hooks change;
- exact ownership markers and the owned objects to create, retain, or remove;
- previous and candidate validated configuration and compiled static state;
- immutable prefix snapshot manifest identities; and
- recovery progress, including switched iptables families.

Persist configuration paths and source identity, never credential contents.
CrowdSec decisions are not a durable cache:
surviving kernel entries retain only their remaining leases, and authoritative
LAPI synchronization rebuilds the store before readiness after restart. Static
rollback restores prior dynamic-set references without resetting timeouts.
Live renewal follows the [source lease contract](data-sources.md) and never
extends a decision deadline. If kernel state was lost on reboot, source
initialization must succeed before a complete initial reconcile.

### Durable record publication

Keep the previous generations and snapshot manifest reachable until durable
commit. After every required packet-path switch succeeds, prepare one active
record containing the transaction ID, target/generation, configuration,
compiled state, and snapshot manifest ID.

Publishing this active record, and every journal replacement, uses the same
ordered durable-write recipe:

1. Exclusively create a temporary file in the destination directory, write the
   complete versioned record, and handle short writes and all write errors.
2. `fsync` the temporary file before exposing it under the active/journal name.
   Failure here leaves the previous named record untouched.
3. Atomically rename the synced temporary file over the destination on the
   same filesystem. Never truncate or rewrite the active record in place.
4. `fsync` the parent directory to make the name replacement durable.
5. Only after all barriers succeed publish in-memory success and allow
   retirement of previous generations and referenced snapshot objects.

This active record is the commit point for both firewall recovery and cache
selection. A crash before rename leaves the previous named record; after
rename but before directory sync, restart may observe the previous or candidate
record, but either contains complete synced bytes. Recovery follows that
observed transaction ID, not the last attempted operation or journal phase.
An active record naming the transaction proves commitment on recovery even if
the crash preceded the journal phase update. Orphaned temporary files and
staging files never select a revision.

A rename or directory-sync error with uncertain publication is not a clean
precommit failure. Keep mutations fenced and retain both generations, the
journal, and all referenced objects. Inspect the named record and retry the
required file/directory durability barriers before publishing a live outcome
or retiring anything. If its identity or durability cannot be established,
remain in degraded recovery; never guess success or blindly overwrite it with
the previous record. Startup similarly makes its validated observed record
durable before completing the corresponding recovery and admitting new work.

### Startup recovery

At startup, while holding lifecycle ownership and before admitting new work:

1. Validate the journal, active record, referenced immutable files, and observed
   ownership markers. Missing or inconsistent evidence fails closed to operator
   repair; never infer deletion authority from a name alone.
2. If the active record does not name the prepared transaction, restore the
   previous owned static selection and remove the candidate artifacts. For a
   first installation with no previous selection, remove only recorded candidate
   artifacts. Recovery is idempotent and inspects actual rules because a crash
   may occur before a successful switch is recorded.
3. If the active record names the transaction, retain that selection and finish
   recorded retirement/cleanup. Never roll back a committed transaction merely
   because garbage collection failed.
4. Finish and durably clear the journal only after the corresponding recovery
   and cleanup succeed, then initialize sources and admit current configuration.

The [same-table priority reload](firewall-backends.md#same-table-priority-reload)
uses the same precommit/postcommit decision, restoring previous hook definitions
and references before commit or retaining candidate hooks afterward. The
backend owns the atomic recreation procedure; the journal retains complete
definitions because old same-named hook objects need not survive physically.

An explicit cleanup intent instead resumes deletion of all recorded owned
targets; it never restores a policy being intentionally removed. Remove its
active record only after owned artifacts are gone. Partial cleanup retains
the journal and metadata for the next invocation.

### Recovery failure

On recovery or rollback failure, retain all evidence and old generations,
report enforcement unhealthy, and block normal mutations. A live daemon retries
recovery with bounded backoff; startup fails without `READY=1` if recovery
cannot complete. Operators may repair prerequisites and restart, or stop the
service and invoke explicit cleanup. A previously sent `READY=1` cannot be
revoked; [operations](operations.md) defines the ongoing health signal.

## Backend and target migration

Changing `firewall.backend` or the nftables table name is a journaled migration.
A priority-only change within the same nftables table instead uses atomic
base-chain replacement and does not create overlapping old/new hooks. For
cross-target migration:

1. Durably record both targets and prepare the complete replacement.
2. Apply the candidate on the new target while retaining the previous target.
3. Durably commit the new active record and publish the candidate revision.
4. Remove only recorded owned artifacts from the previous target.

The previous target is never torn down before replacement succeeds. Until
retirement completes, either target can deny a packet: overlap can overblock
relative to the candidate and can double-count operational counters. It is not
an atomic cross-target replacement. A precommit failure restores the previous
target and removes the candidate; failed compensation enters degraded recovery.
A postcommit cleanup failure retains the new committed revision and the pending
retirement journal, reports enforcement unhealthy, and retries cleanup without
admitting further mutations. It never claims that the new revision alone
describes the overlapping enforcement.

## Failure safety

The last-known-good revision remains authoritative when a candidate is unsafe:

- Unknown or invalid configuration never enters the writer.
- An incomplete source snapshot is an error, never an empty selector result.
- A missing parent chain required by the candidate fails preflight. A missing
  obsolete custom parent does not prevent removal of remaining owned artifacts.
- A failed nftables switch is atomic; a partially committed iptables update
  requires compensation and may enter degraded recovery.
- First start with required geo selectors and neither a valid committed cache
  nor a successful RIPEstat response fails before any new policy mutation.
- A rejected reload leaves the prior revision running; apply/recovery failures
  follow the backend-specific guarantees rather than claiming universal atomicity.
- Refresh failure retains cached prefixes and the active rules. Logs and
  metrics expose the error and snapshot age; the normal schedule retries.

The [CrowdSec contract](data-sources.md#crowdsec-stream) additionally
retains failed deltas in the authoritative in-memory store and retries them
idempotently.

## Security and trust boundaries

Configuration and credential files are privileged local input. RIPEstat and
CrowdSec are network trust boundaries: responses are bounded, validated, and
normalized before compilation. Firewall commands and netlink transactions are
output boundaries and accept only typed desired state, never source-provided
firewall syntax. No source adapter can select commands, chain names, or raw
rules.

`run` and `cleanup` require UID 0. The planned installed service adds the
capability restrictions and systemd hardening in [operations](operations.md);
a source build does not install that unit. Metrics are unauthenticated,
loopback-only by default, and contain no secrets or unbounded identifiers.

## Future deployment boundaries

Remote configuration and centrally supplied prefix snapshots may replace their
respective source adapters later; they do not change the compiler, writer, or
backend contracts. Their protocols, authentication, and consistency model are
intentionally undecided.

A future container/Helm delivery may target
[Cilium Host Firewall](https://docs.cilium.io/en/stable/security/host-firewall/)
rather than mutate each node's nftables state directly. A possible backend would
reconcile owned `CiliumClusterwideNetworkPolicy` resources selected by
`spec.nodeSelector`, with host-firewall enforcement already enabled by the
cluster operator.

That is not a committed backend or deployment topology. Before implementation,
define ownership, revision switching, CrowdSec representation, required Cilium
capabilities, chart values, and Kubernetes RBAC. A cluster controller versus
node-local DaemonSet is a later requirements decision. Add `build/package/` and
`charts/perimeterd/` only with working artifacts, not placeholder directories.
