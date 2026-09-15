# Data Sources

> **Version-1 source contract.** The RIPEstat adapter, immutable cache, and static
> policy refresh/recovery integration are implemented for nftables. CrowdSec
> dynamic-ban integration remains planned. The
> [implementation plan](implementation-plan.md) tracks delivery.

Version 1 uses RIPEstat for static country/ASN prefixes and CrowdSec LAPI for
dynamic ingress bans. [Configuration](configuration.md) defines selectors and
defaults; [architecture](architecture.md) defines revision commit behavior and
process lifecycle. Sources produce typed data and never emit firewall syntax.
This document owns source wire compatibility, source-side validation, cache
coupling, authoritative dynamic state, timed projection, and lease behavior.

## RIPEstat scope and accuracy

### Normative provider contract

RIPEstat is the sole version 1 geo/ASN provider. It is usable without an
account, API key, downloaded commercial database, or central perimeterd
service. Requests use only the official HTTPS JSON API and always include
`sourceapp=perimeterd`:

- Countries use RIPEstat
  [`country-resource-list`](https://stat.ripe.net/docs/data-api/api-endpoints/country-resource-list)
  with the normalized ISO-3166-1 alpha-2 code as `resource` and
  `v4_format=prefix`.
- ASNs use RIPEstat
  [`announced-prefixes`](https://stat.ripe.net/docs/data-api/api-endpoints/announced-prefixes)
  with the numeric ASN as `resource`.

### Accuracy and interpretation

Country results derive from the RIR statistics files and describe address
allocation or registration country. ASN results describe observed routing
announcements. Neither identifies a device's physical location and neither
promises MaxMind-style geolocation accuracy. VPNs, hosting networks, mobile
carriers, transfers, and routing changes can make country policy differ from a
user's actual location.

For an ASN response, each prefix has a visibility timeline. Perimeterd retains
the prefix only when that timeline includes the response's `query_endtime`. A
prefix seen earlier in the query window but no longer announced at its end is
excluded.

### Evaluated alternative: sapics/ip-location-db

The [`sapics/ip-location-db`](https://github.com/sapics/ip-location-db)
project is not the version 1 source. Its daily `server-country` database is a
credible candidate for a future physical-endpoint-location provider:

- routing and geofeed inputs can locate deployed infrastructure more accurately
  than RIR allocation country;
- `server-country` matches the address visible to a firewall, whereas
  `user-country` attempts to infer a user behind VPN or proxy infrastructure;
- the combined `server-country-cidr.csv` asset is a directly streamable
  `prefix,country_code` representation for both address families.

RIPEstat remains the version 1 choice because it is an official primary API,
fetches only referenced selectors, supplies explicit query metadata, and
generally produces coarser sets better suited to both nftables and
iptables/ipset. The SAPICS database is a complete global snapshot with much
finer country boundaries, so a selected country or region can require
materially more firewall prefixes. Its data-generation pipeline, mutable
`latest` release, provider-hosted checksums, geofeeds without explicit
licenses, and emitted legacy or non-ISO codes such as `AN`, `FX`, and `XK`
also require an explicit trust and normalization contract.

If a SAPICS provider is added later, it must consume
`server-country-cidr.csv`, not MMDB or the start/end range CSV. CIDR CSV maps
directly to `netip.Prefix` and supports strict streaming validation; MMDB is
optimized for individual IP lookups rather than enumerating every prefix for
selected countries. The adapter must resolve one release metadata document,
capture the release and asset identities, verify the asset SHA-256 digest,
enforce file-size, record-count, and derived-prefix limits, define handling for
non-current country codes and contradictory overlaps, and stage the complete
validated snapshot before publication. No provider configuration field is
added until such an implementation exists.

## Resolution transaction

`PrefixSource.Resolve` expands only selectors referenced by enabled policies.
Every resolution is a complete candidate, not a stream of independently
publishable selector updates.

RIR service regions use a release-pinned, explicit country assignment from the
[RIPE NCC country/RIR table](https://www.ripe.net/community/internet-governance/internet-technical-community/the-rir-system/list-of-country-codes-and-rirs/),
reviewed on 2026-09-15 and cross-checked against the
[NRO table](https://www.nro.net/list-of-country-codes-and-rirs-ordered-by-country-code/).
These are not M49 geographic groups: for example, Taiwan belongs to APNIC,
Iran and Cyprus to RIPE, and the Dominican Republic to LACNIC. The embedded
assignments cover all 249 supported ISO country codes exactly once.

### Normative resolution steps

1. Expand configured countries, RIR service regions, and groups to unique
   country/ASN selectors. Reject a configuration exceeding 512 unique expanded
   selectors before issuing requests.
2. Fetch missing or stale selectors with at most four requests in flight and
   the configured per-request timeout (`30s` by default).
3. Cap each decoded HTTP response at 32 MiB. Crossing the limit fails that
   selector; the body is never partially accepted.
4. Require a successful HTTP response, RIPEstat API status `ok`, and the
   endpoint-specific schema and identity checks below:
   - **Country resource list:** the request identity is the normalized
     uppercase ISO-3166-1 alpha-2 country code sent as `resource`, with
     `v4_format=prefix`. The successful response need not contain
     `data.resource`; the country request and its validated endpoint URL bind
     the result to that identity. If an implementation receives an optional
     `data.resource`, it must normalize it to uppercase and reject a mismatch.
   - **Announced prefixes:** the request identity is the canonical decimal ASN
     (for example, `AS3333` and `3333` both become `3333`). A successful
     response must contain `data.resource`, and its value must normalize to
     exactly that decimal ASN. Missing, malformed, or mismatched ASN identity
     is an error.
5. For announced prefixes, apply the `query_endtime` visibility check before
   normalization. A prefix is retained only when its timeline contains that
   instant; a prefix seen earlier but no longer announced at the end is
   excluded.
6. Normalize every prefix with Go `net/netip`: parse, reject malformed or
   wrong-family values, mask host bits to the canonical network, deduplicate,
   remove a prefix contained by a broader retained prefix, and sort by address
   family, address, then prefix length.
7. Validate each selector result completely, including query times, endpoint/API
   version, and all decoded prefix arrays. Assemble one immutable
   `PrefixSnapshot` referring to one complete manifest.

The snapshot is all-or-nothing. A failed, truncated, malformed, mismatched, or
partial response never becomes an empty valid selector. A candidate revision is
publishable only when every required selector has a valid result and each
enabled policy resolves at least one prefix overall.

Reject duplicate object keys at every nesting level, including Unicode
case-fold-equivalent keys such as `status` and `STATUS`. Such aliases must not
overwrite status, identity, prefix, or visibility fields during decoding.
Unrelated, unambiguous provider metadata remains permitted.

A family-specific empty result has mode-dependent behavior, defined
canonically in [configuration](configuration.md): blocklist does nothing for
that family; allowlist denies all globally routable addresses in that family.
The compiler records the empty family explicitly rather than silently
disabling the policy.

### Actual-response fixtures

The adapter's compatibility fixtures must include bounded bodies captured from
actual responses of each official endpoint, with the request URL, capture date,
and API version recorded beside each fixture. A fixture is not valid merely
because it is a hand-written JSON object that resembles the documented schema.
The country success fixture must exercise a response without `data.resource`; the
ASN success fixture must exercise the normalized `data.resource` echo; and the
set must include status failure, schema failure, identity mismatch, and a prefix
whose visibility ends before `query_endtime`. Synthetic minimal responses may
supplement these fixtures but cannot replace them. Fixtures contain no
credentials or other secrets.

## Immutable selector objects and snapshot manifests

The prefix cache is a content-addressed object store, not a directory whose
current files are assembled on restart. Source objects and manifests are
immutable; publication selects one complete manifest.

### Selector objects

A selector object is canonical UTF-8 JSON containing:

- its schema version;
- normalized selector identity;
- endpoint and API version;
- request parameters and query times;
- separate sorted IPv4 and IPv6 arrays; and
- the normalized-result content identifier.

The object filename is the SHA-256 of its canonical bytes. Under
`/var/lib/perimeterd/prefixes/`, objects and manifests occupy separate
`objects/` and `manifests/` directories. Writes use an exclusively created
temporary file in the destination directory, write complete bytes, `fsync` the
file, rename to its content-addressed name, and `fsync` the directory. If that
name exists, validate its bytes and reuse it; never overwrite it or advance
metadata in place. A re-fetch with changed metadata creates a new object;
unchanged content may be referenced again without rewriting it. Canonical bytes
use RFC 8785 JSON canonicalization; schema versions define array ordering and
UTC timestamp representation.

### Snapshot manifests

A snapshot manifest is also canonical UTF-8 JSON and immutable. It contains the
source and endpoint/API versions, the complete sorted set of required selector
identities, one object identifier and validation/retrieval metadata for every
selector, and a manifest schema version. Its identifier is the SHA-256 of its
canonical bytes. A manifest is valid only when every referenced object exists,
hashes correctly, validates against its selector identity, and has the expected
family arrays. `PrefixSnapshot` is materialized only by reading one manifest
and exactly its referenced objects; it never combines independently selected
cache files.

### Cache publication and durable-commit coupling

The source cache follows the shared durable-commit contract in
[architecture](architecture.md#durable-apply-and-crash-recovery); this section
specifies only the cache-specific coupling rules:

1. Stage and validate every needed object, then write and `fsync` the complete
   manifest and atomically install it, followed by a directory `fsync`.
2. Carry the manifest identifier in the candidate and in the durable apply
   journal before any firewall mutation. The journal record includes the
   transaction ID, previous and candidate snapshot manifest identifiers,
   target, generation, compiled static model, ownership, and phase. The journal
   phase alone is not the commit point.
3. Change the active committed record, including its transaction ID and
   candidate manifest identifier, only after complete enforcement succeeds.
   Atomically and durably installing that active record is the commit point.
   Previous generations and their referenced objects remain until that commit is
   durable.
4. Garbage-collect an object or manifest only after no active, journaled, or
   retained generation references it. Garbage collection never changes an
   active pointer.

If a refresh fails after staging some objects, those objects and an
uncommitted manifest are ignored as orphans; the active manifest is unchanged.
If a crash occurs before the active record transaction commits, architecture's
precommit recovery restores the previous owned enforcement before accepting new
mutations. If the active record transaction is durable, recovery treats it as
committed and finishes retirement/cleanup. Recovery therefore cannot select a
snapshot whose selectors come from mixed uncommitted generations; validation of
journal and committed references is mandatory before work is admitted.

### Fresh reuse and stale fallback

Only currently referenced selectors refresh. The default schedule is once per
`24h` interval plus an independently sampled delay from zero through `10m`;
the request timeout defaults to `30s` and concurrency remains at most four.
Freshness uses the configured refresh interval and recorded retrieval time;
jitter delays scheduled work but does not extend cache freshness. Fresh objects
referenced by a committed manifest may be reused without a request.

For a refresh, newly fetched objects and fresh reused objects are assembled
into a new complete candidate manifest only after every required selector passes
validation. A failed refresh discards the whole candidate, including
successful fetches already staged; it does not publish a mixture of those
objects with stale replacements.

An active daemon may continue enforcing its last committed manifest when a
refresh fails. That manifest is the sole stale fallback: the daemon does not
construct a new fallback from independently aged selector files. On restart, a
valid committed manifest covering every required selector may be used whole
when refresh fails. A reload may reuse that manifest's selector results when it
covers every candidate selector; if the selector set shrinks, write a new
complete manifest referencing only that subset, preserving every retrieval
timestamp. No fetched partial results enter this fallback manifest.
Refresh failure includes a successfully fetched snapshot that cannot compile
into a usable policy, such as one emptied by exclusions. Before fallback or
fresh-cache reuse, the committed snapshot must still satisfy the candidate
configuration; coverage alone does not make an invalid policy acceptable.

A reload requiring a selector absent from the active manifest must fetch it
successfully; stale data cannot satisfy a newly introduced selector. On first
start, with no active manifest, every required selector must succeed before new
policy mutation or readiness. Snapshot age uses the oldest retrieval time among
required selectors, never the manifest creation time, so reusing stale data
cannot make it appear fresh. Report refresh failure and retry at the next
normal schedule.

## CrowdSec stream

When enabled, perimeterd uses the MIT-licensed
[`github.com/crowdsecurity/go-cs-bouncer`](https://github.com/crowdsecurity/go-cs-bouncer)
for authenticated API client setup and its stream-mode data types, not its
point-query protocol. The adapter owns the polling loop and calls the exposed
`APIClient.Decisions.GetStream` with explicit `DecisionsStreamOpts.Startup`.
It does not delegate recovery to `StreamBouncer.Run`: the current
[implementation](https://raw.githubusercontent.com/crowdsecurity/go-cs-bouncer/main/stream_bouncer.go)
keeps `Startup=false` after post-start errors and does not implement this
design's reconnect contract. Pin and review the dependency used for these APIs.
CrowdSec describes bouncers as
[remediation components](https://docs.crowdsec.net/u/bouncers/intro/) that act
on Security Engine decisions.

### Supported LAPI contract

Version 1 supports the reviewed CrowdSec LAPI baseline at
[v1.7.6](https://github.com/crowdsecurity/crowdsec/tree/v1.7.6), including the
stream decoder behavior reviewed in
[`pkg/apiclient/client_http.go`](https://github.com/crowdsecurity/crowdsec/blob/v1.7.6/pkg/apiclient/client_http.go)
and the feature registration in
[`pkg/fflag/crowdsec.go`](https://github.com/crowdsecurity/crowdsec/blob/v1.7.6/pkg/fflag/crowdsec.go).
The LAPI deployment is an explicit prerequisite, not a capability that the
adapter discovers from a response:

- `chunked_decisions_stream` must be disabled in both
  `CROWDSEC_FEATURE_CHUNKED_DECISIONS_STREAM` (set it to `false`) and
  `<ConfigDir>/feature.yaml` (the file must not list
  `- chunked_decisions_stream`; the usual path is
  `/etc/crowdsec/feature.yaml`). The two settings are required together so
  that an environment or file setting cannot silently enable the mode.
- The endpoint's JSON, headers, transfer encoding, or a successful envelope
  cannot attest that the server is running with that feature disabled. In the
  defective chunked-LAPI mode, a response can be a syntactically valid,
  apparently complete `new`/`deleted` envelope even though the backing
  database read produced only a partial result. Envelope validity therefore
  proves wire-format validity, not database query success or completeness; it
  must never authorize replacing the authoritative store on its own.
- A different CrowdSec release, a changed stream implementation, or enabled
  chunked mode is unsupported until a reviewed compatibility update establishes
  its response and cursor semantics with primary-source evidence and actual
  response fixtures. Support is added explicitly, not inferred from version
  ordering or HTTP framing.

Every request to `/v1/decisions/stream` uses `dedup=false`, including the
initial `startup=true` request, every reconnect `startup=true` request, and each
incremental `startup=false` poll. The go-cs-bouncer API does not expose this
option, so the adapter wraps the HTTP transport with a narrow pre-dispatch
query injector. For that stream endpoint only, it parses the existing URL query
and sets the single `dedup` value to `false`; it preserves `startup`, IP/range
scope filters, cursors, all other SDK options, the configured endpoint path,
authentication headers, and request context. It does not append a second
ad-hoc query string or inject `dedup` into unrelated LAPI requests.
Authentication material and complete URLs containing credentials remain
excluded from logs and diagnostics.

The explicit `dedup=false` contract preserves every applicable decision ID and
its independent expiry/provenance. Server-side deduplication can collapse
overlapping decisions before the adapter validates identity and maintains the
authoritative store.

### Compatibility rationale and primary-source evidence

The reviewed behavior is defined by the
[database stream queries](https://github.com/crowdsecurity/crowdsec/blob/v1.7.6/pkg/database/decisions.go),
[SDK request options](https://github.com/crowdsecurity/crowdsec/blob/v1.7.6/pkg/apiclient/decisions_service.go),
and the defective
[chunked query-error path](https://github.com/crowdsecurity/crowdsec/blob/v1.7.6/pkg/apiserver/controllers/v1/decisions.go#L267-L284).
These sources explain the explicit version pin, the disabled chunked feature,
and the transport-level `dedup=false` requirement; they are compatibility
rationale, not an alternative runtime contract. See
[operations](operations.md#supported-crowdsec-lapi-prerequisite) for operator
checks and the required server restart after feature changes.

### Response-envelope validation

`GetStream` has an EOF-masking hazard if an empty body is turned into a
zero-value response. The adapter therefore installs a response-body gate on
the HTTP transport before the client's typed decoder. Disable the underlying
Go transport's automatic decompression so the gate can bound both wire-entity
and decompressed bytes. Limit actual reads rather than trusting
`Content-Length`: both limits are 32 MiB, using a one-byte overflow sentinel.
Accept identity and bounded gzip decoding; reject unsupported or malformed
content encodings. The gate returns the validated decoded body with consistent
encoding/length metadata, so no second layer decompresses it again. Disable
the dependency's HTTP debug/body-dump features even when perimeterd's own
logging level is debug; validation is not permission to log a body or headers.

The gate must validate one complete JSON envelope before returning bytes to
`APIClient.Decisions.GetStream`:

- the body is non-empty and its top-level value is exactly one object;
- after that object's closing `}`, only JSON whitespace is allowed; a second
  value, any other trailing byte, or an incomplete document is an error;
- `new` and `deleted` each occur exactly once and each value is either an array
  or JSON `null` (null is normalized to an empty array); missing, duplicate,
  malformed, or other-typed required fields are errors; and
- unknown members may be ignored only after their complete JSON values have
  been parsed, so malformed data cannot be hidden in an unexamined suffix.

`{"new":[],"deleted":[]}` is a valid empty envelope, distinct from an empty
body, which is malformed and never means "no decisions". It becomes an
authoritative empty snapshot only under the supported LAPI contract and the
successful full-synchronization path below. Only after the envelope succeeds
does the client perform its typed decode, followed by validation of every
applicable decision. No per-decision decoder or item-by-item loop may bypass
the envelope gate, and decoder EOF or any typed-decode error is a
malformed-response failure rather than an empty projection. Debug diagnostics
may include bounded status and size metadata and an error category, but never
the body, raw JSON, or decision payload.

Any envelope, typed-decode, or decision-validation failure discards the response
and preserves the prior authoritative store and its expiry processing when one
exists; it never installs an empty candidate.

### Decision acceptance and expiry

The adapter accepts only decisions whose type is `ban` and whose scope/value
is a valid IP address or CIDR. It canonicalizes addresses and masks CIDRs with
`net/netip`, rejects malformed decisions, requires an LAPI decision ID, and
stores an absolute expiry. An LAPI-provided absolute expiry is authoritative
and retained exactly; pair it with a local monotonic deadline for scheduling.
If the API supplies only a valid duration `d`, capture wall-clock and monotonic
instants at request start, `(wall_start, mono_start)`, and derive the
conservative deadline as `wall_start + d - 1s`, paired with
`mono_start + d - 1s`. Request-start anchoring charges request/response latency;
the one-second cushion covers the API's duration rounding. Consequently a
duration-only decision can expire locally up to the request age plus that
cushion early, in addition to native timeout quantization.

An already elapsed deadline causes that decision to be omitted as expired, not
a malformed-response error or evidence that the entire snapshot is empty.
Renewal and retry never rebase the retained deadline on their execution time. A
newly fetched snapshot derives deadlines from that new request's timing; no
decision authority is persisted across restart. API keys, certificate paths, and
decision credentials are never part of a decision key or persisted state.

### Authoritative stream and decision identity

The authoritative in-memory store is keyed by `(endpoint identity, LAPI
decision ID)`. Endpoint identity is the canonical configured LAPI URL without
credentials. Every client has a monotonically increasing local client epoch. A
single reader assigns ordered stream-batch sequences; each decision retains that
provenance. The store processes every batch in order and maintains the current
valid, unexpired decision set and timed projection `P(D)`.

The store also maintains a monotonically increasing **desired revision**. It
advances for every accepted decision or expiry change that can alter authority,
provenance, prefix, or deadline, including the remove-then-add transition for
an update. An unknown or already-deleted ID is an idempotent no-op and does not
advance it. Source-batch sequence is input ordering only; it is not an
enforcement watermark. Coalescing may skip intermediate projections only after
all source deltas have been processed.

Every submission to the serialized firewall writer carries an immutable
dispatch snapshot: the client epoch, the store's desired revision, the current
timed `P(D)` (or a delta derived from that exact snapshot), and a monotonically
increasing **enforcement operation sequence**. Allocate a fresh operation
sequence for every backend attempt, including initial and reconnect reconciles,
incremental updates, expiry removals, renewals, and retries; never reuse one
for a retry or a timer callback.

For ordinary dynamic updates and lease work, the writer admits an operation
only while holding the same serialization fence used to observe and mutate the
active store, and only when all of these hold:

```text
operation.client_epoch == active_client_epoch
operation.desired_revision == current_store.desired_revision
operation.operation_sequence > applied_operation_watermark
```

The epoch binds the operation to its endpoint and replacement generation. The
revision comparison and snapshot selection are one writer-boundary decision: an
event arriving during an apply is ordered after that apply and cannot advance
the store behind an already-admitted operation. A queued operation whose epoch
or revision is stale is discarded without a backend call; it is rebuilt from a
fresh store snapshot with a new operation sequence.

Advance `applied_operation_watermark` only after the admitted backend operation
has succeeded and the success is acknowledged. A failed, ambiguous, or
possibly partially applied operation does not advance it; reconcile the current
owned dynamic sets to the latest current `P(D)` and retry with a fresh dispatch
snapshot and operation sequence. The operation sequence is monotonic for the
daemon lifetime and is never reset when an epoch or desired revision changes.
Retired client epochs and operations at or below the applied watermark cannot
mutate enforcement.

### Stream synchronization and activation

The first request to `/v1/decisions/stream` uses `startup=true` and IP/range
scope filters. Treat its `new` list as the complete authoritative set of active
decisions, starting from an empty staged store; its `deleted` list is not merged
into an old store. Validate identity, scope, value, and expiry for every
applicable ban. Unsupported types/scopes are ignored, not converted to bans.
The complete valid projection is included in the initial firewall reconcile;
readiness requires its successful apply and durable configuration commit.
Partial backend application follows the rollback/degraded guarantees in
[architecture](architecture.md), not an assertion that nothing changed.

Subsequent polls use `startup=false` and apply `deleted` before `new` within
each batch. On any transport, status, or malformed-response failure, mark the
integration unhealthy and stage `startup=true` for the next attempt under a new
client epoch. Keep the old store, epoch, and expiring enforcement active until
a validated full snapshot has been applied successfully.

Initial activation, reconnect, and configuration-driven client replacement are
explicit writer activation operations, not ordinary updates from a new epoch
pretending to be active already. At their writer boundary, validate the staged
client's identity and desired revision against the selected complete snapshot,
validate any enclosing configuration's freshness, and assign a new
enforcement operation sequence above the applied watermark. Apply from this
selected staged context while holding the same admission fence; do not publish
it as the active store or admit its ordinary events yet.

On success, publish the selected epoch/store and operation watermark together,
then resume incremental polling. Configuration-driven activation additionally
waits for the durable configuration commit. On failure, the old epoch/store
remain authoritative; compensate any partial enforcement from their current
unexpired projection with a fresh operation sequence. Failed compensation
marks enforcement unhealthy and blocks other mutations until recovery succeeds.
Queued old or staged events cannot mutate either store midway through this
activation; after publication, ordinary admission rejects the retired epoch.

Polling is single-flight per client. Use exponential retry delays beginning at
`1s`, doubling to a `60s` maximum with uniformly sampled jitter between half
and all of the current delay. Reset after two consecutive successful polls.
Normal successful polling uses `crowdsec.update_frequency`. Every LAPI attempt
uses at most a `30s` context timeout; while initial readiness is pending, clip
that timeout to the remaining bounded-startup budget. This request deadline is
independent of a decision lease. Expiry processing continues during outages; an
outage never extends a decision's expiry.

### Overlap, expiry, and backend projection

Let `D` be the valid, unexpired decisions keyed by endpoint and decision ID.
Keep their original prefixes and expiries independently; never merge away
provenance. For each address `a`, define `E(a)` as the latest expiry among
decisions covering it, or no expiry if none cover it. The required denied union
is exactly the addresses for which `E(a)` is in the future.

Construct the timed projection `P(D)` by partitioning each address family at
decision boundaries into disjoint ranges with constant `E(a)`, coalescing
adjacent ranges only when their deadlines agree, and decomposing those ranges
into CIDRs. This is representable by nftables interval sets and ipset without
overlapping timeout elements. Identical-prefix decisions share membership until
their last covering ID expires or is deleted. A broader, shorter ban cannot
erase a longer-lived narrow ban when it expires, and deleting one ID cannot
delete another ID's coverage.

Each projected element carries its absolute deadline, not a new duration
starting at retry time. The concrete remaining-lifetime, kernel-cap, and
renewal algorithm is defined in [renewable kernel leases](#renewable-kernel-leases).
Local expiry also reconciles the projection. Apply `/0` lowering after
projection as specified in
[firewall backends](firewall-backends.md#ipset-prefix-representation).

### Renewable kernel leases

The authoritative absolute deadline in each timed `P(D)` element drives an
expiring kernel lease; retrying or renewing never changes that deadline. A
renewal timer carries only a logical lease identity and wake-up state. It does
not carry a replayable projection, desired revision, or enforcement operation.
When the timer fires, the scheduler reads the current authoritative store and
current timed `P(D)` at dispatch, drops a removed or expired identity, and
builds a fresh dispatch snapshot under the store/writer serialization fence.
Thus an unrelated decision or expiry update does not cancel an outstanding
lease: an entry still present in the current store remains scheduled and is
renewed from its retained deadline. A removed decision cannot be resurrected by
an old callback.

At every admitted writer submission, capture `now` immediately before the
backend call and compute `remaining = deadline - now` from the retained
deadline (monotonic time while the daemon is running). Let `u` be the selected
backend's timeout granularity. Round down first, then cap:

```text
rounded = floor(remaining / u) * u
grant = min(rounded, 86400s)
```

If `remaining <= 0`, expire the contribution. If it is still future but
`grant <= 0`, omit its native element until the ordinary deadline event; do not
enqueue an immediate self-retrying update. Never pass zero, because zero means
permanent on some backends. The `86400s` (24-hour) ceiling is a cross-backend
compatibility maximum, not an LAPI request timeout.

Schedule a renewal at half of a granted lease only when the cap actually
truncated coverage (`rounded > 86400s`), using the monotonic grant time (a
24-hour grant renews at 12 hours). At that renewal, recompute `remaining` from
the same authoritative deadline and repeat the round-down and cap steps. When
the rounded remaining lifetime is at most 24 hours, submit the final uncapped
lease and schedule no renewal. Rounding alone is not a reason to renew, so a
short final lease cannot create a repeated tiny-lease or busy-renewal loop.

The renewal scheduler is independent of the LAPI poller and remains active
while LAPI is disconnected, a response is rejected by the envelope/typed
validation gate, reconnect is pending, or dynamic enforcement is in degraded
recovery. Renewal and reconciliation still pass through the serialized writer;
they cannot bypass a static transaction's mutation fence. If static recovery
blocks writes, queued renewals wait and kernel leases may expire early.

A stale callback or queued attempt is benign: recompute any outstanding lease
obligation from current state without changing health merely for losing an
admission race. A removed obligation generates no backend call. A failed,
ambiguous, or partially applied renewal retains the authoritative decision and
outstanding obligation, marks enforcement unhealthy, and schedules a retry
using the `1s`-to-`60s` exponential backoff and jitter defined above. The retry
reads the current store and projection again and allocates a new operation
sequence, and is admitted only under the current client epoch and desired
revision. It recomputes the remaining lifetime; if the 24-hour cap no longer
truncates it, it submits the final uncapped lease and stops the renewal loop. A
failed renewal never resets the deadline or falls back to a permanent lease.
If the backend is unavailable until the granted lease expires, the dynamic
entry can fail open and is reconciled from the current projection when writes
recover. A timer callback that loses the revision race is therefore rescheduled
from the current state, not replayed with its stale snapshot.

During a daemon restart no process can renew. Startup must perform a new
authoritative `startup=true` synchronization and submit only currently
unexpired decisions using their remaining lifetimes; it must not turn a prior
duration into a fresh deadline. If kernel state survives the restart, its
remaining timeout is reconciled; if a reboot or teardown lost that state, the
initial reconcile rebuilds it after synchronization. While the daemon is down,
an entry can therefore expire before its far-future authoritative deadline:
with no reboot, the last granted lease lasts no more than 24 hours after the
daemon stops (and may have less remaining), while a reboot can lose kernel state
immediately. This bounded fail-open tradeoff is why leases are capped and
renewed rather than installed as permanent entries.

An update for an existing decision ID first removes its old prefix/expiry
contribution and then applies its new validated contribution as one store
transition. A deletion names the decision ID and removes only that ID's
contribution; an unknown or already deleted ID is an idempotent no-op. At the
absolute LAPI expiry, the store performs the same contribution removal even
without a stream event. Expired decisions never reappear after reconnect
snapshot validation. The global allowlist still has precedence over this
projection: a retained decision may be present in `D` but cannot deny while
covered by the effective allowlist.

The authoritative store computes additions and deletions for dedicated dynamic
IPv4 and IPv6 firewall sets and sends those deltas to the serialized writer; it
does not invoke a backend itself. Successful updates are incremental and do not
rebuild static global or geo sets.

If a backend delta fails or may have been partially applied, inspect the current
owned dynamic sets and reconcile them to the latest timed `P(D)`. Do not replay
an obsolete event or assume an earlier batch was wholly unapplied. Fold later
events and expiry into the next projection, including deadline changes as well
as membership changes. A failed deletion remains pending until the unwanted
element is gone; a failed addition retains its authoritative decision. Runtime
delta failure sets enforcement health to zero until current-state reconciliation
succeeds. Native expiry remains effective even while a static transaction's
degraded recovery blocks dynamic mutations.

## CrowdSec availability, endpoint changes, and secrets

CrowdSec is optional. When enabled:

- the key file must exist, be readable, and contain a usable credential;
- initial LAPI authentication, authoritative full synchronization, exact
  projection, and its backend apply must succeed before readiness;
- later disconnects retain currently valid decisions and enforcement, mark the
  integration unhealthy, obtain a full snapshot on reconnect, and use bounded
  exponential backoff;
- expiry processing and current `P(D)` projection reconciliation continue while
  disconnected; and
- replacement credentials are authenticated as a staged reload resource.

Credential replacement and endpoint replacement are staged configuration changes
under [architecture](architecture.md#staged-reload). Each replacement obtains
a full `startup=true` snapshot into a separate store. The old store and its
expiry processing remain authoritative until the configuration's durable commit
promotes the new client epoch. Do not poll two clients sharing one LAPI stream
cursor concurrently: pause old polling at a batch boundary while synchronizing
its replacement, retaining its store and enforcement. If staging fails, resume
the old client via a full synchronization rather than assuming its incremental
cursor is unchanged.

For an endpoint change, the new endpoint's snapshot is the sole candidate
authority; never union old-endpoint decisions into it. Disabling CrowdSec stages
an empty projection. Apply the selected projection with the candidate static
state at the writer boundary; retire the old client and store only after durable
commit. A failed apply compensates to the old client's current, unexpired
projection; failed compensation enters degraded recovery, not a claim that old
enforcement survived untouched. Precommit crash recovery restores the prior
static selection and re-synchronizes its configured LAPI before readiness. These
changes do not independently commit outside the configuration transaction.

The API key is read from `crowdsec.api_key_file`. Its value must never appear in
the main YAML example, logs, metrics, process arguments, error wrapping, or
diagnostic dumps. Logs also omit complete prefix lists; metrics use bounded
source/result labels only. CrowdSec decisions are not persisted as secrets or as
an authority across restart: restart performs a new authoritative LAPI snapshot
and reconciliation. See [operations](operations.md) for credential file modes
and observability.

## Source failure matrix

| Failure | Required behavior |
| --- | --- |
| Required cache missing and RIPEstat unavailable | First start fails before firewall mutation and readiness. An active daemon keeps its committed manifest and enforcement and retries. |
| Malformed, partial, status-failed, or identity-mismatched RIPEstat response | Reject the whole candidate. An active daemon exposes failure and age without replacing its committed manifest. |
| Corrupt staged objects or orphaned/uncommitted manifests | Ignore them and fetch or use a complete valid committed manifest. First start fails if a complete candidate cannot be built. |
| Corrupt objects referenced by recovery state | Do not silently substitute a newly fetched generation. Recovery validates the journal and committed references before admitting work; missing recovery evidence requires repair as specified in [architecture](architecture.md#durable-apply-and-crash-recovery). |
| CrowdSec key missing or unreadable | Fail first-start readiness. A reload is rejected and its active client remains. |
| Initial CrowdSec authentication or authoritative snapshot failure | Fail first-start readiness before applying a candidate. |
| Initial backend application failure | Withhold readiness and perform backend-specific compensation; preserve recovery evidence if it fails. |
| Credential/endpoint replacement or disable failure | Keep the old configuration committed, resume its synchronization, and compensate any partial apply. Failed compensation reports degraded enforcement. |
| Later CrowdSec outage or reconnect snapshot failure | Mark the integration unhealthy, retain unexpired decisions until local expiry, and retry the full authoritative synchronization. |
| CrowdSec backend delta failure | Recompute the current `P(D)` projection from the authoritative store, queue that reconciliation, and retry idempotently. |
