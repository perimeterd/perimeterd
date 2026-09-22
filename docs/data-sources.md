# Data Sources

> **Implemented status.** The RIPEstat resolver and immutable cache provide
> static country/ASN snapshots, including release-pinned country-based RIR and
> group expansion. Source-backed policy is implemented on both nftables and
> iptables/ipset (legacy and nf_tables tool families). Refresh, cache, and
> durable-recovery behavior are implemented; backend realization is specified
> in [firewall backends](firewall-backends.md).
>
> CrowdSec dynamic bans are also implemented on both backends, with
> authoritative synchronization, timed overlap projection, staged reloads, and
> renewable finite kernel leases. The supported LAPI deployment prerequisite
> below remains mandatory. The [implementation plan](implementation-plan.md)
> owns delivery status; [operations](operations.md#current-source-build-runtime)
> describes source-build use and its production-security limitations.
>
> Custom HTTP(S) text IP lists extend static snapshots without changing CrowdSec
> authority or leases.
>
> Named provider selectors reuse this static-source pipeline with dynamic
> provider resolution through jsDelivr; no embedded provider catalog is required.
>
> [Lookup source attribution](#lookup-source-attribution) explains this committed
> evidence without initiating source requests or using desired-but-unapplied decisions.
>
> [OpenZiti upstream transport](#openziti-upstream-transport) optionally connects
> LAPI and custom-list clients to private services without host-wide tunneling.

## Contents

- [RIPEstat scope and accuracy](#ripestat-scope-and-accuracy)
  - [Normative provider contract](#normative-provider-contract)
  - [Accuracy and interpretation](#accuracy-and-interpretation)
  - [Evaluated alternative: sapics/ip-location-db](#evaluated-alternative-sapicsip-location-db)
- [Resolution transaction](#resolution-transaction)
  - [Normative resolution steps](#normative-resolution-steps)
  - [Actual-response fixtures](#actual-response-fixtures)
- [Immutable selector objects and snapshot manifests](#immutable-selector-objects-and-snapshot-manifests)
  - [Selector objects](#selector-objects)
  - [Snapshot manifests](#snapshot-manifests)
  - [Cache publication and durable-commit coupling](#cache-publication-and-durable-commit-coupling)
  - [Fresh reuse and stale fallback](#fresh-reuse-and-stale-fallback)
- [Custom HTTP(S) IP lists](#custom-https-ip-lists)
  - [Text format and validation](#text-format-and-validation)
  - [HTTP transport](#http-transport)
  - [List identity and immutable cache](#list-identity-and-immutable-cache)
  - [Per-list refresh and complete snapshots](#per-list-refresh-and-complete-snapshots)
- [Named provider feeds](#named-provider-feeds)
  - [Dynamic IDs and jsDelivr mapping](#dynamic-ids-and-jsdelivr-mapping)
  - [Provider identity, refresh, and fallback](#provider-identity-refresh-and-fallback)
  - [Upstream meaning and freshness limits](#upstream-meaning-and-freshness-limits)
  - [Why not go-cloudip](#why-not-go-cloudip)
- [OpenZiti upstream transport](#openziti-upstream-transport)
- [CrowdSec stream](#crowdsec-stream)
  - [Supported LAPI contract](#supported-lapi-contract)
  - [Compatibility rationale and primary-source evidence](#compatibility-rationale-and-primary-source-evidence)
  - [Response-envelope validation](#response-envelope-validation)
  - [Decision acceptance and expiry](#decision-acceptance-and-expiry)
  - [Authoritative stream and decision identity](#authoritative-stream-and-decision-identity)
  - [Stream synchronization and activation](#stream-synchronization-and-activation)
  - [Ephemeral backend inputs](#ephemeral-backend-inputs)
  - [Overlap, expiry, and backend projection](#overlap-expiry-and-backend-projection)
  - [Renewable kernel leases](#renewable-kernel-leases)
- [CrowdSec availability, endpoint changes, and secrets](#crowdsec-availability-endpoint-changes-and-secrets)
- [Source failure matrix](#source-failure-matrix)
- [Lookup source attribution](#lookup-source-attribution)

Version 1 uses RIPEstat for static country/ASN prefixes, custom HTTP(S)
text lists as another static selector type, and CrowdSec LAPI for dynamic
ingress bans. Named feeds from `rezmoss/cloud-provider-ip-addresses` also use
the static-source pipeline. [Configuration](configuration.md) defines selectors and defaults;
[architecture](architecture.md) defines revision admission, commit behavior,
and process lifecycle. Sources produce typed data and never emit firewall
syntax. This document owns source wire compatibility, source-side validation,
cache coupling, authoritative dynamic state, timed projection, and lease
behavior.

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

`internal/source.Resolver.Resolve` expands only selectors referenced by
enabled policies and stages one complete immutable cache snapshot. Every
resolution is a complete candidate, not a stream of independently publishable
selector updates.
The steps below describe RIPEstat resolution; the
[custom-list extension](#custom-https-ip-lists) specifies how additional
selectors join the same transaction.

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
New objects and manifests use schema version 3 with explicit
[transport identity](#transport-identity-and-saved-evidence). Committed
version-1/2 objects and manifests remain readable, stabilizable, and protected
from collection by their original exact references. The fields below describe
RIPEstat records; [list identity](#list-identity-and-immutable-cache) adds
source-specific metadata within the same cache.

### Selector objects

A selector object is canonical UTF-8 JSON containing:

- its schema version;
- normalized selector identity;
- endpoint and API version;
- effective transport identity;
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

The [durable-apply contract](architecture.md#durable-apply-and-crash-recovery)
owns revision admission, journal phases, active-record publication, and crash
recovery. Source-specific rules are deliberately narrower:

1. Stage and validate every needed object, then install and `fsync` the complete
   manifest and its directory before it is named as a candidate.
2. Bind the manifest to the immutable candidate revision and journal before
   firewall mutation. Compiled static state and ownership live in the referenced
   revisions; the journal phase is not the commit point.
3. Change the active record only after complete enforcement succeeds. Keep the
   previous manifest and its objects reachable until that record is durably
   installed.
4. Collect an object or manifest only after no active record, journal, or
   retained generation references it; collection never changes an active pointer.

A failed refresh may leave staged objects or an uncommitted manifest as
orphans, but it cannot change the active manifest. Loading is exact and
all-or-nothing: every referenced object is validated, and independent cache
files are never combined. Recovery validates its recorded references before
admitting work; it does not substitute a newly fetched generation for missing
recovery evidence.

### Fresh reuse and stale fallback

Only currently referenced RIPEstat selectors refresh. The default schedule is once per
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

## Custom HTTP(S) IP lists

Named `ip_lists` resolve operator-selected HTTP or HTTPS text feeds for
`include.ip_lists` and `exclude.ip_lists`. They are independent of RIPEstat and
do not infer countries or ASNs. [Configuration](configuration.md#custom-ip-lists)
owns names, URL validation, defaults, references, and policy behavior.

### Text format and validation

- Accept UTF-8 plain text with LF or CRLF lines and an optional final newline.
  Trim surrounding ASCII spaces and tabs; ignore blank lines and full-line
  comments beginning with `#` after trimming.
- Every remaining line must contain exactly one IPv4 or IPv6 address or CIDR.
  Inline comments, comma-separated values, address ranges, hostnames, zone
  identifiers, HTML/JSON, and directives to load other files are invalid.
- Normalize with `net/netip`: bare addresses become `/32` or `/128`, CIDRs are
  masked, and duplicates and contained prefixes are removed. Sort by family,
  address, then prefix length. IPv4 and IPv6 may coexist in one file; `/0`
  prefixes are valid and use the existing native lowering.
- Validate the complete body, including entries from a disabled address family.
  A malformed line rejects the whole response; never silently skip bad entries
  or accept a valid prefix before a broken tail. Diagnostics identify the list
  name and line number without logging complete response bodies.
- An empty or comment-only body is invalid, not a request to clear enforcement.
  A single-family list is valid, subject to the existing family-empty
  allowlist/blocklist semantics. Exclusions that empty an enabled policy also
  reject the candidate, as for other static selectors.

The supplied
[Zoom list](https://cdn.jsdelivr.net/gh/rezmoss/cloud-provider-ip-addresses@main/zoom/zoom_ips.txt)
is an example of this line-oriented IPv4/IPv6 format. Tests must use local
fixtures rather than depend on that mutable public URL.

### HTTP transport

Fetch with HTTP GET. Require a final HTTP 200 and a fully read, validated body;
204, unsolicited 304, other statuses, transport errors, truncated reads, or
timeouts fail resolution. Parse the body as text regardless of MIME type or
filename extension; a `.txt` suffix is not required.

Use the list's `request_timeout` for the entire fetch, including redirects and
body reading. Enforce the existing 32 MiB decoded-response cap, including after
decompression. Across static providers, at most four requests may be in flight;
list workers do not get an additional independent concurrency allowance.
Reject a candidate with more than 512 distinct required static selectors
(expanded country/ASN selectors plus named list identities) before requests.

Follow at most ten redirects, applying the same URL constraints at every hop.
HTTP-to-HTTPS and same-scheme redirects are allowed; HTTPS-to-HTTP downgrade is
rejected. HTTPS uses normal certificate and hostname verification. No remote
response can supply configuration or executable content.

Configured endpoints may be public or private, including local HTTP servers.
Configuring a URL therefore authorizes network access from the daemon; this is
privileged local configuration, not an untrusted remote URL submission API.
Prefer HTTPS and trust the publisher: HTTP permits in-transit policy changes,
and HTTPS cannot ensure a publisher's list is correct. Do not log query strings,
full URLs, or response bodies; use configured names for diagnostics. URLs may
be persisted as source identity in root-only state, so they are not a supported
secret-storage mechanism.

### List identity and immutable cache

Version-2 selector objects and manifest entries identify custom lists with
`source_kind: "ip_list"` and `source_name` equal to the configured list name.
Their `endpoint` is the configured URL and `api_version` is text-parser format
`"1"`. `parameters` is empty and query-time fields are empty strings: a text
source does not fabricate RIPEstat metadata. All-RIPEstat manifests retain
`source: "ripestat"`; manifests containing lists use `source: "static"`. Use the
configured URL with scheme and DNS host normalized to lowercase, preserving
path and query bytes; redirect destinations do not replace that identity.
Changing the name or URL requires resolution under a new identity; changing
only the interval or timeout does not invalidate already validated prefixes.

List objects store that identity, retrieval time, normalized family arrays,
and content identifiers; RIPEstat query times and API metadata are not invented
for a text source. Mixed manifests bind the complete required selector set to
exact objects. A list referenced in multiple include/exclude positions uses one
object. Different configured names remain distinct selectors even if they use
the same URL.

The same checksums, bounded decoding, durability barriers, exact-reference
recovery, and garbage-collection rules apply; see
[immutable selector objects and snapshot manifests](#immutable-selector-objects-and-snapshot-manifests)
for the common manifest contract. Recovery reads the object IDs recorded in
the manifest rather than reconstructing IDs with the current schema.

### Per-list refresh and complete snapshots

Only lists referenced by enabled policies are fetched or scheduled. Each uses
its own positive `refresh_interval` (default `24h`) and `request_timeout`
(default `30s`), independent of `geo` timings. There is no additional
custom-list jitter setting. Freshness is measured from successful retrieval,
not manifest creation or firewall application.

A single static scheduler applies the [common freshness and fallback
rules](#fresh-reuse-and-stale-fallback): it selects due or missing sources and
reuses fresh objects from the committed manifest. RIPEstat retains its
jittered schedule; a list deadline must not force a still-fresh RIPEstat
selector or another list to download. Each attempt stages one complete
candidate for the active configuration under the existing epoch and
refresh-sequence admission fences, and a later candidate accounts for all
currently due selectors rather than overwriting a newer source result.

When a list attempt fails, retain the entire committed snapshot and its
retrieval timestamps. Retry failed due selectors after their configured
intervals, not in a tight loop caused by stale retrieval times; other sources
keep their own deadlines. Do not publish successful partial fetches with stale
replacements. Only selectors selected for fetching receive a retry deadline; a
reused peer that expires during another request is not treated as failed.
Because publication requires one complete snapshot, a stale selector's
outstanding retry cooldown can defer the whole transaction without moving
other selectors' own deadlines.

First start needs every required selector to resolve. Restart and reload may
use the complete committed fallback only when it covers every required
identity and still compiles under the candidate configuration; a subset manifest
preserves its retrieval times. Adding a list or changing its URL cannot fall
back to an unrelated or previously named endpoint. A failed reload keeps the
old configuration and its schedule. Disabling/removing the last active reference
stops that list's refresh after commit, without deleting cache evidence still
required by a retained revision or journal.

Refresh failures retain static enforcement without an expiry limit, unlike
CrowdSec leases. This favors continuity over automatic removal of stale list
entries; operators must monitor freshness. Source timestamp reporting uses the
oldest required committed retrieval per source kind, never resets age on
fallback, and must not label custom-list data as RIPEstat.

## Named provider feeds

Provider-wide IP/CIDR sets come from
[`rezmoss/cloud-provider-ip-addresses`](https://github.com/rezmoss/cloud-provider-ip-addresses),
using its merged, dual-stack text files. The
[configuration contract](configuration.md#named-providers) owns selector
syntax, defaults, and policy semantics. No provider catalog is embedded or
required at runtime; provider IDs are resolved dynamically.

### Dynamic IDs and jsDelivr mapping

For a locally validated ID, construct the default URL exactly as:

```text
https://cdn.jsdelivr.net/gh/rezmoss/cloud-provider-ip-addresses@main/{id}/{id}_ips_merged.txt
```

For `zoom`, this is:

```text
https://cdn.jsdelivr.net/gh/rezmoss/cloud-provider-ip-addresses@main/zoom/zoom_ips_merged.txt
```

Use jsDelivr and the `main` branch by default, not raw GitHub, a dated release,
or a bundled classification database. The initial configuration exposes timing
settings only; custom `ip_lists` remain available for alternate URLs or pinned
revisions. Do not silently fail over to another origin or branch.

The required file is the existence check: issue one bounded content GET per
missing/due provider, not a preliminary HEAD request, repository listing,
GitHub API lookup, `summary.json` catalog fetch, or metadata request. The
repository and path template are fixed source configuration; provider names
are not compiled-in membership. IDs not known when perimeterd was built must
still resolve if a valid feed is now served at the mapped URL.

Require a final HTTP 200 with a non-empty, fully validated body under the existing
[text format](#text-format-and-validation) and [transport rules](#http-transport).
Reuse UTF-8/IP/CIDR normalization, invalid-line rejection, TLS verification,
redirect limits, HTTPS downgrade rejection, whole-request timeout, and the
32 MiB decoded-body cap. Each distinct provider counts toward the shared
512-selector cap and uses the same four-request allowance as other static
sources. Fetch both address families and validate the whole file even when one
firewall family is disabled.

HTTP 404 means resolution failed at the mapped endpoint; report the provider ID
and failure status without interpreting it as an empty provider or silently
removing its selector. CDN caching can delay both newly added feeds and updates,
so a missing file is not proof that the provider is permanently absent upstream.
Other failed statuses, malformed/empty bodies, and transport failures also fail
resolution. Diagnostics must distinguish offline syntax errors from runtime
source failures; never dump response bodies.

### Provider identity, refresh, and fallback

The separate `provider` selector/source kind is keyed by the exact provider ID,
not a synthetic entry in the user-defined `ip_lists` namespace. Its
objects and manifest entries store `source_kind: "provider"`, `source_name`
equal to that ID, `endpoint` equal to the derived CDN URL, and `api_version: "1"`
for the shared text parser. Retrieval time, normalized family arrays, and
content identifiers follow the existing static-source format. New version-3
records explicitly bind providers to direct transport.
The derived URL and parser identity must match the candidate's source mapping;
an old object for another provider, endpoint, or format is not fallback.
Changing only refresh/timeout settings does not change source identity.

Provider-containing manifests retain the `source: "static"` root introduced in version 2 and
bind every required selector to an exact immutable object. There is no parallel
cache. Existing version-1 RIPEstat and version-2 custom-list evidence remains
readable and stabilizable by its exact stored object references. Provider
request parameters and query-time fields are empty rather than invented
RIPEstat metadata.

Each required provider uses `providers.refresh_interval` (default `24h`) and
`providers.request_timeout` (default `30s`). The interval is measured from its
successful retrieval; sharing settings does not force downloading fresh peers.
Only enabled-policy references fetch, repeated references resolve once, and
removing the final active reference stops refresh after commit. The existing
static scheduler, epoch/sequence fences, exact attempted-selector retry tracking,
and writer govern provider results as well as other static sources.

A new unknown provider cannot borrow another provider's data or an unrelated
custom-list object. Without a valid complete committed fallback covering every
required identity, failed resolution prevents startup readiness or rejects a
reload before activation. A rejected reload leaves the old configuration and
schedule running. A later 404 or outage fails the refresh and retains the entire
committed snapshot; it does not terminate healthy retained enforcement or clear
that provider's prefixes. Restart/reload fallback is permitted only for the
same previously committed identities and a still-valid complete policy.
Fallback never counts as a successful fetch or resets retrieval timestamps.

Provider failures do not publish successful partial updates from other sources.
Use the existing retry cooldown and complete-snapshot barrier; do not cache a
missing provider permanently, so subsequent attempts can recover when its feed
becomes available. Stale static enforcement has no automatic expiry.

### Upstream meaning and freshness limits

The default follows mutable `main` through a CDN. Independent provider requests
may observe different cache ages or repository commits. Perimeterd guarantees
atomic local candidate publication, not a common upstream Git revision. The
initial feature does not resolve a shared commit SHA or promise a CDN purge SLA.

A successful retrieval proves that the CDN supplied a syntactically acceptable
set, not that every original provider feed was freshly or completely collected.
Upstream `generated_date`, `last_changed_date`, and `content_sha256` are not
runtime acceptance inputs: publication time is not original-source freshness,
unchanged sets can be old without being stale, and the metadata hash is not
necessarily a published TXT file's byte checksum. Perimeterd uses its own
immutable content identities and reports its committed retrieval time.

Provider sets can overlap and contain infrastructure used by unrelated tenants.
Whole-provider TXT discards service/region labels. Some providers, such as
[Alibaba](https://github.com/rezmoss/cloud-provider-ip-addresses/blob/main/alibaba/README.md),
are BGP-derived rather than official customer/service feeds; do not imply
stronger attribution or coverage guarantees. The publisher and CDN are network
trust boundaries, not sources of executable firewall scripts or configuration.

### Why not go-cloudip

Do not add [`go-cloudip`](https://github.com/rezmoss/go-cloudip) for this adapter.
Its public API is for point-IP classification, not bulk CIDR enumeration, and
its separate `cloudip-db` pipeline currently covers a smaller provider set.
Its own cache, embedded fallback, and update lifecycle are not perimeterd's
committed-source authority. Reuse the existing text transport/parser and static
transaction path instead.

## OpenZiti upstream transport

The [configuration](configuration.md#optional-openziti-configuration)
selects a transport independently for each custom list and for the CrowdSec
client. Omission means the existing direct transport. RIPEstat and named-provider
feeds remain direct; custom lists can represent privately hosted equivalents.
The selected source kind, text/JSON parsing, include/exclude algebra, and dynamic
decision semantics do not change.

### Service binding and HTTP safety

Bind an opted-in HTTP client to one loaded identity generation and exact service
name using the SDK's service-dial API, not a dialer that can fall back to the
ordinary network when interception or discovery fails. Apply this to every
connection, including reconnects and pool replacements. Never share an HTTP
connection across identities, service bindings, or application origins.
An HTTP proxy environment variable must not redirect an opted-in application
request onto the ordinary network. SDK control/edge connections still require
ordinary underlay DNS/connectivity; application hostnames do not.

The URL supplies HTTP Host, path/query, and HTTPS server-name/certificate
verification. TLS runs over the Ziti connection for an HTTPS URL, using the
normal OS trust store. A Ziti identity's controller CA is not automatically a
trusted CA for the application endpoint. Do not add `insecure_skip_verify`,
rewrite the URL to the Ziti service name, or weaken LAPI API-key authentication.
Plain HTTP remains permitted under the existing source rules, but Ziti
encryption may end at a hosting proxy/router rather than at the HTTP server.

For a Ziti custom list, follow at most ten redirects and only within the
configured origin (same scheme, hostname, and effective port). Relative and
same-origin redirects use the same identity/service. Reject cross-origin,
scheme-changing, and downgrade redirects rather than discovering another
service or falling back to direct HTTP. For a Ziti LAPI, reject redirects.
Existing direct-source redirect behavior is unchanged.

The caller's wait for authentication, service discovery, router selection,
dialing, application TLS, redirects, and body reading must fit its existing
end-to-end deadline. Cancellation releases the caller; late-arriving connections
are closed rather than handed to an abandoned request. Admit at most eight
perimeterd SDK dial workers process-wide and one per loaded identity generation,
before creating goroutines; waiting for admission is itself cancellable.
Preserve existing decoded-body limits, static request concurrency, selector
limits, CrowdSec retry/backoff, and the process startup deadline. SDK connection
maintenance must not issue extra source GETs or create an independent LAPI stream
consumer.

### SDK cancellation limitation

The integration uses unmodified `sdk-golang v1.8.2`, not a local SDK fork.
That release's controller-version discovery retries without observing context
closure, and parts of authentication do not honor the dial caller's context.
Consequently, SDK background work can survive request cancellation or SDK
`Close`; perimeterd must not claim to have drained it. This limitation was
explicitly accepted rather than patched locally.

Perimeterd bounds its own caller waits, admission, and shutdown, closes its HTTP
pools, and invokes SDK context closure outside the writer. A stuck SDK dial holds
one of the eight admission slots until it returns; if all slots remain occupied,
further Ziti dials time out waiting for admission. Direct sources and read-only
lookup are independent of those slots. SDK-internal discovery workers are not
covered by this application worker limit and may remain after retired contexts,
especially during repeated failed activations or identity changes. Process exit
terminates that residual work; operators may need a controlled restart after
connectivity is restored. These failures never authorize direct fallback or
extend CrowdSec decisions.

The limitation is reproducible with a controller returning HTTP 503: a 100 ms
dial context expires while the SDK call remains blocked, and version requests
continue after SDK `Close`. See the pinned
[discovery loop](https://github.com/openziti/sdk-golang/blob/v1.8.2/edge-apis/client_edge_client.go#L272-L286).

### Transport identity and saved evidence

New selector objects/manifests use a version-3 extension
that binds every entry to its transport as well as its existing selector,
URL/parameters, and parser identity. Direct entries record `type: "direct"`.
Ziti list entries additionally record the selected identity profile name,
exact service name, and a non-secret `identity_generation` fingerprint.
No raw identity JSON, private key, authentication token, or SDK session is
stored in source objects, manifests, revisions, or journals.
Use a `transport` mapping on the object and corresponding manifest entry:
`type` is always present; `identity`, `identity_generation`, and `service` are
required only for `openziti` and forbidden for `direct`. The generation is
64 lowercase hexadecimal SHA-256 digits. Entry/object identities must agree;
reject unknown fields, unsupported combinations, and malformed fingerprints.

Compute the generation once as SHA-256 over the loaded identity's canonical
controller endpoint/trust configuration and public client certificate chain/key.
Validate that private keys match their certificates, but do not persist or
log private-key material. Changing controller/trust configuration or client
certificate changes the generation even if the file path is unchanged.
This deliberately treats certificate renewal conservatively as a new generation
requiring a fresh fetch before data can be selected under that identity.
Ordinary refresh uses the committed loaded generation; it must not re-read
credentials at the same path and silently change routing authority.

Changing direct/Ziti mode, identity profile/generation, or service requires a
new source identity, just as changing a URL does. Old-route data is not fallback
for the new route, even if list name and URL are identical. Timing-only changes
do not invalidate data. Reuse/fallback requires a complete committed snapshot
matching every effective identity; an outage never resets retrieval timestamps.

Version-1 RIPEstat and version-2 direct list/provider evidence remains readable
and is interpreted only as direct transport. Recover legacy objects by their
saved identifiers without rewriting them or inventing Ziti identity evidence.
Recovery, integrity checks, and garbage collection use saved routing metadata
without loading credentials or contacting Ziti. Fresh activation of a selected
Ziti configuration still validates its referenced local identity material.
Lookup continues to explain committed source membership without using an SDK
context or treating current Ziti availability as firewall authority.

### Failure and dynamic-authority boundaries

| Condition | Required behavior |
| --- | --- |
| Direct-only or no active Ziti references | No identity-file access, SDK contexts, enrollment, or Ziti traffic; preserve existing behavior and prerequisites |
| Referenced identity cannot be loaded/validated | Fail startup activation or reject the reload; no direct fallback, and do not replace the active generation |
| Ziti list unavailable or unauthorized | Fail that fetch; retain selected static enforcement and normal retry scheduling; use only exact-identity complete committed fallback where already permitted |
| Changed route/identity cannot fetch its list | Reject activation of the changed identity; never reinterpret the old route's cache as new evidence |
| Initial Ziti LAPI synchronization fails | Withhold readiness or reject replacement, under the existing LAPI startup/reload contract |
| Active Ziti LAPI disconnects or access is revoked | Mark disconnected, retain only normally unexpired decisions/finite leases, and retry full authoritative synchronization; never renew expired decisions because Ziti is unavailable |
| One SDK context serves both a list and LAPI | Share connections, not source authority: preserve independent list deadlines, LAPI expiry/cursor handling, and existing health semantics |

Changes to LAPI transport, identity generation, or service are endpoint/credential
replacements even when the application URL and API key stay the same. Stage a
separate full snapshot and promote it only through the enclosing configuration
transaction; never union decisions from old and new routes. SDK reconnect alone
does not make a CrowdSec cursor authoritative. On failure, resume the selected
client using existing full-resynchronization rules.

Logs use configured source/profile names and bounded failure classes, not raw
SDK configuration, URLs, keys, session tokens, or unredacted SDK errors.
Existing source-kind timestamps and connection/enforcement health retain their
meaning; identity IDs and service names do not become metric labels.

Upstream references: the [Go SDK](https://github.com/openziti/sdk-golang),
[HTTP client example](https://github.com/openziti/sdk-golang/blob/main/example/http-client/README.md),
and [service termination model](https://netfoundry.io/docs/openziti/learn/core-concepts/services/overview/#service-termination).
Examples are integration guidance, not permission to copy disabled TLS
verification or substitute mutable SDK `main` for a pinned tested release.

## CrowdSec stream

The implemented adapter uses the MIT-licensed
[`github.com/crowdsecurity/go-cs-bouncer`](https://github.com/crowdsecurity/go-cs-bouncer)
for authenticated API client setup and its stream-mode data types, not its
point-query protocol. The adapter owns the polling loop and calls the exposed
`APIClient.Decisions.GetStream` with explicit `DecisionsStreamOpts.Startup`.
It must not delegate recovery to `StreamBouncer.Run`: the current
[implementation](https://raw.githubusercontent.com/crowdsecurity/go-cs-bouncer/main/stream_bouncer.go)
keeps `Startup=false` after post-start errors and does not implement this
design's reconnect contract. The implementation pins `go-cs-bouncer v0.0.21`
and the `crowdsec v1.8.1` SDK in `go.mod`; it does not run the SDK poller.
CrowdSec describes bouncers as
[remediation components](https://docs.crowdsec.net/u/bouncers/intro/) that act
on Security Engine decisions.

### Supported LAPI contract

The supported and tested CrowdSec LAPI server baseline is
[v1.8.1](https://github.com/crowdsecurity/crowdsec/tree/v1.8.1), using its normal
chunked decision stream. No legacy feature-flag override is required.

The adapter uses `/v1/decisions/stream`, not repeated downloads from
`/v1/decisions`. Initial synchronization, reconnects, and staged client
replacement request a full `startup=true` snapshot; ordinary polls use
`startup=false` and consume incremental additions and deletions. This avoids
repeatedly downloading large external blocklists, which may contain around
100,000 IPs/CIDRs. There is no periodic full-snapshot polling workaround.

The upstream query-error issue is an explicitly accepted temporary risk,
documented below; it does not block support for this server release.

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

The reviewed behavior is defined by the v1.8.1
[database stream queries](https://github.com/crowdsecurity/crowdsec/blob/v1.8.1/pkg/database/decisions.go),
[SDK request options](https://github.com/crowdsecurity/crowdsec/blob/v1.8.1/pkg/apiclient/decisions_service.go),
and [stream controller](https://github.com/crowdsecurity/crowdsec/blob/v1.8.1/pkg/apiserver/controllers/v1/decisions.go).
The pinned real-LAPI gate verifies all decision IDs with `dedup=false`,
incremental updates without replaying the active snapshot, overlapping-ID
deletion, reconnect, and valid authoritative emptiness.

**Accepted upstream risk.**
[crowdsecurity/crowdsec#4691](https://github.com/crowdsecurity/crowdsec/issues/4691)
tracks a database query failure that can produce HTTP 200 with a valid-looking
empty or incomplete stream envelope. Envelope validation cannot distinguish
that response from successful data. A startup or reconnect snapshot may
therefore replace CrowdSec authority with an incomplete or empty set; restoring
all omitted decisions may require a later full synchronization. Static global
and geo policy are not replaced by CrowdSec snapshots.

This risk is deliberately accepted because CrowdSec is an additional protection
layer. Perimeterd proceeds under the normal stream
contract while the issue is addressed upstream. Do not add a database-fault
regression for this condition, block current-server support on it, downgrade
the server, or substitute repeated full-list downloads. The compatibility
gate deliberately excludes this condition; it does not claim it is fixed.
Malformed-response validation, explicit HTTP-error handling, local expiry,
and renewable lease protections remain unchanged.

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
- lowercase `new` and `deleted` each occur exactly once and each value is either
  an array or JSON `null` (null is normalized to an empty array); missing,
  duplicate, malformed, or other-typed required fields are errors. Case variants
  such as `New` and `Deleted` are also errors, not ignored extensions, because
  the SDK's case-insensitive decoder could use them to overwrite validated
  fields; and
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
`net/netip`, rejects malformed decisions and zone-qualified (scoped) addresses,
requires an LAPI decision ID, and stores an absolute expiry. Scope rejection
precedes canonicalization so converting to a prefix cannot silently broaden
authority. An LAPI-provided absolute expiry is authoritative and retained
exactly; pair it with a local monotonic deadline for scheduling.
If the API supplies only a valid duration `d`, capture wall-clock and monotonic
instants at request start, `(wall_start, mono_start)`, and derive the
conservative deadline as `wall_start + d - 1s`, paired with
`mono_start + d - 1s`. Request-start anchoring charges request/response latency;
the one-second cushion covers the API's duration rounding. Consequently a
duration-only decision can expire locally up to the request age plus that
cushion early, in addition to native timeout quantization.

Mapped IPv4 source addresses, such as `::ffff:198.51.100.77`, are canonicalized
to IPv4 `/32` authority. A source CIDR wholly within the mapped `/96` becomes
the equivalent IPv4 network (`::ffff:198.51.101.129/120` becomes
`198.51.101.0/24`). Broader IPv6 ranges and the 128-bit IPv6 residual ranges
produced by overlap projection retain their IPv6 family.

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

### Ephemeral backend inputs

The durable `Target` contains static packet-path state and the identity of the
owned dynamic containers (`DynamicGeneration`), not CrowdSec decisions,
deadlines, or authority. The current timed projection is an ephemeral
`DynamicState` passed at one writer boundary:

| Backend operation | Dynamic input | Meaning |
| --- | --- | --- |
| `Preflight` | selected projection | Admission and capacity/ownership checks only; it does not authorize a later write. |
| `Apply` for static refresh or recovery | `nil` | Selects static state while preserving existing dynamic leases. It must not renew or replay a captured projection. |
| `Apply` for activation/replacement | selected projection, including explicit empty | Installs or replaces dynamic authority; an empty projection clears dynamic leases. |
| `UpdateDynamic` | current projection | Reconciles already-owned dynamic containers without rebuilding static generations. |

An explicit empty projection clears entries from the selected dynamic containers;
`nil` alone is not an instruction to clear them. Disabling CrowdSec instead
selects a target without `DynamicGeneration` and retires its dynamic containers.
Each non-`nil` projection is validated, but never serialized as durable authority.
Recovery preserves surviving leases until a fresh activation or dynamic update.

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

Both current backends use `u = 1s`: ipset accepts integer-second timeouts, and
the nftables JSON API requires integer seconds for timed elements. Sub-second
positive lifetimes are omitted rather than encoded as a zero/permanent lease.

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
Failed dynamic writes explicitly wake this scheduler when scheduling a retry,
including when the active decision store is empty and has no expiry or renewal
timer. A reconnect whose new-snapshot write and compensation both fail must not
leave recovery dependent on another decision or expiry event.

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

The writer derives the complete current projection from the authoritative store
and passes it to the backend. The backend reconciles its owned dynamic IPv4 and
IPv6 sets without rebuilding static global or geo sets. Incremental LAPI events
do not imply that every native write is an element-by-element delta.

If a dynamic write fails or may have been partially applied, inspect the current
owned dynamic sets and reconcile them to the latest timed `P(D)`. Do not replay
an obsolete event or assume an earlier batch was wholly unapplied. Fold later
events and expiry into the next projection, including deadline changes as well
as membership changes. A failed deletion remains pending until the unwanted
element is gone; a failed addition retains its authoritative decision. Runtime
write failure sets enforcement health to zero until current-state reconciliation
succeeds. Native expiry remains effective even while a static transaction's
degraded recovery blocks dynamic mutations.

## CrowdSec availability, endpoint changes, and secrets

CrowdSec is optional. When enabled, the credential file must be readable and
usable; initial authentication, authoritative `startup=true` synchronization,
projection, and backend activation must succeed before readiness. A later
disconnect marks the integration unhealthy but retains valid decisions and
finite leases while expiry and projection reconciliation continue. Reconnect
uses a full snapshot with bounded backoff. See [operations](operations.md) for
credential-file modes and observability.

Credential replacement, endpoint replacement, and disabling the integration
follow [staged reload](architecture.md#staged-reload):

- Authenticate each replacement and obtain a separate full `startup=true`
  snapshot before promotion.
- Keep the old client, store, expiry processing, and enforcement authoritative
  until the durable configuration commit promotes the new epoch.
- Pause the old poller at a batch boundary while staging a replacement; never
  poll one LAPI cursor concurrently from two clients.
- If staging fails, resume the old client with a full synchronization rather
  than assuming its incremental cursor remains valid.

At the writer boundary, an endpoint change uses only the new endpoint's
snapshot; it never unions decisions from different endpoints. Disabling
CrowdSec omits dynamic generation so target migration retires the old dynamic
containers. Where a dynamic generation remains selected, an explicit empty
projection clears its leases; `nil` preserves them. [Architecture](architecture.md)
owns the journal commit point, compensation, and crash recovery. Old resources
are retired only after durable commit; failed compensation enters degraded
recovery rather than claiming that old enforcement survived untouched. A
precommit restart restores the prior static selection and re-synchronizes its
configured LAPI before readiness. These source changes do not commit outside
the enclosing configuration transaction.

The API key comes from `crowdsec.api_key_file`; its value must never appear in
examples, logs, metrics, process arguments, error wrapping, or diagnostics.
Logs omit complete prefix lists and metrics use bounded source/result labels.
CrowdSec decisions are not persisted as secrets or authority across restart:
startup performs a new authoritative snapshot and reconciliation.


## Source failure matrix

The following failure behavior is implemented for both static source kinds.

### RIPEstat and cache (implemented)

| Required cache missing and RIPEstat unavailable | First start fails before firewall mutation and readiness. An active daemon keeps its committed manifest and enforcement and retries. |
| Malformed, partial, status-failed, or identity-mismatched RIPEstat response | Reject the whole candidate. An active daemon reports the refresh failure without replacing its committed manifest. |
| Corrupt staged objects or orphaned/uncommitted manifests | Ignore them and fetch or use a complete valid committed manifest. First start fails if a complete candidate cannot be built. |
| Corrupt objects referenced by recovery state | Do not silently substitute a newly fetched generation. Recovery validates the journal and committed references before admitting work; missing recovery evidence requires repair as specified in [architecture](architecture.md#durable-apply-and-crash-recovery). |
| Initial backend application failure | Withhold readiness and perform backend-specific compensation; preserve recovery evidence if it fails. |

### Custom HTTP(S) lists

| Failure | Required behavior |
| --- | --- |
| Invalid line, empty body, failed status, timeout, redirect violation, or decoded-size overflow | Reject the complete candidate; retain the committed manifest and enforcement, report failure, and retry on schedule. |
| New list or changed URL cannot resolve | Fail first-start readiness or reject the reload; never reuse the old endpoint under the new identity. |
| Required list is stale and unavailable at restart | Use only a valid complete committed fallback that covers every required identity and compiles; otherwise withhold readiness without applying partial policy. |
| List result succeeds but compilation, apply, or durable publication fails | Do not independently publish list cache selection; use the existing writer compensation/recovery rules. |

### Named provider failures

| Failure | Required behavior |
| --- | --- |
| Provider ID has unsafe syntax | Reject offline, without network access. |
| New syntactically valid ID returns 404 or invalid content | Fail runtime resolution and first-start readiness, or reject the reload; never omit the selector or treat it as empty. |
| Previously committed provider returns 404, 5xx, or invalid content | Fail the refresh, keep the complete committed snapshot and its timestamps, and retry; only exact-identity complete fallback is eligible on restart/reload. |
| One provider succeeds while another required source fails | Do not publish a partial candidate or independently advance cache selection. |

### CrowdSec integration

| Failure | Required behavior |
| --- | --- |
| CrowdSec key missing or unreadable | Fail first-start readiness. A reload is rejected and its active client remains. |
| Initial CrowdSec authentication or authoritative snapshot failure | Fail first-start readiness before applying a candidate. |
| Credential/endpoint replacement or disable failure | Keep the old configuration committed, resume its synchronization, and compensate any partial apply. Failed compensation reports degraded enforcement. |
| Later CrowdSec outage or reconnect snapshot failure | Mark the integration unhealthy, retain unexpired decisions until local expiry, and retry the full authoritative synchronization. |
| CrowdSec backend delta failure | Recompute the current `P(D)` projection from the authoritative store, queue that reconciliation, and retry idempotently. |

## Lookup source attribution

The [lookup command](operations.md#ipcidr-lookup) explains
the sources used by the running applied revision without fetching,
refreshing, discovering, or enriching any feed. Source membership is not a
verdict; the compiled rule order and the
[applied-state query view](architecture.md#applied-state-query-view) determine
which evidence actually contributes to a decision.

### Static provenance

Load/use only the exact manifest selected by that revision, not the newest file
or any unreferenced historical cache object. Its selector records retain
normalized country/ASN, `ip_list`, and `provider` identities, prefixes, retrieval
times, and source-format identity. Their union in a compiled policy set does
not replace this per-selector evidence. The distinct `ip_list` and `provider`
namespaces remain distinct even when names or prefixes coincide.

Use the selected policy's include/exclude references to connect leaf membership
to a policy. Group and RIR attribution additionally identifies the configured
group/region and matching expanded country; it is an expansion path, not a
separate upstream geolocation result. Use the membership expansion associated
with the selected view, never a separately updated catalog. Disabled or
unreferenced sources are not queried, and missing evidence is not proof that
an address belongs to no country or provider.

Report all relevant overlapping memberships and their include/exclude roles,
not an arbitrary first match. An exclusion can change the effective policy set
without becoming a global allow. A global allow or earlier stage can shadow
matching source-backed policies. An allowlist miss is explained as absence from
the effective include-minus-exclude set, not as a fabricated blocking source.
For globals, identify the effective global allow/block entry and known built-in
membership; do not claim an entry was operator-supplied when normalization has
erased that distinction.

Attribution identifies retained normalized ranges, not original TXT line numbers
or a byte-for-byte upstream record. Country evidence still means allocation or
registration country, not physical location. Provider evidence still means
membership in that feed, not proof of endpoint ownership. Display source
kind/name and retrieval time without exposing potentially secret-bearing URLs.
Lookup requires no additional cache schema change or raw-response retention;
version-1/2/3 recovery compatibility remains intact.

### CrowdSec provenance

Retain in-memory decision evidence with the acknowledged applied projection:
decision ID, normalized prefix, absolute decision expiry, client epoch, and
effective native lease evidence. Identify all contributing overlapping IDs;
neither maximum-expiry projection nor `/0` backend lowering may arbitrarily
collapse attribution to one ID. Keep decision expiry distinct from the
renewable kernel lease. When a desired deletion or update has not yet applied,
explain the acknowledged state, not the newer desired store.

CrowdSec attribution in this feature means the source kind and retained decision
identity/deadlines. The client currently discards upstream `origin`, `scenario`,
and similar descriptive fields; detailed scenario attribution is not promised
and must not be inferred from an ID or prefix. Adding that metadata would
require a separate retention contract, not a lookup-time LAPI request.
Do not persist live decisions as recovery or offline-query authority. After a
restart, lookup requires freshly synchronized, successfully applied dynamic
evidence under the normal startup contract.
