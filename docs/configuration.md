# Configuration

> **Schema and policy reference.** Offline validation and the source-build
> runtime support the fields below, including `ip_lists`, dynamic `providers`,
> and [optional OpenZiti transport](#optional-openziti-configuration). Check the
> [implementation plan](implementation-plan.md) and
> [current runtime instructions](operations.md#current-source-build-runtime)
> before using a configuration for enforcement.

This document owns the version 1 YAML schema, defaults, local validation, and
policy semantics. Start with the annotated configuration and field table;
policy rules, evaluation, and examples follow. [Data sources](data-sources.md)
owns external resolution and compatibility; [firewall backends](firewall-backends.md)
owns the kernel realization.

The CLI default configuration path is `/etc/perimeterd/perimeterd.yaml`;
`--config PATH` overrides it for `run` and `validate`. A source build does not
install that path. The planned package uses it as its configuration location.
The runtime defaults state and prefix caches to `/var/lib/perimeterd` and
creates missing directories when invoked as root. Parsing accepts exactly one
YAML document. Each schema-defined mapping rejects unknown and duplicate
fields; `groups`, `ip_lists`, and `openziti.identities` intentionally use
user-defined names as mapping keys. Scalar types are checked without coercion,
and `version` must be exactly `1`. Explicit nulls, aliases, and merge keys are
rejected rather than silently defaulted or expanded.

## Contents

- [Document and fragment forms](#document-and-fragment-forms)
- [Fully annotated configuration](#fully-annotated-configuration)
- [Canonical field and default table](#canonical-field-and-default-table)
- [Global address lists](#global-address-lists)
- [Custom IP lists](#custom-ip-lists)
- [Named providers](#named-providers)
- [Optional OpenZiti configuration](#optional-openziti-configuration)
- [Policy schema](#policy-schema)
- [Evaluation semantics](#evaluation-semantics)
- [Empty desired state](#empty-desired-state)
- [Global list example](#global-list-example)
- [Policy examples](#policy-examples)
- [Validation phases](#validation-phases)

## Document and fragment forms

The block in [Fully annotated configuration](#fully-annotated-configuration)
is one complete YAML document. `configs/perimeterd.yaml` is another complete
example. Every later YAML block in this document is a root-level fragment.
Fragments can be merged at the shown top-level key before running
`perimeterd validate`; a fragment is not a standalone configuration.

## Fully annotated configuration

Omitted optional fields take the defaults shown here. `version` and
`firewall.backend` are required even when their displayed values are used.
The displayed `crowdsec.api_key_file` path is an example, not a default.
Custom-list definitions and include/exclude usage are shown in the
[custom list example](#custom-list-example).
Named-provider include/exclude usage is shown in the
[provider example](#named-provider-example).

```yaml
version: 1

logging:
  level: info                 # debug, info, warn, error
  format: json                # json or text

metrics:
  listen: 127.0.0.1:2112      # empty string disables the listener

global:
  allowlist: []               # local ranges are always included
  blocklist: []               # direct IP/CIDR denies

firewall:
  backend: nftables           # required: nftables or iptables
  deny_action: drop           # drop or reject
  ipv4: true
  ipv6: true
  nftables:
    table: perimeterd
    priority: -10
  iptables:
    attachments:
      - chain: INPUT
        direction: ingress
      - chain: OUTPUT
        direction: egress

geo:
  refresh_interval: 24h
  request_timeout: 30s
  refresh_jitter: 10m

groups: {}

ip_lists: {}

providers:
  refresh_interval: 24h
  request_timeout: 30s

policies: []

crowdsec:
  enabled: false
  lapi_url: http://127.0.0.1:8080
  api_key_file: /etc/perimeterd/credentials.d/crowdsec_api_key
  update_frequency: 10s
```

`geo` uses RIPEstat as the only version 1 provider and has no configurable
provider field; [data sources](data-sources.md) owns its endpoints, snapshots,
and compatibility contract. `crowdsec.lapi_url` is an independent absolute
HTTP or HTTPS URL; HTTP is permitted for a local LAPI. CrowdSec requires the
supported remote deployment described below.

## Canonical field and default table

A dash means required with no default. Backend-specific sections may coexist
and are always validated; only the selected backend is applied.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `version` | int | — | Required; exactly `1` |
| `logging.level` | text | `info` | `debug`, `info`, `warn`, `error` |
| `logging.format` | text | `json` | `json` or `text` |
| `metrics.listen` | text | `127.0.0.1:2112` | Host:port; empty disables |
| `global.allowlist` | address list | `[]` | Additional allows |
| `global.blocklist` | address list | `[]` | Direct denies |
| `firewall.backend` | text | — | Required; nftables or iptables |
| `firewall.deny_action` | text | `drop` | `drop` or `reject` |
| `firewall.ipv4` | bool | `true` | Enable IPv4 |
| `firewall.ipv6` | bool | `true` | Enable IPv6 |
| `firewall.nftables.table` | text | `perimeterd` | Table name |
| `firewall.nftables.priority` | int | `-10` | Filter hook priority; `-199` through `2147483647` inclusive |
| `firewall.iptables.attachments` | list | `INPUT`/ingress and `OUTPUT`/egress when omitted | Parent jumps |
| `attachments[].chain` | text | — | Required parent chain |
| `attachments[].direction` | text | — | Ingress or egress |
| `attachments[].input_interfaces` | list | `[]` | Input matches |
| `attachments[].output_interfaces` | list | `[]` | Output matches |
| `attachments[].original_destination` | bool | `false` | Pre-DNAT ports |
| `geo.refresh_interval` | duration | `24h` | Positive |
| `geo.request_timeout` | duration | `30s` | Positive, per request |
| `geo.refresh_jitter` | duration | `10m` | Positive upper delay |
| `groups` | map | `{}` | Lowercase name to countries |
| `ip_lists` | map | `{}` | List name to HTTP(S) text source |
| `ip_lists.<name>.url` | URL | — | Required absolute HTTP(S) URL |
| `ip_lists.<name>.refresh_interval` | duration | `24h` | Positive per-list interval |
| `ip_lists.<name>.request_timeout` | duration | `30s` | Positive timeout for a complete fetch |
| `ip_lists.<name>.transport` | map | direct | Optional [transport binding](#optional-openziti-configuration) |
| `providers.refresh_interval` | duration | `24h` | Positive interval shared by named-provider sources |
| `providers.request_timeout` | duration | `30s` | Positive timeout for a complete provider fetch |
| `policies` | list | `[]` | Policy declarations, ordered by direction and priority |
| `crowdsec.enabled` | bool | `false` | Enable the supported LAPI stream integration |
| `crowdsec.lapi_url` | URL | `http://127.0.0.1:8080` | Absolute HTTP(S) LAPI URL |
| `crowdsec.api_key_file` | path | none | Required by schema when enabled |
| `crowdsec.update_frequency` | duration | `10s` | Positive |
| `crowdsec.transport` | map | direct | Optional [transport binding](#optional-openziti-configuration) |
| `openziti.identities` | map | `{}` | Named enrolled identity-file profiles; [fields below](#optional-openziti-configuration) |

`metrics.listen` must parse as one host:port. The loopback default avoids
accidental unauthenticated exposure; a non-empty listener that cannot bind
prevents readiness. All duration fields use Go duration syntax and must be
strictly positive.

Defaults apply only when a key is omitted. Valid explicit values are retained:
for example, `metrics.listen: ""` disables the listener, `firewall.ipv4: false`
and `firewall.ipv6: false` disable those families, and an explicit nftables
priority of `0` remains `0`. An explicit `attachments: []` clears the
attachment default, while an explicit empty selector member list is rejected;
an empty selector mapping is discussed in [Selectors](#selectors). An explicit
empty configured global list contributes no configured entries (the effective
allowlist still adds immutable local ranges).
While CrowdSec is disabled, `api_key_file: ""` is equivalent to omission; when
enabled, the schema requires a non-empty path.

The `crowdsec` block is accepted by offline schema validation and runtime
enforcement. Enabling it also requires the operator-verified
[supported LAPI contract](data-sources.md#supported-lapi-contract).
Neither local validation nor a successful API call can attest that remote
deployment meets that prerequisite.

### iptables attachments

Omitting `firewall.iptables.attachments` retains the default `INPUT`/ingress
and `OUTPUT`/egress attachments. An explicit `attachments: []` is accepted by
offline validation for either backend and means no managed attachment jumps; it
does not restore the defaults. The list is unused when nftables is selected.
For iptables, a non-empty runtime target requires at least one attachment, and
local validation does not attest that the configured policy has a packet path.
The [runtime attachment contract](firewall-backends.md#iptables-attachment-contract)
defines the enforcement requirement.

Local validation treats `INPUT` and `OUTPUT` as host parents. Every other parent
requires a non-empty `input_interfaces` list for ingress or `output_interfaces`
list for egress; this conservatively covers custom chains without inferring
their topology. Interface lists are sorted and deduplicated before identical
attachments are collapsed. Parent-chain existence and ownership are checked
only during runtime reconciliation, not by `validate`.

### nftables hook priority

The priority must be a signed 32-bit integer strictly greater than `-200`.
Local validation rejects `-200` and lower values, even when iptables is selected.
Changing a valid priority uses the backend's
[same-table priority reload](firewall-backends.md#same-table-priority-reload);
this setting never changes iptables parent-chain ordering.

**Rationale:** OUTPUT conntrack lookup occurs at priority `-200`, and the
NEW-flow guard must run afterward. Equal priorities have no guaranteed order;
raw priority `-300` is therefore invalid too. See
[Netfilter hook ordering](https://wiki.nftables.org/wiki-nftables/index.php/Netfilter_hooks).

## Global address lists

`global.allowlist` and `global.blocklist` accept IP addresses and CIDRs. A bare
IPv4 or IPv6 address is normalized to a `/32` or `/128`. CIDRs are masked to
their canonical network; duplicates and ranges contained by a broader range
are removed. Malformed addresses are configuration errors. These lists require
no external source resolution.

Zero-length prefixes (`0.0.0.0/0` and `::/0`) are valid. The logical model keeps
them canonical; the [ipset backend](firewall-backends.md#iptables-and-ipset)
lowers them into representable entries without changing precedence.

The effective global allowlist is the union of configured entries and these
built-in local ranges:

- `10.0.0.0/8`, `172.16.0.0/12`, and `192.168.0.0/16`;
- `127.0.0.0/8` and `169.254.0.0/16`; and
- `::1/128`, `fe80::/10`, and `fc00::/7`.

Built-in entries cannot be removed in version 1. This guarantees that private,
loopback, link-local, and IPv6 unique-local traffic cannot be denied by a
global block, CrowdSec decision, or geo policy. Configured allowlist entries
extend this protection, for example with an operator's public home address.

Both lists apply to ingress source addresses and egress destination addresses,
independent of protocol or port. Global allowlist matches win over every
perimeterd denial source, including overlapping global blocklist entries.
Global blocklist matches then deny before CrowdSec and geo policy, using
`firewall.deny_action`. An allowlist return is not a global firewall `ACCEPT`;
rules owned by other managers may still deny it.
As with every perimeterd policy, list changes affect new flows and do not
terminate established connections.

## Custom IP lists

`ip_lists` is a top-level map of reusable text-list sources. Names follow the
same lowercase DNS-label-like syntax as policy names and occupy a separate
namespace from `groups`. Each definition accepts only `url`, `refresh_interval`,
`request_timeout`, and optional [transport](#optional-openziti-configuration);
defaults are listed above. Definitions are validated even when unreferenced. An omitted or
empty `ip_lists` map defines no sources.

`url` must be an absolute `http` or `https` URL with a host, no user information,
and no fragment. Query strings are permitted; file paths and other schemes are
not. HTTPS is recommended; HTTP deliberately provides no transport authenticity
or confidentiality. There are no custom authentication, header, or TLS-bypass
fields. Offline validation checks URL syntax and references without fetching
content, resolving DNS, or checking availability.

Policies reference names through the separate `ip_lists` selector category in
both `include` and `exclude`. Every referenced name must exist, including in
disabled policies. An explicitly empty `ip_lists: []` selector is invalid,
matching other selector categories. A list referenced several times is resolved
once per candidate; unused definitions and references only in disabled policies
cause no network requests.

Each source serves plain text with one IPv4/IPv6 address or CIDR per line.
See [the source contract](data-sources.md#custom-https-ip-lists) for
normalization, blank/comment lines, invalid or empty responses, and cache
fallback. `refresh_interval` is independent for each list and is not controlled
by `geo.refresh_interval` or `geo.refresh_jitter`.

### Custom list example

This root-level fragment illustrates both selector positions and mixed
country/list policy using the supplied
[Zoom IP feed](https://cdn.jsdelivr.net/gh/rezmoss/cloud-provider-ip-addresses@main/zoom/zoom_ips.txt):

```yaml
ip_lists:
  zoom:
    url: https://cdn.jsdelivr.net/gh/rezmoss/cloud-provider-ip-addresses@main/zoom/zoom_ips.txt
    refresh_interval: 6h
    request_timeout: 30s

policies:
  - name: zoom-egress
    priority: 100
    direction: egress
    mode: allowlist
    traffic: ["any"]
    include:
      ip_lists: [zoom]
  - name: ingress-except-zoom
    priority: 100
    direction: ingress
    mode: blocklist
    traffic: ["any"]
    include:
      countries: [US]
    exclude:
      ip_lists: [zoom]
```

**Expected:** the egress policy permits listed destinations
at the policy stage and denies other geo-eligible destinations. The ingress
policy denies US prefixes minus the Zoom list; exclusion is subtraction from
this policy, not a global allow overriding CrowdSec or global blocks. Existing
established-flow, local-range, and surrounding-firewall behavior remains intact.
The public feed is an illustrative operator-selected dependency, not a pinned
or endorsed perimeterd source.

## Named providers

`include.providers` and `exclude.providers` refer directly to provider IDs from
[`rezmoss/cloud-provider-ip-addresses`](https://github.com/rezmoss/cloud-provider-ip-addresses).
No top-level per-provider definitions, `ip_lists` entries, embedded catalog, or
release-pinned provider membership are required. New upstream provider IDs work
without a perimeterd release once their feeds are available.

The optional top-level `providers` mapping accepts only `refresh_interval` and
`request_timeout`, both positive durations. It controls this source type as a
whole, independently of `geo` and custom-list timings. Omission or `{}` uses the
defaults in the field table. There are no per-provider overrides, URL/ref
settings, or additional jitter setting in this initial contract. Use `ip_lists`
for an explicitly selected alternate endpoint or pinned revision.

Provider IDs are literal, case-sensitive upstream slugs matching
`^[a-z0-9_-]+$`: non-empty lowercase ASCII letters, digits, hyphens, and
underscores. Do not derive IDs from display names or substitute aliases.
Reject whitespace, uppercase letters, dots, slashes, backslashes, percent
escapes, and URL/ref/query syntax rather than allowing path construction to
escape the fixed endpoint template. Underscores are valid, unlike custom-list
names; for example, `apple_private_relay` is a provider ID.

Offline `validate` checks syntax, scalar types, positive durations, and non-empty
selector lists; it **does not check remote existence**. A syntactically valid but
nonexistent ID therefore passes offline validation and fails runtime resolution.
Disabled policies have the same local checks but cause no provider requests;
their IDs are checked for existence when enabled.

Resolution fetches the required provider's merged TXT file dynamically, using
the [jsDelivr `@main` contract](data-sources.md#named-provider-feeds).
A failed or invalid response is a runtime source error, never an empty set or
an ignored selector. A new unknown provider has no matching committed fallback:
it prevents first-start readiness or rejects a reload before applying policy.
An existing active revision is not discarded on resolution failure; exact
identity and complete-snapshot fallback rules are owned by the
[provider source contract](data-sources.md#provider-identity-refresh-and-fallback).

Repeated IDs are deduplicated, and only providers referenced by enabled policies
are resolved. `providers: [aws]` and `ip_lists: [aws]` are distinct selectors;
neither shadows the other. Provider sets use the same family-aware union and
subtraction as other categories, including cross-category exclusions. They do
not extend global allow/block lists or bypass address classification, global
allow precedence, CrowdSec, or established-flow handling.

### Named provider example

```yaml
providers:
  refresh_interval: 6h
  request_timeout: 30s

policies:
  - name: selected-providers
    priority: 100
    direction: ingress
    mode: blocklist
    traffic: ["any"]
    include:
      providers: [aws, alibaba]
    exclude:
      providers: [datadog]
```

**Expected:** block new ingress flows whose source is in
`(AWS union Alibaba) minus Datadog`, subject to the existing classifier and
precedence rules. Provider sets may overlap; an exclusion is subtraction, not a
global allow. Each ID represents the entire published provider address set, not
a service/region filter or authenticated provider identity.

## Optional OpenZiti configuration

These additive version-1 fields opt individual upstreams into private-service
connections. Existing configurations keep direct HTTP(S) behavior without an OpenZiti installation,
identity file, environment setting, or extra enable/disable switch.

The top-level `openziti.identities` map defines reusable named identity
profiles. Only `ip_lists.<name>.transport` and `crowdsec.transport` select this
transport. There is no global default that reroutes other sources.

| Field | Type | Default | Meaning |
| --- | --- | --- | --- |
| `openziti.identities` | map | `{}` | Profile names use the same syntax as policy names |
| `openziti.identities.<name>.identity_file` | path | none | Required absolute path to an externally enrolled SDK identity configuration |
| `ip_lists.<name>.transport.type` | enum | `direct` | `direct` or `openziti`; omission of the transport mapping also means direct |
| `crowdsec.transport.type` | enum | `direct` | Same selection, active only when CrowdSec is enabled |
| `transport.identity` | text | none | Required named identity profile for `openziti`; forbidden for `direct` |
| `transport.service` | text | none | Required exact, case-sensitive, non-blank Ziti service name for `openziti`; forbidden for `direct` |

Unknown/duplicate keys, invalid types, explicit nulls, unsupported transport
types, and missing profile references fail offline validation. All definitions
are checked even when unused or CrowdSec is disabled; profile files are not read
until an active upstream needs them. `{}` is the direct transport default, not
an implicit opt-in inferred from identity/service fields. A defined profile
alone performs no enrollment, authentication, or connectivity check.

Offline validation checks paths and reference syntax only. It does not open
identity/key files, resolve names, contact controllers, attest permissions or
service availability, or satisfy posture requirements. Runtime supports
pre-enrolled, noninteractive certificate identities with embedded PEM or local
PEM-file references. Referenced paths resolve relative to the identity file's
directory, never the process working directory. Interactive login/MFA,
external-token acquisition, enrollment commands, HSM/plugin configuration, and
credential-file rotation by the daemon are outside this initial feature.

URLs remain ordinary absolute HTTP(S) URLs under their existing validation.
`service` selects the connection destination; URL host/port still define
application authority and HTTPS verification. [Transport rules](data-sources.md#service-binding-and-http-safety)
and [saved cache identity](data-sources.md#transport-identity-and-saved-evidence)
define routing and persisted evidence. There is no `ziti://` URL,
implicit hostname-to-service mapping, TLS verification bypass, or replacement
for `crowdsec.api_key_file`. Existing request/refresh timeouts remain authoritative;
there is no independent retry budget that can extend them.

### Mixed-transport example

This root-level fragment leaves one list direct while sharing one Ziti
identity between a private list and LAPI. The service names are independently
provisioned; the illustrative `.internal` names need not resolve on the host,
but their HTTPS certificates must verify against the normal trust store.
An enabled policy activates its referenced lists' transports; an enabled
CrowdSec client activates its own transport.

```yaml
openziti:
  identities:
    private-sources:
      identity_file: /etc/perimeterd/credentials.d/openziti/private-sources.json

ip_lists:
  public-feed:
    url: https://example.org/public-ips.txt
    # transport omitted: ordinary HTTP(S), with no Ziti dependency
  private-feed:
    url: https://feeds.internal/blocked-ips.txt
    refresh_interval: 6h
    request_timeout: 30s
    transport:
      type: openziti
      identity: private-sources
      service: perimeterd-private-feeds

crowdsec:
  enabled: true
  lapi_url: https://lapi.internal:8080
  api_key_file: /etc/perimeterd/credentials.d/crowdsec_api_key
  transport:
    type: openziti
    identity: private-sources
    service: perimeterd-lapi

policies:
  - name: feed-ingress
    priority: 100
    direction: ingress
    mode: blocklist
    traffic: ["any"]
    include:
      ip_lists: [public-feed, private-feed]
```

An omitted/empty `openziti.identities` map is valid for direct-only deployments.
An unreferenced profile or list and a disabled CrowdSec client cause no identity
file access or SDK activity. See [architecture](architecture.md#optional-openziti-upstream-transport)
for selected-resource ownership and [operations](operations.md#openziti-operations)
for provisioning, secret handling, and rotation.

## Policy schema

Each policy accepts exactly these keys:

| Field | Required | Validation |
| --- | --- | --- |
| `name` | yes | Unique lowercase DNS-label-like identifier |
| `priority` | yes | Unique non-negative integer per direction; lower first |
| `direction` | yes | `ingress` or `egress` |
| `mode` | yes | `allowlist`, `blocklist`, or `disabled` |
| `traffic` | yes | Non-empty traffic list described below |
| `include` | yes | Selector mapping; enabled policy is locally non-empty and resolves at runtime |
| `exclude` | no | Selector mapping subtracted from include |

A policy name starts and ends with an ASCII lowercase alphanumeric character
and may contain lowercase alphanumerics or hyphens. Duplicate names are always
invalid. Priorities order policies independently within each direction.
Duplicate priorities in one direction are invalid even when the traffic scopes
do not overlap; the same number may appear once for ingress and once for
egress. There is no declaration-order, name, or backend-specific tie-breaker.
The validation error identifies the direction, duplicate priority, and both
policy names.

### Traffic

`traffic` is a non-empty list of quoted strings. Each entry is exactly one of:

- `"N"` or `"N-M"` for a TCP port or inclusive TCP port range;
- `"N/tcp"`, `"N-M/tcp"`, `"N/udp"`, or `"N-M/udp"` for an explicit
  transport protocol;
- `"icmp"` for every ICMPv4 type and code;
- `"icmpv6"` for every ICMPv6 type and code; or
- `"any"` for every IP protocol in both address families.

Ports are decimal `1` through `65535`. YAML integers, whitespace, uppercase or
unknown protocols, zero, empty or reversed ranges, and non-decimal values are
errors. Parsing removes duplicates and merges overlapping or adjacent ranges
independently for TCP and UDP. ICMP type/code selection is not supported in
version 1. `"icmp"` and `"icmpv6"` may be combined with TCP or UDP entries;
each applies only to its corresponding address family. `"any"` must be the
only list entry.

### Selectors

`include` and `exclude` each accept these optional list fields:

- `countries`: ISO-3166-1 alpha-2 codes, case-insensitive on input and
  normalized to uppercase;
- `rirs`: `AFRINIC`, `APNIC`, `ARIN`, `LACNIC`, or `RIPE`;
- `groups`: built-in or configured group names;
- `asns`: strings in canonical `AS<number>` form for unsigned 32-bit values
  `AS0` through `AS4294967295`; leading zeroes are not accepted;
- `ip_lists`: names defined by the top-level `ip_lists` map;
- `providers`: dynamically resolved upstream provider IDs, with no
  embedded catalog or user-defined source entry.

Unknown countries, RIRs, groups, list names, malformed ASNs, and explicitly
present empty category lists are errors. An empty selector mapping is allowed for `exclude`
and for a disabled policy's `include`; an enabled policy must have a non-empty
`include` and must resolve to at least one prefix overall before firewall
mutation.
Provider IDs are the exception to local membership checks: their syntax is
validated offline, but existence requires runtime resolution as described above.

Union selectors within and across categories, then subtract exclusions
independently for each address family. An excluded prefix wins over every
include:

```text
effective_v4 = union(include_v4) - union(exclude_v4)
effective_v6 = union(include_v6) - union(exclude_v6)
```

Custom groups map one unique lowercase DNS-label-like name to a non-empty list
of valid country codes. They cannot shadow built-ins.

The regional built-ins `africa`, `asia`, `europe`, and `oceania` follow
[UN M49 regions](https://unstats.un.org/unsd/methodology/m49/). The Americas
are split along the UN subdivisions into `northern-america` and
`latin-america-caribbean`; there is no `americas` alias.

The institutional built-ins are `european-union`, sourced from the
[EU member list](https://european-union.europa.eu/principles-countries-history/eu-countries_en);
`schengen-area`, sourced from the
[European Commission](https://home-affairs.ec.europa.eu/policies/schengen/schengen-area_en);
and `nato`, sourced from
[NATO's published membership](https://www.nato.int/en/about-us/organization/nato-member-countries).
The derived `euro-atlantic` group is exactly the union of `european-union`,
`schengen-area`, and `nato`; it is computed from those memberships rather than
maintained as a separate country list. Exact memberships and source revisions
are embedded in the binary and change only in a release.

Threat, sanctions, and geopolitical-adversary sets are intentionally not
built-ins because their membership depends on an operator's jurisdiction and
risk model. Define them as custom groups with an explicit country list.

RIR selectors use embedded service-region country memberships and resolve
those countries through the same RIPEstat country endpoint. Their names are
case-insensitive on input and normalized uppercase.

If an enabled policy resolves prefixes overall but a selected address family
has none, a blocklist is a no-op for that family; an allowlist denies every
globally routable address in that family. This fail-closed allowlist behavior
is intentional and must be reviewed when enabling both families.

These same rules apply to custom-list-only and mixed-source policies. Custom
lists do not extend `global.allowlist` or `global.blocklist` and do not bypass
the [geo address classifier](#geo-address-classification). The existing term
“geo policy” denotes this policy stage even when all its selectors are custom
lists. Exclusions subtract from the union of every include category, not just
from lists; removing all effective prefixes rejects an enabled policy.
Provider selectors obey these same rules, including when all
selectors in a policy are providers.

### Disabled policy

`mode: disabled` is an explicit none/reset state. The policy name, priority,
direction, traffic, and selector syntax remain locally validated, but selectors
are not fetched or resolved and the policy emits no rules or sets. A disabled
policy therefore continues to reserve its priority within its direction, so
enabling it cannot silently reorder another policy. Removing the policy has the
same firewall result for that policy. Other policies and enabled CrowdSec
artifacts remain.

## Evaluation semantics

The ordering below is the contract for static policy and the enabled CrowdSec
stage on both native backends.

The [IP/CIDR lookup](operations.md#ipcidr-lookup) explains these
same semantics using the daemon's applied revision. It introduces no YAML fields
and is not an offline evaluation of the file currently on disk.

1. `ESTABLISHED,RELATED` traffic returns before all perimeterd denial rules.
2. Traffic that is not a new conntrack flow returns.
3. A remote address in the effective global allowlist returns before every
   perimeterd denial source.
4. A remote address in the global blocklist is denied.
5. On new ingress, a matching CrowdSec decision is denied.
6. Remaining non-global remote addresses bypass geo policy and return.
7. Geo policies for the packet direction are considered by ascending priority.
8. The first policy whose L4 traffic scope matches fully decides the geo result:
   - blocklist: deny when the remote address is in `effective`; otherwise
     return to the surrounding firewall;
   - allowlist: return when the remote address is in `effective`; otherwise
     deny.
9. If no traffic scope matches, return without a verdict.

Ingress compares the source address; egress compares the destination address.
A return is never a global `ACCEPT`. Rules owned by firewalld, ufw, Docker, or
an administrator continue after perimeterd returns.

Geo policy applies only to new conntrack flows and geo-eligible unicast remote
addresses, defined exactly below. References to globally routable or global
addresses in geo examples mean this classification, not a live routing lookup.
CrowdSec may deny any explicitly banned valid IP or CIDR not present in the
effective global allowlist.
Established traffic returns first, preserving
replies to host-originated connections in ingress and replies to accepted
inbound connections in egress.

### Geo address classification

The version 1 classifier is a compiled-in prefix policy, identical in both
backends. It is not Go's `Addr.IsGlobalUnicast`, an operating-system route
lookup, or an inference from presence in a RIPEstat result. It does not prove
that a route is currently announced.

The following tables are the normative baseline, reviewed against the IANA
[IPv4](https://www.iana.org/assignments/iana-ipv4-special-registry/iana-ipv4-special-registry-1.csv)
and [IPv6](https://www.iana.org/assignments/iana-ipv6-special-registry/iana-ipv6-special-registry-1.csv)
special-purpose registries on 2026-09-07. They deliberately exclude deprecated
or indeterminate-reachability assignments as well as non-global assignments.

For IPv4, start with `0.0.0.0/0`, remove the following prefixes, then restore
the two exact exceptions listed in the final row:

| Classification | Prefixes |
| --- | --- |
| Unspecified/this-network | `0.0.0.0/8` |
| Private | `10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16` |
| Shared address space | `100.64.0.0/10` |
| Loopback and link-local | `127.0.0.0/8`, `169.254.0.0/16` |
| IETF protocol assignments | `192.0.0.0/24` |
| Documentation | `192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24` |
| Deprecated relay assignment | `192.88.99.0/24` |
| Benchmarking | `198.18.0.0/15` |
| Multicast and reserved, including limited broadcast | `224.0.0.0/4`, `240.0.0.0/4` |
| Restore as geo-eligible | `192.0.0.9/32`, `192.0.0.10/32` |

For IPv6, start only with `2000::/3` and `64:ff9b::/96`. Remove the following
prefixes from that union, then restore the listed exceptions:

| Classification | Prefixes |
| --- | --- |
| IETF protocol assignments, including Teredo | `2001::/23` |
| Documentation | `2001:db8::/32`, `3fff::/20` |
| Indeterminate-reachability 6to4 | `2002::/16` |
| Restore as geo-eligible | `2001:1::1/128`, `2001:1::2/128`, `2001:1::3/128`, `2001:3::/32`, `2001:4:112::/48`, `2001:20::/28`, `2001:30::/28` |

Every IPv6 address outside the initial union is non-eligible. This excludes
unspecified, loopback, IPv4-mapped, local-use translation, discard-only, dummy,
SRv6 SID, unique-local, link-local, multicast, and other reserved space without
relying on a library's evolving classification. The restored exceptions are
more specific than their excluded parent; backend prefix compaction must not
erase those holes.

This classifier is consulted only after global allow, global block, and enabled
ingress CrowdSec checks. Exclusion from geo policy is not
an unconditional allow: a configured global block or CrowdSec ban can still
deny non-eligible space unless the effective global allowlist protects it.

Changes to these tables require an explicit reviewed release change with the
registry snapshot date, boundary/exception checks, and release notes. The
daemon never refreshes them from the network; an IANA or Go library update
cannot silently change enforcement. Newly allocated IPv6 space outside the
initial union requires such a release before geo policy applies there.

## Empty desired state

The no-artifacts predicate is: no enabled geo policies, an empty normalized
`global.blocklist`, and `crowdsec.enabled: false`. Disabled policies do not
prevent this state. When it holds, reconciliation removes all owned firewall
artifacts, including allow-only rules and accounting objects, through the
normal journaled apply/cleanup path. Configured and built-in allows alone do
not require a firewall path.

Disabling CrowdSec retires its owned dynamic containers; configured static
policy remains unless the no-artifacts predicate also holds. This is separate
from clearing a currently enabled CrowdSec decision store; see the
[dynamic authority contract](data-sources.md#ephemeral-backend-inputs).

An empty policy list does not suppress a remaining global block. When CrowdSec
is enabled, keep its dynamic path even when its current decision store is empty.
Do not infer the no-artifacts state from a temporarily empty source response or
from allows shadowing configured denies.

When the no-artifacts predicate is false, compilation requires at least one
enabled address family. Disabling both `firewall.ipv4` and `firewall.ipv6` does
not silently turn requested enforcement into the canonical empty state; the
compiler returns an error. This is separate from local YAML validation.

## Global list example

```yaml
global:
  allowlist:
    - 198.51.100.24/32
  blocklist:
    - 203.0.113.77
```

**Expected:** the configured home address and all built-in local ranges return
before global blocks, CrowdSec, or geo policy. The offensive address is
normalized to `203.0.113.77/32` and denied on new ingress and egress flows
before CrowdSec or geo evaluation. If an address matches both lists, allowlist
wins. The documentation addresses are illustrative and must be replaced.

## Policy examples

Except for the complete document above, every fenced YAML block here is a
root-level fragment. A block containing `policies:` supplies that top-level
list; blocks containing `groups:` or `crowdsec:` likewise supply root keys.
Combine a fragment with the complete schema before validation.

### Five-country all-port egress allowlist

```yaml
policies:
  - name: approved-egress
    priority: 100
    direction: egress
    mode: allowlist
    traffic: ["any"]
    include:
      countries: [CA, DE, FR, GB, US]
```

**Expected:** a new globally routed egress flow returns only when its
destination is allocated to one of the five countries; all other global
destinations are denied. Non-global and established flows return.

### Euro-Atlantic all-port egress allowlist

```yaml
policies:
  - name: euro-atlantic-egress
    priority: 100
    direction: egress
    mode: allowlist
    traffic: ["any"]
    include:
      groups: [euro-atlantic]
```

**Expected:** a new globally routed egress flow returns only when its
destination belongs to the union of the embedded EU, Schengen, and NATO
memberships. Other global destinations are denied; non-global and established
flows return.

### Operator-defined restricted origins

```yaml
groups:
  restricted-origins: [BY, CN, IR, KP, RU]

policies:
  - name: restricted-ingress
    priority: 100
    direction: ingress
    mode: blocklist
    traffic: ["any"]
    include:
      groups: [restricted-origins]
```

**Expected:** new globally routed ingress from the five operator-selected
countries is denied. The name carries no built-in membership or special
semantics; changing the threat model requires changing the explicit country
list.

### SSH ingress allowlist for one country

```yaml
policies:
  - name: ssh-admin
    priority: 10
    direction: ingress
    mode: allowlist
    traffic: ["22"]
    include:
      countries: [CH]
```

**Expected:** new TCP/22 from a Swiss prefix returns; the same traffic from
another global prefix is denied. Other ports do not match this policy.

### Web TCP and QUIC blocklist

```yaml
policies:
  - name: blocked-web-origins
    priority: 20
    direction: ingress
    mode: blocklist
    traffic: ["80", "443", "443/udp"]
    include:
      countries: [KP, SY]
```

**Expected:** new TCP/80, TCP/443, and UDP/443 from either selected country are
denied; other sources and traffic return.

### Asia excluding Japan

```yaml
policies:
  - name: asia-web
    priority: 20
    direction: ingress
    mode: blocklist
    traffic: ["80", "443", "443/udp"]
    include:
      groups: [asia]
    exclude:
      countries: [JP]
```

**Expected:** matching web traffic from Asia is denied except Japanese
prefixes, which return to the surrounding firewall.

### APNIC and ASN selectors

```yaml
policies:
  - name: apnic-or-example-asn
    priority: 30
    direction: egress
    mode: blocklist
    traffic: ["any"]
    include:
      rirs: [APNIC]
      asns: [AS64496]
```

**Expected:** a new egress flow to any prefix in the APNIC service-region union
or currently announced by `AS64496` is denied. The ASN is illustrative; a real
deployment must choose an intended ASN.

### Custom NATO-partners group

```yaml
groups:
  nato-partners: [AU, JP, KR, NZ]

policies:
  - name: partner-egress
    priority: 100
    direction: egress
    mode: allowlist
    traffic: ["any"]
    include:
      groups: [nato, nato-partners]
```

**Expected:** new globally routed egress returns for embedded NATO members and
the four configured partner countries; other global destinations are denied.

### Disable only SSH while retaining web and CrowdSec
This requires the [supported LAPI deployment](data-sources.md#supported-lapi-contract).

Before:

```yaml
policies:
  - name: ssh-admin
    priority: 10
    direction: ingress
    mode: allowlist
    traffic: ["22"]
    include:
      countries: [CH]
  - name: web-blocks
    priority: 20
    direction: ingress
    mode: blocklist
    traffic: ["80", "443"]
    include:
      countries: [KP]

crowdsec:
  enabled: true
  lapi_url: http://127.0.0.1:8080
  api_key_file: /etc/perimeterd/credentials.d/crowdsec_api_key
  update_frequency: 10s
```

After, either retain the entry with `mode: disabled` or remove only the entire
`ssh-admin` entry:

```yaml
policies:
  - name: ssh-admin
    priority: 10
    direction: ingress
    mode: disabled
    traffic: ["22"]
    include:
      countries: [CH]
  - name: web-blocks
    priority: 20
    direction: ingress
    mode: blocklist
    traffic: ["80", "443"]
    include:
      countries: [KP]

crowdsec:
  enabled: true
  lapi_url: http://127.0.0.1:8080
  api_key_file: /etc/perimeterd/credentials.d/crowdsec_api_key
  update_frequency: 10s
```

**Expected:** the SSH policy's owned static artifacts disappear. `web-blocks`
and all unexpired CrowdSec dynamic entries remain. Removing the `ssh-admin`
entry instead produces the same policy-scoped cleanup.

### Narrow override before a broad direction default

```yaml
policies:
  - name: ssh-override
    priority: 10
    direction: ingress
    mode: allowlist
    traffic: ["22"]
    include:
      countries: [CH]
  - name: ingress-default
    priority: 100
    direction: ingress
    mode: blocklist
    traffic: ["any"]
    include:
      groups: [asia]
```

**Expected:** TCP/22 is decided entirely by `ssh-override`; an Asian source
cannot fall through to `ingress-default` after matching that scope. Every other
new ingress protocol/port reaches the broad priority-100 policy.

## Validation phases

`perimeterd validate` reads the selected YAML file and performs strict decoding
of one document, defaulting, field/value checks, local group expansion, policy
syntax checks, and uniqueness checks. It does not read credential files,
resolve external selectors or source prefixes, contact services, bind metrics,
verify parent chains, or mutate a firewall. Success therefore means that the
document is accepted by offline schema validation; remote source availability,
credential usability, and runtime firewall prerequisites remain unverified.

`run` acquires lifecycle ownership and recovers durable state before reading
the current YAML, so invalid current YAML does not prevent recovery from being
attempted. After loading the document, runtime staging resolves enabled
selectors from the RIPEstat/cache path, compiles the policy against a complete
snapshot, requires every enabled policy to resolve to a non-empty prefix set
overall, binds the metrics listener, verifies configured parent chains for a
non-empty target, and stages then applies a backend reconcile. Reload repeats
this full staging path; initial readiness additionally requires the decision
projection to be applied and its durable active revision committed.

The runtime supports RIPEstat-backed country/ASN policy and CrowdSec ingress
bans on both nftables and iptables/ipset. CrowdSec enablement additionally
requires the operator-verified remote deployment prerequisite. A configuration with
both `firewall.ipv4: false` and `firewall.ipv6: false` is locally valid when
it requests no artifacts, but runtime compilation rejects it when enforcement
is requested. See [architecture](architecture.md) for freshness, commit,
rollback, and recovery.
