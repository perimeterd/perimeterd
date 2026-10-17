# Operations

This document owns operator procedures, process startup/shutdown, service
integration, observability, and package lifecycle. [Configuration](configuration.md)
owns YAML fields and policy semantics; [data sources](data-sources.md) owns
upstream wire, cache/fallback, and transport contracts; [architecture](architecture.md)
owns revision admission, durable commit, and recovery; [firewall backends](firewall-backends.md)
owns native kernel behavior.

> **Status boundary.** The runtime capabilities below are available to source
> builds and packaged installations. Building from source does not install the
> systemd unit or tmpfiles payload. Feature availability is separate from release
> qualification; see the [README](../README.md) and
> [development release workflow](development.md#release-workflow). A local
> package build alone is not release qualification.

## Contents

- Runtime and service
  - [Runtime capabilities](#runtime-capabilities)
  - [Source-build prerequisites](#source-build-prerequisites)
  - [Build, validate, and run from source](#build-validate-and-run-from-source)
  - [Operator sequence](#operator-sequence)
    - [Prerequisites](#prerequisites)
    - [Configure and validate](#configure-and-validate)
    - [Start and check health](#start-and-check-health)
    - [Reload, recover, and cleanup](#reload-recover-and-cleanup)
  - [Supported CrowdSec LAPI prerequisite](#supported-crowdsec-lapi-prerequisite)
  - [Lifecycle lock and recovery](#lifecycle-lock-and-recovery)
- Upstream operations
  - [Custom IP list operations](#custom-ip-list-operations)
  - [Named provider operations](#named-provider-operations)
  - [OpenZiti operations](#openziti-operations)
- [IP/CIDR lookup](#ipcidr-lookup)
- [Daemon status](#daemon-status)
- Installed service and observability
  - [Installed layout](#installed-layout)
  - [systemd service contract](#systemd-service-contract)
  - [Prometheus metrics](#prometheus-metrics)
  - [Logging](#logging)
- [Packages](#packages)
  - [Package lifecycle](#package-lifecycle)

## Runtime capabilities

The runtime supports:

- strict offline `validate` and `version` commands;
- `run` and `cleanup` under one process-lifetime ownership lock;
- acknowledged `reload` through the running daemon's private Unix socket;
- nftables and iptables/ipset policy application, including both legacy and
  nf_tables iptables tool families;
- direct global lists, DB-IP Lite country snapshots (or explicit RIPEstat), and
  independent RIPEstat ASN data, with local RIR and group country expansion;
- reusable HTTP(S) custom IP-list sources and dynamically resolved named-provider
  feeds, with immutable snapshots, refresh, and cache fallback;
- selected per-upstream OpenZiti transport for custom lists and CrowdSec;
- durable revision/journal recovery, backend and target migration, and custom
  iptables attachments;
- CrowdSec ingress bans with authoritative synchronization, expiry, renewable
  kernel leases, and staged credential/endpoint replacement;
- explicit Docker `DOCKER-USER` bridge attachments with pre-DNAT port matching;
- read-only IP/CIDR lookup with source explanations;
- read-only daemon status with applied-policy metadata and loaded-data counts;
- backend-owned native processed and terminal-denial counters; and
- the [Prometheus metrics](#prometheus-metrics) surface, collected in memory.

Docker coexistence is verified for Docker Engine 29.8.1's iptables bridge
backend with both iptables tool families and IPv4/IPv6. Docker's native nftables
backend, rootless networking, and Swarm are outside that verified scope.
See the [Docker attachment contract](firewall-backends.md#docker-docker-user-attachment).
`configs/perimeterd.yaml` includes an unreferenced custom-list source, which
causes no request until an enabled policy references it. Provider feeds likewise
resolve only for enabled policy references; see the [source contracts](data-sources.md).

### Source-build prerequisites

Build with the Go version declared in [`go.mod`](../go.mod), then run the daemon
on Linux as root. Use a disposable VM or isolated network namespace; never test
policy against the development host's firewall.

Install the native tools for the selected backend before `run`:

- nftables: `nft` in `PATH`;
- iptables: `iptables`, `ip6tables`, `iptables-save`, `ip6tables-save`,
  `iptables-restore`, `ip6tables-restore`, and `ipset` in `PATH`.

The iptables commands must all report the same implementation (`legacy` or
`nf_tables`) and the IPv4/IPv6 pair must match. A missing or mixed family or
variant is an error; perimeterd does not auto-detect a replacement or silently
fall back. Configured iptables parent chains must already exist. The backend
also uses the host-wide xtables lock for restore operations; do not substitute a
private lock. See the [attachment contract](firewall-backends.md#iptables-attachment-contract).

Keep the selected command alternatives unchanged while perimeterd-owned
iptables artifacts remain. To switch between legacy and nf_tables, first stop
the daemon and run cleanup with the original tools, then change the alternatives
and reconcile again; never change `PATH` underneath recorded ownership.

For Docker bridge filtering, start Docker and its bridge network first. Select
perimeterd's iptables backend and the same iptables tool family Docker uses.
`DOCKER-USER` must already exist for every enabled family. Constrain the ingress
attachment to external input interfaces and enable `original_destination` when
policy ports refer to published host ports rather than translated container
ports. Perimeterd does not create Docker chains, permit services on behalf of
Docker, or watch Docker lifecycle events. Preserve its tagged jumps when another
manager edits the parent chain.

Enabled country, RIR, or group policies need direct HTTPS access to
`download.db-ip.com` by default, or RIPEstat when explicitly selected. ASN
selectors always need RIPEstat. First resolution needs complete matching evidence;
an acceptable committed snapshot can cover it under the normal fallback rules.
Enabled custom lists/providers likewise need their endpoints unless matching
committed snapshots cover all required sources.
Installations with no enabled source-backed selectors and
`crowdsec.enabled: false` make no source requests.

### Build, validate, and run from source

Build the source tree, then validate and run the same complete configuration.
`run` and `validate` accept `--config PATH`; when omitted, both use
`/etc/perimeterd/perimeterd.yaml`. The source build does not create that path.

```sh
make build
CONFIG=/etc/perimeterd/perimeterd.yaml
sudo bin/perimeterd validate --config "$CONFIG"
sudo bin/perimeterd run --config "$CONFIG"
```

`validate` is local-only and does not require root; this example uses `sudo`
because the configuration is kept root-readable only. It does not resolve
selectors, read credentials, contact DB-IP, RIPEstat, or CrowdSec, bind the metrics
listener, or touch firewall state. Success establishes local schema and
semantic validity, not runtime readiness. See
[configuration validation phases](configuration.md#validation-phases) for the
complete validation/runtime boundary. Only `run` synchronizes and enforces
source-backed or CrowdSec decisions.

`make build` also writes Bash completion to `bin/completions/perimeterd`.
For a source build, load it into the current Bash session:

```bash
source bin/completions/perimeterd
```

Completion offers commands, their options, configuration paths, and enumerated
lookup values. It does not contact the daemon, read configuration or credentials,
or access the network or firewall.

The default persistent paths are `/var/lib/perimeterd` for revisions, journals,
and immutable prefix snapshots, and `/run/perimeterd/owner.lock` for the
lifecycle lock. Invoked as root, the runtime creates missing directories. Do
not delete either path, its records, or the lock inode to bypass recovery or
ownership checks. A committed static policy remains in the kernel after a
normal stop. CrowdSec entries retain only their remaining finite kernel lease;
without the daemon, they can expire before the original decision deadline.

After successful startup recovery, while holding the lifecycle lock and before
staging new policy, perimeterd removes unreferenced revision files and leftover
revision publication temp files under `/var/lib/perimeterd/revisions/`. The active
revision is retained; collection does not run while a journal is pending.
Unknown filenames are left untouched, and an unsafe matching file or cleanup
error prevents startup rather than risking removal of recovery evidence.
Collection runs on restart, not periodically while the service is running.

Source-backed candidates use immutable, content-addressed manifests under
`/var/lib/perimeterd/prefixes/`; the committed revision selects its manifest.
Do not edit these files or choose one by modification time. Startup validates
referenced cache evidence before mutating the firewall. Unreferenced cache
files are collected only after startup recovery or explicit cleanup, not while
source workers may be staging candidates.

Country/ASN refresh uses `geo.refresh_interval` (default `24h`) plus jitter up to
`geo.refresh_jitter` (default `10m`). Each attempt defaults to `30s`, covering slot
admission, download, and parse; at most four source requests are in flight and
512 selectors are accepted. DB-IP country work is one coherent batch for every
required country whenever any is due/missing/mismatched. Monthly artifact release
and retrieval time are different: refresh can replace bytes from the same month.
Unacceptable data or source/native/durable capacity rejection leaves the committed
policy and provenance unchanged. Failed refreshes retry on the normal schedule;
provider changes and newly introduced countries require matching fresh evidence.

### Country-provider upgrades and outages

Newly parsed YAML, including old files with no provider key, defaults to DB-IP
geographic country classification. To retain RIPEstat allocation/registration
country behavior, add `geo.country_provider: ripestat` before upgrading/reloading.
Country groups and RIR selections follow that choice; ASN remains RIPEstat.
Historical committed configurations with no field recover as RIPEstat without
rewriting immutable bytes. They may remain enforced after a failed switch, but
status/lookup must keep their actual RIPEstat provenance.

First DB-IP activation needs a complete validated country batch. There is no
silent RIPE fallback, current-month-to-previous-month fallback is allowed only
for HTTP 404, and committed releases never move backward. Same-provider restart
fallback requires complete valid coverage; a new provider/missing country cannot
reuse incompatible evidence. Do not confuse this with binary rollback: older
binaries cannot read new DB-IP commits. Never delete durable state to force a
downgrade. See [configuration upgrades](configuration.md#country-provider-upgrades)
and [source selection](data-sources.md#db-ip-lite-country-default).

DB-IP's finer boundaries can exceed existing capacity fences. In the
[measured real-data envelope](development.md#db-ip-lite-real-data-validation),
EU data activated/recovered on iptables but an additional retained generation
was rejected; a RIPE-region-plus-US policy exceeded native/durable limits.
Review large group/RIR deployments before changing provider. Rejection is not
permission to truncate data, widen ranges, or remove recovery evidence.

Encoded-state and native-input limits are safety fences, not tuning knobs.
Admission accounts for the candidate and required retained state; rejection
before execution performs no native writes. Do not interpret every later
execution failure as unchanged enforcement: partial or ambiguous results follow
the backend's compensation and recovery contract. See
[firewall backends](firewall-backends.md) and
[durable admission](architecture.md#durable-apply-and-crash-recovery).

## Custom IP list operations

Define reusable HTTP(S) sources under `ip_lists`, with a per-list
`refresh_interval`, and reference names from policy include/exclude selectors.
The [configuration example](configuration.md#custom-list-example) and
[source contract](data-sources.md#custom-https-ip-lists) own the schema,
text format, HTTP safeguards, and complete-snapshot refresh/fallback behavior.

Prefer HTTPS and review the publisher's coverage before use, especially an
IPv4-only list in a dual-stack allowlist. Lists inherit policy classification
and precedence; an exclude is not a global bypass. Refreshes change only new
flows. No custom list is fetched unless an enabled policy references it.
Ensure the daemon can still reach the feed and DNS under any egress policy.
Custom lists do not automatically allow their own HTTP(S) endpoints through the
firewall; retain the necessary outbound access using existing policy controls.

Reload URL, interval, and reference changes with `perimeterd reload`; a rejected
pre-apply reload retains the old configuration and its timers. With no matching committed
fallback, an unavailable required list prevents first-start readiness or rejects
a reload. Later outages retain the entire committed static snapshot and retry
on schedule; stale entries have no automatic expiry. Removing/disabling a
policy, not serving an empty file, is the deliberate removal mechanism.
Monitor source age and refresh errors, not enforcement health alone.

List definitions may point to private servers reachable by the daemon.
Plain HTTP trusts that network path as well as the publisher. Do not use URLs
as secret storage: their identity is retained in root-only durable state, while
logs should identify lists by name and omit URLs and query strings.

## Named provider operations

Use provider IDs directly in
`include.providers`/`exclude.providers`; no `ip_lists` declaration or compiled-in
provider list is needed. See the [example](configuration.md#named-provider-example)
and [source contract](data-sources.md#named-provider-feeds).

Offline validation verifies ID syntax, not remote membership. A typo that is
syntactically valid can therefore pass `validate` but fail startup/reload when
the corresponding jsDelivr `@main` merged TXT URL is fetched. Disabled policies
do not contact the CDN; their IDs are checked remotely only when enabled. A new
missing provider fails activation, never becoming an empty or ignored selector.

Only providers used by enabled policies are fetched, with source-wide refresh
and request timeout settings. Keep DNS and HTTPS access to jsDelivr and any
permitted redirect destinations available under restrictive egress policy;
there is no automatic firewall bypass for the daemon's own source requests.

A later 404, CDN outage, malformed response, or upstream removal fails refresh
but retains complete committed enforcement. Exact-identity complete fallback is
also eligible on restart/reload; it does not reset source age. Monitor refresh
errors and committed retrieval age, not just enforcement health. CDN caching
can delay newly published IDs and changed feeds; no purge or original-provider
freshness guarantee is implied. Do not remove exclusions to work around a
missing feed without considering the resulting policy expansion.

## OpenZiti operations

The [transport fields](configuration.md#optional-openziti-configuration) opt in
per upstream. Direct-only deployments remain unchanged: no Ziti installation,
identity, controller, or additional daemon is required. There is no host-wide opt-in.

For each opted-in LAPI or custom list:

1. Provision a Ziti network and host the application as a service, using an
   SDK-enabled server or a hosting tunneler/proxy/router that can reach it.
   Perimeterd is the client, not that hosting component.
2. Enroll a dedicated noninteractive machine identity externally and authorize
   it to dial only the required services. Configure suitable identity/router and
   service/router policies. Required posture checks must be satisfiable without
   an operator prompt; interactive MFA/login is not part of daemon startup.
3. Install the enrolled identity JSON and any referenced PEM files locally.
   Identity JSON and private keys must be root-owned regular files with no
   group/other permissions (`0600` or `0400`); protect their directories from
   non-root writes. Every path component must be free of symlinks. Public
   certificate/CA files may be readable by others, but must not be executable or
   group/other-writable. Enrollment JWTs are not runtime identities.
4. Keep ordinary outbound connectivity to advertised controller and edge-router
   endpoints, including their DNS dependencies, available from the host.
   No client-side Ziti tunneler, TUN interface, or private-application route is
   required. Perimeterd's own egress policy can still break authentication,
   reconnect, or later router selection; there is no automatic allow-rule bypass.
5. Configure each upstream's identity profile and exact service name, separately
   from its HTTP(S) URL. Service hosting must deliver the corresponding application
   protocol/port. Keep HTTPS hostname validation and normal OS trust; install
   an application CA in that trust store when needed. The identity's controller
   CA does not automatically authenticate an HTTPS list server or LAPI.
6. Keep the normal CrowdSec API key and
   [supported LAPI deployment contract](data-sources.md#supported-lapi-contract).
   Overlay access grants connectivity, not application authentication.

`validate` remains offline and cannot verify identity files, authorization,
posture, controller/router reachability, service hosting, or application TLS.
At runtime those checks apply only to active Ziti references. Unreferenced
profiles/lists and disabled CrowdSec must not cause identity-file reads or
connections. No automatic enrollment, direct fallback, interactive sign-in,
or SDK installation step is allowed.

Rotate identities by provisioning and validating replacements externally,
then replacing their files safely and running `perimeterd reload`. Capture one complete
credential bundle, including referenced files; avoid replacing only half of a
certificate/key pair. Prefer a new directory/profile when coordinating multiple
files. A same-path replacement is still a new loaded generation when certificate,
trust, or network identity changes. It requires new-route static evidence and,
for CrowdSec, a new authoritative snapshot before selection. A failed reload
keeps the previous loaded generation; file replacement alone does not hot-swap
it. Plan an overlap window before revoking/expiring the old identity.

Later network/service failures use the existing source contracts: static
snapshots remain enforced and age visibly, while CrowdSec decisions and kernel
leases expire normally. A complete exact-identity static cache may support
offline fallback, but does not authorize borrowing data from a different
transport/identity. Referenced local credentials must still be loadable for
activation. Recovery of saved firewall state and explicit `cleanup` remain local.
Check source errors/freshness and CrowdSec connectivity separately from
enforcement health; SDK connectivity is not proof of current enforcement.

Treat SDK logs and diagnostics as secret-bearing input. Do not log enrolled
JSON, private keys, tokens, or unrestricted SDK debug dumps. The integration
sanitizes errors and excludes credential material from durable source evidence.
Active OpenZiti profiles reject `DEBUG` or `SWAGGER_DEBUG` values other than
unset, `false`, or `0`: OpenAPI wire dumps bypass SDK logrus controls and can
contain authentication responses. Use perimeterd's `logging.level` instead.
Metrics-disabled operation and `lookup` remain independent of SDK availability.

The pinned, unmodified SDK has a
[cancellation/cleanup limitation](data-sources.md#sdk-cancellation-limitation):
perimeterd's caller deadlines and shutdown remain bounded, but some SDK discovery
or authentication work may continue after cancellation or context closure.
Eight outstanding SDK dials exhaust application admission until a call returns;
subsequent Ziti requests then time out without direct fallback. Repeated failed
activations can also leave SDK-internal discovery workers. Restore underlay
connectivity and, if necessary, perform a controlled daemon restart; do not
discard durable enforcement or credentials to bypass recovery.

## Daemon status

```sh
sudo bin/perimeterd status
sudo bin/perimeterd status --json
```

`status` reports the running daemon's last coherently acknowledged applied
state through `GET /v1/status` on `/run/perimeterd/control.sock`. It requires
root, uses the existing private socket permissions, and bounds a round trip
to five seconds. It works with `metrics.listen: ""`; it does not parse the
current YAML, read durable state as an offline fallback, contact sources, or
inspect the kernel firewall. After upgrading from a binary without this
endpoint or with an older status schema, restart the upgraded daemon;
configuration reload cannot upgrade a running process. Incompatible
daemon/client schemas fail explicitly, never as misleading empty counts.

The report includes the running daemon version, uptime and runtime health,
revision/configuration epoch and source manifest when present, firewall
backend/families/deny action, policy names/priorities/directions/modes/traffic
scopes, iptables attachments, loaded source counts, static compiled set
memberships, and acknowledged CrowdSec metadata. Disabled policies are labeled
`mode=disabled`. No source URLs, credentials, full configuration, or individual
prefixes are included.

Text uptime uses compact elapsed days, hours, minutes, and seconds, omitting
zero-valued units: `1260` seconds appears as `uptime=21m`, and `90061` seconds
as `uptime=1d1h1m1s`. Zero uptime is `0s`. JSON keeps
`daemon.uptime_seconds` as an integer number of seconds for scripts.

Applied state is explicit:

- `applied`: one coherent acknowledged revision is available;
- `empty`: no managed enforcement is applied, confirmed by the writer;
- `unavailable`: startup/recovery, an in-flight mutation, or uncertainty prevents
  a coherent answer. It is not an empty policy.

Rejected reloads that retain the old applied view continue to report its
revision. Native transitions invalidate the view; status never mixes generations.
A coherent revision can coexist with degraded runtime health. The report is
an as-of daemon acknowledgement, not an independent audit of kernel rules or
a guarantee of end-to-end reachability.

Loaded source counts reuse Prometheus's family/source/type semantics: unique prefix
elements within each label combination and enabled family, including built-in
local ranges. They are not counts of unique protected addresses, packets or
bytes. There is no grand total across overlapping categories. Native packet
and byte statistics remain on the [Prometheus surface](#prometheus-metrics).

**Compiled firewall sets** is a separate static-only summary of the last
acknowledged target. Each row reports the prefix count of one logical set,
after compilation/normalization, and each enabled family has a membership
total. Equal policy memberships share one row per family, with sorted
`policies` consumers derived from actual rule references. The representative
`geo/<name>` identifies the data object, not its sole policy. Empty consumers
print as `policies=-`. Different family memberships may share differently.
Distinct, overlapping sets still contribute separately; global/internal sets
are not merged into policy sets. `geo_eligible` remains included, and
`global_allowlist` includes built-in local ranges. Present zero-count static sets
and zero family totals remain visible; disabled families and absent sets are
not invented.

These totals reveal repeated memberships, not a count of duplicates or unique
addresses. They are not native interval markers, ipset allocation sizes, memory
usage, retained old/new generation totals, or a kernel audit. This logical
counting is the same for nftables and both iptables frontends. Dynamic CrowdSec
sets are excluded entirely: empty persisted prefixes do not mean there are no
live decisions. Normalized live CrowdSec native-element counts are not reported.

CrowdSec counts include unexpired decisions from the last acknowledged dynamic
write for enabled families, not newer fetched decisions awaiting application
or unique addresses. Its `epoch`, `operation`, and `valid_until` identify that
acknowledgement. `validity` is `disabled`, `valid`, `stale`, or `unknown`; counts
are omitted unless valid. An expired validity deadline means stale, never zero.
An acknowledged empty write can be valid with zero counts and no deadline.

Human-readable reports and JSON go to stdout, including degraded/unavailable
reports. Operational errors go to stderr; an unreachable daemon produces no
report and never falls back to disk.

| Exit | Meaning |
| --- | --- |
| `0` | Healthy coherent report, including confirmed empty enforcement |
| `1` | Degraded/unavailable state, stale/unknown enabled CrowdSec state, transport/protocol failure, or output failure |
| `2` | Invalid command usage |

Example source/compiled excerpt with explicitly selected RIPEstat country mode,
identical ingress/egress country sets, and a distinct SSH selection:

```text
Loaded source prefix elements (per family/source/type; not unique IPs or packet counts):
  family=ipv4 source=global type=allowlist count=1
  family=ipv4 source=global type=blocklist count=1
  family=ipv4 source=local type=local count=5
  family=ipv4 source=ripestat type=country count=4
  family=ipv6 source=global type=allowlist count=1
  family=ipv6 source=global type=blocklist count=1
  family=ipv6 source=local type=local count=3
  family=ipv6 source=ripestat type=country count=5
Compiled firewall sets (static target memberships; shared sets counted once; not a kernel audit):
  family=ipv4 set=geo/egress policies=egress,ingress count=3
  family=ipv4 set=geo/ssh policies=ssh count=1
  family=ipv4 set=geo_eligible policies=- count=118
  family=ipv4 set=global_allowlist policies=- count=6
  family=ipv4 set=global_blocklist policies=- count=1
  family=ipv4 total_memberships=129
  family=ipv6 set=geo/egress policies=egress,ingress count=3
  family=ipv6 set=geo/ssh policies=ssh count=2
  family=ipv6 set=geo_eligible policies=- count=53
  family=ipv6 set=global_allowlist policies=- count=4
  family=ipv6 set=global_blocklist policies=- count=1
  family=ipv6 total_memberships=63
  Dynamic CrowdSec memberships excluded; decision counts reported separately.
```

JSON retains full identifiers and uses `schema_version: 4`. Applied details
include deterministic `sources` rows (`provider`, optional `release`, oldest
`retrieved_at` per provider/release) and require
`compiled_sets.sets` rows (`family`, `id`, unsigned `count`, sorted unique
`policies`) and `compiled_sets.totals` rows (`family`, unsigned `count`).
Consumer arrays must be present even when empty. Collections are non-null
arrays; each present family has one total, even when zero. Empty or
unavailable applied states retain their existing absence of details.
Historical unshared revisions show their actual separate rows until a new
shared representation commits. Migration and failed-reload recovery use the
ordinary journal protocol; do not delete state to force sharing.
For example, inspect source provenance and all three count concepts without parsing text labels:

```sh
sudo bin/perimeterd status --json |
  jq '{state: .applied.state, revision: .applied.revision,
       firewall: .applied.details.firewall,
       sources: .applied.details.sources,
       prefix_counts: .applied.details.prefix_counts,
       compiled_sets: .applied.details.compiled_sets,
       crowdsec: .applied.details.crowdsec}'
```

## IP/CIDR lookup

Lookup explains perimeterd's applied policy and contributing sources, not
end-to-end reachability. It is read-only and requires the running daemon.
The [architecture](architecture.md#read-only-lookup-and-explanation)
owns coherent state publication, transport, security, and resource bounds.

### Query input and scope

`lookup` is available in packaged and source-built binaries. It queries the
running daemon; it does not compile the current YAML or contact sources itself.

```text
perimeterd lookup IP_OR_CIDR
    [--direction ingress|egress]
    [--protocol tcp|udp|icmp|other]
    [--port 0..65535]
    [--json]
```

Examples:

```sh
sudo bin/perimeterd lookup 8.8.8.8
sudo bin/perimeterd lookup 8.8.8.8 --direction ingress --protocol tcp --port 443
sudo bin/perimeterd lookup 8.8.8.0/24 --direction ingress --protocol tcp --port 443
sudo bin/perimeterd lookup 2001:4860:4860::8888 --json
```

- Accept exactly one IPv4/IPv6 address or CIDR, never a hostname or URL.
  Normalize addresses to host prefixes and mask CIDR host bits; display the
  canonical queried prefix so its full scope is explicit. Reject malformed,
  zone-qualified, and IPv4-mapped IPv6 input rather than guess its family.
- Omitted direction summarizes both ingress and egress. Omitted protocol or
  port summarizes all corresponding traffic scopes; supplying a port requires
  an explicit `tcp` or `udp` protocol. `icmp` is family-appropriate ICMP;
  `other` means protocols outside TCP, UDP, and ICMP.
- Evaluate **new conntrack flows**. Existing established/related and other
  non-new flows bypass denial under the existing
  [evaluation semantics](configuration.md#evaluation-semantics); lookup does
  not inspect conntrack or test an existing connection.
- Ingress treats the supplied address as the remote source; egress treats it
  as the remote destination. The port is the destination port as seen by each
  reported attachment: original destination when configured, translated/current
  destination otherwise. Always identify that basis and any interface
  constraints. Do not infer routes, matching interfaces, or a DNAT mapping from
  an address. Outcomes are conditional on traversal of the named managed path,
  not proof that a specific host/container packet reaches it.
- CIDR results cover the entire queried prefix. Split differing address ranges
  and traffic/attachment scopes, including uncovered portions, rather than
  treat any match as full coverage. Disabled families and directions without
  owned enforcement are explicitly not managed, not missing output.

No `--config`, offline mode, or source refresh is part of this command. Editing
YAML without an accepted reload cannot change its answer. Lookup uses the
running owner's shared control socket at `/run/perimeterd/control.sock`,
independently of whether metrics are enabled.

### Lookup results and errors

The implemented command uses these verdicts in both human and JSON output:

| Verdict | Meaning |
| --- | --- |
| `blocked` | Every requested address/traffic scope is denied by perimeterd on the reported managed paths; outcomes identify DROP or REJECT. |
| `not_blocked` | No requested scope is denied by perimeterd; distinguish explicit global allow, policy pass, classifier bypass, no matching policy, and not-managed scope. |
| `mixed` | Some requested addresses or traffic/attachment scopes are blocked and others are not; list the complete partition rather than choose a default port or direction. |
| `unknown` | The daemon cannot provide a coherent, complete applied-state answer; this is never an allow or block assertion. |

Different reasons or DROP/REJECT actions can share the same aggregate verdict,
but remain separate outcomes. A first traffic-matching policy's pass is terminal
within perimeterd: later policies do not get another opportunity to deny.
Allowlist misses are denial by absence, not evidence of membership in a blocking
feed. "Not blocked" deliberately does not mean ACCEPT: other firewall rules can
still deny after perimeterd returns.

The lookup response uses schema 2 on the unchanged `/v1/lookup` path:

- `schema_version: 2`, canonical query and effective new-flow assumptions,
  aggregate `verdict`, and an explicit error code/message when not complete;
- `observed_at`, selected revision/configuration epoch, exact static manifest
  identity when present, and acknowledged CrowdSec epoch/operation identity
  when applicable; identifiers that are unavailable are not fabricated;
- complete outcomes: covered CIDR, direction, traffic scope, managed attachment
  and interface/port-basis conditions, verdict/action, deciding stage and policy
  name/priority when applicable, and a reason for pass or denial;
- source evidence separately identifying matching includes, exclusions, and
  shadowed memberships, with normalized ranges and static retrieval timestamps
  or dynamic decision/lease deadlines. Country/ASN keep semantic kind/name;
  `provider` is `dbip-lite` or `ripestat`, with `release` only for DB-IP.
  A matching source contributes only in the deciding rule's context.
  [Data sources](data-sources.md#lookup-source-attribution)
  defines available provenance and its limits.

Status and lookup clients reject mixed response schema versions explicitly;
the reload protocol and all HTTP paths remain unchanged.

Sort scopes, ranges, and source identities deterministically. Human output
summarizes the same complete result as `--json`, without silently hiding mixed
coverage or arbitrarily choosing one source. Do not expose credentials, raw
upstream payloads, secret-bearing URLs, or HTTP query strings.

Exit `0` means a complete lookup, including a `blocked` or `mixed` verdict;
it is not an assertion of connectivity. Invalid input/usage exits `2`.
Unavailable enforcement, missing/refused daemon connection, incompatible
protocol version, busy/deadline failure, and response/work limits exit `1`
with explicit diagnostics. With `--json`, report a structured error rather than
a partial success. A failed or limited lookup cannot default to `not_blocked`.
The [transport bounds](architecture.md#private-control-transport-and-lifecycle)
apply equally to human and JSON output; narrow the prefix or traffic scope
after a limit error.

During an apply, uncertain commit, failed rollback, pending recovery, or
unresolved target retirement, return `unknown`. A rejected candidate that
never disturbed enforcement leaves the old applied view queryable. Source
outages can still produce a valid answer from acknowledged last-known-good
enforcement; show the old retrieval time and actual known lease coverage, not
the latest attempted download or desired CrowdSec store.

When the daemon is stopped, lookup is unavailable. Static rules can remain
enforced and CrowdSec leases can expire during that downtime; neither fact
permits a saved configuration or manifest to impersonate live authority.

## Operator sequence

This runbook covers both source-built and packaged installations. Source-build
commands assume no installed systemd unit or tmpfiles payload; package installs
use the service instructions below.

### Prerequisites

1. For a source build, build the binary and install selected backend tools
   listed in [Source-build prerequisites](#source-build-prerequisites).
   Packages declare their backend alternatives.
2. Use a disposable VM or isolated network namespace. Verify that configured
   iptables parent chains already exist.
3. Write the complete configuration as root with mode `0600`. Keep credentials
   outside the YAML in root-owned files with mode `0600`.
4. Run the local `validate` command using the built or installed binary. The
   process must be able to read the private configuration; `validate` itself
   does not require root and does not attest runtime prerequisites. See
   [Build, validate, and run from source](#build-validate-and-run-from-source).

### Configure and validate

Set `firewall.backend` explicitly to `nftables` or `iptables`; there is no
capability auto-selection or fallback after an apply error. Use a complete
configuration document, not one of the root-level fragments in
[Configuration](configuration.md#document-and-fragment-forms).

The attachment schema, defaults, and offline normalization are owned by
[Configuration](configuration.md#iptables-attachments). Offline validation
accepts an explicit `firewall.iptables.attachments: []`; at runtime it means no
managed attachment jumps. With iptables selected, a non-empty desired policy
then fails reconciliation before mutation because it has no managed packet path;
nftables ignores this list.
See the [iptables attachment contract](firewall-backends.md#iptables-attachment-contract)
for ownership and packet-path guarantees.
Only the canonical [empty desired state](configuration.md#empty-desired-state)
may converge to no owned artifacts; administrator-managed jumps do not count as
active enforcement.

### Start and check health

For a source build, start with the `run` command in
[Build, validate, and run from source](#build-validate-and-run-from-source), in
the foreground, and watch stdout/stderr.

For a packaged installation, first validate the configured file, then start
and inspect the service:

```sh
sudo /usr/bin/perimeterd validate --config /etc/perimeterd/perimeterd.yaml
sudo systemctl start perimeterd.service
sudo systemctl status perimeterd.service
sudo /usr/bin/perimeterd status
sudo journalctl -u perimeterd.service -f
```

Package installation does not enable or start the service. To start it at boot,
run `sudo systemctl enable perimeterd.service` after reviewing the configuration
and runtime prerequisites.
With either installation, if `metrics.listen` is non-empty, the listener binds
before the first firewall commit; its default is loopback-only
`127.0.0.1:2112`. A bind failure prevents startup readiness. `GET /metrics` is
unauthenticated, so expose a non-loopback address only behind suitable network
access control.

The current endpoint emits `perimeterd_enforcement_health`,
`perimeterd_crowdsec_connected`, and
`perimeterd_prefix_snapshot_timestamp_seconds{source}` for each required static
source kind. Each timestamp is the oldest retrieval time for that kind, not
manifest publication time; see the [Prometheus metrics](#prometheus-metrics)
contract for all series and labels.

The CrowdSec gauge is zero when disabled or awaiting valid synchronization;
LAPI unavailability does not extend retained decisions. The endpoint also exports
the full [Prometheus metrics](#prometheus-metrics) surface, including sampled
native packet/byte accounting. Native traversal semantics and inspection paths
are in [Packet and byte accounting](firewall-backends.md#packet-and-byte-accounting).

### Reload, recover, and cleanup

1. Edit a complete configuration and run `sudo bin/perimeterd reload` for a
   foreground source build, or `sudo systemctl reload perimeterd.service` for a
   package installation. The packaged unit runs `/usr/bin/perimeterd reload` and
   propagates its acknowledged result.
2. A pre-apply rejection retains the previous policy. Degraded or unknown
   completion is not proof of rollback: preserve durable evidence, inspect the
   error and structured logs, and do not delete state to force a reload.
3. If enforcement becomes unhealthy, stop ordinary changes. Preserve the
   journal, active record, revisions, source manifests, and ownership metadata;
   restart the source-built `run` process or the packaged service and let
   recovery proceed, or invoke explicit cleanup only after stopping the daemon.
4. For intentional decommissioning, stop the process or service, confirm it is
   inactive, and run `cleanup` with the source-built or installed binary
   (`sudo bin/perimeterd cleanup` or `sudo /usr/bin/perimeterd cleanup`). Package
   removal performs this cleanup through its
   [lifecycle procedure](#package-lifecycle). Cleanup retains the owner identity.
   Do not purge or relabel retained state to make an incompatible daemon start.

The command is:

```text
perimeterd reload [--expect-config-sha256 HEX]
```

It requires root and contacts the existing `/run/perimeterd/control.sock`; it
does not take the lifecycle lock, read durable state, accept a configuration path,
or submit YAML. The daemon reads its own configured file once, hashes those exact
bytes, and parses the same bytes. To correlate a deployment with rendered content:

```sh
digest=$(sudo sha256sum /etc/perimeterd/perimeterd.yaml)
sudo /usr/bin/perimeterd reload --expect-config-sha256 "${digest%% *}"
```

The optional digest must be 64 hexadecimal characters. A mismatch is rejected
before credential loading, source resolution, or native apply. It covers only the
configuration bytes, not referenced feeds or credential files. Success prints the
committed revision and actual digest; it guarantees this request completed commit,
required native work, and runtime publication with healthy enforcement and no
pending recovery. A later reload or background refresh can supersede that revision.

| Outcome | Meaning | Exit |
| --- | --- | --- |
| `applied` | This request completed clean commit and healthy runtime publication | 0 |
| `rejected` | This request did not commit or enter an uncertain native transaction | 1 |
| `degraded` | This candidate is known committed, but required completion failed; revision included | 1 |
| `unknown` | Completion cannot be established, including a lost response or timeout; rollback is not claimed | 1 |

Usage errors exit 2, and `reload --help` works without a daemon. Failure diagnostics
include outcome/code and actionable detail without exposing YAML or credentials.
Malformed, incompatible, or inconsistent responses fail closed. There is no
automatic retry, asynchronous fallback, request history, or polling API.

The client waits at most 75 seconds; the server operation/write bound is 80 seconds,
before systemd's existing 90-second reload deadline. Header/body reads and lookup
operations retain their five-second limits. Source timeouts are unchanged. A slow
request can return unknown completion: cancellation before native apply prevents
that mutation, but an already-started transaction completes under the daemon's
context, even if its client leaves. Do not automatically retry an ambiguous result.

`systemctl reload` returns nonzero for rejected, degraded, or unknown completion.
An ordinary pre-apply rejection leaves the daemon running without a restart and
keeps the old policy. An old daemon without this endpoint fails safely.
Manual `SIGHUP` remains asynchronous: signal delivery does not acknowledge
application, and an admitted signal can supersede an older staging request.
Startup requests are explicitly rejected as `not_ready`, rather than queued.

Backend-specific mixed-family windows, migration overlap, retained ownership,
and degraded recovery are defined in
[architecture](architecture.md#durable-apply-and-crash-recovery) and
[firewall backend failure behavior](firewall-backends.md#failure-and-cleanup-behavior).

## Unsupported development state

Internal durable records use version 2; the configuration schema remains
version 1. Because perimeterd has not been deployed, version-1 development
state is unsupported rather than migrated. Both `run` and `cleanup` reject
unsupported record versions without changing durable records or native rules.
Changing a record's version number does not make its contents compatible.

Recreate disposable development guests instead of converting their records.
For any manual decommissioning of a retained host, stop the daemon, preserve
private state and native inventories, and require operator review of exact
resources and any enforcement gap. Never flush the host ruleset, delete
unrelated tables or bypass ownership validation.

There is no automatic legacy-table adoption. An existing table without the
canonical witness fails ownership validation; complete table absence permits
reconstruction only from validated current-format state.

## Supported CrowdSec LAPI prerequisite

CrowdSec LAPI v1.8.1 is the supported baseline and uses its normal chunked
decision stream; no feature-flag change or older-server pin is required. The
wire protocol, synchronization, expiry, and lease details belong to the
[supported LAPI contract](data-sources.md#supported-lapi-contract).

Register a bouncer in that LAPI deployment and store its API key in a
root-readable file with mode `0600`. Configure `crowdsec.enabled: true`,
`lapi_url`, and `api_key_file`, then run or reload the daemon. Initial
synchronization must succeed before readiness. A same-path key rotation is
reread on acknowledged reload or manual `SIGHUP`; a failed replacement retains the old authenticated client
and its bans. The default update frequency is `10s`; request deadlines are at
most `30s`. Failures do not extend a decision's absolute expiry. Lease renewal
continues from retained authority while the writer can safely reconcile it.

CrowdSec streams have separate **256 MiB (268,435,456-byte) wire and decoded
limits**. Both count actual reads, including chunked bodies and trailing
whitespace; gzip must finish with a valid checksum. These are fixed safety
ceilings, not configurable response sizes or process-RSS guarantees. Static
provider/list decoded limits remain 32 MiB.

Startup, reload, and background synchronization failures retain a secret-safe
category:

| Diagnostic category | Operator check |
| --- | --- |
| `HTTP 401` / `HTTP 403` | Check the registered bouncer and the root-readable key file; an HTTP response proves the server was reached, not that authentication succeeded. |
| Other numeric HTTP status | Inspect LAPI/proxy health and server-side logs; the daemon never reads or prints an error body. |
| `wire size limit exceeded` / `decoded size limit exceeded` with `268435456 bytes` | Measure the stream's wire/expanded size using isolated credentials. A larger valid stream is outside the supported ceiling; do not infer authentication or LAPI failure from a reset caused by the client closing it. |
| Unsupported encoding, malformed/truncated gzip, malformed envelope/decision data | Check proxy encoding/truncation and LAPI response integrity. Even a valid decision prefix is discarded when the tail fails validation. |
| DNS, connection, TLS, timeout, canceled, or generic transport/read failure | Check the selected direct/OpenZiti route, DNS where applicable, application TLS trust, and the unchanged 30-second request budget. Generic errors deliberately omit arbitrary lower-level text. |

Do not paste API keys, complete URLs/query strings, response bodies, or decision
metadata into diagnostics. The versioned `perimeterd/<build version>` User-Agent
is accepted by the pinned LAPI and records the running build as the bouncer
version. After a failed reload/poll, use `perimeterd status` to inspect
acknowledged state and representative `lookup`/packet probes to distinguish
retained enforcement from connectivity; decisions and finite leases still expire.

The known upstream database-query behavior is accepted: a successful-looking
empty or partial full snapshot may remove CrowdSec bans. Restoration may
require a later full synchronization; static global and geo policy are
unaffected. This is tracked in
[crowdsecurity/crowdsec#4691](https://github.com/crowdsecurity/crowdsec/issues/4691)
and is not worked around as a compatibility blocker. Decision snapshots and
key contents are not written into durable revisions.

## Lifecycle lock and recovery

`run` and `cleanup` acquire the exclusive, nonblocking `flock` at
`/run/perimeterd/owner.lock` and hold it for their whole lifetime. A second
daemon, or cleanup while the daemon is active, fails without mutation. Never
unlink or replace this inode. It is distinct from `/run/xtables.lock`, which
serializes compatible iptables restore commands only and does not coordinate
nftables, migrations, or durable state.

Recovery is authoritative from durable revisions, the prepared journal, and the
published active record, not from current YAML or a partial kernel listing.
Startup recovers pending work before loading current YAML. If recovery reports
uncertain publication, failed compensation, or unhealthy enforcement, preserve
the journal, active record, revisions, source manifests, and ownership
metadata; do not force a reload or delete state. Follow the canonical
[exclusive lifecycle ownership](architecture.md#exclusive-lifecycle-ownership),
[durable apply and crash recovery](architecture.md#durable-apply-and-crash-recovery),
and [backend migration](architecture.md#backend-and-target-migration)
procedures.

## Installed layout

DEB/RPM packages install the following layout. A source build alone does not
install these paths or create a service:

- `/usr/bin/perimeterd`: root-owned static executable;
- `/usr/share/bash-completion/completions/perimeterd`: root-owned, mode `0644`,
  generated Bash completion; loaded on demand when the distribution's
  `bash-completion` support is installed and enabled;
- `/etc/perimeterd/perimeterd.yaml`: `root:root`, mode `0600`;
- `/etc/perimeterd/credentials.d/`: `root:root`, mode `0700`, with files mode
  `0600`;
- `/var/lib/perimeterd/`: `root:root`, mode `0700`, for state and cache;
- `/run/perimeterd/`: `root:root`, mode `0700`, for runtime state;
- `/run/perimeterd/owner.lock`: root-owned mode `0600` lifecycle lock;
- `/run/perimeterd/control.sock`: daemon-created root-owned mode `0600` private
  control socket shared by lookup and reload, not a tmpfiles-created node;
- `/run/xtables.lock`: root-owned mode `0600` shared by iptables and
  ip6tables; and
- a packaged tmpfiles declaration and `perimeterd.service` in the distribution
  system-unit directory.

The control socket replaces the former `lookup.sock` with no legacy listener,
alias, or client fallback. When upgrading from a binary using the old path,
replace the binary and restart the daemon (`sudo systemctl restart
perimeterd.service` for a package installation); a configuration reload cannot
activate this socket rename. The CLI and running daemon must use the same
socket contract.

The package must preserve the lifecycle-lock inode across service stop/restart,
create the state/runtime directories, and provision the shared xtables lock
without unlinking or replacing an existing lock. There is deliberately no
service user in that contract: the process remains UID 0 and is constrained to
`CAP_NET_ADMIN` and `CAP_NET_RAW` by the installed unit.

## systemd service contract

The packaged `packaging/perimeterd.service` uses the following contract:

```systemd
[Unit]
Description=perimeterd firewall policy daemon
Wants=network-online.target
Requires=systemd-tmpfiles-setup.service
After=network-online.target crowdsec.service systemd-tmpfiles-setup.service

StartLimitIntervalSec=60s
StartLimitBurst=5

[Service]
Type=notify
NotifyAccess=main
TimeoutStartSec=90s
ExecStart=/usr/bin/perimeterd run --config /etc/perimeterd/perimeterd.yaml
ExecReload=/usr/bin/perimeterd reload
Restart=on-failure
RestartSec=5s
StateDirectory=perimeterd
RuntimeDirectory=perimeterd
RuntimeDirectoryPreserve=yes
StateDirectoryMode=0700
RuntimeDirectoryMode=0700
CapabilityBoundingSet=CAP_NET_ADMIN CAP_NET_RAW
AmbientCapabilities=CAP_NET_ADMIN CAP_NET_RAW
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
ProtectControlGroups=yes
ProtectKernelTunables=yes
ProtectKernelModules=yes
RestrictSUIDSGID=yes
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6 AF_NETLINK
UMask=0077
ReadWritePaths=/run/xtables.lock
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

The packaged tmpfiles payload must create, but never replace, the shared lock:

```text
f /run/xtables.lock 0600 root root -
```

`systemd-tmpfiles-setup.service` is ordered before perimeterd so the host lock
exists before startup. `After=crowdsec.service` is ordering only; it does not
start or require CrowdSec. `ProtectSystem=strict` remains in force, while
`ReadWritePaths` grants access to this exact lock rather than making `/run`
generally writable. The service never uses a private lock path.

### Recovery before validation

The unit deliberately does not use `ExecStartPre=validate`: `run` must recover
persisted state before reading current YAML. It must extend the activation
window while bounded startup proceeds and send `READY=1` only after recovery,
source resolution, backend validation, initial reconcile, durable commit, and
any required CrowdSec synchronization. `READY=1` is not a revocable
health assertion; operators must also monitor the enforcement-health metric.

Recovery failures are classified by typed causes, not error-message text.
Capacity violations, invalid ownership/target metadata, inconsistent durable
records, and missing executables/files or permission failures stop the attempt
immediately. Unknown native and other transient failures retain exponential
retries after `1s`, `2s`, `4s`, `8s`, `16s`, then at most `30s`, within the
original startup deadline. Native-command child timeouts remain transient while
the recovery context is live; they never reset or extend the startup budget.
Cancellation or expiry of the lifecycle context admits no further attempt.
Permanent runtime recovery failures also terminate the daemon rather than
leaving an unrecoverable writer retrying indefinitely. systemd's existing
restart/rate-limit policy remains separate from in-process recovery.

A bootstrap logger reports the first recovery failure before current YAML,
metrics, or the control socket are available. New recovery diagnostics use
fixed safe categories, attempt and retry-delay fields, and numeric capacity
required/limit bytes and static/dynamic generation counts when available.
They do not echo native output, remote payloads, prefixes, or credentials.
Timeout diagnostics distinguish a recovery operation timing out from the
overall startup deadline expiring.
An old `retained generations exceed inspection budget` message is not evidence
that there are stale generations: repeated references to one native generation
must not be charged as distinct objects.

Preserve the active record, journal, immutable revisions, source manifests, and
native objects when investigating. Collect `systemctl status perimeterd`,
`journalctl -u perimeterd -b`, the numeric failure context, and read-only native
inventory for the configured table. `perimeterd status` is available only if a
daemon has reached its control socket. Deploy a corrected binary and restart
against the same state/configuration; recovery must complete before current
YAML can be applied. Do not flush the table, delete the journal, disable a
family/CrowdSec, trim a country group, or increase the startup timeout to bypass
capacity checks. A genuinely over-capacity target still fails closed; the
[finite native limits](firewall-backends.md#capacity-and-complete-inspection)
are distinct from source-stream limits and total process memory.

### Bounded startup deadline

The current `run` startup deadline is 75 minutes, measured with a monotonic
clock from process entry. It covers lifecycle ownership, recovery, local
validation, source resolution, compilation, initial apply, and durable
publication. Startup contexts and child-command deadlines are bounded by the
remaining time; request timeouts cannot extend it. Known fatal errors exit
immediately.

The installed unit's [`TimeoutStartSec=90s`](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#TimeoutStartSec=)
is the initial activation window, not the total startup budget. A source build
implements the same notification protocol but does not install the unit.

While initialization is in progress, the main process sends
`EXTEND_TIMEOUT_USEC` immediately and every 20s, requesting the smaller of
60s and the remaining overall deadline, together with a bounded `STATUS`
describing the current phase. The notifier is independent of the serialized
writer so a pending source fetch or apply cannot starve it; notification
delivery failure is surfaced. Requested extension intervals never exceed the
remaining deadline.

Phase status distinguishes opening persisted state, recovering persisted
firewall state, resolving sources, and applying configuration. Extension ticks
retain the latest phase or safe recovery-failure category rather than replacing
it with a generic startup message. On failure, extension sending stops before
the final failed `STATUS` is emitted; no later extension or `READY=1` follows.
Readiness and normal stop behavior otherwise remain unchanged.

The budget accommodates 512 uncached selectors at concurrency four when every
successful request takes the default 30s: source fetching can consume up to
64m, leaving 11m for other initialization. This is a deadline policy, not a
promise that arbitrarily slow sources or recovery succeed. No independent
retry loop resets the startup clock.

At the overall deadline, startup cancels, admits no further mutations,
withholds `READY=1`, and exits nonzero. If apply or compensation cannot finish,
the journal and every required recovery object remain for the next invocation.
systemd enforces the last requested activation deadline if the process stalls.
Direct non-systemd runs enforce the same overall deadline without notification
delivery. After readiness, the startup timer and extensions stop; this is not a
runtime watchdog and does not change reload semantics.

## Prometheus metrics

If `metrics.listen` is configured, `GET /metrics` emits the following runtime
gauges alongside the accounting and outcome metrics below:

- `perimeterd_enforcement_health` (unlabeled gauge): `1` only when the selected
  enforcement is healthy; it becomes `0` during degraded recovery. A listener
  failure terminates `run`, so the endpoint is no longer served.
- `perimeterd_prefix_snapshot_timestamp_seconds{source}` (gauge), emitted
  separately for each required static source kind: `dbip-lite`, `ripestat`,
  `ip_list`, and `provider`. It is the oldest committed retrieval time for that
  kind, never month start or manifest publication time. Unreferenced kinds emit no timestamp.
- `perimeterd_crowdsec_connected` (unlabeled gauge): the active integration's
  synchronization/poll outcome. It is `0` when disabled, not yet synchronized,
  or after a failed poll/reconnect, and `1` after successful polling/activation.
  It is separate from enforcement health and does not count current bans.

The `source="provider"` timestamp series uses the oldest retrieval among
required committed provider objects. Provider IDs are never metric labels.

`perimeterd_enforcement_health` reports the last acknowledged enforcement and
recovery outcome, not an atomicity guarantee for an in-flight native operation.
Failed dynamic writes, degraded recovery, or incomplete target cleanup set it
to `0`; successful reconciliation and required cleanup restore it.
`READY=1` is a one-time systemd activation notification, not a revocable health
assertion. Later failures cannot retract it.

The endpoint allows only `GET` on `/metrics`; other paths return 404 and other
methods return 405. Read headers are limited to 5s, complete request reads and
writes to 10s, and idle keep-alive connections to 30s. Listener replacement
uses a 5s graceful-shutdown deadline and force-closes an expired listener.
Metrics are unauthenticated and must not be exposed beyond a trusted network
boundary.

The selected backends create native processed-path and terminal-denial
packet/byte counters independently of the listener. Disabling exposition stops
native collection without changing enforcement. See
[firewall accounting](firewall-backends.md#packet-and-byte-accounting) for
traversal and denial semantics.

The endpoint also exports:

- `perimeterd_build_info` (gauge): constant `1` with bounded build metadata.
- `perimeterd_config_reload_total{result}` (counter): `success` requires clean
  committed apply, completed runtime publication, and healthy enforcement without
  pending recovery; degraded/uncertain application counts as `error`. Background
  refresh accounting is separate. This metric is not a per-request acknowledgement.
- `perimeterd_reconcile_total{reason,result}` (counter): reconcile outcomes.
- `perimeterd_reconcile_duration_seconds{reason}` (histogram): apply latency.
- `perimeterd_prefixes{family,source,type}` (gauge): active prefix count.
- `perimeterd_source_requests_total{source,result}` (counter): request outcomes.
- `perimeterd_crowdsec_decisions{family}` (gauge): active unexpired bans.
- `perimeterd_backend_apply_total{backend,result}` (counter): apply outcomes.
- `perimeterd_firewall_processed_packets_total{backend,family,direction}` and
  `perimeterd_firewall_processed_bytes_total{backend,family,direction}`
  (counters): processed path traversals and their bytes.
- `perimeterd_firewall_denied_packets_total{backend,family,direction,reason,action}`
  and `perimeterd_firewall_denied_bytes_total{backend,family,direction,reason,action}`
  (counters): executed terminal denial decisions and their bytes.
- `perimeterd_firewall_counter_read_total{backend,result}` (counter): native
  counter-read outcomes.
- `perimeterd_firewall_counter_timestamp_seconds{backend}` (gauge): timestamp
  of the last successful native counter read.

The prefix gauge includes built-in local, configured global, DB-IP Lite,
RIPEstat, and custom-list prefixes through fixed labels. Country counts use the
committed provider (`dbip-lite/country` or `ripestat/country`); ASN stays
`ripestat/asn`. Custom lists use `source="ip_list"` and `type="ip_list"`.
Provider data uses the fixed `source="provider"` and
`type="provider"` values, not per-provider label values.
Source request observations count one logical DB-IP country batch, including
its retries, not one imagined download per country. Release, country, digest,
and URL never become metric labels. Failed candidates do not advance committed
freshness, overall source age, counts, or provider summaries.

Each scrape sees one complete prefix snapshot, including when a reconcile
re-publishes unchanged counts.

Allowed label values remain bounded: firewall `reason` is `global_blocklist`, `crowdsec`, or
`geo_policy` (including list-based policies); `action` is `drop` or `reject`;
and counter-read `result` is `success` or `error`. No metric label may contain
an address, ASN, country, policy/list/provider name, URL, raw error, or unbounded remote
revision.

The fixed 15-second background sampler reads native counters through the
serialized backend path and serves last in-memory values without querying the
firewall from the Prometheus handler. When a reconcile replaces raw counters,
it attempts a final read of the retired generation after dispatch switches
away from it and before removal, then establishes the replacement baseline. A
failed final read records an accounting gap and never rolls back enforcement.
Exported process-lifetime totals remain monotonic across reconciles; a daemon
restart is an ordinary Prometheus counter reset.
Baselines are established on the first successful complete read after collection
starts or restarts, so values accumulated before the active metrics window are
not imported. A failed initial read leaves baseline initialization pending;
retirement reads before that first complete read report read outcomes but do not
import pre-activation traffic. Pending recovery suspends complete snapshots;
retirement baselines survive failed removal and retries after initialization,
preventing the same cumulative native values from being counted twice.

A failed periodic read retains prior values, increments the `error` result, and
leaves the last-success timestamp unchanged. Counter collection never changes
firewall state or readiness. A process or host crash, external rule replacement,
or external counter reset can lose accounting. These metrics are operational
telemetry, not lossless billing or audit records. Snapshot age is derived from
the prefix timestamp gauge; native-counter staleness is derived from the
counter timestamp gauge. Exposition follows the official
[Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).

## Logging

The current runtime uses Go `log/slog` and writes stdout; stderr is reserved
for process-start failures before logging initializes. Levels are `debug`,
`info`, `warn`, and `error`; formats are `text` and `json`. Records include a
timestamp and message and may include bounded fields such as `component`,
`operation`, `revision`, `backend`, `policy`, `family`, `duration`, and `error`.
Credentials, authorization headers, complete prefix lists, and packet IP
addresses must not be logged. Network-boundary errors are scrubbed before they
reach logs.

## Packages

The release builds one `perimeterd` package as RPM and DEB through GoReleaser
v2's nFPM integration. Builds are
static Linux binaries (`CGO_ENABLED=0`) for amd64 (`GOAMD64=v1`) and arm64.
Each package contains the binary, generated Bash completion, systemd unit,
packaged `/usr/lib/tmpfiles.d/perimeterd.conf` (or the distribution equivalent),
commented example configuration, MIT license, and this documentation. The
example configuration is installed as `config|noreplace`; upgrades never
replace an operator-edited file.

Dependency alternatives must provide either nftables or a complete
iptables/ipset stack, without selecting a backend implicitly:

- Debian: `nftables | iptables, nftables | ipset`;
- RPM: a rich dependency equivalent to
  `(nftables or (iptables and ipset))`.

When iptables is selected, the daemon validates the matched legacy or
nf_tables IPv4/IPv6 tools and shared xtables lock; it never silently changes
variants. Release workflows and provenance checks are owned by
[development](development.md#release-workflow). Packages also depend on
`ca-certificates` for HTTPS upstreams.

Verify every downloaded release subject before installing. Download its
`checksums.txt` and `provenance.sigstore.json` along with the artifacts and
their exactly named `<artifact-name>.spdx.sbom.json` companions. In the
download directory:

```sh
sha256sum --check checksums.txt
COMMIT='INSERT_ADMITTED_SOURCE_SHA'
REF='refs/tags/INSERT_VERSION'    # use refs/heads/main for a main prerelease
for file in $(sed -n 's/^[0-9a-f]\{64\}  //p' checksums.txt) checksums.txt; do
    gh attestation verify "$file" \
      --bundle provenance.sigstore.json --repo perimeterd/perimeterd \
      --signer-workflow perimeterd/perimeterd/.github/workflows/release.yml \
      --source-digest "$COMMIT" --source-ref "$REF"
done
```

The manifest covers seven parents (both architecture-specific binary
tarballs, four native packages, and the source archive) and their seven
companion SPDX JSON documents; the manifest itself is another provenance
subject. The bundle is not checksum-covered. Inspect the expected GitHub
workflow, repository, admitted source commit and ref when verifying a hosted
release; `gh attestation verify` checks the bundle cryptographically, not just
its decoded payload. A valid signature authenticates the document and
subject bytes; it does **not** establish SBOM inventory completeness.

Binary archive and DEB/RPM SBOMs describe the shipped executable's effective
linked Go modules, the Go standard library/toolchain version, and a separate
release-version application identity. The Go main-module source identity may
have a pseudo-version distinct from the release version; do not assign the
release version to third-party modules. The source-archive SBOM also covers
source/development and tooling inputs, which need not ship in the binary.
Local workflow references can have unknown versions without hiding a linked
dependency. `nftables`, `iptables`, `ipset` and `ca-certificates` are host
installation requirements, not pinned components embedded in static binaries.
To independently check executable linkage against Go build metadata, run
`python3 scripts/release-assets.py DOWNLOADED_DIR ABSENT_DESTINATION` from a
checkout of the release scripts with the Go version in `go.mod` and `bsdtar`
installed; this validates downloaded files without rebuilding or rescanning.

## Package lifecycle

Package lifecycle scripts preserve enforcement except for explicit final removal:

- post-install installs the unit and tmpfiles payload, runs
  `systemd-tmpfiles --create` against the installed perimeterd tmpfiles file
  when systemd is available (including installation after boot), and runs
  `systemctl daemon-reload`. A provisioning failure is reported; the script
  does not enable or start an unconfigured daemon and prints guidance only;
- upgrade preserves configuration, credentials, state, recovery, ownership
  metadata, active rules, and both lock inodes. Any restart follows
  distribution policy; the script never runs cleanup, purges state, or
  unlinks/replaces `/run/xtables.lock` or `/run/perimeterd/owner.lock`; and
- final removal stops `perimeterd.service` and requires it to be inactive, then
  runs `perimeterd cleanup` under the shared lifecycle lock using persisted
  target metadata. It removes packaged files only after cleanup succeeds and
  reloads systemd. If stop or cleanup fails, it reports the error and preserves
  active rules, recovery metadata, ownership metadata, state, and locks.

Even after successful removal or DEB purge, package scripts retain credentials,
cache, state, and both lock inodes. Dpkg may remove its managed configuration
file on purge; RPM preserves an edited configuration as `.rpmsave`. Operators
may remove retained private data manually only after successful cleanup and
after confirming no perimeterd process remains. Scripts never flush global
netfilter state, create Docker-owned chains, infer ownership from names alone,
or remove the host-wide xtables lock.

Package downgrade permission is not persistent-state compatibility. The daemon
supports internal state format 2, not earlier development formats. Cleanup
retains its versioned owner record; installing an older reader does not convert
that state. Use a binary compatible with the retained format, or recreate a
disposable development guest. Never erase or relabel records to force startup;
permanent removal of retained data is a separate decommissioning decision.

