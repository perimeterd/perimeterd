# Operations

This document owns operator procedures, process startup/shutdown, service
integration, and observability. [Configuration](configuration.md) owns fields
and policy semantics; [architecture](architecture.md) owns revision admission,
durable commit, and recovery; [firewall backends](firewall-backends.md) owns
native kernel behavior. The [implementation plan](implementation-plan.md) is
authoritative for delivery status.

> **Status boundary.** The source-build instructions in this document describe
> what runs today, including Docker's iptables bridge integration. Installed
> packages, systemd payloads, and release artifacts remain first-release work.
> A full-schema configuration is not a capability list.

## Current source-build runtime

The current binary implements:

- strict offline `validate` and `version` commands;
- `run` and `cleanup` under one process-lifetime ownership lock;
- nftables and iptables/ipset policy application, including both legacy and
  nf_tables iptables tool families;
- direct global address lists and RIPEstat country/ASN snapshots, with local
  RIR and built-in/custom group expansion;
- immutable source snapshots, refresh, cache fallback, durable revision/journal
  recovery, backend and target migration, and custom iptables attachments;
- CrowdSec ingress bans with authoritative synchronization, expiry, renewable
  kernel leases, and staged credential/endpoint replacement;
- explicit Docker `DOCKER-USER` bridge attachments with pre-DNAT port matching;
- backend-owned native processed and terminal-denial counter objects; and
- enforcement-health, CrowdSec connection, and committed-prefix timestamp gauges.

Docker coexistence is verified for Docker Engine 29.8.1's iptables bridge
backend with both iptables tool families and IPv4/IPv6. Docker's native nftables
backend, rootless networking, and Swarm are outside that verified scope.
See the [Docker attachment contract](firewall-backends.md#docker-docker-user-attachment).
Offline validation intentionally accepts the complete version-1 schema.
`configs/perimeterd.yaml` is a full-schema example and must not be treated as a
runnable capability list.

### Source-build prerequisites

Build with Go `1.27.1` (the version declared by `go.mod`) and run on Linux as
root. Use a disposable VM or isolated network namespace; never test policy
against the development host's firewall.

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

A source-backed policy needs network access to the fixed RIPEstat endpoints on
its first resolution unless an acceptable committed snapshot covers every
required selector. Configurations with neither geo selectors nor CrowdSec make
no source requests.

### Build, validate, and run

Build the source tree, then validate and run the same complete configuration.
`run` and `validate` accept `--config PATH`; when omitted, both use
`/etc/perimeterd/perimeterd.yaml`. The source build does not create that path.

```sh
make build
CONFIG=/etc/perimeterd/perimeterd.yaml
bin/perimeterd validate --config "$CONFIG"
sudo bin/perimeterd run --config "$CONFIG"
```

`validate` is local-only: it parses one YAML document and performs schema and
semantic checks without reading credentials, resolving selectors, contacting
RIPEstat or CrowdSec, binding the metrics listener, or touching firewall state.
It does not require root, but the selected file must be readable. A successful
validation therefore does not prove that source data, credentials, LAPI
compatibility, or native backend tools are available. Only `run` synchronizes
and enforces source-backed or CrowdSec decisions.

The default persistent paths are `/var/lib/perimeterd` for revisions, journals,
and immutable prefix snapshots, and `/run/perimeterd/owner.lock` for the
lifecycle lock. Invoked as root, the runtime creates missing directories. Do
not delete either path, its records, or the lock inode to bypass recovery or
ownership checks. A committed static policy remains in the kernel after a
normal stop. CrowdSec entries retain only their remaining finite kernel lease;
without the daemon, they can expire before the original decision deadline.

Source-backed candidates use immutable, content-addressed manifests under
`/var/lib/perimeterd/prefixes/`; the committed revision selects its manifest.
Do not edit these files or choose one by modification time. Startup validates
referenced cache evidence before mutating the firewall. Unreferenced cache
files are collected only after startup recovery or explicit cleanup, not while
source workers may be staging candidates.

Refresh uses `geo.refresh_interval` (default `24h`) plus sampled jitter up to
`geo.refresh_jitter` (default `10m`). Each request defaults to a `30s` timeout;
at most four source requests are in flight and at most 512 selectors are
accepted. Incomplete, malformed, oversized, or otherwise unacceptable source
data leaves the committed policy unchanged. A committed snapshot is reused
only when it covers every required selector; a newly introduced selector must
resolve successfully. Failed refreshes retain the active policy and retry on
the normal schedule.

Encoded-state and native-input limits are safety fences, not tuning knobs.
Admission accounts for the candidate and required retained state; rejection
before execution performs no native writes. Do not interpret every later
execution failure as unchanged enforcement: partial or ambiguous results follow
the backend's compensation and recovery contract. See
[firewall backends](firewall-backends.md) and
[durable admission](architecture.md#durable-apply-and-crash-recovery).

## Operator sequence

This is the current source-build runbook. It does not assume a package,
installed systemd unit, tmpfiles payload, or automatic service startup.

### Prerequisites

1. Build the binary and install the selected backend tools listed in
   [Source-build prerequisites](#source-build-prerequisites).
2. Use a disposable VM or isolated network namespace. Verify that configured
   iptables parent chains already exist.
3. Write the complete configuration as root with mode `0600`. Keep credentials
   outside the YAML in root-owned files with mode `0600`.
4. Run the `validate` command from [Build, validate, and run](#build-validate-and-run).
   It checks only the local document and does not attest runtime prerequisites.

### Configure and validate

Set `firewall.backend` explicitly to `nftables` or `iptables`; there is no
capability auto-selection or fallback after an apply error. Use a complete
configuration document, not one of the root-level fragments in
[Configuration](configuration.md#document-and-fragment-forms).

An explicit `firewall.iptables.attachments: []` clears the default attachment
jumps and is accepted by local validation. When iptables is selected, a
non-empty desired policy then fails runtime reconciliation before mutation
because it has no managed packet path. nftables ignores this list. Only the
canonical [empty desired state](configuration.md#empty-desired-state) may
converge to no owned artifacts; do not infer active enforcement from
administrator-managed jumps. See the
[iptables attachment contract](firewall-backends.md#iptables-attachment-contract).

### Start and check health

Start with the `run` command shown in
[Build, validate, and run](#build-validate-and-run), in the foreground, and
watch its stdout/stderr. If `metrics.listen` is non-empty, the listener binds
before the first firewall commit; its default is loopback-only `127.0.0.1:2112`.
A bind failure prevents startup readiness. `GET /metrics` is unauthenticated,
so expose a non-loopback address only behind suitable network access control.

The current endpoint emits `perimeterd_enforcement_health`,
`perimeterd_crowdsec_connected`, and, for an active source-backed revision,
`perimeterd_prefix_snapshot_timestamp_seconds{source="ripestat"}`. The latter
is the oldest required selector retrieval time, not manifest publication time.
The CrowdSec gauge is zero when disabled or awaiting valid synchronization;
LAPI unavailability does not extend retained decisions. The selected backend's
native counter objects are not collected or exported by this endpoint; their
semantics and inspection paths are in
[Packet and byte accounting](firewall-backends.md#packet-and-byte-accounting).
The broader Prometheus metric surface remains planned (see
[Prometheus metrics](#prometheus-metrics)).

### Reload, recover, and cleanup

1. Edit a complete configuration and send `SIGHUP` to the foreground process.
2. If resolution, compilation, preflight, apply, or durable publication fails,
   keep the active revision and inspect structured logs. Do not delete state to
   force a reload.
3. If enforcement becomes unhealthy, stop ordinary changes. Preserve the
   journal, active record, revisions, source manifests, and ownership metadata;
   restart `run` and let recovery proceed, or invoke explicit cleanup only
   after stopping the daemon.
4. For intentional decommissioning, stop the process, confirm it is inactive,
   run `sudo bin/perimeterd cleanup`, and purge state only after cleanup reports
   success.

Backend-specific mixed-family windows, migration overlap, retained ownership,
and degraded recovery are defined in
[architecture](architecture.md#durable-apply-and-crash-recovery) and
[firewall backend failure behavior](firewall-backends.md#failure-and-cleanup-behavior).

## Supported CrowdSec LAPI prerequisite

**Implemented source-build integration.** CrowdSec LAPI v1.8.1 is the
supported baseline and uses its normal chunked decision stream; no feature-flag
change or older-server pin is required. The wire protocol, synchronization,
expiry, and lease details belong to the [supported LAPI
contract](data-sources.md#supported-lapi-contract).

Register a bouncer in that LAPI deployment and store its API key in a
root-readable file with mode `0600`. Configure `crowdsec.enabled: true`,
`lapi_url`, and `api_key_file`, then run or reload the daemon. Initial
synchronization must succeed before readiness. A same-path key rotation is
reread on `SIGHUP`; a failed replacement retains the old authenticated client
and its bans. The default update frequency is `10s`; request deadlines are at
most `30s`. Failures do not extend a decision's absolute expiry. Lease renewal
continues from retained authority while the writer can safely reconcile it.

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

**Planned package artifact.** A source build does not install these paths or
create a service. The eventual package contract is:

- `/usr/bin/perimeterd`: root-owned static executable;
- `/etc/perimeterd/perimeterd.yaml`: `root:root`, mode `0600`;
- `/etc/perimeterd/credentials.d/`: `root:root`, mode `0700`, with files mode
  `0600`;
- `/var/lib/perimeterd/`: `root:root`, mode `0700`, for state and cache;
- `/run/perimeterd/`: `root:root`, mode `0700`, for runtime state;
- `/run/perimeterd/owner.lock`: root-owned mode `0600` lifecycle lock;
- `/run/xtables.lock`: root-owned mode `0600` shared by iptables and
  ip6tables; and
- a packaged tmpfiles declaration and `perimeterd.service` in the distribution
  system-unit directory.

The package must preserve the lifecycle-lock inode across service stop/restart,
create the state/runtime directories, and provision the shared xtables lock
without unlinking or replacing an existing lock. There is deliberately no
service user in that contract: the process remains UID 0 and is constrained to
`CAP_NET_ADMIN` and `CAP_NET_RAW` by the planned unit.

## systemd service contract

**Planned integration; not runnable from the repository's source build.** The
installed unit is expected to use this shape:

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
ExecReload=/bin/kill -HUP $MAINPID
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

The planned unit must not use `ExecStartPre=validate`: `run` must recover
persisted state before reading current YAML. It must extend the activation
window while bounded startup proceeds and send `READY=1` only after recovery,
source resolution, backend validation, initial reconcile, durable commit, and
any required CrowdSec synchronization. `READY=1` is not a revocable
health assertion; operators must also monitor the enforcement-health metric.

### Bounded startup deadline

The current `run` startup deadline is 75 minutes, measured with a monotonic
clock from process entry. It covers lifecycle ownership, recovery, local
validation, source resolution, compilation, initial apply, and durable
publication. Startup contexts and child-command deadlines are bounded by the
remaining time; request timeouts cannot extend it. Known fatal errors exit
immediately.

The planned unit's [`TimeoutStartSec=90s`](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#TimeoutStartSec=)
is the initial activation window, not the total startup budget. The notification
protocol below is implemented, but a source build does not install a unit.

While initialization is in progress, the main process sends
`EXTEND_TIMEOUT_USEC` immediately and every 20s, requesting the smaller of
60s and the remaining overall deadline, together with a bounded `STATUS`
describing the current phase. The notifier is independent of the serialized
writer so a pending source fetch or apply cannot starve it; notification
delivery failure is surfaced. Requested extension intervals never exceed the
remaining deadline.

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

**Current source-build surface.** If `metrics.listen` is configured, `GET
/metrics` emits:

- `perimeterd_enforcement_health` (unlabeled gauge): `1` only when the selected
  enforcement is healthy; it becomes `0` during degraded recovery. A listener
  failure terminates `run`, so the endpoint is no longer served.
- `perimeterd_prefix_snapshot_timestamp_seconds{source="ripestat"}` (gauge),
  when a source-backed revision is active. It is the oldest required selector's
  retrieval time, not manifest publication time.
- `perimeterd_crowdsec_connected` (unlabeled gauge): the active integration's
  synchronization/poll outcome. It is `0` when disabled, not yet synchronized,
  or after a failed poll/reconnect, and `1` after successful polling/activation.
  It is separate from enforcement health and does not count current bans.

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
packet/byte counter objects independently of this listener. The current source
build does not collect or export those counters over HTTP; disabling metrics
exposition does not change enforcement. See
[firewall accounting](firewall-backends.md#packet-and-byte-accounting) for
traversal and denial semantics.

**Planned release metric surface.** The following names and labels remain the
version-1 observability contract, not a claim that the source build currently
exports them:

- `perimeterd_build_info` (gauge): constant `1` with bounded build metadata.
- `perimeterd_config_reload_total{result}` (counter): reload outcomes.
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

The prefix gauge includes built-in local, configured global, and RIPEstat
prefixes through fixed `source` and `type` label values. Allowed label values
remain bounded: firewall `reason` is `global_blocklist`, `crowdsec`, or
`geo_policy`; `action` is `drop` or `reject`; and counter-read `result` is
`success` or `error`. No metric label may contain an address, ASN, country,
policy name, raw error, or unbounded remote revision.

The planned fixed 15-second background sampler reads native counters through the
serialized backend path and serves last in-memory values without querying the
firewall from the Prometheus handler. When a reconcile replaces raw counters,
it attempts a final read of the retired generation after dispatch switches
away from it and before removal, then establishes the replacement baseline. A
failed final read records an accounting gap and never rolls back enforcement.
Exported process-lifetime totals remain monotonic across reconciles; a daemon
restart is an ordinary Prometheus counter reset.

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

**Planned release artifact.** The intended release produces one `perimeterd`
package as RPM and DEB through GoReleaser v2's nFPM integration. Builds are
static Linux binaries (`CGO_ENABLED=0`) for amd64 (`GOAMD64=v1`) and arm64.
Each package contains the binary, systemd unit, packaged
`/usr/lib/tmpfiles.d/perimeterd.conf` (or the distribution equivalent),
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
[development](development.md) and remain planned.

## Package lifecycle

**Planned release artifact.** Package scripts must never mutate firewall policy
as a side effect:

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

Purge may remove configuration, credentials, cache, and state only after owned
firewall cleanup succeeds. Scripts must not flush global netfilter state,
create Docker-owned chains, infer ownership from names alone, or remove the
host-wide xtables lock.
