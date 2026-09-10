# Operations

For the planned version 1 release, this document specifies the installed
system, systemd service, observability, and package lifecycle.
[Configuration](configuration.md) defines operator fields; [architecture](architecture.md)
defines readiness and cleanup safety.

## Current source-build runtime

The implemented runtime is limited to `firewall.backend: nftables`, direct
`global.allowlist`/`global.blocklist` IPs and CIDRs, disabled geo policy modes,
and `crowdsec.enabled: false`. ASN/country/RIR/group source resolution and the
iptables/ipset backend are not wired into the runtime yet. Offline `validate`
still checks the full configuration contract; successful validation does not
mean an unsupported runtime integration is available.

Use a disposable VM or isolated network namespace, not the development host's
firewall. A minimal direct-rule configuration is:

```yaml
version: 1
global:
  allowlist: []
  blocklist: ["8.20.0.2/32"]
firewall:
  backend: nftables
  ipv4: true
  ipv6: true
policies: []
crowdsec:
  enabled: false
```

Build with `make build`, save the configuration as
`/etc/perimeterd/perimeterd.yaml`, and run:

```sh
sudo bin/perimeterd run --config /etc/perimeterd/perimeterd.yaml
```

`run` remains in the foreground. Send `SIGHUP` to stage a reload and `SIGTERM`
to stop without removing enforcement. After stopping, `sudo bin/perimeterd
cleanup` removes only recorded owned artifacts; it does not read current YAML.
Do not remove `/var/lib/perimeterd` or the stable `/run/perimeterd/owner.lock`
to bypass recovery or ownership checks. The runtime creates its private state
and runtime directories when needed and holds the same lock for its lifetime.

Immutable revision files, the prepared journal, and durable `active.json`
publication define recovery authority. Startup recovers persisted state before
reading YAML. An uncertain publication fences new applies until stabilization;
post-commit retirement failures are retried without rolling back the committed
revision. Ownership inspection rejects unknown children. nftables sets use their
recorded owner/generation-qualified names plus exact type, flags, and contents
inside the marked table: nft JSON does not round-trip set comments.

Encoded state records are limited to 16 MiB and rejected before publication if
oversized. Native preflight requires each complete target to fit the 8 MiB
installation limit and budgets inspection of both retained generations before
preparing a transaction. The conservative inspection budget is 48 MiB per table,
with a hard 64 MiB native-output capture limit. Oversized reloads leave the
committed revision recoverable rather than installing unreadable state.

When configured, `/metrics` currently exposes `perimeterd_enforcement_health`;
named kernel packet/byte counters remain in nftables. The full metric suite,
installed systemd unit, packages, and release gates below remain planned.
Startup sends bounded systemd timeout extensions and `READY=1` only after
reconciliation, durable commit, and required recovery complete.
The metrics server bounds complete request reads and response writes to ten
seconds, headers to five seconds, and idle keep-alive connections to thirty
seconds; a client withholding a request body cannot retain a connection forever.
During listener replacement, an expired graceful-shutdown deadline does not
degrade enforcement health if the old listener and connections are successfully
force-closed. Actual resource-close failures still degrade health.

The following operator sequence assumes the planned package and installed unit,
not just the current source build.

## Operator sequence

### Prerequisites

1. Install the package. Its post-install hook provisions the shared xtables
   lock when systemd is available; no service starts automatically.
2. If installing after boot, confirm `/run/xtables.lock` was created by the
   packaged tmpfiles declaration before enabling the unit.
3. If `crowdsec.enabled` is true or the LAPI endpoint is being replaced,
   complete the [supported LAPI prerequisite](#supported-crowdsec-lapi-prerequisite)
   checks, including both feature-flag locations. `validate` cannot perform
   the remote attestation; leave CrowdSec disabled until the operator checks
   pass.
4. Ensure the selected backend tools and any configured parent chains exist.
   For iptables, verify the validated legacy or nft variant is a matched
   IPv4/IPv6 set and that `/run/xtables.lock` is the shared writable host file.

### Configure and validate

5. Write `/etc/perimeterd/perimeterd.yaml` and any credential file as root with
   mode `0600`.
6. Run `perimeterd validate --config /etc/perimeterd/perimeterd.yaml`.

### Start and check health

7. Enable and start `perimeterd.service`; check readiness, the bounded
   `perimeterd_enforcement_health` metric, journal, and `/metrics`.
8. For a manual `perimeterd run` outside systemd, first run the installed
   tmpfiles declaration, create `/run/perimeterd` if systemd is not managing
   `RuntimeDirectory`, and run as root. Never substitute a private xtables lock.

### Reload, recover, and cleanup

9. Use `systemctl reload perimeterd` for staged changes. A health value of `0`
   after readiness requires recovery; it is not made healthy by systemd's
   already-sent `READY=1`. If recovery fails, repair prerequisites and restart,
   or stop the service and invoke explicit cleanup as described in the
   [durable recovery contract](architecture.md#durable-apply-and-crash-recovery);
   preserve recovery metadata and do not purge state.
10. Before intentional decommissioning, stop the service and confirm it is
    inactive, then run `perimeterd cleanup`. Purge configuration or state only
    after cleanup reports success; a failure preserves recovery metadata and
    owned locks for retry.

## Supported CrowdSec LAPI prerequisite

Before setting `crowdsec.enabled: true`, install and verify the reviewed
CrowdSec v1.7.6 LAPI deployment described in the [supported LAPI
contract](data-sources.md#supported-lapi-contract). This is the only version 1
baseline; a future CrowdSec version requires review before it is used.

The `chunked_decisions_stream` feature must be disabled in both locations on
the CrowdSec host:

- in the environment of the `crowdsec` process, set
  `CROWDSEC_FEATURE_CHUNKED_DECISIONS_STREAM=false`; and
- in `ConfigDir/feature.yaml` (normally
  `/etc/crowdsec/feature.yaml`), leave out the
  `- chunked_decisions_stream` list entry.

An environment value of `false` does not override a YAML list entry that
enables the feature. If `ConfigDir/feature.yaml` still contains
`- chunked_decisions_stream`, the feature remains enabled. Inspect both
locations, restart CrowdSec after changing either one, and inspect the new
process's effective environment and loaded feature configuration.

This is an operator-checked deployment prerequisite, not a capability that
perimeterd can attest remotely. `perimeterd validate` checks local
configuration and cannot prove the remote CrowdSec version or effective
feature state. Successful authentication, HTTP status, response-envelope
validation, or a `Transfer-Encoding` header likewise cannot prove that the
server is using the safe supported path or that the backend is complete.
Before initial enable and every LAPI endpoint replacement, check the server
version and both feature-flag locations, then run `perimeterd validate`; enable
or reload only after those checks pass. The protocol and request details remain
in the [source contract](data-sources.md#supported-lapi-contract).

## Lifecycle lock and recovery

Before reading or mutating firewall state, persisted ownership metadata, or
recovery state, both `perimeterd run` and `perimeterd cleanup` open
`/run/perimeterd/owner.lock` and acquire an exclusive nonblocking `flock`.
This is process-lifetime ownership, not merely iptables serialization. A
second daemon, or cleanup while the service is active, fails clearly and
performs no mutation. Stop the service and confirm it is inactive before
package scripts or an operator invokes cleanup. Neither command unlinks or
replaces `owner.lock`; `RuntimeDirectoryPreserve=yes` protects its inode while
the service and cleanup hand off ownership. See the
[exclusive lifecycle ownership contract](architecture.md#exclusive-lifecycle-ownership).

The xtables lock remains a separate host-wide lock used by legacy and nft
iptables restore operations. It does not replace the lifecycle lock and does
not serialize nftables changes, target migration, or persisted metadata.

For operator-visible recovery behavior, see the architecture's
[durable apply and crash recovery](architecture.md#durable-apply-and-crash-recovery)
and [failure safety](architecture.md#failure-safety) contracts. In particular,
iptables IPv4 and IPv6 applies are separate operations: a failure after one
family commits can expose a mixed-generation window. Compensating rollback is
attempted but cannot erase that window. If rollback or recovery cannot restore
the last committed target, perimeterd retains recovery metadata and keeps the
last committed revision authoritative, reports enforcement degraded, and blocks
ordinary reload or other mutation.
Only recovery or explicit cleanup may proceed under the lifecycle lock.

Target migration applies the replacement before removing the recorded old
target. During overlap both owned targets can enforce and may overblock. Old
target cleanup must finish before migration is healthy; if it fails, both
targets and recovery metadata remain for operator repair, the daemon is
not-ready on the next activation, and enforcement health stays degraded. See
[backend and target migration](architecture.md#backend-and-target-migration).

Recovery metadata is never discarded to make a stop, upgrade, removal, or
failed cleanup appear successful. The durable active-record transaction is the
commit point; journal phases alone are not authoritative. If recovery fails,
state and ownership records remain intact and mutations stay blocked except for
recovery or explicit cleanup. Package purge is forbidden until owned cleanup
has succeeded.

## Installed layout

- `/usr/bin/perimeterd`: root-owned executable; static daemon and CLI.
- `/etc/perimeterd/perimeterd.yaml`: `root:root`, mode `0600`; configuration.
- `/etc/perimeterd/credentials.d/`: `root:root`, mode `0700`; secret directory.
- `/etc/perimeterd/credentials.d/*`: `root:root`, mode `0600`; credentials.
- `/var/lib/perimeterd/`: `root:root`, mode `0700`; state and cache.
- `/run/perimeterd/`: `root:root`, mode `0700`; runtime state.
- `/run/perimeterd/owner.lock`: root-owned mode `0600` lifecycle lock shared by
  `run` and `cleanup`.
- `/run/xtables.lock`: root-owned mode `0600` host-wide lock shared by the
  iptables and ip6tables command families.
- `/usr/lib/tmpfiles.d/perimeterd.conf` (or the distribution's equivalent
  tmpfiles directory): packaged declaration for the shared xtables lock.
- `perimeterd.service`: `root:root`, mode `0644`; distribution system unit.

The package installs the unit into the distribution's system unit directory,
commonly `/usr/lib/systemd/system/` or `/lib/systemd/system/`; operators do not
hard-code one path across distributions. systemd creates the state and runtime
directories with `StateDirectory=perimeterd` and
`RuntimeDirectory=perimeterd`. `RuntimeDirectoryPreserve=yes` keeps
`/run/perimeterd/owner.lock` available with the same inode across a service
stop/restart, so a stopped service can hand the lock to an explicitly invoked
cleanup command.

The package's tmpfiles payload contains this declaration:

```text
f /run/xtables.lock 0600 root root -
```

The `f` entry creates the exact host lock when it is absent and does not
unlink, replace, or truncate an existing lock. It is never moved into a
private service namespace or replaced with a per-service lock. Package scripts
and cleanup therefore leave `/run/xtables.lock` in place even when perimeterd
is removed.

There is deliberately no service user. The process remains UID 0 so
`iptables-restore --wait` and `ip6tables-restore --wait` interoperate through
the root-owned global xtables lock rather than a separate, non-interoperable
lock. The unit constrains privileges to `CAP_NET_ADMIN` and `CAP_NET_RAW` plus
filesystem hardening. The iptables backend supports both the legacy
(`iptables-legacy`/`ip6tables-legacy`) and nft
(`iptables-nft`/`ip6tables-nft`) command variants. Startup and reload validate
a matched IPv4/IPv6 save/restore tool family, the selected variant's `ipset`
compatibility, and access to the shared lock; a missing or mixed variant fails
closed rather than silently falling back.

## systemd service contract

The packaged unit follows this model:

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

`systemd-tmpfiles-setup.service` is required and ordered before perimeterd, so
the packaged declaration provisions `/run/xtables.lock` during boot before the
daemon can run. `ProtectSystem=strict` is retained; `ReadWritePaths` grants
the daemon access to that exact host file and does not make `/run` generally
writable. The service never uses a private lock path and never unlinks or
recreates the host lock.

`After=crowdsec.service` is ordering only; it does not require or start
CrowdSec. CrowdSec-disabled systems remain valid. When CrowdSec is enabled,
the operator must first satisfy the [supported LAPI
contract](data-sources.md#supported-lapi-contract). Then `run` must complete
authentication, an authoritative initial LAPI decision synchronization, and
application of that synchronized decision set in the initial firewall
reconcile before it sends `READY=1`. Authentication and response-envelope
validation are necessary input checks, not proof that the remote backend
implements the supported server path or complete decision contract. A
connected or authenticated client without a completed authoritative sync is
not ready. Failure of that initial sync or application prevents readiness and
lets systemd retry the service.

The process stays in the foreground and never writes a PID file or application
log file. It sends `READY=1` only after source-dependent validation, metrics
bind, backend-variant validation, the required initial CrowdSec work (when
enabled), the initial firewall reconcile, and durable active-record commit.
See systemd's
[`Type=notify` service behavior](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#Type=)
and [execution sandbox options](https://www.freedesktop.org/software/systemd/man/latest/systemd.exec.html).

### Recovery before validation

The service invokes `run` directly: it has no `ExecStartPre=validate`.
`run` first acquires lifecycle ownership and recovers journaled transactions
using persisted state, even if the current YAML is missing or invalid. Only
after recovery completes does it parse and validate that YAML and initialize
sources. A configuration error then exits nonzero without undoing recovered
enforcement. The standalone `validate` command remains available for operators
and packaging checks; it is not a prerequisite that can block recovery.

### Bounded startup deadline

Version 1 gives each `run` invocation a fixed overall startup deadline of
`75m`, measured with a monotonic clock from process entry. It includes ownership
acquisition, recovery, validation, source resolution, compilation, initial apply,
and durable commit. All startup contexts and child-command deadlines are
bounded by the remaining time; a configured request timeout does not extend
the overall deadline. A known fatal error exits immediately rather than waiting.

`TimeoutStartSec=90s` is the explicit initial systemd activation window, not
the total allowed initialization time. While initialization is in progress,
the main process sends `EXTEND_TIMEOUT_USEC` immediately and every `20s`,
requesting the smaller of `60s` and the remaining overall deadline, together
with a bounded `STATUS` describing the current phase. The notifier is separate
from the serialized writer so a pending fetch or apply cannot starve it, and
notification delivery failure is surfaced. Requested extension intervals never
exceed the remaining overall deadline. See
[systemd startup timeout extension](https://www.freedesktop.org/software/systemd/man/latest/systemd.service.html#TimeoutStartSec=).

This accommodates 512 uncached selectors at concurrency four even when every
successful request takes the default `30s`: fetching consumes up to `64m`,
leaving `11m` for other initialization. It is a deadline policy, not a promise
that arbitrarily slow sources or recovery always succeed. No independent
retry loop resets the startup clock.

At the overall deadline, cancel startup, admit no further mutations, withhold
`READY=1`, and exit nonzero. Preserve the journal and every required recovery
object if apply/compensation cannot finish; the next invocation recovers them.
systemd enforces the last requested activation deadline if the process stalls.
Direct non-systemd runs enforce the same overall deadline without notification
delivery. After readiness the startup timer and extensions stop; this mechanism
is not a runtime watchdog and does not change reload semantics.

A reload stages `SIGHUP`; reload failure keeps the active revision. A normal
stop leaves static rules and current dynamic kernel leases in place. CrowdSec
bans are not guaranteed to persist for their full source duration while the
daemon is down: capped leases expire unless a running owner renews them.
Static policy remains active independently. See the
[source lease contract](data-sources.md#overlap-expiry-and-backend-projection).
`run` and `cleanup` share the lifecycle lock described below; cleanup is only
for explicit removal of owned artifacts after the service has stopped.

## Prometheus metrics

The daemon serves unauthenticated Prometheus exposition at exactly `/metrics`
on `metrics.listen`. The default `127.0.0.1:2112` is loopback-only; an empty
string disables the listener. Operators exposing another address must provide
network access control or a trusted proxy. Initial bind failure prevents
readiness; a reload binds the replacement listener before committing the
revision.

The version 1 metric surface is:

- `perimeterd_build_info` (gauge): constant `1` with bounded build metadata.
- `perimeterd_config_reload_total{result}` (counter): reload outcomes.
- `perimeterd_reconcile_total{reason,result}` (counter): reconcile outcomes.
- `perimeterd_reconcile_duration_seconds{reason}` (histogram): apply latency.
- `perimeterd_prefixes{family,source,type}` (gauge): active prefix count.
- `perimeterd_prefix_snapshot_timestamp_seconds{source}` (gauge): snapshot time.
- `perimeterd_source_requests_total{source,result}` (counter): request outcomes.
- `perimeterd_crowdsec_decisions{family}` (gauge): active unexpired bans.
- `perimeterd_crowdsec_connected` (gauge): `1` while connected.
- `perimeterd_backend_apply_total{backend,result}` (counter): apply outcomes.
- `perimeterd_enforcement_health` (gauge): unlabeled; `1` only while the
  committed static selection and current desired dynamic projection are known
  applied and required cleanup is complete; `0` during partial apply, pending
  failed dynamic updates, degraded recovery, or incomplete target cleanup.
- `perimeterd_firewall_processed_packets_total{backend,family,direction}`
  (counter): owned direction-path traversals entering the perimeterd path.
- `perimeterd_firewall_processed_bytes_total{backend,family,direction}`
  (counter): bytes entering an owned direction-path traversal.
- `perimeterd_firewall_denied_packets_total{backend,family,direction,reason,action}`
  (counter): terminal denial decisions actually executed by perimeterd.
- `perimeterd_firewall_denied_bytes_total{backend,family,direction,reason,action}`
  (counter): bytes for terminal denial decisions actually executed by
  perimeterd.
- `perimeterd_firewall_counter_read_total{backend,result}` (counter): kernel
  counter-read outcomes.
- `perimeterd_firewall_counter_timestamp_seconds{backend}` (gauge): time of
  the last successful kernel counter read.

The prefix gauge includes built-in local, configured global, and RIPEstat
prefixes through fixed `source` and `type` label values.

Allowed label values come from fixed enumerations. Firewall counter `reason` is
`global_blocklist`, `crowdsec`, or `geo_policy`; `action` is `drop` or
`reject`; and counter-read `result` is `success` or `error`. Metrics never use
an IP, ASN, country, policy name, raw error text, or unbounded remote revision
as a label. `perimeterd_enforcement_health` has no labels and is the bounded
post-readiness enforcement signal.

`processed` counts each traversal when it enters an owned perimeterd
direction path, including traversals that later return because they are
established, non-new, globally allowed, non-global, or unmatched. A packet may
traverse multiple valid attachments, such as `FORWARD` and `DOCKER-USER`, or
both target generations during migration; each traversal contributes, so this
is not a globally unique-packet total and no packet-mark de-duplication is
used. A return is not an acceptance verdict from the surrounding firewall.
`denied` counts only the terminal perimeterd denial decision actually executed
on a traversal. It does not count an unexecuted duplicate rule or a generated
rejection response. Executed terminal rules from multiple generated paths
contribute to the bounded aggregate reason; policy identities never become
metric labels.

A fixed 15-second background sampler reads kernel counters through the
serialized backend path and serves the last in-memory values without querying
the firewall from the Prometheus handler. A reconcile that replaces raw
counters attempts a final read of the retired generation after the dispatch
switch and before removal, then establishes the replacement baseline. A failed
final read records an accounting gap but never rolls back enforcement. The
exported process-lifetime counters otherwise remain monotonic across
perimeterd reconciles. A daemon restart is an ordinary Prometheus counter
reset.

A failed read retains the prior values, increments the error result, and
leaves the last-success timestamp unchanged. Counter collection never changes
firewall state or readiness. These metrics are operational telemetry, not
lossless billing or audit records: a process or host crash, external rule
replacement, or external counter reset can lose accounting. Snapshot age is
derived from the prefix timestamp gauge; firewall-counter staleness is derived
from the counter timestamp gauge. Exposition follows the official
[Prometheus exposition format](https://prometheus.io/docs/instrumenting/exposition_formats/).

`READY=1` is a systemd activation notification, not a revocable enforcement
health assertion. A post-readiness apply, rollback, or migration-cleanup
failure sets `perimeterd_enforcement_health` to `0` and reports status and
bounded metrics; the daemon does not pretend it can retract `READY=1`.
Health returns to `1` only after serialized recovery confirms the active
committed enforcement and required cleanup. Operators must alert on this
metric in addition to systemd readiness.

## Logging

Logging uses the Go standard library `log/slog` and writes stdout only;
stderr is reserved for process-start failures before logging initializes. Both
streams remain attached to journald under systemd. Supported levels are
`debug`, `info`, `warn`, and `error`; formats are human-readable `text` and
machine-readable `json`.

Every record has a timestamp and message. Stable fields are used where
applicable:

- `component`
- `operation`
- `revision`
- `backend`
- `policy`
- `family`
- `duration`
- `error`

The API key, credential contents, authorization headers, full prefix lists,
and packet IP addresses are forbidden. Error values are scrubbed at the
network boundary so wrapped errors cannot leak credentials.

## Packages

One package named `perimeterd` is produced as both RPM and DEB with
[GoReleaser v2's nFPM integration](https://goreleaser.com/customization/nfpm/).
Builds are static Linux binaries with `CGO_ENABLED=0` for:

- `amd64` with `GOAMD64=v1`; and
- `arm64`.

Each package contains the binary, systemd unit, packaged tmpfiles payload
`/usr/lib/tmpfiles.d/perimeterd.conf` (or the distribution equivalent),
commented example configuration, [MIT license](../LICENSE), and
documentation. The example configuration is installed with nFPM type
`config|noreplace`; upgrades never replace an operator-edited file.

Dependency relationships guarantee either nftables or the complete
iptables/ipset pair:

- Debian: `nftables | iptables, nftables | ipset`
- RPM rich dependency: `(nftables or (iptables and ipset))`

The selected backend remains an explicit YAML choice; package dependency
resolution does not auto-select it. When iptables is selected, the daemon
explicitly validates either the host's legacy command variant or its nft
variant, including matching IPv4/IPv6 tools and the shared xtables lock; it
does not silently switch variants after startup.

## Package lifecycle

Package scripts have narrow responsibilities and never mutate firewall policy
as a side effect:

- **Post-install:** install the unit and tmpfiles payload, run
  `systemd-tmpfiles --create` against the installed perimeterd tmpfiles file
  when systemd is available (including installation after boot), and run
  `systemctl daemon-reload`. Report a provisioning failure and do not enable
  or start the daemon. Print enable/configuration guidance only; do not enable
  or start an unconfigured firewall daemon.
- **Upgrade:** preserve configuration, credentials, state, recovery and
  ownership metadata, and active firewall rules. Restart only under
  distribution policy; never run cleanup, purge state, or unlink/recreate
  `/run/xtables.lock` or `/run/perimeterd/owner.lock`.
- **Final removal:** stop `perimeterd.service` and require it to be inactive,
  then invoke `perimeterd cleanup` under the shared lifecycle lock using
  persisted target metadata. Remove packaged files only after cleanup
  succeeds, and reload systemd. If stopping or cleanup fails, report the error
  and preserve active rules, recovery metadata, ownership metadata, state, and
  locks; do not broaden deletion.
- **Purge:** additionally remove configuration, credentials, cache, and state
  according to package-manager semantics only after owned-rule cleanup has
  succeeded. A failed cleanup forbids purging state or recovery metadata and
  requires an explicit recovery or cleanup retry.

Scripts never alter host default firewall policies, globally flush netfilter,
create Docker chains, infer ownership from object names alone, or remove the
host-wide xtables lock.

