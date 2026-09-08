# Development

This document defines the proposed implementation layout, engineering gates,
test boundaries, CI, and releases. It creates no implementation scaffolding.
The design baseline is Go 1.27, the current stable major release during this
design pass; see the official [Go release history](https://go.dev/doc/devel/release).

## Proposed repository layout

```text
cmd/perimeterd/main.go
internal/app/                 process lifecycle and event orchestration
internal/config/              YAML schema, defaults, strict validation
internal/configsource/        local source; future remote source boundary
internal/policy/              selectors, precedence, backend-neutral compiler
internal/prefixsource/        source interface, cache, RIPEstat adapter
internal/crowdsec/            LAPI stream adapter and expiring decision state
internal/firewall/            backend contract and shared desired-state types
internal/firewall/nftables/   netlink implementation
internal/firewall/iptables/   iptables-restore/ip6tables-restore + ipset implementation
internal/state/               atomic on-disk last-known-good snapshots
internal/observability/       slog setup and Prometheus collectors
configs/perimeterd.yaml       commented example configuration
packaging/systemd/            hardened systemd unit
packaging/tmpfiles/           boot-safe shared xtables lock provisioning
packaging/scripts/            package lifecycle scripts
.github/workflows/            CI, security analysis, release workflows
test/e2e/                     privileged network-namespace and Docker scenarios
docs/                         architecture and operator/developer contracts
.goreleaser.yaml              static binaries and nfpm packages
.golangci.yml                 lint/format policy
Makefile                      small, discoverable local/CI entry points
```

Ownership follows [architecture](architecture.md): `internal/app` alone
coordinates revisions and the serialized writer; source packages return typed
candidates; `internal/policy` knows no backend syntax; backend packages consume
shared immutable state and do not fetch source data.

No `pkg/` tree exists until a real supported public Go API exists. A future
container/Helm delivery adds `build/package/` and `charts/perimeterd/` only
when those artifacts are implemented, not as empty placeholders.

## Local commands

The Makefile exposes small, composable targets:

| Target | Contract |
| --- | --- |
| `fmt` | Run pinned `gofumpt` and `goimports`; fail on a remaining diff in CI |
| `lint` | Run the pinned golangci-lint policy and spelling/import checks |
| `test` | Run shuffled unit tests and write coverage output |
| `test-race` | Run unit tests with the race detector |
| `test-e2e` | Run explicitly privileged network-namespace/backend scenarios |
| `build` | Build the local daemon with version metadata |
| `package` | Create local GoReleaser/nFPM snapshot packages |
| `verify` | Run module, format, lint, vulnerability, build, and test gates |

Tool binaries are pinned in the Go tool/module manifest or a checksummed tool
bootstrap file. GitHub Actions are pinned to immutable commit SHAs, with a
comment naming the human-readable release. No workflow downloads an unpinned
`latest` binary.

## Static and dependency analysis

Formatting uses `gofumpt` followed by `goimports`. The pinned golangci-lint
configuration enables at least `govet`, `staticcheck`, `errcheck`, `revive`,
`gosec`, spelling checks, and import-order checks. CI also runs `govulncheck`
and `go mod verify`.

Unit tests run shuffled to expose ordering assumptions, under the race detector
in a separate job, and produce coverage reports without a vanity threshold.
Coverage is diagnostic; behavior-focused review of the [verification
matrix](#verification-matrix) is the gate. CodeQL scans Go on pull
requests, default-branch pushes, and its configured schedule. Renovate tracks
Go modules, GitHub Actions, GoReleaser, and pinned development tools, and raises
reviewable update pull requests. GitHub Actions updates must retain immutable
commit SHAs and refresh their human-readable release comments.

## Verification matrix

The tables below are the canonical verification matrix. Every row names the
contract, a concrete behavior or failure boundary, and the layer that proves
it. The unit and fixture layers assert behavior or typed/model output, not
shell-source substrings, incidental log prose, implementation call counts, or
a specific internal function decomposition. A row may be exercised by more
than one layer when the real boundary matters.

### Configuration and compiler

| Contract | Concrete behavior or boundary | Verification layer |
| --- | --- | --- |
| YAML contract | Unknown YAML fields are rejected; defaults, local validation, and canonical normalization are applied. | Unit; PR and release CI |
| Selector algebra | Selector union/subtraction and `netip` prefix compaction produce the expected canonical prefixes. | Unit; PR and release CI |
| Global and built-in ranges | Global IP/CIDR normalization and built-in local ranges are retained; allow-over-block precedence is explicit. | Unit; privileged netns E2E |
| Policy priority | Priority ordering, first-matching-traffic-scope compilation, and family-empty allowlist/blocklist behavior remain deterministic. | Unit; privileged netns E2E |
| Decision ordering | Established/new-flow and global-list/CrowdSec/geo ordering are preserved. | Unit; privileged netns E2E |
| Geo classifier | Exact geo-classification boundaries and restored exceptions are enforced, including shared/documentation space that `IsGlobalUnicast` does not exclude. | Unit; privileged netns E2E |
| Country policy | Country allowlist and blocklist behavior is correct by TCP/UDP port. | Privileged IPv4/IPv6 netns E2E where applicable |
| Local-range safety | Built-in LAN ranges remain reachable despite global and CrowdSec bans. | Privileged IPv4/IPv6 netns E2E where applicable |
| Explicit allow precedence | A configured public global allow overrides block, CrowdSec, and geo denial. | Privileged IPv4/IPv6 netns E2E where applicable |
| Direct global blocks | Global IP/CIDR blocks affect new ingress and egress flows. | Privileged IPv4/IPv6 netns E2E where applicable |
| Country egress | Five-country all-port egress is selected as configured. | Privileged IPv4/IPv6 netns E2E where applicable |
| Independent policy changes | SSH and web policy updates/removals are independent rather than replacing one another. | Privileged IPv4/IPv6 netns E2E where applicable |
| Geographic subtraction | Asia-minus-Japan exception subtraction is exact. | Privileged IPv4/IPv6 netns E2E where applicable |
| ASN policy | An ASN match selects the intended policy. | Privileged IPv4/IPv6 netns E2E where applicable |
| Policy cleanup | `disabled` and removed policies clean up their owned enforcement. | Privileged IPv4/IPv6 netns E2E |
| Full-range boundaries | IPv4 `/0` and IPv6 `/0` global and dynamic entries retain allow precedence. | Privileged IPv4/IPv6 netns E2E where applicable |
| Empty geo state | Empty geo policies retain direct global blocks; a truly empty desired state removes accounting and allow-only artifacts. | Privileged IPv4/IPv6 netns E2E |

### Sources and compatibility

| Contract | Concrete behavior or boundary | Verification layer |
| --- | --- | --- |
| RIPEstat country adapter | Checked-in bounded actual-response fixtures cover country success without an echo, validation of an echo when present, unexpected/mismatched identities, and failed status. | Unit with checked-in fixtures; PR and release CI |
| RIPEstat ASN adapter | Checked-in bounded actual-response fixtures cover normalized ASN identity checks, unexpected/mismatched echoes, failed status, and prefix visibility at `query_endtime`. | Unit with checked-in fixtures; PR and release CI |
| CrowdSec snapshot authority | Authoritative initial/reconnect snapshots, decision-ID deletion, overlapping ranges with independent expiry, endpoint replacement, disable, and failed-delta recovery from the current desired projection are preserved. | Unit fixture; privileged netns E2E |
| Raw CrowdSec envelope | Before dependency decoding, HTTP 200 with empty/truncated bodies, missing or duplicate list keys, wrong list types, trailing JSON, or decompressed-size overflow rejects the snapshot and retains existing bans. | Unit fixture; privileged netns E2E |
| Valid empty CrowdSec lists | Complete empty/null lists from a supported server legitimately clear an authoritative snapshot. | Unit fixture; privileged netns E2E |
| Non-deduplicated decisions | Initial/reconnect/incremental streams with two decision IDs for one prefix, deletion of the longer ban, and expiration of the remaining ID remove coverage at the correct deadline rather than retaining a hidden ID. | Unit fixture; real-LAPI compatibility; privileged netns E2E |
| Request adaptation | Startup/scopes and other supported options survive request adaptation while all decision IDs are obtained. A server-shaped valid partial-success envelope demonstrates that JSON validation cannot attest completeness. | Unit fixture; real-LAPI compatibility |
| Real LAPI compatibility | A pinned real supported LAPI verifies all IDs with `dedup=false`, manual deletion of the longer overlapping ban, reconnect, and server-query failures as observable failures rather than valid partial snapshots. | Real supported LAPI compatibility job |
| LAPI deployment mode | The compatibility deployment checks both environment and feature configuration for the disabled defective chunked path. Changing supported LAPI releases or modes requires this gate and reviewed server source evidence; support is not inferred from a version string or HTTP transfer encoding alone. | Real supported LAPI compatibility job; reviewed source evidence |
| Partial-response regression | A regression fixture preserves the known valid-JSON partial response to document why a client-only gate cannot certify server behavior. | Unit fixture; real-LAPI compatibility |
| Refresh safety | Malformed refreshes retain last-known-good rules. | Privileged netns E2E |
| CrowdSec startup/reconnect | Initial CrowdSec synchronization enforces existing bans before readiness; reconnect replaces stale decisions; endpoint replacement fences old events. | Privileged netns E2E |
| Outage behavior | CrowdSec precedence and local expiry work during a fixture outage. | Privileged netns E2E |
| Malformed reconnect | Malformed HTTP 200 CrowdSec snapshots retain bans on reconnect. | Privileged netns E2E |

### Writer and leases

| Contract | Concrete behavior or boundary | Verification layer |
| --- | --- | --- |
| Revision admission | Stale refreshes after reload, superseded reload completions, retired-client events, and out-of-order dynamic-store updates cannot publish stale state. | Unit; PR and release CI |
| Unchanged revisions | Renewal of an unchanged desired revision is admitted without requiring a desired-state change. | Unit; privileged netns E2E |
| Stale operations | A stale operation is rejected without suppressing a required retry. | Unit |
| Lease retention | Retained lease scheduling survives unrelated decision changes. | Unit |
| Deletion before dispatch | Deleting a decision before dispatch does not resurrect it. | Unit |
| Absolute deadlines | Decision deadlines are derived absolutely under response delay/rounding. | Unit; privileged netns E2E |
| Native lease renewal | Renewable native leases cover long bans, outage renewal, failed renewal, process downtime, and final expiry without permanent zero timeouts. | Unit; privileged netns E2E |
| Long-decision admission | Long-decision lease renewal passes writer admission without a desired-state change while preserving deadlines. | Privileged netns E2E |
| Staged replacement | `SIGHUP` performs staged replacement rather than exposing a partial policy. | Privileged netns E2E |

### Persistence and recovery

| Contract | Concrete behavior or boundary | Verification layer |
| --- | --- | --- |
| Cache and snapshots | Strict versioned cache decoding, immutable selector blobs, and complete snapshot manifests reject corruption or malformed state rather than silently accepting it; corruption and crashes before or after active-record commit are covered. | Unit |
| Active-record checkpoints | Crash checkpoints before file sync, before rename, and before directory sync recover using complete observed record bytes; ambiguous rename/sync failures retain recovery evidence and fence work. | Unit; privileged netns E2E |
| Durable commit recovery | Crashes before and after durable commit recover the correct target, snapshot, and owned generations without broad cleanup. | Privileged netns E2E |
| Pending apply recovery | A pending apply journal plus invalid current YAML recovers before configuration failure is reported. | Disposable systemd VM |

### Kernel backend and coexistence

| Contract | Concrete behavior or boundary | Verification layer |
| --- | --- | --- |
| Hook priority validation | nftables hook priority `-200` is rejected, `-199` is accepted, and the signed-32-bit upper boundary is handled independently of selected backend. | Unit |
| nftables model | Exact typed nftables model generation, including stable named counters, is preserved. | Unit |
| iptables model | Exact `iptables-restore`, `ip6tables-restore`, and ipset transaction models preserve stable ownership and accounting-role comments. | Unit |
| DROP and REJECT | DROP timeout is observable and REJECT behavior is protocol-correct. | Privileged IPv4/IPv6 netns E2E where applicable |
| Family transaction | A failed second-family iptables commit restores the previous selection; failed compensation exposes unhealthy enforcement; subsequent recovery succeeds. | Privileged iptables/ipset netns E2E |
| nftables priority reload | OUTPUT denial at the lowest supported priority after conntrack works; priority-only reload preserves enforcement, counters, and dynamic sets; combined priority/policy reload applies both changes atomically; precommit crash recovery restores the previous hook priority and generated references. | Privileged nftables netns E2E |
| Flow symmetry | Established-flow behavior is symmetric for host-originated and inbound connections in both directions. | Privileged IPv4/IPv6 netns E2E where applicable |
| Docker coexistence | A remapped host port receives an ingress policy through `DOCKER-USER` constrained to the external interface with original-destination matching, while unrelated container egress still works. | Separate privileged Docker job |
| Backend tool families | Both validated iptables-legacy and iptables-nft tool families are exercised; save/restore variants are never mixed in one run. | Privileged iptables/ipset netns E2E |

### Metrics

| Contract | Concrete behavior or boundary | Verification layer |
| --- | --- | --- |
| Counter accounting | Backend counter snapshot parsing handles generation rollover, reset detection, failed reads, and monotonic delta accumulation. | Unit |
| Processed metrics | Processed metrics count owned-path traversals, including a packet passing both FORWARD and DOCKER-USER attachments. | Privileged netns E2E |
| Denied metrics | Denied metrics count only executed terminal decisions. | Privileged netns E2E |
| Metric cardinality and reload | Labels stay bounded and totals stay monotonic across a policy reload. | Privileged netns E2E |

### Service and packaging

| Contract | Concrete behavior or boundary | Verification layer |
| --- | --- | --- |
| Lifecycle ownership | Exclusive lifecycle ownership rejects a concurrent `run` or live `cleanup`, including service stop/start without replacing the lock inode. | Privileged netns E2E; disposable systemd VM |
| Test isolation | Tests own namespaces, temporary state, fixture ports, and cleanup. Isolated mount views of both `/run/perimeterd` and `/var/lib/perimeterd` accompany each test network namespace. Tests never run against the host's production namespace or assume public RIPEstat/CrowdSec availability. | Privileged netns E2E |
| Static analysis gates | Formatting, spelling/import policy, pinned lint, module verification, vulnerability analysis, and CodeQL are required gates; tool binaries and Actions remain pinned as stated above. | PR/default-branch CI and release workflow |
| Build and test gates | Normal build, shuffled unit tests, race tests, coverage artifact, privileged nftables E2E, privileged iptables/ipset E2E, Docker, and pinned CrowdSec compatibility are required. | PR/default-branch CI and release workflow |
| Package smoke | RPM/DEB smoke installation checks installed paths and modes, package dependency alternatives, configuration preservation across upgrade, tmpfiles and systemd payloads, and `perimeterd validate`. | Matching-architecture package containers |
| Systemd sandbox | A disposable systemd VM boots with no pre-existing xtables lock and proves the installed service reconciles both supported iptables tool variants under its actual filesystem and capability sandbox. Container payload inspection alone is not evidence that the service sandbox works. | Disposable systemd VM |
| Boot and restart lifecycle | The VM covers install-after-boot tmpfiles provisioning, lifecycle-lock exclusion, retained runtime-directory inode across restart, ongoing degraded enforcement health, and removal failure preserving recovery state. | Disposable systemd VM |
| Startup timeout protocol | A cold-start fixture taking more than `90s` remains activating through `EXTEND_TIMEOUT_USEC` and becomes ready only after commit; a stalled initializer terminates at the overall startup bound without discarding recovery evidence. A fake clock is used for exhaustive deadline boundaries, not to replace the real systemd activation scenario. | Disposable systemd VM; unit fake-clock boundary fixtures |
| Release artifacts | GoReleaser v2 creates static Linux binaries for `amd64` (`GOAMD64=v1`) and `arm64`, one DEB and one RPM per architecture, checksums, SBOMs, a source archive, and GitHub artifact attestations only after all gates pass. | Release workflow; matching-architecture package containers; systemd VM |
| Architecture coverage | Each package is installed in a matching-architecture distribution container; pinned QEMU/binfmt runs non-native architecture containers. | Package smoke |
| Version provenance | Signed tag-derived version, commit, and build time are injected into `perimeterd version` and `perimeterd_build_info`. Untagged branch builds may produce snapshot artifacts for CI but can never publish a release. | Release workflow; package smoke |

## Privileged end-to-end suite

`test/e2e/` runs the built daemon in disposable Linux network namespaces with
veth peers and local fixture HTTP/RIPEstat/CrowdSec servers. The suite executes
for nftables and iptables/ipset, and for IPv4 and IPv6 where the scenario
applies. The matrix above is the scenario inventory; this section records the
shared execution contract rather than repeating those rows.

The separate privileged Docker job executes the [Docker coexistence row](#kernel-backend-and-coexistence). The separate CrowdSec compatibility job uses a pinned real supported LAPI rather than fixtures; its deployment and required server-source review are specified in the [sources and compatibility matrix](#sources-and-compatibility).

Shared namespace, mount, fixture, cleanup, host-isolation, availability, and
iptables-family prerequisites are the [test-isolation contract in the service
and packaging matrix](#service-and-packaging).

## Pull-request and branch CI

`.github/workflows/ci.yml` and `.github/workflows/codeql.yml` run on pull
requests targeting the default branch and pushes to the default branch. They
invoke the verification layers in the [matrix](#verification-matrix):

- static and dependency gates (format, lint, spelling/import policy, module
  verification, vulnerability analysis, and CodeQL);
- normal build, shuffled unit tests, race tests, and a coverage artifact;
- privileged nftables E2E and privileged iptables/ipset E2E;
- Docker and pinned CrowdSec compatibility; and
- RPM/DEB package smoke installation and configuration preservation.

Workflow permissions default to read-only and are elevated per job only when a
specific upload or attestation step requires it. Superseded runs for the same
branch or pull request use concurrency cancellation. Release workflow runs are
never cancelled by a later tag.

## Release workflow

`.github/workflows/release.yml` triggers only on signed SemVer tags matching
`vMAJOR.MINOR.PATCH`. Tag signature and exact pattern validation precede build.
The workflow runs the same static-analysis, unit, race, privileged E2E, Docker,
CrowdSec compatibility, and package gates as ordinary CI, using the verification
layers in the [matrix](#verification-matrix), then invokes GoReleaser
v2.

The release gate executes the release-artifact, architecture-coverage,
package-smoke, systemd-sandbox, boot-and-restart, startup-timeout, and
version-provenance rows in the [service and packaging
matrix](#service-and-packaging). Those rows are the authoritative checks for
GoReleaser v2 outputs, matching-architecture containers and pinned QEMU/binfmt,
installed paths and modes, dependency alternatives, configuration preservation,
tmpfiles/systemd payloads, `perimeterd validate`, the real systemd
filesystem/capability sandbox, pending-apply recovery, `EXTEND_TIMEOUT_USEC`,
fake-clock boundaries, and version metadata.

Only after those checks, the workflow publishes a GitHub Release with:

- two DEBs and two RPMs;
- checksums;
- SBOMs;
- a source archive; and
- GitHub artifact attestations.

The signed tag-derived version, commit, and build time are injected into
`perimeterd version` and `perimeterd_build_info`. An untagged branch build may
produce snapshot artifacts for CI but can never publish a release.

## License discipline

The repository remains MIT-licensed. Behavior may be studied from
[geoip-shell](https://github.com/friendly-bits/geoip-shell), but its GPL-3.0
implementation is not copied or translated. Reuse of the MIT-licensed
[CrowdSec firewall bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer)
or [Go bouncer client](https://github.com/crowdsecurity/go-cs-bouncer) requires
normal dependency review and preservation of applicable copyright and license
notices in distributions.
