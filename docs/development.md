# Development

This document maps the current implementation and executable verification gates,
then defines the full version-1 verification and delivery requirements. The
[implementation plan](implementation-plan.md) is authoritative for milestone
status; a requirement below does not imply that its integration or CI job exists.

The Go module pins Go 1.27.1; see the official
[Go release history](https://go.dev/doc/devel/release).

## Current repository layout

```text
cmd/perimeterd/main.go
internal/app/                 lifecycle, candidates, serialized writer, HTTP and notifications
internal/cli/                 command dispatch, validation and version reporting
internal/config/              YAML schema, defaults and strict validation
internal/config/catalog/      checked-in selector catalogs
internal/policy/              immutable snapshots and backend-neutral compiler
internal/prefix/              prefix normalization and set algebra
internal/firewall/            typed targets, native backend routing and reconciliation
internal/source/              RIPEstat resolution, immutable cache and local HTTP fixtures
internal/state/               revision store, record codec/validation and durable filesystem IO
configs/perimeterd.yaml       full-schema annotated example; not a runtime capability list
.github/workflows/ci.yml      quality, build, unit/race and native firewall gates
.github/workflows/codeql.yml  Go security analysis
tests/e2e/                   native namespace fixtures and runtime/recovery scenarios
docs/                         design contracts, current operations and implementation plan
.golangci.yml                 lint/format policy
Makefile                      local and CI entry points
```

Ownership follows [architecture](architecture.md): `internal/app` owns
revision admission and the serialized writer; `internal/policy` stays
backend-neutral; source resolution and cache publication stay in
`internal/source`; native firewall mutation stays in `internal/firewall`.
The detailed lifecycle, source, configuration, and packet-path contracts belong
to their canonical documents rather than this contributor guide.

The most useful file boundaries when changing an existing path are:

- `internal/app/publication.go`: staged metrics/listener reservations and
  transaction-gated runtime publication.
- `internal/config/catalog/`: checked-in country, RIR, and ASN vocabulary.
- `internal/firewall/exec.go`: bounded native subprocess I/O shared by
  backends.
- `internal/firewall/iptables.go`, `iptables_inventory.go`, `iptables_codec.go`,
  `iptables_model.go`, and `ipset_codec.go`: iptables/ipset staging, inventory,
  native grammars, deterministic lowering, and snapshot decoding.
- `internal/firewall/nftables.go` and `nftables_model.go`: nftables inspection,
  reconciliation, and native model generation.
- `internal/state/store.go`, `records.go`, and `filesystem.go`: durable
  lifecycle, record validation/encoding, and filesystem barriers.
- `tests/e2e/`: namespace admission and isolation (`harness_test.go`), traffic
  probes (`network_test.go`), daemon lifecycle (`daemon_test.go`), geo
  scenarios (`geo_test.go`), native backend scenarios (`nftables_test.go` and
  `iptables_test.go`), runtime/recovery boundaries (`runtime_test.go`,
  `recovery_test.go`), and failure injection (`crash_test.go`).

### Planned additions

CrowdSec runtime support, Docker-specific coexistence, installed
systemd/tmpfiles payloads, package lifecycle scripts, and GoReleaser/release
workflows belong to later milestones. Their eventual package layout should
follow the real integration boundaries; these directories and files are not
present scaffolding.

No `pkg/` tree exists until a real supported public Go API exists. Future
container/Helm delivery adds `build/package/` and `charts/perimeterd/` only
when those artifacts are implemented, not as empty placeholders.

## Pure compiler API

`internal/policy` is the backend-neutral compiler seam. It consumes normalized
configuration and an immutable source snapshot, and emits typed policy state;
it does not fetch sources or mutate the filesystem or kernel. Prefix
normalization and set algebra live in `internal/prefix`, while checked-in
selector vocabulary lives in `internal/config/catalog`.

For behavior rather than package mechanics, use the owning references:
[configuration](configuration.md) defines schema, defaults, and evaluation
semantics; [data sources](data-sources.md) defines selector resolution and
snapshot/cache contracts; [firewall backends](firewall-backends.md) defines
native lowering and packet-path behavior; [architecture](architecture.md)
defines revision admission, publication, and recovery; and
[operations](operations.md) defines runtime procedures, service boundaries, and
metrics. The compiler and backend models have focused unit coverage; the
isolated packet interpreter is test-only.

## Local commands

The `Makefile` is the source of truth for executable local gates. It provides
`fmt`, `fmt-check`, `lint`, `vuln`, `test`, `test-race`, `test-e2e`, `build`, and
`verify`. Use Go 1.27.1, or enable automatic toolchain selection when the
installed Go is older. The race target requires a native C compiler and enables
CGO for that command.

```sh
export GOTOOLCHAIN=auto
make fmt
make verify
make test-race
bin/perimeterd validate --config configs/perimeterd.yaml
```

`make build` writes `bin/perimeterd` with `GOOS=linux`, the host `GOARCH`, and
`CGO_ENABLED=0` by default. Override these variables when a different local
build is needed; for example, `GOARCH=arm64 make build` cross-compiles the
Linux binary. The current CI build matrix checks Linux `amd64` and `arm64`;
other local `GOARCH` values are not release-support claims. Version metadata
defaults to `dev`/`unknown`/`unknown`; override `VERSION`, `COMMIT`, and
`BUILD_TIME` at build time. CI supplies its revision and UTC build timestamp.

`perimeterd validate` is an offline local check. It does not fetch sources or
touch the firewall. Run the opt-in native gate separately:

```sh
make test-e2e
# If unprivileged user namespaces are unavailable:
make test-e2e E2E_SUDO=sudo
```

The `test-e2e` target first builds the binary, then checks for `nft`, `ip`,
`ipset`, `unshare`, `nsenter`, `iptables-nft`, `ip6tables-nft`,
`iptables-legacy`, and `ip6tables-legacy`. The harness requires Linux and also
invokes the corresponding frontends and save/restore tools inside its isolated fixture.
Install `iptables` and `ipset` on Debian-family systems; Fedora provides the
variants in `iptables-nft` and `iptables-legacy`. The host kernel must support
`hash:net`, `hash:ip`, xtables set matches, and IPv4/IPv6 filter and NAT tables.
Load the required modules before using an unprivileged user namespace.

The fixture creates disposable mount, network, PID, and (for unprivileged
callers) user namespaces, verifies isolation before mutation, and mounts
private runtime/state directories. Root callers, including CI with `sudo`,
retain their existing user namespace while executing binaries beneath private
checkout-owned directories. The fixture process is PID-namespace init, so its
exit or timeout terminates descendants. It exercises real CLI lifecycle,
IPv4/IPv6 TCP/UDP packets, reloads, kernel counters, ownership collisions, and
interrupted transactions, and never applies test rules to the development
host's firewall. Tagged E2E sources are formatted and linted by the ordinary
gates but execute only through this target. CI runs this native gate in a
separate Linux job.

Ingress and egress probes distinguish silent DROP from protocol REJECT,
including local UDP sends that return `EPERM` for both actions: a subsequent
ICMP error or receive timeout determines the outcome. TCP exchanges have
explicit deadlines. Configuration files and readiness sockets use private,
unique temporary directories, and table-deletion assertions require successful
ruleset inspection plus explicit absence; command failures, timeouts, and
malformed inspection output fail the assertion.

The executable target inventory is:

| Target | Contract |
| --- | --- |
| `fmt` | Rewrite all Go sources selected with the `e2e` build tag using pinned `gofumpt` followed by `goimports` |
| `fmt-check` | Check pinned `gofumpt` and `goimports` formatting without modifying files |
| `lint` | Run golangci-lint's pinned `gci` diff check and lint policy with the `e2e` build tag |
| `vuln` | Run pinned `govulncheck ./...` |
| `test` | Run shuffled unit tests and write `coverage.out` |
| `test-race` | Run all package tests with the race detector and shuffled order |
| `test-e2e` | Build and run the explicitly privileged Linux namespace/backend scenarios |
| `build` | Build the current CLI with version metadata |
| `verify` | Run `go mod verify`, `fmt-check`, `lint`, `vuln`, `build`, and `test` |

`verify` intentionally does not run `test-race` or `test-e2e`; those are
separate gates. `package` is a planned GoReleaser/nFPM snapshot-packaging
command, not an implemented target or a successful no-op.

Tool dependencies and exact versions are pinned in the `tool` and module
requirements in [`go.mod`](../go.mod). The Make targets invoke them with `go tool`,
so a globally installed tool or a version copied into this guide is not the
authority.

| Tool | Go module | Used by |
| --- | --- | --- |
| `gofumpt` | `mvdan.cc/gofumpt` | `fmt`, `fmt-check` |
| `goimports` | `golang.org/x/tools` | `fmt`, `fmt-check` |
| `golangci-lint` | `github.com/golangci/golangci-lint/v2` | `lint` |
| `govulncheck` | `golang.org/x/vuln` | `vuln` |

GitHub Actions in the existing workflows are pinned to immutable commit SHAs
with comments naming their releases. No current workflow downloads an
unpinned `latest` binary.

## Static and dependency analysis

Formatting uses `gofumpt` followed by `goimports`; `.golangci.yml` separately
enables the `gci` import-order formatter for its diff check. The pinned
golangci-lint policy enables `govet`, `staticcheck`, `errcheck`, `revive`,
`gosec`, and US spelling checks. `make verify` also runs `go mod verify` and
`govulncheck`.

Unit tests run shuffled to expose ordering assumptions, while race tests run
in a separate command. `make test` writes `coverage.out`; coverage is
diagnostic and has no vanity threshold. Behavior-focused review of the
[verification matrix](#verification-matrix), not coverage percentage, is the
release gate.

CodeQL scans Go on pull requests and pushes to `main`, plus its configured
weekly schedule. Renovate currently tracks Go modules and GitHub Actions,
including the pinned development tools; it does not track a nonexistent
GoReleaser workflow. GitHub Actions updates must retain immutable
commit SHAs and refresh their human-readable release comments.

## Version 1 verification and delivery requirements

The remaining sections are the complete first-release contract, not a list of
currently passing tests. The local commands above describe what can run now.
Static source-backed policy and both native backend paths are implemented;
CrowdSec runtime support, Docker-specific coexistence, package/systemd
integration, and release workflows remain planned. The
[implementation plan](implementation-plan.md) tracks milestone status.

## Verification matrix

The tables below are the canonical requirements matrix, not an inventory of
currently passing tests. Every row names a contract, a concrete behavior or
failure boundary, and the required verification layer. Unit and fixture tests
assert behavior or typed/model output, not
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

The current `tests/e2e/` suite exercises direct-global and source-backed geo
policy on nftables and both iptables tool families in disposable Linux namespaces.
The shared packet matrix covers country/RIR/group/ASN selectors, exclusions,
priority, family-empty behavior, and retained policy after source failure.
The iptables suite additionally verifies per-family compensation, crash recovery,
backend migration, custom attachment/interface matching, original-destination
ports, and preservation of foreign chains, rules, and ipsets.
Prerequisites are described under [local commands](#local-commands).
Unit/integration source tests use local HTTP servers and checked-in official
RIPEstat responses with provenance metadata.

The version-1 suite must expand that coverage with CrowdSec and Docker scenarios.
The matrix above defines those acceptance requirements.

The planned separate Docker job must execute the [Docker coexistence row](#kernel-backend-and-coexistence).
The planned CrowdSec compatibility job must use a pinned real supported LAPI
rather than fixtures, with deployment and server-source review as specified in
the [sources and compatibility matrix](#sources-and-compatibility).

Shared namespace, mount, fixture, cleanup, host-isolation, availability, and
iptables-family prerequisites are the [test-isolation contract in the service
and packaging matrix](#service-and-packaging).

## Pull-request and branch CI

The existing `.github/workflows/ci.yml` triggers for pull requests targeting
`main` and pushes to `main`. It has three current jobs:

- `verify (amd64)` runs `make verify`, then `make test-race`, and uploads
  `coverage.out`.
- `build` runs `make build` for both `GOARCH=amd64` and `GOARCH=arm64`.
- `privileged firewall E2E` installs the namespace prerequisites and runs
  `E2E_SUDO=sudo make test-e2e`, covering the nftables and both iptables tool
  families selected by the suite.

The separate `.github/workflows/codeql.yml` scans Go for the same pull-request
and `main` push events plus its weekly schedule. These workflows are the
current executable CI gates; the matrix below remains the full first-release
verification contract.

Before version 1, CI must also implement the matrix's Docker, pinned CrowdSec
compatibility, package installation/upgrade, and systemd-VM gates. Listing them
as requirements does not mean those jobs exist.

Workflow permissions are read-only by default and elevated only for a job's
required security or artifact operation. Superseded runs for the same branch or
pull request use concurrency cancellation. The planned release workflow must
never cancel an earlier release because a later tag arrived.

## Release workflow

**Planned:** `.github/workflows/release.yml` and GoReleaser configuration do not
exist yet. The following is the release acceptance contract.

The workflow must trigger only on signed SemVer tags matching
`vMAJOR.MINOR.PATCH`. Tag signature and exact pattern validation must precede
build. It must run the complete static-analysis, unit, race, privileged E2E,
Docker, CrowdSec compatibility, and package gates from the
[matrix](#verification-matrix), then invoke GoReleaser v2.

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
