# Development

This document maps the current implementation and executable verification gates,
then defines the full version-1 verification and delivery requirements. The
[implementation plan](implementation-plan.md) is authoritative for milestone
status; a requirement below does not imply that its integration or CI job exists.

The Go module pins Go 1.27.1; see the official
[Go release history](https://go.dev/doc/devel/release).

## Contents

- [Current repository layout](#current-repository-layout)
- [Pure compiler API](#pure-compiler-api)
- [Local commands](#local-commands)
  - [Native namespace gate](#native-namespace-gate)
  - [Docker gate](#real-docker-coexistence-gate)
  - [Real-LAPI gate](#real-lapi-compatibility-gate)
  - [OpenZiti gate](#real-openziti-transport-gate)
- [Opt-in scale measurements](#opt-in-scale-measurements)
- [Version 1 verification and delivery requirements](#version-1-verification-and-delivery-requirements)
- [Verification matrix](#verification-matrix)
- [Privileged end-to-end suite](#privileged-end-to-end-suite)
- [Pull-request and branch CI](#pull-request-and-branch-ci)
- [Release workflow](#release-workflow)
- [License discipline](#license-discipline)

## Current repository layout

```text
cmd/perimeterd/main.go
internal/app/                 lifecycle, candidates, serialized writer, HTTP and notifications
internal/cli/                 command dispatch, validation, lookup and version reporting
internal/config/              YAML schema, defaults and strict validation
internal/config/catalog/      checked-in country/group/RIR catalogs and ASN validation
internal/crowdsec/            bounded LAPI adapter, authoritative store and timed projection
internal/lookup/              pure applied-state evaluation, attribution and private query transport
internal/policy/              immutable snapshots and backend-neutral compiler
internal/prefix/              prefix normalization and set algebra
internal/firewall/            typed targets, native backend routing and reconciliation
internal/source/              RIPEstat, text-list/provider resolution and immutable cache
internal/state/               revision store, record codec/validation and durable filesystem IO
internal/upstream/            identity capture, bounded SDK admission and service-bound HTTP pools
configs/perimeterd.yaml       annotated complete configuration example
.github/workflows/ci.yml      quality, build, unit/race, native firewall, Docker, LAPI and Ziti gates
.github/workflows/codeql.yml  Go security analysis
tests/e2e/                   native namespace fixtures and runtime/recovery scenarios
tests/crowdsec/              pinned real-LAPI streaming compatibility gate
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

- `internal/config/config.go`, `parse.go`, and `normalize.go`: normalized public
  models, strict raw YAML decoding, and defaults/semantic normalization.
- `internal/app/candidate.go` and `staged_candidate.go`: immutable candidate data
  and separately owned transient staging resources.
- `internal/upstream/identity.go` and `manager.go`: validated credential capture
  and identity-generation/session lifecycle.
- `internal/source/source.go`: shared selector metadata and active identity-profile
  selection; `cache_format.go` and `cache.go`: canonical cache wire validation and
  filesystem storage.
- `internal/app/publication.go`: staged metrics/listener reservations and
  transaction-gated runtime publication.
- `internal/app/crowdsec.go`: staged client epochs, serialized dynamic
  reconciliation, independent expiry/renewal workers, and reconnect handover.
- `internal/crowdsec/`: response validation, decision identity, absolute
  deadlines, and maximum-expiry overlap projection.
- `internal/app/lookup.go`: atomic applied-view publication, invalidation,
  acknowledged dynamic lease evidence, and query completion fencing.
- `internal/lookup/`: complete address/traffic partitions, source explanation,
  strict bounded HTTP-over-Unix transport, and the daemon client.
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
  scenarios (`geo_test.go`, `custom_list_test.go`, and `providers_test.go`), native backend scenarios (`nftables_test.go` and
  `iptables_test.go`), real Docker coexistence (`docker_harness_test.go`,
  `docker_test.go`), actual daemon lookup and packet parity (`lookup_test.go`),
  runtime/recovery boundaries (`runtime_test.go`, `recovery_test.go`), OpenZiti
  acceptance scenarios and fixture machinery (`openziti_test.go`,
  `openziti_harness_test.go`), and failure injection (`crash_test.go`).

### Planned additions

Installed systemd/tmpfiles payloads, package lifecycle scripts, and
GoReleaser/release workflows belong to later milestones. Their eventual package
layout should follow the real integration boundaries; these directories and files are not
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

The `Makefile` is the source of truth for executable local gates and scale
profiles. It provides `fmt`, `fmt-check`, `lint`, `vuln`, `test`, `test-race`,
`build`, `build-e2e`, `test-e2e`, `test-crowdsec`, `test-openziti`, `test-docker`,
`verify`, and the four opt-in scale targets. Use Go 1.27.1, or enable automatic
toolchain selection when the installed Go is older. The race target requires a
native C compiler and enables CGO for that command.

### Correctness and build gates

```sh
export GOTOOLCHAIN=auto
make fmt
make verify
make test-race
bin/perimeterd validate --config configs/perimeterd.yaml
```

`make fmt` rewrites the Go sources selected with the `e2e,crowdsec` build
tags. `make fmt-check` checks the same source set without modifying files.
`make lint` runs the pinned `golangci-lint` formatting diff and lint policy;
the lint pass uses the `e2e,crowdsec` build tags. `make vuln` runs
`govulncheck`. `make test` runs shuffled unit tests and writes `coverage.out`;
`make test-race` runs the package tests with the race
detector and shuffled order. The coverage artifact is diagnostic and has no
vanity threshold: behavior coverage in the [verification
matrix](#verification-matrix), not a percentage, is the release gate.

`make build` writes `bin/perimeterd` with `GOOS=linux`, the host `GOARCH`, and
`CGO_ENABLED=0` by default. Override these variables when a different local
build is needed; for example, `GOARCH=arm64 make build` cross-compiles the
Linux binary. The current CI build matrix checks Linux `amd64` and `arm64`;
other local `GOARCH` values are not release-support claims. Version metadata
defaults to `dev`/`unknown`/`unknown`; override `VERSION`, `COMMIT`, and
`BUILD_TIME` at build time. CI supplies its revision and UTC build timestamp.

`perimeterd validate` is an offline local check. It does not fetch sources or
touch the firewall. `make verify` runs `go mod verify`, `fmt-check`, `lint`,
`vuln`, `build`, and `test`; it intentionally excludes the race, native, Docker,
and real-LAPI gates below.

### Native namespace gate

Run the opt-in native gate separately:

```sh
make test-e2e
# If user namespaces are unavailable or legacy /proc inventory is inaccessible:
make test-e2e E2E_SUDO=sudo
```

The target first builds the binary, then checks for `nft`, `ip`, `ipset`,
`unshare`, `nsenter`, `iptables-nft`, `ip6tables-nft`, `iptables-legacy`, and
`ip6tables-legacy`. The harness requires Linux and invokes the corresponding
frontends and save/restore tools inside its isolated fixture. Install
`iptables` and `ipset` on Debian-family systems; Fedora provides the variants
in `iptables-nft` and `iptables-legacy`. The host kernel must support
`hash:net`, `hash:ip`, xtables set matches, and IPv4/IPv6 filter and NAT
tables. Load the required modules before using an unprivileged user namespace.

The fixture creates disposable mount, network, PID, and (for unprivileged
callers) user namespaces, verifies isolation before mutation, and mounts
private `/run/perimeterd` and `/var/lib/perimeterd` directories. Root callers,
including CI with `sudo`, retain their existing user namespace while
executing binaries beneath private checkout-owned directories. The fixture
process is PID-namespace init, so its exit or timeout terminates descendants.
It exercises real CLI lifecycle, IPv4/IPv6 TCP/UDP packets, reloads, kernel
counters, ownership collisions, and interrupted transactions, and never
applies test rules to the development host's firewall. Tagged E2E sources are
formatted and linted by the ordinary gates but execute only through opt-in
native/Docker targets. CI runs the native gate in a separate Linux job.

Normal daemon shutdown must exit successfully through the shared lifecycle
helper, including when the process exited before cleanup began. Crash scenarios
use an explicit expected-kill path. Reload assertions wait for the intended
configuration to become durably selected, candidate-correlated rejection
evidence, or changed packet behavior; a request starting is not proof that its
candidate finished. Keep bounded quiet windows for absence assertions and real
lease-expiry waits, not fixed sleeps standing in for reload completion.

Ingress and egress probes distinguish silent DROP from protocol REJECT,
including local UDP sends that return `EPERM` for both actions: a subsequent
ICMP error or receive timeout determines the outcome. TCP exchanges have
explicit deadlines. Configuration files and readiness sockets use private,
unique temporary directories, and table-deletion assertions require successful
ruleset inspection plus explicit absence; command failures, timeouts, and
malformed inspection output fail the assertion.

### Real Docker coexistence gate

This gate needs a **real Docker Engine toolset**, not a Podman-compatible CLI:

```sh
make test-docker E2E_SUDO=sudo
# Use a separately provisioned Docker toolset instead of PATH:
make test-docker E2E_SUDO=sudo DOCKER_TEST_BINDIR=/absolute/path/to/docker
```

`DOCKER_TEST_BINDIR` points to the directory containing `docker`, `dockerd`,
`containerd`, its shims, `runc`, and the other Engine runtime binaries. CI
downloads the official Docker 29.8.1 static toolset and verifies its pinned
SHA-256 before running this target; refresh the version and checksum together.
The gate rejects Podman and records actual client, daemon, and runtime versions.

Run as privileged root with the native namespace prerequisites above, a writable
cgroup hierarchy, bridge/NAT support, and space in `/tmp`. The fixture creates
a private daemon socket, configuration, data/exec roots, runtime directory, and
cgroup parent after entering isolated mount/network/PID namespaces. It never
connects to the host Docker socket or changes the host firewall. Before starting
the daemon, it masks `/sys/kernel/security` with empty read-only tmpfs inside
the private mount namespace. Docker 29.8 loads `docker-default` at startup;
this mask makes AppArmor unavailable to the private Engine and runtime without
changing host profiles. A failed mask aborts the gate rather than starting an
unprotected daemon. Docker uses the iptables firewall backend and vfs storage
with the userland proxy disabled.
The fixture imports the statically linked E2E executable into a scratch image;
no container image pull or live RIPEstat request is needed.

Both iptables-nft and iptables-legacy run the same IPv4/IPv6 bridge scenarios.
Published host ports `18080` and `18081` map to container port `8080`; the
fixture checks original-destination matching, its translated-port contrast,
external-interface scoping, unrelated container egress, downstream foreign
denial, missing-parent reload rejection, retained enforcement on stop, owned
cleanup, and preservation of Docker/foreign rules and default policies across
all iptables tables. The address choice keeps the egress denial check meaningful:
private/ULA container addresses would bypass denial through the built-in allowlist.

Both targets run a security-isolation regression against a private stand-in
for securityfs, including on hosts without AppArmor. It verifies that policy
interfaces are hidden, the mask is read-only, and underlying policy files are
unchanged; it never loads or replaces real host profiles. See the
[Docker attachment contract](firewall-backends.md#docker-docker-user-attachment)
for packet-path ownership and attachment semantics.

`test-e2e` skips the real-engine scenario unless `PERIMETERD_DOCKER_E2E=1`;
use `test-docker` to supply the complete contract. Docker's native nftables
backend, rootless networking, and Swarm are outside the verified scope. See
the [Docker attachment contract](firewall-backends.md#docker-docker-user-attachment).

### Real-LAPI compatibility gate

The real-LAPI gate needs Docker (or a compatible Podman CLI):

```sh
make test-crowdsec
# Optional explicit runtime:
CROWDSEC_CONTAINER_RUNTIME=podman make test-crowdsec
```

It runs a digest-pinned CrowdSec v1.8.1 container on an isolated network with
an ephemeral loopback port, private SQLite data, and the normal chunked stream.
The compatibility cases cover duplicate-prefix IDs, incremental updates without
retransmitting the active snapshot, deletion of the longer overlap, reconnect,
and authoritative emptiness. The fixture is destroyed afterward.

The known query-error behavior in
[crowdsecurity/crowdsec#4691](https://github.com/crowdsecurity/crowdsec/issues/4691)
is an accepted temporary upstream risk, not a compatibility-test condition.
Do not inject database faults or introduce full-list polling to work around it.
See the [supported LAPI contract](data-sources.md#supported-lapi-contract) for
the wire and authority requirements.

### Real OpenZiti transport gate

The [architecture](architecture.md#optional-openziti-upstream-transport),
[configuration](configuration.md#optional-openziti-configuration),
and [transport contract](data-sources.md#openziti-upstream-transport)
own the feature. The standard binary pins unmodified `sdk-golang v1.8.2`;
the real fixture pins OpenZiti controller/router/CLI **2.0.4** and CrowdSec
**1.8.1**. No build tag, SDK shared library, host tunneler, enrollment, or
credential is required to run a direct-only deployment. Static `linux/amd64`
and `linux/arm64` builds remain supported.

With the [native prerequisites](#privileged-end-to-end-suite) installed, provide
the pinned `ziti` executable and a directory containing the real `crowdsec` and
`cscli` binaries (symlinks into the release archive are sufficient):

```sh
E2E_SUDO=sudo \
ZITI_TEST_BINARY=/absolute/path/to/ziti \
CROWDSEC_TEST_BINDIR=/absolute/path/to/crowdsec-bin \
make test-openziti
```

The gate verifies versions, creates private user/network/mount/PID namespaces,
and provisions disposable controller/router, enrolled identities, services,
HTTP(S) list endpoints, and two real LAPIs. It runs nftables, iptables-legacy,
and iptables-nft. CI verifies SHA-256 checksums before extracting fixture
archives; update versions and checksums together. No production identity,
controller, LAPI, or host tunneler is used.

Native cases cover mixed direct/private feeds, unresolved application names,
proxy and cross-origin escape rejection, HTTPS hostname validation, denied
services, same-path identity rotation, IPv4/IPv6 enforcement and lookup,
shared list/LAPI identity use, and a same-URL/same-key LAPI service replacement
that requires a new full snapshot without retaining the old authority.
Stopping the replacement LAPI proves finite IPv6 decision expiry during outage.

### Target inventory and pinned tools

The executable target inventory is:

| Target | Contract |
| --- | --- |
| `fmt` | Rewrite Go sources selected with `e2e,crowdsec` build tags using pinned `gofumpt` followed by `goimports` |
| `fmt-check` | Check pinned `gofumpt` and `goimports` formatting without modifying files |
| `lint` | Run golangci-lint's pinned `gci` diff check, then lint with `e2e,crowdsec` build tags |
| `vuln` | Run pinned `govulncheck ./...` |
| `test` | Run shuffled unit tests and write `coverage.out` |
| `test-race` | Run all package tests with the race detector and shuffled order |
| `build` | Build the current CLI with version metadata |
| `build-e2e` | Build the E2E binary and check native tool prerequisites |
| `test-e2e` | Build and run the isolated Linux namespace/backend scenarios |
| `test-crowdsec` | Run the digest-pinned real LAPI streaming compatibility scenarios |
| `test-openziti` | Run the real pinned OpenZiti list/LAPI transport scenarios across all three native backend variants |
| `test-docker` | Run real isolated Docker bridge coexistence with both iptables tool families |
| `verify` | Run `go mod verify`, `fmt-check`, `lint`, `vuln`, `build`, and `test` |
| `bench-scale-small` | Run baseline control-plane/serialization benchmarks with `-benchmem` |
| `bench-scale-large` | Run large-100k/large-250k control-plane/serialization benchmarks with `-benchmem` |
| `bench-native-scale-small` | Run the isolated small native scale profile |
| `bench-native-scale-large` | Run the isolated large native scale profile |

`verify` intentionally does not run `test-race`, `test-e2e`, `test-docker`, or
`test-crowdsec`; those are separate gates. `package` is a planned
GoReleaser/nFPM snapshot-packaging command, not an implemented target or a
successful no-op.

Tool dependencies and exact versions are pinned in the `tool` and module
requirements in [`go.mod`](../go.mod). Make targets invoke them with `go tool`,
so a globally installed tool or a version copied into this guide is not the
authority.

| Tool | Go module | Used by |
| --- | --- | --- |
| `gofumpt` | `mvdan.cc/gofumpt` | `fmt`, `fmt-check` |
| `goimports` | `golang.org/x/tools` | `fmt`, `fmt-check` |
| `golangci-lint` | `github.com/golangci/golangci-lint/v2` | `lint` |
| `govulncheck` | `golang.org/x/vuln` | `vuln` |

Formatting uses `gofumpt` followed by `goimports`; `.golangci.yml` separately
enables the `gci` import-order formatter for its diff check. The pinned
golangci-lint policy enables `govet`, `staticcheck`, `errcheck`, `revive`,
`gosec`, and US spelling checks. `make verify` also runs module verification
and `govulncheck`.

## Opt-in scale measurements

These profiles are repeatable measurements, not correctness tests or release
performance gates. They use deterministic synthetic inputs and never fetch live
continent feeds or inject the accepted upstream CrowdSec issue
[#4691](https://github.com/crowdsecurity/crowdsec/issues/4691). Run the
control-plane/serialization profiles without privileges:

```sh
make bench-scale-small
make bench-scale-large
# Repeat a profile when comparing noisy hosts:
SCALE_BENCHTIME=10x make bench-scale-large
```

`bench-scale-small` selects the `baseline` sub-benchmarks.
`bench-scale-large` selects `large-100k` and `large-250k` sub-benchmarks.
Both commands use `-benchmem`; `SCALE_BENCHTIME` defaults to one measured
iteration so the large profile remains practical to run explicitly. The
profiles report measurements for comparison, but impose no time, allocation,
RSS, or throughput threshold.

The benchmark scope and reported quantities are:

- `internal/crowdsec`: `BenchmarkLAPISnapshotAdmission` builds complete LAPI
  JSON with SDK-matching decision metadata for one and 250,000 decisions. It
  reports serialized input bytes, decision count, time/op, allocations/op,
  admitted operations, capacity-rejected operations, and Linux `/proc`
  `VmHWM` when available. `BenchmarkAuthorityProjection` measures
  authoritative-store admission and timed projection for one and 100,000
  decisions. `BenchmarkCrowdSecReconnectRenewalRefresh` measures
  authority-only cold startup/reconnect, unchanged renewal projection, and
  changed-source refresh for one and 100,000 decisions; it does not execute
  native reconciliation.
- `internal/app`: `BenchmarkSyntheticGeoNormalization` and
  `BenchmarkSyntheticGeoCompileAndTarget` use normalized synthetic country
  data containing 1,024 or approximately 100,000 disjoint IPv4 prefixes. They
  report input and normalized prefix counts, serialized input/target sizes,
  time/op, and allocations/op. `BenchmarkAppReconcileCombinedAuthorityAndGeo`
  constructs a durable revision with the synthetic geo snapshot and a
  250,000-decision CrowdSec authority, then repeatedly calls the production
  `reconcileLocked(ctx, state, false)` path. Its no-event backend records
  projection size, so the benchmark measures state reads,
  admission/reconciliation, and lease bookkeeping without native commands.

The LAPI safety fence caps both the raw HTTP response read and, when
compressed, the decompressed response read at 32 MiB. The 250,000-decision
fixture intentionally retains realistic metadata and may be rejected at
admission when its serialized envelope exceeds that limit. Such a capacity
rejection is reported as `capacity-rejected/op`; malformed or other unexpected
errors fail the benchmark rather than being treated as support for the
workload. These LAPI wire/read limits are separate from encoded-state and
native backend input/inspection budgets; those operational limits are described
in the [operator sequence](operations.md#operator-sequence).

`-benchmem` allocations and the optional `VmHWM` sample are process
measurements, not peak kernel memory, native set memory, or end-to-end RSS
attribution. `VmHWM` is cumulative for the process, including fixture setup
and earlier profiles, so it cannot be attributed to one dispatch.

Native execution is a separate, explicit measurement and runs only inside the
existing namespace fixture:

```sh
make bench-native-scale-small
make bench-native-scale-large
```

These targets build the normal binary, check native tool prerequisites, and
run the verbose `TestE2ECrowdSecNativeMeasurement` binary through the same
`E2E_SUDO` convention as `test-e2e`. The test re-executes in disposable mount,
network, and PID namespaces, adding a user namespace for unprivileged runs,
before creating any native objects; it never uses the host firewall. The large
profile combines approximately 100,000 synthetic static geo prefixes with
250,000 CrowdSec source decisions. It supplies authority directly, independently
of the LAPI response-body limit, and therefore does not establish that the
equivalent JSON payload would be admitted by LAPI.

Each native profile reports only the phases it reaches: authority admission,
activation preflight/apply, unchanged renewal, cold reconnect, and geo-refresh
preflight/apply/retire/reconcile (including nil dynamic activation). Native
capacity rejection stops that profile; later dependent phases are not
exercised. Native phase timings have no performance assertions. The native
input/inspection budgets and capacity errors are correctness boundaries, not
implicit timing or throughput targets.

## Version 1 verification and delivery requirements

The remaining sections are the complete first-release contract, not a list of
currently passing tests. The local commands above describe what can run now.
Static source-backed policy, including HTTP(S) IP lists and direct dynamic
provider selectors, CrowdSec, both native backend paths, and Docker's iptables
bridge integration are implemented; package/systemd integration and release
workflows remain planned. The
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
| Custom list selectors | Both include and exclude accept named lists; reject unknown names, invalid URLs/durations, and empty reference lists without network I/O. Disabled policies validate references without fetching. | Unit; offline CLI smoke |
| Mixed-source policy | List-only and mixed country/ASN/list union and cross-category subtraction preserve priority, classifier, global/CrowdSec precedence, family-empty behavior, and `/0` lowering. | Unit; both-backend IPv4/IPv6 netns E2E |
| Provider selectors | Validate safe ID syntax including underscores without network or catalog membership checks; reject unsafe paths and empty selector lists. Disabled policies do not resolve. Provider-only and mixed-source union/subtraction preserve classification and precedence, and provider/custom-list names do not collide. | Unit; offline CLI smoke |

### Sources and compatibility

| Contract | Concrete behavior or boundary | Verification layer |
| --- | --- | --- |
| RIPEstat country adapter | Checked-in bounded actual-response fixtures cover country success without an echo, validation of an echo when present, unexpected/mismatched identities, and failed status. | Unit with checked-in fixtures; PR and release CI |
| RIPEstat ASN adapter | Checked-in bounded actual-response fixtures cover normalized ASN identity checks, unexpected/mismatched echoes, failed status, and prefix visibility at `query_endtime`. | Unit with checked-in fixtures; PR and release CI |
| Text list parsing | IPv4/IPv6 hosts and CIDRs, host-bit masking, duplicate/contained prefixes, LF/CRLF, blank/comment lines, and final lines without newline normalize correctly; malformed tails, empty/comment-only bodies, and disabled-family errors reject the entire response. | Unit fixtures |
| List transport | Local HTTP and TLS fixtures exercise success, certificate failure, redirects/downgrade/loop limits, failed status, truncation, timeout, and decoded-size overflow; shared source concurrency and selector caps remain bounded. | Local HTTP(S) fixture tests |
| Mixed-source cache | Complete manifests bind source/name/URL/format identity; changed URLs cannot reuse old fallback. Existing RIPEstat-only recovery evidence remains readable and stabilizable by original object IDs; missing/corrupt referenced objects block unsafe recovery. | Unit; durable-store fault tests |
| Per-list scheduling | Distinct intervals fetch due lists without downloading fresh peers; retry deadlines do not busy-loop or delay unattempted peers, partial failures never publish, stale candidates cannot overwrite newer snapshots, and rejected reloads keep old timers. | Clock-controlled scheduler and app/fixture tests |
| List lifecycle | Refresh changes new-flow enforcement; outage/restart retain complete committed fallback, first start/new-URL failure withhold activation, and disabling/removing references stops fetching after commit. | Both-backend IPv4/IPv6 netns E2E with local fixtures |
| Dynamic provider existence | A fixture ID absent from any source-code enumeration resolves through the exact jsDelivr `@main` merged-file template; an unknown ID fails on 404. No inventory, metadata, or GitHub API request is needed. A failed first attempt must not permanently cache absence. | Local HTTP(S) fixtures with transport injection |
| Provider failure and identity | Missing/invalid include or exclude providers prevent first-start activation or reject reload without silently dropping selectors; exact-identity complete fallback preserves committed policy on refresh/restart. Cross-provider and custom-list cache substitution fail; old cache generations still recover. | Unit; durable-store and app fixtures |
| Provider timing and publication | Shared provider settings remain independent of geo/custom-list timings; only missing/due enabled references fetch. Rejected reloads retain schedules, fresh peers are reused, only attempted selectors enter cooldown, and a mixed-source failure cannot partially publish. | Clock-controlled app/fixture tests |
| Provider native lifecycle | Provider-only and mixed include/exclude, both policy modes, changed feeds, 404 retention, unknown-ID reload rejection, restart fallback, and final-reference removal affect actual new-flow enforcement on nftables and both iptables tool families with IPv4/IPv6. No live CDN dependency in CI. | Privileged netns E2E with local fixtures |
| CrowdSec snapshot authority | Authoritative initial/reconnect snapshots, decision-ID deletion, overlapping ranges with independent expiry, endpoint replacement, disable, and failed-delta recovery from the current desired projection are preserved. | Unit fixture; privileged netns E2E |
| Raw CrowdSec envelope | Before dependency decoding, HTTP 200 with empty/truncated bodies, missing or duplicate list keys, wrong list types, trailing JSON, or decompressed-size overflow rejects the snapshot and retains existing bans. | Unit fixture; privileged netns E2E |
| Valid empty CrowdSec lists | Complete empty/null lists from a supported server legitimately clear an authoritative snapshot. | Unit fixture; privileged netns E2E |
| Non-deduplicated decisions | Initial/reconnect/incremental streams with two decision IDs for one prefix, deletion of the longer ban, and expiration of the remaining ID remove coverage at the correct deadline rather than retaining a hidden ID. | Unit fixture; real-LAPI compatibility; privileged netns E2E |
| Request adaptation | Startup/scopes and other supported options survive request adaptation while all decision IDs are obtained. | Unit fixture; real-LAPI compatibility |
| Real LAPI compatibility | The pinned v1.8.1 LAPI verifies all IDs with `dedup=false`, incremental updates without replaying unchanged active decisions, deletion of the longer overlapping ban, reconnect, and valid empty snapshots. | Real supported LAPI compatibility job |
| LAPI deployment mode | Use the current server's normal chunked stream. The accepted upstream query-error issue is documented, not fault-injected, worked around, or used to block compatibility. | Real supported LAPI compatibility job; accepted-risk documentation |
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

### Lookup and explanation

The [operator contract](operations.md#ipcidr-lookup),
[query architecture](architecture.md#read-only-lookup-and-explanation),
and [provenance contract](data-sources.md#lookup-source-attribution)
own behavior; keep their checks in the existing verification gates.

| Contract | Concrete behavior or boundary | Verification layer |
| --- | --- | --- |
| Evaluation parity | New-flow global allow/block, CrowdSec, classifier, first traffic-matching policy and terminal pass, family-empty allowlists, both deny actions, both directions, disabled families, and confirmed empty managed state agree with native behavior. Non-new-flow bypass is disclosed rather than probing conntrack. | Pure evaluator cases; actual CLI and IPv4/IPv6 packet probes on nftables and both iptables tool families |
| Full query coverage | IP hosts, canonicalized CIDRs, `/0`, nested exclusions, sparse/partial coverage, and omitted protocol/port/direction produce a complete non-overlapping partition and correct aggregate verdict without host enumeration. Reject malformed/mapped/zoned addresses and invalid flag combinations. | Deterministic prefix/flow cases; CLI smoke |
| Attachment semantics | Output identifies interface constraints and original-versus-current destination-port basis; it never infers a route or NAT mapping. Matched lookup scopes agree with remapped Docker packet probes, and downstream foreign denial is not mislabeled as perimeterd denial. | Existing private Docker gate extended with actual CLI queries |
| Source explanation | Overlapping country/group/RIR/ASN/list/provider memberships, same-name list/provider identities, cross-category exclusions, global shadowing, and allowlist absence explain the deciding rule without inventing a single origin. Unreferenced and disabled feeds are never fetched; old committed snapshots retain exact attribution after refresh failure. | Local source fixtures; app and CLI scenarios |
| Dynamic applied evidence | Pending additions/deletions, overlapping IDs, `/0`, unequal expiry, renewal without desired changes, failed/ambiguous writes, reconnect, endpoint replacement, and restart distinguish desired decisions from acknowledged leases. Origin/scenario metadata is not fabricated or fetched. | Fake-clock and writer fault cases; CrowdSec/native lifecycle with CLI queries |
| Publication consistency | Accepted/rejected reload, per-family apply, safe/failed compensation, pre/postcommit failure, retirement, recovery, and query completion racing a new write cannot mix generations or return a definitive answer from invalidated evidence. | App race/fault cases; existing native recovery scenarios extended with CLI queries |
| Private interface | Root-only socket, metrics-disabled operation, ownership-lock exclusion, safe stale-socket handling, reload reuse, shutdown cleanup, daemon absence, protocol mismatch, and JSON/human exit semantics preserve the contract. Requests make no source/credential/backend calls and do not alter counters, leases, readiness, or durable state. | Isolated socket/CLI tests; privileged lifecycle smoke |
| Bounded failure | Oversized request/response, too many partitions/evidence records, concurrency saturation, cancellation, and slow clients fail explicitly without partial success, unbounded work, or writer starvation. Invalid/unknown results never imply allow. | Deterministic limit/deadline cases; concurrent query/write race coverage |

### Optional OpenZiti transport

See the [real OpenZiti gate](#real-openziti-transport-gate) for pinned fixtures,
commands, and native scenarios. Focused adapter/cache/lifecycle tests cover the
remaining boundaries below.

| Contract | Concrete behavior or boundary | Verification layer |
| --- | --- | --- |
| True opt-in | Legacy/explicit-direct configs, empty or unused profiles, unreferenced lists, and disabled CrowdSec never read identity files or initialize/contact Ziti; existing direct transport behavior stays unchanged. | Offline schema cases plus actual daemon smoke with inaccessible identity paths and forbidden Ziti endpoints |
| Exact routing | Explicit identity/service selection works with a non-resolving application hostname and no host tunneler. Unmatched services, denied access, revoked identity, and proxy environment variables never produce direct application connections. | Pinned private Ziti network; direct-listener/DNS tripwires |
| HTTP/TLS isolation | Valid HTTPS works; wrong application hostname/CA fails. Ziti controller trust does not replace application trust. List same-origin redirects work within limits; cross-origin/scheme redirects and all LAPI redirects fail without leaking API keys. | Real HTTPS endpoints through Ziti plus negative routing probes |
| Deadlines and bounds | Slow auth/discovery/dial/TLS/body, cancellation and router outage honor caller fetch/startup limits, static concurrency, response-size caps, bounded application dial admission, and bounded shutdown. Explicitly verify the [unmodified SDK cleanup limitation](data-sources.md#sdk-cancellation-limitation); do not claim all SDK work drains. | Focused cancellation/resource regressions and supervised daemon scenarios |
| Credential generations | Same-path replacement, referenced-file changes, rejected/superseded reloads, last-reference removal, shared identity users, and uncertain commit/recovery cannot close the selected context or reuse a stale connection under new identity authority. | App race/fault cases plus actual identity rotation and reconnect |
| Source identity | Direct/Ziti, profile, generation, service, and URL changes cannot borrow old-route fallback. Version-1/2 direct evidence remains recoverable; version-3 objects are checked without credentials/network access. | Cache compatibility/corruption/recovery fixtures and offline restart/cleanup |
| Static policy | Mixed direct/Ziti lists preserve complete-snapshot publication, causal include/exclude attribution, and refresh failure retention. SDK outages do not affect read-only lookup of healthy retained enforcement. | Actual CLI and IPv4/IPv6 packet probes on nftables and both iptables families |
| CrowdSec authority | API-key authentication, duplicate IDs, full resynchronization, finite leases/expiry, and same-URL identity/service replacement keep the existing LAPI contract. List and LAPI sharing a context do not share cursors, source state, or deadlines. | Supported real LAPI exposed through Ziti; native expiry/reload/failure scenarios |
| Secret and deployment boundary | Identity/config/key/token material never appears in logs, metrics, or durable evidence; SDK inclusion preserves supported static builds and introduces no extra direct-only installation/service requirements. | Error/log capture, saved-state inspection, cross-build and existing delivery gates |

Use isolated disposable infrastructure, not an operator's Ziti network. A fake
dialer cannot establish no-fallback, authorization, cancellation, or SDK
lifecycle behavior. `TestControllerStallDoesNotBlockCallerOrManagerShutdown`
exercises the real SDK against a stalled HTTPS controller; the accepted
[unmodified SDK cleanup limitation](data-sources.md#sdk-cancellation-limitation)
still applies, so do not claim all SDK work drains. The capability-discovery
ordering and the complete transport contract belong to the canonical
[data-sources](data-sources.md#openziti-upstream-transport) reference. Keep
existing native, Docker, CrowdSec compatibility, lookup, lint, and race gates
passing.

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

The current `tests/e2e/` suite is the executable native boundary for direct
global and source-backed geo policy on nftables and both iptables tool
families. Its shared packet scenarios cover country/RIR/group/ASN selectors,
exclusions, priority, family-empty behavior, and retained policy after source
failure. Backend-specific scenarios cover iptables family compensation,
crash recovery, migration, custom attachment/interface and
original-destination matching, foreign-object preservation, nftables
capacity, and runtime refresh/lease boundaries. CrowdSec scenarios cover
startup synchronization, reload/restart handover, finite leases, overlap,
native expiry, and ingress precedence.

Run prerequisites and isolation through the [local commands](#local-commands);
the verification matrix remains the authoritative list of required behavior.
Unit and source-integration tests use local HTTP servers and checked-in
official RIPEstat responses with provenance metadata. The opt-in native scale
profiles own the large synthetic measurements described in
[scale measurements](#opt-in-scale-measurements), rather than this section
repeating their phase inventory.

The real-LAPI compatibility job uses the pinned supported LAPI rather than
fixtures, with deployment and server-source review as specified in the
[sources and compatibility matrix](#sources-and-compatibility). It verifies
normal chunked streaming, duplicate-prefix IDs, mapped IPv4 authority,
incremental updates, overlap deletion, reconnect, and authoritative
emptiness. The separate real Docker job executes the
[Docker coexistence row](#kernel-backend-and-coexistence) through
[`make test-docker`](#real-docker-coexistence-gate).

Shared namespace, mount, fixture, cleanup, host-isolation, availability, and
iptables-family prerequisites are the [test-isolation contract in the service
and packaging matrix](#service-and-packaging).

## Pull-request and branch CI

The existing `.github/workflows/ci.yml` triggers for pull requests targeting
`main` and pushes to `main`. It has six current jobs:

- `verify (amd64)` runs `make verify`, then `make test-race`, and uploads
  `coverage.out`.
- `build` runs `make build` for both `GOARCH=amd64` and `GOARCH=arm64`.
- `privileged firewall E2E` installs the namespace prerequisites and runs
  `E2E_SUDO=sudo make test-e2e`, covering the nftables and both iptables tool
  families selected by the suite.
- `real CrowdSec LAPI compatibility` runs `make test-crowdsec` against the
  digest-pinned v1.8.1 container.
- `isolated Docker coexistence` provisions the checksum-pinned Docker 29.8.1
  Engine toolset and runs `E2E_SUDO=sudo make test-docker`, covering IPv4/IPv6
  bridge packet paths on both iptables tool families.
- `real OpenZiti list and LAPI transports` provisions checksum-pinned OpenZiti
  2.0.4 and CrowdSec 1.8.1 binaries and runs `E2E_SUDO=sudo make test-openziti`
  with explicit fixture paths, covering all three native backend variants.

The separate `.github/workflows/codeql.yml` scans Go for the same pull-request
and `main` push events plus its weekly schedule. Renovate tracks Go modules
and GitHub Actions, including the pinned development tools; it does not track
a nonexistent GoReleaser workflow. Actions updates must retain immutable
commit SHAs and refresh their human-readable release comments. These are the
current executable CI gates; the [verification matrix](#verification-matrix)
remains the full first-release contract. Scale targets are opt-in, not CI gates.

Before version 1, CI and release orchestration must additionally implement the
matrix's package installation/upgrade and systemd-VM gates. The pinned Docker
and CrowdSec compatibility gates already exist in branch CI but must also be
included in the release workflow. Listing planned jobs as requirements does not
mean those jobs exist.

Workflow permissions are read-only by default and elevated only for a job's
required security or artifact operation. Superseded CI runs for the same
branch or pull request use concurrency cancellation. The planned release
workflow must never cancel an earlier release because a later tag arrived.

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
