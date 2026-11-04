# Development

This document owns contributor commands, verification requirements, CI, and
release qualification. Runtime procedures belong to [operations](operations.md);
configuration, source, and backend contracts belong to their reference documents.
Feature completion alone does not establish production readiness.

Use the Go version declared in [`go.mod`](../go.mod), with automatic toolchain
selection if needed. Track new work in issues with acceptance criteria linked
to the owning reference document rather than a separate implementation plan.

## Contents

- [Current repository layout](#current-repository-layout)
- [Pure compiler API](#pure-compiler-api)
- [Local commands](#local-commands)
  - [Native namespace gate](#native-namespace-gate)
    - [Production-scale nft recovery](#production-scale-nft-recovery)
  - [Docker gate](#real-docker-coexistence-gate)
  - [Real-LAPI gate](#real-lapi-compatibility-gate)
  - [OpenZiti gate](#real-openziti-transport-gate)
- [Opt-in scale measurements](#opt-in-scale-measurements)
- [Verification matrix](#verification-matrix)
- [Pull-request and branch CI](#pull-request-and-branch-ci)
- [Release workflow](#release-workflow)
  - [Channels and signing](#channels-and-signing)
  - [Durable identity and reruns](#durable-identity-and-reruns)
  - [Required gates and release assets](#required-gates-and-release-assets)
  - [Publication and recovery](#publication-and-recovery)
- [License discipline](#license-discipline)

## Current repository layout

```text
cmd/perimeterd/main.go
internal/app/                 lifecycle, candidates, serialized writer, HTTP and notifications
internal/cli/                 command dispatch, validation, lookup, status, reload and version reporting
internal/config/              YAML schema, defaults and strict validation
internal/config/catalog/      checked-in country/group/RIR catalogs and ASN validation
internal/control/             secure shared Unix transport, status and synchronous reload protocols
internal/crowdsec/            bounded LAPI adapter, authoritative store and timed projection
internal/lookup/              applied-state evaluation, attribution, query validation and handler
internal/policy/              immutable snapshots and backend-neutral compiler
internal/metrics/             bounded-label instrumentation and native counter accumulation
internal/prefix/              prefix normalization and set algebra
internal/firewall/            typed targets, native backend routing and reconciliation
internal/source/              DB-IP Lite, RIPEstat, text-list/provider resolution and immutable cache
internal/state/               revision store, record codec/validation and durable filesystem IO
internal/upstream/            identity capture, bounded SDK admission and service-bound HTTP pools
configs/perimeterd.yaml       annotated complete configuration example
.github/workflows/ci.yml      quality, build, unit/race, native firewall, Docker, LAPI and Ziti gates
.github/workflows/codeql.yml  Go security analysis
.github/workflows/packages.yml package builds, architecture smoke and reusable systemd gate
.github/workflows/systemd.yml installed-service VM gate
.github/workflows/release.yml version admission, gated publication and rerun recovery
.goreleaser.yaml              binary, package, archive, checksum and SBOM definitions
packaging/                   systemd/tmpfiles payloads and package lifecycle scripts
scripts/                     pinned tool installation and release admission/publication helpers
tests/e2e/                    native namespace, Docker, OpenZiti and runtime/recovery scenarios
tests/crowdsec/               pinned real-LAPI streaming compatibility gate
tests/packaging/              matching-architecture package lifecycle checks
tests/systemd/                installed-service acceptance in a disposable VM
tests/release/                release identity, publication and asset-admission regressions
docs/                         design contracts, operations and contributor guidance
.golangci.yml                 lint/format policy
Makefile                      local and CI entry points
```

Ownership follows [architecture](architecture.md): `internal/app` owns
revision admission and the serialized writer; `internal/policy` owns the
backend-neutral model and its typed family-plan deep copy; source resolution
and cache publication stay in `internal/source`; native firewall mutation
stays in `internal/firewall`.
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
  selection; `resolve.go`: source timing and fetch; `cache_format.go`: cache
  request identity, wire schemas, and validation; `cache_json.go`: canonical JSON
  codec; `cache.go`: filesystem storage.
- `internal/app/publication.go`: staged metrics/listener reservations with
  explicit collector and context dependencies, and transaction-gated publication.
- `internal/app/crowdsec.go`: staged client epochs, serialized dynamic
  reconciliation, independent expiry/renewal workers, and reconnect handover.
- `internal/crowdsec/`: response validation, decision identity, absolute
  deadlines, and maximum-expiry overlap projection.
- `internal/app/lookup.go`: atomic applied-view publication, invalidation,
  acknowledged dynamic lease evidence, and query completion fencing.
- `internal/app/status.go`: public applied-policy summary, loaded source counts,
  static compiled set memberships/totals, acknowledged decision expiry/validity,
  and the same query completion fence.
- `internal/control/`: secure Unix socket/server/client lifecycle, strict reload
  request/results, and independent reload-handler capacity. Header/body reads
  retain five seconds; routed lookup/status writes/evaluation retain five seconds;
  reload client/server bounds are 75/80 seconds, before systemd's 90 seconds.
- `internal/lookup/`: complete address/traffic partitions, source explanation,
  strict query protocol/handler, and the daemon client using shared Unix transport.
- `internal/app/reload.go` and `run.go`: synchronized readiness, event-loop-owned
  epoch waiter, read-once configuration digest, cancellation, and completion after
  healthy committed runtime publication.
- `internal/config/catalog/`: checked-in country, RIR, and ASN vocabulary.
- `internal/firewall/exec.go`: bounded native subprocess I/O shared by
  backends.
- `internal/firewall/iptables.go`, `iptables_inventory.go`, `iptables_codec.go`,
  `iptables_model.go`, and `ipset_codec.go`: iptables/ipset staging, inventory,
  native grammars, deterministic lowering, and snapshot decoding.
- `internal/firewall/nftables.go` and `nftables_model.go`: nftables inspection,
  reconciliation, and native model generation.
- `internal/state/store.go`, `records.go`, and `filesystem.go`: durable lifecycle,
  record validation/encoding, and filesystem barriers, using internal state
  format 2 with explicit rejection of version-1 development state and unknown
  future versions before native mutation; no state conversion or owner floor.
- `tests/e2e/`: namespace admission and isolation (`harness_test.go`), traffic
  probes (`network_test.go`), daemon lifecycle (`daemon_test.go`), geo
  scenarios (`geo_test.go`, `custom_list_test.go`, and `providers_test.go`), native backend scenarios (`nftables_test.go` and
  `iptables_test.go`), real Docker coexistence (`docker_harness_test.go`,
  `docker_test.go`), actual daemon lookup and packet parity (`lookup_test.go`),
  runtime/recovery boundaries (`runtime_test.go`, `recovery_test.go`), OpenZiti
  acceptance scenarios and fixture machinery (`openziti_test.go`,
  `openziti_harness_test.go`), and failure injection (`crash_test.go`).

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

The [`Makefile`](../Makefile) is the source of truth for executable local gates
and scale profiles; the [target inventory](#target-inventory-and-pinned-tools)
summarizes their scope. Use the Go version
declared in `go.mod`, or enable automatic toolchain selection when the installed
Go is older. The race target requires a native C compiler and enables CGO.

### Correctness and build gates

```sh
export GOTOOLCHAIN=auto
make fmt
make verify
make gohawk
make support-check
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

`make gohawk` runs the pinned standalone analyzer's default core checks with
the `e2e,crowdsec` build tags. Experimental checks are not enabled. Gohawk
analyzes production code, not `_test.go` functions; it supplements rather than
replaces race and lifecycle tests. Review diagnostics on tool upgrades instead
of adding blanket suppressions.

`make build` writes `bin/perimeterd` with `GOOS=linux`, the host `GOARCH`, and
`CGO_ENABLED=0` by default. Override these variables when a different local
build is needed; for example, `GOARCH=arm64 make build` cross-compiles the
Linux binary. The current CI build matrix checks Linux `amd64` and `arm64`;
other local `GOARCH` values are not release-support claims. Version metadata
is owned by `internal/buildinfo` and defaults to `dev`/`unknown`/`unknown`;
override `VERSION`, `COMMIT`, and `BUILD_TIME` at build time. Make and GoReleaser
inject that shared package's linker variables. CI supplies its revision and UTC
build timestamp. CLI, metrics, and status retain the raw version; CrowdSec uses
the same version in its sanitized `perimeterd/<version>` User-Agent.

`make build` also generates `bin/completions/perimeterd` for Bash. The
`completions` target reads the CLI's offline command help with a host-native Go
generator, so cross-builds never execute the target binary. Commands, options,
and enumerated option values come from that help rather than a second CLI
definition. GoReleaser runs the same target before release builds and includes
the result in both DEB and RPM packages.

`perimeterd validate` is an offline local check. It does not fetch sources or
touch the firewall. `make verify` runs `go mod verify`, `fmt-check`, `lint`,
`vuln`, `build`, and `test`; gohawk, supporting-file checks, race tests,
privileged integration, package, and systemd gates run separately.

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

Acknowledgement regressions use channels/checkpoints to hold native apply and
publication, replace a file after its read, supersede staging with another request
or `SIGHUP`, and distinguish degraded commitment from native uncertainty. Actual
Unix transport tests cover reload beyond five seconds, short lookup/slow-upload
limits, independent capacity, strict response/digest validation, and no retries.
`tests/e2e/reload_test.go` exercises real CLI acknowledgements, immediate packet
behavior, pre-apply rejection/mismatch, the production client timeout, and missing
socket failure across nftables and both iptables families. Systemd/role VM surfaces
also check nonzero reload propagation and exact successful-marker preservation.

Status regressions cover acknowledged static publication, rejected applies
retaining the previous view, recovery/empty state, nonblocking reads during
native apply, concurrent epoch/count consistency, dynamic publication retaining
static metadata, secret omission, and expiry/validity boundaries with metrics
disabled. Control and CLI coverage distinguishes degraded reports from protocol
failures and unavailable sockets, including stdout/exit behavior. Native smoke
verification runs the actual status, lookup and reload CLI against a daemon in
isolated network/mount namespaces, never against the development host firewall.

Compiled membership regressions keep source de-duplication separate from
materialized per-set counts and explicit policy consumers, including shared
ingress/egress data, distinct SSH selection, internal/global sets, empty sets,
disabled families, deeply immutable returned slices, and count/revision
consistency across publication and recovery. Control schema 4 adds committed
source summaries to coherent unsigned family totals, non-null collections,
and sorted unique consumer arrays. Lookup schema 2 adds provider/release
without renaming semantic country/ASN evidence; malformed/old reports fail.
Focused checks include `go test ./internal/policy ./internal/firewall ./internal/state ./internal/app ./internal/control ./internal/cli ./internal/lookup`
and `CGO_ENABLED=1 go test -race ./internal/prefix ./internal/policy ./internal/state ./internal/app ./internal/control ./internal/lookup`.

The native `make test-e2e` gate includes `TestE2EStatusCompiledSets` for
nftables, iptables-legacy, and iptables-nft. It runs the production daemon
entrypoint in a separate process with only a local country-source HTTP
transport injected, and uses the actual status/text, status/JSON, reload, and
lookup CLI over the private socket. Deterministic country and LAPI fixtures
prove shared consumer rows, correct logical totals, acknowledged split/merge
changes, restart reconstruction, and live decision updates that preserve the
static summary. The fixture retains adjacent logical CIDRs rather than
assuming native interval coalescing. Distinct decision IDs sharing an address
remain separate acknowledged decisions, not static memberships. No live sources
or production rules are used.

`TestE2ESharedPolicyLifecycle` uses actual recorded pre-sharing targets from
`internal/testutil/historicalfixture`, not a legacy compiler. nftables and both
iptables frontends recover them as recorded, migrate normally, split and merge
memberships independently per family, remove/reselect the representative, and
exercise rollback plus prepared/switched/retirement interruptions with real
packets, lookup policy identity, counters, native references, and orphan checks.
An unchanged direct-LAPI nft reload may retain its generation; iptables keeps
its existing distinct-container authority replacement behavior. Query checks
wait for the completion fence after retained-authority resynchronization.

Ingress and egress probes distinguish silent DROP from protocol REJECT,
including local UDP sends that return `EPERM` for both actions: a subsequent
ICMP error or receive timeout determines the outcome. TCP exchanges have
explicit deadlines. Configuration files and readiness sockets use private,
unique temporary directories, and table-deletion assertions require successful
ruleset inspection plus explicit absence; command failures, timeouts, and
malformed inspection output fail the assertion.

The focused nft ownership scenarios are `TestE2ENFTReloadOwnership`,
`TestE2ENFTMissingWitnessRefused` and `TestE2EOldStateRecordVersionRefused`.
Run matching current-source daemon/test binaries on the pinned Rocky 8 guest
and a modern kernel; revision selection alone is not proof of packet enforcement.
They cover real reload traffic, stable witness identity, absent-table
reconstruction, missing-witness refusal and explicit old-state rejection by
both `run` and `cleanup`, before and after cleanup.

`TestE2ECrowdSecNFTInventoryCapacity` runs supported and over-budget fixtures
in separate disposable namespaces. The supported 340,000-static /
319,000-dynamic prefix combination must be admitted, completely inspected,
and recovered by a fresh backend with nil dynamic activation. Packet probes
verify static IPv6 and dynamic IPv4 enforcement after recovery. The
700,000-static-per-generation / 638,000-dynamic fixture first proves that the
static-only two-generation transition and the dynamic payload fit independently,
then requires a combined-inventory `CapacityError` whose scope is `inventory`
and required bytes exceed its limit. Rejection must preserve prior enforcement
and permit a later admissible replacement, renewal, dynamic removal, and owned
cleanup. These are native capacity/recovery
boundaries, not assumptions about an obsolete output ceiling.

Internal durable records use version 2 while the configuration schema remains
version 1. There is no legacy layout migration or old-binary fixture requirement.
The state-version regression supplies a checksum-valid version-1 owner envelope
to the current daemon and requires a genuine bounded failure with unchanged
durable/native bytes. A timeout is never a passing refusal.

The sibling role's test-only `--candidate-dist` mode consumes original
`make package` output and runs two disposable overlays per pinned guest. Build
one real non-published snapshot, retain its metadata/checksums/package bytes,
and use the exact same artifacts for every install/reinstall. Record the daemon
HEAD **and dirty-tree patch/untracked source**, Go/tool versions, build command,
native package NVR/architecture, image digest and full VM logs. Embedded HEAD
and a source archive of HEAD alone do not identify dirty working-tree code.
Local synthetic GitHub metadata and generated checksums are not independent
provenance or signing, and local VM passes do not imply hosted CI or publication.

#### Production-scale nft recovery

`make test-e2e` also runs `TestE2ENFTProductionCapacity` in the existing
privileged firewall CI job. It launches production `app.Run` in a separate
process with only its country-source HTTP client injected, then drives real
CLI reload/status requests, native nftables, durable state, and IPv4/IPv6
TCP/UDP packet probes inside the disposable namespace. It is not a recording
backend or a mock substitute for the daemon lifecycle.

The deterministic country fixture expands the real `euro-atlantic` group.
Sparse prefixes preserve the exact post-normalization pair: 152,419 IPv4 and
31,565 IPv6 memberships per policy. Shared geo storage is 183,984 memberships,
versus the recorded unshared pair's 367,968. Unrelated global/eligibility sets
contribute 179, giving 184,163 static memberships initially and 184,167 after
adding the distinct CZ/SK SSH set. The priority-10 SSH scope explicitly includes
both `22/tcp` and `22/udp`, ahead of priority-100 ingress/egress `any` policies.
The captured historical shorthand is TCP-only and remains unchanged during
historical recovery; normal application selects the current dual-protocol YAML.
Both families and DROP actions remain enabled. The independent LAPI fixture
streams 107,938,931 bytes and admits 399,999 unexpired decision IDs at a `10s`
update frequency. IDs, logical memberships, native elements, and unique
addresses are different quantities.

The scenario first recovers recorded unshared storage, interrupts genuinely
distinct old/new preparation and native switching, and migrates through the
normal journal protocol. It then verifies initial/shared counts, SSH reload,
egress-only exclusion and split, restored equality and merge, post-switch
rollback, unchanged reload, source refresh, dynamic deletions, clean restart,
same-ID prepared recovery, and further old/new recovery. Native object/reference
checks ensure successful retirement leaves no obsolete sets. TCP/UDP probes
distinguish DROP from REJECT and preserve SSH restriction, CrowdSec precedence,
and both traffic directions. Transient native failure, cancellation, and
over-capacity startup retain their safe retry/exit and journal-evidence checks.

The gate reports fixture generation separately, plus per-stage wall time,
static memberships, full native inventory bytes, projected dynamic elements,
daemon-only `/proc` peak RSS and cumulative CPU ticks, and native-child CPU/RSS.
The scheduled-refresh measurement includes waiting for the fixture's one-minute
refresh interval; restart measurements may include synchronization and packet
probes. These are resource observations, not latency thresholds. The full
transition peak includes simultaneous old/unshared and new/shared generations;
it is not interchangeable with a fresh-daemon measurement. Reference
before/after measurements below use the same fresh two-policy inputs, without
claiming that membership savings imply proportional RSS savings. Native
verification on nftables 1.1.6 does not qualify untested versions or hosted
runners.

#### Shared DB-IP-era capacity gate

`TestE2EDBIPCapacity` extends the existing isolated daemon harness to nftables,
iptables-legacy, and iptables-nft. The historical production nft workload above
is retained separately. The new offline source profile requires these unique
post-normalization memberships:

| Static set | IPv4 | IPv6 |
| --- | ---: | ---: |
| Shared Euro-Atlantic ingress/egress | 400,098 | 482,656 |
| Distinct CZ/SK SSH | 3,977 | 5,749 |
| Global/eligibility | 123 | 56 |

Total static storage is 892,659 memberships. The local LAPI supplies 150,000
unexpired, sparse, effective IP/range projections across both families, not
just raw decision rows. Growth to 300,000 exercises ipset resizing beyond
initial capacity. The SSH policy uses TCP-only `22`; UDP is not implicitly
restricted by that shorthand.

The iptables incident variant explicitly attaches INPUT and interface-scoped
DOCKER-USER ingress only. A separate variant adds OUTPUT before testing egress;
compiling an egress policy alone is not enforcement evidence. nftables retains
its intrinsic ingress/egress hooks. The gate requires TCP/UDP and both-family
packet behavior, real changed-country refresh, in-place ban replacement/
deletion/renewal, resize-spare retirement, clean restart, prepared/partially
switched recovery, genuine over-budget rejection, later admissible work, and
foreign-object preservation.

Replacement/deletion/renewal compares every native timed member with the new
projection, including finite expiry within measured update and native read
windows plus whole-second rounding. Update/read windows are bounded at
10m/3m, both below the one-hour renewal. Source leases start at 12h and renew
to 13h, below
the 24h native grant cap; unchanged capped grants cannot prove renewal.
Focused regressions reject the same-count/no-replacement counterexample and,
separately, correct membership with stale leases.

The over-budget stage sends a staged daemon reload a real startup LAPI
snapshot, not a direct backend call. Its 131,072 source decisions split 65,536
IPv6 /64 parents around longer-lived /128 exceptions into 4,259,840 timed
pieces. The source response and durable envelope must fit their own fences.
The gate requires the reload's numeric native-capacity diagnostic, unchanged
active revision/target/configuration epoch, a completed journal, exact retained
native membership/expiry, and packet enforcement. Resuming the old LAPI client
can allocate a fresh client epoch without selecting the rejected contents;
the acknowledged epoch/operation pair must not regress.
A subsequent admissible source/configuration reload changes both sparse
membership and deadlines and must acknowledge a new authority with exact
native contents. Separate native-capacity cases retain direct preflight tests.

Unchanged direct-LAPI reload retains nft identities. iptables deliberately
replaces both generations for fresh authority; the capacity change preserves
that contract rather than adding non-atomic authority sharing. Same-identity
recovery and ordinary source refresh with retained dynamic identity remain
required on every backend.

Large-profile reloads use the existing asynchronous `SIGHUP` path and require
a newer acknowledged configuration epoch/revision plus completed journal,
then inspect the kernel and probe packets. This does not assert that these
large reloads finish inside the unchanged 75-second CLI / 80-second server /
90-second service-manager deadlines. The separate acknowledged-reload tests
continue to exercise that public contract.

One complete sparse nft inventory was 60,880,072 bytes and took 34.38 seconds
(2.46 seconds user CPU, 31.60 seconds system CPU). Stopping the daemon to remove
update contention did not make the old production preflight succeed: its child
deadline expired after 30.10 seconds. The approved nft native-call deadline is
therefore 120 seconds; iptables/ipset remains 30 seconds. These measurements
qualified the operation responsible, rather than treating a timeout as a
capacity rejection or silently changing retries.

The scale scenario has a two-hour namespace deadline and a peer lifetime one
minute longer. These are test-harness lifetimes, not production startup/retry policy.
The peer must not expire at the original small-fixture 900-second lifetime
while recovery and packet checks are still running.

Run through `make build-e2e`, then the existing isolated runner:

```sh
sudo env PERIMETERD_E2E=1 E2E_BINARY="$PWD/bin/perimeterd" \
  bin/perimeterd-e2e -test.v -test.count=1 -test.run '^TestE2EDBIPCapacity$'
```

The opt-in `PERIMETERD_CAPACITY_DBIP_FILE` and
`PERIMETERD_CAPACITY_DBIP_REFRESH_FILE` environment variables select downloaded
and controlled-refresh local artifacts. The same production DB-IP parser runs
through the injected HTTP transport; permanent tests never download live data.
Synthetic packet-address expectations are omitted only in this live-source
mode, not in the deterministic packet gate.

The durable-record ceiling is 32 MiB with no schema migration. A real November
2026 incident-shaped revision payload measured 17,207,875 bytes: it failed
`Store.Prepare` under the former 16 MiB bound and succeeded after the increase.
The controlled source refresh relabeled one US `/24` range as JP and measured
17,207,859 payload bytes. These are payload sizes, not native inventory or RSS.
Both records retain the same version-2 format.

The initial 64/192/256 MiB firewall proposal was not sufficient for the full
growth-transition profile: the existing nft estimator required 211,401,178
inventory bytes for two distinct static generations and 300,000 projected
memberships, above 201,326,592. The accepted coordinated limits are therefore
64/256/384 MiB (input/inventory/output). Neither the workload nor the mutation
input ceiling was relaxed.

An offline probe of the production estimators produced the following byte
counts. nft input is the candidate batch estimate; nft inventory is the
identity union with projected dynamic representation headroom. ipset inventory
assumes empty observed inventory, includes shared projected contents once, and
does **not** measure a populated resize spare or live observed formatting.
These are estimates, not native output or memory measurements:

| Static generations | Dynamic generations | Bans per dynamic identity | nft input bytes | nft inventory bytes | ipset inventory bytes |
| ---: | ---: | ---: | ---: | ---: | ---: |
| 1 | 1 | 150,000 | 52,673,818 | 105,434,676 | 60,361,172 |
| 2 | 1 | 150,000 | 52,873,913 | 191,612,050 | 110,565,343 |
| 1 | 1 | 300,000 | 62,568,382 | 125,223,804 | 70,818,236 |
| 2 | 1 | 300,000 | 62,768,477 | 211,401,178 | 121,022,407 |
| 2 | 2 | 300,000 | 62,568,382 | 250,384,200 | 141,636,472 |

The final row measures identical memberships under distinct static and dynamic
identities, with a full projected population on each; the earlier two-static
rows use changed-country data. This is projected representation headroom, not
an exact live-recovery estimate. Native observation can change the charge.

The same production iptables admission calculator estimated per-family
restore input as follows. These rule batches exclude separately chunked
`ipset restore` membership commands; the shared 64 MiB fence applies to each
native invocation:

| Attachment shape | Deny action | IPv4 restore estimate bytes | IPv6 restore estimate bytes |
| --- | --- | ---: | ---: |
| Incident ingress only | DROP | 14,213 | 14,213 |
| Incident ingress only | REJECT | 16,175 | 16,171 |
| Explicit bidirectional | DROP | 17,835 | 17,835 |
| Explicit bidirectional | REJECT | 20,239 | 20,234 |

The opt-in download used release `2026-11`: 4,623,153 encoded bytes,
32,485,911 decoded CSV bytes, 732,796 rows. Encoded SHA-256 was
`e5c8459d638a272ece7f4d7cfa49dce18d91b4f403f6940ba9249bf0db3781fd`;
the production resolver recorded decoded-artifact SHA-256
`5e968a64a29b973f794c5abc46d0711a0ba87c8a16c411e1cd70312db7a5d4e1`.
The controlled refresh's decoded SHA-256 was
`84b4527eb03c5f9fa58c5405a64072b2ae84539962f65885511f6f1633d67116`.
It removed one Euro-Atlantic IPv4 membership (400,098 to 400,097), leaving
892,658 total static memberships. These observations are mutable-vendor
smoke evidence, not permanent expected values or authenticity signatures.

Boundary regressions also ran natively on Go 1.27.3, nftables 1.1.6,
ipset 7.24, iptables 1.8.11 (legacy and nf_tables), and kernel
`7.2.11-200.fc44.x86_64`. These are separate from the DB-IP daemon matrix.
Representative complete nft inspection samples:

| Boundary fixture | Complete output bytes | Wall seconds | Child user seconds | Child system seconds | Child rusage max RSS KiB |
| --- | ---: | ---: | ---: | ---: | ---: |
| Supported: 340k static inputs / 319k bans | 68,264,661 | 24.843 | 1.894 | 22.609 | 1,067,200 |
| Standalone: 638k bans | 84,191,406 | 46.664 | 2.185 | 44.089 | 1,382,540 |
| Live: 700k static inputs / 638k bans | 138,047,889 | 97.287 | 4.201 | 91.835 | 2,151,800 |

Input-profile labels above exclude unrelated compiler defaults; output includes
the complete table. Child `rusage` peak can include inherited pre-exec fixture
RSS and is not an isolated native-child heap measurement. It must not be added
to daemon `VmHWM` or treated as kernel-memory usage.

Independent source/durable fences and combined native rejection samples:

| Boundary | Resource / scope | Bytes | Limit bytes | Outcome |
| --- | --- | ---: | ---: | --- |
| Enlarged country response | Source JSON, not native I/O | 32,153,300 | 33,554,432 | Fits size fence |
| Encoded candidate envelope | State record, not native I/O | 32,159,394 | 33,554,432 | Fits size fence; not published |
| Second static generation with live 638k bans | nft-table / inventory | 285,738,708 | 268,435,456 | Rejected |
| Changed country plus renewable projected authority | nft-table / input | 71,354,210 | 67,108,864 | Rejected |
| Populated ipset resize spare, both iptables variants | ipsets / inventory | 280,203,408 | 268,435,456 | Rejected |

The inventory regression admitted the static-only transition and the dynamic
contents independently, rejected their union before mutation, retained previous
packet enforcement, then admitted replacement/removal and owned cleanup.
Both iptables variants also passed the 1,000,000-live / 2,000,000-desired resize
regression: desired contents fit alone, while old live contents plus populated
spare were rejected without losing any live member.

The source-refresh fixture ruled out an independent source/durable rejection,
retained the acknowledged target and bans on native input rejection, and
renewed the exact prior projection after stopping the writer.

##### Native lifecycle measurements (2026-11-02)

These measurements predate the scale-gate assertion corrections. At that time,
delete/replace/renew checked only counts and two peer removals; those rows do
not prove exact replacement membership or renewed leases. The over-budget rows
used direct backend `Preflight`, not a candidate submitted to the daemon, so
they prove backend rejection only, not daemon rejection/recovery handling.

The complete `make test-e2e E2E_SUDO='sudo -n'` gate passed, including the
historical production nft workload. The older large-snapshot resync test also
passed five additional repetitions after replacing its packet-before-status
race with the existing bounded acknowledgement wait. Docker, OpenZiti, and the
opt-in native-measurement scenario were not enabled; no requested capacity
backend was skipped. Tool/kernel versions are the same as the boundary run
above. All mutations used disposable namespaces, never the host firewall.

Each committed target below contains 892,659 unique normalized static
memberships with the per-family/set distribution above. Recorded S/D counts
are distinct durable static/dynamic identities, not the number of target
arguments. At a prepared interruption, the candidate's objects need not yet
exist in the kernel. At the distinct switched interruption, nft inspection
observed 600,000 timed elements across two containers, representing two copies
of the 300,000-member authority rather than 600,000 distinct effective bans.

nft inventory bytes cover the complete owned table. iptables inventory cells
are **ipset save / IPv4 rules / IPv6 rules**, three separate scopes, including
the deliberately foreign ipset/rules. They must not be summed into one
admission budget. Native interval formatting can differ from normalized CIDR
membership counts. These observed bytes are not the estimator values above.

Wall times include status waits, packet probes and diagnostic reads. Recovered
rows are cumulative from the corresponding interruption's start; do not sum
those rows with the interrupted rows. Country refresh includes installing the
alternate source, the ordinary changed-membership return with retained dynamic
identity, and restoring normal refresh cadence. The asynchronous reload helper
requires a coherent pre-signal epoch, then a newer acknowledged epoch/revision
and completed journal; an unavailable pre-signal view is not epoch zero.

Daemon peaks are process-lifetime `VmHWM`: cumulative until stop, fresh after
restart/recovery. A dash means the interrupted process had exited before the
sample. Child CPU covers the diagnostic inspection command only (summed over
the three iptables inspection children); child RSS is their maximum, not sum.
Linux child `rusage` may inherit the fixture parent's pre-exec RSS peak. These
are not isolated child heaps or kernel-memory measurements.

**Deterministic offline lifecycle**

All admitted stages passed. Both-family TCP/UDP probes verified allowlists,
TCP-only SSH and CrowdSec ingress precedence; egress probes ran only after the
explicit OUTPUT attachment on iptables. Every recovered/healthy checkpoint
verified projection counts, removal of obsolete owned sets/spares, and
foreign-object preservation. nft same-ID switched interruption uses the
durable `switched` phase after recovery's native apply; distinct nft switching
and iptables IPv4 partial switching occur before the journal phase advances.

**nftables**

| Stage | Bans / identity | Recorded S/D | Complete inventory bytes | Journal sample |
| --- | ---: | --- | --- | --- |
| Incident first start | 150,000 | 1/1 | 60,880,077 | none |
| Bidirectional attachment | 150,000 | 1/1 | 60,880,105 | none |
| Unchanged policy reload | 150,000 | 1/1 | 60,880,107 | none |
| Country refresh | 150,000 | 1/1 | 60,880,169 | none |
| Delete/replace/renew | 149,998 | 1/1 | 60,880,919 | none |
| Growth; spare retired | 300,000 | 1/1 | 74,526,233 | none |
| Rejected candidate; old retained | 300,000 | 1/1 | 74,526,234 | none |
| Later admissible reload | 300,000 | 1/1 | 74,526,234 | none |
| Clean restart | 300,000 | 1/1 | 74,526,237 | none |
| Prepared same-ID; interrupted | 300,000 | 1/1 | 74,526,237 | prepared |
| Prepared same-ID; recovered | 300,000 | 1/1 | 74,526,237 | none |
| Switched same-ID; interrupted | 300,000 | 1/1 | 74,526,237 | switched |
| Switched same-ID; recovered | 300,000 | 1/1 | 74,526,239 | none |
| Prepared distinct-ID; interrupted | 300,000 | 2/2 | 74,526,239 | prepared |
| Prepared distinct-ID; recovered | 300,000 | 1/1 | 74,526,239 | committed |
| Switched distinct-ID; interrupted | 300,000 | 2/2 | 149,047,372 | prepared |
| Switched distinct-ID; recovered | 300,000 | 1/1 | 74,526,239 | none |

| Stage | Phase wall seconds | Daemon peak KiB | Inspection child user/system seconds | Child rusage peak KiB |
| --- | ---: | ---: | --- | ---: |
| Incident first start | 128.988 | 2,167,216 | 2.506 / 33.235 | 1,317,248 |
| Bidirectional attachment | 322.529 | 2,167,216 | 2.536 / 32.579 | 1,317,176 |
| Unchanged policy reload | 294.654 | 2,167,216 | 2.540 / 31.791 | 1,317,116 |
| Country refresh | 688.637 | 2,287,176 | 2.602 / 30.367 | 1,316,700 |
| Delete/replace/renew | 198.943 | 2,287,176 | 2.459 / 30.217 | 1,316,968 |
| Growth; spare retired | 218.095 | 2,287,176 | 2.970 / 32.026 | 1,556,620 |
| Rejected candidate; old retained | 106.105 | 2,287,176 | 3.055 / 31.891 | 1,556,616 |
| Later admissible reload | 302.161 | 2,468,064 | 3.320 / 34.345 | 1,556,500 |
| Clean restart | 533.381 | 2,081,652 | 3.573 / 35.731 | 1,554,844 |
| Prepared same-ID; interrupted | 56.903 | — | 3.365 / 35.385 | 1,554,948 |
| Prepared same-ID; recovered | 580.579 | 2,643,432 | 3.835 / 41.956 | 1,554,900 |
| Switched same-ID; interrupted | 123.678 | — | 3.672 / 40.244 | 1,554,780 |
| Switched same-ID; recovered | 630.526 | 2,291,076 | 3.639 / 38.765 | 1,554,716 |
| Prepared distinct-ID; interrupted | 201.679 | — | 2.880 / 31.815 | 1,554,928 |
| Prepared distinct-ID; recovered | 656.727 | 2,471,584 | 2.914 / 36.305 | 1,555,088 |
| Switched distinct-ID; interrupted | 304.767 | — | 5.952 / 62.359 | 3,101,268 |
| Switched distinct-ID; recovered | 816.376 | 1,994,564 | 2.810 / 30.957 | 1,554,968 |

**iptables-legacy**

| Stage | Bans / identity | Recorded S/D | Complete inventory bytes | Journal sample |
| --- | ---: | --- | --- | --- |
| Incident first start | 150,000 | 1/1 | 60,089,768 / 6,600 / 6,575 | none |
| Bidirectional attachment | 150,000 | 1/1 | 60,089,768 / 8,785 / 8,757 | none |
| Unchanged policy reload | 150,000 | 1/1 | 60,089,768 / 8,783 / 8,738 | none |
| Country refresh | 150,000 | 1/1 | 60,089,768 / 8,812 / 8,769 | none |
| Delete/replace/renew | 149,998 | 1/1 | 60,090,530 / 8,824 / 8,789 | none |
| Growth; spare retired | 300,000 | 1/1 | 70,285,824 / 8,829 / 8,795 | none |
| Rejected candidate; old retained | 300,000 | 1/1 | 70,285,824 / 8,833 / 8,799 | none |
| Later admissible reload | 300,000 | 1/1 | 70,285,824 / 8,803 / 8,767 | none |
| Clean restart | 300,000 | 1/1 | 70,285,824 / 8,807 / 8,767 | none |
| Prepared same-ID; interrupted | 300,000 | 1/1 | 70,285,824 / 8,807 / 8,767 | prepared |
| Prepared same-ID; recovered | 300,000 | 1/1 | 70,285,824 / 8,829 / 8,787 | none |
| Switched same-ID; interrupted | 300,000 | 1/1 | 70,285,824 / 8,829 / 8,787 | prepared |
| Switched same-ID; recovered | 300,000 | 1/1 | 70,285,824 / 8,832 / 8,787 | none |
| Prepared distinct-ID; interrupted | 300,000 | 2/2 | 70,285,824 / 8,835 / 8,787 | prepared |
| Prepared distinct-ID; recovered | 300,000 | 1/1 | 70,285,824 / 8,832 / 8,787 | none |
| Switched distinct-ID; interrupted | 300,000 | 2/2 | 140,571,508 / 15,605 / 15,558 | prepared |
| Switched distinct-ID; recovered | 300,000 | 1/1 | 70,285,825 / 8,832 / 8,787 | none |

| Stage | Phase wall seconds | Daemon peak KiB | Inspection child user/system seconds | Child rusage peak KiB |
| --- | ---: | ---: | --- | ---: |
| Incident first start | 24.195 | 977,228 | 0.308 / 0.161 | 404,156 |
| Bidirectional attachment | 74.145 | 1,535,356 | 0.289 / 0.173 | 511,872 |
| Unchanged policy reload | 43.332 | 1,535,356 | 0.329 / 0.155 | 519,656 |
| Country refresh | 173.163 | 1,599,112 | 0.293 / 0.164 | 519,656 |
| Delete/replace/renew | 33.612 | 1,599,112 | 0.316 / 0.151 | 519,656 |
| Growth; spare retired | 44.081 | 1,599,112 | 0.315 / 0.222 | 579,980 |
| Rejected candidate; old retained | 42.806 | 1,599,112 | 0.340 / 0.203 | 2,296,180 |
| Later admissible reload | 46.394 | 1,738,656 | 0.354 / 0.194 | 2,296,180 |
| Clean restart | 77.449 | 1,445,100 | 0.350 / 0.205 | 2,296,180 |
| Prepared same-ID; interrupted | 15.083 | — | 0.378 / 0.195 | 2,296,180 |
| Prepared same-ID; recovered | 115.462 | 1,400,224 | 0.329 / 0.228 | 2,296,180 |
| Switched same-ID; interrupted | 20.268 | — | 0.391 / 0.171 | 2,296,180 |
| Switched same-ID; recovered | 122.553 | 1,402,976 | 0.361 / 0.181 | 2,296,180 |
| Prepared distinct-ID; interrupted | 52.907 | — | 0.364 / 0.197 | 2,296,180 |
| Prepared distinct-ID; recovered | 157.898 | 1,394,776 | 0.334 / 0.225 | 2,296,180 |
| Switched distinct-ID; interrupted | 67.365 | — | 0.722 / 0.401 | 2,296,180 |
| Switched distinct-ID; recovered | 179.136 | 1,347,136 | 0.343 / 0.188 | 2,296,180 |

**iptables-nft**

| Stage | Bans / identity | Recorded S/D | Complete inventory bytes | Journal sample |
| --- | ---: | --- | --- | --- |
| Incident first start | 150,000 | 1/1 | 60,089,768 / 6,616 / 6,591 | none |
| Bidirectional attachment | 150,000 | 1/1 | 60,089,768 / 8,801 / 8,773 | none |
| Unchanged policy reload | 150,000 | 1/1 | 60,089,768 / 8,799 / 8,754 | none |
| Country refresh | 150,000 | 1/1 | 60,089,768 / 8,828 / 8,785 | none |
| Delete/replace/renew | 149,998 | 1/1 | 60,090,530 / 8,840 / 8,805 | none |
| Growth; spare retired | 300,000 | 1/1 | 70,285,824 / 8,845 / 8,811 | none |
| Rejected candidate; old retained | 300,000 | 1/1 | 70,285,824 / 8,849 / 8,815 | none |
| Later admissible reload | 300,000 | 1/1 | 70,285,824 / 8,819 / 8,783 | none |
| Clean restart | 300,000 | 1/1 | 70,285,824 / 8,819 / 8,783 | none |
| Prepared same-ID; interrupted | 300,000 | 1/1 | 70,285,824 / 8,819 / 8,783 | prepared |
| Prepared same-ID; recovered | 300,000 | 1/1 | 70,285,824 / 8,843 / 8,803 | none |
| Switched same-ID; interrupted | 300,000 | 1/1 | 70,285,824 / 8,843 / 8,803 | prepared |
| Switched same-ID; recovered | 300,000 | 1/1 | 70,285,824 / 8,843 / 8,803 | none |
| Prepared distinct-ID; interrupted | 300,000 | 2/2 | 70,285,824 / 8,848 / 8,803 | prepared |
| Prepared distinct-ID; recovered | 300,000 | 1/1 | 70,285,824 / 8,848 / 8,803 | none |
| Switched distinct-ID; interrupted | 300,000 | 2/2 | 140,571,508 / 15,621 / 15,574 | prepared |
| Switched distinct-ID; recovered | 300,000 | 1/1 | 70,285,824 / 8,848 / 8,803 | none |

| Stage | Phase wall seconds | Daemon peak KiB | Inspection child user/system seconds | Child rusage peak KiB |
| --- | ---: | ---: | --- | ---: |
| Incident first start | 24.201 | 961,660 | 0.312 / 0.165 | 384,244 |
| Bidirectional attachment | 74.648 | 1,558,896 | 0.288 / 0.157 | 430,568 |
| Unchanged policy reload | 44.072 | 1,578,812 | 0.309 / 0.186 | 562,216 |
| Country refresh | 175.143 | 1,691,552 | 0.293 / 0.157 | 562,216 |
| Delete/replace/renew | 34.206 | 1,691,552 | 0.312 / 0.185 | 562,216 |
| Growth; spare retired | 43.927 | 1,691,552 | 0.335 / 0.211 | 562,216 |
| Rejected candidate; old retained | 43.569 | 1,691,552 | 0.341 / 0.215 | 2,266,624 |
| Later admissible reload | 47.125 | 1,711,048 | 0.381 / 0.190 | 2,266,624 |
| Clean restart | 78.191 | 1,295,776 | 0.392 / 0.196 | 2,266,624 |
| Prepared same-ID; interrupted | 15.189 | — | 0.381 / 0.213 | 2,266,624 |
| Prepared same-ID; recovered | 119.015 | 1,395,420 | 0.369 / 0.182 | 2,266,624 |
| Switched same-ID; interrupted | 22.871 | — | 0.364 / 0.252 | 2,266,624 |
| Switched same-ID; recovered | 134.726 | 1,380,000 | 0.385 / 0.232 | 2,266,624 |
| Prepared distinct-ID; interrupted | 59.538 | — | 0.394 / 0.216 | 2,266,624 |
| Prepared distinct-ID; recovered | 170.639 | 1,393,332 | 0.368 / 0.215 | 2,266,624 |
| Switched distinct-ID; interrupted | 69.370 | — | 0.729 / 0.408 | 2,266,624 |
| Switched distinct-ID; recovered | 183.087 | 1,346,840 | 0.341 / 0.193 | 2,266,624 |

Each backend ended with owned cleanup, no active record or journal, and foreign
objects retained. Complete cleanup wall seconds were 45.100 (nftables), 11.881
(iptables-legacy), and 11.769 (iptables-nft). Complete scenario wall seconds were
5,529.14, 1,148.57, and 1,186.85 respectively; this includes repeated full
inspection and crash/recovery exercises, not just a production reload.

The direct backend preflights rejected nft input at
175,413,689 required / 67,108,864 allowed bytes, and ipset inventory at
351,362,799 / 268,435,456 on both iptables frontends. Observed counts and
packets stayed intact; a subsequent reload and cleanup passed. The daemon
did not receive these rejected candidates.

**Live DB-IP lifecycle**

The opt-in run used the November artifact and controlled single-range refresh
whose digests are recorded above, with the same isolated synthetic LAPI.
First-start and settled checkpoints had 892,659 static memberships; the
alternate artifact temporarily removed one membership before the ordinary
scheduled return restored it. Projected bans were 150,000, then 149,998 after
delete/replacement, then 300,000 after growth. All three backends completed the
same lifecycle/recovery/rejection/cleanup matrix. Synthetic packet-address
assertions were intentionally omitted in this mode; packet proof belongs to
the deterministic matrix, not to assumed geography of live addresses.

**nftables**

| Stage | Bans / identity | Recorded S/D | Complete inventory bytes | Journal sample |
| --- | ---: | --- | --- | --- |
| Incident first start | 150,000 | 1/1 | 23,557,005 | none |
| Bidirectional attachment | 150,000 | 1/1 | 23,557,020 | none |
| Unchanged policy reload | 150,000 | 1/1 | 23,557,020 | none |
| Country refresh | 150,000 | 1/1 | 23,557,076 | none |
| Delete/replace/renew | 149,998 | 1/1 | 23,557,824 | none |
| Growth; spare retired | 300,000 | 1/1 | 37,203,134 | none |
| Rejected candidate; old retained | 300,000 | 1/1 | 37,203,134 | none |
| Later admissible reload | 300,000 | 1/1 | 37,203,134 | none |
| Clean restart | 300,000 | 1/1 | 37,203,136 | none |
| Prepared same-ID; interrupted | 300,000 | 1/1 | 37,203,136 | prepared |
| Prepared same-ID; recovered | 300,000 | 1/1 | 37,203,136 | none |
| Switched same-ID; interrupted | 300,000 | 1/1 | 37,203,136 | switched |
| Switched same-ID; recovered | 300,000 | 1/1 | 37,203,136 | none |
| Prepared distinct-ID; interrupted | 300,000 | 2/2 | 37,203,137 | prepared |
| Prepared distinct-ID; recovered | 300,000 | 1/1 | 37,203,137 | none |
| Switched distinct-ID; interrupted | 300,000 | 2/2 | 74,401,204 | prepared |
| Switched distinct-ID; recovered | 300,000 | 1/1 | 37,203,138 | none |

| Stage | Phase wall seconds | Daemon peak KiB | Inspection child user/system seconds | Child rusage peak KiB |
| --- | ---: | ---: | --- | ---: |
| Incident first start | 25.189 | 1,612,156 | 0.862 / 0.915 | 449,440 |
| Bidirectional attachment | 39.055 | 1,825,840 | 0.891 / 0.759 | 449,420 |
| Unchanged policy reload | 40.199 | 1,825,840 | 0.895 / 0.821 | 502,872 |
| Country refresh | 134.198 | 2,478,160 | 0.860 / 0.750 | 502,872 |
| Delete/replace/renew | 15.539 | 2,478,160 | 0.897 / 1.272 | 502,872 |
| Growth; spare retired | 27.907 | 2,478,160 | 1.422 / 3.395 | 688,320 |
| Rejected candidate; old retained | 13.567 | 2,478,160 | 1.424 / 3.369 | 688,472 |
| Later admissible reload | 66.217 | 2,478,160 | 1.558 / 4.662 | 688,280 |
| Clean restart | 108.100 | 2,405,640 | 1.417 / 3.470 | 688,304 |
| Prepared same-ID; interrupted | 21.358 | — | 1.503 / 3.773 | 688,208 |
| Prepared same-ID; recovered | 121.657 | 2,404,788 | 1.428 / 3.984 | 687,864 |
| Switched same-ID; interrupted | 36.005 | — | 1.489 / 3.692 | 688,312 |
| Switched same-ID; recovered | 140.269 | 2,137,456 | 1.415 / 3.354 | 688,096 |
| Prepared distinct-ID; interrupted | 69.894 | — | 1.517 / 3.563 | 688,256 |
| Prepared distinct-ID; recovered | 174.340 | 2,401,440 | 1.508 / 3.944 | 688,308 |
| Switched distinct-ID; interrupted | 93.589 | — | 2.914 / 9.335 | 1,369,684 |
| Switched distinct-ID; recovered | 207.063 | 2,214,684 | 1.502 / 3.430 | 688,132 |

**iptables-legacy**

| Stage | Bans / identity | Recorded S/D | Complete inventory bytes | Journal sample |
| --- | ---: | --- | --- | --- |
| Incident first start | 150,000 | 1/1 | 57,632,881 / 6,596 / 6,575 | none |
| Bidirectional attachment | 150,000 | 1/1 | 57,632,881 / 8,743 / 8,700 | none |
| Unchanged policy reload | 150,000 | 1/1 | 57,632,881 / 8,767 / 8,700 | none |
| Country refresh | 150,000 | 1/1 | 57,632,881 / 8,773 / 8,703 | none |
| Delete/replace/renew | 149,998 | 1/1 | 57,633,643 / 8,776 / 8,703 | none |
| Growth; spare retired | 300,000 | 1/1 | 67,828,937 / 8,779 / 8,703 | none |
| Rejected candidate; old retained | 300,000 | 1/1 | 67,828,937 / 8,779 / 8,703 | none |
| Later admissible reload | 300,000 | 1/1 | 67,828,937 / 8,779 / 8,703 | none |
| Clean restart | 300,000 | 1/1 | 67,828,937 / 8,779 / 8,703 | none |
| Prepared same-ID; interrupted | 300,000 | 1/1 | 67,828,937 / 8,779 / 8,703 | prepared |
| Prepared same-ID; recovered | 300,000 | 1/1 | 67,828,937 / 8,780 / 8,703 | none |
| Switched same-ID; interrupted | 300,000 | 1/1 | 67,828,937 / 8,780 / 8,703 | prepared |
| Switched same-ID; recovered | 300,000 | 1/1 | 67,828,938 / 8,783 / 8,703 | none |
| Prepared distinct-ID; interrupted | 300,000 | 2/2 | 67,828,938 / 8,789 / 8,703 | prepared |
| Prepared distinct-ID; recovered | 300,000 | 1/1 | 67,828,937 / 8,788 / 8,703 | none |
| Switched distinct-ID; interrupted | 300,000 | 2/2 | 135,657,735 / 15,566 / 15,474 | prepared |
| Switched distinct-ID; recovered | 300,000 | 1/1 | 67,828,937 / 8,788 / 8,703 | none |

| Stage | Phase wall seconds | Daemon peak KiB | Inspection child user/system seconds | Child rusage peak KiB |
| --- | ---: | ---: | --- | ---: |
| Incident first start | 26.385 | 930,364 | 0.300 / 0.188 | 378,940 |
| Bidirectional attachment | 45.879 | 1,507,228 | 0.298 / 0.211 | 379,064 |
| Unchanged policy reload | 46.017 | 1,515,480 | 0.303 / 0.195 | 465,172 |
| Country refresh | 147.982 | 1,550,908 | 0.307 / 0.191 | 465,172 |
| Delete/replace/renew | 12.772 | 1,550,908 | 0.302 / 0.210 | 465,172 |
| Growth; spare retired | 15.321 | 1,550,908 | 0.383 / 0.218 | 591,928 |
| Rejected candidate; old retained | 12.436 | 1,550,908 | 0.398 / 0.185 | 1,823,268 |
| Later admissible reload | 48.772 | 1,622,576 | 0.373 / 0.219 | 1,823,268 |
| Clean restart | 80.468 | 1,287,104 | 0.410 / 0.223 | 1,823,268 |
| Prepared same-ID; interrupted | 16.564 | — | 0.360 / 0.220 | 1,823,268 |
| Prepared same-ID; recovered | 90.389 | 1,366,784 | 0.347 / 0.228 | 1,823,268 |
| Switched same-ID; interrupted | 21.952 | — | 0.354 / 0.219 | 1,823,268 |
| Switched same-ID; recovered | 97.189 | 1,289,784 | 0.378 / 0.212 | 1,823,268 |
| Prepared distinct-ID; interrupted | 57.294 | — | 0.396 / 0.248 | 1,823,268 |
| Prepared distinct-ID; recovered | 134.640 | 1,285,696 | 0.408 / 0.204 | 1,823,268 |
| Switched distinct-ID; interrupted | 71.743 | — | 0.744 / 0.433 | 1,823,268 |
| Switched distinct-ID; recovered | 155.949 | 1,230,352 | 0.359 / 0.218 | 1,823,268 |

**iptables-nft**

| Stage | Bans / identity | Recorded S/D | Complete inventory bytes | Journal sample |
| --- | ---: | --- | --- | --- |
| Incident first start | 150,000 | 1/1 | 57,632,881 / 6,612 / 6,591 | none |
| Bidirectional attachment | 150,000 | 1/1 | 57,632,881 / 8,757 / 8,709 | none |
| Unchanged policy reload | 150,000 | 1/1 | 57,632,881 / 8,783 / 8,716 | none |
| Country refresh | 150,000 | 1/1 | 57,632,881 / 8,789 / 8,719 | none |
| Delete/replace/renew | 149,998 | 1/1 | 57,633,643 / 8,792 / 8,719 | none |
| Growth; spare retired | 300,000 | 1/1 | 67,828,937 / 8,795 / 8,719 | none |
| Rejected candidate; old retained | 300,000 | 1/1 | 67,828,937 / 8,795 / 8,719 | none |
| Later admissible reload | 300,000 | 1/1 | 67,828,938 / 8,795 / 8,719 | none |
| Clean restart | 300,000 | 1/1 | 67,828,937 / 8,795 / 8,719 | none |
| Prepared same-ID; interrupted | 300,000 | 1/1 | 67,828,937 / 8,795 / 8,719 | prepared |
| Prepared same-ID; recovered | 300,000 | 1/1 | 67,828,937 / 8,796 / 8,719 | none |
| Switched same-ID; interrupted | 300,000 | 1/1 | 67,828,937 / 8,796 / 8,719 | prepared |
| Switched same-ID; recovered | 300,000 | 1/1 | 67,828,937 / 8,799 / 8,719 | none |
| Prepared distinct-ID; interrupted | 300,000 | 2/2 | 67,828,937 / 8,803 / 8,719 | prepared |
| Prepared distinct-ID; recovered | 300,000 | 1/1 | 67,828,937 / 8,804 / 8,719 | none |
| Switched distinct-ID; interrupted | 300,000 | 2/2 | 135,657,734 / 15,582 / 15,490 | prepared |
| Switched distinct-ID; recovered | 300,000 | 1/1 | 67,828,937 / 8,804 / 8,719 | none |

| Stage | Phase wall seconds | Daemon peak KiB | Inspection child user/system seconds | Child rusage peak KiB |
| --- | ---: | ---: | --- | ---: |
| Incident first start | 25.578 | 945,972 | 0.328 / 0.167 | 377,316 |
| Bidirectional attachment | 45.021 | 1,489,580 | 0.330 / 0.175 | 392,220 |
| Unchanged policy reload | 45.678 | 1,489,580 | 0.324 / 0.182 | 483,604 |
| Country refresh | 147.419 | 1,545,512 | 0.352 / 0.146 | 483,604 |
| Delete/replace/renew | 12.730 | 1,545,512 | 0.310 / 0.197 | 483,604 |
| Growth; spare retired | 15.107 | 1,545,512 | 0.334 / 0.228 | 596,732 |
| Rejected candidate; old retained | 12.212 | 1,545,512 | 0.384 / 0.222 | 2,245,308 |
| Later admissible reload | 50.009 | 1,666,396 | 0.393 / 0.219 | 2,245,308 |
| Clean restart | 81.239 | 1,246,376 | 0.420 / 0.201 | 2,245,308 |
| Prepared same-ID; interrupted | 16.826 | — | 0.377 / 0.239 | 2,245,308 |
| Prepared same-ID; recovered | 91.200 | 1,350,496 | 0.367 / 0.219 | 2,245,308 |
| Switched same-ID; interrupted | 21.919 | — | 0.352 / 0.233 | 2,245,308 |
| Switched same-ID; recovered | 97.261 | 1,275,924 | 0.387 / 0.234 | 2,245,308 |
| Prepared distinct-ID; interrupted | 56.810 | — | 0.384 / 0.218 | 2,245,308 |
| Prepared distinct-ID; recovered | 134.146 | 1,279,500 | 0.384 / 0.199 | 2,245,308 |
| Switched distinct-ID; interrupted | 70.181 | — | 0.750 / 0.461 | 2,245,308 |
| Switched distinct-ID; recovered | 153.531 | 1,226,884 | 0.357 / 0.211 | 2,245,308 |

Live owned-cleanup wall seconds were 14.239, 12.607 and 12.051 for nftables,
iptables-legacy and iptables-nft. Each ended with no active record/journal or
owned native objects, with foreign objects retained. Complete live scenario
wall seconds were 1,128.45, 927.77 and 924.12. Direct backend preflights
rejected nft input at 172,963,498 / 67,108,864 bytes and ipset inventory at
348,912,608 / 268,435,456 on both frontends; later daemon work was admitted,
but these were not daemon-side rejection scenarios.

`make verify`, `make test-race`, formatting, lint, the complete native suite,
and both capacity matrices passed. The 75-second CLI / 80-second server /
90-second service reload deadlines remain unchanged: these lifecycle results
are not a claim of synchronous CLI completion for the large nft profile.

##### Scale gate assertion corrections (2026-11-04)

The corrected deterministic lifecycle passed separately on nftables,
iptables-legacy and iptables-nft, with the same 892,659-static / 150,000-ban
initial profile and growth to 300,000. The replacement stage verified every
one of the 149,998 desired native members and its renewed lease, not just
counts and the two removed peer bans. Retained authority after rejection and
the later changed admissible authority also passed exact native inspection.

The daemon received the oversized LAPI startup snapshot during a real
`SIGHUP` reload and emitted the following numeric native rejection. Source
body sizes fit 256 MiB. The unchanged static durable envelope fit 32 MiB
with an additional 1 KiB metadata reserve; no dynamic decision list was
persisted or rejected at the durable fence.

| Backend | Native resource/scope | Required bytes | Limit bytes | LAPI body bytes | Static durable envelope bytes |
| --- | --- | ---: | ---: | ---: | ---: |
| nftables | nft-table/input | 423,753,620 | 67,108,864 | 18,295,793 | 19,658,245 |
| iptables-legacy | ipsets/inventory | 458,247,128 | 268,435,456 | 18,295,793 | 19,658,736 |
| iptables-nft | ipsets/inventory | 458,247,128 | 268,435,456 | 18,295,793 | 19,658,736 |

Each backend retained its active revision, full target and configuration
epoch with no journal after rejection. Exact prior membership/lease and
packet checks passed. The later admissible snapshot moved sparse membership
offset 1,000 to 2,000 and renewed 13h authority to 14h, acknowledged a newer
revision/client epoch, and matched every native member/lease. Clean restart,
all existing interruption/recovery checkpoints, obsolete-object retirement
and owned cleanup passed; final active record/journal were absent and foreign
objects remained.

The expiry oracle includes measured write/read windows because relative
grants are calculated before native encoding/execution. A short isolated
native smoke verified preservation and changed admissible work when nft
resumed the old source under a fresh client epoch. The comparator regressions
also cover observed write latency and prove that this allowance cannot hide
a one-hour stale lease. Both helper regressions passed with and without
`-race`; `make verify`, lint/formatting and `make test-race` passed.

The scale runs used `-test.run '^TestE2EDBIPCapacity$/^nftables$'` and
`-test.run '^TestE2EDBIPCapacity$/^iptables-'` in disposable namespaces.
This correction run did not repeat the entire native suite or opt-in live
artifact matrix; the older measurements above retain their explicit scope.
Temporary native diagnostic drivers were removed. Production behavior and
capacity/deadline settings were not changed by these assertion corrections.

Use the [verification matrix](#verification-matrix) for required behavior and
the [service and packaging matrix](#service-and-packaging) for shared isolation
requirements. Unit and source-integration tests use local HTTP servers and
checked-in official RIPEstat responses with provenance metadata. DB-IP uses
isolated synthetic whole-artifact fixtures with explicit range/encoding/provenance
boundaries; live downloads are opt-in smoke evidence, never unit-test constants.
Large synthetic workloads belong to the opt-in [scale measurements](#opt-in-scale-measurements).

### DB-IP Lite real-data validation

These measurements predate the coordinated capacity change and retain its
former native/durable fences as a historical baseline. Their feasibility
outcomes do not qualify or disqualify the current binary; current workload
evidence is recorded in the [shared capacity gate](#shared-db-ip-era-capacity-gate).

Local smoke on 2026-10-17 used Go 1.27.2, nftables 1.1.6, and iptables 1.8.11
(legacy and nf_tables). The actual `source.Resolver.Resolve` downloaded the
vendor's `2026-10` artifact over HTTPS in one country batch. Encoded size was
4,491,785 bytes, decoded CSV 31,210,433 bytes; gzip SHA-256 was
`097426b8ddae89157d444a59ac1847e873f7943c32d52becc4371c8b0273af80`,
and the recorded complete decoded-artifact SHA-256 was
`53864a68fbfef02c27c717d08d431a6d453e9e00e77d9e8da841d382267fca88`.
These are observations of mutable vendor bytes, not CI constants or a signature.

A throwaway driver (removed after use) replayed those exact bytes through the
same resolver/parser for each capacity profile, then used the real application
engine, durable store, and native backend in disposable mount/network/PID
namespaces. Every profile had two identical ingress/egress blocklists with both
families enabled, default global/local handling, and no CrowdSec. `EU` means the
embedded `european-union` group. `RIR+US` means
`include: {rirs: [RIPE], countries: [SK, CZ, US]}`. No source/native/durable
limits were raised, data truncated, or CIDRs widened.

Body read/parse includes gzip validation, all unselected CSV rows, range
conversion, and normalization. Resolve/stage also includes immutable cache
publication and compilation. RSS is the process's Linux `VmHWM` after that
stage, not inherited `getrusage` high-water values. Timings are local smoke
observations under concurrent verification load, not isolated benchmarks or SLOs.
The following resolver samples used the nftables profiles:

| Profile | IPv4 CIDRs | IPv6 CIDRs | Read/parse ms | Resolve/stage ms | Stage peak KiB | Source object bytes |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| SK/CZ | 3,960 | 3,182 | 287 | 302 | 24,928 | 135,639 |
| US | 155,176 | 97,738 | 310 | 649 | 110,632 | 4,879,475 |
| EU | 151,394 | 322,876 | 411 | 1,210 | 138,560 | 9,131,381 |
| RIR+US | 394,988 | 524,560 | 477 | 2,033 | 281,140 | 17,641,837 |

The actual applied lookup view retained semantic `country` evidence, provider
`dbip-lite`, release `2026-10`, the matching normalized prefix, and the shared
successful retrieval timestamp. Live address observations:

| Address | Country | Matching source prefix |
| --- | --- | --- |
| `92.180.233.6` | SK | `92.180.192.0/18` |
| `187.14.124.226` | CZ | `187.14.124.0/24` |
| `187.13.17.209` | SK | `187.13.16.0/23` |
| `2a01:c847:23:6500:e14:d9c3:ff0d:f2cc` | SK | `2a01:c840::/28` |

This geographic classification is not proof of the person's or hardware's
location and may change in later vendor artifacts.

For admitted profiles, another process exited at the real `after-switch`
checkpoint before durable publication. The namespace-init keeper then required
two journal-referenced revisions and recovered with a fresh engine/backend.
The journal was still `prepared`, while native selection had already changed:
recovery restored the original durable authority and retired the interrupted
candidate. The peak below is the larger individual `VmHWM` of keeper and crash
process, not their sum and not a daemon-only memory claim.

| Backend | Profile | Preflight ms | Apply ms | Recovery ms | Revision bytes | Peak process KiB | Retained generation |
| --- | --- | ---: | ---: | ---: | ---: | ---: | --- |
| nftables | SK/CZ | 6 | 32 | 325 | 147,274 | 35,248 | after-switch crash recovered |
| nftables | US | 18 | 918 | 6,178 | 4,891,625 | 447,660 | after-switch crash recovered |
| nftables | EU | 23 | 1,750 | 14,000 | 9,129,853 | 724,624 | after-switch crash recovered |
| iptables-legacy | SK/CZ | 12 | 96 | 422 | 147,527 | 33,840 | after-switch crash recovered |
| iptables-legacy | US | 126 | 1,673 | 6,978 | 4,891,878 | 356,084 | after-switch crash recovered |
| iptables-legacy | EU | 262 | 3,883 | 18,880 | 9,130,106 | 501,868 | inspection rejection; original recovered |
| iptables-nft | SK/CZ | 14 | 98 | 467 | 147,527 | 33,664 | after-switch crash recovered |
| iptables-nft | US | 144 | 2,359 | 7,193 | 4,891,878 | 365,880 | after-switch crash recovered |
| iptables-nft | EU | 242 | 3,625 | 16,297 | 9,130,106 | 491,760 | inspection rejection; original recovered |

Two journal-referenced revision files at the interruption:

| Backend | SK/CZ bytes | US bytes | EU bytes |
| --- | ---: | ---: | ---: |
| nftables | 295,496 | 9,784,198 | 18,260,654 |
| iptables (either frontend) | 296,002 | 9,784,704 | not admitted |

EU first activation and single-generation
recovery passed on iptables, but `iptables retained generations exceed inspection
budget` rejected the additional generation before a journal/native mutation.
At those former limits, EU was not a fully supported iptables refresh/reload envelope.

The larger RIR+US candidate was attempted while SK/CZ was already committed:

| Backend | Candidate rejection | New revision bytes | Original authority after recovery |
| --- | --- | ---: | --- |
| nftables | input requires 41,539,034 bytes, limit 33,554,432 | 0 | SK/CZ retained |
| iptables-legacy | encoded durable record exceeds 16 MiB | 0 | SK/CZ retained |
| iptables-nft | encoded durable record exceeds 16 MiB | 0 | SK/CZ retained |

All three preserved the exact active revision/manifest and matching applied
lookup provenance after recovery. The iptables durable-preparation refusal
temporarily required recovery under existing health rules; it did not publish
the oversized candidate. These are bounded capacity outcomes, not truncated
country successes or permission to raise unrelated budgets.

The original pre-DB-IP fixture was also recovered through a real nft backend.
Positive IPv4/IPv6 TCP controls worked before recovery, the recovered recorded
allowlist denied the probes, and cleanup restored the controls. All five raw
fixture files kept the SHA-256 values in
`internal/state/testdata/pre-dbip-provenance.json`, and status reported RIPEstat,
not the new YAML default.

`TestE2EDBIPNative` separately passed real CLI validation/startup/reload/status/
lookup, RIPEstat → DB-IP → RIPEstat, failed provider/mixed-source/compiler/native/
durable-publication candidates, unavailable-upstream restart, and interrupted
provider-switch recovery. Its actual TCP/UDP packets cover both families on
nftables, iptables-legacy, and iptables-nft. These deterministic fixtures are
synthetic and do not redistribute vendor database rows.

Local package smoke passed DEB/RPM install/upgrade/removal on Debian 13 and
Fedora 44 for amd64 and arm64, including installed README/data-source attribution.
Both binary release archives carried the notice in README; the packaged YAML
names `dbip-lite`. Snapshot source archives still represent Git HEAD, not the
uncommitted tree; local dirty-tree artifacts are not hosted release qualification.

Completed local command evidence:

```sh
env GOTOOLCHAIN=auto make verify
env GOTOOLCHAIN=auto make gohawk
env GOTOOLCHAIN=auto make test-race
env GOTOOLCHAIN=auto make support-check
env GOTOOLCHAIN=auto make test-e2e E2E_SUDO=sudo
sudo env PERIMETERD_E2E=1 E2E_BINARY="$PWD/bin/perimeterd" \
  bin/perimeterd-e2e -test.v -test.count=1 -test.run '^TestE2EDBIPNative$'
env GOTOOLCHAIN=auto make package
env PACKAGE_CONTAINER_RUNTIME=podman make test-package
env PACKAGE_CONTAINER_RUNTIME=podman make test-package PACKAGE_ARCH=arm64
```

All listed commands passed; lint reported zero issues and support checks ran
80 release tests. This evidence does not imply hosted CI, publication, a pinned
older-kernel VM pass, or an older-binary downgrade after DB-IP commitment.

The one-shot driver/downloads were removed. The permanent native scenario runs
through `GOTOOLCHAIN=auto make test-e2e E2E_SUDO=sudo`; no live vendor download is
part of ordinary tests.

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
and authoritative emptiness. Actual release/development clients must also update
the uniquely attributable bouncer's recorded type/version without a
`bad user agent` warning. The fixture is destroyed afterward.

The same CI `make test-crowdsec` gate runs `TestLargeLAPISnapshot` against local
HTTP with a generated **400,000-decision stream exceeding 100 MiB** (and the
observed 98,499,095-byte production snapshot). It retains realistic metadata and
both new/deleted entries, checks IDs, normalization, startup/incremental behavior,
and expiry boundaries, and reports elapsed time, allocations, and process peak
RSS. Generation streams one record at a time; no giant fixture blob is retained.
Small limits, unknown-length/chunked reads, gzip integrity, nesting, partial
admission, secrecy, cancellation, and close regressions remain in normal
`internal/crowdsec`/`internal/app` tests.

The native CI `make test-e2e` gate includes `TestE2ECrowdSecLargeSnapshot`: actual
daemon startup with the same >100 MiB generator, acknowledged status/lookup,
IPv4/IPv6 enforcement, truncated/over-limit poll retention without partial
updates, authoritative resynchronization, and sanitized HTTP/size startup
failures. It reports daemon-only peak RSS separately from the generator. Existing
native backend and real OpenZiti/LAPI scenarios remain required.

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

With the [native prerequisites](#native-namespace-gate) installed, provide
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
| `gohawk` | Run pinned gohawk core checks with `e2e,crowdsec` build tags; production code only |
| `vuln` | Run pinned `govulncheck ./...` |
| `test` | Run shuffled unit tests and write `coverage.out` |
| `test-race` | Run all package tests with the race detector and shuffled order |
| `build` | Build the current CLI with version metadata and generate Bash completion |
| `completions` | Generate Bash completion from the CLI's offline command help |
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
| `release-tools` | Check for `bsdtar`; install checksum-pinned GoReleaser and Syft into `bin/release-tools` |
| `support-tools` | Install checksum-pinned ShellCheck and build the pinned Ubuntu-26.04-aware actionlint into `bin/support-tools` |
| `support-check` | Run ShellCheck, actionlint (including embedded shell), `goreleaser check`, and `test-release` without formatting, package builds, VMs, or secrets |
| `package` | Build local snapshot packages, binary/source archives, seven companion SBOMs, and checksums in `dist` |
| `package-fixtures` | Build an older package set in `dist-upgrade` and the candidate in `dist` |
| `test-package` | Exercise DEB/RPM installation, upgrade, validation, failed removal, and removal |
| `test-systemd` | Run the installed package in the pinned Ubuntu QEMU VM, including the real startup deadline |
| `test-release` | Exercise signed-tag/prerelease admission, durable metadata/tag recovery, immutable publication against an isolated API, and checksum/SBOM staging |

#### Package and systemd gates

These gates run separately from `verify` and `support-check`.
Local package verification on an amd64 Linux build host:

```sh
make package-fixtures
make test-package PACKAGE_ARCH=amd64 PACKAGE_CONTAINER_RUNTIME=podman
make test-package PACKAGE_ARCH=arm64 PACKAGE_CONTAINER_RUNTIME=podman
make test-systemd SYSTEMD_PACKAGE=dist
make test-release
```

The arm64 container requires QEMU/binfmt on an amd64 host; CI pins both the
setup action and binfmt image. The systemd gate boots a SHA-256-pinned Ubuntu
26.04 cloud image and requires QEMU, `qemu-img`, `cloud-localds`, SSH, and KVM
when available. CI runs `tests/systemd/run.sh --fast dist`, covering real
activation beyond 90 seconds without waiting for the 75-minute deadline. Run
`make test-systemd SYSTEMD_PACKAGE=dist` to exercise the full deadline locally.
`package-fixtures` refuses to overwrite an existing `dist-upgrade` fixture.

#### Supporting-file gate

Run `ruff check .` from the repository root to lint the Python release scripts
and tests. `make test-release` exercises release admission, metadata recovery,
freshness decisions, SBOM extraction, and publication.

Run `make support-check` on Linux amd64 for the lightweight supporting-file
gate; the first invocation downloads checksum-verified tools and may need
network access. Install `bsdtar` first (`libarchive-tools` on Ubuntu,
`bsdtar` on Fedora) to inspect DEB/RPM payloads without installing them.
`GOTOOLCHAIN=auto make support-check` selects the module's Go toolchain if
the host Go is older. For generated-output proof, build in an isolated
checkout if `dist/` contains user-owned files; `make package` cleans `dist/`.
Run `python3 scripts/release-assets.py dist /tmp/perimeterd-staged` with an
absent destination, then run it again with `/tmp/perimeterd-staged` as input
and another absent destination. Both checks inspect the actual binaries with
`go version -m` and `bsdtar`, without Syft or a build tree in admission.
Compare the staged inventory and manifest with `dist/`. The supporting-file
gate itself does not build packages or start VMs.

#### Tool pin maintenance

Tool dependencies and exact versions are pinned in the `tool` and module
requirements in [`go.mod`](../go.mod). Make targets invoke them with `go tool`,
so a globally installed tool or a version copied into this guide is not the
authority.

Update Go patch releases in the `go` directive; CI uses
`go-version-file: go.mod`. Keep runtime and tool-module updates at explicit
versions, regenerate checksums with `go mod tidy`, and run `make verify` and
`make test-race` with the selected toolchain. Review transitive updates as part
of the same change. Exercise dependency-sensitive runtime paths as well:
live metrics scrapes for Prometheus changes, immutable cache publication
and reload for `golang.org/x/sys` changes, and real identity loading and
private list/LAPI transport (`make test-openziti`) for OpenZiti module changes.

For analyzer pin updates, also run `make gohawk`. For YAML parser updates,
smoke-test the built CLI with
`bin/perimeterd validate --config configs/perimeterd.yaml`; this check stays offline
and does not touch the firewall.

Keep the CodeQL `init`, `autobuild`, and `analyze` steps pinned to the same
release commit, with matching version comments. Validate workflow changes with
the pinned `actionlint` and `shellcheck` tools.

| Tool | Go module | Used by |
| --- | --- | --- |
| `gofumpt` | `mvdan.cc/gofumpt` | `fmt`, `fmt-check` |
| `goimports` | `golang.org/x/tools` | `fmt`, `fmt-check` |
| `golangci-lint` | `github.com/golangci/golangci-lint/v2` | `lint` |
| `govulncheck` | `golang.org/x/vuln` | `vuln` |
| `gohawk` | `github.com/kojah/gohawk` | `gohawk` |

Formatting uses `gofumpt` followed by `goimports`; `.golangci.yml` separately
enables the `gci` import-order formatter for its diff check. The pinned
golangci-lint policy enables `govet`, `staticcheck`, `errcheck`, `revive`,
`gosec`, and US spelling checks. `make verify` also runs module verification
and `govulncheck`.

Error checking also covers values received from error channels, including
test cleanup. Keep process exit errors in timeout diagnostics.

The **release maintainer** owns atomic updates of downloaded binaries; Renovate
updates Go modules (including `go tool` dependencies) and GitHub Actions only,
not the downloaded binary pins below. The current manual-pin inventory and
OS extractor prerequisite are:

| Download or prerequisite | Version/pin location | Real consumer after update |
| --- | --- | --- |
| GoReleaser | `scripts/install-release-tools.sh` (v2.18.2) | Fresh installer, `goreleaser check`, real archive/package/SBOM build and admission |
| Syft | `scripts/install-release-tools.sh` (v1.52.0) | Fresh installer and real binary archive, native package and source SBOMs; compare actual linked Go inventories against build information |
| `bsdtar` (OS package, not a downloaded pin) | Ubuntu `libarchive-tools`; Fedora `bsdtar`; installed in build and publish jobs | Real DEB/RPM payload extraction and admission for both architectures, including unsafe paths/links |
| OpenZiti | `.github/workflows/ci.yml` | Verify archive layout; existing real OpenZiti gate |
| CrowdSec binary | `.github/workflows/ci.yml` | Verify archive layout; existing integration consumer; inspect paired CrowdSec fixture version |
| Docker Engine | `.github/workflows/ci.yml` | Verify archive layout; existing isolated Docker gate |
| ShellCheck | `scripts/install-support-tools.sh` | Fresh installer, reported version, `make support-check` |
| actionlint | pinned Ubuntu-26.04 PR commit and source archive SHA-256 in `scripts/install-support-tools.sh` | Fresh source build, reported version, `make support-check` |

For each update, select a specific upstream version and correct Linux build
asset; obtain upstream verification material where available. Verify
publisher provenance or a publisher checksum using the upstream-supported
mechanism; record the exact archive SHA-256, then update version, URL, and
checksum **together**. Install into a fresh temporary directory and run the
real consumer above before submitting one reviewed change. Hashing an
unauthenticated download alone does not authenticate its publisher. Do not
raise a version while leaving a stale checksum. The supporting actionlint
pin tracks [upstream runner-label PR #683](https://github.com/rhysd/actionlint/pull/683)
until an upstream release includes Ubuntu 26.04; it leaves label diagnostics
enabled. Future checksum-aware automation is not part of this workflow.

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

- `internal/crowdsec`: `BenchmarkLAPISnapshotAdmission` streams complete LAPI
  JSON with SDK-matching metadata for one, 250,000, and 400,000 decisions
  (`large-100MiB`). It reports serialized input bytes, decision count, time/op,
  allocations/op, admitted operations, and Linux `/proc` `VmHWM` when available.
  All three profiles must be admitted; unexpected rejection fails the benchmark.
  `BenchmarkAuthorityProjection` measures
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

The LAPI safety fence independently caps wire and decoded reads at
**256 MiB (268,435,456 bytes)**. The realistic 250,000-decision fixture must now
fit and be admitted, not count as an expected capacity rejection. The larger
400,000-decision profile also exceeds the observed 98,499,095-byte snapshot.
Run all admission profiles explicitly with:

```sh
GOTOOLCHAIN=auto go test -run '^$' -bench '^BenchmarkLAPISnapshotAdmission$' -benchtime=1x -benchmem ./internal/crowdsec
```

These wire/read ceilings are separate from encoded-state and native backend
input/inspection budgets; those operational limits are described in the
[operator sequence](operations.md#operator-sequence). They bound input, not
output-state memory or total RSS. Admission retains the output batch and one
decision at a time, not complete wire/decoded/`RawMessage` envelope copies.

`-benchmem` allocations and optional `VmHWM` are process measurements, not peak
kernel memory, native set memory, or end-to-end RSS attribution. Generator CPU
and per-record allocations are included, but the serialized fixture is not
retained. `VmHWM` is cumulative across setup and earlier profiles, so run one
sub-benchmark in a fresh process for attributable comparisons. The local HTTP
gate includes its server/generator; the isolated daemon gate measures daemon RSS
without generator memory.

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

The production-shaped static nft capacity probe is separate from those CrowdSec
profiles:

```sh
sudo env GOTOOLCHAIN=auto PERIMETERD_CAPACITY_MEASURE=1 \
  go test ./internal/firewall -run '^TestNFTProductionCapacityMeasurement$' -count=1 -v
```

It verifies private network isolation before mutation, materializes real
old/new generations, inspects the complete native table, and reports the old
argument-sum estimate alongside the current unique-object estimate. The direct
native generation path is measurement-only, not an alternate daemon admission
path. The unchanged stage correctly issues no mutation. Local Linux x86-64 /
Go 1.27.2 / nftables 1.1.6 shared-probe reference measurements were:

| Stage | Unique inventory estimate (bytes) | Complete native inventory (bytes) | Mutation input (bytes) |
| --- | --- | --- | --- |
| Initial | 15,988,996 | 2,767,985 | 7,955,073 |
| SSH old/new pair | 31,931,690 | 5,529,849 | 7,955,815 |
| Unchanged | 16,009,028 | 2,773,128 | 0 |
| Country-refresh old/new pair | 32,460,472 | 5,789,374 | 8,210,190 |

The probe maximum remains below the unchanged 96 MiB inventory budget,
32 MiB per-command input, and 128 MiB capture ceilings. The independent
460,000-static / 319,000-dynamic native gate still exceeds the combined budget
with individually admissible payloads and requires an inventory-specific
capacity error. Sharing policy sets does not shrink that unrelated global-set
fixture or weaken rejection.

Before/after observations used a saved unshared baseline binary and identical
initial two-policy source/traffic inputs. The LAPI fixture in both fresh-daemon
runs contained 107,938,931 bytes and 399,999 unexpired IDs:

| Measurement | Unshared baseline | Shared |
| --- | ---: | ---: |
| Geo pair memberships | 367,968 | 183,984 |
| All static memberships, including 179 unrelated | 368,147 | 184,163 |
| Source/model/target and batch preparation wall | 480.14 ms | 318.01 ms |
| Native mutation exec-to-exit wall | 1.397 s | 0.788 s |
| Measurement-process peak RSS at initial stage | 415,396 KiB | 213,904 KiB |
| Native child `rusage` peak RSS upper bound | 458,956 KiB | 231,524 KiB |
| Fresh-daemon initial apply plus inspection wall | 7.785 s | 6.810 s |
| Fresh-daemon-only `VmHWM` | 790,328 KiB | 365,912 KiB |

Native exec timing was isolated with process-event tracing because the saved
baseline's aggregate native wall also included inventory inspection. Prefix
hashing, target construction, batch generation, source fixture memory, and
compiler allocations belong to the measurement process, not the daemon.
Native-child `rusage` may include inherited pre-exec generator memory; it is
not pure nft RSS. Separate daemon `VmHWM` excludes the HTTP fixture generator.
These observations include allocator/GC and scheduling effects, not a general
memory percentage or kernel-memory estimate. Only the reported geo pair's
membership reduction is exactly 50%; other sets and retained generations
remain.

## Verification matrix

The tables below define release acceptance, not an inventory of currently passing
tests. A source build or individual check does not qualify a release. Each row
names a contract, a concrete behavior or failure boundary, and the required
verification layer. Unit and fixture tests assert behavior or typed/model output,
not shell-source substrings, incidental log prose, implementation call counts,
or a specific internal function decomposition. A row may be exercised by more
than one layer when the real boundary matters.

### Configuration and compiler

| Contract | Concrete behavior or boundary | Verification layer |
| --- | --- | --- |
| YAML contract | Unknown YAML fields are rejected; defaults, local validation, and canonical normalization are applied. | Unit; PR and release CI |
| Selector algebra | Selector union/subtraction and `netip` prefix compaction produce the expected canonical prefixes. | Unit; PR and release CI |
| Global and built-in ranges | Global IP/CIDR normalization and built-in local ranges are retained; allow-over-block precedence is explicit. | Unit; privileged netns E2E |
| Policy priority | Priority ordering, first-matching-traffic-scope compilation, and family-empty allowlist/blocklist behavior remain deterministic. | Unit; privileged netns E2E |
| Exact static sharing | Equal family-effective geo sequences share one lexicographic representative after collision-safe equality; partial overlaps, internal/dynamic sets and family-inapplicable policies remain separate. Rule ordering, modes, scopes, counters and lookup identities do not change. | Compiler/evaluator/lookup unit; forced-collision regression |
| Shared native lifecycle | Historical unshared targets recover unchanged, migrate atomically, split/merge, replace representatives and retain old enforcement on failed transitions without orphaned/referenced-set deletion. | Durable-state/app unit; nftables and both iptables netns E2E |
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
| DB-IP configuration/history | New YAML explicitly defaults to `dbip-lite`; strict enums reject invalid/null values. Authentic pre-change RIPE revisions/cache retain exact bytes, provider meaning, recovery, and failed-switch authority. | Config/state/cache behavioral tests with original serializer fixture provenance |
| DB-IP artifact/parser | Direct monthly HTTPS, current-404-only previous month, UTC rollover/clock rollback, existing retry budget, accepted gzip envelopes/trailers, whole-file UTF-8/range/country validation, all fixed streaming limits, XK/ZZ exclusion, exact CIDR boundaries and explicit empty families. | Isolated source/prefix fixtures; actual vendor smoke separately |
| DB-IP batch/provenance | Any due/missing/new country refreshes all required leaves from one artifact. ASN-only/disabled fetch none; coherent subset reuse, complete stale fallback, forged metadata rejection, schema-3-only metadata, and unchanged historical bytes hold through Stage/Load/publication. | Source/cache/state/app transaction tests |
| DB-IP applied surfaces | Status schema 4, lookup schema 2, semantic country/ASN evidence, provider/release ordering/coalescing, committed source summaries, URL/parameter secrecy, bounded metrics and one request per logical country batch. | Strict control/lookup/CLI and committed-publication tests |
| DB-IP native lifecycle | Provider reload both ways, failed switch, same-provider unavailable-upstream restart, country+ASN, exact inclusion/exclusion and both families, recovery/publication failures. | Disposable nftables, iptables-nft and iptables-legacy namespace smoke with controlled artifacts |
| DB-IP real-data envelope | Current vendor artifact release/digest/size and four investigated addresses are observations. Measure SK/CZ, US, EU and multi-country/RIR parser/RSS, object/revision sizes, native preflight/apply and retained recovery; over-capacity rejection must be bounded and atomic. Never truncate or casually raise unrelated limits. | Opt-in actual resolver/native smoke; report exact local evidence, not hosted qualification |
| RIPEstat country adapter | Checked-in bounded actual-response fixtures cover country success without an echo, validation of an echo when present, unexpected/mismatched identities, and failed status. | Unit with checked-in fixtures; PR and release CI |
| RIPEstat ASN adapter | Checked-in bounded actual-response fixtures cover normalized ASN identity checks, unexpected/mismatched echoes, failed status, and prefix visibility at `query_endtime`. | Unit with checked-in fixtures; PR and release CI |
| Text list parsing | IPv4/IPv6 hosts and CIDRs, host-bit masking, duplicate/contained prefixes, LF/CRLF, blank/comment lines, and final lines without newline normalize correctly; malformed tails, empty/comment-only bodies, and disabled-family errors reject the entire response. | Unit fixtures |
| CSV list parsing and identity | Explicit one-based columns, numeric operators, variable-width quoted/multiline records, and complete validation normalize matching IPv4/IPv6 prefixes. Malformed/zero-match feeds cannot publish; every parsing-option change rejects old fresh/stale evidence, canonical metadata survives exact-reference recovery, and timing-only changes retain reuse. | Local unit/HTTP fixtures; candidate/recovery and lookup regressions |
| CSV native lifecycle | Confidence filtering blocks only selected addresses; threshold reload changes dual-stack new-flow enforcement. Unavailable changed-threshold reload rejects old-filter fallback; malformed/zero-match refresh and restart outage preserve committed rules. | nftables and both iptables tool families in isolated namespaces with local CSV fixtures |
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
| CrowdSec rollback authority | Failed precommit applies retain the old durable revision, authenticated client, decisions, and selected enforcement. Rollback resynchronization may replace the in-memory state and epoch; tests wait for that transition rather than require pointer identity. A committed disable removes authority. | App checkpoint fixtures; shuffled race tests |
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
| Startup timeout protocol | CI's cold-start fixture takes more than `90s`, remains activating through `EXTEND_TIMEOUT_USEC`, and becomes ready only after commit. Fake-clock tests cover the overall deadline; the opt-in full VM gate verifies real 75-minute termination without losing recovery evidence. | CI fast systemd VM; unit fake-clock fixtures; opt-in full systemd VM |
| Release artifacts | GoReleaser v2 builds static Linux binaries for `amd64` (`GOAMD64=v1`) and `arm64`, one archive, DEB and RPM per architecture, plus a source archive. All seven parents have exact checksum-covered companion SPDX SBOMs; the six executable inventories cover their linked Go modules, stdlib and release application identity. Build and publish staging inspect the same checksum-verified bytes, not regenerated artifacts. | Real snapshot and release-mode builds; asset admission; release workflow; matching-architecture package containers; systemd VM |
| Architecture coverage | Each package is installed in a matching-architecture distribution container; pinned QEMU/binfmt runs non-native architecture containers. | Package smoke |
| Version provenance | Stable releases use a verified signed tag; main prereleases use their durably admitted development version. Both inject version, commit, and build time into `perimeterd version` and `perimeterd_build_info`. Local and PR snapshots do not publish releases. | Release workflow; package smoke |

## Pull-request and branch CI

`.github/workflows/ci.yml` runs for pull requests targeting `main` and as a
reusable gate of the release workflow on main pushes and stable tags:

- `supporting-file gate` runs `make support-check` on pull requests and reusable
  release CI calls. It checks package lifecycle/install shell, all workflows
  (including embedded shell and Ubuntu 26.04 runner labels), GoReleaser config,
  and release regressions.
- `verify (amd64)` runs `make verify`, then `make test-race`, and uploads
  `coverage.out`.
- `gohawk (amd64)` runs `make gohawk` as a blocking core-analysis gate.
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
- `packages` builds DEBs/RPMs for amd64 and arm64, checks their real lifecycle
  in matching-architecture Debian/Fedora containers, and exercises the installed
  service in a systemd VM.

The separate `.github/workflows/codeql.yml` scans Go for pull requests, its
weekly schedule, and release-workflow invocations. CI, CodeQL, and package jobs
read the Go version from `go.mod` after checkout; all executable workflow jobs
have explicit deadlines (including the retained 120-minute systemd VM limit).
Renovate tracks Go modules and GitHub Actions, including pinned development
tools. Non-major updates and pin/digest maintenance are grouped separately
for CI setup actions, artifact/provenance actions, Go development tools,
CrowdSec, OpenZiti, and go-openapi libraries. Major updates stay outside
these project groups (existing upstream monorepo grouping may still apply);
CodeQL actions and the Go language directive are not absorbed into them.
Actions retain immutable commit SHAs and refreshed human-readable
release comments. Renovate does not automerge these updates: normal review,
required PR checks, and existing security handling still apply. Downloaded
binary pins use the manual procedure above. Scale targets are opt-in, not CI
gates.

Workflow permissions are read-only by default and elevated only for a job's
required security or artifact operation. Superseded pull-request CI and CodeQL
runs are cancelled. Release runs and their reusable CI and CodeQL checks use the
caller run ID in their concurrency groups, so queued checks for different
releases do not replace one another.

## Release workflow

### Channels and signing

`.github/workflows/release.yml` has two publication channels:

- A signed, canonical **bare SemVer** tag such as `0.0.1` or `0.0.2` publishes
  a stable release. `v0.0.1`, leading zeroes, and prerelease/build suffixes are
  rejected. The tagged commit must be reachable from `origin/main`.
- A push to `main` admits a development prerelease candidate, but superseded
  candidates do not publish. Its version is the next patch after the highest
  reachable stable SemVer tag, followed by `-dev.RUN.gSHORTCOMMIT`; without a
  stable tag the base is `0.0.1`. Prereleases never become GitHub's latest
  release.

Configure Actions secret `RELEASE_SIGNING_PUBLIC_KEYS` with the trusted
ASCII-armored OpenPGP public keys before publishing stable tags. Use a repository
secret or an organization secret with access granted to this repository. Keep
private signing keys on the signing machine; only public keys belong in Actions.
Admission uses an isolated keyring, disables automatic key retrieval, checks the
triggering commit and main ancestry, and verifies the annotated tag signature.
For example:

```sh
git tag -s 0.0.1 -m 'Release 0.0.1'
git push origin 0.0.1
```

### Main candidate freshness

After persisting the admitted version and triggering commit, each executed
main metadata job waits **60 seconds**, then requests the current
`refs/heads/main` SHA from GitHub. A different SHA successfully supersedes
that run: its release CI, CodeQL, and package jobs do not run, and it neither
attests nor publishes. This is not a successful test result for the skipped
commit. A missing ref, malformed response, or API/authentication failure
instead fails the job; it is never treated as supersession.

The publish job checks main again after all existing gates and asset staging,
immediately before attestation. If main advanced during those gates, both
attestation and publication are skipped. A failed newest candidate never
falls back to an older superseded run. After the final affirmative decision,
an active publisher finishes without cancellation or repeated freshness
checks. A push arriving after that decision may result in two releases; the
branch comparison and publication are not atomic. Stable signed tags bypass
both freshness checks and the wait, even when main advances beyond their
admitted ancestor. Direct PR CI and CodeQL behavior is unchanged.

### Durable identity and reruns

The metadata job admits the ref, selects the version once, and uploads the
immutable `release-metadata-<run_id>` Actions artifact with 90-day retention
**before** it exposes downstream outputs. On later attempts it retrieves the
same run's decision and checks run/repository/ref/commit/run number, then
repeats main ancestry and stable-tag signature admission. New reachable tags
cannot change a saved prerelease version. Missing, expired, ambiguous, invalid,
or inaccessible metadata fails closed; an initial upload failure has not
admitted downstream builds. After expiry/deletion or an initial failure before
upload, use a separately admitted new release run under the normal triggers;
neither a guessed version nor an arbitrary override recovers that run. The
repository's Actions retention policy must permit the configured 90 days.

A rerun that executes metadata keeps the saved version and commit but waits
another 60 seconds and makes a new early freshness decision. A failed-jobs-only
rerun can reuse successful metadata and gate jobs; its publish job therefore
always makes its own late lookup. If an old main run is rerun after main
advances, it skips publication even when an old draft or published release
already exists: the workflow does not attest, repair, or mutate those remote
objects. Owner action is required for a superseded draft. Still-current main
and stable-tag reruns retain the publisher's immutable recovery behavior.

Every package build attempt uploads the candidate and its paired upgrade
fixture under names unique to the **producer's** run attempt. Architecture
smoke, systemd, and publication consume the successful producer's exported
artifact name; they never derive it from the consumer's attempt. A full rerun
can rebuild different bytes without colliding with earlier uploads. A
failed-jobs-only rerun reuses the successful producer's artifact output.
These names and bytes must be inspected in the hosted workflow before treating
rerun integration as verified.

### Required gates and release assets

Both channels run static analysis, unit and race tests, CodeQL, privileged
native E2E, real Docker/CrowdSec/OpenZiti compatibility, package lifecycle, and
the fast systemd VM gate before publication. GoReleaser 2.18.2 and Syft 1.52.0
are checksum-pinned by `scripts/install-release-tools.sh`; `bsdtar` comes from
the runner's `libarchive-tools` package. The publish job also provisions Go
from `go.mod` to inspect downloaded executables.

The [service and packaging matrix](#service-and-packaging) defines package
installation, architecture, sandbox, restart, recovery, and version-metadata
acceptance. The fast systemd gate verifies startup activation beyond 90 seconds
with `EXTEND_TIMEOUT_USEC`; the real 75-minute stalled-startup scenario remains
an explicit [full VM check](#package-and-systemd-gates), not a CI publication gate.

The tested artifacts—not a rebuild—are checksum-verified, semantically admitted,
attested with GitHub's OIDC-backed signing identity, uploaded to a draft, and
then published:

- two Linux binary archives, two DEBs, two RPMs, and one source archive, **each**
  with its exact checksum-covered `<artifact-name>.spdx.sbom.json` companion;
- SHA-256 `checksums.txt` covering all seven parents and seven companions; and
- GitHub artifact attestations for every checksum-covered file **and**
  `checksums.txt`, in `provenance.sigstore.json` (the bundle itself is outside
  the checksum manifest).

That is 14 checksum entries, 15 attested subjects including the manifest, and
16 final assets including the provenance bundle for the current matrix. Admission
checks exact architecture/name pairs, parent digest/filename and executable
relationships, native wrapper version/architecture, and every effective linked
Go module and stdlib version against `go version -m` on extracted binaries.
The archive/DEB/RPM SBOM represents the **shipped executable**, while the source
archive SBOM is a broader source/development inventory; the latter is not a
dependency oracle for a binary. A distinct release-application component records
the admitted version; Syft's Go main-module pseudo-version remains its source
identity. Pseudo-versions are not shortened, and unversioned local Go
replacements are rejected instead of being assigned invented versions.
Runtime OS packages (including firewall tools and CA certificates) are
installation requirements, not statically linked Go components.

GoReleaser fixes final artifact filenames before SBOM generation and checksums:
nFPM's conventional DEB/RPM separators, release suffixes, and architecture
suffixes remain, but `~` in an external basename becomes `-` for GitHub release
asset compatibility. Stable names without `~` are unchanged. Checksum-covered
asset basenames must start and end with an ASCII letter or digit and otherwise
contain only ASCII letters/digits, `_`, `-`, or `.`. For example,
`perimeterd_0.0.1-dev.1.g09a3c501a820-1_amd64.deb` still contains the native
package version `0.0.1~dev.1.g09a3c501a820-1`; its internal `~` preserves
package-manager prerelease ordering. The tested names and bytes flow unchanged
through staging, Actions artifacts, attestation subjects, and release upload.
There is no post-build or publish-time rename: GitHub returning a different
upload name is a publication failure.

### Publication and recovery

Before publishing, the workflow stages the same checksum-covered inventory
again. It looks up releases through the paginated authenticated release listing
(which includes pending drafts), rejects duplicate version matches, and fetches
the selected release by ID. A draft's tag may not yet exist remotely: for an
admitted prerelease, the workflow checks the pending draft's exact target commit
and existing asset bytes/provenance before creating the missing tag ref at that
commit without force. A concurrent matching ref is reused; a different target
fails. Stable releases still require their pre-existing signed tag, and a
published release without a matching ref is never repaired.

A rerun checks the remote tag's peeled commit and release channel, downloads
and compares every existing checksum-covered asset byte-for-byte, and verifies
the remote provenance against the repository, release workflow, source
ref/commit and subject digests with `gh attestation verify`. A matching draft
only gains missing assets and, if necessary, its prerelease ref; it stays
private until complete. A matching published release is a verification-only
success and does not reset an older release as latest. Wrong tags, channels,
bytes, unexpected assets, invalid provenance, ambiguous drafts, or an
incomplete published release fail without overwriting or deleting remote
assets. A valid pre-existing provenance bundle is retained even when a new
attestation uses different timestamps or serialization.

A filename-policy fix requires a newly admitted run from the fixed commit:
rerunning the failed workflow attempt uses its original checkout and cannot
import later code. Cleanup of a failed run's old draft/tag belongs to the
repository owner, not to publication recovery. Automated recovery applies
only to a matching release identity and matching existing asset names, bytes,
and provenance; it never renames or replaces conflicting remote assets.

The admitted version, commit, and build time are injected into
`perimeterd version` and `perimeterd_build_info`. Local snapshot builds never
publish. Publishing requires the workflow's `contents: write`, `id-token:
write`, and `attestations: write` permissions; no signing private key is stored
in the repository.

## License discipline

The repository remains MIT-licensed. Behavior may be studied from
[geoip-shell](https://github.com/friendly-bits/geoip-shell), but its GPL-3.0
implementation is not copied or translated. Reuse of the MIT-licensed
[CrowdSec firewall bouncer](https://github.com/crowdsecurity/cs-firewall-bouncer)
or [Go bouncer client](https://github.com/crowdsecurity/go-cs-bouncer) requires
normal dependency review and preservation of applicable copyright and license
notices in distributions.
