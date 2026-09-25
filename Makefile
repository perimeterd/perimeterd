SHELL := /bin/sh

MODULE := github.com/perimeterd/perimeterd
BINARY := bin/perimeterd
GO ?= go
GOOS ?= linux
GOARCH ?= $(shell $(GO) env GOHOSTARCH)
CGO_ENABLED ?= 0
VERSION ?= dev
COMMIT ?= unknown
BUILD_TIME ?= unknown

export GOOS GOARCH CGO_ENABLED LDFLAGS

GOFUMPT := $(GO) tool gofumpt
GOIMPORTS := $(GO) tool goimports -local $(MODULE)
GOLANGCI := $(GO) tool golangci-lint
GOVULNCHECK := $(GO) tool govulncheck
LDFLAGS := -s -w -X '$(MODULE)/internal/cli.Version=$(VERSION)' -X '$(MODULE)/internal/cli.Commit=$(COMMIT)' -X '$(MODULE)/internal/cli.BuildTime=$(BUILD_TIME)'
GO_SOURCES := $(GO) list -tags=e2e,crowdsec -f '{{range .GoFiles}}{{$$.Dir}}/{{.}} {{end}}{{range .TestGoFiles}}{{$$.Dir}}/{{.}} {{end}}{{range .XTestGoFiles}}{{$$.Dir}}/{{.}} {{end}}' ./...
E2E_TEST_BINARY := bin/perimeterd-e2e
E2E_SUDO ?=
CROWDSEC_CONTAINER_RUNTIME ?= docker
DOCKER_TEST_BINDIR ?=
ZITI_TEST_BINARY ?=
CROWDSEC_TEST_BINDIR ?=
RELEASE_TOOLS := $(abspath bin/release-tools)
PACKAGE_DIST ?= dist
PACKAGE_UPGRADE_FROM ?= dist-upgrade
PACKAGE_ARCH ?= $(GOARCH)
PACKAGE_CONTAINER_RUNTIME ?= docker
SYSTEMD_PACKAGE ?=

.PHONY: fmt fmt-check lint test test-race vuln build build-e2e test-e2e test-crowdsec test-openziti test-docker verify bench-scale-small bench-scale-large bench-native-scale-small bench-native-scale-large
.PHONY: release-tools package package-fixtures test-package test-systemd test-release

fmt:
	@files="$$($(GO_SOURCES))" || exit $$?; \
	$(GOFUMPT) -w $$files && \
	$(GOIMPORTS) -w $$files

fmt-check:
	@files="$$($(GO_SOURCES))" || exit $$?; \
	formatted="$$($(GOFUMPT) -l $$files)" || exit $$?; \
	if [ -n "$$formatted" ]; then \
		printf '%s\n' "$$formatted"; \
		exit 1; \
	fi; \
	formatted="$$($(GOIMPORTS) -l $$files)" || exit $$?; \
	if [ -n "$$formatted" ]; then \
		printf '%s\n' "$$formatted"; \
		exit 1; \
	fi

lint:
	$(GOLANGCI) fmt --diff --config .golangci.yml .
	$(GOLANGCI) run --build-tags=e2e,crowdsec --config .golangci.yml ./...

test:
	$(GO) test -shuffle=on -covermode=atomic -coverprofile=coverage.out ./...

test-race:
	CGO_ENABLED=1 $(GO) test -race -shuffle=on ./...

vuln:
	$(GOVULNCHECK) ./...

build:
	mkdir -p "$(dir $(BINARY))"
	$(GO) build -trimpath -ldflags "$$LDFLAGS" -o "$(BINARY)" ./cmd/perimeterd

build-e2e: build
	@for tool in nft ip ipset unshare nsenter iptables-nft ip6tables-nft iptables-legacy ip6tables-legacy; do \
		command -v "$$tool" >/dev/null 2>&1 || { \
			printf 'native E2E requires %s in PATH\n' "$$tool" >&2; exit 1; \
		}; \
	done
	mkdir -p "$(dir $(E2E_TEST_BINARY))"
	$(GO) test -tags 'linux e2e' -c -o "$(E2E_TEST_BINARY)" ./tests/e2e

test-e2e: build-e2e
	$(E2E_SUDO) env PERIMETERD_E2E=1 E2E_BINARY="$(abspath $(BINARY))" "$(abspath $(E2E_TEST_BINARY))" -test.v -test.count=1

test-crowdsec:
		command -v "$(CROWDSEC_CONTAINER_RUNTIME)" >/dev/null 2>&1 || { \
			printf 'test-crowdsec requires %s in PATH\n' "$(CROWDSEC_CONTAINER_RUNTIME)" >&2; exit 1; \
		}
	CROWDSEC_CONTAINER_RUNTIME="$(CROWDSEC_CONTAINER_RUNTIME)" $(GO) test -tags crowdsec -count=1 -run '^TestRealLAPICompatibility$$' ./tests/crowdsec

# Requires pinned real OpenZiti and CrowdSec binaries; no host tunneler or
# production controller/LAPI is used. The fixture runs in private namespaces.
test-openziti: build-e2e
	$(E2E_SUDO) env PERIMETERD_E2E=1 PERIMETERD_OPENZITI_E2E=1 ZITI_TEST_BINARY="$(ZITI_TEST_BINARY)" CROWDSEC_TEST_BINDIR="$(CROWDSEC_TEST_BINDIR)" E2E_BINARY="$(abspath $(BINARY))" "$(abspath $(E2E_TEST_BINARY))" -test.v -test.run '^TestE2EOpenZiti$$' -test.count=1

# Requires a real Docker Engine toolset, not a Podman-compatible CLI. The test
# starts a private daemon inside the same isolated namespaces as native E2E.
test-docker: build-e2e
	$(E2E_SUDO) env PERIMETERD_E2E=1 PERIMETERD_DOCKER_E2E=1 DOCKER_TEST_BINDIR="$(DOCKER_TEST_BINDIR)" E2E_BINARY="$(abspath $(BINARY))" "$(abspath $(E2E_TEST_BINARY))" -test.v -test.run '^TestE2EDocker(Coexistence|SecurityIsolation)$$' -test.count=1

SCALE_BENCHTIME ?= 1x

# Scale measurements are opt-in and deliberately run one measured iteration by
# default: the large profile exercises stream and native capacity boundaries.
# Use SCALE_BENCHTIME=10x for repeated runs.
bench-scale-small:
	$(GO) test -run '^$$' -bench '^Benchmark(LAPI|Authority|CrowdSec|SyntheticGeo|AppReconcile)/baseline$$' -benchmem -benchtime="$(SCALE_BENCHTIME)" ./internal/crowdsec ./internal/app

bench-scale-large:
	$(GO) test -run '^$$' -bench '^Benchmark(LAPI|Authority|CrowdSec|SyntheticGeo|AppReconcile)/large-(100k|250k)$$' -benchmem -benchtime="$(SCALE_BENCHTIME)" ./internal/crowdsec ./internal/app

bench-native-scale-small: build-e2e
	$(E2E_SUDO) env PERIMETERD_E2E=1 PERIMETERD_NATIVE_MEASURE=1 PERIMETERD_NATIVE_PROFILE=small E2E_BINARY="$(abspath $(BINARY))" "$(abspath $(E2E_TEST_BINARY))" -test.v -test.run '^TestE2ECrowdSecNativeMeasurement$$' -test.count=1

bench-native-scale-large: build-e2e
	$(E2E_SUDO) env PERIMETERD_E2E=1 PERIMETERD_NATIVE_MEASURE=1 PERIMETERD_NATIVE_PROFILE=large E2E_BINARY="$(abspath $(BINARY))" "$(abspath $(E2E_TEST_BINARY))" -test.v -test.run '^TestE2ECrowdSecNativeMeasurement$$' -test.count=1

release-tools: $(RELEASE_TOOLS)/goreleaser $(RELEASE_TOOLS)/syft

$(RELEASE_TOOLS)/goreleaser $(RELEASE_TOOLS)/syft &: scripts/install-release-tools.sh
	scripts/install-release-tools.sh "$(RELEASE_TOOLS)"

package: release-tools
	PATH="$(RELEASE_TOOLS):$$PATH" goreleaser check
	PATH="$(RELEASE_TOOLS):$$PATH" goreleaser release --snapshot --clean --skip=publish

# The baseline is deliberately below every publishable version; these artifacts
# exercise actual package-manager upgrade behavior, not a same-version reinstall.
package-fixtures: release-tools
	test ! -e dist-upgrade
	PATH="$(RELEASE_TOOLS):$$PATH" SNAPSHOT_VERSION=0.0.0-0 goreleaser release --snapshot --clean --skip=publish,sbom
	mv dist dist-upgrade
	$(MAKE) --no-print-directory package

test-package:
	PACKAGE_CONTAINER_RUNTIME="$(PACKAGE_CONTAINER_RUNTIME)" tests/packaging/run.sh "$(PACKAGE_DIST)" "$(PACKAGE_ARCH)" "$(PACKAGE_UPGRADE_FROM)"

test-systemd:
	tests/systemd/run.sh "$(SYSTEMD_PACKAGE)"

test-release:
	python3 -m unittest discover -s tests/release -p 'test_*.py'

verify:
	$(GO) mod verify
	$(MAKE) --no-print-directory fmt-check
	$(MAKE) --no-print-directory lint
	$(MAKE) --no-print-directory vuln
	$(MAKE) --no-print-directory build
	$(MAKE) --no-print-directory test
