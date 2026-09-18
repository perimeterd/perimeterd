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

.PHONY: fmt fmt-check lint test test-race vuln build build-e2e test-e2e test-crowdsec verify bench-scale-small bench-scale-large bench-native-scale-small bench-native-scale-large

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

verify:
	$(GO) mod verify
	$(MAKE) --no-print-directory fmt-check
	$(MAKE) --no-print-directory lint
	$(MAKE) --no-print-directory vuln
	$(MAKE) --no-print-directory build
	$(MAKE) --no-print-directory test
