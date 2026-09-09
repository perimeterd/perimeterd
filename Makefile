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
GO_SOURCES := $(GO) list -f '{{range .GoFiles}}{{$$.Dir}}/{{.}} {{end}}{{range .TestGoFiles}}{{$$.Dir}}/{{.}} {{end}}{{range .XTestGoFiles}}{{$$.Dir}}/{{.}} {{end}}' ./...

.PHONY: fmt fmt-check lint test test-race vuln build verify

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
	$(GOLANGCI) run --config .golangci.yml ./...

test:
	$(GO) test -shuffle=on -covermode=atomic -coverprofile=coverage.out ./...

test-race:
	CGO_ENABLED=1 $(GO) test -race -shuffle=on ./...

vuln:
	$(GOVULNCHECK) ./...

build:
	mkdir -p "$(dir $(BINARY))"
	$(GO) build -trimpath -ldflags "$$LDFLAGS" -o "$(BINARY)" ./cmd/perimeterd

verify:
	$(GO) mod verify
	$(MAKE) --no-print-directory fmt-check
	$(MAKE) --no-print-directory lint
	$(MAKE) --no-print-directory vuln
	$(MAKE) --no-print-directory build
	$(MAKE) --no-print-directory test
