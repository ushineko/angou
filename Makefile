default: help

.PHONY: help
help: ## Show this help
	@echo
	@echo "Available commands:"
	@echo
	@awk -F ':|##' '/^[^\t].+?:.*?##/ {printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF}' $(MAKEFILE_LIST)

BINDIR=$(shell go env GOPATH)
MODULE=github.com/ushineko/angou
VERSION?=$(shell cat VERSION 2>/dev/null || echo dev)
COMMIT?=$(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
# RELEASE_KEY is the fingerprint of the offline release-signing key this build
# trusts (spec 001 R5.4.1). It is empty for ordinary development builds, which
# makes them refuse to install a binary from a store rather than trusting any
# signature they can verify. A real release sets it.
RELEASE_KEY?=
LDFLAGS=-w -s -X $(MODULE)/internal/buildinfo.Version=$(VERSION) -X $(MODULE)/internal/buildinfo.Commit=$(COMMIT) -X $(MODULE)/internal/release.SigningKeyFingerprint=$(RELEASE_KEY)

LINT_NAME?=golangci-lint
LINT_VERSION?=v2.12.2
LINT_PROGRAM=$(LINT_NAME)-$(LINT_VERSION)

# Release asset coordinates for the pinned linter version.
# (The upstream install.sh is not used: its checksum extraction matches the
# .sbom.json asset line and fails verification on recent releases.)
LINT_VERSION_NUM=$(LINT_VERSION:v%=%)
LINT_BASE_URL=https://github.com/golangci/golangci-lint/releases/download/$(LINT_VERSION)

.PHONY: install-lint
install-lint: $(BINDIR)/bin/$(LINT_PROGRAM) ## Install linter

$(BINDIR)/bin/$(LINT_PROGRAM):
	@echo "Setting up $(LINT_PROGRAM) ..."
	@set -e; \
	os=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	arch=$$(uname -m); \
	case "$$arch" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; esac; \
	dist="$(LINT_NAME)-$(LINT_VERSION_NUM)-$$os-$$arch"; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	curl -fsSL "$(LINT_BASE_URL)/$$dist.tar.gz" -o "$$tmp/$$dist.tar.gz"; \
	curl -fsSL "$(LINT_BASE_URL)/$(LINT_NAME)-$(LINT_VERSION_NUM)-checksums.txt" -o "$$tmp/checksums.txt"; \
	want=$$(awk -v f="$$dist.tar.gz" '$$2 == f {print $$1}' "$$tmp/checksums.txt"); \
	got=$$( (sha256sum "$$tmp/$$dist.tar.gz" 2>/dev/null || shasum -a 256 "$$tmp/$$dist.tar.gz") | awk '{print $$1}'); \
	if [ -z "$$want" ] || [ "$$want" != "$$got" ]; then echo "checksum mismatch for $$dist.tar.gz: want '$$want' got '$$got'"; exit 1; fi; \
	tar -C "$$tmp" -xzf "$$tmp/$$dist.tar.gz"; \
	mkdir -p "$(BINDIR)/bin"; \
	mv -v "$$tmp/$$dist/$(LINT_NAME)" "$(BINDIR)/bin/$(LINT_PROGRAM)"

.PHONY: setup
setup: install-lint ## Setup system for local development
	@echo "Make sure your system path includes GOPATH/bin. See README.md for details."

# Pin lint to the Go toolchain in go.mod so results match CI regardless of system Go version.
LINT_GO_TOOLCHAIN := $(shell grep '^toolchain' go.mod | awk '{print $$2}')

.PHONY: lint
lint: export GOTOOLCHAIN = $(LINT_GO_TOOLCHAIN)
lint: install-lint ## Lint files
	@go version
	$(BINDIR)/bin/$(LINT_PROGRAM) run --timeout 5m0s --config config/.golangci-$(LINT_VERSION).yml ./...

.PHONY: shellcheck
shellcheck: ## Lint the plaintext bootstrap entrypoint (spec 001 R5.6)
	@shellcheck internal/core/assets/bootstrap.sh

.PHONY: test
test: ## Run unit tests with the race detector (fast, no build)
	@go test -race ./...

.PHONY: e2e
e2e: build-static ## Build the real binary and run end-to-end tests against throwaway stores
	@ANGOU_E2E_BIN=$(CURDIR)/angou go test -race -tags e2e -count=1 -v ./tests/e2e/...

.PHONY: e2e-keyring
e2e-keyring: build-static ## Run the keyring tests against the real KWallet (INTERACTIVE - see below)
	@echo "These tests write a per-run entry into your session's KWallet and remove it"
	@echo "afterwards. KWallet may raise an access dialog: this target needs a human at"
	@echo "the desktop to answer it, and will hang without one. Do not run it in CI."
	@ANGOU_E2E_BIN=$(CURDIR)/angou go test -race -tags 'e2e e2e_keyring' -count=1 -v ./tests/e2e/...

.PHONY: e2e-container
e2e-container: build-all ## Bootstrap test on a bare machine (no angou, no gpg, no Go)
	@./tests/e2e/container/run.sh

.PHONY: coverage
coverage: ## Run all tests and open a coverage report in the default browser
	@go test -coverprofile coverage.out ./...
	@go tool cover -html=coverage.out
	@rm -f coverage.out

.PHONY: build
build: ## Build the CLI for the host platform
	go build -ldflags='$(LDFLAGS)' -trimpath -o angou ./cmd/angou

.PHONY: build-static
build-static: ## Build the static CGO-free CLI (the bootstrap artifact, spec 001 R6.2)
	CGO_ENABLED=0 go build -ldflags='$(LDFLAGS)' -trimpath -o angou ./cmd/angou

.PHONY: build-gui
build-gui: ## Build the desktop navigator (requires CGO)
	CGO_ENABLED=1 go build -ldflags='$(LDFLAGS)' -trimpath -o angou-gui ./cmd/angou-gui

.PHONY: build-all
build-all: ## Build static CLI binaries for every platform, plus the host's GUI
	@set -e; for p in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
		os=$${p%/*}; arch=$${p#*/}; \
		echo "building $$os/$$arch ..."; \
		mkdir -p dist; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -ldflags='$(LDFLAGS)' -trimpath -o dist/angou-$$os-$$arch ./cmd/angou; \
	done
	@# The GUI is built for this machine only. It needs CGO, so cross-compiling
	@# it would need a C toolchain per target -- a store therefore carries a GUI
	@# for the platforms someone has actually built on, and the CLI for all of
	@# them. Nothing about recovery depends on the difference: bootstrap.sh
	@# installs the CLI and skips these.
	@echo "building the GUI for this host ..."; \
	if CGO_ENABLED=1 go build -ldflags='$(LDFLAGS)' -trimpath \
		-o dist/angou-gui-$$(go env GOOS)-$$(go env GOARCH) ./cmd/angou-gui; then \
		echo "  built dist/angou-gui-$$(go env GOOS)-$$(go env GOARCH)"; \
	else \
		echo "  the GUI did not build; the CLI binaries are unaffected" >&2; \
	fi
	@ls -l dist/

.PHONY: release
release: build-all ## Stash built binaries into the store bootstrap namespace (spec 001 R5.3)
	./angou release --store "$(STORE)" --dist dist/

.PHONY: install
install: build ## Install the CLI plus MIME, magic, and desktop integration
	install -Dm755 angou $(HOME)/.local/bin/angou

.PHONY: clean
clean: ## Remove build artifacts
	@rm -rf angou angou-gui dist/ coverage.out count.out
