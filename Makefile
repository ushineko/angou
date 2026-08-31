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
LDFLAGS=-w -s -X $(MODULE)/lib/container.Version=$(VERSION) -X $(MODULE)/lib/container.Commit=$(COMMIT)

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
	@shellcheck bootstrap/bootstrap.sh

.PHONY: test
test: ## Run all tests with the race detector
	@go test -race ./...

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
build-all: ## Build static CLI binaries for every supported platform
	@set -e; for p in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64; do \
		os=$${p%/*}; arch=$${p#*/}; \
		echo "building $$os/$$arch ..."; \
		mkdir -p dist; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch \
			go build -ldflags='$(LDFLAGS)' -trimpath -o dist/angou-$$os-$$arch ./cmd/angou; \
	done
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
