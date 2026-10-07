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

# migrated_fynedo tells Fyne this front end has been through the fyne.Do
# migration, so it stops asking which goroutine it is on. Without it, Fyne
# answers that question with runtime.Stack -- a full traceback -- on every
# Canvas.Refresh. Profiled on a sibling program during a window drag: 52% of the
# process's CPU was printing tracebacks. Every UI mutation off the main
# goroutine here goes through fyne.Do, which is what the tag asserts.
# See fynedesygn docs/fyne-quirks.md, quirk 31.
FYNE_TAGS?=migrated_fynedo

# EXE is ".exe" on Windows and empty elsewhere. A Windows binary without it
# cannot be run by name, so every host-platform output carries it. The
# cross-compiled artifacts in dist/ do not: `angou release` reads the platform
# out of the filename (angou-<goos>-<goarch>), and bootstrap.ps1 copies the
# Windows build to angou.exe itself.
EXE := $(shell go env GOEXE)

# The Windows GUI is linked as a GUI-subsystem program, or launching it from
# the Start menu opens a console window beside it.
GUI_LDFLAGS := $(LDFLAGS)
ifeq ($(shell go env GOOS),windows)
GUI_LDFLAGS += -H windowsgui
endif

LINT_NAME?=golangci-lint
LINT_VERSION?=v2.12.2
LINT_PROGRAM=$(LINT_NAME)-$(LINT_VERSION)

# Release asset coordinates for the pinned linter version.
# (The upstream install.sh is not used: its checksum extraction matches the
# .sbom.json asset line and fails verification on recent releases.)
LINT_VERSION_NUM=$(LINT_VERSION:v%=%)
LINT_BASE_URL=https://github.com/golangci/golangci-lint/releases/download/$(LINT_VERSION)

.PHONY: install-lint
install-lint: $(BINDIR)/bin/$(LINT_PROGRAM)$(EXE) ## Install linter

# Windows releases are zip archives holding golangci-lint.exe; everything else
# is a tarball. Git Bash and MSYS report a uname of MINGW64_NT-... or MSYS_NT-...
# MSYS2 does not ship unzip, but it ships bsdtar, and so does Windows itself
# (System32\tar.exe); either reads a zip.
$(BINDIR)/bin/$(LINT_PROGRAM)$(EXE):
	@echo "Setting up $(LINT_PROGRAM) ..."
	@set -e; \
	os=$$(uname -s | tr '[:upper:]' '[:lower:]'); \
	arch=$$(uname -m); \
	case "$$arch" in x86_64) arch=amd64;; aarch64|arm64) arch=arm64;; esac; \
	ext=tar.gz; exe=; \
	case "$$os" in mingw*|msys*|cygwin*) os=windows; ext=zip; exe=.exe;; esac; \
	dist="$(LINT_NAME)-$(LINT_VERSION_NUM)-$$os-$$arch"; \
	tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	curl -fsSL "$(LINT_BASE_URL)/$$dist.$$ext" -o "$$tmp/$$dist.$$ext"; \
	curl -fsSL "$(LINT_BASE_URL)/$(LINT_NAME)-$(LINT_VERSION_NUM)-checksums.txt" -o "$$tmp/checksums.txt"; \
	want=$$(awk -v f="$$dist.$$ext" '$$2 == f {print $$1}' "$$tmp/checksums.txt"); \
	got=$$( (sha256sum "$$tmp/$$dist.$$ext" 2>/dev/null || shasum -a 256 "$$tmp/$$dist.$$ext") | awk '{print $$1}'); \
	if [ -z "$$want" ] || [ "$$want" != "$$got" ]; then echo "checksum mismatch for $$dist.$$ext: want '$$want' got '$$got'"; exit 1; fi; \
	if [ "$$ext" = tar.gz ]; then tar -C "$$tmp" -xzf "$$tmp/$$dist.$$ext"; \
	elif command -v unzip >/dev/null; then unzip -q "$$tmp/$$dist.$$ext" -d "$$tmp"; \
	else bsdtar -C "$$tmp" -xf "$$tmp/$$dist.$$ext" 2>/dev/null || "$$SYSTEMROOT/System32/tar.exe" -C "$$tmp" -xf "$$tmp/$$dist.$$ext"; fi; \
	mkdir -p "$(BINDIR)/bin"; \
	mv -v "$$tmp/$$dist/$(LINT_NAME)$$exe" "$(BINDIR)/bin/$(LINT_PROGRAM)$$exe"

.PHONY: setup
setup: install-lint ## Setup system for local development
	@echo "Make sure your system path includes GOPATH/bin. See README.md for details."

# Pin lint to a Go toolchain so results match CI regardless of system Go version.
#
# Read from go.mod's toolchain line until the fynedesygn adoption raised the go
# directive to 1.26.0 and go removed that line as redundant, leaving this empty
# and the linter running under whatever Go is installed -- which panics when
# that is newer than the Go the linter binary was built with. Pinned literally
# now, as nmsbonker and fynedesygn do.
LINT_GO_TOOLCHAIN?=go1.26.0

.PHONY: lint
lint: export GOTOOLCHAIN = $(LINT_GO_TOOLCHAIN)
lint: install-lint ## Lint files
	@go version
	$(BINDIR)/bin/$(LINT_PROGRAM)$(EXE) run --timeout 5m0s --config config/.golangci-$(LINT_VERSION).yml ./...

.PHONY: shellcheck
shellcheck: ## Lint the plaintext bootstrap entrypoint (spec 001 R5.6)
	@shellcheck internal/core/assets/bootstrap.sh

.PHONY: test
test: ## Run unit tests with the race detector (fast, no build)
	@go test -race ./...

.PHONY: e2e
e2e: build-static ## Build the real binary and run end-to-end tests against throwaway stores
	@ANGOU_E2E_BIN=$(CURDIR)/angou$(EXE) go test -race -tags e2e -count=1 -v ./tests/e2e/...

.PHONY: e2e-keyring
e2e-keyring: build-static ## Run the keyring tests against the real KWallet (INTERACTIVE - see below)
	@echo "These tests write a per-run entry into your session's KWallet and remove it"
	@echo "afterwards. KWallet may raise an access dialog: this target needs a human at"
	@echo "the desktop to answer it, and will hang without one. Do not run it in CI."
	@ANGOU_E2E_BIN=$(CURDIR)/angou$(EXE) go test -race -tags 'e2e e2e_keyring' -count=1 -v ./tests/e2e/...

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
	go build -ldflags='$(LDFLAGS)' -trimpath -o angou$(EXE) ./cmd/angou

# The CLI is CGO-free on Linux, where CGO_ENABLED=0 yields a genuinely static,
# dependency-free bootstrap artifact (spec 001 R6.2). On macOS it cannot be: the
# Keychain backend links Security.framework through cgo (spec 003 R1.3), and a
# CGO_ENABLED=0 darwin binary was never static anyway — it still links libSystem.
# So the darwin CLI is built with cgo and the linux CLI without.
HOST_OS := $(shell go env GOOS)
CLI_CGO := 0
ifeq ($(HOST_OS),darwin)
CLI_CGO := 1
endif

.PHONY: build-static
build-static: ## Build the bootstrap CLI (CGO-free on Linux; Keychain-linked on macOS)
	CGO_ENABLED=$(CLI_CGO) go build -ldflags='$(LDFLAGS)' -trimpath -o angou$(EXE) ./cmd/angou

.PHONY: build-gui
build-gui: ## Build the desktop navigator (requires CGO; on Windows, MinGW-w64 gcc on PATH)
	CGO_ENABLED=1 go build -tags $(FYNE_TAGS) -ldflags='$(GUI_LDFLAGS)' -trimpath -o angou-gui$(EXE) ./cmd/angou-gui

.PHONY: build-app
build-app: ## Assemble the macOS app bundle around the GUI (spec 003 R5)
	@if [ "$(HOST_OS)" != "darwin" ]; then \
		echo "build-app is macOS-only: it assembles a .app bundle. Host is $(HOST_OS)." >&2; \
		exit 1; \
	fi
	$(MAKE) build-gui
	@mkdir -p dist
	@chmod +x tools/make-icns.sh tools/make-app.sh
	@tools/make-icns.sh packaging/angou.svg dist/angou.icns
	@tools/make-app.sh angou-gui dist/angou.icns "$(VERSION)" "$(COMMIT)" dist
	@echo "built dist/angou-gui.app"

.PHONY: build-all
build-all: ## Build CLI binaries for every platform, plus the host's GUI
	@# The Keychain-linked darwin CLI needs cgo and a macOS SDK, so it can only be
	@# produced on a Mac, and only for the arch being built on (cross-arch cgo is
	@# more trouble than it earns here). Every other darwin binary is the CGO-free
	@# recovery stub: it has no keyring, which is the state bootstrap leaves behind
	@# anyway, so recovery from the store is unaffected. This mirrors the GUI's
	@# host-only rule (spec 002 R2.2.1). Linux is CGO-free on every host.
	@set -e; host=$$(go env GOOS); hostarch=$$(go env GOARCH); mkdir -p dist; \
	for p in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64; do \
		os=$${p%/*}; arch=$${p#*/}; cgo=0; note=; \
		if [ "$$os" = darwin ] && [ "$$host" = darwin ] && [ "$$arch" = "$$hostarch" ]; then \
			cgo=1; note=" (with Keychain)"; \
		elif [ "$$os" = darwin ]; then \
			note=" (CGO-free recovery stub: no Keychain)"; \
		fi; \
		echo "building $$os/$$arch ...$$note"; \
		CGO_ENABLED=$$cgo GOOS=$$os GOARCH=$$arch \
			go build -ldflags='$(LDFLAGS)' -trimpath -o dist/angou-$$os-$$arch ./cmd/angou; \
	done
	@# The GUI is built for this machine only. It needs CGO, so cross-compiling
	@# it would need a C toolchain per target -- a store therefore carries a GUI
	@# for the platforms someone has actually built on, and the CLI for all of
	@# them. Nothing about recovery depends on the difference: bootstrap.sh
	@# installs the CLI and skips these.
	@echo "building the GUI for this host ..."; \
	if CGO_ENABLED=1 go build -tags $(FYNE_TAGS) -ldflags='$(GUI_LDFLAGS)' -trimpath \
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
	@rm -rf angou angou-gui angou.exe angou-gui.exe dist/ coverage.out count.out
