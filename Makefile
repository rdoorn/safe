.PHONY: build test lint vet fmt clean image install uninstall tools

BINARIES := safe safe-init safe-fw safe-dns safe-keyholder
BIN_DIR  := bin
PREFIX   ?= /usr/local
INSTALL_DIR := $(PREFIX)/bin

# Pinned to the version CI runs (see .gitlab-ci.yml golangci/golangci-lint image).
GOLANGCI_VERSION := v2.7.2
# Resolve golangci-lint from PATH (CI image) or the persistent GOPATH/bin
# (populated by `make tools`; GOPATH/bin is not on PATH in the sandbox).
GOLANGCI := $(shell command -v golangci-lint 2>/dev/null || echo $(shell go env GOPATH)/bin/golangci-lint)

build:
	@mkdir -p $(BIN_DIR)
	@for b in $(BINARIES); do \
		echo "  build $$b"; \
		go build -o $(BIN_DIR)/$$b ./cmd/$$b; \
	done

# Install only the host binary. The four in-container binaries (safe-init,
# safe-fw, safe-dns, safe-keyholder) are baked into the safe-runtime image
# and don't need to be on the host. PREFIX=/usr/local by default; override
# with `make install PREFIX=$HOME/.local` for a user-local install.
install: build
	@if [ -w "$(INSTALL_DIR)" ]; then SUDO=; else SUDO=sudo; fi; \
	echo "  install $(INSTALL_DIR)/safe"; \
	$$SUDO install -m 0755 $(BIN_DIR)/safe $(INSTALL_DIR)/safe

uninstall:
	@if [ -w "$(INSTALL_DIR)" ]; then SUDO=; else SUDO=sudo; fi; \
	echo "  remove  $(INSTALL_DIR)/safe"; \
	$$SUDO rm -f $(INSTALL_DIR)/safe

test:
	TMPDIR="$${GOTMPDIR:-$$TMPDIR}" go test ./...

# Install dev tooling into GOPATH/bin (persistent across sandbox runs).
# CGO_ENABLED=0 avoids the C link step (the sandbox has no usable C linker)
# and golangci-lint is pure Go, so a static build is correct anyway.
tools:
	CGO_ENABLED=0 go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@$(GOLANGCI_VERSION)

lint:
	@command -v "$(GOLANGCI)" >/dev/null 2>&1 || { echo "golangci-lint not found — run 'make tools'"; exit 1; }
	$(GOLANGCI) run ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

clean:
	rm -rf $(BIN_DIR)
