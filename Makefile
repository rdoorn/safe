.PHONY: build test lint vet fmt clean image install uninstall

BINARIES := safe safe-init safe-fw safe-dns safe-keyholder
BIN_DIR  := bin
PREFIX   ?= /usr/local
INSTALL_DIR := $(PREFIX)/bin

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
	go test ./...

lint:
	golangci-lint run ./...

vet:
	go vet ./...

fmt:
	gofmt -w .

clean:
	rm -rf $(BIN_DIR)
