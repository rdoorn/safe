.PHONY: build test lint vet fmt clean image

BINARIES := safe safe-init safe-fw safe-dns safe-keyholder
BIN_DIR  := bin

build:
	@mkdir -p $(BIN_DIR)
	@for b in $(BINARIES); do \
		echo "  build $$b"; \
		go build -o $(BIN_DIR)/$$b ./cmd/$$b; \
	done

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
