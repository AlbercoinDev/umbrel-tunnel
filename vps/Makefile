SHELL := /bin/bash
GO ?= go
BIN := umbrel-tunnel
VERSION := $(shell tr -d ' \n' < VERSION)
DIST := dist
LDFLAGS := -s -w -X main.version=$(VERSION)
GOFLAGS := -trimpath -buildvcs=false
BINS := $(DIST)/$(BIN)-linux-amd64 $(DIST)/$(BIN)-linux-arm64

.PHONY: all build test vet fmt check clean dist tarballs checksums

all: build

build:
	CGO_ENABLED=0 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $(DIST)/$(BIN) ./cmd/umbrel-tunnel

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w .

check: fmt vet test

$(DIST)/$(BIN)-linux-amd64:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $@ ./cmd/umbrel-tunnel

$(DIST)/$(BIN)-linux-arm64:
	@mkdir -p $(DIST)
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build $(GOFLAGS) -ldflags '$(LDFLAGS)' -o $@ ./cmd/umbrel-tunnel

tarballs: $(BINS)
	@for arch in amd64 arm64; do \
		name="$(BIN)-$(VERSION)-linux-$$arch"; \
		rm -rf "$(DIST)/$$name"; \
		mkdir -p "$(DIST)/$$name/packaging"; \
		cp "$(DIST)/$(BIN)-linux-$$arch" "$(DIST)/$$name/$(BIN)"; \
		cp install.sh VERSION "$(DIST)/$$name/"; \
		cp packaging/* "$(DIST)/$$name/packaging/"; \
		tar -C "$(DIST)" -czf "$(DIST)/$$name.tar.gz" "$$name"; \
		echo "  $(DIST)/$$name.tar.gz"; \
	done

# Per-binary sidecars let `umbrel-tunnel update --from <url>` verify the
# download on its own: update.Apply looks for <url>.sha256 next to the binary.
checksums: tarballs
	@cd $(DIST) && for arch in amd64 arm64; do \
		sha256sum "$(BIN)-linux-$$arch" > "$(BIN)-linux-$$arch.sha256"; \
	done
	@cd $(DIST) && sha256sum $(BIN)-$(VERSION)-linux-*.tar.gz $(BIN)-linux-amd64 $(BIN)-linux-arm64 > SHA256SUMS
	@cat $(DIST)/SHA256SUMS

dist: clean
	$(MAKE) checksums

clean:
	rm -rf $(DIST)
