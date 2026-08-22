.PHONY: all build clean run list test lint package rock help

# Binary name
BINARY_NAME=nspect

# Default target when running 'make' without arguments
.DEFAULT_GOAL := help

all: build

build:
	CGO_ENABLED=0 GOFLAGS="-trimpath" go build -ldflags="-s -w" -o $(BINARY_NAME) main.go

clean:
	rm -f $(BINARY_NAME) *.deb *.rpm *.rock
	rm -rf build

run: build
	./$(BINARY_NAME) --pid $$$$

list: build
	./$(BINARY_NAME) --list

test:
	go test -v ./...

lint:
	go vet ./...
	@if command -v golangci-lint > /dev/null 2>&1; then \
		golangci-lint run ./...; \
	elif [ -f $$(go env GOPATH)/bin/golangci-lint ]; then \
		$$(go env GOPATH)/bin/golangci-lint run ./...; \
	else \
		echo "golangci-lint is not installed. Run 'go install github.com/golangci/golangci-lint/cmd/golangci-lint@latest' to install."; \
	fi

package:
	chmod +x package.sh
	./package.sh

rock:
	@command -v rockcraft > /dev/null 2>&1 || { echo "rockcraft not installed. Run: sudo snap install rockcraft --classic"; exit 1; }
	rockcraft pack --verbosity brief

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@echo "  build   - Compile the auditor binary (static, stripped)"
	@echo "  clean   - Remove compiled binaries, packages, and build folders"
	@echo "  run     - Build and audit the calling process context"
	@echo "  list    - Build and list running isolated processes"
	@echo "  test    - Run all Go tests"
	@echo "  lint    - Run go vet and golangci-lint static analysis"
	@echo "  package - Build Debian (.deb) and Red Hat (.rpm) installer packages"
	@echo "  rock    - Build OCI Rock image using rockcraft (requires: sudo snap install rockcraft --classic)"
	@echo "  all     - Build the binary (alias for build)"
	@echo "  help    - Show this help menu"



