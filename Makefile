.PHONY: all build clean run list test package help

# Binary name
BINARY_NAME=nspect

# Default target when running 'make' without arguments
.DEFAULT_GOAL := help

all: build

build:
	go build -o $(BINARY_NAME) main.go

clean:
	rm -f $(BINARY_NAME) *.deb *.rpm
	rm -rf build

run: build
	./$(BINARY_NAME) --pid $$$$

list: build
	./$(BINARY_NAME) --list

test:
	go test -v ./...

package:
	chmod +x package.sh
	./package.sh

help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Available targets:"
	@echo "  build   - Compile the auditor binary"
	@echo "  clean   - Remove compiled binaries, packages, and build folders"
	@echo "  run     - Build and audit the calling process context"
	@echo "  list    - Build and list running isolated processes"
	@echo "  test    - Run all Go tests"
	@echo "  package - Build Debian (.deb) and Red Hat (.rpm) installer packages"
	@echo "  all     - Build the binary (alias for build)"
	@echo "  help    - Show this help menu"


