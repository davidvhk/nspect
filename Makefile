.PHONY: all build clean run list test package help

# Binary name
BINARY_NAME=nspect

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
	@echo "Makefile targets:"
	@echo "  all     - Build the binary (default)"
	@echo "  build   - Compile the auditor binary"
	@echo "  clean   - Remove the compiled binary, packages, and temp folders"
	@echo "  run     - Build and audit the calling process context"
	@echo "  list    - Build and list running isolated processes"
	@echo "  test    - Run Go tests"
	@echo "  package - Build Debian (.deb) and Red Hat (.rpm) installer packages"

