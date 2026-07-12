#!/bin/bash
set -e

VERSION="0.0.4"
ARCH="amd64"
RPM_ARCH="x86_64"

# Clean previous build directories
rm -rf build
mkdir -p build

echo "=== Building nspect binary ==="
go build -o build/nspect main.go

# ---------------- DEB Package ----------------
echo "=== Building DEB package ==="
DEB_DIR="build/deb"
mkdir -p "$DEB_DIR/DEBIAN"
mkdir -p "$DEB_DIR/usr/local/bin"
mkdir -p "$DEB_DIR/usr/share/doc/nspect"

cp build/nspect "$DEB_DIR/usr/local/bin/"
cp README.md "$DEB_DIR/usr/share/doc/nspect/"

cat <<EOF > "$DEB_DIR/DEBIAN/control"
Package: nspect
Version: ${VERSION}
Section: security
Priority: optional
Architecture: amd64
Maintainer: David Vanhoucke <vanhouckedavid@gmail.com>
Description: Linux Capability & Namespace Auditor
 nspect is a lightweight, zero-dependency Go tool designed to audit 
 namespace isolation, capabilities, writeable mounts, environment 
 variable passwords/secrets, socket configurations, and file descriptor limits.
EOF

# Build DEB packages manually using tar and ar
(
    cd "$DEB_DIR"
    # control.tar.gz
    tar -czf ../control.tar.gz -C DEBIAN control
    # data.tar.gz
    tar -czf ../data.tar.gz --exclude=DEBIAN usr
)

echo "2.0" > build/debian-binary

# Order is critical for deb packages
(
    cd build
    ar rcs "../nspect_${VERSION}_amd64.deb" debian-binary control.tar.gz data.tar.gz
)
echo "DEB package created: nspect_${VERSION}_amd64.deb"

# ---------------- RPM Package ----------------
if ! command -v rpmbuild &> /dev/null; then
    echo "rpmbuild not found, skipping RPM package generation."
    exit 0
fi

echo "=== Building RPM package ==="
RPM_DIR="$(pwd)/build/rpm"
mkdir -p "$RPM_DIR"/{SOURCES,SPECS,BUILD,RPMS,SRPMS,BUILDROOT}

# Create source tarball
tar -czf "$RPM_DIR/SOURCES/nspect-${VERSION}.tar.gz" --exclude=build --transform "s,^,nspect-${VERSION}/," *

cat <<EOF > "$RPM_DIR/SPECS/nspect.spec"
Name:           nspect
Version:        ${VERSION}
Release:        1
Summary:        Linux Capability & Namespace Auditor
License:        MIT
URL:            https://github.com/david/nspect
Source0:        nspect-%{version}.tar.gz

%description
A lightweight, zero-dependency Go tool designed to audit namespace isolation, capabilities, writeable mounts, environment variable passwords/secrets, socket configurations, and file descriptor limits.

%prep
%setup -q

%build
go build -o nspect main.go

%install
rm -rf \$RPM_BUILD_ROOT
mkdir -p \$RPM_BUILD_ROOT/usr/local/bin
cp nspect \$RPM_BUILD_ROOT/usr/local/bin/nspect

%files
/usr/local/bin/nspect

%changelog
* Sat Jun 27 2026 David Vanhoucke <vanhouckedavid@gmail.com> - 0.0.1-1
- Initial beta release
* Sun Jun 28 2026 David Vanhoucke <vanhouckedavid@gmail.com> - 0.0.2-1
- add mounting audit
EOF

rpmbuild --define "_topdir $RPM_DIR" -bb "$RPM_DIR/SPECS/nspect.spec"

# Copy generated RPM back to root
cp "$RPM_DIR/RPMS/x86_64/nspect-${VERSION}-1.x86_64.rpm" ./nspect-${VERSION}-1.x86_64.rpm
echo "RPM package created: nspect-${VERSION}-1.x86_64.rpm"

# Clean temp build artifacts
rm -rf build
