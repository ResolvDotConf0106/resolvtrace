#!/bin/bash
set -e
VERSION="1.0.0"
PKG="resolvtrace"
ARCH="amd64"
BUILD_DIR="build/${PKG}_${VERSION}_${ARCH}"

mkdir -p "${BUILD_DIR}/usr/bin"
mkdir -p "${BUILD_DIR}/etc/systemd/system"
mkdir -p "${BUILD_DIR}/var/log/resolvtrace"
mkdir -p "${BUILD_DIR}/DEBIAN"

cp dns_sniffer                  "${BUILD_DIR}/usr/bin/dns_sniffer"
cp systemd/resolvtrace.service  "${BUILD_DIR}/etc/systemd/system/resolvtrace.service"
cp debian/control               "${BUILD_DIR}/DEBIAN/control"
cp debian/postinst              "${BUILD_DIR}/DEBIAN/postinst"
cp debian/prerm                 "${BUILD_DIR}/DEBIAN/prerm"

chmod 755 "${BUILD_DIR}/usr/bin/dns_sniffer"
chmod 755 "${BUILD_DIR}/DEBIAN/postinst"
chmod 755 "${BUILD_DIR}/DEBIAN/prerm"

dpkg-deb --build "${BUILD_DIR}"
echo "[✓] Built: ${BUILD_DIR}.deb"
