#!/bin/sh
# Build an AppImage of the desktop wallet.
#
# Why an AppImage and not a .deb, an .rpm and a Flatpak: the desktop wallet
# links libwebkit2gtk, whose package name differs on every distribution
# (libwebkit2gtk-4.1-0 on Debian and Ubuntu, webkit2gtk4.1 on Fedora,
# webkit2gtk-4.1 on Arch, and so on). A distribution package per distribution
# is a maintenance surface this project does not have, and a wrong dependency
# name is an install that fails on exactly the systems nobody tested.
#
# An AppImage carries what it needs and runs on all of them. It is also the
# one Linux format with no gatekeeper of any kind: chmod +x and run.
#
# This needs linuxdeploy, which is not vendored here — a release script that
# downloads a tool is a release script that must verify it, and the
# verification is the caller's to do:
#
#   curl -fsSLO https://github.com/linuxdeploy/linuxdeploy/releases/download/continuous/linuxdeploy-x86_64.AppImage
#   sha256sum linuxdeploy-x86_64.AppImage      # compare against the release page
#   chmod +x linuxdeploy-x86_64.AppImage
#   LINUXDEPLOY=./linuxdeploy-x86_64.AppImage sh packaging/appimage/build.sh
#
# Run it from the repository root.

set -eu

LINUXDEPLOY="${LINUXDEPLOY:-linuxdeploy}"
VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
# The name drops a leading v, as every other release artefact does: the tag is
# v1.2.3 and the file is zycord-wallet-1.2.3-... See DIST_VERSION in the
# Makefile for why the two differ.
DIST_VERSION="${VERSION#v}"
OUT="${OUT:-dist}"
APPDIR="${OUT}/AppDir"

command -v "$LINUXDEPLOY" >/dev/null 2>&1 || {
    echo "appimage: linuxdeploy not found. See the header of this script." >&2
    exit 1
}

# webkit2_41 is required, not decorative: Wails v2.15.0 declares
# `#cgo !webkit2_41 pkg-config: webkit2gtk-4.0`, and libwebkit2gtk-4.0-dev was
# dropped after Ubuntu 22.04. Without the tag this fails at pkg-config on every
# distribution whose 4.1 package the header above names.
echo "==> building zycord-wallet ${VERSION}"
(cd desktop && go build -tags desktop,production,webkit2_41 -trimpath \
    -ldflags "-s -w -X main.version=${VERSION}" -o "../${OUT}/zycord-wallet" .)

rm -rf "$APPDIR"
mkdir -p "$APPDIR/usr/bin" "$APPDIR/usr/share/applications"
mv "${OUT}/zycord-wallet" "$APPDIR/usr/bin/zycord-wallet"
cp packaging/appimage/zycord-wallet.desktop "$APPDIR/usr/share/applications/"

# No icon: the application ships without one rather than pulling an image
# toolchain into a build whose argument is that it is boring and inspectable.
# linuxdeploy wants one anyway, so it gets a 1x1 placeholder it can copy.
mkdir -p "$APPDIR/usr/share/icons/hicolor/256x256/apps"
printf '\211PNG\r\n\032\n' > "$APPDIR/usr/share/icons/hicolor/256x256/apps/zycord-wallet.png"

echo "==> packaging"
OUTPUT="${OUT}/zycord-wallet-${DIST_VERSION}-linux-$(uname -m).AppImage" \
    "$LINUXDEPLOY" --appdir "$APPDIR" --output appimage

echo
echo "This artefact is NOT byte-identical across rebuilds: it uses cgo, and an"
echo "AppImage additionally bundles whatever shared libraries this machine has."
echo "zcd is reproducible. Do not publish a reproducibility claim for this file."
