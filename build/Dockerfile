# The canonical build container.
#
# docs/ARCHITECTURE.md §1 P6 and docs/RELEASE.md §5: reproducible builds are the
# only trust an anonymous author can offer, and `-trimpath` plus a pinned Go
# toolchain stopped being sufficient the moment there was cgo (R1-L2). RandomX
# is C++, so a released binary now depends on a C toolchain's version and
# behaviour as well, and neither is a property of this repository unless
# something pins them.
#
# Everything here is pinned BY CONTENT, not by tag:
#
#   - the base image by digest, because a tag is mutable and a mutable base is
#     not a pinned toolchain;
#   - the Go toolchain by sha256 of the official tarball;
#   - the C/C++ toolchain by Debian package version;
#   - RandomX by the vendored tree, which core/pow/randomx/PINNED carries a
#     hash of and TestVendoredTreeMatchesPinned recomputes without cgo.
#
# What this container does NOT do is make the build reproducible. The build is
# reproducible on its own — `make repro` proves it across two paths and with
# and without a .git — and this fixes the one remaining variable, which is
# which compiler ran.
FROM debian@sha256:731dd1380d6a8d170a695dbeb17fe0eade0e1c29f654cf0a3a07f372191c3f4b

# The C toolchain, from a SNAPSHOT of the Debian archive rather than from its
# live mirrors.
#
# The base image digest above fixes the filesystem it starts from; it does not
# fix what `apt-get install` fetches, because the archive moves. Pinning
# individual package versions by hand looks equivalent and is not: the version
# strings are unverifiable from here and would rot into a build that fails on
# a date nobody chose. snapshot.debian.org serves the archive AS IT WAS at a
# timestamp, so the package set is a function of that timestamp and of nothing
# else.
#
# Change SNAPSHOT and you change the compiler; that is a release decision and
# it belongs in a diff, which is the whole point of writing it down here.
ARG SNAPSHOT=20250811T000000Z
RUN set -eux; \
    printf '%s\n' \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${SNAPSHOT}/ bookworm main" \
      "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${SNAPSHOT}/ bookworm-security main" \
      > /etc/apt/sources.list; \
    rm -f /etc/apt/sources.list.d/*; \
    apt-get update; \
    apt-get install -y --no-install-recommends ca-certificates curl g++ make git; \
    rm -rf /var/lib/apt/lists/*

# The Go toolchain, by checksum. Not apt's: Debian's Go tracks Debian's
# release, and the version a binary embeds must be a decision of this file.
#
# It is a decision this file shares with two others, and they have to agree.
# The Makefile's GO_TOOLCHAIN is the pin every build obeys (it exports
# GOTOOLCHAIN, which reaches the `make build` run inside this container too),
# and go.mod's `toolchain` line is what CI's setup-go installs. If GO_VERSION
# here ever drifts from those, `make canonical` asks a container holding one Go
# to build with another — a download this image has no reason to be able to do,
# and a silent one if it could. sim/wiring/toolchain_test.go fails on the drift
# instead. Changing the version is a release decision: every published hash
# moves with it.
ARG GO_VERSION=1.26.2
ARG GO_SHA256_amd64=990e6b4bbba816dc3ee129eaeaf4b42f17c2800b88a2166c265ac1a200262282
ARG GO_SHA256_arm64=c958a1fe1b361391db163a485e21f5f228142d6f8b584f6bef89b26f66dc5b23
RUN set -eux; \
    arch="$(dpkg --print-architecture)"; \
    case "$arch" in \
      amd64) sha="$GO_SHA256_amd64" ;; \
      arm64) sha="$GO_SHA256_arm64" ;; \
      *) echo "no pinned Go checksum for $arch" >&2; exit 1 ;; \
    esac; \
    curl -fsSL -o /tmp/go.tgz "https://go.dev/dl/go${GO_VERSION}.linux-${arch}.tar.gz"; \
    echo "$sha  /tmp/go.tgz" | sha256sum -c -; \
    tar -C /usr/local -xzf /tmp/go.tgz; \
    rm /tmp/go.tgz
ENV PATH=/usr/local/go/bin:$PATH

# GOTOOLCHAIN=local: without it, a go.mod naming a newer toolchain makes the
# build silently DOWNLOAD one, and the pinned version above becomes a
# suggestion. That is the same class of defect as a mutable base tag.
#
# The Makefile exports GOTOOLCHAIN=go<GO_VERSION> and so overrides this for the
# targets it runs; the two say the same thing by construction (see GO_VERSION
# above), so the effect is the same and the refusal stays for anything invoking
# `go` in here directly.
ENV GOTOOLCHAIN=local \
    GOFLAGS= \
    CGO_ENABLED=1 \
    SOURCE_DATE_EPOCH=0

WORKDIR /src

# No default build command. `make build` and `make build-randomx` are the
# entry points and they belong to the caller, so that this file describes a
# toolchain and nothing else.
