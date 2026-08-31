#!/bin/sh
# Install zcd and zycordd on a Unix host.
#
# Download, verify, and only then install. There is no `curl | sh` form of this
# script and there will not be one: piping an unverified script into a shell is
# the wrong posture for software that holds money, and it is the wrong posture
# even when the script is ours. The whole argument of docs/INSTALL.md is that
# you should not have to trust the publisher — a pipe into sh is the one thing
# that makes that impossible.
#
# So: fetch it, read it, run it.
#
#   curl -fsSLO <release-url>/install.sh
#   less install.sh
#   sh install.sh --version v1.2.3
#
# POSIX sh, no bashisms: this runs on whatever a minimal VPS image has.

set -eu

# The account this project publishes from, written out rather than left as a
# placeholder to be substituted at release time.
#
# It was a placeholder, and the guard that used to sit below refused to run an
# unstamped copy. Two things retired that: the repository is published, so the
# account is not a secret this file could keep -- a reader downloaded the script
# from it -- and the substitution never actually happened, because `make dist`
# does not stage this file and the workflow does not upload it, so the copy the
# install docs tell people to fetch has never existed. A guard against a step
# nobody performs only breaks the clone somebody does have.
#
# --repo is still here and still works, which is what a fork or a mirror uses.
REPO_URL="${ZYCORD_REPO_URL:-https://github.com/thesimstoshi/zycord}"

# `gh attestation verify` wants owner/name, not a URL, and deriving it here
# means the --repo flag keeps working for a fork or a mirror without a second
# thing to pass.
REPO_SLUG=""

VERSION=""
PREFIX="${PREFIX:-/usr/local/bin}"

usage() {
    cat <<'USAGE'
usage: sh install.sh --version vX.Y.Z [options]

  --version VERSION   release tag to install (required)
  --prefix DIR        install into DIR (default: /usr/local/bin)
  --repo URL          release host (default: the public repository)

What this proves depends on what is installed. The checksum check always runs
and shows the files match this release's own list. If `gh` is present the build
provenance is checked too, which is what says the release came out of the
project's workflow rather than from whoever served you the list. The script
tells you which of the two it managed.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --prefix)  PREFIX="${2:?--prefix needs a value}"; shift 2 ;;
        --repo)    REPO_URL="${2:?--repo needs a value}"; shift 2 ;;
        -h|--help) usage; exit 0 ;;
        *) echo "install.sh: unknown option $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -z "$VERSION" ]; then
    echo "install.sh: --version is required (there is no 'latest': a release you did not name is a release you did not choose)" >&2
    exit 2
fi

die() { echo "install.sh: $*" >&2; exit 1; }

REPO_SLUG=$(printf '%s' "$REPO_URL" | sed -e 's|^[a-z]*://||' -e 's|^[^/]*/||' -e 's|/*$||')
need() { command -v "$1" >/dev/null 2>&1 || die "$1 is required and was not found"; }

need curl
need tar

# The checksum tool differs across systems and one of them must be present:
# an installer that silently skips verification because it could not find a
# hasher is an installer that does not verify.
if command -v sha256sum >/dev/null 2>&1; then
    SHA256_CHECK="sha256sum --check --ignore-missing"
elif command -v shasum >/dev/null 2>&1; then
    SHA256_CHECK="shasum -a 256 --check --ignore-missing"
else
    die "neither sha256sum nor shasum is available; refusing to install without verifying"
fi

case "$(uname -s)" in
    Linux)  OS=linux ;;
    Darwin) OS=darwin ;;
    *) die "$(uname -s) is not a platform this script installs; build from source" ;;
esac

case "$(uname -m)" in
    x86_64|amd64)  ARCH=amd64 ;;
    aarch64|arm64) ARCH=arm64 ;;
    *) die "$(uname -m) is not a platform this script installs; build from source" ;;
esac

NAME="zycord-${VERSION#v}-${OS}-${ARCH}"
BASE="${REPO_URL%/}/releases/download/${VERSION}"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT INT TERM
cd "$WORK"

echo "==> fetching ${NAME}"
curl -fsSL --proto '=https' --tlsv1.2 -O "${BASE}/${NAME}.tar.gz"
curl -fsSL --proto '=https' --tlsv1.2 -O "${BASE}/SHA256SUMS"

# Build provenance, where the tooling for it exists.
#
# There is no signature to check any more, and that is a deliberate change
# rather than something lost. A release is built by GitHub Actions and goes
# straight to whoever downloads it; nothing passes through a machine that could
# hold a signing key, so a key in this path would either live in CI -- where it
# belongs to whoever can push a workflow file -- or describe a step nobody
# performs. What replaces it is an attestation the build itself produces,
# keyless, naming the workflow and the commit the bytes came out of.
#
# `gh` is not a dependency of this script and is not going to become one: it is
# a large Go program and this installs on machines that have curl and a shell.
# So the check runs when it happens to be available and is NAMED, not silently
# skipped, when it is not -- a check that vanishes without saying so is how an
# installer teaches people that verification is optional.
if command -v gh >/dev/null 2>&1; then
    echo "==> verifying build provenance"
    gh attestation verify "${NAME}.tar.gz" --repo "${REPO_SLUG}" \
        || die "provenance did not verify; do not install this file"
else
    echo "==> gh is not installed, so build provenance was NOT checked"
    echo "    The checksum below proves the file matches this release's own list."
    echo "    It cannot prove the list came from the project. To check that:"
    echo "      gh attestation verify ${NAME}.tar.gz --repo ${REPO_SLUG}"
fi

echo "==> verifying checksums"
$SHA256_CHECK SHA256SUMS || die "the checksum did not match; do not install this file"

echo "==> unpacking"
tar xzf "${NAME}.tar.gz"

echo "==> installing into ${PREFIX}"
INSTALL="install -m 0755"
if [ ! -w "$PREFIX" ]; then
    command -v sudo >/dev/null 2>&1 || die "$PREFIX is not writable and sudo is not available; re-run with --prefix pointing somewhere you own"
    INSTALL="sudo install -m 0755"
fi
$INSTALL "${NAME}/zcd" "${PREFIX}/zcd"
$INSTALL "${NAME}/zycordd" "${PREFIX}/zycordd"

echo
"${PREFIX}/zcd" version
cat <<NEXT

What you just installed is from the ATTESTED tier, and that tier is DEVNET-ONLY.

These binaries are pure Go, CGO_ENABLED=0, and byte-identical to anyone else's
build of this tag — which is the whole point of them, and which is also why they
carry no RandomX engine. Mainnet and the public testnet both declare
pow_engine: randomx-v1, and a node that cannot verify a network's engine refuses
to start on it rather than accepting one BLAKE3 pass as proof of work. So:

  zycordd --devnet --dir ./devnet     works, and is how to find out how it works
  zycordd --dir ./data                REFUSES: this binary holds no randomx-v1
  zycordd --testnet --dir ./data      REFUSES, for the same reason

To join a network, take the archive with -randomx in its name from the same
release page and install it the same way:

  ${NAME}-randomx.tar.gz

That one is cgo, so it is NOT byte-identical across machines: it is checksummed
by SHA256SUMS.randomx and it has no line in SHA256SUMS.binaries. The two tiers
are disjoint sets — the archive you can reproduce is not the one you can mine
with, and the one you can mine with is not one anybody can attest. That is
stated rather than hidden; docs/INSTALL.md, "Two tiers of assurance", is the
longer version, and \`zcd version\` above printed which one you are holding.

What is worth doing next, with what you have:

  zcd genesis                 rebuild block 0 and check it against the announced values
  zcd vectors                 check this build against the protocol's golden vectors

The strongest check available is not either of the above. Clone the repository
at this tag, run \`make build\`, and compare the SHA-256 of your bin/zcd against
SHA256SUMS.binaries from the release. If they match, the binary you just
installed contains that source and nothing else. That check covers every line of
consensus code the -randomx binary runs too; only the work function differs, and
it is a vendored copy of a published implementation pinned in
core/pow/randomx/PINNED.

There is no coin yet. Anyone selling you ZCD today is scamming you.
NEXT
