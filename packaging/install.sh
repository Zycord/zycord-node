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

# PUBLISHER is a placeholder, substituted when this script is published as a
# release asset. It is a placeholder rather than a real name because
# docs/RELEASE.md §3 and §4 treat every string in the tree as an identity
# surface, and a packaging file is exactly the kind of place a handle survives
# an audit that only read the Go source. The guard below refuses to run an
# unstamped copy rather than fetching from a host that does not exist.
REPO_URL="${ZYCORD_REPO_URL:-https://github.com/PUBLISHER/zycord}"

# The project key's fingerprint, which is the one thing in this file that is
# not a placeholder and must never become one. It is not an identity surface:
# it is the anti-impersonation anchor, published in full in the whitepaper
# header and in the genesis announcement precisely so that a reader can check
# a key file against it without knowing who holds the key. Hard-coded here so
# that the failure message below can print something actionable — a script that
# says "import the project key" without saying which key, from where, is not
# telling anyone anything they can act on.
PROJECT_KEY_FPR="E72439CEDD8511F9D607550B87FD60D5EB4A0B29"
PROJECT_KEY_FPR_SPACED="E724 39CE DD85 11F9 D607 550B 87FD 60D5 EB4A 0B29"
VERSION=""
PREFIX="${PREFIX:-/usr/local/bin}"
KEYRING="${ZYCORD_KEYRING:-}"
SKIP_SIGNATURE=0

usage() {
    cat <<'USAGE'
usage: sh install.sh --version vX.Y.Z [options]

  --version VERSION   release tag to install (required)
  --prefix DIR        install into DIR (default: /usr/local/bin)
  --keyring FILE      GPG keyring holding the project key
  --repo URL          release host (default: the public repository)
  --no-signature      check the SHA-256 sums but not the signature over them

--no-signature is a real reduction in what this proves, and it is offered
because "no gpg on the box" otherwise means "skip verification entirely",
which is worse. Without it you have verified that the files match a
SHA256SUMS you downloaded from the same place; with it you have verified that
SHA256SUMS was written by whoever holds the project key.
USAGE
}

while [ $# -gt 0 ]; do
    case "$1" in
        --version) VERSION="${2:?--version needs a value}"; shift 2 ;;
        --prefix)  PREFIX="${2:?--prefix needs a value}"; shift 2 ;;
        --keyring) KEYRING="${2:?--keyring needs a value}"; shift 2 ;;
        --repo)    REPO_URL="${2:?--repo needs a value}"; shift 2 ;;
        --no-signature) SKIP_SIGNATURE=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) echo "install.sh: unknown option $1" >&2; usage >&2; exit 2 ;;
    esac
done

if [ -z "$VERSION" ]; then
    echo "install.sh: --version is required (there is no 'latest': a release you did not name is a release you did not choose)" >&2
    exit 2
fi

die() { echo "install.sh: $*" >&2; exit 1; }

case "$REPO_URL" in
    *PUBLISHER*) die "this copy was not stamped by the release process; pass --repo <url> or set ZYCORD_REPO_URL" ;;
esac
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

if [ "$SKIP_SIGNATURE" -eq 0 ]; then
    command -v gpg >/dev/null 2>&1 || die "gpg is required to verify the signature; install it, or pass --no-signature and understand what that gives up"
    curl -fsSL --proto '=https' --tlsv1.2 -O "${BASE}/SHA256SUMS.asc"
    echo "==> verifying the signature over SHA256SUMS"
    if [ -n "$KEYRING" ]; then
        gpg --no-default-keyring --keyring "$KEYRING" --verify SHA256SUMS.asc SHA256SUMS \
            || die "the signature over SHA256SUMS did not verify against $KEYRING"
    else
        # Against the caller's own keyring. If the project key is not in it,
        # gpg fails here and that is the correct outcome: an installer that
        # fetched the key from the same server as the files would be checking
        # that the server agrees with itself.
        #
        # So this script does not fetch the key. It prints where to get one and
        # what to compare it against, because "import the project key first" is
        # not actionable advice when the default keyserver serves a copy GnuPG
        # refuses to import (no user ID, no self-signature) and nothing here
        # named a keyserver that does not.
        gpg --verify SHA256SUMS.asc SHA256SUMS || {
            cat >&2 <<KEYHELP
install.sh: the signature over SHA256SUMS did not verify.

If gpg said the public key is not available, the key is simply not in your
keyring yet. Import it, then re-run this script:

  gpg --keyserver hkps://keyserver.ubuntu.com \\
      --recv-keys ${PROJECT_KEY_FPR}

or, without a keyserver, take zycord-release-key.asc from the release page or
packaging/zycord-release-key.asc from a clone, and \`gpg --import\` it.

Do NOT use keys.openpgp.org for this key: it serves a copy with no user ID and
no self-signature, which gpg reports as "new key but contains no user ID -
skipped" and does not import.

Whichever source you use, the key is only worth the fingerprint it matches, and
the fingerprint is published in the whitepaper header and in the genesis
announcement:

  ${PROJECT_KEY_FPR_SPACED}

  gpg --fingerprint ${PROJECT_KEY_FPR}

If the key IS in your keyring and the signature still does not verify, do not
install this file.
KEYHELP
            exit 1
        }
    fi
else
    echo "==> skipping the signature check (--no-signature)"
    echo "    This verifies the files against a SHA256SUMS from the same host, and nothing more."
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
