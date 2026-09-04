#!/bin/sh
# Build and run the aarch64 conformance harness against the vendored RandomX.
#
# Two modes, chosen automatically:
#
#   native   on an aarch64 machine, build and run directly.
#   cross    on anything else, cross-compile for aarch64 and run under
#            qemu-user. Needs an aarch64 g++ and qemu-aarch64; both come from
#            the distribution and NEITHER needs root to use — see below.
#
# Usage:  sh core/pow/randomx/arm64/run.sh [sweep-count]
#
# Set RX_FAST=1 to additionally exercise the full-dataset path, which is the
# one a mining node runs and which reaches a different a64 code-generation
# branch than the light path. It allocates ~2.1 GiB and is much slower under
# emulation, so it is opt-in.
#
# -O2 here against the cgo build's -O3, and it does not weaken what this
# checks. The optimisation level applies to the C++ that RUNS the JIT, not to
# the machine code the JIT EMITS: the emitted bytes come from emit32 calls with
# constants the compiler does not get to reinterpret, so -O2 and -O3 generate
# the same program for the VM to execute. What the level could change is the
# interpreter and the argon2/superscalar helpers, and those are pinned by
# upstream's published vectors here in both modes -- a compiler that broke them
# at one level would fail those vectors. It is -O2 because it builds faster
# under emulation and this is a conformance run rather than a benchmark; no
# timing here should be read as a hashrate.
#
# Getting the toolchain WITHOUT root, which is how this was first run:
#
#   apt-get download qemu-user-static g++-aarch64-linux-gnu \
#     gcc-aarch64-linux-gnu cpp-aarch64-linux-gnu gcc-13-aarch64-linux-gnu \
#     g++-13-aarch64-linux-gnu cpp-13-aarch64-linux-gnu gcc-13-cross-base \
#     binutils-aarch64-linux-gnu libc6-dev-arm64-cross libc6-arm64-cross \
#     linux-libc-dev-arm64-cross libgcc-13-dev-arm64-cross \
#     libstdc++-13-dev-arm64-cross libstdc++6-arm64-cross \
#     libgcc-s1-arm64-cross libasan8-arm64-cross libatomic1-arm64-cross \
#     libgomp1-arm64-cross libitm1-arm64-cross liblsan0-arm64-cross \
#     libtsan2-arm64-cross libubsan1-arm64-cross libhwasan0-arm64-cross
#   for d in *.deb; do dpkg-deb -x "$d" root/; done
#   export ARM_SYSROOT=$PWD/root
#
# With ARM_SYSROOT set this script finds everything inside it. Without it, the
# script uses whatever aarch64-linux-gnu-g++ and qemu-aarch64 are on PATH.
set -e

HERE=$(cd "$(dirname "$0")" && pwd)
SRC="$HERE/../upstream"
N="${1:-32}"
OUT=$(mktemp -d)
trap 'rm -rf "$OUT"' EXIT

# The vendored sources this tree actually compiles for arm64, which is the
# portable set plus the a64 JIT. The x86 generator is listed because
# randomx.cpp references its symbols unconditionally; the argon2 SIMD files are
# listed for the same reason and disable themselves internally.
CPP="aes_hash allocator assembly_generator_x86 blake2_generator bytecode_machine
     cpu dataset instruction instructions_portable jit_compiler_a64 randomx
     soft_aes superscalar virtual_machine vm_compiled vm_compiled_light
     vm_interpreted vm_interpreted_light"
C="argon2_core argon2_ref argon2_avx2 argon2_ssse3 reciprocal virtual_memory"

if [ "$(uname -m)" = "aarch64" ]; then
    MODE=native
    CXX="${CXX:-g++}"; CC="${CC:-gcc}"; RUN=""
    FLAGS="-O2 -DNDEBUG -march=armv8-a+crypto -I$SRC"
else
    MODE=cross
    if [ -n "$ARM_SYSROOT" ]; then
        B="$ARM_SYSROOT/usr/bin"
        CXX="$B/aarch64-linux-gnu-g++"; CC="$B/aarch64-linux-gnu-gcc"
        RUN="$B/qemu-aarch64-static"
        LD_LIBRARY_PATH="$ARM_SYSROOT/usr/lib/x86_64-linux-gnu"
        export LD_LIBRARY_PATH
        FLAGS="--sysroot=$ARM_SYSROOT -B$ARM_SYSROOT/usr/aarch64-linux-gnu/lib
               -L$ARM_SYSROOT/usr/aarch64-linux-gnu/lib
               -O2 -DNDEBUG -march=armv8-a+crypto -I$SRC"
    else
        CXX=aarch64-linux-gnu-g++; CC=aarch64-linux-gnu-gcc
        RUN=$(command -v qemu-aarch64-static || command -v qemu-aarch64)
        FLAGS="-O2 -DNDEBUG -march=armv8-a+crypto -I$SRC"
    fi
    command -v "$CXX" >/dev/null 2>&1 || [ -x "$CXX" ] || {
        echo "no aarch64 C++ compiler: set ARM_SYSROOT or install g++-aarch64-linux-gnu" >&2
        exit 2
    }
    [ -n "$RUN" ] || { echo "no qemu-aarch64: set ARM_SYSROOT or install qemu-user-static" >&2; exit 2; }
fi

echo "# mode=$MODE sweep=$N fast=${RX_FAST:-0}"

for f in $CPP; do $CXX $FLAGS -std=c++11 -c "$SRC/$f.cpp" -o "$OUT/$f.o"; done
for f in $C;   do $CC  $FLAGS            -c "$SRC/$f.c"   -o "$OUT/$f.o"; done
$CC  $FLAGS -c "$SRC/blake2/blake2b.c"          -o "$OUT/blake2b.o"
$CXX $FLAGS -c "$SRC/jit_compiler_a64_static.S" -o "$OUT/a64static.o"
$CXX $FLAGS -std=c++11 -static "$HERE/conformance.cpp" "$OUT"/*.o \
     -o "$OUT/conformance" -lpthread

exec $RUN "$OUT/conformance" "$N"
