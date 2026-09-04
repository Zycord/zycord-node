// An aarch64 conformance harness for the vendored RandomX, and the thing it
// exists to answer: does THIS tree's engine compute rx/2 correctly on the
// architecture where v2.0's ~1-in-2^28 invalid-hash bug lived?
//
// It is C++ rather than Go, and a separate program rather than a test, for one
// reason: cgo cannot cross-compile without a cross toolchain, so the Go test
// suite cannot reach aarch64 on an amd64 machine at all. This harness links the
// same vendored sources the cgo build links, cross-compiled for aarch64, and
// runs under qemu-user. run.sh is the recipe and needs no root.
//
// What it checks, and why each item is here rather than assumed:
//
//   - upstream's OWN published vectors (src/tests/tests.cpp at the tag PINNED
//     names) under rx/0 and rx/2, on the interpreter AND on the a64 JIT, and
//     under THREE flag configurations: soft AES, hard AES, and hard AES with
//     RANDOMX_FLAG_SECURE. A build where the V2 flag did nothing reproduces the
//     rx/0 column and fails the rx/2 one.
//
//     The AES axis is not a performance sweep. jit_compiler_a64.cpp branches on
//     RANDOMX_FLAG_HARD_AES at the "Enable RandomX v2 AES tweak" site in BOTH
//     generators, emitting a different instruction at the same patch address,
//     inside the rx/2 delta; and randomx.cpp's create_vm switch keys on it, so
//     without it only the ...Default VM classes are ever built. A run that left
//     it clear would exercise exactly the branch a real arm64 miner does not
//     take, since every ARMv8 core with the crypto extensions reports hard AES.
//     SECURE is here for the third VM class, which takes the W^X path;
//   - upstream's Commitment test, which is the value this chain's consensus
//     rule compares against the target;
//   - a JIT-versus-interpreter sweep on rx/2, under soft AES and hard AES. The
//     vectors reach the inputs the vectors reach; the bug v2.0.1 fixed was
//     reached by roughly one input in 268 million, so a sweep over varied blobs
//     is what puts pressure on the code generator rather than on four fixed
//     programs;
//   - the FULL-DATASET path, under RX_FAST=1. This is not decoration. The
//     vectors above run LIGHT, which on aarch64 reaches the
//     `*_vm_instructions_end_light_v2` tweak; a mining node runs the dataset
//     path, which reaches a DIFFERENT one (`*_vm_instructions_end_v2`).
//     Measured: swapping the dataset path's v2 tweak for the v1 one is
//     invisible to a light-only run and is caught here. It runs all four cells
//     of {rx/0, rx/2} x {soft, hard AES} and needs ~2.1 GiB.
//
// Every vector below is upstream's own published output. Nothing here compares
// this implementation against itself.

#include "randomx.h"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <string>

static std::string hex(const unsigned char* p, int n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < n; i++) { s += d[p[i] >> 4]; s += d[p[i] & 15]; }
    return s;
}

struct Vec { const char* key; const char* input; const char* want; };

// rx/0 — tests.cpp test_a..test_d
static Vec v1vec[] = {
 {"test key 000","This is a test","639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"},
 {"test key 000","Lorem ipsum dolor sit amet","300a0adb47603dedb42228ccb2b211104f4da45af709cd7547cd049e9489c969"},
 {"test key 000","sed do eiusmod tempor incididunt ut labore et dolore magna aliqua","c36d4ed4191e617309867ed66a443be4075014e2b061bcdaf9ce7b721d2b77a8"},
 {"test key 001","sed do eiusmod tempor incididunt ut labore et dolore magna aliqua","e9ff4503201c0c2cca26d285c93ae883f9b1d30c9eb240b820756f2d5a7905fc"},
};
// rx/2 — the same four under RANDOMX_FLAG_V2
static Vec v2vec[] = {
 {"test key 000","This is a test","22ec6b861b3eb23686b2efbad69513c967ecfce80983df66c9c5b4fbfb4cdb6f"},
 {"test key 000","Lorem ipsum dolor sit amet","9e2c772c12fd48f93c14c97fdc89d556264d9100597023f44d9163e279012ecf"},
 {"test key 000","sed do eiusmod tempor incididunt ut labore et dolore magna aliqua","4d6b063a1a603751d525f18a171336a4002f2f06df6c17e4b25fe17e17796e42"},
 {"test key 001","sed do eiusmod tempor incididunt ut labore et dolore magna aliqua","97024134686ce27d362ea8d86d8ef16483ac272abdabd46ef13359400777fe5e"},
};

static int failures = 0;
static int checks = 0;

static void hashWith(randomx_flags fl, const char* key, const void* in, size_t inlen, unsigned char* out) {
    randomx_cache* c = randomx_alloc_cache(fl);
    if (!c) { printf("FATAL alloc_cache\n"); exit(2); }
    randomx_init_cache(c, key, strlen(key));
    randomx_vm* vm = randomx_create_vm(fl, c, nullptr);
    if (!vm) { printf("FATAL create_vm\n"); exit(2); }
    randomx_calculate_hash(vm, in, inlen, out);
    randomx_destroy_vm(vm);
    randomx_release_cache(c);
}

static void run(const char* label, randomx_flags fl, Vec* vs, int n) {
    for (int i = 0; i < n; i++) {
        unsigned char out[RANDOMX_HASH_SIZE];
        hashWith(fl, vs[i].key, vs[i].input, strlen(vs[i].input), out);
        std::string got = hex(out, RANDOMX_HASH_SIZE);
        checks++;
        if (got != vs[i].want) {
            failures++;
            printf("FAIL %s [%d]\n  got  %s\n  want %s\n", label, i, got.c_str(), vs[i].want);
        } else {
            printf("ok   %s [%d] %s\n", label, i, got.c_str());
        }
    }
}

int main(int argc, char** argv) {
    printf("# arch: aarch64 (qemu-user)\n");

    // The matrix, and the reason it is a matrix rather than one column.
    //
    // RANDOMX_FLAG_HARD_AES is not a performance switch on aarch64: at
    // jit_compiler_a64.cpp's two "Enable RandomX v2 AES tweak" sites -- one in
    // the light generator, one in the dataset generator -- it decides WHICH
    // INSTRUCTION is emitted at the same patch address, `movi v28.4s, 0` under
    // hard AES against a branch into the soft-AES FE mix without it. Both are
    // inside the rx/2 delta. And randomx.cpp's create_vm switch keys on the
    // same flag, so without it only the `...Default` VM classes are ever
    // instantiated and `...HardAes` never is.
    //
    // A run that leaves it clear therefore exercises exactly one branch of the
    // newest arm64 code, and it is the branch a real arm64 miner does NOT
    // take: every ARMv8 core with the crypto extensions reports hard AES and
    // randomx_get_flags sets it. RANDOMX_FLAG_SECURE is here for the third VM
    // class, which takes the W^X path through the JIT buffer.
    struct Cfg { const char* name; randomx_flags extra; };
    const Cfg cfgs[] = {
        {"soft-aes",        RANDOMX_FLAG_DEFAULT},
        {"hard-aes",        RANDOMX_FLAG_HARD_AES},
        {"hard-aes+secure", (randomx_flags)(RANDOMX_FLAG_HARD_AES | RANDOMX_FLAG_SECURE)},
    };

    for (const Cfg& c : cfgs) {
        randomx_flags base = c.extra;
        randomx_flags jit  = (randomx_flags)(c.extra | RANDOMX_FLAG_JIT);
        randomx_flags v2f  = (randomx_flags)(c.extra | RANDOMX_FLAG_V2);
        randomx_flags jv2  = (randomx_flags)(c.extra | RANDOMX_FLAG_JIT | RANDOMX_FLAG_V2);

        // SECURE only changes the JIT's page permissions, so the interpreter
        // rows under it would repeat the row above and are skipped.
        bool secure = (c.extra & RANDOMX_FLAG_SECURE) != 0;

        printf("\n## %s, interpreter\n", c.name);
        if (secure) {
            printf("skip interpreter under SECURE: the flag only changes JIT page "
                   "permissions, so this would repeat the row above\n");
        } else {
            char l0[64], l2[64];
            snprintf(l0, sizeof(l0), "rx/0 interp %s", c.name);
            snprintf(l2, sizeof(l2), "rx/2 interp %s", c.name);
            run(l0, base, v1vec, 4);
            run(l2, v2f,  v2vec, 4);
        }

        printf("\n## %s, a64 JIT\n", c.name);
        {
            char l0[64], l2[64];
            snprintf(l0, sizeof(l0), "rx/0 jit %s", c.name);
            snprintf(l2, sizeof(l2), "rx/2 jit %s", c.name);
            run(l0, jit, v1vec, 4);
            run(l2, jv2, v2vec, 4);
        }

        // Upstream's Commitment test — tests.cpp at v2.0.1 — INSIDE this loop,
        // so the value the consensus rule compares is checked under the same
        // configuration as the digests above it rather than under whichever
        // flags happened to be in scope. It sat outside for one revision and
        // the record claimed it as hard-AES coverage when it had only ever run
        // soft; the fix is to run it, not to reword the claim.
        //
        // The commitment itself is BLAKE2b over the blob and the digest and
        // touches no AES, so what varies across configurations is the digest
        // it is taken over, not the function taking it.
        printf("\n## %s, commitment vector\n", c.name);
        {
            const char* key = "test key 000";
            const char* in  = "This is a test";
            const char* want = "133be717399046b03ae82ce8ddd9d1ee4d3ea7fca03a50dec09b6848cbb98e18";
            for (int pass = 0; pass < 2; pass++) {
                if (pass == 0 && secure) continue; // interpreter: see the skip above
                randomx_flags fl = pass ? jv2 : v2f;
                unsigned char h[RANDOMX_HASH_SIZE], comm[RANDOMX_HASH_SIZE];
                hashWith(fl, key, in, strlen(in), h);
                randomx_calculate_commitment(in, strlen(in), h, comm);
                std::string got = hex(comm, RANDOMX_HASH_SIZE);
                checks++;
                if (got != want) { failures++;
                    printf("FAIL commitment %s (%s)\n  got  %s\n  want %s\n",
                           c.name, pass?"jit":"interp", got.c_str(), want); }
                else printf("ok   commitment %s (%s) %s\n",
                            c.name, pass?"jit":"interp", got.c_str());
            }
        }
    }

    // JIT vs interpreter sweep on rx/2 — the class of bug that lived on arm64.
    // The sweep, under hard AES as well as soft. The interpreter has no
    // hard-AES code path of its own -- softAes is a template parameter and the
    // interpreted classes are chosen by the same switch -- so this compares the
    // hard-AES JIT against the interpreter, which is the comparison that
    // catches a code generator wrong on inputs the four vectors do not reach.
    for (int aes = 0; aes < 2; aes++) {
        randomx_flags ax = aes ? RANDOMX_FLAG_HARD_AES : RANDOMX_FLAG_DEFAULT;
        randomx_flags v2f = (randomx_flags)(ax | RANDOMX_FLAG_V2);
        randomx_flags jv2 = (randomx_flags)(ax | RANDOMX_FLAG_JIT | RANDOMX_FLAG_V2);
        printf("\n## a64 JIT vs interpreter sweep, rx/2, %s\n",
               aes ? "hard-aes" : "soft-aes");
        const char* key = "zycord sweep key";
        randomx_cache* ci = randomx_alloc_cache(v2f);
        randomx_cache* cj = randomx_alloc_cache(jv2);
        randomx_init_cache(ci, key, strlen(key));
        randomx_init_cache(cj, key, strlen(key));
        randomx_vm* vi = randomx_create_vm(v2f, ci, nullptr);
        randomx_vm* vj = randomx_create_vm(jv2, cj, nullptr);
        int n = argc > 1 ? atoi(argv[1]) : 64;
        int mism = 0;
        for (int i = 0; i < n; i++) {
            unsigned char blob[43];
            for (int k = 0; k < 43; k++) blob[k] = (unsigned char)((i * 131 + k * 17 + (k*k)) & 0xff);
            blob[39] = (unsigned char)(i & 0xff);
            blob[40] = (unsigned char)((i >> 8) & 0xff);
            blob[41] = 0; blob[42] = 0;
            unsigned char a[RANDOMX_HASH_SIZE], b[RANDOMX_HASH_SIZE];
            randomx_calculate_hash(vi, blob, sizeof(blob), a);
            randomx_calculate_hash(vj, blob, sizeof(blob), b);
            checks++;
            if (memcmp(a, b, RANDOMX_HASH_SIZE) != 0) {
                mism++; failures++;
                printf("FAIL sweep[%d]\n  interp %s\n  jit    %s\n", i, hex(a,32).c_str(), hex(b,32).c_str());
            }
        }
        printf("%s sweep: %d inputs, %d mismatches\n", mism ? "FAIL" : "ok  ", n, mism);
        randomx_destroy_vm(vi); randomx_destroy_vm(vj);
        randomx_release_cache(ci); randomx_release_cache(cj);
    }

    // Full-dataset (fast) mode. The vectors above run LIGHT, which on a64
    // reaches the *_light_v2 tweak; the dataset path reaches a different one
    // (*_vm_instructions_end_v2), so a light-only run leaves that codegen
    // untested. This section is what covers it. Miners run this path.
    if (getenv("RX_FAST")) {
        printf("\n## full-dataset (fast) mode, a64 JIT\n");
        // Four passes: {rx/0, rx/2} x {soft AES, hard AES}. Hard AES is the
        // configuration a real arm64 miner runs, and the dataset generator has
        // its own copy of the AES tweak, so this is the cell that matters most
        // and it is the last one to have had no coverage at all.
        for (int pass = 0; pass < 4; pass++) {
            bool v2 = (pass & 1) != 0;
            bool hard = (pass & 2) != 0;
            randomx_flags ax = hard ? RANDOMX_FLAG_HARD_AES : RANDOMX_FLAG_DEFAULT;
            randomx_flags fl = (randomx_flags)(ax | RANDOMX_FLAG_JIT |
                                               RANDOMX_FLAG_FULL_MEM | (v2 ? RANDOMX_FLAG_V2 : 0));
            randomx_flags cf = (randomx_flags)(ax | RANDOMX_FLAG_JIT |
                                               (v2 ? RANDOMX_FLAG_V2 : 0));
            Vec* vs = v2 ? v2vec : v1vec;
            randomx_cache* c = randomx_alloc_cache(cf);
            randomx_init_cache(c, vs[0].key, strlen(vs[0].key));
            randomx_dataset* ds = randomx_alloc_dataset(fl);
            if (!ds) { printf("SKIP fast mode: dataset alloc failed (needs ~2.1 GiB)\n"); randomx_release_cache(c); break; }
            randomx_init_dataset(ds, c, 0, randomx_dataset_item_count());
            randomx_vm* vm = randomx_create_vm(fl, nullptr, ds);
            for (int i = 0; i < 3; i++) {
                if (strcmp(vs[i].key, vs[0].key) != 0) continue;
                unsigned char out[RANDOMX_HASH_SIZE];
                randomx_calculate_hash(vm, vs[i].input, strlen(vs[i].input), out);
                std::string got = hex(out, RANDOMX_HASH_SIZE);
                checks++;
                if (got != vs[i].want) { failures++;
                    printf("FAIL %s fast %s [%d]\n  got  %s\n  want %s\n",
                           v2?"rx/2":"rx/0", hard?"hard-aes":"soft-aes", i, got.c_str(), vs[i].want); }
                else printf("ok   %s fast %s [%d] %s\n",
                            v2?"rx/2":"rx/0", hard?"hard-aes":"soft-aes", i, got.c_str());
            }
            randomx_destroy_vm(vm);
            randomx_release_dataset(ds);
            randomx_release_cache(c);
        }
    }

    printf("\n# checks=%d failures=%d\n", checks, failures);
    printf(failures ? "# RESULT: FAIL\n" : "# RESULT: PASS\n");
    return failures ? 1 : 0;
}
