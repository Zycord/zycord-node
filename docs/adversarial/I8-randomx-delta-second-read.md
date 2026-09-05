# Zycord — Adversarial Review: the rx/2 upstream delta, re-read against its own record

**Scope:** standing risk 1 of [randomx-v2](../decisions/randomx-v2.md) §8.6 — the
adversarial pass over the upstream JIT/assembly delta between RandomX **v1.2.3**
and **v2.0.1** that the two v1 passes do not cover. Risks 2 (arm64 silicon),
3 (a seed-epoch boundary on rx/2) and 4 (the first-production-user sentence in
the ANN) are explicitly **not** in scope here and are left open; the closing
section says why each.

**Persona:** the reader who does not accept that a risk is closed because a
document says so. [I8-randomx](I8-randomx.md) is a line-by-line read of the same
delta, and §8.9 records it as discharging this risk on the compiled surface. A
second reader adds nothing by agreeing; the only useful question is **which of
that record's load-bearing claims survive being re-derived independently, and
what does the tree fail to check that the record did not think to ask.**

**Verdict.** Every claim of I8-randomx that this pass re-derived **holds**. Three
of them were reproduced from scratch — by assembling the vendored assembly and
measuring label distances, and by two differential models built from the source
rather than from the record — and each model was mutation-checked so that
agreement is evidence rather than a tautology. **No new defect was found in the
vendored C++.**

**The finding is in the tree's own tests, not in upstream.** The single test
whose name promises the highest-value check in this whole area —
`TestJITAgreesWithInterpreter` — **does not run under rx/2**, which is the only
function either shipping network computes. It is not vacuous; it is
*mis-scoped*, and it is mis-scoped along exactly the axis the delta changed.
This was proven by mutation rather than by reading: a deliberate rx/2 code-generation
fault was planted in the x86 JIT and that test passed.

---

## What was actually done, and on what hardware

| | |
|---|---|
| Toolchain | gcc/g++ 13.3.0, Go 1.26.2, amd64 Linux |
| cgo engine | **built and run.** `CGO_ENABLED=1 go test -tags randomx ./core/pow/randomx/` compiles and passes |
| Vendored tree | verified byte-identical to `PINNED` by `TestVendoredTreeMatchesPinned` **after** all mutation work |
| arm64 | **not run.** No aarch64 hardware and no emulator run performed here |
| Benchmarks / soaks | **deliberately not run** — ~8 GiB machine; no timing in this document |

Three mutations were planted in `core/pow/randomx/upstream/jit_compiler_x86.cpp`
to measure what the test suite notices. **All were reverted**; the pinning guard
above is the evidence, and this branch's diff touches no code of any kind.

---

## D1 — `TestJITAgreesWithInterpreter` never runs under rx/2 ⚠️ **coverage gap on the shipping function**

**The claim in one sentence:** the tree's JIT-versus-interpreter equivalence
check — the classic RandomX consensus-split guard — is constructed with
`Options{Keys: 1, MaxVMs: 1}` and therefore exercises **rx/0 only**, while
mainnet and the public testnet both declare `randomx-v2`.

`core/pow/randomx/randomx_cgo_test.go:137-155`:

```go
jit := mustEngine(t, Options{Keys: 1, MaxVMs: 1})
ref := mustEngine(t, Options{Keys: 1, MaxVMs: 1, Interpreted: true})
```

Neither engine sets `V2: true`. Across the whole cgo test file, `V2: true`
appears in exactly **two** tests — `TestOfficialVectorsV2` and
`TestLightAndFastAgreeUnderV2`. `TestSoftAESAgreesWithHardAES`
(`randomx_cgo_test.go:225`) has the same gap for the same reason.

**Why this is not a pedantic point.** The delta's whole content is
version-conditional code generation. `RANDOMX_FLAG_V2` gates **six** distinct
sites in the x86 generator alone:

| `jit_compiler_x86.cpp` | what is generated differently |
|---|---|
| 322 | dataset-read block, **full-dataset (miner) path** |
| 334 | dataset-read block, light (verifier) path |
| 402, 403 | loop-store block, hard-AES arm |
| 421 | soft-AES LUT block appended |
| 866 | the CFROUND rounding-mode guard |

A test that never sets the flag reaches **none** of these six on the arm the
network takes. It is measuring the code path that no node runs.

**Measured, not argued.** Three mutations, each a plausible careless backport,
each rebuilt correctly (the shim was touched in the same edit — Go's build cache
does not see into `upstream/`, which the test file itself warns about at line 33):

| # | mutation | `TestJITAgreesWithInterpreter` | what did catch it |
|---|---|---|---|
| M1 | V2 CFROUND guard removed (`if (false)` at :866) | **PASSED** | `TestOfficialVectorsV2`, `TestLightAndFastAgreeUnderV2` |
| M2 | V2 CFROUND test mask `0x00078000` → `0x00070000` (one bit dropped) | **PASSED** | `TestOfficialVectorsV2`, `TestLightAndFastAgreeUnderV2` |
| M3 | **full-dataset path** forced to the v1 dataset-read block under V2 (:322) | **PASSED** | **`TestLightAndFastAgreeUnderV2` alone** |

`TestOfficialVectors` and `TestTheISUBREdgeCase` passed under all three, as they
should — they are rx/0 anchors.

**M3 is the one that matters and it is worth stating precisely.** It is a
miner-path-only rx/2 code-generation fault. Every published vector still passes,
because every vector test uses a **light** engine and the light path was left
untouched. `TestJITAgreesWithInterpreter` still passes, because it is rx/0.
**Exactly one test in the tree fails**, and it fails on a 4-input sweep:

```
--- PASS: TestOfficialVectorsV2
--- PASS: TestJITAgreesWithInterpreter
--- PASS: TestLightAndFastAgree
--- FAIL: TestLightAndFastAgreeUnderV2
```

So the entire defence of rx/2 miner-path code generation on amd64 rests on
`TestLightAndFastAgreeUnderV2` hashing four inputs.

**`TestLightAndFastAgreeUnderV2` is itself well-built, and that is not the
complaint.** It is non-vacuous in the strong sense CONTRIBUTING.md asks for: it
asserts `boundKey(fast)` really is the key under test, so both sides cannot
silently become the light path; it asserts both engines report `NameV2`; and it
re-checks the light result against upstream's published digest so "they agree"
cannot be satisfied by both being wrong together. The problem is **breadth, not
soundness** — four inputs against a defect class upstream's own v2.0 bug
reached at roughly one input in 2²⁸.

**This is a recurrence, not a new species.** [I7](I7.md) §I7-H1 records this same
test being *fully vacuous* once before, comparing the JIT against itself because
`Interpreted` was a no-op. That was fixed for the rx/0 axis. The rx/2 axis was
added to the engine afterwards and the cross-check was never extended to it —
the identical shape §8.5a of the decision record describes for
`TestLightAndFastAgree`, arriving through a third door.

**The asymmetry that makes this concrete.** The **arm64** conformance harness
`core/pow/randomx/arm64/conformance.cpp:193-229` *does* run a JIT-versus-interpreter
sweep under `RANDOMX_FLAG_V2`, under both AES arms, and its own header (line 29)
says why: *"reached by roughly one input in 268 million, so a sweep over varied
blobs"*. **The emulated architecture has coverage that the architecture mainnet
actually ships on does not.** Whatever the right depth is, amd64 currently has
less of it than arm64.

**No fix is made here.** This is an audit branch and the change is a test change
in the consensus zone; it is reported rather than applied. What would close it is
small and is stated in "What would close risk 1" below.

---

## D2 — I8-4's CFROUND agreement, re-derived independently ✅ *holds*

CFROUND is the delta's one genuinely new *consensus rule*, and it is the
dangerous kind: under rx/2 the rounding mode updates only when
`isrc & 60 == 0`, so whether the two implementations agree depends on **a value
in a register**, not on the program text. No fixed vector is guaranteed to
reach a disagreement.

I8-4 asserts the three implementations agree, on the strength of decoding the
x86 immediate as `60 << 13`. That decode was **not taken on trust**. The two
implementations were re-read from the vendored source —

- interpreter, `bytecode_machine.hpp:263`: `((flags & RANDOMX_FLAG_V2) == 0) || ((isrc & 60) == 0)`, over `isrc = rotr(*ibc.isrc, ibc.imm)`
- x86 JIT, `jit_compiler_x86.cpp:856-878`: `rol rax, (13 - (imm & 63)) & 63`, then `TEST_EAX_60SL13 = {0xa9,0x00,0x80,0x07,0x00}` — `test eax, 0x00078000` — then `jnz` over the `ldmxcsr` block

— and modelled against each other over **12,800,000 states** (all 64 values of
`imm & 63` × 200,000 `src` values each: every single-bit value, every
single-hole value, and an xorshift sweep).

```
checked=12800000 predicate mismatches=0 rounding-mode mismatches=0
```

Both the *update predicate* and the *resulting rounding mode* agree
(interpreter `isrc % 4` against the JIT's `(eax & 0x6000) >> 13`).

**The model is discriminating, which is what makes the zero worth anything.**
Three mutations of the model:

| mutation | mismatches |
|---|---|
| mask `0x00078000` → `0x0003C000` | 800,797 |
| rotate constant `13` → `12` | 799,832 predicate, 599,664 mode |
| interpreter constant `60` → `62` | 399,956 |

**I8-4 is confirmed.** The non-obvious part — that the JIT's `rol` by
`13 - imm` composes with a mask pre-shifted by 13 to test the same four bits of
`rotr(src, imm)` that the interpreter tests — is correct.

---

## D3 — I8-5's dataset-pointer agreement, re-derived independently ✅ *holds*

The interpreter's rx/2 change (`vm_interpreted.cpp:87-94`) captures the read
address from `ma` **before** XOR-ing `ma`, where v1 XORs `mx` after the swap.
The x86 assembly does the same thing with `rbp` packing both halves and
`ror rbp, 32` as the swap — different enough that agreement is worth
demonstrating.

Both were re-modelled from the two sources (`vm_interpreted.cpp` against
`asm/program_read_dataset.inc` and `asm/program_read_dataset_v2.inc`) over
**600,000 random `(ma, mx, r2, r3)` states, under v1 and v2**:

```
states=600000 v1 mismatches=0 v2 mismatches=0
```

Mutation-checked, and both plausible errors give a **100%** v2 mismatch rate
while v1 stays clean — the signature of a version-selective fault:

| mutation | v1 | v2 |
|---|---|---|
| take the v2 read address *after* the XOR | 0 | 600,000 |
| let v2 mutate `mx` as v1 does | 0 | 600,000 |

**I8-5 is confirmed**, independently of the record's own 600k run.

---

## D4 — I8-2's `codePos += readDatasetSize`, re-measured ✅ *correct today; the coincidence is real*

`jit_compiler_x86.cpp:321-328` copies one of two dataset-read blocks and then
advances the cursor by a constant naming only one of them:

```cpp
if (vmFlags & RANDOMX_FLAG_V2) {
    memcpy(code + codePos, codeReadDatasetV2, readDatasetV2Size);
} else {
    memcpy(code + codePos, codeReadDataset, readDatasetSize);
}
codePos += readDatasetSize;      // v1's size, on both branches
```

Both sizes are label distances, invisible as numbers in the source. The vendored
assembly was **assembled here** (`gcc -c -x assembler-with-cpp` on
`upstream/jit_compiler_x86_static.S`) and the symbol table read:

```
0x1fa  randomx_program_read_dataset
0x23c  randomx_program_read_dataset_v2
0x27e  randomx_program_read_dataset_sshash_init
0x2bd  randomx_program_read_dataset_sshash_init_v2
0x2fc  randomx_program_read_dataset_sshash_fin
```

`readDatasetSize = 0x23c - 0x1fa = 66`; `readDatasetV2Size = 0x27e - 0x23c = 66`.
**Equal, so the line is correct.** The light-path pair is 63 and 63, and the
light path uses `emit()` — which advances by the size it actually copied — so it
does not have this shape at all.

**The reason for the equality was checked at the source rather than inferred.**
`asm/program_read_dataset_v2.inc` is the same fifteen instructions as
`asm/program_read_dataset.inc` in a different order — v2 does
`xor rbp, rax` / `mov edx, ebp` / `ror rbp, 32` where v1 does
`ror rbp, 32` / `xor rbp, rax` / `mov edx, ebp` — and `mov`, `ror` and `xor`
on these operands have fixed encodings, so reordering cannot change the total
length.

**I8-2 is confirmed as written, including its characterisation as a latent
fragility rather than a defect.** It is correct by a coincidence that a future
upstream revision can withdraw without any test noticing — and note that the
site it would break is `generateProgram`, **the miner path**, whose only guard is
the four-input test D1 identifies.

---

## D5 — What this pass did **not** re-derive, listed so the coverage is not overstated

A second read is only worth reading if it says where it stopped.

- **I8-1 (the `RandomXCodeSize` bound) was not re-measured.** The worst-case
  `codePos` figures — 13,442 and 13,495 against 16,384 — were taken from
  I8-randomx and not independently reproduced. What *was* done is confirming
  that `TestTheJITCodeBufferIsSizedForTheLargerV2Program` passes on the restored
  tree, which pins the five declarations but is a source check, not a run of the
  generator. **The bound itself remains single-sourced.**
- **I8-3, I8-6, I8-7, I8-8, I8-10 were not re-derived.** They were read for
  internal consistency against the vendored source and nothing contradicted
  them; that is weaker than the treatment D2–D4 got and is not claimed as more.
- **No arm64 work of any kind.** I8-7's `clear_cache` reasoning from label
  offsets was not re-checked, and no emulator was run.
- **The RISC-V half of the delta (~2,450 lines) was not read**, for the reason
  I8-randomx gives: `vendor.sh` compiles none of it. That remains true and
  remains an exposure if a RISC-V build is ever shipped.
- **`jit_compiler_x86_static.asm` (MASM) was not read.** The GNU `.S` is what
  builds here.
- **The 1-in-2²⁸ class is not excluded**, and nothing in this pass could exclude
  it. Reading finds defects that are wrong on their face. D1's whole point is
  that the tree's *volume* defence against that class is thinner on amd64 than
  the record implies, not that this pass supplied any.

---

## Status

| | finding | severity | state |
|---|---|---|---|
| D1 | `TestJITAgreesWithInterpreter` and `TestSoftAESAgreesWithHardAES` never set `V2`; rx/2 miner-path codegen on amd64 is guarded by one 4-input test | **medium — coverage, not a defect** | reported, not fixed |
| D2 | CFROUND agreement, 12.8M states, mutation-checked | consensus-critical | **I8-4 confirmed** |
| D3 | dataset-pointer agreement, 600k states, mutation-checked | consensus-critical | **I8-5 confirmed** |
| D4 | `codePos += readDatasetSize`, label distances measured (66 = 66) | latent fragility | **I8-2 confirmed** |
| D5 | what was not re-derived | — | stated above |

**No consensus defect was found, and no change to consensus code or to the
vendored C++ is proposed by this document.**

---

## What would close risk 1

D1 is the only actionable item and the fix is small:

1. **Run the JIT-versus-interpreter cross-check under rx/2.** Either add
   `V2: true` engines to `TestJITAgreesWithInterpreter` or add a sibling in the
   shape `TestLightAndFastAgreeUnderV2` already sets — the latter matches the
   file's existing convention of naming the version in the test so a failure
   says which function broke. The same applies to `TestSoftAESAgreesWithHardAES`.
2. **Cover the miner path in that sweep, not only the light path.** M3 is
   invisible to every light-mode check, and the miner path is where
   `generateProgram` and D4's fragile line live. That means a `fastEngine` with
   `MineOn` bound, as `TestLightAndFastAgreeUnderV2` already does.
3. **Widen the sweep.** Four inputs is the current depth on the only test that
   catches M3; the arm64 harness runs hundreds and its header explains why.
   Depth here is cheap relative to what it guards.

Each of those must be shown to fail under M1–M3 before being trusted; the three
mutations are recorded above precisely so the next person does not have to
rediscover them.

**Risk 1 should not be ticked on the strength of this document alone.** What this
pass establishes is that I8-randomx's substantive claims about the *upstream
code* survive independent re-derivation. What it also establishes is that the
*tree's own guard* against the failure mode those claims are about is aimed at
the wrong version on amd64 — and that was not visible from reading either record.

---

## The other three standing risks — all still open

Recorded here only so that this document cannot be misread as closing them.

- **Risk 2 — arm64 on real silicon. OPEN.** Untouched by this pass: no aarch64
  hardware is available here, and emulation was not run either. §8.8's position
  stands unchanged — the emulator covers code generation, not a real core's
  instruction-cache coherency around self-modifying code, which is where a JIT
  is most exposed. Note D1 in passing: the emulated harness is currently the
  *stronger* of the two on the rx/2 cross-check axis.
- **Risk 3 — a seed-epoch boundary on rx/2. OPEN as an operator action.** The
  localnet recipe exists (`make localnet`, and the amd64 run recorded at
  `docs/localnet/soaks/rx2-epoch-boundary.txt`); running one is an operator
  action and was deliberately not performed on this machine, which has neither
  the memory budget for a mining soak nor any business starting a node.
- **Risk 4 — the first-production-user sentence in the ANN. OPEN.** It belongs
  to the announcement, which is a different issue, and no wording is proposed
  here.
