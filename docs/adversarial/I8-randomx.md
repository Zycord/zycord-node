# Zycord — Implementation Findings I8: the rx/2 delta, read

**Scope:** the ~800-line upstream delta between RandomX v1.2.3 and v2.0.1, read line by line; the cgo binding around it; the pinning pipeline; and the engine's behaviour on attacker-supplied input.

**Persona:** the reader. [randomx-v2](../decisions/randomx-v2.md) §8.6 named four gaps and §8.8 closed three of them by *pressure from outside* — differential vectors, mutation, an emulated arm64 run. It was explicit that the fourth was untouched: **"This pass was differential and mutation-driven: it puts pressure on the code generators from outside rather than reading them."** This pass is the read. It exists because rx/2 has no other production user — Monero has neither activated nor vendored it — so no one else's traffic has found these bugs for us.

**The headline, stated first because it is the question the freeze turns on: no memory-unsafety, no unbounded loop, and no division by zero was found anywhere reachable from a peer's block.** The verifier's path was the first thing read and the most heavily checked. What the read did find is one line whose correctness rests on a coincidence, and several places where the delta is safe for reasons that are not written down. Those are recorded below with the evidence that settles them.

---

## What was actually read, and what was not

The "~800 lines" of §4 is a real number for the wrong denominator. The full `v1.2.3..v2.0.1` diff over `src/` minus `tests/` is **4,428 insertions across 65 files**. Most of it is RISC-V:

| | files | +/− | compiled here? |
|---|---|---|---|
| RISC-V (`*rv64*`, `cpu_rv64.S`) | 10 | ~2,450 / ~100 | **no** — not in `vendor.sh`'s source lists |
| `jit_compiler_x86_static.asm` (MASM) | 1 | 44 / 0 | **no** — the `.S` is used, not the `.asm` |
| **compiled `.cpp` / `.c` / `.S`** | **14** | **844 / 136** | **yes** |
| **headers reached by those** | **18** | **~190 / ~40** | **yes** |

So the reviewable surface is **~1,650 changed lines across 32 files**, and §4's "~800 lines concentrated in two JIT generators and hand-written assembly" describes the compiled half accurately. **All 32 were read.** The RISC-V files were not read line by line, and the justification is mechanical rather than a judgement call: they appear in no `vendor.sh` source list, so cgo never hands them to a compiler. `aes_hash.cpp`'s 58 added lines are likewise entirely inside `#ifdef __riscv` and are dead on both architectures this chain ships.

Two files carry most of the risk and got most of the time: `jit_compiler_x86.cpp` (+134/−34) and `jit_compiler_a64.cpp` (+95/−9), plus their static assembly (+36 and +338).

---

## I8-1 — The one line that stands between rx/2 and a heap overflow ✅ *upstream is correct; now pinned by a test*

**This is the most important thing in the delta and it is a single expression.**

rx/2 raises the program length from 256 instructions to 384. Upstream did this by making the length a *runtime* function of a flag — `Program::getSize(flags)` returns `RANDOMX_PROGRAM_SIZE_V2` or `..._V1` — while every buffer the program is written into stays a *compile-time* array. That is the correct design, and it is only safe if every one of those arrays is sized by the maximum rather than by a version:

- `Program::programBuffer[RANDOMX_PROGRAM_MAX_SIZE]` (`program.hpp`)
- `InterpretedVm::bytecode[RANDOMX_PROGRAM_MAX_SIZE]` (`vm_interpreted.hpp`)
- `CompilerState::instructionOffsets[RANDOMX_PROGRAM_MAX_SIZE]` (`jit_compiler.hpp`)
- `RandomXCodeSize = alignSize(ReserveCodeSize + MaxRandomXInstrCodeSize * RANDOMX_PROGRAM_MAX_SIZE, CodeAlign)` (`jit_compiler_x86.cpp:133`)

Upstream widened all four. **The last one is the one with no guard rail at all**: the x86 JIT's `emitByte`/`emit32`/`emit64`/`emit` are four one-line `memcpy`s into `code + codePos` with **no bounds check of any kind**, so nothing but that arithmetic prevents the generator writing past the allocation.

*One precision, because the list above is easy to over-read.* The x86 generator does **not** use `CompilerState::instructionOffsets`; it keeps its own `std::vector<int32_t>`, which grows on `push_back` and cannot overflow. That array belongs to the shared `CompilerState` the RV64 compiler builds on. It is in the list and in the test because it is real code sized by `MAX_SIZE` and a regression there would matter to any build that uses it — not because the x86 path depends on it. **On the x86 path the whole of the protection is `RandomXCodeSize`.**

**Measured rather than argued.** A harness built against the vendored sources compiles programs and reports the maximum `codePos` reached:

| run | max `codePos` | bound | headroom |
|---|---|---|---|
| 20,000 random rx/2 programs, full path | 5,810 | 16,384 | 10,574 |
| **all 256 opcodes × 256 `mod` values, 384 instructions each, full path** | **13,442** | 16,384 | 2,942 |
| **the same sweep, light path** (the verifier's) | **13,495** | 16,384 | 2,889 |

The sweep is exhaustive over the opcode byte rather than random, so the 13,442 is a **bound and not a sample**.

**The mutation is what makes this worth writing down.** Recomputing `RandomXCodeSize` from `RANDOMX_PROGRAM_SIZE_V1` — one identifier, exactly the edit a careless backport would make — gives a 12,288-byte buffer, and the same worst-case program **overflows it by 1,154 bytes**, into the superscalar-hash region that `superScalarHashOffset` places immediately after. That would be a heap overflow on *every hash*, on miner and verifier alike.

**Now pinned.** `TestTheJITCodeBufferIsSizedForTheLargerV2Program` in `pinned_test.go` checks all four declarations and the `MAX ≥ V1, V2` relation. It reads the vendored source rather than running the JIT, deliberately: it needs no C toolchain and no amd64, so it runs in the same ordinary `go test ./...` that `TestVendoredTreeMatchesPinned` runs in. All four properties were mutated individually and **all four mutations kill it**.

---

## I8-2 — `codePos += readDatasetSize` after copying `readDatasetV2Size` bytes ⚠️ *correct today, by coincidence*

`JitCompilerX86::generateProgram` picks one of two dataset-read blocks and then advances the write cursor by a constant that names only one of them:

```cpp
if (vmFlags & RANDOMX_FLAG_V2) {
    memcpy(code + codePos, codeReadDatasetV2, readDatasetV2Size);
} else {
    memcpy(code + codePos, codeReadDataset, readDatasetSize);
}
codePos += readDatasetSize;      // <- v1's size, on both branches
```

Both sizes are label distances in the hand-written assembly, so neither is visible as a number in the source. Assembling `jit_compiler_x86_static.S` and reading the symbol table settles it:

```
randomx_program_read_dataset            0x1fa
randomx_program_read_dataset_v2         0x23c   ->  readDatasetSize   = 66
randomx_program_read_dataset_sshash_init 0x27e  ->  readDatasetV2Size = 66
```

**They are equal, so the line is correct.** They are equal because `program_read_dataset_v2.inc` is the same seven instructions as `program_read_dataset.inc` in a different order — v2 modifies `ma` before the swap where v1 modifies `mx` after it — and reordering identical instructions does not change their encoded length.

This is a latent fragility rather than a defect, and it is recorded because the cost of it going wrong is asymmetric. If a future upstream revision adds one instruction to the v2 block, this line under-advances `codePos`, and the *next* `emit` overwrites the tail of the dataset read with the program epilogue — producing a JIT that computes a wrong hash on the mining path only, on a build where every published vector still passes because the light path uses `emit()` (which advances by the size it actually copied) and is unaffected. The light path at `generateProgramLight` has the same two-branch shape and does **not** have this problem, for exactly that reason.

**No action taken.** Patching it would mean editing the vendored tree, which `vendor.sh`'s own header forbids for good reasons. It is written here so that the next person to bump the tag knows to re-measure those two labels.

---

## I8-3 — `randomx_init_dataset`'s new four-item alignment, and why the Go caller never reaches its stack buffer ✅ *safe as called*

rx/2 rewrote `randomx_init_dataset` to fill items in groups of four, adding two branches that did not exist in v1.2.3. One of them writes through a **stack buffer**:

```cpp
if (itemCount < 4) {
    uint8_t buf[randomx::CacheLineSize * 4];
    cache->datasetInit(cache, buf, startItem, startItem + 4);
    memcpy(dataset->memory + startItem * CacheLineSize, buf, itemCount * CacheLineSize);
}
```

`datasetInit` is JIT-generated code writing 4 × 64 bytes into a 256-byte stack array — exactly fitting, with no margin, and reached whenever a caller asks for one, two or three items.

**This build never reaches it, and the reason is arithmetic rather than luck.** `DatasetItemCount` is 34,078,719, which is **≡ 3 (mod 4)**. `initDataset` in `randomx_cgo.go` splits that into `workers` spans of `n/workers` (+1 for the first `n%workers`). Enumerating every worker count from 1 to 64: **no span is ever smaller than 4**, so the stack-buffer branch is unreachable from this binding. The unaligned `else` branch is the one that fires, on essentially every configuration.

That branch re-initialises an overlapping four-item tail:

```cpp
cache->datasetInit(cache, ..., startItem, startItem + itemCount - (itemCount % 4));
startItem += itemCount - 4;
cache->datasetInit(cache, ..., startItem, startItem + 4);
```

**The overlap is real and it is within one span, never across two.** Checked by enumeration over worker counts 1–64: the MAIN and TAIL writes of a single worker overlap by up to three items, and those two calls are sequential on the same goroutine; **cross-worker overlaps: zero**, and the union of all spans covers `[0, DatasetItemCount)` exactly. Since `initDatasetItem` is a pure function of `(cache, itemNumber)`, rewriting an item with the same bytes is harmless. So the concurrency contract `initDataset`'s comment relies on — "disjoint item ranges are safe to call concurrently" — still holds under v2's new branching, which is not obvious from reading either side alone.

---

## I8-4 — CFROUND, the one new consensus rule, agrees in all three implementations ✅ *checked by decoding*

rx/2's other semantic change is a guard on `CFROUND`, which sets the FPU rounding mode. Under v2 the rounding mode is updated **only when `isrc & 60 == 0`**. A disagreement here between the interpreter and either JIT is a consensus split that no vector need catch, because it depends on the value in a register rather than on the program text.

Three independent implementations, decoded rather than eyeballed:

| | expression | check |
|---|---|---|
| interpreter (`bytecode_machine.hpp`) | `((flags & V2) == 0) \|\| ((isrc & 60) == 0)` | literal `60` |
| x86 JIT (`h_CFROUND`) | `test eax, {0xa9,0x00,0x80,0x07,0x00}` after `rol rax, 13` | imm32 = `0x78000` = **60 << 13**, and the compensating `rol 13` puts `isrc` bits 2–5 at bits 15–18 → **tests the same four bits** |
| a64 JIT (`h_CFROUND`) | `emit32(0xF27E0E9F)` | decoded as AArch64 logical-immediate `N=1, immr=62, imms=3` → **`tst tmp, #60`** |

All three test bits 2–5 of `rotr(src, imm)`, and all three are gated on `RANDOMX_FLAG_V2`. The x86 one is the interesting case: the `60 << 13` is not a typo but the consequence of the JIT rotating left by 13 instead of right by `imm`, and it took decoding the immediate to see that it agrees.

---

## I8-5 — The interpreter and the x86 assembly agree on rx/2's dataset-pointer change ✅ *differentially modelled, mutation-checked*

The change with the widest blast radius in the interpreter is four lines:

```cpp
const uint64_t readPtr = datasetOffset + (mem.ma & CacheLineAlignMask);
auto& mp = (getFlags() & RANDOMX_FLAG_V2) ? mem.ma : mem.mx;
mp ^= nreg.r[config.readReg2] ^ nreg.r[config.readReg3];
datasetPrefetch(datasetOffset + (mp & CacheLineAlignMask));
```

Under v1 the XOR modifies `mx` *after* the swap; under v2 it modifies `ma` *before* it, and the read address is captured from `ma` **before** the XOR. The JIT does the same thing in assembly with `rbp` holding both halves and `ror rbp, 32` for the swap — different enough that agreement is worth demonstrating rather than assuming.

Both were modelled and compared over **600,000 random `(ma, mx, r2, r3)` states, under v1 and v2**: read address and prefetch address agree in **every** case, 0 mismatches. Two plausible ways to get it wrong — taking the read address *after* the XOR, and letting v2 mutate `mx` as v1 does — each produce a **100% mismatch rate**, so the model is discriminating rather than trivially true.

**Bounds, which is the part that matters for a peer's block.** `CacheLineAlignMask` is `0x7fffffc0`, so the largest read is at `datasetOffset + 0x7fffffc0`, plus 64 bytes for the cache line, plus the largest `datasetOffset` (`DatasetExtraItems * 64` = 33,554,368) — **2,181,038,016 bytes, exactly `DatasetSize`.** The masked read is in bounds by construction, with zero slack, under both versions.

**And in light mode — the verifier's mode — the question does not arise at all.** `InterpretedLightVm::datasetRead` overrides the full-memory one and never indexes `mem.memory`; it recomputes the item into a local `int_reg_t rl[8]` via `initDatasetItem`. A peer-supplied header cannot steer a read off the end of anything, because in light mode there is no buffer being indexed.

---

## I8-6 — The remotely-triggerable path, end to end ✅ *no unsafety found*

This is the item the brief ranked highest, so the path is written out rather than summarised. A peer's block reaches `randomx_calculate_hash` through `Engine.Hash`:

- **The cgo boundary passes no Go pointer into C that outlives the call.** `input` is passed as `unsafe.Pointer(&input[0])` guarded by `if len(input) > 0` — so a zero-length attacker-supplied field yields a `nil` pointer rather than a panic on `&input[0]` — with `runtime.KeepAlive(input)` after. `out` is a `types.Hash`, a fixed 32-byte array, and `RANDOMX_HASH_SIZE` is 32. The key goes through `C.CBytes` with a matching `defer C.free`: a copy into C memory, not a Go pointer.
- **`randomx_calculate_hash` consumes the input exactly once**, as `blake2b(tempHash, 64, input, inputSize, nullptr, 0)`. Everything after that runs on the 64-byte `tempHash`, so no attacker-controlled length reaches the VM at all. There is no path by which `inputSize` can cause an over-read.
- **The loop is `for (chain = 0; chain < RANDOMX_PROGRAM_COUNT - 1; ...)`** — a compile-time constant, 7. Nothing a peer sends changes the iteration count. There is no unbounded loop in this path.
- **No division occurs on attacker-controlled data outside the VM's own instruction semantics**, where `IDIV`-class operations are already reciprocal-based and zero-guarded upstream (unchanged by the delta).
- **FP state is saved and restored** around the call (`fegetenv`/`fesetenv`), which matters more under v2 than v1 precisely because CFROUND's behaviour changed.

The one thing worth flagging as *not proven*: `runtime.KeepAlive(out)` is absent at both call sites. It is safe here because `out` is a local whose address is taken and which is returned by value, so it is live across the call by Go's own rules — but it is safe by escape analysis rather than by statement.

---

## I8-7 — arm64 cache maintenance around the v2 patches ✅ *complete for instructions*; ⚠️ *one data write sits outside the range*

The a64 generator patches its template in place and then calls `__builtin___clear_cache(code + MainLoopBegin, code + codePos)`. Because `codePos` is repeatedly *repositioned* to label offsets rather than advanced monotonically, whether a given patch is inside that range is not visible from the source. Cross-assembling `jit_compiler_a64_static.S` for aarch64 and reading the symbol table answers it:

**Light path (the verifier's).** The last write is `light_dataset_offset`, leaving `codePos = 0x4d0c`, so the range is `[0xfc, 0x4d0c)`. Every patch is inside it — `v2_FE_mix` (0x4b98), `light_cacheline_align_mask` (0x4cec), `vm_instructions_end_light_tweak` (0x4cf0), `light_dataset_offset` (0x4d04). **Complete.**

**Full path (the miner's).** The last `emit32` is at `v2_FE_mix`, leaving `codePos = 0x4b9c`, range `[0xfc, 0x4b9c)`. The program body (0x1d0), the `vm_instructions_end` 16-byte memcpy (0x4b30), both cacheline masks (0x4b40, 0x4b4c), `update_spMix1` (0x4b84) and `v2_FE_mix` itself are all inside. **Complete for every instruction.**

**The one write outside the range is `randomx_program_aarch64_aes_lut_pointers` at 0x5048**, written only on the v2 **soft-AES** path, 16 bytes at `codePos` far past the clear range. It is **not** a defect: the label is `.fill 2, 8, 0` — a data slot — and it is consumed by `adr x19, ...` / `ldp x19, x20, [x19]`, i.e. loaded as data, never executed. ARMv8 requires I-cache maintenance for modified *instructions*; a plain load of a plain store to the same core needs none. It is recorded because it is the sort of thing that reads like a bug until the label is looked up, and because it is on the path a soft-AES arm64 verifier would take.

**What none of this settles.** All of the above is *static* reasoning from label offsets. §8.8's caveat stands unchanged: the emulator does not model a real core's instruction-cache coherency, and this read does not either. A run on real aarch64 silicon remains owed.

---

## I8-8 — The pinning pipeline is genuinely reproducible now, and the pinned bytes really are upstream's ✅ *verified three ways*

§8.2 records two latent bugs fixed the day rx/2 landed. Both fixes were verified rather than taken on trust.

**Locale.** Recomputing the tree hash under four caller locales with the `LC_ALL=C` pin in place gives `822401d8…` every time. Removing the pin and running under `en_US.UTF-8` gives `d96521a5…` — **the bug reproduces exactly as described**, so the fix is load-bearing and not cosmetic.

**Line endings.** `git check-attr` reports `text: unset` for `jit_compiler_rv64_vector_static.h`, the CRLF file, and the file on disk still has its 9 CR bytes. A **fresh clone** of `dev` recomputes `822401d8…`, matching `PINNED` — which is the property that was actually broken and is the one worth testing.

**The bytes.** The stronger claim — that what is vendored *is* upstream — was checked directly rather than through the hash: `git archive` of commit `aaafe713…`, tests removed, `diff -r` against `core/pow/randomx/upstream/`. **No differences.** The vendored tree is byte-identical to tevador's v2.0.1, verified against the upstream repository rather than against a number this repository wrote down itself.

---

## I8-9 — Flag handling: every construction site agrees ✅ *structurally, not just by inspection*

§8.5a records the mutation where `RANDOMX_FLAG_V2` was set on `fastFlags` alone, producing a node whose miner and verifier compute different functions. The current construction makes that class of divergence **structurally impossible** rather than merely correct:

```go
if o.V2 { flags |= C.RANDOMX_FLAG_V2 }
e := &Engine{ flags: flags, fastFlags: flags | C.RANDOMX_FLAG_FULL_MEM }
```

`fastFlags` is *derived from* `flags`, so no flag can be set on one and not the other except `FULL_MEM` itself. Every downstream site was checked and every one uses one of those two values: `randomx_alloc_cache(e.flags)`, `randomx_create_vm(e.flags, cache, nil)` for the light/key-table VMs, `randomx_alloc_dataset(e.fastFlags)` and `randomx_create_vm(e.fastFlags, nil, e.dset)` for the mining VMs. Light-versus-full and hard-versus-soft AES both ride on the same pair.

Upstream's side agrees: `CompiledVm`'s constructor calls `compiler.setFlags(flags)` unconditionally, and the `setFlagV2`/`clearFlagV2` overrides re-sync the compiler whenever the VM's own flag word changes — so the JIT's copy cannot drift from the VM's. Every VM constructor now takes `randomx_flags` and assigns `vmFlags`; there is no path to an uninitialised flag word. **This is the one place where reading found the delta had been designed to prevent the exact bug this repository already hit once.**

---

## I8-10 — Cache and dataset lifecycle across a seed epoch ✅ *no use-after-free path found*

Checked because the brief named it, and because a key change under a running VM is where the C and Go lifetimes meet.

- **Reference counting is sound.** `destroy` runs only when `evicted && refs == 0`, and refs cannot rise after eviction because the entry has left `e.keys` and `entryFor` is the only place a reference is taken. `destroy` drains all `MaxVMs` VMs from the channel *before* `randomx_release_cache`, so no VM outlives the cache it was created against.
- **The fill cannot free the cache under itself.** `MineOn` takes `entry, err := e.keyedFor(k)` with `defer e.put(entry)` **before** `initDataset(e.dset, entry.cache, ...)` — the reference is held across the whole fill.
- **A key change under a running VM cannot tear.** `MineOn` sets `e.fastKey = ""` under `fmu.Lock()` before filling and restores it after, so a reader either sees the old key (and is refused by the `fastKey != key` check) or waits. `fastHash` uses `TryRLock` and falls back to the light path rather than blocking, which costs speed and cannot cost correctness because both modes compute the same function.
- **Allocation failure is handled at every site**: `randomx_alloc_cache`, `randomx_alloc_dataset` and `randomx_create_vm` are all nil-checked, and the VM-creation failure path destroys the VMs already created, releases the cache, and decrements `liveCaches` rather than leaking it.

The `dealloc` path itself gained one thing from the delta and it is a hardening: `freePagedMemory` now guards `munmap` with `if (ptr)`.

---

## I8-11 — Things in the delta that turned out to be nothing, recorded so they are not re-read

A read is only useful if it also says where it found nothing, so that the next person does not spend the time again.

- **`soft_aes.cpp` (+41/−40) is a pure regrouping.** The eight named LUT arrays became two `[4][256]` arrays. Extracting every 32-bit constant from both versions: **2,048 values in v1.2.3, 2,048 in v2.0.1, identical in the same order.** The `sbox` array was deleted, and nothing on either compiled architecture references it.
- **`aes_hash.cpp` (+58/−1)** is entirely `#ifdef __riscv` dispatch plus one comment typo fix.
- **`cpu.cpp` (+53/−1)** is RISC-V SIGILL probing plus a refactor of the constructor's member initialisation to NSDMI defaults; amd64/arm64 behaviour is unchanged. The new namespace-scope `const Cpu cpu` is read only from RISC-V code on this build — `randomx_get_flags` uses its own **local** `randomx::Cpu cpu`, in v2.0.1 exactly as in v1.2.3 — so there is no static-initialisation-order hazard reachable here.
- **`intrin_portable.h` (+56)** adds only bit-cast helpers (`rx_cast_vec_i2f`/`_f2i`, mapping to `_mm_castsi128_pd` and `vreinterpretq_*`) used by the interpreter's new v2 AES block, plus a `posix_memalign`-based `rx_aligned_alloc`.
- **`assembly_generator_x86.cpp`, `virtual_machine.cpp`, `vm_compiled.cpp`, `bytecode_machine.cpp`** are flag-threading only — passing `randomx_flags` down to the call sites that now need it.
- **The `SuperscalarProgram(&)[N]` → `SuperscalarProgramList` change** is a template-to-`std::array` refactor. `programs.size()` replaces `N`; both are `RANDOMX_CACHE_ACCESSES`. Note that the several `prog.getSize()` calls in the JITs that were *not* changed to take `flags` are `SuperscalarProgram::getSize()`, a different class with an unchanged meaning — an easy misread, and a place where a "fix" would break the dataset path.

---

## Status

| | finding | severity | state |
|---|---|---|---|
| I8-1 | JIT code buffer must be sized by `MAX_SIZE`; mutation overflows by 1,154 B | would be critical | upstream correct; **now pinned by a test** |
| I8-2 | `codePos += readDatasetSize` on both branches | latent, zero impact today | documented; equal by measurement |
| I8-3 | `init_dataset`'s `<4` stack-buffer branch | unreachable from this binding | proven by enumeration |
| I8-4 | CFROUND agreement across three implementations | consensus-critical | verified by decoding |
| I8-5 | interpreter/JIT dataset-pointer agreement | consensus-critical | 600k states, mutation-checked |
| I8-6 | the peer-reachable path | the brief's top priority | **no unsafety found** |
| I8-7 | a64 `clear_cache` coverage | none for instructions | one *data* write outside range, correctly |
| I8-8 | pinning reproducibility and provenance | — | verified three ways |
| I8-9 | flag agreement across construction sites | — | structurally guaranteed |
| I8-10 | cache/dataset lifecycle | — | no use-after-free path |

**What this read does not do**, stated as plainly as §8.8 states its own limits:

- **It does not exclude the 1-in-2²⁸ class of bug.** Reading finds defects that are wrong on their face; the v2.0 bug this pass exists to guard against was wrong on roughly one input in 268 million and would have read as correct. Only volume closes that, and the testnet is the volume.
- **It is a read of the code, not of the hardware.** I8-7 reasons from assembled label offsets, not from a running aarch64 core. Nothing here substitutes for the real-silicon run that remains owed.
- **It did not read the RISC-V delta**, ~2,450 lines. Justified because `vendor.sh` compiles none of it — but if this chain ever ships a RISC-V build, that code is unaudited and this document is the record that it is.
- **`jit_compiler_x86_static.asm`** (the MASM variant, +44) was not read; the GNU `.S` is what builds here.
