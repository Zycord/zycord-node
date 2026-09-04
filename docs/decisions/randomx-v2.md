# Zycord — Whether mainnet genesis ships RandomX v2, and what the four gates found

**Scope:** upstream released the successor work function while this chain is still pre-genesis, so the question is forced onto the pre-freeze clock rather than chosen. Either genesis ships **rx/2** — riding the testnet relaunch the encoding milestone already forces — or it ships **rx/0** and the question closes until after launch, where it becomes this chain's first hard fork. Params are hashed into the network id, so there is no "keep it warm" middle path and no way to defer the choice past the 2026-09-12 freeze.

**Four gates were set, all of which had to pass by 2026-09-06, under an explicit rule: *a single missed gate means v1 without regret.* Three passed on primary-source evidence, gate 3 failed on a factual inversion of its own premise, and gate 4 failed on schedule. §§1–6 are that record, written before the decision and left unedited.**

**THE OWNER DECIDED TO SHIP rx/2 AT GENESIS ANYWAY, AND §8 IS THAT DECISION AND WHAT WAS BUILT.** The gates are not deleted or softened to agree with it: a record rewritten to match its outcome is worth nothing the second time it is consulted. What §8 adds is what §§1–6 did not have — gate 3's finding independently re-verified, two of this record's own claims corrected by that work, and the schedule question answered with an implementation in hand rather than an estimate.

Everything below cites upstream source at a named tag or merge commit. Where this record contradicts the issue that commissioned it, the contradiction is stated rather than smoothed; where §8 contradicts §§1–6, the same.

---

## 1. Gate 1 — the v1/v2 API selection, and whether one build serves both

**PASS.** Reviewed at `tevador/RandomX` pull request 317, merged 2026-02-17 as commit bb6ed2c3ac84abcbb3f8bf50bf53fb9160abec32, and read at tag **v2.0.1** (commit aaafe71322df6602c21a5c72937ac284724ae561) against **v1.2.3** (commit 12f2c2ffe2108d6cf54c391fee33c8bc3646cdab), which is the tag this tree vendors.

**Selection is a flag, not a separate function, and not a separate build.** The entire public-API delta between the two tags is two additions to `src/randomx.h`:

```c
RANDOMX_FLAG_V2 = 128,                                    /* new enumerator */
RANDOMX_EXPORT void *randomx_get_cache_memory(randomx_cache *cache);
```

Nothing else in the header changed but a typo fix in a doc comment. There is no `randomx_calculate_hash_v2`, no second library target, and no compile-time switch. `randomx_create_vm(flags, ...)` takes `RANDOMX_FLAG_V2` alongside the existing flags, and the version is a property of the VM.

**One build serves both, and the evidence is that the selection is a runtime branch in the hot path rather than a preprocessor one.** Every consumer of the flag at v2.0.1 tests it at run time:

| Site | What it selects |
|---|---|
| `src/program.hpp:57` | `(flags & RANDOMX_FLAG_V2) ? RANDOMX_PROGRAM_SIZE_V2 : RANDOMX_PROGRAM_SIZE_V1` |
| `src/vm_interpreted.cpp:89,99` | the AES register mix and the prefetch source register |
| `src/jit_compiler_x86.cpp:322,334,402,421,866` | emitted x86 code |
| `src/jit_compiler_a64.cpp:176,202,248,275,1067` | emitted AArch64 code |
| `src/virtual_machine.hpp:63–66` | `setFlagV2()` / clear, per VM |

A single vendored tree therefore yields an engine that can compute either function, selected per `randomx_vm`. That matters here beyond convenience: it means a `randomx-v2` engine and the existing `randomx-v1` engine could be two `pow.Engine` values over one vendored library, and `selectEngine`'s refusal semantics (§ARCHITECTURE 12) keep working unchanged in both directions.

**No memory size changed. This is the load-bearing half of the gate and it is a clean pass.** `src/configuration.h` at the two tags is identical in every allocation-governing constant:

| Constant | v1.2.3 | v2.0.1 |
|---|---|---|
| `RANDOMX_ARGON_MEMORY` | 262144 | 262144 |
| `RANDOMX_DATASET_BASE_SIZE` | 2147483648 | 2147483648 |
| `RANDOMX_DATASET_EXTRA_SIZE` | 33554368 | 33554368 |
| `RANDOMX_SCRATCHPAD_L3` / `L2` / `L1` | 2097152 / 262144 / 16384 | 2097152 / 262144 / 16384 |
| `RANDOMX_ARGON_SALT` | `RandomX\x03` | `RandomX\x03` |
| `RANDOMX_CACHE_ACCESSES` | 8 | 8 |

The only configuration change is that `RANDOMX_PROGRAM_SIZE` 256 became the pair `RANDOMX_PROGRAM_SIZE_V1 256` / `RANDOMX_PROGRAM_SIZE_V2 384`, with `RANDOMX_PROGRAM_MAX_SIZE 384` sizing the buffers for the larger of the two. So cache is 256 MiB, dataset is ~2.08 GiB and the scratchpad is 2 MiB under both versions. **The seed-epoch stall this tree already measured and already prefetches against (§6 of the XMRig record: 574.9 ms cold, 24.8 ms warm) is governed by cache and dataset construction, and neither moved** — the cache-build cost is Argon2 over an unchanged 256 MiB with an unchanged salt. That removes the memory-footprint and epoch-boundary risk that would otherwise have been the expensive part of a v2 move.

**`randomx_get_cache_memory` exists, and the gate asked why. The answer is that it is not a v2 feature.** Its implementation at v2.0.1 `src/randomx.cpp:141` is three lines returning `cache->memory` — a plain accessor for a field that was already there, exposing the cache buffer so a caller can allocate, share, or inspect it without reaching into the opaque struct. It is unrelated to the v2 algorithm change and unrelated to any size change; it landed in the same release, not because of it. **Nothing in a v2 binding is obliged to call it,** which corrects the framing in the commissioning issue: it is a convenience for embedders managing their own memory, not a hook the algorithm selection requires.

## 2. Gate 2 — rx/2 on ARM64 in shipped XMRig: JIT or interpreter?

**PASS, with one correction to the premise.** The gate asked about "XMRig 6.26.x". **There is no 6.26.x. `v6.26.0` (2026-03-28, commit b2ca72480c58d197e18c885d9fc1a0c8d517e60a) is the newest XMRig tag that exists**, and it is the only release carrying rx/2. Six months of stable-release presence is therefore six months of one release, not of a maintained patch series — a smaller soak than the phrasing suggests, and §5 returns to it.

**ARM64 gets a real JIT, not the interpreter.** The initial rx/2 PR (xmrig/xmrig pull request 3769, merged 2026-01-30) shipped only "RandomX v2 interpreter" and "RandomX v2 JIT compiler (x86)", and named ARM64 explicitly as deferred:

> Will be added in another pull requests: RandomX v2 JIT compiler (ARM64), RandomX v2 JIT compiler (RISC-V), Stratum support for RandomX v2 commitments

That deferred work landed the next day. **xmrig/xmrig pull request 3772, "RandomX v2 (ARM64)", merged 2026-01-31 as commit a189d84fcded326522b12385d51ac509aa01aed7**, and touches exactly four files, all of them the AArch64 JIT:

```
src/crypto/randomx/jit_compiler_a64.cpp
src/crypto/randomx/jit_compiler_a64.hpp
src/crypto/randomx/jit_compiler_a64_static.S
src/crypto/randomx/jit_compiler_a64_static.hpp
```

`git merge-base --is-ancestor a189d84 v6.26.0` confirms it is **in the released tag**, so this is not a master-branch claim.

Read at v6.26.0, the AArch64 JIT emits native code for all three VM-level v2 tweaks, each as its own branch rather than a fallback:

| Tweak | `jit_compiler_a64.cpp` | What is emitted |
|---|---|---|
| AES register mix | 178, 281 | hardware-AES path patches out the v1 jump (`movi v28.4s, 0`); soft-AES path branches to `randomx_program_aarch64_v2_FE_mix_soft_aes` with LUT pointers patched in |
| Dataset prefetch | 201, 254 | copies the v2 tail over the v1 tail at `..._vm_instructions_end_v2` (and the light-mode variant) |
| CFROUND | 1118 | emits `tst`/`bne` (`0xF27E0E9F`, `0x54000081`) so the rounding mode updates ~16× less often |

The v2 targets are real symbols in the hand-written assembly, not stubs — `jit_compiler_a64_static.S` declares and defines `randomx_program_aarch64_v2_FE_mix`, `..._v2_FE_mix_soft_aes`, `..._vm_instructions_end_v2` and `..._vm_instructions_end_light_v2`. Both hardware-AES and soft-AES ARM64 paths are covered, and the JIT keeps its Apple-specific handling (the `XMRIG_OS_APPLE` guard around `flushInstructionCache`), which is the platform the gate was actually about.

Upstream RandomX v2.0.1 independently carries the same ARM64 JIT support at `src/jit_compiler_a64.cpp:176,202,248,275,1067`, so this is not an XMRig-only implementation that our vendored library would lack.

**Release binaries exist for the relevant hardware.** v6.26.0 publishes `xmrig-6.26.0-macos-arm64.tar.gz` and `xmrig-6.26.0-windows-arm64.zip` among its assets. **Apple/ARM miners would get JIT-speed rx/2 from a stock, signed, official download** — which is the entire content of this gate.

**What this gate does not establish** is a measurement. No rx/2 hashrate on ARM64 was taken here, on this hardware or any other; the claim is "the JIT path exists, is compiled in, and is reached", not "it is fast" and not "it is correct on this silicon". The v2.0.1 release exists precisely because v2.0 had a ~1-in-2²⁸ invalid-hash bug on ARM/RISC-V JIT, which is a reminder that this code is young where it is newest.

## 3. Gate 3 — per-nonce targeting under `Tweak_V2_COMMITMENT`

**FAIL. The shipped behaviour is the exact opposite of the premise this gate was written to confirm, and the premise appears in both commissioning issues.**

The expectation on record was that XMRig's rx/2 share filter runs on the **plain RandomX hash**, with the commitment computed only for shares that already beat the target and submitted as a separate field — from which it followed that rx/2 "slots under our planned LE-target rule and 43-byte blob unchanged". Read at v6.26.0, `src/backend/cpu/CpuWorker.cpp`, that is not what happens.

**The tweak is unconditionally on for every rx/2 job.** `RandomX_ConfigurationMoneroV2::RandomX_ConfigurationMoneroV2()` (`src/crypto/randomx/randomx.cpp:55–63`) sets `ProgramSize = 384` and all four tweaks to 1, including `Tweak_V2_COMMITMENT = 1`. `RxAlgo::base()` (`src/crypto/rx/RxAlgo.cpp:35`) returns `&RandomX_MoneroConfigV2` for `Algorithm::RX_V2`, and `RxAlgo::apply()` installs it via `randomx_apply_config`. The base-class constructor defaults the tweaks to 0 (`randomx.cpp:164–167`), but nothing re-clears them for rx/2. **There is no configuration, no pool-protocol field and no command-line flag that yields rx/2 with the commitment off.** Answering the gate's second half: yes, the tweak is on for generic rx/2 jobs — necessarily and always.

**And under that tweak the share filter is commitment-targeted, not hash-targeted.** The hashing block, `CpuWorker.cpp:319–326`:

```cpp
randomx_calculate_hash_next(m_vm, tempHash, m_job.blob(), job.size(), m_hash);

if (RandomX_CurrentConfig.Tweak_V2_COMMITMENT) {
    memcpy(m_commitment, m_hash, RANDOMX_HASH_SIZE);
    randomx_calculate_commitment(prev_job, prev_job_size, m_hash, m_hash);
    ...
}
```

**The two buffer names are inverted relative to their contents, which is why a reading from the PR description alone gets this backwards.** `m_commitment` is loaded with the *raw hash*; `randomx_calculate_commitment` then writes the *commitment* over `m_hash` in place, reading `m_hash` as its `hash_in`. From that line onward `m_hash` holds the commitment and `m_commitment` holds the raw hash.

The target comparison, twelve lines later at `CpuWorker.cpp:354–358`, is the same one this chain's consensus rule was matched to:

```cpp
const uint64_t value = *reinterpret_cast<uint64_t*>(m_hash + (i * 32) + 24);
...
if (value < job.target())
```

It reads `m_hash`. **Under rx/2 that is the commitment.** The filter is commitment-targeted.

The submission confirms it from the other end. `JobResults::submit(job, nonce, m_hash + (i*32), extra_data)` with `extra_data = m_commitment` (`CpuWorker.cpp:371–372`), and `Client.cpp:205–241` puts `result.result()` — the filtered value, i.e. the commitment — into the Stratum **`result`** field, and `result.commitment()` — the raw hash — into a field literally named **`commitment`**. So the wire field named `commitment` carries the hash, and the field named `result` carries the commitment. The naming is inverted at every layer, consistently.

For completeness, the commitment is `blake2b(input ‖ H)` over the *job blob that produced H*, 32-byte output (`randomx.cpp:633–638`); `prev_job` exists because the hash pipeline is one nonce behind, so the commitment must be taken over the blob of the *previous* round rather than the current one.

**Consequence, and it is the whole reason this gate is a gate.** The commitment issue named the disqualifying condition in advance and pointed it at the wrong side. The real position is the mirror image: **this chain's LE-target rule, as frozen and as pinned by `xmrig_cross_vector_test.go`, compares the raw RandomX digest. Stock XMRig under rx/2 compares the commitment.** Those are independent uniform values. A stock rx/2 miner would filter on a number this chain's `CheckWork` does not evaluate, and would therefore submit losing nonces and discard winning ones — the precise silent failure mode catalogued in §1 of the XMRig record, where a miner reports healthy hashrate and every share is refused with no error naming the cause.

**Adopting rx/2 at genesis therefore does not leave consensus unchanged.** It forces a choice between exactly two options, and both are expensive:

- **Move consensus to be commitment-targeted.** This is the commitment issue promoted from optional to mandatory: a 32-byte field in the fixed SSZ header (220 → 252 bytes), the `PoWSeed()`/`PoWInput()` derivation boundary, every golden vector, the spec's header section, and the LE-target rule re-pointed at the commitment. All of it inside nine days, all of it consensus-frozen at genesis.
- **Keep hash-targeted consensus and ship rx/2 anyway.** This reintroduces the exact incompatibility the XMRig decision was made to eliminate, and reintroduces it *silently*.

The second is not a real option. The first is not a nine-day option — and it is worth stating that it is not merely *large*, it is large in the one region this tree has already identified as unforgiving: `xmrig_cross_vector_test.go` §5 records that the mutation it cannot see is one *inside the seed preimage*, caught only by a single test in `core/types`. Moving the derivation boundary is work in that region.

**The gate fails.** Under the commissioning issue's own rule, that alone settles the outcome, and gate 4 is recorded below for completeness rather than because it can change anything.

## 4. Gate 4 — does the work fit before 2026-09-12 without displacing the relaunch?

**FAIL — and it fails on the audit, not on the vendoring.** The two halves separate cleanly and the estimate is anchored in this tree's actual pipeline rather than in a general sense of difficulty.

**The vendoring half is genuinely small, and this is the gate's one good news.** `core/pow/randomx/vendor.sh` clones a pinned commit, copies `src/` minus `tests/`, and generates one `#include` shim per translation unit from three hardcoded lists (`portable_c`, `portable_cc`, and four arch-specific lines). Whether those lists still cover v2 decides how much of the script has to change. Comparing `CMakeLists.txt` at the two tags: **the portable, amd64 and arm64 source lists are unchanged.** Every file v2.0.1 adds — `aes_hash_rv64_vector.cpp`, `aes_hash_rv64_zvkned.cpp`, `jit_compiler_rv64_vector.cpp`, `jit_compiler_rv64_vector_static.S`, `cpu_rv64.S` and the new `asm/*.inc` fragments — is RISC-V, and this tree emits no RISC-V shims because Go's filename constraints there buy nothing it uses. So `vendor.sh` needs a `TAG`/`COMMIT` bump and nothing else; `PINNED`, `pinned.go` and the tree hash regenerate themselves; `TestVendoredTreeMatchesPinned` keeps working unmodified. Realistically **hours, not days**, and the build-tag structure, the no-`import "C"`-outside-this-package rule and the cgo flags all survive untouched.

**The audit half is where it breaks, and the number is specific.** The adversarial-pass issue requires a third I7-style adversarial pass over the delta, because the v1 binding's two passes do not transfer. That delta, restricted to the files this tree actually compiles:

| File | Change |
|---|---|
| `jit_compiler_a64_static.S` | +338 / −10 |
| `jit_compiler_x86.cpp` | +134 / −34 |
| `jit_compiler_a64.cpp` | +95 / −9 |
| `aes_hash.cpp` | +58 / −1 |
| `randomx.cpp` | +44 / −25 |
| `soft_aes.cpp` | +41 / −40 |
| `jit_compiler_x86_static.S` | +36 / −2 |
| `vm_interpreted.cpp` | +33 / −8 |
| `randomx.h`, `configuration.h`, `program.hpp`, others | +24 / −11 |

**Roughly 800 changed lines, and the mass of it is in two JIT code generators and hand-written assembly** — the least reviewable code in the dependency, and the exact category that produced v2.0's ~1-in-2²⁸ ARM/RISC-V invalid-hash bug. This is not a delta an adversarial pass reads in an afternoon; the I7 pass over the v1 binding is the calibration, and this is comparable work on less familiar ground.

**The vector work has a specific, non-obvious cost that a headline estimate misses.** Upstream v2.0.1 does publish rx/2 vectors — `src/tests/tests.cpp` carries paired v1/v2 expectations for `test_a` through `test_e` (e.g. v2 `22ec6b86…` against v1 `639183aa…`), driven under `RANDOMX_FLAG_V2` for both interpreter and compiler. **But `test_f` has no v2 variant.** It asserts `78af2a18…` unconditionally and runs only in the v1 block. `test_f` is the ISUB_R edge case, and it is the exact vector `TestTheConsensusInterfaceComputesUpstreamsFunction` is built on — chosen, per the comment in `xmrig_cross_vector_test.go`, for a property unrelated to that bug and not interchangeable with the others. So the tier-1 cross-vector anchor cannot be ported; it has to be **re-designed onto a different vector**, and re-argued, not re-run. Nine mutations are recorded against that file with their outcomes, and they are claims about v1 until re-executed.

**Then the parts no estimate shortens.** Cache/dataset build times, memory footprint and hashrate deltas on both amd64 and arm64 (the vendoring issue); soak across several seed-epoch boundaries on both architectures (the adversarial-pass issue); `make bench` regenerated. The measurements are wall-clock by nature — a dataset build and several epoch boundaries on two architectures cannot be compressed by adding attention.

**Against the calendar.** Nine days to the freeze, three to the relaunch. The relaunch and the encoding milestone are committed and this work sits on top of them, not beside them. The 2026-09-06 relaunch would have to carry a v2 engine that, on this schedule, would be vendored and audited in the same window — so the public soak the relaunch is *for* would begin on code whose adversarial pass had not finished. **That inverts the purpose of the relaunch.** And the estimate is bounded below by gate 3: if rx/2 requires the commitment-targeted header change, the commitment issue's consensus work lands in the same nine days, and gate 4 is not close.

**Even with gate 3 hypothetically resolved,** ~800 lines of JIT and assembly under a third adversarial pass, a re-designed tier-1 vector anchor, and two-architecture soak across epoch boundaries do not fit before 2026-09-12 without displacing what is already committed. The gate fails on its own terms.

## 5. What the priority order says, independently of the gates

The gates decide this under the issue's own rule. The standing decision order agrees, and it is worth recording that the two do not have to be traded off against each other.

**The whitepaper does not bind the version.** §16's era table names the Era-0 work function as "PoW (RandomX [14])" and the design notes argue for CPU mining on demographic grounds — "mine on the laptop you already have", "keeping honest commodity hardware competitive is RandomX's entire design brief". Reference [14] is the 2019 RandomX paper. **Nothing in the whitepaper distinguishes rx/0 from rx/2**, and both satisfy every property it actually claims. So the highest authority in the order is silent here, and this is genuinely a lower-tier decision rather than one the whitepaper settles. Recorded explicitly because the reverse — a whitepaper commitment to v1 — would have closed the question without any gates at all, and it does not exist.

**Public precedent, verified rather than repeated.** The claim on file was "no production chain appears to run rx/2 yet, and Monero has not activated it." Checked directly, it is stronger than stated:

- **Monero has not merely failed to activate v2 — it has not vendored it.** `monero-project/monero` at its latest release, **v0.18.5.1 (2026-07-08)**, pins the `external/randomx` submodule at commit 6c4340ba4561aec9a3611c1aedf9931239777fb3, which is RandomX **v1.2.2**. Not v2.0, not v2.0.1.
- A code search across `monero-project/monero` for `RANDOMX_FLAG_V2` returns **0 results**; for `randomx_calculate_commitment`, **0 results**. The algorithm the ecosystem is said to be converging on is absent from the reference implementation's tree sixteen months after the commitment scheme was proposed.
- xmrig/xmrig pull request 3775 says so in its own words: `BlockTemplate` and `DaemonClient` were left unchanged "because Monero codebase hasn't implemented commitments yet, so there is no reference code."

**So the soak is thinner than the "six months in stable releases" framing implies.** It is one release, `v6.26.0`, with no patch release behind it, carrying an algorithm that no chain sends it jobs for. Miner-side code that has never been exercised against a live chain has been *compiled* for six months, not *run* for six months. Meanwhile v2.0 shipped a consensus-relevant invalid-hash bug on ARM/RISC-V JIT that needed v2.0.1 to fix — found in seven weeks, in the code path with the least production exposure.

**A launch is the worst moment to be the first production user of anything**, and on this evidence a v2 genesis would make this chain the first production user of rx/2, of XMRig's rx/2 client path, and — given gate 3 — of a commitment-targeted consensus rule that Monero itself has not shipped. Three firsts at once, at the moment with the least operational slack and no repair path short of a fork.

**Simplicity.** v1 is vendored, bound, twice-adversarially-reviewed, cross-vector-pinned against tevador's published rx/0 vectors and against XMRig's own source constants, and measured on the testnet the relaunch continues. Its compatibility story is finished and written down. That is the least error-prone option available and it requires no new work at all.

## 6. What the gates imply

Recorded as findings; the decision is the owner's.

- **Three gates pass and one fails.** Gate 1 passes cleanly and better than expected — a runtime flag, one build for both, and *no memory-size change at all*, which removes the seed-epoch and footprint risk that would have been the expensive part. Gate 2 passes: ARM64 gets a genuine JIT for all three v2 tweaks, in a released tag, with official Apple-silicon binaries. **Gate 3 fails.** Gate 4 fails independently.
- **Gate 3 is not a near miss and not a matter of degree.** The premise on file — that XMRig's rx/2 share filter is hash-targeted — is factually inverted. `m_hash` holds the commitment at the moment of comparison, `Tweak_V2_COMMITMENT` cannot be turned off for rx/2, and this chain's frozen LE-target rule compares the raw digest. **Under the commissioning issue's own rule, one missed gate ends it.**
- **The good news from gates 1 and 2 does not offset it.** They establish that a v2 *engine* would be cheap to stand up and would run well on the hardware the chain cares about. Gate 3 is not about the engine; it is about whether stock XMRig and this chain's consensus agree on which number to compare. They do not, and no property of the engine repairs that.
- **The commitment issue answers itself, in the direction opposite to the one it anticipated.** It expected to close as *"no — stock XMRig is hash-targeted, so commitment-targeted consensus would break compatibility."* The evidence says stock XMRig **is** commitment-targeted for rx/2, so under rx/2 it is *hash*-targeted consensus that breaks compatibility. The conclusion for the freeze is unchanged — the header does not grow a 32-byte field nine days out — but the reasoning on file should be corrected rather than left standing, because it is the kind of error that looks settled.
- **Nothing here is an argument that rx/2 is bad.** The efficiency case is real, the API is clean, the ARM64 support is real. What the evidence says is that adopting it *at this genesis* would make this chain the first production user of an unsoaked algorithm **and** would force a consensus-header change into the last nine days before a freeze. The question reopens naturally: after Monero activates, the ecosystem has soaked it, the commitment semantics are settled by someone else's mainnet, and it can be planned as a fork with a schedule instead of a deadline.
- **If v1 is retained, no file changes.** `pow_engine` stays `randomx-v1` in `spec/params.json` and `spec/params.testnet.json`, the relaunch carries the engine it already carries, and the vendoring, commitment and adversarial-pass issues close against this record.

## 7. What would reopen this

- **Monero activating v2 on mainnet**, which supplies the soak, settles the commitment semantics in production, and makes the reference implementation a second source for both.
- **A shipped XMRig that is hash-targeted for rx/2**, or that exposes the commitment tweak as a per-job option. Either would retire gate 3 as stated; the first would let rx/2 slot under the current consensus rule unchanged, which is what was originally assumed to be true.
- **Not the efficiency argument, and not ecosystem convergence.** Both were already counted in favour of v2 before the gates ran, and neither is what failed. A stronger version of either does not reopen a question that turned on §3.
- **Not a faster estimate for gate 4.** Gate 4 failing second is why it is recorded second; if gate 3 were resolved, gate 4 would still have to be re-run against a real schedule rather than argued down.

---

**Primary sources.** `tevador/RandomX` pull request 317 (merge commit bb6ed2c3ac84abcbb3f8bf50bf53fb9160abec32), tags `v2.0.1` (commit aaafe71322df6602c21a5c72937ac284724ae561) and `v1.2.3` (commit 12f2c2ffe2108d6cf54c391fee33c8bc3646cdab) — `src/randomx.h`, `src/configuration.h`, `src/randomx.cpp`, `src/program.hpp`, `src/virtual_machine.hpp`, `src/vm_interpreted.cpp`, `src/jit_compiler_a64.cpp`, `src/jit_compiler_x86.cpp`, `src/tests/tests.cpp`, `CMakeLists.txt`. `xmrig/xmrig` tag `v6.26.0` (commit b2ca72480c58d197e18c885d9fc1a0c8d517e60a) — `src/backend/cpu/CpuWorker.cpp`, `src/crypto/randomx/randomx.cpp`, `src/crypto/rx/RxAlgo.cpp`, `src/crypto/rx/RxSeed.h`, `src/net/JobResult.h`, `src/base/net/stratum/Client.cpp`, `src/base/crypto/Algorithm.{h,cpp}`, `src/crypto/randomx/jit_compiler_a64{.cpp,_static.S}`; pull requests 3769, 3772 (commit a189d84fcded326522b12385d51ac509aa01aed7), 3774, 3775, 3782 and 3783. `monero-project/monero` tag `v0.18.5.1`, `external/randomx` submodule pin.

---

## 8. The decision, and what was built against it

**The owner decided that mainnet genesis ships rx/2 and that the relaunched testnet is BORN on it rather than forking onto it.** No height gate, no chain-id branch, no activation height: both networks start on v2. §§1–7 are left exactly as they were written, because a gate record edited to agree with the decision it preceded is worth nothing the second time somebody consults it.

This section is what the implementation found. It re-verifies gate 3 independently, **corrects two claims §§1–6 got wrong**, records the measurements, and states plainly what is and is not anchored.

### 8.1 Gate 3's finding, re-verified from source

Re-read at `xmrig/xmrig` v6.26.0 (commit b2ca72480c58d197e18c885d9fc1a0c8d517e60a) rather than taken from §3. **It holds in every particular.**

- `RandomX_ConfigurationMoneroV2::RandomX_ConfigurationMoneroV2()` sets `Tweak_V2_COMMITMENT = 1` (`src/crypto/randomx/randomx.cpp:55–63`), and `RxAlgo::base()` returns `&RandomX_MoneroConfigV2` for `Algorithm::RX_V2` (`src/crypto/rx/RxAlgo.cpp`). Unconditional for every rx/2 job.
- `CpuWorker.cpp:319–326` copies the raw hash into `m_commitment`, then calls `randomx_calculate_commitment(prev_job, prev_job_size, m_hash, m_hash)` — **the same buffer as input and output**, so the commitment overwrites the hash in place.
- The share filter at `CpuWorker.cpp:354` reads `m_hash`, which by then is the commitment.
- `Client.cpp:205–241` puts `result.result()` — the filtered value, the commitment — into the Stratum field named `result`, and `result.commitment()` — the raw hash — into the field named `commitment`. Inverted at every layer, consistently.

One detail §3 left implicit and worth stating, because it decides which bytes the commitment covers. `randomx_calculate_hash_next` finishes the *previous* nonce's hash while seeding the scratchpad from the *next* input (`randomx.cpp:618–631`), so the pipeline runs one nonce behind, and `prev_job` is the blob that actually produced the hash in hand. **The commitment is therefore over the blob that produced H**, not over some earlier unrelated blob — which is what makes `blake2b(pow_input ‖ pow_hash)` the right consensus form.

**The conclusion is the one §3 reached and both commissioning issues got backwards: under rx/2 it is hash-targeted consensus that breaks stock miners, and commitment-targeted consensus that matches them.**

### 8.2 Two corrections to this record

**Correction 1 — upstream DOES publish a commitment vector, and §4 says it does not have one.** §4's vector paragraph is right that `test_f` has no v2 variant, and that was the load-bearing problem for the tier-1 anchor. What it missed is that `src/tests/tests.cpp` at v2.0.1 carries a test named "Commitment test":

```cpp
calcStringCommitment("test key 000", "This is a test", &hash);
assert(equalsHex(hash, "133be717399046b03ae82ce8ddd9d1ee4d3ea7fca03a50dec09b6848cbb98e18"));
```

run against a VM created with `RANDOMX_FLAG_V2`, where `calcStringCommitment` is `randomx_calculate_hash` followed by `randomx_calculate_commitment`. **That is a genuine upstream anchor for the exact number this chain's consensus now compares**, and it binds three things a BLAKE2b conformance vector does not: the function, the operand order (`input ‖ H`, not the reverse), and that the mode is unkeyed. It is checked in `core/crypto/blake2b` against upstream's own intermediate `H`, and again in `core/pow/randomx` against the `H` this engine produces — the join between the two halves. §4's estimate was written without it, and the vector work is materially smaller because it exists.

**Correction 2 — "roughly 800 changed lines under a third adversarial pass" overstates what this change actually required of the vendoring, and understates what it required elsewhere.** §4 is right that the delta is ~800 lines concentrated in JIT code generators and hand-written assembly, and right that this is the least reviewable code in the dependency. What the implementation showed is that **`vendor.sh` needed a two-line tag bump and nothing else** — the portable, amd64 and arm64 source lists are unchanged, every added file is RISC-V, and the tree built and passed every existing test on the first attempt. The audit burden §4 describes is real and is **not discharged by this work**; see 8.6.

Against that, two costs §4 did not anticipate at all, both found by running the pipeline rather than by reading it:

- **`vendor.sh` sorted filenames under the caller's locale.** `sort` collates by locale, and under `en_US.UTF-8` glibc ignores punctuation, so `jit_compiler_rv64.cpp` orders after `jit_compiler_rv64_vector.cpp` where byte-wise it orders before. `pinned_test.go` recomputes the same hash in Go with `sort.Strings`, which is byte-wise and has no locale. **The two implementations agreed only for as long as no two vendored filenames differed in a way collation treats specially. v1.2.3 had no such pair; v2.0.1 does.** So the tree hash was a function of who ran the script, and the guard that exists to make the vendored tree byte-exact would have failed on a correctly vendored tree. Pinned to `LC_ALL=C`.
- **One new upstream file, `jit_compiler_rv64_vector_static.h`, has CRLF line endings**, and `.gitattributes`' `* text=auto eol=lf` rewrote it on the way into the index. A fresh clone therefore held different bytes from a re-vendor, and the two computed different tree hashes. The vendored subtree is now `-text`, stored verbatim.

**Both were latent before this change and neither is about rx/2.** They are recorded here because this is the work that surfaced them, and because they are the same class of defect as the build-cache hazard `vendor.sh`'s own comment describes: a guard that appears to hold and does not.

### 8.3 What the commitment cost the header, and what it bought

`HeaderSize` went from **228 to 260** — not the 220 → 252 the commissioning issue estimated, because 228 was already a correction of an earlier wrong number. The field is the full 32-byte digest; a truncation would not reproduce the commitment.

Measured on this machine (6 cores, shared, moderate load), interleaved in one process:

| | median | range over 7 runs |
|---|---|---|
| light verify, rx/0 | 21.05 ms | 20.16 – 23.11 |
| light verify, rx/2 | 21.90 ms | 18.82 – 23.40 |
| commitment (BLAKE2b over 75 B) | 207 ns | 207 – 524 |

**The commitment is ~10^5 times cheaper than the verify it defers.** That ratio is the whole trade: a cited-header flood is refused at 207 ns per header instead of 21 ms, and a header that passes the commitment has had a full proof of work spent on it before the node pays for RandomX.

### 8.4 rx/2 versus rx/0, measured, and what this machine cannot say

| | rx/0 median | rx/2 median | ratio |
|---|---|---|---|
| light verify | 21.05 ms | 21.90 ms | 1.04 |
| cache build | 698 ms | 681 ms | 0.98 |
| dataset build (6 threads) | 6.39 s | 7.52 s | 1.18 |
| light-mode RSS | 258.19 MiB | 258.19 MiB | 1.0000 |
| full-memory RSS | 2338.50 MiB | 2338.42 MiB | 0.99997 |

**The timing rows are reported as "no difference this machine can resolve", and that is the honest reading rather than a hedge.** Intra-sample spread is 15–24% for verify and 24–50% for the dataset build; every ratio above is inside its own sample's noise, and the dataset row's 1.18 rests on three runs whose v2 range (6.17–9.24 s) contains the entire v1 range. This is a shared machine, and ARCHITECTURE §15's protocol — own process, idle machine, medians over many runs — is not satisfiable on it. **Nothing here should be quoted as a hashrate delta in either direction.** What can be said is bounded: whatever the difference is, it is smaller than this hardware's noise floor, which is itself larger than any efficiency claim rx/2 makes.

**The memory rows are different in kind and are a real result.** Light mode differs by 4 KB out of 264 MB and full memory by 84 KB out of 2.39 GB — measurement jitter around a shared allocator, not a size change. That confirms gate 1's byte-identical `configuration.h` finding *empirically* rather than by reading a header, and it settles the seed-epoch and footprint risk that §1 called the expensive part of a v2 move. **A node running rx/2 costs exactly what a node running rx/0 costs.**

### 8.5 The cross-vector anchor, and what is now unanchored

§4 was right that the tier-1 anchor could not be ported, and this is what replaced it. `TestTheConsensusInterfaceComputesUpstreamsFunction` now rests on four upstream constants, all from tevador v2.0.1 `src/tests/tests.cpp`:

1. **`test_a` through `test_d` under `RANDOMX_FLAG_V2`.** Same keys and inputs as the v1 table, different published digests in every byte. Held in `officialVectorsV2` beside `officialVectors`, so the pair is a **differential**: a build where the V2 option did nothing reproduces the v1 column and fails, and a build where v1 had silently become v2 fails the other table.
2. **Upstream's own switch vector** — `639183aa…` under v1 and `22ec6b86…` under v2 for one key and input — asserted across two engines rather than by toggling a flag on one VM, because two engines is what `selectEngine` builds.
3. **The commitment vector** (8.2), joined to the hash *this* engine produces.
4. The unchanged tiers 2–4: the 43-byte blob rebuilt from XMRig's offsets, the zero gap, and XMRig's share test — the last now running on the commitment, assembled from `randomx_calculate_commitment`'s three lines rather than by calling this tree's own function.

**What is NOT anchored, stated plainly rather than left to be inferred: the interface-key claim.** Every published rx/2 vector has a short ASCII key ("test key 000"), and a `types.Hash` is exactly 32 bytes, so **no v2 vector can be driven through `Engine.Hash` with its own key at all.** What the test asserts instead is that `Hash(key)` and `hashRaw(string(key[:]))` are the same function of the same 32 bytes, which is what transfers the `officialVectorsV2` coverage to the interface consensus calls. It is not itself checked against an upstream number, because no upstream number of that shape exists. **This is the same weakness rx/0 had** — the 32-byte form of `test_f`'s key is not the 31 bytes upstream hashed either — so it is not a regression, but it is now without a neighbouring vector that shares key material, and it should not be described as if `test_f` had been replaced like for like. **It has not been. It has been replaced by four other things, and the gap it left is this one.**

No 43-byte digest or commitment is recorded anywhere, for the reason the cross-vector file has always given: no upstream vector is 43 bytes, so such a constant could only come from this engine, and a vector produced by the implementation it checks restates the code in hexadecimal.

### 8.5a Mutations, and the two that are worth more than the table

Every new test was proven to fail under a deliberate mutation before being
trusted. The full table lives beside the code it guards —
`core/pow/randomx/xmrig_cross_vector_test.go` for the V-series,
`core/crypto/blake2b/blake2b_test.go`'s subject for the B-series — and the rows
are not repeated here. Two results are.

**V2 had no test at all, and mutation is the only reason there is one now.**
`Options.V2` sets `RANDOMX_FLAG_V2` on `flags`, from which `fastFlags` is
derived, so light and fast necessarily bind the same function. Setting it on
`fastFlags` alone compiles, passes every vector test in the package, and
produces a node whose *miner* computes rx/2 while its *verifier* computes rx/0 —
every block it seals rejected by every node including itself. Nothing saw it:
`TestLightAndFastAgree` constructs two default engines, both v1, so it never
reached the flag, and every vector test uses a light engine.
`TestLightAndFastAgreeUnderV2` exists because the mutation was run, not because
the gap was noticed by reading. **That is the same failure shape as the
prefetch/mining-key incident this tree has already paid for once**, arriving
through a different door.

**V7 survives, and is recorded rather than omitted.** Removing the
digest-identity half of `CheckWork` leaves every test in the cross-vector file
green, because every header that file builds carries the digest of its own blob
— the mismatch case is never constructed there, and a stock miner never submits
one either. It is correct scoping rather than a hole, and it is caught in
`core/pow` by a test that perturbs `PoWHash` by one bit under a target nothing
can fail. Both facts are in the table.

**One test's own first version was vacuous and that is recorded at the line.**
The header-field sweep's `Target` case subtracted one from a field `blobHeader`
leaves at zero, so a saturating subtraction was a no-op and the test reported a
field that had never varied. It failed, which is how it was found; the fix is an
addition, and the near-miss is written at the call site rather than quietly
corrected.

### 8.6 What this work does NOT do, and it is the part that matters most

**The adversarial pass §4 requires over the ~800-line upstream delta has not been done.** The vendoring was mechanical and the tests pass; that is evidence the library computes upstream's published vectors, and it is *not* evidence that two JIT code generators and several hundred lines of hand-written AArch64 and x86 assembly are free of the class of defect that produced v2.0's ~1-in-2²⁸ invalid-hash bug on ARM/RISC-V. **A vector suite catches a code generator that is wrong on the inputs the vectors reach.** The bug v2.0.1 fixed was reached by roughly one input in 268 million.

**Nothing here has run on arm64.** Gate 2 established that a real AArch64 JIT exists in the released tag and is reached; every measurement in 8.4 is amd64. The architecture where v2's newest code lives, and where v2.0's bug lived, is the one this work has not touched.

**No soak has happened.** No epoch boundary has been crossed on rx/2 on any network, on either architecture.

**And the standing risk §5 records is unchanged by any of the above.** Monero has not activated rx/2 and `v0.18.5.1` still pins RandomX v1.2.2; a code search of `monero-project/monero` for `RANDOMX_FLAG_V2` and for `randomx_calculate_commitment` returns nothing. **Shipping this at genesis makes this chain the first production user of rx/2, of XMRig's rx/2 client path, and of a commitment-targeted consensus rule that no other chain runs.** That is the decision the owner made with the evidence in front of them; it is recorded here as a risk that was accepted, not as one that was retired.

### 8.7 What would reopen it

- **Any disagreement between this engine and a real XMRig binary**, which nothing in this tree can detect: every check here is against published source constants and published vectors, and "a stock miner was pointed at a node and found a block" remains unproven for rx/2 exactly as §5 of [xmrig](xmrig.md) records it for rx/0.
- **The adversarial pass finding anything in the JIT delta.** It is outstanding, and until it is done the strongest statement available is "upstream's vectors reproduce".
- **An arm64 result.** Either a measurement or a failure would be new information; there is none.
