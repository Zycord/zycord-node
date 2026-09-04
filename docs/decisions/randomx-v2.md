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

**The adversarial pass §4 requires over the ~800-line upstream delta has not been done.** *Partly addressed by section 8.8 below, which is a differential and mutation pass rather than the line-by-line read §4 asks for.* The vendoring was mechanical and the tests pass; that is evidence the library computes upstream's published vectors, and it is *not* evidence that two JIT code generators and several hundred lines of hand-written AArch64 and x86 assembly are free of the class of defect that produced v2.0's ~1-in-2²⁸ invalid-hash bug on ARM/RISC-V. **A vector suite catches a code generator that is wrong on the inputs the vectors reach.** The bug v2.0.1 fixed was reached by roughly one input in 268 million.

**Nothing here has run on arm64.** Gate 2 established that a real AArch64 JIT exists in the released tag and is reached; every measurement in 8.4 is amd64. The architecture where v2's newest code lives, and where v2.0's bug lived, is the one this work has not touched. *Partly superseded: section 8.8 below runs the a64 JIT under emulation and records what that is and is not worth.*

**No soak has happened.** No epoch boundary has been crossed on rx/2 on any network, on either architecture. *Superseded on amd64: see section 8.8 below.*

**And the standing risk §5 records is unchanged by any of the above.** Monero has not activated rx/2 and `v0.18.5.1` still pins RandomX v1.2.2; a code search of `monero-project/monero` for `RANDOMX_FLAG_V2` and for `randomx_calculate_commitment` returns nothing. **Shipping this at genesis makes this chain the first production user of rx/2, of XMRig's rx/2 client path, and of a commitment-targeted consensus rule that no other chain runs.** That is the decision the owner made with the evidence in front of them; it is recorded here as a risk that was accepted, not as one that was retired.

### 8.7 What would reopen it

- **Any disagreement between this engine and a real XMRig binary**, which nothing in this tree can detect: every check here is against published source constants and published vectors, and "a stock miner was pointed at a node and found a block" remains unproven for rx/2 exactly as §5 of [xmrig](xmrig.md) records it for rx/0.
- **The adversarial pass finding anything in the JIT delta.** It is outstanding, and until it is done the strongest statement available is "upstream's vectors reproduce".
- **An arm64 result.** Either a measurement or a failure would be new information; there is none.

### 8.8 The adversarial pass: what it closed, and what it did not

A second pass ran against `feat/randomx-v2-commitment` before the freeze,
in parallel with the merge and with the four gaps in 8.6 as its brief. It is
recorded here rather than in a competing document so that one section carries
the residual risk.

**Nothing it found is a consensus defect.** No verifier/miner divergence, no
path by which a stock miner's valid share is refused or an invalid one
admitted. The three findings below are a coverage gap, an unreachable unpinned
rule, and a comment that describes an ordering its code does not implement.

#### What it closed

**arm64 is no longer untested, and the qualifier matters.** `core/pow/randomx/arm64/`
cross-compiles the vendored sources for aarch64 and runs upstream's own
published vectors under rx/0 and rx/2, on the interpreter *and* on the a64 JIT,
plus upstream's Commitment test and a JIT-versus-interpreter sweep. All pass.

**The numbers, and which run each comes from, because they are not all the same
run.** Measured: **40 vector checks — upstream's four (key, input) pairs under
rx/0 and rx/2, across interpreter and a64 JIT, across soft AES, hard AES and
hard AES with `SECURE` — 0 failures**; and upstream's Commitment vector
reproducing `133be717…` under soft AES and hard AES, on both the interpreter
and the JIT. The Commitment check sat OUTSIDE the configuration loop for one
revision, on hoisted soft-AES flags, while this paragraph claimed it as
hard-AES coverage. It is now inside the loop and the claim is a measurement
rather than a description.

Two sweep runs, and they are different sizes. The **400-input**
JIT-versus-interpreter sweep with 0 mismatches was the **soft-AES-only** run
(418 checks in total). A later run of the full matrix swept **40 inputs under
soft AES and 40 under hard AES, 0 mismatches on both**, for 125 checks and 0
failures overall. So hard AES has a sweep, at a tenth of the depth soft AES
has; the deeper number belongs to soft AES alone and is not claimed for both.
The hard-AES cells of the full-dataset section are wired but have not been run
to completion, and remain open below.
`run.sh` needs no root — the toolchain and `qemu-aarch64` unpack from `.deb`
files into a user prefix, and the recipe is in the script's own header.

**What that is worth, stated precisely: this is emulation, not hardware.**
qemu-user translates the a64 instructions the JIT emits; it does not reproduce
a real core's memory ordering, its instruction-cache coherency, or its
`__builtin___clear_cache` behaviour, and those are exactly where a
self-modifying code generator goes wrong. So the result rules out *wrong code
generation* on arm64, for the configurations listed below, and does not rule
out *wrong execution* on an arm64 chip. **A run on real hardware is still
owed**, and it is now one command (`sh core/pow/randomx/arm64/run.sh`, which
takes the native path on an aarch64 box) rather than a project.

**Which configurations, because "arm64 is covered" was too broad for one
revision of this section and the correction is the point.** The first version
of the harness built every VM from `RANDOMX_FLAG_DEFAULT` and therefore never
set `RANDOMX_FLAG_HARD_AES`. That is not a performance switch on this
architecture: `jit_compiler_a64.cpp` branches on it at the "Enable RandomX v2
AES tweak" site in *both* generators — `generateProgram` for the dataset path
and `generateProgramLight` for the light one — emitting `movi v28.4s, 0` under
hard AES against a branch into the soft-AES FE mix without it, at the same
patch address, inside the rx/2 delta. `randomx.cpp`'s `create_vm` switch keys
on the same flag, so only the `...Default` VM classes were ever instantiated.
**Every check in the first revision therefore exercised the branch a real arm64
miner does not take**, since any ARMv8 core with the crypto extensions reports
hard AES and `randomx_get_flags` sets it.

The harness now runs the vectors under three configurations — soft AES, hard
AES, and hard AES with `RANDOMX_FLAG_SECURE` — so both branches of both patch
sites are exercised and the `...HardAes` and `...Secure` classes are
instantiated alongside `...Default`. The JIT-versus-interpreter sweep is wired to run
under soft and hard AES, and the full-dataset section under all four cells of
{rx/0, rx/2} x {soft, hard} — but see the note above on which of those has
actually been run to completion: the hard-AES sweep and the hard-AES
full-dataset cells are wired and not yet measured. Everything reported as
passing reproduces upstream's published digests. Nothing was dropped for being unrunnable under emulation: qemu
implements the ARMv8 AES instructions, so the hard-AES path executes rather
than trapping. The interpreter is not re-run under `SECURE`, and that is a
genuine skip rather than a gap — the flag changes only the JIT buffer's page
permissions and the interpreted classes are selected by the same switch, so it
would repeat the row above it.

**What the AES branches are, since two mutations that survived say it plainly.**
Forcing the hard-AES site to take the soft-AES branch, and forcing the soft-AES
site to take the hard-AES one, both leave every vector green. That is the
correct answer rather than missing coverage: the two branches are two
implementations of the same AES, and upstream's vectors are what require them
to agree. The branch is a dispatch choice, not a semantic one. What is *not*
inert is the instruction the hard-AES arm emits, and the mechanism is worth
stating exactly because a first attempt at this mutation was described wrongly.
The site's default content is `b v1_FE_mix`, which falls into `FE_store` and
terminates; the hard-AES arm overwrites that branch with `movi v28.4s, 0`, so
execution falls through into the `aese`/`aesd` block and mixes against a
zeroed `v28`. Zeroing that register is therefore semantic, not housekeeping.
Emitting `movi v29.4s, 0` instead leaves `v28` uncleared and **fails on the
digest**: every rx/2 hard-AES row and the hard-AES commitment vector are wrong,
while rx/0 and every soft-AES row stay green. That is the kill, and its
selectivity is also the proof the site is reached under these runs rather than
dead. An earlier version of this row reported a kill-by-hang; that was a
different edit and weaker evidence, since a timeout can mask an unrelated
failure and says nothing about which bytes changed.

**The consequence of H/I/J/K, since a reader should not have to derive it.**
Because soft and hard AES compute the same function, the hard-AES column cannot
catch a wrong hash that the soft-AES column would have missed — anything the
two branches agree on, they agree on wrongly together. What the hard-AES column
buys is different and narrower: it exercises code generation and VM
instantiation that were previously never reached at all (`...HardAes`,
`...HardAesSecure`, and both patch sites' other arm), so it catches a defect in
*that* code — as mutation L does — rather than a defect in AES itself. Anyone
reading "hard AES passes" as independent confirmation of the digests is reading
more into it than it says.

**The light path and the dataset path are different a64 code, and a light-only
harness misses half of it.** This was found by mutation, not by reading.
Swapping the dataset path's v2 tweak
(`randomx_program_aarch64_vm_instructions_end_v2`) for the v1 one is invisible
to every vector run in light mode, because light mode reaches a *different*
symbol (`..._end_light_v2`). The same swap on the light symbol fails eight
vectors, the Commitment vector and every sweep input, while rx/0 stays green
throughout — the exact signature of a version-selective codegen fault. The
harness now runs the full-dataset path too, behind `RX_FAST=1`, and the
mutation that survived the first version is killed by the second. **A miner
runs the dataset path**, so this was the half that mattered.

**An epoch-boundary soak has run on rx/2.** On the small-params local net at
`randomx_key_interval: 16`, `randomx_key_lag: 2`, five-second blocks, engine
`randomx-v2`, amd64, six threads: **836 blocks, 52 seed-epoch boundaries
crossed, 0 rejected, 0 reorgs, 0 undone, deepest reorg 0** — a single distinct
value across every status line of the run. The node was stopped at height 339
and cold-started against the same directory; it reloaded the chain, re-verified
it and continued mining, which exercises verification across those boundaries
from disk rather than from warm caches. The first boundary landed at height 18,
as [`localnet/README.md`](../localnet/README.md) predicts. Against mainnet's
`randomx_key_interval: 2048` at a thirty-second block, that many boundaries is
something over a month of mainnet re-keys.

The status lines are committed at
[`localnet/soaks/rx2-epoch-boundary.txt`](../localnet/soaks/rx2-epoch-boundary.txt)
rather than only quoted here — 239 samples over the two runs, every one of them
`undone=0 rejected=0 reorgs=0 deepest=0`, so the numbers above can be checked
instead of taken.

**The shipped local-net recipe could not be run at all, which the soak found
before it could measure anything.** The file declared `randomx-v1` — not the
function either shipped network declares, so a soak on it would have rehearsed
the wrong engine — and pinned `genesis_time` to 2026-09-06T00:00:00Z, so a node
started before that date correctly refuses to date a block before genesis,
reports how long it will wait, and mines nothing. The soak ran on a copy with
both corrected. Both were then fixed on `dev` independently and identically
while this pass was running, so the file in the tree is now right; what
survives here is the guard. `sim/wiring`'s engine check pinned the literal
`randomx-v1` for as long as mainnet declared rx/2 — it was enforcing the drift
rather than catching it — and now reads the value from mainnet, so the two
cannot separate again without a test saying so.

**Hostile headers now have a test.** `core/pow/hostile_test.go` drives the work
check with saturated and malformed headers — `height = 2^64 - 1` among them,
because the key comes from the height and `KeyFor`'s arithmetic is what lets
`CheckWork` be total — and requires that it never panics and never accepts one.
The reserved gap gets the same treatment with every field an attacker controls
saturated. Both fail under mutation; the rows are below.

#### Mutations run, and the survivor

| | mutation | result |
|---|---|---|
| A1 | a64 JIT: dataset path takes the **v1** tweak under `RANDOMX_FLAG_V2` | **survived** the light-only harness; killed once `RX_FAST` was added |
| A2 | a64 JIT: light path takes the **v1** tweak under `RANDOMX_FLAG_V2` | killed — 8 vectors, the Commitment vector and every sweep input, rx/0 green |
| H/I/J/K | a64 JIT: force either AES branch to take the other, at either generator | **survived, and correctly** — the two branches are two implementations of one AES, and upstream's vectors are what require them to agree |
| L | a64 JIT: the hard-AES arm zeroes `v29` instead of `v28`, so the fall-through `aese`/`aesd` mix against a key the JIT never cleared | killed on the DIGEST — every rx/2 hard-AES row and the hard-AES commitment vector fail, while rx/0 and every soft-AES row stay green |
| C | `PoWInput` writes the nonce's high byte into reserved byte 32 | killed |
| D | `checkWorkWith` drops the digest-identity half | killed |
| E | `CheckCommitment`: `Gt` → `Gte`, turning `commitment <= target` into `<` | **SURVIVED, and no test was written for it — see below** |

**E is a real unpinned consensus rule and it is recorded as a residual rather
than covered, because a test that covered it would be vacuous.** The mutation
changes the rule only where `commitment == target` exactly. `Target` sits inside
`PoWSeed`'s preimage, so the commitment is a function of the target, and a
header where the two are equal is a fixed point of BLAKE2b∘BLAKE3 — a 1-in-2²⁵⁶
search. Measured: five rounds of "set the target to the commitment and re-seal"
walk to five unrelated values. **No header a test or an attacker can construct
distinguishes `Gt` from `Gte`**, which is also why the mutation survives
`go test ./core/... ./spec/...` and the whole `-tags randomx` package including
the cross-vector tests. A first draft of a test for it was written, found to
pass under the mutation, and deleted rather than shipped — the failure mode
8.5a's last paragraph describes, caught this time before the commit.

The rule is unreachable in both directions, so nothing is exploitable by it.
What it costs is that the `<=` in `CheckCommitment` and the `!...Gt` in
`Solver.TryHash` are load-bearing text no test defends: a future edit that
flipped **one** of them would produce a miner disagreeing with its own verifier
on a set of headers of measure zero, and nothing would say so.

**One inaccurate comment, no defect.** `node/miner.SealWhile` says the winning
digest "is stored BEFORE the flag, so that a reader which observes `found` also
observes the matching hash". The code stores it *after* the
`CompareAndSwap`. The pair cannot actually tear — every consuming read of
`winner` and `winnerHash` happens after `wg.Wait()`, and the CAS admits one
writer — so the safety is real but comes from the join, not from the ordering
the comment claims. The comment should be corrected to say so.

#### What is still open going into the freeze

- **Real arm64 hardware.** Emulation covers code generation, now including the
  hard-AES branch a real miner takes; it does not cover a real core's cache
  coherency around self-modifying code, and that is precisely where the JIT is
  most exposed. One command, no project — but it has not been run on a chip,
  and the emulator agreeing is not the chip agreeing.
- **The line-by-line read of the ~800-line delta.** *Closed on the compiled
  surface by section 8.9 below; still open for RISC-V, which this build does
  not compile.* This pass was differential and mutation-driven: it puts
  pressure on the code generators from outside rather than reading them. §4's
  ask is discharged for the code that ships and explicitly not for the code
  that does not.
- **The 1-in-2²⁸ class of bug is not excluded by any of this.** The sweep is
  hundreds of inputs against a defect density of roughly one in 268 million.
  What the sweep can catch is a generator wrong on a broad class of programs;
  what it cannot catch is one wrong on a rare one. Only volume closes that, and
  the relaunched testnet is the volume — it is now live on rx/2, so this is an
  item being worked off by the network rather than one waiting on a decision.
- **The hard-AES sweep is a tenth as deep as the soft-AES one, and the
  hard-AES full-dataset cells have not been run.** Hard AES has 40 swept inputs
  against soft AES's 400, and `RX_FAST=1` has only ever been run under soft
  AES. Running `sh core/pow/randomx/arm64/run.sh <n>` with a larger `n` and
  `RX_FAST=1` closes both and needs nothing but emulator time — the cheapest
  open item on this list.
- **No soak on arm64**, and none under emulation either — the soak is a running
  node, and the node is not cross-compiled. Every soak number here is amd64.
- **The harness builds `-O2` against the cgo build's `-O3`.** It does not
  weaken what is checked — the emitted machine code comes from `emit32` with
  fixed constants rather than from the optimiser, and the interpreter and
  helpers that the level *could* change are pinned by upstream's vectors in
  both modes — but no timing from a harness run is a hashrate.
- **Still the first production user.** §5's standing risk is untouched: Monero
  has not activated rx/2, and "a stock XMRig binary found a block on this
  chain" remains unproven for rx/2. Nothing in this pass could prove it, because
  nothing in this tree can run XMRig.

### 8.9 The line-by-line read, and what it leaves open

The gap 8.6 named first and 8.8 left open — "**the ~800-line delta between
v1.2.3 and v2.0.1 has never been read line by line**" — was read. The findings
are in [I8-randomx](../adversarial/I8-randomx.md); this section records only
what moved, because this is the section the freeze decision is taken against.

**Nothing found is a consensus defect, and nothing found is memory-unsafe on
any path a peer can reach.** That was the read's first priority and it is the
one result worth stating without qualification.

**The denominator was wrong, and correcting it is most of what made the read
tractable.** The full `v1.2.3..v2.0.1` diff over `src/` minus `tests/` is
**4,428 insertions across 65 files**, not ~800 lines. But `vendor.sh` compiles
14 of those files: the rest is RISC-V (~2,450 lines, in no source list), the
MASM variant of the x86 assembly, and test code. **The compiled surface is
~1,650 changed lines across 32 files, and all 32 were read.** §4's "~800 lines
concentrated in two JIT generators and hand-written assembly" is an accurate
description of the compiled half; it was never a description of the whole diff.

**The most valuable thing the read found is a line that is correct.**
`RandomXCodeSize` in `jit_compiler_x86.cpp` is computed from
`RANDOMX_PROGRAM_MAX_SIZE`. Because rx/2's programs are 384 instructions
against v1's 256, and because the x86 JIT's four `emit` primitives have **no
bounds check of any kind**, that single identifier is the whole of what
prevents the generator writing past its allocation. Compiling the worst case —
all 256 opcodes swept, 384 instructions each — reaches **13,442 bytes against
a 16,384-byte buffer** on the mining path and 13,495 on the light one.
Recomputing the bound from the v1 constant, one identifier changed, **overflows
it by 1,154 bytes** into the superscalar-hash region, on every hash, on miner
and verifier alike. Upstream got it right; nothing in this tree was checking
that they had. `TestTheJITCodeBufferIsSizedForTheLargerV2Program` now checks
it, in the no-build-tag half of the package so it runs without a C toolchain,
and all five properties it pins were mutated and all five mutations kill it.

**The arm64 generator has the same invariant and it lives in assembly**, which
is the part most likely to be missed on a future tag bump: the a64 JIT patches
a fixed template rather than emitting a free-standing program, so the slot the
program body goes into is a `.fill RANDOMX_PROGRAM_MAX_SIZE*12` in
`jit_compiler_a64_static.S`, and its `emit32` is an unchecked store exactly as
x86's is. That `.fill` is pinned by the same test.

**Two things that read as defects and are not, both recorded so they are not
re-investigated.** `generateProgram` advances `codePos` by v1's
`readDatasetSize` after copying either block — safe only because assembling the
static file shows both blocks are **66 bytes** (v2 reorders the same seven
instructions), and fragile if upstream ever lengthens one. And
`randomx_init_dataset`'s new `itemCount < 4` branch fills a 256-byte **stack**
buffer from JIT-generated code; it is unreachable from this binding because
`DatasetItemCount` is 34,078,719 ≡ 3 (mod 4) and no span across worker counts
1–64 is ever smaller than 4. The same enumeration shows the new unaligned
branch's overlapping tail write never crosses a worker boundary, so
`initDataset`'s concurrency assumption survives v2's rewrite.

**Three consensus-critical agreements were checked rather than assumed.**
CFROUND's new `isrc & 60` guard agrees across the interpreter, the x86 JIT
(`60 << 13` after a compensating `rol 13`) and the a64 JIT (`0xF27E0E9F`
decoding to `tst #60`) — the last two by decoding the immediates, since neither
is legible as `60` in the source. rx/2's dataset-pointer change — modifying
`ma` before the swap rather than `mx` after it, and reading from the pre-XOR
`ma` — was modelled from both the interpreter and the assembly and compared
over **600,000 random states under both versions with zero mismatches**, with
two plausible mis-implementations each killing the model at a 100% rate. And
the masked dataset read is in bounds by construction with **zero slack**: the
largest possible read ends at exactly `DatasetSize`.

**What the read closed on arm64, and what it did not.** Cross-assembling
`jit_compiler_a64_static.S` and reading the symbol table shows that **every
patched instruction on both the light and full paths falls inside the
`__builtin___clear_cache` range**, which is not visible from the source because
`codePos` is repositioned to label offsets rather than advanced. The one write
outside the range, `aes_lut_pointers` on the v2 soft-AES path, is a `.fill`
data slot consumed by `ldp` and correctly needs no I-cache maintenance. **This
does not weaken 8.8's arm64 caveat in the slightest.** It is static reasoning
from label offsets; it says the code generator emits the right bytes and clears
the right range, and it says nothing about a real core's cache coherency around
self-modifying code. **The real-silicon run is still owed.**

**The pinning pipeline was verified rather than trusted.** 8.2's two fixes both
hold: the tree hash is identical under four caller locales with `LC_ALL=C` and
**the bug reproduces exactly** (`d96521a5…` under `en_US.UTF-8`) without it; a
fresh clone recomputes the pinned hash, so the CRLF fix holds where it matters.
And the stronger claim was checked directly rather than through the hash —
`git archive` of the pinned commit, tests removed, `diff -r` against the
vendored tree: **no differences.** The vendored bytes are upstream's, verified
against upstream rather than against a number this repository wrote itself.

#### What section 8.9 does NOT close

- **The 1-in-2²⁸ class of bug is untouched by a read, and this is the important
  one.** Reading finds defects that are wrong on their face. The v2.0 bug that
  motivates all of this was wrong on roughly one input in 268 million and would
  have read as perfectly correct. 8.8's judgement stands unchanged: only volume
  closes it, and the testnet is the volume.
- **Real arm64 hardware.** Unchanged from 8.8, and 8.9 adds only static
  evidence. The emulator agreeing is not the chip agreeing, and neither is a
  symbol table.
- **The RISC-V delta, ~2,450 lines, was not read.** Justified because
  `vendor.sh` compiles none of it. If this chain ever ships a RISC-V build,
  that code is unaudited and this sentence is the record that it is.
- **`jit_compiler_x86_static.asm`**, the MASM variant, was not read; the GNU
  `.S` is what this build assembles.
- **Still the first production user.** §5's standing risk is untouched by a
  read of the source, and "a stock XMRig binary found a block on this chain"
  remains unproven for rx/2.
