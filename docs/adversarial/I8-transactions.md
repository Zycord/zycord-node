# Zycord — Implementation Findings I8: the transaction path

**Scope:** the whole life of a transaction — construction, signing, admission, the mempool, inclusion in a block, and the state transition. `core/fold`, `core/validity`, `core/state`, `core/crypto`, `node/mempool`, `node/miner`'s selection, and the native operations in the fold. Read against the money path as it stood after F8b, the burst valve, B18's block ceilings and the epoch controller, and before the builder change I8-M1 below produced — with the public testnet live on it.

**Persona:** the auditor who assumes the *reading* is worthless. I1 audited this surface at M0, when it was four programs and a fold. Everything since has been networking, proof of work and the ceilings; the money path has been extended — F8b, the burst valve, B18, the epoch controller — without being re-attacked as a whole. So the question here is not "is the code well argued", because it is, extravagantly. It is **which of these arguments is load-bearing and which is decoration**, and the only instrument that answers that is a mutation that should fail and does.

The headline is a negative result and it is the right one: **fourteen mutations across the money path, fourteen killed.** No vacuous test was found on this surface. The one defect below was not found by reading the fold at all — it was found by asking which block rules the *builder* enforces, and discovering that the answer is four out of five.

---

## I8-M1 — The builder enforces four of the five block ceilings, and the fifth stops the node ⬜ *open; latent on mainnet, live on devnet*

`miner.Select` packs a block against B12 (certificate count), B13 (bytes), B5 (sequential gas) and B6 (parallel gas). It never sums `len(c.Sigs)`, so it does not enforce **B18**, the per-block signature ceiling. B18 shipped after `Select` was written and the packing loop was not revisited.

An over-B18 block is not invalid-and-shipped — `Chain.Apply` is authoritative and refuses it. The defect is that the refusal is **unattributable**, and that removes the miner's only recovery path:

- B18 reports through `invalid()`, not `invalidCert(i, …)`. That is *correct*: it is a genuine block-level property with no single culpable certificate, exactly as B5, B6, B12 and B13 are.
- `dropTheDrops`' recovery is `errors.As(err, &cre)` against `*fold.CertRuleError`. With no index there is nothing to exclude, so control reaches the "not attributable to any one certificate" arm and returns the error.
- `Assemble` propagates it; `MineOneWhile` returns without retrying. **There is no empty-block floor on that path** — the `return nil, nil` floor sits *inside* the `CertRuleError` branch B18 never enters.

So a pool holding enough signature-dense certificates stops the node producing blocks at all, and keeps it stopped. Nothing sheds them: they are individually valid, the pool admitted them under its own rules, and `Pool.OnBlock` — which would clear them — runs only downstream of a successful `Apply`, which never happens. The same failure reaches `node/stratum`, where `Assemble` failing means `newJob` fails and every connected miner stops receiving work.

**Measured, end to end, on devnet.** Twenty-five RETIRE certificates of sixteen signatures each, funded for real out of mined coin and admitted by the node's own mempool (25 of 25):

```
attempt 1: Assemble failed: miner: candidate block is invalid: fold: invalid block: B18: 400 signatures exceeds the ceiling of 384
attempt 2: … (identical)
attempt 3: … (identical)
```

`node/miner/sig_ceiling_test.go` carries the witness at three altitudes: `Select` returns a set over the ceiling, the fold's refusal of that set carries no index, and `Assemble` fails on three successive attempts. Each is armed against measuring the wrong ceiling — the fixture fails if its own pool exceeds B12, B13, B5 or B6, so a witness that stopped separating B18 would say so rather than pass.

### Why this is MEDIUM and not HIGH, stated as a measurement rather than a hope

**It is not reachable on mainnet or testnet with any Era-0 shape.** Swept across both signature-dense families and four signature widths:

| network | shape | width | Select took | vs B18 | over? |
|---|---|---|---|---|---|
| mainnet | RETIRE | 16 | 283 certs / 4528 sigs | 6000 | no |
| mainnet | RETIRE | 2 | 2133 certs / 4266 sigs | 6000 | no |
| mainnet | fan-in TRANSFER | 16 | 350 certs / 5600 sigs | 6000 | no |
| mainnet | fan-in TRANSFER | 2 | 1967 certs / 3934 sigs | 6000 | no |
| devnet | RETIRE | 16 | 25 certs / 400 sigs | 384 | **yes** |
| devnet | fan-in TRANSFER | 2 | 193 certs / 386 sigs | 384 | **yes** |

On mainnet, B5 binds first — at **99.9%** of the sequential ceiling — and stops the builder at 4528 signatures against a ceiling of 6000. The margin is **24.5%**.

**And the margin is structural rather than lucky**, which is the part that decides whether the freeze can leave `Select` as it is. `SeqGasLimit(t) = 2t` and `MaxSigsPerBlock(t)` both scale linearly and unclamped in T, so the ratio is preserved across the whole range the epoch controller can move T through — from `SeqGasTargetGenesis` to the `SeqGasCapacity` clamp at 3.2× genesis:

```
T=1600000 (1.00x): 4528 sigs vs 6000 -> margin 24.5%   seq 3197900/3200000
T=2400000 (1.50x): 6784 sigs vs 9000 -> margin 24.6%   seq 4791200/4800000
T=3200000 (2.00x): 9056 sigs vs 12000 -> margin 24.5%  seq 6395800/6400000
T=4000000 (2.50x): 11312 sigs vs 15000 -> margin 24.6% seq 7989100/8000000
T=5120000 (3.20x): 14400 sigs vs 19200 -> margin 25.0% seq 10170000/10240000
```

So a live mainnet chain cannot walk into this by growing. What *would* open it is a parameter change, and the two that do are exactly the kind under discussion before a freeze: **`max_sigs_per_block_genesis` below 4528**, or the binding gas ceiling raised by **33%**. Either is a one-line edit to `spec/params.json` that no test would currently refuse, because nothing anywhere asserts the relationship between what `Select` packs and what B18 admits.

**Disposition.** The fix is one accumulator in `Select`'s packing loop, beside the three already there. What should not be done is making B18 attributable — it is not a property of any one certificate, and forcing an index onto it would be a worse rule to buy a better error message. The second, cheaper half is that `dropTheDrops`' non-attributable arm should fall back to a truncated list rather than to no block: **B18 is the first block rule to reach that arm, and any future one reproduces the same total stall.** That is the durable half of this finding.

---

## I8-N1 — Fourteen mutations, fourteen killed ✅ *the negative result*

The money path's safety properties are armed. Each mutation below was applied to the shipped source, run against the scoped suite, and reverted. None survived.

| # | Mutation | Killed by |
|---|---|---|
| M1 | B3 seen-set replay check disabled | `TestReplayOfAnAppliedCertificateInvalidatesTheBlock`, `TestACoSignerCannotReSignOneBodyIntoASecondBillAcrossBlocks` |
| M2 | F3 deposit balance check disabled (spend without funds) | `TestConservation`, `TestDroppedIsNotBilledAndNotSeen`, `TestGoldenVectors` |
| M3 | V1 chain-id binding removed (cross-network replay) | `TestV1/wrong_chain`, `TestEveryRejectionTermIsSeparated` |
| M4 | B1 TTL bound removed (withhold-and-bill-later) | `TestGoldenVectors/invalid-expired` |
| M5 | B8 in-block duplicate check removed | `TestOneAuthorizationCannotBeAmplifiedAcrossOneBlock`, `TestASingleSignerCannotReSignOneBodyIntoTwoBills` |
| M6 | F8b `sweepBurned` disabled (strand value under a burn) | four `one-shot-burn-*` golden vectors |
| M7 | `settle`'s refund-to-burned check disabled | `TestBurnedRefundIsReported`, `TestBurnWithADeadRefundAddressStrandsAndAccountsForNothing` |
| M8 | Coinbase ring spent-payee check disabled | `TestGoldenVectors/coinbase-burned-into-a-payee-spent-in-the-same-block` |
| M9 | V6 one-shot MARK_SPENT requirement removed (one-shot reuse) | `TestV6/one-shot_debit_without_a_burn` |
| M10 | V4 minimality removed (a signature authorising nothing) | `TestV4/superfluous_signature` |
| M11 | V3 write-set equality removed (declare writes the program does not derive) | `TestV3/inflated_credit` |
| M12 | `VerifyStrict` torsion-free check removed | `TestMixedOrderKeysAreRefused` |
| M13 | `VerifyStrict` low-order key check removed | `TestIdentityKeysForgeEverySignature`, `TestLowOrderKeysAreRefused` |
| M14 | V5 deposit-covers-ceiling check removed | `TestV5/under-reserved` |

Two observations are worth more than the table.

**The golden vectors are the fastest gate and they are byte-level.** M2, M4, M6 and M8 were caught by `spec` in under seven seconds each, naming the vector. A money-creating change to the fold does not need the 264-second `core/fold` suite to be noticed; it moves committed bytes. That is the property the corpus exists for and it is real.

**M2 is the one worth dwelling on.** Disabling F3's insolvency check does not merely let an unfunded certificate through — the following `remaining, _ := balance.Sub(...)` discards its underflow flag, so the deposit cell wraps to near-2²⁵⁶. It was caught by `TestConservation` *and* by two golden vectors *and* by `sim`'s differential fold, by three independent routes. During this audit a parallel reader observed the mutation mid-run and reported it as a live defect in the tree; it was not, and the tree was verified clean immediately after. Recorded because the false positive is itself evidence: **the sabotage was legible to a reader who had never seen the mutation list**, which is the property a consensus tree wants.

---

## I8-N2 — `mempool.Readmit` is wired, and the prior finding is closed ✅

I4-H2 recorded `Readmit` as "correct, complete, and called from nowhere". It is now called from three places: `node/p2p/engine.go`'s reorg path, `node/p2p/syncdriver.go`'s sync-driven reorg, and `node/chain`'s reorg TTL test. `sim/wiring` enforces the general shape — a definition with no non-test caller fails the build — and names this defect and I4-H2's `node/sync` as the two prior instances. Nothing further to report; the finding is closed and the mechanism that would have caught it exists.

---

## I8-L1 — Two invariants held at a distance, neither asserted where it is relied on ⬜ *open, documentation-shaped*

Neither is a defect today. Both are places where a correct behaviour depends on a rule in another file that does not know it is load-bearing, which is the shape that survives a refactor and stops being true.

**`State.Undo`'s seen handling depends on B1.** `UndoLog.SeenAdded` and `SeenRemoved` must be disjoint, or the delete clobbers the restore and a reorg silently loses a seen entry — which is a replay window. They are disjoint only because B1 enforces `c.TTL >= h.Height` while `PruneSeen` removes only `ttl < h.Height - 1`, and `markSeen` runs strictly before the prune. Three facts in two packages, none of which cites the others. Weakening B1 to admit `c.TTL < h.Height` would make `Undo` lossy with nothing failing.

**`Select` and B18 have no stated relationship at all.** I8-M1 is the live instance. The 24.5% margin is a consequence of the gas schedule and nobody wrote it down; a parameter change spends it silently.

The general form is the one I6-M1 already named: a safety property whose argument lives in a comment in a different package is a property with no instrument. Both want a test that fails when the coupling breaks, not a paragraph.

---

## What I attacked and could not break

Recorded because a list of what held is worth as much as the finding, and because "I did not look" and "I looked and it held" are different claims.

**Money.** Conservation is `supply_after = supply_before + Emission(height) − burned`, checked over a block containing an applied certificate, a self-inflicted skip and a drop, with an anti-vacuity guard requiring the burn to be non-zero. M2 kills it. The identity counts the treasury without being told it exists, because the treasury is an ordinary native balance cell — which is why the burst forfeiture and the burned coinbase both had to be registered as burns rather than as reduced credits, and both are.

**Replay.** Three layers, each independently armed: V1 binds the chain id inside the signing message (M3), `SigningMessage` binds the consensus root so a respin invalidates every certificate of the previous incarnation, and B3's seen set is keyed on an id whose preimage excludes the signatures (M1, M5). The signature-exclusion is what makes one authorization have one key; with signatures in the preimage a required signer could mint fresh ids from the others' authority, which the tree records as measured at 2× a single transfer's value in one block.

**Malleability.** The id is over the body, the exemplar hash is over the bytes, and the block's cert root commits to exemplars. A permuted or re-nonced signature list is a second exemplar of one authorization: refused in-block by B8 and across blocks by B3. Sorting is strict-increasing on reads, writes and signatures at both the decoder and V1, so no structure has two encodings.

**One-shot addresses.** V6 requires the burn (M9), F8b moves the residual to the certificate's own signed refund address (M6), `settle` refuses to refund into a dead cell (M7), and the coinbase ring refuses to mature into one (M8). The documented residual — a balance in an asset the certificate never names is unreachable and still lost — is recorded in `docs/decisions/one-shot-burn-scope.md` route 3 as an accepted loss, and I did not find a fifth route.

**Determinism.** No `time.Now`, no `math/rand`, no float, no goroutine anywhere in `core/state`, `core/ssz`, `core/fold` or `core/validity`. Every map iteration whose result reaches a return value or a state write sorts first. `refreshLeaves` derives leaf liveness from the maps rather than from write history, so a key deleted and re-added, or zeroed and restored, lands in its canonical position regardless of the sequence that produced it. `foldOrder`'s comparison is total — two entries tie only on identical ids, which B8 forbids within a block — so `SliceStable` is not doing load-bearing work and proposer input order is not observable in the state root. The seen set is excluded from the root entirely, which is what makes the prune schedule unable to move it.

**The differential is genuinely independent for the fold.** `sim/refold` imports neither `core/fold` nor `core/state`; it uses `math/big` against the reference's u256 limbs and reimplements F8b, the coinbase ring, the burst valve and the epoch controller. It does import `core/validity`, so the V-rules are shared and differentiated only by their own vectors — stated in the package's own doc rather than hidden. The one genuinely self-referential surface, `ssz.ListRoot` on both sides of the root comparison, is already known and already remediated by `core/state/naive`, whose independence is enforced by a Makefile import-count check rather than by discipline.

---

## What I could not reach

- **Whether B18 is reachable on mainnet with a shape I did not construct.** I swept the two signature-dense Era-0 families at four widths each. The bound is the gas schedule, not my imagination, and the 24.5% margin is measured at every T — but the sweep is a sweep. What would settle it is a search over the certificate shape space maximising signatures per unit of sequential gas, which is a small optimisation problem nobody has posed.
- **The refund-cascade depth against `maxDropPasses = 4`.** The miner's own comment records that an attempted cascade witness collapsed into a single pass and was removed rather than kept as a test asserting less than its name. I did not construct one either. It is a revenue question rather than a validity one, and it is honestly labelled in the source.
- **Whether the pool's admission rules would shed an I8-M1 flood before it reached `Select` on mainnet parameters.** On devnet the flood was admitted 25 of 25 once funded. Mainnet's aggregate deposit screen prices the same flood far higher in capital, and I measured the capital but not the pool's behaviour at that scale.
- **Anything about live testnet behaviour.** Every measurement here is from the suite on this tree.

---

## Disposition

| | |
|---|---|
| I8-M1 | ⬜ open — `Select` does not enforce B18; latent on mainnet behind a 24.5% margin that is structural across the range of T, live on devnet. Two fixes: one accumulator in `Select`, and a truncating fallback on `dropTheDrops`' non-attributable arm |
| I8-N1 | ✅ fourteen mutations across the money path, fourteen killed; no vacuous test on this surface |
| I8-N2 | ✅ `mempool.Readmit` wired in three places; I4-H2 closed |
| I8-L1 | ⬜ open — two invariants held at a distance (`Undo`↔B1, `Select`↔B18), neither asserted where relied on |

**What this pass should be read for.** Not the fold, which held against everything I could aim at it and whose tests are real. The finding is that **the block rules are enforced twice — once by the fold and once by the builder — and only one of those two lists is complete.** The fold's list is the one that decides validity, so the gap does not corrupt state; it stops the node instead, on the one rule whose refusal carries no index to recover from. Before the freeze, the cheap question to ask of every block-level rule is not "does the fold check it" but "does the builder respect it, and what happens to a node that finds out it does not".
