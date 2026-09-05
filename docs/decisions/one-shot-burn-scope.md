# Zycord — A burn is address-scoped, and the rule that guards it is an effect rather than a verdict

**Scope:** what happens to what a one-shot (`0x01`) address still holds when a certificate burns it. Raised after an earlier proposed fix — `AccessGuardEQ` on the debited slot, §5 — was found to close one of the four routes to the same loss. The same defect reached from the wallet side is a node that understates a balance; `docs/WALLET.md` rule 1 is that half.

**Verdict:** the loss was real on every route and is closed by **F8b**, which moves the residual to the certificate's own refund address at commit. The rule that suggests itself first — *refuse the burn unless the address is empty* — is refused here with a proof, not a preference: it makes a fold verdict a function of a balance any stranger can raise, which is precisely the case whitepaper §5's attribution theorem forbids. That mistake was made, measured, and is written up in §4 rather than deleted, because the general lesson is the durable part: **no fold rule's verdict may read a cell a stranger can credit.**

---

## 1. The invariant, and the two scopes that did not meet

A one-shot burn is **address-scoped**. `MARK_SPENT` names `SpentSlot(addr)` — a slot whose word is all zeroes and "belongs to no value" (`core/types/slots.go`) — and once it lands, every read and write under the *whole address* fails forever. That is the whitepaper's write-once cell: "a signature from its key moves it to *spent*, permanently" (§4).

Every guard Era 0 derives is **slot-scoped**, and a lower bound. `deriveTransfer` emits `AccessGuardGE` on `BalanceSlot(src, asset)` — *this cell holds at least what I am taking*. And the deposit cell carries no read at all: F3 debits it outside the write set, so `Derive`, which is the Era-0 instruction set and nothing else, never sees it.

The invariant nothing expressed:

> **A certificate that burns a one-shot address must not destroy what it did not account for.**

Whitepaper §3 says where a condition of this shape belongs, in the imperative — "**Writes are checked, and checked before any of them lands**" — and §4 says what for, in a sentence written about a different instance of the same failure: "Value destroyed in silence, with nothing in the fold failing, is precisely what the staging step of §3 exists to prevent." A burn that strands a balance is exactly that: an `APPLIED` certificate, no error at any layer, drops under an address no key opens again.

## 2. The routes, measured on `main` before the fix

Every figure below is from `core/fold/oneshot_scope_test.go` run against the unfixed fold. Devnet parameters.

| Route | Shape | Stranded |
|---|---|---|
| 1 | A moveless program (`ISSUE`, `MINT`, `RETIRE`) whose one-shot deposit cell reserves only the fee ceiling. There is no move to sweep with. | **813,735,000** of 900,000,000 drops |
| 2 | A `TRANSFER` whose one-shot deposit cell is not a move source. `withDepositMarkSpent` burns it; derivation guards only move sources. | **833,930,000** of 900,000,000 |
| 3 | A balance in an asset the certificate never names. | the whole asset balance |
| 4 | A sweep sized against a balance a single unaudited node understated. `GUARD_GE` is satisfied by any figure at or below the truth. | **600,000,000** of 900,000,000 |
| — | A `RETIRE` of an address that still holds a balance. No debit anywhere in the certificate. | **100,000,000** of 100,000,000 |
| — | A `TRANSFER` moving *part* of an asset balance out of a one-shot address whose native cell the reservation empties. | **400,000** of 500,000 of the asset |

`AccessGuardEQ` on the debited slot — the superseded proposal — reaches route 4 and nothing else. Routes 1 and 2 have no read on the cell that burns; route 3 has no slot the certificate names.

## 3. The rule

**F8b.** At commit, after F8 has landed the writes and the registry entries: for every address `a` that this certificate marks spent, and for each of

- `a`'s **native balance cell**, and
- every cell under `a` that **this certificate itself names** in its write set,

whatever the cell still holds is moved to the same *word* under `Deposit.RefundTo.Addr`, and the source cell is zeroed. A destination whose authority some **earlier** certificate burned, or whose cell would carry past 2²⁵⁶, is **not written**: the value stays exactly where it was, which is what the fold did before F8b existed. The outcome reports `swept` and `swept_stranded` beside `refunded` and `refund_burned`, both counting native drops only. `core/fold/fold.go`, `sweepBurned`; mirrored in `sim/refold/refold.go`.

**F8b never destroys value and never fails, and §4a says why that is not a style choice.**

**Why `Deposit.RefundTo`.** It is the certificate's own declared change address: inside `SigningMessage`, so every signer signed it; V5 requires it to be a native balance cell of a user address; and V5 forbids it from naming any address this certificate marks spent. So the destination is named by the certificate, chosen by its signers, and provably still spendable when the sweep runs. There is no other address in an Era-0 certificate with all three properties.

**The derived read set does not move.** `deriveTransfer` still emits `AccessGuardGE`, `core/validity/derive.go` is not in the diff, and V3, V6 and every vector's declared reads are untouched. Wallets build the same certificates they built before.

## 4. The design that was wrong, and why it is written down rather than replaced

The first implementation of this decision refused the burn: a certificate that would mark an address spent while its native cell was non-empty became `SKIPPED_STALE`. It closed every route in §2, it passed the full suite, the differential fold, and all three lemmas that pin §5's attribution theorem — and it was wrong.

**Whitepaper §5, verbatim:** "A billed skip is always exactly one of three things … **No party the certificate does not name can cause it to be billed.**"

A verdict that reads a cell's balance is a verdict a stranger operates, because a credit needs no signature. Measured, one block, the griefer's addresses appearing nowhere in the victim's certificate — not source, destination, signer, deposit or refund:

```
found low one-shot underwriter after 1 derivations: 01137e0a27b7 < 014d37b29d0a
griefer outcome=APPLIED        charged=1780380
victim  outcome=SKIPPED_STALE  charged=1000000
victim burned=false balance=833930001
```

The cost ratio was not the one the `AccessGuardEQ` proposal assumed either. That proposal measured the griefer at 727,282 drops, which is the *test helper's* fee bid; a griefer has no reason to tip, because F1 orders by `(underwriter id, seq, cert id)` and never by fee. At zero priority:

| attack | griefer pays | victims pay | ratio |
|---|---|---|---|
| one 1-drop dust, `Bid(50_000, 0, 500, 0)` | **107,822** | 1,000,000 | **9.3 : 1** |
| one multi-move `TRANSFER` dusting many one-shot addresses | ~170,000 | 1,000,000 × n | **~188 : 1** and up |

A claim from that design's own pull request is retracted here rather than quietly dropped: it said a griefer could not be ordered ahead of a sweep inside one block, because F1 sorts by underwriter and a `0x01` underwriter precedes every `0x02` one. True, and irrelevant — the griefer simply underwrites from a `0x01` address of its own that sorts lower, which took **one** key derivation to find.

**Three lemmas said the theorem was fine, because all three ask the wrong question.** `theorem_test.go`'s closure properties reason over *derived write sets*: which writes a program emits, and which of them require a signature. That is exactly right for a rule expressed as a write, and blind to a rule expressed anywhere else — and the skip rule was a staging condition, not a write. `TestCreditStormCausesNoBilledSkips`, the suite's poisoning-immunity scenario, could not see it either: it stormed a *persistent* victim, where no credit reaches any rule that decides an outcome.

The fix for the instrument is `TestLemmaNoUnsignedCreditChangesAnOutcome`, a fourth closure property that reasons over **outcomes** by running the fold: for a certificate that burns a one-shot address, no credit from a party the certificate names nowhere may change its outcome or its charge. Reinstating the skip rule makes it fail by name. `TestCreditStormCausesNoBilledSkips` now storms a one-shot victim as well, in a prior block — and the prior block is load-bearing: in the *same* block the victim's `0x01` underwriter sorts first, so a persistent stormer can never be evaluated before it and the case would test the fold's sort rather than its rules.

**The general rule, which is the durable part:** a rule that decides APPLIED versus SKIPPED from a balance is a rule any third party can operate. Rules of that shape belong after the verdict, as effects. This is the form the `BOND` design constraint in ARCHITECTURE §17 needs, and the form the cEVM will need.

## 4a. The second design that was wrong: destroying what it could not deliver

The revision that introduced F8b *destroyed* a residual it could not deliver and added the amount to `res.Burned`. Two defects followed, and both were invisible because the branch had no coverage at all: replacing it with a silent `return` left `go test ./...` green across 32 packages.

**A stateless-valid certificate could make every block carrying it invalid.** `res.Burned` is the block's **native** burn accumulator, bounded in every other caller by total supply. An asset cap is an arbitrary `u256` — `deriveMint` rejects only `amount > cap` and `cap == 0` — so the construction is: `ISSUE` with `cap = u256.Max`, `MINT` that cap to a one-shot cell, retire some address and name it as `RefundTo`, then `TRANSFER` one unit of the asset out. Measured on devnet:

```
one-shot holds 115792089237316195423570985008687907853269984665640564039457584007913129639935 of the asset
certificate passes validity.Check (V1-V9): it relays and is includable
BLOCK REJECTED: fold: invalid block: conservation assertion failed: accumulated burn overflows 256 bits
```

Permissionless, repeatable, and **not present on `main`**, because before F8b no attacker-chosen asset quantity ever reached `res.Burned`.

**And it broke the native conservation identity**, reachable without the huge cap: `after == before + emission − res.Burned` over `nativeSupply` is falsified the moment an asset amount is counted as destroyed native supply. Both implementations were wrong identically, so the differential agreed; and `res.Burned` is pinned in every golden vector and compared at `sim/differential.go`, so it is consensus-visible accounting.

**The fix is to make the branch do nothing.** F8b delivers, or it leaves the value exactly where it already was. Nothing enters `res.Burned`, no accumulator can overflow, and no certificate can invalidate a block through this path. The value left behind is reported as `swept_stranded` rather than being silent, and it can only happen when `RefundTo`'s authority was burned by an *earlier* certificate — V5 forbids the same-certificate case statelessly, and settlement is burning that certificate's own deposit remainder into the same dead address at F9, so `refund_burned` is non-zero on exactly these outcomes too.

**The overflow branch is unreachable, and the proof is written down because the branch cannot be tested.** MINT is the only creator of asset units and its `GUARD_LE` holds `minted ≤ cap ≤ 2²⁵⁶−1`; every other operation — TRANSFER, settlement, and F8b itself — only moves units between balance cells. So the balances of one asset sum to its minted total and no two of them can exceed it. Native supply is bounded far below 2²⁵⁶ by the emission schedule. The branch exists anyway, because a fold that reasons "this cannot happen" and then wraps is the failure mode checked arithmetic is here to prevent.

**Why the two counters are native-only, and what carries the rest.** `Swept` and `SweptStranded` count drops, like `Charged`, `Refunded` and `RefundBurned`. One `u256` cannot mean "400,000 of asset X plus 3 drops", and no other outcome field reports an asset amount — MINT and TRANSFER move assets and say nothing about them there.

That left the asset half of the leave-alone branch with no signal at all: a certificate whose reservation empties the native cell reports `swept = 0`, `swept_stranded = 0` and still leaves an asset balance under the burn. `StrandedCells` closes it and is deliberately **a count, not a sum** — a count needs no currency. It says *something was left*, which is what makes the loss loud, and a consumer that wants the amounts reads the cells under the address the outcome already names as burned. `spec/vectors/011` pins `stranded_cells: 2`; `TestAnAssetOnlyStrandIsStillReported` pins the case where it is the only non-zero field in the record.

## 4b. What F8b gives an understated sweep that it never had: a beneficiary

A certificate has one `Deposit.RefundTo` and may burn one-shot addresses belonging to several signers, so a residual under my cell can be delivered to somebody else's. Measured: Alice builds a two-source sweep with `RefundTo` = Alice's address; Bob's node understates his cell at 300,000,000 when it holds 900,000,000; Bob's 600,000,000-drop residual lands in Alice's cell. On `main` that value was destroyed and nobody gained.

This is a **new incentive, not a new loss** — the value was lost before and is merely redirected now — and it is closed wallet-side by `CheckBurnedResidualComesHome`: if a certificate marks spent an address **I control**, `RefundTo` must also be an address I control. Anything burned that is not mine is not my exposure; its owner runs the same check with their own set. **It reads no state at all**, which is exactly what makes it useful here: `CheckSweepsWholeCell` computes against the node's own number and therefore agrees with the lie, while this check reads only the certificate's bytes and the caller's own address set.

**It is a set and not a key, and that is a correction rather than a detail.** The first form compared each burned address against the same public key `RefundTo` derives from. Correct for a single-key wallet, wrong for the model the whitepaper describes: §4 generates a one-shot address per payment received and §12's stealth outputs ride the same rail, so a wallet with per-payment keys consolidates several of its own one-shot cells in one certificate — and the same-key rule refuses it, forcing the change into `persistent(K_payment)`, a fresh account per payment, which is exactly the linkage the one-shot rail exists to avoid. Measured: a 4-address batch retire refunding to the payer's own address, and a fresh one-shot sweep whose fee change went to the wallet's main address, were both refused under the same-key form. No *live* false positive existed — `zcd wallet retire` signs with a single key — but the reference wallet is single-key because it is a reference, and this is going into `docs/WALLET.md` as policy. `CheckAll` now takes the caller's owned addresses and `session.Owned()` supplies them.

Whitepaper §5's clause that a skip fee is "burned rather than paid, so nobody profits by triggering it" is about **skips**, and F8b moves nothing on a skip — so the clause is untouched. The principle behind it is not, and the wallet rule is the answer to the principle.

The cost is that a certificate funded by one party which burns another's one-shot address is now refused by the reference wallet. `zcd wallet retire` is unaffected (it deposits from the key's own persistent address), and a signer who genuinely means to send their residual to somebody else can send it with an explicit move, where the amount is in the bytes they sign.

## 5. Other rejected alternatives

**`AccessGuardEQ` for one-shot debits.** Insufficient and credit-sensitive: it reaches route 4 alone, and it fails the §4 test above for the same reason the skip rule does — an `EQ` read against a cell a stranger can credit is a verdict a stranger controls. That proposal recorded the cost as Scenario B and accepted it; the attribution theorem is the argument it did not have.

**Require *every* cell under the address to be empty (full address scope).** This is what the invariant literally asks for, and it is refused twice over. First, it is a verdict, so §4 applies. Second, even as an effect it is unreachable: `BalanceWord(asset) = blake3(tag ‖ asset)`, so a slot does not name its asset; `core/state` is a flat `map[Slot]U256` with no per-address index; and `/balance` (`node/rpc/rpc.go`) answers for an *explicit* asset, so a wallet cannot enumerate either. Sweeping everything would need a scan of the whole cell table inside the one stage that does not parallelise.

**Forbid crediting a non-native asset to a one-shot address.** Would make address scope and native scope coincide, statelessly and for free. Rejected: it removes asset payments to one-shot addresses entirely, which is the unlinkability the one-shot rail exists for (whitepaper §12's stealth outputs "ride this rail unchanged"). Closing a leak by deleting the feature is not closing it.

**Let the burn not happen when value remains — apply, and keep the address alive.** Rejected on the whitepaper: §4 says a signature from a one-shot address's key moves it to spent, *permanently*. A certificate signed by that key, applied, that left the address alive would contradict the primitive rather than guard it, and would give one address two spends.

**Accept and document (the status quo).** Rejected on the project's own contributing rule — "a wallet that only documents them has moved the problem to the user" — and because the wallet's check structurally cannot catch route 4: the only number it can check a balance against is the same node's report.

## 6. What the whitepaper says, and what is amended

**Nothing.** This is stated explicitly because the *first* design would have required amending three separate statements of the attribution theorem — `docs/whitepaper.md` §5, `docs/ARCHITECTURE.md` §9, and `docs/adversarial/I1.md` I1-H3 — plus the `BOND` constraint that is derived from it. F8b requires none of them, and that is the strongest evidence available that it is the right placement:

| Claim | Status under F8b |
|---|---|
| §4 "a signature from its key moves it to *spent*, permanently" | unchanged — every burn still lands, unconditionally |
| §4 "a skip occurs only when a guard genuinely fails … not when the balance merely changed" | unchanged — no new skip exists |
| §5 "no party the certificate does not name can cause it to be billed" | unchanged, and now defended by a lemma that can see this class |
| §11 `RETIRE` "no reads, no value moved, a pure write" | the program is unchanged; see below |
| §3 the staging step exists to prevent value destroyed in silence | satisfied, at commit rather than at staging |
| §3 "exactly one state touch per certificate … one touch per declared slot" | **strained, and named here rather than left to a reader.** F8b touches slots the certificate declares nowhere. The native half has precedent — settlement already writes `NativeBalanceSlot(RefundTo)` as a fold-level primitive exempt from guards and from the registry — but the *asset* half writes `Slot{Addr: RefundTo.Addr, Word: BalanceWord(asset)}`. The fold has always written undeclared slots — the two base fees, the gas target, the applied-gas sample, the cited count, the treasury, the beacon — so the novelty is not that, and saying it was would be false. It is that every one of those is a **fixed protocol cell at a fixed address**, enumerable by anyone, whereas F8b is the first *per-certificate* rule whose undeclared touch lands at a slot **derived from certificate data**: an address the signers chose, crossed with a word taken from a declared source slot. Nothing about consensus breaks: the fold is sequential and deterministic, and §7a shows the touches are bounded and paid for. That distinction is exactly why the forward reach is real: §10's forced queue takes "a deterministic lease on its slots", meaning *declared* slots, and a lease can enumerate the protocol cells but cannot enumerate F8b's destinations. Whoever builds that lease has to read this row. |

**§11 is the one that needs a sentence, and it is a clarification rather than an amendment.** F8b moves value on a `RETIRE` certificate that burns a funded address. `RETIRE`'s *program* is untouched — still no reads, still one pure write — and what moves is the retired address's own residual, into the certificate's own `RefundTo` cell, which settlement already credits on every `RETIRE`. The clause "moves no value" is contrasting `RETIRE` with **spending**, and `RETIRE` still cannot spend: it names no payee, takes no amount, and can send nothing anywhere its signer did not already declare as their own change address. `docs/ARCHITECTURE.md` §9 now says that in as many words rather than leaving it to a reader's inference.

The alternative reading — that §11 forbids any value movement on a `RETIRE` certificate — is named here rather than argued away, and it is worth being exact about what refutes it. *Settlement refunds the deposit remainder on every `RETIRE`* is **not** the refutation: for `zcd wallet retire` the deposit cell is the signer's persistent address, which is not the address being retired, so that is value leaving a different cell. The refutation is narrower and it is one of this PR's own measured routes: a one-shot address may fund the deposit of its own `RETIRE` (F-VAL-5), and then F3 debits that cell, `withDepositMarkSpent` burns it, and F9 pays the remainder to `RefundTo` — value out of the very address the certificate burns, on a `RETIRE`, with no F8b involved and on `main` today. Under the strict reading §11 was already false before this change. What actually holds the line is the sentence above it: `RETIRE` names no payee and takes no amount, so nothing it moves can reach anywhere its signer did not already declare as their own change address.

## 7. What this does not cover

A balance in an asset the certificate never names is still lost when the address burns (route 3). Pinned by `TestForeignAssetsUnderABurnedAddressAreStillLost` so it reads as a decision. The answer remains `docs/WALLET.md` rule 1: name every asset in the certificate that burns the address. **The invariant §1 states is therefore not fully achieved**, and the residue is deliberate rather than overlooked: closing it is `docs/WALLET.md` rule 1's obligation on the signer, not the fold's.

One case is not covered and does not destroy anything either: a residual owed to a `RefundTo` whose authority an *earlier* certificate burned stays under the burned source, reported as `swept_stranded`. That is the same loss `main` already had, with the addition that the outcome now says so.

**`swept_stranded` is not a promise that the value survives, and reading it as one would be the wrong lesson.** F8b declines to *destroy* it — nothing enters `res.Burned`, no accumulator moves, and the conservation identity is untouched, which is the whole point of §4a. But the cell it stays in is under a spent address, and whitepaper §4 says of exactly those cells that "the *values* under a spent cell are compactable once the block that spent it is buried deeper than the reorg horizon". So a stranded residual is unreachable by any signature from the moment the burn lands, and a node that compacts will eventually stop storing it. The distinction F8b actually draws is between *the fold destroying value* and *the value being unreachable*: the first is an accounting act with a consensus-visible accumulator behind it and a bug class attached (§4a); the second is what `main` already did on every route in §2. Only the first is fixed here, and `swept_stranded` names the second rather than curing it.

## 7a. What F8b costs the one stage that does not parallelise, and why no gas constant moves

Whitepaper §8 prices the sequential stage because it is the scarce one, and `Certificate.SeqGas` is a pure function of the certificate's bytes — reads, writes, `MARK_SPENT` count, seen insert. F8b performs state touches that appear in none of those counts, so the question is not rhetorical: does an attacker now get fold work for free?

### The bound, which is the whole of the argument

A *probe* below means one hash-table lookup. Two facts, both readable off `sweepBurned` and `moveResidual`:

1. **`moveResidual` costs at most 9 probes.** `Get(src)`, `IsSpent(dst)`, `Get(target)`, and two `journal.set`s at 3 each — each of those being a `Get` for the undo entry plus `State.Set`'s two maps, `dirtyCells` and `cells`.
2. **It is called at most once per declared write.** Once for the burned address's native cell — chargeable to that address's own `MARK_SPENT`, which is itself a declared write — and once for each of *this certificate's own* writes under that address. No write is ever visited twice: V1 requires the write list strictly sorted by slot, so no slot repeats.

Every declared write costs **at least 200 gas** (`gas_seq_per_write`, before whatever its `MARK_SPENT` or guard read adds on top). So:

> **F8b's marginal work can never cost the fold less than 200 ÷ 9 ≈ 22.2 gas per probe**, for any certificate, under any parameter set with `gas_seq_per_write ≥ 200`.

That is a bound rather than a search, and it is stated that way on purpose: the worst-case-shape approach has now been got wrong twice in this document, once by miscounting probes and once by naming a shape derivation cannot produce. A bound cannot be falsified by a cleverer certificate.

### Where the existing schedule sits, so the bound means something

The declared work is not one probe per declared item either, and counting it any other way makes the comparison meaningless:

| Item | Charged | Probes | gas/probe |
|---|---|---|---|
| a declared read | 100 | `readsHold`: `IsSpent` + `Get` = **2** | 50 |
| a declared `DELTA_SUB` | 200 | `stageWrites`: `IsSpent` + `Get`; `journal.set`: undo `Get` + `dirtyCells` + `cells` = **5** | 40 |
| a declared `MARK_SPENT` | 700 | `stageWrites`: `IsSpent`; `journal.markSpent`: `IsSpent` + `State.MarkSpent`'s `spent` + `dirtySpent` = **4** | 175 |

So the schedule already pays between **40 and 175** gas per probe depending on the shape — a spread of more than four — before F8b exists at all.

The most F8b-dense certificate the format permits is a `TRANSFER` moving **31** different assets out of a **single** one-shot source. Concentrating on one source is what makes it dense: it keeps all of F8b's work while paying for one `MARK_SPENT` rather than one per move. Measured through `validity.Derive` rather than reasoned about — 31 moves derives 31 reads and 63 writes, and 32 moves derives 65 and is refused by `max_writes = 64`:

- charged: 63×200 + 1×500 + 31×100 + 100 = **16 300**
- probes: 31 debits×5 + 31 credits×5 + 1 mark×4 + 31 reads×2 + F8b's (1 native + 31 asset)×9 = **664**
- → **24.5 gas per probe**, against the 22.2 floor the bound guarantees and the 40 the cheapest declared work costs.

### The verdict

F8b's densest certificate is about **39 % cheaper per probe** than the cheapest declared work already in the schedule, and it cannot go below 22.2 whatever anybody builds. That is a real mispricing and a small one, inside a schedule whose own internal spread is already a factor of four. It is not amplifiable — every F8b touch is chained to an already-paid declared write — and the shape that reaches it is a legitimate consolidating sweep of one address's 31 asset balances, which is exactly what §3's scope clause was written to serve. **No gas constant moves, and the genesis id stays where it is.** Had the number come out badly the fix would have been `gas_seq_per_write`, since that is the term the bound divides.

*Two earlier revisions of this section are retracted and kept. The first claimed 83 gas/probe with "20 % of margin", counting one probe per `journal.set` and omitting `IsSpent` entirely. The second corrected those but still counted `MARK_SPENT` at 3 probes rather than 4 — applying the two-map rule to `State.Set` and not to `State.MarkSpent` — and named a 21-source worst case that is not the worst, because spreading the moves across sources buys `MARK_SPENT` charges the concentrated shape avoids. Both errors moved the headline in the flattering direction, which is the reason the bound is now stated first and the shape search second.*

## 7b. F8b removes an incidental deterrent on §5's third case, and the deterrent was never real

Whitepaper §5's attribution theorem has exactly one case where the bill is separated from the cause: "a credit to a one-shot address whose own holder retired it (`RETIRE`, §11) after the certificate was signed." Before F8b, retiring an address that still held a balance destroyed that balance, so a griefer who wanted to skip somebody's in-flight payment paid for the privilege out of their own cell. F8b returns the balance. The deterrent is gone, and it is worth saying so plainly rather than letting a later reader discover it.

It was not a deterrent. `deriveTransfer` marks every debited one-shot source spent (`core/validity/derive.go`, "every debited one-shot address burns its own authority"), so a griefer could always **sweep the address with a `TRANSFER` instead of retiring it** — same `MARK_SPENT`, same skip for the in-flight credit, and the balance recovered in full. The cheaper of the two routes was always the free one, which is why the loss on the other never priced anything. What §5 relies on is unchanged and is stated in the theorem itself: the skip fee is *burned*, so the griefer gains nothing; only one-shot cells can be retired, so a payee publishing a persistent address presents no surface; and `max_retire_addrs` caps the burst. `TestCarveOutIsLimitedToNamedDestinations` and `TestCarveOutIsAvoidableByAddressVersion` pin those, and neither moves under F8b.

## 8. Consensus status

This changes what applied certificates do to state, so it is a consensus change. It moves no consensus parameter and **does not move the genesis id**: `spec/vectors/000-genesis-mainnet.json` and `001-genesis-devnet.json` are byte-identical after `go run ./spec/gen`, and `zcd genesis` prints the same params hash, genesis id and state root as `main`. The chain has not launched, so the mechanism is the one every prior Era-0 rule change used — regenerate the corpus, explain the diff, record it in the architecture changelog and this log — and not an activation height.

## 9. What is pinned by tests

| Test | Property |
|---|---|
| `core/fold.TestBurningAnAddressStrandsNothingItCanName` | the routes of §2, each its own subtest |
| `core/fold.TestPartialAssetSweepStrandsNothingItNames` | the named-cell half of the rule — the only test that fails when that clause is deleted |
| `core/fold.TestForeignAssetsUnderABurnedAddressAreStillLost` | the deliberate limit of §3's scope |
| `core/fold.TestUnsweptOneShotDepositReturnsTheRest` | route 1, and where the value goes |
| `core/fold.TestUnderstatedBalanceReturnsTheRemainder` | the understating-node route end to end, with the wallet's own tautology reproduced; the lie now costs nothing |
| `core/fold.TestDustBeforeASweepCostsTheVictimNothing` | the `AccessGuardEQ` proposal's Scenario B, which no longer exists |
| `core/fold.TestLemmaNoUnsignedCreditChangesAnOutcome` | §5's theorem, checked over outcomes rather than write sets; fails if the skip rule is reinstated |
| `core/fold.TestCreditStormCausesNoBilledSkips` | the same, under load, with a one-shot victim and a prior-block storm |
| `sim.TestNoBurnedAddressHoldsDrops` | the state-wide law over the adversarial generator |
| `sim.TestDifferentialFold` | `core/fold` and `sim/refold` agree on the native sweep, on the *named-cell* sweep, and on the resulting state root. Stated precisely because the first version of this row was not: the generator produced no certificate that named a non-native cell under an address it burned, so deleting the asset clause from `sim/refold` alone left the whole `sim` suite green. `genAssetVault`/`genAssetPartialSpend` produce that shape now, the same mutation fails every seed, and `r.NamedAssetBurns` is asserted non-zero per seed so the coverage cannot quietly return to none (the `OneShotFunded` pattern). |
| — *not* covered by the differential | The **leave-alone** branch, and this is a choice rather than an impossibility. The *native* form of it would falsify `sim.TestNoBurnedAddressHoldsDrops` — a law worth more than the coverage — but an **asset-only** strand would not, since that law is about drops: a certificate whose `RefundTo` an earlier one burned and whose reservation empties the native cell leaves only asset cells behind, which is vector `011`'s second-cell shape. So the generator could reach the branch with the law intact, and the reason it does not is that the shape needs a third stage machine to arrange a dead refund address on purpose, for a branch two direct tests already pin. Covered by golden vector `011` and by `TestBurnWithADeadRefundAddressStrandsAndAccountsForNothing`, both of which fail when the branch is changed. |
| `spec/vectors/009-one-shot-burn-returns-the-remainder` | the native half: 813,735,000 drops reported as `swept` |
| `spec/vectors/010-one-shot-burn-returns-a-named-asset-remainder` | the named-cell half: 400,000 of an asset, observed in the cells |
| `spec/vectors/011-one-shot-burn-strands-into-a-dead-refund-address` | the branch that moves nothing, with a cell holding 2²⁵⁶−1 of an asset: an implementation that destroys instead of leaving cannot replay it, because it rejects the block |
| `core/fold.TestBurnWithADeadRefundAddressStrandsAndAccountsForNothing` | the same, plus the native conservation identity to the drop |
| `wallet.TestRefusesABurnWhoseResidualGoesToSomebodyElse` | §4b's incentive, refused without reading a balance — and *not* refused for a co-signer who is not exposed |
| `wallet.TestAcceptsAMultiKeyConsolidatingSweep` | the false positive the same-key form had, and the counterparty case it must still refuse |
| `core/fold.TestAnAssetOnlyStrandIsStillReported` | an asset left behind with no drops beside it, which only `StrandedCells` can report |
