# Zycord — I1-H2: Miner Revenue and the Two Markets

**Scope:** the Era-0 fee rules (§8, §15) and the block-assembly incentive they create. Raised as an open question in [I1](I1.md); resolved here rather than deferred to the M5 parameter freeze, because an incentive frozen into genesis is not a parameter — it is a fork.

**Verdict:** the rule as specified is wrong. The sequential market — the scarce one — carried no priority signal, so a revenue-maximising builder optimised the abundant resource. Fixed by giving **both** markets a priority tip, burning both base fees, and paying tips on applied certificates only.

**Revision (R2-H1).** The first version of this document settled the *miner* side and left the *user* side unexamined: it adopted pay-your-bid without weighing the two-field structure EIP-1559 exists to provide. §7 now does that, and the conclusion changed — the bid is two fields per market, a maximum and a priority. The miner-side conclusions below are unaffected: they are identical under both structures.

---

## 1. Where a miner's money comes from

Six candidate revenue lines. "Before" is the rule as written in spec v0.2 F11; "after" is this document's proposal.

| # | Line | Before | After | What it incentivises |
|---|---|---|---|---|
| 1 | **Emission** `emission(H)` | paid | paid | Produce *a* valid block. Content-blind: identical whatever the block holds, so it can never influence ordering. |
| 2 | **Sequential base fee** `seq_gas × seq_base` | burned | **burned** | Nothing directly — and that is the point (§4.2). Burning makes congestion pricing honest. |
| 3 | **Sequential priority tip** `seq_gas × min(seq_priority, seq_max − seq_base)` | *never charged* | **paid, applied only** | Order by willingness to pay for **state mutation** — the scarce resource. This line is the fix. |
| 4 | **Parallel base fee** `par_gas × par_base` | burned | burned | Nothing directly; same reasoning as line 2. |
| 5 | **Parallel priority tip** `par_gas × min(par_priority, par_max − par_base)` | paid, applied only | paid, applied only | Order by willingness to pay for **verification** — the abundant resource. |
| 6 | **Skip fees** `SKIP_FEE` | burned | burned | Nothing. Deliberately: a miner that profited from skips would assemble blocks to harvest other people's deposits. |

Line 3 is the whole finding. Before the fix it was not merely unpaid — it was **never charged**. A signer bidding above the sequential base fee handed the network nothing and told the miner nothing; the bid functioned purely as a ceiling that kept the certificate includable as the market drifted (B4).

## 2. Why that is backwards

The two-market thesis (§8) rests on one asymmetry: **verification parallelises and state mutation does not.** Parallel capacity grows with every core that joins; the sequential fold is one loop that every node runs in order, forever, and it is the only thing that does not scale out.

With only line 5 paid, a revenue-maximising builder ranks certificates by parallel-tip density. Three consequences follow, in increasing order of seriousness:

**(a) The scarce resource is allocated by the wrong auction.** Under sequential congestion the builder is indifferent between two certificates that pay the same parallel tip and consume wildly different sequential gas. It will fill the sequential ceiling with whatever happens to pay for verification.

**(b) Users cannot express sequential urgency.** There is no on-chain bid that buys sequential priority. A user who urgently needs a state write has no protocol-level way to say so.

**(c) The auction moves off-chain.** This is the real cost. An unpriced scarce resource is not free — it is **sold somewhere the protocol cannot see**. A builder holding sequential capacity that nobody can bid for on-chain will sell ordering privately, which is precisely the MEV leakage §6 was designed to keep inside applications rather than hand to block producers. The design that was supposed to let applications capture their own MEV would instead have created a fresh, protocol-level MEV market on the base layer, by omission.

**A note on when this bites.** At genesis, emission is `69,420 ZCD` per block while a full block of transfers tips a few thousandths of a ZCD.[^redenom]

[^redenom]: Whitepaper v1.0 redenominated the curve: the genesis subsidy is now `21 ZCD`/block (ARCHITECTURE §15). This review is left as written, because it is a dated record of what was reviewed. The finding is unaffected — the argument turns on the *ratio* of subsidy to tips, which falls from roughly 14,000,000:1 to roughly 4,200:1 and leaves miners just as content-indifferent, and just as content-sensitive once the chain is congested. Re-derive rather than trust this footnote if the ratio ever matters to a decision. Miners will be close to content-indifferent for years, and the distortion is theoretical during that period. It becomes load-bearing exactly when the chain is congested enough for users to bid meaningfully above base — which is the regime the fee market exists for. That is an argument for fixing it now, not later: the harm arrives long after the rule is unchangeable.

## 3. The two requirements

**Invariant (what the fix must achieve).** *The miner's ordering incentive must track the scarce resource.* Operationally: when the sequential ceiling binds, a certificate's chance of inclusion must be monotone in its sequential bid, and the revenue-maximising block must be the one maximising sequential-tip density.

**Constraint (what the fix must not break).** *No profit from skips.* Everything routed to the miner must come only from **applied** certificates, so that a builder maximising revenue is thereby maximising application and can never gain by assembling a block that triggers somebody else's skip (R1-C1's economic half).

## 4. The proposal

### 4.1 The change

Both markets charge the full bid. The base portion of each is burned; the excess over base is a priority tip paid to the miner, on the applied path only.

```
per market:
  effective = min(priority, max − base)     ← the clamp; see §7
  burn      = gas × base                    ← destroyed
  tip       = gas × effective               ← to the miner, if APPLIED

charge = burn + tip, summed over both markets  ← debited from the deposit
```

Skips are unchanged: `charge = SKIP_FEE`, burned in full, `tip = 0`. Drops are unchanged: nothing.

This is the reviewer's prior, and the analysis below supports it — with one addition worth stating explicitly, because it is evidence the specification *intended* this all along.

### 4.2 Should the sequential base fee also pay the miner? **No.**

Argued against, and this is the sharper half of the question.

A base fee that reached the miner could be manipulated at zero cost. A miner would stuff its own block with self-paying certificates: it pays the base fee to itself, so the stuffing is free, and the inflated usage drives the base fee up for everyone else in subsequent blocks. That is a tax the miner levies on all other users by burning nothing but its own block space — which it controls anyway.

Burned, the same attack costs real money: every unit of self-stuffed gas destroys the miner's own coin. The burn is what makes the base fee a *measurement* of demand rather than a *lever*. This is the same reasoning that put the burn in EIP-1559, and it applies with more force here, because Zycord has two base fees and therefore two levers.

So: base fees burned, tips paid. Line 2 and line 4 stay exactly as they were.

### 4.3 Why the constraint survives

Tips are computed and returned only on the applied path — a skipped certificate returns no tip at all. Three checks:

- **A skip cannot pay the miner.** It charges `SKIP_FEE`, which is burned.
- **Including a known skipper is strictly worse than excluding it.** The certificate consumes sequential and parallel gas against both ceilings (the gas is charged whatever the outcome) and returns nothing. A builder that can predict a skip — and it can, since it dry-runs the fold over its own candidate block (§12) — always prefers to leave it out.
- **A miner cannot re-order to manufacture a skip.** Fold order is canonical: `(underwriter, Seq, cert_id)`, computed by the fold over a copy of the block (F1). The proposer's arrangement is erased before anything is applied, so there is no ordering choice to exploit.

The constraint therefore holds more strongly after the fix than before it: the miner is no longer merely indifferent to skips, it is actively against them, because a skip is a certificate that consumed ceiling space and paid nothing.

### 4.4 A side effect worth recording: the deposit ceiling becomes meaningful

V5 already required `Deposit.Amount ≥ max(SKIP_FEE, seq_gas × seq_price + par_gas × par_price)`.

That formula only makes sense if the sequential price is collected. Under the old rule the deposit reserved against a sequential price that could never be charged — evidence the specification's fee model always assumed line 3 was collected, and that F11 simply failed to say where it went.

### 4.5 Rejected alternatives

- **Leave it as specified, document the asymmetry.** Rejected: §4.2(c) is not an asymmetry, it is an off-chain auction the protocol cannot observe, and after genesis it is unfixable without a fork.
- **Pay the miner both base fees and drop the tips.** Rejected: reintroduces free base-fee manipulation (§4.2) and removes the marginal signal entirely — every certificate at the same gas pays the same, so ordering within a block is again unpriced.
- **Pay the sequential tip on skips too, to price the fold work a skip really costs.** Rejected: it recreates exactly the harvesting incentive R1-C1 closed. A builder would seek out certificates likely to skip. The fold work a skip causes is real, but the right instrument for it is `SKIP_FEE` — burned, constant, and therefore unharvestable (R1-H1).
- **Meter sequential gas more expensively instead of adding a tip.** Rejected: raising the base fee raises the *burn*, not the miner's revenue, so it changes what users pay without changing what builders optimise. It addresses congestion, not allocation.
- **A single merged market.** Rejected: it is the design this network exists to reject (§8). A signature check would compete at auction with a storage write, and heavy cryptography would stop being cheap.

## 7. The bid structure (R2-H1)

The first version of this document decided *who gets the money*. It did not decide *what the signer offers*, and the omission mattered.

### 7.1 The two candidates

**Pay-your-bid** (originally adopted). One price per market; `charge = gas × price`; the whole excess over base is the tip. A first-price auction with a public reserve.

**Two-field** (adopted now). A maximum and a priority per market:

```
effective = min(priority, max − base)
burn = gas × base        tip = gas × effective        charge = burn + tip
```

Canonical form requires `priority ≤ max` in each market, and B4 becomes `max ≥ base` — the maximum is the solvency bound.

### 7.2 Why the choice is forced here: the TTL-buffer argument

Three rules interact:

- **B4** makes a certificate unincludable once the base fee passes its price.
- **TTL_MAX** lets a certificate wait up to 240 blocks for inclusion.
- The base fee moves **±12.5% per block**.

So a signer who wants their certificate to survive its window must name a price far above today's base fee. That margin is not greed, it is the price of not being stranded — and under pay-your-bid it is **paid in full whenever the certificate is included early.** Every certificate pays its own risk margin, forever, to a miner who did nothing to earn it. The safer the signer plays, the more they are charged for playing safe.

Under two-field the margin lives in `max`, which is never charged. The signer pays `base + priority` at the moment of inclusion. Raising the maximum costs nothing unless the market actually moves into it.

This is not the classical bid-shading argument against first-price auctions — a public base fee genuinely mitigates that, and it is why pay-your-bid looked defensible. It is an interaction between Zycord's *own* B4, TTL and fee-drift rules, and it makes two-field strictly better for the signer at the cost of two `uint256` fields.

### 7.3 What pay-your-bid bought, stated fairly

- **Exact cost at signing time.** A signer knew what a certificate would cost before broadcasting it, without knowing when it would land. Under two-field the charge depends on the base fee at inclusion, so the signer knows a *bound* rather than a number. For a fee that is a rounding error beside the amount transferred, a bound is enough.
- **A marginally simpler settle path** — one multiplication per market instead of a clamp and two.
- **A ceiling equal to the charge.** Under two-field the ceiling is `gas × max`, which is the worst case the signer authorised — the correct meaning of a ceiling, but no longer equal to what is usually paid.

### 7.4 The cost that is not zero: reserve, not fees

The safety buffer is free in *fees*. It is not free in *balance*.

The deposit reserves against `gas × max`, so a signer naming a hundredfold buffer must hold a hundredfold reservation at F3 — refunded at F9, within the same fold step, but real while it lasts. A signer with a small balance therefore cannot name a large buffer, and the protection that two-field offers is weakest exactly for the smallest users.

This is a genuine regression against pay-your-bid, where ceiling and charge coincided. It is accepted because the lockup is intra-block rather than for the certificate's whole life, and because the alternative charges *everybody* their buffer rather than merely bounding how large a buffer the poorest can name. Wallets must size headroom against available balance, and a holder who cannot afford a wide maximum shortens the TTL rather than the safety — recorded as rule 5 in [WALLET.md](../WALLET.md).

**Recorded for the trail: this regression was found by the implementer, and missed by the reviewer who specified the change.** It surfaced as a test failure — a certificate that used to be affordable stopped being one — after the design had been reviewed and signed off. It is the mirror image of R2 finding what I1 missed. The process's credibility is the stack, not any one stratum, and a layer that reports what the layer above it did not see is the stack working.

### 7.5 Rejected alternatives for the bid structure

- **Pay-your-bid.** Rejected on §7.2; the structural overpayment is permanent and grows with how cautiously a signer sets their price.
- **A single price with a protocol-fixed refund of the excess** (charge base, refund the rest, no tip). This is the *original* rule, and it is what created I1-H2: no priority signal at all.
- **Relax B4 instead** — let a certificate be included at any price and simply charge it the base fee. Rejected: that reintroduces R1-H3 exactly, where fee drift bills a signer for market motion they could not avoid, and it makes the deposit ceiling unbounded over the TTL window (R1-H1).
- **Shorten TTL_MAX so the buffer is small.** Rejected: TTL is the user's tolerance for latency, not a fee parameter, and shortening it to paper over a fee bug would make dependent certificate chains and offline signing worse for a problem with a two-field solution.
- **Priority as a fraction of base rather than an absolute price.** Rejected: it re-couples the two markets to the base fee's motion, so a signer's *ordering* offer would move when they only meant to buy solvency headroom.

## 5. What is pinned by tests

In `sim/incentive_test.go` — these do not test the fold, they test what a rational builder *does* under it. `sim/builder.go` is the reference revenue-maximising selector they run against; `node/miner` will be a faster version of the same thing.

| Test | Property |
|---|---|
| `TestSequentialBidCarriesAPriceSignal` | Raising a sequential bid strictly raises the miner's revenue, in proportion to sequential gas. Fails flat under the old rule. |
| `TestBuilderAllocatesScarceGasByScarceBid` | With the sequential ceiling binding, the builder selects sequential bidders over parallel bidders that pay more in absolute terms. |
| `TestInclusionIsMonotoneInTheSequentialBid` | Raising your own bid never removes you from the block. A market where paying more can hurt is not a market. |
| `TestNoRevenueFromSkips` | The block reward is exactly `emission + Σ applied tips`; a lavishly-bidding skipped certificate contributes zero, and its skip fee is burned in full. |
| `TestBuilderPrefersApplyingCertificates` | A zero-tip certificate never displaces a paying one, and adding one does not change revenue. |
| `TestBaseFeesAreBurnedNotPaid` | A certificate offering no priority tips nothing and is burned in full; `charge = burn + tip` holds for every bid. |
| `TestSafetyBufferIsFree` | Raising `max` while holding `priority` and the base fee fixed does not change the charge. This is R2-H1's property and the one pay-your-bid fails. |
| `TestEarlyInclusionNeverCostsMore` | The charge is non-decreasing in the base fee, so prompt inclusion never costs more than late inclusion. |

**Mutation-checked.** Reverting *both* implementations to the old rule — so that `core/fold` and `sim/refold` still agree with each other — fails four of the six. That matters: the differential fold catches inconsistency between two implementations, but only these catch two implementations consistently agreeing on the wrong design.

## 6. Disposition

Implemented in `core/types.Certificate.Fees`, applied by `core/fold` at F9, mirrored independently in `sim/refold`. Architecture spec §15 and F9/F11 updated; I1-H2 and R2-H1 both resolved.

The rule is live and [ARCHITECTURE §15](../ARCHITECTURE.md) is what owns it now — the two base fees as consensus state, and the F12b input clamp that arrived afterwards and that §7.2's argument turns on: without it a block bursting to `4T` moves the base fee by up to +37.5 % against a −12.5 % floor, and the `SeqMax` safety margin derived here from a symmetric ±12.5 % drift would not have been the margin a signer needed.

`FeeBid` is now four fields — `SeqMax`, `SeqPriority`, `ParMax`, `ParPriority` — so the certificate's encoding changed, and with it every golden vector. That the whole corpus moved is the correct and intended signal: this is a consensus change, and it looks like one in the diff.

Remaining for M1: `node/miner` implements the same selection over a real mempool, and the honest disclosure in §4.2(c) should be revisited once there is a live fee market to measure — a builder's actual behaviour is the only test that is not a simulation.

### A process note

R2 observed that this document had a rejected-alternatives section for the miner side and none for the bid structure, and that the gap is exactly where R2-H1 was hiding. The rule that follows: **an economic mechanism gets a rejected-alternatives section even when the choice feels forced.** "Feels forced" is the feeling of not having looked, and in the economic layer there is no compiler to notice.
