# Zycord — Mempool Admission and Eviction

**Scope:** the certificate pool's behaviour under pressure. Raised as a deferred item in [I2](I2.md)'s confidence section and reclassified as an M2 blocker by the post-M1 review: harmless without a network, a cheap censorship vector with one.

**Status:** designed and implemented here; tuning is explicitly not final and is what the M3 testnet exists to measure.

---

## 1. The attack the M1 pool enabled

The M1 pool refused arrivals when full. That is the wrong shape, and with a network it is exploitable:

> An attacker floods the pool to capacity with minimum-priority certificates. Legitimate high-priority certificates are then **refused at the door**. Under congestion — the exact condition the fee market exists to resolve — entry is decided by arrival time rather than by price.

Three things make it cheap:

- **The floor is low by design.** A certificate offering zero priority is perfectly valid; it pays the base fee and nothing more. Filling a pool costs the attacker only the deposits, which are *refunded* if the certificates never commit — and they never commit, because the attacker's certificates are the ones a rational miner declines to include.
- **The victim pays nothing to be censored.** The attacker does not need the certificates mined. Occupying the queue is the whole attack.
- **It is not a consensus bug**, which is why it survived M1 review. Mempools are local; two nodes disagree about pool contents constantly and nothing forks. That is exactly what makes it easy to under-weight.

It is a **local censorship vector with a global effect**: if enough of the network runs the same refusing pool, a high-priority certificate cannot find a node that will hold it.

## 2. The design

### 2.1 Eviction by price under pressure

A full pool admits a higher-paying arrival by evicting the lowest-paying resident. The metric is **sequential priority per unit of sequential gas**.

Not the parallel tip, and not the total. The sequential loop is the scarce resource — the one thing that does not parallelise — and ranking a pool by parallel tip would re-import [R2-H2](R2.md)'s error one layer up: the abundant resource priced, the scarce one not. A pool ordered by parallel tip would evict exactly the certificates a rational miner most wants, which is the opposite of the pool's job.

The comparison is integer, on a common denominator, so two certificates rank identically on every node that runs this code:

```
value(c) = c.SeqPriority        # per unit of sequential gas, already a density
```

Sequential priority is *already* a per-gas price, so no division is needed and no rounding enters the ordering.

**Two quantities, deliberately separated.** §1's flood is what happens when they are conflated. The pool has to answer two different questions under pressure, and the original code answered both by reading `victims[0]` — the cheapest survivor of §2.3's chain-safety filter:

- the **order**: which resident leaves first;
- the **floor**: what an arrival must beat to be admitted at all.

They have different correctness conditions. The order must not be buyable. The floor must never sit below the price of anything the arrival actually displaces.

**The order: chains are ranked as units, by their cheapest member.**

```
price(underwriter) = min over that underwriter's pooled certificates of SeqPriority
```

Ties break on the certificate's own priority and then on its id, so the order is total. The justification is §2.3's own: a dependent chain is worth something only as a whole, because nothing above a `Seq` can apply until that `Seq` has. A chain whose base bids zero is a zero-priority occupant of the pool however much its tail declares, and ranking it by its tail would rank it by the one member that cannot be delivered on its own. §2.3 makes all but the tail structurally unevictable, so ranking by the tail's own declaration is precisely the pinnable quantity: an attacker buys protection for 63 unbid certificates with one bid.

Rejected alternative for the ranking: **the total over the chain's members.** A single expensive tail lifts the whole chain's total, so the ranking is bought back with the same certificates. Only a rule monotone in the *cheapest* member forces the bid onto every certificate.

**The floor: the cheapest removable resident's own declaration.** There is one invariant, and everything here is subordinate to it:

> An arrival may displace a certificate only if it beats **that certificate's own declared `SeqPriority`** by the bump margin.

It is enforced where it is stated — at the point of removal, against each victim, one at a time. The floor is not what carries it, and this is the whole of the design: because the pass filters victims individually, the floor is free to be the *lowest* price at which entry is possible rather than the highest price the pass might need, and so it is §2.1's opening sentence, in the currency residents actually declare:

```
floor = min over the removable residents of SeqPriority
```

Removable, not resident: §2.3 makes only an underwriter's highest pooled `Seq` evictable, and a chain's cheap base cannot leave without stranding what sits above it. It is therefore not a price anyone can be admitted against, and counting it would let an arrival buy a removal the pass cannot perform. That filter is the entire difference between this floor and the pool-wide minimum, and it is what `TestEvictionFloorIsTheCheapestRemovableNotThePoolMinimum` pins.

**The floor is not read from chain prices, at any cut.** That was the second attempt at §1's flood and it fails for a reason worth writing down, because it is the reason both earlier shapes of this rule failed: **the floor was denominated in one metric and the victims in another.** A chain price is a `min` over the chain's members; the certificate the pass removes is the *tail*, whose own declaration is unbounded above that minimum. So the guarantee delivered was "the arrival beats the `need`-th smallest chain minimum", not "the arrival beats every resident it removes".

The gap is not narrow, and closing it needs no attacker to motivate it. Take every resident to be an ordinary two-certificate fee bump — `Seq 0` at 1, `Seq 1` at 1,000,000, which is what fee bumping *is*. Once `need` such chains are pooled, all `need` chain prices at the cut are base prices, the floor collapses to the cheap end, and an arrival declaring **2** removes `need` certificates declaring **1,000,000**. The threshold is exactly `need = highWater − lowWater`: nine such chains and the arrival is refused, ten and it fires. Under the shipped defaults that is about 1,000 concurrent fee-bumping chains in a 20,000 pool — roughly 11% of it, which is a busy day rather than an attack budget. The earlier "cheapest chain price in the pool" rule was the same defect with the threshold at **one**. Pinned by `TestFeeBumpedChainsDoNotCollapseTheEvictionFloor` and `TestArrivalMustOutbidEveryResidentItRemoves`.

Chain price still decides the **order**. It no longer decides who may be removed.

**The ordering has its own cost, and it is the same shape read a third way.** A chain is ranked at its cheapest member, so an honest fee bump — cheap base, dear tail — is the pool's *first* victim, and the certificate that actually leaves is the dear tail. An arrival that outbids that tail removes it in preference to residents declaring far less: measured, an honest chain whose tail declares 10,000 is taken by an arrival at 20,000 while 79 independent residents declaring 100 survive. The invariant holds — the arrival outbid what it took — but it inverts this section's opening sentence, and §2.1 previously recorded this trade-off only for the floor. It is the price of not letting a flooder buy protection for 63 unbid certificates with one bid, and it is why the *order* stays keyed on the chain minimum while the *floor* does not.

**And the floor is not a rank statistic at the low-water cut either, which was the third attempt.** Denominating the gate in the victims' own declarations is necessary but not sufficient: the *rank* matters too. Taking the floor at the `need`-th smallest removable declaration guarantees a full low-water batch, and buys that guarantee by quantifying the gate at the **top** of the cut instead of the bottom — which is §1's censorship attack wearing §2's clothes.

The reason is §2.3 again. The removable set holds one entry per underwriter, not one per certificate, so it shrinks as chains lengthen. The floor is the `need/removable` quantile of it: at many short chains that is the cheap end and the rule behaves; as the removable count falls toward `need` the quantile climbs toward 1; and at or below `need` removable residents the floor is exactly the **dearest** removable declaration. One resident declaring high then sets the admission price for the whole pool. Measured on `smallPolicy` (100/90/80, so `need = 10`) with nine 10-long chains, every certificate declaring 100 except one user's newest, who is in a hurry and declares 1,000,000:

| arrival declares | `need`-th smallest | cheapest removable | `main`, before §1 was addressed |
|---|---|---|---|
| 200 | refused | admitted | admitted |
| 1 000 | refused | admitted | admitted |
| 5 000 | refused | admitted | admitted |
| 50 000 | refused | admitted | admitted |
| 999 999 | refused | admitted | admitted |
| 1 100 000 | admitted | admitted | admitted |

An arrival at five hundred times the market rate, refused because of one unrelated certificate. Note the third column: this is the one place where fixing §1's flood had made the pool *worse* than the code it replaced. `main` took the floor at the cheapest removable tail and admitted the arrival — it then evicted the millionaire too, which is the defect this section exists to close, but its floor was never pinnable by one certificate. Reached the other way round, that is §1's own vector at a price of **one certificate** rather than one per identity. Pinned by `TestOneDearTailCannotSetThePoolsAdmissionPrice`.

The batch was not paying for itself either — and the evidence for that is a set of counts, not a stopwatch. Wall time on a shared machine moved by 3–8× run to run while the effect under test is smaller than that, so two independent measurements of the same two commits disagreed with each other. What is quoted here instead is what the wall time is a noisy function of, all three exact and machine-independent, all three asserted by `TestEvictionPathCostIsCountedNotTimed` so this table cannot drift from the code:

- **admitted** — how much of the offered traffic gets in;
- **passes** — how many arrivals ran an eviction pass at all;
- **sorted** — how many certificates those passes sorted, in total.

Pool of 4,000 at its high-water mark, 300 arrivals, `need = 200`:

| distribution | `need`-th smallest | | cheapest candidate | | |
|---|---|---|---|---|---|
| | admitted | passes | admitted | passes | sorted |
| flat | 300 | 2 | 300 | 2 | 7 000 |
| tight spread | 300 | 2 | 300 | 2 | 7 000 |
| wide spread | **111** | **190** | 300 | **5** | 492 |
| geometric ladder | **250** | **52** | 300 | **3** | 1 620 |
| marginal ladder | **0** | 300 | **49** | 300 | **49** |

**Refusing an arrival does not skip the pass.** It runs the whole floor computation and then says no, and it leaves the pool at its high-water mark, so the next arrival pays again. That is the wide-spread and geometric-ladder rows: the refusing gate runs **38× and 17× as many passes** to admit *less* traffic. Admitting drains toward the low-water mark and buys the arrivals behind it a free ride.

**The last row is not a distribution, it is an attacker**, and it is the one shape where the refusing gate is genuinely cheaper. One identity rents the pool's single cheapest slot and climbs it a drop at a time, so every arrival clears the floor — its own previous certificate — and can take exactly that one certificate. Both rules run a pass on all 300 arrivals; the difference is that a floor at the cut refuses every one of them before reaching the sort, and this floor must admit them, because refusing them is refusing §1's arrival.

That is paid for where it arises rather than by giving the gate back. The invariant is applied when the candidate list is **built**, not when it is walked, so the sort is bounded by what the arrival may take rather than by the size of the pool: across all 300 passes the ladder sorts **49 certificates in total**, at most one per pass. With the filter in the removal loop instead it would sort the whole removable set every time — an `O(n log n)` sort under the write lock, per certificate, for the price of one deposit cell. Pinned structurally in `TestAnEvictionPassSortsOnlyWhatTheArrivalCanTake` and in the `worst pass` assertion above.

The `sorted` column is a *bound*, not a promise of small: §1's own flood state — every resident declaring zero, one arrival declaring a drop — is an arrival that outbids everybody, so it sorts everybody. That is the `flat` row's 3,600-certificate pass. Hysteresis prices it: the pass clears to the low-water mark and the next `need` arrivals run no pass at all, which is why 300 arrivals cost two passes there and three hundred on the ladder.

What is left in either case is the two `O(n)` passes over the pool — the chain summary, then the candidate list — that every pass had paid since before §1 was addressed, refused arrivals included. Reducing *that* is §2.6's subject, and it is now closed by a fast path ahead of them rather than by making either pass cheaper: see §2.6.

**The floor and the candidate set are one computation, and they have to be.** A minimum read over every *removable* resident is not a conservative approximation of a minimum read over the residents *this arrival may take* — it is an incoherent one. A user extending their own chain sets the pool minimum with their own cheap base, which §2.3 then forbids the pass to remove. The gate would say yes at a price no candidate carries, the pass would find nothing to do, and the arrival would be admitted having outbid nobody: occupancy climbing past the high-water mark on every such arrival, hysteresis never engaging, and the hard cap at `MaxCertificates` left as the only bound. Reading the floor over the candidates instead makes the two agree — clearing the floor means beating the cheapest candidate, so **an accepted pass always removes at least one certificate** and occupancy never leaves the band. That user is refused with `ErrBelowEvictionFloor`, which is the honest answer: every certificate they could have displaced outbids them. Pinned by `TestOccupancyNeverRisesAboveTheHighWaterMark`.

**What the invariant costs, stated plainly rather than argued away.** An attacker's chain tail declaring `P` is protected at `P` — exactly as an honest resident declaring `P` is, because the pool cannot tell them apart: they are the same declaration. So an attacker can again raise the floor by declaring on **one evictable tail per identity** — every one of them, since the floor is a minimum — which is §1's upward vector at §1's price, unchanged from the code this replaces. That is not a regression that can be engineered away here, and the reason is structural: the shape "cheap base, dear tail" is simultaneously the flooder's pin and the honest user's fee bump, so any rule that lets a cheap arrival remove a dear tail *is* the collapse described above. The two goals are the same declaration read in opposite directions. Closing the upward half needs the declaration to cost something — an aggregated deposit screen, and a bid that is settled rather than merely declared, both below — and not a different floor metric.

The floor itself is one `min`, taken in the same pass that builds the candidate list, so an arrival that fails the bump is refused without the pool ever being sorted. The refusal path would still be two `O(n)` passes over the pool and one map allocation, because the chain summary is built first — that cost predates §1 and is §2.6's, not this section's. §2.6 puts a cheap, sound lower bound on the floor ahead of both passes, so the common refusal never reaches them.

**What this does and does not cost an attacker.** The rules above bound *which* resident may set the floor; they do not price it, and the distinction is load-bearing:

> `FeeBid.SeqPriority` is a **declared** field, collected only when a certificate commits. An honest user who bids high pays, because their certificates are mined. A flooder's certificates are designed never to commit, so raising the declared bid on all of them costs nothing but locked, refundable deposit — a property of what the pool can observe rather than of any one defect, and one the correction below explains cannot be fixed at the pool.
>
> This paragraph used to continue: *"Worse, the deposit screen is a per-certificate `max` against a shared cell rather than a sum, so one funded cell backs every certificate that identity pools at that bid simultaneously. A uniform-priority 64-chain flood therefore costs the same 3.13 ZCD it cost before §1 was addressed at all."* That is now **fixed** — the screen sums every ceiling a cell already backs — so that amplification is gone and the sentence is kept only as the historical statement of the gap. Measured on the fixed tree: funding one identity with a single 64-certificate chain's largest ceiling (20,592,000 drops) admits **20 of 64** certificates, where the aggregated requirement for the whole chain is 83,592,000 drops. Before the fix the same funding admitted all 64.

So the barrier any of these rules erects is a quantity that is currently free to *settle*, though not free to *back*. Canonical form requires `SeqPriority ≤ SeqMax`, and the deposit screen tests `SeqGas × SeqMax + ParGas × ParMax`, so declaring a high priority forces a proportionally high `SeqMax` and the screen demands the capital to cover it. How much capital is not a single number and should not be quoted as one: the ratio between pinning the floor at 1,000,000 and bidding a market rate of 100 is **600× when the parallel half of the bid is negligible and about 1.3× when it dominates**, because `ParGas × ParMax` sits in the same sum and `SkipFee` floors the cheap end. What is invariant is the direction — the screen is monotone in the declared priority, so an attacker who pins the floor high locks capital in proportion. §2.5's point stands: that capital is the Sybil defence and it is denominated in mined coin. What a settled bid changes is that the declaration would also have to be *paid* rather than merely backed, which is a different bound and the one this section needs. The argument that "forcing the bid onto every certificate is precisely what an honest user pays to be ranked highly" is true of the honest user and false of the flooder, and it becomes true of both once the deposit screen aggregates — which it now does. `TestPinnedChainCostsTheSumOfItsDeclarations` and `TestPinCostScalesWithTheDeclaredTail` measure both halves against the enforced admission threshold rather than against what a test fixture chooses to deposit; the second pins the increment exactly, at the tail's own ceiling increase.

**A correction, because this section used to name the builder fix as the source of that first half and it cannot be.** That fix direction had two parts — rank the *pool* by a settleable quantity, and stop the *builder* packing certificates it will not be paid for. Only the second is implementable, and the reason is worth stating precisely rather than hand-wavingly, because the obvious version of the argument is wrong.

The obvious version: "the pool would have to evaluate `readsHold` at the tip, and a chained certificate's reads are false until its predecessor commits". That is **not** generally true, and `core/validity/derive.go` is why. A TRANSFER derives `GUARD_GE` against the debited balance with an `OpDeltaSub` write — relative, not absolute — so two chained transfers from a sender who can afford both declare reads that *both* hold at the tip. MINT is the same shape: `GUARD_LE` against a pre-computed remainder, specifically so that concurrent mints do not invalidate each other. The derivation is built to make ordinary chains applicable out of order, and it succeeds.

The actual reason is stronger and does not depend on the read shape at all: **applicability at the tip is not the quantity a settled bid asks for.** What is wanted is a bid the flooder cannot declare for free, and `readsHold` at the tip does not supply one. A flood is a set of certificates whose reads hold perfectly well *now* — the attacker constructs them that way, and nothing stops them — and which are designed never to be worth mining. Screening them on tip applicability admits every one. Conversely the predicate does have false positives against honest traffic (an `EXACT` read against a cell an earlier chain member sets, a read on a one-shot address a predecessor burns), so it refuses some legitimate chained certificates while catching none of the flood. It is the wrong test in both directions, which is a stronger objection than "it is unavailable".

And the settleable quantity itself is not observable at admission for a plainer reason: whether a certificate ever pays its declared `SeqPriority` depends on whether a *miner includes it*, at some future height, in competition with certificates that do not exist yet. No function of the tip state and the certificate can answer that. The pool can price *backing* — that is the deposit screen, and the fix was to make it aggregate correctly — but it cannot price *settlement*.

So closing §1's upward half rests on the aggregated deposit screen here, plus whatever prices the declaration itself; it does not rest on the builder fix. What that fix actually delivers is the builder half, and that is closed: the dry run already knows each certificate's outcome, so the builder now excludes everything that is not `Applied` rather than only `DROPPED`. That is the right place for it — the builder is downstream of a real fold against a real candidate block, which is exactly the information the pool does not have. It stops miners spending block space on certificates the fold will pay them nothing for; it does not, and cannot, change the pool's floor.

One subtlety there, because the obvious implementation is wrong. A `DROPPED` certificate is state-neutral, so removing one cannot change any other certificate's outcome and a single dry-run pass is exact. A **skip is not neutral**: the fold debits `Deposit.Cell` and credits `Deposit.RefundTo`, and the V-rules require only that `RefundTo` be a native balance slot at a user address — not that it be the depositor. So a skip can be a net *credit* to a third party, and a later certificate's `GUARD_GE` can hold in the dry run **only because that skip ran**. Remove the skip on the strength of that same dry run and the later certificate skips for real, in the final block, unpaid — precisely the outcome the fix exists to prevent. `dropTheDrops` therefore iterates to a fixpoint; it terminates because each pass either removes at least one certificate or returns. `TestMinerDropsSkipsThatOnlyOtherSkipsPaidFor` is the witness, and it fails against a single-pass builder. **§1's own acceptance criterion, read as "a floor an attacker cannot pin", is not met by this section and cannot be** — the paragraph above explains why no choice of floor metric substitutes for pricing the declaration, and §2.1's closing subsection states what *is* delivered now that the screen aggregates: the pin survives as a mechanism, but not at §1's flat price. What *is* closed here is narrower and worth having on its own: **an arrival can no longer remove a certificate that outbids it.** That is §2.2's guarantee, stated in the currency residents actually declare, and it was not delivered before — neither by the original `victims[0]` gate, which covered only the first of `need` removals, nor by either chain-priced replacement.

**What closes §1's flood, now that the screen aggregates.** The pin is not made impossible, and this section has argued at length that it cannot be: "cheap base, dear tail" is simultaneously the flooder's pin and the honest user's fee bump, so the pool cannot refuse one without refusing the other. What is closed is the *flat price* §1 actually reports.

Two mechanisms compose, and only these two — neither is a floor metric:

- **The aggregated deposit screen removes the per-identity discount.** The screen sums every ceiling a cell already backs, so a 64-certificate chain costs the sum of its members rather than the largest one. Measured: the enforced admission threshold for §1's own chain shape is 83,592,000 drops, exactly the sum; before the fix it was 20,592,000, exactly the largest single ceiling.
- **Canonical form plus `FeeCeiling` bound the pin's height.** `UnmarshalFeeBid` refuses `SeqPriority > SeqMax` and `FeeCeiling` is computed from `SeqMax`, so a tail cannot declare a pinning priority without declaring the capital to back it. Below `SkipFee / seqGas` (1,666 at `spec.Devnet()`'s rates for a minimal transfer) `SkipFee` dominates and the pin is free; above it the cost rises one-for-one with the declaration, for an attacker's tail exactly as for an honest fee bump's. Measured: raising the pinned tail 20× past that boundary raises the enforced cost by 19,592,000 drops — precisely the tail's own ceiling increase, no more and no less.

**Not the builder fix.** An earlier draft credited that for the second half. It cannot: it is a builder fix, downstream of admission, and the pool's floor is not a quantity it touches — see the correction below. The enforced-cost measurements above are taken entirely at admission.

Whether the resulting absolute figures deter a real adversary is a separate, open question — the same undetermined-number question §4 raises about every default in this document, `SkipFee` included, and left to the M3 testnet. What is settled is the shape of the curve: there is no attacker-specific discount at any point on it.

There is one more dependency worth recording, because it is remote from the code that relies on it. Chain pricing means a single cheap certificate sets its whole underwriter's eviction rank, which would be a griefing primitive if a third party could attach a certificate to somebody else's chain. It cannot: `UnderwriterID()` is `Deposit.Cell.Addr`, **V5** requires that cell to be a *user* address, and **V4** then requires that address's signature. V4's requirement is a condition (`if crypto.IsUserAddress(...)`) rather than a whitelist, so an era that ever admitted a non-user deposit cell would make chain pricing remotely griefable for the price of one certificate, where the old tail pricing was not.

### 2.2 Anti-churn

Naive price-eviction is itself a denial of service: an attacker who can displace the marginal certificate by one drop forces the evicted one to be re-gossiped, and repeats. Three mitigations, which interact and are therefore designed together:

**A minimum bump to displace.** An arrival must beat the certificate it would evict by `max(1 drop, ⌊resident × EvictionBumpPercent / 100⌋)`. Stated that way on purpose: the multiplication is integer and it truncates, so the *percentage* is a target the rule approaches from below — a resident declaring 19 is displaced at 20, which is 5.26%, and one declaring 99 at 108, which is 9.09%. The guarantee is the formula, not the percentage. This is the standard replace-by-fee guard and it turns "displace for one drop, repeatedly" into "pay 10% more each round", which is a geometric cost the attacker cannot sustain.

The floor of one drop is not decoration. `resident × bumpPercent / 100` is integer division and it truncates, so at 10% the percentage bump is exactly **zero** for every resident declaring fewer than ten drops — and the comparison is `≥`, so an arrival declaring *exactly* what the resident declared displaced it, free, as often as it liked. §1 makes that the attacker's home range: a zero-priority certificate is perfectly valid and costs only a refundable deposit, so a flood sits at the bottom of the scale by construction. Against residents declaring five drops, twenty consecutive same-price displacements were accepted, each one a forced re-gossip — the churn this section exists to price, at zero cost, in the range where it is cheapest to mount. The rule was already written down for `resident == 0`, where a strict increase was required; it now applies at every price, which is the same rule and subsumes the special case. Pinned by `TestDisplacementAlwaysCostsAtLeastOneDrop`.

**A per-sender quota.** `MaxPerUnderwriter` (already present) bounds how much of the pool one identity can occupy. Without it, price-eviction lets a single well-funded key own the whole pool at the cost of one high bid; with it, an attacker needs many funded identities, and funding them costs real coins that must first be *mined*.

**Hysteresis.** Eviction only engages above `EvictionHighWater` (default 90% of capacity) and, once engaged, evicts down to `EvictionLowWater` (default 85%) — as far as the arrival's price reaches. Without a gap, the pool sits exactly at capacity and every arrival triggers an eviction — the marginal certificate thrashes, and the network re-gossips it forever.

The gap and the bump have to be designed together, because one pass can remove up to `high − low` residents and each of them pays the re-gossip. "Beat the marginal resident by 10%" therefore has to be quantified over the whole cut, and over each victim's **own** declaration. §2.1's answer is to quantify it exactly there and nowhere else: the pass re-checks every victim against the arrival at the point of removal, so a victim the arrival did not outbid is *skipped* rather than the arrival being refused. The batch is proportional to what the arrival outbids, hysteresis is best-effort, and the floor is free to stay at the cheap end where §1 needs it.

The alternative — refusing any arrival that cannot fund the full cut — is what §2.1 measures and rejects. It does not reduce churn (a skipped victim is not re-gossiped either), it does not reduce work (a refused arrival leaves the pool full, so the next one pays the same pass), and it prices entry at the top of the cut, which is §1.

### 2.3 Dependent chains evict as units

The hazard: evicting a `Seq = n` certificate whose `Seq = n+1` child is still pooled **strands the child.** It can never apply — its parent's writes never happened — so it will skip and be billed, and the pool will happily keep offering it to miners until it does.

The rule: **under pressure, evict from the tail of a sender's `Seq` sequence, never from the middle.** A certificate is evictable only if no certificate from the same underwriter with a higher `Seq` is pooled. That makes the pool's eviction order agree with the fold's commit order (F1 sorts by `(underwriter, Seq, id)`), which is the property that keeps a chain either wholly present or truncated from its end.

**§2.3 through the third door: the rescreen sweep.** "Under pressure" scopes the rule above to the eviction pass, and the sweep that runs at every new tip answers to neither it nor `Readmit`. `rescreenLocked` drops certificates that have stopped being admissible, and such a certificate has to go wherever in a chain it sits — so dropping the middle strands everything above it, which is exactly the state this section exists to prevent, reached with no eviction pass misbehaving at all.

Its four reasons are not alike, and the difference is the whole rule:

- **Already committed.** The certificate was *billed*, which usually means it applied — and then its `Seq + 1` is *next in line* rather than stranded, so truncating there would throw away the chain about to become the pool's most valuable. A repair that truncated on every reason would be a worse bug than the one it fixed. Benign in the common case only; see the residual below.
- **TTL passed**, **below the base fee**, **deposit no longer covers.** The certificate never applied and cannot be included as it stands, so nothing above it can ever apply either.

Both stranding witnesses are ordinary traffic, not attacks. Neither needs more than a chain whose members declare different ceilings or different deadlines — a modest bound on a routine payment and a higher one on an urgent follow-up:

```
base SeqMax 10 000, tail 5 000 000; the sequential base fee rises to 20 000
  -> base dropped, tail pooled and permanently unappliable
base TTL 12, tail TTL 30; rescreened at tip 15
  -> base dropped, tail pooled and permanently unappliable
```

So a stranding removal truncates that underwriter's chain above it, cut at **the lowest vacated `Seq` that no surviving certificate re-occupies**. Every clause of that is load-bearing:

- **Lowest**, not merely one of them. A cut taken higher leaves a member whose predecessor is gone, and makes the answer depend on map iteration order, so two nodes would disagree about their pools.
- **Re-occupancy**, because a duplicate `Seq` is not stranding: `Seq` is an ordering key rather than a nonce, so a certificate still standing at a vacated `Seq` keeps the chain above it reachable.
- **Per `Seq`, not per underwriter.** Testing re-occupancy once, at the lowest vacancy, and then exempting the whole underwriter is wrong whenever a chain vacates two levels and only the lower is re-occupied — `Seq 0` twice with one dropped, `Seq 1` dropped, `Seq 2` standing. The chain is still reachable through `Seq 0` and still holed at `Seq 1`, so the cut is 1 and `Seq 2` goes.

**Residual, and it is not closable in this package.** `Seen` means *billed*, not *applied*: `core/fold` settles `SkippedStale` and `SkippedOverflow` through the same path that ends in `markSeen`. So a base that committed **and skipped** is `Seen`, its writes never happened, and its successor's declared reads will not hold — that successor is guaranteed to skip and stays pooled. The pool cannot tell the two apart: `StateReader` carries `Get`, `IsSpent` and `Seen`, and none of them reports which outcome a certificate had. Truncating on every `Seen` would discard the successor in the common applied case, which is the worse error, so the benign reading is kept and the gap recorded. Closing it needs the outcome to reach the pool, which is wider than §2.3.

Pinned by `TestRescreenTruncatesAChainItStrands`, whose six scenarios are the two witnesses, the committed-base counter-case, the lowest-cut requirement, the per-`Seq` re-occupancy shape, and the plain duplicate `Seq`.

The cost is that a low-paying certificate deep in a long chain protects the chain above it *from being evicted out of order*. That is correct: the chain is only worth anything as a whole, and evicting its base to save space would leave the pool holding certificates that are guaranteed to skip.

What it must **not** do — and what §1's flood found it doing — is let that low-paying certificate raise the price everybody else pays for entry. Being unevictable and being expensive are different properties, and the original code conflated them by taking the floor from whatever survived this rule's filter. §2.1 separates them: this rule decides *which* certificates may leave, the chain price decides *in what order*, and the cheapest of the certificates that may leave decides *what the arrival must pay*. Neither is weakened to obtain the others, and `TestEvictionNeverStrandsADependentChain` still pins this rule exactly as written.

**How the absence of stranding is actually obtained, because it is not obvious and a refactor would destroy it.** The chain summary is computed **once** per eviction pass and is deliberately *stale* for the rest of it. Evictability is `Seq == maxSeq` read from that snapshot, so every entry an underwriter contributes to the victim list sits at that underwriter's highest pooled `Seq` *in the snapshot* — and removing any **subset** of those strands nothing, because nothing in the pool sits above them. A pass that removes many certificates therefore cannot hole a chain even though the snapshot stops describing the pool after the first removal.

It is a subset property and not a uniqueness one. `Seq` is an ordering key rather than a nonce, so one underwriter may pool several certificates at the same `Seq` — replace-by-fee is exactly that — and then contributes several entries. Verified on `Seq 0, 1, 1`: both tails may be taken in one pass and `Seq 0` survives with no hole. Recomputing the snapshot between evictions — or letting the order return a member that sits *below* another pooled member of the same chain in order to hit the low-water target — would strand chains immediately. The corollary is that a pass may **under-deliver** on the low-water mark when few chains are evictable. That is not an oversight to be tidied away; it is the shape of the safety property, and the phrase "peeled off across successive evictions" above means *successive passes*, not successive removals within one. §2.1's floor is chosen to be consistent with it: a gate that guaranteed a full cut would have to refuse, at the dearest removable price, exactly the arrivals this rule was already going to under-deliver for.

**§2.3 through the front door: admission holes chains too, and eviction's care did not cover it.** Everything above is about the eviction pass. But nothing at *admission* enforces `Seq` contiguity, and a chain enters the pool one certificate at a time, so the same hole is reachable without any eviction pass ever misbehaving:

- **Readmission after a reorg.** `Readmit` fed an abandoned branch's certificates to `Add` one at a time and discarded the errors. During a reorg the pool is at its high-water mark, so any member can be refused — and with chain-unit ordering a chain containing one cheap member is the pool's *first* victim, so a member could also be admitted and then evicted by a later member's own eviction pass, while that later member was admitted above the gap. Measured over which of a 40-certificate chain's positions holds the cheap member: **7 of 40** positions holed before chain-unit ordering, **31 of 40** after it, **0 of 40** now. `Readmit` now walks each underwriter's certificates in `Seq` order and stops at the first one that does not end up pooled, so what is readmitted is always a prefix. Dropped members are re-gossiped like any other certificate the pool declined.
- **A user extending their own chain.** The arrival's eviction pass ranks its *own* underwriter's chain by that chain's cheapest member, so a user whose `Seq 0` bid little has the cheapest chain in the pool — and the first victim their `Seq 1`'s admission reaches is their own `Seq 0`. The pass now refuses to evict a certificate from the arrival's own underwriter below the arrival's `Seq`: eviction may not strand a chain on behalf of the certificate it is making room for.

Pinned by `TestReadmitNeverHolesADependentChain` and `TestAnArrivalNeverEvictsItsOwnChainBase`.

### 2.4 What is not changed

Admission still runs the V-rules first and unconditionally, still applies the deposit screen against the current tip, and still refuses certificates whose TTL is expired, unbounded, or too near. Eviction is what happens *after* a certificate has earned a place, not a relaxation of how it earns one.

### 2.5 What the per-sender quota is, and is not

`MaxPerUnderwriter` is **not** the Sybil defence, and reading it as one would be a mistake with consequences — it is a bound on how much of the pool a single identity can occupy, and identities are free.

The Sybil defence is the **deposit screen applied against the current tip, summed across everything a cell backs**. A certificate is admitted only if its signer's deposit cell is covered, *at the current tip*, for the sum of its own fee ceiling and every other certificate already pooled against that same cell — not for its own ceiling in isolation. An earlier version of this screen checked each certificate independently, which let one funded cell back up to `MaxPerUnderwriter` certificates simultaneously at the cost of one; that was a correctness defect, not a design choice, and it is fixed now. An attacker who wants N pool slots therefore needs at least `ceil(N / MaxPerUnderwriter)` funded identities, each funded for the full sum it backs, and in Era 0 — no premine, no allocation — the only source of funds is mined coins. The cost of flooding the pool is denominated in proof of work, not in key generation.

Worked example, `DefaultPolicy`: the pool cannot be held above its high-water mark — crossing it evicts down to the low-water mark in one pass — so the reachable, holdable occupancy is `EvictionHighWater` of `MaxCertificates`, i.e. 18,000 slots. Each slot's minimum cost is `skip_fee` (the deposit ceiling's protocol-constant floor, R1-H1) regardless of which identity funds it, so the **minimum** capital to occupy all 18,000 is exactly `18,000 × skip_fee = 18,000 × 1,000,000 drops = 18,000,000,000 drops = 180 ZCD` — up from the roughly 2.82 ZCD the unaggregated screen allowed for the same occupancy, a ~64x increase that tracks `MaxPerUnderwriter` exactly, because that is precisely the amplification the defect used to give away for free. `MaxPerUnderwriter` bounds only how thinly that capital may be concentrated, not its total: reaching 18,000 slots needs at least `ceil(18,000 / 64) = 282` funded identities, with 281 filled to the quota and one holding the 16-certificate remainder (282 identities funded to the full quota would cover 18,048 slots and cost proportionally more, ≈180.48 ZCD — a valid but non-minimal way to reach the same occupancy).

This capital is locked but not spent, which matters for how much of a deterrent it actually is. **A settled bid** (open) would change this: a certificate's declared `SeqPriority` is only ever collected on the *applied* path — a certificate a rational miner never includes pays nothing beyond its deposit reservation, and flood certificates are built to never be included. So the 180 ZCD is refundable in full the moment the flood is withdrawn, not burned, and the eviction-floor-pinning question this composes with is §2.1's, not this section's.

The quota's actual job is smaller and worth stating separately: it stops one *legitimate* heavy user from crowding the pool by accident, and it forces an attacker's capital to be split across identities rather than concentrated, which makes the eviction ranking work on a wider spread of prices. It is a fairness and dispersion knob, and it is *not* made redundant by the screen being summed: the sum prices occupancy honestly, but nothing about pricing it honestly stops one identity — however well funded — from buying every slot. The quota is what still forces that capital to spread across many prices. If the quota were removed entirely, the pool would still cost money to flood, but one whale could own it; if the deposit screen were removed, the quota would buy nothing at all.

The distinction matters for tuning. Raising `MaxPerUnderwriter` relaxes fairness and lowers the identity count needed to reach a given occupancy (raising it, in turn, raises the capital needed per identity, since the sum scales with how much that identity backs). Weakening the deposit screen — admitting on a declared deposit rather than a covered one, say, checking it against the arrival alone rather than the sum, or screening against a stale state — removes the defence.

### 2.6 The cost of saying no

Everything §2.1 describes runs *before* the arrival's price is consulted: the chain summary, then the candidate list and the `min` read off it. Both are `O(len(byID))`. That is the correct shape for an arrival that is going to be admitted — the pass has to know what it may remove — but it is the wrong shape for one that is going to be refused, and refusals are the case an attacker controls. Gossiping a stream of certificates priced below the market forces two full walks of the pool per certificate, under the write lock, for the price of one gossip message and one signature. `Candidates()`, `IDs()`, `Stats()` and every RPC reader contend on that lock. That is the contention this section closes.

The exact floor cannot be made cheaper. It is a minimum over a set defined by a per-entry predicate — §2.3's evictability, plus the arrival's own chain base — so answering it exactly means visiting every entry, and no data structure changes that. What *can* be made cheap is a **sound lower bound** on it, and a bound is enough to refuse:

> `floor = min(candidates) ≥ min(all pooled)`

because the candidates are a subset of what is pooled, and a subset's minimum is never below the whole set's. The pool maintains `min(all pooled)` incrementally in a lazily-cleaned min-heap — pushed on admission, never popped on removal, swept on read, and rebuilt when it has drifted past twice the pool's size so it is bounded by the pool rather than by the node's admission history. Amortised `O(1)` per certificate.

The refusal follows because `beatsByBump` is monotone in its resident argument: raising the price you must beat never makes beating it easier. So an arrival that cannot clear the lower bound provably cannot clear the floor, and it is refused with the same `ErrBelowEvictionFloor` the exact path would have returned — without the pool being walked at all.

Three properties are worth stating explicitly, because they are what keep this a fast path rather than a second authority:

- **It can only refuse, never admit.** Clearing the bound decides nothing; the arrival falls through to the exact computation, which remains the sole authority on admission and on which residents may be removed. Nothing here ever licenses a removal, so §2.2's invariant and §2.3's chain rule are untouched.
- **Its soundness does not depend on *which* residents the candidate filter excludes**, only that it excludes rather than invents. Both exclusions are `continue`s over a loop ranging the pool, so a future third exclusion, or a change to §2.3's rule, keeps the bound sound without this section needing to know. What would break it is a floor synthesised from something other than a resident's own declaration — a value read off `params`, say. That is the one refactor this section forbids.
- **A stale heap entry is safe.** It names a price that was pooled and no longer is, which can only sit below the live minimum — the conservative direction. Sweeping it keeps the bound *tight enough to fire*; it is not what keeps it correct.

One behavioural difference, deliberate: an arrival can now be refused with `ErrBelowEvictionFloor` where the exact path would have said `ErrFull`, when the pool is non-empty but holds no candidate for that particular arrival. Neither error is distinguished by any caller — they exist to tell an operator reading logs why a pool is refusing — and `ErrBelowEvictionFloor` is the more accurate of the two here, since the pool is at high water rather than at its hard cap and the arrival underbid it.

**Measured, with the counterfactual, because one column would prove nothing.** The comparison is the same tree with the fast path disabled and nothing else changed (darwin/arm64, `-benchtime 300x`):

| pool size | fast path | disabled | ratio |
|---|---|---|---|
| 500 | 2.09 ms | 1.70 ms | 0.8× |
| 4 000 | 1.67 ms | 4.08 ms | 2.4× |
| 18 000 | 2.23 ms | 48.99 ms | **22×** |

Disabled, a refusal costs 1.70 → 4.08 → 48.99 ms across a 36× range in pool size. With the fast path the same column reads 2.09 → 1.67 → 2.23 ms: flat inside this box's run-to-run spread. At 500 the fast path measures marginally *slower*, which is reported rather than trimmed — the difference is below the spread, and a small pool is precisely where two `O(n)` passes cost nothing anyway. The property is the shape and not the constant: refusal cost stops being a function of how much is pooled, and pool size is the attacker's only lever. `BenchmarkRejectedArrivalIsSizeIndependent`.

Those numbers were taken when a refused arrival still paid for Ed25519 inside `Add`, which dominated the absolute column and compressed every ratio in it. §2.8 removed that term from the refusal path, so **every figure in the table above is stale, ratios included** — subtracting the same constant `k` from both columns does not preserve `b/a`, it raises it wherever `b > a`, which is precisely why the old order compressed these ratios in the first place. The staleness is therefore in the direction that makes this section's point more strongly and cannot make it weaker: the fast-path column loses `k` from a cost that was flat, the disabled column loses `k` from a cost that grew with the pool, and the 22× row can only get further apart. What the row asserts is the *shape* — refusal cost independent of pool size — and that survives any common constant. Re-measuring belongs to the double-verification residual below, not to this section's claim.

What this does **not** do is change the price of entry. The floor is the same number it was; only the cost of computing a refusal falls. §2.1's unclosed half — that the floor's currency is declared rather than settled, and so is free for a flooder to pin — is untouched and still needs a settled bid; the aggregated deposit screen is the half that has landed.

### 2.7 The screen bounds slots; it does not bound bytes

A certificate's encoded size is not uniform. The V-rules permit shapes from a few hundred bytes (a single transfer) to over ten thousand (the structural maximum for reads, writes, signatures and moves a certificate can carry at once), and nothing about the count budget above prices the difference — `MaxCertificates` slots of the expensive shape cost dramatically more resident memory than the same count of the cheap one, at the same capital cost per slot, because `FeeCeiling`'s per-byte term is priced far below what it would take to make size itself expensive.

The pool therefore carries a second, independent budget measured in bytes, with its own high- and low-water hysteresis (reusing `EvictionBumpPercent`, `EvictionHighWater` and `EvictionLowWater` against `MaxBytes` rather than inventing a second set of knobs). Either budget reaching its high water triggers the same eviction discipline described in §2.1-§2.6 — the same §2.6 fast path, the same chain prices, the same candidate set carrying §2.3's chain-safety and own-chain predicates, the same floor read from that set. Only the stopping condition differs: the byte pass drains until the pool is under its byte low water rather than its count low water. A byte-driven eviction and a count-driven one are therefore indistinguishable to a resident: the pool does not know or care which budget made room, and neither budget can license removing a certificate the arrival did not outbid.

Two asymmetries with the count budget are deliberate, and both come from the same fact — a certificate is worth exactly one slot but anything from 848 B to roughly 15 KB.

**The byte trigger counts the arrival; the count trigger does not.** Testing occupancy *before* the arrival can only ever overshoot a count budget by one slot, which the low-water gap absorbs. Testing it before the arrival against a *byte* budget lets a pool resting one byte below the mark admit a maximum-shape certificate with no byte check at all, so the effective bound becomes `MaxBytes` plus one worst-case certificate rather than `MaxBytes`. The overshoot is transient — the next arrival finds the pool over its high water and evicts back down — which is precisely why it is easy to miss: a pool sampled only after a settled sequence reads clean while having held nearly twice its budget in between. Resident memory is what this budget bounds, so the peak is what the rule is written against and what `TestByteBudgetCountsTheArrival` measures.

**The byte pass's final `ErrFull` is reachable; the count pass's is not.** Clearing the floor guarantees the pass removes at least one *certificate*, which is what makes the count budget's hard cap unreachable. It guarantees nothing about how many *bytes* that certificate carried. A pool of minimal certificates cannot make room for a maximum-shape arrival one 848-byte eviction at a time once the candidate set is exhausted, and in that case the arrival is refused rather than admitted over the budget.

### 2.8 Admission is ordered by cost

The pool is an ingress pipeline, so the ingress-cost rule applies to it: **integer/structural comparisons, then dedup and window checks, then budget checks, then signature work.** `Add` used to run the whole of `validity.Check` — including V2, the Ed25519 verification — as its first statement, ahead of every gate that can refuse in constant time. That is the ordering defect this section closes.

The cheapest refusal the pool has needs no funds at all: a certificate whose TTL has already passed is refused by two integer comparisons, stays refused as the chain advances, and can be replayed indefinitely because gossip dedup is per-message rather than per-certificate. Under the old order each replay bought a full signature verification. Under the new one it buys two comparisons.

The order is now:

| stage | checks | cost |
|---|---|---|
| structural | `validity.CheckStructural` — V1, V3, V4, V5, V6, V7 | integer comparisons over the decoded body |
| dedup / window | `byID` lookup, the TTL window (B1/B2's policy shadow), the committed-set lookup | one map read each |
| budget | fee floor, aggregate deposit screen (§2.5), `MaxPerUnderwriter` | a few state reads |
| signature | `validity.CheckSignatures` — V2 | Ed25519, and roughly two orders of magnitude above everything above it |
| eviction | §2.1–§2.7 | `O(1)` amortised to refuse, `O(n)` to admit |

Three things this does not change, and they are the whole risk:

- **The set of admitted certificates.** Every gate that moved is a predicate with no side effect, so admission is the same conjunction evaluated in a different order. What moves is the *error identity* of a certificate that fails a policy gate **and** V2 at once: it is now named by the policy gate rather than by V2. That is the intended effect and not a side effect — it is exactly what makes the free refusal free — and no golden vector records a mempool policy error, because the corpus records V-rule identities and the pool's errors are not V-rules.
- **The boundary property.** V2 still runs unconditionally on every certificate the pool admits. A caller that already checked validity still pays for it here, because a boundary that trusts its input is not a boundary. `Add` orders the predicate; it does not weaken it.
- **What an unverified certificate can touch.** The eviction pass deliberately stayed *behind* V2. It is the first thing in `Add` that mutates the pool, and moving it in front of the signature check would have let a certificate with a forged signature evict honest residents for free — trading that flood for a strictly worse one. `TestAnUnverifiedCertificateNeverEvicts` pins that boundary from the other side.

**The lock the reorder must not put signature work under.** §2.6 spent a whole heap-backed fast path on one observation: `Candidates()`, `IDs()`, `Stats()` and every RPC reader contend on the pool's write lock, so work done under it is work an attacker can make everyone else wait for. Moving V2 after the `screen` gates put it inside that critical section, which would have been a strictly worse version of the same problem — a forged certificate is never pooled, so it never raises the aggregate deposit screen (§2.5) or the per-underwriter count that bound honest traffic, and **one funded deposit cell therefore screens an unbounded stream of distinct forgeries**, each buying a full Ed25519 pass under the lock for the price of a gossip message. `Add` consequently screens under the lock, releases it to verify, and retakes it to re-screen, evict and insert. The re-screen is what keeps that decomposition honest: `screen` is a pure predicate, so evaluating it again on the second acquisition is exactly the atomic decision the single critical section took, and without it concurrent arrivals of one id are admitted more than once (`TestAdmissionIsStillAtomicAcrossTheReleasedLock` measures 7 of 16) and, more to the point, two certificates from one underwriter are both admitted against a deposit funded for one, which is the amplification §2.5 exists to stop (`TestTheAggregateDepositScreenSurvivesTheReleasedLock`). A refused certificate still increments the refusal counter exactly once, because the first screen only decides whether V2 is worth paying for.

The order is enforced by a data dependency rather than by this paragraph: `Pool.screen` is the sole producer of the unexported `screened` value, `Pool.verifySignatures` requires one, so V2 cannot be moved back in front of the cheap gates without the move being visible at its call site. The code already carried a comment claiming the checks ran in the right order, one line above the code that did not, which is why a comment is not what this section relies on.

**The residual.** `node/p2p/engine.go` runs its own `validity.Check` immediately before calling `Add`, so a gossiped certificate that reaches admission is still verified twice — the pool's half of the double verification is closed here, the engine's half is not. The reorder does remove the second verification for every certificate a cheap gate refuses, which is the attacker-controlled case, but an *accepted* certificate still pays twice.

## 3. Rejected alternatives

- **Refuse arrivals when full** (the M1 behaviour). Rejected: §1.
- **Evict the oldest.** Rejected: it is the same attack with an extra step — an attacker refreshes their certificates and legitimate traffic ages out. It also evicts precisely the certificates closest to being included.
- **Evict randomly.** Rejected: it makes the attack probabilistic rather than impossible, gives an attacker a linear return on volume, and makes a node's behaviour unreproducible against its own logs.
- **Rank by total fee (sequential + parallel).** Rejected: a certificate that is enormous in the abundant market outranks one that is valuable in the scarce one. This is R2-H2's mistake relocated, and it would be worse here because the pool feeds the builder.
- **Rank by deposit size.** Rejected: the deposit is a *ceiling*, not a payment, and after R2-H1 it reflects how much headroom a signer bought rather than what they offered. Ranking by it would reward locking capital rather than paying for ordering.
- **No per-sender quota, relying on price alone.** Rejected: price alone lets one identity own the pool. The quota is what forces an attacker to spread across identities that must each be funded from mined coins.
- **Global fee floor that rises with pool occupancy.** Tempting, and it is a real design used elsewhere. Rejected for Era 0 as *premature*: it is a second fee market bolted onto a node, with its own dynamics and its own grinding surface, at a moment when nobody has observed the first one. Reopen it after the M3 testnet has produced data.

## 4. What is not decided here

**The numbers.** `MaxCertificates`, `MaxBytes`, `MaxPerUnderwriter`, `EvictionBumpPercent`, and the water marks are reasonable, not derived. They are node policy rather than consensus — nodes may differ without forking anything — but a default that every node inherits is a de facto standard, and there is no evidence for these six values yet. `MaxBytes` was sized by measuring real encoded certificates rather than guessed outright (§2.7), which is a step better than the others, but it is still a default and not a derivation. Measuring all of them is a stated purpose of the public testnet.

**Fee-floor dynamics under sustained congestion.** See the rejected alternative above.

## 5. Pinned by

| Test | Property |
|---|---|
| `TestFloodDoesNotCensorHigherPayingArrivals` | A pool filled with minimum-priority certificates still admits a high-priority one, by eviction. This is §1's attack, and it fails against the M1 pool. |
| `TestEvictionRanksBySequentialPriority` | The evicted certificate is the lowest sequential-priority resident, not the lowest total fee. |
| `TestEvictionRequiresABump` | An arrival that does not beat the cheapest removable resident by the bump is refused, so displacement is not free. |
| `TestDisplacementAlwaysCostsAtLeastOneDrop` | The bump is at least one drop at every price, not only at zero. The percentage truncates to nothing below ten drops, which is where §1's flood lives, and `≥` then made same-price displacement free and repeatable. |
| `TestEvictionNeverStrandsADependentChain` | No certificate is evicted while a higher-`Seq` certificate from the same underwriter is pooled. |
| `TestEvictionHysteresis` | Eviction engages at the high-water mark and clears toward the low-water mark, so the marginal certificate does not thrash. How far it clears is bounded by what the arrival outbids; see the next two rows. |
| `TestAnEvictionPassSortsOnlyWhatTheArrivalCanTake` | The pass sorts the residents this arrival may take, not every removable resident. One identity renting the cheapest slot must not be able to price an `O(n log n)` sort under the write lock per certificate. |
| `TestOccupancyNeverRisesAboveTheHighWaterMark` | The floor is read over the residents the arrival may take, not every removable one, so an accepted pass always removes at least one certificate. A user extending their own chain cannot set the floor with a base the pass is forbidden to remove and be admitted having outbid nobody. |
| `TestAdmissionRequiresACoveredDepositIsTheSybilDefence` | A certificate whose deposit is not covered at the current tip is refused, which is the property §2.5 identifies as the Sybil defence. |
| `TestPinnedChainCostsTheSumOfItsDeclarations` | §1's own chain shape costs the **sum** of its members' ceilings to pool, not the largest one, measured as the enforced admission threshold by binary search rather than by what a fixture deposits. Fails against a per-certificate screen with the exact gap it leaves. |
| `TestPinCostScalesWithTheDeclaredTail` | Raising the pinned tail raises the enforced cost by exactly the tail's own ceiling increase, so the pin is priced in proportion to its height rather than flat. |
| `TestTheFloorIsStillPinnableAndThatIsDeliberate` | The floor remains pinnable by a Seq-chain flood, and that is deliberate — the shape is indistinguishable from an honest fee bump. Records what §1's fix does *not* close, so the cost results above are not misread as removing the mechanism. |
| `TestFeeCeilingScalesWithDeclaredPriorityPastTheFreeZone` | The arithmetic the two above rest on: `FeeCeiling` is flat at `SkipFee` below `SkipFee / seqGas` and scales with the declared priority above it. |
| `TestChainedFloodCannotPinTheEvictionFloor` | A flood of `Seq` chains cannot buy the eviction *order*: an arrival that outbids the flood's tails removes the flood, not the honest residents that declare a hundred times less. It also pins the invariant's price — an arrival below the tails' declarations is refused, not admitted against them. The crossing of §2.1, §2.2 and §2.3, and it is §1's flood. |
| `TestEvictionFloorIsTheCheapestRemovableNotThePoolMinimum` | The floor is the cheapest **removable** declaration, not the cheapest thing in the pool. An arrival declaring 2 cannot evict residents declaring 1,000,000 merely because one honest chain's base bids 1 — a base cannot leave, so it is not a price to be admitted against. The witness contains no attacker. |
| `TestOneDearTailCannotSetThePoolsAdmissionPrice` | One resident declaring 1,000,000 cannot price entry for a pool whose market is 100. Fails on any floor taken at the low-water cut, where a removable set smaller than `need` makes the floor the *dearest* removable declaration. The witness contains no attacker either. |
| `TestAPartiallyQualifyingArrivalIsAdmittedAndTakesWhatItBeats` | An arrival that outbids the cheapest removable resident but not the whole cut is admitted, and removes exactly the residents it outbid — hysteresis is best-effort, and the invariant is carried by the per-victim check rather than by the gate. |
| `TestFeeBumpedChainsDoNotCollapseTheEvictionFloor` | The same witness at the threshold that a chain-priced floor fails at: `need` ordinary fee-bumped chains, every removable certificate declaring 1,000,000, an arrival declaring 2 refused. Fails on any floor read from chain prices. |
| `TestArrivalMustOutbidEveryResidentItRemoves` | The dual direction, against each removed certificate's **own** `FeeBid.SeqPriority` and in a fixture where every chain's base and tail differ: an under-priced arrival is refused, and an admitted arrival outbids by the bump every certificate the pass actually removed. |
| `TestReadmitNeverHolesADependentChain` | Readmitting a 40-certificate chain into a full pool leaves a prefix, never a hole, wherever the cheap member sits. |
| `TestRescreenTruncatesAChainItStrands` | The rescreen sweep drops a no-longer-admissible certificate wherever it sits, so it truncates the chain above it — cut at the lowest vacated `Seq` that nothing re-occupies, tested per `Seq` rather than per underwriter, and never for a certificate dropped because it was already billed. Both witnesses are ordinary traffic: a chain whose members declare different ceilings, and one whose members declare different deadlines. |
| `TestAnArrivalNeverEvictsItsOwnChainBase` | A certificate's admission never evicts a lower `Seq` from its own underwriter, so a user extending their own chain cannot strand it. |
| `TestFloorLowerBoundIsExactlyTheTrueMinimum` | §2.6's heap really does return `min(byID)` — checked against an independently recomputed minimum across randomised admissions and removals, with removals not restricted to the minimum so lazy cleanup is genuinely exercised rather than only ever popping the top. |
| `TestFloorHintStaysBoundedInSize` | The heap is bounded by the pool's size, not by the node's admission history. §2.6 buys refusal cost with memory, and this is the half that keeps the memory paid for. |
| `TestCheapBoundNeverRefusesWhatTheExactFloorWouldAdmit` | The relation §2.6 actually rests on, which neither of the two rows above pins: failing the cheap bound implies failing the exact floor. Real multi-`Seq` chains, so §2.3's rule genuinely excludes chain interiors and the two floors differ rather than coinciding trivially; arrival prices and `Seq` swept across both. Counts its own cheap refusals and strictly-loose bounds, so it cannot pass vacuously. |
| `BenchmarkRejectedArrivalIsSizeIndependent` | A refused arrival's cost reads roughly flat across pools of 500, 4,000 and 18,000, rather than growing with the pool as two `O(n)` passes would. §2.6's claim, as a measurement rather than an argument. |
| `TestAFreeRefusalBuysNoSignatureVerification` | Every gate in `Pool.screen` — dedup, the three TTL bounds, the committed set, the fee floor, the deposit screen, the per-underwriter cap — refuses at a cost of zero Ed25519 verifications, counted rather than timed. §2.8, and it fails on the previous order with a count of one for every gate. |
| `TestAFreeRefusalOutranksAForgedSignature` | The same property read through the public API with no test seam: a certificate that trips a cheap gate *and* carries a forged signature comes back named by the gate, not by V2. Which error is returned is a direct observation of which check ran. |
| `TestAForgedSignatureIsStillRefused` | The anti-vacuity companion to the row above — the forgery really does break V2 when no gate stands in front of it, so those rows are about ordering rather than about a certificate that was invalid twice over. |
| `TestTheCounterCanSeeAVerification` | One certificate, two tips: refused outside its TTL window at zero verifications, admitted inside it at one. The counter's zero is a zero it could have failed to produce. |
| `TestEveryFreeRefusalIsCoveredHere` | Every sentinel the pool exports is either covered by a row in the table above or is one of the two the eviction pass owns, so a gate added to `screen` cannot quietly go unmeasured. The sentinel list is read out of `mempool.go` by an AST pass rather than maintained by hand, because a hand-maintained list is blind to the one change it exists to catch — a newly declared sentinel. |
| `TestAnUnverifiedCertificateNeverEvicts` | The safety half of §2.8's reorder: a certificate with a forged signature that would otherwise clear the eviction floor removes nobody, while its honestly-signed twin does — so the pool really was at a mark where an eviction was there to be wrongly bought. |
| `TestVerificationDoesNotHoldThePoolLock` | `Add` pays for V2 with `pool.mu` released, so one certificate's Ed25519 pass never stalls another goroutine's read of the pool. Carries its own control — the same probe run under a deliberately held write lock must report the reader blocked — so "not held" is an observation rather than a blind spot. Fails against the first form of the reorder, which verified inside the critical section. |
| `TestAdmissionIsStillAtomicAcrossTheReleasedLock` | Releasing the lock across V2 does not split the admission decision from the insert: sixteen concurrent `Add`s of one certificate admit it exactly once. Fails with the re-screen removed (7 of 16 admitted). |
| `TestTheAggregateDepositScreenSurvivesTheReleasedLock` | The same atomicity where it is actually load-bearing rather than where a map would catch it anyway: two distinct certificates from one underwriter, raced against a cell funded for exactly one, admit exactly one. The `byID` dedup cannot decide this — §2.5's screen is a sum over what is already pooled, so its answer depends on whether the first arrival has landed. Fails with the re-screen removed. |
| `TestNoTestInThisPackageRunsInParallel` | The signature counters swap a package variable, so the package's own sources are read and any `t.Parallel()` fails the suite — the precondition those counters state, enforced rather than asserted. |
| `TestAnAdmittedCertificateIsVerifiedExactlyOnce` | `Pool.Add` pays for exactly one Ed25519 pass per admission. The pool's half of the double verification; the engine's pre-`Add` check is the other half and is not closed here. |
| `TestEvictionIsDeterministic` | Two pools given the same arrivals in the same order hold the same set — a node must be reproducible against its own logs. |
| `TestDepositScreenSumsAcrossPooledCertificates` | A cell funded for one certificate's ceiling but not two refuses the second, even though a per-certificate check would admit it — §2.5's aggregate screen. |
| `TestDepositScreenAdmitsUpToWhatTheCellCovers` | The positive half of the above: once the cell covers the sum, the second certificate is admitted. |
| `TestRescreenReEnforcesTheAggregateDepositSum` | If a cell's balance falls below what it backs, rescreening sheds from the tail of each affected chain until the sum fits again — the amplification does not come back on the next block. |
| `TestMaxPerUnderwriterBindsAfterAggregation` | The quota still caps one identity's occupancy even when that identity is funded far beyond what it needs — §2.5's claim that aggregation does not make the quota redundant. |
| `TestByteBudgetEvictsFarBelowCountHighWater` | The byte budget makes room by evicting, and engages long before the count budget would — §2.7. |
| `TestByteBudgetRequiresABump` | Displacement by the byte budget is bump-gated, the same as displacement by the count budget. |
| `TestByteBudgetNeverStrandsADependentChain` | The byte-budget eviction path is tail-safe, the same as the count-budget path (§2.3). |
| `TestByteBudgetCountsTheArrival` | `MaxBytes` bounds the pool, not the pool plus one worst-case certificate: a trigger that reads occupancy before the arrival admits a maximum-shape certificate unchecked whenever the pool rests below the mark. Measured as a peak across arrivals, because the overshoot is transient — the witness reads clean on every other step. |

Per the anti-vacuity rule, each floor test recomputes the *rejected* rule from the pool's own contents and asserts it would have decided differently in that same scenario, before any assertion about the live rule: the pool-minimum rule, the `need`-th-smallest-chain-price rule, and the `need`-th-smallest-declared-price rule each get their own witness. `TestArrivalMustOutbidEveryResidentItRemoves` additionally asserts that at least one certificate the pass removed declares *more* than its chain price, so the scenario cannot stop distinguishing a declared-price floor from a chain-price one without the test noticing. None can pass by measuring the scenario instead of the rule.
