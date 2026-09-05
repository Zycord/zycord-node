# Zycord — Whether genesis ships the health signal armed, and what shipping it latent commits the project to

**Status: PENDING. The decision is the owner's and is not made in this document.** §§1-5 are the evidence, §6 states the three branches with their real costs, §7 is a recommendation with its reasoning, and §8 is the single question that has to be answered. Nothing here changes a consensus rule, a parameter, or a line of Go, and §6 explains why the recommended branch cannot.

**Scope.** Whitepaper §8.1 gives the elastic sequential ceiling a health gate: an epoch whose blocks cited more than `health_gate_bps` of competing headers withholds growth in `T` for that epoch. The *rules* for citing are implemented, consensus-complete and genesis-frozen. The *miner* never cites anything, so in this release nothing ever reports an epoch unhealthy and the gate can only ever permit growth. That is sound — an empty citation list is valid by construction — which is exactly why it can be shipped without anybody noticing they decided to. [ARCHITECTURE §20](../ARCHITECTURE.md) states the gate in the alternative: the miner gathers and cites real competing headers, **or the decision to ship without it is made explicitly rather than by default**. This document exists to make that choice recordable before block 0 on 2026-09-15.

**The freeze is what removes the option of deferring.** `Header.CitesRoot` is in the fixed-size SSZ header and in the consensus root; it cannot be added after launch and it cannot be dropped after launch. The field ships from block 0 whichever way this goes. So the *implementation* may arrive in any later release and the *decision* cannot arrive later than block 0 in any meaningful sense.

---

## 1. What the tree implements today

Read at this branch. Every claim below is at the cited file and line.

**The rules are complete and they are consensus.** `core/fold/blockrules.go` enforces eight of them:

| Rule | Site | What it requires |
|---|---|---|
| B15 | `blockrules.go:102` | at most `max_cites_per_block` (4) citations |
| B16 | `blockrules.go:109` | `CitesRoot` commits to the cited headers |
| B17 | `blockrules.go:292` | no citation at height 0 or 1 |
| C0 | `blockrules.go:312` | a citation carries a known header version |
| C1 | `blockrules.go:318` | a citation names the parent's height, `h.Height-1` |
| C2 | `blockrules.go:322` | a citation shares the citing block's grandparent |
| C3 | `blockrules.go:327` | a citation is not the block's own parent restated |
| C4 | `blockrules.go:332` | a citation was mined at the parent height's actual target |
| C5 | `blockrules.go:339` | citation ids strictly increase |

C2 and C4 are pinned against state — `PrevParentIDSlot` and `PrevTargetSlot` — so a citation cannot be invented from nothing. The cited header's own proof of work is checked, deliberately *outside* the fold, in `node/p2p` and `node/sync` (`node/p2p/engine.go:3032`, `node/sync/sync.go:696`), because up to `max_cites_per_block` RandomX evaluations inside the one sequential stage would cost more than everything else the fold does. `blockrules.go:260-285` records why that split is sound and [`spec/wire.md`](../spec/wire.md) §9 rule 7 states it normatively, since a rule the fold does not enforce has to be written where an independent implementation is obliged to read it. `sim/refold/refold.go:965` reimplements the same rules independently and the two folds are held against each other differentially.

**The consumer is implemented too.** `cited_count` accumulates in state, and F2b compares `cited_count × 10000 ≤ health_gate_bps × epoch_length` to decide whether `T` may grow. Both constants are in `ConsensusRoot()`. `health_gate_bps` is 200 and `epoch_length` is 2880 (`spec/params.json`), so the gate trips above 57.6 cited competitors per epoch.

**What is missing is exactly one thing: a producer.** `node/miner/miner.go:260` builds the candidate block with `Cites` left nil, and says so in the source:

> Cites is left empty: gathering competing headers to cite (whitepaper §8.1's health signal) is not implemented by this miner. An empty list is always valid — it is the safe default, since an unhealthy-looking epoch only withholds *growth*, never decay or the floor — but it does mean this miner's blocks never themselves supply the health signal.

**There is one production assembly path and it is that one.** `node/stratum` does not build blocks of its own: its `Assembler` interface is documented at `node/stratum/stratum.go:210` as satisfied by `*miner.Miner`, `cmd/zycordd/main.go:503` wires exactly that, and `node/stratum/conn.go:443` copies `j.block.Cites` out of the block the miner already assembled. So the pool path inherits the empty list rather than supplying a second one. Genesis emits an empty list by construction (`core/genesis/genesis.go:60`). **The only code in the tree that ever writes a non-empty `Cites` is the simulator** — `sim/harness/harness.go:84`'s `ProposeWithCites`, used by `sim/scenario.go` and `sim/perturbation.go` to exercise rules the fuzzer could otherwise never reach.

So the position is precise: the rules are load-bearing consensus, the gate is wired to state, and the signal is structurally always zero.

## 2. The fact that reframes the question, and it is not in the issue

The citation window is **one block**, and this is structural rather than a parameter. C1 requires the cited header to be at `h.Height-1` and C2 requires it to share the citing block's grandparent, so a block can only ever cite a sibling of its own parent. `blockrules.go:284` calls this out as the reason dedupe needs no set in state — there is nothing to deduplicate across blocks — and [ARCHITECTURE.md:474](../ARCHITECTURE.md) states the consequence without softening it:

> Whitepaper §8.1 says "recent competing headers", which is wider, and the difference is not cosmetic: **a one-block window undercounts exactly when the network is unhealthy.** A proposer at height H has roughly one block interval to have heard about a competitor at H−1; if propagation is slower than that — precisely the condition the health gate exists to detect — the competitor is never citable, the epoch reads as healthy, and growth is permitted when it should be withheld. **The gate therefore fails *permissive* under slow propagation**, the opposite of the direction §8.1 asks it to lean.

This is decisive for costing the branches. A fully implemented miner side does not deliver the gate whitepaper §8.1 describes; it delivers a gate whose detection is structurally weakest in the regime it exists for. The same architecture bullet names the fix — a W-block window needs "a bounded, prunable, reorg-safe cited-id set in consensus state" — and that is a second seen-set, in consensus, which after block 0 is a hard fork.

So the question is not binary. It is three-way, and the third branch is the one the issue title actually asks for.

## 3. What is holding capacity while the gate is latent

One thing, and its own standing is disputed.

ARCHITECTURE §20 puts it plainly: the health gate is "the *only* mechanism the paper gives for keeping capacity inside what propagation carries, and `BlockByteCapacity` (§15) is now the sole backstop holding growth short of the transport's bound." `block_byte_capacity` is 8,000,000 (`spec/params.json:16`). The failure mode it guards is named in the parameter's own commentary and it is the bad one: "not a rejected block but a block every node agrees is valid and no node can transmit."

That value is retained on a comparison with a data-availability network carrying 8 MB per 6 seconds, which at a 30-second interval is roughly 5× conservative in byte rate. ARCHITECTURE §20 records that the comparison's *sufficiency* is "disputed and reserved to the owner", because a DA network's nodes carry opaque blobs while a node here must carry, fold, verify and write every byte. GENESIS-CHECKLIST §1.5 ties the two items together for exactly this reason: a checklist flagging only the byte capacity would leave a reader believing the gate was load-bearing.

**This coupling is a standing commitment, not a footnote.** While the gate is latent, `block_byte_capacity` is load-bearing alone. It must not be weakened, and its re-derivation on the relaunched testnet (issue #7, the §1 sixth measurement) is doing work for two gates rather than one.

## 4. What the transport pairing already guarantees, and what it does not

`MaxBlockChunks` is 4 and `BlockChunkBytes` is 4 MiB, pinned against `block_byte_capacity` in both directions by `TestBlockByteCapacityFitsChunkedTransfer` over every parameter set `spec/` embeds. So a block consensus calls valid always fits the chunked transfer, and an era re-pin has to raise the transport constants in the same release.

That is a guarantee about *framing*, not about *propagation time*. It says a valid block can be moved in four chunks; it says nothing about whether the network moves it inside a block interval under load. The health gate is the mechanism for the second question. Nothing else in the tree measures it.

## 5. What re-verifying `health_gate_bps` is worth

GENESIS-CHECKLIST §1.4 re-verifies `health_gate_bps` = 200 at the freeze. That confirms the number the gate *would* use. It says nothing about whether anything ever feeds the gate. Both are needed and the first does not substitute for the second — which is why §1.5 is a separate item rather than a note under §1.4.

Worth recording alongside it: the gate's comparison is `≤` rather than `<`, and ARCHITECTURE §8's commentary shows the two spellings cannot disagree at any shipped parameter set, because `cited_count` is an integer and `health_gate_bps × epoch_length` is 576,000 on mainnet and testnet. That is a real property of the frozen numbers and it is already pinned by a witness test at a legal but unshipped set. It is not affected by this decision in either direction.

---

## 6. The three branches

### (a) Implement miner-side gathering before the freeze

**What it costs.** Work in `node/miner`: the miner must track headers it has seen at `h.Height-1` that share its grandparent, keep them across the reorg boundary, filter them by C0-C5 before including them, order them by id for C5, bound them at 4, and do all of it without lengthening block assembly, which `node/stratum/conn.go:323` prices at ~570 µs against a real chain and which sits on the pool's getjob path. It also needs tests that fail without the property, in a package with no existing citation-gathering surface to extend.

**When it lands.** In the days before the 2026-09-15 genesis, in the same window as the relaunched testnet — which is the project's measuring instrument for issue #7's §1 measurements. Destabilising the miner in the week its output is the measurement is a cost paid twice.

**What it buys.** A gate that under-detects precisely under slow propagation (§2). The yield is structurally capped by the one-block window regardless of how well the gathering is implemented.

**Assessment: high cost, capped yield, worst possible timing.** Not recommended.

### (b) Widen the citation window before the freeze

**What it costs.** A consensus change: a bounded, prunable, reorg-safe cited-id set in consensus state, plus new rules, golden vectors, the `sim/refold` differential restated independently, and the spec text. Under CONTRIBUTING's consensus-zone bar, in the same days the rx/2 review budget is already committed to (issues #11, #12).

**What it buys.** The gate whitepaper §8.1 actually describes — genuinely more than (a) buys.

**Assessment: right change, impossible schedule.** Ruled out on the calendar alone, not on merit. Not recommended, and §9 records it as an Era-1 question rather than dropping it.

### (c) Ship the gate latent, by decision, and write it down

**What it costs.** Nothing in code. §1 established that no production path writes `Cites` and that the only producers are simulator-only, so this branch is genuinely code-free: a decision document, a checklist state, and one sentence in the launch announcement.

**What it commits the project to, and these are obligations rather than observations:**

1. **The gate is decoration in Era 0 and must be described that way in public.** A ceiling that can only grow, because nothing ever reports it unhealthy, is not the gate whitepaper §8.1 describes. The announcement and any capacity documentation must not cite the health gate as an active protection. Saying otherwise would put a guard where there is none.
2. **`block_byte_capacity` is the sole backstop and its standing must not be weakened while nothing else is load-bearing.** This binds the outcome of issue #7's sixth measurement: that measurement may *confirm* 8,000,000, and it may argue it down, but an argument for raising it has to answer that it is currently alone.
3. **Miner-side gathering is scheduled, not abandoned.** It is non-consensus and can land in any post-genesis minor release, which is precisely the property that makes deferring it legitimate rather than convenient.
4. **Window widening is an Era-1 fork question**, revisited if and only if the gate is ever to be load-bearing rather than latent.

**Assessment: the outcome §20 explicitly permits, taken deliberately and with its price stated.**

### There is no fourth branch

Two tempting ones do not exist:

- **Drop the field.** `Header.CitesRoot` is in the fixed-size SSZ header and in the consensus root. It is frozen in both directions — it cannot be added later and it cannot be removed later. There is no "ship without the field and add it in Era 1."
- **Feed the gate from a cheap non-consensus source.** `checkCites` pins citations against state (C2, C4) and their proof of work is checked in full. A signal assembled from anything weaker would not satisfy the rules that make `cited_count` trustworthy, and `cited_count` moves `T`, which moves real money.

---

## 7. Recommendation

**(c) — ship latent, by decision, with the four commitments in §6 recorded.**

The reasoning, in the order it actually weighs:

1. **(a) buys less than it looks like it buys.** The one-block window means an armed gate under-detects in the exact regime the gate exists for. Paying miner-destabilising work in genesis week for a structurally capped signal is a bad trade at any schedule, and this is the worst schedule available.
2. **(b) is the change that would be worth making and cannot be made now.** Recording it as an Era-1 question preserves it; attempting it in the freeze window would put a consensus change through a compressed review, which is the failure mode the consensus zone's rules exist to prevent.
3. **(c) is what §20 permits, and the permission is conditional on exactly the thing this document does.** §20's alternative is not a loophole; it is a requirement that the choice be visible. Meeting it costs no code and no risk.
4. **The safety argument holds independently of all three.** An empty list withholds growth only, never decay and never the floor. Nothing is unsound under (c). What is lost is a protection, not a correctness property — and §6's commitment 1 is what stops that loss being quietly misdescribed.

**What the recommendation is not.** It is not an argument that the health gate is unimportant, and it is not a claim that `block_byte_capacity` at 8,000,000 is sufficient. It is an argument that the gate cannot be made load-bearing before block 0 by any available route, and that the honest response is to say so in the launch material rather than to ship a half-armed mechanism and let readers assume it works.

## 8. The question that has to be answered

Exactly one, and neither this document nor any contributor may answer it:

> **Does mainnet genesis ship with the health gate latent — the miner citing nothing, `block_byte_capacity` = 8,000,000 as the sole backstop on capacity growth, and the launch material stating plainly that the gate is inactive in Era 0 — or is miner-side citation gathering implemented before the 2026-09-15 freeze?**

Answering **latent** closes GENESIS-CHECKLIST §1.5 as *decided, shipping without*, records the four commitments in §6(c), and closes issue #8 with no code change. Answering **implement** reopens branch (a) on the pre-freeze clock and needs a schedule against the relaunched testnet before it starts.

## 9. What would reopen this

- **A decision to make the gate load-bearing in a later era.** Branch (b) is its prerequisite, not its optimisation: the one-block window has to be widened first, and that is a fork.
- **Evidence from the relaunched testnet that propagation does not carry `block_byte_capacity`.** That would not arm the gate, but it would move the backstop, and §6(c)'s second commitment is what makes the finding land somewhere.
- **Not the miner work becoming cheap.** Branch (a)'s problem is the window, not the effort, and a cheaper implementation of a capped signal is still a capped signal.
- **Not a later release shipping the gathering.** That is expected under (c) commitment 3 and is a minor release, not a reopening — the gate stays latent in effect until the window is widened.

---

**Sources.** `core/fold/blockrules.go` (`checkCites`, B15-B17, C0-C5, and the package commentary on why the work check lives in the node layer); `core/genesis/genesis.go:60`; `node/miner/miner.go:260`; `node/stratum/stratum.go:210`, `node/stratum/conn.go:443`, `cmd/zycordd/main.go:503`; `node/p2p/engine.go:3032`; `node/sync/sync.go:696`; `sim/harness/harness.go:84`; `sim/refold/refold.go:965`; `spec/params.json` (`health_gate_bps`, `epoch_length`, `max_cites_per_block`, `block_byte_capacity`, and their commentary); [ARCHITECTURE §8, §15, §20](../ARCHITECTURE.md); [GENESIS-CHECKLIST §1.3-§1.5](../GENESIS-CHECKLIST.md); [decisions/testnet-measurements](testnet-measurements.md) §1.
