# Zycord — Stock XMRig mines this chain, and two encoding rules were changed to make it true

**Scope:** whether this chain's proof-of-work encoding should match what unmodified XMRig already computes, or whether XMRig should be forked to match this chain. Raised when the header's hashing input and its digest comparison were both found to be shapes no released miner produces. Two consensus rules changed as a result — the digest is read little-endian, and the hashing blob is 43 bytes with the nonce at offset 39 — and this document is why, and why the alternative was refused.

**Verdict: native compatibility, and the two rules moved.** Neither change costs the protocol anything it was using. The digest's byte order was never a decision this protocol had made — a digest is 32 opaque bytes out of a function somebody else wrote, so which end is most significant is a convention, and the convention was chosen to match the producer. The blob's shape was a decision, and it was made without knowing that the number in it is compiled into every miner rather than negotiated by the pool protocol. **The rejected alternative — ship a patched XMRig — is refused on three grounds that compound: every miner would have to trust an unverifiable custom binary, the fork would need rebasing on upstream forever, and the target-encoding mismatch would leak out of consensus and into pool software permanently.** The last is the one that makes the decision irreversible rather than merely expensive, and §4 is about it.

What binds the outcome is not this document. `core/pow/randomx/xmrig_cross_vector_test.go` rebuilds the blob from XMRig's own published offsets and compares byte for byte, and runs XMRig's own share test against `CheckWork`; §5 records what it does and does not reach.

---

## 1. What was found, and what it would have cost

Two rules, found separately, each of which alone makes the chain unmineable by every miner that exists.

| Rule | What this tree did | What stock XMRig does | Consequence of leaving it |
|---|---|---|---|
| Digest comparison | `be256(digest) ≤ Target` | reads `digest[24:32]` as a little-endian `uint64`, compares `< target` | Every share a stock miner finds is uniform noise to the node, and vice versa. No proxy can translate. |
| Hashing blob | 40 bytes, 32-byte seed then an 8-byte LE nonce at offset 32 | writes 4 LE bytes at offset **39** of whatever blob it is handed | The miner searches bytes the node does not hash. Every submitted share is wrong at the node and correct at the miner. |

Both are *silent*. Neither produces an error message, a rejected connection, or a log line naming the cause. A miner points at the chain, reports a healthy hashrate, finds shares at the expected rate, submits them, and every one is refused — a failure mode indistinguishable from a broken pool, and one that would be diagnosed by whoever cared most and abandoned by everyone else.

**The two are independent and they compound.** Fixing the digest alone leaves the miner hashing the wrong bytes; fixing the blob alone leaves both parties hashing the same bytes and reading opposite ends of the answer.

## 2. Why the numbers are not ours to choose

Neither value was picked here, and the evidence is upstream source rather than an argument.

**Offset 39, four bytes.** `xmrig::Job::nonceOffset()` returns `39` for the whole RandomX family — the switch names `32` for KAWPOW, `76` for GHOSTRIDER, `147` for RX_YADA, and falls through to `39` for everything else — and `Job::nonceSize()` returns `4` for everything but KAWPOW. `WorkerJob::nonce()` is `reinterpret_cast<uint32_t*>(blob + nonceOffset())`, which is where the little-endian-ness comes from: the nonce is written through a `uint32_t*` in host byte order, and every host XMRig supports is little-endian. **The offset is 39 because that is where Monero's block-hashing blob puts the nonce**, and it is compiled in. No field in the pool protocol moves it.

**43 bytes is XMRig's floor, not a coincidence.** `Job::setBlob` refuses any blob shorter than `nonceOffset() + nonceSize()` — 43. This chain's blob is the smallest one stock XMRig accepts, so the seven reserved bytes between the 32-byte seed and the nonce are not padding anyone chose: they are the distance between 32 and 39, and there is nothing to trim.

**The comparison.** `CpuWorker::start`, verbatim:

```cpp
const uint64_t value = *reinterpret_cast<uint64_t*>(m_hash + (i * 32) + 24);
if (value < job.target())
```

Eight bytes at offset 24 of a 32-byte digest, read as a native little-endian `uint64`, against a 64-bit target. That is the top limb of `le256(digest)`, and it is the whole reason the consensus rule reads the digest little-endian.

**The change costs the protocol nothing in difficulty.** A digest is uniform, so either reading lands at or below a given target with the same probability. What changes is *which* nonces win, and therefore who can mine at all.

## 3. What the alternative was, and the two ordinary objections to it

The alternative is a real option and was treated as one: fork XMRig, change `nonceOffset()` to return 32 and the share test to read the other end, ship binaries.

**Trust.** A miner running an unofficial binary is running code that could steal its shares, its wallet, or its machine, and it has no practical way to check. XMRig is a widely-read, widely-packaged, reproducible-ish project with a long public history; a fork by an anonymous new chain has none of that. Some fraction of miners will build from source and audit; most will not, and the honest ones who will not are the ones a fair launch is aimed at. **The hashrate that can reach this chain becomes a function of who is willing to trust an unverifiable binary from a stranger**, which for a young chain is close to nobody. This is the objection that matters most at genesis and it is the least interesting technically.

**Maintenance.** XMRig releases regularly, and the fork has to be rebased on every one of them, forever, by whoever is maintaining this chain. A rebase that is skipped leaves the fork's users on an old miner with old bugs and old CPU support; a rebase that is done badly is a fork that computes something subtly different. Neither failure announces itself. This is the objection that compounds with time rather than with size, and it is the reason the decision does not get cheaper by being deferred.

Both are ordinary and both are, on their own, survivable by a project willing to pay. The third is not.

## 4. The third objection: the mismatch does not stay inside consensus

This is the ground the decision actually rests on, and it is a property of the *target encoding* rather than of the miner.

Under the little-endian rule a 64-bit Stratum job target is a clean truncation of the 256-bit consensus target:

```
t64 = max(1, floor((TARGET + 1) / 2^192))
```

The bytes that truncation keeps are exactly the digest bytes XMRig compares, so every share found under `t64` satisfies the full 256-bit check up to a boundary sliver one part in `2^64` wide. **Under a big-endian rule no such truncation exists at all** — the 64-bit window the miner reads and the most significant bytes of a big-endian target are opposite ends of the digest, and the ends are independent.

So a big-endian chain cannot express its target in the field Stratum has for it. What it has to do instead is put a *differently-encoded* target into a standard field and rely on every consumer knowing. That is not a cost paid once by the miner fork. It is paid by:

- every pool, which must special-case this chain's target arithmetic in its share validator;
- every proxy, which must not translate between this chain and any other;
- every dashboard, monitor, and hashrate calculator that turns a target into a difficulty;
- every future re-implementation of any of the above.

**And it is unfixable later.** Changing the digest convention after launch is a consensus fork that invalidates every historical header, so the encoding chosen at genesis is the encoding forever. The miner fork can in principle be abandoned — upstream might one day merge support — but the target mismatch it exists to serve would have been baked into the chain and into every piece of software that ever spoke to it. **A rejected alternative whose cost is permanent and external is not comparable to one whose cost is temporary and internal**, and that asymmetry is what decides this rather than any estimate of how many miners would trust a binary.

## 5. What is now enforced, and what is not

The rules are stated normatively in [ARCHITECTURE](../ARCHITECTURE.md) §12. Two files hold them and the division is worth naming, because they look like duplicates and are not. `core/pow/blobpath_internal_test.go` checks that the miner and the verifier in *this tree* hash the same bytes; it needs no cgo, runs on the development engine, and is the fast guard against internal drift. `core/pow/randomx/xmrig_cross_vector_test.go` checks that those bytes are the bytes **XMRig** hashes, against constants that came from outside this repository — which is the only axis on which an internal comparison can say nothing at all. Its design is a reaction to a specific failure: the check it supersedes compared two *verdicts*, both of which are `false` for almost every nonce, so a solver with the nonce at the wrong offset or the digest read from the wrong end agreed with the rule on all but a vanishing fraction of the space and passed.

| What it checks | Against what | Reached by |
|---|---|---|
| The engine is rx/0 through the interface consensus calls | tevador's published vectors at the pinned tag | `TestTheConsensusInterfaceComputesUpstreamsFunction` |
| The 43 bytes are XMRig's 43 bytes | a second assembly from XMRig's offsets, importing no constant from `core/types` | `TestTheBlobThisTreeBuildsIsTheBlobXMRigSearches` |
| The reserved gap is zero on both sides | as above | `TestTheReservedGapIsZeroInTheBlobXMRigWouldBeServed` |
| The comparison reads the end XMRig reads | `CpuWorker::start`'s own line, transcribed | `TestXMRigsShareTestAgreesWithTheConsensusRule` |
| A share XMRig accepts is accepted, one it rejects is not | as above, through `pow.CheckWork` | `TestCheckWorkAcceptsWhatAStockMinerWouldSubmit` |
| The solver finds the set a stock miner finds | as above, through `pow.Solver` | `TestTheSolverFindsWhatAStockMinerFindsForTheSameHeader` |

Every assertion compares bytes, or compares verdicts only against a target loose enough that both verdicts occur — and then asserts both occurred, so no comparison can degenerate into two constants. Nine mutations are recorded in the file with their outcomes.

**One of the nine survives, and it is recorded rather than omitted.** Making `PoWSeed` zero `ExtraNonce` as well as `Nonce` — the obvious symmetry, and the wrong one, which would collapse every pooled miner onto one seed and silently un-shard every pool — passes every test in that file. That is correct scoping and not a hole: the file takes `PoWSeed()` as an opaque 32 bytes on both sides of every comparison, so it cannot see inside the seed preimage. The rule is held by `core/types.TestExtraNonceIsInsideTheSeedAndTheNonceIsNot`, which was confirmed to fail under that mutation.

**Which is worth stating precisely, because the plausible answer is wrong.** `core/pow.TestTheSolverHashesTheHeadersOwnBlob` also passes under that mutation, despite a comment predicting it would not — and for the same structural reason: both sides of its comparison reach `PoWSeed()`, so a change *inside* the seed moves them together and the bytes still match. **Any test whose two sides both call `PoWSeed` is blind to the seed's preimage by construction.** Only a test that varies `ExtraNonce` and watches the seed can see it, and there is exactly one.

**What no test here reaches is a real XMRig binary.** Everything above is checked against XMRig's published *source constants* and against tevador's published *vectors*, which is a strictly weaker claim than "a stock miner was pointed at a node and found a block". That end-to-end confirmation belongs to whatever serves Stratum jobs and is not this document's to make.

## 6. What the seed schedule contributes, unchanged

The schedule did not move and is worth stating in the miner's vocabulary, because it is the part of this integration that was already right.

`KeyFor(height)` **is** a Stratum `seed_hash`: the 32-byte value a pool sends with a job, which the miner uses to key its cache and never derives. So the schedule needs no new field, no new message, and no miner-side change at all.

What is unusual is that **the next epoch's key is derivable arbitrarily far ahead**, because it is a function of height alone. Upstream RandomX keys from a key block's *hash*, so the next key is unknowable until that block is mined and is revised by any reorg across it: every dataset rebuild arrives when a block arrives, and a pool cannot warm a cache for a key it cannot yet name. Here every participant can compute the key for any future height and build whenever it is idle. That is why the key-rotation stall this tree measured — 8–11 s of a node verifying nothing at every boundary — was removable by prefetch at all, at 24.8 ms warm against 574.9 ms cold; under upstream's schedule the same prefetch would depend on which branch wins.

The cost side is not hidden: a height-derived key is one fewer thing binding the proof to chain history, and ARCHITECTURE §21 carries that entry with its reversal trigger.

## 7. What would reopen this

- **Upstream XMRig changing `nonceOffset()` for the RandomX family.** It would not make this chain's blob wrong — 39 is fixed in the chain's own rules now and cannot move without a consensus fork — but it would mean stock miners no longer match, which is the condition this whole decision exists to maintain.
- **A different engine.** If the work function is ever not rx/0, the offsets and the share test are that engine's, not XMRig's rx/0 path's, and §5's table is re-derived rather than edited.
- **Nothing about miner trust or maintenance cost.** Those were the ordinary objections in §3 and they were not what decided it; a change in either does not reopen a decision that turned on §4.
