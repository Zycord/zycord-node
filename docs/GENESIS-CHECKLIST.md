# Genesis go/no-go

Mainnet genesis is **2026-09-15 00:00 UTC** — `genesis_time` 1789430400 in
[`spec/params.json`](../spec/params.json), which is a consensus value and
therefore already committed to. This is the list of everything that must be true
before block 0, with the state of each item, and it is updated as items close
rather than rewritten at the end.

**Every state below was verified against the tree at the time of writing, before
any freeze tag existed** — the tags then were `v0.1.0` through `v0.1.3`. A state
here is a claim about a specific tree, so read it against the freeze tag once
there is one: anything still marked not-started under a tag that postdates it is
either stale text or a real gap, and both are worth finding.

---

## The rule that governs this list

> **If a measurement in [§1 of the testnet measurements](decisions/testnet-measurements.md)
> says a genesis value is wrong, the date moves — and the move is a signed post,
> never a quiet slip.**

That sentence is the point of publishing this document at all, so it is worth
being exact about what it commits to and what it does not.

It is not a promise that nothing will go wrong. It is a promise about **what
happens when something does**: that the finding is published, that the reasoning
is published with it, and that the new date is published under the project key —
the same key that signs release tags and the genesis announcement
([RELEASE.md §6](RELEASE.md)). A reader who wants to know whether a date moved,
and why, reads one signed statement rather than inferring it from a repository
that quietly stopped matching its own announcement.

**Why the commitment is cheap to make and expensive to break.** A §1 value is a
consensus parameter. It enters `ConsensusRoot()`, which produces the genesis id,
which *is* the network id — so a wrong one is not a bug to be fixed in a release,
it is a chain nobody can repair without a fork, on a project whose entire
proposition is that nobody can change the rules. Moving a date costs two weeks of
schedule. Launching on a value a measurement contradicted costs the thing the
design exists to protect. There is no version of that trade where shipping is the
brave choice.

**The runway is short and that is not a reason to soften this.** The window
between the testnet relaunch under the new proof-of-work encoding and the 15th is
the known cost of making the encoding stock-miner-compatible before mainnet
exists rather than after, when it would be a hard fork. That cost was accepted
deliberately. What it buys is a date this list can still move, and a compressed
measurement window is exactly the condition under which a pre-committed rule is
worth more than a resolution to be careful.

**The mirror of the rule, so it cannot be read as an escape hatch.** A
measurement that is *late* is not a measurement that contradicts a value. If §1
is not collected, the date moves for the same reason and by the same mechanism —
an uncollected measurement is not a passing one. This list has no state in which
a box goes green because time ran out.

---

## How to read the states

| Mark | Meaning |
|---|---|
| ✅ | Done, and checkable from this tree or from a published artifact |
| 🟡 | In progress; the work exists and is not finished |
| ⬜ | Not started |
| ◻️ | **Wanted, and explicitly not blocking.** Genesis proceeds without it |

Every blocking item is one somebody has to *do*. Nothing on this list closes by
elapsed time.

---

## 1. Blocking — the chain does not start until these are true

### 1.1 The proof-of-work encoding is stock-miner-compatible, and it is consensus

✅ **Done, and it moved twice.** Every item below is consensus-visible, so after
block 0 each one is a hard fork.

The finding behind the first round: the vendored RandomX is a byte-identical
tevador tree with stock constants — the same function stock miners already
compute. What stopped a stock miner joining was not the algorithm but the
encoding conventions around it, and they were cheaper to change before genesis
than they will ever be again.

- **The digest is compared little-endian.** ✅ `u256.FromLEBytes` exists and the
  work check uses it. The Monero-family convention reads the other end of the
  same 32 bytes, so the two cannot be translated between: a share a stock miner
  finds is noise to a node reading it the other way. **The rule now applies to
  the commitment rather than to the digest — see below — and the endianness is
  unchanged.**
- **The hashing blob is 43 bytes with a 4-byte nonce at offset 39.** ✅
  `Header.PoWInput()` builds it, bytes 32–38 are reserved must-be-zero, and the
  seal is `Nonce u32` + `ExtraNonce u32`, which is what lets a pool hand each
  connected miner a disjoint search space.
- **The built-in miner searches that layout.** ✅ Through `pow.Solver`, which
  builds its buffer from `PoWInput` rather than from a second copy of the rules.
- **The spec and the golden vectors say so, cross-checked against upstream's
  published test vectors.** ✅
  [`core/pow/randomx/xmrig_cross_vector_test.go`](../core/pow/randomx/xmrig_cross_vector_test.go)
  rebuilds the blob from XMRig's own offsets and runs XMRig's own share test
  against `CheckWork`, and
  [`docs/decisions/xmrig.md`](decisions/xmrig.md) is the record for why native
  compatibility was chosen over shipping a patched miner.

**Then the work function itself moved, and that is the second round.** Mainnet
and the relaunched testnet declare `pow_engine: "randomx-v2"`, and the testnet
is *born* on rx/2 rather than forking onto it. Two things follow, both frozen at
block 0:

- **The target is compared against the COMMITMENT, `blake2b(pow_input ‖
  pow_hash)`, not against the RandomX digest.** ✅ This is not a choice: rx/2
  sets `Tweak_V2_COMMITMENT` unconditionally, and stock XMRig's share filter
  reads the commitment — the buffer named `m_hash` holds it, because
  `randomx_calculate_commitment` overwrites its input in place, and the Stratum
  field names are inverted to match. A chain comparing the raw digest under rx/2
  would have every stock miner discard its winning nonces and submit losing
  ones, silently. [`docs/decisions/randomx-v2.md`](decisions/randomx-v2.md) §8.1
  is the derivation from source.
- **The header carries the digest, and `HeaderSize` is 260.** ✅ Up from 228. The
  field is what lets a verifier form the commitment without evaluating RandomX,
  which is a microsecond against ~21 ms — the asymmetry cited headers, flood
  handling and light verification are priced on.

**What is NOT done, and it is the standing risk this section must not hide.**
The adversarial pass over the ~800-line upstream JIT and assembly delta has not
happened; nothing has run on arm64; no epoch boundary has been crossed on rx/2
on any network; and Monero has neither activated rx/2 nor vendored it, so this
chain would be its first production user. `docs/decisions/randomx-v2.md` §8.6
carries all four, and the go/no-go rule in this document applies to them: **if a
genesis value is wrong the date moves.**

### 1.2 The public testnet is relaunched under those rules

⬜ **Not started, and gated on 1.1.** The encoding changes invalidate the running
network by construction: any parameter change moves `ConsensusRoot()`, which is
genesis's parent id, so the old chain and the new one cannot be confused for one
another even by accident — nodes on the two disconnect at the handshake
([TESTNET.md §Resets](TESTNET.md)).

What the relaunch has to include, beyond the restart itself: a release carrying
the RandomX tier for every published platform, the seed infrastructure moved to
the new parameters, a fresh install that mines within ten minutes on all three
operating systems, and every place the testnet's network id or genesis date
appears saying the same thing.

**The relaunch also resets the measurement clock**, which is why it sits directly
under the item below it. `genesis_time` in
[`spec/params.testnet.json`](../spec/params.testnet.json) is 1788652800
(2026-09-06), the relaunch day; it moved there from the first incarnation's
1788048000 (2026-08-30), because the difficulty rule reads the gap between a
block's timestamp and its parent's and a genesis dated well before block 1 makes
the first blocks measure the parameter file rather than the network. The date
sits before the 1.4 freeze target below, and deliberately: that item requires
every consensus-visible encoding change to be *running* on the relaunched
network, which a relaunch dated after it could not satisfy.

Tracked under the **Testnet relaunch** milestone, due 2026-09-10.

### 1.3 The §1 measurements are collected on the relaunched network

🟡 **In progress on the current testnet, and the relaunch restarts it.** This is
the go/no-go input, and it closes last.

[decisions/testnet-measurements.md §1](decisions/testnet-measurements.md) is the
list of values that are irreversible at genesis. It has six entries and they do
not all ask for the same thing, which is why they are enumerated here rather than
summarised as "the measurements":

1. **`undo_depth` — mainnet 1024.** The reorg horizon past which a node refuses
   to reorganise at all. Below the real reorg-depth tail it is not a margin, it
   is a **permanent partition boundary**, and the failure is silent: nothing
   triggers a resync when `ErrBeyondUndoHorizon` fires. What the testnet owes is
   the *distribution* of reorg depth — the 99th and 99.9th percentiles and the
   maximum — over a period long enough to include real incidents. `deepest_reorg`
   and `reorg_events` are on `/metrics` and persist across restarts.
   **The lab figures are not a substitute**, and §1 says so at length: the
   four-node soak was measuring its own harness, its instrument was
   right-censored at the parameter under test, and its sync driver put a
   128-block floor under any reorg it stepped back for. Collection of this
   distribution starts at the version carrying that fix.
2. **`epoch_length` — mainnet 2880.** State roots are checked only at epoch
   boundaries, so this is also the latency before a silently diverged node is
   detected. Measure how long divergence actually takes to surface, and whether a
   day at 30-second blocks is a tolerable window for a node to be wrong before
   anything says so.
3. **The emission constants** — `genesis_emission`, `emission_decay_divisor`,
   `tail_emission`, `treasury_share_bps`. **Deliberately not on the measurement
   list**, recorded here so the omission is not read as an oversight. All four
   enter the consensus root, but a testnet has no market, no holders and no
   security budget, so it cannot tell you whether the curve is right — only that
   the arithmetic holds, which the unit tests and the differential fold already
   do more exactly. What the testnet does confirm is mechanical: that
   `zcd emission --height N` matches the schedule at the tail boundary, that the
   97/3 split sums to the subsidy at every epoch's rate, and that the treasury
   cell's balance equals 3% of cumulative subsidy at any height. These are
   conservation checks, not measurements. The residual risk is stated plainly in
   §1: these are the parameters most likely to be wrong in hindsight and least
   likely to be shown wrong before genesis, and the mitigation is that they are
   argued in public where the review window can challenge them.
4. **`ttl_max`, `max_certs_per_block_genesis`, the gas ceilings.** The fee markets
   and the mempool are downstream of these and none has been observed under real
   demand. The testnet is the first time anyone contends for sequential gas for a
   reason other than a test wanting them to.
5. **The sequential gas density of real traffic.** The number is sequential gas
   per byte *of block*, as a distribution rather than a mean. The calibration
   half of this entry is **closed**: `seq_gas_target_genesis` was lowered to
   1,600,000, putting the break-even at 0.64 gas per byte against a measured
   plain-transfer density of 0.704 — 9.1% of margin, so a physically full block
   of ordinary payments pushes the sequential base fee **up** rather than down.
   It had to be closed here rather than deferred, because the number is in the
   consensus root and a testnet carrying a different value measures its own
   economics rather than mainnet's. What is still open is **validation**: whether
   the distribution of real traffic sits where the one measured shape does. If it
   lands below 0.64 plus margin, the magnitude returns to the owner.
6. **`block_byte_capacity` paired with the chunked-transfer bound.** The number to
   measure — the sustained per-node bandwidth distribution — is already collected
   under §2. What is **open and deliberately unresolved** is what that measurement
   is allowed to decide: whether it *sets* the pairing or only *confirms* it.
   That is a decision about who can run a node and it belongs to the owner. It is
   recorded here so the measurement arrives with the question still open rather
   than pre-answered.

**What "collected" means for this checkbox**: each entry has a number from the
relaunched public testnet and a written argument in the style of the decision
documents, posted signed. An entry that reaches the freeze with "it seemed
reasonable" is an entry nobody has measured, and §1 values cannot be revisited
afterwards by anyone, including whoever wrote them.

### 1.4 Parameters and vectors are frozen, and the freeze is tagged

⬜ **Not started. Target 2026-09-12.** The point after which a consensus change is
a fork, declared in public — and the reason for the date is that it leaves the
relaunched testnet at least two full days of frozen-rules soak before genesis.

Preconditions: every consensus-visible encoding change from 1.1 merged and
running on the relaunched network; [`spec/params.json`](../spec/params.json)
final; the golden vectors final. Then the freeze commit is tagged and the tag is
referenced from the README status table and from this document.

**State: no freeze tag exists.** The tags in this repository are `v0.1.0` through
`v0.1.3`.

**Four numbers are re-read and re-verified at the freeze commit**, because it is
the last moment any of them can move: `seq_gas_target_genesis` = 1,600,000, the
`seq_gas_capacity`/`seq_gas_target_genesis` ratio = 3.2, `health_gate_bps` = 200,
and `epoch_length` = 2880. All four enter `ConsensusRoot()`. The derivations are
in `spec/params.json`'s own `notes` and in
[decisions/capacity-eras.md](decisions/capacity-eras.md), which is where a reader
checks them rather than taking this list on trust. If a pre-freeze change moved
any of the four, the owner re-ratifies the target and the capacity ratio before
the freeze — the ratification is of figures, not of prose.

**If the freeze slips past the 12th, the genesis-date conversation happens in the
open**, under the rule at the top of this document.

### 1.5 The health signal ships, or the decision to ship without it is made explicitly

⬜ **Not decided.** The mechanism is not implemented, and the decision that
closes this item has not been recorded either way.

**What exists and what does not.** The citation *rules* are complete: the header
carries `CitesRoot`, blocks carry `Cites`, the fold checks them (B15–B17, C0–C5)
and a cited header's own proof of work is checked alongside the block's. What is
missing is the miner side — `node/miner` leaves `Cites` empty, with a comment
saying so, because gathering competing headers to cite is unimplemented. An empty
list is always valid, and it is the safe default: an epoch that looks unhealthy
withholds *growth* only, never decay and never the floor. So nothing here is
unsound, and that is precisely why it can be shipped without anybody noticing
they decided to.

**Why it is on this list rather than in a code backlog.** The carrier is
genesis-frozen. `Header.CitesRoot` cannot be added after launch without a hard
fork, so the field ships from block 0 whether or not anything fills it — which
means the *implementation* can arrive in any later release, and the **decision**
cannot arrive later than block 0 in any meaningful sense. [ARCHITECTURE §20](ARCHITECTURE.md)
therefore states the gate in the alternative: the miner gathers and cites real
competing headers, **or the decision to ship without it is made explicitly rather
than by default**. Recording the decision is what closes this item; implementing
the mechanism is not required to close it.

**The consequence, stated as §20 states it.** Without citations nothing ever
reports an epoch unhealthy, so the health gate is a ceiling that can only ever
grow — decoration rather than the gate whitepaper §8.1 describes. §20 puts the
cost plainly: the gate is the *only* mechanism the paper gives for keeping
capacity inside what propagation carries, and **`block_byte_capacity` is then the
sole backstop holding growth short of the transport's bound.**

**That is what ties this item to 1.3's sixth measurement, and why the pair
matters more than either half.** Two things hold capacity inside what the network
can actually carry. One is latent by construction in this release. The other is
`block_byte_capacity` — 8,000,000, retained on an analogy to a data-availability
network and recorded in §1 as a value whose standing is *disputed and reserved to
the owner*. A checklist that flagged only the second would leave a reader
believing the first was load-bearing. It is not, and [ARCHITECTURE §20](ARCHITECTURE.md)
says so in its own words: the gate is latent rather than load-bearing, and
widening the one-block citation window is a prerequisite to relying on it rather
than an optimisation of it.

**This item does not record which way the decision goes**, and that is deliberate
— it is the owner's to make, alongside the byte-capacity question it is coupled
to. What this list asserts is only that it is an open decision, that shipping
without the mechanism is a permitted outcome under §20 provided it is chosen
rather than defaulted into, and that the choice is written down before block 0
rather than discovered afterwards from an empty field.

**It also sets what 1.4's re-verification of `health_gate_bps` = 200 is worth.**
Re-reading that figure at the freeze confirms the number the gate would use; it
says nothing about whether anything ever feeds the gate. Both are needed and the
first does not substitute for the second.

### 1.6 The release is signed, and the genesis values are published and reproducible

⬜ **Not started for the genesis release.** The mechanism exists and is
documented; what has not happened is the release itself.

A launch commits, weeks in advance, to a small set of values that anyone can
rebuild from the tagged source in milliseconds. `zcd genesis` prints them:
network, chain id, params hash, genesis id, state root, genesis time, cells
written, and `allocations 0`. That last line is the one carrying the fair-launch
claim, and it is literally true — the treasury cell is credited from the block
subsidy, `emission(0)` is zero, and a zero cell is an absent cell, so block 0
allocates nothing to anybody including the treasury.

**The project key fingerprint is published alongside them, in full**, and it must
match the one in the whitepaper header — a mismatch is a release blocker, not a
typo. The key does not sign release artifacts; it exists so a reader can tie two
statements to one author without learning who that is, which is the only
anti-impersonation guarantee an anonymous project can offer.

The full gate is [RELEASE.md §8](RELEASE.md), which this item does not restate.
The parts of it that bear specifically on genesis: `make ci` green on the tagged
commit, `make soak-long` green over hours and then a multi-day run,
`go run ./spec/gen` producing no diff, byte-identical rebuild verified, the
release published by the workflow rather than assembled by hand, and a released
binary started against the tagged mainnet parameters that did not refuse.

**One item inside that gate is a genesis-specific hazard worth naming here.** The
launch transition preserves genesis byte for byte, so it is the one reset that
cannot retreat to a new network id — which makes every rehearsal participant a
heavy peer on the same network at the moment nobody is watching the peer set.
Every node ever pointed at the rehearsal network is enumerated from the peers
files, provisioning records and monitoring; each is stopped and wiped or verified
wiped; the new network starts only from empty data directories; and the
enumeration is written into the reset log. **The launch does not proceed until
that list closes.** Waiting is the remedy, not a fresh identity.

### 1.7 Seed infrastructure is ready

⬜ **Not stood up for mainnet.** The software mechanism ships and is exercised by
the testnet; the mainnet seed itself does not exist yet, so this item has not
started in the sense the mark means.

A network nobody can join without first copying an address out of an
announcement has no honest newcomers, so the software carries one built-in seed —
today `testnet.zycord.com:9421`, in [`cmd/zycordd`](../cmd/zycordd/). It is a
name rather than an address so it can be moved without a release, `--no-seeds`
refuses it, and the node prints what it will dial. The testnet relaunch moves it
to the relaunched network; genesis needs the mainnet equivalent standing and
reachable before block 0.

**This is a declared debt rather than a finished item, and it stays open after
genesis.** [RELEASE.md §4](RELEASE.md) is explicit: a registrar record and a
static address exist and are the project's, which no amount of the mitigations
above changes. **The exception closes when a second seed somebody else operates
is published**, and until then this line is a standing item rather than a
satisfied one. That is a post-genesis condition, not a launch blocker — but it is
written here so nobody reads the green mark this item eventually gets as meaning
the underlying problem went away.

---

## 2. Wanted, and explicitly not blocking

**These do not gate block 0, and this section says so plainly rather than leaving
it to be inferred.** Every one of them is wanted; none of them is a reason to
move the date; and none of them will be quietly reclassified into a blocker to
justify a slip, or out of one to justify shipping.

### 2.1 Independent reproducible-build attestations

◻️ **Open and wanted. The tooling ships; no signature has been submitted.**

[`attestations/`](../attestations/) holds a README and a template and nothing
else. That is the honest state.

This is the substitute for a code-signing certificate, and it is not a
consolation prize. A certificate asserts *"this came from entity X"*, backed by an
authority that checked a legal identity — which no authority will ever do for a
pseudonymous project, and buying one would publish the legal name the rest of the
release discipline exists to protect. A reproducible build asserts something
else: *"this binary contains this source, and anyone can check."* One person
checking proves the tag is reproducible. Several independent people checking, and
signing what they got, proves the shipped binary is what the source produces —
which is the thing a certificate was only ever a proxy for. The interesting attack
was never impersonation; it is the publisher's own build machine adding something,
and a certificate cannot see that.

Only `zcd` and `zycordd` are attestable. The desktop wallet is not attested on
any platform and nobody should sign a claim about it.

### 2.2 External review

◻️ **Open and wanted. Not blocking. No external review has been done.**

Stated without hedging: the genesis date does not wait for a review that has not
started, and this project is not going to pretend otherwise in either direction.
Reviews of `core/` and of the RandomX cgo binding are both open. The two
in-project adversarial passes over the binding are **not** that review — the
distinction is that an external review is by independent parties, and calling
in-house work by the same name would be the exact kind of quiet inflation the
adversarial record exists to prevent.

What stands in its place is not nothing, and it is also not a substitute: the
full adversarial record in [`docs/adversarial/`](adversarial/) is published
unedited, including the reviews that found instruments failing rather than code
failing. For an anonymous project the review trail *is* the credibility, and a
design with no visible record of being attacked reads as a design nobody
attacked. But a published record of self-review is evidence about diligence, not
about correctness, and the honest reading of this row is that the strongest
external check on the consensus rules before genesis is the public testnet and
the people mining on it.

If you can break it: [SECURITY.md](../SECURITY.md).

### 2.3 A Stratum endpoint and pool integration

◻️ **Not blocking, and deliberately scheduled after genesis.**

The reason is a clean split. The encoding changes in 1.1 are consensus and must
be frozen before the 15th. **Stratum is not consensus** — it is a transport, so
if it lands late it is a minor release rather than a fork. It must not slip the
genesis date and genesis must not wait for it. The built-in miner is the
launch-day mining path if it comes to that.

Tracked under the **Stratum & pools** milestone, due 2026-09-30, which overlaps
the genesis milestone and does not gate it.

### 2.4 An upstream miner coin-list entry

◻️ **Not blocking.** A distribution channel, not a dependency, and only sensible
to propose once a stock miner has been proven to mine a testnet block end to end.

### 2.5 The explorer network-stats page

◻️ **Not blocking.** Separate repository.

---

## 3. What this document is, and what keeps it honest

It is mirrored in the announcement and updated as items close. Two rules govern
edits to it:

**Every number here is the same number everywhere.** Any figure that appears in
the README, the announcement, the site or the whitepaper is the same figure in
all of them. This document introduces no number that is not already derivable
from the tree — the genesis time is `spec/params.json`, the four re-verified
parameters are `spec/params.json`'s `notes` and
[decisions/capacity-eras.md](decisions/capacity-eras.md), and the §1 enumeration
is [decisions/testnet-measurements.md](decisions/testnet-measurements.md).

**A state here is a claim someone can check.** Every mark above is grounded in
something in this repository or in a published artifact, and where the answer is
"not started" or "nobody has done this", it says so in those words. A checklist
that reports what its author hopes is true is worse than no checklist, because it
converts an unknown into a false assurance — which is the same failure mode the
measurements document records its own instruments committing, and the reason that
document is worth reading before this one.

The milestones above are named by their subject, date and scope rather than by a
tracker reference, and that is deliberate rather than an omission to be tidied up
later: this repository is published as files under a fresh origin, so a bare
issue number resolves to nothing for the reader who has only these files, while
the prose still reads as though the reasoning were one click away.
