# Zycord — Implementation Findings I8: the P2P layer under a malicious node

**Scope:** `node/p2p` and `node/sync` — the peer lifecycle, the wire codec, the
gossip ingress pipeline, peer scoring and the ban system, sync candidacy and
rotation, block-body transfer, and peer exchange. The threat model is the one
the owner states first: *anyone can take this code, modify it, run a node, and
attack another node or the network.* The attacker holds the source, can change
anything, and can run as many identities as it cares to pay for.

**Persona:** the auditor arriving at a hardened surface. I5 turned this layer
over once and left seven open questions in its confidence section; I7 left one
open in `I7-H4`. So the productive question here was not *what is unguarded* —
very little is — but **which guard is aimed at the wrong fact**. Every finding
below is a mechanism that is correct about the thing it measures and wrong
about the thing it is used to decide, which is I5-M5's lesson (*"a filter is
only as good as the signal it filters on"*) arriving through a different door.

The headline finding is a way to get an honest peer permanently banned, with
no attacker required at all — and the ban persists to disk.

---

## HIGH

### I8-H1 — An honest peer is banned for a body this node never asked for ✅ *fixed*

**Problem.** `OnBlockAnnounceFrom` writes `e.pending[id]` and returns a
`get-block` request in the same step. The request then crosses two gates inside
`Node.serve` before it reaches the wire, and **neither told the engine when it
threw one away**:

```go
if v.Err != nil && v.Score <= ScoreProtocolViolation { return }   // dropped
if n.Peers.Banned(conn.Addr) || n.Peers.BannedKey(...) { return } // banned
if v.Reply != nil {
        if err := conn.SendDeadline(...); err != nil { return }   // write failed
}
```

A third path reaches the same state without any gate: `forgetPeer` — the only
teardown hook a connection has — deletes `e.tips` and the peer's partial
transfers and **does not touch `e.pending`**. So a peer that announces a block
and then disconnects leaves its entry standing.

Sixty seconds later `ReapUnservedBodies` charges that entry
`ScoreUnservedBody` (−10). Its single exemption is
`Chain.CanonicalHeader(id) == nil` — the block became canonical — so a block
this node never obtained by any other route is charged in full.

`spec/wire.md` §9 rule 5 prices **"announced and would not serve"**. On every
one of these paths the request never left this node, so *did not serve* was
never true of anybody. The charge is for not being **asked**.

**Why it accumulates rather than annoys.** Three properties compose:

- The address charged for an *outbound* peer is `Conn.Addr`, which is that
  peer's stable dialled listen address, not an ephemeral socket.
- `Peer.Score` carries `json:"score"` and rides the peer store to disk, so the
  penalty survives a restart.
- There is **no score decay and no unban path anywhere in `peerstore.go`**. A
  banned peer receives no messages, so it can never earn the `+1` back. The
  distance is bounded by `ScoreFloor` (−200) and the return trip is infinite.

Ten badly-timed departures therefore ban an honest peer permanently. On the
live two-node testnet the natural driver is an **operator restart**: a node
that announces a block and is restarted inside the next sixty seconds pays
−10 at its peer, every time, and nothing anywhere reports it. The symptom is a
number in a file.

**And it is self-amplifying.** The ban gate stands *between* the verdict and
the send. Once a peer crosses `ScoreBanThreshold`, every further announcement
it lands before the socket closes writes a `pending` entry whose `get-block`
that same gate discards — driving it from −100 toward the floor. The mechanism
that acts on the ban feeds the counter that caused it.

**Reproduced.** `TestAnAnnouncerIsNotChargedForABodyThisNodeNeverRequested`
drives ten truthful announcements from a peer that departs before it can be
asked, and the peer ends at **−100, banned**, holding a stable listen address
that persists. `TestADiscardedGetBlockDoesNotBecomeAnUnservedBodyCharge`
drives the gate half at the engine seam `Node.serve` calls.

**Fix, in two pieces because there are two ways to reach it.**
`forgetPeer` now drops the departing connection's pending announcements
(`dropPeerPendingLocked`), and `Node.serve` tells the engine
(`ForgetUnrequestedBody`) whenever it builds a `get-block` and then does not
send it. The entry is *dropped* rather than kept-and-exempted, because the
announcement is genuinely unanswerable — nothing arrives on a connection that
no longer exists — and the network re-announces the same block for free. The
`seenBlocks` entry is deliberately left alone: the reap's charging branch
clears that to keep a late re-delivery applicable, and here there is neither a
charge nor a delivery to protect.

The rule is unweakened in the direction it exists for. An announcer that was
asked and would not serve, on a connection that stays up, still leaves its
entry standing and is still charged.

**What the fix gives up, at full width.** A peer that announces and then
*deliberately* hangs up before the window elapses now escapes the −10 it used
to pay. That is a real concession and not a rounding error, so it is stated
rather than implied: the charge is now conditional on the connection
surviving the window.

Three things bound it. The announcement had to pass `work.Check` to reach
`pending` at all, so each wasted slot costs the sender a real proof-of-work
evaluation — this is not a free way to consume the reap. The disconnect
forfeits the connection, which is the resource every other defence in this
layer is keyed on, and re-establishing one is priced by the listener's
per-source admission. And the entry is dropped rather than retained, so the
abandoned announcement costs this node nothing to hold.

Set against that, the behaviour it replaces charged an *honest* peer for the
same event, permanently and to disk. Between a defence that misses a
disconnecting liar and one that bans a restarting friend, this layer's own
stated preference — the exemptions around `ErrOrphanOutOfWindow`,
`ErrWrongParent` and the whole of `SyncPenalty` — is consistently the first.
Charging the liar without charging the friend needs the announcer's *identity*
to carry the debt across the socket, and `ReapUnservedBodies` is handed a
connection address and never a public key. That is the shape of the real fix
and it is larger than this one.

**And the identity half already behaved this way**, which is the argument that
settled the choice. `Node.reapUnservedBodies` recovers the key by looking the
address up in `n.conns`, so a departed peer was *already* exempt from the
identity-keyed charge — its comment says so, and prices the alternative:
*"holding a public key per pending announcement so a ten-point penalty can
outlive the connection buys less than it costs."* The two tallies simply
disagreed about departure, and only the address-keyed one persisted to disk.
This makes them agree, in the direction the surviving half had already
chosen.

**Both tests are mutation-proven**, which matters because the first two
versions of this finding were wrong (below). Removing `dropPeerPendingLocked`
fails the first at −100; stubbing `ForgetUnrequestedBody` to a no-op fails the
second at −100.

### I8-H1b — The fix for I8-H1 shipped the evasion this package forbids by name ✅ *fixed; found by review, and it is my own defect*

`ForgetUnrequestedBody` took a block id and deleted on it alone. `pending` is
keyed by block id and nothing else, so that is an unscoped mutation of it from
a message path — *"lets any peer cancel any other peer's debt"*, in the words
of `unservedbody_evasion_internal_test.go`, which exists to forbid exactly this
and has done since before this audit.

**Reachable through the chunk-continuation path.** `OnBlockChunkFrom` answers a
mid-transfer chunk with a second `KindGetBlock` whose id it read off the
*sender's own frame*. The call site matched on message kind alone, so a peer
sending a valid chunk 0 naming somebody else's announced id received a
`get-block` for an id it did not owe — and when the serve seam discarded that
reply, it cleared the victim's entry. Confirmed at the engine seam: the
attacker's chunk 0 returns `Err=nil` with `Reply=get-block(victim's id)`.

Practically it is cheap to defend against and cheap to attack: 4 MiB to cancel
one −10. It points toward ban **suppression** rather than the amplification
I8-H1 is about, so it does not undo that fix — but it disarms the reap quietly,
which is the worse direction to be wrong in silently.

**Fix.** The delete now requires the pending entry to belong to the connection
the frame arrived on. The check lives beside the map rather than at the call
site, because the call site holds no lock and cannot read `pending` without
one, and a guard next to the thing it protects cannot be forgotten by the next
caller.

**Why the existing guard did not catch it, which is the part worth keeping.**
`TestAPeerCannotCancelAnotherPeersUnservedBody` drives `OnBlockChunk` and reads
the returned `Verdict`. `Node.serve` does something the verdict alone does not
describe: it takes `v.Reply` and, on the branches where it does not hand the
frame to the connection, tells the engine to forget the entry that reply was
for. That seam is a *second* mutator of `pending` reachable from a chunk path,
and the guard had no view of it. **The guard passes against the unscoped
version.** It is not vacuous — it kills the mutant it was written for — but its
coverage stopped one call frame short of where the new code lives, which is the
same shape as the three instruments this tree has already caught measuring
nothing, arriving as *a guard that cannot see the path it guards*.

`TestAPeerCannotCancelAnotherPeersUnservedBodyThroughTheServeSeam` covers the
seam and fails against the unscoped version with `charged=[]`. It asserts its
own setup first — the chunk must be accepted, the continuation must be produced,
and it must name the victim's id — or the scoping it is about is never
exercised.

**The general lesson, since this is the second time in one audit.** I8-L1 was a
test that could not fail; this is a guard that could not see. Both were written
by someone who had just read the rule they broke: the file naming this evasion
is the file the new test was added to.

### I8-H2 — The same charge, aimed by a third party ✅ *fixed, at the announcer*

The mechanism above needs no adversary. It also **has** one, and the attacker
never has to touch the node that does the banning.

`OnGetBlock` refuses over-budget requests through `refuseUnbudgeted`, which
returns a verdict carrying **no `Reply`** — correctly unscored, since a budget
refusal is a price and not a judgement. The budget it consults has two arms,
and the second is `nodeServedBytesExhausted`: a **node-wide** ceiling of
`connSet × BlockByteCapacity`, keyed on nothing and shared by every asker. The
code says so itself — *"a shared lever… enough of them can hold all of it, so a
peer that has spent nothing of its own budget can be refused."*

So: an attacker floods honest miner **A** with requests until A's shared
ceiling is spent. A then announces a block to victim **V**. V asks for the
body; A's `OnGetBlock` refuses on the node-wide arm and sends nothing; sixty
seconds later V charges A −10. Twelve blocks and A is banned at V — **and the
attacker is not connected to V at all.** The score persists to disk with no
decay, so the ban is permanent.

I8-H1's fix does not close this one, and should not be read as though it did:
here V's request genuinely *was* sent, so V's books are correct. What is wrong
is that a refusal A was not at fault for is indistinguishable at V from a
refusal to serve.

**No longer merely read — demonstrated.** The earlier text called this confirmed
as a mechanism and unmeasured as an exploit. It is now driven end to end.
`TestAThirdPartyDrainsTheSharedBudgetSoAnHonestNodeRefusesALegitimateRequest`
establishes the premise: two identities drain the `connSet = 2` node-wide
ceiling and a fresh victim's `get-block` comes back with no reply and **no score
against it**, so A's silence is caused by a third party and is unattributable at
V. `TestAThirdPartyStillDrivesAnHonestPeerToABan` then drives the consequence at
the Node seam, where both tallies move: **12 announcements accepted, address
score −120, banned on the address AND the identity.** That test asserts the
defect as it stood.

**Superseded, and the correction matters more than the reframing.** That
sentence used to read *"closing I8-H2 means inverting its last assertion"*, and
following it would have produced a vacuous test. Both tests in
`thirdpartyban_internal_test.go` drive **V's engine and nothing else** — there is
no A-side engine anywhere in the file — so a fix that lives in A's serve path
cannot change either outcome. Pointed one way the assertion fails for the fix;
pointed the other it is a guard that cannot fail, which is I8-L1's defect
arriving for the third time in this document. Both tests are therefore **kept
as they are and retitled**: they pin what the transport shows the scorer, which
the fix deliberately does not change, and the second is now the *ghost-flood
terminator seen from the inside* — the assertion that refuses the two candidates
below that failed by weakening the charge.

**The shape the attack actually has, which is the part that defeats the obvious
fixes.** A real miner builds each block on **its own** tip. Under the drain A
serves nothing on any path — `KindGetBlock` is the single dispatch case for both
the announce fetch and the sync body fetch — so **V's tip never advances** and A
runs away from it. Measured in that test: of 12 announcements, exactly **1**
names V's tip. Every later one is, at V, an orphan whose parent V does not hold.
That is not an edge case but the normal condition of a lagging receiver, and the
difficulty gate's own comment already measured it from the other side: a node one
block behind sees *19 of 20* honest announcements name a parent it does not hold,
and a rejoining node 14 of 15.

**Why the small network is the cheap case, not the safe one.**
`replyBudgetExhausted` reads the node-wide arm **first**, and the ceiling is
`connSet × BlockByteCapacity` over the connections a node *actually holds* — not
over the 48-connection adversarial maximum the first write-up reasoned from. At
`connSet = 2`, the live testnet, that is 16,000,000 bytes against a per-identity
budget of 8,000,000: **two identities' worth, not forty-eight.** The ceiling
sized as a node-wide backstop is, on a small network, barely above the per-peer
budget it sits behind — so the smaller the network, the cheaper this is, and a
two-node testnet is the cheapest case rather than the safest.

**Four fixes were built or costed, and each fails. Recorded so the next author
does not re-derive them.**

- **Bound `ScoreUnservedBody` outright**, below `ScoreBanThreshold`, so the
  charge can never ban. Built, and it **disarms the ghost-flood defence**: that
  same charge is the *only* terminator of a peer spraying cheap `max_target`
  announcements at an unheld parent, and with the bound in place
  `TestAGhostFloodReachesNeitherForwardNorReframe` stops banning. Rejected by
  measurement, not by argument.
- **Bound it only for a tip-extension** — an announcement naming V's own tip,
  which the difficulty gate forces to carry real work, so it cannot be minted
  cheaply and the ghost flood keeps its ban. Built, mutation-proven in both
  directions, and **ineffective against the attack**: on the shape above only 1
  of 12 charges qualifies, and that one lands at −10, far above the floor, so the
  bound never even engages. Score with the fix in place: **−120, still banned on
  both tallies.** This is the reason the finding is not marked closed. The
  discriminator is sound and cannot be gamed upward — `pending` has exactly one
  production write site, behind height `tip+1`, `Target.Eq(want)` and
  `work.Check` — it simply covers the wrong 1/12 of the traffic.
- **Retry on the requester side before charging.** Keeps the ghost ban (a
  flooder has no body to serve on the retry either), but a *sustained* drain
  defeats it: the node-wide bucket refills every `TargetBlockSeconds` and holding
  it empty costs the attacker roughly 530 KB/s at `connSet = 2`, so every retry
  meets the same refusal.
- **Score decay, or a bounded unban path.** The ghost-flood test drives its
  charges in ~0 s of wall clock, so any decay slow enough to leave that ban
  intact is far too slow to save A under a drain measured in block intervals. A
  general decay is also the freeze-gated behaviour change the Confidence section
  below already declines to make unmeasured.

**And the wire change does not close it either, which is the finding's real
sting.** An explicit "budgeted, ask later" answer was the standing recommendation
— make A's refusal *legible* to V. It fails twice. It is **not
backward-tolerant**: `ReadFrame` rejects an unknown message kind and the dispatch
scores it `ScoreProtocolViolation` (−50) before the node drops the peer, so the
new frame bans its sender at any node not yet upgraded — a coordinated upgrade,
not a free repair. Worse, the claim is **forgeable**: a ghost flooder answers
"budgeted" to every `get-block` and escapes the ban outright, reopening the flood
this charge exists to terminate; and bounding how often a peer may claim it
re-bans the honest A, whose whole situation is being unable to serve for a long
time. The indistinguishability moves one message along and survives.

**What would actually close it.** V has to establish that A is genuinely ahead
*without trusting A's word*, and the only unforgeable evidence is **cumulative
work V verifies itself**: a forward header chain rooted at V's own tip, with each
successive target *derived* by V (as `node/sync.ValidateHeaders` and
`chain.ConsiderBranch` already do along a branch) rather than read out of
`Header.Target`. An honest miner's run-away chain anchors at V's tip and
validates; a ghost chain is unanchored and never does; and an attacker who wants
the leniency has to mine at real difficulty, which is not a flood but
participation. That is the shape of the fix. It is also branch difficulty
derivation plus bounded per-peer header state on the hostile gossip ingress path
— consensus-adjacent, and the difficulty gate deliberately stops at the tip today
for a measured liveness reason (refusing the lagging fringe's unheld-parent
announcements is the failure that reverted I7-H4's tip window). It wants its own
review and is not a pre-freeze change.

**A claim from the rejected fix that was wrong, corrected here.** It argued that
withholding a real block gains an attacker nothing because "it propagates via
every other peer". On the announce path it does not: the seen-set dedup read at
the top of `OnBlockAnnounceFrom` fires **across peers**, so the first announcer
of an id suppresses every other peer's announcement of it with `CostDeduped`
until the entry is cleared — which for a charged entry is the reap at
`PendingBodyTimeout`. The first announcer holds the floor for the window.

**Status for the freeze — superseded.** This section used to end by saying the
finding was open, that publishing this document published a live recipe, and
that marking it fixed was *not* available. The fix below is the fifth candidate,
and it is the one that closes it. The paragraph is kept rather than deleted
because the four failures it rests on are still the reason this shape and not
another one.

**The fix: an announcer never refuses what it announced.**

All five candidates before this one worked on **V's side of the asymmetry**,
teaching the *scorer* leniency, and every one of them either spared the
ghost-flooder, covered 1/12 of the traffic, or died against a sustained
drain.
This one reframes the defect at the other endpoint. V charges A for an unserved
body **that A volunteered**: the announcement was A's own discretionary act, and
the shared ceiling then makes A break the promise the announcement is. So the
obligation is attached to the announcement:

> **An outbound block announcement reserves the right of each announced peer to
> fetch that body once, and the node-wide ceiling cannot starve that lane.**

Two chokepoints, no wire change, no scoring change, nothing in the consensus
zone. `node/p2p/announceledger.go` holds the rule and its reasoning; the
mechanics are:

- **Record at send.** `Node.Broadcast` is the single funnel every outbound
  `KindBlockAnnounce` passes through — `AnnounceBlock` for this node's own mined
  block, the gossip and fork-choice forwards through `Node.serve`'s `Forward`
  arm, and `relayReleased` for a withheld block that matured — so the promise is
  recorded there and a fifth producer added later still lands on it. It is
  recorded **after** a successful send, keyed on `replyBudgetKey(Conn.Addr,
  Conn.PeerKey)`, which is exactly the `payer` string the serve path is handed.
- **Redeem at serve.** In `OnGetBlock`, at the call site of
  `replyBudgetExhausted` and **not inside it** — that function is shared with
  `OnGetHeaders`, and a header range is not something this node ever promised
  anybody, so an exemption that leaked there would be a hole in the ceiling
  rather than a lane through it. The promise is *looked up* before the chain
  read (a map read, so an unpromised peer still buys nothing) and *spent* after
  the payload exists, because it is denominated in bytes.

**Why the four known failures do not arise.**

- *Ghost flood (killed candidate 1, the blanket bound).* Untouched, for two independent
  reasons. The fix changes which requests **A serves** and never what **V
  scores**, so no leniency exists at the scorer at all; and the ledger is keyed
  on A's own outbound announcements, so a ghost's block — which A never
  announced — has no entry to redeem. `TestAGhostFloodReachesNeitherForwardNorReframe`
  passes unchanged, and `TestAThirdPartyStillDrivesAnHonestPeerToABan`
  is now retained precisely as the assertion that this stayed true.
- *The tip-extension bound's 1-in-12 (candidate 2).* Does not apply: the
  discriminator here is "did A announce this body to this peer", which is true of
  **all twelve** announcements rather than the one that happened to extend V's
  tip. Measured end to end below.
- *The sustained drain (candidate 4, requester retry).* The drain is re-applied
  every round in the two-engine test, after the announcement, so the ceiling is
  empty at every single request. A promise is not a retry.
- *Forgeability (the wire answer).* There is nothing to forge. The ledger is A's
  memory of A's own sends; no peer can write to it, no new frame exists, and an
  un-upgraded peer sees only that A serves where it used to refuse — which was
  always protocol-legal, since the refusal was discretionary.

**Bounds, because an exemption without them is a hole.** Redemption is
once-per-`(payer, block id)`, capped by *cumulative bytes* at
`announcedRedemptionFactor` (2) times the body's real on-wire size, read from
this node's own store and never from the request. Bytes rather than requests
because the budget gate runs per chunk: a promise consumed on first use would
serve chunk 0 past the ceiling and refuse the rest, leaving the receiver holding
a partial it still gets charged for — strictly worse than the defect. Inert
today (`block_byte_limit_genesis` 2,500,000 against `BlockChunkBytes` 4,194,304,
so every body is one chunk) and live after an era re-pin toward
`block_byte_capacity`; the rule is written for both regimes because only one is
testable. Promises expire at `announcedTTL` = `2 × PendingBodyTimeout`, stated
against that constant rather than in block intervals, which invert between
devnet at 5 s and mainnet at 30 s. The ledger is bounded per peer at
`maxAnnouncedPerPeer` (32, against a ban distance of 10 charges) and across
peers by expiry on the sweep that already reaps `pending` and `seenBlocks`.

**Amplification, sized rather than asserted.** A redemption exists only where
this node announced, once per `(peer, id)`, byte-capped. The node-wide ceiling is
already `connSet × BlockByteCapacity` — *"every connection fetches one maximal
block"* — and the reserved lane's worst case is the same quantity: each announced
peer redeems once per announced block. It is not new egress the ceiling must be
widened for; it is the ceiling's own sizing rationale given priority over garbage
instead of being consumed by it. The bytes are **still debited to both layers**,
so the overshoot stays visible to the counter that exists to make it visible, and
the ceiling is a leaky bucket (`refilledServed`) so an exempt reply drains at the
refill rate and cannot be latched. At the committed parameters the exempt
quantity is `BlockByteLimit` against a per-connection ceiling of
`BlockByteCapacity` — 2.5 MB against 8 MB, **0.31×** — and that ratio drifts
toward 1.0× if an era re-pin raises the elastic limit.

**The safety precondition, named because it is what makes the promise
honourable.** Every outbound `KindBlockAnnounce` stands behind a successful
`Chain.Apply`: `cmd/zycordd` announces after `miner.MineOne`, `node/stratum`
after `chain.Apply` (**two** `AnnounceBlock` call sites, not one — an earlier
statement of this precondition said one and was wrong; both are past an apply, so
the argument survives the correction), the tip-extension forward is returned only
in the `err == nil` arm, the fork-choice forward carries `reorg.Adopted`, and the
withhold release re-propagates a body this node accepted. So an announcement
implies the body is held and every entry is redeemable. If a future change ever
emits an announcement ahead of holding the body, the TTL stops being
belt-and-braces and becomes load-bearing.

**Measured, at both endpoints.** The closure is asserted in
`announceledger_internal_test.go`, and the headline is
`TestAThirdPartyDrainDoesNotBanAnHonestMinerAcrossTwoEngines`: A and V as
separate engines, a third party draining A's node-wide ceiling **every round
after the announcement**, twelve rounds on the same shape the V-side test uses.
Result: **12 announcements, 12 served by A, V's address score 0, banned on
neither tally.**

**And the shape inverts, which is the result rather than a complication.** The
V-side test asserts V's tip never advances and that exactly 1 of 12
announcements names it — that frozen-V shape is what the drain *causes* and what
made the tip-extension discriminator cover the wrong 1/12. With the promise
honoured V is not frozen: it receives each body, applies it, and tracks A block
for block, so **all 12** announcements are tip-extensions and V ends at A's own
height. The test asserts that too, and it is what stops it passing for a lazy
reason: a fix that made A serve nothing while V happened not to charge would
leave V at height 0, and a fix that stopped V charging without A serving would
leave the count at 1. Both are caught.

**Every assertion is mutation-proven**, which this document has three times over
recorded as the only thing that catches an instrument measuring nothing. Eight
mutants, each killed: removing the exemption (all five tests); dropping the byte
cap (redeemed 5 times, want 2); making redemption peer-unscoped, then
id-unscoped (each caught by its own bound); disabling the TTL; removing the
per-peer cap (128 promises held, want 32); making `reapAnnouncedLocked` a no-op
(64 payers survived); and unhooking the `Broadcast` seam so the ledger is correct
but unreachable from production — that last one is I8-H1b's lesson applied in
advance, since a guard proven against a direct call says nothing about whether
the production path reaches it. One of these bugs was real rather than injected:
the first version deleted a payer's bucket from the map when expiry emptied it,
including on the very first record, so every promise landed in an orphaned map.
The tests caught it immediately.

**What it deliberately does not fix, and the coupling that follows.**
Sync-path refusals stay uncharged by construction (`syncdriver.go` exempts
`ErrTransport`), so no ban rides them today — but whoever closes *"a peer that
refuses a body during sync is never charged"* must route that charge around
budget refusals or through this same ledger, **or this attack returns through the
new door.** And this does not replace the cumulative-work verification described
above: that one hardens V against shapes no ledger at A can address, and it
should still happen post-freeze with its own review. This is the transport-local
half, and it is pre-freeze-safe because it touches no consensus surface, no wire
kind and no scoring rule.

---

## MEDIUM

### I8-M1 — `Merkleize` can index past `zeroHashes` on an operator's own parameters ⚠️ *latent, not peer-reachable*

`ssz.Merkleize` derives `depth` by `for 1<<depth < limit { depth++ }` and then
reads `zeroHashes[depth]`, where `zeroHashes` is a `[64]crypto.Hash`. A
`cert_list_capacity` above `2^63` drives `depth` to 64 and indexes out of
range; `1<<depth` overflows alongside it.

`Params.Validate` checks that `cert_list_capacity` is positive, is at least
`max_certs_per_block_genesis`, and survives the `seq_gas_capacity`
cross-multiplication — but **imposes no ceiling**. The same argument applies to
`max_cites_per_block`.

Not reachable from the network, and that was checked rather than assumed:
params reach this code solely through `e.Chain.Params()`, and nothing anywhere
decodes a parameter set off the wire. The committed sets are far below the
bound. It is recorded because `Validate`
already refuses far less exotic things, and because the guard is one
comparison. The panic that made I5-H15 critical is the same function.

---

## What was attacked and found sound

Recorded because a negative result from a deliberate attempt is evidence, and
because the next auditor should not re-run these.

- **Remote panics.** Every `panic(` in `core/` and `node/` was enumerated and
  traced against the ten p2p entry points and the sync path. **None is
  reachable from peer input.** The I5-H15 merkleisation panic is guarded at
  three independent places — the announce ceiling, `UnmarshalBlock`'s decode
  bounds, and `blockrules.go` for locally-built blocks. Every wire decoder
  checks its exact length before indexing. `FuzzDecodeBlock` ran 910k
  executions with no crash. This matters more than usual because **there is no
  `recover()` anywhere in the tree** — a panic in any per-peer goroutine is the
  whole process — so the blast radius of a future regression in those guards is
  total. That is worth stating as policy rather than leaving as a property.
- **Wire-codec resource bounds.** `MaxMessageBytes` is checked before
  allocation; every list decoder cross-checks its claimed count against the
  bytes actually present, so a large claim allocates nothing. `UnmarshalPeers`
  establishes `len(rest) >= 4` before computing `len(rest)-4`.
- **The ban system's Direction-A exemptions.** `ErrWrongParent`,
  `ErrOrphanOutOfWindow`, `ErrOrphanPoolFull`, `ErrNotBetter`,
  `ErrUnknownAncestor`, `ErrBeyondUndoHorizon` and `chain.ErrLocal` are all
  uncharged. The `ErrBodyUnavailable`-laundered-from-transport bug I5 flagged
  as open is genuinely closed, and the fix was verified mechanically rather
  than from its comment: `sync.go` now wraps with **two `%w` verbs**, so both
  sentinels survive into `errors.Is` and the exemption really fires.
- **Losing a mining race on the body path.** Pinned by
  `TestACompetingSiblingBlockCostsTheSenderNothing`, and it holds.
- **Peer-exchange poisoning and store flooding.** `AddFrom` requires a
  parseable `host:port`, and admission is bounded per source cohort
  (`MaxPerSourceStored`) under a global `MaxPeers`, so one gossiping peer
  cannot fill the store or displace another source's entries. The documented
  `0.0.0.0:9421` sync freeze is closed by re-routing an undialable candidate
  over the socket it already owns.
- **Transfer-table cross-peer eviction.** The per-peer eviction arm is scoped
  to the evicting peer's own transfers; the table-full arm counts peers against
  `MaxPartialTransfers` = 64, which exceeds the whole connection set of 48. The
  global byte budget *is* cross-peer, but it is inert at the committed
  parameters: `block_byte_limit_genesis` is below `BlockChunkBytes`, so bodies
  travel as one chunk and never enter `e.partial` at all. It becomes live at an
  era re-pin past 4 MiB.

---

## LOW / NOTES

- **I8-L1 — Two wrong versions of I8-H1 came first, and both looked right.**
  The first framed it as a *fork race*: a losing sibling is never canonical, so
  its honest announcer is charged. That reproduced — and the fix built for it
  (exempt anything the chain or the orphan pool holds) **passed its own test
  with the fix mutated back out.** The test was vacuous, because `pending` is
  already cleared the moment a body decodes, so serving in time exempts the
  announcer whether it wins the race or loses it. Probing all three orderings
  settled it: the charge turns *only* on whether the body arrived inside the
  window, never on the race. The finding survived; the mechanism in it was
  wrong, and the mutation is what said so. Recorded at length because this is
  the third instrument in this project to report success while measuring
  nothing, and the first to do it inside an audit written after I5 named the
  pattern.
- **I8-L2 — `holdOrphan`'s distance arithmetic wraps and fails safe by
  accident.** `distance := int64(Height) - int64(tip.Height)` followed by a
  sign flip: a declared height of `1<<63` makes the negation a no-op in Go, and
  `uint64(distance)` is then `1<<63`, which exceeds `HeightWindow` and is
  refused. Correct outcome, arrived at by an overflow rather than by a check.
- **I8-L3 — `Candidate.Tip()` indexes `Headers[len-1]` with no empty guard.**
  Safe today by a three-hop argument across `accept`, `adopt` and
  `extendToCoverWith`; nothing asserts it at the site that would panic.
- **I8-L4 — Goodwill is bankable, and it is bounded.** `ScoreUsefulMessage` is
  +1 against a `ScoreCeiling` of +100, so a long-lived peer sitting at the
  ceiling absorbs ten invalid messages instead of five. That is a 2× amnesty,
  not an unbounded one, and it is already measured in-tree. Earning score
  requires a message that is new *and* valid, which the chain rate-limits,
  while −20 is charged at line rate; the ratio favours the defender.
- **I8-L5 — `e.pending` is bounded by proof of work rather than by a cap, and
  nothing says so.** `seenBlocks` and `pending` are written on adjacent lines
  in the same critical section, and only the first is capped on insert —
  `MaxSeenBlocks` = 4096, evicting the oldest, with a comment explaining that a
  flood can insert faster than the 15 s ticker sweeps. That argument applies
  verbatim to `pending`, which has no cap at all, and `evictOldestSeenLocked`
  does not clear the matching `pending` entry, so `pending` can exceed
  `MaxSeenBlocks`. It is nonetheless bounded, by two things neither of which is
  a size limit: an entry is written only *after* `work.Check` passes, and the
  per-connection and node-wide work-eval budgets bound how many evaluations a
  peer population can buy per period; and every entry expires at
  `PendingBodyTimeout`. So the real bound is `work-eval ceiling × 60 s` worth of
  distinct valid headers, which is small — but it is an emergent bound, not a
  stated one, and the one line that would make it explicit is the line its
  neighbour already has. Recorded rather than changed: adding an insert cap
  here changes which announcement is dropped under load, and that is a policy
  choice this audit should not make unmeasured.
- **I8-L6 — Identity bans are evictable under identity churn.** `AdjustKey`
  admits a newcomer by evicting the least-worthy entry at `MaxIdentities`, so
  an attacker spending five invalid messages per throwaway identity can push an
  older ban out of the store. Bounded, acknowledged in-tree, and the
  alternative — refusing newcomers — was measured to freeze the store shut.

---

## Confidence

- **I8-H2 is CLOSED, at the announcer, and the previous entry here is
  superseded.** It used to read *"the tree carries no fix for this finding"*.
  It does now: the announced-body ledger, driven end to end across two engines
  under a drain re-applied every round, with eight mutants killed. What has
  **not** changed, deliberately, is anything at the scorer — V is exactly as
  strict as it was, which is what keeps the ghost-flood terminator armed and is
  the property the four failed candidates each traded away.
- **What I am least sure of on the fix is its behaviour on a real network, not
  its logic.** Everything here is unit-driven. The three things a soak would
  test that no test here does: whether the per-peer bound of 32 is comfortable
  under real reorg churn (it is sized against a ban distance of 10 and an
  announce rate bounded by proof of work, both arguments rather than
  measurements); whether the 0.31× amplification stays where the arithmetic puts
  it once real connection sets and real block sizes are involved; and the
  multi-chunk redemption path, which **no test in this tree can reach** because
  `block_byte_limit_genesis` is below `BlockChunkBytes` at every committed
  parameter set. That last one is written from the rule rather than from a
  measurement and is the first thing an era re-pin should re-examine.
- **The `payer` key is the fix's single point of agreement, and it is
  unpinned across a reconnect.** Record and redeem both use `replyBudgetKey`, so
  they agree by construction — but a peer connected *without* an authenticated
  key falls back to `Conn.Addr`, which for an inbound peer is an ephemeral port.
  Such a peer's promises are unredeemable after a reconnect. That is the
  fallback path `replyBudgetKey`'s own comment calls "the fallback and not the
  design", reached only by callers that never completed a handshake, so it does
  not arise in production — but it is the seam where a future change could make
  the two halves disagree silently, since a promise that is never found looks
  exactly like a promise that was never made.
- **What I am least sure of on I8-H2 is the size of the real fix, not its
  shape.** Verified forward-chain anchoring is the only unforgeable
  discriminator I could construct, and I did not build it, so its cost is
  reasoned rather than measured — in particular how the bounded per-peer header
  state interacts with the orphan pool and the key-epoch budgets, and whether
  deriving targets along a branch on the announce path can be done without
  reintroducing the lagging-fringe refusal that reverted I7-H4.
- **The fix for I8-H1 is unit-proven and has not run on a network.** Both tests
  are mutation-proven and the p2p suite is green around them, but neither the
  chaos soak nor the live testnet has exercised the new teardown path. The
  disconnect case is the one a real network produces constantly, so this is the
  first thing a soak would confirm or refute.
- **No decay, no unban, no minimum-peer floor.** These are structural and
  unchanged by anything here. A node that has banned every peer able to tell it
  it is behind still reports `ahead_peers=0`, byte-identical to a node at the
  tip — the `Health` struct exposes the raw counts upstream of the ban filter
  precisely so an operator can tell those apart, but that is a diagnostic and
  not a recovery. The documented self-isolation incident's *shape* therefore
  survives even with I8-H1 closed: what changed is one way of entering it, and
  I8-H2's announce-path entry is now closed too, so both known ways in are shut —
  but the *class* is not, and that is the part unchanged by either fix: a node
  that has banned every peer able to tell it it is behind still has no way back.
  A slow decay toward zero, and suspending
  bans when the candidate set would empty, are the two changes that would close
  the class rather than an instance — and I8-H2's own section records why the
  decay half cannot be tuned to close it without disarming the ghost-flood ban.
  Neither is made here; both are larger than an audit's follow-up commit and
  both change behaviour a freeze should not absorb unmeasured.
- **`ScoreUnservedBody` was the only charge I traced end to end.** The other
  five negative-score call sites were read and reasoned about, not driven. The
  reap is the one where the fault and the charge are separated by sixty seconds
  and a different code path, which is why it was the one worth driving.
- **The `-race` gap is closed for the fix, and not for the layer.** CGO is
  available after all — the earlier claim here was wrong — and the fix plus the
  whole unserved-body evasion set run clean under the detector. That covers the
  code this audit added; it says nothing about the interleavings in
  `unregister`'s teardown that `sync.md` §7 already names, because no test
  drives them.
- **I8-H1b is the second defect in this audit found by someone other than its
  author, in code its author had just written.** The first, I8-L1, was a test
  that could not fail. Both were caught by mutation — one by mine, one by a
  reviewer's — and neither by reading. I do not have a method that would have
  caught either from the inside, and the honest reading of two in one pass is
  that the rate is a property of the work rather than of these two instances.
