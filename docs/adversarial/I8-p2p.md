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

### I8-H2 — The same charge, aimed by a third party ✅ *fixed*

The mechanism above needs no adversary. It also **had** one, and the attacker
never had to touch the node that did the banning.

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
seconds later V charges A −10. Ten blocks and A was banned at V — **and the
attacker was not connected to V at all.** The score persisted to disk with no
decay, so the ban was permanent.

I8-H1's fix does not close this one, and should not be read as though it did:
here V's request genuinely *was* sent, so V's books are correct. What was wrong
is that a refusal A was not at fault for is indistinguishable at V from a
refusal to serve.

**Why the small network was the cheap case, not the safe one — the reason the
fix mattered before a small-network launch.** `replyBudgetExhausted` reads the
node-wide arm **first**, and the ceiling is `connSet × BlockByteCapacity` over
the connections a node *actually holds* — not over the 48-connection
adversarial maximum the first write-up reasoned from. At `connSet = 2`, the
live testnet, that is 16,000,000 bytes against a per-identity budget of
8,000,000: **two identities' worth, not forty-eight.** The ceiling sized as a
node-wide backstop is, on a small network, barely above the per-peer budget it
sits behind — so the smaller the network, the cheaper this is, and a two-node
testnet is the cheapest case rather than the safest. This stays true; it is now
the reason the fix was taken rather than an open measurement.

**The fix: the ambiguous signal can no longer ban on its own.** The honest root
fix is to make A's refusal *legible* to V — an explicit "budgeted, ask later"
answer rather than silence. That is a wire change and it is **not
backward-tolerant**: `ReadFrame` rejects an unknown message kind and the
dispatch scores it `ScoreProtocolViolation` (−50), so a new response kind sent
to an un-upgraded node bans the *sender* faster than the hole it closes. On a
live network about to be published that is a coordination cost, not a free
repair, so it is deferred to its own review (see the residual below).

What was taken instead is smaller and keys on the one fact that separates A's
case from a genuine offender: **A's block is a tip-extension.** An honest miner
announces a block that extends V's own tip, and the difficulty gate in
`OnBlockAnnounceFrom` forces such an announcement to carry V's real
proof-of-work target — a `max_target` header naming the tip is refused
`ScoreInvalidMessage` there, so only a real block reaches `pending` as a
tip-extension. That fact is recorded on the pending entry (`announcedBody.atTip`),
and `ReapUnservedBodies` **bounds the unserved-body charge for a tip-extension**
at `ScoreUnservedBodyFloor` (−50, above `ScoreBanThreshold`): however long a
third party sustains the drain, A's real-block announcements can leave it
heavily penalised (disfavoured in sync selection) but never ban it. Both tallies
are bounded — the address (`Engine.ReapUnservedBodies` → `AdjustNotBelow`) and
the identity (`Node.reapUnservedBodies` → `AdjustKeyNotBelow`) — because the ban
check is `Banned(addr) || BannedKey(key)` and a bound on one half alone still
bans on the other.

**Why bounding only the tip-extension is what keeps the ghost-flood ban intact.**
The unserved-body charge is also the *only* terminator of a ghost flood — a peer
spraying cheap `max_target` announcements naming an **unheld** parent at tip+100,
which it will never back (`TestAGhostFloodReachesNeitherForwardNorReframe`, and
the multi-node `announceforward` case). Those are the opposite of a
tip-extension: cheap to mint and third-party floodable, so the charge on them is
left **unbounded** and still bans. The two are indistinguishable at V by
magnitude or rate — which is why a blanket bound, a decay or a retry each either
disarms the ghost ban or fails against a sustained drain — but they are cleanly
separable by whether the announcement carried real work for V's own next block.
An attacker cannot borrow the tip-extension's leniency for a flood: a cheap
tip-child is refused `ScoreInvalidMessage` at the gate before it ever reaches
`pending`, and a real one costs a real block's work.

**What it gives up, stated rather than implied.** A peer that mines real blocks
extending V's tip and then will not serve them can no longer be *banned* on that
signal — it settles at the floor. That is deliberate and it is the honest case:
withholding a real block gains an attacker nothing (it propagates via every other
peer), and body-availability withholding was already carried by sync rotation
rather than score (`ScoreUnservedBody`'s own doc), with the reachable ban for a
peer that serves bytes that are a lie being `SyncPenalty`, untouched. Every
*attributable* penalty — `ScoreInvalidMessage` (−20), `ScoreProtocolViolation`
(−50), `SyncPenalty`, `ScoreExcessRequest` — is unbounded and still reaches
`ScoreBanThreshold`; a peer at the floor still crosses into a ban the moment it
earns one. So **no genuine ban is weakened**: the orphan-flood ban fires
unchanged, and the attributable bans are untouched.

**Reproduced, and mutation-proven both ways.**
`TestAThirdPartyDrainingTheSharedBudgetCannotBanAnHonestPeer` drives twelve
unserved tip-extensions at the Node seam so both tallies move (it asserts each is
`atTip`, or it would exercise the wrong path). It reached −120, banned on both,
against the pre-fix tree, and settles at −50, unbanned, now. Forcing the reap to
charge every entry *unbounded* bans it again — the address half at −120, the
identity half through `BannedKey`. Forcing it to bound *every* entry makes the
ghost-flood test stop banning. So the discriminator is load-bearing in both
directions and neither test is vacuous.
`TestAThirdPartyDrainsTheSharedBudgetSoAnHonestNodeRefusesALegitimateRequest`
pins the premise: two identities drain the `connSet = 2` node-wide ceiling and a
fresh victim's get-block is refused with no reply and **no score against it**.
`TestTheUnservedBodyFloorDoesNotWeakenAnAttributableBan` pins the attributable
side. The set runs clean under `-race` (CGO is available).

**Residual, stated plainly.** Three things are not closed here. The wire-level
"budgeted, ask later" answer — the root fix that makes A's refusal *legible* —
is deferred to its own pre-freeze review for the compatibility reason above; the
bound makes it no longer urgent, not unnecessary. The discriminator is the tip:
if V is a block or more **behind**, A's real announcement names a parent V does
not yet hold, so V classifies it as an orphan and the charge is unbounded — the
same lagging-fringe case the difficulty gate itself declines to judge, and the
one a rejoining node produces. On the healthy mesh I8-H2 targets, V holds the
tip A extends; the residual is the syncing/partitioned node, where a slow-decay
or minimum-peer floor is the class-level answer the Confidence section records.
And the fix is forward-looking: it stops the mechanism *forming* a ban but does
not retroactively lift one already on disk from before the upgrade — a peer an
earlier tree drove below the floor stays where it was left, because healing an
existing score needs that same decay / bounded-unban path, a larger freeze-gated
change not made here.

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

- **I8-H2 is fixed and the fix is unit-proven, not soak-proven.** The whole
  chain is now driven, not only read: an honest peer's tip-extensions ban it on
  both tallies against the pre-fix tree and do not after the bound. The
  discriminator is mutation-proven in both directions — charge every entry
  unbounded and the honest peer bans; bound every entry and the ghost flood
  stops banning — so the tip-extension axis is load-bearing rather than
  decorative. What is *not* exercised is a live network, the same gap I8-H1's
  fix has, and the lagging-node edge in the residual is reasoned, not driven.
  The bound is deliberately narrower than the wire "budgeted, ask later" answer
  it defers: it does not make A's refusal legible to V, and it does not un-ban a
  peer an earlier tree already banned.
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
  survives even with I8-H1 and I8-H2 closed: what changed is two ways of
  entering it, both by bounding a specific charge rather than by adding
  recovery. A peer already banned on disk before those fixes is not healed by
  either. A slow decay toward zero, and suspending bans when the candidate set
  would empty, are the two changes that would close the class rather than an
  instance.
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
