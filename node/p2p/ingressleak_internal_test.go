package p2p

import (
	"fmt"
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/spec"
)

// solveMaxTarget mines h against MaxTarget, the easiest target on the chain, so
// a distinct valid header costs a handful of expected hashes to produce. It is
// what the seen-set reachability derivation calls "vary the nonce, so unbounded
// distinct valid headers at one height". The search starts at `start`, so
// callers that need distinct headers over otherwise identical fields pass
// disjoint windows and land on distinct valid nonces (hence distinct ids).
func solveMaxTarget(tb testing.TB, h types.Header, start uint64) types.Header {
	tb.Helper()
	p := spec.Devnet()
	for n := start; n < start+(1<<24); n++ {
		h.PoW.Nonce = n
		if pow.CheckWork(pow.Dev{}, h, p) == nil {
			return h
		}
	}
	tb.Fatal("no MaxTarget solution found")
	return h
}

// floodHeader builds a distinct valid announcement header for the seen-set flood: a
// header at the receiver's own working epoch (height tip+1, so the key-epoch
// budget exempts it), naming an *invented* parent so the tip-target rule does
// not apply and MaxTarget is accepted, dated at the tip's own time so it is
// never future-dated, and salted so every id differs.
func floodHeader(tb testing.TB, c interface {
	Tip() types.Header
}, salt uint64) types.Header {
	tb.Helper()
	p := spec.Devnet()
	tip := c.Tip()
	var parent types.Hash
	parent[0], parent[1] = 0xde, 0xad
	h := types.Header{
		Version:  types.HeaderVersion,
		Height:   tip.Height + 1,
		ParentID: parent,
		Time:     tip.Time,
		CertRoot: certRoot(nil, p),
		Target:   p.MaxTarget,
		PoW:      types.PoWSeal{SeedEpoch: pow.SeedEpochFor(tip.Height+1, p)},
	}
	// A disjoint nonce window per salt, so every solved header has a distinct
	// nonce and therefore a distinct id — the flood of "unbounded distinct valid
	// headers" the finding describes, not one header re-announced.
	return solveMaxTarget(tb, h, salt<<24)
}

// TestBlockSeenSetStaysBoundedUnderAFlood is the bound: the block-announce
// dedup set never grows past MaxSeenBlocks however many distinct valid headers
// a flood inserts.
//
// Before the fix seenBlocks was written once per accepted announcement and
// deleted nowhere — ReapUnservedBodies reaped pending and left it immortal — so
// this loop would have grown it to `flood` entries, an unbounded remote leak on
// a working-epoch ingress path the key-epoch budget does not charge. The
// assertion is a positive verifiable state (a floor rule, not silence): after
// inserting well past the cap the set is pinned *at* the cap, which is only true
// if eviction fired for every insert past it — a smaller number would mean
// announcements were refused rather than evicted (the flood must still be
// accepted, or the leak is not the thing being measured) and a larger one that
// the cap did not hold.
//
// **The flood is paced across periods, and the work-eval budgets make that
// necessary.** The work-evaluation budgets cap how many distinct announcements
// reach the work check — and therefore the seen-set insert — per refill period:
// a single connection at MaxWorkEvalsPerConn, and the node as a whole at the
// node-wide ceiling refilling NodeWorkEvalRefillPerPeriod per period. So a
// tight-loop flood can no longer reach the seen-set's cap at all — that is the
// whole of those budgets, and it is a stronger bound, not a regression. The
// seen-set cap is a separate, longer-lived defence: it bounds a flood that
// persists across MANY periods, accumulating one refill-batch at a time, which
// is exactly what a determined attacker does (identities and reconnects are
// free, per the seen-set's own reachability note). So the flood is dealt out
// one refill batch per period, each batch on a fresh connection so no
// per-connection budget binds and the node-wide bucket refills between them,
// every announcement reaching the insert — which keeps this measuring the
// seen-set cap rather than the work budgets in front of it.
func TestBlockSeenSetStaysBoundedUnderAFlood(t *testing.T) {
	c, e, _ := announceChain(t, 4)
	// A clock the test drives, so the node-wide work-eval ceiling refills between
	// batches. Anchored past the tip so headers dated at tip.Time are not future.
	clock := int64(c.Tip().Time) + 1
	e.Now = func() time.Time { return time.Unix(clock, 0) }
	period := int64(workEvalPeriod(c.Params()))

	// One batch of admittable announcements per refill period, on a fresh
	// connection each so the per-connection budget never binds. Sized at the
	// node-wide refill so every announcement in a batch is admitted.
	const batch = NodeWorkEvalRefillPerPeriod
	floodConn := func(i int) string {
		b := i / batch
		return fmt.Sprintf("10.66.%d.%d:5000", b/250, b%250+1)
	}
	// advance moves to the next batch's period before announcement i, so the
	// node-wide ceiling has refilled a batch's worth of credits for it.
	advance := func(i int) {
		if i > 0 && i%batch == 0 {
			clock += period
		}
	}

	// One accepted announcement proves the flood really reaches the insert, so a
	// pinned-at-cap count below cannot be an artefact of a path that refuses.
	first := floodHeader(t, c, 0)
	v := e.OnBlockAnnounce(floodConn(0), BlockAnnounce{Header: first}.MarshalAnnounce())
	if v.Reply == nil || v.Score != ScoreUsefulMessage {
		t.Fatalf("the first flood announcement was not accepted (score %d, reply %v); "+
			"nothing measured below reaches seenBlocks if the path refuses", v.Score, v.Reply)
	}

	const flood = MaxSeenBlocks + 200
	for i := 1; i < flood; i++ {
		advance(i)
		h := floodHeader(t, c, uint64(i))
		if v := e.OnBlockAnnounce(floodConn(i), BlockAnnounce{Header: h}.MarshalAnnounce()); v.Reply == nil {
			t.Fatalf("flood announcement %d was not admitted to the insert (%v); the pacing "+
				"no longer keeps every announcement inside the work budgets, so this measures "+
				"a refusal rather than the seen-set cap", i, v.Err)
		}
		e.mu.Lock()
		n := len(e.seenBlocks)
		e.mu.Unlock()
		if n > MaxSeenBlocks {
			t.Fatalf("seenBlocks holds %d after %d distinct announcements, past the cap "+
				"of %d: the block-announce set is not bounded", n, i+1, MaxSeenBlocks)
		}
	}

	e.mu.Lock()
	n := len(e.seenBlocks)
	e.mu.Unlock()
	if n != MaxSeenBlocks {
		t.Fatalf("seenBlocks holds %d after flooding %d distinct valid announcements, "+
			"want it pinned at the cap of %d: a smaller count means the flood was refused "+
			"rather than deduped-and-evicted, a larger one that the cap did not fire",
			n, flood, MaxSeenBlocks)
	}
}

// TestSeenBlocksReapForgetsAgedIdsButKeepsFreshOnes is the TTL half: the
// sweep that reaps unserved pending bodies also ages the dedup set, so an
// honest steady state does not drift up to the cap while an id whose block
// settled long ago is not remembered forever. It is verified positively on both
// sides — an aged id is gone, a fresh one is kept — so a reaper that cleared the
// whole set (which would defeat dedup) fails it just as one that cleared nothing.
func TestSeenBlocksReapForgetsAgedIdsButKeepsFreshOnes(t *testing.T) {
	c, e, _ := announceChain(t, 4)
	base := time.Unix(int64(c.Tip().Time)+1, 0)
	e.Now = func() time.Time { return base }
	const peer = "10.66.0.10:5000"

	old := floodHeader(t, c, 1)
	if v := e.OnBlockAnnounce(peer, BlockAnnounce{Header: old}.MarshalAnnounce()); v.Reply == nil {
		t.Fatalf("the aged announcement was not accepted: %v", v)
	}

	// The clock advances past the TTL, and a second announcement lands *now*, at
	// the far end of that window.
	base = base.Add(SeenBlockTTL + time.Minute)
	fresh := floodHeader(t, c, 2)
	if v := e.OnBlockAnnounce(peer, BlockAnnounce{Header: fresh}.MarshalAnnounce()); v.Reply == nil {
		t.Fatalf("the fresh announcement was not accepted: %v", v)
	}

	// One reap sweep at the current clock: the first id is older than the TTL,
	// the second is not.
	e.ReapUnservedBodies(base)

	e.mu.Lock()
	_, keptOld := e.seenBlocks[old.ID()]
	_, keptFresh := e.seenBlocks[fresh.ID()]
	e.mu.Unlock()
	if keptOld {
		t.Fatal("an id older than SeenBlockTTL survived the reap: the set is not aged")
	}
	if !keptFresh {
		t.Fatal("a fresh id was reaped: the TTL sweep cleared more than it should, " +
			"which would defeat the dedup the set exists for")
	}
}

// TestAnHonestReannouncementIsStillDeduped is the liveness direction (rule
// 22): bounding the set must not stop it doing its job. An honest peer that
// re-sends a block it already announced still finds it deduped, so a flood does
// not re-propagate — the property seenBlocks exists for, intact after the cap
// and TTL were added.
func TestAnHonestReannouncementIsStillDeduped(t *testing.T) {
	c, e, _ := announceChain(t, 4)
	const honest = "10.66.0.11:5000"

	// A real child on this node's own tip, declaring the difficulty rule's own
	// target — the honest announce path, not the invented-parent flood shape.
	h := tipHeaderAt(t, c, ruleTarget(c), 3)
	raw := BlockAnnounce{Header: h}.MarshalAnnounce()

	if v := e.OnBlockAnnounce(honest, raw); v.Reply == nil || v.Score != ScoreUsefulMessage {
		t.Fatalf("first honest announcement not accepted: score %d reply %v", v.Score, v.Reply)
	}
	v := e.OnBlockAnnounce(honest, raw)
	if v.Cost != CostDeduped {
		t.Fatalf("an honest re-announcement of a block already seen was not deduped "+
			"(cost %v): the dedup the seen-set exists for regressed", v.Cost)
	}
}

// futureLeakBlock mines a valid future-dated block for the dead-peer-tip tests:
// a header at height 1 (a working epoch, so the key-epoch budget exempts it)
// naming an invented parent, empty cites, declaring MaxTarget, dated far enough
// ahead to be withheld now and released once the clock reaches it. It reaches
// recordAnnounce on release — which is the mutation under test — regardless of
// what fork choice then makes of an orphan with an unknown parent.
func futureLeakBlock(tb testing.TB, e *Engine) (*types.Block, []byte) {
	tb.Helper()
	p := e.Chain.Params()
	var parent types.Hash
	parent[0], parent[1] = 0xbe, 0xef
	h := types.Header{
		Version:  types.HeaderVersion,
		Height:   1,
		ParentID: parent,
		Time:     e.now() + p.FutureTimeLimitSeconds + 30,
		CertRoot: certRoot(nil, p),
		Target:   p.MaxTarget,
		PoW:      types.PoWSeal{SeedEpoch: pow.SeedEpochFor(1, p)},
	}
	h = solveMaxTarget(tb, h, 0)
	blk := &types.Block{Header: h}
	return blk, blk.MarshalSSZ()
}

// TestReleaseWithheldDoesNotResurrectADeadPeersTip: a withheld block
// released after its deliverer has disconnected must not recreate that peer's
// tips entry.
//
// forgetPeer deletes tips[conn] at disconnect and never touches the withhold
// queue (keyed by block id), so before the fix ReleaseWithheld's
// e.OnBlock(w.peer, ...) ran recordAnnounce under the dead ephemeral address
// and minted a tips entry nothing reaps — breaking len(tips) <= len(conns) and,
// since undialable peers stay in candidacy, seeding a permanent undialable sync
// candidate for zero attacker cost. The block still has to reach fork choice;
// only the peer-attributed mutation is suppressed.
func TestReleaseWithheldDoesNotResurrectADeadPeersTip(t *testing.T) {
	e := testEngine(t)
	clk := time.Unix(1_700_000_000, 0)
	e.Now = func() time.Time { return clk }
	const dead = "10.66.0.2:41000"

	// A completed handshake makes the peer a live connection, exactly as one
	// would be when it delivered the future-dated body.
	e.recordTip(dead, Hello{Protocol: ProtocolVersion, NetworkID: e.Chain.NetworkID(), ListenAddr: dead})

	blk, raw := futureLeakBlock(t, e)
	if err := e.withhold(dead, blk, raw); err != nil {
		t.Fatalf("the future-dated block was not withheld: %v", err)
	}

	// The connection drops: forgetPeer removes the tips entry, the withheld
	// entry keyed by id survives.
	e.forgetPeer(dead)
	e.mu.Lock()
	if len(e.tips) != 0 {
		e.mu.Unlock()
		t.Fatal("forgetPeer left a tips entry behind; the premise of this test is gone")
	}
	e.mu.Unlock()

	// The clock reaches the block's release time and the queue fires.
	clk = time.Unix(int64(blk.Header.Time), 0)
	rel := e.ReleaseWithheld()

	// Liveness first: the block still reached the ingress path — the release is
	// the whole point, and suppressing the tip mutation must not suppress it.
	if len(rel) != 1 || rel[0].ID != blk.Header.ID() {
		t.Fatalf("the matured block was not released to fork choice: %d entries", len(rel))
	}

	// The bound: no tips entry was resurrected under the dead address.
	e.mu.Lock()
	_, revived := e.tips[dead]
	total := len(e.tips)
	e.mu.Unlock()
	if revived || total != 0 {
		t.Fatalf("ReleaseWithheld recreated a tips entry for a disconnected peer "+
			"(revived=%v, len(tips)=%d): the dead-address leak is open", revived, total)
	}
}

// TestReleaseWithheldStillRegistersALivePeersTip is the liveness direction
// (rule 22): the liveness gate must suppress the mutation only for a *dead*
// peer. A peer still connected when its withheld block matures must still have
// its tip recorded, or the fix would silence the candidacy signal a released
// block legitimately carries.
func TestReleaseWithheldStillRegistersALivePeersTip(t *testing.T) {
	e := testEngine(t)
	clk := time.Unix(1_700_000_000, 0)
	e.Now = func() time.Time { return clk }
	const live = "10.66.0.3:41000"

	e.recordTip(live, Hello{Protocol: ProtocolVersion, NetworkID: e.Chain.NetworkID(), ListenAddr: live})

	blk, raw := futureLeakBlock(t, e)
	if err := e.withhold(live, blk, raw); err != nil {
		t.Fatalf("the future-dated block was not withheld: %v", err)
	}

	// No disconnect: the peer is still live when the block matures.
	clk = time.Unix(int64(blk.Header.Time), 0)
	rel := e.ReleaseWithheld()
	if len(rel) != 1 || rel[0].ID != blk.Header.ID() {
		t.Fatalf("the matured block was not released: %d entries", len(rel))
	}

	// recordAnnounce ran on release: the block's height (1) is above this node's
	// own (genesis, 0) and it is not canonical, so OffersUnknown is set — the
	// peer-attributed side effect the dead-peer case suppresses, alive here.
	e.mu.Lock()
	tip, ok := e.tips[live]
	e.mu.Unlock()
	if !ok {
		t.Fatal("a live peer's tip entry was dropped on release: the liveness gate " +
			"suppressed the mutation for a connected peer: the gate over-corrected")
	}
	if tip.OffersUnknown.IsZero() {
		t.Fatal("a live peer that delivered a withheld block ahead of this node was " +
			"not recorded as a sync candidate on release: recordAnnounce did not run")
	}
}
