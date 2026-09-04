package p2p_test

import (
	"bytes"
	"errors"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/node/p2p"
)

// The two halves of the timestamp rules on the gossip path, and the
// median-ratchet freeze through the second of them.
//
// Half one is the lower time bound: it was enforced in node/sync and nowhere
// else, so the same block was valid or invalid depending on how it arrived.
// Half two is the future-time limit, which had a predicate
// (`pow.IsTooFarAhead`) and no mechanism at all — and which is the only defence
// against the median-time push that drives the LWMA to its floor.

// retime returns a copy of a block dated at t. Work is free in this harness, so
// changing the timestamp — which changes the id — leaves the block otherwise
// valid, and only the rule under test can refuse it.
//
// "Otherwise valid" now takes a re-seal. The time is part of PoWSeed and so of
// PoWInput, so a copy dated differently is a different blob, and the digest the
// original carried is no longer the digest of its own bytes — the work rule's
// identity half refuses it, ahead of every rule these tests are named for. So
// the copy is re-sealed the way a miner would seal a block it had just retimed.
// At this harness's u256.Max target every commitment passes, so it is one
// evaluation and work stays free.
func retime(b *types.Block, t uint64) *types.Block {
	cp := *b
	cp.Header.Time = t
	sealDevBlock(&cp.Header)
	return &cp
}

func TestGossipRefusesABlockAtOrBelowTheMedianTime(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	victim := newNode(t, "v", p, key(t, 2).Persistent())
	// Every sender below has to have handshaked: Handle refuses a non-hello
	// frame on a connection that never identified itself, and a test
	// that skipped this would pass on the refusal rather than on the rule it
	// is named for.
	handshake(t, victim, "a:1")
	handshake(t, victim, "attacker:1")
	handshake(t, victim, "honest:1")

	// A window long enough for the median to be a real median.
	blocks := a.mine(t, p.MedianTimeBlocks+2)
	for _, b := range blocks[:len(blocks)-1] {
		if v := victim.engine.Handle("a:1", p2p.KindBlock, deliver(b)); v.Err != nil {
			t.Fatalf("priming the victim: %v", v.Err)
		}
	}

	last := blocks[len(blocks)-1]
	median := pow.MedianTime(victim.chain.RecentHeaders(p.MedianTimeBlocks), p)

	// The attack block: correct work, correct declared target, dated *at* the
	// median of the last eleven. node/sync.ValidateHeaders refuses this; before
	// the fix the gossip path took it, and the two ingress paths then disagreed
	// about the canonical chain forever.
	backdated := retime(last, median)
	v := victim.engine.Handle("attacker:1", p2p.KindBlock, deliver(backdated))
	if !errors.Is(v.Err, pow.ErrTimeTooEarly) {
		t.Fatalf("a backdated block was accepted by gossip: %v", v.Err)
	}
	if victim.chain.Height() != last.Header.Height-1 {
		t.Fatalf("the backdated block was applied: height %d", victim.chain.Height())
	}

	// The negation, in this same scenario: the identical block dated one second
	// past the median is accepted. Without this the test would pass against a
	// node that refused every block, and would be measuring the harness.
	ontime := retime(last, median+1)
	if v := victim.engine.Handle("honest:1", p2p.KindBlock, deliver(ontime)); v.Err != nil {
		t.Fatalf("a block one second past the median was refused: %v", v.Err)
	}
	if victim.chain.Height() != last.Header.Height {
		t.Fatal("the on-time block did not extend the chain")
	}
}

// fixedClock returns a clock a test drives by assignment.
func fixedClock(at *uint64) func() time.Time {
	return func() time.Time { return time.Unix(int64(*at), 0) }
}

// liveClock is fixedClock for a test that starts a Node. `withholdLoop` reads
// the clock from its own goroutine, so a plain variable would be a data race
// and -race would be right about it.
type liveClock struct{ sec atomic.Uint64 }

func (c *liveClock) set(s uint64)   { c.sec.Store(s) }
func (c *liveClock) now() time.Time { return time.Unix(int64(c.sec.Load()), 0) }

func TestFutureBlockIsWithheldAndAppliedWhenTheClockCatchesUp(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	victim := newNode(t, "v", p, key(t, 2).Persistent())

	blocks := a.mine(t, 4)
	now := blocks[len(blocks)-1].Header.Time
	victim.engine.Now = fixedClock(&now)
	handshake(t, victim, "a:1")
	handshake(t, victim, "attacker:1")
	for _, b := range blocks[:len(blocks)-1] {
		if v := victim.engine.Handle("a:1", p2p.KindBlock, deliver(b)); v.Err != nil {
			t.Fatalf("priming the victim: %v", v.Err)
		}
	}

	last := blocks[len(blocks)-1]
	ahead := retime(last, now+p.FutureTimeLimitSeconds+60)
	before := victim.chain.Height()
	medianBefore := pow.MedianTime(victim.chain.RecentHeaders(p.MedianTimeBlocks), p)

	v := victim.engine.Handle("attacker:1", p2p.KindBlock, deliver(ahead))
	if !errors.Is(v.Err, p2p.ErrBlockWithheld) {
		t.Fatalf("a future-dated block was judged rather than withheld: %v", v.Err)
	}
	if v.Forward {
		t.Fatal("a withheld block was relayed; the timestamp would propagate unvalidated")
	}
	if v.Score != p2p.ScoreFutureBlock {
		t.Fatalf("a future-dated block scored %d; it is early, not an offence", v.Score)
	}
	if victim.engine.WithheldCount() != 1 {
		t.Fatalf("the block was dropped rather than queued: %d held",
			victim.engine.WithheldCount())
	}
	if victim.chain.Height() != before {
		t.Fatal("the future-dated block was applied")
	}
	// The freeze property, stated directly: while the block is withheld it moves
	// the median-time-past by nothing at all, so the solve times the LWMA reads
	// cannot be driven by a timestamp the network has not reached.
	if got := pow.MedianTime(victim.chain.RecentHeaders(p.MedianTimeBlocks), p); got != medianBefore {
		t.Fatalf("the median moved to %d while the block was withheld", got)
	}
	// Releasing before the time has come does nothing: the trigger is the
	// clock, not the call.
	if rel := victim.engine.ReleaseWithheld(); len(rel) != 0 {
		t.Fatal("a block was released before its time")
	}

	// The clock advances past Time - FTL and the block is judged normally.
	now = ahead.Header.Time - p.FutureTimeLimitSeconds
	rel := victim.engine.ReleaseWithheld()
	if len(rel) != 1 {
		t.Fatalf("the matured block was not released: %d", len(rel))
	}
	if rel[0].Verdict.Err != nil {
		t.Fatalf("the released block was refused: %v", rel[0].Verdict.Err)
	}
	if !rel[0].Verdict.Forward {
		t.Fatal("an accepted block was not relayed on release")
	}
	if victim.chain.Height() != before+1 {
		t.Fatal("the released block did not extend the chain")
	}
	if victim.engine.WithheldCount() != 0 {
		t.Fatal("the queue still holds a released block")
	}
}

func TestWithholdQueueIsBoundedAndKeepsTheSoonestBlocks(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	a.mine(t, 2)

	now := a.chain.Tip().Time
	a.engine.Now = fixedClock(&now)
	handshake(t, a, "flooder:1")
	limits := p2p.DefaultWithholdLimits()

	// Near-future blocks first, then a far-future flood four times the queue's
	// size. Eviction by distance-from-validity keeps the near ones; eviction by
	// arrival order — FIFO, LRU, or "drop when full and take the newest" —
	// would flush them. The order is the discriminator, so do not swap these
	// two calls.
	//
	// The assertion below is `== MaxBlocks`, not `!= 0`, and the difference is
	// the whole test. `!= 0` is satisfied by *any* policy that happens to leave
	// one near block behind, so a "drop a random entry" policy passed it about
	// seventeen runs in twenty — surviving one uniformly-random eviction out of
	// 256 from a 64-slot queue is not unlikely, it is the common case — and
	// removing the `worst.releaseAt <= incoming` guard, which costs exactly one
	// slot, passed it every time. Both mutants are alive under `!= 0` and dead
	// under `== MaxBlocks`. What the implementation actually guarantees is the
	// strong statement: **every** near-future block survives and **every**
	// far-future block is refused, so that is what is asserted.
	flood := func(offset uint64, n int) []types.Hash {
		ids := make([]types.Hash, 0, n)
		for i := 0; i < n; i++ {
			blk := fakeOrphan(t, p, a.chain.Height()+1, a.chain.Tip().Target, uint64(i))
			blk.Header.Time = now + offset + uint64(i)
			// Re-sealed: the fields above feed PoWSeed, so the seal fakeOrphan
			// (or the miner) left is the digest of a different blob now.
			sealDevBlock(&blk.Header)
			ids = append(ids, blk.Header.ID())
			a.engine.Handle("flooder:1", p2p.KindBlock, deliver(blk))
		}
		return ids
	}

	nearIDs := flood(p.FutureTimeLimitSeconds+1, limits.MaxBlocks)
	if got := a.engine.WithheldCount(); got != limits.MaxBlocks {
		t.Fatalf("the queue holds %d of %d near-future blocks before the flood; "+
			"the test is not exercising a full queue and the eviction policy is "+
			"therefore never consulted", got, limits.MaxBlocks)
	}

	flood(limits.HorizonSeconds/2, limits.MaxBlocks*4)
	if got := a.engine.WithheldCount(); got != limits.MaxBlocks {
		t.Fatalf("after the flood the queue holds %d blocks against a limit of "+
			"%d; the sender prices the memory", got, limits.MaxBlocks)
	}

	// Every near-future block matures within a minute; every far-future one is
	// half the horizon away and matures much later. So a correct queue releases
	// exactly the near set and nothing else.
	now += p.FutureTimeLimitSeconds + 60
	released := a.engine.ReleaseWithheld()
	if len(released) != limits.MaxBlocks {
		t.Fatalf("%d of %d near-future blocks survived the flood: eviction is "+
			"not by distance from validity. A policy that drops an arbitrary "+
			"entry, or one that admits a further-future block over a nearer one, "+
			"lands here", len(released), limits.MaxBlocks)
	}

	// And they are the *same* blocks, not merely the same number of them. Count
	// alone would pass a queue that had swapped the near set for a far one of
	// equal size, which is exactly the exchange the policy exists to refuse.
	want := make(map[types.Hash]bool, len(nearIDs))
	for _, id := range nearIDs {
		want[id] = true
	}
	for _, rel := range released {
		id := rel.ID
		if !want[id] {
			t.Fatalf("a block that was not in the near-future set was released; " +
				"the queue kept a far-future block over a near one")
		}
		delete(want, id)
	}
	if len(want) != 0 {
		t.Fatalf("%d near-future blocks were evicted and never came back", len(want))
	}
	if a.engine.WithheldCount() != 0 {
		t.Fatalf("the queue still holds %d blocks after every near one matured: "+
			"a far-future block was admitted", a.engine.WithheldCount())
	}
}

func TestBlocksBeyondTheHorizonAreNotHeld(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	a.mine(t, 2)

	now := a.chain.Tip().Time
	a.engine.Now = fixedClock(&now)
	handshake(t, a, "attacker:1")
	handshake(t, a, "peer:1")

	// The attack's own timestamp: now + 10^9, thirty-one years. Holding it is storage
	// whose retention the attacker chose.
	blk := fakeOrphan(t, p, a.chain.Height()+1, a.chain.Tip().Target, 7)
	blk.Header.Time = now + 1_000_000_000
	// Re-sealed: the fields above feed PoWSeed, so the seal fakeOrphan
	// (or the miner) left is the digest of a different blob now.
	sealDevBlock(&blk.Header)
	v := a.engine.Handle("attacker:1", p2p.KindBlock, deliver(blk))
	if !errors.Is(v.Err, p2p.ErrBlockBeyondHorizon) {
		t.Fatalf("got %v, want a beyond-horizon drop", v.Err)
	}
	if a.engine.WithheldCount() != 0 {
		t.Fatal("a block dated thirty-one years ahead was queued")
	}
	if v.Score != p2p.ScoreFutureBlock {
		t.Fatalf("dropping past the horizon scored %d; it is still not a "+
			"validity judgement", v.Score)
	}

	// Inside the horizon the same block is held: the drop is a bound, not a
	// refusal of everything future-dated.
	near := fakeOrphan(t, p, a.chain.Height()+1, a.chain.Tip().Target, 8)
	near.Header.Time = now + p.FutureTimeLimitSeconds + 5
	// Re-sealed: the fields above feed PoWSeed, so the seal fakeOrphan
	// (or the miner) left is the digest of a different blob now.
	sealDevBlock(&near.Header)
	a.engine.Handle("peer:1", p2p.KindBlock, deliver(near))
	if a.engine.WithheldCount() != 1 {
		t.Fatal("a block just past the limit was not held")
	}
}

func TestFutureAnnouncementIsNeitherForwardedNorRememberedAsSeen(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	victim := newNode(t, "v", p, key(t, 2).Persistent())

	blocks := a.mine(t, 3)
	now := blocks[len(blocks)-1].Header.Time
	victim.engine.Now = fixedClock(&now)
	handshake(t, victim, "a:1")
	handshake(t, victim, "attacker:1")
	handshake(t, victim, "honest:1")
	for _, b := range blocks[:len(blocks)-1] {
		victim.engine.Handle("a:1", p2p.KindBlock, deliver(b))
	}

	ahead := retime(blocks[len(blocks)-1], now+p.FutureTimeLimitSeconds+30)
	ann := p2p.BlockAnnounce{Header: ahead.Header, CertExemplars: ahead.CertExemplars()}
	payload := ann.MarshalAnnounce()

	v := victim.engine.Handle("attacker:1", p2p.KindBlockAnnounce, payload)
	if v.Forward {
		t.Fatal("a future-dated announcement was relayed")
	}
	if v.Reply != nil {
		t.Fatal("the body of a future-dated block was requested")
	}
	if !errors.Is(v.Err, p2p.ErrBlockWithheld) {
		t.Fatalf("got %v, want a withhold", v.Err)
	}

	// The same announcement, once the clock has caught up, must still be
	// useful. A seen-cache entry here would be a permanent rejection wearing a
	// cache's clothes: the block would never be requested by this node again.
	//
	// "Still useful" is read off the body request and the score, not off
	// `Forward`: under Option A no accepted announcement is relayed, so
	// `Forward` is false here and for a deduped one alike, and a probe reading
	// it would agree with the wrong answer (`PROTOCOL.md` rule 24).
	now = ahead.Header.Time
	v = victim.engine.Handle("honest:1", p2p.KindBlockAnnounce, payload)
	if v.Err != nil || v.Reply == nil || v.Score != p2p.ScoreUsefulMessage {
		t.Fatalf("the re-announcement after maturity was deduped away "+
			"(cost=%v score=%d): %v", v.Cost, v.Score, v.Err)
	}
}

// medianPushIsBoundedByFTL is the acceptance criterion for the freeze, stated as
// arithmetic rather than as a simulation: whatever a miner does with
// timestamps, no block this node applies can date further ahead than FTL, so
// the median-time-past it derives its solve times from cannot be pushed to a
// point where every honest block after it reports a one-second solve.
func TestMedianTimePastCannotBePushedBeyondTheFutureTimeLimit(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	victim := newNode(t, "v", p, key(t, 2).Persistent())

	blocks := a.mine(t, p.MedianTimeBlocks+2)
	now := blocks[len(blocks)-1].Header.Time
	victim.engine.Now = fixedClock(&now)
	handshake(t, victim, "a:1")
	handshake(t, victim, "attacker:1")
	for _, b := range blocks[:len(blocks)-1] {
		victim.engine.Handle("a:1", p2p.KindBlock, deliver(b))
	}

	// Six of eleven at now + 10^9 is the whole attack. Every one of them is
	// refused a place in the chain.
	for i := 0; i < p.MedianTimeBlocks/2+1; i++ {
		poison := retime(blocks[len(blocks)-1], now+1_000_000_000+uint64(i))
		victim.engine.Handle("attacker:1", p2p.KindBlock, deliver(poison))
	}
	median := pow.MedianTime(victim.chain.RecentHeaders(p.MedianTimeBlocks), p)
	if median > now+p.FutureTimeLimitSeconds {
		t.Fatalf("the median-time-past is %d against a clock of %d: the LWMA "+
			"reads solve times an attacker set", median, now)
	}
	assertNoFutureHeader(t, victim, now, p)
}

func assertNoFutureHeader(t *testing.T, n *testNode, now uint64, p *params.Params) {
	t.Helper()
	for _, h := range n.chain.RecentHeaders(int(p.DifficultyWindow) + 1) {
		if h.Time > now+p.FutureTimeLimitSeconds {
			t.Fatalf("header %d is dated %d against a clock of %d", h.Height, h.Time, now)
		}
	}
}

// TestAReleasedBlockIsUsableByAPeerInEitherRelayShape pins what a peer does
// with a released block, which is the half of the question this file can answer
// without a socket: `Released` carries the decoded block rather than bytes,
// precisely so that the caller cannot push the frame it reassembled back out,
// and both shapes a caller may legitimately build from that block are accepted
// here — an announcement, and a single-chunk `KindBlock`.
//
// **This test does not decide which shape the node sends, and its name and doc
// used to claim it did.** They said the relay was an announcement and that
// `withholdLoop` called `AnnounceBlock`; `relayReleased` sends the body in a
// single-chunk `KindBlock` envelope, for the reason set out at its own
// definition — a peer whose clock is behind refuses an announcement and keeps
// nothing, while it queues a body. The payload here is hand-built, so any
// rewrite of the relay left this test green: what actually pins the sent shape
// is `TestWithholdLoopRelaysABodyAPeerBehindThisClockCanStillHold`, over a real
// socket, and this one is now what it always in fact was — a receiver-side
// acceptance test.
//
// The negation is the last case: the pre-chunking shape, a bare body sent as
// `KindBlock` with no chunk envelope, is refused by a peer as malformed.
// Without it this test would pass against any relay at all.
func TestAReleasedBlockIsUsableByAPeerInEitherRelayShape(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	victim := newNode(t, "v", p, key(t, 2).Persistent())
	peer := newNode(t, "w", p, key(t, 3).Persistent())

	blocks := a.mine(t, 4)
	now := blocks[len(blocks)-1].Header.Time
	victim.engine.Now = fixedClock(&now)
	peer.engine.Now = fixedClock(&now)
	handshake(t, victim, "a:1")
	handshake(t, victim, "attacker:1")
	handshake(t, peer, "a:1")
	handshake(t, peer, "v:1")
	for _, b := range blocks[:len(blocks)-1] {
		for _, n := range []*testNode{victim, peer} {
			if v := n.engine.Handle("a:1", p2p.KindBlock, deliver(b)); v.Err != nil {
				t.Fatalf("priming %s: %v", n.name, v.Err)
			}
		}
	}

	ahead := retime(blocks[len(blocks)-1], now+p.FutureTimeLimitSeconds+30)
	if v := victim.engine.Handle("attacker:1", p2p.KindBlock, deliver(ahead)); !errors.Is(v.Err, p2p.ErrBlockWithheld) {
		t.Fatalf("the block was not withheld: %v", v.Err)
	}

	now = ahead.Header.Time
	rel := victim.engine.ReleaseWithheld()
	if len(rel) != 1 || !rel[0].Verdict.Forward {
		t.Fatalf("the matured block was not released for relay: %d entries", len(rel))
	}
	if rel[0].ID != ahead.Header.ID() {
		t.Fatal("the release did not carry the block it judged")
	}
	// And it carries the bytes that were delivered, not a re-encoding: the
	// relay frames these directly, so if they ever stopped being the
	// delivered body the relay would send something nobody sent.
	if !bytes.Equal(rel[0].Raw, ahead.MarshalSSZ()) {
		t.Fatal("the release did not carry the bytes it was delivered")
	}
	relBlk, err := rel[0].Decode(p)
	if err != nil {
		t.Fatalf("the released bytes do not decode: %v", err)
	}

	// The announcement shape: what `releaseRelay` falls back to for a body too
	// large to travel in one chunk.
	ann := p2p.BlockAnnounce{Header: relBlk.Header, CertExemplars: relBlk.CertExemplars()}
	v := peer.engine.Handle("v:1", p2p.KindBlockAnnounce, ann.MarshalAnnounce())
	if v.Err != nil {
		t.Fatalf("a peer refused the announcement a released block is relayed as: %v", v.Err)
	}
	// What this shape has to buy is the fetch. It is not itself re-relayed —
	// under Option A no accepted announcement is — and the second hop is
	// carried by the body broadcast the fetch leads to.
	if v.Reply == nil || v.Reply.Kind != p2p.KindGetBlock {
		t.Fatal("the relayed announcement did not make a peer fetch the body")
	}

	// The body shape, which is what `releaseRelay` actually sends at every
	// committed parameter set: the block inside the single-chunk envelope
	// `KindBlock` carries. This peer's clock has reached the release point too,
	// so it applies rather than queues — the behind-the-clock case, which is
	// the one that decides *why* the body is the right shape, needs two real
	// clocks and lives in
	// TestWithholdLoopRelaysABodyAPeerBehindThisClockCanStillHold.
	chunk := p2p.BlockChunk{ID: rel[0].ID, Chunk: 0, Total: 1, Data: rel[0].Raw}
	if v := peer.engine.Handle("v:1", p2p.KindBlock, chunk.MarshalBlockChunk()); v.Err != nil {
		t.Fatalf("a peer refused the body shape a released block is relayed as: %v", v.Err)
	}
	if peer.chain.Tip().ID() != rel[0].ID {
		t.Fatal("the relayed body was accepted but not applied")
	}

	// And the shape neither relay may revert to. A bare body pushed as
	// KindBlock is a chunk header as far as the receiver is concerned, so it
	// decodes to garbage or to nothing — silently, since the sender never
	// learns.
	if v := peer.engine.Handle("v:1", p2p.KindBlock, rel[0].Raw); v.Err == nil {
		t.Fatal("a bare block body was accepted as a KindBlock frame; the relay " +
			"could push bodies again and nothing here would notice")
	}
}

// TestAnInvalidBlockCannotDodgeScoringByDatingItselfAhead closes the queue's
// one accountability hole: the release judges the block through OnBlock, which
// is not Handle, so the score the verdict carries has to be applied here or it
// is applied nowhere.
//
// Left unapplied, the queue is an opt-out from peer scoring — date any invalid
// block up to FTL ahead and the penalty for it lands on nobody, at a cost of at
// most one future-time limit of delay. The block is refused either way; what
// the score buys is the price of *repeating* it.
func TestAnInvalidBlockCannotDodgeScoringByDatingItselfAhead(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())

	// The reference: the same corruption delivered on time, so the test knows
	// what the offence is worth before asking what the queue does with it.
	onTime := newNode(t, "n", p, key(t, 2).Persistent())
	future := newNode(t, "f", p, key(t, 3).Persistent())

	blocks := a.mine(t, 4)
	now := blocks[len(blocks)-1].Header.Time
	onTime.engine.Now = fixedClock(&now)
	future.engine.Now = fixedClock(&now)
	handshake(t, onTime, "a:1")
	handshake(t, onTime, "attacker:1")
	handshake(t, future, "a:1")
	handshake(t, future, "attacker:1")
	// The handshake itself is worth a point (OnHello returns
	// ScoreUsefulMessage), so this test's exact-equality assertions are stated
	// against the score the sender holds *after* identifying itself. Baselining
	// rather than hard-coding +1 keeps the comparison about the withhold queue.
	baseOnTime, _ := onTime.peers.Get("attacker:1")
	baseFuture, _ := future.peers.Get("attacker:1")
	for _, b := range blocks[:len(blocks)-1] {
		for _, n := range []*testNode{onTime, future} {
			if v := n.engine.Handle("a:1", p2p.KindBlock, deliver(b)); v.Err != nil {
				t.Fatalf("priming %s: %v", n.name, v.Err)
			}
		}
	}

	// A tip extension whose work, declared target and median are all correct,
	// and whose body does not match the root its header commits to. It is
	// refused by the fold, which is a statement about the block rather than
	// about this node or its clock, so it is scoreable on any path.
	corrupt := func(t uint64) *types.Block {
		cp := *blocks[len(blocks)-1]
		cp.Header.Time = t
		cp.Header.StateRoot = types.Hash{0xff}
		// Re-sealed: the fields above feed PoWSeed, so the seal fakeOrphan
		// (or the miner) left is the digest of a different blob now.
		sealDevBlock(&cp.Header)
		return &cp
	}

	v := onTime.engine.Handle("attacker:1", p2p.KindBlock, deliver(corrupt(now+1)))
	if v.Err == nil || v.Score >= 0 {
		t.Fatalf("the reference corruption was accepted or scored %d on the "+
			"ordinary path; the test has nothing to compare against: %v", v.Score, v.Err)
	}
	want := v.Score
	if got, _ := onTime.peers.Get("attacker:1"); got.Score != baseOnTime.Score+want {
		t.Fatalf("the ordinary path scored %d, not %d", got.Score-baseOnTime.Score, want)
	}

	// The same block, dated past the limit. It is queued and costs nothing yet.
	ahead := corrupt(now + p.FutureTimeLimitSeconds + 30)
	if v := future.engine.Handle("attacker:1", p2p.KindBlock, deliver(ahead)); !errors.Is(v.Err, p2p.ErrBlockWithheld) {
		t.Fatalf("the block was not withheld: %v", v.Err)
	}
	if got, _ := future.peers.Get("attacker:1"); got.Score != baseFuture.Score {
		t.Fatalf("a withheld block scored its sender %d before it was judged",
			got.Score-baseFuture.Score)
	}

	now = ahead.Header.Time
	rel := future.engine.ReleaseWithheld()
	if len(rel) != 1 || rel[0].Verdict.Err == nil {
		t.Fatalf("the corrupt block was not refused on release: %+v", rel)
	}
	if got, _ := future.peers.Get("attacker:1"); got.Score != baseFuture.Score+want {
		t.Fatalf("the sender scored %d for a block that scores %d on the ordinary "+
			"path: dating a block ahead of the future-time limit buys immunity "+
			"from peer scoring", got.Score-baseFuture.Score, want)
	}
}

// TestWithholdLoopRelaysABodyAPeerBehindThisClockCanStillHold is the only test
// in this file that runs `Node.withholdLoop` — over a real socket, between two
// real nodes — and it exists because nothing did.
//
// `TestAReleasedBlockIsRelayedHashFirstAndNotAsABody` below pins the *shape* a
// peer accepts, which is not the same question as what this node sends: it
// hand-builds the payload, so rewriting the relay to any other wrong shape left
// it green. The bug that made this merge necessary — a bare body pushed as
// `KindBlock`, which now carries a `BlockChunk` — could return without a single
// test noticing.
//
// The scenario is also the one that decides *which* relay is correct, so it is
// worth stating rather than tuning: **the receiving node's clock is behind the
// releasing node's.** That is the ordinary case, not a contrived one — a block
// is released the first tick after `Time - FTL`, and any peer even a second
// behind has not reached that point yet. It is where the two candidate relays
// stop agreeing:
//
//   - a **body** meets `OnBlock`, which withholds it: the peer queues it and
//     releases it on its own clock a moment later;
//   - an **announcement** meets `OnBlockAnnounce`, which refuses it and keeps
//     nothing, because a future-dated id is deliberately not marked seen;
//   - a bare body sent as `KindBlock` fails `UnmarshalBlockChunk` outright.
//
// Only the first leaves the peer holding anything, so `WithheldCount() == 1` on
// the receiver kills all three of the others.
func TestWithholdLoopRelaysABodyAPeerBehindThisClockCanStillHold(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, "s", p, key(t, 1).Persistent())
	a := newNode(t, "a", p, key(t, 2).Persistent())
	b := newNode(t, "b", p, key(t, 3).Persistent())

	blocks := source.mine(t, 4)
	now := blocks[len(blocks)-1].Header.Time
	var aClock, bClock liveClock
	aClock.set(now)
	bClock.set(now)
	a.engine.Now = aClock.now
	b.engine.Now = bClock.now
	handshake(t, a, "s:1")
	handshake(t, a, "attacker:1")
	handshake(t, b, "s:1")
	for _, blk := range blocks[:len(blocks)-1] {
		for _, n := range []*testNode{a, b} {
			if v := n.engine.Handle("s:1", p2p.KindBlock, deliver(blk)); v.Err != nil {
				t.Fatalf("priming %s: %v", n.name, v.Err)
			}
		}
	}

	// A holds a block dated past its own limit.
	ahead := retime(blocks[len(blocks)-1], now+p.FutureTimeLimitSeconds+30)
	if v := a.engine.Handle("attacker:1", p2p.KindBlock, deliver(ahead)); !errors.Is(v.Err, p2p.ErrBlockWithheld) {
		t.Fatalf("setup: the block was not withheld by a: %v", v.Err)
	}

	if err := b.node.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("b listening: %v", err)
	}
	t.Cleanup(b.node.Stop)
	a.peers.Add(b.node.ListenAddr())
	a.node.DialInterval = 20 * time.Millisecond
	a.node.WithholdInterval = 20 * time.Millisecond
	// Long enough that no sync pass runs: this measures the relay, and a sync
	// would carry the block by a route the test is not about.
	a.node.SyncInterval = time.Hour
	a.node.Start()
	t.Cleanup(a.node.Stop)

	waitFor(t, "a to connect to b", func() bool { return a.node.PeerCount() > 0 })

	// A's clock reaches the release point. B's does not move, so B is behind by
	// exactly the margin that decides the question.
	aClock.set(ahead.Header.Time - p.FutureTimeLimitSeconds)
	waitFor(t, "b to hold the relayed block", func() bool { return b.engine.WithheldCount() == 1 })

	if a.chain.Height() != ahead.Header.Height {
		t.Fatalf("a released the block but did not apply it: height %d", a.chain.Height())
	}
	if a.engine.WithheldCount() != 0 {
		t.Fatal("a still holds the block it released")
	}

	// And it is the right block, not merely one block: b releases it once its
	// own clock reaches the same point, and the chains agree.
	bClock.set(ahead.Header.Time)
	rel := b.engine.ReleaseWithheld()
	if len(rel) != 1 || rel[0].Verdict.Err != nil {
		t.Fatalf("b could not release what it was relayed: %+v", rel)
	}
	if b.chain.Tip().ID() != a.chain.Tip().ID() {
		t.Fatal("b applied a different block than the one a relayed")
	}
}

// waitFor polls a condition rather than sleeping through it, so the test costs
// what the network costs rather than a fixed guess.
func waitFor(t *testing.T, what string, ok func() bool) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if ok() {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("timed out waiting for %s", what)
}

// TestBeyondHorizonDropsAreObservable: a node whose clock is far enough behind
// that gossip lands past the withhold horizon must be able to say so. Before
// this the condition was completely silent — the drop is not a validity
// judgement and scores nobody, so nothing counted and nothing logged.
//
// Delivered as KindBlock bodies rather than announcements, because that is the
// frame a node in this condition actually receives. Its own announcement
// handler drops a future-dated header before it reaches seenBlocks, so it never
// asks for a body; what reaches it is the flood — node.go's serve loop
// re-broadcasts an accepted body to every peer but the sender.
func TestBeyondHorizonDropsAreObservable(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	a.mine(t, 2)

	now := a.chain.Tip().Time
	a.engine.Now = fixedClock(&now)
	senders := []string{"198.51.100.7:5000", "203.0.113.9:5000"}
	for _, s := range senders {
		handshake(t, a, s)
	}

	if r := a.engine.BeyondHorizon(); r.Count != 0 || r.MaxSkewSeconds != 0 || r.Groups != 0 {
		t.Fatalf("a fresh engine reports %+v, want a zero report", r)
	}

	horizon := a.engine.WithholdHorizonSeconds()

	// Two blocks past the horizon, the second further than the first, and from
	// two different senders. This is the shape a slow clock produces: honest
	// blocks, from everybody, all of them ahead.
	for i, ahead := range []uint64{horizon + 60, horizon + 600} {
		blk := fakeOrphan(t, p, a.chain.Height()+1, a.chain.Tip().Target, uint64(20+i))
		blk.Header.Time = now + ahead
		// Re-sealed: the fields above feed PoWSeed, so the seal fakeOrphan
		// (or the miner) left is the digest of a different blob now.
		sealDevBlock(&blk.Header)
		if v := a.engine.Handle(senders[i], p2p.KindBlock, deliver(blk)); !errors.Is(v.Err, p2p.ErrBlockBeyondHorizon) {
			t.Fatalf("block %d: got %v, want a beyond-horizon drop", i, v.Err)
		}
	}

	r := a.engine.BeyondHorizon()
	if r.Count != 2 || r.BeyondHorizon != 2 {
		t.Fatalf("reported %+v, want 2 blocks, both charged to the horizon", r)
	}
	// The worst skew is the second block's, and it is the raw gap against this
	// node's clock rather than the amount by which it passed the horizon.
	if want := horizon + 600; r.MaxSkewSeconds != want {
		t.Fatalf("worst skew reported as %ds, want %ds (the gap to this node's clock, not the excess over the horizon)",
			r.MaxSkewSeconds, want)
	}
	// And the senders are recorded, grouped by /16, which is the only part of
	// the report that bears on whose clock is the outlier.
	if r.Groups != 2 {
		t.Fatalf("blocks from two /16 groups reported as %d group(s)", r.Groups)
	}

	// A block inside the horizon is held rather than dropped, and the report
	// has to say which: the three bounds cost the node different things.
	inside := fakeOrphan(t, p, a.chain.Height()+1, a.chain.Tip().Target, 99)
	inside.Header.Time = now + horizon/2
	// Re-sealed: the fields above feed PoWSeed, so the seal fakeOrphan
	// (or the miner) left is the digest of a different blob now.
	sealDevBlock(&inside.Header)
	if v := a.engine.Handle(senders[0], p2p.KindBlock, deliver(inside)); !errors.Is(v.Err, p2p.ErrBlockWithheld) {
		t.Fatalf("a block inside the horizon: got %v, want it withheld", v.Err)
	}
	held := a.engine.BeyondHorizon()
	if held.Withheld != 1 || held.BeyondHorizon != 2 || held.Count != 3 {
		t.Fatalf("after one held block the report is %+v, want 1 withheld and the "+
			"2 horizon drops unchanged", held)
	}
	if held.QueueDepth != 1 {
		t.Fatalf("queue depth reported as %d, want 1: the depth is the lag and the "+
			"evidence the condition is still going", held.QueueDepth)
	}
}

// TestQueueSaturationIsCountedAndKeptApart covers the middle of the three
// bounds.
//
// withhold refuses a future-dated block three ways: it queues it, it drops it
// because the queue holds only blocks that mature sooner, or it drops it past
// the horizon. All three are counted, and counted apart, because they cost the
// node different things — the first loses nothing and only delays, the other
// two lose the block — and a report that blurred them would name the wrong
// bound to whoever went looking.
func TestQueueSaturationIsCountedAndKeptApart(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	a.mine(t, 2)

	now := a.chain.Tip().Time
	a.engine.Now = fixedClock(&now)
	handshake(t, a, "198.51.100.7:5000")
	handshake(t, a, "203.0.113.9:5000")

	limits := p2p.DefaultWithholdLimits()
	horizon := a.engine.WithholdHorizonSeconds()

	// Fill the queue with blocks maturing as late as the horizon allows.
	for i := 0; i < limits.MaxBlocks; i++ {
		blk := fakeOrphan(t, p, a.chain.Height()+1, a.chain.Tip().Target, uint64(1000+i))
		blk.Header.Time = now + horizon - uint64(i)
		// Re-sealed: the fields above feed PoWSeed, so the seal fakeOrphan
		// (or the miner) left is the digest of a different blob now.
		sealDevBlock(&blk.Header)
		if v := a.engine.Handle("198.51.100.7:5000", p2p.KindBlock, deliver(blk)); !errors.Is(v.Err, p2p.ErrBlockWithheld) {
			t.Fatalf("filling the queue at %d: %v", i, v.Err)
		}
	}
	if got := a.engine.WithheldCount(); got != limits.MaxBlocks {
		t.Fatalf("the queue holds %d blocks, want it full at %d", got, limits.MaxBlocks)
	}
	full := a.engine.BeyondHorizon()
	if full.Withheld != uint64(limits.MaxBlocks) || full.QueueFull != 0 || full.BeyondHorizon != 0 {
		t.Fatalf("filling the queue reported %+v, want every block charged to "+
			"Withheld and nothing to either drop bound", full)
	}

	// One more, inside the horizon but maturing later than everything queued,
	// from a second group. Eviction refuses and the block is dropped.
	late := fakeOrphan(t, p, a.chain.Height()+1, a.chain.Tip().Target, 2000)
	late.Header.Time = now + horizon
	// Re-sealed: the fields above feed PoWSeed, so the seal fakeOrphan
	// (or the miner) left is the digest of a different blob now.
	sealDevBlock(&late.Header)
	if v := a.engine.Handle("203.0.113.9:5000", p2p.KindBlock, deliver(late)); !errors.Is(v.Err, p2p.ErrBlockBeyondHorizon) {
		t.Fatalf("a block the full queue cannot admit: got %v, want it dropped", v.Err)
	}

	r := a.engine.BeyondHorizon()
	if r.QueueFull != 1 {
		t.Fatalf("a queue-saturation drop reported as %+v, want 1 under QueueFull "+
			"— this used to be the silent case", r)
	}
	if r.BeyondHorizon != 0 {
		t.Fatalf("a block inside the horizon was counted against the horizon (%+v); "+
			"the bounds refuse for different reasons and naming the wrong one "+
			"sends the reader after the wrong number", r)
	}
	if r.MaxSkewSeconds != horizon {
		t.Fatalf("worst skew %ds, want %ds: the gap is recorded on this path too, "+
			"or the report carries a count with no magnitude", r.MaxSkewSeconds, horizon)
	}
	if r.Groups != 2 || r.FirstGroup != "198.51.0.0/16" {
		t.Fatalf("recorded %d group(s) / first %q, want 2 and the first sender's group",
			r.Groups, r.FirstGroup)
	}
}

// TestASlowClockIsVisibleBelowTheHorizon drives the slow-clock stall the way it
// actually happens, rather than by handing the counter two blocks.
//
// A node slow by 300 s on devnet is nowhere near the 3600 s horizon and never
// loses a block: every one is queued and released late, so the node runs
// permanently behind while refusing nobody. That is the stall exactly, at a
// tenth of the skew the finding names, and a counter watching only what is
// *dropped* reads zero across the whole of it. Measured:
//
//	skew        100   200   300   400   500
//	withheld      0   300   300   300   300
//	dropped       0     0     0     0     0
//	queue depth   0     3    23    43    63
func TestASlowClockIsVisibleBelowTheHorizon(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	a.mine(t, 2)

	now := a.chain.Tip().Time
	a.engine.Now = fixedClock(&now)

	const skew = 300 // seconds slow: far inside the horizon, nothing dropped
	const blocks = 300
	senders := []string{"198.51.100.7:5000", "203.0.113.9:5000", "192.0.2.5:5000"}
	for _, s := range senders {
		handshake(t, a, s)
	}

	withheld := 0
	for i := 0; i < blocks; i++ {
		blk := fakeOrphan(t, p, a.chain.Height()+1, a.chain.Tip().Target, uint64(i))
		// An honest block, dated at the network's time, which this node's clock
		// reads as skew seconds in the future.
		blk.Header.Time = now + skew
		// Re-sealed: the fields above feed PoWSeed, so the seal fakeOrphan
		// (or the miner) left is the digest of a different blob now.
		sealDevBlock(&blk.Header)
		if v := a.engine.Handle(senders[i%len(senders)], p2p.KindBlock, deliver(blk)); errors.Is(v.Err, p2p.ErrBlockWithheld) {
			withheld++
		}
		// withholdLoop drains once a second; the clock advances one block
		// interval between arrivals.
		for k := uint64(0); k < p.TargetBlockSeconds; k++ {
			now++
			a.engine.ReleaseWithheld()
		}
	}

	if withheld == 0 {
		t.Fatalf("a node %ds slow held no block at all across %d of them; the "+
			"scenario this test is about did not happen", skew, blocks)
	}
	r := a.engine.BeyondHorizon()
	if r.BeyondHorizon != 0 || r.QueueFull != 0 {
		t.Fatalf("%+v: nothing should be dropped %ds inside a %ds horizon, so a "+
			"counter watching only drops is the one that reads zero here",
			r, a.engine.WithholdHorizonSeconds()-skew, a.engine.WithholdHorizonSeconds())
	}
	if r.Withheld != uint64(withheld) {
		t.Fatalf("%d blocks were held and %d were counted (%+v) — the uncounted "+
			"ones are the silence itself", withheld, r.Withheld, r)
	}
	if r.MaxSkewSeconds != skew {
		t.Fatalf("worst skew reported as %ds, want %ds — the number an operator "+
			"has to set their clock by", r.MaxSkewSeconds, skew)
	}
	// The standing backlog is the lag, and it is what says the condition is
	// still going rather than over.
	if r.QueueDepth == 0 {
		t.Fatalf("a node %ds slow reports an empty withhold queue; the backlog is "+
			"the lag and there has to be one", skew)
	}
	// Every sender looks ahead, because the node is slow. That is the reading,
	// and it is the one thing that separates this from a peer misbehaving.
	if r.Groups != len(senders) {
		t.Fatalf("blocks from %d groups reported as %d; a slow clock makes every "+
			"peer look ahead at once and that is the diagnosis",
			len(senders), r.Groups)
	}
}

// TestEveryDelivererOfTheSameBlockIsEvidence is the defect that inverted the
// diagnosis in exactly the band the withheld counter was added for.
//
// A block gossiped by eight peers reaches withhold eight times: node.go's serve
// loop re-broadcasts an accepted body to every peer but the sender, and a
// future-dated announcement never reaches seenBlocks, so OnBlock's dedupe never
// fires. Seven of those eight matched withhold's "already queued" early return,
// which recorded nothing — so the breadth set held one group where eight had
// sent it, and the report named a single peer as the suspect on a node whose
// own clock was the outlier.
func TestEveryDelivererOfTheSameBlockIsEvidence(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	a.mine(t, 2)

	now := a.chain.Tip().Time
	a.engine.Now = fixedClock(&now)
	senders := []string{
		"198.51.100.7:5000", "203.0.113.9:5000", "192.0.2.5:5000", "10.1.0.4:5000",
	}
	for _, s := range senders {
		handshake(t, a, s)
	}

	// One block, delivered by everybody, as the flood delivers it.
	blk := fakeOrphan(t, p, a.chain.Height()+1, a.chain.Tip().Target, 7)
	blk.Header.Time = now + p.FutureTimeLimitSeconds + 60
	// Re-sealed: the fields above feed PoWSeed, so the seal fakeOrphan
	// (or the miner) left is the digest of a different blob now.
	sealDevBlock(&blk.Header)
	for _, s := range senders {
		if v := a.engine.Handle(s, p2p.KindBlock, deliver(blk)); !errors.Is(v.Err, p2p.ErrBlockWithheld) {
			t.Fatalf("delivery from %s: got %v, want it withheld", s, v.Err)
		}
	}

	r := a.engine.BeyondHorizon()
	if r.Groups != len(senders) {
		t.Fatalf("one block delivered by %d groups recorded %d of them; the breadth "+
			"evidence is what separates a slow local clock from one fast peer, and "+
			"collapsing it to the first deliverer inverts the diagnosis",
			len(senders), r.Groups)
	}
	// The block itself is queued once, so it is counted once. Breadth and
	// magnitude are different questions and only one of them dedupes.
	if r.Withheld != 1 || r.QueueDepth != 1 {
		t.Fatalf("%+v: the same block was queued more than once, or counted more "+
			"than once", r)
	}
}

// TestAFutureDatedAnnouncementIsCounted covers the earliest ingress, and the
// only one a node with a single upstream ever sees.
//
// Blocks gossip hash-first: AnnounceBlock broadcasts a header, and a body only
// floods one hop later from a peer that accepted it. A node whose only peer is
// the block's origin therefore receives announcements and never a body — and
// OnBlockAnnounce drops a future-dated one without requesting the body, so
// nothing downstream of it ever runs. Measured before this: every counter zero
// and nothing logged, on a node 4000 s slow.
func TestAFutureDatedAnnouncementIsCounted(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	blocks := a.mine(t, 3)

	now := a.chain.Tip().Time
	a.engine.Now = fixedClock(&now)
	handshake(t, a, "198.51.100.7:5000")

	ahead := retime(blocks[len(blocks)-1], now+p.FutureTimeLimitSeconds+600)
	ann := p2p.BlockAnnounce{Header: ahead.Header, CertExemplars: ahead.CertExemplars()}
	v := a.engine.Handle("198.51.100.7:5000", p2p.KindBlockAnnounce, ann.MarshalAnnounce())
	if !errors.Is(v.Err, p2p.ErrBlockWithheld) {
		t.Fatalf("a future-dated announcement: got %v, want it refused as early", v.Err)
	}

	r := a.engine.BeyondHorizon()
	if r.Announced != 1 || r.Count != 1 {
		t.Fatalf("a dropped future-dated announcement reported as %+v, want 1 "+
			"announcement counted — on a single-upstream node this is the only "+
			"sensor there is", r)
	}
	if r.Groups != 1 || r.FirstGroup != "198.51.0.0/16" {
		t.Fatalf("the announcer was not recorded as evidence: %+v", r)
	}
	if want := p.FutureTimeLimitSeconds + 600; r.MaxSkewSeconds != want {
		t.Fatalf("worst skew %ds, want %ds", r.MaxSkewSeconds, want)
	}
	// And nothing was queued: an announcement costs this node nothing to lose,
	// because the network re-sends it and the id is kept out of seenBlocks.
	if r.Withheld != 0 || r.QueueDepth != 0 {
		t.Fatalf("%+v: an announcement was queued as though it were a body", r)
	}
}

// TestForwardedCountsAReleasedWithheldBlock covers the engine's second exit.
//
// ReleaseWithheld does not go through Handle — it calls OnBlock directly — so
// everything Handle does on the way out has to be repeated here or it does not
// happen for released blocks at all. That is already true of peer scoring, and
// the comment there says so; Forwarded is the same hazard one field over.
//
// A released block that is accepted *is* relayed: withholdLoop broadcasts
// exactly these. So it must be counted, and a node under a future-dated flood
// is precisely when someone would go looking at the number.
func TestForwardedCountsAReleasedWithheldBlock(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	victim := newNode(t, "v", p, key(t, 2).Persistent())

	blocks := a.mine(t, 4)
	now := blocks[len(blocks)-1].Header.Time
	victim.engine.Now = fixedClock(&now)
	handshake(t, victim, "a:1")
	for _, b := range blocks[:len(blocks)-1] {
		if v := victim.engine.Handle("a:1", p2p.KindBlock, deliver(b)); v.Err != nil {
			t.Fatalf("priming the victim: %v", v.Err)
		}
	}

	ahead := retime(blocks[len(blocks)-1], now+p.FutureTimeLimitSeconds+60)
	if v := victim.engine.Handle("a:1", p2p.KindBlock, deliver(ahead)); !errors.Is(v.Err, p2p.ErrBlockWithheld) {
		t.Fatalf("setup: the block was not withheld: %v", v.Err)
	}

	// Withholding is not a forward, and must not be counted as one — the
	// outcome is not known yet.
	before := victim.engine.Forwarded

	now = ahead.Header.Time - p.FutureTimeLimitSeconds
	rel := victim.engine.ReleaseWithheld()
	if len(rel) != 1 || rel[0].Verdict.Err != nil {
		t.Fatalf("setup: the matured block was not released and accepted: %+v", rel)
	}
	if !rel[0].Verdict.Forward {
		t.Fatal("setup: an accepted block was not relayed on release; there is " +
			"no forward here to count")
	}
	if got := victim.engine.Forwarded; got != before+1 {
		t.Fatalf("Forwarded = %d after a released block was accepted and relayed, "+
			"want %d: ReleaseWithheld is the engine's second exit and does not "+
			"count what leaves through it", got, before+1)
	}
}

// TestTheWithholdQueueCountsEverythingItRetains is the byte bound's property:
// the queue holds exactly one representation of each block — the delivered
// bytes — so `withheldBytes` is the footprint rather than a fraction of it.
//
// **This is a test of the bound, not of the queue.** wire.md §9 rule 8 makes
// MaxBytes the entire memory argument for the withhold path ("A node MUST bound
// whatever it holds — by count and by bytes"), and the queue used to retain a
// decoded `*types.Block` beside the frame it counted. Nothing was
// double-counted and nothing leaked; the bound simply described one of two held
// things, so a full 8 MiB queue really held about 16.5 MiB — and every existing
// test passed throughout, because they all measure how many blocks are queued
// and none measures how much memory that is.
//
// So the assertion is a comparison between the accounting and the heap, and it
// is deliberately not a comparison of block counts. A count-based assertion
// passes identically with `blk` restored, which makes it a test of the scenario
// rather than of the rule (CONTRIBUTING). The mutation that must kill this test
// is re-adding the field and populating it at admission, and the reason it dies
// is that the retained heap moves while `withheldBytes` does not.
//
// The threshold is a factor, not a byte count, because the absolute numbers
// depend on the block shape and on the allocator. It is set at 1.6x of the
// accounted bytes: the smallest decode expansion measured over any block shape
// is about 1.03x, so restoring `blk` moves the ratio to at least ~2.03x and is
// caught with room to spare, while a correct queue measures near 1.0x plus map
// and per-entry overhead. A tighter bound would be measuring the allocator.
func TestTheWithholdQueueCountsEverythingItRetains(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	a.mine(t, 2)

	now := a.chain.Tip().Time
	a.engine.Now = fixedClock(&now)
	handshake(t, a, "flooder:1")

	// Blocks fat enough that the block dominates the per-entry bookkeeping —
	// otherwise the map and the struct headers are the measurement and the
	// thing under test is noise. The certificates need not be valid: the
	// withhold gate runs before anything judges a block's contents, which is
	// the whole reason this queue is a cheap surface and needs a bound at all.
	const blocks = 24
	var raw int
	for i := 0; i < blocks; i++ {
		blk := fakeOrphan(t, p, a.chain.Height()+1, a.chain.Tip().Target, uint64(i))
		for j := 0; j < 400; j++ {
			blk.Certs = append(blk.Certs, &types.Certificate{
				ChainID: p.ChainID, Seq: uint64(j), TTL: 100,
				Program: types.Program{Kind: types.ProgramTransfer,
					Transfer: &types.TransferArgs{Moves: make([]types.Move, 1)}},
			})
		}
		blk.Header.CertRoot = blk.ComputeCertRoot(p)
		blk.Header.Time = now + p.FutureTimeLimitSeconds + 10 + uint64(i)
		// Re-sealed: the fields above feed PoWSeed, so the seal fakeOrphan
		// (or the miner) left is the digest of a different blob now.
		sealDevBlock(&blk.Header)
		raw += len(blk.MarshalSSZ())
		a.engine.Handle("flooder:1", p2p.KindBlock, deliver(blk))
	}
	if got := a.engine.WithheldCount(); got != blocks {
		t.Fatalf("%d of %d blocks were queued; the test is not measuring a "+
			"populated queue", got, blocks)
	}

	// The accounting first: it must be the delivered bytes, exactly. If this
	// drifts, the heap comparison below is measuring against a number that is
	// already wrong and would quietly absorb the error.
	if got := a.engine.WithheldBytes(); got != raw {
		t.Fatalf("the queue accounts %d bytes for %d delivered bytes; the byte "+
			"bound is not counting the frames it was given", got, raw)
	}

	// And now the heap the queue actually retains. Measured as the delta across
	// dropping the whole queue rather than across filling it, so that the
	// harness built to fill it — the chain, the engine, the test's own copies
	// of the blocks — is on both sides of the subtraction and cancels.
	var held, freed runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&held)
	now += p.FutureTimeLimitSeconds + 3600
	if rel := a.engine.ReleaseWithheld(); len(rel) != blocks {
		t.Fatalf("%d of %d blocks were released; the queue was not drained and "+
			"the measurement below would attribute the remainder to overhead",
			len(rel), blocks)
	}
	if a.engine.WithheldCount() != 0 || a.engine.WithheldBytes() != 0 {
		t.Fatalf("the drained queue still accounts %d blocks and %d bytes",
			a.engine.WithheldCount(), a.engine.WithheldBytes())
	}
	runtime.GC()
	runtime.ReadMemStats(&freed)

	// HeapAlloc is unsigned and the release path allocates as it judges, so a
	// nonsensical delta means the measurement failed rather than that the queue
	// is small. Say so instead of reporting a pass.
	if freed.HeapAlloc >= held.HeapAlloc {
		t.Skipf("the heap did not shrink when the queue drained (%d -> %d): "+
			"this measurement cannot see the queue on this run",
			held.HeapAlloc, freed.HeapAlloc)
	}
	retained := held.HeapAlloc - freed.HeapAlloc
	ratio := float64(retained) / float64(raw)
	t.Logf("queue of %d blocks: accounted %d bytes, retained %d bytes on the "+
		"heap, ratio %.2fx", blocks, raw, retained, ratio)

	if ratio > 1.6 {
		t.Fatalf("the queue accounts %d bytes but retains %d on the heap "+
			"(%.2fx): MaxBytes bounds a fraction of what is held, so the "+
			"memory argument wire.md §9 rule 8 rests on understates the real "+
			"footprint. A decoded block retained beside the counted frame "+
			"lands here", raw, retained, ratio)
	}
}

// TestARejectedReleaseIsReturnedButNotMarkedForRelay pins the contract on
// Released.Raw: the bytes are carried for every release, including the ones the
// ordinary path refused, and Verdict is what says which of them may travel.
//
// The queue judges nothing while a block is withheld, so a released block may
// turn out to be invalid — and it is still returned, because the release is
// also where the sender is charged for it. That makes `Raw` a field a caller
// must not read without reading `Verdict.Forward` beside it: relaying a refused
// block would push onward exactly what this node just declined, one hop out.
//
// The same hazard existed on `Released.Block` and nothing pinned it
// either. It is pinned now because the field changed shape, and a field whose
// safe use depends on a sibling field is worth a test rather than a comment.
func TestARejectedReleaseIsReturnedButNotMarkedForRelay(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, "a", p, key(t, 1).Persistent())
	a.mine(t, 2)

	now := a.chain.Tip().Time
	a.engine.Now = fixedClock(&now)
	handshake(t, a, "attacker:1")

	// Parented on nothing this node will ever hold and dated ahead, so it is
	// withheld now and refused on release rather than applied.
	bad := fakeOrphan(t, p, a.chain.Height()+1, a.chain.Tip().Target, 7)
	bad.Header.Height = 999_999
	bad.Header.Time = now + p.FutureTimeLimitSeconds + 5
	// Re-sealed: the fields above feed PoWSeed, so the seal fakeOrphan
	// (or the miner) left is the digest of a different blob now.
	sealDevBlock(&bad.Header)
	if v := a.engine.Handle("attacker:1", p2p.KindBlock, deliver(bad)); !errors.Is(v.Err, p2p.ErrBlockWithheld) {
		t.Fatalf("the block was not withheld, so the release path is not under "+
			"test: %v", v.Err)
	}

	now = bad.Header.Time
	rel := a.engine.ReleaseWithheld()
	if len(rel) != 1 {
		t.Fatalf("%d blocks released, want 1", len(rel))
	}

	// Returned, with its bytes, so the caller can see what was refused and the
	// sender can be charged — this is not a silent drop.
	if len(rel[0].Raw) == 0 {
		t.Fatal("a refused release carried no bytes; the caller cannot tell " +
			"what was refused and the block vanishes silently")
	}
	if !bytes.Equal(rel[0].Raw, bad.MarshalSSZ()) {
		t.Fatal("a refused release carried bytes other than the delivered ones")
	}
	// And emphatically not marked for relay.
	if rel[0].Verdict.Forward {
		t.Fatal("a block the ordinary path refused came back marked Forward: " +
			"withholding would then merely delay propagating what this node " +
			"rejected rather than prevent it")
	}
	if rel[0].Verdict.Err == nil {
		t.Fatal("a refused release carries no error, so a caller reading only " +
			"Err would treat it as accepted")
	}
}

// TestWithholdLoopDoesNotRelayABlockTheOrdinaryPathRefused pins the consumer
// half of the forwarding rule: `withholdLoop` must read `Verdict.Forward`
// before relaying, not merely be handed it.
//
// wire.md §9 rule 8 makes relay-on-release conditional on acceptance — a
// withheld block is "neither accepted nor rejected", and only once the ordinary
// path has judged it and *accepted* it may it travel. A node that relayed every
// release would propagate blocks it had itself just refused, which is the rule
// failing one hop out.
//
// **This is a different property from the one the engine test pins, and the
// difference is why both exist.**
// `TestARejectedReleaseIsReturnedButNotMarkedForRelay` pins the *producer*:
// `ReleaseWithheld` returns `Forward == false` and a non-nil `Err` for a block
// the ordinary path refused. That says nothing about whether anyone reads the
// flag. Removing the guard in `withholdLoop` leaves that test — and the whole
// package suite — green, which is the mirror shape CONTRIBUTING names: the
// producer's contract measured, the consumer's use of it assumed.
//
// The measurement is the peer's state and not this node's, because "did not
// relay" is only observable from the other end of a socket. B is primed with
// the same chain and left at a clock that would happily *withhold* the block if
// it arrived — so B holding nothing means nothing was sent, rather than that
// something was sent and refused.
func TestWithholdLoopDoesNotRelayABlockTheOrdinaryPathRefused(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, "s", p, key(t, 1).Persistent())
	a := newNode(t, "a", p, key(t, 2).Persistent())
	b := newNode(t, "b", p, key(t, 3).Persistent())

	blocks := source.mine(t, 4)
	now := blocks[len(blocks)-1].Header.Time
	var aClock, bClock liveClock
	aClock.set(now)
	bClock.set(now)
	a.engine.Now = aClock.now
	b.engine.Now = bClock.now
	handshake(t, a, "s:1")
	handshake(t, a, "attacker:1")
	handshake(t, b, "s:1")
	for _, blk := range blocks[:len(blocks)-1] {
		for _, n := range []*testNode{a, b} {
			if v := n.engine.Handle("s:1", p2p.KindBlock, deliver(blk)); v.Err != nil {
				t.Fatalf("priming %s: %v", n.name, v.Err)
			}
		}
	}

	// A block that is withheld now and REFUSED on release: dated ahead so the
	// withhold gate takes it before anything judges it, and at a fabricated
	// height so that the ordinary path cannot accept it once it matures.
	//
	// The pairing matters, and its absence is *detected* rather than merely
	// undesirable. A block that is merely late is accepted on release and
	// relayed correctly, so a version of this test without the fabricated
	// height would be measuring the scenario instead of the rule — the shape
	// CONTRIBUTING calls a test that "passes under both the rule and its
	// negation". Verified by arming exactly that: drop the height below *and*
	// remove the guard in withholdLoop, and this test does not pass. It fails
	// on the premise check further down — "a applied the block, so it was not
	// refused on release" — and says why it declined to measure, which is what
	// that branch is for.
	bad := retime(blocks[len(blocks)-1], now+p.FutureTimeLimitSeconds+30)
	bad.Header.Height = 999_999
	bad.Header.CertRoot = bad.ComputeCertRoot(p)
	// Re-sealed: the fields above feed PoWSeed, so the seal fakeOrphan
	// (or the miner) left is the digest of a different blob now.
	sealDevBlock(&bad.Header)
	if v := a.engine.Handle("attacker:1", p2p.KindBlock, deliver(bad)); !errors.Is(v.Err, p2p.ErrBlockWithheld) {
		t.Fatalf("setup: the block was not withheld by a, so the release path "+
			"is not under test: %v", v.Err)
	}

	if err := b.node.Listen("127.0.0.1:0"); err != nil {
		t.Fatalf("b listening: %v", err)
	}
	t.Cleanup(b.node.Stop)
	a.peers.Add(b.node.ListenAddr())
	a.node.DialInterval = 20 * time.Millisecond
	a.node.WithholdInterval = 20 * time.Millisecond
	a.node.SyncInterval = time.Hour
	a.node.Start()
	t.Cleanup(a.node.Stop)

	waitFor(t, "a to connect to b", func() bool { return a.node.PeerCount() > 0 })

	// A's clock reaches the release point, so withholdLoop judges the block and
	// refuses it.
	aClock.set(bad.Header.Time - p.FutureTimeLimitSeconds)
	waitFor(t, "a to release the block", func() bool { return a.engine.WithheldCount() == 0 })

	// Not applied — the premise of the test. If this fires, the block was
	// accepted after all and the test measures nothing.
	if a.chain.Height() == bad.Header.Height {
		t.Fatal("a applied the block, so it was not refused on release and " +
			"this test is not exercising the refused path")
	}

	// Now give the relay every chance to arrive: many withhold ticks, and B's
	// clock left behind the block's release point so that a body reaching B
	// would be *withheld* rather than refused — the outcome that leaves
	// evidence. B holding nothing therefore means nothing was sent.
	for i := 0; i < 25; i++ {
		if b.engine.WithheldCount() != 0 || b.chain.Height() == bad.Header.Height {
			t.Fatalf("b received a block that a had just refused: withheld=%d "+
				"height=%d. withholdLoop relayed a release whose verdict was "+
				"not Forward, so a block this node rejected propagates anyway "+
				"and the withhold rule holds for exactly one hop",
				b.engine.WithheldCount(), b.chain.Height())
		}
		time.Sleep(20 * time.Millisecond)
	}
}
