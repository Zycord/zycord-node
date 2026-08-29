package p2p_test

import (
	"errors"
	"testing"
	"time"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/p2p"
	"zycord/spec"
)

// forkedPeerSetup mines a chain, reorgs the top of it away, and returns the
// block that lost.
//
// The losing block is the one thing a peer can announce that this node holds a
// header for, is not built on, and therefore cannot place — the only shape in
// which OffersUnknown is the *sole* thing that can make its announcer a sync
// candidate. A peer announcing a block this node has never seen at all would
// also be ahead by height, and a test built on that would pass whether or not
// OffersUnknown worked.
func forkedPeerSetup(t *testing.T, victim *testNode, p *params.Params) *types.Block {
	t.Helper()
	victim.mine(t, 4)

	losing, err := victim.chain.BlockAt(3)
	if err != nil {
		t.Fatal(err)
	}
	ancestor, err := victim.chain.BlockAt(2)
	if err != nil {
		t.Fatal(err)
	}
	// A heavier two-block branch takes heights 3 and 4 off the victim's chain.
	branch := buildHarderBranch(t, victim.chain, p, key(t, 7).Persistent(), ancestor.Header, 2, 0)
	if !branch.Work().Gt(worthOf(t, victim.chain, 3, 4)) {
		t.Fatal("setup: the branch does not carry more work than the two blocks it replaces")
	}
	reorg, err := victim.chain.ConsiderBranch(branch)
	if err != nil {
		t.Fatalf("considering the harder branch: %v", err)
	}
	if !reorg.Adopted {
		t.Fatal("setup: the heavier branch was not adopted, so nothing was orphaned")
	}
	if _, err := victim.chain.Header(losing.Header.ID()); err != nil {
		t.Fatalf("setup: the orphaned header was not retained, so there is no "+
			"way for this to go wrong: %v", err)
	}
	if _, err := victim.chain.CanonicalHeader(losing.Header.ID()); err == nil {
		t.Fatal("setup: the orphaned block is still canonical, so the victim can place it")
	}
	return losing
}

// helloFromAForkedPeer completes a handshake whose claims are strictly behind
// the victim, so that nothing but OffersUnknown can make the peer a candidate.
func helloFromAForkedPeer(t *testing.T, victim *testNode, addr string, h types.Header) {
	t.Helper()
	victim.peers.Add(addr)
	victim.engine.Handle(addr, p2p.KindHello, p2p.Hello{
		Protocol:   p2p.ProtocolVersion,
		NetworkID:  victim.chain.NetworkID(),
		Height:     h.Height,
		Work:       u256.One.Bytes(),
		ListenAddr: addr,
	}.MarshalHello())
	if got := victim.engine.SyncCandidates(); len(got) != 0 {
		t.Fatalf("setup: the peer is already a candidate on its handshake claims "+
			"(%d), so the announce below cannot be what makes it one", len(got))
	}
}

// TestAShorterHeavierBranchStillMakesItsHoldersSyncCandidates.
//
// The property: an announcement of a block this node cannot place makes its
// announcer worth asking whenever the branch it implies is one fork choice
// could still adopt — which is bounded by the reorg horizon (undo_depth), not
// by this node's own height.
//
// The old bound was one height. All three candidacy tests then fail together
// for the peer holding a branch that is heavier but two or more blocks shorter:
// its height loses, its handshake work sample predates the divergence, and its
// announcement falls outside the one-block window. It will not sync from us
// either, because we are the ones who look shorter to it. Neither side asks,
// and a fork that fork choice would happily resolve never gets the chance —
// HANDOFF §7 records an observed 154-block reorg onto a branch 30 blocks
// shorter, so the distance this test uses is the mild case, not the extreme.
//
// The setup asserts the announcement is *accepted*: the node plainly recognises
// the block as new and relays it onward, which is what makes "and yet its
// announcer is not worth asking" a contradiction rather than a preference.
func TestAShorterHeavierBranchStillMakesItsHoldersSyncCandidates(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	losing := forkedPeerSetup(t, victim, p)

	// One more block puts the announced height two below our own, which is
	// exactly the distance the old bound refused.
	victim.mine(t, 1)
	own := victim.chain.Height()
	if own != losing.Header.Height+2 {
		t.Fatalf("setup: announced height is %d below our own %d, want 2",
			own-losing.Header.Height, own)
	}
	if own-losing.Header.Height > p.UndoDepth {
		t.Fatalf("setup: the distance %d is already past the reorg horizon %d, so "+
			"the fix under test is not what decides this case",
			own-losing.Header.Height, p.UndoDepth)
	}

	const addr = "10.0.0.1:9421"
	helloFromAForkedPeer(t, victim, addr, losing.Header)

	v := victim.engine.Handle(addr, p2p.KindBlockAnnounce, p2p.BlockAnnounce{
		Header:        losing.Header,
		CertExemplars: losing.CertExemplars(),
	}.MarshalAnnounce())
	// Accepted means a body was asked for and the announcer was rewarded. It no
	// longer means forwarded — under Option A nothing forwards an
	// accepted announcement — so the setup gate reads the two facts that
	// separate acceptance from every refusal on this path.
	if v.Err != nil || v.Reply == nil || v.Score != p2p.ScoreUsefulMessage {
		t.Fatalf("setup: the announcement was not accepted (cost=%v score=%d "+
			"err=%v), so this test is not about candidacy", v.Cost, v.Score, v.Err)
	}

	if got := victim.engine.SyncCandidates(); len(got) != 1 {
		t.Fatalf("a peer announcing a block %d heights below our own that we cannot "+
			"place is not a sync candidate (%d): the node accepted that very "+
			"announcement as new, so it recognises the block — but a branch that is "+
			"heavier and shorter leaves nobody to ask",
			own-losing.Header.Height, len(got))
	}
}

// TestAnAnnouncementBeyondTheHorizonIsNotACandidate is the other half:
// the bound moved to the reorg horizon, it did not go away.
//
// A peer whose unplaceable block sits deeper than undo_depth below our tip is
// offering a branch ConsiderBranch would refuse on arrival, so asking it buys
// nothing. Without a bound at all the check would be "does this peer hold any
// block we lack", which every peer on a long-lived network can satisfy forever
// with a single ancient header.
func TestAnAnnouncementBeyondTheHorizonIsNotACandidate(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	losing := forkedPeerSetup(t, victim, p)
	victim.mine(t, 1)
	// A horizon of one block reproduces the deeper-than-undo_depth case without
	// mining undo_depth blocks. The rule under test reads the parameter, so the
	// parameter is the honest way to drive it — but it is narrowed only after
	// the setup's own reorg, which ConsiderBranch would otherwise refuse for
	// being deeper than the horizon it is being asked to demonstrate.
	p.UndoDepth = 1
	own := victim.chain.Height()
	if own-losing.Header.Height <= p.UndoDepth {
		t.Fatalf("setup: distance %d is within the horizon %d, so this test cannot "+
			"observe the bound", own-losing.Header.Height, p.UndoDepth)
	}

	const addr = "10.0.0.2:9421"
	helloFromAForkedPeer(t, victim, addr, losing.Header)
	victim.engine.Handle(addr, p2p.KindBlockAnnounce, p2p.BlockAnnounce{
		Header:        losing.Header,
		CertExemplars: losing.CertExemplars(),
	}.MarshalAnnounce())

	if got := victim.engine.SyncCandidates(); len(got) != 0 {
		t.Fatalf("a peer offering a block %d below our tip, past the %d-block reorg "+
			"horizon, is a sync candidate (%d): fork choice would refuse that branch, "+
			"so there is nothing to ask for", own-losing.Header.Height, p.UndoDepth, len(got))
	}
}

// TestAFutureDatedAnnouncementStillRefreshesTheTip.
//
// The property: a node whose clock is slow does not *also* lose its view of who
// is worth asking. Refusing to judge a header is not a reason to forget that
// the peer showed it to us.
//
// OnBlockAnnounce returns on the future-time branch before it reaches
// recordAnnounce, so the defect is a missing call rather than a wrong one and
// no happy-path test can see it. The victim here is slow by far more than
// future_time_limit_seconds, which is the condition the clock-skew sensors
// instrument and which is self-worsening: gossip stops being accepted and, at the same
// instant, sync candidacy stops being refreshed — so the one mechanism left is
// degraded by the failure of the other.
//
// The announcement is still not believed. It is still dropped, still not
// relayed, still kept out of seenBlocks; the test asserts that refusal
// explicitly, so a version of this fix that quietly started accepting
// future-dated blocks would fail here rather than pass.
func TestAFutureDatedAnnouncementStillRefreshesTheTip(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	losing := forkedPeerSetup(t, victim, p)

	// The victim's clock is slow, which is the same thing as every peer's block
	// being dated ahead of it. One block below our tip, so the candidacy horizon is
	// not what this test is measuring.
	if own := victim.chain.Height(); own != losing.Header.Height+1 {
		t.Fatalf("setup: distance is %d, want 1 so that only the clock is under test",
			own-losing.Header.Height)
	}
	slow := time.Unix(int64(losing.Header.Time)-int64(p.FutureTimeLimitSeconds)-1000, 0)
	victim.engine.Now = func() time.Time { return slow }

	const addr = "10.0.0.3:9421"
	helloFromAForkedPeer(t, victim, addr, losing.Header)

	v := victim.engine.Handle(addr, p2p.KindBlockAnnounce, p2p.BlockAnnounce{
		Header:        losing.Header,
		CertExemplars: losing.CertExemplars(),
	}.MarshalAnnounce())
	if !errors.Is(v.Err, p2p.ErrBlockWithheld) {
		t.Fatalf("setup: the announcement was not refused as future-dated (%v), so "+
			"this test never reaches the branch it is about", v.Err)
	}
	if v.Forward {
		t.Fatal("a future-dated announcement was forwarded: it is not judgeable, so it " +
			"is not relayed")
	}

	if got := victim.engine.SyncCandidates(); len(got) != 1 {
		t.Fatalf("a slow node did not keep the peer that showed it an unplaceable "+
			"block as a sync candidate (%d): the clock stops this node taking blocks "+
			"from gossip, and it must not also degrade the view of who to ask, which "+
			"is the mechanism it has left", len(got))
	}
}

// TestTheCandidacyHorizonIsExactlyUndoDepth pins the boundary itself.
//
// The property: the widened bound is undo_depth and not merely "something
// larger than one", and it is inclusive at exactly undo_depth.
//
// Inclusive is a deliberate one-block overshoot rather than the tight
// condition. The announced block sits on the branch, so the fork point is at
// h.Height-1 or lower and the implied reorg is at least own-h.Height+1 deep;
// at a distance of exactly undo_depth that is undo_depth+1, which
// ConsiderBranch refuses for every possible fork point. So the peer this test
// keeps is one we did not strictly have to ask. That is the direction the rule
// errs on purpose: an unnecessary round trip against a horizon of 1024 is
// cheap, and erring the other way leaves nobody to ask. What the test pins is that the
// overshoot is exactly one block and does not grow.
//
// Written as its own scenario rather than folded into the test above because
// an announcement is deduped by seenBlocks, so the same block cannot be
// offered twice to the same node under two different horizons.
//
// Without this pair the constant is unpinned in both directions: the rule
// reads a parameter, and a test that only ever measures a distance far inside
// the horizon would pass for any horizon at all, including a wrong multiple of
// the right one.
func TestTheCandidacyHorizonIsExactlyUndoDepth(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	losing := forkedPeerSetup(t, victim, p)
	victim.mine(t, 1)

	// This writes undo_depth on the live *params.Params the chain holds, which
	// is worth stating rather than doing quietly. It is sound here for three
	// reasons: devnetEasy copies spec.Devnet() per call, so the struct is
	// local to this test; the narrowing happens after the setup's own reorg,
	// which ConsiderBranch would otherwise refuse at this value; and nothing
	// that reads undo_depth runs again afterwards — considerBranchLocked and
	// the pruning horizon in node/chain/store.go are both done, and the only
	// remaining chain calls are Height, CanonicalHeader and Params.
	//
	// It is also the honest way to drive the rule, which reads the parameter
	// rather than a literal. Mutating `horizon` to UndoDepth*2 in the rule is
	// killed only by this test and the beyond-the-horizon test; with devnet's
	// undo_depth of 128 and a distance of 2, a test that did not narrow the
	// parameter would pass for any horizon at all. The alternative is mining
	// 128 blocks to measure the same thing more slowly.
	own := victim.chain.Height()
	p.UndoDepth = own - losing.Header.Height
	if p.UndoDepth != 2 {
		t.Fatalf("setup: distance is %d, want 2 so the horizon under test is not "+
			"the degenerate one-block bound this fix replaced", p.UndoDepth)
	}

	const addr = "10.0.0.4:9421"
	helloFromAForkedPeer(t, victim, addr, losing.Header)
	victim.engine.Handle(addr, p2p.KindBlockAnnounce, p2p.BlockAnnounce{
		Header:        losing.Header,
		CertExemplars: losing.CertExemplars(),
	}.MarshalAnnounce())

	if got := victim.engine.SyncCandidates(); len(got) != 1 {
		t.Fatalf("a peer offering a block exactly %d below our tip, at the reorg "+
			"horizon rather than past it, is not a sync candidate (%d): the bound "+
			"is undo_depth inclusive by one block on purpose, because it decides "+
			"who is asked and an unnecessary round trip is cheaper than having "+
			"nobody to ask",
			p.UndoDepth, len(got))
	}
}

// TestAnUnplaceableBlockAboveOurTipStillMakesItsHolderACandidate.
//
// The property: widening the bound downwards did not cost the case it started
// with. A peer showing us a block we cannot place at a height *above* our own
// is the original reason OffersUnknown exists, and the rewritten test is a
// disjunction whose first branch is what carries it.
//
// That branch also carries the overflow argument: the bound is written as
// `h.Height >= own || own-h.Height <= horizon` rather than as
// `h.Height+horizon >= own` because the addition wraps for a claimed height
// near the top of uint64. Delete the first branch and the subtraction in the
// second underflows for every ahead peer instead, silently answering "no" for
// exactly this scenario — which is why it is pinned separately from the
// shorter-branch case, where both branches happen to agree.
func TestAnUnplaceableBlockAboveOurTipStillMakesItsHolderACandidate(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, "victim", p, key(t, 1).Persistent())
	losing := forkedPeerSetup(t, victim, p)

	// A header this node has never seen, claiming a height above our tip. Only
	// the height moves, so it still carries the work and the certificate root
	// the announce path checks before candidacy is considered at all.
	ahead := losing.Header
	ahead.Height = victim.chain.Height() + 2
	if _, err := victim.chain.CanonicalHeader(ahead.ID()); err == nil {
		t.Fatal("setup: the fabricated header is already canonical")
	}

	const addr = "10.0.0.5:9421"
	helloFromAForkedPeer(t, victim, addr, losing.Header)
	v := victim.engine.Handle(addr, p2p.KindBlockAnnounce, p2p.BlockAnnounce{
		Header:        ahead,
		CertExemplars: losing.CertExemplars(),
	}.MarshalAnnounce())
	if v.Err != nil {
		t.Fatalf("setup: the announcement was refused (%v), so this test never "+
			"reaches candidacy", v.Err)
	}

	// Asserted on the tip rather than on candidacy alone: a peer claiming a
	// height above ours is a candidate by height whichever way this clause
	// goes, so counting candidates here would pass with the clause deleted.
	got := victim.engine.SyncCandidates()
	if len(got) != 1 {
		t.Fatalf("a peer offering an unplaceable block above our tip is not a sync "+
			"candidate (%d)", len(got))
	}
	if got[0].OffersUnknown.IsZero() {
		t.Fatal("a peer that showed us an unplaceable block above our tip was not " +
			"recorded as offering anything unknown: that is the case OffersUnknown " +
			"was written for, and it is the only candidacy signal that survives " +
			"the handshake going stale — the horizon widening must not have cost it")
	}
}

// A body a peer delivers is candidacy evidence, and the body path never said so.
//
// PeerTip.OffersUnknown is the one candidacy signal that is not frozen at the
// handshake — every comment in this file turns on that — and it was written
// from exactly two places: recordTip, and recordAnnounce on the announce path.
// Handing this node a block it cannot place is the strongest thing a peer can
// do to show it is ahead, and it bought nothing.
//
// The second subtest is why that is reachable at this revision rather than only
// under a gossip change. OnBlockAnnounceFrom dedupes on seenBlocks and returns
// *ahead* of its own recordAnnounce call, so where two upstreams hold the same
// block only the first announcement to arrive refreshes anybody — and the
// second upstream, which delivers the body, stays frozen at whatever its Hello
// said. Fed only by the peer it does not count, a node behind has nobody to ask.
//
// Deliberately not asserted: the repeat delivery whose id is already seen and
// no longer pending. That returns CostDeduped before the decode and this change
// stands behind that gate on purpose — see OnBlock's own comment for why moving
// in front of it is an asymmetric cost a sender sets the rate of.
func TestADeliveredBodyWeCannotPlaceMakesItsSenderASyncCandidate(t *testing.T) {
	t.Run("a peer that delivers and never announced", func(t *testing.T) {
		p := spec.Devnet()
		ahead := newNode(t, "ahead", p, key(t, 1).Persistent())
		lag := newNode(t, "lag", p, key(t, 2).Persistent())
		handshake(t, ahead, "lag:1")
		// The handshake helper sends the receiver's OWN hello, so this records
		// the peer at lag's height of zero — which is the whole point: nothing
		// but the delivery can make it a candidate.
		handshake(t, lag, "ahead:1")

		blocks := ahead.mine(t, 20)
		last := blocks[len(blocks)-1]
		if got := lag.engine.SyncCandidates(); len(got) != 0 {
			t.Fatalf("setup: lag already has %d sync candidates before anything was "+
				"delivered, so this test would pass without the body path doing "+
				"anything", len(got))
		}

		// The body on the wire, obtained by asking the peer that holds it. No
		// announcement is ever shown to lag.
		served := ahead.engine.Handle("lag:1", p2p.KindGetBlock,
			p2p.GetBlock{ID: last.Header.ID()}.MarshalGetBlock())
		if served.Reply == nil {
			t.Fatalf("setup: the holder would not serve the body (%v)", served.Err)
		}
		v := lag.engine.Handle("ahead:1", p2p.KindBlock, served.Reply.Payload)
		if v.Cost == p2p.CostDeduped {
			t.Fatal("setup: the delivery was deduped, so it never reached the line " +
				"under test")
		}
		if lag.chain.Height() != 0 {
			t.Fatalf("setup: lag applied the block (height %d), so this is the "+
				"tip-extension path and not the unplaceable one this test names",
				lag.chain.Height())
		}

		got := lag.engine.SyncCandidates()
		if len(got) != 1 {
			t.Fatalf("a peer that delivered a block this node cannot place is not a "+
				"sync candidate (%d): the body path is the only thing that ran, and "+
				"a node fed bodies by a peer it does not count has nobody to ask",
				len(got))
		}
		if got[0].Height != last.Header.Height {
			t.Fatalf("the deliverer's height is %d, the block it delivered is at %d: "+
				"the tip was left frozen at the handshake sample",
				got[0].Height, last.Header.Height)
		}
		if got[0].OffersUnknown.IsZero() {
			t.Fatal("the deliverer was not recorded as offering anything unknown, so " +
				"its candidacy lapses with offersUnknownWindow and does not survive " +
				"the handshake going stale — which is the failure this records")
		}
	})

	// The placement claim, driven rather than reasoned.
	//
	// OnBlock's comment gives two reasons the refresh must not sit after
	// Chain.Apply, and the two subtests above pin only the first: both deliver a
	// block the node cannot place, so a refresh moved below would never be
	// REACHED, and a mutant moved there dies of that alone. The second reason is
	// that recordAnnounce gates OffersUnknown on CanonicalHeader, so a refresh
	// that ran after Apply would find the block canonical and silently decay to
	// a height update — a mutant that is reached, runs, and quietly records half
	// of what it should. Nothing above drives a node that APPLIES a delivered
	// body, so nothing above can tell those two apart. This does.
	t.Run("a peer whose delivered body this node applies", func(t *testing.T) {
		p := spec.Devnet()
		ahead := newNode(t, "ahead", p, key(t, 1).Persistent())
		lag := newNode(t, "lag", p, key(t, 2).Persistent())
		handshake(t, ahead, "lag:1")
		handshake(t, lag, "ahead:1")

		blk := ahead.mine(t, 1)[0]
		served := ahead.engine.Handle("lag:1", p2p.KindGetBlock,
			p2p.GetBlock{ID: blk.Header.ID()}.MarshalGetBlock())
		if served.Reply == nil {
			t.Fatalf("setup: the holder would not serve the body (%v)", served.Err)
		}
		v := lag.engine.Handle("ahead:1", p2p.KindBlock, served.Reply.Payload)
		if v.Cost == p2p.CostDeduped {
			t.Fatal("setup: the delivery was deduped, so it never reached the line " +
				"under test")
		}
		// The whole point of this subtest: the block is APPLIED, so a refresh
		// standing below Chain.Apply would be reached and would still run.
		if lag.chain.Height() != blk.Header.Height {
			t.Fatalf("setup: lag is at height %d and did not apply the delivered "+
				"block at %d, so this is the unplaceable path the subtests above "+
				"already cover and not the one this names",
				lag.chain.Height(), blk.Header.Height)
		}

		got := lag.engine.SyncCandidates()
		if len(got) != 1 {
			t.Fatalf("the peer whose body this node applied is not a sync candidate "+
				"(%d)", len(got))
		}
		if got[0].OffersUnknown.IsZero() {
			t.Fatal("the peer whose body this node applied was recorded without " +
				"OffersUnknown: the refresh ran after Chain.Apply, found the block " +
				"canonical, and decayed to a height update — which leaves candidacy " +
				"resting on a height this node has just drawn level with, i.e. on " +
				"nothing. The refresh must stand ahead of Apply")
		}
	})

	t.Run("the second upstream, whose announcement was deduped", func(t *testing.T) {
		p := spec.Devnet()
		ahead := newNode(t, "ahead", p, key(t, 1).Persistent())
		lag := newNode(t, "lag", p, key(t, 2).Persistent())
		handshake(t, ahead, "lag:1")
		handshake(t, lag, "b:1")
		handshake(t, lag, "c:1")

		blocks := ahead.mine(t, 20)
		last := blocks[len(blocks)-1]
		ann := p2p.BlockAnnounce{
			Header:        last.Header,
			CertExemplars: last.CertExemplars(),
		}.MarshalAnnounce()

		vb := lag.engine.Handle("b:1", p2p.KindBlockAnnounce, ann)
		if vb.Reply == nil {
			t.Fatalf("setup: the first announcement was refused (%v)", vb.Err)
		}
		vc := lag.engine.Handle("c:1", p2p.KindBlockAnnounce, ann)
		if vc.Cost != p2p.CostDeduped {
			t.Fatalf("setup: the second upstream's announcement cost %v rather than "+
				"being deduped, so this test is not the scenario it names", vc.Cost)
		}

		served := ahead.engine.Handle("lag:1", p2p.KindGetBlock, vb.Reply.Payload)
		if served.Reply == nil {
			t.Fatalf("setup: the holder would not serve the body (%v)", served.Err)
		}
		// The second upstream's body wins the race, while the first upstream's
		// pending entry still stands — so this delivery is not deduped either.
		v := lag.engine.Handle("c:1", p2p.KindBlock, served.Reply.Payload)
		if v.Cost == p2p.CostDeduped {
			t.Fatal("setup: the second upstream's body was deduped, so it never " +
				"reached the line under test")
		}

		var b, c bool
		for _, got := range lag.engine.SyncCandidates() {
			switch got.Conn {
			case "b:1":
				b = true
			case "c:1":
				c = got.Height == last.Header.Height && !got.OffersUnknown.IsZero()
			}
		}
		if !b {
			t.Fatal("setup: the announcing upstream is not a candidate, so the " +
				"announce path is broken and this test measures nothing")
		}
		if !c {
			t.Fatal("the upstream whose announcement was deduped and whose body was " +
				"delivered is not a sync candidate at the delivered height: two " +
				"upstreams fed this node and it counts one of them")
		}
	})
}
