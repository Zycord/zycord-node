package p2p

import (
	"testing"
	"time"
)

// TestReapingAnUnservedAnnouncementForgetsItsSeenEntryToo.
//
// OnBlock's dedup gate reads `seen && !waiting`. The reap used to clear
// `pending[id]` and leave `seenBlocks[id]` standing, so the moment
// PendingBodyTimeout elapsed the gate went true and stayed true — and the
// *first* gossip delivery of that body came back CostDeduped and was thrown
// away. That is the honest-slow-link case wire.md §9 rule 5's window
// constraint exists for ("a peer honestly serving a large block over a slow
// link must not be mistaken for one that will not serve at all"), and it was
// penalised twice: once in score, and once by having its work discarded.
//
// The assertions are positive and staged, so a fix that deleted the wrong
// thing fails just as one that deleted nothing: the announcement is accepted
// (anti-vacuity — a refused announcement writes neither map and everything
// below would pass for the wrong reason), the reap charges the announcer (so
// this is the charging branch and not the canonical exemption), the seen entry
// is gone, and the late body is applied rather than deduped.
//
// The sweep runs at PendingBodyTimeout+1s, far inside SeenBlockTTL (10
// minutes), so the deletion measured here cannot be the seen-set's TTL sweep.
func TestReapingAnUnservedAnnouncementForgetsItsSeenEntryToo(t *testing.T) {
	e, _, blk := ingressFixture(t)
	const slow = "10.4.0.1:41000"
	id := blk.Header.ID()

	ann := BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
	if v := e.OnBlockAnnounce(slow, ann.MarshalAnnounce()); v.Reply == nil || v.Err != nil {
		t.Fatalf("setup: the announcement was not accepted (reply %v, err %v); "+
			"neither map is written on a refusal, so nothing below would be measured",
			v.Reply, v.Err)
	}
	e.mu.Lock()
	_, seen := e.seenBlocks[id]
	_, waiting := e.pending[id]
	e.mu.Unlock()
	if !seen || !waiting {
		t.Fatalf("setup: after an accepted announcement seen=%v waiting=%v, want both true", seen, waiting)
	}

	// The window elapses with no body: the announcer is charged and the
	// announcement must be forgotten — both halves of it.
	charged := e.ReapUnservedBodies(time.Now().Add(PendingBodyTimeout + time.Second))
	if len(charged) != 1 || charged[0] != slow {
		t.Fatalf("the reap charged %v, want exactly [%s]: this test is about the "+
			"charging branch, and any other outcome means it did not run", charged, slow)
	}

	e.mu.Lock()
	_, stillSeen := e.seenBlocks[id]
	e.mu.Unlock()
	if stillSeen {
		t.Fatal("the reap charged the announcer and left the id in seenBlocks: the " +
			"announcement is half-forgotten, so OnBlock's `seen && !waiting` gate is " +
			"now permanently true for it and the body can never be applied")
	}

	// The slow link finally delivers the body it was asked for. This is the
	// *first* delivery of it, not a repeat: there is nothing to dedup.
	v := e.OnBlock(slow, blk.MarshalSSZ())
	if v.Cost == CostDeduped {
		t.Fatalf("the first delivery of a reaped announcement's body was deduped "+
			"(%v): the honest slow link is charged ScoreUnservedBody AND has its "+
			"work discarded", v.Err)
	}
	if v.Err != nil {
		t.Fatalf("the late body was refused: %v", v.Err)
	}
	if got := e.Chain.Tip().ID(); got != id {
		t.Fatalf("the late body was not applied: tip is %x, want %x", got[:8], id[:8])
	}
}

// TestReapingAnAlreadyCanonicalAnnouncementKeepsItsSeenEntry is the other half
// of that decision, and the control for the test above.
//
// The reap's canonical branch is uncharged — wire.md §9 rule 5 constraint 3:
// the peer is not at fault for a body this node no longer needs — and it keeps
// its seen entry, because deduping a body the chain already holds is exactly
// what the gate is for. Only the charging branch forgets.
//
// It is also what says the sweep is selective rather than a blanket clear: the
// same call, at the same clock, over an entry of the same age, keeps this one.
func TestReapingAnAlreadyCanonicalAnnouncementKeepsItsSeenEntry(t *testing.T) {
	e, _, blk := ingressFixture(t)
	const peer = "10.4.0.2:41000"
	id := blk.Header.ID()

	ann := BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
	if v := e.OnBlockAnnounce(peer, ann.MarshalAnnounce()); v.Reply == nil || v.Err != nil {
		t.Fatalf("setup: the announcement was not accepted (reply %v, err %v)", v.Reply, v.Err)
	}

	// The same block lands by a route that never touches pending — direct
	// application, standing in for headers-first sync.
	if _, err := e.Chain.Apply(blk); err != nil {
		t.Fatalf("setup: applying the block directly: %v", err)
	}

	if charged := e.ReapUnservedBodies(time.Now().Add(PendingBodyTimeout + time.Second)); len(charged) != 0 {
		t.Fatalf("the reap charged %v for a block the chain already holds; rule 5 "+
			"constraint 3 exempts it, and this test's premise is that branch", charged)
	}
	e.mu.Lock()
	_, seen := e.seenBlocks[id]
	e.mu.Unlock()
	if !seen {
		t.Fatal("the uncharged canonical branch dropped its seenBlocks entry: the reap " +
			"forgets the announcement only where it charges for it, and deduping a " +
			"body the chain already holds is what the gate exists to do")
	}
}
