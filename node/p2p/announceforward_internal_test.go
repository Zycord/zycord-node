package p2p

import (
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
)

// unheldParentGhost builds the remaining half: a header naming a parent this
// node does not hold, at a height far enough above the tip that no plausibility
// ceiling binds and still inside the key epoch the node is working in, declaring
// a target no digest can exceed.
//
// It is the header no check on the announce path can reach. `plausibleCeiling`
// saturates within a few blocks of the tip, the median-time rule needs ancestry,
// the difficulty rule needs the window preceding the parent, and `Target <=
// max_target` is a bound this header meets by declaring exactly it.
func unheldParentGhost(tb testing.TB, c *chain.Chain, salt uint64) types.Header {
	tb.Helper()
	p := c.Params()
	height := c.Tip().Height + 100
	h := types.Header{
		Version:  types.HeaderVersion,
		Height:   height,
		ParentID: types.Hash{0xab, byte(salt), byte(salt >> 8)},
		Time:     c.Tip().Time + 100*p.TargetBlockSeconds,
		CertRoot: certRoot(nil, p),
		Target:   u256.Max,
		PoW:      types.PoWSeal{SeedEpoch: pow.SeedEpochFor(height, p), Nonce: uint32(salt) | 1<<31},
	}
	// The ghost carries the digest of its own blob, as an honest header does.
	//
	// It still costs its sender essentially nothing — one evaluation at
	// u256.Max, where every commitment passes, rather than the search a real
	// target demands — so the finding this fixture exists for is unchanged: a
	// header with no work behind it in any meaningful sense is accepted by the
	// work check and must be stopped by the forward rule instead. What changed
	// is that "no work" is now one hash rather than zero, and saying so is
	// cheaper than leaving the fixture failing.
	sealDev(&h, p)
	if err := pow.CheckWork(pow.Dev{}, h, p); err != nil {
		tb.Fatalf("the ghost does not pass CheckWork (%v); at u256.Max no "+
			"commitment can exceed the target and the whole finding is that it "+
			"passes", err)
	}
	return h
}

// TestAnAnnouncementIsForwardedOnlyByANodeThatHoldsTheBody is Option A,
// end to end on real Engines.
//
// **The defect.** `wire.md` §9 rule 5 makes a receiver charge the announcer
// once when its window elapses with no body, and `pending` can only name the
// peer the message arrived from — the wire carries no origin. §8's flood rule
// made that peer the *last hop*, and the last hop is the one party guaranteed
// to be unable to serve: an announcement a node forwards is by construction one
// whose body it has just asked for itself. So every honest relay was, in §9
// rule 5's own words, a peer advertising what it will not back, and its
// downstream banned it for that. Measured on this arrangement's ancestor: 23
// ghosts, 5,336 B, the honest relay at −108 and banned, the announcer never
// scored by that downstream at all.
//
// **What this pins.** A node forwards an announcement only once it holds the
// body, and this return is the one that does not — so the ghost dies at the
// injection point, the downstream never hears it, and the charge that terminates
// the flood stays armed and aimed at the party that chose to announce.
//
// # Why the assertions are shaped the way they are
//
// `Forward == false` is *also* what every refusal on this path produces, so read
// alone it would agree with the truth everywhere except at the point it exists
// to observe (`PROTOCOL.md` rule 24). Each row therefore establishes acceptance
// first, on facts a refusal cannot produce — a `get-block` reply and
// `ScoreUsefulMessage` — and only then reads the forward. And the harness relays
// to the downstream **exactly when the verdict says to**, so restoring the
// forward is not merely a different assertion but a different run: the
// downstream pends, charges, and bans the relay, which is the failure this test
// is named for.
//
// The absolute counts are properties of this arrangement's reap schedule and not
// of the tree — the same finding was recorded at 23, at 12 and at 6 — so nothing
// here asserts one. What is asserted is the pair: the relay is never banned, and
// the announcer is.
func TestAnAnnouncementIsForwardedOnlyByANodeThatHoldsTheBody(t *testing.T) {
	t.Run("a ghost with an unheld parent dies at the injection point", func(t *testing.T) {
		cb, relay, _ := announceChain(t, 4)
		cc, down, _ := announceChain(t, 4)
		if cb.Tip().ID() != cc.Tip().ID() {
			t.Fatal("setup: the two engines were meant to start on the same tip")
		}
		const (
			attacker = "10.66.0.2:5000"
			relayer  = "10.66.0.3:5000"
		)
		// Both parties start where a long-lived gossiping peer sits, so the two
		// columns are read from the same place.
		relay.Peers.Adjust(attacker, ScoreCeiling)
		down.Peers.Adjust(relayer, ScoreCeiling)

		// Anti-vacuity on the arrangement itself: the ghost's height has to be
		// inside the key epoch this node is working in, or the key-epoch budget
		// refuses it and every count below measures that instead of the forward.
		p := cb.Params()
		ghostEpoch := pow.SeedEpochFor(cb.Tip().Height+100, p)
		if !workingKeyEpoch(ghostEpoch, pow.SeedEpochFor(cb.Tip().Height, p)) {
			t.Fatalf("setup: the ghost's key epoch %d is outside the working set, so "+
				"the budget refuses it and this test measures the budget", ghostEpoch)
		}

		accepted, forwarded, chargedToRelay := 0, 0, 0
		const send = 40
		for i := 0; i < send && !relay.Peers.Banned(attacker); i++ {
			ghost := unheldParentGhost(t, cb, uint64(i)+1)
			raw := BlockAnnounce{Header: ghost}.MarshalAnnounce()

			v := relay.OnBlockAnnounce(attacker, raw)
			if v.Score != 0 {
				relay.Peers.Adjust(attacker, v.Score)
			}
			// Acceptance, on facts no refusal produces. Without this the
			// forward count below is satisfied by a ghost that never got past
			// the work check, and the test would pass on a tree that had
			// stopped admitting the class it is about.
			if v.Reply == nil || v.Score != ScoreUsefulMessage {
				t.Fatalf("ghost %d was not accepted (cost=%v score=%d err=%v); this "+
					"ghost is the one no check on the announce path can reach, and a "+
					"refusal here means the counts below measure that refusal", i,
					v.Cost, v.Score, v.Err)
			}
			accepted++

			if v.Forward {
				forwarded++
				w := down.OnBlockAnnounce(relayer, raw)
				if w.Score != 0 {
					down.Peers.Adjust(relayer, w.Score)
				}
			}
			// Both reapers, once per announcement.
			chargedToRelay += len(down.ReapUnservedBodies(time.Now().Add(2 * PendingBodyTimeout)))
			relay.ReapUnservedBodies(time.Now().Add(2 * PendingBodyTimeout))
		}

		t.Logf("unheld-parent ghosts at tip+100: accepted=%d forwarded=%d "+
			"charged_to_relay=%d", accepted, forwarded, chargedToRelay)

		if accepted == 0 {
			t.Fatal("no ghost was accepted, so this arrangement exercises nothing")
		}
		if forwarded != 0 {
			t.Fatalf("the relay forwarded %d ghosts; each one becomes a pending entry "+
				"on its downstream keyed to the relay itself, and §9 rule 5 then "+
				"charges the relay for a body it never had", forwarded)
		}
		if chargedToRelay != 0 {
			t.Fatalf("the downstream charged an unserved body %d times against a relay "+
				"that handed it nothing", chargedToRelay)
		}
		if n := len(down.PendingBodies()); n != 0 {
			t.Fatalf("the downstream holds %d pending bodies it was never announced", n)
		}
		if down.Peers.Banned(relayer) {
			t.Fatal("the honest relay was banned by its own downstream, which is the defect")
		}
		// And the terminator is still armed, now aimed at the party that chose
		// to announce. Deleting the charge was measured at sixty ghosts accepted
		// and forwarded with no score ever negative, so this half is not
		// decoration.
		if !relay.Peers.Banned(attacker) {
			t.Fatal("the announcer of the ghosts was never banned; the charge that " +
				"terminates a ghost flood from a directly connected peer has to " +
				"land, and under Option A the party it names is the announcer")
		}
	})

	t.Run("the block still reaches the second hop, carried by the body", func(t *testing.T) {
		ca, miner, _ := announceChain(t, 4)
		cb, relay, _ := announceChain(t, 4)
		cc, down, _ := announceChain(t, 4)
		if ca.Tip().ID() != cb.Tip().ID() || cb.Tip().ID() != cc.Tip().ID() {
			t.Fatal("setup: the three engines were meant to start on the same tip")
		}
		const (
			minerAddr = "10.66.0.5:5000"
			relayAddr = "10.66.0.6:5000"
		)
		// One real block, mined past the tip the three share.
		extendChain(t, ca, ca.Params().TargetBlockSeconds)
		blk, err := ca.BlockAt(ca.Height())
		if err != nil {
			t.Fatal(err)
		}

		ann := BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
		v := relay.OnBlockAnnounce(minerAddr, ann.MarshalAnnounce())
		if v.Reply == nil || v.Score != ScoreUsefulMessage {
			t.Fatalf("the honest announcement was not accepted (cost=%v score=%d): %v",
				v.Cost, v.Score, v.Err)
		}
		if v.Forward {
			t.Fatal("an accepted announcement was relayed; a node forwards one only " +
				"once it holds the body, and this node has just asked for it")
		}

		// The miner serves the body it announced.
		served := miner.OnGetBlock(relayAddr, v.Reply.Payload)
		if served.Reply == nil {
			t.Fatalf("the announcer did not serve the body it announced: %v", served.Err)
		}
		body := relay.OnBlockChunk(minerAddr, served.Reply.Payload)
		if body.Err != nil {
			t.Fatalf("the relay refused the body: %v", body.Err)
		}
		if cb.Height() != ca.Height() {
			t.Fatalf("the relay is at height %d, the miner at %d", cb.Height(), ca.Height())
		}
		// **This is the forward that carries the block past the first hop**, and
		// it is the one Option A leaves alone: `OnBlock` marks an accepted body
		// for broadcast, and the serve loop floods it to every peer but the
		// sender. Removing the announcement's forward costs propagation nothing
		// because this was always what did the work.
		if !body.Forward {
			t.Fatal("an accepted body was not marked for broadcast; with the " +
				"announcement no longer relayed this is the only thing that carries " +
				"a block past the first hop")
		}

		if d := down.OnBlockChunk(relayAddr, served.Reply.Payload); d.Err != nil {
			t.Fatalf("the downstream refused the body the relay broadcasts: %v", d.Err)
		}
		if cc.Height() != ca.Height() {
			t.Fatalf("the block did not reach the second hop: downstream at %d, "+
				"miner at %d", cc.Height(), ca.Height())
		}
	})
}
