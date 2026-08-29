package p2p_test

import (
	"testing"
	"time"

	"zycord/node/p2p"
)

// TestSyncSurvivesAPeerThatAlreadyHoldsACrossingPair is the liveness half of
// the per-identity admission cap, and it is here because the cap's
// first shape broke it.
//
// Two nodes that are peers hold *three* legs between them, not two. Two are
// the steady-state gossip pair — this node's outbound dial crossing the
// peer's, which is exactly the pair MaxConnsPerIdentity was chosen to admit —
// and the third is the dedicated connection Node.SyncFrom opens for every
// sync attempt (wire.md §12: no request ids, no state machine, so a sync
// attempt gets its own socket). The sync leg lands on the peer's register as
// a third entry carrying the same authenticated Ed25519 key.
//
// A cap that counted the gossip pair and the sync leg together therefore
// refused the sync leg *after* a completed TLS handshake, and there is no
// fallback for that: syncOnce re-routes to syncOverGossip only on
// ErrUndialable, and a post-handshake close is not that, so the attempt is
// simply lost. In an era-0 network where nodes dial each other, a node behind
// the tip is refused by every candidate it holds a pair with — the permanent
// freeze a node that never syncs from an inbound peer suffers, reached through
// a new door.
//
// The arrangement holds real dialled connections rather than reaching into
// the node's table, so the count register sees is the count a live peer
// produces. Both legs are dialled from the victim: the source's table is what
// the guard reads, and it sees one entry per socket keyed on the victim's
// identity either way, which is the whole quantity under test.
func TestSyncSurvivesAPeerThatAlreadyHoldsACrossingPair(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, "source", p, key(t, 1).Persistent())
	source.mine(t, 3)
	serveSyncTo(t, source)

	victim := newNode(t, "victim", p, key(t, 2).Persistent())
	victim.clock = source.clock

	// The gossip pair, held open for the whole attempt. Two, not
	// MaxConnsPerIdentity: the arrangement being reproduced is the honest
	// steady state between two peers, and what is asserted is that the sync
	// leg still fits beside it — so this stays two however the cap moves.
	for i := 0; i < 2; i++ {
		held, err := victim.node.Identity.Dial(source.node.ListenAddr(), 5*time.Second)
		if err != nil {
			t.Fatalf("setup: holding gossip leg %d open: %v", i, err)
		}
		defer held.Close()
	}
	// Give the source's accept loop time to register both legs; without this
	// the sync dial can win the race and the case under test never arises.
	waitForConnCount(t, source.node, 2)

	if err := victim.node.SyncFrom(source.node.ListenAddr()); err != nil {
		t.Fatalf("syncing from a peer this node already holds a gossip pair with: %v\n\n"+
			"The dedicated sync connection is a third leg for one identity on "+
			"the source's register. If the per-identity admission cap counts it "+
			"against the same budget as the gossip pair, the sync leg is refused "+
			"after its TLS handshake and this attempt is lost — syncOnce falls "+
			"back to syncOverGossip only on ErrUndialable, which a post-handshake "+
			"close is not. A node behind the tip is then refused by every "+
			"candidate it is peered with, which is that freeze.", err)
	}
	if victim.chain.Tip().ID() != source.chain.Tip().ID() {
		t.Fatal("the sync reported success but the victim did not catch up, so " +
			"this test would pass on a node that syncs nothing")
	}
}

// waitForConnCount blocks until the node's served set reaches n entries.
//
// Polled rather than slept: the accept loop registers on its own goroutine, and
// a fixed sleep is either slower than it needs to be or flaky on a loaded
// machine.
func waitForConnCount(t *testing.T, n *p2p.Node, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if n.PeerCount() >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("setup: the source never registered %d connections, so the "+
		"arrangement this test needs was never reached", want)
}
