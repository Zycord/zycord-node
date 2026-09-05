package p2p

import (
	"testing"
	"time"

	"zycord/core/types"
)

// TestAnUnservedBodyChargesTheIdentityAndNotOnlyTheAddress is the seam between
// the unserved-body penalty and the identity tally, which landed on separate
// branches and meet for the first time here.
//
// `Engine.ReapUnservedBodies` can only charge the connection address it was
// handed: the engine never sees a public key. An address-only penalty is one a
// peer sheds by reconnecting on a fresh ephemeral port — precisely what
// identity-keyed scoring established must not be true of any score — so
// `Node.reapUnservedBodies` charges the identity behind the address as well,
// the same pairing `Node.serve` performs for every message.
//
// Internal because the pairing is between a private map (`Node.conns`) and a
// private one (`PeerStore.identity`): an external test can observe the address
// half and nothing else, which is exactly the half that already worked.
func TestAnUnservedBodyChargesTheIdentityAndNotOnlyTheAddress(t *testing.T) {
	e := testEngine(t)
	id, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(id, e, e.Peers, 1)

	const addr = "10.7.7.7:9000"
	announcer, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	key := announcer.PublicKey()
	n.conns[addr] = &Conn{Addr: addr, PeerKey: key}

	// One announced block whose body never arrives. Written straight into the
	// map the reaper reads: what is under test is the charging, not
	// OnBlockAnnounce's route into it, which network_test.go already pins.
	var blockID types.Hash
	blockID[0] = 0xa1
	e.mu.Lock()
	e.pending[blockID] = announcedBody{peerAddr: addr, announced: time.Now()}
	e.mu.Unlock()

	addrBefore, _ := e.Peers.Get(addr)
	keyBefore := identityScore(t, e.Peers, key)

	n.reapUnservedBodies(time.Now().Add(PendingBodyTimeout + time.Second))

	if got, _ := e.Peers.Get(addr); got.Score != addrBefore.Score+ScoreUnservedBody {
		t.Fatalf("the address tally moved by %d, want %d",
			got.Score-addrBefore.Score, ScoreUnservedBody)
	}
	if got := identityScore(t, e.Peers, key); got != keyBefore+ScoreUnservedBody {
		t.Fatalf("the identity tally moved by %d, want %d: an unserved body is "+
			"forgotten the moment the announcer reconnects on a new source port",
			got-keyBefore, ScoreUnservedBody)
	}

	// The negation, in this same sweep: a peer this node is no longer
	// connected to has no identity to charge, and the reaper must not panic or
	// charge somebody else's. Without this the test would pass against an
	// implementation that charged every live identity for every late entry.
	var otherID types.Hash
	otherID[0] = 0xb2
	e.mu.Lock()
	e.pending[otherID] = announcedBody{peerAddr: "10.7.7.8:9000", announced: time.Now()}
	e.mu.Unlock()

	keyBefore = identityScore(t, e.Peers, key)
	n.reapUnservedBodies(time.Now().Add(PendingBodyTimeout + time.Second))
	if got := identityScore(t, e.Peers, key); got != keyBefore {
		t.Fatalf("a connected peer's identity was charged %d for an entry "+
			"belonging to a disconnected one", got-keyBefore)
	}
	if len(e.PendingBodies()) != 0 {
		t.Fatal("a reaped entry was left in the map")
	}
}

func identityScore(t *testing.T, ps *PeerStore, key []byte) int {
	t.Helper()
	ps.identityMu.Lock()
	defer ps.identityMu.Unlock()
	return ps.identity[string(key)].score
}
