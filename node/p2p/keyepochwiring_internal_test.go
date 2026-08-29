package p2p

import (
	"fmt"
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/core/u256"
)

// TestNodeChargesAKeyEpochToTheConnectionsAuthenticatedIdentity is the wiring
// test for the key-epoch budget, and it is the only one that goes through a
// socket.
//
// Every other test of this budget calls the engine directly and names the payer
// itself, so every one of them still passes if Engine.HandleFrom goes back to
// calling OnBlockAnnounce without the peer key. The budget would still exist,
// still refill and still refuse — and would be keyed on "ip:ephemeral_port",
// which is the defect the identity keying answers rather than a fix. Measured
// as a mutation: reverting that one dispatcher line left the whole package
// green.
//
// So what this pins is the one production call site. A real TLS connection, a
// real handshake, one real announcement naming a key epoch outside the two this
// node is working in, and the credit charged under the DIALLER's public key
// rather than under the address the OS gave the socket. It is the exact shape
// of TestNodeChargesAServedReplyToTheConnectionsAuthenticatedIdentity next
// door, for the budget that shares its keyspace.
func TestNodeChargesAKeyEpochToTheConnectionsAuthenticatedIdentity(t *testing.T) {
	h := newBudgetHarness(t)
	// The harness clock is fixed at the tip's time; the node under test is
	// reached over a socket and answers on the wall clock, so this test uses
	// the real one for both.
	h.e.Now = time.Now
	peers := h.e.Peers

	serverID, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	n := NewNode(serverID, h.e, peers, 1)
	if err := n.Listen("127.0.0.1:0"); err != nil {
		t.Fatal(err)
	}
	n.Start()
	t.Cleanup(n.Stop)

	client, err := NewIdentity()
	if err != nil {
		t.Fatal(err)
	}
	c, err := client.Dial(n.ListenAddr(), 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })

	hello := h.e.Hello()
	hello.ListenAddr = ""
	if err := c.Send(KindHello, hello.MarshalHello()); err != nil {
		t.Fatal(err)
	}

	// Two epochs above this node's own, so workingKeyEpoch does not exempt it
	// and the announcement really is charged. Dated at this node's clock, so
	// the future-time check that stands ahead of the price does not answer
	// first.
	own := pow.SeedEpochFor(h.c.Tip().Height, h.c.Params())
	h.now = time.Now()
	ann := h.headerAtEpoch(t, own+2, 7, u256.Max)
	if err := c.Send(KindBlockAnnounce, ann.announce()); err != nil {
		t.Fatal(err)
	}

	// The charge happens on the server's read loop, so it is awaited rather
	// than assumed. A poll and not a sleep: the failure below must be "it never
	// arrived", not "it arrived late".
	key := string(client.PublicKey())
	deadline := time.Now().Add(10 * time.Second)
	var byKey identityEntry
	var byAddr uint32
	var entries int
	for time.Now().Before(deadline) {
		peers.identityMu.Lock()
		byKey = peers.identity[key]
		entries = len(peers.identity)
		byAddr = 0
		for k, e := range peers.identity {
			if k != key && e.unheldEpochs > 0 {
				byAddr = e.unheldEpochs
			}
		}
		peers.identityMu.Unlock()
		if byKey.unheldEpochs > 0 || byAddr > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if byKey.unheldEpochs != 1 {
		t.Fatalf("the identity store charged %d key-epoch credits to the "+
			"dialler's public key, want 1; %d entries exist and one not keyed "+
			"on that identity holds %d. Engine.HandleFrom is not passing the "+
			"peer key to the announce handler, so the budget is keyed on an "+
			"ephemeral source port and is re-bought for the price of one TLS "+
			"handshake",
			byKey.unheldEpochs, entries, byAddr)
	}
	// Anti-vacuity: an entry keyed on the connection address as well would mean
	// something is charging twice and this test cannot say which charge it read.
	if byAddr != 0 {
		t.Fatalf("an identity entry not keyed on the dialler's public key holds "+
			"%d key-epoch credits alongside the %d charged to the key",
			byAddr, byKey.unheldEpochs)
	}
	t.Logf("one real announcement over TLS at key epoch %d: %d credit charged "+
		"to the dialler's Ed25519 identity, %d identity entries",
		own+2, byKey.unheldEpochs, entries)
}

// TestASpentKeyEpochBudgetIsNoMoreEvictableThanTheScoreBesideIt separates the
// one line of SpendUnheldKeyEpoch that is not about arithmetic.
//
// The budget shares identityEntry with the score, and a full store gives up the
// entry worth least by lessWorthKeeping: first by identityWorth, which is a
// score's distance from zero, and then — for the entries that tie at zero, which
// is every budget-only entry — by lastSeen, oldest first. So an entry planted by
// this budget and never stamped carries lastSeen 0, ties with every other such
// entry, and the victim falls through to the key-string tiebreak. Eviction then
// picks by NAME rather than by age, and a name is what the sender chooses: an
// attacker whose spent entry sorts the wrong way has it evicted for it, and an
// absent entry is a full budget. ChargeServedBytes stamps lastSeen next door for
// this reason and this is the same store.
//
// Measured as a mutation: dropping the stamp left the whole package green.
//
// The arrangement is the smallest one that can see it — the store filled to
// MaxIdentities by this budget alone, each entry stamped a second later than the
// last, then one more identity presented. The victim must be the FIRST one
// planted. Without the stamp the victim is decided by the key strings, and the
// names below are chosen so that the two answers differ.
func TestASpentKeyEpochBudgetIsNoMoreEvictableThanTheScoreBesideIt(t *testing.T) {
	ps, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	const period = 320
	// Zero-padded and ascending, so "oldest" and "largest key string" are
	// opposite answers: lessWorthKeeping breaks a lastSeen tie with `ka > kb`,
	// which prefers the LAST name, while the oldest entry carries the FIRST.
	name := func(i int) string { return fmt.Sprintf("identity-%06d", i) }

	for i := 0; i < MaxIdentities; i++ {
		if !ps.SpendUnheldKeyEpoch(name(i), MaxUnheldKeyEpochsPerPeer, period, uint64(1000+i)) {
			t.Fatalf("setup: identity %d was refused on its first credit", i)
		}
	}
	ps.identityMu.Lock()
	full := len(ps.identity)
	ps.identityMu.Unlock()
	if full != MaxIdentities {
		t.Fatalf("setup: the store holds %d entries, want %d; nothing below is "+
			"about a full store", full, MaxIdentities)
	}

	// One more identity, which the store admits by evicting.
	ps.SpendUnheldKeyEpoch("newcomer", MaxUnheldKeyEpochsPerPeer, period, uint64(1000+MaxIdentities))

	ps.identityMu.Lock()
	oldestGone := true
	newestGone := true
	for k := range ps.identity {
		if k == name(0) {
			oldestGone = false
		}
		if k == name(MaxIdentities-1) {
			newestGone = false
		}
	}
	held := len(ps.identity)
	ps.identityMu.Unlock()

	if held != MaxIdentities {
		t.Fatalf("the store holds %d entries after admitting one more, want %d",
			held, MaxIdentities)
	}
	if !oldestGone || newestGone {
		t.Fatalf("admitting a newcomer evicted the OLDEST spent budget=%v and "+
			"the newest=%v, want true and false. A budget entry that never "+
			"stamps lastSeen ties with every other at zero, so the store gives "+
			"one up by key string — a value the sender chooses — and an absent "+
			"entry is a full budget", oldestGone, !newestGone)
	}
}
