package p2p

import (
	"testing"
	"time"

	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/spec"
)

// An announcement writes e.pending unconditionally (engine.go, the single
// write site), and the get-block that would answer it is emitted by
// Node.serve only AFTER two gates that can both discard it. When the request
// is never sent, the body can never arrive, and sixty seconds later
// ReapUnservedBodies charges the announcer ScoreUnservedBody for a body this
// node never asked for.
//
// This drives the disconnect form, which needs no attacker at all: the peer
// announces truthfully and then goes away before it can be asked. forgetPeer
// clears e.tips and the partial transfers and does not clear e.pending, so the
// entry outlives the connection and is reaped against the peer's persisted
// address.
func TestAnAnnouncerIsNotChargedForABodyThisNodeNeverRequested(t *testing.T) {
	p := spec.Devnet()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.New(p, mempool.DefaultPolicy())
	work := &countingPoW{}
	e := NewEngine(c, pool, peers, work, "n:1")

	mine := func(payout byte) *types.Block {
		m := &miner.Miner{
			Chain: c, Pool: pool, Engine: work,
			Payout: [32]byte{0x02, payout, payout, payout},
			Now:    func() uint64 { return c.Tip().Time + p.TargetBlockSeconds },
		}
		_ = m
		b, err := m.Assemble()
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Seal(b, 1<<20); err != nil {
			t.Fatal(err)
		}
		return b
	}

	const honest = "10.7.0.1:9421"
	peers.Add(honest)
	now := time.Now()

	for round := 0; round < 10; round++ {
		blk := mine(byte(round + 1))
		ann := BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
		v := e.OnBlockAnnounce(honest, ann.MarshalAnnounce())
		if v.Err != nil {
			t.Fatalf("round %d: the honest announcement was refused: %v", round, v.Err)
		}
		// Anti-vacuity: the announcement must have been accepted and must have
		// asked for the body, or there is no unanswered request to measure.
		if v.Reply == nil {
			t.Fatalf("round %d: the announcement produced no get-block, so this "+
				"test would pass without exercising the unanswered-request path", round)
		}
		e.mu.Lock()
		_, waiting := e.pending[blk.Header.ID()]
		e.mu.Unlock()
		if !waiting {
			t.Fatalf("round %d: no pending entry was written", round)
		}

		// Node.serve discards the get-block here -- the peer is banned, the
		// write fails, or the socket is already gone. The engine is never told.
		// Then the peer disconnects, and forgetPeer leaves pending standing.
		e.forgetPeer(honest)

		// The block is NOT learned another way -- the announcer was this
		// node's only route to it, which is the whole reason the get-block
		// mattered. It never becomes canonical, so the reap's one exemption
		// does not apply.
		now = now.Add(PendingBodyTimeout + time.Second)
		e.ReapUnservedBodies(now)
	}

	got, _ := peers.Get(honest)
	if peers.Banned(honest) {
		t.Fatalf("an honest peer was banned (score %d) for ten blocks it "+
			"announced truthfully and was never asked to serve: the get-block "+
			"never left this node, so 'did not serve' was never true. "+
			"wire.md 9 rule 5 charges an announcer for not serving, and this "+
			"charges it for not being asked", got.Score)
	}
	if got.Score < 0 {
		t.Fatalf("an honest announcer was charged %d points for bodies this node "+
			"never requested", got.Score)
	}
}

// The other half of the same defect, reached through the gate rather than the
// teardown: Node.serve discards the get-block because the peer is already
// banned or the write fails, and the connection stays up. forgetPeer never
// runs, so only ForgetUnrequestedBody can clear the entry.
//
// Driven at the engine seam Node.serve calls, because the gates themselves
// live in a connection loop this test has no socket for.
func TestADiscardedGetBlockDoesNotBecomeAnUnservedBodyCharge(t *testing.T) {
	p := spec.Devnet()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.New(p, mempool.DefaultPolicy())
	work := &countingPoW{}
	e := NewEngine(c, pool, peers, work, "n:1")

	const honest = "10.7.0.2:9421"
	peers.Add(honest)
	now := time.Now()

	for round := 0; round < 10; round++ {
		m := &miner.Miner{
			Chain: c, Pool: pool, Engine: work,
			Payout: [32]byte{0x02, byte(round + 1), 7, 7},
			Now:    func() uint64 { return c.Tip().Time + p.TargetBlockSeconds },
		}
		blk, err := m.Assemble()
		if err != nil {
			t.Fatal(err)
		}
		if err := m.Seal(blk, 1<<20); err != nil {
			t.Fatal(err)
		}

		ann := BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
		v := e.OnBlockAnnounce(honest, ann.MarshalAnnounce())
		if v.Err != nil || v.Reply == nil || v.Reply.Kind != KindGetBlock {
			t.Fatalf("round %d: no get-block was produced (err %v), so the "+
				"discard below would have nothing to discard", round, v.Err)
		}

		// Node.serve's gate fires: the frame is never handed to the socket.
		// This is exactly what it now tells the engine.
		g, err := UnmarshalGetBlock(v.Reply.Payload)
		if err != nil {
			t.Fatalf("round %d: the get-block did not decode: %v", round, err)
		}
		e.ForgetUnrequestedBody(honest, g.ID)

		now = now.Add(PendingBodyTimeout + time.Second)
		e.ReapUnservedBodies(now)
	}

	got, _ := peers.Get(honest)
	if got.Score < 0 {
		t.Fatalf("an honest announcer was charged %d points for get-blocks this "+
			"node built and then threw away", got.Score)
	}
}
