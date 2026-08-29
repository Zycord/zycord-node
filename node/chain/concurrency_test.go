package chain_test

import (
	"sync"
	"testing"

	"zycord/core/types"
)

// Concurrent access to the chain.
//
// A running node touches `chain.Chain` from at least four goroutines: the miner
// assembling and applying, a message loop per peer applying gossiped blocks,
// the sync driver applying branches, and the RPC server reading. Every existing
// test drove it from one goroutine, so `go test -race` had nothing to find and
// reported nothing — which read as a clean bill of health rather than as an
// unasked question.
//
// The chaos soak asked it. A miner sealing an epoch state root reads the state
// while a gossiped block is writing it, and the root it commits to is computed
// from a torn read: a mix of before and after that no fold ever produced. The
// block is then rejected by every node including its author, and because state
// roots are only checked at epoch boundaries the divergence surfaces dozens of
// blocks after the moment that caused it.
//
// This test reproduces that access pattern directly. It must be run under
// `-race`, where it fails against an unsynchronised chain and passes against a
// synchronised one.
func TestChainSurvivesConcurrentAccess(t *testing.T) {
	p := devnetEasy()
	p.EpochLength = 4 // boundaries every four blocks, so sealing happens often
	payout := key(t, 1).Persistent()

	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)
	n.mine(t, 1)

	// A peer's chain, mined independently, whose blocks arrive as gossip would
	// deliver them.
	peer := openNode(t, t.TempDir(), p, payout)
	defer peer.close(t)
	peer.clock += p.TargetBlockSeconds
	peer.mine(t, 12)

	var wg sync.WaitGroup

	// The miner. Errors are expected and irrelevant: losing a race to the
	// applier is normal. The test is about memory safety, not outcome.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 12; i++ {
			_, _, _ = n.miner.MineOne(1 << 20)
		}
	}()

	// A gossip loop delivering the peer's blocks.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for h := uint64(1); h <= peer.chain.Height(); h++ {
			blk, err := peer.chain.BlockAt(h)
			if err != nil {
				continue
			}
			_, _ = n.chain.Apply(blk)
		}
	}()

	// The RPC server, reading everything the /status and /balance handlers read.
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; i < 2000; i++ {
			_ = n.chain.Height()
			_ = n.chain.Tip().ID()
			_ = n.chain.TotalWork()
			_ = n.chain.Snapshot().State.Get(types.SeqBaseFeeSlot())
			_ = n.chain.StoredStateRoot()
		}
	}()

	wg.Wait()

	// Whatever chain it ended on, the node must agree with itself: the state in
	// memory is the state that was committed.
	if got, want := n.chain.StateRoot(), n.chain.StoredStateRoot(); got != want {
		t.Fatalf("in-memory state diverged from the committed state:\n  memory %x\n  stored %x", got, want)
	}
}

// TestConcurrentStateRootAfterAFailedEpochBoundaryBlock: `Chain.StateRoot` is a
// read, and stays one no matter what state the last rejected block left behind.
//
// Making the epoch state root incremental turned `state.Root` from a pure
// computation into one that writes back what it derived — the two key/leaf
// arrays, both merkle trees, and a `clear` of the two dirty sets. Its three
// callers were not changed and all three hold `Chain.mu` in **shared** mode:
// this function, `StateRef.Root` inside `Chain.Read`, and `Chain.Snapshot`'s
// `Clone`, which reads every field the other two write. Shared means two of
// them can be in there at once.
//
// That was argued safe by an invariant nobody had written down — "the dirty
// sets are empty whenever the exclusive lock is released", so every shared-lock
// caller takes the fast path and touches nothing. The invariant was already
// false. `fold.apply` undoes its own writes on the error paths that come after
// it has mutated state, F14 `state root mismatch at epoch boundary` among them,
// and `Undo` marks every restored key dirty; `applyLocked` then returns the
// error **without** calling `Root`, and releases the lock with both dirty sets
// full. The trigger is one block of valid proof-of-work carrying a deliberately
// wrong epoch-boundary state root, which any peer can gossip — and the race
// that follows includes concurrent `clear` and range over the same map, which
// Go is permitted to escalate from a detected race to an unrecoverable
// `fatal error: concurrent map iteration and map write`.
//
// So this test puts the node in exactly that state and then reads it the way
// the RPC server does. It is a `-race` test: without synchronisation inside
// `state.State` it reports data races in `refreshLeaves`, and with it the same
// eight goroutines are clean.
func TestConcurrentStateRootAfterAFailedEpochBoundaryBlock(t *testing.T) {
	p := devnetEasy()
	p.EpochLength = 2
	n := openNode(t, t.TempDir(), p, key(t, 1).Persistent())
	defer n.close(t)

	// Mine up to an epoch boundary, so the block we re-apply is one whose state
	// root the fold actually checks (F14).
	for n.chain.Height() == 0 || !p.IsEpochBoundary(n.chain.Height()) {
		n.mine(t, 1)
	}
	blk, err := n.chain.BlockAt(n.chain.Height())
	if err != nil {
		t.Fatal(err)
	}
	if err := n.chain.Rollback(); err != nil {
		t.Fatal(err)
	}
	before := n.chain.StateRoot()

	// The same block, with a state root no fold could have produced. It applies
	// cleanly right up to the boundary check, which rejects it — after the fold
	// has written and undone the whole block.
	bad := *blk
	bad.Header.StateRoot[0] ^= 0xff
	if _, err := n.chain.Apply(&bad); err == nil {
		t.Fatal("a block with a corrupted epoch-boundary state root was accepted")
	}

	// Eight RPC-shaped readers, which is the shape /status has.
	var wg sync.WaitGroup
	roots := make([]types.Hash, 8)
	for g := 0; g < 8; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			roots[g] = n.chain.StateRoot()
		}(g)
	}
	wg.Wait()

	// And they must all have computed the same thing: the state the rejected
	// block was undone back to.
	for g, got := range roots {
		if got != before {
			t.Fatalf("reader %d computed %x; the state was undone back to %x", g, got[:8], before[:8])
		}
	}
	if got, want := n.chain.StateRoot(), n.chain.StoredStateRoot(); got != want {
		t.Fatalf("in-memory state diverged from the committed state:\n  memory %x\n  stored %x", got, want)
	}
}
