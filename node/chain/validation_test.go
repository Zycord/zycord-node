package chain_test

import (
	"errors"
	"testing"

	"zycord/core/u256"
	"zycord/node/chain"
)

// Fork-choice validation.
//
// ConsiderBranch used to weigh a candidate branch's declared target and
// timestamp without checking either against the rule that was supposed to
// produce them. These two tests pin that fix. The regression pin for the
// body-decoding header reads — depthOf and workSince no longer decoding a full
// block body just to read the header beside it — lives in depth_work_test.go
// instead, as a white-box test in package chain: it needs to call the two
// unexported functions directly, because switchTo's own unwind loop genuinely
// needs the bodies of whatever it unwinds (to return them for mempool
// re-admission), so a black-box test that deleted those same bodies would fail
// for a reason unrelated to depthOf or workSince before ever isolating the
// property those reads are about.
//
// TestConsiderBranchRejectsAForgedFirstBlockHeight pins a third gap review
// found in this same function while this PR was open: nothing anywhere
// checked the first branch block's declared Height against the ancestor it
// names as parent. depthOf keys on the declared ParentID, not on Height;
// the "branch must be a chain" loop started at index 1 and so never looked
// at block 0. A forged height on block 0 reached switchTo (which sets
// c.height directly from it) and core/fold.ApplyBlock (which computes the
// block subsidy from the same field) unchecked.

// TestConsiderBranchRejectsAForgedTarget is the regression pin for the
// unchecked declared target on the fork-choice path: a branch header whose
// declared target is not the one the difficulty rule computes from the
// preceding window must be refused outright, the same way
// node/sync.ValidateHeaders already refuses it — not weighed into accumulated
// work as though the declaration were a fact.
func TestConsiderBranchRejectsAForgedTarget(t *testing.T) {
	p := devnetEasy()
	payout := key(t, 1).Persistent()
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)
	n.mine(t, 3)
	tipBefore := n.chain.Tip().ID()

	ancestor := ancestorAt(t, n, 1)
	branch := buildBranch(t, n, payout, ancestor, 1, fastSolveSeconds)

	// A target the rule did not produce, declared instead of derived — the
	// R4-H1 shape wire.md §9 names: a validator MUST reject a header whose
	// declared target is not the one the rule derives from the preceding
	// window, and until this fix ConsiderBranch was the one path that did not.
	branch.Blocks[0].Header.Target = branch.Blocks[0].Header.Target.SatAdd(u256.One)

	_, err := n.chain.ConsiderBranch(branch)
	if !errors.Is(err, chain.ErrForgedTarget) {
		t.Fatalf("got %v, want ErrForgedTarget", err)
	}
	if n.chain.Tip().ID() != tipBefore {
		t.Fatal("the chain moved despite refusing a branch with a forged target")
	}
}

// TestConsiderBranchRejectsABackdatedBlock is the regression pin for the
// timestamp rules' fork-choice slice: a branch header at or below the median
// time of its predecessors must be refused here too, closing the gap the
// gossip- and sync-path fix left open — a backdated block could still become
// canonical through the orphan pool even after the gossip and sync paths
// refused it.
func TestConsiderBranchRejectsABackdatedBlock(t *testing.T) {
	p := devnetEasy()
	payout := key(t, 1).Persistent()
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)
	n.mine(t, 3)
	tipBefore := n.chain.Tip().ID()

	ancestor := ancestorAt(t, n, 1)
	branch := buildBranch(t, n, payout, ancestor, 1, fastSolveSeconds)

	// Far below any real median: genesis_time alone is a large Unix
	// timestamp, so 1 second past the epoch is below the median of any
	// window this chain could present.
	branch.Blocks[0].Header.Time = 1

	_, err := n.chain.ConsiderBranch(branch)
	if !errors.Is(err, chain.ErrBadTime) {
		t.Fatalf("got %v, want ErrBadTime", err)
	}
	if n.chain.Tip().ID() != tipBefore {
		t.Fatal("the chain moved despite refusing a backdated branch block")
	}
}

// TestConsiderBranchRejectsAForgedFirstBlockHeight reproduces the exact
// probe review found: mine a long real chain, build an otherwise-honest
// branch a few blocks back, and forge the declared height of every block in
// it by the same constant offset — down to a small height that, if it were
// ever folded, would land in an earlier, higher-emission era. The offset is
// applied uniformly and ParentIDs are re-linked afterward (a block's id is
// a hash of its whole header, Height included), so the branch is internally
// consistent — the *only* thing wrong with it is that its first block's
// height does not match the real ancestor's height + 1. Before this fix
// that was exactly the gap: internal linkage (block i+1 one above block i)
// was checked from index 1 onward, and depthOf/ConsiderBranch's ancestor
// lookup keyed on the declared ParentID rather than on Height, so nothing
// ever compared the first block against the ancestor it claims to extend.
func TestConsiderBranchRejectsAForgedFirstBlockHeight(t *testing.T) {
	p := devnetEasy()
	payout := key(t, 1).Persistent()
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)
	n.mine(t, 200)
	tipBefore := n.chain.Tip().ID()
	heightBefore := n.chain.Height()

	ancestor := ancestorAt(t, n, 2)
	branch := buildBranch(t, n, payout, ancestor, 2, fastSolveSeconds)

	const forgedFirstHeight = 4
	offset := branch.Blocks[0].Header.Height - forgedFirstHeight
	parent := ancestor.ID()
	for _, blk := range branch.Blocks {
		blk.Header.Height -= offset
		blk.Header.ParentID = parent
		parent = blk.Header.ID()
	}

	_, err := n.chain.ConsiderBranch(branch)
	if err == nil {
		t.Fatal("a branch whose first block declares a forged height was accepted")
	}
	tipAfter := n.chain.Tip().ID()
	if tipAfter != tipBefore || n.chain.Height() != heightBefore {
		t.Fatalf("the chain moved despite refusing a forged-height branch: "+
			"tip %x at height %d, want %x at %d",
			tipAfter[:8], n.chain.Height(), tipBefore[:8], heightBefore)
	}
}
