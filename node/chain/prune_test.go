package chain_test

import (
	"errors"
	"testing"

	"zycord/core/params"
	"zycord/node/chain"
	"zycord/node/storage"
)

// Undo-log pruning.
//
// docs/ARCHITECTURE.md §14 requires undo beyond UNDO_DEPTH to be pruned; these
// tests pin that it actually happens, that it stops at exactly the right
// boundary (a reorg at depth == UNDO_DEPTH must still work; TestReorgBeyond-
// TheUndoHorizonIsRefused already pins the other side, depth > UNDO_DEPTH),
// that it survives a restart, and that it is atomic with the commit that
// makes it safe.
//
// The boundary these pin carries one block of slack: pruning runs
// through tip - UNDO_DEPTH - 1, so UNDO_DEPTH+1 logs are retained and the
// deepest log any admissible reorg can need has one spare height below it.
// See pruneUndoLocked's doc comment for why, and
// TestPruningKeepsOneBlockOfSlackBelowTheDeepestAdmissibleReorg for the
// property itself.

// smallUndoParams returns devnet with a small, test-reachable UNDO_DEPTH.
func smallUndoParams() *params.Params {
	p := devnetEasy()
	p.UndoDepth = 4
	return p
}

// TestUndoLogsArePrunedBeyondTheHorizon: once the tip is more than UNDO_DEPTH
// blocks past a height, that height's undo log must be gone — the exact
// behaviour docs/ARCHITECTURE.md §14 mandates and that was, at the time,
// entirely absent.
func TestUndoLogsArePrunedBeyondTheHorizon(t *testing.T) {
	p := smallUndoParams()
	n := openNode(t, t.TempDir(), p, key(t, 1).Persistent())
	defer n.close(t)

	n.mine(t, 10) // tip height 10, horizon = 10 - 4 - 1 = 5 (one block of slack)

	for h := uint64(0); h <= 5; h++ {
		if n.chain.UndoLogPresentForTest(h) {
			t.Errorf("height %d: undo log still present, want pruned (tip=10, undo_depth=4)", h)
		}
	}
	for h := uint64(6); h <= 10; h++ {
		if !n.chain.UndoLogPresentForTest(h) {
			t.Errorf("height %d: undo log missing, want retained (within the horizon)", h)
		}
	}
}

// TestUndoPruningStopsAtExactlyTheRetainedCount: the retained set must be
// exactly UNDO_DEPTH+1 entries — not UNDO_DEPTH (which is the provably tight
// count, and the one this deliberately does not use: see
// pruneUndoLocked's doc comment for the block of slack), not fewer (which
// would make a depth==UNDO_DEPTH reorg fail with data that should exist), and
// not more (which would mean the pruner is not keeping up).
func TestUndoPruningStopsAtExactlyTheRetainedCount(t *testing.T) {
	p := smallUndoParams()
	n := openNode(t, t.TempDir(), p, key(t, 1).Persistent())
	defer n.close(t)

	n.mine(t, 50)

	present := 0
	for h := uint64(0); h <= n.chain.Height(); h++ {
		if n.chain.UndoLogPresentForTest(h) {
			present++
		}
	}
	if want := int(p.UndoDepth) + 1; present != want {
		t.Fatalf("retained %d undo logs at tip %d with undo_depth %d, want exactly %d",
			present, n.chain.Height(), p.UndoDepth, want)
	}
}

// TestPruningKeepsOneBlockOfSlackBelowTheDeepestAdmissibleReorg is the whole
// of the pruning/admission margin as a property.
//
// considerBranchLocked admits depth == UNDO_DEPTH, and unwinding that reorg
// reads undo logs down to tip - UNDO_DEPTH + 1. Pruning through
// tip - UNDO_DEPTH would leave that log present and the next one below it
// gone: tight, correct, and with nothing between "right" and "wrong by one".
// This pins the slack instead — the log one *below* the deepest any admissible
// reorg can ask for is still there — and pins that it is exactly one block, so
// the slack cannot quietly grow into "pruning stopped working". Removing the
// -1 from pruneUndoLocked's horizon fails the middle check here; dropping the
// horizon another block fails the last one.
func TestPruningKeepsOneBlockOfSlackBelowTheDeepestAdmissibleReorg(t *testing.T) {
	p := smallUndoParams()
	n := openNode(t, t.TempDir(), p, key(t, 1).Persistent())
	defer n.close(t)

	n.mine(t, 20) // well past the horizon; pruning has run many times

	tip := n.chain.Height()
	deepest := tip - p.UndoDepth + 1 // the deepest log a depth==UNDO_DEPTH reorg reads
	if !n.chain.UndoLogPresentForTest(deepest) {
		t.Fatalf("height %d's undo log is gone, but a depth==%d reorg from tip %d needs it",
			deepest, p.UndoDepth, tip)
	}
	if slack := deepest - 1; !n.chain.UndoLogPresentForTest(slack) {
		t.Fatalf("height %d's undo log is gone: pruning meets admission with zero margin, "+
			"which is what the block of slack buys one block away from (tip %d, undo_depth %d)",
			slack, tip, p.UndoDepth)
	}
	if beyond := deepest - 2; n.chain.UndoLogPresentForTest(beyond) {
		t.Fatalf("height %d's undo log survived: the slack is one block, not two — "+
			"anything more is a pruner that has stopped keeping up (tip %d, undo_depth %d)",
			beyond, tip, p.UndoDepth)
	}
	if pruned, ok := n.chain.UndoPrunedThroughForTest(); !ok || pruned != deepest-2 {
		t.Fatalf("metaUndoPruned is %d (ok=%v), want %d: the bookmark is inclusive and must "+
			"name the highest height the slack lets go", pruned, ok, deepest-2)
	}
}

// TestReorgAtExactlyTheHorizonSucceedsAfterPruning proves pruning does not
// over-delete: a reorg whose depth is exactly UNDO_DEPTH must still find every
// undo log it needs, even after many blocks' worth of pruning has run.
// TestReorgBeyondTheUndoHorizonIsRefused already pins the other edge
// (depth > UNDO_DEPTH is refused); this is the boundary that must keep
// working, not merely keep refusing.
func TestReorgAtExactlyTheHorizonSucceedsAfterPruning(t *testing.T) {
	p := smallUndoParams()
	payout := key(t, 1).Persistent()
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)

	n.mine(t, 20) // well past the horizon; pruning has run several times over

	ancestor := ancestorAt(t, n, p.UndoDepth) // depth == UNDO_DEPTH exactly
	branch := buildBranch(t, n, payout, ancestor, int(p.UndoDepth)+1, fastSolveSeconds)

	reorg, err := n.chain.ConsiderBranch(branch)
	if err != nil {
		t.Fatalf("a depth==UNDO_DEPTH reorg was refused after pruning: %v", err)
	}
	if !reorg.Adopted {
		t.Fatal("the heavier branch was not adopted")
	}
}

// TestReorgLongerThanTheHorizonDoesNotLeakTheOverlappingHeight is a
// regression test for a completeness bug found in review: when a reorg's
// incoming branch is longer than UNDO_DEPTH and at least one block is rolled
// back, the new pruning horizon can land on a height that is *both* the old
// chain's just-undone block and the new chain's freshly applied one.
// pruneUndoLocked used to resolve that height through storage's stale,
// pre-batch view of the height index — finding the *old* chain's id there
// (a harmless re-delete; the undone-blocks loop already deletes it) instead
// of the *new* chain's id this same batch is writing at that height. Because
// metaUndoPruned advanced past the height regardless, the new chain's undo
// log there was never targeted for deletion, and — since every later prune
// call starts strictly after metaUndoPruned — could never be reconsidered:
// retained forever, silently defeating pruning along exactly the path that
// matters. This is not contrived: node/sync's extendToCover deliberately
// sizes a resync candidate branch as depth + UNDO_DEPTH, longer than what it
// replaces, to cover exactly this shape of reorg.
func TestReorgLongerThanTheHorizonDoesNotLeakTheOverlappingHeight(t *testing.T) {
	p := smallUndoParams()
	payout := key(t, 1).Persistent()
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)

	n.mine(t, 10) // tip height 10; pruning has already run (horizon 10-4-1=5)

	// Fork one block back — rolling back exactly the old height-10 block —
	// with a branch longer than UNDO_DEPTH, so the new horizon reaches back
	// into the range this same batch is applying. Height 10 is simultaneously
	// the old chain's rolled-back block and the new chain's freshly applied
	// one: the exact collision.
	ancestor := ancestorAt(t, n, 1) // height 9
	branchLen := int(p.UndoDepth) + 2
	branch := buildBranch(t, n, payout, ancestor, branchLen, fastSolveSeconds)

	reorg, err := n.chain.ConsiderBranch(branch)
	if err != nil {
		t.Fatalf("the longer, heavier branch was refused: %v", err)
	}
	if !reorg.Adopted {
		t.Fatal("the longer, heavier branch was not adopted")
	}

	newTip := n.chain.Height()
	horizon := newTip - p.UndoDepth - 1 // one block of slack
	if horizon < 10 {
		t.Fatalf("setup: horizon %d does not reach the collision height 10 (new tip %d)", horizon, newTip)
	}

	// The bug's symptom: the new chain's undo log at the overlapping height
	// is retained forever instead of being pruned like every other height at
	// or below the horizon.
	if n.chain.UndoLogPresentForTest(10) {
		t.Fatal("height 10's undo log (the new chain's block, already beyond the new horizon) " +
			"was not pruned immediately after the reorg — the overlapping-height leak")
	}

	// And it stays correctly pruned, not merely delayed, as the chain keeps
	// moving well past it — the bookmark must not have quietly skipped it.
	// Extended with buildBranch/ConsiderBranch rather than n.mine: the
	// reorg above adopted a branch mined at harderTarget(), which LWMA folds
	// into the difficulty it now expects next, and the plain miner's bounded
	// attempt budget cannot clear that — exactly as the existing reorg tests
	// in this file already extend branches without a real PoW search, since
	// fold-level validity does not check a header's target against LWMA (that
	// happens in node/sync's header-sequence validation, not core/fold).
	tip := n.chain.Tip()
	extension := buildBranch(t, n, payout, tip, 10, fastSolveSeconds)
	if _, err := n.chain.ConsiderBranch(extension); err != nil {
		t.Fatalf("extending the chain past the collision height failed: %v", err)
	}
	if n.chain.UndoLogPresentForTest(10) {
		t.Fatal("height 10's undo log resurfaced, or was never really gone")
	}
	pruned, ok := n.chain.UndoPrunedThroughForTest()
	if !ok || pruned < 10 {
		t.Fatalf("metaUndoPruned is %d (ok=%v), want at least 10: a leaked height must not "+
			"be silently skipped by the bookmark", pruned, ok)
	}
}

// TestUndoPruningSurvivesRestart: the pruned set, and the bookmark of how far
// pruning has progressed, must not be an artifact of the in-memory Chain —
// closing and reopening must neither resurrect deleted entries nor rescan and
// re-derive them from scratch in a way that disagrees with what is on disk.
func TestUndoPruningSurvivesRestart(t *testing.T) {
	p := smallUndoParams()
	dir := t.TempDir()
	payout := key(t, 1).Persistent()

	n := openNode(t, dir, p, payout)
	n.mine(t, 15)
	prunedBefore, ok := n.chain.UndoPrunedThroughForTest()
	if !ok {
		t.Fatal("setup: no pruning recorded after 15 blocks with undo_depth 4")
	}
	n.close(t)

	again := openNode(t, dir, p, payout)
	defer again.close(t)

	prunedAfter, ok := again.chain.UndoPrunedThroughForTest()
	if !ok || prunedAfter != prunedBefore {
		t.Fatalf("pruning bookmark did not survive restart: before=%d after=(%d,%v)",
			prunedBefore, prunedAfter, ok)
	}
	for h := uint64(0); h <= prunedAfter; h++ {
		if again.chain.UndoLogPresentForTest(h) {
			t.Fatalf("height %d: pruned entry resurrected by reopening", h)
		}
	}

	// The chain is still fully usable: mining and an in-horizon reorg both
	// still work post-restart.
	again.mine(t, 1)
	ancestor := ancestorAt(t, again, p.UndoDepth)
	branch := buildBranch(t, n, payout, ancestor, int(p.UndoDepth)+1, fastSolveSeconds)
	if _, err := again.chain.ConsiderBranch(branch); err != nil {
		t.Fatalf("a depth==UNDO_DEPTH reorg failed after a restart mid-pruning: %v", err)
	}
}

// TestUndoPruningIsCrashAtomicWithTheCommit: pruning rides the same batch as
// the block commit that makes it safe. A crash mid-write must therefore never
// land "the tip moved but the stale undo log did not get deleted" or its
// opposite — only "neither happened" (torn tail, discarded on replay) or
// "both happened" (durable). storage.Store already proves this at the record
// level; this pins it at the level the pruner actually cares about.
func TestUndoPruningIsCrashAtomicWithTheCommit(t *testing.T) {
	p := smallUndoParams()
	payout := key(t, 1).Persistent()

	// Mine one store up to just short of the block whose commit will newly
	// cross the pruning horizon, so the crashed write is exactly the one
	// pruning statement under test.
	dir := t.TempDir()
	n := openNode(t, dir, p, payout)
	n.mine(t, 4) // horizon has not yet passed height 0 (tip=4, undo_depth=4)
	if _, ok := n.chain.UndoPrunedThroughForTest(); ok {
		t.Fatal("setup: pruning ran earlier than expected")
	}
	if !n.chain.UndoLogPresentForTest(0) {
		t.Fatal("setup: height 0's undo log is already gone before the boundary commit")
	}
	n.close(t)

	// Reopen with a fault injector that severs the very next write — the
	// commit of block 5, which is the first commit whose batch includes any
	// prune at all (horizon = 5 - 4 - 1 = 0, so height 0 and only height 0 is
	// pruned; the block of slack is why height 1 waits for block 6).
	var armed bool
	crashDir := dir
	crashed := openNodeWith(t, crashDir, p, payout, storage.Options{
		FaultInjector: func(record []byte) ([]byte, error) {
			if armed {
				return record, nil
			}
			armed = true
			cut := len(record) / 2
			return record[:cut], errors.New("simulated crash mid-write")
		},
	})
	if _, _, err := crashed.miner.MineOne(1 << 20); err == nil {
		t.Fatal("expected the injected fault to fail this commit")
	}
	crashed.chain.Close() // best-effort; the store may already be poisoned by the tear

	// Reopen clean and check which of the two consistent outcomes landed.
	recovered := openNode(t, crashDir, p, payout)
	defer recovered.close(t)

	if recovered.chain.Height() == 5 {
		// The write actually completed durably (the injector's cut still
		// decoded, or landed before the fsync observed the error) — then
		// pruning must have landed too.
		if recovered.chain.UndoLogPresentForTest(0) {
			t.Fatal("tip advanced to 5 but height 0 was not pruned: torn state")
		}
	} else if recovered.chain.Height() == 4 {
		// The torn write was discarded on replay — the tip must still be at
		// 4, and pruning (which only ever happens in the *same* batch as the
		// commit that advances the tip) must not have happened either.
		if !recovered.chain.UndoLogPresentForTest(0) {
			t.Fatal("tip rolled back to 4 but height 0's undo log was pruned anyway: torn state")
		}
	} else {
		t.Fatalf("recovered at height %d, want 4 (discarded) or 5 (landed)", recovered.chain.Height())
	}

	// And the chain keeps working either way.
	recovered.mine(t, 1)
}

// TestARefusedDeepReorgLeavesTheStateWhereItFoundIt is the other half of the
// edge pruning deliberately leaves open (see pruneUndoLocked's doc comment): a
// reorg can ask for an undo log at a height already pruned, because the tip
// can *drop* in height (TestMoreWorkWinsOverMoreBlocks) while the pruning
// bookmark, correctly, never walks backwards. The claim attached to that
// acceptance is that such a reorg "fails loudly ... a refusal, not silent
// corruption" — this test is what makes that claim checkable rather than
// asserted, and it is only reachable at all because pruning exists: before
// pruning existed no undo log within UNDO_DEPTH was ever missing.
//
// What must hold after the refusal is the whole of the reorg contract: the
// tip is where it was, and the in-memory state is what the tip's own
// committed state root says it is. A partially-unwound state that still
// claims the old tip would be exactly the silent corruption the acceptance
// promises does not happen, and every later block would fold onto it.
// dropUndoParams returns devnet with an UNDO_DEPTH small enough to reach in a
// test, but large enough that a *legal* reorg can still lower the tip.
//
// That floor is real and worth stating: the tip drops only when a shorter
// branch out-works a longer one, and a branch's target is now re-derived
// rather than declared, so the only way to buy work is faster solve times
// feeding LWMA. LWMA averages over DifficultyWindow (90) blocks, so a few fast
// blocks barely move it and the advantage accrues with branch length — while
// considerBranchLocked caps the fork at UNDO_DEPTH.
//
// Measured against the real pow.NextTarget, largest *legal* tip drop by
// UNDO_DEPTH (fork at the depth cap, shortest branch that still out-works it):
//
//	UNDO_DEPTH    4 ->   0 blocks
//	UNDO_DEPTH    8 ->   1 block
//	UNDO_DEPTH   16 ->   7 blocks  (replacing 16 with 9)
//	UNDO_DEPTH   32 ->  20 blocks  (replacing 32 with 12)
//	UNDO_DEPTH   64 ->  50 blocks  (replacing 64 with 14)
//	UNDO_DEPTH  128 -> 112 blocks  (replacing 128 with 16)
//
// The winning branch grows only logarithmically (9, 12, 14, 16) while the fork
// depth doubles, so the drop approaches UNDO_DEPTH itself. Read that as the
// cost it is, not as reassurance: the drop, less the one block of slack
// pruning buys, *is* the width of the admissible-but-pruned gap that pruneUndoLocked's
// accepted edge leaves open, so the gap scales up with UNDO_DEPTH rather than
// away — the slack is a constant against a term that grows. Devnet ships 128 and
// mainnet 1024. This uses 16 — the smallest value that makes the shape
// reachable in a test that stays fast.
func dropUndoParams() *params.Params {
	p := devnetEasy()
	p.UndoDepth = 16
	return p
}

// TestARefusedDeepReorgLeavesTheStateWhereItFoundIt is the other half of the
// edge pruning deliberately leaves open (see pruneUndoLocked's doc comment): a
// reorg can ask for an undo log at a height already pruned, because the tip
// can *drop* in height while the pruning bookmark, correctly, never walks
// backwards. The claim attached to that acceptance is that such a reorg "fails
// loudly ... a refusal, not silent corruption" — this test is what makes the
// claim checkable rather than asserted, and it is only reachable at all
// because pruning exists: before it, no undo log within UNDO_DEPTH was ever
// missing, which is why the unwind-loop half-rollback could be triaged as
// needing "a pre-existing store inconsistency".
//
// What must hold after the refusal is the whole of the reorg contract: the tip
// is where it was, and the in-memory state is what the tip's own committed
// state root says it is. A partially-unwound state that still claims the old
// tip is exactly the silent corruption the acceptance promises does not
// happen, and every later block would fold onto it.
func TestARefusedDeepReorgLeavesTheStateWhereItFoundIt(t *testing.T) {
	p := dropUndoParams()
	payout := key(t, 1).Persistent()
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)

	// A settled chain: 60 blocks, pruned through 60 - 16 - 1 = 43.
	// Fifteen blocks replaced by thirteen faster ones, 60 -> 58: the tip still
	// DROPS in height, which is the whole point of this fixture, while the
	// branch genuinely outweighs what it replaces.
	//
	// This was 15 -> 9 while NextTarget normalised against the window's last
	// target. That rule compounded each retarget onto its own previous output,
	// so a run of minimum-gap blocks drove the target down far faster than the
	// hashrate behind them justified, and nine of them could out-weigh fifteen.
	// Normalising against the window's average is deliberately damped —
	// that damping is what makes the controller stable — so the same nine
	// blocks now carry ~0.69x the work they replace. Twelve are still short at
	// ~0.97x; thirteen are the first that clear it, at ~1.07x, and fourteen
	// give ~1.17x. Thirteen is chosen rather than fourteen because the tip must
	// still DROP — that is the property this fixture exists for — and the
	// margin is thin enough to be worth naming: a change that damps the
	// controller further would need this constant revisited, and the
	// Work().Gt() check below is what says so.
	const mined, replacing, with = 60, 15, 13
	n.mine(t, mined)

	// Drop the tip: fifteen blocks replaced by thirteen faster ones, 60 -> 58.
	branch := buildBranch(t, n, payout, ancestorAt(t, n, replacing), with, fastSolveSeconds)
	if !branch.Work().Gt(worthOf(t, n, replacing)) {
		t.Fatal("setup: the challenger does not carry more work than what it replaces")
	}
	if reorg, err := n.chain.ConsiderBranch(branch); err != nil || !reorg.Adopted {
		t.Fatalf("setup: the shorter, heavier branch was not adopted: (%v, %v)", reorg.Adopted, err)
	}

	newTip := uint64(mined - replacing + with) // 58
	if n.chain.Height() != newTip {
		t.Fatalf("setup: height is %d, want %d (the tip must have dropped)", n.chain.Height(), newTip)
	}
	bookmark := uint64(mined) - p.UndoDepth - 1 // 43 (one block of slack)
	pruned, ok := n.chain.UndoPrunedThroughForTest()
	if !ok || pruned != bookmark {
		t.Fatalf("setup: metaUndoPruned is %d (ok=%v), want %d", pruned, ok, bookmark)
	}
	// The gap this test needs: the depth check will now admit a reorg reaching
	// back to 58 - 16 = 42, but everything at or below 43 was already pruned.
	// The margin is one height (42 vs 43) where it used to be six, because the
	// branch that lowers the tip is now thirteen blocks rather than nine — see
	// the constant above — and because the block of slack retains one more
	// log, narrowing the admissible-but-pruned band by one more. It is still a
	// real gap, and the check below fails loudly rather than silently if a
	// future change closes it.
	if admitted := newTip - p.UndoDepth; pruned <= admitted {
		t.Fatalf("setup: nothing the depth check admits was pruned (bookmark %d, admitted floor %d)",
			pruned, admitted)
	}

	tipBefore := n.chain.Tip().ID()
	heightBefore := n.chain.Height()
	rootBefore := n.chain.StateRoot()
	if stored := n.chain.StoredStateRoot(); rootBefore != stored {
		t.Fatalf("setup: live state root %x already disagrees with the committed one %x",
			rootBefore, stored)
	}

	// A reorg at depth == UNDO_DEPTH from the *current* tip, which
	// considerBranchLocked therefore admits — but which has to unwind through
	// height 44, pruned back when the tip was 60. It gets several blocks in
	// before it discovers the gap, which is what makes an unrestored return
	// observable at all.
	deep := buildBranch(t, n, payout, ancestorAt(t, n, p.UndoDepth), int(p.UndoDepth)+4, fastSolveSeconds)
	reorg, err := n.chain.ConsiderBranch(deep)
	if err == nil {
		t.Fatal("a reorg through a pruned undo log was accepted; it must be refused")
	}
	if reorg.Adopted {
		t.Fatal("the refused reorg reports itself as adopted")
	}
	// The unwind walks down from 58 and finds every log present until height
	// 43 — which is the bookmark itself. So this is also the *boundary* case of
	// the comparison in missingUndoCauseLocked: metaUndoPruned is inclusive, the
	// height it names is pruned, and an off-by-one here would hand the operator
	// the diagnosis for a damaged disk in the one case they are likeliest to
	// meet. TestTheUndoBookmarkSeparatesADeliberatePruneFromADataFault drives
	// the height one above this one and must get the other answer.
	if !errors.Is(err, chain.ErrPrunedUndoHorizon) || !errors.Is(err, chain.ErrLocal) {
		t.Fatalf("refusal is %v, want ErrLocal wrapping ErrPrunedUndoHorizon: the log at the "+
			"bookmark was deleted on purpose while the tip stood higher, so the operator needs "+
			"the resync instruction rather than a pointer at a healthy disk", err)
	}
	// Still ErrLocal, and still not the sender's doing: the fix must not widen
	// into scoring, or a node with a retreated horizon starts fining the peers
	// that delivered the branch which exposed it.
	if errors.Is(err, chain.ErrUndoUnavailable) {
		t.Fatalf("refusal is %v, want it NOT to report a damaged store: this store is healthy "+
			"and no repair can bring a deliberately pruned log back", err)
	}

	if got := n.chain.Tip().ID(); got != tipBefore {
		t.Fatalf("tip moved to %x on a refused reorg, want %x", got, tipBefore)
	}
	if got := n.chain.Height(); got != heightBefore {
		t.Fatalf("height is %d on a refused reorg, want %d", got, heightBefore)
	}
	if got := n.chain.StateRoot(); got != rootBefore {
		t.Fatalf("live state root is %x after a refused reorg, want %x: the partial unwind was "+
			"not put back, so the node now claims a tip whose state it no longer holds", got, rootBefore)
	}
	if got, stored := n.chain.StateRoot(), n.chain.StoredStateRoot(); got != stored {
		t.Fatalf("live state root %x disagrees with the committed state root %x", got, stored)
	}

	// And the chain is still usable: a refusal is a refusal, not a wedge. The
	// extension goes through buildBranch rather than n.mine because the branch
	// adopted above was timed at fastSolveSeconds, which is exactly what makes
	// LWMA demand a harder target next — more than the dev miner's bounded
	// attempt budget will find.
	on := buildBranch(t, n, payout, n.chain.Tip(), 1, fastSolveSeconds)
	if _, err := n.chain.ConsiderBranch(on); err != nil {
		t.Fatalf("extending the chain after a refused reorg: %v", err)
	}
	if got := n.chain.Height(); got != heightBefore+1 {
		t.Fatalf("height is %d after extending, want %d", got, heightBefore+1)
	}
	if got, stored := n.chain.StateRoot(), n.chain.StoredStateRoot(); got != stored {
		t.Fatalf("state root %x disagrees with the committed root %x after extending", got, stored)
	}
}

// TestTheUndoBookmarkSeparatesADeliberatePruneFromADataFault is the other
// direction of the deliberate-prune / data-fault comparison, and it is
// deliberately the same fixture as
// TestARefusedDeepReorgLeavesTheStateWhereItFoundIt with exactly one thing
// changed: which height the unwind first finds missing.
//
// There the first missing log is at 43, the bookmark itself, and the answer
// must be ErrPrunedUndoHorizon. Here height 44's log — one above the bookmark,
// retained and then destroyed — goes missing first, and the answer must still
// be ErrUndoUnavailable, because nothing pruned it and a store that lost it is
// genuinely damaged.
//
// Both cases reach the identical line in switchTo with an identical symptom.
// The bookmark is the only thing that tells them apart, so a change that
// collapsed missingUndoCauseLocked into either constant would still pass one of
// these two tests and fail the other. That is the point of the pair: the test
// above alone would let the comparison be replaced by "always pruned", which is
// the same class of defect one level up — an operator instruction attached to a
// case that does not need it.
//
// This says nothing about undo logs being missing for only these two reasons.
// It says this comparison separates these two reachable cases, at the boundary,
// in both directions (PROTOCOL rule 21).
func TestTheUndoBookmarkSeparatesADeliberatePruneFromADataFault(t *testing.T) {
	p := dropUndoParams()
	payout := key(t, 1).Persistent()
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)

	// Identical to the test above: 60 blocks pruned through 43, then fifteen
	// replaced by thirteen faster ones so the tip DROPS to 58 and the horizon
	// retreats while the bookmark correctly stays put.
	const mined, replacing, with = 60, 15, 13
	n.mine(t, mined)

	branch := buildBranch(t, n, payout, ancestorAt(t, n, replacing), with, fastSolveSeconds)
	if reorg, err := n.chain.ConsiderBranch(branch); err != nil || !reorg.Adopted {
		t.Fatalf("setup: the shorter, heavier branch was not adopted: (%v, %v)", reorg.Adopted, err)
	}
	newTip := uint64(mined - replacing + with) // 58
	if n.chain.Height() != newTip {
		t.Fatalf("setup: height is %d, want %d (the tip must have dropped)", n.chain.Height(), newTip)
	}
	bookmark := uint64(mined) - p.UndoDepth - 1 // 43 (one block of slack)
	pruned, ok := n.chain.UndoPrunedThroughForTest()
	if !ok || pruned != bookmark {
		t.Fatalf("setup: metaUndoPruned is %d (ok=%v), want %d", pruned, ok, bookmark)
	}

	// The one difference from the test above. Height 44 sits one *above* the
	// bookmark, so pruning never touched it and its log is present — until this
	// destroys it, which is what a damaged store looks like. The unwind walks
	// down from 58 and now meets 44 before it ever reaches 43, so the height
	// that decides the diagnosis is 44 rather than 43.
	const fault = 44
	if fault <= int(bookmark) {
		t.Fatalf("setup: height %d is not above the bookmark %d, so this test would be "+
			"driving the same branch as the one above it", fault, bookmark)
	}
	if !n.chain.UndoLogPresentForTest(fault) {
		t.Fatalf("setup: height %d has no undo log to destroy", fault)
	}
	if err := n.chain.CorruptForTest("undo", fault, nil); err != nil {
		t.Fatalf("setup: deleting the undo log at height %d: %v", fault, err)
	}

	tipBefore := n.chain.Tip().ID()
	heightBefore := n.chain.Height()
	rootBefore := n.chain.StateRoot()

	// The same admissible-but-doomed reorg the test above uses: depth exactly
	// UNDO_DEPTH from the current tip, so the gate lets it through.
	deep := buildBranch(t, n, payout, ancestorAt(t, n, p.UndoDepth), int(p.UndoDepth)+4, fastSolveSeconds)
	reorg, err := n.chain.ConsiderBranch(deep)
	if err == nil {
		t.Fatal("a reorg through a destroyed undo log was accepted; it must be refused")
	}
	if reorg.Adopted {
		t.Fatal("the refused reorg reports itself as adopted")
	}
	if !errors.Is(err, chain.ErrUndoUnavailable) || !errors.Is(err, chain.ErrLocal) {
		t.Fatalf("refusal is %v, want ErrLocal wrapping ErrUndoUnavailable: height %d is above "+
			"the bookmark %d, so nothing pruned it and the store really is damaged",
			err, fault, bookmark)
	}
	if errors.Is(err, chain.ErrPrunedUndoHorizon) {
		t.Fatalf("refusal is %v, want it NOT to claim a deliberate prune: height %d is above "+
			"the bookmark %d, and telling the operator to resync hides a failing disk",
			err, fault, bookmark)
	}

	// A refusal is still a refusal on this branch too: the unwind loop's contract
	// does not depend on which diagnosis was chosen.
	if got := n.chain.Tip().ID(); got != tipBefore {
		t.Fatalf("tip moved to %x on a refused reorg, want %x", got, tipBefore)
	}
	if got := n.chain.Height(); got != heightBefore {
		t.Fatalf("height is %d on a refused reorg, want %d", got, heightBefore)
	}
	if got := n.chain.StateRoot(); got != rootBefore {
		t.Fatalf("live state root is %x after a refused reorg, want %x: the partial unwind was "+
			"not put back", got, rootBefore)
	}
	if got, stored := n.chain.StateRoot(), n.chain.StoredStateRoot(); got != stored {
		t.Fatalf("live state root %x disagrees with the committed state root %x", got, stored)
	}
}

// TestATipDroppingReorgNeitherLeaksNorOverPrunes pins what the monotone
// pruning bookmark does when the tip height *falls*: it must not delete undo
// logs the shorter chain still needs (over-pruning), and it must not strand
// heights below itself as permanently unprunable (the leak class the
// overlapping-height fix above closed for the other shape — there the height
// was inside the batch, here it is below the bookmark entirely).
func TestATipDroppingReorgNeitherLeaksNorOverPrunes(t *testing.T) {
	p := dropUndoParams()
	payout := key(t, 1).Persistent()
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)

	// Fifteen blocks replaced by thirteen faster ones, 60 -> 58: the tip still
	// DROPS in height, which is the whole point of this fixture, while the
	// branch genuinely outweighs what it replaces.
	//
	// This was 15 -> 9 while NextTarget normalised against the window's last
	// target. That rule compounded each retarget onto its own previous output,
	// so a run of minimum-gap blocks drove the target down far faster than the
	// hashrate behind them justified, and nine of them could out-weigh fifteen.
	// Normalising against the window's average is deliberately damped —
	// that damping is what makes the controller stable — so the same nine
	// blocks now carry ~0.69x the work they replace. Twelve are still short at
	// ~0.97x; thirteen are the first that clear it, at ~1.07x, and fourteen
	// give ~1.17x. Thirteen is chosen rather than fourteen because the tip must
	// still DROP — that is the property this fixture exists for — and the
	// margin is thin enough to be worth naming: a change that damps the
	// controller further would need this constant revisited, and the
	// Work().Gt() check below is what says so.
	const mined, replacing, with = 60, 15, 13
	n.mine(t, mined) // pruned through 43

	branch := buildBranch(t, n, payout, ancestorAt(t, n, replacing), with, fastSolveSeconds)
	if reorg, err := n.chain.ConsiderBranch(branch); err != nil || !reorg.Adopted {
		t.Fatalf("setup: the shorter, heavier branch was not adopted: (%v, %v)", reorg.Adopted, err)
	}
	newTip := uint64(mined - replacing + with) // 58
	if n.chain.Height() != newTip {
		t.Fatalf("setup: height is %d, want %d (the tip must have dropped)", n.chain.Height(), newTip)
	}

	// The horizon retreated with the tip. Nothing new may be deleted and
	// nothing already retained may be dropped: everything from the bookmark to
	// the new tip must still be there — including the reorg's own blocks,
	// several of which (heights 46..58) were written below where the bookmark
	// stands.
	bookmark := uint64(mined) - p.UndoDepth - 1 // 43 (one block of slack)
	for h := bookmark + 1; h <= newTip; h++ {
		if !n.chain.UndoLogPresentForTest(h) {
			t.Errorf("height %d's undo log went missing after a tip-lowering reorg", h)
		}
	}
	if pruned, ok := n.chain.UndoPrunedThroughForTest(); !ok || pruned != bookmark {
		t.Fatalf("metaUndoPruned is %d (ok=%v), want %d: the bookmark must not walk backwards, "+
			"and a retreating horizon must not advance it either", pruned, ok, bookmark)
	}

	// Growing back past the old high-water mark must resume pruning from the
	// bookmark and sweep every height the shorter chain re-populated — none of
	// them may be skipped because the bookmark once stood above them. Growing
	// to height 63 puts the horizon at 46, three past the bookmark and into
	// the reorg's own blocks, while stopping short of the epoch boundary at 64
	// (buildBranch cannot cross one: an epoch block needs a folded state root).
	//
	// Derived from the current tip rather than hard-coded, because the tip a
	// tip-lowering reorg lands on moved when the branch sizes above changed.
	// Height() is unsigned, so the subtraction is guarded rather than
	// wrapped — a fixture change that pushed the tip past 63 would otherwise
	// turn into a nonsense branch length instead of a readable failure.
	const growTo = 63
	if h := n.chain.Height(); h >= growTo {
		t.Fatalf("setup: the tip is already at %d, at or past the height %d this "+
			"step grows to (and the epoch boundary at %d): the branch sizes above "+
			"no longer leave room for this half of the test",
			h, growTo, p.EpochLength)
	}
	extension := buildBranch(t, n, payout, n.chain.Tip(),
		int(growTo-n.chain.Height()), fastSolveSeconds)
	if _, err := n.chain.ConsiderBranch(extension); err != nil {
		t.Fatalf("extending past the old high-water mark: %v", err)
	}

	tip := n.chain.Height()
	horizon := tip - p.UndoDepth - 1 // one block of slack
	if horizon <= bookmark {
		t.Fatalf("setup: horizon %d does not reach past the old bookmark %d (tip %d)",
			horizon, bookmark, tip)
	}
	for h := uint64(1); h <= horizon; h++ {
		if n.chain.UndoLogPresentForTest(h) {
			t.Errorf("height %d's undo log survived past the horizon %d (tip %d)", h, horizon, tip)
		}
	}
	present := 0
	for h := horizon + 1; h <= tip; h++ {
		if !n.chain.UndoLogPresentForTest(h) {
			t.Errorf("height %d's undo log is missing from inside the horizon", h)
		} else {
			present++
		}
	}
	if want := int(p.UndoDepth) + 1; present != want {
		t.Fatalf("retained %d undo logs at tip %d, want exactly %d", present, tip, want)
	}
	if pruned, ok := n.chain.UndoPrunedThroughForTest(); !ok || pruned != horizon {
		t.Fatalf("metaUndoPruned is %d (ok=%v), want %d", pruned, ok, horizon)
	}
}

// The remaining three exits of switchTo's unwind loop.
//
// TestARefusedDeepReorgLeavesTheStateWhereItFoundIt above covers the exit
// pruning makes reachable on healthy hardware — the missing undo log. There are
// three more, and each one mutates c.state via fold.UndoBlock on an
// earlier iteration before failing on a later one, so each must put memory
// back before reporting. They need a damaged local store to reach, which is
// exactly what the finding says ("requires a pre-existing store inconsistency"), and
// what CorruptForTest produces.
//
// The shape is shared: mine a chain, damage one key several blocks below the
// tip, then offer a heavier branch forking *below* the damage so the unwind
// has to walk through it. The unwind undoes the healthy blocks above the
// damage first — that is the state that must be restored — and only then
// hits the unreadable one.
func testUnwindExitRestoresState(t *testing.T, kind string, garbage []byte, wantErr error) {
	t.Helper()

	p := dropUndoParams()
	payout := key(t, 1).Persistent()
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)

	n.mine(t, 30)

	// Fork below the damage-to-be, with enough fast blocks to genuinely
	// out-work what it replaces, so the reorg is admitted and reaches the
	// unwind. The branch is built *before* the store is damaged: buildBranch
	// reads this chain's own headers to re-derive each target, so
	// corrupting first would break the fixture rather than the code path.
	const replacing, with = 5, 5
	branch := buildBranch(t, n, payout, ancestorAt(t, n, replacing), with, fastSolveSeconds)
	if !branch.Work().Gt(worthOf(t, n, replacing)) {
		t.Fatal("setup: the challenger does not carry more work than what it replaces")
	}

	// Damage a block three below the tip, so the unwind undoes heights 30 and
	// 29 into memory before reaching the unreadable record at 28.
	const damaged = 28
	if err := n.chain.CorruptForTest(kind, damaged, garbage); err != nil {
		t.Fatalf("setup: corrupting the %s record at height %d: %v", kind, damaged, err)
	}

	tipBefore := n.chain.Tip().ID()
	heightBefore := n.chain.Height()
	rootBefore := n.chain.StateRoot()
	if stored := n.chain.StoredStateRoot(); rootBefore != stored {
		t.Fatalf("setup: live state root %x already disagrees with the committed one %x",
			rootBefore, stored)
	}

	reorg, err := n.chain.ConsiderBranch(branch)
	if err == nil {
		t.Fatalf("a reorg through an unreadable %s record was accepted; it must be refused", kind)
	}
	if reorg.Adopted {
		t.Fatal("the refused reorg reports itself as adopted")
	}
	if !errors.Is(err, chain.ErrLocal) {
		t.Fatalf("refusal is %v, want it wrapped in ErrLocal: a damaged local store is this "+
			"node's own fault, and node/p2p must not score the sending peer for it", err)
	}
	if wantErr != nil && !errors.Is(err, wantErr) {
		t.Fatalf("refusal is %v, want it to wrap %v", err, wantErr)
	}

	// The whole point of the unwind-loop fix: a refusal must leave the node where
	// it found it.
	if got := n.chain.Tip().ID(); got != tipBefore {
		t.Fatalf("tip moved to %x on a refused reorg, want %x", got, tipBefore)
	}
	if got := n.chain.Height(); got != heightBefore {
		t.Fatalf("height is %d on a refused reorg, want %d", got, heightBefore)
	}
	if got := n.chain.StateRoot(); got != rootBefore {
		t.Fatalf("live state root is %x after a refused reorg, want %x: the partial unwind was "+
			"not put back, so the node now claims a tip whose state it no longer holds", got, rootBefore)
	}
	if got, stored := n.chain.StateRoot(), n.chain.StoredStateRoot(); got != stored {
		t.Fatalf("live state root %x disagrees with the committed state root %x", got, stored)
	}
}

// TestAnUnreadableBlockBodyLeavesTheStateWhereItFoundIt covers the exit at
// blockLocked: the body of a block being rolled back is gone.
func TestAnUnreadableBlockBodyLeavesTheStateWhereItFoundIt(t *testing.T) {
	// ErrNotFound, not ErrUndoUnavailable: the body is what is missing, and
	// this exit used to report the undo log instead, pointing an operator at
	// the wrong record.
	testUnwindExitRestoresState(t, "block", nil, chain.ErrNotFound)
}

// TestAnUndecodableUndoLogLeavesTheStateWhereItFoundIt covers the exit at
// decodeUndo: the undo log is present but its bytes are not a valid record.
// This is the case the finding pairs with the torn-write defects — a record that
// survived as bytes but not as meaning.
func TestAnUndecodableUndoLogLeavesTheStateWhereItFoundIt(t *testing.T) {
	testUnwindExitRestoresState(t, "undo", []byte{0xff, 0xff, 0xff, 0xff}, nil)
}

// TestAnUndecodableCanonicalHeaderIsRefusedBeforeAnythingIsUnwound pins where
// a damaged canonical *header* is actually caught, which is not the unwind
// loop at all: workSince walks the canonical headers to price the branch
// before switchTo is ever called, so the refusal happens with nothing yet
// undone and no state to put back.
//
// That ordering is why switchTo's headerLocked exit is unreachable through
// ConsiderBranch today. The exit is still wired through c.unwound rather than
// left bare, because "unreachable" here is a property of the order two other
// functions happen to run in — not an invariant this loop states or enforces —
// and the finding names it as one of the three. This test pins the ordering that makes
// it moot, so a future change that prices a branch without reading those
// headers first fails here rather than silently re-opening the hole.
func TestAnUndecodableCanonicalHeaderIsRefusedBeforeAnythingIsUnwound(t *testing.T) {
	p := dropUndoParams()
	payout := key(t, 1).Persistent()
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)

	n.mine(t, 30)

	const replacing, with = 5, 5
	branch := buildBranch(t, n, payout, ancestorAt(t, n, replacing), with, fastSolveSeconds)

	const damaged = 28
	if err := n.chain.CorruptForTest("header", damaged, []byte{0x00}); err != nil {
		t.Fatalf("setup: corrupting the header record at height %d: %v", damaged, err)
	}

	tipBefore := n.chain.Tip().ID()
	heightBefore := n.chain.Height()
	rootBefore := n.chain.StateRoot()

	reorg, err := n.chain.ConsiderBranch(branch)
	if err == nil {
		t.Fatal("a reorg priced against an undecodable canonical header was accepted")
	}
	if reorg.Adopted {
		t.Fatal("the refused reorg reports itself as adopted")
	}

	// Nothing was unwound, so the state must be untouched for the trivial
	// reason rather than the restored one — but it must still be untouched.
	if got := n.chain.Tip().ID(); got != tipBefore {
		t.Fatalf("tip moved to %x on a refused reorg, want %x", got, tipBefore)
	}
	if got := n.chain.Height(); got != heightBefore {
		t.Fatalf("height is %d on a refused reorg, want %d", got, heightBefore)
	}
	if got := n.chain.StateRoot(); got != rootBefore {
		t.Fatalf("live state root is %x after a refused reorg, want %x", got, rootBefore)
	}
	if got, stored := n.chain.StateRoot(), n.chain.StoredStateRoot(); got != stored {
		t.Fatalf("live state root %x disagrees with the committed state root %x", got, stored)
	}
}

// TestACorruptLocalHeaderIsNotChargedToThePeer is the peer-scoring half of the
// same rule the unwind exits above follow: a record this node wrote itself and
// can no longer decode is this node's fault.
//
// headerLocked wrapped the *missing* case in ErrNotFound but returned the
// *decode* case bare, so a single bit-rotted canonical header escaped
// ConsiderBranch unwrapped. node/p2p's OnBranch checks ErrNotBetter,
// ErrUnknownAncestor, ErrBeyondUndoHorizon and ErrLocal, then falls through to
// ScoreInvalidMessage — so an honest peer gossiping a legitimate competing
// branch was charged -20 for this node's disk, and at -100 banned. Five honest
// peers, and because a ban also drops a peer from sync candidacy, a node with
// one bad sector isolates itself from the network that could have repaired it
// — the exact outcome OnBranch's own comment says the ErrLocal check exists to
// prevent (found reviewing the unwind-loop fix).
func TestACorruptLocalHeaderIsNotChargedToThePeer(t *testing.T) {
	p := dropUndoParams()
	payout := key(t, 1).Persistent()
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)

	n.mine(t, 30)

	const replacing, with = 5, 5
	branch := buildBranch(t, n, payout, ancestorAt(t, n, replacing), with, fastSolveSeconds)

	// One bit-rotted canonical header, inside the range pricing the branch
	// has to read.
	if err := n.chain.CorruptForTest("header", 28, []byte{0x00}); err != nil {
		t.Fatalf("setup: corrupting the header at height 28: %v", err)
	}

	_, err := n.chain.ConsiderBranch(branch)
	if err == nil {
		t.Fatal("a branch priced against an undecodable local header was accepted")
	}
	if !errors.Is(err, chain.ErrLocal) {
		t.Fatalf("refusal is %v, want it wrapped in ErrLocal: node/p2p scores every error "+
			"that is not ErrLocal (or one of the three ordinary refusals) as ScoreInvalidMessage, "+
			"so leaving this bare bans honest peers for this node's own bad disk", err)
	}
}

// TestACorruptLocalBlockBodyIsNotChargedToThePeer is the same rule for bodies:
// UnmarshalBlock failing on bytes this node committed is a local fault.
//
// It drives Block and BlockAt rather than a reorg deliberately. Reaching a
// corrupt body through ConsiderBranch proves nothing about blockLocked's own
// wrap, because switchTo's unwind exit routes through c.unwound, which marks
// the error ErrLocal unconditionally — the assertion passes on unwound's wrap
// even with blockLocked's removed (a review caught exactly that, in an earlier
// version of this test that reorged). Block and BlockAt reach blockLocked with
// no such wrapper in between, so they are where the wrap is load-bearing.
// (BlockAt used to be on node/p2p's OnGetHeaders serving path; it is not since
// that responder stopped decoding a whole block per header, and Block is no
// longer on OnGetBlock's since that one stopped decoding and re-marshalling a
// whole block to serve one chunk — the wrap still matters to every other caller
// that decodes a stored record, which is what this test drives.)
func TestACorruptLocalBlockBodyIsNotChargedToThePeer(t *testing.T) {
	p := dropUndoParams()
	payout := key(t, 1).Persistent()
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)

	n.mine(t, 30)

	const damaged = 28
	id, ok := n.chain.CanonicalIDAt(damaged)
	if !ok {
		t.Fatalf("setup: no canonical block at height %d", damaged)
	}
	if err := n.chain.CorruptForTest("block", damaged, []byte{0x01, 0x02}); err != nil {
		t.Fatalf("setup: corrupting the block at height %d: %v", damaged, err)
	}

	// BlockAt: the height-indexed read node/p2p serves peers from.
	_, err := n.chain.BlockAt(damaged)
	if err == nil {
		t.Fatal("BlockAt returned an undecodable body without an error")
	}
	if !errors.Is(err, chain.ErrLocal) {
		t.Fatalf("BlockAt refusal is %v, want it wrapped in ErrLocal: a body this node "+
			"committed and can no longer decode is this node's fault, and node/p2p scores "+
			"every error that is not ErrLocal against the peer that prompted the read", err)
	}

	// Block: the same read by id.
	_, err = n.chain.Block(id)
	if err == nil {
		t.Fatal("Block returned an undecodable body without an error")
	}
	if !errors.Is(err, chain.ErrLocal) {
		t.Fatalf("Block refusal is %v, want it wrapped in ErrLocal", err)
	}
}
