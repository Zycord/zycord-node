package chain_test

import (
	"fmt"
	"testing"

	"zycord/node/chain"
	"zycord/node/storage"
)

// Reorg commit safety.
//
// switchTo's own doc comment makes one promise: "a node must never be left
// on a partial branch." These tests pin the two ways that promise broke —
// a legal reorg's storage transaction outgrowing what one record can hold,
// and three of the unwind loop's four error returns skipping the memory
// restore the fourth already did — and the two ways it now holds even so.

// TestSwitchToRestoresMemoryOnUndoLogFailure is the regression pin for the
// unwind loop's half-rollback.
//
// Before the fix, a storage fault reached partway through switchTo's unwind
// loop left c.state moved (fold.UndoBlock had already run for at least one
// block) while c.tip and c.height stayed at their original values — the
// chain reporting a tip and height whose state no fold actually produced.
// Only one of the loop's four error returns (a missing block record) routed
// through restore(); the other three, including this one, did not.
//
// This corrupts the undo log for a block that is *not* the tip, so the
// unwind loop's first iteration (the tip's own undo) succeeds and mutates
// memory before the second iteration's corrupted record is reached — the
// shape the finding names specifically: "fold.UndoBlock has already run for the
// current cursor block before the failure."
func TestSwitchToRestoresMemoryOnUndoLogFailure(t *testing.T) {
	p := devnetEasy()
	payout := key(t, 1).Persistent()
	dir := t.TempDir()

	n := openNode(t, dir, p, payout)
	n.mine(t, 4)
	tipBefore := n.chain.Tip().ID()
	heightBefore := n.chain.Height()
	rootBefore := n.chain.StateRoot()

	// The block whose undo log will be deleted: height 3, one below the tip
	// (height 4) and one above the branch's ancestor (height 1) — so the
	// unwind loop's *second* of three iterations is the one that fails.
	victim, err := n.chain.BlockAt(3)
	if err != nil {
		t.Fatal(err)
	}
	victimID := victim.Header.ID()
	n.close(t)

	deleteUndoLog(t, dir, victimID)

	reopened := openNode(t, dir, p, payout)
	defer reopened.close(t)

	// A branch heavy enough to win, forking below the corrupted block, so
	// switchTo's unwind loop must walk through it.
	ancestor := ancestorAt(t, reopened, 3)
	branch := buildBranch(t, n, payout, ancestor, 2, fastSolveSeconds)
	if !branch.Work().Gt(worthOf(t, reopened, 3)) {
		t.Fatal("setup: the branch does not carry more work than what it replaces")
	}

	_, err = reopened.chain.ConsiderBranch(branch)
	if err == nil {
		t.Fatal("a reorg that unwinds through a corrupted undo log unexpectedly succeeded")
	}

	// c.height and c.tip were never touched inside the unwind loop in either
	// version of the code — they are only assigned after it completes — so
	// this much held before the fix too. The state root is the one that
	// actually distinguishes the two: before the fix, c.state reflected
	// block 4's undo already applied (one block further back than the tip
	// claims); after the fix, restore() put it back.
	if got := reopened.chain.Tip().ID(); got != tipBefore {
		t.Fatalf("tip is %x after a failed reorg, want %x", got[:8], tipBefore[:8])
	}
	if got := reopened.chain.Height(); got != heightBefore {
		t.Fatalf("height is %d after a failed reorg, want %d", got, heightBefore)
	}
	if got := reopened.chain.StateRoot(); got != rootBefore {
		t.Fatalf("state root is %x after a failed reorg, want %x: "+
			"c.state was not restored to match c.tip and c.height", got[:8], rootBefore[:8])
	}

	// And the node must still be usable: a failed reorg is not a fatal
	// condition, so the desynced state (before the fix) would have corrupted
	// every block folded on top of it from here on.
	reopened.mine(t, 1)
	if reopened.chain.Height() != heightBefore+1 {
		t.Fatalf("mining after a failed reorg gave height %d, want %d", reopened.chain.Height(), heightBefore+1)
	}
}

// deleteUndoLog removes a block's undo log directly on disk, simulating the
// storage inconsistency the unwind-loop paths need to reach — an undo log this
// deep is not pruned in ordinary operation, so today this is the only
// way to trigger them.
func deleteUndoLog(t *testing.T, dir string, id [32]byte) {
	t.Helper()
	s, err := storage.Open(dir, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	key := append([]byte("u/"), id[:]...)
	b := &storage.Batch{}
	b.Delete(key)
	if err := s.Commit(b); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

// TestReorgTooLargeForOneRecordStillCommits is the regression pin for the
// oversized reorg record: a reorg whose storage transaction cannot fit in a
// single record must still land as one atomic unit, not fail outright.
// mutationBudget is shrunk so a handful of small test blocks reproduce the same
// "more than one record" shape that UNDO_DEPTH * BLOCK_BYTE_CAPACITY produces
// at real parameters, without needing gigabytes of real data.
func TestReorgTooLargeForOneRecordStillCommits(t *testing.T) {
	restore := chain.SetMutationBudgetForTest(64)
	defer restore()

	p := devnetEasy()
	payout := key(t, 1).Persistent()
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)
	n.mine(t, 6)

	ancestor := ancestorAt(t, n, 5)
	branch := buildBranch(t, n, payout, ancestor, 5, fastSolveSeconds)
	if !branch.Work().Gt(worthOf(t, n, 5)) {
		t.Fatal("setup: the branch does not carry more work than what it replaces")
	}

	reorg, err := n.chain.ConsiderBranch(branch)
	if err != nil {
		t.Fatalf("a reorg whose transaction exceeds one storage record was refused: %v", err)
	}
	if !reorg.Adopted {
		t.Fatal("the heavier branch was not adopted")
	}
	if got, want := n.chain.Height(), uint64(6); got != want {
		t.Fatalf("height is %d, want %d", got, want)
	}
	if got, want := n.chain.Tip().ID(), branch.Blocks[len(branch.Blocks)-1].Header.ID(); got != want {
		t.Fatal("the chain did not end up on the branch it adopted")
	}
	if n.chain.StoredStateRoot() != n.chain.StateRoot() {
		t.Fatal("the committed state root does not match the in-memory one: the multi-record " +
			"transaction did not land atomically")
	}

	// The undo logs for the new blocks must have landed too, not just the
	// header/block/height keys: roll back the chunked reorg's own tip, which
	// can only succeed if its undo log is actually on disk.
	//
	// Mining a further block here instead would be a weaker check and a
	// flaky one: harderTarget() is genuinely hard, real proof of work against
	// it now governs the difficulty window, and devnet's trivial engine has
	// no guarantee of solving it within any fixed attempt budget.
	if err := n.chain.Rollback(); err != nil {
		t.Fatalf("rolling back the chunked reorg's tip failed: %v", err)
	}
	if got, want := n.chain.Height(), uint64(5); got != want {
		t.Fatalf("height after rollback is %d, want %d", got, want)
	}
	if got, want := n.chain.Tip().ID(), branch.Blocks[len(branch.Blocks)-2].Header.ID(); got != want {
		t.Fatal("rollback did not land on the branch's second-to-last block")
	}
}

// TestChunkedReorgIsCrashAtomic is TestReorgIsCrashAtomic's counterpart for
// the case switchTo's storage transaction now splits across more than one
// record. With mutationBudget shrunk enough that a modest branch
// already needs several records, the same crash-at-every-offset sweep must
// find the same property holding across all of them: wholly on the old
// branch, or wholly on the new one, never a mixture — proving that splitting
// the bytes did not split the atomicity guarantee.
func TestChunkedReorgIsCrashAtomic(t *testing.T) {
	restoreBudget := chain.SetMutationBudgetForTest(96)
	defer restoreBudget()

	p := devnetEasy()
	payout := key(t, 1).Persistent()

	probe := reorgFixture(t, p, payout, nil)
	recordLen := probe.commitBytes
	probe.close(t)
	if recordLen == 0 {
		t.Fatal("the reorg produced no commit; the test cannot measure it")
	}

	for offset := 0; offset <= recordLen; offset += 1 + recordLen/48 {
		t.Run(fmt.Sprintf("offset=%d", offset), func(t *testing.T) {
			remaining := offset
			fixture := reorgFixture(t, p, payout, func(record []byte) ([]byte, error) {
				if remaining >= len(record) {
					remaining -= len(record)
					return record, nil // this record lands whole
				}
				cut := record[:remaining]
				remaining = 0
				return cut, errSimulatedCrash
			})

			oldTip, oldRoot := fixture.oldTip, fixture.oldRoot
			newTip := fixture.newTip
			dir := fixture.dir
			fixture.abandon()

			reopened, err := chain.Open(dir, p)
			if err != nil {
				t.Fatalf("crash at offset %d left the chain unopenable: %v", offset, err)
			}
			defer reopened.Close()

			tip := reopened.Tip().ID()
			switch tip {
			case oldTip:
				if reopened.StateRoot() != oldRoot {
					t.Fatalf("crash at offset %d: on the old tip with the wrong state", offset)
				}
			case newTip:
				if reopened.StoredStateRoot() != reopened.StateRoot() {
					t.Fatalf("crash at offset %d: on the new tip with an inconsistent state", offset)
				}
			default:
				t.Fatalf("crash at offset %d left the node on neither branch (tip %x)", offset, tip[:6])
			}

			if _, err := reopened.BlockAt(reopened.Height()); err != nil {
				t.Fatalf("crash at offset %d: the tip block is not readable", offset)
			}
		})
	}
}
