package chain_test

import (
	"testing"

	"zycord/node/storage"
)

// The three unwind-loop error returns that leave state rolled back while tip,
// height and disk still name the old chain, and that the rest of the suite
// does not exercise: a missing block record, an undo log that will not
// decode, and a missing parent header. Only the fourth (a missing undo log)
// had a regression pin — TestSwitchToRestoresMemoryOnUndoLogFailure — and a
// fix that routes four paths through restore deserves four tests, not one.
//
// Each case breaks exactly one record on disk, offers a heavier branch, and
// demands that the failed reorg left c.state, c.tip and c.height exactly
// where they started, and the node still able to mine.

// mutateStore applies raw key edits directly to a closed node's store.
func mutateStore(t *testing.T, dir string, edit func(b *storage.Batch)) {
	t.Helper()
	s, err := storage.Open(dir, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	b := &storage.Batch{}
	edit(b)
	if err := s.Commit(b); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
}

func chainKey(prefix string, id [32]byte) []byte { return append([]byte(prefix), id[:]...) }

// runUnwindFaultCase mines four blocks, hands the caller the id of the block
// at height 3 to break however it likes, then reopens and offers a branch
// that forks below it.
func runUnwindFaultCase(t *testing.T, name string, breakIt func(b *storage.Batch, victim [32]byte)) {
	t.Helper()
	t.Run(name, func(t *testing.T) {
		p := devnetEasy()
		payout := key(t, 1).Persistent()
		dir := t.TempDir()

		n := openNode(t, dir, p, payout)
		n.mine(t, 4)
		tipBefore := n.chain.Tip().ID()
		heightBefore := n.chain.Height()
		rootBefore := n.chain.StateRoot()

		// Height 3: one below the tip and one above the branch's ancestor,
		// so the unwind loop has already moved c.state at least once by the
		// time it reaches the broken record.
		victim, err := n.chain.BlockAt(3)
		if err != nil {
			t.Fatal(err)
		}
		victimID := victim.Header.ID()

		// The branch is built while the store is still whole: two of these
		// cases break a record the test's own helpers would otherwise read
		// (worthOf walks the very block whose record is deleted), and the
		// fault is meant to fire inside switchTo's unwind loop, not in the
		// setup.
		ancestor := ancestorAt(t, n, 3)
		replacedWork := worthOf(t, n, 3)
		branch := buildBranch(t, n, payout, ancestor, 2, fastSolveSeconds)
		if !branch.Work().Gt(replacedWork) {
			t.Fatal("setup: the branch does not carry more work than what it replaces")
		}
		n.close(t)

		mutateStore(t, dir, func(b *storage.Batch) { breakIt(b, victimID) })

		re := openNode(t, dir, p, payout)
		defer re.close(t)

		if _, err := re.chain.ConsiderBranch(branch); err == nil {
			t.Fatal("a reorg that unwinds through a broken record unexpectedly succeeded")
		}

		if got := re.chain.Tip().ID(); got != tipBefore {
			t.Fatalf("tip is %x, want %x", got[:8], tipBefore[:8])
		}
		if got := re.chain.Height(); got != heightBefore {
			t.Fatalf("height is %d, want %d", got, heightBefore)
		}
		if got := re.chain.StateRoot(); got != rootBefore {
			t.Fatalf("state root is %x, want %x: c.state was left desynced from c.tip "+
				"and c.height by a failure in the unwind loop", got[:8], rootBefore[:8])
		}
		// A failed reorg is not a fatal condition; a desynced state would
		// corrupt every block folded on top of it from here on.
		re.mine(t, 1)
		if re.chain.Height() != heightBefore+1 {
			t.Fatalf("height %d after mining on top of a failed reorg, want %d",
				re.chain.Height(), heightBefore+1)
		}
	})
}

func TestAttackUnwindLoopFaultsAllRestoreMemory(t *testing.T) {
	// The one path that restored even before the fix, kept here so all
	// four sit side by side.
	runUnwindFaultCase(t, "missing block record", func(b *storage.Batch, victim [32]byte) {
		b.Delete(chainKey("b/", victim))
	})

	// An undo log that is present but does not decode.
	runUnwindFaultCase(t, "undecodable undo log", func(b *storage.Batch, victim [32]byte) {
		b.Put(chainKey("u/", victim), []byte{0xff, 0xff, 0xff, 0xff, 0x01})
	})

	// A missing parent header: c.state has already been moved by this very
	// block's undo and `undone` already holds it, so restore has to redo it.
	// This is the path the fix's own comment calls "something changed and
	// nothing recorded how to change it back".
	runUnwindFaultCase(t, "missing parent header", func(b *storage.Batch, victim [32]byte) {
		b.Delete(chainKey("h/", victim))
	})
}
