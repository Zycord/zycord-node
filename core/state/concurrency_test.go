package state

import (
	"sync"
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
)

// Root and Clone are readers, and this file is where that is pinned.
//
// core/ holds no goroutine anywhere else, in implementation or in test, and
// that is deliberate — determinism beats performance in the consensus zone.
// The exception here is unavoidable: the property being asserted is that two
// goroutines may call Root at the same time, and there is no way to assert that
// without two goroutines. Nothing in the package under test starts one.
//
// The reason it needs asserting at all is that the incremental root cache
// made Root write. It refreshes the two key/leaf arrays, mutates both
// ssz.Trees in place, sets root/rootValid, and clears the two dirty sets. Its
// callers in node/chain hold the chain lock in *shared* mode, so while Root
// was pure that was correct, and with the cache it was correct only while the
// dirty sets happened to be empty at every shared-lock acquisition. They are
// not: any fold error path that runs after the fold has mutated state calls
// Undo and returns without a Root, and F14 (state root mismatch at an epoch
// boundary) is exactly such a path, reachable from one gossiped block.
//
// Rather than restore that invariant and rely on five call sites remembering
// it, State guards its cache with cacheMu, which makes Root safe under any
// lock — or none. These tests fail under -race without it.

// buildDirtyState returns a state with a populated, up-to-date cache and then
// dirties it, which is the shape a failed epoch-boundary block leaves behind:
// the arrays are valid, the dirty sets are not empty, and the next Root has
// real merging to do.
func buildDirtyState(t *testing.T, n int) *State {
	t.Helper()
	s := New()
	for i := 0; i < n; i++ {
		s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
		s.MarkSpent(addrOf(i))
	}
	s.Root() // bring the cache up to date, exactly as writeHead does

	// Now write across a nextPow2 crossing in both subtrees and delete some
	// cells, so refreshLeaves does a full merge rather than a no-op.
	for i := n; i < n+40; i++ {
		s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
		s.MarkSpent(addrOf(i))
	}
	for i := 0; i < 10; i++ {
		s.Set(slotOf(i), u256.U256{}) // zero deletes
	}
	if len(s.dirtyCells) == 0 || len(s.dirtySpent) == 0 {
		t.Fatal("the state is not dirty; the test would assert nothing")
	}
	return s
}

// TestConcurrentRootOnDirtyState: N goroutines calling Root on a dirty state
// must be race-free and must all get the one right answer.
//
// This is the unit-level form of the chain-level regression in
// node/chain/concurrency_test.go. It belongs here too, because the guarantee is
// State's and not the Chain's: a future caller that reaches Root under some
// other lock, or a package that uses core/state without node/chain at all, is
// covered by this and not by that.
func TestConcurrentRootOnDirtyState(t *testing.T) {
	for _, n := range []int{1, 63, 64, 65, 200} {
		s := buildDirtyState(t, n)
		want := s.Clone().Root() // the answer, computed on an independent copy

		const readers = 8
		got := make([]types.Hash, readers)
		var start, done sync.WaitGroup
		start.Add(1)
		for g := 0; g < readers; g++ {
			done.Add(1)
			go func(g int) {
				defer done.Done()
				start.Wait() // release them together, to widen the window
				got[g] = s.Root()
			}(g)
		}
		start.Done()
		done.Wait()

		for g, h := range got {
			if h != want {
				t.Fatalf("n=%d: reader %d got %x, want %x", n, g, h[:8], want[:8])
			}
		}
		// And the surviving cache must still be the canonical one, so a race
		// that merely produced the right hash from a torn array is caught too.
		checkIdentical(t, s, "after concurrent readers")
	}
}

// TestConcurrentRootAndCloneOnDirtyState: Chain.StateRoot and Chain.Snapshot
// both run under the chain's shared lock, so Root and Clone can be inside the
// state at the same time — one writing the cache the other is copying.
func TestConcurrentRootAndCloneOnDirtyState(t *testing.T) {
	s := buildDirtyState(t, 100)
	want := s.Clone().Root()

	var start, done sync.WaitGroup
	start.Add(1)
	clones := make([]*State, 4)
	roots := make([]types.Hash, 4)
	for g := 0; g < 4; g++ {
		done.Add(2)
		go func(g int) { defer done.Done(); start.Wait(); roots[g] = s.Root() }(g)
		go func(g int) { defer done.Done(); start.Wait(); clones[g] = s.Clone() }(g)
	}
	start.Done()
	done.Wait()

	for g, h := range roots {
		if h != want {
			t.Fatalf("reader %d got %x, want %x", g, h[:8], want[:8])
		}
	}
	// Every clone — taken before, during or after the refresh — must still be a
	// state that computes the same root. A clone that copied a half-written
	// array would not.
	for g, c := range clones {
		if got := c.Root(); got != want {
			t.Fatalf("clone %d roots to %x, want %x", g, got[:8], want[:8])
		}
		if got, wantFS := c.Root(), c.rootFromScratch(); got != wantFS {
			t.Fatalf("clone %d: cached %x, from scratch %x", g, got[:8], wantFS[:8])
		}
	}
}

// TestCloneDoesNotShareTheRootCache: State.Clone must not alias any of the
// seven cache fields or either tree.
//
// This is the same hole tree_internal_test.go closes one layer down. Aliasing
// them is invisible to a single-threaded test — refreshLeaves allocates fresh
// arrays rather than writing in place, and ssz.Tree is self-healing — so the
// adversarial review's mutations "Clone shares the trees" and "Clone aliases
// the leaf arrays" survived 1.55 M differential root comparisons. What they
// break is memory safety when a Snapshot is handed to another goroutine, and
// that is what this asserts: backing arrays, by address.
func TestCloneDoesNotShareTheRootCache(t *testing.T) {
	s := New()
	for i := 0; i < 100; i++ {
		s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
		s.MarkSpent(addrOf(i))
	}
	s.Root()
	c := s.Clone()

	if len(c.cellKeys) == 0 || len(c.spentKeys) == 0 {
		t.Fatal("the clone has an empty cache; the test would assert nothing")
	}
	if &c.cellKeys[0] == &s.cellKeys[0] {
		t.Error("Clone aliases cellKeys")
	}
	if &c.cellLeaves[0] == &s.cellLeaves[0] {
		t.Error("Clone aliases cellLeaves")
	}
	if &c.spentKeys[0] == &s.spentKeys[0] {
		t.Error("Clone aliases spentKeys")
	}
	if &c.spentLeaves[0] == &s.spentLeaves[0] {
		t.Error("Clone aliases spentLeaves")
	}
	if c.cellTree == s.cellTree {
		t.Error("Clone shares the cell tree")
	}
	if c.spentTree == s.spentTree {
		t.Error("Clone shares the registry tree")
	}
	// The dirty maps are maps, so identity is the whole question.
	s.Set(slotOf(1000), u256.FromUint64(7))
	if _, shared := c.dirtyCells[slotOf(1000)]; shared {
		t.Error("Clone shares dirtyCells")
	}
	s.MarkSpent(addrOf(1000))
	if _, shared := c.dirtySpent[addrOf(1000)]; shared {
		t.Error("Clone shares dirtySpent")
	}
}
