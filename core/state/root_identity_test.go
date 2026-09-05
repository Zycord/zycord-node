package state

import (
	"fmt"
	"sort"
	"testing"

	"zycord/core/crypto"
	"zycord/core/ssz"
	"zycord/core/types"
	"zycord/core/u256"
)

// rootFromScratch is the epoch state root's definition without the cache: sort
// the whole key set, hash every leaf, merkleise each subtree against nextPow2
// of its own length, combine.
//
// This is the body of State.Root as it stood before the cache, verbatim, and
// what it checks is the **cache** — that maintaining the arrays incrementally
// reproduces the from-scratch build bit for bit, over states reached by every
// path including undo. That is a real property and this is a real check of
// it.
//
// It is NOT a second implementation of the merkleisation, and an earlier
// version of this comment claimed it was ("written out independently of the
// implementation"; "a reference that shares code with the thing it checks is
// checking nothing" — true, and it described this function). It calls
// ssz.ListRoot, nextPow2, crypto.Sum and the same three tag constants, so the
// tag, the tree, zeroHashes and MixInLength are the same code object on both
// sides: a wrong tag or a wrong capacity moves both roots together and this
// test still passes. That was measured, and core/state/naive is the answer;
// naive_differential_test.go is where the merkleisation is checked against
// something that is not itself.
func (s *State) rootFromScratch() types.Hash {
	slots := s.SortedCells()
	cellLeaves := make([]types.Hash, len(slots))
	for i, slot := range slots {
		v := s.cells[slot].Bytes()
		cellLeaves[i] = crypto.Sum(crypto.TagStateCell, slot.Addr[:], slot.Word[:], v[:])
	}

	addrs := s.SortedSpent()
	spentLeaves := make([]types.Hash, len(addrs))
	for i, a := range addrs {
		spentLeaves[i] = crypto.Sum(crypto.TagStateSpent, a[:])
	}

	cellRoot := ssz.ListRoot(cellLeaves, nextPow2(len(cellLeaves)))
	spentRoot := ssz.ListRoot(spentLeaves, nextPow2(len(spentLeaves)))
	return crypto.Sum(crypto.TagStateRoot, cellRoot[:], spentRoot[:])
}

// invalidateRootCache throws the cache away so a caller can force the
// from-scratch build path. Only tests and benchmarks need it.
func (s *State) invalidateRootCache() {
	s.cached = false
	s.cellKeys, s.cellLeaves = nil, nil
	s.spentKeys, s.spentLeaves = nil, nil
	s.cellTree, s.spentTree = ssz.NewTree(), ssz.NewTree()
	s.rootValid = false
	s.dirtyCells = resetDirtyCells(s.dirtyCells)
	s.dirtySpent = resetDirtySpent(s.dirtySpent)
}

// checkIdentical asserts the cached root equals the definition, and also that
// the cached key arrays are exactly the canonical sorted key sets — so a
// failure says which half drifted rather than only that a hash differs.
func checkIdentical(t *testing.T, s *State, what string) {
	t.Helper()
	got := s.Root()
	if want := s.rootFromScratch(); got != want {
		t.Fatalf("%s: incremental root %x, from scratch %x", what, got[:8], want[:8])
	}
	wantCells := s.SortedCells()
	if len(s.cellKeys) != len(wantCells) {
		t.Fatalf("%s: cached %d cell keys, state has %d", what, len(s.cellKeys), len(wantCells))
	}
	for i := range wantCells {
		if s.cellKeys[i] != wantCells[i] {
			t.Fatalf("%s: cached cell key %d is %x, canonical is %x",
				what, i, s.cellKeys[i].Addr[:4], wantCells[i].Addr[:4])
		}
	}
	wantSpent := s.SortedSpent()
	if len(s.spentKeys) != len(wantSpent) {
		t.Fatalf("%s: cached %d registry keys, state has %d", what, len(s.spentKeys), len(wantSpent))
	}
	for i := range wantSpent {
		if s.spentKeys[i] != wantSpent[i] {
			t.Fatalf("%s: cached registry key %d is %x, canonical is %x",
				what, i, s.spentKeys[i][:4], wantSpent[i][:4])
		}
	}
}

// TestRootIsBitIdenticalToFromScratch is the whole claim of the cache: it
// changes the cost and nothing else.
//
// The property being constrained, stated before the test: for every reachable
// state, and for every write history that reaches it, Root() equals the
// from-scratch definition. Two halves matter and both are exercised —
// *reachable state* (empty, one leaf, the power-of-two boundaries where
// nextPow2 moves the merkle capacity) and *write history* (fresh build,
// incremental insert, in-place update, delete-to-zero, undo, and clone), since
// only the second can be got wrong by a cache.
func TestRootIsBitIdenticalToFromScratch(t *testing.T) {
	t.Run("empty", func(t *testing.T) {
		checkIdentical(t, New(), "empty")
	})

	// The capacity boundaries. nextPow2 changes the tree depth as the live
	// count crosses a power of two, and it does so independently
	// for the two subtrees — so the cell count and the registry count are
	// stepped across the boundary separately, not together.
	t.Run("capacity boundaries", func(t *testing.T) {
		for _, n := range []int{0, 1, 2, 3, 4, 5, 7, 8, 9, 15, 16, 17, 31, 32, 33, 63, 64, 65} {
			s := New()
			// Grow one leaf at a time and check at every size, so a crossing
			// is checked both as "built at this size" and as "grown into it".
			for i := 0; i < n; i++ {
				s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
				checkIdentical(t, s, "cells growing")
			}
			for i := 0; i < n; i++ {
				s.MarkSpent(addrOf(i))
				checkIdentical(t, s, "registry growing")
			}
			// And shrinking back across the same boundaries, which is the
			// delete path the merge has to handle.
			for i := 0; i < n; i++ {
				s.Set(slotOf(i), u256.Zero)
				checkIdentical(t, s, "cells shrinking")
			}
		}
	})

	// A write history with every shape mixed: fresh keys, repeats of keys
	// already present, deletions of live and of absent keys, registry
	// additions, and Root() called at irregular intervals so that some dirty
	// sets are large and some are a single key.
	t.Run("mixed history", func(t *testing.T) {
		s := New()
		for step := 0; step < 400; step++ {
			r := mix(uint64(step))
			switch r % 4 {
			case 0:
				s.Set(slotOf(int(r%97)), u256.FromUint64(r%11+1))
			case 1:
				s.Set(slotOf(int(r%97)), u256.Zero)
			case 2:
				s.MarkSpent(addrOf(int(r % 53)))
			case 3:
				s.Set(slotOf(int(r%23)), u256.FromUint64(r|1))
			}
			if step%7 == 0 || step%13 == 0 {
				checkIdentical(t, s, "mixed history")
			}
		}
		checkIdentical(t, s, "mixed history final")
	})

	// Clone must carry a cache that is still correct for the copy, and the two
	// copies must not share it.
	t.Run("clone", func(t *testing.T) {
		s := New()
		for i := 0; i < 40; i++ {
			s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
			s.MarkSpent(addrOf(i))
		}
		_ = s.Root()
		s.Set(slotOf(100), u256.FromUint64(7)) // dirty at clone time
		c := s.Clone()
		checkIdentical(t, c, "clone")
		c.Set(slotOf(200), u256.FromUint64(9))
		checkIdentical(t, c, "clone diverged")
		checkIdentical(t, s, "original after clone diverged")
		if c.Root() == s.Root() {
			t.Fatal("clone and original produced the same root after diverging")
		}
	})
}

// TestRootAfterUndoMatchesRootBefore is the reorg case: a rollback restores
// state through Undo, not through the writes that produced it, and the cache
// has to end up where a from-scratch build would.
//
// The property: undoing a block returns the root to exactly the value it had
// before that block. This is what makes `switchTo` and `rollbackLocked`
// correct, and it is the case the dirty set cannot get from "what this block
// wrote" alone — Undo *removes* registry entries and *restores* old cell
// values, both of which are dirtying operations in the opposite direction.
func TestRootAfterUndoMatchesRootBefore(t *testing.T) {
	s := New()
	for i := 0; i < 70; i++ {
		s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
		s.MarkSpent(addrOf(i))
	}
	before := s.Root()

	// Apply a "block": overwrite live cells, create new ones, drain one to
	// zero, and retire two addresses — recording the undo log exactly as the
	// fold does.
	log := &UndoLog{}
	write := func(i int, v u256.U256) {
		slot := slotOf(i)
		log.Cells = append(log.Cells, CellUndo{Slot: slot, Old: s.Get(slot)})
		s.Set(slot, v)
	}
	write(3, u256.FromUint64(999))
	write(3, u256.FromUint64(1000)) // twice in one block: undo must reach the pre-block value
	write(500, u256.FromUint64(5))
	write(501, u256.FromUint64(6))
	write(9, u256.Zero) // drained: the leaf disappears
	for _, i := range []int{300, 301} {
		s.MarkSpent(addrOf(i))
		log.SpentAdded = append(log.SpentAdded, addrOf(i))
	}
	during := s.Root()
	checkIdentical(t, s, "after block")
	if during == before {
		t.Fatal("the block did not move the root, so undoing it proves nothing")
	}

	s.Undo(log)
	checkIdentical(t, s, "after undo")
	if got := s.Root(); got != before {
		t.Fatalf("root after undo is %x, before the block it was %x", got[:8], before[:8])
	}

	// And a rebuild from the maps, which is what a restart does, agrees with
	// the undone cache.
	s.invalidateRootCache()
	if got := s.Root(); got != before {
		t.Fatalf("root rebuilt from scratch after undo is %x, want %x", got[:8], before[:8])
	}
}

// TestRootAfterUndoAcrossACapacityBoundary is the intersection the two tests
// above cover only separately.
//
// `capacity boundaries` steps the live count across every nextPow2 crossing but
// never undoes; TestRootAfterUndoMatchesRootBefore undoes but sits at 70 ± 2
// entries, so its capacity is 128 from start to finish. Undo *across* a
// crossing is the case where the tree is re-shaped in one direction and has to
// be re-shaped back, and it was untested — reviewed as correct, which is not
// the same as pinned.
//
// Both subtrees move together here, and they move by different amounts, because
// their capacities are independent: a block that pushes the cells over a
// crossing and leaves the registry below one is the shape that would catch a
// refreshLeaves which reused the wrong subtree's key array.
func TestRootAfterUndoAcrossACapacityBoundary(t *testing.T) {
	bases := []int{1, 2, 3, 4, 7, 8, 15, 16, 31, 32, 63, 64, 65}
	for _, base := range bases {
		for delta := 1; delta <= 3; delta++ {
			t.Run(fmt.Sprintf("base%d+%d", base, delta), func(t *testing.T) {
				s := New()
				for i := 0; i < base; i++ {
					s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
					s.MarkSpent(addrOf(i))
				}
				before := s.Root()
				checkIdentical(t, s, "seed")

				// Grow: delta new cells, delta-1 new registry entries, so the
				// two subtrees cross their boundaries at different moments.
				log := &UndoLog{}
				for i := 0; i < delta; i++ {
					slot := slotOf(base + i)
					log.Cells = append(log.Cells, CellUndo{Slot: slot, Old: s.Get(slot)})
					s.Set(slot, u256.FromUint64(uint64(i)+7))
				}
				for i := 0; i < delta-1; i++ {
					a := addrOf(base + i)
					s.MarkSpent(a)
					log.SpentAdded = append(log.SpentAdded, a)
				}
				checkIdentical(t, s, "grown")
				if s.Root() == before {
					t.Fatal("growth did not move the root, so undoing it proves nothing")
				}

				s.Undo(log)
				checkIdentical(t, s, "undone growth")
				if got := s.Root(); got != before {
					t.Fatalf("root after undoing growth is %x, want %x", got[:8], before[:8])
				}

				// Shrink across the same boundary by draining to zero, which is
				// a delete, and undo that too.
				shrink := delta
				if shrink > base {
					shrink = base
				}
				log = &UndoLog{}
				for i := 0; i < shrink; i++ {
					slot := slotOf(base - 1 - i)
					log.Cells = append(log.Cells, CellUndo{Slot: slot, Old: s.Get(slot)})
					s.Set(slot, u256.Zero)
				}
				checkIdentical(t, s, "shrunk")
				if shrink > 0 && s.Root() == before {
					t.Fatal("shrinking did not move the root")
				}

				s.Undo(log)
				checkIdentical(t, s, "undone shrink")
				if got := s.Root(); got != before {
					t.Fatalf("root after undoing the shrink is %x, want %x", got[:8], before[:8])
				}

				// And the restart path agrees with the twice-undone cache.
				s.invalidateRootCache()
				if got := s.Root(); got != before {
					t.Fatalf("root rebuilt from scratch is %x, want %x", got[:8], before[:8])
				}
			})
		}
	}
}

// TestSortedCellsIsIndependentOfTheCache guards the assumption checkIdentical
// leans on: SortedCells/SortedSpent read the maps, not the cached arrays, so
// they cannot agree with a wrong cache by construction.
func TestSortedCellsIsIndependentOfTheCache(t *testing.T) {
	s := New()
	for i := 0; i < 10; i++ {
		s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
	}
	_ = s.Root()
	// Corrupt the cache behind the accessors' back.
	s.cellKeys = nil
	s.cellLeaves = nil
	got := s.SortedCells()
	if len(got) != 10 {
		t.Fatalf("SortedCells returned %d slots from a wiped cache; it is reading the cache", len(got))
	}
	if !sort.SliceIsSorted(got, func(i, j int) bool { return got[i].Less(got[j]) }) {
		t.Fatal("SortedCells is not sorted")
	}
}
