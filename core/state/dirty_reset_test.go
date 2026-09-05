package state

import (
	"reflect"
	"runtime"
	"testing"

	"zycord/core/u256"
)

// The dirty sets must not keep the memory of the largest block they ever saw.
//
// `clear` empties a Go map and keeps its buckets. That is the right trade for
// the steady state — a few hundred keys a block — and the wrong one exactly
// once per process, because chain.load replays the entire state through Set
// and MarkSpent at startup. Without a reset the two sets are sized to the
// whole state from the first restart onward and never shrink again, on top of
// a root cache that is already the larger half of §14's memory disclosure.
//
// The property is asserted structurally rather than by measuring the heap: a
// map that was reallocated is a different map, and reflect can see that
// without a GC, a timer or a tolerance. TestDirtyResetReleasesTheBuckets, in
// dirty_reset_memory_test.go, then confirms the structural signal corresponds
// to real memory.

func mapPtr(m any) uintptr { return reflect.ValueOf(m).Pointer() }

func TestLargeDirtySetIsReallocatedNotCleared(t *testing.T) {
	s := New()
	_ = s.Root() // establish the cache, so the merge paths run below

	for i := 0; i <= dirtyResetThreshold; i++ { // threshold+1 keys: over the line
		s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
		s.MarkSpent(addrOf(i))
	}
	// The old maps are held, not just their addresses: comparing a uintptr to
	// freed memory would report "cleared in place" if the allocator happened to
	// hand the same address back. A test whose whole value is being trustworthy
	// does not get to rely on that not happening.
	oldCells, oldSpent := s.dirtyCells, s.dirtySpent
	cellsBefore, spentBefore := mapPtr(oldCells), mapPtr(oldSpent)
	_ = s.Root()
	defer runtime.KeepAlive(oldCells)
	defer runtime.KeepAlive(oldSpent)
	if mapPtr(s.dirtyCells) == cellsBefore {
		t.Errorf("a dirty cell set of %d keys was cleared in place; its buckets are retained forever",
			dirtyResetThreshold+1)
	}
	if mapPtr(s.dirtySpent) == spentBefore {
		t.Errorf("a dirty registry set of %d keys was cleared in place; its buckets are retained forever",
			dirtyResetThreshold+1)
	}
	if len(s.dirtyCells) != 0 || len(s.dirtySpent) != 0 {
		t.Fatal("the dirty sets are not empty after Root")
	}
}

// The other half of the rule, and the one that keeps it from becoming churn:
// an ordinary block must not pay an allocation per commit.
func TestSmallDirtySetIsClearedInPlace(t *testing.T) {
	s := New()
	for i := 0; i < 4096; i++ { // a state larger than the threshold...
		s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
		s.MarkSpent(addrOf(i))
	}
	_ = s.Root()

	for i := 0; i < 200; i++ { // ...written by an ordinary block
		s.Set(slotOf(i), u256.FromUint64(uint64(i)+7))
		s.MarkSpent(addrOf(i)) // already spent: still marks dirty
	}
	oldCells, oldSpent := s.dirtyCells, s.dirtySpent
	cellsBefore, spentBefore := mapPtr(oldCells), mapPtr(oldSpent)
	_ = s.Root()
	defer runtime.KeepAlive(oldCells)
	defer runtime.KeepAlive(oldSpent)
	if mapPtr(s.dirtyCells) != cellsBefore || mapPtr(s.dirtySpent) != spentBefore {
		t.Fatal("a 200-key dirty set was reallocated; ordinary blocks should clear in place")
	}
}
