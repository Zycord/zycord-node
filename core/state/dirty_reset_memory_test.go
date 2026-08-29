//go:build !race

// The heap-accounting half of the dirty-set reset, split out because it must
// not run under the race detector.
//
// Not for speed, though it costs 19 s there against 1.7 s here: the reading is
// a difference of two HeapAlloc samples, and race instrumentation changes both
// the size of every allocation and when it is reclaimed, so under -race this
// asserts a number no node would ever see. A measurement is true about the
// conditions it was taken under. The structural tests beside it are the ones
// that prove the property, and those run everywhere.

package state

import (
	"runtime"
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
)

// TestDirtyResetReleasesTheBuckets is the one that costs real memory to run,
// and it is the reason the two structural tests in dirty_reset_test.go are
// trustworthy: it
// confirms that "a different map" means "the buckets came back".
//
// It runs the production shape — the restart path, which is the only way the
// dirty sets ever reach the size of the state — and asserts the heap after the
// first Root is close to what the maps and the cache alone need. The margin is
// wide (the measured retention is 14 MB against a 4 MB bar) because this is a
// heap measurement, not a proof; the proof is the pair beside it.
func TestDirtyResetReleasesTheBuckets(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~64 MB")
	}
	const n = 100_000

	base := heapInUse()
	s := New()
	for i := 0; i < n; i++ { // exactly what chain.load does
		s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
		s.MarkSpent(addrOf(i))
	}
	_ = s.Root()
	withReset := heapInUse()
	runtime.KeepAlive(s)

	// The same state with the dirty sets re-inflated to what `clear` would have
	// kept: the difference between the two readings is the retention.
	s.dirtyCells = make(map[types.Slot]struct{}, n)
	s.dirtySpent = make(map[types.Address]struct{}, n)
	for i := 0; i < n; i++ {
		s.dirtyCells[slotOf(i)] = struct{}{}
		s.dirtySpent[addrOf(i)] = struct{}{}
	}
	clear(s.dirtyCells)
	clear(s.dirtySpent)
	withoutReset := heapInUse()
	runtime.KeepAlive(s)

	retained := float64(withoutReset-withReset) / (1 << 20)
	t.Logf("state after restart+Root: %.1f MB with the reset, %.1f MB without it (%.1f MB retained by clear)",
		float64(withReset-base)/(1<<20), float64(withoutReset-base)/(1<<20), retained)
	if retained < 4 {
		t.Fatalf("clear retained only %.1f MB at n=%d; either the maps changed shape or this test "+
			"is no longer measuring what it claims", retained, n)
	}
}
