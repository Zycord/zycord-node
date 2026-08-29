//go:build !race

// The heap-accounting half of the shrink rule, split out because it must not
// run under the race detector, for the reason dirty_reset_memory_test.go gives:
// the reading is a difference of two HeapAlloc samples, and race
// instrumentation changes both the size of every allocation and when it is
// reclaimed, so under -race this would assert a number no node would ever see.
//
// The structural tests in shrink_test.go are the ones that prove the property,
// and those run everywhere. This one confirms the structural signal -- "a
// different map" -- corresponds to real memory coming back.

package state

import (
	"runtime"
	"testing"

	"zycord/core/u256"
)

// A drained map must give its buckets back to the heap, not merely be a
// different map.
//
// Reported as a ratio of retained-to-peak rather than as an absolute figure,
// so that the assertion does not encode this machine's allocator or this
// version's map layout. The measurement reproduces the one the shrink rule
// was chosen against: 200,000 cells written and then all drained to zero, and
// 200,000 seen entries pruned by TTL.
func TestShrinkReleasesTheBuckets(t *testing.T) {
	if testing.Short() {
		t.Skip("allocates ~60 MB")
	}
	const n = 200_000

	t.Run("cells", func(t *testing.T) {
		base := heapInUse()
		s := New()
		for i := 0; i < n; i++ {
			s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
		}
		_ = s.Root()
		peak := heapInUse()
		for i := 0; i < n; i++ {
			s.Set(slotOf(i), u256.Zero) // every cell deleted: zero is absence
		}
		_ = s.Root()
		drained := heapInUse()
		runtime.KeepAlive(s)

		if got := len(s.SortedCells()); got != 0 {
			t.Fatalf("%d cells still live; this is not measuring an emptied map", got)
		}
		reportRetention(t, "cells", base, peak, drained, n)
	})

	t.Run("seen", func(t *testing.T) {
		base := heapInUse()
		s := New()
		for i := 0; i < n; i++ {
			s.MarkSeen(hashOfIndex(i), uint64(i)+1)
		}
		peak := heapInUse()
		_ = s.PruneSeen(uint64(n) + 1) // TTL expires the whole set
		pruned := heapInUse()
		runtime.KeepAlive(s)

		if got := s.SeenCount(); got != 0 {
			t.Fatalf("%d seen entries still live; this is not measuring an emptied map", got)
		}
		reportRetention(t, "seen", base, peak, pruned, n)
	})
}

// reportRetention states the reading and the conditions it was taken under, and
// asserts the ratio rather than the megabytes.
//
// The bar is 20% of peak. The measured retention with the fix is under 1%, and
// without it 43% for cells and 98% for seen, so the bar sits an order of
// magnitude clear of the fix and far clear of the defect -- wide enough that a
// different allocator, GOGC setting or map implementation does not move it, and
// tight enough that reverting the fix fails it. A heap difference is a
// measurement, not a proof; the proof is the structural pair in shrink_test.go.
func reportRetention(t *testing.T, name string, base, peak, after uint64, n int) {
	t.Helper()
	const mb = 1 << 20
	grown := float64(peak - base)
	retained := float64(after - base)
	ratio := retained / grown
	t.Logf("%s: peak %.1f MB above baseline, %.1f MB retained with the map empty "+
		"(%.1f%% of peak, %.0f B per emptied entry, n=%d)",
		name, grown/mb, retained/mb, ratio*100, retained/float64(n), n)
	if ratio > 0.20 {
		t.Errorf("%s: %.1f%% of the peak heap (%.1f MB) is retained with the map empty; "+
			"the buckets of the high-water mark were not released",
			name, ratio*100, retained/mb)
	}
}
