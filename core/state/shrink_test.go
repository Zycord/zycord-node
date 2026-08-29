package state

import (
	"runtime"
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
)

// The three properties this file pins, stated before the tests that observe
// them, per CONTRIBUTING:
//
//  1. A map whose live population has fallen below a quarter of its own
//     high-water mark releases its buckets rather than keeping them for the
//     process lifetime.
//  2. The shrink cannot reach a consensus value: two states holding equal
//     contents agree on Root() even when they reached it by completely
//     different shrink schedules.
//  3. The high-water mark is never below the live count, whatever path wrote
//     the map -- including Undo, which reaches s.seen directly.
//
// Property 1 is the fix. Property 2 is what makes it admissible in the
// consensus zone. Property 3 is what keeps property 1 from being silently
// disarmed by a reorg.

// --- Property 1: the buckets come back ------------------------------------

// A drained cell map must not keep the buckets of its high-water mark.
//
// Asserted structurally rather than by measuring the heap: a map that was
// rebuilt is a different map, and reflect can see that without a GC, a timer or
// a tolerance. TestShrinkReleasesTheBuckets, in shrink_memory_test.go, then
// confirms the structural signal corresponds to real memory.
func TestDrainedCellMapIsRebuiltNotLeftFull(t *testing.T) {
	const n = 8 * shrinkFloor
	s := New()
	for i := 0; i < n; i++ {
		s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
	}
	// Hold the map itself, not just its address: comparing a uintptr to freed
	// memory would report "not rebuilt" if the allocator handed the same
	// address back.
	old := s.cells
	before := mapPtr(old)
	defer runtime.KeepAlive(old)

	// Drain past the trigger -- strictly past: the rule fires on
	// live < peak/shrinkDivisor, so leaving exactly peak/shrinkDivisor alive
	// is the last state that must NOT rebuild. One-shot payment outputs drain
	// like this, one certificate at a time.
	for i := 0; len(s.cells) >= n/shrinkDivisor; i++ {
		s.Set(slotOf(i), u256.Zero)
	}
	if mapPtr(s.cells) == before {
		t.Errorf("a cell map drained from %d to %d live was never rebuilt; its buckets are retained "+
			"for the process lifetime", n, len(s.cells))
	}
	if s.cellsPeak != len(s.cells) {
		t.Errorf("peak %d not re-based to the live count %d after the rebuild; the rule cannot be "+
			"amortised O(1) unless it re-arms from the new size", s.cellsPeak, len(s.cells))
	}
}

// The same for the seen set, driven by the path that actually empties it.
func TestPrunedSeenMapIsRebuiltNotLeftFull(t *testing.T) {
	const n = 8 * shrinkFloor
	s := New()
	for i := 0; i < n; i++ {
		s.MarkSeen(hashOfIndex(i), uint64(i)+1)
	}
	old := s.seen
	before := mapPtr(old)
	defer runtime.KeepAlive(old)

	_ = s.PruneSeen(uint64(n)) // expires all but the last
	if mapPtr(s.seen) == before {
		t.Errorf("a seen map pruned from %d to %d live was never rebuilt; its buckets are retained "+
			"for the process lifetime", n, len(s.seen))
	}
}

// The other half of the rule, and the one that keeps it from becoming churn: an
// ordinary block, which empties nothing, must not pay a rebuild.
func TestOrdinaryBlockDoesNotRebuildTheCellMap(t *testing.T) {
	const n = 8 * shrinkFloor
	s := New()
	for i := 0; i < n; i++ {
		s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
	}
	old := s.cells
	before := mapPtr(old)
	defer runtime.KeepAlive(old)

	for i := 0; i < 200; i++ { // a block's worth of one-shot spends
		s.Set(slotOf(i), u256.Zero)
	}
	if mapPtr(s.cells) != before {
		t.Fatalf("a 200-cell block rebuilt a map of %d live cells; the fold would pay Theta(N) per "+
			"block", n)
	}
}

// A state that never grows past the floor must never rebuild: below it the
// buckets are worth less than the allocation that would release them.
func TestSmallStateNeverRebuilds(t *testing.T) {
	s := New()
	for i := 0; i < shrinkFloor-1; i++ {
		s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
	}
	old := s.cells
	before := mapPtr(old)
	defer runtime.KeepAlive(old)

	for i := 0; i < shrinkFloor-1; i++ {
		s.Set(slotOf(i), u256.Zero)
	}
	if mapPtr(s.cells) != before {
		t.Fatalf("a state that peaked at %d cells rebuilt below the %d floor", shrinkFloor-1, shrinkFloor)
	}
}

// --- Property 2: the schedule cannot reach the root ------------------------

// Two states with equal contents must agree on Root() even when one has been
// rebuilt and the other has not.
//
// This is the consensus-zone admissibility argument, and it is asserted rather
// than reasoned about. It is the cells-analogue of the dirty sets' "both
// branches return an empty set, so the choice cannot reach the root" -- except
// that here the two branches return maps with *different internal iteration
// order*, so the claim needs a witness.
func TestRootIsInvariantToTheShrinkSchedule(t *testing.T) {
	const n = 8 * shrinkFloor
	const live = 64

	// A: grow to n, drain to `live`. Crosses the trigger, so it is rebuilt.
	a := New()
	for i := 0; i < n; i++ {
		a.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
		a.MarkSeen(hashOfIndex(i), uint64(i)+1)
	}
	for i := live; i < n; i++ {
		a.Set(slotOf(i), u256.Zero)
	}
	_ = a.PruneSeen(uint64(n))

	// B: the same contents, reached without ever crossing the trigger, so it
	// is never rebuilt.
	b := New()
	for i := 0; i < live; i++ {
		b.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
	}
	b.MarkSeen(hashOfIndex(n-1), uint64(n))

	if len(a.cells) != len(b.cells) || len(a.seen) != len(b.seen) {
		t.Fatalf("the two states do not hold equal contents (cells %d/%d, seen %d/%d); the "+
			"comparison below would be measuring the scenario rather than the rule",
			len(a.cells), len(b.cells), len(a.seen), len(b.seen))
	}
	if a.cellsPeak == b.cellsPeak {
		t.Fatalf("both states ran the same shrink schedule (peak %d); this test asserts nothing "+
			"unless the schedules differ", a.cellsPeak)
	}
	if got, want := a.Root(), b.Root(); got != want {
		t.Fatalf("the shrink schedule reached the state root: rebuilt state %x, un-rebuilt state %x",
			got, want)
	}
}

// A clone must carry the peaks. They cannot reach the root -- which is exactly
// why the differential runner should keep *exercising* that, rather than
// preserving it by accident because clones start at zero and shrink on a
// different schedule from the node they mirror.
func TestCloneCarriesTheHighWaterMarks(t *testing.T) {
	s := New()
	for i := 0; i < 4*shrinkFloor; i++ {
		s.Set(slotOf(i), u256.FromUint64(uint64(i)+1))
		s.MarkSeen(hashOfIndex(i), uint64(i)+1)
	}
	// Materialise BOTH peaks. Set's delete branch raises only cellsPeak, so a
	// prune is needed as well -- without it seenPeak is still 0 here and the
	// seen assertion below compares 0 to 0, which is a test that passes when
	// Clone drops the field entirely.
	s.Set(slotOf(0), u256.Zero)
	_ = s.PruneSeen(1)

	// Guard the guard: an assertion against a zero peak asserts nothing.
	if s.cellsPeak == 0 || s.seenPeak == 0 {
		t.Fatalf("a peak was never materialised (cells %d, seen %d); the comparisons below would "+
			"hold just as well against a Clone that dropped the field", s.cellsPeak, s.seenPeak)
	}

	c := s.Clone()
	if c.cellsPeak != s.cellsPeak {
		t.Errorf("Clone lost cellsPeak: %d, want %d", c.cellsPeak, s.cellsPeak)
	}
	if c.seenPeak != s.seenPeak {
		t.Errorf("Clone lost seenPeak: %d, want %d", c.seenPeak, s.seenPeak)
	}
}

// --- Property 3: the mark is never below the live count --------------------

// Undo reaches s.seen directly on both of its seen paths, so a mark maintained
// at insertion goes stale below the live count and disarms the rule forever.
//
// The scenario is ordinary consensus operation, not an attack: prune at a TTL
// boundary, then reorg across it. Without the fix the mark is left at the
// post-prune population while the map holds the pre-prune one.
func TestSeenPeakIsNeverBelowTheLiveCountAfterUndo(t *testing.T) {
	const n = 8 * shrinkFloor
	s := New()
	log := &UndoLog{}
	for i := 0; i < n; i++ {
		s.MarkSeen(hashOfIndex(i), uint64(i)+1)
	}
	// A block prunes almost the whole set...
	log.SeenRemoved = s.PruneSeen(uint64(n))
	if s.SeenCount() >= n/shrinkDivisor {
		t.Fatalf("the prune did not cross the trigger (%d live of peak %d); the reorg below would "+
			"not exercise the stale-mark path", s.SeenCount(), n)
	}
	// ...and then the chain reorgs across it, re-inflating the map.
	s.Undo(log)
	if s.SeenCount() != n {
		t.Fatalf("Undo restored %d entries, want %d", s.SeenCount(), n)
	}
	if s.seenPeak < s.SeenCount() {
		t.Fatalf("seenPeak %d is below the live count %d after a reorg across a TTL boundary; the "+
			"map can never be released again", s.seenPeak, s.SeenCount())
	}

	// And the rule must still fire afterwards, which is the consequence that
	// makes the stale mark matter.
	old := s.seen
	before := mapPtr(old)
	defer runtime.KeepAlive(old)
	_ = s.PruneSeen(uint64(n))
	if mapPtr(s.seen) == before {
		t.Fatal("the seen map was not rebuilt after a reorg re-inflated it; the shrink rule has been " +
			"disarmed for the process lifetime")
	}
}

// --- Amortisation ----------------------------------------------------------

// The rule must be amortised O(1) against the deletes that drive it, including
// under schedules chosen to break it.
//
// The bound is what makes a Theta(live) rebuild admissible on the fold's hot
// path at all: without it, an adversary who can sit on the trigger buys a full
// map copy per certificate.
//
// The entries a rebuild copies are counted without any hook in production code
// -- the consensus zone does not get a test seam. A rebuild is observed
// *directly*, by the cell map changing identity, and the entries it copied are
// the live count sampled immediately before the operation that triggered it.
//
// The obvious cheaper instrument -- watching cellsPeak step downward, since a
// rebuild is the only thing that re-bases it -- is the one thing this test must
// not use, and the reason is worth recording because the test looked correct
// with it. That signal is computed *downstream* of the re-base, and the
// re-base is exactly the line whose removal makes the rule pathological:
// without it the trigger stays armed after every rebuild, so an adversary
// holding the map at the boundary buys a full copy per certificate. Under that
// mutation the peak never steps down, so the derived counter reported
// `ratio=0.000` on all three shapes and the test PASSED while the code was
// copying 2,048 entries per Set. That is CONTRIBUTING's mirror: "an instrument
// that derives its signal from the state the bug corrupts inherits the bug's
// blindness". Map identity is upstream of the peak and survives the mutation,
// which is the whole reason it is used here.
func TestShrinkIsAmortisedConstant(t *testing.T) {
	const n = 16 * shrinkFloor

	type driver struct {
		s        *State
		ops      int
		copied   int
		rebuilds int
		mapID    uintptr
	}
	set := func(d *driver, i int, v u256.U256) {
		live := len(d.s.cells) // what a rebuild triggered by this op would copy
		d.s.Set(slotOf(i), v)
		d.ops++
		if id := mapPtr(d.s.cells); id != d.mapID {
			if d.mapID != 0 { // the first sample establishes the identity
				d.rebuilds++
				d.copied += live
			}
			d.mapID = id
		}
	}
	nonZero := func(i int) u256.U256 { return u256.FromUint64(uint64(i) + 1) }

	cases := []struct {
		name string
		run  func(d *driver)
	}{
		{"monotone drain", func(d *driver) {
			for i := 0; i < n; i++ {
				set(d, i, nonZero(i))
			}
			for i := 0; i < n; i++ {
				set(d, i, u256.Zero)
			}
		}},
		{"oscillate across the trigger", func(d *driver) {
			for i := 0; i < n; i++ {
				set(d, i, nonZero(i))
			}
			for round := 0; round < 20; round++ {
				for i := n - 1; i >= n/shrinkDivisor-1; i-- {
					set(d, i, u256.Zero)
				}
				for i := n/shrinkDivisor - 1; i < n; i++ {
					set(d, i, nonZero(i))
				}
			}
		}},
		{"sawtooth held at the trigger", func(d *driver) {
			for i := 0; i < n; i++ {
				set(d, i, nonZero(i))
			}
			for i := n - 1; i >= n/shrinkDivisor; i-- {
				set(d, i, u256.Zero)
			}
			for round := 0; round < 50_000; round++ {
				set(d, 0, u256.Zero)
				set(d, 0, nonZero(0))
			}
		}},
	}

	// A generous ceiling: the measured worst case across these three shapes is
	// well under 0.2 copies per Set. The bar is 1.0 because the property is
	// "bounded by a constant", not "equal to the number measured today" -- a
	// rule that copied more entries than it saw operations would not be
	// amortised at all, and one that merely drifted from 0.17 to 0.3 would
	// still be correct.
	const bar = 1.0
	for _, c := range cases {
		d := &driver{s: New()}
		c.run(d)
		ratio := float64(d.copied) / float64(d.ops)
		t.Logf("%-30s ops=%-8d rebuilds=%-4d entries copied=%-9d ratio=%.3f",
			c.name, d.ops, d.rebuilds, d.copied, ratio)
		if ratio > bar {
			t.Errorf("%s: %.3f entries copied per Set exceeds the amortised bound of %.1f",
				c.name, ratio, bar)
		}
	}
}

// The seen half of the same property, which needs its own test because it is
// driven by a different operation and instrumented on a different sample.
//
// TestShrinkIsAmortisedConstant above drives s.cells through Set, and the line
// whose removal it catches is maybeShrinkCells' re-base. The identical line in
// maybeShrinkSeen was uncovered: deleting it left the entire package green,
// because nothing here drove the seen map across its trigger more than once.
//
// It is not a benign line. PruneSeen is the only thing that empties s.seen in
// ordinary operation and it runs every block (F10). Without the re-base the
// mark stays at the pre-prune peak forever, so once the live set is under the
// trigger *every subsequent PruneSeen rebuilds the whole map* rather than one
// call doing it and re-arming. Measured by the shape below: 1 rebuild and
// 0.237 entries copied per deleted entry with the line, 5,000 rebuilds and
// 1184.348 without -- a full map copy per block, indefinitely, for an attacker
// who sets the inclusion rate.
//
// Two deliberate differences from the cells instrument, both forced by
// PruneSeen deleting many entries per call rather than one:
//
//   - The denominator is entries *deleted*, not calls. Deletes are what drive
//     a map below its mark, so they are the operations the cost must be
//     amortised against; counting calls would let one Theta(live) call hide
//     behind one increment.
//   - The copy cost is sampled *after* the operation, not before. A rebuild
//     copies len(s.seen) as it stands once the deletes are done, so the
//     post-op count is exactly what was copied. The cells test samples before
//     its op only because Set deletes exactly one entry, making the two differ
//     by one; here they differ by thousands.
//
// The rebuild is still observed by map identity, upstream of the mark, for the
// reason the comment above TestShrinkIsAmortisedConstant gives at length: an
// instrument derived from the mark cannot see the mark's own re-base removed.
func TestSeenShrinkIsAmortisedConstant(t *testing.T) {
	const n = 16 * shrinkFloor
	const rounds = 5_000

	s := New()
	mapID := mapPtr(s.seen)
	rebuilds, copied, deleted := 0, 0, 0

	// prune runs one PruneSeen and accounts for what it cost: the entries it
	// removed, and -- if the map changed identity -- the entries the rebuild
	// copied.
	prune := func(below uint64) {
		before := len(s.seen)
		_ = s.PruneSeen(below)
		deleted += before - len(s.seen)
		if id := mapPtr(s.seen); id != mapID {
			rebuilds++
			copied += len(s.seen) // exactly what the rebuild copied
			mapID = id
		}
	}

	for i := 0; i < n; i++ {
		s.MarkSeen(hashOfIndex(i), uint64(i)+1)
	}
	// Seed the adversarial position: drained to exactly the trigger, which is
	// the last population that must NOT rebuild.
	prune(uint64(n - n/shrinkDivisor + 1))
	if len(s.seen) != n/shrinkDivisor {
		t.Fatalf("seed prune left %d live, want exactly the trigger at %d", len(s.seen), n/shrinkDivisor)
	}
	if rebuilds != 0 {
		t.Fatalf("the seed prune rebuilt at exactly peak/%d; the rule fires on live < peak/%d",
			shrinkDivisor, shrinkDivisor)
	}
	if s.seenPeak != n {
		t.Fatalf("seenPeak %d, want the pre-prune peak %d; this shape is not sitting on the trigger",
			s.seenPeak, n)
	}

	// Now hold it there: each round expires one entry and admits one, so the
	// live count oscillates by one across the boundary for as long as the
	// attacker cares to pay for it.
	for r := 0; r < rounds; r++ {
		prune(uint64(n - n/shrinkDivisor + 2 + r))
		s.MarkSeen(hashOfIndex(n+r), uint64(n+r)+1)
	}

	ratio := float64(copied) / float64(deleted)
	t.Logf("sawtooth held at the trigger: deletes=%d rebuilds=%d entries copied=%d ratio=%.3f",
		deleted, rebuilds, copied, ratio)

	if deleted == 0 {
		t.Fatal("no entries were deleted; the shape drove nothing and the ratio below is vacuous")
	}

	// Assert the rebuild count directly, and treat it as the primary signal.
	//
	// The ratio alone is a blunt instrument here, because 12,288 of the 17,288
	// deletes come from the seed prune, which copies nothing. At ~4,096 entries
	// per rebuild it takes about five rebuilds to cross a bar of 1.0, so the
	// ratio's real sensitivity is "five or more rebuilds" -- it would sit under
	// the bar for a re-base that was merely wrong rather than absent (setting
	// the mark to len*2, say). The property the rule actually claims is *one
	// collapse, one rebuild*: after a rebuild the mark is the live count, so
	// re-arming needs fourfold growth, which this shape never supplies.
	// rebuilds is observable, so assert it rather than inferring it.
	if rebuilds != 1 {
		t.Errorf("%d rebuilds for a single collapse across the trigger, want exactly 1; the mark is "+
			"not being re-based to the live count, so the rule re-arms without the fourfold growth "+
			"that makes it amortised", rebuilds)
	}
	// The same bound and the same reasoning as the cells case: the property is
	// "bounded by a constant", not "equal to today's number". Measured 0.237
	// here against 1184.348 with the re-base removed, so the bar sits with a
	// 4x margin below it and a ~1,200x margin above.
	const bar = 1.0
	if ratio > bar {
		t.Errorf("%.3f entries copied per deleted entry exceeds the amortised bound of %.1f; "+
			"the seen map is being rebuilt on every prune rather than once per collapse",
			ratio, bar)
	}
}

func hashOfIndex(i int) types.Hash {
	a := addrOf(i)
	var h types.Hash
	copy(h[:], a[:])
	return h
}
