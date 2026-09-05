// A differential between the shipped epoch state root and a second
// implementation that does not import zycord/core/ssz at all.
//
// What makes this different from every root check already in the tree: the
// existing ones — sim/refold's fold comparison and root_identity_test.go's
// "definition written out independently" — both call ssz.ListRoot, so the tag,
// the tree, zeroHashes, MixInLength and nextPow2 are the same code object on
// both sides. They are one implementation agreeing with itself. core/state/naive
// shares BLAKE3 and nothing else, and `make check-imports` holds that boundary
// against the toolchain's dependency graph.
//
// The four things the audit found committed nowhere in spec/vectors — the spent
// leaf tag, the registry's sort order, the spent subtree's padding and its
// dynamic capacity — are what the tests below are built around, which is why
// every one of them drives a *non-empty* registry.
package state_test

import (
	"bytes"
	"fmt"
	"math/rand"
	"sort"
	"testing"

	"zycord/core/state"
	"zycord/core/state/naive"
	"zycord/core/types"
	"zycord/core/u256"
)

// shadow is an independent model of the two structures the root covers. It
// exists so the naive merkleiser is fed from something other than the State it
// is checking: driving naive.Root from s.SortedCells()/s.SortedSpent() would
// hand it the shipped comparator and make the sort order untestable, which is
// half of what the audit found uncovered.
//
// It models exactly the three mutators that reach the root — Set, MarkSpent and
// Undo — and nothing else. The seen set is excluded from the root by rule, so
// it is excluded here.
type shadow struct {
	cells map[types.Slot][32]byte
	spent map[types.Address]bool
}

func newShadow() *shadow {
	return &shadow{
		cells: make(map[types.Slot][32]byte),
		spent: make(map[types.Address]bool),
	}
}

// set mirrors State.Set: writing zero deletes, so a drained cell is
// indistinguishable from one that never existed.
func (m *shadow) set(slot types.Slot, v [32]byte) {
	var zero [32]byte
	if v == zero {
		delete(m.cells, slot)
		return
	}
	m.cells[slot] = v
}

func (m *shadow) markSpent(a types.Address) { m.spent[a] = true }

// input renders the model as the naive merkleiser's arguments. Map iteration is
// unordered on purpose: naive.Root sorts, and if it did not, this test would be
// flaky rather than quietly agreeing with the shipped comparator.
func (m *shadow) input() ([]naive.Cell, [][32]byte) {
	cells := make([]naive.Cell, 0, len(m.cells))
	for slot, v := range m.cells {
		cells = append(cells, naive.Cell{Addr: slot.Addr, Word: slot.Word, Value: v})
	}
	spent := make([][32]byte, 0, len(m.spent))
	for a := range m.spent {
		spent = append(spent, a)
	}
	return cells, spent
}

// checkAgrees is the assertion the whole file exists for.
//
// It makes two statements, and keeps them apart so a failure says which broke:
// that the shipped State still holds what the model holds, and that the two
// merkleisations of those contents agree bit for bit.
func checkAgrees(t *testing.T, s *state.State, m *shadow, what string) {
	t.Helper()

	live := s.SortedCells()
	if got, want := len(live), len(m.cells); got != want {
		t.Fatalf("%s: state holds %d cells, model holds %d", what, got, want)
	}
	for _, slot := range live {
		want, ok := m.cells[slot]
		if !ok {
			t.Fatalf("%s: state holds slot %x/%x the model does not", what, slot.Addr, slot.Word)
		}
		if got := s.Get(slot).Bytes(); got != want {
			t.Fatalf("%s: slot %x/%x is %x in the state and %x in the model",
				what, slot.Addr, slot.Word, got, want)
		}
	}
	if got, want := s.SpentCount(), len(m.spent); got != want {
		t.Fatalf("%s: registry holds %d entries, model holds %d", what, got, want)
	}
	for _, a := range s.SortedSpent() {
		if !m.spent[a] {
			t.Fatalf("%s: registry holds %x the model does not", what, a)
		}
	}

	cells, spent := m.input()
	if got, want := s.Root(), naive.Root(cells, spent); got != want {
		t.Fatalf("%s: shipped root %x, independent root %x (%d cells, %d registry entries)",
			what, got, want, len(cells), len(spent))
	}
}

// addressPool builds addresses whose ordering is hostile to a comparator that
// is nearly right: pairs that differ only in the first byte, pairs that agree on
// 31 bytes and differ only in the last, the all-zero and all-ones extremes, and
// unstructured ones underneath. A comparator that compares the wrong end, or
// compares a prefix, reorders this pool; a pool of uniformly random addresses
// would be reordered too, but would not say which end the fault was on.
func addressPool(rng *rand.Rand, n int) []types.Address {
	out := make([]types.Address, 0, n)
	var zero, ones types.Address
	for i := range ones {
		ones[i] = 0xff
	}
	out = append(out, zero, ones)

	var stem types.Address
	rng.Read(stem[:])
	for i := 0; len(out) < n && i < 24; i++ {
		tail := stem
		tail[31] = byte(i * 7)
		head := stem
		head[0] = byte(i * 11)
		out = append(out, tail, head)
	}
	for len(out) < n {
		var a types.Address
		rng.Read(a[:])
		out = append(out, a)
	}
	return out[:n]
}

// wordPool mixes the low words a hand-written protocol cell occupies with words
// that look like a hash, so that one address holds slots at both ends of the
// word ordering.
func wordPool(rng *rand.Rand, n int) [][32]byte {
	out := make([][32]byte, n)
	for i := range out {
		if i < 2 {
			out[i][31] = byte(i)
			continue
		}
		rng.Read(out[i][:])
	}
	return out
}

func randomValue(rng *rand.Rand) [32]byte {
	var v [32]byte
	rng.Read(v[:])
	if v == [32]byte{} {
		v[31] = 1
	}
	return v
}

// TestTheSpentSubtreeIsCommittedAtEveryPaddingShape walks the registry across
// every leaf count from 0 to 33 and over the two powers of two above that.
//
// This is the direct answer to the audit's measurement, and the premise has now
// narrowed twice while the conclusion has not moved at all. Every committed
// state root in spec/vectors was taken over ListRoot([], 1) when this test was
// written. TWO vectors now commit over a non-empty registry, and they close
// different things:
//
//   - 059-epoch-boundary-over-a-spent-registry carries TWO entries, which
//     closes the tag, the comparator and the capacity at two;
//   - 063-coinbase-burned-into-a-payee-spent-in-the-same-block carries ONE,
//     which closes the tag and the capacity at one — nextPow2(1) = 1 against
//     nextPow2(2) = 2 is a real choice — and closes the comparator not at all,
//     because one element has one permutation.
//
// Measured rather than reasoned from the shape: moving TagStateSpent fails both
// vectors, capacity nextPow2(n+1) fails both, and reversing State.SortedSpent
// fails 059 and 011 while 063 passes. spec/README.md states the same split, so
// this comment and the normative surface agree by construction rather than by
// somebody remembering to update both.
//
// **What is closed is still only the exactly-filled shapes, one and two.** The
// padding of a partially filled spent subtree is committed nowhere — a count of
// 5 pads to 8 and a count of 33 pads to 64 — and neither is any capacity above
// two; outside this file nothing has an opinion about what those roots are. The
// sweep below is therefore the same test it was, over a domain the corpus still
// does not reach, rather than a test whose reason expired.
func TestTheSpentSubtreeIsCommittedAtEveryPaddingShape(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5be47))
	pool := addressPool(rng, 132)

	counts := make([]int, 0, 36)
	for n := 0; n <= 33; n++ {
		counts = append(counts, n)
	}
	counts = append(counts, 63, 64, 65, 127, 128, 129)

	for _, n := range counts {
		t.Run(fmt.Sprintf("registry=%d", n), func(t *testing.T) {
			s := state.New()
			m := newShadow()

			// One cell, so the failure cannot be blamed on an empty cell
			// subtree, and so the two sides of the final Sum are distinguishable.
			slot := types.Slot{Addr: pool[0], Word: [32]byte{31: 9}}
			v := randomValue(rng)
			s.Set(slot, u256.FromBytes(v))
			m.set(slot, v)

			// Insertion order is deliberately not sorted order: the registry is
			// filled from the end of the pool backwards.
			for i := 0; i < n; i++ {
				a := pool[len(pool)-1-i]
				s.MarkSpent(a)
				m.markSpent(a)
			}
			if s.SpentCount() != n {
				t.Fatalf("registry holds %d entries, wanted %d — the pool has duplicates", s.SpentCount(), n)
			}
			checkAgrees(t, s, m, fmt.Sprintf("registry of %d", n))
		})
	}
}

// TestTheRegistryIsCommittedInAddressOrderRatherThanInsertionOrder builds the
// same registry three ways and holds each against the independent merkleisation.
//
// # Which assertion does which job, because an assertion that cannot fail reads
// as coverage
//
// An earlier version of this comment claimed the two shipped-against-shipped
// comparisons isolated the comparator. They do not, and saying so was worse
// than omitting them:
//
//   - forward.Root() == backward.Root() is shipped against shipped, and cannot
//     fail for ANY deterministic comparator, right or wrong — both sides call
//     the same SortedSpent. It says nothing about the sort *order*. What it does
//     say is that the root does not depend on insertion order at all: a leaf
//     array that kept arrival order, or a map iterated in consensus order, would
//     break it, and neither of those is a comparator fault.
//   - short.Root() != forward.Root() is shipped against shipped too. It fixes
//     only that a registry entry reaches the root at all — that the merkleisation
//     is not ignoring the leaf that sorts first.
//   - checkAgrees is the only assertion here that can see a wrong comparator,
//     because naive re-sorts from the model with its own bytes.Compare. It is
//     applied to all three states for that reason. A reversed SortedSpent is
//     caught by it and by neither of the other two — measured, not assumed: the
//     mutation grid in the PR reports that mutant killed at registry=2, by this
//     assertion alone.
func TestTheRegistryIsCommittedInAddressOrderRatherThanInsertionOrder(t *testing.T) {
	rng := rand.New(rand.NewSource(0x0d3e5))
	pool := addressPool(rng, 17)

	forward, backward := state.New(), state.New()
	m := newShadow()
	for i := range pool {
		forward.MarkSpent(pool[i])
		backward.MarkSpent(pool[len(pool)-1-i])
		m.markSpent(pool[i])
	}
	if forward.Root() != backward.Root() {
		t.Fatalf("insertion order reached the root: %x vs %x", forward.Root(), backward.Root())
	}
	checkAgrees(t, forward, m, "registry filled forwards")
	checkAgrees(t, backward, m, "registry filled backwards")

	// And the ordering is load-bearing rather than a hash of an unordered set:
	// dropping the address that sorts first must move the root, and the shorter
	// registry must still be the one the independent merkleisation computes.
	sorted := append([]types.Address(nil), pool...)
	sort.Slice(sorted, func(i, j int) bool { return bytes.Compare(sorted[i][:], sorted[j][:]) < 0 })
	short := state.New()
	shortModel := newShadow()
	for _, a := range sorted[1:] {
		short.MarkSpent(a)
		shortModel.markSpent(a)
	}
	if short.Root() == forward.Root() {
		t.Fatal("dropping the first registry entry did not move the root")
	}
	checkAgrees(t, short, shortModel, "registry missing its first entry")
}

// TestNaiveMerkleisationAgreesUnderRandomisedMutation drives the state through
// Set, MarkSpent, Undo, Clone and interleaved Root and holds the two
// merkleisations against each other throughout.
//
// # Axes explored
//
//  1. cell writes — fresh slots, overwrites of live slots, and writes of zero
//     (the delete path, which is what makes a drained cell indistinguishable
//     from one that never existed);
//  2. registry growth, driven so the entry count crosses several powers of two
//     and therefore several capacities;
//  3. Undo over a batch that mixes cell restores with registry removals;
//  4. Clone, whose root must equal the original's — and this arm is weaker than
//     it looks. ssz.Tree's own doc comment says no assertion about root *values*
//     can detect a Clone that failed to copy, because the tree is self-healing:
//     a stale or shared tree costs recomputation and never correctness. What
//     this arm fixes is that a clone commits to the state it was taken from;
//     that the copy is a copy is asserted by address, in
//     core/ssz/tree_internal_test.go, and cannot be asserted here;
//  5. Root call placement — the cached fast path, the dirty-merge path and the
//     from-scratch path are selected by *when* Root is called, so the call is a
//     step kind rather than a fixture;
//  6. address shape — see addressPool: adjacent addresses that differ only in
//     the first or only in the last byte.
//
// # Limits — what this cannot reach, stated beside the number
//
// The counts below are a lower bound on what was explored, not a claim about
// the space. Specifically this test does NOT reach:
//
//   - the shrink and dirty-reset thresholds (both 1024). 32 cell addresses × 4
//     words bounds the live set at 128, so maybeShrinkCells never fires and the
//     dirty sets are never large enough to be thrown away rather than cleared.
//     That is the next test's job, and it is named for it.
//   - the address space, and this is the widest gap. Addresses come from two
//     pools — 32 for cells, 162 for the registry — drawn from one seed, so a
//     comparator that is wrong only on addresses these pools do not contain
//     survives here. addressPool is shaped rather than uniform for that reason,
//     but a shaped sample is still a sample of 2^256.
//   - in THIS test, any capacity above 256. The capacities a run actually
//     committed to are logged at the end rather than asserted in prose, because
//     they are a property of the pools and the seed and will move if either
//     does. Read across the file before quoting that as the suite's ceiling:
//     TestNaiveMerkleisationAgreesAcrossTheShrinkAndDirtyResetThresholds commits
//     to a 2048-capacity cell subtree, which is the largest anything here
//     reaches. Above that nothing does: the rule at the millions of registry
//     entries R1-C3-iii's never-prune guarantee accumulates over a chain's
//     lifetime is unchecked, and nothing here is cheap enough to check it.
//   - which of Root's three internal paths a given call took. from-scratch,
//     dirty-merge and the cached fast path are selected by *when* Root is called,
//     and this test drives all three by construction — but nothing that runs
//     counts them, and a counter inferring them from the driver's own model
//     would be the driver confirming itself. That both leaf-building paths are
//     reached is held by the two spent-leaf-tag mutants in the PR's grid, killed
//     at state.go:432 and at state.go:497 independently. It is probe-verified,
//     not test-verified, and it stops being either the day nobody re-runs the
//     probes.
//   - PruneSeen and MarkSeen. The seen set is excluded from the root by rule
//     (F14), so nothing here says anything about it — including that it is still
//     excluded.
//   - anything below BLAKE3. naive shares core/crypto/blake3, and u256's
//     big-endian byte order reaches the shipped leaf through State.Get; a defect
//     in either is invisible to this differential. The mix-in-length encoding is
//     a weaker version of the same gap: a *change* to it does move the shipped
//     root and is caught, but naive derived the encoding by reading core/ssz, so
//     the two agreeing says nothing about whether either matches SSZ.
//   - concurrency. Root's cacheMu contract is pinned by
//     TestConcurrentRootOnDirtyState, not here.
//
// # Cost
//
// It goes into `make ci` twice, once plain and once under -race, so the step
// count is chosen against that rather than against how long the machine will
// tolerate. The comparison, not the mutation, is what costs: the state is kept
// deliberately small and the root is compared on a fraction of the steps, except
// below 64 registry entries where every state is compared because those checks
// are the cheapest in the run. The four tests in this file measure at roughly
// 0.6 s of test time plain and 14 s under -race, net of this package's own
// build-and-start floor, which is ~20x and is the figure that matters for the
// `race` target. No ratio against the rest of core/state is stated here: two
// paired measurements of this same code put it at 1/4.7 and 1/9.6, because the
// denominator moves with machine load while the numerator barely does.
func TestNaiveMerkleisationAgreesUnderRandomisedMutation(t *testing.T) {
	const steps = 24000

	rng := rand.New(rand.NewSource(0x40501))
	cellAddrs := addressPool(rng, 32)
	burnAddrs := append(append([]types.Address(nil), cellAddrs...), addressPool(rng, 130)...)
	words := wordPool(rng, 4)

	s := state.New()
	m := newShadow()

	// Anti-vacuity: a driver that never took a branch proves nothing about it,
	// and a step distribution that silently stopped reaching one is exactly the
	// failure this counts against.
	var deletes, undos, commits, clones, roots, marks int
	spentCaps := make(map[int]bool)
	cellCaps := make(map[int]bool)

	// Mutations arrive in batches, because a block is what the undo log is a
	// batch of, and because a driver that undoes back to the last undo never
	// grows: an earlier version of this test ended at zero live cells and one
	// registry entry after 6,000 steps, agreeing with the naive merkleiser about
	// almost nothing. Most batches commit; a minority are reversed.
	for step := 0; step < steps; {
		var pending state.UndoLog
		var pendingCells [][32]byte // the model's own copy of each restored value

		ops := 1 + rng.Intn(12)
		for i := 0; i < ops; i++ {
			switch r := rng.Intn(100); {
			case r < 45: // write a live value
				slot := types.Slot{Addr: cellAddrs[rng.Intn(len(cellAddrs))], Word: words[rng.Intn(len(words))]}
				v := randomValue(rng)
				pending.Cells = append(pending.Cells, state.CellUndo{Slot: slot, Old: s.Get(slot)})
				pendingCells = append(pendingCells, m.cells[slot])
				s.Set(slot, u256.FromBytes(v))
				m.set(slot, v)

			case r < 65: // drain a cell
				slot := types.Slot{Addr: cellAddrs[rng.Intn(len(cellAddrs))], Word: words[rng.Intn(len(words))]}
				pending.Cells = append(pending.Cells, state.CellUndo{Slot: slot, Old: s.Get(slot)})
				pendingCells = append(pendingCells, m.cells[slot])
				s.Set(slot, u256.U256{})
				m.set(slot, [32]byte{})
				deletes++

			default: // burn an address
				a := burnAddrs[rng.Intn(len(burnAddrs))]
				if !m.spent[a] {
					pending.SpentAdded = append(pending.SpentAdded, a)
				}
				s.MarkSpent(a)
				m.markSpent(a)
				marks++
			}
			step++

			// A root taken *inside* the batch, on a dirty state that is about to
			// be reversed. This is the shape fold.apply leaves behind when F14
			// rejects a block, and it is the one that exercises the dirty-merge
			// path rather than the cached one.
			if rng.Intn(24) == 0 {
				checkAgrees(t, s, m, fmt.Sprintf("step %d, mid-batch", step))
				spentCaps[capacityOf(s.SpentCount())] = true
				cellCaps[capacityOf(len(m.cells))] = true
				roots++
			}
		}

		if rng.Intn(4) == 0 {
			s.Undo(&pending)
			for i := len(pending.Cells) - 1; i >= 0; i-- {
				m.set(pending.Cells[i].Slot, pendingCells[i])
			}
			for _, a := range pending.SpentAdded {
				delete(m.spent, a)
			}
			undos++
		} else {
			commits++
		}
		step++

		// Every small registry is committed to, not a random sample of them: the
		// low capacities are where the padding is deepest relative to the leaves
		// and they are also the cheapest checks in the run, so sampling them is
		// the one economy not worth making.
		if rng.Intn(12) == 0 || s.SpentCount() < 64 {
			checkAgrees(t, s, m, fmt.Sprintf("step %d, batch sealed", step))
			spentCaps[capacityOf(s.SpentCount())] = true
			cellCaps[capacityOf(len(m.cells))] = true
			roots++
		}
		if rng.Intn(40) == 0 {
			c := s.Clone()
			cells, spent := m.input()
			want := naive.Root(cells, spent)
			if got := c.Root(); got != want {
				t.Fatalf("step %d: clone roots at %x, independent root %x", step, got, want)
			}
			if got := s.Root(); got != want {
				t.Fatalf("step %d: original roots at %x after Clone, independent root %x", step, got, want)
			}
			clones++
		}
	}
	checkAgrees(t, s, m, "final")

	// The existential this test actually supports: at least this much was
	// reached. It is not a claim that nothing else exists.
	if roots < 1000 || undos < 200 || commits < 500 || clones < 50 || deletes < 1000 || marks < 1000 {
		t.Fatalf("driver did not reach its own axes: %d roots, %d undos, %d commits, %d clones, %d deletes, %d marks",
			roots, undos, commits, clones, deletes, marks)
	}
	if s.SpentCount() == 0 {
		t.Fatal("the registry ended empty — this test would then be checking the same constant the corpus does")
	}
	// A root taken at k distinct capacities is a root taken at k distinct tree
	// depths, each with its own amount of padding. That, and not the step count,
	// is what makes the capacity rule reachable at all — so it is asserted rather
	// than hoped for, and both subtrees are counted because a run that only ever
	// grew one of them would look identical from the step counters.
	//
	// The margins are one each and are stated because a guard with none is one
	// edit from vacuous: the run reaches 8 registry capacities against a floor of
	// 7 and 6 cell capacities against a floor of 5. It skips the capacities a
	// batch jumps over — a batch adds several registry entries at once, so the
	// count can step from 1 to 5 and never be rooted at 2 — and those are exactly
	// the ones TestTheSpentSubtreeIsCommittedAtEveryPaddingShape covers
	// exhaustively, at every count from 0 to 33. Neither test's coverage is a
	// reason to weaken the other's floor.
	spent, cell := sortedCapacities(spentCaps), sortedCapacities(cellCaps)
	if len(spent) < 7 {
		t.Fatalf("the registry root was only ever taken at these capacities: %v", spent)
	}
	if len(cell) < 5 {
		t.Fatalf("the cell root was only ever taken at these capacities: %v", cell)
	}
	t.Logf("%d steps: %d root comparisons, %d batches reversed, %d committed, %d clones, "+
		"%d drains, %d burns; ended at %d live cells and %d registry entries; "+
		"capacities committed to: registry %v, cells %v",
		steps, roots, undos, commits, clones, deletes, marks,
		len(m.cells), len(m.spent), spent, cell)
}

func sortedCapacities(m map[int]bool) []int {
	out := make([]int, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Ints(out)
	return out
}

func capacityOf(n int) int {
	c := 1
	for c < n {
		c *= 2
	}
	return c
}

// TestNaiveMerkleisationAgreesAcrossTheShrinkAndDirtyResetThresholds crosses the
// two size-keyed branches the previous test names as out of reach: the dirty set
// large enough to be thrown away rather than cleared (dirtyResetThreshold, 1024)
// and a cell map that has fallen far enough below its own high-water mark to be
// reallocated (shrinkFloor 1024, shrinkDivisor 4).
//
// Both are cache and allocation machinery with no consensus meaning, which is
// precisely why they are worth a differential: a root that changed when a map
// was reallocated would be a fork nobody was looking for.
//
// # Limits
//
// It crosses the two thresholds and nothing else. It is a straight line — grow,
// commit, drain, commit — with no undo, no clone and no interleaving, because a
// randomised driver at this size costs seconds rather than milliseconds. It also
// does not cross the *seen* map's shrink, which the root does not cover.
func TestNaiveMerkleisationAgreesAcrossTheShrinkAndDirtyResetThresholds(t *testing.T) {
	rng := rand.New(rand.NewSource(0x5417c))

	s := state.New()
	m := newShadow()

	const grown = 1400 // > dirtyResetThreshold, so the first Root resets rather than clears
	slots := make([]types.Slot, grown)
	for i := range slots {
		var a types.Address
		rng.Read(a[:])
		slots[i] = types.Slot{Addr: a, Word: [32]byte{31: byte(i % 251)}}
		v := randomValue(rng)
		s.Set(slots[i], u256.FromBytes(v))
		m.set(slots[i], v)
	}
	// A registry that crosses a power of two while the cells are at their peak.
	registry := addressPool(rng, 70)
	for _, a := range registry {
		s.MarkSpent(a)
		m.markSpent(a)
	}
	checkAgrees(t, s, m, "at the cell high-water mark")

	// Drain to below peak/shrinkDivisor, which is what arms maybeShrinkCells.
	for _, slot := range slots[:grown-200] {
		s.Set(slot, u256.U256{})
		m.set(slot, [32]byte{})
	}
	if s.SpentCount() != len(registry) {
		t.Fatalf("draining cells moved the registry: %d entries, wanted %d", s.SpentCount(), len(registry))
	}
	checkAgrees(t, s, m, "after the cell map shrank")

	// And back up, on the reallocated map.
	for _, slot := range slots[:400] {
		v := randomValue(rng)
		s.Set(slot, u256.FromBytes(v))
		m.set(slot, v)
	}
	checkAgrees(t, s, m, "after regrowing onto the shrunk map")
}
