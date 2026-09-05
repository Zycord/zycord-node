// Package state holds the three pieces of consensus state the fold reads and
// writes: the cells, the spent-address registry, and the seen set.
//
// Maps are used for storage but are *never* iterated in consensus order —
// every traversal sorts first. Non-determinism from map iteration is the
// classic way a consensus implementation forks against itself, and this
// package is the only place in core/ that holds a map at all.
//
// The epoch state root is maintained from a dirty set (ARCHITECTURE §14), not
// rebuilt from scratch: the sorted key order and the leaf hashes of both
// subtrees are cached, and a Root() call re-hashes only the leaves whose slot
// or registry entry was written since the last call. The *definition* is
// unchanged and the value is bit-identical to the from-scratch computation for
// every state. `rootFromScratch` in root_identity_test.go is the same
// definition without the cache, and TestRootIsBitIdenticalToFromScratch holds
// the two against each other over states built by every path that reaches here,
// including undo.
//
// That check is about the *cache*, not about the merkleisation: rootFromScratch
// calls ssz.ListRoot and nextPow2 like Root does, so a wrong tag or capacity
// moves both sides together. The merkleisation is checked against
// core/state/naive, which cannot reach core/ssz by any path, in
// naive_differential_test.go.
//
// What is *not* achievable, and what §14 was read as promising, is a cost
// proportional to the dirty set alone. The leaves are a canonically **sorted
// list**, so inserting one registry entry shifts the position of every leaf
// after it and no cached internal merkle node past that point survives; and
// the capacity is `nextPow2(len(leaves))`, which re-shapes the whole tree
// when the live count crosses a power of two. A position-stable root — a
// sparse merkle tree keyed by slot — would be incremental in the strong
// sense, but it is a different value and therefore a hard fork. So the merkle
// build stays Θ(N) and the sort, which was the dominant term, is gone.
//
// Concretely, and this is the honest headline rather than the flattering one:
// only the *hashing* is proportional to the dirty set. refreshLeaves rebuilds
// the whole key/leaf array whenever any key is dirty, and ssz.Tree compares
// every leaf slot, so no root is cheaper than a full pass over the live state.
// One new cell or one RETIRE — a single write — costs 7–8× less than the
// from-scratch build, not the 28–73× that writes to already-existing cells
// show. root_bench_test.go measures all six regimes and §14 tabulates them.
package state

import (
	"sort"
	"sync"

	"zycord/core/crypto"
	"zycord/core/ssz"
	"zycord/core/types"
	"zycord/core/u256"
)

// SeenEntry is a certificate id with the height beyond which it can no longer
// be included, and is therefore prunable.
type SeenEntry struct {
	ID  types.Hash
	TTL uint64
}

// CellUndo restores one cell to its previous value.
type CellUndo struct {
	Slot types.Slot
	Old  u256.U256
}

// UndoLog is everything needed to reverse one block exactly.
//
// It is cheap precisely because writes are declared: undo is a reversed list of
// pairs, not a re-execution. Restoring the seen set and the registry alongside
// the cells is what makes the billing law survive reorgs — a certificate
// re-included on the new branch nets to one bill, never two.
type UndoLog struct {
	Cells       []CellUndo
	SpentAdded  []types.Address
	SeenAdded   []types.Hash
	SeenRemoved []SeenEntry
}

// State is the mutable consensus state.
type State struct {
	cells map[types.Slot]u256.U256
	spent map[types.Address]struct{}
	seen  map[types.Hash]uint64

	// High-water marks for the shrink rule below. They are hints, not
	// state: nothing derived from them reaches the root, and two nodes that
	// disagree about them still agree about every consensus value. See
	// maybeShrinkCells.
	//
	// s.spent has no counterpart and must not get one: registry entries are
	// never pruned (R1-C3-iii), so the map only ever grows and there is
	// nothing to release.
	cellsPeak int
	seenPeak  int

	// The root cache. `cellKeys`/`cellLeaves` and `spentKeys`/`spentLeaves`
	// are parallel arrays in canonical order, valid only when `cached` is
	// true. `dirtyCells`/`dirtySpent` name the keys written since the arrays
	// were last brought up to date; they are *sets of keys*, never iterated in
	// consensus order — every use sorts first, exactly as SortedCells does.
	// They are reset rather than cleared once large, because `clear` keeps a
	// map's buckets and chain.load dirties one key per live entry — see
	// resetDirtyCells.
	//
	// cacheMu guards every field below it, and it exists because Root() writes
	// them. See the comment on Root.
	cacheMu     sync.Mutex
	cached      bool
	cellKeys    []types.Slot
	cellLeaves  []types.Hash
	spentKeys   []types.Address
	spentLeaves []types.Hash
	dirtyCells  map[types.Slot]struct{}
	dirtySpent  map[types.Address]struct{}
	cellTree    *ssz.Tree
	spentTree   *ssz.Tree
	root        types.Hash
	rootValid   bool
}

// New returns empty state: no cells, no spent addresses, no seen ids. This is
// exactly the pre-genesis state, and `zcd genesis` starts from it.
func New() *State {
	return &State{
		cells:      make(map[types.Slot]u256.U256),
		spent:      make(map[types.Address]struct{}),
		seen:       make(map[types.Hash]uint64),
		dirtyCells: make(map[types.Slot]struct{}),
		dirtySpent: make(map[types.Address]struct{}),
		cellTree:   ssz.NewTree(),
		spentTree:  ssz.NewTree(),
	}
}

// Clone returns an independent deep copy. The differential runner and the
// vector generator rely on it; the fold does not.
//
// Clone reads the root cache, which Root writes, so it takes cacheMu for the
// same reason Root does — Chain.Snapshot and Chain.StateRoot both run under the
// chain's *shared* lock and can therefore run at the same time.
func (s *State) Clone() *State {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()
	out := &State{
		cellsPeak: s.cellsPeak,
		seenPeak:  s.seenPeak,

		cells:      make(map[types.Slot]u256.U256, len(s.cells)),
		spent:      make(map[types.Address]struct{}, len(s.spent)),
		seen:       make(map[types.Hash]uint64, len(s.seen)),
		dirtyCells: make(map[types.Slot]struct{}, len(s.dirtyCells)),
		dirtySpent: make(map[types.Address]struct{}, len(s.dirtySpent)),

		cached:      s.cached,
		cellKeys:    append([]types.Slot(nil), s.cellKeys...),
		cellLeaves:  append([]types.Hash(nil), s.cellLeaves...),
		spentKeys:   append([]types.Address(nil), s.spentKeys...),
		spentLeaves: append([]types.Hash(nil), s.spentLeaves...),
		cellTree:    s.cellTree.Clone(),
		spentTree:   s.spentTree.Clone(),
		root:        s.root,
		rootValid:   s.rootValid,
	}
	for k := range s.dirtyCells {
		out.dirtyCells[k] = struct{}{}
	}
	for k := range s.dirtySpent {
		out.dirtySpent[k] = struct{}{}
	}
	for k, v := range s.cells {
		out.cells[k] = v
	}
	for k := range s.spent {
		out.spent[k] = struct{}{}
	}
	for k, v := range s.seen {
		out.seen[k] = v
	}
	return out
}

// Get returns a cell's value. Absent cells read as zero — there is no
// "missing" value in the model, only zero.
//
// A caller holding a *sparse* State — one filled from a partial fetch rather
// than by folding — therefore cannot tell a cell that is empty from one it
// never asked about, and zero is the benign answer of the two. That is not
// fixed here and will not be: see docs/decisions/sparse-state-readers.md, and
// wallet/session.View for the pattern such a caller is expected to follow.
func (s *State) Get(slot types.Slot) u256.U256 { return s.cells[slot] }

// Set writes a cell. Writing zero deletes the entry, so that a cell that has
// been drained is indistinguishable from one that never existed. Without this,
// the state root would depend on history rather than on state.
func (s *State) Set(slot types.Slot, v u256.U256) {
	s.dirtyCells[slot] = struct{}{}
	if v.IsZero() {
		// The mark is raised *before* the delete, so that a map at its true
		// high-water mark is recorded at that mark rather than one short of
		// it. Sampling after the delete would under-count the peak by one on
		// every fresh descent, which is invisible at scale but makes the
		// trigger boundary off by one and the tests below unable to state a
		// crisp threshold.
		if len(s.cells) > s.cellsPeak {
			s.cellsPeak = len(s.cells)
		}
		delete(s.cells, slot)
		s.maybeShrinkCells()
		return
	}
	s.cells[slot] = v
}

// IsSpent reports whether an address's signing authority has been burned.
//
// The same conflation as Get, on the other axis: MarkSpent is written only for
// an address a caller learned was spent, so on a sparse State a live address
// and one nobody has heard of both read false — again the benign answer. Same
// resolution: docs/decisions/sparse-state-readers.md.
func (s *State) IsSpent(a types.Address) bool {
	_, ok := s.spent[a]
	return ok
}

// MarkSpent burns an address permanently. There is no inverse: pruning may
// delete cell *values* under a spent address, but never the registry entry
// (R1-C3-iii), because a resurrected address silently burns every payment sent
// to it.
func (s *State) MarkSpent(a types.Address) {
	s.spent[a] = struct{}{}
	s.dirtySpent[a] = struct{}{}
}

// SpentCount returns the number of registry entries.
func (s *State) SpentCount() int { return len(s.spent) }

// Seen reports whether a certificate id has already been committed — applied
// or billed-skipped — on this chain, and the TTL it was recorded with.
func (s *State) Seen(id types.Hash) (uint64, bool) {
	ttl, ok := s.seen[id]
	return ttl, ok
}

// MarkSeen records a certificate id. Every billed outcome calls this; with the
// block rule that forbids including a seen id, it is the mechanical half of
// "one signature, at most one bill".
func (s *State) MarkSeen(id types.Hash, ttl uint64) { s.seen[id] = ttl }

// SeenCount returns the number of live seen entries.
func (s *State) SeenCount() int { return len(s.seen) }

// PruneSeen drops entries whose TTL has passed and returns them, so the caller
// can log them for undo. An entry is prunable once no valid block can include
// its certificate again.
func (s *State) PruneSeen(below uint64) []SeenEntry {
	if len(s.seen) > s.seenPeak { // before the deletes; see the note in Set
		s.seenPeak = len(s.seen)
	}
	var pruned []SeenEntry
	for id, ttl := range s.seen {
		if ttl < below {
			pruned = append(pruned, SeenEntry{ID: id, TTL: ttl})
		}
	}
	// Deterministic order: the undo log is consensus-adjacent data and must not
	// depend on map iteration.
	sort.Slice(pruned, func(i, j int) bool {
		return bytesLess(pruned[i].ID[:], pruned[j].ID[:])
	})
	for _, e := range pruned {
		delete(s.seen, e.ID)
	}
	s.maybeShrinkSeen()
	return pruned
}

// Undo reverses a block exactly, restoring cells, registry entries and the
// seen set.
func (s *State) Undo(log *UndoLog) {
	// Cells are restored in reverse order so that repeated writes to one slot
	// unwind to the value it held before the block, not to an intermediate.
	for i := len(log.Cells) - 1; i >= 0; i-- {
		s.Set(log.Cells[i].Slot, log.Cells[i].Old)
	}
	for _, a := range log.SpentAdded {
		delete(s.spent, a)
		s.dirtySpent[a] = struct{}{}
	}
	// Belt and braces, and deliberately kept as such: maybeShrinkSeen's own
	// max(peak, live) below is what actually holds the invariant here, because
	// the SeenRemoved restores land *after* this line. Removing this raise
	// changes nothing any test can see -- it can only lower the recorded peak,
	// which makes the rule fire less eagerly, never more. It stays because the
	// peak is meant to be the true high-water mark of the map, and Undo is the
	// one path that can shrink it between entry and exit.
	if len(s.seen) > s.seenPeak {
		s.seenPeak = len(s.seen)
	}
	for _, id := range log.SeenAdded {
		delete(s.seen, id)
	}
	for _, e := range log.SeenRemoved {
		s.seen[e.ID] = e.TTL
	}
	// Undo both drains the seen set (SeenAdded) and re-inflates it
	// (SeenRemoved), and it reaches the map directly rather than through
	// MarkSeen. Shrinking here is what keeps a reorg across a TTL boundary
	// from leaving a re-inflated map that can never be released again.
	s.maybeShrinkSeen()
}

// SortedCells returns every non-zero cell in canonical slot order.
func (s *State) SortedCells() []types.Slot {
	out := make([]types.Slot, 0, len(s.cells))
	for k := range s.cells {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Less(out[j]) })
	return out
}

// SortedSpent returns every registry entry in canonical address order.
func (s *State) SortedSpent() []types.Address {
	out := make([]types.Address, 0, len(s.spent))
	for k := range s.spent {
		out = append(out, k)
	}
	sort.Slice(out, func(i, j int) bool { return bytesLess(out[i][:], out[j][:]) })
	return out
}

// SortedSeen returns every live seen entry in canonical id order.
func (s *State) SortedSeen() []SeenEntry {
	out := make([]SeenEntry, 0, len(s.seen))
	for id, ttl := range s.seen {
		out = append(out, SeenEntry{ID: id, TTL: ttl})
	}
	sort.Slice(out, func(i, j int) bool { return bytesLess(out[i].ID[:], out[j].ID[:]) })
	return out
}

// Root computes the epoch state root over the cells and the spent registry.
//
// The seen set is deliberately excluded: it is prunable, fully determined by
// recent history, and every full node holds it anyway for the block rule that
// forbids replay. Committing it would tie the root to the pruning schedule.
//
// # Root is a reader, and cacheMu is what keeps that true
//
// Maintaining the root incrementally means Root *writes*: it refreshes the two
// key/leaf arrays, mutates both ssz.Trees in place, sets `root`/`rootValid` and
// clears the dirty sets. Its callers did not change when that happened, and
// three of them — Chain.StateRoot, StateRef.Root inside Chain.Read, and
// Chain.Snapshot's Clone — hold the chain's lock in **shared** mode, which
// permits two of them to run at once.
//
// That was safe only under an unstated invariant: "the dirty sets are empty
// whenever the exclusive lock is released", so every shared-lock caller takes
// the pure-read fast path below. The invariant was false. `fold.apply` calls
// `s.Undo` on its post-mutation error paths — F14, `state root mismatch at
// epoch boundary`, among them — and `Chain.applyLocked` returns that error
// *without* calling Root, releasing the exclusive lock with both dirty sets
// full. One valid-PoW block carrying a deliberately wrong epoch-boundary root
// is enough to put a live node in that state, after which two concurrent
// readers race on the leaf arrays and on `clear`ing a map another goroutine is
// ranging — which Go may escalate to an unrecoverable fatal error.
//
// cacheMu removes the invariant instead of documenting it. The contract is the
// one the chain's RWMutex already implements and the one Root had on main:
//
//   - **readers** — Root, Clone, Get, IsSpent, Seen, Sorted* — are safe to run
//     concurrently with each other, whatever else is or is not empty;
//   - **mutators** — Set, MarkSpent, MarkSeen, Undo, PruneSeen — still require
//     exclusive access, exactly as before.
//
// So cacheMu is only ever contended by readers, costs nothing on the fold path,
// and the guarantee is structural: a future caller cannot reintroduce the race
// by picking the wrong lock, because Root no longer depends on which lock it
// was called under. TestConcurrentRootOnDirtyState pins it here and
// TestConcurrentStateRootAfterAFailedEpochBoundaryBlock pins it end to end.
func (s *State) Root() types.Hash {
	s.cacheMu.Lock()
	defer s.cacheMu.Unlock()

	// Nothing written since the last call means the same answer: the root is a
	// pure function of the cells and the registry, and the dirty sets being
	// empty is exactly the statement that neither moved. Rollback and switchTo
	// both call Root on paths where this is often true.
	if s.rootValid && len(s.dirtyCells) == 0 && len(s.dirtySpent) == 0 {
		return s.root
	}
	s.refreshLeaves()
	cellRoot := s.cellTree.Root(s.cellLeaves, nextPow2(len(s.cellLeaves)))
	spentRoot := s.spentTree.Root(s.spentLeaves, nextPow2(len(s.spentLeaves)))
	s.root = crypto.Sum(crypto.TagStateRoot, cellRoot[:], spentRoot[:])
	s.rootValid = true
	return s.root
}

// refreshLeaves brings the two cached leaf arrays up to date with the maps.
//
// With no cache it is a full build — the from-scratch order, so the arrays it
// leaves behind are by construction the ones the definition would produce.
// With a cache it is a single merge pass over the sorted union of the existing
// keys and the dirty keys: untouched leaves are carried through untouched,
// touched keys are re-hashed if they are still live and dropped if they are
// not, and keys that are new arrive in their canonical position. No leaf
// depends on where its key came from, so the result is the sorted key set of
// the maps with the definition's leaf hash on each — the same array, whatever
// the history of writes and undos that produced it.
//
// The rejected alternative, measured rather than assumed and recorded in
// §21's decisions log: when every dirty key is already present — a block of
// pure overwrites — no leaf changes position, so the arrays could be kept and
// each dirty leaf rewritten in place after a binary search, skipping the
// merge entirely. It works, and it is worth 6.3 ms -> 3.7 ms at 100k and 72
// ms -> 25 ms at 1M (the remainder is ssz.Tree's leaf scan, which it does not
// touch). It is not taken, for two reasons that both point the same way: it
// buys a constant factor on the *only* regime an attacker can leave behind —
// one RETIRE (700 gas) or one new cell (200 gas for the credit write, 600 for
// the cheapest whole certificate) restores the merge and the Θ(N) — and it
// buys it with a second write path through the leaf arrays, in the zone where
// CONTRIBUTING says determinism beats performance. The shape is the problem,
// and a position-stable root is the thing that fixes it; see the note above
// on why that is a hard fork.
//
// Callers must hold cacheMu; Root is the only one.
func (s *State) refreshLeaves() {
	if !s.cached {
		s.cellKeys = s.SortedCells()
		s.cellLeaves = make([]types.Hash, len(s.cellKeys))
		for i, slot := range s.cellKeys {
			s.cellLeaves[i] = s.cellLeaf(slot)
		}
		s.spentKeys = s.SortedSpent()
		s.spentLeaves = make([]types.Hash, len(s.spentKeys))
		for i, a := range s.spentKeys {
			s.spentLeaves[i] = crypto.Sum(crypto.TagStateSpent, a[:])
		}
		s.dirtyCells = resetDirtyCells(s.dirtyCells)
		s.dirtySpent = resetDirtySpent(s.dirtySpent)
		s.cached = true
		return
	}

	if len(s.dirtyCells) > 0 {
		dirty := make([]types.Slot, 0, len(s.dirtyCells))
		for slot := range s.dirtyCells {
			dirty = append(dirty, slot)
		}
		sort.Slice(dirty, func(i, j int) bool { return dirty[i].Less(dirty[j]) })

		keys := make([]types.Slot, 0, len(s.cells))
		leaves := make([]types.Hash, 0, len(s.cells))
		i, j := 0, 0
		for i < len(s.cellKeys) || j < len(dirty) {
			switch {
			case j >= len(dirty) || (i < len(s.cellKeys) && s.cellKeys[i].Less(dirty[j])):
				keys = append(keys, s.cellKeys[i])
				leaves = append(leaves, s.cellLeaves[i])
				i++
			default:
				slot := dirty[j]
				// A dirty key may or may not already be in the array; if it is,
				// skip the stale copy.
				if i < len(s.cellKeys) && s.cellKeys[i] == slot {
					i++
				}
				if _, live := s.cells[slot]; live {
					keys = append(keys, slot)
					leaves = append(leaves, s.cellLeaf(slot))
				}
				j++
			}
		}
		s.cellKeys, s.cellLeaves = keys, leaves
		s.dirtyCells = resetDirtyCells(s.dirtyCells)
	}

	if len(s.dirtySpent) > 0 {
		dirty := make([]types.Address, 0, len(s.dirtySpent))
		for a := range s.dirtySpent {
			dirty = append(dirty, a)
		}
		sort.Slice(dirty, func(i, j int) bool { return bytesLess(dirty[i][:], dirty[j][:]) })

		keys := make([]types.Address, 0, len(s.spent))
		leaves := make([]types.Hash, 0, len(s.spent))
		i, j := 0, 0
		for i < len(s.spentKeys) || j < len(dirty) {
			switch {
			case j >= len(dirty) || (i < len(s.spentKeys) && bytesLess(s.spentKeys[i][:], dirty[j][:])):
				keys = append(keys, s.spentKeys[i])
				leaves = append(leaves, s.spentLeaves[i])
				i++
			default:
				a := dirty[j]
				if i < len(s.spentKeys) && s.spentKeys[i] == a {
					i++
				}
				if _, live := s.spent[a]; live {
					keys = append(keys, a)
					leaves = append(leaves, crypto.Sum(crypto.TagStateSpent, a[:]))
				}
				j++
			}
		}
		s.spentKeys, s.spentLeaves = keys, leaves
		s.dirtySpent = resetDirtySpent(s.dirtySpent)
	}
}

// shrinkDivisor is the fraction of its own high-water mark a map must fall
// below before its buckets are rebuilt: live < peak/4.
//
// Go's `clear` and `delete` empty a map without releasing its buckets, so a
// long-lived map is permanently sized to the largest it has ever been. The two
// dirty sets already dodge this (see dirtyResetThreshold); s.cells and s.seen
// did not, and unlike the dirty sets they are driven by workload rather than by
// restart. Measured on go1.26.2 darwin/arm64: 200,000 cells all
// drained to zero left 26.0 MB resident with SortedCells() empty (~136 B per
// emptied entry), and 200,000 seen entries pruned by TTL left 12.0 MB with
// SeenCount() == 0 (~63 B). Both figures are the ones the rule was chosen
// against, reproduced to the digit.
//
// Why 4 and not 2 or 8: the rule must be amortised O(1) against the deletes
// that drive it, and re-basing the mark to the live count after a rebuild is
// what makes it so. Re-arming then requires the map to grow fourfold again, so
// an adversary sitting on the trigger and oscillating across it pays one
// rebuild and then nothing. Measured over three shapes, two of them chosen to
// break exactly that — counting rebuilds by map identity, since a counter
// derived from the mark cannot see the mark's own removal:
//
//	monotone drain of 32,768 cells      2 rebuilds   0.156 copies/Set
//	20 oscillations across the trigger  20 rebuilds  0.161 copies/Set
//	50,000-round sawtooth at the trigger 1 rebuild   0.032 copies/Set
//
// The adversarial oscillation is the worst of the three and is still 24x under
// the bound the test enforces. A divisor of 2 doubles the copying for the same
// asymptotics and 8 halves the memory recovered; 4 is the usual place to stand
// and nothing here is sensitive to it.
//
// # Why this is safe in the consensus zone
//
// The peaks are hints and the rebuild is not observable. Neither counter is
// read by anything that computes a consensus value: the root is a function of
// s.cells and s.spent alone, refreshLeaves rebuilds the canonical key set from
// those maps, and every consumer of map iteration in this package sorts first
// or writes into another map. A rebuilt map holds exactly the same key-value
// pairs, so the only thing it can change is Go's internal iteration order —
// which no consensus value depends on, by the rule this package exists to
// enforce. Two nodes running completely different shrink schedules therefore
// agree on every root, and TestRootIsInvariantToTheShrinkSchedule pins that
// directly rather than leaving it as an argument.
//
// The same reasoning is why the peaks are copied by Clone even though they
// cannot reach the root: the differential runner should keep exercising "the
// schedule cannot reach the root" as a property, not preserve it by accident.
const shrinkDivisor = 4

// shrinkFloor is the size below which shrinking is not attempted. Below it the
// buckets are worth less than the allocation that releases them, and an empty
// or nearly-empty map is the common case for a node that has just started.
//
// It shares a value with dirtyResetThreshold and nothing else: that one is the
// point past which a *drained* dirty set is worth reallocating, this one is the
// point past which a *partially* emptied state map is. Different maps,
// different question, independently chosen. They are not one knob and should
// not be unified.
const shrinkFloor = 1024

// maybeShrinkCells and maybeShrinkSeen release a map's buckets once it has
// fallen far enough below its own high-water mark, and re-base the mark.
//
// The mark is recomputed as max(peak, live) on every call rather than
// maintained at each insertion, and that is the whole reason these are two
// functions instead of a counter bump in Set and MarkSeen. Undo writes to
// s.seen directly on both of its seen paths — deleting SeenAdded and restoring
// SeenRemoved — so a peak maintained only at insertion goes stale below the
// live count after a prune-then-reorg across a TTL boundary, and the rule can
// then never fire again. Deriving the mark from len() at the point of use makes
// that unrepresentable: the peak is never below the live count, whatever path
// wrote the map.
//
// That guarantee is load-bearing on the seen side and defence-in-depth on the
// cells side, and the asymmetry is structural rather than an oversight. Removing
// the raise from maybeShrinkSeen fails TestSeenPeakIsNeverBelowTheLiveCountAfterUndo,
// because Undo's SeenRemoved restores write s.seen after every other raise has
// run. Removing it from maybeShrinkCells fails nothing, because Set is the only
// writer of s.cells and already raises before its delete. It is kept anyway: the
// invariant is meant to hold whatever path writes the map, and a future caller
// that reaches s.cells directly should not silently disarm the rule the way
// Undo would have.
//
// Two functions rather than one generic, for the reason resetDirtyCells gives:
// this is the consensus zone, where the argument is that there is very little
// to read.
func (s *State) maybeShrinkCells() {
	if len(s.cells) > s.cellsPeak {
		s.cellsPeak = len(s.cells)
	}
	if s.cellsPeak < shrinkFloor || len(s.cells) >= s.cellsPeak/shrinkDivisor {
		return
	}
	m := make(map[types.Slot]u256.U256, len(s.cells))
	for k, v := range s.cells {
		m[k] = v
	}
	s.cells = m
	s.cellsPeak = len(s.cells)
}

func (s *State) maybeShrinkSeen() {
	if len(s.seen) > s.seenPeak {
		s.seenPeak = len(s.seen)
	}
	if s.seenPeak < shrinkFloor || len(s.seen) >= s.seenPeak/shrinkDivisor {
		return
	}
	m := make(map[types.Hash]uint64, len(s.seen))
	for k, v := range s.seen {
		m[k] = v
	}
	s.seen = m
	s.seenPeak = len(s.seen)
}

// dirtyResetThreshold is the size past which a drained dirty set is thrown
// away rather than cleared in place.
//
// Go's `clear` empties a map without releasing its buckets, and the dirty sets
// are inflated to the size of the whole state on a path every node takes:
// chain.load replays every cell through Set and every registry entry through
// MarkSpent at startup, so after one restart the two sets hold one entry per
// live entry — and keep the memory for them forever, however small the blocks
// that follow. Measured on the same machine: 14.0 MB retained at 100k cells + 100k
// registry entries, 224 MB at 1M + 1M, which is comparable to the whole root
// cache this file exists to add (31 MB and 281 MB) and was not part of its
// accounting.
//
// 1024 is not "a block's worth of keys" — at the genesis sequential ceiling
// (2T = 3,200,000 at the genesis sequential target, gas_seq_per_write = 200)
// a full block can dirty 16,000 — and the threshold is not load-bearing
// either way. It is the point past which the buckets (~139 kB at 1024 slot
// keys) are worth more than the allocation that releases them, so a
// lightly-loaded chain clears in place and pays nothing. Above it, two
// allocations per Root: measured at +35 kB and +13 allocs against the ~9.7 MB
// and ~126 allocs refreshLeaves already makes at n=100k, i.e. 0.4%, with no
// time difference above the noise floor. Dropping the threshold entirely
// would also be defensible; keeping it costs one branch.
const dirtyResetThreshold = 1024

// resetDirtyCells and resetDirtySpent drain a dirty set, releasing its buckets
// if it had grown large. `len` is exact and deterministic and no map is
// iterated, but neither matters for consensus: both branches return an empty
// set, so the choice cannot reach the root. It could not anyway — the root is a
// function of s.cells and s.spent, refreshLeaves rebuilds the canonical key set
// from those maps regardless of what the dirty sets held, and two honest nodes
// already disagree about len(dirtyCells) (a freshly restarted node holds one
// entry per live cell; a running one holds a block's worth) while being
// required to agree on the root.
//
// One thing does change, and it is worth naming because it is a downgrade in
// failure mode rather than in safety: `clear` never wrote the s.dirtyCells
// *field*, and this does, under cacheMu, while Set/MarkSpent/Undo read the
// field under no lock. That pairing is unreachable — mutators require the
// chain's exclusive lock and Root only ever holds it shared — and it is the
// same pairing s.cells itself has always been in. But if it ever became
// reachable, a mutator holding the stale map pointer would silently drop a
// dirty key and produce a wrong state root, where a torn map would have tripped
// the runtime's own detector. The contract on Root is what keeps that shut.
//
// Two functions rather than one generic: this package is in the consensus zone,
// where the argument is that there is very little to read, and a generic would
// be the only one in the repository.
func resetDirtyCells(m map[types.Slot]struct{}) map[types.Slot]struct{} {
	if len(m) > dirtyResetThreshold {
		return make(map[types.Slot]struct{})
	}
	clear(m)
	return m
}

func resetDirtySpent(m map[types.Address]struct{}) map[types.Address]struct{} {
	if len(m) > dirtyResetThreshold {
		return make(map[types.Address]struct{})
	}
	clear(m)
	return m
}

func (s *State) cellLeaf(slot types.Slot) types.Hash {
	v := s.cells[slot].Bytes()
	return crypto.Sum(crypto.TagStateCell, slot.Addr[:], slot.Word[:], v[:])
}

func nextPow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}

func bytesLess(a, b []byte) bool {
	for i := range a {
		if a[i] != b[i] {
			return a[i] < b[i]
		}
	}
	return false
}
