package state_test

import (
	"math/rand"
	"testing"

	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
)

func slot(rng *rand.Rand) types.Slot {
	var s types.Slot
	rng.Read(s.Addr[:])
	rng.Read(s.Word[:])
	return s
}

// TestRootIsIndependentOfInsertionOrder. The state is stored in maps; the root
// must not be. This is the classic way a consensus implementation forks against
// itself, so it is checked directly rather than inferred.
func TestRootIsIndependentOfInsertionOrder(t *testing.T) {
	rng := rand.New(rand.NewSource(1))
	slots := make([]types.Slot, 64)
	values := make([]u256.U256, len(slots))
	for i := range slots {
		slots[i] = slot(rng)
		values[i] = u256.FromUint64(rng.Uint64() | 1)
	}
	spent := make([]types.Address, 8)
	for i := range spent {
		rng.Read(spent[i][:])
	}

	forward := state.New()
	for i := range slots {
		forward.Set(slots[i], values[i])
	}
	for _, a := range spent {
		forward.MarkSpent(a)
	}

	for round := 0; round < 20; round++ {
		order := rng.Perm(len(slots))
		backward := state.New()
		for _, i := range order {
			backward.Set(slots[i], values[i])
		}
		for _, i := range rng.Perm(len(spent)) {
			backward.MarkSpent(spent[i])
		}
		if forward.Root() != backward.Root() {
			t.Fatal("the state root depends on insertion order")
		}
	}
}

// TestZeroIsAbsent: a drained cell must be indistinguishable from one that
// never existed, or the state root would depend on history rather than state.
func TestZeroIsAbsent(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	s := slot(rng)

	empty := state.New()
	drained := state.New()
	drained.Set(s, u256.FromUint64(1000))
	drained.Set(s, u256.Zero)

	if drained.Root() != empty.Root() {
		t.Fatal("a drained cell left a trace in the state root")
	}
	if len(drained.SortedCells()) != 0 {
		t.Fatal("a zero cell is still stored")
	}
	if !drained.Get(s).IsZero() {
		t.Fatal("an absent cell does not read as zero")
	}
}

// TestRootSeparatesCellsFromRegistry: a spent address and a cell must not be
// able to stand in for one another in the root.
func TestRootSeparatesCellsFromRegistry(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	var addr types.Address
	rng.Read(addr[:])

	withCell := state.New()
	withCell.Set(types.Slot{Addr: addr}, u256.One)

	withSpent := state.New()
	withSpent.MarkSpent(addr)

	if withCell.Root() == withSpent.Root() {
		t.Fatal("a cell and a registry entry produce the same root")
	}
	if withCell.Root() == state.New().Root() {
		t.Fatal("a non-empty state has the empty root")
	}
}

// TestSeenIsNotInTheRoot: the seen set is prunable and fully determined by
// recent history. Committing it would tie the root to the pruning schedule.
func TestSeenIsNotInTheRoot(t *testing.T) {
	s := state.New()
	root := s.Root()
	s.MarkSeen(types.Hash{1, 2, 3}, 99)
	if s.Root() != root {
		t.Fatal("the seen set entered the state root")
	}
}

// TestPruneSeenIsDeterministic: the pruned list feeds the undo log, which is
// consensus-adjacent, so its order must not come from a map.
func TestPruneSeenIsDeterministic(t *testing.T) {
	build := func() *state.State {
		s := state.New()
		rng := rand.New(rand.NewSource(4))
		for i := 0; i < 200; i++ {
			var id types.Hash
			rng.Read(id[:])
			s.MarkSeen(id, uint64(rng.Intn(100)))
		}
		return s
	}
	first := build().PruneSeen(50)
	for i := 0; i < 10; i++ {
		again := build().PruneSeen(50)
		if len(again) != len(first) {
			t.Fatal("pruning removed a different number of entries")
		}
		for j := range first {
			if again[j] != first[j] {
				t.Fatal("the pruned list is not in a deterministic order")
			}
		}
	}
}

// TestUndoRestoresRepeatedWrites: a slot written twice in one block must unwind
// to the value it held before the block, not to an intermediate.
func TestUndoRestoresRepeatedWrites(t *testing.T) {
	rng := rand.New(rand.NewSource(5))
	s := slot(rng)

	st := state.New()
	st.Set(s, u256.FromUint64(100))
	before := st.Root()

	log := &state.UndoLog{}
	for _, v := range []uint64{200, 300, 0, 400} {
		log.Cells = append(log.Cells, state.CellUndo{Slot: s, Old: st.Get(s)})
		st.Set(s, u256.FromUint64(v))
	}
	st.Undo(log)

	if got := st.Get(s); !got.Eq(u256.FromUint64(100)) {
		t.Fatalf("undo restored %s, want 100", got.String())
	}
	if st.Root() != before {
		t.Fatal("undo did not restore the root")
	}
}

// TestCloneIsIndependent: the differential runner and the miner's dry run both
// depend on a copy that cannot be written through.
func TestCloneIsIndependent(t *testing.T) {
	rng := rand.New(rand.NewSource(6))
	s := slot(rng)

	original := state.New()
	original.Set(s, u256.One)
	original.MarkSeen(types.Hash{9}, 5)

	clone := original.Clone()
	clone.Set(s, u256.FromUint64(999))
	clone.MarkSpent(s.Addr)
	clone.MarkSeen(types.Hash{8}, 6)

	if !original.Get(s).Eq(u256.One) {
		t.Fatal("writing the clone changed the original's cells")
	}
	if original.IsSpent(s.Addr) {
		t.Fatal("writing the clone changed the original's registry")
	}
	if original.SeenCount() != 1 {
		t.Fatal("writing the clone changed the original's seen set")
	}
}
