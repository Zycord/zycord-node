package sync_test

import (
	"errors"
	"testing"

	"zycord/core/pow"
	"zycord/core/u256"
	"zycord/node/checkpoints"
	"zycord/node/sync"
)

// The attack these two layers exist for, driven end to end.
//
// The launch era is CPU-mined, so a young chain's cumulative work is small in
// absolute terms. An attacker who arrives in week two with a rented botnet does
// not have to outrace the honest tip — the cheaper theft is to mine a heavier
// chain **from genesis** in private and feed it to everyone who joins later.
// The early network keeps its own chain; every new node adopts the attacker's.
// `undo_depth` cannot help, because a node with no history has nothing to
// refuse to undo.
//
// Each layer is driven alone, with the other switched off, because "refused"
// with both installed would not say which one did it — and the schedule ships
// them at different releases, so each has to stand up by itself.
func TestAHeavierFromGenesisChainIsRefusedAtEachLayerIndependently(t *testing.T) {
	p := devnetEasy()

	// The chain the early network built.
	honest := newNode(t, p, key(t, 1).Persistent())
	honest.mine(t, 12)

	// The attacker's private chain from the same genesis, heavier.
	attacker := newNode(t, p, key(t, 2).Persistent())
	attacker.mine(t, 24)
	if !attacker.chain.TotalWork().Gt(honest.chain.TotalWork()) {
		t.Fatalf("the attacker's chain is not heavier (%s vs %s); this test would prove nothing",
			attacker.chain.TotalWork(), honest.chain.TotalWork())
	}

	honestFive, err := honest.chain.BlockAt(5)
	if err != nil {
		t.Fatal(err)
	}
	pinned := honestFive.Header.ID()

	// The control: with no defence, a node with no history takes the heavier
	// chain. This is the theft, and it is what the two layers below refuse.
	t.Run("undefended, the joining node adopts the attacker", func(t *testing.T) {
		defer checkpoints.Install(checkpoints.Set{})
		checkpoints.Install(checkpoints.Set{})

		victim := newNode(t, p, key(t, 3).Persistent())
		res, err := sync.Run(victim.chain, pow.Dev{}, &peer{t: t, chain: attacker.chain}, 128)
		if err != nil {
			t.Fatalf("sync: %v", err)
		}
		if !res.Adopted || victim.chain.Height() != 24 {
			t.Fatalf("the undefended node did not adopt the attacker (adopted=%v height=%d); "+
				"the two layers below would then be refusing something that never happened",
				res.Adopted, victim.chain.Height())
		}
	})

	// Layer 2 alone: one pin, no work floor.
	t.Run("a checkpoint alone refuses it", func(t *testing.T) {
		defer checkpoints.Install(checkpoints.Set{})
		checkpoints.Install(checkpoints.Set{
			Network:      "devnet",
			SunsetHeight: checkpoints.Sunset,
			MinimumAge:   checkpoints.MinAge,
			Points:       []checkpoints.Checkpoint{{Height: 5, BlockID: pinned}},
		})

		victim := newNode(t, p, key(t, 4).Persistent())
		_, err := sync.Run(victim.chain, pow.Dev{}, &peer{t: t, chain: attacker.chain}, 128)
		if !errors.Is(err, sync.ErrContradictsCheckpoint) {
			t.Fatalf("want ErrContradictsCheckpoint, got %v", err)
		}
		if victim.chain.Height() != 0 {
			t.Fatalf("the refusal came after %d blocks were folded; it must come before "+
				"a single body is requested", victim.chain.Height())
		}
	})

	// Layer 1 alone: a work floor, no pins.
	t.Run("a chain-work floor alone refuses it", func(t *testing.T) {
		defer checkpoints.Install(checkpoints.Set{})
		floor := attacker.chain.TotalWork().SatAdd(u256.FromUint64(1))
		checkpoints.Install(checkpoints.Set{
			Network:            "devnet",
			MinChainWork:       floor,
			MinChainWorkHeight: 5,
			SunsetHeight:       checkpoints.Sunset,
			MinimumAge:         checkpoints.MinAge,
		})

		victim := newNode(t, p, key(t, 5).Persistent())
		_, err := sync.Run(victim.chain, pow.Dev{}, &peer{t: t, chain: attacker.chain}, 128)
		if !errors.Is(err, sync.ErrBelowMinChainWork) {
			t.Fatalf("want ErrBelowMinChainWork, got %v", err)
		}
		if victim.chain.Height() != 0 {
			t.Fatalf("the refusal came after %d blocks were folded", victim.chain.Height())
		}
	})

	// And the chain the pin was taken from still syncs. A defence that refuses
	// the network it was published to protect is worse than none: the failure
	// would look identical to the attack, and every joining node would stall.
	t.Run("the chain the pin names still syncs", func(t *testing.T) {
		defer checkpoints.Install(checkpoints.Set{})
		checkpoints.Install(checkpoints.Set{
			Network:            "devnet",
			MinChainWork:       u256.FromUint64(1),
			MinChainWorkHeight: 5,
			SunsetHeight:       checkpoints.Sunset,
			MinimumAge:         checkpoints.MinAge,
			Points:             []checkpoints.Checkpoint{{Height: 5, BlockID: pinned}},
		})

		victim := newNode(t, p, key(t, 6).Persistent())
		res, err := sync.Run(victim.chain, pow.Dev{}, &peer{t: t, chain: honest.chain}, 128)
		if err != nil {
			t.Fatalf("the honest chain was refused by its own checkpoint: %v", err)
		}
		if !res.Adopted || victim.chain.Height() != 12 {
			t.Fatalf("adopted=%v height=%d, want the honest chain's 12", res.Adopted, victim.chain.Height())
		}
	})
}

// A refusal is worth nothing if it can be walked around by asking for a
// smaller range, so the pin has to hold at every batch size the driver can
// choose — including one small enough that the candidate reaching the pinned
// height is not the first candidate the peer serves.
func TestTheCheckpointHoldsAtEveryBatchSize(t *testing.T) {
	p := devnetEasy()
	honest := newNode(t, p, key(t, 1).Persistent())
	honest.mine(t, 12)
	attacker := newNode(t, p, key(t, 2).Persistent())
	attacker.mine(t, 24)

	honestTen, err := honest.chain.BlockAt(10)
	if err != nil {
		t.Fatal(err)
	}

	for _, batch := range []uint32{1, 2, 8, 128} {
		func() {
			defer checkpoints.Install(checkpoints.Set{})
			checkpoints.Install(checkpoints.Set{
				Network:      "devnet",
				SunsetHeight: checkpoints.Sunset,
				MinimumAge:   checkpoints.MinAge,
				Points: []checkpoints.Checkpoint{
					{Height: 10, BlockID: honestTen.Header.ID()}},
			})
			victim := newNode(t, p, key(t, 7).Persistent())
			_, err := sync.Run(victim.chain, pow.Dev{}, &peer{t: t, chain: attacker.chain}, batch)
			if !errors.Is(err, sync.ErrContradictsCheckpoint) {
				t.Fatalf("batch %d: want ErrContradictsCheckpoint, got %v", batch, err)
			}
			// Below the pin the node is allowed to have followed the attacker —
			// nothing has contradicted anything yet — but it must stop at the
			// pinned height rather than through it.
			if victim.chain.Height() >= 10 {
				t.Fatalf("batch %d: the node reached height %d, past the pin at 10",
					batch, victim.chain.Height())
			}
		}()
	}
}

// The empty table is the v1.0.0 shape, and it must change nothing at all: the
// enforcement ships in the first binary and enforces nothing until the first
// patch release fills the file in.
func TestTheEmptyTableChangesNothing(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, p, key(t, 1).Persistent())
	source.mine(t, 6)

	defer checkpoints.Install(checkpoints.Set{})
	checkpoints.Install(checkpoints.Set{})

	fresh := newNode(t, p, key(t, 2).Persistent())
	res, err := sync.Run(fresh.chain, pow.Dev{}, &peer{t: t, chain: source.chain}, 128)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !res.Adopted || fresh.chain.Height() != 6 {
		t.Fatalf("adopted=%v height=%d", res.Adopted, fresh.chain.Height())
	}
}
