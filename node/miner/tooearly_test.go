package miner_test

import (
	"errors"
	"testing"

	"zycord/core/pow"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/spec"
)

// The miner used to clamp a header's timestamp up to the median-past floor when
// its own clock was behind that floor, which is the state every node is in
// before its network's genesis. These tests pin the refusal that replaced the
// clamp, and the shape of what it hands back — because "wait" is only useful
// advice if the caller can say how long for.

// earlyHarness returns a miner whose clock is `behind` seconds short of the
// genesis timestamp its chain declares, and the params it was built from.
//
// The clock does not advance. Every other miner harness in this tree steps its
// clock by TargetBlockSeconds per reading, which is what keeps them permanently
// ahead of the floor and is why none of them ever met this refusal; a fixed
// clock is the operator who started their node early and went to bed.
func earlyHarness(t *testing.T, behind uint64) *miner.Miner {
	t.Helper()
	p := spec.Devnet()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatalf("opening a chain: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	return &miner.Miner{
		Chain:  c,
		Pool:   mempool.New(p, mempool.DefaultPolicy()),
		Engine: pow.Dev{},
		Payout: [32]byte{0x02, 1, 2, 3},
		Now:    func() uint64 { return p.GenesisTime - behind },
	}
}

// TestAMinerBeforeGenesisRefusesToBuild is the whole point of the change. A
// node started before its network's first block must produce nothing at all:
// not a block held back, not a block dated at the floor — nothing.
func TestAMinerBeforeGenesisRefusesToBuild(t *testing.T) {
	m := earlyHarness(t, 4*3600)

	b, err := m.Assemble()
	if err == nil {
		t.Fatalf("Assemble built a block %d seconds before genesis; "+
			"header time %d", 4*3600, b.Header.Time)
	}
	if !errors.Is(err, miner.ErrTooEarly) {
		t.Fatalf("Assemble refused with %v, want ErrTooEarly", err)
	}

	// MineOne goes through Assemble, so the refusal has to survive the whole
	// path a mining loop actually takes rather than only the direct call.
	if _, _, err := m.MineOne(1 << 16); !errors.Is(err, miner.ErrTooEarly) {
		t.Fatalf("MineOne refused with %v, want ErrTooEarly", err)
	}
	if h := m.Chain.Height(); h != 0 {
		t.Fatalf("chain advanced to height %d while refusing to mine", h)
	}
}

// TestTheRefusalSaysHowLongTheWaitIs pins the numbers a caller reports. The
// gap was computed for an error string and discarded on the sync path once
// already (sync.WithheldError records it); a miner that says "not yet" and
// cannot say "for four hours" leaves an operator with no way to tell a node
// that is waiting from a node that is stuck.
func TestTheRefusalSaysHowLongTheWaitIs(t *testing.T) {
	const behind = 90
	p := spec.Devnet()
	m := earlyHarness(t, behind)

	_, err := m.Assemble()
	var early *miner.TooEarlyError
	if !errors.As(err, &early) {
		t.Fatalf("Assemble returned %v, want a *TooEarlyError", err)
	}

	// Before block 1 the median window holds genesis alone, so the floor is
	// genesis_time itself and the earliest legal timestamp is one past it.
	if want := p.GenesisTime + 1; early.NotBefore != want {
		t.Fatalf("NotBefore = %d, want %d", early.NotBefore, want)
	}
	if want := p.GenesisTime - behind; early.Now != want {
		t.Fatalf("Now = %d, want %d", early.Now, want)
	}
	if want := uint64(behind + 1); early.Remaining() != want {
		t.Fatalf("Remaining() = %d, want %d", early.Remaining(), want)
	}
}

// TestRemainingSaturatesRatherThanUnderflowing guards the arithmetic that
// turns into a duration. Remaining is a uint64 subtraction and the caller
// multiplies it by time.Second into a SIGNED counter, so an underflow here
// does not produce a wrong number — it produces a negative wait, a timer that
// fires at once, and the spin the refusal exists to prevent.
func TestRemainingSaturatesRatherThanUnderflowing(t *testing.T) {
	for _, c := range []struct {
		name string
		e    miner.TooEarlyError
		want uint64
	}{
		{"waiting", miner.TooEarlyError{NotBefore: 100, Now: 40}, 60},
		{"exactly there", miner.TooEarlyError{NotBefore: 100, Now: 100}, 0},
		{"already past", miner.TooEarlyError{NotBefore: 100, Now: 4000}, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			if got := c.e.Remaining(); got != c.want {
				t.Fatalf("Remaining() = %d, want %d", got, c.want)
			}
		})
	}
}

// TestAMinerAtGenesisBuildsImmediately is the other half, and the one that
// would catch an off-by-one turning the refusal into a permanent stall: the
// first second at which a block is legal is the first second at which one is
// built, with no extra block interval of waiting.
func TestAMinerAtGenesisBuildsImmediately(t *testing.T) {
	p := spec.Devnet()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatalf("opening a chain: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	m := &miner.Miner{
		Chain:  c,
		Pool:   mempool.New(p, mempool.DefaultPolicy()),
		Engine: pow.Dev{},
		Payout: [32]byte{0x02, 1, 2, 3},
		Now:    func() uint64 { return p.GenesisTime + 1 },
	}

	b, err := m.Assemble()
	if err != nil {
		t.Fatalf("Assemble refused at the first legal second: %v", err)
	}
	if want := p.GenesisTime + 1; b.Header.Time != want {
		t.Fatalf("header time = %d, want %d", b.Header.Time, want)
	}
}

// TestTheHeaderTimeIsTheClockAndNeverTheFloor is the regression this change
// exists for, stated as a property rather than as a scenario: whatever the
// chain's median says, a block this miner builds carries the reading its own
// clock gave — never a value derived from the floor, which is what the old
// clamp returned and what dated a pre-genesis chain into the future.
func TestTheHeaderTimeIsTheClockAndNeverTheFloor(t *testing.T) {
	p := spec.Devnet()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatalf("opening a chain: %v", err)
	}
	t.Cleanup(func() { c.Close() })

	// Well past the floor, and not a multiple of anything the rule computes,
	// so a clamped value could not coincide with it by accident.
	const offset = 1234
	m := &miner.Miner{
		Chain:  c,
		Pool:   mempool.New(p, mempool.DefaultPolicy()),
		Engine: pow.Dev{},
		Payout: [32]byte{0x02, 1, 2, 3},
		Now:    func() uint64 { return p.GenesisTime + offset },
	}

	b, err := m.Assemble()
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if want := p.GenesisTime + offset; b.Header.Time != want {
		t.Fatalf("header time = %d, want the clock's %d", b.Header.Time, want)
	}
}

// TestAProducedBlockSatisfiesTheRuleItsOwnParentImplies pins the invariant the
// gate's placement exists to protect: the timestamp a block declares is judged
// by peers against the median window ending at THAT BLOCK'S PARENT, so it must
// be checked against that window and not against whatever the chain's tip
// happened to be when the miner asked.
//
// **This test does not reproduce the race it guards.** Forcing a tip to move
// between the floor read and the snapshot needs a hook the production miner
// deliberately does not have, so the ordering in Assemble is held by review and
// by the comment there. What this catches is everything else that would break
// the same invariant without a race — a wrong window length, an off-by-one in
// the floor, or a future edit that goes back to the tip-anchored window.
func TestAProducedBlockSatisfiesTheRuleItsOwnParentImplies(t *testing.T) {
	p := spec.Devnet()
	m := sealHarness(t)

	// Enough blocks for the median window to be full, so the floor is a real
	// median rather than the degenerate one- or two-header case.
	for i := 0; i < p.MedianTimeBlocks+3; i++ {
		if _, _, err := m.MineOne(1 << 20); err != nil {
			t.Fatalf("mining block %d: %v", i+1, err)
		}
	}

	b, err := m.Assemble()
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	window := m.Chain.HeadersEndingAt(b.Header.Height-1, p.MedianTimeBlocks)
	if len(window) == 0 {
		t.Fatal("no window for the block's own parent")
	}
	if err := pow.CheckMedianTime(b.Header, window, p); err != nil {
		t.Fatalf("a block this miner built fails the median-past rule its own "+
			"parent's window implies — every peer would refuse it: %v", err)
	}
}
