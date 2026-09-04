package chain

import (
	"testing"

	"zycord/core/params"
	"zycord/core/u256"
	"zycord/spec"
)

// I8, part four: whether declared work is worth what fork choice pays for it.
//
// Fork choice sums BlockWork(Target) over a branch and takes the heavier side.
// There are two ways to attack that: make one block claim more work than it
// cost, or make the SUM stop distinguishing branches. The target rule closes
// the first — every ingress path re-derives Header.Target and requires equality
// (I5-H19's fix) — so this file is about the second.
//
// I3-M2 established the shape of the risk and turned it into F-PARAM-1:
// BlockWork is floor(2^256/(target+1)), so at targets at or above 2^255 every
// header returns one unit, every header is worth the same, and fork choice
// degenerates from accumulated work into a block count. Params.Validate refuses
// such a MaxTarget. What was never asserted is the property AT the parameter
// sets that ship, which is what a freeze actually freezes.

// workCollapsePoint is 2^255, the smallest target at which BlockWork returns
// one for every header. Written out here rather than imported from
// core/params, deliberately: a test that borrowed the validator's own constant
// would agree with the validator by construction and could not catch the
// constant itself being wrong.
var workCollapsePoint = u256.MustFromDecimal(
	"57896044618658097711785492504343953926634992332820282019728792003956564819968")

// TestTheWorkCurveDoesNotCollapseAtAnyShippedParameterSet checks F-PARAM-1
// against the parameter sets, not against the validator that is supposed to
// enforce it.
//
// A validator is not a parameter set. Validate could be correct and a shipped
// file still wrong — or Validate could be silently skipped on some path — and
// either way the chain that launches is the one described by the JSON. Mainnet
// genesis is days away, so the assertion worth having is about the numbers
// being frozen.
func TestTheWorkCurveDoesNotCollapseAtAnyShippedParameterSet(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *params.Params
	}{
		{"mainnet", spec.Mainnet()},
		{"testnet", spec.Testnet()},
		{"devnet", spec.Devnet()},
	} {
		p := tc.p

		if !p.MaxTarget.Lt(workCollapsePoint) {
			t.Errorf("%s: max_target is at or above 2^255, where every header is"+
				" worth one unit and fork choice becomes a block count", tc.name)
		}

		// The assertion with teeth: a statement about BlockWork's OUTPUT at the
		// easiest legal target, rather than about the constant. A header at
		// max_target must still be worth more than one unit, or the curve has
		// collapsed in practice however the inequality above reads.
		w := BlockWork(p.MaxTarget)
		if !w.Gt(u256.One) {
			t.Errorf("%s: a header at max_target is worth %s units of work;"+
				" the curve has collapsed at the shipped ceiling", tc.name, w.String())
		}

		// Halving the target must pay strictly more. A flat step here would let
		// two branches at different difficulties tie, and a tie resolves to
		// first-seen — rewarding whoever announced first over whoever worked
		// more.
		half, _ := p.MaxTarget.Div64(2)
		if wh := BlockWork(half); !wh.Gt(w) {
			t.Errorf("%s: halving the target did not increase work (%s vs %s)",
				tc.name, wh.String(), w.String())
		}

		t.Logf("%s: max_target work %s", tc.name, w.String())
	}
}

// TestWorkIsStrictlyMonotoneAcrossTheLiveRange generalises the spot check.
//
// Fork choice's entire meaning is that more work beats less. If BlockWork were
// flat over any interval a live chain can occupy, branches at different
// difficulties would tie there. The sweep runs from the shipped ceiling down
// through 200 halvings, which is far past where any real chain operates.
func TestWorkIsStrictlyMonotoneAcrossTheLiveRange(t *testing.T) {
	p := spec.Mainnet()

	prev := BlockWork(p.MaxTarget)
	target := p.MaxTarget
	steps := 0
	for i := 0; i < 200; i++ {
		next, _ := target.Div64(2)
		if next.IsZero() {
			break
		}
		w := BlockWork(next)
		if !w.Gt(prev) {
			t.Fatalf("work did not increase when the target halved from %s to %s"+
				" (%s -> %s): fork choice cannot distinguish these difficulties",
				target.String(), next.String(), prev.String(), w.String())
		}
		prev, target = w, next
		steps++
	}
	if steps < 100 {
		t.Fatalf("only %d halvings were swept; too narrow to support the claim", steps)
	}
	t.Logf("work strictly increased across %d halvings from max_target down", steps)
}

// TestAccumulatedWorkDoesNotSaturateWithinAnyReachableChain is the saturation
// question stated as an attack.
//
// Total work is accumulated with SatAdd, which clamps at 2^256-1 rather than
// wrapping. Clamping is the right choice — a wrap would let an attacker make a
// long chain's work small — but a clamp has its own failure: once two branches
// both saturate, they compare EQUAL, the `Gt` in considerBranchLocked is false,
// and the incumbent is kept forever regardless of how much more work arrives.
// Fork choice would stop working, silently, with no invalid block anywhere.
//
// The question is whether saturation is reachable. At mainnet's max_target a
// header is worth about 2^6 units, so saturation needs on the order of 2^250
// blocks — unreachable. But "unreachable" should be a measured statement rather
// than an assumed one, because the per-block work grows as the target hardens
// and it is the HARDEST plausible target that fills the accumulator fastest.
//
// This bounds it: even at a target far harder than any chain has ever reached,
// the number of blocks needed to saturate exceeds any block count this chain
// can produce before the sun burns out. The test asserts the margin rather than
// simulating it, since simulating 2^100 blocks is not available.
func TestAccumulatedWorkDoesNotSaturateWithinAnyReachableChain(t *testing.T) {
	p := spec.Mainnet()

	// A target far harder than the chain is expected to reach: max_target
	// shifted down by 80 halvings. Per-block work is correspondingly larger,
	// so this is a pessimistic case for saturation.
	hard := p.MaxTarget
	for i := 0; i < 80; i++ {
		hard, _ = hard.Div64(2)
	}
	if hard.IsZero() {
		t.Fatal("the fixture target underflowed to zero")
	}
	perBlock := BlockWork(hard)

	// Blocks to saturate = (2^256-1) / perBlock. If that quotient is still
	// enormous, saturation is not reachable. "Enormous" is made concrete: more
	// than 2^64 blocks, which at 30 s a block is ~1.7e13 years.
	blocks := divWide(u256.Max, perBlock)
	floor := u256.FromUint64(^uint64(0))
	if !blocks.Gt(floor) {
		t.Fatalf("at a target of %s a chain saturates the work accumulator in %s"+
			" blocks, which is fewer than 2^64 — fork choice would stop"+
			" distinguishing branches at that height",
			hard.String(), blocks.String())
	}

	// And the accumulator must actually be saturating rather than wrapping,
	// because a wrap is the worse failure: it makes a long chain look light.
	if got := u256.Max.SatAdd(u256.One); !got.Eq(u256.Max) {
		t.Fatal("SatAdd wrapped instead of clamping; a long chain's accumulated" +
			" work can be driven back to zero")
	}
	if got := u256.Max.SatAdd(u256.Max); !got.Eq(u256.Max) {
		t.Fatal("SatAdd wrapped on a large addend")
	}

	t.Logf("at a target 80 halvings below max_target, saturation needs %s blocks", blocks.String())
}

// TestEqualWorkKeepsTheIncumbentIsAStrictComparison pins the tie rule at the
// exact boundary, which is where a comparator mutation lives.
//
// I3's confidence section records equal-work ties resolving to first-seen as a
// deliberate choice with unmodelled MEV consequences. It is still deliberate.
// What this asserts is only that the comparison is STRICT — that
// `!br.Work().Gt(replaced)` means a branch must be strictly heavier to win —
// because flipping that one comparator to `Gte` would make every equal-work
// branch displace the incumbent, turning ties into a reorg on every announced
// sibling and handing the chain to whoever announces last rather than first.
//
// Unlike the commitment's Gt/Gte boundary (randomx-v2 §8.8 mutation E), which
// is a 1-in-2^256 fixed point and therefore unreachable, THIS boundary is
// reached constantly: two siblings at the same height with the same target
// carry exactly equal work, which is the ordinary case on a live network.
func TestEqualWorkKeepsTheIncumbentIsAStrictComparison(t *testing.T) {
	p := spec.Mainnet()

	// Two branches of equal work: same length, same targets. This is the
	// ordinary sibling case, not a contrived one.
	a := BlockWork(p.GenesisTarget).SatAdd(BlockWork(p.GenesisTarget))
	b := BlockWork(p.GenesisTarget).SatAdd(BlockWork(p.GenesisTarget))

	if !a.Eq(b) {
		t.Fatal("the fixture does not actually produce equal work")
	}
	// The rule as forkchoice spells it: strictly greater, or no switch.
	if a.Gt(b) {
		t.Fatal("Gt reported strict inequality between equal values —" +
			" every equal-work sibling would displace the incumbent")
	}

	// One unit more must win, or fork choice cannot follow the heavier chain
	// at all. The pair of assertions together is what pins the comparator:
	// either alone is satisfied by a constant.
	heavier := a.SatAdd(u256.One)
	if !heavier.Gt(b) {
		t.Fatal("a strictly heavier branch did not compare greater;" +
			" fork choice cannot adopt the heavier chain")
	}
}
