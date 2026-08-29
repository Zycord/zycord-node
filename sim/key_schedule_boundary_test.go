package sim_test

// The key-schedule sweep, which is the arm sim/parameter_boundary_test.go
// deliberately left standing.
//
// The census of twice-written parameter-shaped rules listed
// randomx_key_interval and randomx_key_lag among the parameters whose boundary
// "is never approached from either side". That is false at devnet's shipped
// 64/8, and TestTheKeyScheduleBoundaryIsAlreadyDrivenAtThe ShippedDevnetValue
// over in parameter_boundary_test.go pins exactly why. What that test is
// careful to say it does NOT cover is what this file is for:
//
//  1. only k = 1 was driven -- the devnet boundaries at 136, 200 and 264 are
//     crossed by existing runs, but nothing asserts them and no test names a
//     k > 1 boundary as its subject;
//  2. neither shipped non-devnet interval was driven -- mainnet's first
//     boundary is at height 2,112 and testnet's at 576, against runs that reach
//     200 to 300 blocks;
//  3. the widest lag Validate accepts -- lag = interval - 1 -- was driven
//     nowhere, and it is the arm most likely to separate the two derivations,
//     because it is where pow.SeedEpochFor's `height - lag < interval` guard and
//     sim/refold's counting loop are closest together.
//
// **The instrument is empty blocks, not the scenario generator, and that is the
// whole reason heights of 2,112 are affordable here.** The rule under test is
// B0b, and B0b is a function of the header's height and the parameters and
// nothing else -- no certificate, no state, no clock. So block *contents* are
// not a variable this sweep has, and paying the traffic generator's ~12 ms per
// block to reach mainnet's first boundary would buy nothing at all. Every block
// below still goes through sim.Differential, so every height is judged by both
// folds and compared on the whole observable surface, exactly as a generated
// block is; what is dropped is the traffic, not the comparison.
//
// **What makes these two derivations, and not one read twice.** core/fold reaches
// pow.SeedEpochFor, a closed form -- (h - lag) / interval, with an underflow
// guard. sim/refold counts boundaries at or below the height in a loop. The
// harness proposer fills the header's declared epoch from the closed form, and
// refold's loop is what judges it, so an honest block accepted by both is the
// two forms agreeing at that height, and a forged one refused by both is the
// two forms agreeing about the neighbouring value as well.
//
// **The discipline this file follows is the one the B2 horizon sweep set**,
// same as parameter_boundary_test.go: state the reachable range of the compared
// quantity, state the two consecutive values that separate the rule, and state
// whether that pair lies inside the reachable range. Here the compared quantity
// is the header's declared seed epoch; the separating pair at the k-th boundary
// is h = k*interval + lag - 1 (epoch k-1) against h = k*interval + lag (epoch
// k); and the reachable range is the run's height range, which this file sets
// on purpose rather than inheriting from a run built for something else.
//
// Every regime asserts Validate() first, so no arm measures a configuration no
// network could be started with.
//
// **Mutants, measured at the tip this file was written against.** Each line is a
// one-token edit, run against these three tests and against the package's own
// differential runner with this file removed:
//
//	sim/refold  loop capped at epoch 1 (`for epoch < 1 && ...`)
//	            -> killed here at 136, 1088 and 191; mainnet's k=1 arm survives it.
//	               TestDifferentialElasticCeiling also kills it, incidentally, at
//	               seed 6 step 191 -- as a divergence at a step number, not as a
//	               statement about the schedule. That is gap 1: the boundary was
//	               crossed, never named.
//	sim/refold  interval hard-coded to devnet's 64
//	            -> killed by testnet and mainnet only; both devnet arms survive it.
//	               That is gap 2, and nothing else in this tree kills it.
//	core/fold   B0b narrowed to `SeedEpoch > want`, so a header UNDER-declaring
//	            its epoch is accepted
//	            -> killed by all three arms; survives every seed of
//	               TestDifferentialElasticCeiling. The runner's probeSeedEpoch only
//	               ever ADDS 1..3 to the honest epoch, so the lower neighbour is
//	               forged nowhere before this file. That is why every probe below
//	               is two-sided.
//	core/pow    `height < lag` dropped from SeedEpochFor's guard
//	            -> killed by all three arms, from height 1 in each.
//	core/pow    that same guard narrowed to `height < interval`
//	            -> survives all three, as pow.go's own comment already records:
//	               with Validate pinning lag < interval the two forms are equal.
//
// Not covered, and recorded rather than fixed: sim/refold's counting loop is
// not total -- (epoch+1)*interval + lag can overflow for a large epoch and the
// loop would then never terminate. Reaching it needs a height near 2^64, and
// Validate already refuses the pair whose sum overflows -- the same guard that
// keeps genesis in the same epoch as every other height -- so it is a property
// of the naive fold's affordability rather than a defect. It is recorded here
// and left; a sweep that widens randomx_key_interval should know this loop is
// O(height/interval) before it picks a value.

import (
	"fmt"
	"testing"

	"zycord/core/crypto"
	"zycord/core/genesis"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/sim"
	"zycord/sim/harness"
	"zycord/sim/refold"
	"zycord/spec"
)

// keySchedulePayout is a persistent user address and nothing more. B11 requires
// a payout address that can actually receive; no rule in this sweep reads any
// other property of it.
var keySchedulePayout = types.Address{crypto.AddrVersionPersistent, 0x34, 0x35}

// keyScheduleChain is a chain driven by both implementations at once: the
// reference fold's state inside a harness.Chain, and sim/refold's beside it.
type keyScheduleChain struct {
	p     *params.Params
	chain *harness.Chain
	naive *refold.State
}

func newKeyScheduleChain(t *testing.T, p *params.Params) *keyScheduleChain {
	t.Helper()
	if err := p.Validate(); err != nil {
		t.Fatalf("this regime is not a configuration any network could be started with, "+
			"so nothing measured in it would be about the protocol: %v", err)
	}
	block, _, err := genesis.Build(p)
	if err != nil {
		t.Fatalf("genesis: %v", err)
	}
	naive := refold.New()
	if _, err := refold.ApplyBlock(naive, block, p); err != nil {
		t.Fatalf("the naive fold rejected genesis: %v", err)
	}
	chain, err := harness.New(p)
	if err != nil {
		t.Fatalf("genesis: %v", err)
	}
	return &keyScheduleChain{p: p, chain: chain, naive: naive}
}

// accept folds an honest block through both implementations and advances the
// tip. Differential moves both states; the harness's header list has to be
// advanced by hand because Chain.Apply would fold the block a second time.
func (k *keyScheduleChain) accept(t *testing.T, b *types.Block) {
	t.Helper()
	accepted, err := sim.Differential(k.chain.State, k.naive, b, k.p)
	if err != nil {
		t.Fatalf("height %d: %v", b.Header.Height, err)
	}
	if !accepted {
		t.Fatalf("both folds rejected the honest empty block at height %d, so this run "+
			"never reached the boundary it was built to cross", b.Header.Height)
	}
	k.chain.Headers = append(k.chain.Headers, b.Header)
	k.chain.Undos = append(k.chain.Undos, nil)
}

// reject hands both folds a COPY of an otherwise honest block declaring the
// wrong key epoch and requires them to agree it is invalid.
//
// This is the half that makes the arm two-sided. A run in which every header
// declares the correct epoch cannot separate "both folds enforce the schedule"
// from "neither does" -- that is the structural blindness sim.Runner's
// probeSeedEpoch exists for, met here at heights that runner cannot reach.
//
// Callers forge BOTH neighbours where both exist. probeSeedEpoch only ever adds
// 1..3 to the honest epoch, so before this file a B0b narrowed to `SeedEpoch >
// want` -- refusing the header that claims too new a key, accepting the one that
// claims too old a key, which is the direction a stale miner actually produces --
// passed every seed of the differential. It does not pass here.
//
// The copy is what keeps it free: types.Block carries its Header by value, so
// mutating the copy's leaves the original alone, and neither fold mutates state
// for a block its block rules refuse.
func (k *keyScheduleChain) reject(t *testing.T, b *types.Block, epoch uint64) {
	t.Helper()
	probe := *b
	probe.Header.PoW.SeedEpoch = epoch
	accepted, err := sim.Differential(k.chain.State, k.naive, &probe, k.p)
	if err != nil {
		t.Fatalf("height %d: the two folds disagreed about a header declaring seed epoch %d: %v",
			b.Header.Height, epoch, err)
	}
	if accepted {
		t.Fatalf("both folds accepted the block at height %d declaring seed epoch %d; "+
			"the key schedule is enforced by neither at this height",
			probe.Header.Height, epoch)
	}
}

// driveKeyBoundaries folds every height from 1 up to the k-th key boundary
// through both implementations, and at each separating pair below it asserts
// the epoch from both sides: the honest value accepted by both, and each
// neighbouring value refused by both.
//
// It returns the boundary heights it drove, so a caller can state them as
// literals and have the arithmetic checked rather than trusted.
func driveKeyBoundaries(t *testing.T, p *params.Params, throughK uint64) []uint64 {
	t.Helper()
	if throughK == 0 {
		t.Fatal("a sweep through zero boundaries drives nothing")
	}
	k := newKeyScheduleChain(t, p)

	// The k-th boundary is k*interval + lag. Validate has already refused a pair
	// whose sum overflows, and throughK is a literal in every caller, so this
	// arithmetic is checked rather than assumed.
	boundaries := make([]uint64, 0, throughK)
	// want maps the heights of every separating pair to the epoch the schedule
	// gives there. Only those heights are probed; the rest are folded honestly
	// so the chain reaches them.
	want := map[uint64]uint64{}
	for n := uint64(1); n <= throughK; n++ {
		b := n*p.RandomXKeyInterval + p.RandomXKeyLag
		boundaries = append(boundaries, b)
		want[b-1] = n - 1
		want[b] = n
	}
	top := boundaries[len(boundaries)-1]

	probed := 0
	for h := uint64(1); h <= top; h++ {
		block, err := k.chain.Propose(keySchedulePayout)
		if err != nil {
			t.Fatalf("height %d: %v", h, err)
		}
		if block.Header.Height != h {
			t.Fatalf("the harness proposed height %d where %d was expected",
				block.Header.Height, h)
		}
		if epoch, ok := want[h]; ok {
			if got := block.Header.PoW.SeedEpoch; got != epoch {
				t.Fatalf("at height %d the closed form gives epoch %d, want %d "+
					"(interval %d, lag %d)", h, got, epoch, p.RandomXKeyInterval, p.RandomXKeyLag)
			}
			// The neighbouring epochs, one on each side where one exists. Below
			// the first boundary epoch 0 has no lower neighbour to forge.
			k.reject(t, block, epoch+1)
			if epoch > 0 {
				k.reject(t, block, epoch-1)
			}
			probed++
		}
		k.accept(t, block)
	}
	if probed != len(want) {
		t.Fatalf("drove %d of the %d separating heights", probed, len(want))
	}
	if got := k.chain.Height(); got != top {
		t.Fatalf("the run ended at height %d, not at the boundary %d it was built to reach",
			got, top)
	}
	return boundaries
}

// TestBothFoldsAgreeAtDevnetKeyBoundariesBeyondTheFirst closes the first gap
// listed above: only k = 1 was driven.
//
// Devnet's shipped 64/8 puts boundaries at 72, 136, 200 and 264. The first is
// already crossed by every run in this package that passes height 72, and
// parameter_boundary_test.go pins that. **Nothing named any of the other three
// as its subject**: TestDifferentialElasticCeiling's 300-step runs cross 136 and
// 200 incidentally, so a mutation exact at k = 1 and wrong after -- the capped
// counting loop in the mutant table above -- is caught only as "seed 6, step 191:
// divergence at height 136", at whichever seed's traffic happens to get there.
// Here it is caught as the boundary it is, at every k, at a height this test
// chose. The difference is not whether the fault is found; it is whether the
// report names the rule, and whether a shorter run or a moved interval leaves
// the coverage silently behind.
//
// The separating pairs are (71, 72), (135, 136), (199, 200) and (263, 264), all
// inside the range this arm drives on purpose.
func TestBothFoldsAgreeAtDevnetKeyBoundariesBeyondTheFirst(t *testing.T) {
	p := spec.Devnet()
	if p.RandomXKeyInterval != 64 || p.RandomXKeyLag != 8 {
		t.Fatalf("devnet ships randomx_key_interval/lag = %d/%d, not 64/8; the boundary "+
			"heights this test names are stale", p.RandomXKeyInterval, p.RandomXKeyLag)
	}
	got := driveKeyBoundaries(t, p, 4)
	assertBoundaries(t, got, 72, 136, 200, 264)
}

// TestBothFoldsAgreeAtTheFirstKeyBoundaryOfEveryShippedNetwork closes the
// second gap: neither non-devnet interval was driven by the differential at
// all.
//
// Mainnet ships 2048/64 and testnet 512/64, so their first boundaries are at
// 2,112 and 576 -- outside every generated run in this package, which reaches
// 200 to 300 blocks. spec/vectors 046-051 pin mainnet's and devnet's boundary
// heights, but a golden vector is core/fold answering alone; it is not the two
// folds agreeing, which is the property this package exists for. Testnet's
// boundary was pinned by neither (spec/README.md notes 054-genesis-testnet stops
// at genesis).
//
// These are the SHIPPED parameter sets, not devnet with the key pair swapped in.
// That costs nothing here because the instrument is empty blocks, and it buys
// the one thing a swapped-in pair could not: the interval is driven alongside
// the epoch length, maturity and emission schedule it actually ships with.
//
// Testnet is driven through k = 2 (heights 576 and 1,088) so that a non-devnet
// interval is covered beyond the first crossing too. Mainnet stops at k = 1;
// its second boundary is at 4,160 and adds no arm this file does not already
// have.
//
// Cost, since 2,112 blocks sounds expensive and is not: the whole test folds in
// about a second, because an empty block is nearly free through both folds. It
// carries no -short guard for that reason.
func TestBothFoldsAgreeAtTheFirstKeyBoundaryOfEveryShippedNetwork(t *testing.T) {
	for _, c := range []struct {
		name    string
		p       *params.Params
		through uint64
		want    []uint64
	}{
		{"testnet", spec.Testnet(), 2, []uint64{576, 1088}},
		{"mainnet", spec.Mainnet(), 1, []uint64{2112}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got := driveKeyBoundaries(t, c.p, c.through)
			assertBoundaries(t, got, c.want...)
			t.Logf("%s: interval %d, lag %d, boundaries %v folded by both implementations",
				c.name, c.p.RandomXKeyInterval, c.p.RandomXKeyLag, got)
		})
	}
}

// TestBothFoldsAgreeAtTheWidestKeyLagValidateAccepts closes the third gap.
//
// Validate refuses randomx_key_lag >= randomx_key_interval, so lag = interval-1
// is the extreme legal value, and this test asserts that bound directly rather
// than assuming it -- a widened Validate would otherwise leave this arm quietly
// measuring an interior point.
//
// **Why the issue calls this the arm most likely to separate the two
// derivations, and what that turned out to be worth.** The lag is what shifts
// the boundary, and every way of getting it wrong is widest where it is widest:
// at devnet's 8 the closed form's underflow guard covers heights 0..7, while at
// 63 it covers 0..62, heights 63..126 fall to `height-lag < interval`, and the
// first boundary is 127. So this is where a fault whose size scales with the lag
// has the most room to show.
//
// Measured, and stated rather than assumed: no mutant found for this file is
// killed HERE and nowhere else. Dropping pow.SeedEpochFor's `height < lag` guard
// -- the fault this arm is shaped for, since 1-63 wraps to a colossal epoch
// refold's loop will never count to -- is refused from height 1 here and, being
// devnet-visible too, at devnet's height 1 as well. Narrowing that guard to the
// interval alone stays invisible here exactly as it does everywhere else, for
// the reason pow.go gives.
//
// This arm therefore earns its place as boundary-value coverage rather than as a
// unique kill: lag = interval-1 is the extreme value the protocol admits and it
// was driven by nothing, and the assertions below pin the bound itself, so a
// widened Validate cannot quietly leave this measuring an interior point.
//
// The separating pairs are (126, 127), (190, 191) and (254, 255). Devnet's
// interval is kept at its shipped 64 so that the lag is the one thing that
// moves; everything else is devnet as it ships.
func TestBothFoldsAgreeAtTheWidestKeyLagValidateAccepts(t *testing.T) {
	p := spec.Devnet()
	p.RandomXKeyLag = p.RandomXKeyInterval - 1
	if err := p.Validate(); err != nil {
		t.Fatalf("lag = interval-1 must be legal, and Validate refused it: %v", err)
	}
	// One step further must not be, or "widest" names nothing.
	over := *p
	over.RandomXKeyLag = over.RandomXKeyInterval
	if err := over.Validate(); err == nil {
		t.Fatal("Validate accepted randomx_key_lag == randomx_key_interval, so the widest " +
			"legal lag is no longer interval-1 and this arm measures an interior point")
	}

	got := driveKeyBoundaries(t, p, 3)
	assertBoundaries(t, got, 127, 191, 255)
}

func assertBoundaries(t *testing.T, got []uint64, want ...uint64) {
	t.Helper()
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("the boundaries driven were %v, and this test names %v; the parameters "+
			"moved and the heights in its comment are stale", got, want)
	}
}
