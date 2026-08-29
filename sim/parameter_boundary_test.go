package sim_test

// The differential runner drives every parameter-shaped consensus rule at
// exactly one value per rule: the one the shipped networks carry. The
// TTL-horizon probe closed that for rule B2; the rest of the class is what this
// file sweeps.
//
// The class is a rule that (a) is stated twice, once in core/fold (or in a
// core/params function only core/fold reaches) and once in sim/refold, and
// (b) compares a certificate, block or state quantity against a parameter.
// A rule outside the class needs no sweep here: where both folds reach the
// SAME core/params function for the bound, there is no second derivation for
// a sweep to disagree with, and the boundary is a property of one function
// that core/params' own tests already pin.
//
// The discipline every arm below follows, taken from the B2 horizon sweep:
//
//   - state the reachable range of the compared quantity -- for B2 it was
//     rule B1, not the width of the field, that bounded it from above;
//   - state the two consecutive values that separate the rule;
//   - state whether that pair lies inside the reachable range at all, because
//     where it does not, the arm that matters inverts.
//
// Every regime here asserts Validate() first, so no arm measures a
// configuration no network could be started with.

import (
	"sort"
	"testing"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/sim"
	"zycord/spec"
)

// elasticBase is devnet with the epoch controller made observable inside a test
// binary, in the shape sim/differential_test.go's TestDifferentialElasticCeiling
// established: a small target and a short epoch so ordinary blocks span the
// ceiling and the burst band, an aggressive Gamma/Delta so a step that happens
// is a visible step, and a health gate the citation rate actually crosses.
//
// It is shared by the arms below so that what separates them is the one
// parameter each is named for, and not a second difference nobody accounted
// for.
func elasticBase() params.Params {
	p := *spec.Devnet()
	p.SeqGasTargetGenesis = 1_000
	p.EpochLength = 16
	p.CoinbaseMaturity = 8
	p.CeilingGrowthDivisor = 4
	p.CeilingDecayDivisor = 4
	p.HealthGateBps = 1_500
	// The subject here is the SEQUENTIAL controller, so the parallel ceiling must
	// not be what limits how much traffic a block carries -- if it is, the dense
	// generator's blocks thin out, the applied median collapses and the growth arm
	// never runs, which reports as an anti-vacuity failure about the fold rather
	// than about the fixture. ParGasLimit(T) is par_gas_ratio x 2T, which is 6,000
	// at this tightened T0 and mainnet's re-derived ratio of 3 -- a couple of
	// transfers. Devnet used to ship 10 and this fixture inherited it; the
	// gas-schedule respin moved devnet onto mainnet's 3, so it is pinned here now,
	// at the value that makes the parallel side inert.
	p.ParGasRatio = 10
	// Kept at the genesis ratio, which is what Validate enforces; the arms that
	// move it move both sides of the pairing together.
	p.SeqGasCapacity = p.SeqGasTargetGenesis *
		uint64(p.BlockByteCapacity) / uint64(p.BlockByteLimitGenesis)
	return p
}

// TestBothFoldsAgreeWhereTheSequentialTargetMeetsItsCapacity drives whitepaper
// 8.1's epoch controller onto the seq_gas_capacity wall from both sides.
//
// **Derivation.** The compared quantity is the controller's output for the next
// epoch's sequential target, before the capacity clamp:
// pre = clamp(2*median_applied, T - T/Delta, T + T/Gamma). Its reachable range
// is bounded from above not by the width of a uint64 but by the growth clamp and
// the length of the run -- T is multiplied by at most (1 + 1/Gamma) per epoch
// boundary, so after H blocks at epoch length L nothing above
// T0 * (1 + 1/Gamma)^floor(H/L) is reachable. That term is this sweep's analogue
// of B1 bounding B2's distance: it is the run, not the field, that binds.
//
// The two consecutive values that separate the rule are pre = seq_gas_capacity,
// which must be returned unchanged, and pre = seq_gas_capacity + 1, which must
// come back as seq_gas_capacity.
//
// **Does that pair lie inside the reachable range at a shipped value? No, by
// three orders of magnitude.** All three shipped networks run
// seq_gas_target_genesis = 1,600,000 against seq_gas_capacity = 5,120,000 --
// testnet and devnet carry mainnet's gas schedule deliberately -- so all three
// share the ratio 3.2 that Validate's pairing rule fixes. With Gamma =
// 512 the wall is ln(3.2)/ln(1 + 1/512) = 597 epoch boundaries away on every
// one of them: 38,208 blocks at devnet's epoch length of 64 and 1,719,360 at
// mainnet's 2,880, against the 300 blocks the longest differential run in this
// package drives. The boundary is approached from neither side, at any seed --
// the sentence that held for B2 before its horizon probe existed, restated for
// this parameter.
//
// **At a swept value it does, and the pair is placed rather than hoped for.**
// With Gamma = 4 and T0 = 1,000 the growth clamp puts pre at exactly 1,250 on
// the first growth boundary, so a capacity of 1,249 makes pre = capacity + 1 and
// a capacity of 1,250 makes pre = capacity. block_byte_capacity moves with the
// capacity in every arm because Validate enforces the two as a ratio.
//
// Every boundary is checked against an oracle re-derived here from 8.1's own
// statement of the controller, using only parameters and consensus state -- a
// test that asked either fold where T should be would be the fold marking its
// own work. The per-arm counters are what make that check non-vacuous: an arm
// whose named relation never occurred has measured the oracle against the
// uninteresting cases only.
//
// What this found: sim/refold's epoch controller carried no capacity clamp at
// all. See its comment at updateSeqGasTarget.
func TestBothFoldsAgreeWhereTheSequentialTargetMeetsItsCapacity(t *testing.T) {
	for _, arm := range []struct {
		name     string
		capacity uint64
		// want names the relation between pre and the capacity that this arm
		// exists to produce, and the counter is asserted non-zero for that
		// relation alone.
		want string
	}{
		{"the_wall_well_inside_the_growth_clamp", 1_100, "above"},
		{"the_first_target_the_wall_refuses", 1_249, "one_above"},
		{"the_last_target_the_wall_admits", 1_250, "equal"},
	} {
		t.Run(arm.name, func(t *testing.T) {
			p := elasticBase()
			p.SeqGasCapacity = arm.capacity
			p.BlockByteCapacity = int(arm.capacity) *
				p.BlockByteLimitGenesis / int(p.SeqGasTargetGenesis)
			if err := p.Validate(); err != nil {
				t.Fatalf("the swept parameter set is not one a network could run: %v", err)
			}
			// The placement is asserted rather than assumed: if Gamma or T0 ever
			// move, this says so instead of quietly measuring a different arm.
			firstGrowth := p.SeqGasTargetGenesis + p.SeqGasTargetGenesis/p.CeilingGrowthDivisor
			switch arm.want {
			case "one_above":
				if firstGrowth != arm.capacity+1 {
					t.Fatalf("the first growth step reaches %d, not capacity+1 = %d, so this arm "+
						"does not sit on the boundary it is named for", firstGrowth, arm.capacity+1)
				}
			case "equal":
				if firstGrowth != arm.capacity {
					t.Fatalf("the first growth step reaches %d, not the capacity %d",
						firstGrowth, arm.capacity)
				}
			case "above":
				if firstGrowth <= arm.capacity+1 {
					t.Fatalf("the first growth step reaches %d, which is not above capacity+1 = %d",
						firstGrowth, arm.capacity+1)
				}
			}

			var hit, boundaries int
			for seed := int64(1); seed <= 6; seed++ {
				r, err := sim.NewRunner(&p, seed)
				if err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
				r.Dense = true
				seedHit := 0
				for i := 0; i < 300; i++ {
					h := r.Chain.NextHeight()
					isBoundary := h > 0 && h%p.EpochLength == 0
					var pre uint64
					if isBoundary {
						pre = controllerOutputBeforeTheWall(r, &p)
					}
					if err := r.Step(); err != nil {
						t.Fatalf("seed %d, step %d: %v", seed, i, err)
					}
					if !isBoundary || r.Chain.Height() != h {
						continue // the block was refused; no boundary was folded
					}
					boundaries++
					after, _ := r.Chain.State.Get(types.SeqGasTargetSlot()).Uint64()
					want := pre
					if want > p.SeqGasCapacity {
						want = p.SeqGasCapacity
					}
					if want < p.SeqGasTargetGenesis {
						want = p.SeqGasTargetGenesis
					}
					if after != want {
						t.Fatalf("seed %d, height %d: the controller asked for %d against a "+
							"capacity of %d and T came out %d, want %d",
							seed, h, pre, p.SeqGasCapacity, after, want)
					}
					switch arm.want {
					case "above":
						if pre > p.SeqGasCapacity+1 {
							seedHit++
						}
					case "one_above":
						if pre == p.SeqGasCapacity+1 {
							seedHit++
						}
					case "equal":
						if pre == p.SeqGasCapacity {
							seedHit++
						}
					}
				}
				hit += seedHit
				endT, _ := r.Chain.State.Get(types.SeqGasTargetSlot()).Uint64()
				t.Logf("seed %d: height=%d T=%d grew=%d decayed=%d withheld=%d on-arm=%d",
					seed, r.Chain.Height(), endT, r.Grew, r.Decayed, r.GateWithheld, seedHit)
			}
			t.Logf("%s: %d boundaries folded, %d of them on this arm", arm.name, boundaries, hit)
			// Asserted across the seeds rather than per seed, for the reason
			// TestDifferentialElasticCeiling gives: whether a given seed grows
			// depends on whether its tips apply or skip, and demanding it of
			// every seed would assert a property of the traffic generator.
			if hit == 0 {
				t.Errorf("no epoch boundary in any seed put the controller's output in the "+
					"%q relation to seq_gas_capacity (%d), so the wall was never reached on "+
					"this arm and both folds agreed about a clamp neither of them ran",
					arm.want, p.SeqGasCapacity)
			}
		})
	}
}

// controllerOutputBeforeTheWall is whitepaper 8.1's
// clamp(2*median_applied(e), T - T/Delta, T + T/Gamma) -- the epoch controller's
// answer before seq_gas_capacity is applied to it -- recomputed from consensus
// state and parameters alone.
//
// Read before the boundary block is folded, which is the only side of the
// transition where these are the values the controller sees: a block writes its
// own applied-gas sample into the ring and its own citations into the counter on
// the way out, and the controller runs before either.
//
// The lower median (element (L-1)/2 of the sorted ring) is not a choice made
// here: it is the convention both folds state, and an oracle that interpolated
// instead would disagree with them on every even-length ring for a reason that
// has nothing to do with the wall.
func controllerOutputBeforeTheWall(r *sim.Runner, p *params.Params) uint64 {
	samples := make([]uint64, p.EpochLength)
	for i := uint64(0); i < p.EpochLength; i++ {
		samples[i], _ = r.Chain.State.Get(types.AppliedGasSampleSlot(i)).Uint64()
	}
	sort.Slice(samples, func(a, b int) bool { return samples[a] < samples[b] })
	median := samples[(p.EpochLength-1)/2]

	cited, _ := r.Chain.State.Get(types.CitedCountSlot()).Uint64()
	healthy := cited*10000 <= p.HealthGateBps*p.EpochLength

	t, _ := r.Chain.State.Get(types.SeqGasTargetSlot()).Uint64()
	lo := t - t/p.CeilingDecayDivisor
	hi := t
	if healthy {
		hi = t + t/p.CeilingGrowthDivisor
	}
	next := 2 * median
	if next < lo {
		next = lo
	}
	if next > hi {
		next = hi
	}
	return next
}

// TestBothFoldsAgreeWhereTheEmissionScheduleMeetsItsTail drives the coinbase
// schedule across the epoch at which emission_decay_divisor stops mattering.
//
// **Derivation.** The compared quantity is the epoch index. core/fold reads the
// subsidy from core/params' precomputed table; sim/refold recomputes the decay
// from the published recurrence on every call, with no table and no u256 -- two
// independent implementations of E(n) = max(tail, E(n-1) - E(n-1)/divisor), and
// Differential compares what they produce as MinerReward, Treasury and the
// state root on every single block.
//
// The reachable range of the epoch index is [0, floor(H/L)] for a run of H
// blocks at epoch length L. The two consecutive values that separate the rule
// are n*-1, the last epoch at which the schedule is still decaying, and n*, the
// first at which the tail has taken over and the divisor no longer reads.
//
// **At a shipped value the pair is outside the range by three orders of
// magnitude.** All three networks decay 2,100,000,000 to 33,000,000 at divisor
// 1054, which reaches the tail at n* = 4,376 -- height 280,064 at devnet's epoch
// length of 64. The subtest below asserts that, so the exclusion is a
// measurement rather than a sentence, and the number here is the one it logs
// rather than a second count of the same walk.
//
// **Two swept regimes, because the schedule has two decay paths and only one of
// them is a division.** The forced one-unit step -- the branch that makes the
// walk terminate, and the branch a large emission_decay_divisor makes long --
// fires only when the divisor exceeds the emission itself, which is true at no
// shipped set at any height: the emission never falls below the tail of
// 33,000,000 and the divisor is 1054, so that branch is dead code in both folds
// today.
func TestBothFoldsAgreeWhereTheEmissionScheduleMeetsItsTail(t *testing.T) {
	t.Run("the_shipped_schedules_reach_the_tail_far_outside_any_run", func(t *testing.T) {
		for _, n := range []struct {
			name string
			p    *params.Params
		}{{"mainnet", spec.Mainnet()}, {"testnet", spec.Testnet()}, {"devnet", spec.Devnet()}} {
			star := tailEpoch(n.p)
			reach := uint64(300) / n.p.EpochLength // the longest run in this package
			if star <= reach {
				t.Fatalf("%s: the tail arrives at epoch %d and a 300-block run reaches epoch %d, "+
					"so this parameter is already swept and the regimes below are redundant",
					n.name, star, reach)
			}
			t.Logf("%s: tail at epoch %d (height %d); a 300-block run reaches epoch %d",
				n.name, star, star*n.p.EpochLength, reach)
		}
	})

	for _, tc := range []struct {
		name                     string
		genesis, tail, divisor   uint64
		wantForcedOneUnitStepped bool
	}{
		// Decay by division, tail reached inside the run: the divisor is well
		// below the emission, so every step is E/divisor and the schedule is
		// the geometric one all three networks run, compressed.
		{"decay_by_division", 2_100_000_000, 2_000_000_000, 200, false},
		// Decay by the forced one-unit step: the divisor is above the emission,
		// so E/divisor is zero at every epoch and the floor is the only thing
		// moving the schedule at all. Unreachable at every shipped set.
		{"decay_by_the_forced_one_unit_step", 2_100_000_000, 2_099_999_990, 3_000_000_000, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := elasticBase()
			p.EpochLength = 8
			p.GenesisEmission = u256.FromUint64(tc.genesis)
			p.TailEmission = u256.FromUint64(tc.tail)
			p.EmissionDecayDivisor = tc.divisor
			if err := p.Validate(); err != nil {
				t.Fatalf("the swept parameter set is not one a network could run: %v", err)
			}
			if got := tc.divisor > tc.genesis; got != tc.wantForcedOneUnitStepped {
				t.Fatalf("regime mislabelled: divisor %d against genesis emission %d",
					tc.divisor, tc.genesis)
			}
			star := tailEpoch(&p)
			if star == 0 {
				t.Fatal("the tail is reached at epoch 0, so no epoch in this run is on the " +
					"decaying side of the boundary and only one side is driven")
			}
			// The run must fold blocks at n*-1 and at n*. Committed heights are
			// contiguous, so reaching height (n*+1)*L is what establishes it.
			need := (star + 1) * p.EpochLength
			t.Logf("tail at epoch %d (height %d); need height %d", star, star*p.EpochLength, need)

			var reached uint64
			for seed := int64(1); seed <= 2; seed++ {
				r, err := sim.NewRunner(&p, seed)
				if err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
				r.Dense = true
				for i := 0; i < 300; i++ {
					if err := r.Step(); err != nil {
						t.Fatalf("seed %d, step %d: %v", seed, i, err)
					}
				}
				if h := r.Chain.Height(); h > reached {
					reached = h
				}
				t.Logf("seed %d: height=%d epoch=%d", seed, r.Chain.Height(),
					r.Chain.Height()/p.EpochLength)
			}
			if reached < need {
				t.Errorf("the longest run reached height %d, short of %d: no block was ever "+
					"folded on the tail side of the boundary, so both folds agreed about a "+
					"branch neither of them took", reached, need)
			}
		})
	}
}

// **Rule B6 is deliberately not swept here, and this note is where its arm used
// to be.** The long form is in par_gas_ceiling_witness_test.go; the short form
// is that B6 is not a member of this file's class at all.
//
// The arm that stood here reached B6 through elasticBase(), which sets the
// *parameter* seq_gas_target_genesis to 1,000 while leaving
// block_byte_limit_genesis at 2,500,000 — moving the shipped ratio from 1.25
// bytes per gas to 2,500. Every other arm in this file survives that, because
// what it sweeps is separated from the byte ceiling. B6 does not: dividing B6's
// ceiling by B13's cancels T, so **what B6 asks is fixed by exactly that
// ratio**, and an arm that reaches B6 only after moving it is measuring a
// different protocol. It also drove the wrong half of the pair — over the
// ceiling but never onto it — leaving `parGas > parCeiling` -> `>=` a
// documented mutant survivor, and its magnitude ("40,000,000 against a largest
// generated block of 18,486, a factor of 2,164") was corrected three times
// before being retired outright.
//
// **Where B6 lives now, and it is two files rather than one:**
//
//   - sim/block_ceiling_boundary_test.go's
//     TestB6CannotFireOnAnyBlockTheByteCeilingAdmits derives — for every block
//     the V-rules admit rather than for every block anyone built — that B6
//     cannot fire at any shipped parameter set or any T. That is why B6 is a
//     witness row and not a sweep row.
//   - sim/par_gas_ceiling_witness_test.go drives the separating pair (L, L+2) at
//     two legal-but-unshipped witnesses on two independent axes, including the
//     equality case L that kills the `>` -> `>=` survivor.
//
// Nothing in this file may reach B6 again through elasticBase(). If a future
// sweep needs to, the thing that has changed is the byte/gas ratio, and that is
// a parameter decision rather than a test one.

// TestTheKeyScheduleBoundaryIsAlreadyDrivenAtTheShippedDevnetValue is the
// mechanical form of an exclusion, so that the exclusion stops holding loudly
// rather than silently.
//
// The census of unswept parameters lists randomx_key_interval and
// randomx_key_lag. They are not unswept. The compared quantity is the header's
// declared seed epoch, against a schedule core/pow states as a closed form ((h
// - lag) / interval, with an underflow guard) and sim/refold states by counting
// boundaries -- two genuinely independent derivations, which is what puts the
// pair in the class.
//
// The reachable range of the compared quantity is the run's own height range.
// The two consecutive values that separate the rule are h = k*interval + lag - 1
// (epoch k-1) and h = k*interval + lag (epoch k). At devnet's shipped 64 and 8
// the first such pair is (71, 72), which is **inside** the range of every run in
// this package that passes height 72 -- so both folds already state the epoch on
// both sides of a real boundary, and no new arm is needed.
//
// This test asserts exactly that, and nothing about the parameter's other
// regimes. What it is not: it is not a claim that mainnet's 2,048/64 or
// testnet's 512/64 are driven -- their first boundaries are at heights 2,112 and
// 576, outside every run here.
func TestTheKeyScheduleBoundaryIsAlreadyDrivenAtTheShippedDevnetValue(t *testing.T) {
	p := spec.Devnet()
	boundary := p.RandomXKeyInterval + p.RandomXKeyLag
	r, err := sim.NewRunner(p, 1)
	if err != nil {
		t.Fatalf("%v", err)
	}
	for i := 0; i < 200; i++ {
		if err := r.Step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	if r.Chain.Height() <= boundary {
		t.Fatalf("the run reached height %d and the first key boundary is at %d, so this "+
			"parameter is NOT driven at a shipped value and the census entry for it stands",
			r.Chain.Height(), boundary)
	}
	// Every header in Headers was accepted by both folds, so a header's seed
	// epoch is a value the two folds agreed on rather than one this test read
	// out of one of them.
	var below, at uint64
	var sawBoth bool
	for _, h := range r.Chain.Headers {
		switch h.Height {
		case boundary - 1:
			below, sawBoth = h.PoW.SeedEpoch, true
		case boundary:
			at = h.PoW.SeedEpoch
		}
	}
	if !sawBoth {
		t.Fatalf("no committed header sits at height %d", boundary-1)
	}
	if below != 0 || at != 1 {
		t.Fatalf("the seed epoch across the boundary at height %d is %d -> %d, want 0 -> 1",
			boundary, below, at)
	}
	t.Logf("height=%d, key boundary at %d folded by both implementations: epoch %d -> %d",
		r.Chain.Height(), boundary, below, at)
}

// tailEpoch re-derives the first epoch at which the schedule saturates, from
// whitepaper 14.2's recurrence and using nothing from core/params but the
// parameters themselves. A test that asked p.Emission where the tail is would
// be asking one of the two implementations under test to mark its own work.
func tailEpoch(p *params.Params) uint64 {
	genesis, ok1 := p.GenesisEmission.Uint64()
	tail, ok2 := p.TailEmission.Uint64()
	if !ok1 || !ok2 {
		panic("this helper is only used on schedules that fit in uint64")
	}
	e := genesis
	for n := uint64(0); n < 1<<21; n++ {
		if e <= tail {
			return n
		}
		step := e / p.EmissionDecayDivisor
		if step == 0 {
			step = 1
		}
		if e-step < tail {
			e = tail
		} else {
			e -= step
		}
	}
	panic("the schedule does not saturate within the bound this helper carries")
}
