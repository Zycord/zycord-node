package refold

import (
	"math/big"
	"strconv"
	"testing"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/spec"
)

// TestTheHealthGateAdmitsTheEpochThatExactlyMeetsItsRate pins F2b's comparator
// in *this* fold: an epoch whose citation rate lands exactly on HealthGateBps
// is healthy, and growth is permitted.
//
// It is the port of core/fold's test of the same name, against this package's
// independent statement of the same sentence — `Cmp(...) <= 0` here against
// `!citedRate.Gt(gateRate)` there. Until it existed, refold's copy was held by
// a note and by nothing else, while core/fold's was pinned; a rule deliberately
// written twice so the two can be compared is not compared at a boundary only
// one of them is held to.
//
// The comparator is not in question. §8's F2b writes it as
// `healthy <- cited_count x 10000 <= HEALTH_GATE_BPS x EpochLength` and
// whitepaper §8.1 states the gate as "<= 2%". What was missing is anything in
// the tree that holds *this* implementation to the answer: cited is an integer,
// so `<=` and `<` can differ only where HealthGateBps x EpochLength is a
// multiple of 10000, and no shipped set makes it one — 200 x 2880 = 576,000 and
// 200 x 64 = 12,800 put the boundary at 57.6 and 1.28 cited headers. The
// differential runner is therefore arithmetically blind to this by
// construction, not by omission.
//
// **Why a custom parameter set is the right instrument, and where its authority
// stops.** A fixture that leaves the shipped ratio measures a different
// protocol; that was established twice over, once when B6's separating pair
// turned out to be half-unreachable by parity and once when both gas markets
// were found calibrated against a density no buildable block can reach. That
// defect has a specific shape: measure Q at p' and report Q at p, where Q
// genuinely varies with p. This is the opposite shape. §8's F2b is *quantified
// over* HEALTH_GATE_BPS, so the asserted property — at citedRate == gateRate,
// healthy is true — has the same truth value at every parameter set, and the
// shipped sets merely make its antecedent vacuous. The fixture **supplies a
// witness**; it does not **substitute a subject**. The two witnesses below are
// what makes that checkable rather than asserted: 1250 x 64 and 625 x 64 are
// independent legal sets whose boundaries sit at different counts (8 and 4),
// and a conclusion that depended on the fixture could not survive both. This
// test does not claim any network will run these numbers, and core/fold's
// TestTheHealthGateBoundaryHasNoIntegerAtAnyShippedParameterSet says in the
// other direction that none of them will.
//
// Limits. It drives updateSeqGasTarget directly rather than through
// ApplyBlock, so it says nothing about the controller being called at the right
// heights; sim's differential holds that.
func TestTheHealthGateAdmitsTheEpochThatExactlyMeetsItsRate(t *testing.T) {
	for _, witness := range []uint64{
		// 1250 x 64 = 80,000, so cited == 8 lands exactly on the gate. This is
		// the witness core/fold's copy of this test uses.
		1250,
		// 625 x 64 = 40,000, boundary at cited == 4. A second, independent
		// witness: it puts the boundary at a different count, so a kill that
		// held only at the first would be a fact about that fixture rather than
		// about the comparator.
		625,
	} {
		t.Run(witnessName(witness), func(t *testing.T) {
			runHealthGateWitness(t, witness)
		})
	}
}

func witnessName(bps uint64) string {
	return "health_gate_bps=" + strconv.FormatUint(bps, 10)
}

func runHealthGateWitness(t *testing.T, bps uint64) {
	t.Helper()
	p := *spec.Devnet()
	p.HealthGateBps = bps

	// The parameter set has to be one the protocol would accept, or this is a
	// statement about a configuration params.Validate would refuse and this
	// fold would never be handed.
	if err := p.Validate(); err != nil {
		t.Fatalf("the chosen parameter set is not one params.Validate accepts (%v); a rule "+
			"pinned at parameters the protocol rejects is pinned at nothing", err)
	}
	gate := p.HealthGateBps * p.EpochLength
	if gate%10000 != 0 {
		t.Fatalf("HealthGateBps x EpochLength is %d, which no integer count of cited headers "+
			"can meet; this test would compare two arms on the same side of the gate", gate)
	}
	onTheGate := gate / 10000
	if onTheGate == 0 {
		t.Fatal("the gate sits at zero cited headers, so the arm below the boundary does not exist")
	}
	// A count no block sequence could produce would put the boundary outside
	// the reachable range and make the separating pair unreachable in principle.
	if reachable := p.EpochLength * uint64(p.MaxCitesPerBlock); onTheGate+1 > reachable {
		t.Fatalf("the gate sits at %d cited headers but an epoch can carry at most %d, so the "+
			"arms astride it are not states this fold can be driven into", onTheGate, reachable)
	}

	// A ceiling step has to be observable at all, or all three arms return the
	// same target and the test asserts nothing.
	target := p.SeqGasTargetGenesis
	step := target / p.CeilingGrowthDivisor
	if step == 0 {
		t.Fatalf("T/gamma is zero at T = %d, so a healthy epoch and an unhealthy one produce the "+
			"same target and this test cannot tell them apart", target)
	}
	grown := target + step
	if grown > p.SeqGasCapacity {
		t.Fatalf("the grown target %d is above seq_gas_capacity %d, so the clamp and not the "+
			"gate would decide the arms", grown, p.SeqGasCapacity)
	}

	for _, arm := range []struct {
		what  string
		cited uint64
		want  uint64
	}{
		// The separating pair. Two consecutive counts astride the boundary,
		// which `<=` and `<` answer differently at the lower one and
		// identically at the upper.
		{"an epoch citing exactly the gate's rate may grow", onTheGate, grown},
		{"one citation past the gate withholds growth", onTheGate + 1, target},
		// The control below the boundary: without it, "the gate admits this
		// count" could be true because the gate admits everything.
		{"an epoch citing less than the gate's rate may grow", onTheGate - 1, grown},
	} {
		t.Run(arm.what, func(t *testing.T) {
			s := healthGateState(&p, target, arm.cited)

			updateSeqGasTarget(s, &p)

			got := s.Get(types.SeqGasTargetSlot()).Uint64()
			if got != arm.want {
				t.Fatalf("with cited_count = %d against a gate of %d, the controller set T to "+
					"%d, want %d. §8's F2b is `cited_count x 10000 <= HEALTH_GATE_BPS x "+
					"EpochLength` and whitepaper §8.1 states the gate as \"<= 2%%\": an epoch "+
					"that meets the rate exactly is healthy",
					arm.cited, onTheGate, got, arm.want)
			}
			// The counter is served and reset by the same step, whichever side
			// of the gate it fell on.
			if left := s.Get(types.CitedCountSlot()); left.Sign() != 0 {
				t.Fatalf("cited_count is %s after the boundary, want zero", left.String())
			}
		})
	}
}

// TestTheGrowthCeilingIsWhatTheHealthSignalMoves is the guard that keeps the
// test above from passing for a benign reason.
//
// Its arms distinguish `grown` from `target`, and that difference is only the
// health signal if nothing else in this controller can produce it. The samples
// and T are held fixed across the two extremes, so the *only* input that
// separates the two answers is cited_count. Without this, an arm returning
// `target` could be the growth clamp, the decay clamp, the capacity clamp or
// the genesis floor rather than the gate.
func TestTheGrowthCeilingIsWhatTheHealthSignalMoves(t *testing.T) {
	for _, bps := range []uint64{1250, 625} {
		t.Run(witnessName(bps), func(t *testing.T) {
			p := *spec.Devnet()
			p.HealthGateBps = bps
			target := p.SeqGasTargetGenesis

			run := func(cited uint64) uint64 {
				s := healthGateState(&p, target, cited)
				updateSeqGasTarget(s, &p)
				return s.Get(types.SeqGasTargetSlot()).Uint64()
			}

			healthy, unhealthy := run(0), run(p.EpochLength*uint64(p.MaxCitesPerBlock))
			if healthy == unhealthy {
				t.Fatalf("an epoch with no citations and one citing the maximum both set T to %d, "+
					"so the health signal moves nothing at these parameters and the arms astride "+
					"the boundary would be comparing the same quantity to itself", healthy)
			}
			if healthy != target+target/p.CeilingGrowthDivisor || unhealthy != target {
				t.Fatalf("the two extremes set T to %d and %d, want %d and %d; the difference "+
					"between the arms is not the growth ceiling and the boundary test is "+
					"measuring something else",
					healthy, unhealthy, target+target/p.CeilingGrowthDivisor, target)
			}
		})
	}
}

// healthGateState builds the state the controller reads: a sample ring flat at
// `target` so the controller's unclamped answer 2 x median is above the growth
// ceiling — which makes what the arms return the ceiling itself, the only thing
// the health signal moves — plus T and the cited counter.
func healthGateState(p *params.Params, target, cited uint64) *State {
	s := New()
	for i := uint64(0); i < p.EpochLength; i++ {
		s.Set(types.AppliedGasSampleSlot(i), new(big.Int).SetUint64(target))
	}
	s.Set(types.SeqGasTargetSlot(), new(big.Int).SetUint64(target))
	s.Set(types.CitedCountSlot(), new(big.Int).SetUint64(cited))
	return s
}
