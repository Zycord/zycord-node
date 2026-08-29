package fold

import (
	"testing"

	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
)

// TestTheHealthGateAdmitsTheEpochThatExactlyMeetsItsRate pins F2b's comparator:
// an epoch whose citation rate lands exactly on HealthGateBps is healthy, and
// growth is permitted.
//
// That is not this file's opinion about which comparator is right. §8's F2b
// writes the rule as `healthy ← cited_count × 10000 ≤ HEALTH_GATE_BPS ×
// EpochLength` and whitepaper §8.1 states the gate as "≤ 2%": the question is
// answered, and what was missing is anything in the tree that holds the
// implementation to the answer. Inverting `!citedRate.Gt(gateRate)` to
// `citedRate.Lt(gateRate)` survived core/validity, core/fold, spec and sim
// alike, because no shipped parameter set can put an integer count on the
// boundary — 200 × 2880 = 576,000 and 200 × 64 = 12,800, neither a multiple of
// 10,000, so the boundaries are 57.6 and 1.28 cited headers.
//
// **Why a custom parameter set is the right instrument here, and where its
// authority stops.** A sweep which drives a boundary only because its fixture
// left the shipped ratio behind is measuring a different protocol, and that
// has been found in this tree twice. That precedent is about a *differential
// sweep* asserting agreement over a region the network will never occupy; it
// does not reach a unit test at chosen parameters, which §21 already
// sanctions and which TestSkipsAreNotDemand and
// TestBurstValveAtGenesisParameters in this package already are. The
// difference is what the test claims. This one claims that the controller
// implements the comparator §8 specifies — a statement about the rule, true
// at every parameter set — and it chooses parameters at which the two
// candidate comparators disagree, precisely so the claim can be observed. It
// does *not* claim that any network will ever run these numbers, and
// TestTheHealthGateBoundaryHasNoIntegerAtAnyShippedParameterSet says in the
// other direction that none of them will.
//
// Limits. (1) It exercises updateSeqGasTarget directly rather than through
// ApplyBlock, so it says nothing about the controller being called at the right
// heights — the elastic-ceiling tests in this package and sim's differential
// hold that. (2) sim/refold's `Cmp(...) <= 0` is a second implementation of the
// same sentence and is not exercised here; the differential cannot separate the
// two comparators either, for the same arithmetic reason, so that copy carries
// its own port of this test rather than being reached from this package.
func TestTheHealthGateAdmitsTheEpochThatExactlyMeetsItsRate(t *testing.T) {
	p := *spec.Devnet()
	// 1250 × 64 = 80,000, a multiple of 10,000, so cited == 8 lands exactly on
	// the gate. Devnet's own 200 × 64 = 12,800 puts it at 1.28 and can express
	// no such count. Nothing else is changed: the arms below differ from each
	// other in cited_count alone.
	p.HealthGateBps = 1250

	// The parameter set has to be one the protocol would accept, or this is a
	// statement about a configuration params.Validate would refuse and the
	// controller would never be handed.
	if err := p.Validate(); err != nil {
		t.Fatalf("the chosen parameter set is not one params.Validate accepts (%v); a rule "+
			"pinned at parameters the protocol rejects is pinned at nothing", err)
	}
	gate := p.HealthGateBps * p.EpochLength
	if gate%10000 != 0 {
		t.Fatalf("HealthGateBps × EpochLength is %d, which no integer count of cited headers "+
			"can meet; this test would compare two arms on the same side of the gate", gate)
	}
	onTheGate := gate / 10000
	if onTheGate == 0 {
		t.Fatal("the gate sits at zero cited headers, so the arm below the boundary does not exist")
	}

	// A ceiling step has to be observable at all, or all three arms return the
	// same target and the test asserts nothing.
	target := p.SeqGasTargetGenesis
	step := target / p.CeilingGrowthDivisor
	if step == 0 {
		t.Fatalf("T/Γ is zero at T = %d, so a healthy epoch and an unhealthy one produce the "+
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
		// The separating pair. Two consecutive counts astride the boundary, which
		// `≤` and `<` answer differently at the lower one and identically at the
		// upper.
		{"an epoch citing exactly the gate's rate may grow", onTheGate, grown},
		{"one citation past the gate withholds growth", onTheGate + 1, target},
		// The control below the boundary: without it, "the gate admits this
		// count" could be true because the gate admits everything.
		{"an epoch citing less than the gate's rate may grow", onTheGate - 1, grown},
	} {
		t.Run(arm.what, func(t *testing.T) {
			j := &journal{s: state.New(), log: &state.UndoLog{}}
			// A median large enough that the controller's unclamped answer is
			// above the growth ceiling, so what the arms return is the ceiling
			// itself — which is the only thing the health signal moves.
			for i := uint64(0); i < p.EpochLength; i++ {
				j.set(types.AppliedGasSampleSlot(i), u256.FromUint64(target))
			}
			j.set(types.SeqGasTargetSlot(), u256.FromUint64(target))
			j.set(types.CitedCountSlot(), u256.FromUint64(arm.cited))

			updateSeqGasTarget(j, &p)

			got, _ := j.s.Get(types.SeqGasTargetSlot()).Uint64()
			if got != arm.want {
				t.Fatalf("with cited_count = %d against a gate of %d, the controller set T to "+
					"%d, want %d. §8's F2b is `cited_count × 10000 ≤ HEALTH_GATE_BPS × "+
					"EpochLength` and whitepaper §8.1 states the gate as \"≤ 2%%\": an epoch "+
					"that meets the rate exactly is healthy",
					arm.cited, onTheGate, got, arm.want)
			}
			// The counter is served and reset by the same step, whichever side of
			// the gate it fell on.
			if left := j.s.Get(types.CitedCountSlot()); !left.IsZero() {
				t.Fatalf("cited_count is %s after the boundary, want zero", left.String())
			}
		})
	}
}

// TestTheGrowthCeilingIsWhatTheHealthSignalMoves is the guard that keeps the
// test above from passing for a benign reason.
//
// Its three arms distinguish `grown` from `target`, and that difference is only
// the health signal if nothing else in the controller can produce it. The lower
// median is what the arms feed, so this fixes the other half: at the same
// samples and the same T, the *only* input that separates the two answers is
// cited_count. Without it, an arm returning `target` could be the growth clamp,
// the decay clamp or the capacity clamp rather than the gate.
func TestTheGrowthCeilingIsWhatTheHealthSignalMoves(t *testing.T) {
	p := *spec.Devnet()
	p.HealthGateBps = 1250
	target := p.SeqGasTargetGenesis

	run := func(cited uint64) uint64 {
		j := &journal{s: state.New(), log: &state.UndoLog{}}
		for i := uint64(0); i < p.EpochLength; i++ {
			j.set(types.AppliedGasSampleSlot(i), u256.FromUint64(target))
		}
		j.set(types.SeqGasTargetSlot(), u256.FromUint64(target))
		j.set(types.CitedCountSlot(), u256.FromUint64(cited))
		updateSeqGasTarget(j, &p)
		v, _ := j.s.Get(types.SeqGasTargetSlot()).Uint64()
		return v
	}

	healthy, unhealthy := run(0), run(p.EpochLength*uint64(p.MaxCitesPerBlock))
	if healthy == unhealthy {
		t.Fatalf("an epoch with no citations and one citing the maximum both set T to %d, so "+
			"the health signal moves nothing at these parameters and the arms astride the "+
			"boundary would be comparing the same quantity to itself", healthy)
	}
	if healthy != target+target/p.CeilingGrowthDivisor || unhealthy != target {
		t.Fatalf("the two extremes set T to %d and %d, want %d and %d; the difference between "+
			"the arms is not the growth ceiling and the boundary test is measuring something "+
			"else", healthy, unhealthy, target+target/p.CeilingGrowthDivisor, target)
	}
}
