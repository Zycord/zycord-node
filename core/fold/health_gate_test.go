package fold_test

import (
	"testing"

	"zycord/core/u256"
	"zycord/spec"
)

// TestTheHealthGateBoundaryHasNoIntegerAtAnyShippedParameterSet records why the
// comparator mutant survived, and makes the reason it survived fail the day it
// stops holding.
//
// **The comparator is not in question.** §8's F2b writes the rule as
// `healthy ← cited_count × 10000 ≤ HEALTH_GATE_BPS × EpochLength` and whitepaper
// §8.1 states the gate as "≤ 2%", so `≤` is settled; the implementation is held
// to it by TestTheHealthGateAdmitsTheEpochThatExactlyMeetsItsRate, at parameters
// chosen so the two candidate comparators disagree. What is open is *which
// parameters ship*, and this test is about that.
//
// Inverting `!citedRate.Gt(gateRate)` to `citedRate.Lt(gateRate)` survived
// core/validity, core/fold, spec and sim because the two differ only
// where citedRate == gateRate, and no shipped parameter set can put an integer
// there: cited is a count, so citedRate is a multiple of 10,000, while gateRate
// is HealthGateBps × EpochLength — 200 × 2880 = 576,000 on mainnet and testnet,
// 200 × 64 = 12,800 on devnet. The boundary sits at 57.6 and at 1.28 cited
// headers, and no block can cite 57.6 competitors. sim's own elasticBase
// (1,500 bps × 16 = 24,000) does not reach it either.
//
// So on the parameters this release ships, **nothing that replays the corpus or
// runs the differential can catch a regression that flips this comparator** —
// the two answer identically on every input those instruments can produce. That
// is a property of the parameter set, and this test asserts it, so the sentence
// above stops being true loudly rather than silently. A genesis parameter set is
// frozen once and forever (LAUNCH §3.5), so a set at which the boundary *is*
// reachable — where one cited header decides whether a whole epoch may grow —
// has to be noticed while it can still be changed, and its consequences taken
// deliberately: at that point the comparator becomes observable on the network,
// and both folds' spellings (core/fold's `!Gt`, sim/refold's `Cmp(…) <= 0`) must
// be confirmed to still agree with §8.
//
// Limits, stated rather than chased. (1) The scan is over spec.Networks(), so a
// parameter set that is not a shipped network — an operator's private chain, a
// test fixture — is outside it; the arithmetic below is what such a set would
// have to be checked against by hand. (2) It asserts a property of the
// parameters, not of the fold: it would stay green if updateSeqGasTarget stopped
// consulting the gate at all, which is what the elastic-ceiling tests in this
// package and sim's differential are for. (3) The equivalence half enumerates
// the cited counts a single epoch can actually reach; the divisibility half
// covers every integer and is the load-bearing one.
func TestTheHealthGateBoundaryHasNoIntegerAtAnyShippedParameterSet(t *testing.T) {
	networks := spec.Networks()
	// A scan that found no network would make every assertion below unreachable
	// and this test green — the failure mode the whole file exists to remove.
	if len(networks) < 3 {
		t.Fatalf("spec.Networks() lists %v; the shipped set has shrunk and this test is "+
			"reading a fragment of it", networks)
	}

	for _, name := range networks {
		t.Run(name, func(t *testing.T) {
			p, err := spec.ParamsFor(name)
			if err != nil {
				t.Fatal(err)
			}
			// Written the way F2b writes it, so that this is a statement about the
			// fold's own expression and not about a uint64 restatement of it.
			gateRate, over := u256.FromUint64(p.HealthGateBps).Mul(u256.FromUint64(p.EpochLength))
			if over {
				t.Fatalf("HealthGateBps × EpochLength overflows 256 bits at %s", name)
			}
			gate := p.HealthGateBps * p.EpochLength
			if !u256.FromUint64(gate).Eq(gateRate) {
				t.Fatalf("%s: the uint64 gate rate %d disagrees with the u256 one %s, so the "+
					"divisibility argument below is about a different number",
					name, gate, gateRate.String())
			}
			// gate == 0 puts the boundary at cited == 0, which every epoch reaches:
			// there the `=` in `≤` is the difference between an idle epoch being
			// healthy and being unhealthy, and it is live rather than latent.
			if gate == 0 {
				t.Fatalf("%s: HealthGateBps × EpochLength is zero, so citedRate == gateRate at "+
					"cited == 0 — every idle epoch sits exactly on the boundary, and §8's `≤` "+
					"makes all of them healthy. That is reachable behaviour on a shipped "+
					"network and almost certainly not the intent of a zero gate", name)
			}
			if gate%10000 == 0 {
				t.Fatalf("%s: HealthGateBps × EpochLength is %d, a multiple of 10,000, so "+
					"cited == %d puts citedRate exactly on gateRate — the boundary is now "+
					"reachable on a shipped network, and one cited header decides whether a "+
					"whole epoch may grow its sequential target. The comparator is not in "+
					"doubt: §8's F2b is `cited_count × 10000 ≤ HEALTH_GATE_BPS × EpochLength` "+
					"and it is pinned by TestTheHealthGateAdmitsTheEpochThatExactlyMeetsItsRate. "+
					"What this test protected is gone: confirm both folds still spell §8's `≤` "+
					"(core/fold's `!Gt`, sim/refold's `Cmp(…) <= 0`), and take the parameter "+
					"choice deliberately before it is frozen (LAUNCH §3.5)",
					name, gate, gate/10000)
			}

			// The behavioural half. Every cited count one epoch can reach — a block
			// carries at most MaxCitesPerBlock citations and an epoch is
			// EpochLength blocks — and at none of them can the gate's `≤` be told
			// from `<`. This is implied by the divisibility above; it is run
			// anyway, because the step from "the product is not a multiple of
			// 10,000" to "no attainable count sits on the boundary" is the step a
			// reader has to take on trust otherwise.
			if p.MaxCitesPerBlock <= 0 {
				t.Fatalf("%s: MaxCitesPerBlock is %d, so this enumeration covers no count at "+
					"all", name, p.MaxCitesPerBlock)
			}
			reachable := p.EpochLength * uint64(p.MaxCitesPerBlock)
			if reachable*10000 <= gate {
				t.Fatalf("%s: an epoch can cite at most %d competitors and the gate sits at "+
					"%d, so no attainable count is anywhere near the boundary and this "+
					"enumeration would sweep only one side of it", name, reachable, gate/10000)
			}
			var crossed bool
			for cited := uint64(0); cited <= reachable; cited++ {
				citedRate, over := u256.FromUint64(cited).Mul(u256.FromUint64(10000))
				if over {
					t.Fatalf("%s: citedRate overflows at cited == %d", name, cited)
				}
				lessOrEqual := !citedRate.Gt(gateRate)
				less := citedRate.Lt(gateRate)
				if lessOrEqual != less {
					t.Fatalf("%s: at cited == %d the gate answers healthy=%v as `≤` and %v as "+
						"`<`; the boundary is reachable after all and the ≤/< choice is "+
						"observable", name, cited, lessOrEqual, less)
				}
				if !lessOrEqual {
					crossed = true
				}
			}
			// Both sides of the gate must appear in the sweep, or the equivalence
			// above was demonstrated over a range that never approached it.
			if !crossed {
				t.Fatalf("%s: no attainable cited count is above the gate, so the sweep never "+
					"reached the boundary it claims to have stepped across", name)
			}
		})
	}
}
