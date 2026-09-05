package sim_test

import (
	"testing"

	"zycord/core/params"
	"zycord/sim"
	"zycord/spec"
)

// maxTTL is the largest value the TTL field can hold. params.Validate accepts
// it as ttl_max: an upper bound in Validate was considered and declined
// deliberately, because the wrap depends on chain height, which validation
// never observes, so a ceiling only chooses which height inverts.
const maxTTL = ^uint64(0)

// TestTheDifferentialReachesB2sTTLHorizonFromBothSides is the anti-vacuity gate
// for a specific blindness: the differential runner never drove a certificate
// anywhere near B2's TTL horizon, so a divergence between the two folds there
// was invisible to the instrument built to catch exactly that.
//
// THE PROPERTY, IN ONE SENTENCE: over a differential run, both folds are handed
// a certificate at the last TTL B2 accepts and at the first TTL B2 refuses, and
// they agree on both.
//
// THE HORIZON, DERIVED RATHER THAN PICKED. For a block at height h:
//
//   - B1 refuses c.TTL < h, so every certificate reaching B2 has a well-defined
//     distance d = c.TTL - h in [0, 2^64-1 - h]. B1 is what bounds d from above,
//     not the width of the field.
//   - B2 accepts exactly d <= ttl_max.
//
// So the separating pair is d = ttl_max against d = ttl_max + 1, and it lies in
// the reachable range exactly when ttl_max < 2^64-1 - h. Those two TTLs differ
// by one on a certificate that is otherwise byte-for-byte the same, which is
// what makes the verdicts attributable to B2 and to nothing else.
//
// WHAT THE RUNNER COULD NOT REACH -- AND AT WHICH SCOPE. Runner.ttl() clamps
// its span to min(ttl_max, 8) and adds 1, so a DRAWN certificate sits d in [1,
// min(ttl_max, 8)] blocks ahead of its block. That caps at ttl_max and no route
// increases d, so the REJECT side d = ttl_max + 1 is unreachable at every
// parameter set -- by construction, not by luck of the seeds. Measured over
// every certificate in every block handed to Differential across the three arms
// below and two seeds: d > ttl_max zero times, max d exactly min(ttl_max, 8).
// Against ttl_max of 240 (mainnet) or 32 (devnet) that side is not approached
// at all. A fold divergence at exactly that horizon shipped once and was found
// by a human reading the tree rather than by a run: the machinery built to
// catch it was structurally incapable of seeing it at every shipped parameter
// set.
//
// d = 0 IS reachable, and the +1 does not prevent it. The +1 bounds the
// distance the generator DRAWS; B2 sees the distance at the height a
// certificate is finally PRESENTED, and genReplay re-presents an
// already-committed certificate at a later height, shifting d down by its age.
// At the same all-blocks scope: d = 0 five times and d < 0 (refused by B1) 78
// times, every one of the 83 a replay. The census that first certified the
// universal counted certificates in COMMITTED blocks, where both figures are
// zero and can be nothing else -- a replay is what makes a block un-committable
// (B3), so that scope structurally excludes the only route to d <= 0. The
// figure was right; the population it quantified over was not stated, and an
// instrument that can only return "pass" is not a check.
//
// The accept side is the one exception, and it is in this very function: the
// ttl_max = 2 arm below gives a span of 2, so the generator reaches
// d = ttl_max on its own -- 241 times across that arm's two seeds. There the
// honest corpus corroborates the probe's accept arm by an independent route.
//
// An earlier version of this header said the clamp was 8 and that the generator
// "has ever" built only at 1..8. That was true of a runner driven only at 32
// and 240, and small.TTLMax = 2 twenty lines below falsified it -- the
// counterexample was in the same screenful as the claim, and it survived three
// passes because a test header reads as machinery that verifies rather than as
// prose that claims. A test comment is an assertion too, and nothing checks it.
//
// WHY THIS DRIVES NON-SHIPPED PARAMETER SETS. The blindness has two independent
// causes and the clamp is only the second. The first is that the runner never
// varies ttl_max at all, so B2's arithmetic is only ever exercised at 32 and
// 240. The three arms below are chosen as the three qualitatively different
// regimes of the derivation above, not as three numbers near a boundary:
//
//   - devnet's shipped 32: the horizon a real network has;
//   - 2, the smallest value params.Validate accepts, where the horizon is so
//     close that the accepted and refused sides are one block apart;
//   - 2^64-1, where 2^64-1 - h is *below* ttl_max for every h > 0, so no
//     reachable distance exceeds the bound and B2 cannot fire. The arm that
//     matters there is the opposite one: the largest expressible TTL must be
//     ACCEPTED. Under the earlier sum form h+ttl_max wrapped below h and every
//     certificate B1 admitted was refused here, which is the divergence this
//     gate was split out of.
//
// THE WRAPPING ARM IS THE STRONGEST DIFFERENTIAL HOME OF THAT LAST PROPERTY,
// and it is worth knowing why rather than rediscovering it.
// sim/rule_agreement_test carried a second instrument for it -- every valid
// golden vector re-folded under ttl_max = 2^64-1 -- and rebinding the signing
// message removed it: that message now binds the consensus root, so a
// certificate cannot be lifted onto a chain that reused its chain_id. ttl_max
// is a consensus parameter, so a corpus block folded under a perturbed
// parameter set fails V2 before B2 is consulted. This arm survives because its
// certificates are BUILT under the parameter set they are folded under, which
// is the shape any parameter-perturbation test has to take from now on.
//
// It was the ONLY home for a while, and that was not good enough: what the
// removed test added was block-shape variety, and a differential over one shape
// proves the two folds agree on one shape. The second home now is
// sim/perturbation.go's catalogue, driven by
// TestBothFoldsAgreeOnEveryBlockShapeAtEveryPerturbedTTLMax over thirteen
// shapes at ttl_max 2 and 2^64-1 on a devnet and a mainnet base. It does not
// replace this arm and does not try to: it holds no horizon probe, so it drives
// no certificate onto d = ttl_max or d = ttl_max + 1. The two are the two axes
// -- this one varies the distance at one shape, that one varies the shape at a
// fixed distance.
func TestTheDifferentialReachesB2sTTLHorizonFromBothSides(t *testing.T) {
	devnet := spec.Devnet()

	small := *devnet
	small.TTLMax = 2

	wrapping := *devnet
	wrapping.TTLMax = maxTTL

	cases := []struct {
		name string
		p    *params.Params
		// wantRejections says whether a reachable distance can exceed
		// ttl_max at all under these parameters. It is derived, not observed:
		// see the arm descriptions above.
		wantRejections bool
	}{
		{"shipped_devnet_ttl_max_32", devnet, true},
		{"minimum_legal_ttl_max_2", &small, true},
		{"wrapping_ttl_max_2_to_the_64_minus_1", &wrapping, false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			// params.Validate is asserted rather than assumed: an arm built on
			// a parameter set no network could ever run would be measuring a
			// configuration the consensus rules never have to handle.
			if err := tc.p.Validate(); err != nil {
				t.Fatalf("%s is not a legal parameter set: %v", tc.name, err)
			}

			var accepted, rejected, zero, declined int
			var atMax, pastMax int
			for seed := int64(1); seed <= 2; seed++ {
				r, err := sim.NewRunner(tc.p, seed)
				if err != nil {
					t.Fatalf("seed %d: %v", seed, err)
				}
				for i := 0; i < 80; i++ {
					// Step reports a divergence between the two folds as an
					// error, including one the horizon probe found. There is
					// no separate assertion for "the folds agreed": this loop
					// completing IS that assertion.
					if err := r.Step(); err != nil {
						t.Fatalf("%s seed %d, step %d: %v", tc.name, seed, i, err)
					}
				}
				accepted += r.HorizonAccepted
				rejected += r.HorizonRejected
				zero += r.HorizonZeroDistance
				declined += r.HorizonDeclined
				atMax += r.HorizonAcceptedAtMax
				pastMax += r.HorizonRejectedPastMax
				t.Logf("%s seed %d: height=%d horizon accepted=%d rejected=%d zero-distance=%d declined=%d at-max=%d past-max=%d",
					tc.name, seed, r.Chain.Height(),
					r.HorizonAccepted, r.HorizonRejected, r.HorizonZeroDistance,
					r.HorizonDeclined, r.HorizonAcceptedAtMax, r.HorizonRejectedPastMax)
			}

			// The non-vacuity assertions. Each names a distance the run must actually
			// have driven; a run that drove none of them would pass every other check in
			// this package while measuring nothing, which is the exact state this gate
			// exists to refuse.
			//
			// The first three do NOT cover the two distances this test is named for, and
			// the comment above said they did. HorizonAccepted is incremented by the d =
			// 0 and d = 2^64-1 arms as well as by d = ttl_max, and HorizonRejected by
			// the 2^64-1 arm as well as by d = ttl_max + 1, so all three guards are
			// satisfied by the NON-boundary arms alone: deleting either boundary arm
			// from probeTTLHorizon, or both, left this test green with all three
			// subtests PASSing -- three separate mutants of the probe, none of them
			// killed -- and that measurement is bound to the tree WITHOUT these guards,
			// not to this one. In that tree a shared off-by-one in BOTH folds also
			// survived once both boundary arms were deleted, so the deletion lost a
			// unique kill and nothing reported it. Here all of those die.
			//
			// The two guards below are separated rather than merely added, and
			// what shows it at THIS head is that deleting the accept arm alone
			// and deleting the reject arm alone fail at different guards with
			// different messages, while deleting both fires both -- they are
			// t.Errorf and not t.Fatalf, so neither masks the other.
			if accepted == 0 {
				t.Errorf("%s: no certificate was ever accepted at the horizon; "+
					"the probe never ran, so this test asserts nothing", tc.name)
			}
			if zero == 0 {
				t.Errorf("%s: no certificate at distance 0 was ever driven. Under the "+
					"earlier wrapping sum h+ttl_max this arm is the first to fail at "+
					"ttl_max = 2^64-1, where the bound computes to h-1 and every "+
					"certificate B1 admits is refused -- a defect present in BOTH "+
					"folds, which is exactly what a differential cannot otherwise "+
					"see. It is also COVERAGE of the extra "+
					"c.TTL > h.Height conjunct sim/refold carries and core/fold does "+
					"not, though it cannot SEPARATE that conjunct at any parameter "+
					"set; see probeTTLHorizon and "+
					"TestEveryInvalidVectorsRuleIsNecessary. What it is NOT is the "+
					"only route to distance 0: genReplay reaches it in the honest "+
					"corpus", tc.name)
			}
			if tc.wantRejections && rejected == 0 {
				t.Errorf("%s: nothing was ever refused past the horizon, so this run "+
					"cannot tell B2 from a deleted B2", tc.name)
			}
			// The separating pair itself, which is the property this test is
			// named for. wantRejections is exactly the condition under which the
			// pair is constructible -- ttl_max < 2^64-1 - h -- so it governs
			// both guards and no second table field is needed. Where it is false
			// the assertion INVERTS rather than lapsing: at ttl_max = 2^64-1,
			// h + ttl_max is representable only at h = 0, and the probe only
			// ever sees PROPOSED blocks, whose height is at least 1. So neither
			// boundary arm is constructible there, and a count that became
			// non-zero would mean the derivation the arms are built from had
			// stopped holding.
			if tc.wantRejections {
				if atMax == 0 {
					t.Errorf("%s: no certificate was ever driven at d = ttl_max, the last "+
						"distance B2 accepts -- so the accept half of the separating pair "+
						"this test is named for was never handed to either fold", tc.name)
				}
				if pastMax == 0 {
					t.Errorf("%s: no certificate was ever driven at d = ttl_max + 1, the "+
						"first distance B2 refuses -- so the reject half of the separating "+
						"pair this test is named for was never handed to either fold, and "+
						"nothing here tells B2 from a B2 that is one off", tc.name)
				}
			} else if atMax != 0 || pastMax != 0 {
				t.Errorf("%s: the boundary pair was driven (at-max=%d past-max=%d) at a "+
					"ttl_max no reachable distance can exceed; h + ttl_max is "+
					"representable only at h = 0 and the probe only sees proposed "+
					"blocks, so this means the derivation the arms are built from no "+
					"longer holds", tc.name, atMax, pastMax)
			}
			// The probe declines any block the control fold refused, so its
			// censuses are conditioned on that fold accepting. If it never
			// accepted, every count above would be zero for a reason that has
			// nothing to do with B2 -- and the guards would read as though the
			// horizon had been driven and found consistent. `accepted == 0`
			// catches it; this reports the denominator so a reader can see how
			// much of the run the probe was actually able to reason about.
			t.Logf("%s: %d probe blocks declined because the control fold refused "+
				"the honest block", tc.name, declined)

			// The mirror, and it is not decoration. If B2 ever fires under a ttl_max of
			// 2^64-1 then something re-introduced a bound that wraps, which is precisely
			// the defect rewriting the bound as a distance from the tip fixed. A test
			// that only ever demanded MORE rejections could not see that.
			if !tc.wantRejections && rejected != 0 {
				t.Errorf("%s: %d certificates were refused past a horizon no reachable "+
					"distance can exceed; a bound that fires here is a bound that "+
					"wrapped", tc.name, rejected)
			}
		})
	}
}
