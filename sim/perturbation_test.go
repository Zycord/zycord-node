package sim_test

import (
	"testing"

	"zycord/core/params"
	"zycord/sim"
	"zycord/spec"
)

// TestBothFoldsAgreeOnEveryBlockShapeAtEveryPerturbedTTLMax is the differential
// this tree lost when the signing message was bound to the consensus root,
// rebuilt so that it can exist.
//
// THE PROPERTY, IN ONE SENTENCE: the two folds agree on a catalogue of thirteen
// distinct block shapes, at a perturbed ttl_max, on two base parameter sets.
//
// WHY IT IS BUILT AND NOT LIFTED. The predecessor took every valid golden
// vector's block and re-folded it under a copy of its parameter set with
// ttl_max = 2^64-1. The signing message now binds the consensus root — that is
// what stops a certificate being lifted off a chain that reused its chain_id —
// and ttl_max is a consensus parameter, so a corpus block folded under a
// perturbed set fails V2 on its first certificate: every row became a row about
// the signature rule rather than about the horizon, and the corpus does not
// carry the keys that would let it be re-signed. The test was removed and the
// loss was named: block-shape variety.
//
// sim.Perturbation is the capability that gives it back. It BUILDS its blocks
// under the parameter set it is handed, holding every key, so V2 is satisfied by
// construction and the block shapes are the catalogue's rather than the
// generator's luck. That is the shape any parameter-perturbation test has to
// take from now on, and lifting a frozen corpus block into a perturbed set is
// now a mistake rather than a shortcut.
//
// WHAT EACH ARM ADDS OVER Runner. The differential runner drives one parameter
// set per run and its own randomised traffic; the wrapping arm of
// TestTheDifferentialReachesB2sTTLHorizonFromBothSides drives ttl_max = 2^64-1
// on devnet and is a stronger instrument for B2's horizon than this is — it is
// not replaced here and should not be. What this adds is the other axis: a
// FIXED population of shapes held constant while the parameters move, and a
// MAINNET base, which no differential in this package has had since the signing
// message started binding the consensus root.
//
// WHAT IT DOES NOT MEASURE. It is not the golden corpus: nothing here pins an
// exact post-state against frozen bytes, and agreement between two folds that
// share the gas schedule, the sort key and every ceiling is bounded exactly as
// sim/refold's package comment states. It also does not cover every shape the
// corpus carries — see sim.Perturbation's header for the two it deliberately
// leaves to Runner and to spec/.
func TestBothFoldsAgreeOnEveryBlockShapeAtEveryPerturbedTTLMax(t *testing.T) {
	const maxTTLMax = ^uint64(0)

	for _, base := range []struct {
		name string
		p    *params.Params
	}{
		// Devnet is the set every other differential in this package runs at.
		// Mainnet is the base the removed test had and nothing replaced: the
		// two differ in ttl_max, epoch length, coinbase maturity and every
		// ceiling, so a fold that read a parameter it should not would have to
		// read the same wrong one twice to stay hidden.
		{"devnet", spec.Devnet()},
		{"mainnet", spec.Mainnet()},
	} {
		for _, pert := range []struct {
			name   string
			ttlMax uint64
		}{
			// The set's own value, so a failure below can be read against a
			// baseline that is not perturbed at all.
			{"shipped", 0},
			// The smallest value params.Validate accepts, where a certificate
			// may reach at most two blocks ahead of the one carrying it.
			{"minimum_legal_ttl_max_2", 2},
			// The widest, and the one the removed test drove: h + ttl_max wraps at every
			// height above zero, which is the arithmetic B2's horizon got wrong in a
			// form BOTH folds shared: the sum h + ttl_max wrapped below h and inverted
			// the rule from a ceiling into a blanket refusal.
			{"wrapping_ttl_max_2_to_the_64_minus_1", maxTTLMax},
		} {
			t.Run(base.name+"/"+pert.name, func(t *testing.T) {
				p := *base.p
				if pert.ttlMax != 0 {
					p.TTLMax = pert.ttlMax
				}
				// Asserted rather than assumed: an arm built on a parameter set
				// no network could run would be measuring a configuration the
				// consensus rules never have to handle.
				if err := p.Validate(); err != nil {
					t.Fatalf("this arm's parameter set is not legal, so it says "+
						"nothing about either fold: %v", err)
				}

				x, err := sim.NewPerturbation(&p)
				if err != nil {
					t.Fatalf("the harness could not reach its funded state: %v", err)
				}
				if err := x.Run(); err != nil {
					t.Fatalf("%v", err)
				}

				// The population this arm quantified over, stated rather than
				// implied. Every catalogue entry must have been driven or must
				// carry a reason it was not, and a shape that vanished from
				// Run() fails here instead of shrinking the claim in silence.
				got := make(map[string]sim.Shape, len(x.Driven))
				for _, s := range x.Driven {
					if _, dup := got[s.Name]; dup {
						t.Fatalf("shape %q was driven twice; the catalogue is not a set", s.Name)
					}
					got[s.Name] = s
				}
				var accepted, rejected, absent int
				for _, name := range sim.PerturbationShapes() {
					s, ok := got[name]
					if !ok {
						t.Fatalf("shape %q is named by PerturbationShapes and was neither "+
							"driven nor recorded absent", name)
					}
					switch {
					case s.Absent:
						if s.Why == "" {
							t.Fatalf("shape %q is absent without a reason; an unstated "+
								"population is what this test exists to prevent", name)
						}
						absent++
						t.Logf("shape %q absent: %s", name, s.Why)
					case s.Accepted:
						accepted++
					default:
						rejected++
					}
				}
				if len(got) != len(sim.PerturbationShapes()) {
					t.Fatalf("the run drove %d shapes and PerturbationShapes names %d; "+
						"one of them is out of date", len(got), len(sim.PerturbationShapes()))
				}

				// The non-vacuity guards. A run that accepted everything would
				// never have handed either fold a block to refuse, and a run
				// that refused everything would have compared two rejections
				// and nothing else.
				if accepted == 0 {
					t.Error("no shape was accepted; the folds agreed only about refusals")
				}
				if rejected == 0 {
					t.Error("no shape was refused; nothing here tells either fold's " +
						"block rules from deleted block rules")
				}
				t.Logf("%s/%s: %d shapes accepted, %d refused, %d absent",
					base.name, pert.name, accepted, rejected, absent)
			})
		}
	}
}

// TestThePerturbationCatalogueIsNotVacuous arms the test above.
//
// A catalogue that reached the folds while every certificate was DROPPED would
// pass every assertion in this file: both folds would agree, some blocks would
// be accepted and some refused, and every named shape would be present. The
// thing that would have been lost is the only thing the shapes are for.
//
// sim.Perturbation checks each shape's outcome census against what the
// catalogue declared, so that run fails rather than passes. This is the
// observation of it: the census over a whole devnet run must show applied,
// skipped and dropped certificates all present, and the two replay shapes must
// be the refused ones. A future edit that funds the catalogue too thinly turns
// APPLIED into DROPPED and fails here as well as inside the harness.
func TestThePerturbationCatalogueIsNotVacuous(t *testing.T) {
	p := *spec.Devnet()
	x, err := sim.NewPerturbation(&p)
	if err != nil {
		t.Fatal(err)
	}
	if err := x.Run(); err != nil {
		t.Fatal(err)
	}

	var applied, skipped, dropped, certs int
	refused := map[string]bool{}
	for _, s := range x.Driven {
		applied += s.Applied
		skipped += s.Skipped
		dropped += s.Dropped
		certs += s.Certs
		if !s.Absent && !s.Accepted {
			refused[s.Name] = true
		}
	}
	if applied == 0 {
		t.Error("no certificate in the whole catalogue APPLIED; every shape is a shape " +
			"about the deposit rule and none is about itself")
	}
	if skipped == 0 {
		t.Error("no certificate was billed a skip, so included gas never exceeded " +
			"applied gas and a fold that confused the two would agree with itself")
	}
	if dropped == 0 {
		t.Error("no certificate was DROPPED, so the one non-billable outcome is " +
			"absent from the catalogue")
	}
	if certs < 10 {
		t.Errorf("the catalogue carried %d certificates in total; that is too few for "+
			"a variety claim", certs)
	}
	for _, name := range []string{"replay-same-bytes", "replay-different-signature"} {
		if !refused[name] {
			t.Errorf("shape %q was not refused; the catalogue's rejection arm is not "+
				"the arm it names", name)
		}
	}
	if len(refused) != 2 {
		t.Errorf("shapes refused: %v — the catalogue declares exactly the two replays "+
			"as refusals, so anything else here is a shape that stopped being itself",
			refused)
	}
	t.Logf("devnet catalogue: %d certificates, %d applied, %d skipped, %d dropped",
		certs, applied, skipped, dropped)
}
