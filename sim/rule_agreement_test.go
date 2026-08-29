package sim_test

import (
	"encoding/hex"
	"errors"
	"math/big"
	"strings"
	"testing"

	"zycord/core/fold"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/sim/refold"
	"zycord/spec"
)

// TestBothFoldsAgreeOnTheRuleTheCorpusRecords replays every invalid golden
// vector through the naive fold and requires it to name the same rule the
// corpus records.
//
// `expect.rule` is a conformance requirement — an invalid vector must pin not
// just the verdict but which rule rejected — and the obvious objection to it is
// that a rule id might be a property of one implementation's control flow
// rather than of the protocol — that `core/fold` reports B12 because of the
// order its own function happens to check things in, and a second
// implementation would answer differently and be equally right. This is the
// check that answers it with a second implementation rather than with an
// argument. `sim/refold` shares no code with `core/fold`, was written for
// obviousness rather than speed, and — the part that gives this test its teeth
// — **checks the rules in a different order**: `core/fold` runs `checkCites`
// before `checkSeedEpoch` (core/fold/blockrules.go), `refold` runs the seed
// epoch first (sim/refold/refold.go). Two orders, one answer, on all
// twenty-three blocks.
//
// What it measures and what it does not. Agreement here is evidence that each
// vector's block breaks one rule rather than two — but only for pairs the two
// folds order differently, which is exactly the C0–C5 / B0b pair
// TestOverDeterminationIsVisibleToThisCheck below arms. It is not a proof of
// single-rule-ness over every possible pair: a pair both folds order the same
// way is invisible here, B3 before B8 being the live example. The corpus-wide
// statement of that property is TestEveryInvalidVectorsRuleIsNecessary in
// rule_necessity_test.go, which deletes each vector's own rule and requires
// the block to become valid — an order-independent check, and so the one that
// covers the pairs this one cannot.
//
// It is deliberately NOT part of `Differential`, which folds blocks the traffic
// generator and the adversarial probes build. Those blocks routinely break two
// rules at once — a forged `PoW.SeedEpoch` on a block that also carries a bad
// citation — and on such a block the two orders answer differently and both are
// correct. Comparing ids there would put benign divergences into the release
// gate for `core/fold`, which is CONTRIBUTING's "a check that can fire for a
// benign reason is not a check". The corpus is the set where the comparison is
// meaningful, because a vector may break only one rule.
func TestBothFoldsAgreeOnTheRuleTheCorpusRecords(t *testing.T) {
	invalid := loadInvalidVectors(t)
	if len(invalid) == 0 {
		t.Fatal("no invalid vectors loaded; this test would assert nothing")
	}
	for _, v := range invalid {
		t.Run(v.Name, func(t *testing.T) {
			p, err := spec.ParamsFor(v.Params)
			if err != nil {
				t.Fatal(err)
			}
			b, err := v.DecodeBlock(p)
			if err != nil {
				t.Fatalf("the block does not decode: %v", err)
			}
			_, naiveErr := refold.ApplyBlock(naiveState(t, v.Pre), b, p)
			if naiveErr == nil {
				t.Fatalf("the naive fold accepted a block the corpus says breaks %s", v.Expect.Rule)
			}
			if !errors.Is(naiveErr, refold.ErrInvalidBlock) {
				t.Fatalf("got %v, want an invalid-block error", naiveErr)
			}
			if got := refold.Rule(naiveErr); got != v.Expect.Rule {
				t.Fatalf("the naive fold rejects this block by %q, the corpus records %q (%v)",
					got, v.Expect.Rule, naiveErr)
			}
		})
	}
}

// TestOverDeterminationIsVisibleToThisCheck arms the test above.
//
// A cross-check that agrees on every input it is given has said nothing until
// it is shown refusing one. This builds the input it must refuse: a committed
// citation vector's block with its `PoW.SeedEpoch` also forged, so the block
// breaks two rules at once. `core/fold` reports the citation rule because it
// checks citations first; `refold` reports B0b because it checks the seed epoch
// first. Both are right, and a vector shaped like this could not carry an
// `expect.rule` at all — which is the corpus property the conformance
// requirement rests on, and this test turns into an observation.
func TestOverDeterminationIsVisibleToThisCheck(t *testing.T) {
	var seed *spec.Vector
	for _, v := range loadInvalidVectors(t) {
		if strings.HasPrefix(v.Expect.Rule, "C") {
			seed = v
			break
		}
	}
	if seed == nil {
		t.Fatal("no citation vector in the corpus to build a two-rule block from; " +
			"this test cannot arm the cross-check and is asserting nothing")
	}
	p, err := spec.ParamsFor(seed.Params)
	if err != nil {
		t.Fatal(err)
	}
	b, err := seed.DecodeBlock(p)
	if err != nil {
		t.Fatal(err)
	}
	// The second broken rule. types.Block carries its Header by value, so the
	// committed vector is untouched; only this copy declares the wrong epoch.
	two := *b
	two.Header.PoW.SeedEpoch += 7

	_, fastErr := fold.ApplyBlock(fastState(t, seed.Pre), &two, p)
	_, naiveErr := refold.ApplyBlock(naiveState(t, seed.Pre), &two, p)
	fastRule, naiveRule := fold.Rule(fastErr), refold.Rule(naiveErr)

	if fastRule != seed.Expect.Rule {
		t.Fatalf("core/fold reports %q on the two-rule block, want the citation rule %q — "+
			"the block this test builds is not the block it means to build",
			fastRule, seed.Expect.Rule)
	}
	if naiveRule != "B0b" {
		t.Fatalf("the naive fold reports %q on the two-rule block, want B0b — "+
			"the two folds no longer order citations and the seed epoch differently, "+
			"so this test can no longer arm the cross-check above", naiveRule)
	}
	if fastRule == naiveRule {
		t.Fatal("both folds agree on a block that breaks two rules; the cross-check " +
			"above cannot observe over-determination and is worth nothing")
	}
	t.Logf("armed: two-rule block reported as %s by core/fold and %s by sim/refold",
		fastRule, naiveRule)
}

func loadInvalidVectors(t *testing.T) []*spec.Vector {
	t.Helper()
	vectors, err := spec.LoadVectors("../spec/vectors")
	if err != nil {
		t.Fatal(err)
	}
	var out []*spec.Vector
	for _, v := range vectors {
		if !v.Expect.Valid {
			out = append(out, v)
		}
	}
	return out
}

func fastState(t *testing.T, pre spec.PreState) *state.State {
	t.Helper()
	s, err := pre.BuildState()
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// naiveState materialises a vector's pre-state into the naive fold's own
// storage. spec.PreState.BuildState builds a core/state; this is the same
// description read into the other implementation, which is what makes the
// comparison a comparison rather than two readings of one object.
func naiveState(t *testing.T, pre spec.PreState) *refold.State {
	t.Helper()
	s := refold.New()
	for _, c := range pre.Cells {
		s.Set(types.Slot{Addr: mustAddr(t, c.Addr), Word: mustHash(t, c.Word)}, mustDec(t, c.Value))
	}
	for _, a := range pre.Spent {
		s.MarkSpent(mustAddr(t, a))
	}
	for _, e := range pre.Seen {
		s.MarkSeen(mustHash(t, e.ID), e.TTL)
	}
	return s
}

func mustHash(t *testing.T, s string) types.Hash {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad 32-byte hex %q: %v", s, err)
	}
	var h types.Hash
	copy(h[:], raw)
	return h
}

func mustAddr(t *testing.T, s string) types.Address { return types.Address(mustHash(t, s)) }

func mustDec(t *testing.T, s string) *big.Int {
	t.Helper()
	v, ok := new(big.Int).SetString(s, 10)
	if !ok {
		t.Fatalf("bad decimal %q", s)
	}
	return v
}

// TestBothFoldsGiveTheSameHorizonAtAWrappingTTLMax lived here and was removed
// when the signing message was rebound onto the consensus root, along with
// loadValidVectorsWithCerts, its only caller.
//
// It took each valid golden vector's block and re-folded it under a copy of the
// vector's parameter set with ttl_max = 2^64-1, requiring both folds to accept.
// That rests on a portability that rebinding deliberately removed — it is what
// stops a certificate being lifted onto a chain that reused its chain_id: the
// signing message now binds the consensus root, ttl_max is a consensus
// parameter, so a corpus block folded under a perturbed set fails V2 on its
// first certificate and never reaches B2. Every row became a row about V2 --
// the exact "second baseline row" its own header warned against.
//
// The property is not lost and this is not a coverage reduction claimed away.
// TestTheDifferentialReachesB2sTTLHorizonFromBothSides's
// wrapping_ttl_max_2_to_the_64_minus_1 arm holds it, and holds it better: it
// drives a full differential run *at* ttl_max = 2^64-1, so its certificates are
// signed under the parameter set they are folded under, both folds see every
// block, and Runner.Step is what reports a divergence. What the deleted test
// added over it was the variety of block shapes the corpus carries, and that
// variety was not available at a perturbed parameter set for as long as the
// only route to a block was to lift one -- by construction, not by omission.
//
// THAT IS NO LONGER THE STATE OF THE TREE. sim.Perturbation BUILDS a catalogue
// of thirteen block shapes under whatever parameter set it is handed, holding
// every key and signing as it goes, and perturbation_test.go's
// TestBothFoldsAgreeOnEveryBlockShapeAtEveryPerturbedTTLMax drives it at
// ttl_max 2 and 2^64-1 on a devnet AND a mainnet base. The variety is back;
// what stays gone is the *corpus's* variety, which no builder reproduces and
// which the corpus itself is the instrument for.
//
// THE RULE FOR THE NEXT AUTHOR, since this is where they will look: a frozen
// corpus block must never be folded under a perturbed parameter set. Now that
// the signing message binds the consensus root, that is not a shortcut with a
// caveat, it is a test that measures V2 while naming another rule. Build the
// block under the set, or re-sign it with a key you hold -- sim.Perturbation is
// the first and core/fold's resignUnder the second.
//
// core/fold's TestTTLHorizonIsACeilingAtEveryAcceptedTTLMax covers the same
// horizon on one implementation, and it survives because it holds the signing
// key and re-signs its witness for each row.
