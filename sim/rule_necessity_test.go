package sim_test

import (
	"testing"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/sim/refold"
	"zycord/spec"
)

// TestEveryInvalidVectorsRuleIsNecessary deletes each invalid vector's own
// recorded rule from the naive fold and requires the block to become valid.
//
// This is the corpus-wide statement of the property docs/ARCHITECTURE.md §8 and
// spec/README.md assert as normative — an invalid vector's block breaks exactly
// one rule — and until now it was held by a sweep run by hand and recorded in
// prose. A conformance requirement checked by a ritual is itself the defect —
// the same one this sweep exists to catch, one level up — so it is a test.
//
// Why necessity and not agreement. TestBothFoldsAgreeOnTheRuleTheCorpusRecords
// beside this file compares two folds that check the rules in different orders,
// which catches over-determination for any pair of rules they order
// *differently*. It is structurally blind to a pair they order the same way,
// and both folds check B8 before B3: a block that is both an in-block duplicate
// and a replay would be reported B3-or-B8 identically by both, agree perfectly,
// and be recorded under whichever id the folds happened to reach. The corpus's
// two newest vectors are exactly that family (052, 053). Necessity does not
// care about order: if a second rule was carrying the block, deleting the first
// leaves it rejected, whichever order they were checked in.
// TestNecessityCatchesTheOverDeterminedBlockAgreementMisses below builds that
// block and requires this check to refuse it.
func TestEveryInvalidVectorsRuleIsNecessary(t *testing.T) {
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
			if v.Expect.Rule == "" {
				t.Fatal("an invalid vector with no rule; spec/gen refuses to emit one")
			}
			if err := ruleIsNecessary(naiveState(t, v.Pre), b, p, v.Expect.Rule); err != nil {
				t.Error(err)
			}
		})
	}
}

// ruleIsNecessary reports why the named rule is not the only thing rejecting
// this block, or nil if deleting it makes the block valid.
func ruleIsNecessary(s *refold.State, b *types.Block, p *params.Params, rule string) error {
	restore := refold.WithoutRule(rule)
	defer restore()

	_, err := refold.ApplyBlock(s, b, p)
	if err == nil {
		return nil
	}
	return &notNecessaryError{rule: rule, second: refold.Rule(err), err: err}
}

type notNecessaryError struct {
	rule   string
	second string
	err    error
}

func (e *notNecessaryError) Error() string {
	second := e.second
	if second == "" {
		second = "an unnamed assertion"
	}
	return "with " + e.rule + " deleted this block is still rejected, by " + second +
		" — so the vector does not pin " + e.rule + ", it pins whichever of the two " +
		"a fold reaches first, and two conformant implementations may disagree " +
		"about which (" + e.err.Error() + ")"
}

// TestNecessityCatchesTheOverDeterminedBlockAgreementMisses arms the sweep
// above.
//
// A gate that passes on every input it has been given has said nothing until it
// is shown refusing one. This builds the input it must refuse, and it is not a
// hypothetical: take 052-invalid-resigned-duplicate-in-block, whose block
// carries one authorization twice, and add that authorization's id to the seen
// set. The block now breaks B8 *and* B3. Both folds check B8 after the
// certificate loop reaches B3 for the first certificate, so both answer B3,
// TestBothFoldsAgreeOnTheRuleTheCorpusRecords is green, and `rejectedBy` is
// green too because its author writes down what the fold told them. One line in
// one JSON file, in exactly the rule family the two newest vectors live in, and
// every automated check in the tree stays green. Necessity is the one that
// notices.
func TestNecessityCatchesTheOverDeterminedBlockAgreementMisses(t *testing.T) {
	var dup *spec.Vector
	for _, v := range loadInvalidVectors(t) {
		if v.Name == "invalid-resigned-duplicate-in-block" {
			dup = v
			break
		}
	}
	if dup == nil {
		t.Fatal("the in-block duplicate vector is gone from the corpus; this test " +
			"cannot arm the sweep and is asserting nothing")
	}
	p, err := spec.ParamsFor(dup.Params)
	if err != nil {
		t.Fatal(err)
	}
	b, err := dup.DecodeBlock(p)
	if err != nil {
		t.Fatal(err)
	}
	if dup.Expect.Rule != "B8" {
		t.Fatalf("this vector now pins %q, not B8; the block this test means to "+
			"build is not the block it would build", dup.Expect.Rule)
	}

	// The second broken rule: the authorization has already been committed.
	// Only this copy of the pre-state carries it; the committed vector is
	// untouched.
	s := naiveState(t, dup.Pre)
	s.MarkSeen(b.Certs[0].ID(), b.Certs[0].TTL)

	// Precondition: the block really does break both rules now. Deleting B3
	// must leave B8 rejecting it, and deleting B8 must leave B3 rejecting it.
	if err := ruleIsNecessary(s, b, p, "B3"); err == nil {
		t.Fatal("with B3 deleted this block is valid, so it does not break B8 as well; " +
			"this test is not building an over-determined block")
	}
	overDetermined := ruleIsNecessary(s, b, p, "B8")
	if overDetermined == nil {
		t.Fatal("with B8 deleted this block is valid, so the seen entry did not take " +
			"effect and this test cannot arm the sweep")
	}

	// And this is the point: the sweep refuses it. Were this block committed as
	// a vector recording either id, TestEveryInvalidVectorsRuleIsNecessary
	// would fail on it — which is what the agreement check and the rejectedBy
	// table both miss, because both folds order B3 before B8 and agree.
	t.Logf("armed: %v", overDetermined)
}
