package p2p

import "testing"

// TestTheZeroCostClassIsUnpricedAndNotFree pins the one property the whole of
// cost discipline rests on and that nothing else in the repository checks: the zero
// value of CostClass is CostUnpriced, and CostUnpriced is not CostFree.
//
// Every other guard is syntactic. TestEveryVerdictIsPriced (sim/wiring) reads
// node/p2p's syntax tree and reports a Verdict literal with no Cost key, or a
// Verdict built as `var v Verdict` and returned; wire.md §10.2 states in prose
// that the zero value "is never a valid answer". None of that survives the
// const block being reordered. Move CostFree to the head of the iota — or
// delete CostUnpriced as redundant with a self-documenting zero — and every
// unset Cost silently becomes a deliberate `Free`, which is precisely the
// unnamed free the fifteen findings were instances of. The syntactic checks
// stay green through that edit, because a missing key is still a missing key
// whatever it defaults to, and the behavioural tests stay green too, because
// no handler names the constant.
//
// So the constant needs one assertion that is about its *value* rather than
// about its spelling, and this is it. It is also the honest call site for a
// zero-value enum member: what CostUnpriced does is be the default, and the
// only thing that can exercise being the default is a check that the default
// is it.
func TestTheZeroCostClassIsUnpricedAndNotFree(t *testing.T) {
	if got := (Verdict{}).Cost; got != CostUnpriced {
		t.Errorf("the zero Verdict's Cost is %v, want unpriced: a Verdict "+
			"nobody filled in must not read as a decision (wire.md §10.2)", got)
	}
	var zero CostClass
	if zero != CostUnpriced {
		t.Errorf("the zero CostClass is %v, want CostUnpriced", zero)
	}
	for _, c := range []struct {
		name string
		val  CostClass
	}{
		{"CostFree", CostFree},
		{"CostScored", CostScored},
		{"CostDeduped", CostDeduped},
		{"CostBudgeted", CostBudgeted},
	} {
		if c.val == CostUnpriced {
			t.Errorf("%s equals CostUnpriced, so a Verdict nobody priced is "+
				"indistinguishable from one priced %s", c.name, c.name)
		}
	}
	if got := CostUnpriced.String(); got != "unpriced" {
		t.Errorf("CostUnpriced.String() = %q, want %q", got, "unpriced")
	}
	// And the arm that is not CostUnpriced: a byte that is no class at all
	// must not print as one, least of all as the class that means "nobody
	// said". 200 is not any of the five and cannot become one by accident.
	if got := CostClass(200).String(); got == "unpriced" {
		t.Error("a CostClass that is not one of the five prints as " +
			"\"unpriced\", so a log line cannot separate a Verdict nobody " +
			"filled in from a value that was never a class")
	}
}
