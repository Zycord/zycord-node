package refold

// Rule deletion, for the necessity sweep that holds the golden corpus's
// single-rule property.
//
// An invalid vector records the rule that rejects its block, and
// docs/ARCHITECTURE.md §8 makes that id a conformance requirement on the
// strength of a stronger claim: the block breaks exactly *one* rule, so the id
// is an answer every conformant implementation must give rather than an
// artefact of one fold's evaluation order. Agreement between two folds cannot
// establish that on its own — it is blind to any pair of rules the two folds
// happen to order the same way, which is precisely where the B3/B8 pair sits.
// The claim needs each recorded rule shown to be *necessary*: delete it, and
// the block must become valid.
//
// That sweep used to be a hand ritual — edit core/fold, run a subtest, revert —
// recorded in prose and trusted. Which is the defect this switch exists to
// abolish, one level up: a conformance property nothing mechanical checks — an
// invalid vector pinned the verdict but not which rule rejected, and the corpus
// was one certificate away from a vector broken by two rules at once. The
// switch below is what turns it into sim's
// TestEveryInvalidVectorsRuleIsNecessary.
//
// It lives HERE, and deliberately not in core/fold. core/ is the consensus
// fold: a rule-disabling switch inside it would be a way to build a node that
// silently does not enforce a rule, which is a far worse thing to own than the
// property it would be proving. sim/refold is the naive reference
// implementation — it is never linked into a node, it exists to be driven by
// tests, and it already funnels every rejection through the one invalid()
// below, so the deletion is exact rather than approximated.
var skipped map[string]bool

// WithoutRule deletes one rule from this fold until the returned function is
// called. The caller must defer that call; the sweep is sequential for this
// reason and must not be run in parallel with any other use of this package.
func WithoutRule(rule string) (restore func()) {
	previous := skipped
	skipped = map[string]bool{rule: true}
	return func() { skipped = previous }
}
