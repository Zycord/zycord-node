package spec_test

import (
	"testing"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
)

// A difficulty vector that passes under both the rule it names and that
// rule's negation is measuring the scenario, not the rule — CONTRIBUTING's
// standard, and the reason the two vectors it caught while this corpus was
// being written (`genesis-only-window`, which coincided with the fallthrough
// answer, and `relative-ceiling-boundary`, whose solve times sat exactly at
// the cap and so could not tell the cap from its absence) were rebuilt rather
// than shipped.
//
// That check was a scratch script the first time. Here it is permanent: a
// second implementation of the rule, sharing no code with core/pow, that can
// be asked to omit exactly one clause at a time. Every vector names the
// clause it exists to pin, and the test fails if omitting that clause still
// produces the vector's committed answer.
//
// The parallel implementation is the point, not an accident: it is also a
// second reading of core/pow.NextTarget. Note precisely what that catches and
// what it does not — the unmutated pass compares this file against the frozen
// JSON, not against core/pow. A rule change in core/pow alone is caught by
// TestGoldenDifficultyVectors; it surfaces here only once the corpus has been
// regenerated against the changed rule, which is exactly when a reviewer wants
// to be told that the two readings have drifted apart.
type diffRule int

const (
	ruleNone               diffRule = iota
	ruleEarlyReturn                 // len(recent) < 2 answers GENESIS_TARGET
	ruleEarlyReturnEdge             // ...and it is < 2, not < 3
	ruleShortWindow                 // the window shrinks to the gaps actually present
	ruleWindowNewest                // the window is the NEWEST DifficultyWindow+1 headers
	ruleWindowTruncation            // ...and it is truncated at all
	ruleLinearWeighting             // solve times are weighted linearly, not equally
	rulePerSampleCap                // each solve time is capped at goal * clamp factor
	ruleWindowAverageBasis          // the ratio applies to the window's AVERAGE target
	ruleRatioDirection              // target moves with average/goal, not goal/average
	rulePerBlockCeiling             // the target may rise by at most the clamp factor
	ruleRelativeFloor               // ...and fall by at most the same
	ruleAbsoluteCeiling             // MAX_TARGET, the absolute bound
	ruleFloorAtOne                  // a target of zero is never returned
	ruleSignedSolveTime             // a backwards solve subtracts (CURRENT behaviour)
)

// uncappedCeiling bounds the solve magnitude on the mutation arms that omit
// the per-sample cap, so that omitting a rule cannot overflow the arithmetic
// instead of changing it. See nextTarget.
const uncappedCeiling = uint64(1) << 40

// ruleName is for failure messages: a bare integer tells a reader nothing.
var ruleName = map[diffRule]string{
	ruleNone:               "none",
	ruleEarlyReturn:        "the len(recent)<2 early return",
	ruleEarlyReturnEdge:    "the early return's threshold being 2 and not 3",
	ruleShortWindow:        "the window shrinking to the gaps present",
	ruleWindowNewest:       "taking the NEWEST headers",
	ruleWindowTruncation:   "truncating the window",
	ruleLinearWeighting:    "linear weighting",
	rulePerSampleCap:       "the per-sample solve cap",
	ruleWindowAverageBasis: "normalising against the window's AVERAGE target",
	ruleRatioDirection:     "the ratio direction",
	rulePerBlockCeiling:    "the per-block rise ceiling",
	ruleRelativeFloor:      "the relative floor",
	ruleAbsoluteCeiling:    "the MAX_TARGET ceiling",
	ruleFloorAtOne:         "the floor at one",
	ruleSignedSolveTime:    "the signed solve time",
}

// nextTarget reimplements pow.NextTarget with one clause omitted (or, for
// ruleSignedSolveTime, one clause *added*). It deliberately does not call
// core/pow: a mutation harness that shared code with its subject could not
// detect a rule going missing from the subject.
//
// rulePerBlockCeiling is the one rule that omits two clauses at once — both
// mechanisms that enforce the per-block rise, the per-sample cap and the
// post-hoc comparison against `upper`. It exists for relative-ceiling-boundary
// alone, whose window is one where either mechanism on its own produces the
// bound (the post-hoc branch is provably unreachable given the cap), so
// omitting one at a time there would measure nothing. That is a statement
// about that window, not about the corpus: rulePerSampleCap below omits the
// cap by itself, and per-block-solve-cap's window does see it go.
func nextTarget(recent []types.Header, p *params.Params, omit diffRule) u256.U256 {
	threshold := 2
	if omit == ruleEarlyReturnEdge {
		threshold = 3 // the ordinary off-by-one, one past the real edge
	}
	if len(recent) < threshold && omit != ruleEarlyReturn {
		return p.GenesisTarget
	}
	if len(recent) < 2 {
		// The fallthrough an implementation that forgot the early return
		// takes: an empty window, whose last (only) header answers.
		return recent[len(recent)-1].Target
	}

	n := int(p.DifficultyWindow)
	if len(recent) < n+1 {
		n = len(recent) - 1
	}
	window := recent[len(recent)-(n+1):]
	switch omit {
	case ruleWindowNewest:
		window = recent[:n+1] // the oldest headers instead of the newest
	case ruleWindowTruncation:
		window = recent // every header handed in, however many that is
	}

	goal := p.TargetBlockSeconds
	maxSolve := goal * p.DifficultyClampFactor
	// Signed throughout, and clamped to zero exactly once, AFTER the loop.
	// Clamping a running sum mid-loop would silently reintroduce the very
	// floor-at-zero that ruleSignedSolveTime exists to remove, and the guard
	// built on it would then pass for the wrong reason.
	var weightedSigned, weights int64
	for i := 1; i < len(window); i++ {
		// The magnitude is taken and capped in uint64, exactly as core/pow
		// does, and only then given a sign. Converting the raw difference to
		// int64 first would wrap on a gap of 2^63 or more — a header a node
		// can legally be handed, since the future-time limit withholds rather
		// than rejects (R1-H2) — and this file would then disagree with
		// core/pow on an input no vector carries, which is precisely the
		// disagreement it exists to detect.
		var magnitude uint64
		negative := false
		switch {
		case window[i].Time > window[i-1].Time:
			magnitude = window[i].Time - window[i-1].Time
		case omit != ruleSignedSolveTime:
			// The shipped rule, and core/pow's behaviour: a
			// backwards step SUBTRACTS instead of vanishing, so the two
			// adjacent intervals a backdate touches cancel. Omitting this
			// rule is the RETIRED floor-at-zero rule — the magnitude stays 0
			// and the backdate's charge is discarded while the donation it
			// makes to the next interval is kept.
			magnitude = window[i-1].Time - window[i].Time
			negative = true
		}
		// The cap bounds the forward side; the other candidate treatment of a
		// backwards step was a symmetric bound, so the mutated arm is clamped
		// both ways. The symmetry is what makes the guard sound: maxSolve >
		// FTL > 0, so the harness sits between the two candidate treatments —
		// an unbounded signed subtraction and a symmetrically bounded one —
		// and "unchanged" here implies unchanged under either of them.
		if omit != rulePerBlockCeiling && omit != rulePerSampleCap {
			if magnitude > maxSolve {
				magnitude = maxSolve
			}
		} else if magnitude > uncappedCeiling {
			// On the two arms that omit the cap there is nothing left to bound
			// the magnitude, and int64(magnitude) would wrap — the same class
			// of bug the magnitude-then-sign rewrite above fixed on the
			// unmutated path. A mutated arm only has to DIFFER from the
			// committed answer, so a wrapped one could "discriminate" for
			// entirely the wrong reason. This ceiling is far above any solve
			// time a chain can carry (2^40 seconds is ~35,000 years) and far
			// below the point where magnitude * weight overflows int64.
			magnitude = uncappedCeiling
		}
		solve := int64(magnitude)
		if negative {
			solve = -solve
		}
		w := int64(i)
		if omit == ruleLinearWeighting {
			w = 1
		}
		weightedSigned += solve * w
		weights += w
	}
	if weights == 0 {
		return window[len(window)-1].Target
	}
	var weighted uint64
	if weightedSigned > 0 {
		weighted = uint64(weightedSigned)
	}

	last := window[len(window)-1].Target
	// The clamp bounds are always taken against the window's LAST target,
	// whichever basis the ratio uses — that is what "per block" means.
	clampRef := last
	if omit != ruleWindowAverageBasis {
		// Current behaviour: canonical Zawy LWMA — the ratio applies to
		// the window's AVERAGE target. Identical to the last target on any
		// window whose targets are all equal, which is why exactly one vector
		// can see it. Summed at full width and divided once here, where
		// core/pow divides per term and carries the remainders: a deliberately
		// independent second reading of the same quantity, and this harness's
		// windows are small enough that the sum cannot overflow.
		var sum u256.U256
		for i := range window {
			sum, _ = sum.Add(window[i].Target)
		}
		last, _ = sum.Div64(uint64(len(window)))
	}
	num, den := weighted, uint64(weights)*goal
	if omit == ruleShortWindow {
		// A denominator sized for the full window, whether or not that many
		// gaps exist.
		full := p.DifficultyWindow
		den = full * (full + 1) / 2 * goal
	}
	if num == 0 {
		num = 1
	}
	next := last.MulDiv64(num, den)
	if omit == ruleRatioDirection {
		next = last.MulDiv64(den, num)
	}

	upper := clampRef.MulDiv64(p.DifficultyClampFactor, 1)
	lower, _ := clampRef.Div64(p.DifficultyClampFactor)
	if omit != rulePerBlockCeiling && next.Gt(upper) {
		next = upper
	}
	if omit != ruleRelativeFloor && next.Lt(lower) {
		next = lower
	}
	if omit != ruleAbsoluteCeiling && next.Gt(p.MaxTarget) {
		next = p.MaxTarget
	}
	if omit != ruleFloorAtOne && next.IsZero() {
		next = u256.One
	}
	return next
}

// pinnedBy names, for every committed difficulty vector, the clause whose
// removal must change that vector's answer. A vector missing from this table
// fails the test: a new vector arrives with its discriminating rule stated, or
// it does not arrive.
var pinnedBy = map[string][]diffRule{
	"genesis-only-window":                   {ruleEarlyReturn},
	"two-header-window":                     {ruleEarlyReturnEdge},
	"short-window-early-chain":              {ruleShortWindow, ruleRatioDirection},
	"window-truncates-to-the-newest":        {ruleWindowNewest, ruleWindowTruncation},
	"retarget-weights-recent-blocks-more":   {ruleLinearWeighting, ruleRatioDirection},
	"retarget-down-away-from-clamps":        {ruleLinearWeighting, ruleRatioDirection},
	"normalises-against-the-window-average": {ruleWindowAverageBasis},
	"per-block-solve-cap":                   {rulePerSampleCap, ruleRatioDirection},
	"relative-floor-fires":                  {ruleRelativeFloor},
	"relative-ceiling-boundary":             {rulePerBlockCeiling},
	"max-target-ceiling-fires":              {ruleAbsoluteCeiling},
	"floor-at-one":                          {ruleFloorAtOne},
	// The three vectors that pin the signed accumulator. Their windows are
	// the only ones in the corpus carrying a genuinely DECREASING timestamp,
	// which is exactly what makes them able to see the sign at all: omitting
	// ruleSignedSolveTime restores the retired floor-at-zero rule and changes
	// their answers.
	//
	// on-time-holds is the corpus's one deliberate BASELINE, and it is listed
	// with an empty rule set on purpose rather than being given a rule it does
	// not really pin.
	//
	// It cannot discriminate anything, and that is structural, not an
	// oversight: its window is 91 headers at exactly the goal over a uniform
	// declared target, so the weighted ratio is exactly 1 — and 1 is a fixed
	// point of every mutation this harness models. Linear weighting and a flat
	// average both give 1; inverting the ratio gives 1; the clamps and
	// ceilings are all far away. No rearrangement of an on-goal window escapes
	// that, because "on goal" is precisely the input on which the controller
	// is specified to do nothing.
	//
	// It earns its place by being the other half of a PAIR. signed-backdate-
	// cancels is this window with exactly one timestamp changed, so the two
	// together are what let a reader attribute that vector's movement to the
	// backdate rather than to the window's shape. TestBaselineVectorsAreAReadableControl
	// below is what keeps that claim true; the empty list here routes it there
	// instead of exempting it from scrutiny.
	"on-time-holds": {},
	// The int64-widening trap. In the harness's vocabulary this two-header
	// window pins the ratio direction and the per-block rise ceiling (its
	// single clamped solve of +480 s is 16x the goal, so the answer sits
	// exactly on the upper bound). The interop bug it exists to catch —
	// widening the raw 2^63 difference to int64 BEFORE clamping, which wraps
	// it to -2^63 and answers -480 instead of +480 — is a different
	// IMPLEMENTATION of the per-sample cap rather than an omission of one of
	// core/pow's branches, so it is not expressible as a rule to omit here.
	// TestTheInt64WideningTrapIsPinned below drives that reading directly.
	"int64-widening-trap":            {ruleRatioDirection, rulePerBlockCeiling},
	"signed-backdate-cancels":        {ruleSignedSolveTime},
	"signed-backdate-cancels-devnet": {ruleSignedSolveTime},
}

func TestDifficultyVectorsAreNotVacuous(t *testing.T) {
	vectors, err := spec.LoadDifficultyVectors("vectors/difficulty")
	if err != nil {
		t.Fatal(err)
	}
	if len(vectors) == 0 {
		t.Fatal("the difficulty vector corpus is empty; run `go run ./spec/gen`")
	}
	seen := make(map[string]bool, len(vectors))

	for _, v := range vectors {
		seen[v.Name] = true
		rules, ok := pinnedBy[v.Name]
		if !ok {
			t.Errorf("%s: no rule listed in pinnedBy — every vector must name the "+
				"clause whose removal changes its answer, or be listed with an "+
				"empty set as a declared baseline", v.Name)
			continue
		}
		if len(rules) == 0 {
			// A declared baseline. It pins no clause by construction, so the
			// loop below would have nothing to assert; TestBaselineVectorsAreAReadableControl
			// carries its burden instead. Only vectors named in that test's
			// table may be empty here.
			if _, paired := baselineOf[v.Name]; !paired {
				t.Errorf("%s: listed in pinnedBy with no rules, but it is not a "+
					"declared baseline — give it the clause it pins, or pair it "+
					"in baselineOf", v.Name)
			}
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			p, err := spec.ParamsFor(v.Params)
			if err != nil {
				t.Fatal(err)
			}
			headers, err := v.DecodeHeaders()
			if err != nil {
				t.Fatal(err)
			}
			// The harness must reproduce the committed answer before it is
			// allowed to argue about mutations of it.
			if got := nextTarget(headers, p, ruleNone); got.String() != v.Expect.NextTarget {
				t.Fatalf("the mutation harness disagrees with the vector unmutated: "+
					"%s, want %s — core/pow.NextTarget and this file have diverged",
					got.String(), v.Expect.NextTarget)
			}
			for _, r := range rules {
				if got := nextTarget(headers, p, r); got.String() == v.Expect.NextTarget {
					t.Errorf("omitting %s leaves the answer at %s: this vector "+
						"cannot tell that rule from its absence", ruleName[r], v.Expect.NextTarget)
				}
			}
		})
	}
	for name := range pinnedBy {
		if !seen[name] {
			t.Errorf("pinnedBy names %q, which is not in the corpus", name)
		}
	}
}

// TestOnlyBackdatedVectorsDependOnTheSignedSolveTime keeps the corpus honest
// about which of its vectors the signed-solve-time rule is allowed to move.
//
// It exists because of a finding against the difficulty retarget: under the
// floor-at-zero treatment of a backwards solve time — `if ST<0 then ST=0` —
// a miner who dates its own block before its parent removes an interval from
// the window instead of cancelling one, which is the unlimited-block-production
// exploit core/pow documents at the signed accumulator. Fixing that arithmetic
// touches every committed answer's derivation, so the corpus needed a standing
// statement of which answers it is entitled to touch. This test is that
// statement; it is not a record of the fix landing, and it outlives it.
//
// The rule is settled in core/pow: a backwards solve time SUBTRACTS instead of
// being floored at zero, so the two adjacent intervals a backdate touches
// cancel. This test does not ask "would the proposed fix move anything" — it
// asks the durable question instead: does this vector's committed answer
// depend on the sign at all? It recomputes each vector under the RETIRED
// floor-at-zero rule and requires the answer to be unchanged.
//
// Unchanged is the right expectation for all but three vectors, because all
// but three use strictly increasing timestamps, on which the sign clause is
// unreachable. Keeping that true is the point: a conformance corpus whose
// every answer moved with an internal arithmetic fix would be pinning the
// arithmetic rather than the rule.
//
// The exceptions are signedDependent below — the three vectors added
// specifically to pin the fix, whose windows carry a genuinely decreasing
// timestamp. For those the answer MUST move under the retired rule, and this
// test asserts that direction instead: they are the reason a future revert back
// to floor-at-zero cannot pass the corpus silently.
// naiveWideningNextTarget is the wrong-but-plausible reading of "signed solve
// time": widen the raw difference to int64 FIRST, then clamp. It is the
// implementation a second team writes if they read core/pow's signed
// accumulator and reach for the obvious subtraction, and it agrees with the
// shipped rule on every input a normal chain produces — the two diverge only
// once a gap reaches 2^63 seconds, which no other vector in this corpus comes
// within thirteen orders of magnitude of.
//
// It is deliberately NOT one of the diffRule mutation arms: those model
// core/pow with a clause REMOVED, and this is the same clause present but
// computed differently. Keeping it separate is what lets the arms stay a
// faithful reading of core/pow.
func naiveWideningNextTarget(recent []types.Header, p *params.Params) u256.U256 {
	if len(recent) < 2 {
		return p.GenesisTarget
	}
	n := int(p.DifficultyWindow)
	if len(recent) < n+1 {
		n = len(recent) - 1
	}
	window := recent[len(recent)-(n+1):]

	goal := p.TargetBlockSeconds
	maxSolve := int64(goal * p.DifficultyClampFactor)
	var weighted, weights int64
	for i := 1; i < len(window); i++ {
		// The bug, and the only line that differs: the raw uint64 gap is
		// widened before it is bounded, so a gap at or above 2^63 wraps.
		solve := int64(window[i].Time - window[i-1].Time)
		if solve > maxSolve {
			solve = maxSolve
		}
		if solve < -maxSolve {
			solve = -maxSolve
		}
		weighted += solve * int64(i)
		weights += int64(i)
	}
	if weights == 0 {
		return window[len(window)-1].Target
	}
	last := window[len(window)-1].Target
	// Mirrors the shipped rule everywhere except the widening itself: the
	// ratio is applied to the window's AVERAGE target, and only the
	// clamp bounds are taken against the last one. Anything else here would
	// make this reading disagree with the corpus for a second, unrelated
	// reason and stop isolating the trap.
	var sum u256.U256
	for i := range window {
		sum, _ = sum.Add(window[i].Target)
	}
	basis, _ := sum.Div64(uint64(len(window)))
	num := uint64(1)
	if weighted > 0 {
		num = uint64(weighted)
	}
	next := basis.MulDiv64(num, uint64(weights)*goal)
	upper := last.MulDiv64(p.DifficultyClampFactor, 1)
	lower, _ := last.Div64(p.DifficultyClampFactor)
	if next.Gt(upper) {
		next = upper
	}
	if next.Lt(lower) {
		next = lower
	}
	if next.Gt(p.MaxTarget) {
		next = p.MaxTarget
	}
	if next.IsZero() {
		next = u256.One
	}
	return next
}

// TestTheInt64WideningTrapIsPinned is the reason int64-widening-trap is in the
// corpus at all.
//
// core/pow takes each solve magnitude in uint64, clamps it to maxSolve, and
// only then applies a sign — and its comment says why. The obvious alternative
// (widen the raw difference to int64, then clamp) is wrong on exactly one
// class of input: a gap at or above 2^63, which NextTarget can legally be
// handed, since it is clockless and the future-time limit is a node-layer
// withhold applied on some ingress paths only.
//
// Two things are asserted, and both matter. First, the naive reading really
// does disagree on this vector — otherwise the vector pins nothing. Second,
// and this is the part that makes the vector worth its bytes, the naive
// reading agrees with the shipped rule on EVERY OTHER vector in the corpus:
// without this one, an implementation carrying the bug is conformant.
func TestTheInt64WideningTrapIsPinned(t *testing.T) {
	vectors, err := spec.LoadDifficultyVectors("vectors/difficulty")
	if err != nil {
		t.Fatal(err)
	}
	const trap = "int64-widening-trap"
	seen := false

	for _, v := range vectors {
		p, err := spec.ParamsFor(v.Params)
		if err != nil {
			t.Fatal(err)
		}
		headers, err := v.DecodeHeaders()
		if err != nil {
			t.Fatal(err)
		}
		got := naiveWideningNextTarget(headers, p).String()
		if v.Name == trap {
			seen = true
			if got == v.Expect.NextTarget {
				t.Fatalf("%s: the int64-widening reading answers this vector "+
					"identically (%s), so the vector does not pin the trap it "+
					"exists for", trap, got)
			}
			t.Logf("%s: shipped %s, naive widening %s", trap, v.Expect.NextTarget, got)
			continue
		}
		if got != v.Expect.NextTarget {
			t.Errorf("%s: the int64-widening reading disagrees here too (%s vs %s). "+
				"That is not wrong, but it means %s is no longer the only vector "+
				"catching the trap — check whether this vector grew a gap near "+
				"2^63 by accident", v.Name, got, v.Expect.NextTarget, trap)
		}
	}
	if !seen {
		t.Fatalf("%s is not in the corpus", trap)
	}
}

// baselineOf pairs a declared baseline vector with the vector it is the
// baseline FOR. A baseline pins no clause of its own — that is what makes it a
// baseline — so this is the table that stops "it is a control" from being an
// excuse for a vector nothing checks.
var baselineOf = map[string]string{
	"on-time-holds": "signed-backdate-cancels",
}

// TestBaselineVectorsAreAReadableControl is the burden a declared baseline
// carries instead of the non-vacuity check it cannot meet.
//
// A control is only worth committing if a reader can hold it against its pair
// and attribute the difference to the one thing that differs. That requires
// two properties, and this test asserts both rather than trusting the
// description:
//
//  1. The pair must actually DIFFER. Two vectors with the same answer teach a
//     reader nothing about what changed between them.
//  2. The baseline must be the UNPERTURBED one — its answer is the target
//     standing still (the ratio is exactly 1, so next == the window's declared
//     target), while its pair has moved away from it. If the baseline itself
//     drifted, it would not be a baseline.
func TestBaselineVectorsAreAReadableControl(t *testing.T) {
	vectors, err := spec.LoadDifficultyVectors("vectors/difficulty")
	if err != nil {
		t.Fatal(err)
	}
	byName := make(map[string]*spec.DifficultyVector, len(vectors))
	for _, v := range vectors {
		byName[v.Name] = v
	}

	for base, pair := range baselineOf {
		t.Run(base, func(t *testing.T) {
			b, ok := byName[base]
			if !ok {
				t.Fatalf("baselineOf names %q, which is not in the corpus", base)
			}
			q, ok := byName[pair]
			if !ok {
				t.Fatalf("baselineOf pairs %q with %q, which is not in the corpus", base, pair)
			}
			if b.Expect.NextTarget == q.Expect.NextTarget {
				t.Fatalf("%s and %s commit the same answer (%s): the control cannot "+
					"show a reader what its pair changed", base, pair, b.Expect.NextTarget)
			}

			headers, err := b.DecodeHeaders()
			if err != nil {
				t.Fatal(err)
			}
			// The baseline's defining property: the target does not move.
			last := headers[len(headers)-1].Target
			if b.Expect.NextTarget != last.String() {
				t.Fatalf("%s is declared a baseline, but its answer (%s) is not the "+
					"target the window already carried (%s) — it is not standing still",
					base, b.Expect.NextTarget, last.String())
			}
		})
	}
}

// signedDependent names the vectors whose committed answers are SUPPOSED to
// change when the solve-time sign is removed — the three added to pin the
// signed rule. Every other vector in the corpus must be blind to it. Membership here
// is a deliberate, reviewed statement, not a place to silence a failure: a
// vector that starts depending on the sign by accident is a vector built with
// a decreasing timestamp it did not mean to have.
var signedDependent = map[string]bool{
	"on-time-holds":                  false, // strictly increasing; the control
	"signed-backdate-cancels":        true,
	"signed-backdate-cancels-devnet": true,
}

func TestOnlyBackdatedVectorsDependOnTheSignedSolveTime(t *testing.T) {
	vectors, err := spec.LoadDifficultyVectors("vectors/difficulty")
	if err != nil {
		t.Fatal(err)
	}

	// The guard is worthless unless the mutated arm can actually fire, and on
	// this corpus it never does: every committed window is strictly
	// increasing, so the signed branch is unreachable and the mutated
	// computation is byte-for-byte the unmutated one. A test that can only
	// pass is not a test. So first, on a window built to have a backwards
	// step, prove the arm changes the answer — if this stops holding, the
	// model of the retired floor-at-zero rule has stopped modelling it, and
	// every "unchanged" below means nothing.
	t.Run("the mutation can fire at all", func(t *testing.T) {
		p := spec.Mainnet()
		// A miner dates its own block 100s before its parent: the backward
		// interval vanishes under the retired floor-at-zero rule and cancels
		// under the shipped signed one.
		backdated := diffTestWindow([]uint64{100, 100, 0, 100, 200}, p.GenesisTarget)
		floored := nextTarget(backdated, p, ruleNone)
		signed := nextTarget(backdated, p, ruleSignedSolveTime)
		if floored.String() == signed.String() {
			t.Fatalf("the signed-solve-time arm is a no-op even on a backdated "+
				"window (%s): it no longer models the retired floor-at-zero rule, "+
				"so this test proves nothing", floored.String())
		}
		t.Logf("backdated window: floor-at-zero %s, signed %s", floored.String(), signed.String())
	})
	for _, v := range vectors {
		t.Run(v.Name, func(t *testing.T) {
			p, err := spec.ParamsFor(v.Params)
			if err != nil {
				t.Fatal(err)
			}
			headers, err := v.DecodeHeaders()
			if err != nil {
				t.Fatal(err)
			}
			got := nextTarget(headers, p, ruleSignedSolveTime)
			if signedDependent[v.Name] {
				// These exist to pin the sign. If the retired rule agrees
				// with them, they have stopped discriminating it and a
				// revert to floor-at-zero would pass the corpus unnoticed.
				if got.String() == v.Expect.NextTarget {
					t.Fatalf("this vector exists to pin the signed accumulator, but the "+
						"retired floor-at-zero rule answers it identically (%s): it no "+
						"longer discriminates the fix", v.Expect.NextTarget)
				}
				return
			}
			if got.String() != v.Expect.NextTarget {
				t.Fatalf("this vector's answer depends on the solve-time sign: "+
					"%s under the retired floor-at-zero rule, %s as committed — "+
					"rebuild it with strictly increasing timestamps, or add it to "+
					"signedDependent if it is meant to pin the sign",
					got.String(), v.Expect.NextTarget)
			}
		})
	}
}

// diffTestWindow builds a header window from cumulative timestamps, mirroring
// spec/gen's diffWindow. It exists so this file can construct a window the
// corpus deliberately does not contain — one with a backwards timestamp.
func diffTestWindow(times []uint64, target u256.U256) []types.Header {
	out := make([]types.Header, len(times))
	for i, t := range times {
		out[i] = types.Header{
			Version: types.HeaderVersion,
			Height:  uint64(i),
			Time:    t,
			Target:  target,
		}
		if i > 0 {
			out[i].ParentID = out[i-1].ID()
		}
	}
	return out
}
