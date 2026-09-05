package sim_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
	"strconv"
	"testing"

	"zycord/core/fold"
)

// TestBothFoldsNameTheSameOutcomeVocabulary holds `sim/refold`'s copy of the
// outcome names against `core/fold`'s.
//
// The outcome vocabulary is a consensus rule implemented twice — PROTOCOL rule
// 12's shape, and the same reason `TestBothFoldsAgreeOnTheRuleTheCorpusRecords`
// exists one level up. `core/fold` spells it as an enum with a `String()`
// method; `sim/refold` spells it as plain strings, deliberately, so that a
// differential failure reads as text rather than as two integers. Two spellings
// of one vocabulary is exactly the shape that drifts.
//
// It is the companion of `spec`'s `TestVectorCoverage`, which derives the set
// of outcomes the corpus must cover from `core/fold` alone. That gate is only
// as wide as the vocabulary it derives from: an outcome added to `refold` and
// not to `core/fold`, or the reverse, would leave the two folds producing
// different answers on a certificate while every corpus check stayed green,
// because the corpus records the *string* and one side would never emit it.
// This is what makes that impossible without a failure.
//
// **Both sides are read, neither is restated.** `core/fold`'s side is walked
// through `String()` until it stops naming values; `refold`'s is read out of its
// own source by an AST scan of the const block, so adding a constant there is
// enough to be counted and no list in this file has to be maintained. A test
// that transcribed either side would pass while the tree drifted, which is the
// defect it exists to catch.
func TestBothFoldsNameTheSameOutcomeVocabulary(t *testing.T) {
	reference := referenceOutcomeNames(t)
	naive := naiveOutcomeNames(t)

	// Anti-vacuity, stated as a lower bound so it survives a fifth outcome:
	// Era 0 has four — applied, two skips and a drop. A scan that found none
	// would report perfect agreement between two empty sets.
	if len(reference) < 4 {
		t.Fatalf("core/fold names %d outcomes through String() (%q), want at least 4: the "+
			"walk has stopped seeing the switch and this comparison would be vacuous",
			len(reference), reference)
	}
	if len(naive) < 4 {
		t.Fatalf("the scan found %d outcome constants in sim/refold (%q), want at least 4: "+
			"it has stopped seeing the const block and this comparison would be vacuous",
			len(naive), naive)
	}

	in := func(set []string, name string) bool {
		for _, s := range set {
			if s == name {
				return true
			}
		}
		return false
	}
	for _, name := range reference {
		if !in(naive, name) {
			t.Errorf("core/fold produces the outcome %q and sim/refold names no such "+
				"outcome. The two folds disagree about what can happen to a certificate, "+
				"and the differential compares strings — so refold can never report it and "+
				"a divergence on it reads as a mismatch about something else. reference=%q "+
				"naive=%q", name, reference, naive)
		}
	}
	for _, name := range naive {
		if !in(reference, name) {
			t.Errorf("sim/refold names the outcome %q and core/fold produces no such "+
				"outcome. spec's TestVectorCoverage derives the corpus's obligation from "+
				"core/fold, so this outcome is demanded by nothing while a second "+
				"implementation reading refold would expect it. reference=%q naive=%q",
				name, reference, naive)
		}
	}
	if !t.Failed() {
		t.Logf("both folds name %d outcomes: %q", len(reference), reference)
	}
}

// referenceOutcomeNames walks core/fold's Outcome through String() until it
// stops naming values.
func referenceOutcomeNames(t *testing.T) []string {
	t.Helper()
	var names []string
	for i := 0; i <= 255; i++ {
		s := fold.Outcome(i).String()
		if s == "UNKNOWN" {
			break
		}
		names = append(names, s)
	}
	sort.Strings(names)
	return names
}

// naiveOutcomeNames reads sim/refold's outcome constants out of its own source.
// refold.Outcome is a string type, so the wire name is the constant's value and
// the scan can take it directly rather than through the package's API — which
// keeps this side of the comparison a reading of the tree rather than a copy of
// it.
func naiveOutcomeNames(t *testing.T) []string {
	t.Helper()

	const src = "refold/refold.go"
	f, err := parser.ParseFile(token.NewFileSet(), src, nil, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", src, err)
	}

	var names []string
	ast.Inspect(f, func(n ast.Node) bool {
		if len(names) > 0 {
			return false
		}
		gd, ok := n.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST || len(gd.Specs) == 0 {
			return true
		}
		first, ok := gd.Specs[0].(*ast.ValueSpec)
		if !ok {
			return true
		}
		if id, ok := first.Type.(*ast.Ident); !ok || id.Name != "Outcome" {
			return true
		}
		for _, s := range gd.Specs {
			vs, ok := s.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, name := range vs.Names {
				if i >= len(vs.Values) {
					t.Fatalf("%s: the outcome constant %s has no value; refold's outcomes "+
						"are their own wire names and one without a literal cannot be read "+
						"here", src, name.Name)
				}
				lit, ok := vs.Values[i].(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("%s: the outcome constant %s is not a string literal, so this "+
						"scan can no longer read the wire names — reword the scan with the "+
						"declaration, or refold's half of the vocabulary goes unchecked",
						src, name.Name)
				}
				v, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s: %s: %v", src, name.Name, err)
				}
				names = append(names, v)
			}
		}
		return false
	})
	sort.Strings(names)
	return names
}
