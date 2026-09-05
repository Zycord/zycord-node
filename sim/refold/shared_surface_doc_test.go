package refold

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"strings"
	"testing"
)

// sharedSymbol is one function the two folds do NOT implement separately: this
// package and core/fold both reach the same code object for it.
//
// selector is the identifier as it is actually called from this package's
// non-test sources; doc is the qualified spelling the package comment must
// carry. Both halves are checked, and the pairing is the point — see
// TestThePackageCommentNamesTheWholeSharedSurface.
type sharedSymbol struct {
	selector string
	doc      string
	why      string
}

var sharedSurface = []sharedSymbol{
	{"SeqGas", "Certificate.SeqGas", "the sequential half of the gas schedule"},
	{"ParGas", "Certificate.ParGas", "the parallel half of the gas schedule"},
	{"ID", "Certificate.ID", "F1's sort key"},
	{"UnderwriterID", "Certificate.UnderwriterID", "F1's primary sort key"},
	{"SizeBytes", "Block.SizeBytes", "the quantity B4 compares against BlockByteLimit"},
	{"ComputeCertRoot", "Block.ComputeCertRoot", "the block's committed certificate root"},
	{"ComputeCitesRoot", "Block.ComputeCitesRoot", "the block's committed citation root"},
	{"MaxCertsPerBlock", "params.MaxCertsPerBlock", "a block ceiling"},
	{"MaxSigsPerBlock", "params.MaxSigsPerBlock", "B18's signature ceiling"},
	{"BlockByteLimit", "params.BlockByteLimit", "a block ceiling"},
	{"SeqGasLimit", "params.SeqGasLimit", "a block ceiling"},
	{"SeqGasBurst", "params.SeqGasBurst", "B5's hard bound"},
	{"ParGasLimit", "params.ParGasLimit", "a block ceiling"},
	{"ParGasTarget", "params.ParGasTarget", "F12b's parallel-market target"},
}

// notShared is the control. NextSeqGasTarget is core/params' epoch controller,
// and updateSeqGasTarget below is this package's independent statement of the
// same law — this package never calls the shared one. If the collector below
// reported it as called, the collector would be reporting names it merely saw
// rather than names this package invokes, and every assertion in this file
// would be worth nothing.
const notShared = "NextSeqGasTarget"

// packageSource parses this package's non-test files and returns the package
// comment together with the set of selector names the sources actually call.
func packageSource(t *testing.T) (doc string, selectors map[string]bool) {
	t.Helper()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("reading sim/refold: %v", err)
	}

	fset := token.NewFileSet()
	selectors = map[string]bool{}
	parsed := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, parser.ParseComments)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		parsed++
		if f.Doc != nil {
			if doc != "" {
				t.Fatalf("two files carry a package comment; this guard reads one")
			}
			doc = f.Doc.Text()
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if sel, ok := n.(*ast.SelectorExpr); ok {
				selectors[sel.Sel.Name] = true
			}
			return true
		})
	}
	if parsed == 0 {
		t.Fatal("no non-test sources were parsed; this guard would pass over an empty package")
	}
	if doc == "" {
		t.Fatal("sim/refold has no package comment at all")
	}
	return doc, selectors
}

// TestThePackageCommentNamesTheWholeSharedSurface is the shared-surface
// finding's first condition, held as a test rather than as a paragraph someone
// remembered to write.
//
// The finding was not that the comment was untidy. It was that the comment
// excluded only "the stateless V-rules and the hash primitives" from what the
// two folds share, while both folds in fact call one implementation of the
// entire gas schedule, of F1's sort key, of the block's committed shape and of
// every ceiling — and that the overstatement is what stopped anyone looking.
// Driven: tripling the per-write term in SeqGas left TestDifferentialFold green
// on all 8 seeds, and SeqGasBurst 4T→8T left `go test ./spec` green.
//
// The two halves below are what makes this more than a spell-check. The doc
// half fails if the comment stops naming something; the source half fails if
// the comment names something this package has stopped sharing. A list that is
// only checked against prose rots into a list of things that used to be true.
func TestThePackageCommentNamesTheWholeSharedSurface(t *testing.T) {
	doc, selectors := packageSource(t)

	for _, s := range sharedSurface {
		if !selectors[s.selector] {
			t.Errorf("the package comment names %s as shared with core/fold, but this "+
				"package no longer calls %s at all; either the sharing ended — in which "+
				"case say so in the comment and drop it from sharedSurface — or the "+
				"call moved and this guard has gone blind (%s)",
				s.doc, s.selector, s.why)
			continue
		}
		if !strings.Contains(doc, s.doc) {
			t.Errorf("this package and core/fold call one implementation of %s (%s), and "+
				"the package comment does not name it. That is the finding exactly: a "+
				"differential which understates its shared surface stops anyone from "+
				"looking for a mutation that moves both sides equally",
				s.doc, s.why)
		}
	}

	if selectors[notShared] {
		t.Fatalf("the control failed: this package appears to call %s, which it is "+
			"supposed to re-implement. Either that is a real regression in this fold's "+
			"independence, or the selector collector is over-reporting and every "+
			"assertion above is vacuous", notShared)
	}
}

// TestThePackageCommentNamesTheJointlyUnexercisedRegions is the other half of
// the same condition, and it is a distinct failure mode from the one above.
//
// Two folds also agree wherever nothing reaches either of them, and that reads
// exactly like agreement earned by two implementations. Measured: deleting this
// package's F12 zero-reward arm leaves TestDifferentialFold green, not because
// the arm is shared — it is written twice — but because no published parameter
// set produces a zero block reward above height 0, so a panic() in BOTH arms
// guarded above height 0 fires zero times.
//
// A reader who knows only about the shared surface would draw the wrong
// conclusion here: they would look for a second implementation and find one.
// The comment has to say both things.
func TestThePackageCommentNamesTheJointlyUnexercisedRegions(t *testing.T) {
	doc, _ := packageSource(t)

	// Every phrase below is a piece of the mechanism itself rather than a
	// pointer to where it was argued. That is deliberate and it is the stronger
	// requirement: a comment can carry a citation while saying nothing, and it
	// cannot carry "deleting this package's F12 zero-reward arm" without having
	// stated what was measured. It is also what lets this file survive being
	// copied into a tree with no issue tracker behind it.
	required := []struct {
		phrase string
		why    string
	}{
		{"make check-imports", "the import-graph boundary that is the whole of what keeps the ceilings' second computation independent"},
		{"deleting this package's F12 zero-reward arm", "the measurement that deleting one F12 arm changes nothing"},
		{"F12", "the rule whose two arms are jointly unexercised"},
		{"rollRing", "this package's statement of that rule, so the reader can find it"},
		{"rollCoinbaseRing", "core/fold's statement of it, so the reader can see it is written twice"},
		{"F2b's health-gate comparator", "the other arm of the same shape, unexercised because its boundary is not an integer at any shipped parameter set"},
		{"core/params/naive", "the second computation that closed the ceilings half"},
	}
	for _, r := range required {
		if !strings.Contains(doc, r.phrase) {
			t.Errorf("the package comment does not mention %q (%s); a green differential "+
				"can mean the two folds share the code or that neither reaches it, and "+
				"a comment that names only the first misleads about the second",
				r.phrase, r.why)
		}
	}

	// Anti-vacuity: the paragraph must actually state the mechanism, not merely
	// name the two arms. "zero" plus a height-0 qualifier is the shortest
	// honest statement of why neither arm is entered.
	if !strings.Contains(doc, "above height 0") {
		t.Error("the package comment cites the measurement but does not say WHY " +
			"the arms are unexercised: no published parameter set produces a zero " +
			"block reward above height 0. Without the reason the citation is a " +
			"bookmark, and the next reader has to re-derive the finding to act on it")
	}
}
