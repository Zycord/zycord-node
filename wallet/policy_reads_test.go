package wallet_test

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/printer"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
)

// The property, in one sentence: every read of core/state.State that package
// wallet can perform is pinned here, and each pinned read names the
// session.View.CoversCertificate axis that answers it.
//
// # Why this test exists
//
// CoversCertificate promises a session view answers every state read the
// policy rules perform on a certificate, or refuses and names the answer it
// does not hold. That promise is a claim about a SET, and the per-axis tests
// in wallet/session cannot check it: they pin that each axis refuses on its
// own separating input, which stays true, and green, the day a rule reads a
// cell no axis covers. The failure this file is written against is exactly a
// rule reading a cell nobody checked was fetched, and it fails OPEN.
//
// # Scope, stated as a positive claim rather than left to be discovered
//
// This pin's SCOPE has been wrong at every previous head, always in the same
// direction and always by a mechanism the previous fix did not predict:
//
//	H1  a rule named something other than Check*        NAMING CONVENTION
//	H3  a read in a helper in another file              FILENAME
//	H4  a read reached as a method (follow step)        CALL FORM
//	H5  a rule reached as a method (select step)        CALL FORM
//	H7  a rule registered in a slice                    CALL FORM
//	H6  st := s; st.SpentCount()                        IDENTIFIER SPELLING
//	N1  var checkRule = func(...) { s.SpentCount() }    DECLARATION FORM
//	N2  a read in a package-level var initializer       DECLARATION FORM
//	N4  an imported package taking an INTERFACE         STRUCTURAL TYPING
//	N6  N4 one package deeper than wallet imports       IMPORT DEPTH
//	N7  a delegate aliasing `import st ".../state"`     IMPORT SPELLING
//	N8  a delegate dot-importing core/state             IMPORT SPELLING
//	N10 a reader PROMOTED onto State by embedding       RECEIVER TYPE
//	N11 N10 with the embedded type in another package   DECLARING PACKAGE
//	N13 a delegate at the MODULE ROOT, path "zycord"    PREFIX BOUNDARY
//	N14 a package-level func in core/state taking *State SEAM BETWEEN PREDICATES
//	N15 a method on ANOTHER core/state type taking *State RECEIVER FORM
//	N15b a core/state func taking an INTERFACE *State satisfies STRUCTURAL TYPING
//	N16 a DOT-IMPORTED core/state callable, inside wallet CALL FORM
//
// The last three escapes were each inside the FIX for the previous one, which
// is what happens when a predicate is repaired against the instance instead of
// the class. The countermeasure has gone three for three: REPLACE A MATCH WITH
// A STRUCTURE. The import PATH killed N7/N8, declaration ENUMERATION killed
// N1/N2, and the package's whole METHOD SET killed N10. Each replacement was
// free on today's code, which is the tell of a correct repair — it changes what
// the guard CANNOT MISS, not what it currently reports.
//
// N7 and N8 were in the FIX rather than in the defect: the packages predicate
// matched the import's local NAME. That is the standing question to ask of any
// predicate here before trusting it — WHAT SPELLING OF CORRECT CODE WOULD THIS
// FAIL TO MATCH? — and it produces N7 in about a minute. The repair is a
// structural question (does this package import the path?) rather than a
// better spelling match.
//
// Stating a claim positively does not make its predicate sound, and being
// pinned is not the same as being sound: every predicate here has now been
// broken at least once AFTER being declared correct.
//
// # Match versus structure: what is still a match, audited rather than assumed
//
// A predicate is STRUCTURAL when it asks a question the language answers, and a
// MATCH when it compares against a spelling someone chose. Every escape above
// came from a match. Where each predicate stands now:
//
// Every name in this table is a function DECLARED in this file; two earlier
// rows named functions that do not exist (`stateMethodNames`, and
// `collectIfItCanReceiveState`, which appeared exactly once in the tree — in
// its own row). A table whose whole job is to tell the next reader which
// predicate is which must not send them to a name that is not there, and this
// is the same class the file catalogues twice: a comment outliving the
// predicate it describes.
//
//	scanPackage decl walk      STRUCTURAL  every decl; unhandled kinds named
//	readsIn                    MATCH       an *ast.SelectorExpr naming a method
//	                                       in the set; a BARE identifier is not
//	                                       matched, which is why the import form
//	                                       that produces one is refused (N16)
//	dotImportedPaths           STRUCTURAL  the import's local name is `.`, asked
//	                                       of the parsed spec (N16)
//	methodSetOf                STRUCTURAL  types.NewMethodSet(*State), promoted
//	                                       methods included; no receiver
//	                                       spelling inspected (memoised by
//	                                       stateMethods)
//	importsState               STRUCTURAL  canonical import path
//	notATestFile               STRUCTURAL  the toolchain's own _test.go rule
//	inTreeImportsOf            STRUCTURAL  module path derived from go.mod,
//	                                       root package included (N13)
//	typeMentions               STRUCTURAL  types.Implements / types.Satisfies
//	                                       for an interface or a constraint;
//	                                       identity elsewhere (N15b)
//	declaredCallablesOf        STRUCTURAL  every callable the package declares,
//	                                       at every declaration form (N15, N15f)
//	receivesState              STRUCTURAL  the receiver AND every parameter,
//	                                       asked of each callable (N15, N15c)
//	packageHoldsState          STRUCTURAL  the one disjunct an input question
//	                                       cannot reach (N15g)
//	interfaceMethodsMatching   MATCH       interface method NAMES vs the set,
//	                                       in the CLOSURE packages only
//
// N15b is why typeMentions is on that list. The interface question had two
// askers — interfaceMethodsMatching by name, in every closure package, and
// typeMentions by identity, inside core/state — and each was sound over its own
// domain. core/state is the one package interfaceMethodsMatching skips, so an
// interface parameter there was asked the nominal question by the predicate
// that cannot answer it and never asked the structural one at all. That is the
// SECOND time the interface case fell in the seam between those two, so the
// repair is at the seam and not on one side of it: inside core/state the type
// checker is already loaded and answers exactly, at no cost.
//
// The two remaining matches, stated rather than left to be found:
//
//   - inTreeImportsOf USED to key on the literal prefix, "sound by argument,
//     not by construction". The argument was that no other SPELLING exists for
//     an in-tree package, and it was true; N13 came through the boundary
//     instead, where the module root has no prefix at all. It now derives the
//     module path from go.mod and treats the root as in-module.
//   - interfaceMethodsMatching compares interface method NAMES against the
//     derived set, for the CLOSURE packages. The structural form is "could a
//     *state.State satisfy this interface", which is a question for a type
//     checker rather than an AST walk — and it is now asked structurally
//     wherever the type checker is already loaded, which is core/state
//     (typeMentions, N15b). Extending it to the closure means type-checking the
//     closure, measured at 19.6s below; that trade is stated with its number
//     rather than left implicit, and anyone who thinks it is wrong has
//     everything needed to overturn it.
//
// # Re-ask every predicate at every distance, not the demonstrated one
//
// Twice in this unit the escape was the same defect one package further out:
// N6 was N4 one package deeper, and N11 was N10 one package deeper. Each repair
// was correct FOR THE DISTANCE ITS MUTANT USED, which is not the same as
// correct, and the first one's lesson was not carried across. So each predicate
// is now asked at every distance the language allows:
//
//	scanPackage        top-level decls, decls nested in literals, and any
//	                   OTHER package - the last handed to the packages
//	                   predicate rather than guessed at
//	importsState       direct imports, and the transitive closure to a
//	                   fixpoint; demonstrated two hops out by N6
//	stateMethods       declared on State, promoted from a same-package
//	                   embedded type (N10), promoted across a package
//	                   boundary (N11), and promoted two levels through two
//	                   packages (N12) - and at any depth by construction,
//	                   because go/types answers with the promoted set
//
// # Sound domains still need to be CONTIGUOUS
//
// N14 is the successor to the rule below and the sharper one. Both predicates
// it slipped between are sound BY CONSTRUCTION - the read set is the method set
// from go/types, the module identity comes from go.mod - and neither was at
// fault. The method set covers everything callable ON a *State; the packages
// predicate covers every package EXCEPT the one defining the type; and a
// package-level function taking *State is in neither region.
//
// So: when each predicate is sound over its own domain, check the domains are
// CONTIGUOUS. Every exclusion is a claim about a boundary, and a boundary needs
// an owner on both sides.
//
// # A new boundary is a new exclusion, so the table is DERIVED, not written
//
// The version of this comment that N15 escaped through listed FOUR exclusions
// where the instrument had six skip sites — and the two it omitted included
// `sig.Recv() != nil`, introduced by the very commit that introduced the table.
// A hand-written completeness claim about an instrument is the weakest artefact
// in any hardening round: it is the one thing the instrument does not check
// about itself, and it went stale in the same commit that made it necessary.
//
// The table is therefore not here any more. Every skip in this file carries a
// machine-readable `EXCLUSION(<id>)` marker naming what covers the excluded
// region, `exclusionOwners` registers each id, and
// TestEveryExclusionInThisInstrumentIsRegisteredWithAnOwner cross-checks the
// two in BOTH directions — an unmarked skip fails, and a row naming an id no
// longer in the source fails.
//
// # What that audit enforces, and what it does not
//
// auditExclusions enumerates skips as `continue` statements AND as type
// switches with no `default:` clause. The second half is the default-less
// type-switch repair: a default-less type switch is a boundary drawn with NO
// STATEMENT AT ALL, so the `continue`-only domain could not see it. Deleting
// typeMentions's `case *types.Map:` arm used to shrink the guard's coverage,
// make a `map[int]*State` parameter invisible, and leave both directions of
// the cross-check green.
//
// The four default-less switches that gap referred to are gone as such. Three
// of them — specName, declaredCallablesOf and typeMentions — now carry a
// `default:` arm that NAMES the kind it met and fails, which is the property
// scanPackage always had and the reason no analogy to it holds any more. The
// fourth is the audit's own ast.Inspect walk, which cannot take a `default:`
// (that walk meets every node in the file, so the arm would fire on all of
// them) and carries a marker and a row instead.
//
// So an unmarked `continue` fails, an unmarked default-less type switch fails,
// and a row naming an id no longer in the source fails. What remains outside
// the domain is stated rather than left to be found: `break`, `goto` and
// `fallthrough` — the single `break` in this file is loop control inside
// auditExclusions itself, not a boundary — and a skip restructured into an
// equivalent `if v, ok := …; ok {}` with its row deleted. That last one cannot
// be guarded against at all: per the standing ruling in PROTOCOL.md, a coherent
// guard-edit can only be NAMED, which is what this paragraph does.
//
// Stated in the other direction so this does not over-correct: the enforcement
// is over boundaries that are WRITTEN as a skip or as an unnamed residual, not
// over every conceivable narrowing of the guard. The claim is smaller than "a
// new boundary cannot be drawn without a row"; it is larger than it was, and it
// is not nothing.
//
// # A complete distance is not a complete domain
//
// N13 arrived after every predicate had been asked at every distance, and it
// was not a distance problem: inTreeImportsOf was complete over depth and
// wrong at the EDGE OF ITS DOMAIN. Make one axis sound by construction and the
// next escape leaves along the axis that FEEDS it. So each predicate's inputs
// are now asked about too, not just its reach:
//
//	module identity   derived from go.mod by walking up for it, exactly as the
//	                  go tool locates a module root - not the literal "zycord/"
//	                  that N13 exploited
//	path -> directory moduleIdentity.dirFor, which assumes no vendor tree;
//	                  pinned by TestTheModuleRootHasNoVendorDirectory
//	file set          parser.ParseDir minus _test.go. Build tags are IGNORED,
//	                  so per-OS files are read on every platform (mutant N3).
//	                  This is the weakest row and it is a DELIBERATE
//	                  over-approximation in the fail-closed direction: a read
//	                  in a linux-only file is pinned when the tests run on
//	                  Windows, which can only ever produce a spurious refusal
//	                  to be explained, never a missed read. The alternative -
//	                  honouring build tags - would make the pinned set depend
//	                  on which machine ran it, so a read could be invisible on
//	                  the developer's platform and live on the operator's.
//	                  Named here rather than left as a row, because "ignored"
//	                  reads like an oversight and it is a choice.
//	method set        go/types, which needs no input from this file at all
//
// # Which predicates consume which
//
// interfaceMethodsMatching is SOUND ON ITS OWN TERMS: any interface a *State
// satisfies has every one of its method names in *State's method set. It broke
// only because the set it consumes was incomplete (N11b). Repairing the
// producer repaired the consumer, and repairing the matcher would have repaired
// neither - so before repairing a predicate, ask which others eat its output.
//
// # A named prediction, not a caveat
//
// The standing prediction was "interfaceMethodsMatching is where the next
// escape will come from". N15b half-confirms and half-refutes it, and the
// refuted half is the more useful one: the escape WAS the interface case, and
// it did NOT come from that predicate. It came from the seam beside it — an
// interface parameter inside core/state, the one package that predicate skips
// by name, where the nominal question was asked by typeMentions instead and
// could not answer it.
//
// That is the second time a case fell between those two domains, and it is why
// the prediction is now stated differently. Naming the predicate the next
// escape will exploit has been wrong twice (N11b named the right family and the
// wrong member; N15b named the right family and the wrong SIDE). The question
// that has been right every time is not "which predicate is weakest" but
// "which region does no predicate own" — so the exclusion registry below,
// which enumerates exactly that, replaces the prediction as the artefact to
// attack.
//
// What remains true of interfaceMethodsMatching: it is the last predicate
// comparing a name a person chose, it covers the CLOSURE packages, and the
// shape to expect there is an interface whose method set a *state.State
// satisfies under a name it is not comparing against. Inside core/state the
// same question is now asked structurally (types.Implements), so the two halves
// of the interface case are no longer answered by two different kinds of
// predicate.
//
// # What the structural version would cost, measured rather than asserted
//
// go/types with the standard library's source importer
// (importer.ForCompiler(fset, "source", nil)) type-checks the whole closure
// without any new module dependency, which matters because go.mod's dependency
// list is deliberately one module family. Measured on this machine:
//
//	core/validity 3.99s   core/state 3.82s   core/types 3.45s   core/params 2.42s
//	core/ssz 2.12s        core/crypto 1.94s  core/u256 1.34s    blake3 0.58s
//	CLOSURE TOTAL (8 packages): 19.6s
//
// against a wallet package that currently tests in about 2.4s. So the honest
// statement is NOT that the structural form is unaffordable — it runs here, it
// needs no new dependency, and ~22s is well inside this project's limits. It
// was not done in this PR, and that is a decision about scope with a number
// attached rather than an impossibility. Anyone who thinks the trade is wrong
// has everything they need to overturn it.
//
// Patching instances did not converge, and neither did "delete the call graph":
// N1 resolves no calls and uses no call form, and escaped at the ENUMERATION
// step, because the scan walked *ast.FuncDecl bodies and a rule declared as a
// var is an *ast.GenDecl that no walk ever reached.
//
// So the scope is now three positive claims about where this instrument looks,
// each pinned by its own test rather than assumed:
//
//	WHICH AST NODES   every top-level declaration in every scanned file, with an
//	                  unhandled declaration kind failing loudly
//	                  -> TestTheScanEnumeratesEveryTopLevelDeclaration
//	WHICH PACKAGES    package wallet, plus the derived fact that no package it
//	                  imports can perform a state read at all
//	                  -> TestNoPackageWalletImportsCanPerformAStateRead
//	WHICH METHODS     every method declared on core/state.State, derived from
//	                  that package's source rather than transcribed
//	                  -> TestTheStateMethodSetIsDerivedAndNotEmpty
//
// The next escape has to come from somewhere one of those three claims declares,
// and then that claim fails rather than this one passing quietly.
//
// # The over-approximations, all deliberate and all fail-closed
//
//  1. No call-graph analysis. A read is pinned whether or not a rule can be
//     proven to reach it; SweepAmount's read is pinned with a note that no rule
//     calls it.
//  2. Attribution ignores the receiver's spelling: any selector naming a State
//     method, on any identifier, anywhere inside a declaration (H6).
//  3. Selectors count whether or not they are called, so a method value is a
//     read.
//  4. Build tags are ignored by parser.ParseDir, so per-OS files are scanned on
//     every platform rather than only where they compile (mutant N3).
//
// When one of these over-approximations does eventually collide with something
// benign, the fix is to NAME the collision — an allowlisted row, with the
// reason — and not to weaken the predicate. A predicate narrowed to stop an
// inconvenient true positive is how this pin becomes the thing other lanes
// learn to ignore.
//
// # What this does NOT catch — limits, each with a live mutant behind it
//
//   - A read through reflection, go:linkname, or unsafe. No mutant was built
//     for this, so nothing is claimed either way — not "acceptable", not
//     "unlikely", untested. It is explicitly NOT vacuously unreachable:
//     core/params imports reflect (params.go:20, root.go:6) and is inside the
//     walked closure.
//   - A read whose method name is not a State method name: an interface or
//     adapter that renames Get at its boundary.
//   - A read in a package outside wallet's transitive in-tree closure. Not a
//     hole a rule can fall into silently: reaching such a package requires an
//     import, and adding one puts it inside the closure that
//     TestNoPackageWalletImportsCanPerformAStateRead walks.
//   - A core/state package-level callable reached through a DOT IMPORT inside
//     package wallet WAS invisible: the enumeration puts such names into the
//     read set, but readsIn matches an *ast.SelectorExpr and a dot-imported
//     call is a bare *ast.Ident with no selector to match, so the matcher was
//     never widened with the enumeration. It is now closed in the cheap,
//     FAIL-CLOSED direction rather than the structural one:
//     TestPackageWalletDoesNotDotImportCoreState refuses the import form
//     outright, so the spelling that hides the read cannot be written. The
//     residual is named — a matcher resolving identifiers with go/types (~2.4s
//     for package wallet) would cover bare calls this file has not thought of,
//     and refusing one import form does not.
//
// Delegation to another package was mutant L1, and its mitigation used to be a
// comment saying every CheckAll rule lives here — an unpinned claim held by
// review, which is exactly the kind of claim this file exists to replace. It
// is now checked, and the check had to survive two falsifications of its own
// reasoning:
//
//   - "A package that never mentions state.State cannot receive one" is FALSE
//     for a package taking an INTERFACE (N4): a *state.State satisfies one
//     structurally, so neither package names the type.
//   - "A package that cannot hold a *state.State cannot pass one deeper" is
//     false for the same reason, so direct imports were not enough (N6).
//
// Both are closed by walking the transitive closure and refusing any interface
// method colliding with State's derived surface. Zero collide today, so nothing
// benign fires. A blanket "no State method name anywhere in an import" was
// REJECTED rather than adopted: core/crypto has six Set and core/params three
// Get on unrelated types, so it would fire for a benign reason — which the
// testing discipline forbids outright, and which would have made this pin the
// thing other lanes learn to ignore.

// pinnedStateReads is every core/state.State read in non-test package wallet,
// as "declaration: read", with the session.View.CoversCertificate axis that
// answers it named beside it. A row with no axis is a fail-open hole of the
// shape the absent-versus-zero and uncovered-read failures both take; a row
// that needs no axis says why.
var pinnedStateReads = []string{
	// coversDebitedCells — the deposit cell.
	"CheckHeadroomAffordable: Get(deposit.Cell)",
	// coversDebitedCells — every move source, and the deposit cell.
	"CheckMovesAreCovered: Get(slot)",
	// coversCreditedPayees — the payee's credited cell and its spent marker.
	"CheckPayeeIsFresh: Get(types.BalanceSlot(m.Dst, m.Asset))",
	"CheckPayeeIsFresh: IsSpent(m.Dst)",
	// coversRefundDestination — the refund destination's spent marker.
	"CheckRefundDestination: IsSpent(deposit.RefundTo.Addr)",
	// coversDebitedCells — the deposit cell, one-shot move sources, RETIRE
	// targets.
	"CheckSweepsWholeCell: Get(slot)",
	// NO AXIS NEEDED, as an assertion rather than an omission. SweepAmount is a
	// helper for callers sizing a sweep, not a rule: CheckAll never calls it, so
	// no certificate is accepted or refused on its answer. It is pinned anyway
	// because this test deliberately does not compute reachability. If a future
	// CheckAll rule calls it, this row is where that becomes visible.
	"SweepAmount: Get(types.BalanceSlot(from, asset))",
}

// scan is what one pass over a package saw. The counts are here so the scan can
// be asserted non-vacuous rather than trusted.
type scan struct {
	reads      []string
	files      int
	decls      int
	declsWalk  int
	unhandled  []string
	methodsFor int
}

func TestEveryStateReadInPackageWalletIsPinnedToACoverageAxis(t *testing.T) {
	methods := stateMethods(t)
	sc := scanPackage(t, ".", methods)

	if err := scanIsUsable(sc.files, sc.declsWalk, len(methods)); err != nil {
		t.Fatalf("%v; this pin is not reading what it claims to", err)
	}

	want := append([]string(nil), pinnedStateReads...)
	sort.Strings(want)
	if strings.Join(sc.reads, "\n") != strings.Join(want, "\n") {
		t.Errorf("the state reads in package wallet do not match the pinned set.\n  in source:\n    %s\n  pinned:\n    %s\n\n"+
			"Every read here is a question a session view may hold no answer for. A new one needs an axis in "+
			"session.View.CoversCertificate that answers it, and a row above naming that axis — otherwise the "+
			"unfetched case reads as the benign answer and the rule passes on a question it never asked.",
			strings.Join(sc.reads, "\n    "), strings.Join(want, "\n    "))
	}
}

// TestTheScanEnumeratesEveryTopLevelDeclaration pins the FIRST scope claim:
// which AST nodes this instrument looks at.
//
// N1 escaped the previous form by being a declaration kind the scan never
// enumerated — a rule declared as a package-level function literal is an
// *ast.GenDecl, and the walk only entered *ast.FuncDecl bodies. Nothing failed;
// the read simply did not exist as far as the scan was concerned. This asserts
// the positive claim instead: every top-level declaration is walked, and a kind
// this scan does not handle is named and fails rather than being skipped.
func TestTheScanEnumeratesEveryTopLevelDeclaration(t *testing.T) {
	methods := stateMethods(t)
	sc := scanPackage(t, ".", methods)

	if len(sc.unhandled) != 0 {
		t.Fatalf("the scan met declaration kinds it does not handle: %v — a read inside one is invisible to this pin", sc.unhandled)
	}
	if sc.declsWalk != sc.decls {
		t.Fatalf("the scan walked %d of %d top-level declarations; the %d it skipped could hide a state read",
			sc.declsWalk, sc.decls, sc.decls-sc.declsWalk)
	}
	if sc.decls == 0 {
		t.Fatal("the scan found no declarations at all, so walking all of them asserts nothing")
	}
}

// TestNoPackageWalletImportsCanPerformAStateRead pins the SECOND scope claim:
// which packages this instrument looks at.
//
// This scan is package-scoped, so a rule that delegated its read to another
// package would be invisible (mutant L1). The mitigation was a comment saying
// every CheckAll rule lives in package wallet — an unpinned claim held by
// review, which is precisely the kind of claim this file exists to replace.
//
// It is checkable instead, and the derivation is stronger than the disclosure:
// a package that never mentions state.State cannot receive a *state.State and
// therefore cannot read one, so if NO package wallet imports mentions it, there
// is nothing in the import set to delegate to. Direct imports suffice — a
// package that cannot hold a *state.State cannot pass one deeper.
func TestNoPackageWalletImportsCanPerformAStateRead(t *testing.T) {
	methods := stateMethods(t)
	mod := thisModule(t)
	// Derived, not written down: the package that defines the type is named
	// relative to this module's own path (N13).
	statePkg := mod.path + "/core/state"
	// The TRANSITIVE closure, not the direct imports. Direct-only was
	// justified by "a package that cannot hold a *state.State cannot pass one
	// deeper" — which the interface case above falsifies, and mutant N6
	// exploits: wallet imports A, A declares nothing and names nothing, and the
	// interface lives in B which wallet never imports. Nothing in the closure
	// collides today, so widening costs nothing.
	imports := transitiveInTreeImportsOf(t, ".")
	if len(imports) < 6 {
		t.Fatalf("only %d in-tree packages found in the closure (%v); this pin is not reading the import set it claims to", len(imports), imports)
	}
	checked := 0
	for _, imp := range imports {
		dir := mod.dirFor(imp)
		if imp == statePkg {
			// EXCLUSION(defining-package): "does it import core/state" is
			// trivially false for core/state itself. Owner: methodSetOf, which
			// derives from that package's own types every name through which a
			// read can be reached — the method set of *State, plus every
			// function and method it declares that can RECEIVE a *State.
			//
			// The package that DEFINES the type is excluded here, because
			// "does it import core/state" is trivially false for core/state
			// itself and would assert nothing.
			//
			// An exclusion is a claim about a boundary, and a boundary needs an
			// owner on BOTH sides, so: what covers the excluded region? Reads
			// reached as methods ON *State are covered by stateMethods, the
			// method set of *State. Reads reached as PACKAGE-LEVEL FUNCTIONS
			// taking *State were covered by nothing — that was N14. Reads
			// reached as methods on ANOTHER type taking *State (N15), or
			// through a parameter a *State merely SATISFIES (N15b), were
			// covered by nothing either, because the N14 repair claimed one
			// side of the boundary it drew. methodSetOf now enumerates every
			// function object the package declares and asks the type checker
			// whether any of its inputs can carry a *State.
			//
			// This justification is rewritten rather than edited because the
			// one it replaces described countStateSelectors, a predicate
			// removed two heads earlier: the justification outlived the
			// predicate it justified and became cover for a live defect. When a
			// predicate is replaced, every comment naming the old one has to be
			// re-read, especially the ones explaining why something is skipped.
			continue
		}
		if _, err := os.Stat(dir); err != nil {
			t.Fatalf("import %s does not resolve to %s: %v", imp, dir, err)
		}
		// A PATH question, not a spelling one. The predicate this replaced
		// matched sel.X.Name == "state" — the import's LOCAL name — so a
		// delegate writing `import st "zycord/core/state"` held a *st.State and
		// escaped (N7), and `import . "zycord/core/state"` made the type a bare
		// identifier and escaped too (N8). An import PATH is canonical: it
		// cannot be aliased, dotted, or renamed, so this asks whether the
		// package can reach the type at all rather than how it spells it.
		if importsState(t, dir) {
			t.Errorf("package %s imports zycord/core/state, so it can hold a *state.State and a wallet rule "+
				"could delegate a read to it — and this pin scans only package wallet. Either that package "+
				"must not touch state, or this pin must grow to cover it (mutants L1/N7/N8).", imp)
		}
		// The second half, and it exists because the derivation above is NOT
		// sufficient on its own. "A package that never mentions state.State
		// cannot receive one" is false for a package that accepts an
		// INTERFACE: mutant N4 declares `type reader interface{ Get(types.Slot)
		// u256.U256 }`, never names state.State, and reads state through it.
		// A *state.State satisfies such an interface structurally, so the type
		// is erased at the package boundary.
		//
		// No import declares such an interface today, on any State method name,
		// so pinning it costs nothing and closes N4 exactly. It is checked
		// against the DERIVED method set, so a reader added to State widens
		// this half too.
		if m := interfaceMethodsMatching(t, dir, methods); len(m) != 0 {
			t.Errorf("package %s declares interface method(s) %v matching core/state.State's surface; a "+
				"*state.State satisfies that interface structurally, so a wallet rule could hand state "+
				"across the package boundary without either package naming the type (mutant N4).", imp, m)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no import was actually checked, so this test asserts nothing")
	}
}

// TestTheMethodSetIsPromotionCompleteAndNothingElse separates the N11 repair.
//
// Three properties in one fixture, and the third is the one the previous
// predicate could not have satisfied:
//
//   - a method PROMOTED onto State by embedding is in the set (N10, N11);
//   - an ordinary State method is in the set;
//   - a method on an UNRELATED type in the same package is NOT. The predicate
//     this replaced took every method declared in the directory, so it would
//     have counted NotPromoted and passed the first two assertions anyway.
//     That is what makes this a test of the method SET rather than of a
//     directory scan, and it is why the control is the load-bearing part.
//
// Cross-package promotion is the same go/types mechanism and is pinned by
// mutant N11 end to end, which embeds from another package entirely.
func TestTheMethodSetIsPromotionCompleteAndNothingElse(t *testing.T) {
	dir := t.TempDir()
	write(t, dir+"/x.go", `package x

type State struct{ cellReader }

type cellReader struct{}

func (r cellReader) Held() int { return 0 }

func (s *State) Get() int { return 0 }

type Unrelated struct{}

func (u Unrelated) NotPromoted() int { return 0 }

func NotAMethod() int { return 0 }
`)
	names, err := methodSetOf(dir, "x", "State")
	if err != nil {
		t.Fatalf("type-checking the fixture: %v", err)
	}
	if !names["Held"] {
		t.Fatal("a method promoted onto State by embedding is missing; that is N10/N11")
	}
	if !names["Get"] {
		t.Fatal("an ordinary State method is missing")
	}
	if names["NotPromoted"] {
		t.Fatal("a method on an unrelated type was included; this is a directory scan, not the method set of *State")
	}
	if names["NotAMethod"] {
		t.Fatal("a function with no receiver was included")
	}
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

// TestTheModuleIdentityIsDerivedAndCoversItsOwnRoot separates the N13 repair.
//
// N13 was this file's own derive-don't-transcribe rule turned on the last
// hard-coded identity left in the instrument: the literal prefix "zycord/".
// go.mod declares `module zycord` host-less, so a package at the MODULE ROOT
// has import path exactly "zycord" — in-module, no prefix, never enumerated,
// never asked either package question. The gap was the prefix's BOUNDARY, not
// another spelling of it.
//
// The controls are the load-bearing part: without them a `contains` that
// returned true for everything, or a derivation that returned the empty string
// (making every path in-module by prefix), would pass the positive cases.
func TestTheModuleIdentityIsDerivedAndCoversItsOwnRoot(t *testing.T) {
	mod := thisModule(t)
	if mod.path == "" {
		t.Fatal("the module path is empty; every path would then look in-module and this pin would enumerate nonsense")
	}
	// Read go.mod independently rather than trusting the accessor that this
	// test exists to check.
	b, err := os.ReadFile(filepath.Join(mod.root, "go.mod"))
	if err != nil {
		t.Fatalf("go.mod not at the derived module root %s: %v", mod.root, err)
	}
	if !strings.Contains(string(b), "module "+mod.path) {
		t.Fatalf("derived module path %q does not appear in the go.mod at %s", mod.path, mod.root)
	}

	// The boundary case N13 exploited.
	if !mod.contains(mod.path) {
		t.Fatal("the module ROOT package is not recognised as in-module; a delegate there is never enumerated (N13)")
	}
	if mod.dirFor(mod.path) != mod.root {
		t.Fatalf("the module root package maps to %q, not to the module root %q", mod.dirFor(mod.path), mod.root)
	}
	// An ordinary in-module package still works.
	if !mod.contains(mod.path + "/core/state") {
		t.Fatal("an ordinary in-module path is not recognised")
	}

	// Controls. A path that merely STARTS WITH the module path is not in this
	// module, and a third-party path never is. Without these, contains could
	// be `strings.HasPrefix(path, mod.path)` — which would sweep in unrelated
	// modules and make the closure walk chase directories that do not exist.
	if mod.contains(mod.path + "x/evil") {
		t.Fatal("a path merely prefixed by the module path was treated as in-module")
	}
	// ASSERTED, NOT SEPARATED — labelled rather than dressed up as a conjunct.
	// No mutant kills this assertion alone: the zycordx case above catches
	// every contains-mutant that would also let a third-party path through, so
	// this one never fires first. It is kept because it states the intended
	// domain for a reader, but by the count-the-conjuncts rule it is an
	// assertion and not a separating input.
	if mod.contains("golang.org/x/crypto") {
		t.Fatal("a third-party path was treated as in-module")
	}
}

// TestThePathToDirectoryMappingHoldsForEveryClosurePackage pins the two
// assumptions moduleIdentity.dirFor makes, rather than the predicate it feeds.
//
// The domain question asked of inTreeImportsOf: what supplies its input? Import
// paths are mapped to directories on the assumption that a path under this
// module lives in the matching directory under this module root. Two things
// break that, and both are the same class:
//
//   - a vendor/ tree, where the compiler reads vendor/<path> while this pin
//     reads <path>;
//   - a NESTED MODULE, where a directory under this root belongs to a
//     different module and its packages are not this module's at all.
//
// ./desktop/go.mod already exists, so the nested-module case is real rather
// than hypothetical. It is outside wallet's closure today, so there is no
// defect — which is exactly why it is pinned now: the arm costs what the
// vendor arm cost, and the day something in the closure moves under a nested
// module this fails by name instead of the pin reading the wrong source.
func TestThePathToDirectoryMappingHoldsForEveryClosurePackage(t *testing.T) {
	mod := thisModule(t)

	if fi, err := os.Stat(filepath.Join(mod.root, "vendor")); err == nil && fi.IsDir() {
		t.Fatal("a vendor/ directory exists: import paths no longer map to the directories this pin reads, " +
			"so every package question it asks may be asked of the wrong source")
	}

	// Every package the closure walk will actually visit must resolve to a
	// directory that is inside THIS module, not inside a nested one.
	closure := append([]string{mod.path + "/wallet"}, transitiveInTreeImportsOf(t, ".")...)
	checked := 0
	for _, imp := range closure {
		dir := mod.dirFor(imp)
		if _, err := os.Stat(dir); err != nil {
			// EXCLUSION(unresolvable-closure-dir): an import path that does not
			// resolve to a directory in this checkout is skipped HERE. Owner:
			// TestNoPackageWalletImportsCanPerformAStateRead, which t.Fatals on
			// exactly that condition rather than skipping it.
			continue
		}
		if owner, err := findModule(dir); err == nil && filepath.Clean(owner.root) != filepath.Clean(mod.root) {
			t.Errorf("package %s resolves to %s, which belongs to the nested module at %s (%s); "+
				"this pin would read source the compiler does not use for that import path",
				imp, dir, owner.root, owner.path)
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no closure directory was checked, so this asserts nothing")
	}

	// The control: the nested module that DOES exist must be detected as
	// nested, otherwise the loop above would pass for a findModule that always
	// returned the root.
	nested := filepath.Join(mod.root, "desktop")
	if _, err := os.Stat(filepath.Join(nested, "go.mod")); err == nil {
		owner, err := findModule(nested)
		if err != nil {
			t.Fatalf("findModule failed inside the known nested module: %v", err)
		}
		if filepath.Clean(owner.root) == filepath.Clean(mod.root) {
			t.Fatal("the known nested module at ./desktop was attributed to the root module; " +
				"the check above cannot detect a nested module at all")
		}
	}
}

// TestAPackageLevelFunctionTakingStateIsARead separates the N14 repair.
//
// The method set answers "what can be called ON a *State". The property is
// "what reads state". A package-level function taking *State is outside the
// method set and inside the one package the packages predicate skips, so it
// fell in the SEAM between two predicates that are each sound over their own
// domain.
//
// The controls are what make this a test of the seam rather than of a name
// list: a function taking no State must not be collected, and a method must
// still be.
func TestAPackageLevelFunctionTakingStateIsARead(t *testing.T) {
	dir := t.TempDir()
	write(t, dir+"/x.go", `package x

type State struct{}

func (s *State) Get() int { return 0 }

func Held(s *State) int { return s.Get() }

func HeldByValue(s State) int { return 0 }

func HeldInASlice(all []*State) int { return 0 }

func Unrelated(n int) int { return n }
`)
	names, err := methodSetOf(dir, "x", "State")
	if err != nil {
		t.Fatalf("type-checking the fixture: %v", err)
	}
	for _, want := range []string{"Get", "Held", "HeldByValue", "HeldInASlice"} {
		if !names[want] {
			t.Errorf("%q reaches a *State and was not collected; that is the N14 seam", want)
		}
	}
	// The control. Without it every assertion above would pass for a predicate
	// that collected every function in the package, which is what the method
	// set was replaced for NOT doing.
	if names["Unrelated"] {
		t.Fatal("a function that cannot reach a State was collected; this is a package scan, not the seam")
	}
}

// TestAnythingInTheDefiningPackageThatCanReceiveStateIsARead separates the
// N15/N15b repair, at every distance the language allows.
//
// N14's fix collected package-scope functions and skipped anything with a
// receiver. That line drew a NEW boundary and claimed one side of it: a method
// on ANOTHER type taking *State is excluded by it, and is not in *State's
// method set either, because its receiver is not State (N15). A parameter that
// names no *State at all but that a *State SATISFIES reached nothing, because
// typeMentions asked a nominal question (N15b).
//
// So the fixture asks the repaired predicate at every distance rather than at
// the two the mutants used — receiver, parameter, interface, type-parameter
// constraint, alias, and a *State reached through the receiver's own field.
//
// The controls are what make this a test of the seam rather than of a package
// scan: a method, a function, an interface parameter and a generic parameter
// that CANNOT carry a *State must each be absent.
func TestAnythingInTheDefiningPackageThatCanReceiveStateIsARead(t *testing.T) {
	dir := t.TempDir()
	write(t, dir+"/x.go", `package x

type State struct{}

func (s *State) Get() int { return 0 }

func (s *State) SpentCount() int { return 0 }

type StateAlias = State

type spentCounter interface{ SpentCount() int }

type stringer interface{ String() string }

type Auditor struct{}

// N15: a method on another type, taking *State as a parameter.
func (Auditor) TooManySpent(s *State) bool { return s.SpentCount() > 1 }

// N15c: the receiver itself carries the state; no parameter at all.
type Holder struct{ s *State }

func (h Holder) HeldViaField() int { return h.s.Get() }

// N15b: an interface a *State satisfies, naming no State type anywhere.
func CountedThrough(c spentCounter) int { return c.SpentCount() }

// N15d: the same question one distance out, as a type-parameter constraint.
func CountedGenerically[T spentCounter](c T) int { return c.SpentCount() }

// N15e: through an alias, which is a spelling and not a type.
func HeldByAlias(s *StateAlias) int { return s.Get() }

// N15f: declared as a var rather than as a func, which is how N1/N2 escaped
// the AST scan. Here it is a *types.Var whose type is a signature.
var HeldByAVar = func(s *State) int { return s.Get() }

// Controls: none of these can carry a *State.
func (Auditor) UnrelatedMethod(n int) int { return n }

func UnrelatedFunc(n int) int { return n }

func UnrelatedInterface(v stringer) string { return v.String() }

func UnrelatedGeneric[T stringer](v T) string { return v.String() }

var UnrelatedVar = func(n int) int { return n }
`)
	names, err := methodSetOf(dir, "x", "State")
	if err != nil {
		t.Fatalf("type-checking the fixture: %v", err)
	}
	for _, want := range []string{
		"Get",                // an ordinary method
		"TooManySpent",       // N15  method on another type taking *State
		"HeldViaField",       // N15c state reached through the RECEIVER
		"CountedThrough",     // N15b interface a *State satisfies
		"CountedGenerically", // N15d the same, as a constraint
		"HeldByAlias",        // N15e through an alias
		"HeldByAVar",         // N15f declared as a var, not as a func
	} {
		if !names[want] {
			t.Errorf("%q can receive a *State and was not collected; that is the seam N15/N15b came through", want)
		}
	}
	// The controls. Without them every assertion above would pass for a
	// predicate that collected every function in the package — which is exactly
	// what the method set replaced, and what a too-loose interface question
	// (asking Implements of an interface a *State does NOT satisfy, or treating
	// every interface as a match) would silently reintroduce.
	for _, unwanted := range []string{"UnrelatedMethod", "UnrelatedFunc", "UnrelatedInterface", "UnrelatedGeneric", "UnrelatedVar"} {
		if names[unwanted] {
			t.Errorf("%q cannot reach a *State and was collected; this is a package scan, not the seam", unwanted)
		}
	}
}

// TestAPackageHoldingStateMakesEveryCallableARead separates the one disjunct
// that asking about INPUTS cannot cover.
//
// Every escape above arrives through a parameter or a receiver. A function with
// NEITHER can still read state if the package keeps a *State in package scope,
// and that route is not reachable by widening the input question — it is a
// different disjunct. It is closed here rather than waited for, which is what
// "go looking for the next route" means: core/state declares no package-scope
// variable at all, so the widening adds nothing today.
//
// The control is the load-bearing half: the SAME fixture without the global
// must NOT collect the input-less function, or this arm would be indis-
// tinguishable from a predicate that collects every declaration.
func TestAPackageHoldingStateMakesEveryCallableARead(t *testing.T) {
	const body = `package x

type State struct{}

func (s *State) SpentCount() int { return 0 }

func TooManyGlobal() bool { return %s }

func AlsoNoInputs() int { return 0 }
`
	held := t.TempDir()
	write(t, held+"/x.go", "package x\n\ntype State struct{}\n\nvar gs *State\n\nfunc (s *State) SpentCount() int { return 0 }\n\nfunc TooManyGlobal() bool { return gs.SpentCount() > 1 }\n\nfunc AlsoNoInputs() int { return 0 }\n")
	names, err := methodSetOf(held, "x", "State")
	if err != nil {
		t.Fatalf("type-checking the held fixture: %v", err)
	}
	for _, want := range []string{"TooManyGlobal", "AlsoNoInputs"} {
		if !names[want] {
			t.Errorf("%q was not collected from a package that keeps a *State in package scope; an input-less "+
				"function there reads state and no input question can see it", want)
		}
	}

	// The control, holding the confusable variable fixed: identical source with
	// the package-scope *State removed.
	free := t.TempDir()
	write(t, free+"/x.go", fmt.Sprintf(body, "false"))
	names, err = methodSetOf(free, "x", "State")
	if err != nil {
		t.Fatalf("type-checking the control fixture: %v", err)
	}
	if names["TooManyGlobal"] || names["AlsoNoInputs"] {
		t.Fatal("an input-less function was collected from a package that holds no state; the disjunct is a " +
			"blanket package scan rather than a question about package-scope state")
	}
	if !names["SpentCount"] {
		t.Fatal("the control fixture's method set is empty, so it separates nothing")
	}
}

// TestTheStateMethodSetIsDerivedAndNotEmpty pins the THIRD scope claim: which
// method names count as a read. Deriving from core/state's source rather than
// transcribing means a reader added to State widens this pin without anyone
// remembering to come here.
func TestTheStateMethodSetIsDerivedAndNotEmpty(t *testing.T) {
	got := stateMethods(t)
	// Three that wallet never calls are in the list on purpose: what is derived
	// is the TYPE's surface, not a transcription of what wallet happens to use.
	for _, want := range []string{"Get", "IsSpent", "SpentCount", "Seen", "SortedCells"} {
		if !got[want] {
			t.Errorf("state.State method %q was not derived; the scan cannot recognise a read through it", want)
		}
	}
	if got["NotAStateMethodAnywhere"] {
		t.Error("the derivation is not reading real declarations")
	}
}

// TestPackageWalletDoesNotDotImportCoreState closes the matcher half of the
// N14/N15 widening.
//
// The ENUMERATION was widened so that core/state's package-level callables —
// functions, func-typed vars, methods on other types — count as reads. The
// MATCHER was not: readsIn is over *ast.SelectorExpr, and a dot-imported
// package-level callable is reached as a bare *ast.Ident with no selector to
// match. So `CheckM16(s)` calling a dot-imported `HeldM16(s)` is a real read
// this scan cannot see, while the converse — the identical declaration reached
// as `state.HeldM16(s)` — is caught. That is H4 (calling form) and N7/N8
// (import spelling) relocated INSIDE package wallet, and it exists because the
// previous round put package-level names into the read set at all.
//
// Two repairs were available. Resolving the call with go/types over package
// wallet is the "replace a match with a structure" move that killed N7/N8, and
// it is priced at about 2.4s in the header. Refusing the import form outright is
// cheap and FAIL-CLOSED, and it is what this does: the read cannot become
// invisible if the spelling that hides it cannot be written. The choice is
// stated rather than implied, and it is the weaker of the two — it removes the
// demonstrated escape rather than the class, because a matcher that resolves
// identifiers would also cover a bare call this file has not thought of.
//
// The ban is scoped to core/state by PATH, derived from go.mod (N13), and not
// to every dot import: a dot import of any OTHER package cannot hide a state
// read, because TestNoPackageWalletImportsCanPerformAStateRead refuses any
// package in the closure that can hold a *State at all. Nothing in package
// wallet dot-imports anything today, so this costs nothing now — the tell of a
// correct widening.
func TestPackageWalletDoesNotDotImportCoreState(t *testing.T) {
	mod := thisModule(t)
	statePkg := mod.path + "/core/state"
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", notATestFile, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing .: %v", err)
	}
	files, imports := 0, 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			files++
			imports += len(file.Imports)
			for _, path := range dotImportedPaths(file) {
				// A plain filter to the one path this test is about, written as
				// a condition rather than a `continue` so it does not present to
				// the exclusion audit as a boundary needing a registered owner.
				// Every OTHER dot import is answered in the paragraph above.
				if path == statePkg {
					t.Errorf("%s dot-imports %s. A dot-imported package-level callable is a bare identifier, and "+
						"readsIn matches selectors — so a read reached this way is invisible to this whole pin. "+
						"Import it normally and call it through the package qualifier; the qualified form is caught.",
						name, path)
				}
			}
		}
	}
	// Non-vacuity: a scan that parsed no file, or found no import at all, would
	// report no dot import for the same reason a broken scan does.
	if files < 2 || imports == 0 {
		t.Fatalf("the dot-import scan read %d files and %d imports; it is not reading package wallet and would "+
			"pass on a source that dot-imports core/state on every line", files, imports)
	}
}

// TestTheDotImportScanSeesADotImport is the positive control for the predicate
// above. A check that can only answer "no dot import" is not a check, and this
// package has none, so the predicate is separated on synthetic sources that
// vary exactly one thing: the import's local name.
func TestTheDotImportScanSeesADotImport(t *testing.T) {
	parse := func(src string) *ast.File {
		t.Helper()
		f, err := parser.ParseFile(token.NewFileSet(), "synthetic.go", src, parser.ImportsOnly)
		if err != nil {
			t.Fatal(err)
		}
		return f
	}
	dotted := parse(`package wallet

import (
	"fmt"
	. "zycord/core/state"
)
`)
	if got := dotImportedPaths(dotted); len(got) != 1 || got[0] != "zycord/core/state" {
		t.Fatalf("a dot import was read as %v, not [zycord/core/state]; this predicate cannot come back dirty", got)
	}
	qualified := parse(`package wallet

import (
	"fmt"
	"zycord/core/state"
	st "zycord/core/state"
)
`)
	if got := dotImportedPaths(qualified); len(got) != 0 {
		t.Fatalf("a plain and an ALIASED import were reported as dot imports (%v); the predicate refuses every "+
			"import form and separates nothing — the aliased form is N7, which this must NOT fire on", got)
	}
	blank := parse(`package wallet

import _ "zycord/core/state"
`)
	if got := dotImportedPaths(blank); len(got) != 0 {
		t.Fatalf("a blank import was reported as a dot import (%v); `_` binds no name, so it hides no call", got)
	}
}

// dotImportedPaths returns every import path in file bound with `.`, whose
// exported names therefore enter the file's scope as BARE IDENTIFIERS.
//
// The question is about the import's local name and nothing else, which is the
// one thing the dot-import mutant varied.
func dotImportedPaths(file *ast.File) []string {
	var out []string
	for _, imp := range file.Imports {
		// A condition rather than a `continue`, so a plain filter does not
		// present to the exclusion audit as a boundary needing a registered
		// owner. `_` and an alias both bind a name that keeps calls through this
		// package selector-shaped, so neither is a dot import.
		if imp.Name != nil && imp.Name.Name == "." {
			out = append(out, strings.Trim(imp.Path.Value, `"`))
		}
	}
	sort.Strings(out)
	return out
}

// scanPackage walks every top-level declaration of every non-test file in dir
// and returns each selector naming one of methods, as "declaration: read".
//
// Attribution is by enclosing top-level declaration, not by enclosing function:
// that is what makes a read inside a package-level var initializer (N1, N2)
// visible at all. Reads inside a function literal are attributed to whatever
// declaration the literal is written in.
func scanPackage(t *testing.T, dir string, methods map[string]bool) scan {
	t.Helper()
	sc := scan{methodsFor: len(methods)}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, notATestFile, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", dir, err)
	}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			sc.files++
			for _, d := range file.Decls {
				sc.decls++
				switch decl := d.(type) {
				case *ast.FuncDecl:
					sc.declsWalk++
					if decl.Body != nil {
						sc.reads = append(sc.reads, readsIn(fset, decl.Name.Name, decl.Body, methods)...)
					}
				case *ast.GenDecl:
					// var, const, type, import. A rule declared as a package
					// level function literal lives here (N1), and so does a
					// read in a plain var initializer (N2).
					sc.declsWalk++
					for _, spec := range decl.Specs {
						sc.reads = append(sc.reads, readsIn(fset, specName(spec, &sc), spec, methods)...)
					}
				default:
					sc.unhandled = append(sc.unhandled, fmt.Sprintf("%T", d))
				}
			}
		}
	}
	sort.Strings(sc.reads)
	return sc
}

// specName is the name a read inside this spec is attributed to.
//
// The kind switch carries a `default:` for the same reason scanPackage's does:
// an ast.Spec kind this instrument does not enumerate is NAMED into
// sc.unhandled and fails TestTheScanEnumeratesEveryTopLevelDeclaration, rather
// than being attributed to "?" and blending in with a spec whose name is
// genuinely absent.
func specName(spec ast.Spec, sc *scan) string {
	switch s := spec.(type) {
	case *ast.ValueSpec:
		if len(s.Names) > 0 {
			return s.Names[0].Name
		}
	case *ast.TypeSpec:
		if s.Name != nil {
			return s.Name.Name
		}
	case *ast.ImportSpec:
		return "import"
	default:
		sc.unhandled = append(sc.unhandled, fmt.Sprintf("ast.Spec %T", spec))
	}
	return "?"
}

// readsIn returns every selector under n naming one of methods, called or not.
func readsIn(fset *token.FileSet, owner string, n ast.Node, methods map[string]bool) []string {
	var out []string
	called := map[ast.Node]bool{}
	ast.Inspect(n, func(x ast.Node) bool {
		call, ok := x.(*ast.CallExpr)
		if !ok {
			return true
		}
		sel, ok := call.Fun.(*ast.SelectorExpr)
		if !ok || !methods[sel.Sel.Name] {
			// EXCLUSION(dot-import): this matcher is over *ast.SelectorExpr, so a call
			// whose Fun is a BARE IDENTIFIER is not matched. The enumeration above puts
			// core/state's package-level callables into `methods`, and a DOT IMPORT
			// reaches one of them as an *ast.Ident with no selector to match — the
			// dot-import escape, and the matcher half of the N14 widening that was
			// never done with it. Owner: TestPackageWalletDoesNotDotImportCoreState,
			// which refuses that one import form outright rather than teaching this
			// matcher to resolve identifiers; a resolving matcher would need go/types
			// over package wallet as well, priced at ~2.4s in the header.
			return true
		}
		called[sel] = true
		out = append(out, owner+": "+sel.Sel.Name+"("+render(fset, call.Args)+")")
		return true
	})
	ast.Inspect(n, func(x ast.Node) bool {
		sel, ok := x.(*ast.SelectorExpr)
		if !ok || !methods[sel.Sel.Name] || called[sel] {
			return true
		}
		out = append(out, owner+": "+sel.Sel.Name+" (method value)")
		return true
	})
	return out
}

// stateMethods returns the method set of *core/state.State, computed by
// go/types rather than derived from declarations.
//
// This is the property itself rather than a proxy for it. Go promotes methods
// from embedded types regardless of which PACKAGE declares them, so any
// predicate built on "methods declared in this directory" is correct only at
// the distance its mutant used:
//
//	N10  a reader on a type embedded in State, declared in core/state
//	N11  the same, declared in another package and embedded across the boundary
//
// N11 is N10 one package further out, exactly as N6 was N4 one package further
// out. Both times the repair was correct for the demonstrated distance, which
// is not the same as correct. types.NewMethodSet(*State) has no distance: it
// answers with the promoted set by construction, so there is no further-out
// version of this escape to find.
//
// It also closes N11b without touching interfaceMethodsMatching. That predicate
// is sound on its own terms — any interface a *State satisfies has every one of
// its method names in *State's method set — and failed only because the set it
// consumed was incomplete. Repairing the producer repairs the consumer; a
// better matcher would have repaired neither.
//
// Cost, measured rather than asserted: 3.7s for core/state alone, with the
// standard library's source importer and NO new module dependency. That is the
// whole cost — the closure is not type-checked, which was the 19.6s figure that
// argued the other way for interfaceMethodsMatching. It is memoised because
// several tests need it and the price should be paid once.
var (
	stateMethodsOnce sync.Once
	stateMethodsSet  map[string]bool
	stateMethodsErr  error
)

func stateMethods(t *testing.T) map[string]bool {
	t.Helper()
	stateMethodsOnce.Do(func() {
		mod, err := findModule(".")
		if err != nil {
			stateMethodsErr = err
			return
		}
		stateMethodsSet, stateMethodsErr = methodSetOf(
			mod.dirFor(mod.path+"/core/state"), mod.path+"/core/state", "State")
	})
	if stateMethodsErr != nil {
		t.Fatalf("computing the method set of *state.State: %v", stateMethodsErr)
	}
	return stateMethodsSet
}

// methodSetOf type-checks dir as importPath and returns the method set of
// *typeName, promoted methods included.
func methodSetOf(dir, importPath, typeName string) (map[string]bool, error) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, notATestFile, 0)
	if err != nil {
		return nil, fmt.Errorf("parsing %s: %w", dir, err)
	}
	var files []*ast.File
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			files = append(files, file)
		}
	}
	if len(files) == 0 {
		return nil, fmt.Errorf("no non-test files in %s", dir)
	}
	conf := types.Config{Importer: importer.ForCompiler(fset, "source", nil)}
	pkg, err := conf.Check(importPath, fset, files, nil)
	if err != nil {
		return nil, fmt.Errorf("type-checking %s: %w", importPath, err)
	}
	obj := pkg.Scope().Lookup(typeName)
	if obj == nil {
		return nil, fmt.Errorf("%s declares no type %s", importPath, typeName)
	}
	ms := types.NewMethodSet(types.NewPointer(obj.Type()))
	names := map[string]bool{}
	for i := 0; i < ms.Len(); i++ {
		names[ms.At(i).Obj().Name()] = true
	}

	// The seam (N14, N15, N15b). The method set answers "what can be called ON a
	// *State"; the property this file guards is "what READS state". Everything
	// declared in this package that can receive a *State is outside the method
	// set and inside the one package the packages predicate skips by name, so it
	// falls between two predicates that are each sound over their own domain.
	//
	// N14's fix collected package-scope funcs and skipped anything with a
	// receiver. That drew a NEW boundary and claimed only one side of it: a
	// method on ANOTHER type taking *State is neither in *State's method set
	// (its receiver is not State) nor a receiverless package function (N15).
	//
	// So the enumeration is structural rather than a form: EVERY function object
	// this package declares — package-scope functions AND every method in every
	// declared type's method set, promoted methods included — asked the one
	// question that matters, at every input the language gives it.
	//
	// Same already-loaded *types.Package, so no second type-check and no new
	// dependency.
	sink := &kindSink{}
	target := stateTarget{named: obj.Type(), ptr: types.NewPointer(obj.Type()), unhandled: sink}
	scope := pkg.Scope()
	held := packageHoldsState(scope, target)
	for _, c := range declaredCallablesOf(scope, sink) {
		// A callable with no state-carrying input can still read state if the
		// package KEEPS a *State in package scope, because then it needs no
		// input at all. That disjunct is the route left open by asking only
		// about inputs, so it is closed here rather than waited for.
		if held || c.receivesState(target) {
			names[c.name] = true
		}
	}
	if err := sink.err("the core/state seam scan"); err != nil {
		return nil, err
	}
	return names, nil
}

// kindSink collects the kinds a `default:` arm met and could not handle, so an
// unenumerated kind is NAMED and fails the run instead of being dropped by a
// switch that simply does not mention it.
//
// It exists because a type switch with no `default:` is a boundary the exclusion
// audit could not see: deleting `case *types.Map:` from typeMentions shrank the
// guard's real coverage and left every cross-check green. The audit now refuses
// a default-less type switch that carries no marker, and these sinks are what
// makes a `default:` arm cheap enough to add everywhere it belongs.
type kindSink struct{ kinds []string }

func (k *kindSink) add(kind string) {
	if k == nil {
		// A sink is required rather than optional: a caller passing none would
		// turn a named failure straight back into the silent skip this exists to
		// remove, so it fails here and loudly instead.
		panic("policy_reads_test: unhandled kind " + kind + " met with no sink to name it in")
	}
	k.kinds = append(k.kinds, kind)
}

func (k *kindSink) err(where string) error {
	if k == nil || len(k.kinds) == 0 {
		return nil
	}
	sort.Strings(k.kinds)
	return fmt.Errorf("%s met kind(s) no arm of its switch enumerates: %s — a kind this instrument does not "+
		"handle is a region no predicate asks about, which is the shape every seam escape in this file came "+
		"through; add an arm for it or state it as a registered exclusion", where, strings.Join(k.kinds, "; "))
}

// stateTarget is the type this instrument is hunting for, in both the forms a
// structural question needs: the named type for identity, and the pointer for
// "does a *State satisfy this interface".
// The sink travels with the target because typeMentions is recursive and takes
// no other carrier; it is where that walk names a types.Type kind it does not
// enumerate.
type stateTarget struct {
	named     types.Type
	ptr       types.Type
	unhandled *kindSink
}

// declaredCallable is one name a package makes callable from outside, with the
// signature behind it. It exists so the enumeration is over what the package
// DECLARES rather than over a declaration form: N1/N2 escaped the AST scan by
// being declared as a var rather than as a func, and the same substitution
// works here — `var TooManySpent = func(s *State) bool` is a *types.Var whose
// type is a signature, not a *types.Func.
type declaredCallable struct {
	name string
	sig  *types.Signature
}

// receivesState reports whether any INPUT this callable has can carry a *State
// — its receiver or any of its parameters.
//
// The receiver is an input, and that is not a detail: a method on a type that
// HOLDS a *State reads state with no parameter at all, which is the shape the
// N15 repair would otherwise have opened in its turn.
//
// EXCLUSION(results-not-walked): sig.Results() is deliberately not asked. A
// function that RETURNS something reaching *State produces state rather than
// consuming it. Owner: the *State so produced is itself a *State, so every read
// performed on it is back inside the method set, which is complete by
// construction. state.New() is the live example — pinning it would name every
// caller that merely constructs a state.
func (c declaredCallable) receivesState(target stateTarget) bool {
	if c.sig == nil {
		return false
	}
	inputs := []types.Type{}
	if recv := c.sig.Recv(); recv != nil {
		inputs = append(inputs, recv.Type())
	}
	params := c.sig.Params()
	for i := 0; i < params.Len(); i++ {
		inputs = append(inputs, params.At(i).Type())
	}
	for _, in := range inputs {
		if typeMentions(in, target, map[types.Type]bool{}, 0) {
			return true
		}
	}
	return false
}

// declaredCallablesOf enumerates every name in scope that can be called, at
// every declaration form and on every declared type.
//
// This is the ENUMERATION half of the seam repair, and it is deliberately over
// forms rather than over one form: package functions, func-typed package
// variables, and the methods of every declared type in both the value and the
// pointer method set — which is where N15 sat, a method whose receiver is not
// State and which is therefore in no method set this instrument was asking.
//
// The object switch carries a `default:`. Before it, an object kind at package
// scope that this switch did not name was skipped in silence, which is the
// same shape as the `case` deletion that shrank typeMentions with every
// cross-check green.
func declaredCallablesOf(scope *types.Scope, sink *kindSink) []declaredCallable {
	var out []declaredCallable
	add := func(name string, t types.Type) {
		sig, _ := types.Unalias(t).(*types.Signature)
		out = append(out, declaredCallable{name: name, sig: sig})
	}
	for _, name := range scope.Names() {
		switch o := scope.Lookup(name).(type) {
		case *types.Const:
			// EXCLUSION(const-object): a package-level constant. Owner: none
			// needed — Go has no constant of function type, so a constant cannot
			// be a callable and cannot receive a *State. This arm exists so the
			// `default:` below can fail on a kind that is genuinely unaccounted
			// for; core/state declares three such constants today.
			continue
		case *types.Func:
			add(o.Name(), o.Type())
		case *types.Var:
			add(o.Name(), o.Type())
		case *types.TypeName:
			named, ok := types.Unalias(o.Type()).(*types.Named)
			if !ok {
				// EXCLUSION(non-named-typename): a type name whose type is not
				// *types.Named declares no methods, so there is no callable
				// here for a read to hide in. Owner: none needed.
				continue
			}
			// Both forms, because a value receiver and a pointer receiver put
			// a method in different method sets and either can take a *State.
			for _, form := range []types.Type{named, types.NewPointer(named)} {
				ms := types.NewMethodSet(form)
				for i := 0; i < ms.Len(); i++ {
					fn, ok := ms.At(i).Obj().(*types.Func)
					if !ok {
						// EXCLUSION(non-func-selection): a method set selection
						// is always a *types.Func; anything else carries no
						// signature to ask about. Owner: none needed.
						continue
					}
					add(fn.Name(), fn.Type())
				}
			}
		default:
			// Named and failed rather than skipped: an object kind at package
			// scope that no arm above enumerates could make a name callable that
			// this instrument would then never ask about.
			sink.add(fmt.Sprintf("declaredCallablesOf: package-scope object %T (%s)", o, name))
		}
	}
	return out
}

// packageHoldsState reports whether the package keeps a *State reachable from
// package scope.
//
// If it does, EVERY callable it declares can read state without taking one as
// an input, so asking about inputs stops being sufficient. core/state holds no
// package-scope variable at all today, so this disjunct adds nothing — which is
// the tell of a correct widening: it changes what the guard CANNOT miss, not
// what it currently reports.
func packageHoldsState(scope *types.Scope, target stateTarget) bool {
	for _, name := range scope.Names() {
		v, ok := scope.Lookup(name).(*types.Var)
		if !ok {
			// EXCLUSION(non-var-object): only a variable is mutable package
			// state. Owner: declaredCallablesOf, which enumerates the funcs and
			// type names in this same scope.
			continue
		}
		if _, isFunc := types.Unalias(v.Type()).(*types.Signature); isFunc {
			// EXCLUSION(func-typed-var): a func-typed package variable is not
			// STORED state; it is a callable. Owner: declaredCallablesOf, which
			// collects it as one and asks its inputs the same question.
			continue
		}
		if typeMentions(v.Type(), target, map[types.Type]bool{}, 0) {
			return true
		}
	}
	return false
}

// typeMentions reports whether t can carry target — structurally, through
// pointers, slices, arrays, maps, channels, tuples, struct fields, function
// signatures, INTERFACE SATISFACTION and type-parameter constraints — rather
// than by comparing type names.
//
// Nominal reachability is not the property. N15b is N4's structural-typing
// blind spot relocated INSIDE core/state: a parameter that names no *State
// anywhere is still handed one if a *State satisfies it, and the type checker
// already knows the answer. So for an interface the question asked is
// types.Implements(*State, iface) — the structural form of the question
// interfaceMethodsMatching can only approximate by name, asked here because
// this package is already loaded and it costs nothing.
//
// It over-approximates on purpose: a function taking []*State or a struct
// holding one can read state just as well as one taking *State, and a false
// positive costs a named row in the table while a false negative is N14/N15
// again. An EMPTY interface parameter is collected for the same reason — a
// *State can be passed to `any`, so the fail-closed answer is yes. Depth-capped
// and cycle-guarded because Go types are graphs.
func typeMentions(t types.Type, target stateTarget, seen map[types.Type]bool, depth int) bool {
	if t == nil {
		return false
	}
	// An alias is a spelling, not a type. Resolving it first is the same move
	// that killed N7/N8 at the import level: ask the language, not the text.
	t = types.Unalias(t)
	// EXCLUSION(depth-cap): the walk stops at 12 levels of type nesting. It
	// returns BEFORE marking t seen, so a visit truncated by the cap does not
	// poison the memo for a later, shallower approach. Owner: nothing — a type
	// nested deeper than 12 is an accepted, stated residual, in the direction
	// that under-reports rather than over-reports.
	// EXCLUSION(cycle-guard): a type already visited on this walk is not
	// revisited. Owner: nothing needed for termination; the residual is that
	// `seen` is keyed by type identity rather than by (type, depth), so a type
	// first reached deep and later shallow is skipped with budget unspent.
	if depth > 12 || seen[t] {
		return false
	}
	seen[t] = true
	if types.Identical(t, target.named) {
		return true
	}
	switch x := t.(type) {
	case *types.Basic:
		// A basic type carries nothing structurally, and the identity check
		// above already asked the only question there is about it. Enumerated
		// rather than left to the `default:` because it is the commonest kind
		// this walk meets.
		return false
	case *types.Pointer:
		return typeMentions(x.Elem(), target, seen, depth+1)
	case *types.Slice:
		return typeMentions(x.Elem(), target, seen, depth+1)
	case *types.Array:
		return typeMentions(x.Elem(), target, seen, depth+1)
	case *types.Chan:
		return typeMentions(x.Elem(), target, seen, depth+1)
	case *types.Map:
		return typeMentions(x.Key(), target, seen, depth+1) || typeMentions(x.Elem(), target, seen, depth+1)
	case *types.Tuple:
		for i := 0; i < x.Len(); i++ {
			if typeMentions(x.At(i).Type(), target, seen, depth+1) {
				return true
			}
		}
	case *types.Struct:
		for i := 0; i < x.NumFields(); i++ {
			if typeMentions(x.Field(i).Type(), target, seen, depth+1) {
				return true
			}
		}
	case *types.Signature:
		return typeMentions(x.Params(), target, seen, depth+1) || typeMentions(x.Results(), target, seen, depth+1)
	case *types.Interface:
		// N15b. IsMethodSet distinguishes an ordinary interface from a
		// constraint carrying type terms; Satisfies is the relation defined for
		// the latter, and asking Implements of it is not defined behaviour.
		if x.IsMethodSet() {
			return types.Implements(target.ptr, x)
		}
		return types.Satisfies(target.ptr, x)
	case *types.TypeParam:
		// A type parameter is only ever as wide as its constraint, which is an
		// interface — so this is the interface case one distance further out.
		return typeMentions(x.Constraint(), target, seen, depth+1)
	case *types.Named:
		// Type ARGUMENTS as well as the underlying type: a generic container
		// instantiated at *State can hold one even where the underlying struct
		// mentions only the parameter.
		if args := x.TypeArgs(); args != nil {
			for i := 0; i < args.Len(); i++ {
				if typeMentions(args.At(i), target, seen, depth+1) {
					return true
				}
			}
		}
		return typeMentions(x.Underlying(), target, seen, depth+1)
	default:
		// Named and failed rather than skipped. This is the arm the case-deletion
		// mutant needed and did not meet: deleting `case *types.Map:` above used to
		// make a `map[int]*State` parameter invisible with every cross-check green,
		// because a kind no arm names simply fell out of the switch as "does not
		// carry state". It now answers fail-closed — an unenumerated kind MIGHT
		// carry a *State — and records the kind, so methodSetOf refuses with its
		// name.
		target.unhandled.add(fmt.Sprintf("typeMentions: types.Type %T", x))
		return true
	}
	return false
}

// moduleIdentity is this module's declared path and the relative directory that
// declares it, both DERIVED from go.mod.
//
// It exists because of N13, and N13 is this file's own derive-don't-transcribe
// rule turned on the last hard-coded identity left in the instrument. The
// predicate keyed on the literal prefix "zycord/", and go.mod declares
// `module zycord` host-less, so a package at the MODULE ROOT has import path
// exactly "zycord" — in-tree, with no "zycord/" prefix, therefore never
// enumerated and never asked either package question. The gap was not a
// spelling of the prefix; it was the prefix's boundary case.
//
// Deriving also fixes the sibling assumption: the directory a path maps to is
// computed from the module root rather than from a hard-coded "../".
type moduleIdentity struct {
	path string // e.g. "zycord"
	root string // relative dir containing go.mod, e.g. ".."
}

var (
	moduleOnce sync.Once
	moduleInfo moduleIdentity
	moduleErr  error
)

func thisModule(t *testing.T) moduleIdentity {
	t.Helper()
	moduleOnce.Do(func() { moduleInfo, moduleErr = findModule(".") })
	if moduleErr != nil {
		t.Fatalf("deriving the module identity: %v", moduleErr)
	}
	return moduleInfo
}

// findModule walks up from start until it finds go.mod, exactly as the go tool
// locates a module root, and reads the module directive out of it.
func findModule(start string) (moduleIdentity, error) {
	dir := start
	for i := 0; i < 12; i++ {
		b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
		if err == nil {
			for _, line := range strings.Split(string(b), "\n") {
				line = strings.TrimSpace(line)
				if !strings.HasPrefix(line, "module ") {
					// EXCLUSION(non-module-line): a go.mod line that is not the
					// module directive. Owner: this loop's own fallthrough,
					// which returns an error when NO module directive was
					// found, so a skipped line cannot present as an identity.
					continue
				}
				p := strings.TrimSpace(strings.TrimPrefix(line, "module "))
				if p == "" {
					return moduleIdentity{}, fmt.Errorf("go.mod in %s has an empty module directive", dir)
				}
				return moduleIdentity{path: p, root: dir}, nil
			}
			return moduleIdentity{}, fmt.Errorf("go.mod in %s declares no module directive", dir)
		}
		dir = filepath.Join(dir, "..")
	}
	return moduleIdentity{}, fmt.Errorf("no go.mod found above %s within 12 levels", start)
}

// contains reports whether an import path names a package of this module,
// INCLUDING the module root itself, which is the case N13 exploited.
func (m moduleIdentity) contains(path string) bool {
	return path == m.path || strings.HasPrefix(path, m.path+"/")
}

// dirFor maps an in-module import path to the directory holding it.
func (m moduleIdentity) dirFor(path string) string {
	if path == m.path {
		return m.root
	}
	return filepath.Join(m.root, strings.TrimPrefix(path, m.path+"/"))
}

// transitiveInTreeImportsOf returns every in-module package reachable from
// dir's non-test imports, dir itself excluded.
func transitiveInTreeImportsOf(t *testing.T, dir string) []string {
	t.Helper()
	seen := map[string]bool{}
	var out []string
	var walk func(string, string)
	walk = func(d, path string) {
		for _, imp := range inTreeImportsOf(t, d) {
			if seen[imp] {
				// EXCLUSION(closure-memo): a package already in the closure is
				// not walked twice. Owner: none needed — this is a memo, not a
				// filter; the package is already in `out` and is therefore
				// still asked every package question.
				continue
			}
			seen[imp] = true
			out = append(out, imp)
			walk(thisModule(t).dirFor(imp), imp)
		}
	}
	walk(dir, "")
	sort.Strings(out)
	return out
}

// inTreeImportsOf returns the zycord/... packages the non-test files of dir
// import.
func inTreeImportsOf(t *testing.T, dir string) []string {
	t.Helper()
	mod := thisModule(t)
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, notATestFile, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parsing %s: %v", dir, err)
	}
	seen := map[string]bool{}
	var out []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, imp := range file.Imports {
				path := strings.Trim(imp.Path.Value, `"`)
				if !mod.contains(path) || seen[path] {
					// EXCLUSION(out-of-module-import): an import outside this
					// module is not enumerated, and a path already seen is a
					// memo. Owner of the first: importsState, which refuses any
					// closure package that imports core/state, so a third-party
					// delegate cannot receive a *State without one. Owner of
					// the second: none needed, the path is already in `out`.
					continue
				}
				seen[path] = true
				out = append(out, path)
			}
		}
	}
	sort.Strings(out)
	return out
}

// importsState reports whether dir imports zycord/core/state by PATH.
//
// A package cannot name a type from a package it does not import, so this is
// the structural form of "can this package hold a *state.State". It is immune
// to the import's local spelling by construction, which the selector-matching
// predicate it replaced was not (N7, N8).
func importsState(t *testing.T, dir string) bool {
	t.Helper()
	mod := thisModule(t)
	for _, imp := range inTreeImportsOf(t, dir) {
		if imp == mod.path+"/core/state" {
			return true
		}
	}
	return false
}

// interfaceMethodsMatching returns the interface method names declared in dir
// that collide with core/state.State's method surface. A package declaring one
// can receive a *state.State without naming the type (mutant N4).
func interfaceMethodsMatching(t *testing.T, dir string, methods map[string]bool) []string {
	t.Helper()
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, dir, notATestFile, 0)
	if err != nil {
		t.Fatalf("parsing %s: %v", dir, err)
	}
	var out []string
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			ast.Inspect(file, func(x ast.Node) bool {
				it, ok := x.(*ast.InterfaceType)
				if !ok || it.Methods == nil {
					return true
				}
				for _, m := range it.Methods.List {
					for _, nm := range m.Names {
						if methods[nm.Name] {
							out = append(out, nm.Name)
						}
					}
				}
				return true
			})
		}
	}
	sort.Strings(out)
	return out
}

// notATestFile is the file filter every parse in this instrument uses.
//
// EXCLUSION(test-files): _test.go files are skipped in every scanned package.
// Owner: nothing, deliberately — a test helper is not a shipped rule, and a
// read in one cannot accept or refuse a certificate.
//
// EXCLUSION(build-tags): parser.ParseDir is called with mode 0 and no build
// context, so //go:build constraints are IGNORED and per-OS files are scanned
// on every platform. Owner: nothing needed — this over-approximates in the
// fail-closed direction. Honouring tags would make the pinned set depend on
// which machine ran the scan, so a read could be invisible on the developer's
// platform and live on the operator's; ignoring them can only ever produce a
// spurious refusal to explain, never a missed read.
func notATestFile(fi fs.FileInfo) bool { return !strings.HasSuffix(fi.Name(), "_test.go") }

// scanIsUsable is the vacuity guard, extracted so each arm can be separated by
// an input rather than only reasoned about. A scan that found one file, no
// declarations, or no State method names is a scan whose comparison is between
// empty sets — the measurement that succeeds by measuring nothing.
func scanIsUsable(files, nDecls, nMethods int) error {
	if files < 2 {
		return fmt.Errorf("the package scan found %d files, so it is not reading the whole package", files)
	}
	if nDecls == 0 {
		return fmt.Errorf("the package scan found %d files but no declarations", files)
	}
	if nMethods == 0 {
		return fmt.Errorf("no methods were derived from core/state, so no read could ever be recognised")
	}
	return nil
}

// TestTheScanRefusesToPassByMeasuringNothing separates all three arms of the
// guard, each with the other two held healthy, plus a control — without which
// all three would pass for a guard that refuses everything.
func TestTheScanRefusesToPassByMeasuringNothing(t *testing.T) {
	if err := scanIsUsable(1, 40, 15); err == nil {
		t.Fatal("a scan that read one file must refuse; it would compare a partial package against the full table")
	}
	if err := scanIsUsable(9, 0, 15); err == nil {
		t.Fatal("a scan that found no declarations must refuse; every comparison would be between empty sets")
	}
	if err := scanIsUsable(9, 40, 0); err == nil {
		t.Fatal("a scan with no State method names must refuse; it would recognise no read at all and pass")
	}
	if err := scanIsUsable(9, 40, 15); err != nil {
		t.Fatalf("a healthy scan must be accepted: %v", err)
	}
}

// exclusionOwners names, for every exclusion this instrument draws, what covers
// the region it excludes. An exclusion is a claim about a boundary, and a
// boundary needs an owner on both sides.
//
// This map is a REGISTRY, not the table. The table is DERIVED from the source
// by auditExclusions, and the two are cross-checked in both directions, because
// the hand-maintained version of this artefact went stale in the very commit
// that made it necessary: the N14 fix drew a new boundary (sig.Recv() != nil),
// added no row, and that unowned boundary was N15. A completeness claim about
// an instrument, written by reading the instrument once, is the weakest artefact
// in any hardening round — it is the one thing the instrument does not check
// about itself.
//
// The enforcement is real and it is BOUNDED, and the bound is stated here
// rather than left for a reader to discover. auditExclusions enumerates skips
// as `continue` statements AND as type switches with no `default:` clause, so
// an unmarked one of either fails, and a row naming an id no longer in the
// source fails. Both directions run over every row already: deleting a row
// alone leaves a marker with no owner, and deleting a marker alone leaves a
// row naming an id the source no longer has. What sitting on an ENFORCED SITE
// adds is the case where both go at once.
//
// Eleven of the seventeen rows below sit on such a site — ten `continue`s and
// one default-less type switch. For ten of those eleven the pair-deletion still
// fails, because the marker is the ONLY one inside the skip's innermost block:
// remove both and the skip survives unmarked, and the audit reports its line.
//
// The eleventh is const-object, and the difference is stated here rather than
// glossed. Its `continue` sits directly in the declaredCallablesOf type-switch
// body — an ast.CaseClause is not an ast.BlockStmt, so the switch body IS the
// innermost block — and that body also holds the non-named-typename and
// non-func-selection markers. The block therefore stays marked without it, so
// const-object is held by the row-without-marker direction only, not by both.
//
// The other six (test-files, build-tags, results-not-walked, depth-cap,
// cycle-guard, dot-import) mark boundaries that are neither a `continue` nor a
// default-less type switch; nothing in the source demands them, and for those
// six this map is still hand-maintained.
//
// The type-switch half was the later widening: a boundary drawn with no
// statement at all was outside the domain entirely, so deleting a `case` arm
// from typeMentions shrank the guard with every cross-check green. The three
// switches that fell in that gap — specName, declaredCallablesOf, typeMentions
// — now carry `default:` arms that NAME the kind they met and fail, which is
// the property scanPackage always had. The fourth, the audit's own ast.Inspect
// walk, cannot take a `default:` and carries a marker instead.
//
// What is still outside the domain, stated: `break`, `goto`, `fallthrough`, and
// a skip restructured into a plain `if`. The last of those cannot be guarded
// against at all — a coherent guard-edit can only be NAMED, per the standing
// ruling in PROTOCOL.md — which is why this section says what the audit
// enforces instead of claiming it closes the class.
var exclusionOwners = map[string]string{
	"defining-package":         "methodSetOf, which derives every reachable name from core/state's own types",
	"unresolvable-closure-dir": "TestNoPackageWalletImportsCanPerformAStateRead, which t.Fatals on it",
	"non-module-line":          "findModule's own fallthrough, which errors when no directive was found",
	"closure-memo":             "none needed: a memo, not a filter; the package is still asked every question",
	"out-of-module-import":     "importsState, which refuses any closure package importing core/state",
	"test-files":               "nothing, deliberately: a test helper is not a shipped rule",
	"build-tags":               "nothing needed: ignoring tags is the fail-closed over-approximation",
	"non-named-typename":       "none needed: a non-named type declares no methods to hide a read in",
	"non-func-selection":       "none needed: a method set selection is always a *types.Func",
	"non-var-object":           "declaredCallablesOf, which enumerates the funcs and type names in that scope",
	"func-typed-var":           "declaredCallablesOf, which collects it as a callable and asks its inputs",
	"results-not-walked":       "the method set of *State, which is complete for reads on a produced *State",
	"depth-cap":                "nothing: a type nested deeper than 12 is a stated residual",
	"cycle-guard":              "nothing needed for termination; the (type, depth) keying residual is stated",
	"const-object":             "none needed: Go has no constant of function type, so a constant is not callable",
	"dot-import":               "TestPackageWalletDoesNotDotImportCoreState, which refuses the one import form readsIn cannot match",
	"inspect-walk":             "none needed: an ast.Inspect walk meets every node, so ignoring a kind narrows nothing",
}

// exclusionMarker is the machine-readable form of a row. It is read out of
// COMMENTS by a parser rather than matched textually, which is why the
// synthetic sources in TestTheExclusionAuditCanComeBackDirty can carry the
// literal string without polluting this file's own audit.
var exclusionMarker = regexp.MustCompile(`EXCLUSION\(([a-z0-9-]+)\):`)

// exclusionAudit is what one mechanical pass over the instrument's own source
// saw. The counts are here so the audit can be asserted non-vacuous.
type exclusionAudit struct {
	ids          []string
	unmarked     []int
	continues    int
	typeSwitches int // every type switch met, whether or not it has a default
	openSwitches int // those of them with no `default:` clause
}

// auditExclusions enumerates every skip in src and every exclusion marker, and
// reports which skips carry no marker.
//
// A skip is one of two things, and the second half is the later widening:
//
//   - a `continue` statement, and
//   - a TYPE SWITCH WITH NO `default:` CLAUSE, which silently drops every kind
//     it does not name. That is a boundary drawn with no statement at all, so
//     the earlier `continue`-only domain could not see it: deleting typeMentions's
//     `case *types.Map:` arm shrank the guard's real coverage, made a
//     `map[int]*State` parameter invisible, and left both directions of the
//     registry cross-check green.
//
// A skip's marker must sit inside the same innermost block — for a `continue`,
// the block containing it; for a default-less type switch, the switch's own
// body. That is a structural relation the parser answers, not a proximity
// heuristic over line numbers.
//
// Two bounds on this, stated rather than left to be found. First, a marker
// anywhere inside a default-less switch's body marks it, including one written
// for a `continue` in one of its cases — the audit does not distinguish a case
// clause from the body, because a case clause is not an ast.BlockStmt and there
// is no cheap structural relation to ask. Second, `break`, `goto` and
// `fallthrough` remain outside the domain; the single `break` in this file is
// loop control inside this very function, not a boundary, so requiring a row
// for it would register a fiction.
func auditExclusions(src []byte, filename string) (exclusionAudit, error) {
	var a exclusionAudit
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, filename, src, parser.ParseComments)
	if err != nil {
		return a, fmt.Errorf("parsing %s: %w", filename, err)
	}
	var markers []token.Pos
	for _, cg := range f.Comments {
		for _, c := range cg.List {
			for _, m := range exclusionMarker.FindAllStringSubmatch(c.Text, -1) {
				a.ids = append(a.ids, m[1])
				markers = append(markers, c.Pos())
			}
		}
	}
	// marked reports whether an EXCLUSION marker sits between the braces of b.
	marked := func(b *ast.BlockStmt) bool {
		if b == nil {
			return false
		}
		for _, m := range markers {
			if b.Lbrace < m && m < b.Rbrace {
				return true
			}
		}
		return false
	}
	var blocks []*ast.BlockStmt
	var skips []token.Pos
	var open []*ast.TypeSwitchStmt
	ast.Inspect(f, func(n ast.Node) bool {
		switch x := n.(type) {
		// EXCLUSION(inspect-walk): this switch names the three node kinds the
		// audit reasons about and ignores every other kind of AST node. Owner:
		// none needed, and a `default:` here would be actively wrong — an
		// ast.Inspect walk meets EVERY node in the file, so the arm would fire on
		// each one. Ignoring a node kind here narrows nothing; it is what walking
		// selectively means. The marker sits INSIDE the switch body because that
		// is where this audit looks for one, which is the audit's own
		// default-less switch answering to its own widened domain.
		case *ast.BlockStmt:
			blocks = append(blocks, x)
		case *ast.BranchStmt:
			if x.Tok == token.CONTINUE {
				skips = append(skips, x.Pos())
			}
		case *ast.TypeSwitchStmt:
			a.typeSwitches++
			if !hasDefaultClause(x.Body) {
				open = append(open, x)
			}
		}
		return true
	})
	a.continues = len(skips)
	a.openSwitches = len(open)
	for _, p := range skips {
		var inner *ast.BlockStmt
		for _, b := range blocks {
			if b.Lbrace < p && p < b.Rbrace && (inner == nil || b.Lbrace > inner.Lbrace) {
				inner = b
			}
		}
		if !marked(inner) {
			a.unmarked = append(a.unmarked, fset.Position(p).Line)
		}
	}
	for _, sw := range open {
		if !marked(sw.Body) {
			a.unmarked = append(a.unmarked, fset.Position(sw.Pos()).Line)
		}
	}
	sort.Ints(a.unmarked)
	return a, nil
}

// hasDefaultClause reports whether a switch body carries a `default:`.
//
// A default-less type switch is a boundary drawn without a statement: every kind
// no case names falls out of it, and nothing in the source says so.
func hasDefaultClause(body *ast.BlockStmt) bool {
	if body == nil {
		return false
	}
	for _, stmt := range body.List {
		if cc, ok := stmt.(*ast.CaseClause); ok && cc.List == nil {
			return true
		}
	}
	return false
}

// TestEveryExclusionInThisInstrumentIsRegisteredWithAnOwner derives the
// exclusion table instead of transcribing it.
//
// The previous table was hand-written prose in this file's header. It listed
// four exclusions where the instrument had six skip sites, and the two it
// omitted included the one this round's predecessor had just introduced. A rule
// saying "every exclusion needs an owner on both sides" cannot be applied by
// reading a table that does not enumerate every exclusion.
func TestEveryExclusionInThisInstrumentIsRegisteredWithAnOwner(t *testing.T) {
	// Derived, not transcribed: the file asks the runtime for its own path
	// rather than naming itself, so renaming it cannot silently empty the scan.
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate this file's own source; the audit would scan nothing")
	}
	src, err := os.ReadFile(thisFile)
	if err != nil {
		t.Fatalf("reading this instrument's own source at %s: %v", thisFile, err)
	}
	a, err := auditExclusions(src, thisFile)
	if err != nil {
		t.Fatal(err)
	}
	// Non-vacuity first: an audit that parsed nothing agrees with everything.
	if a.continues < 5 {
		t.Fatalf("the audit found %d skip sites in this instrument; it is not reading the source it claims to", a.continues)
	}
	// The type-switch half of the domain needs its own non-vacuity arm: counting
	// zero type switches is exactly what the audit did before that half existed,
	// and it looked identical to a clean pass.
	if a.typeSwitches < 4 {
		t.Fatalf("the audit found %d type switches in this instrument; it is not reading the source it claims to, "+
			"and the half of its domain that covers a boundary drawn with no statement is measuring nothing", a.typeSwitches)
	}
	if len(a.ids) < len(exclusionOwners) {
		t.Fatalf("the audit found %d markers for %d registered exclusions; it is not reading the comments it claims to",
			len(a.ids), len(exclusionOwners))
	}

	if len(a.unmarked) != 0 {
		t.Errorf("skip site(s) at line(s) %v carry no EXCLUSION marker. Every skip is a boundary, and a boundary "+
			"needs an owner on both sides — add `// EXCLUSION(<id>): <what covers the excluded region>` inside the "+
			"block (for a type switch with no `default:`, inside the switch body — or give it a `default:` arm that "+
			"names the kind it met and fails) and a row in exclusionOwners. The N14 fix drew a boundary without a "+
			"row and that boundary was N15, and a default-less type switch is a boundary drawn "+
			"with no statement at all.",
			a.unmarked)
	}

	seen := map[string]int{}
	for _, id := range a.ids {
		seen[id]++
		if exclusionOwners[id] == "" {
			t.Errorf("exclusion %q is marked in the source but has no owner in exclusionOwners; "+
				"an exclusion with no named owner is the shape N15 came through", id)
		}
	}
	for id := range exclusionOwners {
		switch seen[id] {
		case 1:
		case 0:
			t.Errorf("exclusionOwners registers %q, which no longer appears in the source; a row that outlives the "+
				"skip it describes becomes cover for a live defect, which has now happened twice in this unit", id)
		default:
			t.Errorf("exclusion id %q is used %d times; ids must be unique or a row cannot name one boundary", id, seen[id])
		}
	}
}

// TestTheExclusionAuditCanComeBackDirty is the positive control for the audit.
//
// A check that can only return "pass" is not a check, and "no unmarked skips"
// is a pass. This runs a source that is KNOWN to have an unmarked skip through
// the identical instrument and asserts it comes back dirty, then marks the same
// skip and asserts it comes back clean — so the audit is shown to discriminate
// rather than merely to agree.
func TestTheExclusionAuditCanComeBackDirty(t *testing.T) {
	dirty := []byte(`package p

func f(xs []int) int {
	n := 0
	for _, x := range xs {
		if x == 0 {
			continue
		}
		n += x
	}
	return n
}
`)
	a, err := auditExclusions(dirty, "dirty.go")
	if err != nil {
		t.Fatal(err)
	}
	if a.continues != 1 {
		t.Fatalf("the audit found %d skips in a source with exactly one; it is not enumerating skips", a.continues)
	}
	if len(a.unmarked) != 1 {
		t.Fatalf("an unmarked skip was not reported (%v); this audit cannot come back dirty and certifies nothing", a.unmarked)
	}

	clean := []byte(`package p

func f(xs []int) int {
	n := 0
	for _, x := range xs {
		if x == 0 {
			// EXCLUSION(synthetic): a zero contributes nothing. Owner: the sum.
			continue
		}
		n += x
	}
	return n
}
`)
	b, err := auditExclusions(clean, "clean.go")
	if err != nil {
		t.Fatal(err)
	}
	if len(b.unmarked) != 0 {
		t.Fatalf("a marked skip was reported as unmarked (%v); the audit refuses everything and separates nothing", b.unmarked)
	}
	if len(b.ids) != 1 || b.ids[0] != "synthetic" {
		t.Fatalf("the marker id was read as %v, not [synthetic]", b.ids)
	}
	// The marker must be read from a COMMENT and not matched textually: the
	// string above lives in a Go string literal in this very file, and this
	// file's own audit must not see it as one of its rows.
	if _, registered := exclusionOwners["synthetic"]; registered {
		t.Fatal("the synthetic control id leaked into the real registry")
	}
}

// TestTheExclusionAuditSeesADefaultLessTypeSwitch is the positive control for
// the default-less-type-switch half of the domain, and it is that mutant in
// miniature.
//
// Three sources, differing in exactly one thing each, so the audit is shown to
// SEPARATE rather than to agree: a type switch with no `default:` and no marker
// is dirty; the same switch with a `default:` is clean; the same switch with a
// marker instead is clean and contributes its id. Without the widening the
// first source comes back clean, which is precisely how deleting a `case` arm
// from typeMentions used to pass.
func TestTheExclusionAuditSeesADefaultLessTypeSwitch(t *testing.T) {
	const openSwitch = `package p

func f(x any) int {
	switch v := x.(type) {
	case int:
		return v
	case string:
		return len(v)
	}
	return 0
}
`
	a, err := auditExclusions([]byte(openSwitch), "open.go")
	if err != nil {
		t.Fatal(err)
	}
	if a.typeSwitches != 1 || a.openSwitches != 1 {
		t.Fatalf("the audit saw %d type switches, %d of them default-less, in a source with exactly one of each; "+
			"it is not enumerating the default-less type switch, the boundary drawn with no statement at all",
			a.typeSwitches, a.openSwitches)
	}
	if len(a.unmarked) != 1 {
		t.Fatalf("a default-less type switch with no marker was not reported (%v); this half of the audit cannot "+
			"come back dirty and certifies nothing", a.unmarked)
	}
	if a.continues != 0 {
		t.Fatalf("the audit found %d continues in a source with none; the two halves of its domain are not separated", a.continues)
	}

	const closedSwitch = `package p

func f(x any) int {
	switch v := x.(type) {
	case int:
		return v
	case string:
		return len(v)
	default:
		panic("unhandled kind")
	}
}
`
	b, err := auditExclusions([]byte(closedSwitch), "closed.go")
	if err != nil {
		t.Fatal(err)
	}
	if b.typeSwitches != 1 || b.openSwitches != 0 {
		t.Fatalf("a type switch WITH a default was counted as %d/%d open; the audit does not read the default clause "+
			"and would demand a marker for a switch that names its own residual", b.typeSwitches, b.openSwitches)
	}
	if len(b.unmarked) != 0 {
		t.Fatalf("a type switch with a default was reported as unmarked (%v); the audit refuses everything and separates nothing", b.unmarked)
	}

	const markedSwitch = `package p

func f(x any) int {
	switch v := x.(type) {
	// EXCLUSION(synthetic-switch): every other kind is covered elsewhere.
	case int:
		return v
	case string:
		return len(v)
	}
	return 0
}
`
	c, err := auditExclusions([]byte(markedSwitch), "marked.go")
	if err != nil {
		t.Fatal(err)
	}
	if c.openSwitches != 1 {
		t.Fatalf("the marked source lost its default-less switch (%d); the control no longer varies one thing", c.openSwitches)
	}
	if len(c.unmarked) != 0 {
		t.Fatalf("a marked default-less type switch was reported as unmarked (%v)", c.unmarked)
	}
	if len(c.ids) != 1 || c.ids[0] != "synthetic-switch" {
		t.Fatalf("the marker id was read as %v, not [synthetic-switch]", c.ids)
	}
	if _, registered := exclusionOwners["synthetic-switch"]; registered {
		t.Fatal("the synthetic control id leaked into the real registry")
	}
}

func render(fset *token.FileSet, args []ast.Expr) string {
	parts := make([]string, 0, len(args))
	for _, a := range args {
		var b strings.Builder
		if err := printer.Fprint(&b, fset, a); err != nil {
			return fmt.Sprintf("<unprintable: %v>", err)
		}
		parts = append(parts, b.String())
	}
	return strings.Join(parts, ", ")
}
