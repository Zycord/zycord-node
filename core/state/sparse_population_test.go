package state_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// This file pins the premise that docs/decisions/sparse-state-readers.md rests
// on, rather than the decision itself.
//
// That decision is "nothing, deliberately": a sparse reader guards itself
// beside its own fetch, as wallet/session.View does, and State keeps exactly
// one answer for an absent cell because zero-is-absence is load-bearing for
// the state root (whitepaper §4, §5/R2-M2). The argument for it is not that
// the conflation is harmless -- it has fixed open four separate times -- but
// that the population which can observe it is *one call site*, and that site
// is guarded by a check derived from source rather than enumerated by hand.
//
// A population of one is a measurement, not a property, and it is the half of
// the argument that rots silently. If a second sparse holder appears, the
// decision is wrong and nothing else in the tree would say so: the new holder
// reads a State that answers every question benignly, so it passes its own
// tests. This instrument is what makes the count fail loudly instead.
//
// It scans source rather than behaviour on purpose. "Was this cell fetched?"
// is not a question State can answer at runtime -- that is the whole issue --
// so there is no assertion about a State value that could stand in for this.

// statePkgPath is the import path of the package this instrument watches.
// Cited rather than retyped at each use so a module rename moves one line.
const statePkgPath = "zycord/core/state"

// sparseness is what a construction site does with the empty State that New
// returns. It is not a property of State -- State is the same type either way
// -- but of whether the site goes on to fill it from a complete source.
type sparseness int

const (
	// dense: the site fills the State from a source that is complete by
	// construction, so an absent cell really is an empty one and the
	// conflation has no reader.
	dense sparseness = iota
	// sparseGuarded: the site fills the State from a partial fetch, so an
	// absent cell may be an unasked one. Such a site must carry its own
	// record of what it fetched and refuse what it cannot answer.
	sparseGuarded
)

// site records one construction of a state.State outside package state.
type site struct {
	class sparseness
	// why states what makes the classification true. A site cannot be
	// registered without one, because the classification is the claim.
	why string
	// guard names the mechanism that answers "was this fetched?" for a
	// sparseGuarded site, and must be empty for a dense one.
	guard string
	// guardTest is the test that pins the guard, as a bare function name.
	//
	// A separate field rather than prose inside guard, because it is the one
	// part of the entry that can be checked: a name in free text is a
	// citation nobody verifies, and this tree has already rotted three
	// citations of exactly this identifier. Measured: replacing the guard
	// prose with a test name that never existed left every test here green.
	// Empty for a dense site, which has no guard to pin.
	guardTest string
}

// stateConstructionSites is every place a state.State is CREATED outside
// package state, in non-test source, keyed by
// "<path from module root>::<function>".
//
// What it is not, stated here because the registry reads stronger than it
// checks. It counts creations, not holders. Clone returns a second
// *state.State and is not scanned -- it propagates its receiver's sparseness
// rather than originating it, and at this head every Clone call in non-test
// source has a dense receiver -- and neither is a sparse state assigned to a
// field, passed across a package boundary or returned from an accessor. The
// guarantee is "every place a state is created is classified, and the sparse
// one names a guard", not "every holder of a sparse state is guarded".
//
// Two routes are known to live in that gap, and neither is visible from here:
//
//   - A sparse *state.State copied out of a session.View into another
//     package's struct. cmd/zcd's nodeState held one until it was deleted:
//     written once, read nowhere, and invisible to every matcher below,
//     because copying a state is not constructing one. That deletion is
//     pinned by TestPackageMainDoesNotImportCoreState, an import tripwire
//     scoped to that one package which makes no claim about the rest of the
//     tree. No such holder exists at this head.
//
//   - Fabrication split across two packages. fabricationImports alarms a
//     single file importing this package together with reflect or unsafe, in
//     all three import forms. It does not fire when one package holds the
//     reflect call and names no zycord type while a second holds the type
//     witness and no reflect import: `(*state.State)(nil)` sits entirely
//     inside the StarExpr prune, so the receiving file mentions the type in
//     no form read here. Measured: every pin in this file stays green
//     while the value produced is a live, nil-mapped, fully readable state --
//     exactly what TestNoPackageOutsideStateBuildsAStateByItsZeroValue exists
//     to count. No helper of that shape is in the tree; it is a capability,
//     not a defect.
//
// Closing either needs go/types or x/tools/go/packages -- a whole-module
// type-check inside this package's test binary, materially heavier than the
// walk it would extend. Until that is paid for, the sentence above is this
// registry's true size, and a reader who takes it for the stronger claim is
// reading more than it checks.
//
// Adding a construction of state.State anywhere in the tree fails
// TestEveryStateConstructionOutsideThePackageIsClassified until it is
// registered here. That is the intended cost: the classification is a claim
// about whether the absent-versus-zero conflation has a reader at that site,
// and it can only be made by the author who knows where the cells come from.
var stateConstructionSites = map[string]site{
	"core/genesis/genesis.go::Build": {
		class: dense,
		why: "the pre-genesis state, which is empty in fact and not merely " +
			"unfetched; every later cell arrives by folding a block.",
	},
	"node/chain/store.go::OpenWith": {
		class: dense,
		why: "the chain's own state, filled by folding every block from " +
			"genesis forward. A cell absent here is absent on the chain.",
	},
	"spec/gen/main.go::genesisVectors": {
		class: dense,
		why: "a golden vector's pre-state. A vector declares the whole " +
			"state it folds against, so empty means empty.",
	},
	"spec/vector.go::(*PreState).BuildState": {
		class: dense,
		why: "the same, read back: PreState is the vector's complete " +
			"declared pre-state, not a subset of a larger one.",
	},
	"wallet/session/session.go::(*Session).FetchState": {
		class: sparseGuarded,
		why: "the only sparse holder in the tree. It holds the few cells one " +
			"node was asked about, so an absent cell is an unasked one and " +
			"reads back as the benign answer -- zero balance, not spent.",
		guard: "session.View.CoversCertificate, which records the fetched " +
			"slots and addresses in two sets and refuses any certificate " +
			"whose rules would read something the view cannot answer.",
		guardTest: "TestEveryStateReadInPackageWalletIsPinnedToACoverageAxis",
	},
}

// TestEveryStateConstructionOutsideThePackageIsClassified is the population
// count. It fails when the tree grows a construction nobody classified.
func TestEveryStateConstructionOutsideThePackageIsClassified(t *testing.T) {
	found, _, _ := scanTree(t)

	for key := range found {
		if _, ok := stateConstructionSites[key]; !ok {
			t.Errorf("unregistered state.State construction at %s\n"+
				"\n"+
				"Every route to a *state.State outside package state must be\n"+
				"classified, because state.State cannot tell an absent cell\n"+
				"from a zero one and the absent answer is the benign one.\n"+
				"Add an entry to stateConstructionSites saying which this is:\n"+
				"\n"+
				"  dense         -- the cells come from a complete source, so\n"+
				"                   an absent cell is genuinely empty.\n"+
				"  sparseGuarded -- the cells come from a partial fetch. The\n"+
				"                   site must then carry its own record of\n"+
				"                   what it fetched and refuse what it cannot\n"+
				"                   answer; name that mechanism in `guard`.\n"+
				"\n"+
				"See docs/decisions/sparse-state-readers.md. If this site is\n"+
				"sparse and has no guard, it is the fail-open defect\n"+
				"arriving a fifth time and the guard is the fix, not the\n"+
				"registration.", key)
		}
	}
}

// TestTheClassificationRegistryHasNoStaleEntries is the other direction, and
// it is what stops the registry from decaying into a list of claims about code
// that no longer exists -- which is how a population count silently stops
// being a count of anything.
func TestTheClassificationRegistryHasNoStaleEntries(t *testing.T) {
	found, _, _ := scanTree(t)

	for key := range stateConstructionSites {
		if _, ok := found[key]; !ok {
			t.Errorf("stateConstructionSites registers %s, which the scan "+
				"did not find.\n"+
				"Either the site moved -- update the key, which is "+
				"\"<path from module root>::<enclosing function>\" -- or it "+
				"is gone and the entry should be deleted.", key)
		}
	}
}

// TestEveryClassificationCarriesItsReasonAndAGuardIffItIsSparse pins that the
// registry cannot be satisfied by classifying a site without saying why, and
// that "sparse" and "has a guard" are the same claim rather than two.
//
// The iff matters in both directions. A sparse site with no guard is the bug;
// a dense site with a guard is a site whose classification is not believed by
// its own author, and that is the state the registry must not be able to hold
// quietly.
func TestEveryClassificationCarriesItsReasonAndAGuardIffItIsSparse(t *testing.T) {
	for key, s := range stateConstructionSites {
		if strings.TrimSpace(s.why) == "" {
			t.Errorf("%s is classified with no reason; the reason is the claim", key)
		}
		switch s.class {
		case sparseGuarded:
			if strings.TrimSpace(s.guard) == "" {
				t.Errorf("%s is classified sparse with no guard named.\n"+
					"A sparse holder with no guard is the fail-open defect itself, "+
					"not a registration of it.", key)
			}
		case dense:
			if strings.TrimSpace(s.guard) != "" {
				t.Errorf("%s is classified dense but names a guard %q.\n"+
					"A dense site needs none; if it needs one it is sparse.",
					key, s.guard)
			}
			if strings.TrimSpace(s.guardTest) != "" {
				t.Errorf("%s is classified dense but names a guard test %q",
					key, s.guardTest)
			}
		}
	}
}

// TestEveryNamedGuardTestExists closes the registry's last piece of unchecked
// free text.
//
// A sparseGuarded entry's whole force is the claim that something pins its
// guard. That claim was prose naming an identifier, and prose naming an
// identifier is how a citation rots: this tree has renamed the very test this
// registry cites, leaving three stale references behind it, and nothing
// noticed. So the name is a field and the field is resolved against the tree.
//
// Test files are where the answer is, and they are exactly what the main scan
// excludes, so this walks them separately rather than reusing it.
func TestEveryNamedGuardTestExists(t *testing.T) {
	declared := testFunctionsInTree(t)

	for key, s := range stateConstructionSites {
		if s.class != sparseGuarded {
			continue
		}
		if strings.TrimSpace(s.guardTest) == "" {
			t.Errorf("%s is classified sparse and names no test pinning its "+
				"guard; an unpinned guard is a claim, not a mechanism", key)
			continue
		}
		if where, ok := declared[s.guardTest]; !ok {
			t.Errorf("%s names %s as the test pinning its guard, and no such "+
				"test is declared anywhere in the tree.\n"+
				"Either it was renamed -- update the entry -- or the guard is "+
				"unpinned, which is the thing this field exists to prevent.",
				key, s.guardTest)
		} else {
			t.Logf("%s -> %s (%s)", key, s.guardTest, where)
		}
	}
}

// citedButNotCode names the camel-cased tokens in this file's comments that
// are deliberately not identifiers, each with the reason it is there.
//
// A registry rather than a regex exception, for the reason
// stateConstructionSites is one: the entry IS the claim, and it can only be
// made by someone who knows why the token is prose. An empty reason is not
// accepted, and an entry that stops appearing is stale and fails -- so this
// cannot quietly become the place rotted citations go to be forgiven.
var citedButNotCode = map[string]string{
	"TestWhatever": "an illustrative placeholder in the prose explaining why " +
		"testFunctionsInTree requires a *testing.T parameter -- it names the " +
		"SHAPE of a function that is not a test, so a real name would be worse.",
	"TestX": "the same placeholder, in the sentence naming the signature `go " +
		"test` requires.",
	"SideView": "the identifier used by MUT-Q, the mutant that put a second " +
		"state.New() inside the registered (*Session).FetchState. It names a " +
		"construction that deliberately never existed in the tree, which is " +
		"the whole content of that measurement.",
}

// TestEveryEntryInTheCitationAllowlistIsUsedAndExplained keeps the allowlist
// from becoming the drain the mechanism above exists to plug.
//
// Both directions, for the same reason the site registry is checked both
// ways: an entry with no reason is an exemption nobody argued for, and an
// entry naming a token this file no longer cites is a permission outliving
// the thing it permitted.
func TestEveryEntryInTheCitationAllowlistIsUsedAndExplained(t *testing.T) {
	const self = "core/state/sparse_population_test.go"

	root := moduleRoot(t)
	src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(self)))
	if err != nil {
		t.Fatalf("reading %s: %v", self, err)
	}
	text := string(src)

	for tok, why := range citedButNotCode {
		if strings.TrimSpace(why) == "" {
			t.Errorf("citedButNotCode[%q] has no reason; the reason is the "+
				"claim, and an exemption without one is a silent skip", tok)
		}
		// Counted in the file as a whole rather than in comments alone: the
		// entry itself mentions the token, so a live entry always has at
		// least that one occurrence, and a token cited nowhere else has
		// exactly one.
		if strings.Count(text, tok) <= 1 {
			t.Errorf("citedButNotCode[%q] is stale: nothing in %s cites it "+
				"any more except its own entry.\n"+
				"Delete the entry -- an exemption that outlives what it "+
				"permitted is how an allowlist turns into a drain.", tok, self)
		}
	}
}

// TestEveryIdentifierThisFileCitesInACommentExists closes the rot class that
// just bit this file.
//
// Two comments here cited a helper by a name it has never had, where they
// meant fabricationImports. That is precisely the citation-rot defect, in the
// file whose own thesis is that a cited identifier must not rot, and it
// shipped in the same round as the guardTest field and
// TestEveryNamedGuardTestExists, which exist to prevent it.
//
// They could not see it. guardTest resolves a name held in a struct FIELD;
// these citations are in COMMENTS, which no mechanism here read. So the
// mechanism built to stop citation rot was blind to citation rot one line
// away from itself.
//
// The rule: a camel-cased token in a comment is a code citation, because
// ordinary English words are not camel-cased. A token that resolves against
// no identifier in the tree is a rotted citation.
//
// # The discriminator covers BOTH cases, and its first version did not
//
// The first version required the token to START lowercase. That half works
// -- it kills a rotted helper name -- but every exported-style citation fell
// outside it, which is most of what this file cites: sibling test names,
// FetchState, IsSpent, the ast node types. Worse, it could not see the
// renamed coverage-axis test recorded as rotted, which the paragraph
// above names as the reason this test exists. The defence against citation
// rot was blind to the very citation whose rot motivated it.
//
// That name is deliberately described here rather than written out. Writing
// it would need an allowlist entry, and forgiving it once would forgive a
// future genuine rot of the same name -- so the prose bends instead, which is
// the tax this mechanism charges and the second time it has charged it.
//
// Widening has to be done on the right axis or it becomes noise. Measured,
// both directions, on this file:
//
//   - `[A-Za-z][a-z0-9]*[A-Z]...` -- 59 tokens, 28 unresolved, of which 20
//     are the ALL-CAPS words this file uses for emphasis (NOT, OPEN, CLOSED,
//     IMPORTS, USES, AST, MUT). Unusable.
//   - `[A-Za-z][a-z0-9]+[A-Z]...` -- requiring a LOWERCASE RUN before the
//     internal capital, so ALL-CAPS drops out by construction. 38 tokens,
//     3 unresolved, all three genuine prose rather than rot.
//
// The second is what is used. The cost is those three, and they are named in
// citedButNotCode below rather than rephrased away, because an allowlist
// entry with an owner is what the previous version of this comment already
// declared to be the answer -- and a prose sentence contorted to satisfy a
// regex is a worse artefact than a registry line saying why.
//
// Scoped to this one file deliberately. It is where the claim lives, the
// blast radius is one file, and a tree-wide version would be a different
// instrument needing its own argument, and three citations in wallet/ are
// outside this file's reach until it exists.
func TestEveryIdentifierThisFileCitesInACommentExists(t *testing.T) {
	const self = "core/state/sparse_population_test.go"

	root := moduleRoot(t)
	src, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(self)))
	if err != nil {
		t.Fatalf("reading %s: %v", self, err)
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, self, src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parsing %s: %v", self, err)
	}

	known := identifiersInTree(t)
	// A leading letter of either case, then a LOWERCASE RUN, then an internal
	// capital. The lowercase run is what keeps ALL-CAPS emphasis out; the
	// case-insensitive first letter is what lets the exported half in.
	camel := regexp.MustCompile(`\b[A-Za-z][a-z0-9]+[A-Z][A-Za-z0-9]*\b`)
	seen := make(map[string]bool)

	for _, group := range f.Comments {
		for _, c := range group.List {
			for _, tok := range camel.FindAllString(c.Text, -1) {
				if seen[tok] || known[tok] {
					continue
				}
				if _, ok := citedButNotCode[tok]; ok {
					continue
				}
				seen[tok] = true
				t.Errorf("%s cites %q in a comment at line %d, and no such "+
					"identifier appears anywhere in the tree.\n"+
					"Either it was renamed -- update the citation -- or it "+
					"never existed. A citation nobody checks is how citation "+
					"rot happens, and this file is where that claim is made.",
					self, tok, fset.Position(c.Pos()).Line)
			}
		}
	}
}

// identifiersInTree collects every identifier appearing in code anywhere in
// the module. A superset of the declared names, deliberately: the question is
// whether a cited name exists at all, and a superset cannot produce a false
// accusation.
func identifiersInTree(t *testing.T) map[string]bool {
	t.Helper()
	root := moduleRoot(t)
	out := make(map[string]bool, 1<<14)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" || name == "vendor" || name == "node_modules" {
				return fs.SkipDir
			}
			if path != root && isNestedCheckout(path) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // unparseable files are not evidence either way here
		}
		ast.Inspect(f, func(n ast.Node) bool {
			if id, ok := n.(*ast.Ident); ok {
				out[id.Name] = true
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree from %s: %v", root, err)
	}
	return out
}

// testFunctionsInTree maps every runnable Test* function declared in a
// _test.go file to where it is declared.
//
// Two exclusions, both learned rather than assumed. testdata/ is skipped
// because the Go tool never compiles it, so a fixture there can carry a
// func TestWhatever() that no `go test` will ever run; without this, a guard
// could be "pinned" by a file that is not code. It is also what the other two
// walks in this file already skip, and a third walk disagreeing with them
// about what the tree is, is the defect that made the F1 control blind.
//
// The signature is checked for the same reason: `func TestX()` with no
// *testing.T parameter is not a test, it is a function whose name begins with
// Test, and `go test` ignores it. Resolving a guard's name to one would be
// resolving it to something that cannot run.
//
// This still resolves a NAME and not a MEANING -- it proves the cited test is
// declared and runnable, never that it pins what the registry entry claims.
func testFunctionsInTree(t *testing.T) map[string]string {
	t.Helper()
	root := moduleRoot(t)
	out := make(map[string]string)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" || name == "vendor" || name == "node_modules" ||
				name == "testdata" {
				return fs.SkipDir
			}
			// A nested repository or worktree is skipped for a reason of its
			// own here: a guard test deleted from this tree still exists in a
			// stale second checkout, and resolving a cited name to that copy
			// would report a guard as present when it is gone.
			if path != root && isNestedCheckout(path) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			t.Errorf("parse %s: %v", rel(root, path), perr)
			return nil
		}
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Recv != nil || !strings.HasPrefix(fd.Name.Name, "Test") {
				continue
			}
			if !takesTestingT(fd) {
				continue
			}
			out[fd.Name.Name] = rel(root, path)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree from %s: %v", root, err)
	}
	return out
}

// TestNoPackageOutsideStateBuildsAStateByItsZeroValue closes the construction
// route the scan above structurally cannot count.
//
// State's fields are all unexported, so `state.State{}` sets none of them --
// but it is still legal Go from any package, and so are `var s state.State`,
// `new(state.State)`, a struct field of type state.State, and equally
// `make([]state.State, n)`, `map[K]state.State`, an array of them, or a named
// type declared over it. So the scan matches the *value type name* rather
// than a list of the forms that reach it: the list was written first and was
// not complete, and the four forms it omitted were measured surviving it.
// Every one of them yields a State whose maps are nil, and a nil map reads:
// Get returns zero for every slot, IsSpent returns false for every address,
// Seen returns false for every id. The zero value of the type is therefore a
// fully readable state that answers every question with the benign answer and
// never errors -- the fail-open direction of the sparse-reader defect in its
// purest form, reachable without calling anything.
//
// It is not made impossible here, because Go has no way to forbid a composite
// literal of an exported type, and detecting it inside Get would put a branch
// on the fold's hottest read for a defect no caller has. It is made *counted*:
// no non-test file outside package state takes this route today, and this test
// is what says so on the day one does.
func TestNoPackageOutsideStateBuildsAStateByItsZeroValue(t *testing.T) {
	_, zeroValue, _ := scanTree(t)

	for _, where := range zeroValue {
		t.Errorf("state.State constructed by its zero value at %s\n"+
			"\n"+
			"A zero-value State has nil maps, and a nil map reads: every\n"+
			"balance is zero, no address is spent, no id is seen. It is the\n"+
			"maximally fail-open state and it never errors.\n"+
			"Use state.New(), and register the site in "+
			"stateConstructionSites.", where)
	}
}

// TestTheScanRefusesToPassByMeasuringNothing is the non-vacuity control.
//
// Every test above passes trivially against an empty scan -- a walk that
// resolved no import, or a module root that came back wrong, reports no
// unregistered sites because it reports no sites. This asserts the scan
// actually reached the tree and found the population the decision document
// describes, so that a broken scan fails here instead of passing everywhere.
func TestTheScanRefusesToPassByMeasuringNothing(t *testing.T) {
	found, _, parsed := scanTree(t)

	// The skip rule first, and on its own terms.
	//
	// The file-set comparison below would now catch a widened skipDir --
	// expectedGoFiles keeps its own literal list and shares nothing with the
	// scan, so widening one side and not the other shows up as a set
	// difference. That was not always so: when the two walks shared skipDir,
	// widening it shrank both by the same amount and the equality still
	// held, which is how adding "sim" hid nine files with every test in this
	// file green.
	//
	// This check is kept anyway, because the two answer different questions.
	// The set comparison asks whether the two walks agree; this asks whether
	// what they agree on is the tree. Both walks skipping sim/ in step is a
	// state the set comparison cannot see and this one can, and the list is
	// written out here rather than referenced because a control that reads
	// the thing it is controlling is not one.
	//
	// sim/ is the directory this matters most for. sim/refold is the second,
	// deliberately naive copy of the consensus rules, it deletes on zero
	// exactly as core/state does, and a sweep that cannot reach it is the
	// trap the contributor rules name outright.
	mayBeSkipped := map[string]bool{
		".git": true, "vendor": true, "testdata": true, "node_modules": true,
	}
	for _, dir := range dirsTheWalkRefuses(t) {
		name := filepath.Base(filepath.FromSlash(dir))
		if mayBeSkipped[name] {
			continue
		}
		// The one refusal that is not by name: a nested repository or git
		// worktree, which is a separate checkout of these sources parked
		// inside the module root and carries its own go.mod, so it is not
		// source this module builds either.
		//
		// The test is re-derived here rather than asked of skipDir, for the
		// same reason the list above is written out rather than referenced: a
		// control that reads the rule it is controlling is not one. This one
		// stays narrow on purpose -- it excuses a directory for being a
		// checkout, and nothing else, so a skipDir widened to any other shape
		// still lands in the error below.
		if _, err := os.Stat(filepath.Join(moduleRoot(t), filepath.FromSlash(dir), ".git")); err == nil {
			continue
		}
		t.Errorf("the walk refuses to descend into %s, so the scan makes "+
			"no claim about anything under it.\n"+
			"skipDir may name only directories that carry no Go source "+
			"this module builds; %q is not one of them.", dir, name)
	}

	// Derived rather than pinned to a number. A hardcoded floor is a guess
	// that ages into either a rubber stamp or a false alarm; counting the
	// files independently makes the control say "the scan parsed everything
	// there was", which is the claim actually wanted.
	//
	// expectedGoFiles shares NOTHING with scanTree but moduleRoot -- see its
	// own comment -- and does no parsing, so a parse failure, an early
	// return, or a filter widened on either side alone shows up here. The
	// comparison is over the file SET in both directions, so a scan that
	// misses files and a scan that reaches files the tree does not hold are
	// separately named, and two errors that cancel in a count cannot pass.
	got := make(map[string]bool, len(parsed))
	for _, f := range parsed {
		got[f] = true
	}
	missing := []string(nil)
	for _, f := range expectedGoFiles(t) {
		if !got[f] {
			missing = append(missing, f)
		}
		delete(got, f)
	}
	if len(missing) > 0 {
		t.Fatalf("the scan never parsed %d of the tree's non-test .go files, "+
			"so it makes no claim about them: %v", len(missing), missing)
	}
	if len(got) > 0 {
		extra := make([]string, 0, len(got))
		for f := range got {
			extra = append(extra, f)
		}
		sort.Strings(extra)
		t.Fatalf("the scan parsed %d files the independent walk does not "+
			"consider part of the tree: %v", len(extra), extra)
	}
	if len(found) == 0 {
		t.Fatal("the scan found no state.State construction anywhere, which " +
			"cannot be true: the chain builds one")
	}
	// The sparse site is the one the decision is about. If the scan cannot
	// see it, every claim made here is about a tree that is not this one.
	const theSparseSite = "wallet/session/session.go::(*Session).FetchState"
	if _, ok := found[theSparseSite]; !ok {
		t.Fatalf("the scan did not find %s, which is the site "+
			"docs/decisions/sparse-state-readers.md names as the reference "+
			"implementation; found %d sites: %v",
			theSparseSite, len(found), sortedKeys(found))
	}
}

// scanTree parses every non-test .go file outside package state and returns
// the construction sites keyed as stateConstructionSites is, the zero-value
// constructions, and the relative path of every file it parsed.
func scanTree(t *testing.T) (found map[string]string, zeroValue []string, parsed []string) {
	t.Helper()

	root := moduleRoot(t)
	found = make(map[string]string)

	// The package's own directory is excluded: inside package state the type
	// is constructed by New and Clone as a matter of course, and `&State{}`
	// there is the implementation rather than a caller's mistake.
	selfDir := filepath.Join(root, filepath.FromSlash("core/state"))

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if skipDir(root, path) || path == selfDir {
				return fs.SkipDir
			}
			return nil
		}
		if !isScannableGoFile(path) {
			return nil
		}

		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			// A file this instrument cannot parse is a file it cannot make
			// a claim about, and silently skipping it is how the scan comes
			// back clean for the wrong reason.
			t.Errorf("parse %s: %v", rel(root, path), perr)
			return nil
		}
		relPath := rel(root, path)
		parsed = append(parsed, relPath)

		local, ok, unreadable := localNameFor(f, statePkgPath)
		if unreadable != "" {
			t.Errorf("%s imports %s as %q, which this scan cannot read.\n"+
				"A dot import makes New and State available unqualified, so "+
				"every matcher here goes blind on this file while the file "+
				"can still construct a State; a blank import is not a use "+
				"but is not distinguishable from one here either.\n"+
				"Import it normally, or alias it.", relPath, statePkgPath, unreadable)
			return nil
		}
		if !ok {
			return nil
		}

		// A file that can reach the type through reflection or unsafe can
		// build one without ever writing a form this scan reads -- see
		// fabricationImports.
		if pkgs := fabricationImports(f); len(pkgs) > 0 {
			t.Errorf("%s imports %s and also imports %s.\n"+
				"Together those can produce a *state.State without naming it "+
				"in any form this scan reads: reflect.New on a type witness, "+
				"or a pointer conversion through unsafe. Both yield the "+
				"nil-mapped, fully readable, never-erroring State that "+
				"TestNoPackageOutsideStateBuildsAStateByItsZeroValue exists "+
				"to count.\n"+
				"If this file genuinely needs both, the registry needs an "+
				"entry for what it builds and this check needs an exemption "+
				"with an owner -- not a silent pass.",
				relPath, statePkgPath, strings.Join(pkgs, " and "))
		}

		funcs := funcRanges(f)
		for _, name := range duplicateKeys(funcs) {
			t.Errorf("%s declares %s more than once, so both share one "+
				"registry key and the second inherits the first's "+
				"classification and any guard it names.\n"+
				"Two distinct receiver types can render the same key when "+
				"typeName cannot tell them apart -- a parenthesized receiver "+
				"is the known case. The key must distinguish them.",
				relPath, name)
		}

		ast.Inspect(f, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.StarExpr:
				// *state.State is how the type is passed around, and passing
				// one is not constructing one. Stop the walk here so the type
				// name underneath is not counted as a zero value.
				if isStateType(v.X, local) {
					return false
				}
			case *ast.SelectorExpr:
				// state.New, whether it is called here or merely named.
				//
				// Matched as a value rather than as a CallExpr's Fun: the
				// call form misses `var ctor = state.New` followed by
				// `ctor()`, which constructs a State with no CallExpr whose
				// Fun is state.New and no state.State selector anywhere. The
				// site recorded is where the function is *named*, which is
				// the place a reader can see what is being built.
				if isSelector(v, local, "New") {
					key := relPath + "::" + enclosing(fset, funcs, v.Pos())
					where := position(fset, relPath, v.Pos())
					// Two constructions under one key is the inheritance
					// failure itself, watched here rather than at any one
					// mechanism that can cause it.
					//
					// duplicateKeys, above, catches the case where two
					// DECLARATIONS render one key. It cannot catch this one:
					// a second state.New() inside an already-registered
					// function is a single declaration, so nothing renders
					// twice, and the map write below would silently overwrite
					// the first site. The second construction then inherits
					// the registered entry's classification and its named
					// guard without either having been assessed for it --
					// which is what the registry exists to prevent, and it
					// needs no keying gap at all to happen.
					//
					// Measured: `SideView = state.New()` added inside the
					// registered (*Session).FetchState, and a closure handing
					// out state.New() inside the registered dense
					// genesis.Build, both left every pin in this file green.
					if prev, dup := found[key]; dup {
						t.Errorf("%s constructs a state.State at %s and again "+
							"at %s, both keyed %s.\n"+
							"The second inherits the first's classification "+
							"and any guard it names. Give them distinct keys, "+
							"or register the site as one construction only if "+
							"one classification is true of both.",
							relPath, prev, where, key)
					}
					found[key] = where
					return true
				}
				// Every other mention of the *value* type is a zero-value
				// State, or a way of making one on demand.
				//
				// Matched by NAME rather than by enumerating the syntactic
				// forms that reach it. The enumeration was tried first and
				// was not complete -- `state.State{}`, `var s state.State`,
				// `new(state.State)` and a struct field were listed, while
				// `[]state.State`, `map[K]state.State`, `[N]state.State` and
				// `type X state.State` were not, and all four were measured
				// surviving it.
				//
				// Why matching the name is the right axis, derived from the
				// package's exported surface rather than from imagination:
				// exactly one exported function returns a *State without
				// already holding one, New. Clone is a method, so it
				// propagates rather than originates. There is no Decode,
				// Parse, From*, Load or Unmarshal. So every construction, in
				// any form anyone invents, must mention either `state.New` or
				// `state.State` -- two identifiers, and this scan keys on the
				// identifier and not the form.
				//
				// That makes RECOGNITION complete. It does not make this
				// clause complete, and an earlier version of this comment
				// claimed it did. Two gaps sit one step past recognition:
				// attribution, handled at the map write above; and the
				// StarExpr prune below this switch, which stops the walk at
				// `*state.State` because a pointer is how the type is passed
				// around. `(*state.State)(nil)` -- the standard type witness
				// handed to reflect -- is neither passing nor constructing,
				// and lives entirely inside that pruned region, so this
				// clause cannot see it. fabricationImports closes that
				// route at the import instead, for the reason the dot-import
				// check does: the escape is a capability, not a form, and
				// watching the capability cannot be evaded by picking a
				// different idiom.
				if isStateType(v, local) {
					zeroValue = append(zeroValue, position(fset, relPath, v.Pos()))
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree from %s: %v", root, err)
	}
	return found, zeroValue, parsed
}

// dirsTheWalkRefuses lists every directory skipDir turns the walk away from,
// as a path from the module root. It applies skipDir and reports what it
// refused, so a directory is named the moment the rule starts excluding it.
func dirsTheWalkRefuses(t *testing.T) []string {
	t.Helper()
	root := moduleRoot(t)
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			return nil
		}
		if skipDir(root, path) {
			out = append(out, rel(root, path))
			return fs.SkipDir
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree from %s: %v", root, err)
	}
	return out
}

// skipDir names the directories neither walk descends into. Shared by the
// scan and by its non-vacuity control so the two cannot disagree about what
// the tree is.
//
// The second rule is by path rather than by name -- see isNestedCheckout.
// root is passed so the walk's own root, which carries .git, is not skipped.
func skipDir(root, path string) bool {
	switch filepath.Base(path) {
	case ".git", "vendor", "testdata", "node_modules":
		return true
	}
	return path != root && isNestedCheckout(path)
}

// isNestedCheckout reports whether dir is the root of its own git repository or
// git worktree: it carries a .git entry, a directory for a clone and a file for
// a worktree.
//
// Such a directory is a separate checkout of these same sources sitting inside
// the module root. Read as part of the tree it doubles every construction site
// and then reports the duplicate as unregistered -- a guard crying wolf at an
// ordinary developer setup, which is how a guard teaches people to ignore it.
//
// The general form is deliberate. A worktree under .claude/worktrees is what
// produced the false failure, but naming that one directory would only wait for
// the next tool to choose another, and the property that matters is "separate
// checkout", not "known cache". Nothing this removes is source this module
// builds either: a checkout carries its own go.mod, so `go build ./...` already
// leaves it alone.
//
// Callers must exclude the walk's own root, which carries .git itself.
func isNestedCheckout(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

// isScannableGoFile is the file-level half of the same rule.
func isScannableGoFile(path string) bool {
	return strings.HasSuffix(path, ".go") && !strings.HasSuffix(path, "_test.go")
}

// expectedGoFiles lists what scanTree ought to have parsed, without parsing.
//
// It shares NOTHING with scanTree except moduleRoot: not skipDir, not the
// ".go"/"_test.go" test, not the self-exclusion path. Every rule below is
// written out again, deliberately duplicated.
//
// That is the opposite of the usual instinct, and the reason is that a control
// sharing a filter with the instrument cannot see that filter being wrong.
// Measured, each leaving every test in this file green: widening the shared
// file-level test with a path exclusion, and repointing the shared
// self-exclusion from core/state to sim, both shrink the scan and the count by
// the same amount, so an equality between them still holds. The second of
// those hid a real second sparse holder -- a new file under sim/ calling
// state.New() with no coverage record -- which is precisely the population
// change this whole instrument exists to report. Sharing moduleRoot is safe
// because a wrong root changes the relative keys, which the stale-entry test
// kills.
//
// The comparison is over the file SET rather than a count, so two errors that
// happen to cancel cannot pass either.
func expectedGoFiles(t *testing.T) []string {
	t.Helper()
	root := moduleRoot(t)
	var out []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" || name == "vendor" || name == "testdata" || name == "node_modules" {
				return fs.SkipDir
			}
			// Written out again rather than shared with skipDir, as every
			// other rule in this walk is: a directory below the root holding
			// its own .git entry is a nested repository or git worktree, a
			// separate checkout of these sources with its own go.mod that this
			// module does not build.
			if path != root {
				if _, serr := os.Stat(filepath.Join(path, ".git")); serr == nil {
					return fs.SkipDir
				}
			}
			if path == filepath.Join(root, "core", "state") {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			return nil
		}
		r, rerr := filepath.Rel(root, path)
		if rerr != nil {
			t.Fatalf("relativising %s: %v", path, rerr)
		}
		out = append(out, filepath.ToSlash(r))
		return nil
	})
	if err != nil {
		t.Fatalf("counting go files from %s: %v", root, err)
	}
	return out
}

// localNameFor returns the name this file refers to the given import path by,
// honouring an alias. A file that does not import it cannot construct one.
//
// The third result is the import form when it is one this scan cannot read:
// "." or "_". A dot import puts New and State into the file scope unqualified,
// so every matcher here -- all of which look for a selector `pkg.X` -- goes
// blind on that file while the file itself can still write `New()` and
// `var s State`. This used to return ("", false) for that case, which
// abandoned the file silently and left the escape open; the caller now fails
// instead. The check is on the import rather than on the expressions because
// that is where the escape is, and it is the one place it can be seen.
func localNameFor(f *ast.File, path string) (name string, ok bool, unreadable string) {
	for _, imp := range f.Imports {
		p, err := strconv.Unquote(imp.Path.Value)
		if err != nil || p != path {
			continue
		}
		if imp.Name != nil {
			if imp.Name.Name == "_" || imp.Name.Name == "." {
				return "", false, imp.Name.Name
			}
			return imp.Name.Name, true, ""
		}
		return "state", true, ""
	}
	return "", false, ""
}

// fabricationImports lists the packages this file imports that can fabricate
// a *state.State without naming it in a form the expression matchers read.
//
// This is the S2 escape, and it is closed at the import for the same reason
// the dot-import check is: the escape is a CAPABILITY, not a form.
//
//	var typ = reflect.TypeOf((*state.State)(nil)).Elem()
//	var Sparse = reflect.New(typ).Interface().(*state.State)
//
// builds, vets, and was measured leaving every pin in this file green. The
// type is named, so the matcher is not at fault -- `(*state.State)(nil)` is a
// type witness sitting inside the region the StarExpr prune skips, and the
// prune is right that a pointer is usually how the type is passed rather than
// made. Narrowing the prune would mean enumerating which pointer positions
// are conversions, which is the method that has now failed three times.
// `(*state.State)(unsafe.Pointer(...))` is the same region and the same
// answer, which is why both packages are named here.
//
// Zero non-test files in the tree import either of these together with the
// state package, so this costs nothing today. It is a tripwire, not a ban:
// a file that genuinely needs both should be registered and exempted with an
// owner, which is a decision someone makes rather than a silence.
//
// # What this does NOT catch, stated here because this is where the claim is
//
// An earlier version of this comment said watching the import "cannot be
// evaded by picking a different reflect idiom". True as written and wrong as
// read: a different IDIOM does not evade it, but two other things do, and
// both were measured leaving every pin in this file green.
//
//   - A dot or blank import of reflect. `import . "reflect"` followed by
//     `New(TypeOf((*state.State)(nil)).Elem())` names no package qualifier at
//     all. That one is CLOSED below, by accepting the unreadable-import form
//     as a hit -- the same hole this file already recognised and fixed for
//     the state package itself, twenty lines up, and then reintroduced here.
//   - A helper package. If package A imports reflect and never names a zycord
//     type, and package B imports A and state but not reflect, neither file
//     trips this and B receives a fabricated *state.State. That one is OPEN.
//     It is a PROPAGATION -- A constructs, B receives -- so following it
//     needs go/types rather than an AST walk, which is exactly what the limits
//     note on stateConstructionSites above already records.
//
// So this alarms the region rather than closing it, and it watches IMPORTS
// rather than USES: it cannot tell a fabrication from a legitimate reflect
// call, and it is blind to one routed through a package that does not import
// state.
func fabricationImports(f *ast.File) []string {
	var out []string
	for _, name := range []string{"reflect", "unsafe"} {
		// The unreadable form counts as a hit. A dot import is precisely how
		// a caller reaches reflect without naming it, so treating "cannot
		// read this import" as "not imported" would reopen the escape in the
		// check that exists to close it.
		if _, ok, unreadable := localNameFor(f, name); ok || unreadable != "" {
			out = append(out, name)
		}
	}
	return out
}

// isSelector reports whether e is exactly `pkg.name`.
func isSelector(e ast.Expr, pkg, name string) bool {
	sel, ok := e.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != name {
		return false
	}
	id, ok := sel.X.(*ast.Ident)
	return ok && id.Name == pkg
}

// isStateType reports whether e is the value type `pkg.State`. A *ast.StarExpr
// is deliberately not matched: `*state.State` is how the type is passed
// around, and passing one is not constructing one.
func isStateType(e ast.Expr, pkg string) bool { return isSelector(e, pkg, "State") }

type funcRange struct {
	name       string
	start, end token.Pos
}

// funcRanges lists the top-level functions of a file with their extents, so a
// construction can be attributed to the function containing it.
//
// The name is qualified by the receiver type -- "(*Session).FetchState", not
// "FetchState". A bare name is not unique within a file, and the collision is
// not cosmetic: a second sparse holder added as a method with the same name as
// a registered one produces a key that is already registered, so it inherits
// that entry's classification AND its named guard, and the pin reports nothing.
// A holder silently acquiring a guard it does not have is the exact failure
// this instrument exists to make impossible, so the key carries the receiver.
func funcRanges(f *ast.File) []funcRange {
	var out []funcRange
	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		out = append(out, funcRange{
			name:  qualifiedFuncName(fd),
			start: fd.Pos(),
			end:   fd.End(),
		})
	}
	return out
}

// qualifiedFuncName renders a declaration's name with its receiver type.
func qualifiedFuncName(fd *ast.FuncDecl) string {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return fd.Name.Name
	}
	return "(" + typeName(fd.Recv.List[0].Type) + ")." + fd.Name.Name
}

// typeName renders a receiver's type for use in a registry key.
//
// It does NOT claim two receivers cannot render the same, and an earlier
// version of this comment did. That claim was false twice over. Type
// parameters are deliberately discarded -- *Stack[T] renders "*Stack" --
// which is harmless only because Stack and Stack[T] cannot coexist, not
// because nothing is dropped. And the switch enumerates AST forms, not the
// Go type grammar: a parenthesized receiver, `func (a (*A)) M()`, is legal
// Go that compiles and vets clean, and it arrives as *ast.ParenExpr. Before
// that case existed, (*A).M and (*B).M in one file both rendered "(?).M" and
// collapsed to a single registry key, so two unregistered sparse holders were
// reported as one -- a contributor fixes the named site, re-runs, sees green,
// and the second holder stays unregistered. gofmt rejects the form, but this
// instrument does not get to assume a formatting gate ran.
//
// The lesson is in the caller, not here: an enumeration of forms has now been
// found incomplete three times, so correctness does not rest on this function
// being total. duplicateKeys below catches a collision whatever produced it.
func typeName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.StarExpr:
		return "*" + typeName(v.X)
	case *ast.ParenExpr:
		return typeName(v.X)
	case *ast.Ident:
		return v.Name
	case *ast.IndexExpr: // generic receiver; type parameters dropped
		return typeName(v.X)
	case *ast.IndexListExpr: // the same, several parameters
		return typeName(v.X)
	case *ast.SelectorExpr:
		return typeName(v.X) + "." + v.Sel.Name
	}
	return "?"
}

// duplicateKeys reports declarations in one file that render the same key.
//
// This is the form-INDEPENDENT half, and it is restored here after being
// deleted for having no separating input. It had one: two parenthesized
// receivers, which typeName rendered identically. The deletion traded the
// defence that catches the class for the one that catches the forms someone
// thought of, on an axis where the enumeration has been wrong in three
// consecutive rounds -- so this check exists precisely for the keying gaps
// nobody has thought of yet, and needs to know nothing about the AST to
// catch them.
//
// A collision means the second declaration inherits the first's registry
// entry, and with it a classification and a named guard it was never
// assessed for. That is the failure this whole instrument exists to prevent,
// so it is an error rather than a note.
func duplicateKeys(funcs []funcRange) []string {
	seen := make(map[string]int, len(funcs))
	for _, fr := range funcs {
		seen[fr.name]++
	}
	var out []string
	for name, n := range seen {
		if n > 1 {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

// enclosing names the function containing pos, receiver included. The key is
// the function rather than the line so that an edit elsewhere in the file does
// not invalidate the registry -- a key that moves on every unrelated change is
// a key nobody maintains.
//
// A construction outside every function is the one case with no name to use,
// and there can be several in one file -- two package-level vars, say. Those
// get the line, because sharing a key is how the second one inherits the
// first's classification and guard, and at file scope there is no receiver to
// tell them apart. Such a key does move when the file is edited above it;
// that is the cost of naming a site that has no name of its own.
func enclosing(fset *token.FileSet, funcs []funcRange, pos token.Pos) string {
	for _, fr := range funcs {
		if pos >= fr.start && pos < fr.end {
			return fr.name
		}
	}
	return "<file scope>:" + strconv.Itoa(fset.Position(pos).Line)
}

// takesTestingT reports whether fd has the signature `go test` requires of a
// test function: exactly one parameter, of type *testing.T.
func takesTestingT(fd *ast.FuncDecl) bool {
	if fd.Type.Params == nil || len(fd.Type.Params.List) != 1 {
		return false
	}
	star, ok := fd.Type.Params.List[0].Type.(*ast.StarExpr)
	if !ok {
		return false
	}
	sel, ok := star.X.(*ast.SelectorExpr)
	if !ok || sel.Sel == nil || sel.Sel.Name != "T" {
		return false
	}
	pkg, ok := sel.X.(*ast.Ident)
	return ok && pkg.Name == "testing"
}

func position(fset *token.FileSet, relPath string, pos token.Pos) string {
	return relPath + ":" + strconv.Itoa(fset.Position(pos).Line)
}

func rel(root, path string) string {
	r, err := filepath.Rel(root, path)
	if err != nil {
		return filepath.ToSlash(path)
	}
	return filepath.ToSlash(r)
}

// moduleRoot walks up from the test's working directory to the directory
// holding go.mod.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's working directory")
		}
		dir = parent
	}
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	// A small list in a failure message; sort so two runs read the same.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j] < out[j-1]; j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}
