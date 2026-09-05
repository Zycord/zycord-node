// The ingress cost contract, asked of the build rather than of a reviewer.
//
// The ingress-cost epic is not a bug. It is fifteen bugs that were one bug: the
// node had no unified notion of what a peer's bytes are allowed to cost, so
// every handler decided locally whether to score, dedup, rate-limit or serve,
// and every adversarial sweep found the next handler that had decided wrong.
// Patching them one at a time cannot converge — a new handler, or a reordering
// of the checks inside an old one, mints instance sixteen.
//
// The two checks here are what make the class closable instead of endless. The
// first says every outcome of every p2p handler names its price, so "nobody
// decided what this costs" is a build failure rather than something a later
// sweep discovers. The second says the specification's table still describes
// the code: docs/spec/wire.md §10.3 is total per (message kind × outcome), and
// a kind that gains a handler without gaining a row fails here.
//
// Neither is a test of behaviour, deliberately. Behaviour is pinned in
// node/p2p (TestACheapRefusalBuysNoWork and its siblings). These are pinned on
// the syntax tree and on the spec text, because what they guard is the thing a
// behavioural test cannot see: the *next* handler, which does not exist yet.
package wiring_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// costClasses is the closed set from wire.md §10.2. A fifth class is a spec
// change, not a code change, which is why this list is spelled here rather
// than derived from whatever the code happens to contain.
var costClasses = map[string]bool{
	"CostFree":     true,
	"CostScored":   true,
	"CostDeduped":  true,
	"CostBudgeted": true,
}

// TestEveryVerdictIsPriced: no outcome of a node/p2p handler leaves the cost
// class unstated.
//
// The property in one sentence: every `Verdict` composite literal in the
// package's production code sets `Cost` to one of the four classes of
// wire.md §10.2.
//
// `CostUnpriced` is the zero value on purpose, so the thing this test looks
// for is a *missing key* rather than a wrong value — and a missing key is
// exactly what a new refusal path looks like when its author did not think
// about the price. That is the failure mode of all fifteen findings: not one
// of them was a wrong cost class, every one of them was an absent one.
//
// Test files are excluded. A test constructs a Verdict to stand for one a
// handler produced, and requiring the field there would test the fixture.
func TestEveryVerdictIsPriced(t *testing.T) {
	fset := token.NewFileSet()
	var unpriced, wrong, unscored, charged, zeroValue []string

	forEachProductionFile(t, filepath.Join("..", "..", "node", "p2p"), fset, func(rel string, file *ast.File) {
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isVerdictLiteral(lit) {
				return true
			}
			where := rel + ":" + posLine(fset, lit.Pos())
			// An empty literal is a Verdict nobody filled in at all; it is
			// still an outcome, and it is still unpriced.
			var got, score string
			scored := false
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				key, ok := kv.Key.(*ast.Ident)
				if !ok {
					continue
				}
				switch key.Name {
				case "Cost":
					got = exprName(kv.Value)
				case "Score":
					scored = true
					score = exprName(kv.Value)
					if lit, ok := kv.Value.(*ast.BasicLit); ok {
						score = lit.Value
					}
				}
			}
			switch {
			case got == "":
				unpriced = append(unpriced, where)
			case !costClasses[got]:
				wrong = append(wrong, where+" = "+got)
			}
			// CostScored is a claim that the sender paid, and Score is the
			// payment. A literal that claims the class and names no score
			// charges nothing while reading as if it charged - a Free wearing
			// the one label the reader trusts, which is worse than an unpriced
			// one because nothing looks at it twice.
			if got == "CostScored" && !scored {
				unscored = append(unscored, where)
			}
			// And the mirror, which is the same defect read the other way: a
			// class that says the sender was not charged, charging. wire.md
			// §10.2 names duplicate gossip as the case - in flood gossip every
			// node receives every message several times by design, so a
			// `Deduped` verdict carrying ScoreInvalidMessage scores honest
			// peers down for the topology working correctly. Closing only the
			// Scored-with-no-Score direction leaves the harm §10.2 actually
			// describes wide open.
			if got != "" && got != "CostScored" && scored && !zeroScores[score] {
				charged = append(charged, where+": "+got+" with Score: "+score)
			}
			return true
		})
		// The composite literal is not the only way to build a Verdict, and
		// the check above sees only that one. `var v Verdict` is a Verdict at
		// CostUnpriced, and a handler that fills in Err and returns it has
		// produced an unpriced outcome that every check in this file used to
		// miss - which falsified the claim, made in Verdict.Cost's own doc
		// comment and in wire.md 10.2, that an unpriced outcome is a build
		// failure. The idiom is live in engine.go's dispatcher, so this is a
		// shape the package already uses rather than one invented to break it.
		zeroValue = append(zeroValue, unpricedZeroValues(rel, fset, file)...)
	})

	for _, w := range unpriced {
		t.Errorf("%s: a Verdict with no Cost. Every outcome names what the sender "+
			"paid (docs/spec/wire.md §10.2): Free, Scored, Deduped or Budgeted. "+
			"Free is a legitimate answer and needs a reason in §10.3's table; "+
			"what is not legitimate is leaving it unsaid.", w)
	}
	for _, w := range wrong {
		t.Errorf("%s: not one of the four classes in wire.md §10.2", w)
	}
	for _, w := range unscored {
		t.Errorf("%s: CostScored with no Score. Scored(n) is the only class "+
			"that terminates a flood of *distinct* messages (wire.md §10.2), "+
			"and n is what does it; a score of zero is CostFree and has to say "+
			"so, with a reason in §10.3's table.", w)
	}
	for _, w := range charged {
		t.Errorf("%s. Free, Deduped and Budgeted all say the sender's score "+
			"does not move; a non-zero Score under one of them charges anyway. "+
			"On a dedup path that is duplicate gossip scored down, which "+
			"wire.md §10.2 names as the thing not to do: in flood gossip every "+
			"node receives every message several times by design. Either the "+
			"class is wrong or the score is.", w)
	}
	for _, w := range zeroValue {
		t.Errorf("%s. A Verdict declared as its zero value carries "+
			"CostUnpriced, and filling in only Err leaves it there - the "+
			"composite-literal check above never sees it, so this is the one "+
			"construction that can reach a caller unpriced. Build it from a "+
			"priced literal, or assign one to it on every path.", w)
	}
}

// zeroScores are the score constants that are defined as zero, so that naming
// one under a class that does not charge is consistent rather than a
// contradiction. ScoreFutureBlock is zero on purpose (peerstore.go): whether a
// block is early is a fact about the receiver's clock (wire.md §9 rule 8), so
// the withheld paths pair CostFree with it and mean it.
var zeroScores = map[string]bool{
	"ScoreFutureBlock": true,
	"0":                true,
}

// TestTheWireCostTableIsTotal: the specification's per-(kind × outcome) table
// covers every message kind the protocol defines, and prices every outcome
// with a class the code can actually produce.
//
// Two directions, and both have been a real defect in this repository before,
// in other files: a spec that describes a table the code has outgrown, and code
// that reaches a state the spec never named. So this test compares the two sets
// rather than reading one of them.
//
// It is deliberately a *coverage* check and not an equality one. §10.3 has
// several rows per kind, the outcomes are prose, and matching prose to return
// statements would be a parser nobody trusts. What it can say soundly is: every
// kind has at least one row, every row names a valid class, and every class the
// p2p package uses appears in the table. A kind added to §3 with no row, and a
// class introduced in code with no row, both fail here.
func TestTheWireCostTableIsTotal(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("..", "..", "docs", "spec", "wire.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(spec)

	kinds := messageKinds(t, text)
	if len(kinds) != 9 {
		t.Fatalf("§3 lists %d message kinds, expected the 9 of protocol 1: %v", len(kinds), kinds)
	}

	table := section(t, text, "### 10.3", "### 10.4")
	rowKinds, rowClasses := costTableRows(table)

	for _, k := range kinds {
		if !rowKinds[k] {
			t.Errorf("§10.3 has no row for message kind %q. The table is total by "+
				"construction: a kind whose outcomes are not priced is the gap "+
				"the ingress-cost epic exists to close.", k)
		}
	}
	for c := range rowClasses {
		if !costClasses["Cost"+c] {
			t.Errorf("§10.3 prices an outcome %q, which is not one of the four "+
				"classes of §10.2", c)
		}
	}

	// And the other direction: a class the code produces but the table never
	// mentions would be an outcome the spec cannot describe.
	fset := token.NewFileSet()
	used := map[string]bool{}
	forEachProductionFile(t, filepath.Join("..", "..", "node", "p2p"), fset, func(_ string, file *ast.File) {
		ast.Inspect(file, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isVerdictLiteral(lit) {
				return true
			}
			for _, el := range lit.Elts {
				if kv, ok := el.(*ast.KeyValueExpr); ok {
					if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Cost" {
						used[exprName(kv.Value)] = true
					}
				}
			}
			return true
		})
	})
	if len(used) == 0 {
		t.Fatal("no Verdict cost classes found in node/p2p; this test would pass vacuously")
	}
	for c := range used {
		if !rowClasses[strings.TrimPrefix(c, "Cost")] {
			t.Errorf("node/p2p produces %s and §10.3's table never prices an "+
				"outcome that way", c)
		}
	}
}

// messageKinds reads the kind names out of §3's table, so that adding a kind
// there is what makes §10.3 owe a row — rather than this test carrying its own
// copy of the list, which is the duplication that lets the two drift.
func messageKinds(t *testing.T, text string) []string {
	t.Helper()
	body := section(t, text, "## 3. Message kinds", "### 3.1")
	re := regexp.MustCompile(`(?m)^\|\s*\d+\s*\|\s*` + "`" + `([a-z-]+)` + "`")
	var out []string
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		out = append(out, m[1])
	}
	sort.Strings(out)
	return out
}

// costTableRows returns the kinds §10.3 prices and the classes it prices them
// with. A row is `| kind | outcome | class |` with the kind and the class in
// backticks; the class may carry an argument, as `Scored(+1)` does.
func costTableRows(table string) (map[string]bool, map[string]bool) {
	kinds, classes := map[string]bool{}, map[string]bool{}
	row := regexp.MustCompile("(?m)^\\|\\s*`([a-z-]+)`\\s*\\|[^|]*\\|(.*)\\|\\s*$")
	class := regexp.MustCompile("`(Free|Scored|Deduped|Budgeted)")
	for _, m := range row.FindAllStringSubmatch(table, -1) {
		kinds[m[1]] = true
		for _, c := range class.FindAllStringSubmatch(m[2], -1) {
			classes[c[1]] = true
		}
	}
	return kinds, classes
}

// section returns the text between two headings.
func section(t *testing.T, text, from, to string) string {
	t.Helper()
	i := strings.Index(text, from)
	if i < 0 {
		t.Fatalf("wire.md has no %q heading", from)
	}
	rest := text[i+len(from):]
	j := strings.Index(rest, to)
	if j < 0 {
		t.Fatalf("wire.md has no %q heading after %q", to, from)
	}
	return rest[:j]
}

// forEachProductionFile parses the non-test .go files of one directory.
//
// Directory rather than package: `go list` would not see files behind build
// tags this machine does not satisfy, and the whole value of a syntax-tree
// check is that it sees what the compiler on one machine does not.
func forEachProductionFile(t *testing.T, dir string, fset *token.FileSet, visit func(rel string, file *ast.File)) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	seen := 0
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("parsing %s: %v", name, err)
		}
		seen++
		visit(filepath.Join(filepath.Base(dir), name), file)
	}
	if seen == 0 {
		t.Fatalf("no production Go files under %s; this check would pass vacuously", dir)
	}
}

// isVerdictLiteral reports whether a composite literal builds a p2p Verdict,
// written either bare (inside the package) or qualified (outside it).
func isVerdictLiteral(lit *ast.CompositeLit) bool {
	switch typ := lit.Type.(type) {
	case *ast.Ident:
		return typ.Name == "Verdict"
	case *ast.SelectorExpr:
		pkg, ok := typ.X.(*ast.Ident)
		return ok && pkg.Name == "p2p" && typ.Sel.Name == "Verdict"
	}
	return false
}

func exprName(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		return v.Sel.Name
	}
	return ""
}

func posLine(fset *token.FileSet, p token.Pos) string {
	return strconv.Itoa(fset.Position(p).Line)
}

// handlerKinds attributes every Verdict-producing function in engine.go to the
// message kind whose outcomes it decides.
//
// It is written out rather than derived because the derivation is the thing
// under test: `Handle`'s switch is what maps a kind to a handler, and a test
// that read the same switch it is checking would agree with any rewiring of
// it. The completeness guard below is what keeps this list from going stale —
// a kind in §3 with no entry here fails, so adding a kind forces the author
// through this map and through §10.3's rows.
var handlerKinds = map[string][]string{
	"OnHello":         {"hello"},
	"OnCertificate":   {"certificate"},
	"OnBlockAnnounce": {"block-announce"},
	// The same kind. OnBlockAnnounce is the no-identity wrapper and this is
	// where every verdict is actually built, exactly as HandleFrom is to
	// Handle.
	"OnBlockAnnounceFrom": {"block-announce"},
	"OnGetBlock":          {"get-block"},
	"OnBlock":             {"block"},
	// The same kind. The On*From refactor — which brought the peer identity in so
	// the key-epoch budget could be charged on the block-body path and a
	// per-connection budget ahead of the announce work check — moved the Verdict
	// construction and the work.Check off OnBlock/OnBlockChunk onto these
	// wrappers, mirroring OnBlockAnnounceFrom's relation to OnBlockAnnounce, so
	// this is where every block-path verdict is now built.
	"OnBlockFrom":      {"block"},
	"OnBlockChunk":     {"block"},
	"OnBlockChunkFrom": {"block"},
	"OnGetHeaders":     {"get-headers"},
	"OnGetPeers":       {"get-peers"},
	"OnPeers":          {"peers"},
	// Not a handler: a refusal shared by the two kinds whose replies are budgeted
	// — nothing else bounds a peer's request rate or the bytes it can make this
	// node send. It is named here rather than inlined into each of them because a
	// per-handler copy of a refusal is the mistake the ingress-cost epic exists to
	// stop, and the error below says naming it is the fix.
	"refuseUnbudgeted": {"get-block", "get-headers"},
}

// caseKinds maps the MessageKind constant a `case` clause of Handle names to
// the wire name §3 and §10.3 use for it.
var caseKinds = map[string]string{
	"KindHello":         "hello",
	"KindCertificate":   "certificate",
	"KindBlockAnnounce": "block-announce",
	"KindGetBlock":      "get-block",
	"KindBlock":         "block",
	"KindGetHeaders":    "get-headers",
	"KindHeaders":       "headers",
	"KindGetPeers":      "get-peers",
	"KindPeers":         "peers",
}

// TestEveryOutcomeAKindReachesHasARowOfItsClass: for each message kind, every
// cost class that kind's handler can actually return is a class §10.3 prices
// that kind with.
//
// The property in one sentence: §10.3 is total per *kind × class*, not merely
// per kind.
//
// This exists because TestTheWireCostTableIsTotal is not what its subject
// suggests, and the gap is exploitable rather than theoretical. That test asks
// two independent questions — does every kind have at least one row, and is
// every class the package uses named *somewhere* in the table — and neither
// relates a kind to its own classes. Measured: adding a `Budgeted` refusal to
// `OnGetHeaders`, whose only rows are `Free` and `Scored(invalid)`, left both
// checks green. A new refusal path landing in a handler with no row for what it
// charges is precisely the shape of all fifteen findings, so the check that
// closes the class has to be the one that fires on it.
//
// It remains a check on classes and not on prose outcomes. Matching a return
// statement to the English in an outcome cell would need a parser nobody
// trusts, and that is a deliberate limit: this catches a kind gaining a *class*
// it is not priced for, and it does not catch a second `Scored` outcome added
// under an existing `Scored` row.
//
// **There is a measured instance of that limit, and it is stated here rather
// than left abstract because a stated limit with an instance is a record and a
// stated limit without one reads as a caveat.** The node-wide key-epoch ceiling
// reached a `Budgeted` outcome on `block-announce` with no §10.3 row at all,
// and this test stayed green for as long as the row was missing — the kind
// already carried a `Budgeted` row for the per-identity layer, so the class was
// found priced. Deleting the row added by the fix and re-running leaves both
// this test and TestTheWireCostTableIsTotal green, which is the bypass driven
// rather than argued. It is not widened for it: the four `Scored(invalid)`
// returns of `OnBlockAnnounceFrom` collapse onto one row, so no arity check is
// available either, and an honest check needs the prose parser the paragraph
// above declines.
//
// One residual is worth naming because it was
// measured rather than reasoned: a row reading "`Free` today; MUST become
// `Budgeted`" names both classes, so the three served-reply kinds are already
// covered for `Budgeted` and a premature `Budgeted` refusal in one of them
// passes here. That is the price of recording the obligation in the table, and
// it is the right price - the obligation is the more valuable of the two. What
// it does mean is that the table can no longer be silent about what a kind
// charges.
func TestEveryOutcomeAKindReachesHasARowOfItsClass(t *testing.T) {
	spec, err := os.ReadFile(filepath.Join("..", "..", "docs", "spec", "wire.md"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(spec)

	for _, k := range messageKinds(t, text) {
		found := false
		for _, ks := range handlerKinds {
			for _, kk := range ks {
				found = found || kk == k
			}
		}
		for _, kk := range caseKinds {
			found = found || kk == k
		}
		if !found {
			t.Errorf("§3 lists message kind %q and nothing in this file attributes "+
				"a handler to it; a kind whose outcomes are unattributed cannot "+
				"be checked against §10.3", k)
		}
	}

	byKind := codeClassesByKind(t)
	if len(byKind) == 0 {
		t.Fatal("no Verdict cost classes attributed to any kind; this test would pass vacuously")
	}
	table := costTableClassesByKind(section(t, text, "### 10.3", "### 10.4"))

	for kind, classes := range byKind {
		for c := range classes {
			if !table[kind][strings.TrimPrefix(c, "Cost")] {
				t.Errorf("the %s handler can return %s and §10.3 has no row "+
					"pricing %s that way. Every outcome names what the sender "+
					"paid (wire.md §10.2); a refusal path added without its row "+
					"is instance sixteen of the ingress-cost epic.", kind, c, kind)
			}
		}
	}
}

// codeClassesByKind reads engine.go and returns, per message kind, the cost
// classes that kind's outcomes can carry.
//
// Two sources, because outcomes live in two places: the per-kind handlers, and
// the `case` clauses of Handle, which decide some outcomes inline rather than
// delegating (a malformed `headers` frame is one). Verdicts in Handle that are
// in no case clause — the handshake-required refusal and the unknown-kind
// refusal — belong to no kind in §3; §10.3 prices both on the `hello` row, as
// the protocol violations they are.
func codeClassesByKind(t *testing.T) map[string]map[string]bool {
	t.Helper()
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, filepath.Join("..", "..", "node", "p2p", "engine.go"), nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	out := map[string]map[string]bool{}
	add := func(kind, class string) {
		if class == "" {
			return // TestEveryVerdictIsPriced is what reports an unpriced literal.
		}
		if out[kind] == nil {
			out[kind] = map[string]bool{}
		}
		out[kind][class] = true
	}
	collect := func(n ast.Node, kinds []string) {
		ast.Inspect(n, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isVerdictLiteral(lit) {
				return true
			}
			for _, el := range lit.Elts {
				kv, ok := el.(*ast.KeyValueExpr)
				if !ok {
					continue
				}
				if key, ok := kv.Key.(*ast.Ident); ok && key.Name == "Cost" {
					for _, k := range kinds {
						add(k, exprName(kv.Value))
					}
				}
			}
			return true
		})
	}

	attributed := map[string]bool{}
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		if kinds, ok := handlerKinds[fn.Name.Name]; ok {
			attributed[fn.Name.Name] = true
			collect(fn.Body, kinds)
			continue
		}
		// HandleFrom and not Handle: the switch moved there when the peer identity
		// was plumbed through for the reply budget, and Handle is now a delegator
		// that mints no Verdict of its own. This name is the one that must follow the
		// switch, because a dispatcher this pass does not recognise reports every
		// case clause as an unattributed helper instead of pricing it.
		if fn.Name.Name != "HandleFrom" {
			// A helper that mints a Verdict decides an outcome too, and this
			// test cannot say whose. Naming it in handlerKinds is the fix.
			collect(fn.Body, nil)
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				if lit, ok := n.(*ast.CompositeLit); ok && isVerdictLiteral(lit) {
					t.Errorf("engine.go:%s builds a Verdict and is not attributed "+
						"to a message kind in handlerKinds; §10.3 is priced per "+
						"kind, so an outcome that belongs to no kind cannot be "+
						"checked against it", fn.Name.Name)
					return false
				}
				return true
			})
			continue
		}
		// Handle decides some outcomes itself rather than delegating, and they
		// belong to two different places. A verdict inside a `case KindX:`
		// clause is that kind's - a malformed `headers` frame is the live
		// example. The rest are the dispatcher's own: the handshake-required
		// refusal before the switch, and the unknown-kind refusal in its
		// `default:`. Those two are protocol violations rather than outcomes of
		// any kind in section 3, and section 10.3 prices both on the `hello`
		// row ("any other kind arriving before it"), so that is where they are
		// attributed. Collecting them against the empty kind list instead
		// drops them silently, which is the one thing this file must not do
		// with an outcome.
		covered := map[token.Pos]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			var kinds []string
			for _, e := range cc.List {
				if k, ok := caseKinds[exprName(e)]; ok {
					kinds = append(kinds, k)
				}
			}
			if len(kinds) == 0 {
				return true // the default clause: left to the dispatcher pass
			}
			for _, st := range cc.Body {
				collect(st, kinds)
				ast.Inspect(st, func(n ast.Node) bool {
					if lit, ok := n.(*ast.CompositeLit); ok && isVerdictLiteral(lit) {
						covered[lit.Pos()] = true
					}
					return true
				})
			}
			return false
		})
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			lit, ok := n.(*ast.CompositeLit)
			if !ok || !isVerdictLiteral(lit) || covered[lit.Pos()] {
				return true
			}
			collect(lit, []string{"hello"})
			return true
		})
	}
	for name := range handlerKinds {
		if !attributed[name] {
			t.Errorf("handlerKinds names %s and engine.go has no such function; "+
				"the attribution is stale", name)
		}
	}
	return out
}

// costTableClassesByKind returns §10.3's rows grouped by the kind they price.
func costTableClassesByKind(table string) map[string]map[string]bool {
	out := map[string]map[string]bool{}
	row := regexp.MustCompile("(?m)^[|] *`([a-z-]+)` *[|][^|]*[|](.*)[|] *$")
	class := regexp.MustCompile("`(Free|Scored|Deduped|Budgeted)")
	for _, m := range row.FindAllStringSubmatch(table, -1) {
		if out[m[1]] == nil {
			out[m[1]] = map[string]bool{}
		}
		for _, c := range class.FindAllStringSubmatch(m[2], -1) {
			out[m[1]][c[1]] = true
		}
	}
	return out
}

// isVerdictType reports whether a type expression names p2p.Verdict, written
// either bare (inside the package) or qualified (outside it).
func isVerdictType(e ast.Expr) bool {
	switch typ := e.(type) {
	case *ast.Ident:
		return typ.Name == "Verdict"
	case *ast.SelectorExpr:
		pkg, ok := typ.X.(*ast.Ident)
		return ok && pkg.Name == "p2p" && typ.Sel.Name == "Verdict"
	}
	return false
}

// unpricedZeroValues finds Verdicts built as a zero value and never replaced by
// a priced one.
//
// The three constructions that produce a CostUnpriced Verdict without writing a
// composite literal are `var v Verdict`, a named result of type Verdict, and
// `new(Verdict)`. Each is reported unless the variable is *wholly* assigned
// somewhere in the same function - `v = Verdict{...}` or `v = e.OnBlock(...)`,
// both of which route the value through a priced literal that the check above
// does see.
//
// Whole assignment is the exact distinction, and it is why engine.go's
// dispatcher is not a finding: `var v Verdict` there is assigned a complete
// verdict on every branch of its switch. Assigning a *field* - `v.Err = ...` -
// is what leaves Cost at its zero value, and a field assignment is not a whole
// assignment, so the escape is reported and the idiom is not.
func unpricedZeroValues(rel string, fset *token.FileSet, file *ast.File) []string {
	var out []string
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if !ok || fn.Body == nil {
			continue
		}
		declared := map[string]token.Pos{}
		if fn.Type.Results != nil {
			for _, f := range fn.Type.Results.List {
				if !isVerdictType(f.Type) {
					continue
				}
				for _, n := range f.Names {
					if n.Name != "_" {
						declared[n.Name] = n.Pos()
					}
				}
			}
		}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			switch v := n.(type) {
			case *ast.GenDecl:
				if v.Tok != token.VAR {
					return true
				}
				for _, sp := range v.Specs {
					vs, ok := sp.(*ast.ValueSpec)
					// A var with an initialiser is built from something, and
					// that something is a literal this file already checks.
					if !ok || len(vs.Values) > 0 || !isVerdictType(vs.Type) {
						continue
					}
					for _, n := range vs.Names {
						if n.Name != "_" {
							declared[n.Name] = n.Pos()
						}
					}
				}
			case *ast.CallExpr:
				// new(Verdict) has no name to track and no way to be priced at
				// its construction, so it is always reported.
				if id, ok := v.Fun.(*ast.Ident); ok && id.Name == "new" &&
					len(v.Args) == 1 && isVerdictType(v.Args[0]) {
					out = append(out, rel+":"+posLine(fset, v.Pos())+": new(Verdict)")
				}
			}
			return true
		})
		if len(declared) == 0 {
			continue
		}
		assigned := map[string]bool{}
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			as, ok := n.(*ast.AssignStmt)
			if !ok {
				return true
			}
			for _, lhs := range as.Lhs {
				id, ok := lhs.(*ast.Ident)
				if !ok {
					continue // a field assignment; it does not price the whole value
				}
				if _, tracked := declared[id.Name]; tracked {
					assigned[id.Name] = true
				}
			}
			return true
		})
		for name, pos := range declared {
			if !assigned[name] {
				out = append(out, rel+":"+posLine(fset, pos)+": "+fn.Name.Name+
					" builds a zero-value Verdict "+name+" and never assigns a priced one to it")
			}
		}
	}
	sort.Strings(out)
	return out
}
