package crypto_test

// Sum is blake3(tag ‖ p1 ‖ p2 ‖ …): the parts are concatenated with no length
// prefix. Two call sites under one tag therefore share a preimage — and, where
// the digest is a storage word, alias onto one state cell — whenever their
// concatenated payloads can be equal.
//
// For the fixed-width families that is impossible by construction. For the two
// families that take a variable-length part it holds only by arithmetic on
// constants that nothing enforced:
//
//   - the TagProtocolWord storage words, six of which are a bare label and
//     three of which are a label followed by an 8-byte index;
//   - the address derivations, which are a version byte followed by a payload.
//
// AddressFromPubKey imposes no *constant* version: core/validity evaluates it
// under a runtime version byte taken from the address being authorised (V4).
// The byte is still confined to 0x01 and 0x02 there, but by a rule in another
// package — deriveIssue rejects a non-user issuer, and CheckDerivation runs
// before CheckAuthorization — rather than by anything visible at the call. That
// is why the version is modelled below as a free byte rather than as its
// constant: this test prices what the call site fixes, and a guard held in a
// neighbouring package is not something a preimage scan should credit itself
// with.
//
// This test finds those call sites by parsing the tree and checks the property
// directly, so that the next label is checked by the compiler's own view of the
// source rather than by whoever reviews the diff.

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// arrayWidths prices `x[:]` where x is a parameter of the enclosing function.
// Only the fixed-width array types the two families in scope actually pass are
// listed. An unlisted type is a scan failure, never a guessed width.
var arrayWidths = map[string]int{
	"Address":   32,
	"Hash":      32,
	"PubKey":    32,
	"Signature": 64,
}

// payloadShape is what one call site can present to blake3: a maximal run of
// compile-time-fixed bytes followed by a run of freely chosen ones.
//
// Free bytes are modelled as fully arbitrary. That over-approximates — a ring
// index is bounded in practice — so a clean result here is sound, while a
// reported collision may be unreachable rather than exploitable. The direction
// is deliberate: this is a tripwire on the preimage, not a reachability
// analysis.
type payloadShape struct {
	label []byte
	free  int
	where string
}

func (p payloadShape) total() int { return len(p.label) + p.free }

// canShareAPreimage reports whether two shapes admit a common byte string.
//
// payload = label ‖ x with |x| = free. A common string needs equal totals, and
// then the shorter label must be a prefix of the longer; the leftover fixed
// bytes are always covered by the shorter site's free tail, because equal
// totals make that leftover exactly the difference of the two free widths.
func canShareAPreimage(a, b payloadShape) bool {
	if a.total() != b.total() {
		return false
	}
	short, long := a.label, b.label
	if len(short) > len(long) {
		short, long = long, short
	}
	return string(long[:len(short)]) == string(short)
}

// part is one priced argument: either a run of fixed bytes or a free width.
type part struct {
	fixed []byte
	free  int
}

type srcFile struct {
	rel  string
	fset *token.FileSet
	ast  *ast.File
}

func (f srcFile) at(n ast.Node) string {
	p := f.fset.Position(n.Pos())
	return f.rel + ":" + strconv.Itoa(p.Line)
}

// TestNoTwoVariableLengthHashCallSitesCanShareAPreimage is what enforces that
// arithmetic.
//
// LIMITS — what this enumeration cannot see, stated beside the number it
// produces, per PROTOCOL.md rule 21. The scan is syntactic and finds sites by
// the identifiers TagProtocolWord, TagAddr, DeriveAddress and AddressFromPubKey
// appearing in the source. It is therefore blind to:
//
//   - a tag or a derivation reached through a function-valued variable, an
//     interface method, or a constant aliased under another name. The scan does
//     fail loudly on the near miss — every syntactic occurrence of those four
//     identifiers must end up inside a site it priced — but an occurrence that
//     never mentions the name is invisible to it;
//   - and the sharp case of that, because it defeats both guards at once: a
//     NEW tag constant carrying a DUPLICATE VALUE. A nineteenth constant
//     TagCoinbaseWord = "zcd/protoword/v1", hashed over the label
//     "coinbase_addr_pending", names a cell byte-identical to
//     pendingCoinbaseWord("coinbase_addr", 7453010313414537311) — and mentions
//     none of the four identifiers above, so assertEveryOccurrenceWasPriced
//     structurally cannot fire on it. The check that should catch it instead is
//     TestDomainSeparationIsTotal, and it cannot: its `tags` slice is a
//     hand-maintained list of eighteen with no completeness assertion, so a
//     nineteenth tag is simply absent from it. That is the same hand-table
//     failure this test refuses for labels, still standing for tags. The two
//     guards each cover the other's blind spot on paper and neither does in
//     fact;
//   - anything in a _test.go file. Test-only derivations are not consensus
//     preimages, and are excluded on purpose;
//   - the other sixteen domain tags. Those are either single-call-site (a lone
//     variable-length payload under its own tag is injective on its own) or
//     fixed-width, with one exception worth naming: TagPoW covers two different
//     call sites — types.Header.PoWSeed and the Dev engine's work function —
//     whose payloads are both unpriceable variable blobs. Nothing compares those
//     two digests to each other, so the overlap has no consequence, but this
//     test does not cover it;
//   - reachability. A pair reported as sharing a preimage may be unreachable,
//     because free bytes are modelled as arbitrary (see payloadShape).
//
// And what it deliberately does NOT do: it does not fail on every new label. A
// seventh TagProtocolWord label that cannot collide passes, which is the correct
// answer. It fails on one that can — which is what the six-label-plus-two-family
// arithmetic was silently relying on a diff review to notice.
func TestNoTwoVariableLengthHashCallSitesCanShareAPreimage(t *testing.T) {
	sc := newScan(t)

	proto := sc.protocolWordShapes()
	addrs := sc.addressShapes()
	sc.assertEveryOccurrenceWasPriced()

	// Anti-vacuity. Stated as lower bounds rather than equalities: a bound
	// survives someone adding a label, and an equality pinned from this same
	// scan would only echo it (rule 21).
	var fixedCount, indexedCount int
	for _, s := range proto {
		if s.free == 0 {
			fixedCount++
		} else {
			indexedCount++
		}
	}
	if fixedCount < 6 {
		t.Fatalf("the scan found %d bare-label TagProtocolWord sites, want at least 6: "+
			"it stopped seeing call sites that are in the tree", fixedCount)
	}
	if indexedCount < 2 {
		t.Fatalf("the scan found %d indexed TagProtocolWord sites, want at least 2: "+
			"it stopped seeing call sites that are in the tree", indexedCount)
	}
	if len(addrs) < 2 {
		t.Fatalf("the scan found %d address derivations, want at least 2: "+
			"it stopped seeing call sites that are in the tree", len(addrs))
	}

	report(t, "TagProtocolWord", proto)
	report(t, "address derivation", addrs)

	assertPairwiseDisjoint(t, "TagProtocolWord", proto)
	assertPairwiseDisjoint(t, "address derivation", addrs)
}

func report(t *testing.T, family string, shapes []payloadShape) {
	t.Helper()
	for _, s := range shapes {
		t.Logf("%s: %d bytes = %q(%d) + %d free  [%s]",
			family, s.total(), s.label, len(s.label), s.free, s.where)
	}
}

func assertPairwiseDisjoint(t *testing.T, family string, shapes []payloadShape) {
	t.Helper()
	for i := 0; i < len(shapes); i++ {
		for j := i + 1; j < len(shapes); j++ {
			if canShareAPreimage(shapes[i], shapes[j]) {
				t.Errorf("%s: %s and %s can present the same %d-byte payload to Sum, "+
					"so they name one cell: %q+%d free against %q+%d free",
					family, shapes[i].where, shapes[j].where, shapes[i].total(),
					shapes[i].label, shapes[i].free, shapes[j].label, shapes[j].free)
			}
		}
	}
}

// ---- the scan ----

type scan struct {
	t     *testing.T
	files []srcFile
	// priced records every identifier occurrence the scan consumed, so that an
	// occurrence it did not consume can be reported rather than skipped.
	priced map[*ast.Ident]bool
}

// watched are the identifiers whose every occurrence must land inside a priced
// site. Their declarations are recorded first and then excused.
var watched = map[string]bool{
	"TagProtocolWord":   true,
	"TagAddr":           true,
	"DeriveAddress":     true,
	"AddressFromPubKey": true,
}

func newScan(t *testing.T) *scan {
	t.Helper()
	sc := &scan{t: t, priced: map[*ast.Ident]bool{}}
	root := repoRoot(t)

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "node_modules":
				return fs.SkipDir
			}
			if path != root && isNestedCheckout(path) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		sc.files = append(sc.files, srcFile{rel: filepath.ToSlash(rel), fset: fset, ast: f})
		return nil
	})
	if err != nil {
		t.Fatalf("walking the tree: %v", err)
	}
	if len(sc.files) == 0 {
		t.Fatal("the scan parsed no files: it is measuring nothing")
	}

	// Declarations are occurrences too, and are excused up front.
	for _, f := range sc.files {
		for _, decl := range f.ast.Decls {
			switch d := decl.(type) {
			case *ast.FuncDecl:
				if watched[d.Name.Name] {
					sc.priced[d.Name] = true
				}
			case *ast.GenDecl:
				for _, spec := range d.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for _, n := range vs.Names {
						if watched[n.Name] {
							sc.priced[n] = true
						}
					}
				}
			}
		}
	}
	return sc
}

// isNestedCheckout reports whether dir is the root of its own git repository or
// git worktree: it carries a .git entry, a directory for a clone and a file for
// a worktree.
//
// Such a directory is a second copy of these sources parked inside the module
// root, and a scan that reads it as part of the tree sees every call site twice
// — so every shape collides with its own duplicate and this test reports a
// preimage collision that does not exist. A worktree under .claude/worktrees is
// what produced that false failure, but the rule is written against .git rather
// than against that one name because the next tool will choose a different
// directory and the property being tested is "is this a separate checkout", not
// "is this someone's cache". Nothing this skips is source the module builds
// either: a nested checkout carries its own go.mod, so `go build ./...` already
// leaves it alone.
//
// The caller must exclude the walk's own root, which carries .git itself.
func isNestedCheckout(dir string) bool {
	_, err := os.Stat(filepath.Join(dir, ".git"))
	return err == nil
}

func repoRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the working directory: the scan has no tree to walk")
		}
		dir = parent
	}
}

// visit calls fn for every call expression in the tree, with the innermost
// enclosing function declaration (nil for a package-level initialiser — which
// is where every bare TagProtocolWord label actually lives).
func (sc *scan) visit(fn func(f srcFile, enclosing *ast.FuncDecl, call *ast.CallExpr)) {
	for _, f := range sc.files {
		for _, decl := range f.ast.Decls {
			var enclosing *ast.FuncDecl
			if fd, ok := decl.(*ast.FuncDecl); ok {
				enclosing = fd
			}
			ast.Inspect(decl, func(n ast.Node) bool {
				if call, ok := n.(*ast.CallExpr); ok {
					fn(f, enclosing, call)
				}
				return true
			})
		}
	}
}

// calleeIdent returns the identifier naming the callee, for both `f(...)` and
// `pkg.f(...)`.
func calleeIdent(call *ast.CallExpr) *ast.Ident {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun
	case *ast.SelectorExpr:
		return fun.Sel
	}
	return nil
}

func argIdent(e ast.Expr) *ast.Ident {
	switch x := e.(type) {
	case *ast.Ident:
		return x
	case *ast.SelectorExpr:
		return x.Sel
	}
	return nil
}

// ---- TagProtocolWord ----

func (sc *scan) protocolWordShapes() []payloadShape {
	var out []payloadShape
	sc.visit(func(f srcFile, enclosing *ast.FuncDecl, call *ast.CallExpr) {
		for i, arg := range call.Args {
			id := argIdent(arg)
			if id == nil || id.Name != "TagProtocolWord" {
				continue
			}
			sc.priced[id] = true
			rest := make([]ast.Expr, 0, len(call.Args)-1)
			rest = append(rest, call.Args[:i]...)
			rest = append(rest, call.Args[i+1:]...)
			out = append(out, sc.shapesFor(f, enclosing, call, rest)...)
		}
	})
	sortShapes(out)
	return out
}

// shapesFor prices a payload, expanding one level of indirection when a part is
// an unresolved parameter of the enclosing function: core/types reaches Sum
// through helpers whose label is a parameter, and a scan that only matched
// literals at the Sum call would not see those two families at all.
func (sc *scan) shapesFor(f srcFile, enclosing *ast.FuncDecl, call *ast.CallExpr, parts []ast.Expr) []payloadShape {
	priced := make([]part, len(parts))
	for i, p := range parts {
		pr, unresolved, ok := priceArg(p, enclosing)
		if ok {
			priced[i] = pr
			continue
		}
		if unresolved == "" || enclosing == nil || !isParam(enclosing, unresolved) {
			sc.t.Fatalf("%s: the scan cannot price argument %d of this hash call. "+
				"It must not guess a width: either write the argument in a form the "+
				"scan prices, or extend the scan", f.at(call), i)
		}
		return sc.expand(f, enclosing, call, parts, i, unresolved)
	}
	return []payloadShape{assemble(sc.t, f.at(call), priced)}
}

// expand re-prices the payload once per caller of the enclosing function,
// substituting each caller's argument for the parameter the scan could not
// resolve. Callers are matched by simple name across the whole tree, which
// over-approximates if two packages share a helper name — it can only add
// shapes to the check, never hide one.
func (sc *scan) expand(f srcFile, enclosing *ast.FuncDecl, call *ast.CallExpr, parts []ast.Expr, idx int, param string) []payloadShape {
	pos := paramIndex(enclosing, param)
	var out []payloadShape
	sc.visit(func(cf srcFile, _ *ast.FuncDecl, c *ast.CallExpr) {
		id := calleeIdent(c)
		if id == nil || id.Name != enclosing.Name.Name || pos >= len(c.Args) {
			return
		}
		priced := make([]part, len(parts))
		for i, p := range parts {
			src := p
			if i == idx {
				src = c.Args[pos]
			}
			pr, _, ok := priceArg(src, nil)
			if !ok {
				sc.t.Fatalf("%s: this call reaches the hash at %s with an argument the "+
					"scan cannot price. It must not guess a width", cf.at(c), f.at(call))
			}
			priced[i] = pr
		}
		out = append(out, assemble(sc.t, cf.at(c), priced))
	})
	if len(out) == 0 {
		sc.t.Fatalf("%s: the hash payload comes from a parameter with no caller the scan "+
			"could find, so nothing here is checked", f.at(call))
	}
	return out
}

// assemble folds priced parts into a shape: fixed bytes accumulate into the
// label until the first free part, and everything after it is free.
func assemble(t *testing.T, where string, parts []part) payloadShape {
	var label []byte
	free := 0
	for _, p := range parts {
		if p.fixed != nil {
			if free > 0 {
				t.Fatalf("%s: fixed bytes follow a variable-width part. The shape model "+
					"here is label ‖ free-tail and cannot describe this call", where)
			}
			label = append(label, p.fixed...)
			continue
		}
		free += p.free
	}
	return payloadShape{label: label, free: free, where: where}
}

// priceArg prices one argument. It returns ok=false with the name of an
// unresolved identifier when the value comes from a parameter, so the caller can
// decide whether to expand or to fail.
func priceArg(e ast.Expr, enclosing *ast.FuncDecl) (part, string, bool) {
	switch x := e.(type) {
	case *ast.BasicLit:
		if x.Kind != token.STRING {
			return part{}, "", false
		}
		s, err := strconv.Unquote(x.Value)
		if err != nil {
			return part{}, "", false
		}
		return part{fixed: []byte(s)}, "", true

	case *ast.CallExpr:
		// []byte(expr) is a conversion, not a call: price what it converts.
		if at, ok := x.Fun.(*ast.ArrayType); ok && at.Len == nil {
			if id, ok := at.Elt.(*ast.Ident); ok && id.Name == "byte" && len(x.Args) == 1 {
				return priceArg(x.Args[0], enclosing)
			}
		}
		// ssz.Uint64(v) is eight freely chosen bytes.
		if sel, ok := x.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "Uint64" {
			return part{free: 8}, "", true
		}
		return part{}, "", false

	case *ast.SliceExpr:
		id, ok := x.X.(*ast.Ident)
		if !ok || enclosing == nil {
			return part{}, "", false
		}
		if w, ok := declaredArrayWidth(enclosing, id.Name); ok {
			return part{free: w}, "", true
		}
		return part{}, "", false

	case *ast.Ident:
		return part{}, x.Name, false
	}
	return part{}, "", false
}

func isParam(fn *ast.FuncDecl, name string) bool { return paramIndex(fn, name) >= 0 }

func paramIndex(fn *ast.FuncDecl, name string) int {
	if fn.Type.Params == nil {
		return -1
	}
	i := 0
	for _, field := range fn.Type.Params.List {
		for _, n := range field.Names {
			if n.Name == name {
				return i
			}
			i++
		}
		if len(field.Names) == 0 {
			i++
		}
	}
	return -1
}

// declaredArrayWidth prices `x[:]` from x's declared parameter type, using the
// table above. A type that is not in the table is not a width the scan knows.
func declaredArrayWidth(fn *ast.FuncDecl, name string) (int, bool) {
	if fn.Type.Params == nil {
		return 0, false
	}
	for _, field := range fn.Type.Params.List {
		for _, n := range field.Names {
			if n.Name != name {
				continue
			}
			id := argIdent(field.Type)
			if id == nil {
				return 0, false
			}
			w, ok := arrayWidths[id.Name]
			return w, ok
		}
	}
	return 0, false
}

// ---- address derivation ----

// addressShapes prices every production address derivation. A derivation's
// identity is the function that performs it, so the three callers of
// AddressFromPubKey are one shape and not three.
func (sc *scan) addressShapes() []payloadShape {
	byKey := map[string]payloadShape{}

	sc.visit(func(f srcFile, enclosing *ast.FuncDecl, call *ast.CallExpr) {
		// The TagAddr hash inside DeriveAddress is the derivation itself; its
		// payload is whatever the call sites below supply, and is priced there.
		if enclosing != nil && enclosing.Name.Name == "DeriveAddress" {
			for _, arg := range call.Args {
				if aid := argIdent(arg); aid != nil && aid.Name == "TagAddr" {
					sc.priced[aid] = true
				}
			}
		}

		id := calleeIdent(call)
		if id == nil {
			return
		}
		switch id.Name {
		case "AddressFromPubKey":
			sc.priced[id] = true
			// The shape comes from the signature — (version byte, pub PubKey) —
			// and not from the arguments, which are runtime values at two of the
			// three call sites.
			byKey["crypto.AddressFromPubKey"] = payloadShape{
				free:  1 + arrayWidths["PubKey"],
				where: "crypto.AddressFromPubKey",
			}
		case "DeriveAddress":
			sc.priced[id] = true
			if enclosing != nil && enclosing.Name.Name == "AddressFromPubKey" {
				// The wrapper itself, already accounted for by its signature.
				return
			}
			if len(call.Args) == 0 {
				sc.t.Fatalf("%s: DeriveAddress called with no version byte", f.at(call))
			}
			// The version byte is modelled as one free byte rather than as its
			// constant: core/validity supplies it at runtime from the address
			// being authorised, so no constant separates these domains.
			shapes := sc.shapesFor(f, enclosing, call, call.Args[1:])
			for _, s := range shapes {
				s.free += 1
				name := f.at(call)
				if enclosing != nil {
					name = enclosing.Name.Name + " (" + name + ")"
				}
				s.where = name
				byKey[name+"/"+strconv.Itoa(s.total())] = s
			}
		}
	})

	out := make([]payloadShape, 0, len(byKey))
	for _, s := range byKey {
		out = append(out, s)
	}
	sortShapes(out)
	return out
}

// ---- completeness ----

// assertEveryOccurrenceWasPriced turns the scan's blind spot into a failure.
// Every syntactic occurrence of a watched identifier must have been consumed by
// a site the scan priced; one that was not means the tree reaches these hashes
// by a route this scan does not model, and the disjointness result above is not
// about the whole tree.
func (sc *scan) assertEveryOccurrenceWasPriced() {
	for _, f := range sc.files {
		ast.Inspect(f.ast, func(n ast.Node) bool {
			id, ok := n.(*ast.Ident)
			if !ok || !watched[id.Name] || sc.priced[id] {
				return true
			}
			sc.t.Errorf("%s: %s is reached here by a route the scan does not price, so the "+
				"preimage-disjointness result does not cover it", f.at(id), id.Name)
			return true
		})
	}
}

func sortShapes(s []payloadShape) {
	sort.Slice(s, func(i, j int) bool {
		if s[i].total() != s[j].total() {
			return s[i].total() < s[j].total()
		}
		return string(s[i].label) < string(s[j].label)
	})
}
