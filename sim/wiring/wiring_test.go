// Package wiring asks the build a question nobody remembers to ask: is this
// connected to anything?
//
// Twice now a piece of Zycord has been correct, complete, tested, and called
// from nowhere. `node/sync` validated header chains and had its own adversarial
// suite while no code path ever invoked it, so a node that fell behind simply
// never caught up ([I4-H2](../../docs/adversarial/I4.md)). `mempool.Readmit`
// was written to return certificates from an abandoned branch and had zero
// callers, so a transaction confirmed and then reorged out vanished from the
// chain and every mempool at once ([I5](../../docs/adversarial/I5.md)).
//
// Neither is visible to a unit test, by construction: a unit test's subject is a
// piece, and both pieces worked. Both are visible to this, which is one pass over
// the syntax tree.
//
// The point is not the sophistication of the tool. It is that the question moves
// from whoever happens to notice to the build — the same move as mechanising
// `Read`'s borrow rule, applied to wiring instead of locking.
package wiring_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// allowed lists exported names that are legitimately unreferenced today.
//
// Every entry needs a reason. An allowlist without reasons becomes a place to
// put things that are failing, which is how a check stops being one.
var allowed = map[string]string{
	// Called by encoding/json through reflection, which no syntax tree shows.
	"U256.MarshalJSON":   "satisfies json.Marshaler; invoked reflectively by encoding/json",
	"U256.UnmarshalJSON": "satisfies json.Unmarshaler; invoked reflectively by encoding/json",

	// Public API for third-party wallets rather than for this repository.
	// Zycord's own wallet does not call it because Era 0's supply cap puts the
	// V6 overflow bound out of reach of any amount it can construct — but the
	// consensus rule exists, so a wallet that wants to warn before signing needs
	// somewhere to ask. Deleting it would remove a documented helper from the
	// only public surface an independent implementation has.
	"MaxDeltaHeadroom": "exported for third-party wallets; unreachable at Era 0 supply, see core/validity V6",
}

// allowedFields is `allowed` for exported struct fields, and carries the same
// rule: every entry needs a reason.
//
// It is empty, and that is a measurement rather than an oversight — but the
// measurement has conditions, and there are two live classes it will not stay
// empty against forever.
//
// **Reflective reads.** A struct handed whole to `encoding/json` has *every*
// exported field read at run time, tagged or not: the tag renames a field, it
// does not decide whether the codec visits it. Two structs in `scanned` are
// passed whole to the codec — `core/params.Params` (Parse's
// json.Decoder.Decode) and `node/p2p.Peer` (peerstore's json.Unmarshal and
// json.MarshalIndent over []Peer). With this change applied they have 53 and 6
// exported fields, and ordinary Go reads all 59 somewhere in the repository, so
// no entry is needed. In the tree this check was written against it was 53 and
// 7, because Peer.Attempts was the seventh — and that field is why this map is
// not simply "tagged fields are exempt". Both structs happen to tag every
// exported field they have, so the tagged count and the exported count coincide
// at either tree; the surface is the exported count. Nothing else in core/ or
// node/ reflects over a struct's *values*. An earlier version of this comment
// offered `grep -rn reflect core/ node/` as the proof and it is not one: that
// command matches 45 lines in 14 files, and one of them is a genuine reflective
// struct walk — node/p2p/withhold_internal_test.go does
// reflect.TypeOf(withheldBlock{}) at :42, NumField at :44 and Field(i) at :45,
// and FieldByName at :73. It walks the *type*, reading field names and types to
// prove no field can hold a decoded block, and never touches a value: no
// reflect.ValueOf, no .Interface(). So it reads no field in this check's sense.
// The claim that survives is the narrower one, and core/ssz states its half in
// its own package comment ("There is no reflection here and no code
// generation").
//
// A json tag is therefore not itself treated as a reference, which is the
// deliberate half: `Peer.Attempts` was tagged, marshalled into peers.json on
// every save, and read by nothing — the tag moved a number to disk and no rule,
// test, document or UI asked for it back.
//
// **Whole-struct reads with no selector anywhere.** `a == b` and `map[T]V`
// compare or hash every field of T, and neither writes a field name down. A
// field added to such a struct is genuinely read and this check will still call
// it unread. Measured on that same tree with go/types over every package in the
// module (external test packages included), nine exported structs in `scanned`
// are read wholesale somewhere: core/types.Slot — the only struct used as a map
// key anywhere in the repository, written as one on 14 source lines in core/
// and node/ (26 across the whole tree) and compared at 10 sites — plus
// core/types.Read, core/types.Write, core/state.SeenEntry, core/u256.U256,
// node/chain.Stats and node/p2p.GetBlock, all compared, and core/params.Params
// and node/p2p.Peer, reflective as above. Adding a field to any of them and
// running this check reports it — verified by adding `Shard uint8` to
// types.Slot and watching the check name `Slot.Shard`.
//
// u256.U256 is on the list for the mechanism rather than for any field: it has
// no exported field at all, so it cannot produce this failure until one is
// added. It is listed because that is exactly when someone would need to know.
//
// That is what this map is for, and it is why it exists rather than the check
// simply exempting those structs: an entry has to say which mechanism reads the
// field, so the next reader can check the claim instead of trusting it.
//
// The other entry a future reader is likely to need is a consensus parameter
// that `Params.ConsensusRoot` commits to and no rule evaluates — but that is a
// finding too, so argue it here rather than assume it.
var allowedFields = map[string]string{}

// scanned are the trees this applies to. cmd/, wallet/ and sim/ are entry
// points and helpers where an unreferenced export is ordinary.
var scanned = []string{"core", "node"}

func TestNoUnreferencedExports(t *testing.T) {
	root := filepath.Join("..", "..")

	defined := map[string]token.Position{} // name -> where
	used := map[string]bool{}
	fset := token.NewFileSet()

	walkGoFiles(t, root, fset, func(rel string, file *ast.File) {
		// Definitions: exported top-level declarations in the scanned trees,
		// excluding tests (a test-only export is a different smell).
		if inScanned(rel) && !strings.HasSuffix(rel, "_test.go") {
			for _, d := range file.Decls {
				switch decl := d.(type) {
				case *ast.FuncDecl:
					name := decl.Name.Name
					if decl.Recv != nil {
						name = receiverName(decl.Recv) + "." + name
					}
					if ast.IsExported(decl.Name.Name) {
						defined[name] = fset.Position(decl.Pos())
					}
				case *ast.GenDecl:
					for _, spec := range decl.Specs {
						switch sp := spec.(type) {
						case *ast.TypeSpec:
							if ast.IsExported(sp.Name.Name) {
								defined[sp.Name.Name] = fset.Position(sp.Pos())
							}
						case *ast.ValueSpec:
							for _, n := range sp.Names {
								if ast.IsExported(n.Name) {
									defined[n.Name] = fset.Position(n.Pos())
								}
							}
						}
					}
				}
			}
		}

		// Uses: every identifier anywhere in the module, plus interface method
		// names (a method reached only through an interface is still named by
		// the interface that declares it).
		//
		// A declaration's own name is NOT a use of itself. Missing that made the
		// first version of this check report nothing, ever: `ast.Inspect` visits
		// the Ident in `func (p *Pool) Readmit(...)`, so every definition marked
		// itself used and the whole pass was decoration. It was caught by
		// planting a deliberately unreferenced export and watching the check stay
		// green — the standing question, asked of the instrument built to answer
		// the standing question.
		declared := declNamePositions(file)
		ast.Inspect(file, func(n ast.Node) bool {
			switch x := n.(type) {
			case *ast.SelectorExpr:
				used[x.Sel.Name] = true
				markQualified(used, x)
			case *ast.Ident:
				if declared[x.Pos()] {
					return true
				}
				used[x.Name] = true
			case *ast.InterfaceType:
				if x.Methods == nil {
					return true
				}
				for _, m := range x.Methods.List {
					for _, nm := range m.Names {
						used[nm.Name] = true
					}
				}
			}
			return true
		})
	})

	// Anti-vacuity: the scan must have found a real corpus. A walk that parsed
	// nothing reports no unreferenced exports and looks identical to success.
	if len(defined) < 200 {
		t.Fatalf("only %d exported declarations found in %v: the scan is not "+
			"reaching the code and its silence means nothing", len(defined), scanned)
	}
	if len(used) < 500 {
		t.Fatalf("only %d identifiers seen across the module: the use-scan is "+
			"not reaching the code", len(used))
	}

	var orphans []string
	for name, pos := range defined {
		short := name
		if i := strings.LastIndex(name, "."); i >= 0 {
			short = name[i+1:]
		}
		if used[short] || used[name] {
			continue
		}
		if _, ok := allowed[name]; ok {
			continue
		}
		orphans = append(orphans, name+"  ("+trimPos(pos.String())+")")
	}
	sort.Strings(orphans)

	if len(orphans) > 0 {
		t.Errorf("%d exported declarations in %v are referenced by nothing, "+
			"anywhere in the module — including tests:\n  %s\n\n"+
			"Each is either dead, or a piece that works and is wired to nothing. "+
			"The second kind has shipped twice (node/sync in I4-H2, mempool.Readmit "+
			"in I5) and is invisible to unit tests by construction. Wire it, delete "+
			"it, or add it to `allowed` with a reason.",
			len(orphans), scanned, strings.Join(orphans, "\n  "))
	}
}

// TestNoUnreadExportedFields pins the same property one level down: an exported
// field of an exported struct whose value nothing ever reads.
//
// TestNoUnreferencedExports cannot see it. It collects definitions from
// `*ast.FuncDecl`, `*ast.TypeSpec` and `*ast.ValueSpec` only; a field is an
// `*ast.Field` inside a `*ast.StructType` and is never recorded, so it can
// never be reported. Planting `NobodyReadsThisField uint64` in `p2p.Engine` and
// running that check alone still gives `ok` — the same experiment that caught
// its own first version being decoration, turned on the blind spot it left.
//
// It is not hypothetical. `Engine.Dropped` was an exported field on an exported
// struct in node/, incremented in one place and read by nothing anywhere. It
// survived long enough to be filed as a double-counting bug and reasoned about
// as an observability problem before anyone noticed that nothing read it at
// all; the fix was to delete it.
//
// **What it misses, measured rather than guessed.** Names are matched without
// their types, so a field is masked by any same-named selector anywhere. Six
// exported fields in core/ and node/ were read by nothing in the tree this
// check was written against, and running this check there reports two of them —
// measured by restoring that tree, dropping this file into it and running the
// test, not by reasoning about it. The six come from an independent go/types
// pass keyed pkgpath.Type.Field, applying the same definition of "read",
// because a name-matched check cannot audit its own recall:
//
//   - Peer.Attempts and PendingBody.PeerAddr — reported, and deleted with it;
//   - PendingBody.ID and PendingBody.Announced — masked by Header.ID() and by
//     the unrelated withhold counter's .Announced;
//   - chain.View.Tip (node/chain/stateref.go:171) — written once in the View
//     literal at node/chain/store.go:241 and read nowhere; masked by
//     Chain.Tip() and by Snapshot.Tip, a different field of a different struct
//     that node/miner/miner.go:91 really does read;
//   - p2p.PeerTip.Seen (node/p2p/syncdriver.go:156) — a composite-literal key
//     at :205 and an assignment at :247, no reads; masked by StateRef.Seen at
//     node/p2p/engine.go:429, which is a *method*.
//
// Four of the five files named above — node/chain/stateref.go,
// node/chain/store.go, node/miner/miner.go and node/p2p/syncdriver.go — are
// byte-identical between that tree and this one. The fifth, node/p2p/engine.go,
// is one of the three files this change touches, so it needs its own evidence
// rather than that blanket: its diff removes PendingBody.PeerAddr and rewrites
// a comment, and adds or removes no read. `.ID` appears 20 times in it at both
// trees, `.Announced` zero times at both (that masker is node/p2p/node.go:505
// and :522), and the `v.State.Seen(id)` at :429 is byte-identical. So the four
// masked entries are the same at either tree.
//
// Two of six is the price of the resolution, and it is paid on purpose: the
// alternative is below, and it costs false positives instead.
//
// **A write is not a read, and that is the whole point of this check.**
// `Engine.Dropped`'s only reference in the tree was `e.Dropped++`. A check that
// counted that as a use would be green on the one case it was built for — the
// mirror CONTRIBUTING.md's table is about. So the question asked here is not
// "is this field named anywhere" but "does anything ever read its value", and
// assignment, `++`/`--`, `+=` and a composite-literal key are all writes.
func TestNoUnreadExportedFields(t *testing.T) {
	root := filepath.Join("..", "..")

	defined := map[string]token.Pos{} // Type.Field -> where
	reads := map[string]bool{}        // field name -> read somewhere
	fset := token.NewFileSet()

	walkGoFiles(t, root, fset, func(rel string, file *ast.File) {
		if inScanned(rel) && !strings.HasSuffix(rel, "_test.go") {
			for name, pos := range exportedStructFields(file) {
				defined[name] = pos
			}
		}
		// Reads come from the whole repository, tests included, and from the
		// desktop module too: this walks source rather than asking `go list`,
		// so a field read only by desktop/ (its own module), only under a build
		// tag this platform does not select, or only by a `_test.go` file still
		// counts. A type-checker-based version of this check would see none of
		// those three.
		for name := range fieldReads(file) {
			reads[name] = true
		}
	})

	// Anti-vacuity, for the same reason as above and with the same failure mode: a
	// walk that collected nothing is silent and looks like success. With this
	// change applied the scan finds 292 fields and 1321 distinct read names, so
	// the floors are a broken scan rather than a moving target. Run against the
	// tree this check was written for, it finds 294 and 1321 — the two extra are
	// the fields this change deletes. Each number is true of the tree named beside
	// it and of nothing else; retake before quoting.
	if len(defined) < 150 {
		t.Fatalf("only %d exported struct fields found in %v: the scan is not "+
			"reaching the code and its silence means nothing", len(defined), scanned)
	}
	if len(reads) < 500 {
		t.Fatalf("only %d distinct field reads seen across the repository: the "+
			"read-scan is not reaching the code", len(reads))
	}

	var orphans []string
	for _, name := range unread(defined, reads, allowedFields) {
		orphans = append(orphans, name+"  ("+trimPos(fset.Position(defined[name]).String())+")")
	}

	if len(orphans) > 0 {
		t.Errorf("%d exported struct fields in %v are never read, anywhere in "+
			"the repository — including tests and the desktop module:\n  %s\n\n"+
			"Being assigned is not being read: `e.Dropped++` was the only "+
			"reference Engine.Dropped ever had before it was deleted, and a "+
			"counter nothing consults is worse than no counter because it invites "+
			"the reading it cannot support. Read it, delete it, or add it to "+
			"`allowedFields` with a reason.\n\n"+
			"Before deleting: `a == b` and `map[T]V` read every field of T and "+
			"name none of them, and so does anything handed whole to "+
			"encoding/json. If the struct is read that way the field is not "+
			"dead and this is a false positive — `allowedFields` names the nine "+
			"structs in scope that were like that when this check was written.",
			len(orphans), scanned, strings.Join(orphans, "\n  "))
	}
}

// TestAWriteIsNotAReadOfTheFieldItWrites runs the whole field pipeline over a
// planted defect, because a check nobody has watched fire is a check nobody
// knows the shape of. The first version of TestNoUnreferencedExports reported
// nothing ever and looked exactly like success; CONTRIBUTING's table has four
// more instruments with the same story.
//
// The planted struct is Engine as it stood before that deletion: Dropped
// incremented in one place, read nowhere. Every other field is one of the ways
// a field is touched without being read, or one of the ways it is read without
// being assigned, so the expected list below is the check's definition of
// "read" written out in full.
func TestAWriteIsNotAReadOfTheFieldItWrites(t *testing.T) {
	const src = `package planted

// Engine as it stood before the deletion, plus one of every other way to
// touch a field.
type Engine struct {
	Dropped   uint64 // ++ only, and nothing reads it: the shape this catches
	Forwarded uint64 // ++ and read
	Assigned  int    // = only
	Summed    int    // += only
	Seeded    int    // set by a composite-literal key only
	Ranged    int    // assigned by a range clause only
	Passed    int    // read as an argument
	Sliced    []byte // written through an index, which reads the field
	Taken     int    // read by address
	Copied    int    // read on the right of an assignment to another field
}

func (e *Engine) tick(n int, xs []int) uint64 {
	e.Dropped++
	e.Forwarded++
	e.Assigned = n
	e.Summed += n
	for e.Ranged = range xs {
	}
	e.Sliced[0] = byte(n)
	e.Assigned = e.Copied
	use(e.Passed, &e.Taken)
	return e.Forwarded
}

func seed() *Engine { return &Engine{Seeded: 1} }

func use(int, *int) {}
`
	got := pipeline(t, src)
	want := []string{
		"Engine.Assigned",
		"Engine.Dropped",
		"Engine.Ranged",
		"Engine.Seeded",
		"Engine.Summed",
	}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("the field check reports\n  %v\nwant\n  %v\n\n"+
			"A miss on Engine.Dropped means this check is blind to the case it "+
			"exists for; an extra name means it would fire on code that is read.",
			got, want)
	}
}

// TestEmbeddingAndUnexportedFieldsAreNotClaimed pins the two exclusions, which
// are the false positives this check would otherwise produce on the first file
// it met.
//
// node/p2p's Conn embeds net.Conn, and every c.Read, c.Write and c.Close in the
// transport is a promoted method that never says "Conn" — so an embedded field
// looks unread to any syntax tree while being the most used field in the
// package. Nothing here may be reported.
//
// Both forms are here because they fail differently, and an earlier draft of
// this comment got the reason backwards. It claimed a qualified embedding is
// masked anyway by `net.Conn`'s own selector — it is not, because the
// package-qualifier rule this file also adds strips `net.Conn` before the read
// set ever sees it. Probed: fieldReads on this source returns
// map[Close:true Value:true], with no "Conn" in it. So both `Conn.Conn` and
// `Conn.Base` are reported the moment the exclusion goes, and the test is
// non-vacuous either way — but the unqualified `Base` is the one that would
// still be reported if the package rule were ever removed, so it stays.
func TestEmbeddingAndUnexportedFieldsAreNotClaimed(t *testing.T) {
	const src = `package planted

import "net"

type Base struct{ Value int }

// Conn, in the shape node/p2p/transport.go has it, plus an unqualified embed.
type Conn struct {
	net.Conn
	Base
	unexported int
}

type unexportedStruct struct {
	ExportedButNotOnTheSurface int
}

func drive(c *Conn) int {
	c.Close()
	return c.Value
}
`
	if got := pipeline(t, src); len(got) != 0 {
		t.Errorf("the field check reports %v; an embedded field, an unexported "+
			"field and a field of an unexported type are all outside its subject",
			got)
	}
}

// TestAPackageQualifierIsNotAFieldRead pins the rule that recovers this check's
// own motivating case.
//
// core/fold exports a constant called Dropped. The five `fold.Dropped` in the
// tree — cmd/zycordd, node/chain/stats.go, and three tests — each put "Dropped"
// into a name-matched read set, so without this rule the check is green on
// `Engine.Dropped`: the field it was built for, in the shape it actually
// shipped in. Measured on the real tree with that field restored: `ok` without
// the rule, and the field named with it.
func TestAPackageQualifierIsNotAFieldRead(t *testing.T) {
	const src = `package planted

import "zycord/core/fold"

// Engine as it stood before the deletion, and the collision that hid it.
type Engine struct {
	Dropped uint64
}

func (e *Engine) tick(outcome int) {
	e.Dropped++
	if outcome == fold.Dropped {
		return
	}
}
`
	got := pipeline(t, src)
	if len(got) != 1 || got[0] != "Engine.Dropped" {
		t.Errorf("the field check reports %v, want [Engine.Dropped]: a constant "+
			"in another package that happens to share the field's name is not a "+
			"read of the field", got)
	}
}

// TestAShadowedImportNameIsTreatedAsAValue pins the guard on the rule above.
//
// The exclusion is safe only while the identifier before the dot really is a
// package. A parameter, variable or field with an import's name makes `fold.X`
// an ordinary field read again, and excluding it would invent an unread field
// out of one that is read — the false positive this whole check is designed
// around. So one non-qualifier occurrence disqualifies the name for the file.
func TestAShadowedImportNameIsTreatedAsAValue(t *testing.T) {
	const src = `package planted

import "zycord/core/fold"

type Engine struct {
	Dropped uint64
}

// fold the parameter shadows fold the package, so fold.Dropped here is a field.
func (e *Engine) tick(fold *Engine) uint64 {
	e.Dropped++
	return fold.Dropped
}
`
	if got := pipeline(t, src); len(got) != 0 {
		t.Errorf("the field check reports %v; `fold` names a parameter in this "+
			"file, so `fold.Dropped` reads the field and nothing here is unread",
			got)
	}
}

// pipeline is the field check applied to one source file: collect, classify,
// report, with the same three functions the tree-wide test uses.
func pipeline(t *testing.T, src string) []string {
	t.Helper()
	file, err := parser.ParseFile(token.NewFileSet(), "planted.go", src, 0)
	if err != nil {
		t.Fatalf("the planted source does not parse: %v", err)
	}
	return unread(exportedStructFields(file), fieldReads(file), nil)
}

// exportedStructFields returns the exported fields of exported top-level struct
// types in one file, keyed Type.Field.
//
// Two exclusions, both about false positives, which are the failure this check
// cannot afford: a check that fires for a benign reason gets disabled, and then
// it protects nothing.
//
// Embedded fields are skipped. An embedded field's name is its type's name and
// nothing that uses it says that name: `Conn` embeds `net.Conn`
// (node/p2p/transport.go:138) and every `c.Read`, `c.Write` and `c.Close` in
// the transport is a promoted method that never mentions `Conn`. Reporting them
// would accuse the most-used field in the package of being unread. It is the
// only embedded field on an *exported* type in core/ and node/; node/sync's
// unexported cachedSource embeds HeaderSource, which this scan never reaches.
//
// Fields of unexported types are skipped, because `scanned`'s subject is the
// exported surface — the same line TestNoUnreferencedExports draws for
// declarations.
func exportedStructFields(file *ast.File) map[string]token.Pos {
	out := map[string]token.Pos{}
	for _, d := range file.Decls {
		gd, ok := d.(*ast.GenDecl)
		if !ok {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || !ast.IsExported(ts.Name.Name) {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok || st.Fields == nil {
				continue
			}
			for _, f := range st.Fields.List {
				for _, n := range f.Names { // len 0 == embedded, skipped
					if ast.IsExported(n.Name) {
						out[ts.Name.Name+"."+n.Name] = n.Pos()
					}
				}
			}
		}
	}
	return out
}

// fieldReads returns the names read through a selector in one file.
//
// A field's value can only be read by naming it after a dot: `x.F`, a promoted
// `x.F` through an embedding, or a method expression. There is no other syntax
// for it. So a selector is the whole population, and everything outside it is
// not evidence that anything read a field — including, deliberately, a
// composite-literal key.
//
// **The composite-literal key is where this check departs from the sketch it
// was built from, which asked for those keys to count as uses.** `T{F: v}`
// initialises F; it does not consult it. Counting an initialisation as a use is
// the same error as counting `e.Dropped++` as one, and it is not academic: the
// only reference `PendingBody.PeerAddr` ever had was a key in a composite
// literal, and it was one of the two fields this check found on the tree it was
// written against (both deleted in the change that added it).
//
// Subtracted from the selector population are the positions that only write:
//
//   - `x.F = v`, `x.F += v` and `x.F++`, which read the field solely to compute
//     the value they immediately store back into it. That read-modify-write is
//     `Engine.Dropped`'s exact shape, and counting it as a use is how a check
//     goes blind to the one case it was built for;
//   - `for x.F = range xs`, the same assignment wearing a different statement.
//     No such line exists in the tree today; it is subtracted because the check
//     should not depend on that staying true.
//
// Subtracted as well are selectors on a package, which are the one large class
// of selector that cannot be a field at all. Without that subtraction this
// check would have been decoration on the very case it exists for: `core/fold`
// exports a constant named `Dropped`, so the five `fold.Dropped` in the tree
// put "Dropped" in the read set and `Engine.Dropped` would have passed.
// Measured: with the planted field restored, the check says `ok` without this
// rule and names Engine.Dropped with it.
//
// Everything else is matched by name without its type, so any `.Score`
// anywhere counts as a read of every field called `Score`. That is deliberate.
// `go/types` would resolve the receiver, but it cannot type-check the desktop
// module from here and it sees only the build tags of the machine it runs on —
// so the price of that resolution is a check that reports fields which *are*
// read, on a platform the runner did not compile. Collisions cost recall, and
// recall is the half a human recovers by reading the code; a false positive
// costs the check itself (CONTRIBUTING, "noise with authority").
func fieldReads(file *ast.File) map[string]bool {
	writes := map[token.Pos]bool{}
	markWrite := func(e ast.Expr) {
		if sel, ok := e.(*ast.SelectorExpr); ok {
			writes[sel.Sel.Pos()] = true
		}
	}
	ast.Inspect(file, func(n ast.Node) bool {
		switch x := n.(type) {
		case *ast.AssignStmt:
			// `:=` cannot have a selector on the left, so every form here —
			// plain, tuple and compound — is a write of the named field.
			for _, lhs := range x.Lhs {
				markWrite(lhs)
			}
		case *ast.IncDecStmt:
			markWrite(x.X)
		case *ast.RangeStmt:
			if x.Tok == token.ASSIGN {
				markWrite(x.Key)
				markWrite(x.Value)
			}
		}
		return true
	})

	pkgs := unshadowedImports(file)
	out := map[string]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		sel, ok := n.(*ast.SelectorExpr)
		if !ok || writes[sel.Sel.Pos()] {
			return true
		}
		if base, ok := sel.X.(*ast.Ident); ok && pkgs[base.Name] {
			return true
		}
		out[sel.Sel.Name] = true
		return true
	})
	return out
}

// unshadowedImports returns the import names of one file that provably cannot
// be anything else in it, so that `fold.Dropped` can be told from `x.Dropped`.
//
// "Provably" is doing the work, and the proof is deliberately crude: a name
// qualifies only if every single occurrence of that identifier in the file is
// the left half of a selector. One `fold := …`, one parameter called `fold`,
// one field of that name, and the name is disqualified for the whole file and
// every `fold.X` in it goes back to counting as a field read. That is the
// conservative direction — a missed exclusion costs recall, an over-eager one
// would invent an unread field out of a variable that shadows a package.
//
// The import's own name is exempt: `import f "path"` puts `f` in an ImportSpec
// where it is nobody's selector, and reading that as a shadow would disqualify
// every aliased import there is.
func unshadowedImports(file *ast.File) map[string]bool {
	names := map[string]bool{}
	exempt := map[token.Pos]bool{}
	for _, im := range file.Imports {
		name := ""
		if im.Name != nil {
			name = im.Name.Name
			exempt[im.Name.Pos()] = true
		} else if path, err := strconv.Unquote(im.Path.Value); err == nil {
			name = path[strings.LastIndex(path, "/")+1:]
		}
		// "_" and "." never appear as a qualifier, so they are not candidates.
		if name != "" && name != "_" && name != "." {
			names[name] = true
		}
	}
	if len(names) == 0 {
		return names
	}

	qualifier := map[token.Pos]bool{}
	ast.Inspect(file, func(n ast.Node) bool {
		if sel, ok := n.(*ast.SelectorExpr); ok {
			if base, ok := sel.X.(*ast.Ident); ok {
				qualifier[base.Pos()] = true
			}
		}
		return true
	})
	ast.Inspect(file, func(n ast.Node) bool {
		if id, ok := n.(*ast.Ident); ok && names[id.Name] {
			if !qualifier[id.Pos()] && !exempt[id.Pos()] {
				delete(names, id.Name)
			}
		}
		return true
	})
	return names
}

// unread returns the Type.Field names in defined that nothing reads, sorted.
//
// Split out from the test so that the whole pipeline — collect, classify,
// report — can be run against a planted defect rather than only against the
// tree, which is the experiment CONTRIBUTING asks of any instrument: watch it
// fire on the failure it exists to catch.
func unread(defined map[string]token.Pos, reads map[string]bool, allow map[string]string) []string {
	var out []string
	for name := range defined {
		if reads[name[strings.LastIndex(name, ".")+1:]] {
			continue
		}
		if _, ok := allow[name]; ok {
			continue
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// inScanned reports whether a repository-relative path lies in a scanned tree.
func inScanned(rel string) bool {
	for _, s := range scanned {
		if rel == s || strings.HasPrefix(rel, s+string(filepath.Separator)) {
			return true
		}
	}
	return false
}

// walkGoFiles parses every .go file under root and hands each to visit, with
// its path relative to root.
//
// It walks the filesystem rather than asking the toolchain for packages, which
// is the property that makes both checks above see the whole repository: the
// desktop wallet is a second Go module, and files behind `windows`, `darwin`,
// `randomx` or `zcdguard` build tags are invisible to a `go list` on any single
// machine.
//
// The cost is that it sees untracked files too, and always in the direction of
// silence: a scratch .go file in the working tree adds to the read set and can
// hide a real finding, so a local green and a clean-checkout green are not the
// same result. CI runs from a fresh checkout, which is the run that counts.
func walkGoFiles(t *testing.T, root string, fset *token.FileSet, visit func(rel string, file *ast.File)) {
	t.Helper()
	err := filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err != nil || info.IsDir() || !strings.HasSuffix(path, ".go") {
			return err
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		file, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return nil // not our job to report syntax errors
		}
		visit(rel, file)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

// declNamePositions returns the positions of every declaration's own name, so
// that a definition does not count as a reference to itself.
func declNamePositions(file *ast.File) map[token.Pos]bool {
	out := map[token.Pos]bool{}
	for _, d := range file.Decls {
		switch decl := d.(type) {
		case *ast.FuncDecl:
			out[decl.Name.Pos()] = true
		case *ast.GenDecl:
			for _, spec := range decl.Specs {
				switch sp := spec.(type) {
				case *ast.TypeSpec:
					out[sp.Name.Pos()] = true
				case *ast.ValueSpec:
					for _, n := range sp.Names {
						out[n.Pos()] = true
					}
				}
			}
		}
	}
	return out
}

// markQualified records pkg.Name so a method reached through a package
// qualifier counts as a use of the qualified form too.
func markQualified(used map[string]bool, sel *ast.SelectorExpr) {
	if id, ok := sel.X.(*ast.Ident); ok {
		used[id.Name+"."+sel.Sel.Name] = true
	}
}

func receiverName(recv *ast.FieldList) string {
	if recv == nil || len(recv.List) == 0 {
		return ""
	}
	switch t := recv.List[0].Type.(type) {
	case *ast.StarExpr:
		if id, ok := t.X.(*ast.Ident); ok {
			return id.Name
		}
	case *ast.Ident:
		return t.Name
	}
	return ""
}

func trimPos(s string) string {
	if i := strings.Index(s, "zycord/"); i >= 0 {
		return s[i+len("zycord/"):]
	}
	return s
}
