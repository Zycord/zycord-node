package p2p_test

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

// verificationReach are the packages through which node/p2p could reach an
// Ed25519 verification, and the symbols this package is allowed to name from
// each.
//
// Every entry is resolved by IMPORT PATH, never by the spelling in front of the
// dot, and this package is its own proof of why. node/p2p imports BOTH
// zycord/node/sync (as `sync`) and the standard library's sync (as `gosync`),
// so `sync.Mutex` and `sync.Run` in these files are two different packages
// wearing one name. A guard that matched the identifier would be reading them
// as one.
//
// FIVE entries — this count is the number of ROWS in verificationReach below,
// and it is not the same quantity as the four packages node/p2p actually
// imports (core/crypto is row 4 and is imported zero times; see importPath).
// Every one of them was added because a mutant reached the predicate through
// it. None is hypothetical:
//
//   - core/validity holds the V-rules themselves.
//   - node/verify RUNS them — verify.go:57 is `out[i] = validity.Check(c, p)` —
//     and its package doc calls it "the stateless-validity pipeline". engine.go
//     already imports it for the proof-of-work cache, so a second pass through
//     it never names core/validity at all.
//   - node/mempool runs them too, inside Pool.Add. This is the sharpest one,
//     because a second `mempool.New(...).Add(cert, …)` does not read as
//     re-verification: it reads as pooling, using the very API that
//     SHOULD run the predicate. Only the *type* is allowed here; constructing a
//     second pool in this package is the finding.
//   - core/crypto is the strict predicate itself, and it is the one row node/p2p
//     does NOT import — its allowed set is empty and it holds by absence.
//     crypto.VerifyStrict written straight into engine.go is killed here. So is
//     the same call inside a goroutine — and THE COUNTER IS BLIND TO THAT ONE,
//     because its delta closes before the goroutine runs. It is the M5 shape
//     one package closer in, which is why this row exists.
//   - crypto/ed25519 is the primitive underneath all of it. node/p2p imports it
//     for peer identity (peerstore.go, transport.go) and uses exactly three
//     symbols, none of which verifies anything.
//
// The allowed sets are deliberately tiny, and each says why its symbol is
// harmless, because adding one is a decision to let this package reach further
// into the verification stack.
var verificationReach = []struct {
	// dir is the package's source directory relative to this one, for packages
	// in this module. When it is set the import path is DERIVED from it and
	// there is no literal to mistype — see importPath below for why that is the
	// whole point rather than a convenience.
	dir []string
	// stdPath is the import path for standard-library packages, which have no
	// directory under this module. Exactly one of dir and stdPath is set.
	stdPath string
	name    string
	allowed map[string]string
}{
	{
		dir:  []string{"..", "..", "core", "validity"},
		name: "validity",
		allowed: map[string]string{
			"Rule": "reads the failed V-rule's name off an error. Evaluates nothing.",
		},
	},
	{
		dir:  []string{"..", "..", "node", "verify"},
		name: "verify",
		allowed: map[string]string{
			"WorkWasChecked": "the proof-of-work cache type (R1-M3). Nothing to do with the V-rules.",
			"NewWorkCache":   "its constructor.",
		},
	},
	{
		dir:  []string{"..", "..", "node", "mempool"},
		name: "mempool",
		allowed: map[string]string{
			"Pool": "the type of the pool this engine was GIVEN. Holding one is the point; " +
				"constructing another here is a second admission pass.",
		},
	},
	{
		// The primitive itself, one import away and in-module. node/p2p imports
		// it ZERO times today, so the empty set below is satisfied by absence
		// rather than by restraint — and that is exactly why it is listed: this
		// is the nearest package to the engine that can verify a signature, it
		// is where the counter lives, and `crypto.VerifyStrict(...)` written
		// straight into engine.go is a shorter reach than any of M1-M5.
		//
		// Asynchronously it is blind to the counter as well (the delta closes
		// first), so without this entry it would be the one shape reachable in
		// one import that NEITHER guard sees.
		//
		// What bounds this row is its own dir, and that is worth stating rather
		// than leaving for a reader to discover: re-pointing dir and name
		// together at some other correctly-named package this file does not
		// import, or deleting the row outright, removes the guard silently —
		// nothing counts the table's rows. That is deliberately NOT guarded.
		// The only defence against a coherent re-point is a fixed expected-path
		// set for the whole table, which reintroduces exactly the authored
		// literal that deriving the path exists to delete, trading a closed
		// slip class for an open one. A typo is a slip in a string nobody
		// reads; re-pointing or deleting a guard's own row is a deliberate,
		// semantically coherent edit that arrives in a reviewable diff and that
		// no author of engine.go can reach. Only the first is a test's job. Closing it here rather than
		// banking it is the point: the sibling shape M4, a hand-rolled
		// ed25519.Verify, is already closed and is LESS likely than this one,
		// because an author who wants a signature checked properly reaches for
		// the tree's own strict predicate, not for a hand-rolled loop.
		dir:     []string{"..", "..", "core", "crypto"},
		name:    "crypto",
		allowed: map[string]string{},
	},
	{
		stdPath: "crypto/ed25519",
		name:    "ed25519",
		allowed: map[string]string{
			"PublicKey":   "peer identity (transport.go, peerstore.go).",
			"PrivateKey":  "this node's own identity key.",
			"GenerateKey": "creating it.",
		},
	},
}

// TestP2PNamesNoRouteToASecondVerification: across every non-test file of
// package node/p2p, the only symbols named from the packages that can
// reach an Ed25519 verification are the ones listed above — none of which
// verifies anything.
//
// # This is the SECONDARY guard, and it is deliberately kept beside the counter
//
// TestAnAdmittedCertificateIsVerifiedExactlyOnceEndToEnd counts evaluations at
// crypto.VerifyStrict and is the primary: it binds the property rather than a
// spelling, and it catches a hop through a package nobody has listed here.
// This test binds spellings, which is weaker in general — but the two have
// **complementary** blind spots, measured rather than assumed, and neither is
// sufficient alone:
//
//	mutant                                  counter   this test
//	M1  package-scope recheckV2, after Add   KILL      KILL
//	M2  hop through verify.Sequential        KILL      KILL
//	M3  second mempool.New(...).Add [1]      KILL      KILL
//	M4  bare ed25519.Verify loop             BLIND     KILL
//	M5  async `go func(){ verify... }()`     BLIND     KILL
//
// [1] M3's POLICY ARGUMENT IS PART OF THE MUTANT, and the counter column above
// is true only when it is stated. With mempool.DefaultPolicy() — what
// cmd/zycordd/main.go:135 builds the node's real pool with — the shadow pool
// admits the certificate, the full predicate runs, and the counter reads
// `cost 2 ... want exactly 1`: KILL. With mempool.Policy{} the pool has
// MaxPerUnderwriter == 0 and refuses at a step-3 gate inside screen(), ahead of
// verifySignatures, so it buys ZERO extra Ed25519 passes and the counter is
// BLIND at any placement. THIS test kills it either way, with a two-symbol
// signature (mempool.New plus the policy constructor), which is why its column
// is unaffected. A grid cell whose verdict depends on an unstated parameter of
// the mutant is not a verdict; it is the row-level form of a reused -run filter.
//
// The counter is blind to M4 because that route never touches
// crypto.VerifyStrict, and blind to M5 because a delta measured around a call
// cannot see work done AFTER the delta closes — no number of rounds can fix
// that, it is the shape of the instrument. This test is blind to nothing in the
// set above, but it is blind by construction to any route through a package not
// named in the table.
//
// So the honest joint claim is: **no second verification reachable either
// synchronously through crypto.VerifyStrict, or by naming any of the five
// packages that can reach one today.** Five is the table's row count, which is
// what this claim ranges over — not the four that node/p2p imports. What
// neither test sees is an
// asynchronous verification through a package added later and not listed here.
// That residual is stated in the PR body rather than closed.
//
// M5 is worth the extra guard on its own. It is not an adversarial shape: it is
// what an author writes when told "the verification is expensive, do not block
// the gossip loop" — the performance-motivated version of exactly the defect
// the double-verification removal is about.
func TestP2PNamesNoRouteToASecondVerification(t *testing.T) {
	fset := token.NewFileSet()

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	var sources []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		sources = append(sources, name)
	}
	// Non-vacuity, asserted before the check rather than after someone doubts
	// it: a walk that read no files reports exactly the empty reference set
	// this test looks for, and a green result from a check that ran nothing is
	// indistinguishable from one that ran everything.
	if len(sources) == 0 {
		t.Fatal("no non-test .go files found in this package; the scan read " +
			"nothing and every assertion below would be vacuous")
	}

	found := 0
	for _, pkg := range verificationReach {
		// Resolve the imported package's own name from its source where that
		// source is in this module. An unaliased import binds the package
		// clause, so deriving the local spelling from the path would be a guess
		// that happens to be right today and would stop being right silently.
		path := importPath(pkg.dir, pkg.stdPath)

		name := pkg.name
		if len(pkg.dir) > 0 {
			parsed, err := parser.ParseDir(fset, filepath.Join(pkg.dir...), nil, 0)
			if err != nil {
				t.Fatal(err)
			}
			resolved := ""
			for n := range parsed {
				if !strings.HasSuffix(n, "_test") {
					resolved = n
				}
			}
			if resolved == "" {
				t.Fatalf("could not resolve the package clause of %s; this guard "+
					"cannot name what it is looking for and would pass vacuously", path)
			}
			if resolved != pkg.name {
				t.Fatalf("%s declares package %q, but this table expects %q; the "+
					"table is stale and the walk below would look for the wrong "+
					"identifier", path, resolved, pkg.name)
			}
			name = resolved

		}

		refs := map[string][]string{}
		importers := 0
		for _, src := range sources {
			file, err := parser.ParseFile(fset, src, nil, 0)
			if err != nil {
				t.Fatal(err)
			}

			local := ""
			for _, spec := range file.Imports {
				imported, err := strconv.Unquote(spec.Path.Value)
				if err != nil || imported != path {
					continue
				}
				switch {
				case spec.Name == nil:
					local = name
				case spec.Name.Name == ".":
					// A dot-import puts the package's exported names into this
					// file's scope unqualified, and nothing short of type
					// resolution can then tell validity.Check from a local
					// Check. The analysis is defeated rather than clean, so it
					// says so instead of passing.
					t.Fatalf("%s dot-imports %s; this guard cannot see through "+
						"that, and a guard that cannot see is not a guard", src, path)
				case spec.Name.Name == "_":
					local = "" // imported for effect only; binds no symbol
				default:
					local = spec.Name.Name
				}
			}
			if local == "" {
				continue
			}
			importers++

			// Every reference, in any expression position — a call, a value, an
			// argument, a field type, a composite literal's type. ParseFile ran
			// without ParseComments and ast.Inspect visits no comments, so the
			// mentions of validity.Check and mempool.New in engine.go's
			// comments — which explain why the calls are not there — cannot
			// register. That is the difference between parsing and matching: a
			// grep for the same strings counts all three.
			ast.Inspect(file, func(nd ast.Node) bool {
				sel, ok := nd.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				x, ok := sel.X.(*ast.Ident)
				if !ok || x.Name != local {
					return true
				}
				at := fset.Position(sel.Pos())
				refs[sel.Sel.Name] = append(refs[sel.Sel.Name], src+":"+strconv.Itoa(at.Line))
				return true
			})
		}

		if importers == 0 {
			// An entry whose allowed set is EMPTY is satisfied by absence: the
			// claim is "this package must not reach that one at all", and not
			// importing it is the strongest way to hold. For every other entry
			// the import is present at this head, so a zero here means the walk
			// stopped resolving rather than that the package got cleaner.
			if len(pkg.allowed) == 0 {
				continue
			}
			t.Errorf("no non-test file in this package imports %s. Either that "+
				"dependency genuinely went away — which is worth reading — or "+
				"this guard has stopped resolving the import and is measuring "+
				"nothing.", path)
			continue
		}
		found += len(refs)

		var offending []string
		for sym := range refs {
			if _, ok := pkg.allowed[sym]; !ok {
				offending = append(offending, sym)
			}
		}
		sort.Strings(offending)
		for _, sym := range offending {
			t.Errorf("%s.%s is named at %v.\n"+
				"Pool.Add already runs the whole stateless predicate — once, and "+
				"below its own window and budget gates — so any further reach "+
				"into the verification stack from this package is a second "+
				"Ed25519 pass over an admitted certificate, or a "+
				"check standing in front of Add's cheap gates (wire.md 10.1).\n"+
				"Allowed from %s: %v.",
				name, sym, refs[sym], path, allowedNames(pkg.allowed))
		}
	}

	// The positive control for the walk as a whole: these packages ARE imported
	// and ARE used at this head, so finding nothing at all means the instrument
	// stopped discriminating rather than that the package got cleaner.
	if found == 0 {
		t.Error("the walk found no reference to any of the imported packages; it is " +
			"not discriminating and every assertion above is worthless")
	}
}

// importPath is the import path of a table row, DERIVED from its directory for
// anything in this module rather than written a second time.
//
// This is the repair for a defect measured on the previous head, and the shape
// of the defect is why derivation rather than a comparison: the row's path and
// its dir were two hand-maintained strings, and nothing related them. The clause
// check reads dir, so it passed whenever dir was right; the import scan reads
// path, so a typo there matched no file. For the rows node/p2p really imports,
// that shows up loudly as importers == 0. The core/crypto row cannot be caught
// that way, because zero importers is its EXPECTED state — its claim is absence
// — so a mistyped path reads exactly like the property holding.
//
// A comparison between the two strings is NOT sufficient, and that was measured
// too: requiring path to end with the tail of dir accepts "zzz/core/crypto",
// which still matches no import. Any check of one string against another leaves
// the half nobody tested. Two strings cannot disagree when there is only one, so
// the literal is deleted instead.
//
// The module prefix below is the one literal left, and it is shared by every
// in-module row rather than per-row. Two quantities, and they are different:
// FOUR rows are in-module (every row with a dir), and THREE of those are
// actually imported by node/p2p — core/crypto is the fourth and is imported
// zero times, which is its whole point. So getting the prefix wrong takes all
// four in-module rows out at once, and THREE of them fail loudly as
// importers == 0; the core/crypto row would stay silent, because zero is
// already its expected reading. That asymmetry is the loud control and the
// reason it is a shared literal rather than a per-row one. Note the two scopes,
// because the word does double duty: that ROW is silent, while the TEST is not,
// since the other three fire. Only a row-local mistake could ever have been
// silent at the level of the test as a whole, and that is exactly what deriving
// the path removes.
func importPath(dir []string, stdPath string) string {
	if len(dir) == 0 {
		return stdPath
	}
	return "zycord/" + strings.Join(dir[2:], "/")
}

func allowedNames(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
