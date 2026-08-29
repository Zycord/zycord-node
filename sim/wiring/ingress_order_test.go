package wiring_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// TestSignatureWorkIsOrderedAfterTheCheapChecks: in every ingress handler, the
// expensive check appears in the source *after* the cheap checks that can
// refuse the same message, and the first write to shared state appears after
// the expensive check.
//
// The property in one sentence: docs/spec/wire.md §10.1's five steps hold in
// engine.go by position, not by belief.
//
// Why this is a syntax-tree test rather than a behavioural one. Proof of work
// has a counter behind it — pow.Engine is an interface, and
// TestACheapRefusalBuysNoProofOfWork in node/p2p drives every handler with a
// structurally-invalid, a duplicate and an out-of-window input and asserts the
// count is zero. **Signature verification has no such counter.** It happens
// inside core/validity → core/crypto, which is stdlib-only consensus code where
// a global counter does not belong, so "no Ed25519 verification happened"
// cannot be tallied from outside the way a hash can. What can be established
// mechanically is the thing the tally would have been evidence *for*: the call
// is below the checks that would have refused the message first.
//
// That is weaker than a counter and it is stated as weaker. It cannot see a
// verification performed in a helper called from above the marker, and it is
// checking one implementation's source rather than its behaviour — a benign
// extraction of a gate into a helper fails it, deliberately and loudly, because
// the alternative is a marker that silently stops measuring. What it does catch
// is precisely the change that has produced this class fifteen times: a
// refactor that hoists the expensive check, or that moves a mutation up in
// front of it, in a handler whose own tests do not measure order.
//
// On the certificate path it is no longer the only guard, and the source
// ordering is not what that one reads. Signatures sit outside a certificate's
// id, so an honest certificate and a signature-mutilated twin share an id, and
// node/p2p's TestADuplicateCertificateIsAnsweredWithoutVerifyingItsSignature
// separates the two orderings by the verdict they return for the twin —
// behaviour, not position. Absence of a counter is not absence of a separating
// input, and treating the two as the same thing is what left this handler on a
// shape assertion alone.
func TestSignatureWorkIsOrderedAfterTheCheapChecks(t *testing.T) {
	fset := token.NewFileSet()
	path := filepath.Join("..", "..", "node", "p2p", "engine.go")
	file, err := parser.ParseFile(fset, path, nil, 0)
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		fn string
		// expensive is the step-4 call: a signature verification or a proof-of-
		// work evaluation.
		expensive string
		// cheap are the step-1 to step-3 gates that MUST precede it. Every one
		// of them is a separate gate in the pipeline, and a hoist past any one
		// of them is a finding on its own — so they are listed and checked
		// individually rather than as "something cheap happens first".
		cheap []string
		// mutates are the step-5 writes that MUST follow it. Empty where the
		// handler has none.
		mutates []string
	}{
		{
			fn: "OnCertificate",
			// OnCertificate no longer has a step-4 call of its own. It ran
			// validity.Check and then Pool.Add, which runs the identical predicate
			// again, so every admitted certificate paid for two Ed25519 passes and the
			// first one stood in front of Add's own window and budget gates — a step-4
			// check above step 2 and step 3. The engine now calls Pool.Add and reads the
			// V-rule off its error.
			//
			// So the marker moves to e.Pool.Add, and what this case still
			// measures on the certificate path is the step-1/step-2 half: the
			// decode and both dedup lookups happen before the engine hands the
			// certificate to the pool at all. That is weaker than the old case
			// and it is stated as weaker, because steps 3, 4 and 5 are now
			// *inside* Add and are pinned where they live: node/mempool's
			// TestAFreeRefusalBuysNoSignatureVerification on the
			// cheap-gates-before-V2 half, and TestAnUnverifiedCertificateNeverEvicts
			// on the mutation-after-V2 half, which is where the epic
			// amendment's measurement was taken.
			expensive: "e.Pool.Add",
			cheap: []string{
				"types.UnmarshalCertificate", // step 1: it must decode at all
				"e.Chain.Read",               // step 2: the committed seen-set
				"e.Pool.Has",                 // step 2: the pool's own record
			},
		},
		{
			fn:        "OnBlockAnnounceFrom",
			expensive: "e.work.Check",
			cheap: []string{
				"UnmarshalAnnounce",   // step 1
				"e.seenBlocks",        // step 2: already seen
				"types.HeaderVersion", // step 1: version
				"MaxCertsPerBlock",    // step 1: a block that could not exist
				// step 3: a clock this node already owns. A future-dated announcement is
				// dropped free and unrelayed (R1-H2), so evaluating the work function for
				// it buys nothing — and the check it would pass reads the header's own
				// declared target and never re-derives it, so it is not evidence either.
				// Below e.work.Check this was an unbounded RandomX hash per message on a
				// path that neither charges nor dedupes.
				"e.tooFarAhead",
				// step 3: the price of the key epoch step 4 is about to demand. It is
				// listed here and not only pinned behaviourally because this is the guard
				// that makes the ordering structural, and the ordering is the whole saving:
				// the work key comes from a height the sender chose, so a budget checked
				// after e.work.Check bounds a verdict and not a resource. docs/spec/wire.md
				// §5 says the same normatively.
				"e.spendKeyEpoch",
			},
			mutates: []string{"e.seenBlocks", "e.pending"},
		},
		{
			// The marker moved from OnBlock to OnBlockFrom: the On*From refactor hoisted
			// OnBlock's Verdict construction and its e.work.Check onto this wrapper,
			// mirroring OnBlockAnnounceFrom. OnBlock is now a one-line delegator (return
			// e.OnBlockFrom(...)) with no step-4 call of its own, so the case follows
			// the work.Check to where it lives now rather than being deleted, exactly as
			// this file's Fatalf demands.
			fn:        "OnBlockFrom",
			expensive: "e.work.Check",
			cheap: []string{
				"types.UnmarshalHeader", // step 1: the cheap header-only decode
				"e.seenBlocks",          // step 2: already delivered and vetted
				"types.UnmarshalBlock",  // step 1: the body must decode
				// step 3: the price of the key epoch step 4 is about to demand, charged
				// *before* the work check exactly as OnBlockAnnounceFrom charges it — the
				// work key comes from a height the sender chose, so a budget checked after
				// e.work.Check would bound a verdict and not a resource. This is the
				// charge-before-work ordering the ingress-cost class exists to keep
				// structural.
				"e.spendKeyEpoch",
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.fn, func(t *testing.T) {
			body := funcBody(t, file, tc.fn)
			reads, writes := markerPositions(body)

			exp, ok := reads[tc.expensive]
			if !ok {
				t.Fatalf("%s no longer calls %s; this test is now measuring "+
					"nothing and needs its marker updated, not deleting",
					tc.fn, tc.expensive)
			}
			for _, c := range tc.cheap {
				at, ok := reads[c]
				if !ok {
					t.Errorf("%s no longer performs %s. Either the gate was "+
						"removed — which is the finding — or it moved, and this "+
						"marker has to move with it.", tc.fn, c)
					continue
				}
				if at > exp {
					t.Errorf("%s: %s is at line %d, after %s at line %d. "+
						"wire.md §10.1: the cheapest check that can refuse a "+
						"message is the one that does, so a peer cannot buy "+
						"the expensive one with a message the cheap one would "+
						"have refused.",
						tc.fn, c, fset.Position(at).Line, tc.expensive,
						fset.Position(exp).Line)
				}
			}
			for _, m := range tc.mutates {
				at, ok := writes[m]
				if !ok {
					t.Errorf("%s no longer writes %s; the marker needs updating", tc.fn, m)
					continue
				}
				if at < exp {
					t.Errorf("%s: %s is written at line %d, before %s at line "+
						"%d. wire.md §10.1: a gate that mutates shared state "+
						"goes after the authentication, never before it — "+
						"running it early hands an unauthenticated stranger a "+
						"write, which is what a forged certificate evicting ten "+
						"honest mempool residents was.",
						tc.fn, m, fset.Position(at).Line, tc.expensive,
						fset.Position(exp).Line)
				}
			}
		})
	}
}

// funcBody returns the body of a named top-level function or method.
func funcBody(t *testing.T, file *ast.File, name string) *ast.BlockStmt {
	t.Helper()
	for _, d := range file.Decls {
		fn, ok := d.(*ast.FuncDecl)
		if ok && fn.Name.Name == name && fn.Body != nil {
			return fn.Body
		}
	}
	t.Fatalf("engine.go has no function %s", name)
	return nil
}

// markerPositions returns, for every selector chain and identifier in a
// function body, the position of its FIRST appearance — once for appearances
// anywhere, and once for appearances on the left of an assignment or as the
// subject of a delete.
//
// First appearance is the right reduction for both questions. For a cheap gate
// it is where the refusal happens; for a mutation it is the earliest write, and
// the earliest write is the one an unauthenticated peer would reach.
func markerPositions(body *ast.BlockStmt) (reads, writes map[string]token.Pos) {
	reads, writes = map[string]token.Pos{}, map[string]token.Pos{}
	record := func(m map[string]token.Pos, key string, pos token.Pos) {
		if key == "" {
			return
		}
		if at, ok := m[key]; !ok || pos < at {
			m[key] = pos
		}
	}
	var mark func(m map[string]token.Pos, e ast.Expr)
	mark = func(m map[string]token.Pos, e ast.Expr) {
		switch v := e.(type) {
		case *ast.Ident:
			record(m, v.Name, v.Pos())
		case *ast.SelectorExpr:
			record(m, chain(v), v.Pos())
		case *ast.IndexExpr:
			mark(m, v.X)
		case *ast.CallExpr:
			mark(m, v.Fun)
		}
	}
	ast.Inspect(body, func(n ast.Node) bool {
		switch v := n.(type) {
		case *ast.SelectorExpr:
			record(reads, chain(v), v.Pos())
		case *ast.Ident:
			record(reads, v.Name, v.Pos())
		case *ast.AssignStmt:
			for _, lhs := range v.Lhs {
				mark(writes, lhs)
			}
		case *ast.CallExpr:
			// delete(e.pending, id) is a write, and it is not an assignment.
			if id, ok := v.Fun.(*ast.Ident); ok && id.Name == "delete" && len(v.Args) > 0 {
				mark(writes, v.Args[0])
			}
			// A call can be the mutation rather than merely containing one:
			// e.Pool.Add admits a certificate. Which calls count as writes is
			// decided by the table above naming them, not here - this only
			// makes a call's name reachable as a write marker.
			record(writes, chain(v.Fun), v.Pos())
		}
		return true
	})
	return reads, writes
}

// chain renders a selector expression as its dotted source form, so that
// "e.work.Check" is one marker rather than three.
func chain(e ast.Expr) string {
	switch v := e.(type) {
	case *ast.Ident:
		return v.Name
	case *ast.SelectorExpr:
		x := chain(v.X)
		if x == "" {
			return ""
		}
		return x + "." + v.Sel.Name
	}
	return ""
}
