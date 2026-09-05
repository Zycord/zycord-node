package types_test

import (
	"encoding/binary"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"runtime"
	"strconv"
	"strings"
	"testing"

	"zycord/core/ssz"
	"zycord/core/types"
)

// blockWithRawLists assembles a block encoding directly from the two variable
// list payloads, bypassing MarshalSSZ so that a list can be given a shape no
// encoder would produce. blockLayout is {HeaderSize, Variable, Variable}.
func blockWithRawLists(certList, citeList []byte) []byte {
	hdr := types.Header{Version: types.HeaderVersion, Height: 1}.MarshalSSZ()
	fixed := len(hdr) + 2*ssz.BytesPerLengthOffset

	out := make([]byte, 0, fixed+len(certList)+len(citeList))
	out = append(out, hdr...)
	out = binary.LittleEndian.AppendUint32(out, uint32(fixed))
	out = binary.LittleEndian.AppendUint32(out, uint32(fixed+len(certList)))
	out = append(out, certList...)
	out = append(out, citeList...)
	return out
}

// maximalClaim is the offset-table amplification shape: every four-byte word
// of the list payload is an offset pointing at its end, so the first word
// claims the largest element count the payload's own length can support and
// every element is empty. It is well-formed under the list codec's offset
// rules.
func maximalClaim(size int) []byte {
	data := make([]byte, size)
	for i := 0; i < size; i += ssz.BytesPerLengthOffset {
		binary.LittleEndian.PutUint32(data[i:], uint32(size))
	}
	return data
}

var blockSink *types.Block

// bytesToRefuse is the total heap charged by iters refusals of a block whose
// certificate list claims the largest element count size bytes can support.
//
// It is read only as a *difference* between two claimed counts, never as a
// budget. The constant part — the header, the field split, the failed
// certificate decode — is identical at both sizes and cancels, leaving only
// what the claim itself bought. That is what makes the assertion below
// insensitive to allocator noise, GC timing and unrelated allocations, none of
// which scale with a number written in the payload.
func bytesToRefuse(t *testing.T, size, iters int) uint64 {
	t.Helper()
	p := testParams()
	enc := blockWithRawLists(maximalClaim(size), nil)
	if _, err := types.UnmarshalBlock(enc, p); err == nil {
		t.Fatalf("a certificate list of %d bytes claiming %d empty elements must be refused",
			size, size/ssz.BytesPerLengthOffset)
	}

	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	for i := 0; i < iters; i++ {
		b, err := types.UnmarshalBlock(enc, p)
		if err == nil {
			t.Fatal("expected refusal")
		}
		blockSink = b
	}
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// TestRefusingABlockCostsTheSameWhateverCountTheFrameClaims: the certificate
// count in a block encoding is not a length prefix — it is derived from a
// wire-supplied offset — so refusing the block must not cost the receiver
// anything proportional to it. The floors UnmarshalBlock passes to the list
// decoder are what make that true, and this is the layer at which the
// floors are chosen, so it is the layer that has to pin the consequence.
//
// The instrument is a scaling delta, not a budget. Allocation *count* cannot
// see this at all: one oversized table is still one allocation, so the count
// stays flat at every n whether a floor is passed or not. Bytes can, and the
// separation is three orders of magnitude — with the floor removed, going from
// 64 to 4096 claimed certificates costs an extra 4096*32 bytes per refusal:
// the 24-byte slice header plus the 8-byte *Certificate the claim buys before
// a single element is shown to be a certificate at all. The threshold sits an
// order of magnitude above the measured noise and an order below the
// amplification it detects, so it can neither fire benignly nor go vacuous.
func TestRefusingABlockCostsTheSameWhateverCountTheFrameClaims(t *testing.T) {
	const iters = 100
	const small, large = 1 << 8, 1 << 12
	const threshold = 50 << 10

	lo := bytesToRefuse(t, small, iters)
	hi := bytesToRefuse(t, large, iters)

	// Signed: with the claim bounded the difference is noise around zero and
	// falls either way from run to run.
	delta := int64(hi) - int64(lo)

	t.Logf("%d refusals each: n=%d %d B, n=%d %d B, delta %+d B",
		iters, small/ssz.BytesPerLengthOffset, lo, large/ssz.BytesPerLengthOffset, hi, delta)

	if delta > threshold {
		t.Fatalf("quadrupling the claimed certificate count cost an extra %d bytes over %d refusals "+
			"(threshold %d): the claim is buying receiver memory before it is checked",
			delta, iters, threshold)
	}
}

// TestEveryVariableListDecodedHereDeclaresAnElementFloor: the delta test above
// can only speak about the lists that exist today. This one speaks about the
// ones that do not exist yet: every ssz.DecodeVariableList call in this
// package's production sources must name a floor.
//
// It walks the AST rather than matching the source text, because a text match
// gets this wrong in both directions. It cannot see through a nested call in an
// earlier argument, so it fires on a call whose floor is perfectly correct — a
// check firing for a benign reason, which PROTOCOL forbids outright — and it
// compares one spelling of zero, so 0x0, or a named constant that happens to be
// zero, walks straight past it. Walking ast.CallExpr removes the first by
// construction; rejecting any integer literal that evaluates to zero removes
// every spelling of the second; resolving package-level const idents removes
// the named one.
//
// The evasions it does NOT catch are stated rather than chased, because they
// are all under-assertions — it stays silent, it never fires wrongly — and
// every one of them is caught behaviourally by
// TestRefusingABlockCostsTheSameWhateverCountTheFrameClaims, which measures
// the amplification itself wherever the call lives: a floor written as a
// conversion (int(0)), a floor held in a package-level var rather than a
// const, a zero constant imported from another package, and a call in a
// package this scan does not cover. What is deliberately NOT left to that
// backstop is anything that makes a call invisible to the walk while `found`
// stays non-zero, because then the non-vacuity guard below stops noticing that
// a decode went missing: an aliased import is handled by matching the selector
// name without its qualifier, and a reference stored as a function value is
// handled by the second pass.
func TestEveryVariableListDecodedHereDeclaresAnElementFloor(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", func(fi fs.FileInfo) bool {
		return !strings.HasSuffix(fi.Name(), "_test.go")
	}, 0)
	if err != nil {
		t.Fatal(err)
	}

	// Package-level constants, so that a floor spelled as a named constant is
	// judged by its value and not by its name.
	consts := map[string]ast.Expr{}
	for _, pkg := range pkgs {
		for _, file := range pkg.Files {
			for _, d := range file.Decls {
				gd, ok := d.(*ast.GenDecl)
				if !ok || gd.Tok != token.CONST {
					continue
				}
				for _, spec := range gd.Specs {
					vs, ok := spec.(*ast.ValueSpec)
					if !ok {
						continue
					}
					for i, name := range vs.Names {
						if i < len(vs.Values) {
							consts[name.Name] = vs.Values[i]
						}
					}
				}
			}
		}
	}

	// isZero reports whether e is a literal zero, or a package-level constant
	// that is one. Anything it cannot resolve counts as a floor: this test
	// refuses only what it can prove is unbounded, so its failures are never
	// guesses.
	var isZero func(ast.Expr, int) bool
	isZero = func(e ast.Expr, depth int) bool {
		if depth > 8 {
			return false
		}
		switch v := e.(type) {
		case *ast.ParenExpr:
			return isZero(v.X, depth+1)
		case *ast.BasicLit:
			if v.Kind != token.INT {
				return false
			}
			n, err := strconv.ParseInt(strings.ReplaceAll(v.Value, "_", ""), 0, 64)
			return err == nil && n == 0
		case *ast.Ident:
			if c, ok := consts[v.Name]; ok {
				return isZero(c, depth+1)
			}
		}
		return false
	}

	// Two passes. The first matches calls; the second checks that no
	// DecodeVariableList selector escaped it. The selector name alone is
	// matched, without requiring the qualifier to be `ssz` — an aliased import
	// would otherwise walk straight past, and no other DecodeVariableList
	// exists for the looser rule to catch by mistake.
	matched := map[ast.Node]bool{}
	found := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				sel, ok := call.Fun.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "DecodeVariableList" {
					return true
				}
				matched[sel] = true
				found++
				line := fset.Position(call.Pos()).Line
				if len(call.Args) != 3 {
					t.Fatalf("%s:%d: DecodeVariableList takes three arguments, found %d",
						name, line, len(call.Args))
				}
				if isZero(call.Args[2], 0) {
					t.Fatalf("%s:%d: this list is decoded with an element floor of zero, which is "+
						"exactly the unbounded claim the element floor exists to close", name, line)
				}
				return true
			})
		}
	}

	// A DecodeVariableList that is named but not called here is taken as a
	// reference stored for calling elsewhere, where its floor is no longer
	// visible to this walk. Refusing it keeps `found` honest: without this, a
	// decode moved behind a function value disappears from the count while the
	// non-vacuity guard below stays satisfied by the other call.
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok || sel.Sel.Name != "DecodeVariableList" || matched[sel] {
					return true
				}
				t.Fatalf("%s:%d: DecodeVariableList is referenced without being called, so the floor "+
					"it is eventually given is not visible here", name, fset.Position(sel.Pos()).Line)
				return true
			})
		}
	}

	if found == 0 {
		t.Fatal("no DecodeVariableList call found: this test proved nothing")
	}
}
