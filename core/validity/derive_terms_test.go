package validity_test

import (
	"errors"
	"go/ast"
	"go/parser"
	"go/token"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"testing"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/spec"
	"zycord/wallet"
)

// ---------------------------------------------------------------------------
// The interior of a pass-through, counted
// ---------------------------------------------------------------------------
//
// terms_test.go counts a rejection term by its `failf` format string, and the
// two sites that spell no format — V1's `fail("V1", err)` around
// Program.CheckShape and V3's `fail("V3", err)` around DeriveCert — are keyed
// by elimination. That key is sound for the *site*; what it cannot do is see
// past it. **A pass-through counts its delegate's whole interior as one term**,
// so DeriveCert's nineteen return sites and CheckShape's six were, between
// them, two of the thirty-eight. This file is the second enrolment: one
// separating input per site of each delegate, counted the same way —
// the sites read out of the source, a bijection against the inputs, and no two
// inputs on one site.
//
// **Why the key is not `errors.Is` alone**, which is the obvious shape and
// the reason it is not what is built here. derive.go spells thirteen distinct
// sentinels across nineteen sites, so six sentinels appear twice:
// ErrEmptyProgram, ErrZeroAmount, ErrBadDst, ErrZeroCap, ErrAmountOverCap and
// — since deriveTransfer gained the same asset whitelist deriveMint already
// had — ErrBadAsset. Keying on sentinel identity would have merged
// deriveMint's ErrAmountOverCap with slotSums.add's — and slotSums.add's is
// the inflation site, the one term in this file with an unbounded
// consequence. A key that collapses exactly the site with the unbounded
// consequence is not a key.
//
// So a site is keyed by **(enclosing function, sentinel)**, which is injective
// over derive.go at head and is checked to be, and a shape site by **(switch
// arm, sentinel)**, which is injective over CheckShape at head and is likewise
// checked. Both keys are read from the AST; neither is typed here.
//
// **Limits, in the shape terms_test.go states its own.**
//
// (1) The discovery rule is a `return` whose results include an identifier or
// selector named Err…, at any arity, methods included — the same scan
// namedErrorReturns performs for spec/README.md's numbers, so the two cannot
// disagree about what a site is. A rejection expressed any other way — a
// wrapped error, an error built at the site, a sentinel returned through a
// variable — is not seen and no input is demanded for it.
//
// (2) The runtime key is weaker than the scan key, and this is the one place it
// matters. `errors.Is` tells an input which sentinel answered, never which
// site. Two sites sharing a sentinel are therefore separated by *construction*
// of the input rather than by the assertion, and what backs that construction
// is a second observable: the program kind. (kind, sentinel) is injective over
// derive.go's nineteen sites — checked below over the declared table — so an
// input that drifted from slotSums.add to deriveMint's ErrAmountOverCap would
// have to have changed program kind from TRANSFER to MINT, which the table
// records and the test compares. That is not a proof of site identity; it is
// the strongest observable available from outside the package, and it is named
// rather than dressed up.
//
// (3) Derive's `default:` arm is excluded, and structurally rather than by
// name: it is the one site inside a `default:` clause, and terms_test.go's
// deriveDefaultArmIsUnreachable proves over the complete Program domain that no
// kind reaches it. Exactly one such site must exist, and this test fails if the
// two scans ever disagree about how many.
//
// (4) These inputs are exercised at the delegate — validity.DeriveCert and
// Program.CheckShape — which is where the term lives, exactly as terms_test.go
// exercises a rule at the rule's own function. What each site does to the
// *whole* predicate is a separate question, answered for the one site where the
// answer has a consequence by TestATransferSummingPastTheWordIsRefusedByCheck
// below.

// deriveSite is a rejection site of derive.go, keyed by its enclosing function
// and the sentinel it returns.
type deriveSite struct {
	fn       string
	sentinel string
}

func (s deriveSite) String() string { return s.fn + " → " + s.sentinel }

// shapeSite is a rejection site of Program.CheckShape, keyed by the switch arm
// it sits in ("" for the body-count guard above the switch, "default" for the
// unknown-kind arm) and the sentinel it returns.
type shapeSite struct {
	arm      string
	sentinel string
}

func (s shapeSite) String() string {
	if s.arm == "" {
		return "before the switch → " + s.sentinel
	}
	return "case " + s.arm + " → " + s.sentinel
}

// derivationInput is one separating input for one site of derive.go.
type derivationInput struct {
	what     string
	site     deriveSite
	sentinel error
	prog     types.Program
}

// TestEveryDerivationTermIsSeparated is the second enrolment's deliverable
// for V3's delegate: one input per firing site of derive.go, and a bijection
// rather than a list.
//
// TestDerivationRejectsNonsense in validity_test.go remains what it has always
// been — a smoke list of eleven programs asserting only that derivation refuses
// them. It is kept because it costs nothing and loses nothing; what it could
// not do is notice a *term* going missing, since a program refused by two
// clauses stays refused when one is deleted. Seven of the seventeen sites that
// existed when that was measured had no case in it and survived deletion with
// core/validity, core/types and spec all green. The number is a statement about
// the tree as it stood when the enrolment was written and is not recounted
// here; the bijection below is what holds the property now, and it grew with
// the asset-whitelist site deriveTransfer gained.
func TestEveryDerivationTermIsSeparated(t *testing.T) {
	p := spec.Devnet()

	firing, excluded := derivationSites(t)
	if len(excluded) != 1 {
		t.Fatalf("derive.go has %d rejection sites inside a `default:` arm (%v); this test "+
			"excludes exactly one — Derive's exhaustiveness stub — and a second would be a "+
			"site with no input and no proof of unreachability", len(excluded), excluded)
	}
	if excluded[0].fn != "Derive" {
		t.Fatalf("the excluded default-arm site is in %s, not Derive; the one site this test "+
			"declines to demand an input for is no longer the one it documents", excluded[0].fn)
	}
	if n := deriveDefaultArmIsUnreachable(t); n != len(excluded) {
		t.Fatalf("the structural scan finds %d unreachable site(s) and this one finds %d; the "+
			"two disagree about which sites can fire", n, len(excluded))
	}

	cases := derivationInputs(t, p)

	// (2) above, enforced rather than asserted: the program kind is what
	// separates two sites sharing a sentinel, so it has to actually separate
	// them across the whole table.
	byKind := map[deriveSite]string{}
	for _, c := range cases {
		k := deriveSite{fn: kindName(c.prog.Kind), sentinel: c.site.sentinel}
		if prev, dup := byKind[k]; dup {
			t.Errorf("%q and %q are both a %s program rejecting with %s. The program kind is "+
				"the only observable separating two sites that share a sentinel, and these two "+
				"share both — neither input can be shown to reach the site it names",
				prev, c.what, kindName(c.prog.Kind), c.site.sentinel)
		} else {
			byKind[k] = c.what
		}
	}

	covered := map[deriveSite]string{}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			if _, ok := firing[c.site]; !ok {
				t.Fatalf("derive.go spells no %s; the site this input was written for has been "+
					"deleted, reworded or moved, and the input now separates nothing", c.site)
			}
			// The delegate itself, which is where the term lives. Seq and the
			// deposit cell are the accepted baseline's, so nothing but the
			// program varies between one input and the next.
			_, _, err := validity.DeriveCert(c.prog, p.ChainID, 0, key(t, 2).Persistent())
			if err == nil {
				t.Fatalf("DeriveCert accepts this program, so %s is separated by nothing", c.site)
			}
			if !errors.Is(err, c.sentinel) {
				t.Fatalf("DeriveCert rejects with %v, and this input is written for %s. Either "+
					"an earlier clause answers first — in which case the term it names is "+
					"separated by nothing — or the input has drifted off it", err, c.site)
			}
			if prev, dup := covered[c.site]; dup {
				t.Errorf("%q and %q both key to %s. Two inputs on one site means some other "+
					"site is separated by nothing while the count still adds up — and if a "+
					"site was deleted along with its guard, the count adds up because the "+
					"demand went with it", prev, c.what, c.site)
			} else {
				covered[c.site] = c.what
			}
		})
	}

	var uncovered []string
	for s := range firing {
		if _, ok := covered[s]; !ok {
			uncovered = append(uncovered, s.String())
		}
	}
	if len(uncovered) > 0 {
		sort.Strings(uncovered)
		t.Errorf("%d of derive.go's %d firing rejection sites are separated by no input: %s. "+
			"V3 forwards all of them as one term, so an unseparated one is invisible to every "+
			"test in this tree", len(uncovered), len(firing), strings.Join(uncovered, "; "))
	}
}

// derivationInputs is the table: one program per firing site of derive.go.
//
// Every program here is refused by the clause it names and by nothing before
// it, which the errors.Is assertion above is what proves. The ordering inside
// each derive function matters and is why several of these look
// over-specified — a MINT written to reach ErrZeroCap must carry a non-zero
// amount, or ErrZeroAmount answers two lines earlier and the input separates
// that instead.
func derivationInputs(t *testing.T, p *params.Params) []derivationInput {
	t.Helper()
	alice, bob, carol := key(t, 2), key(t, 3), key(t, 4)
	a, b, c := alice.Persistent(), bob.Persistent(), carol.Persistent()
	asset := types.DeriveAssetAddress(p.ChainID, a, 0)
	oneShotLo, oneShotHi := orderedOneShots(t)

	return []derivationInput{
		// deriveTransfer, in source order.
		{
			what:     "a TRANSFER with no moves",
			site:     deriveSite{"deriveTransfer", "ErrEmptyProgram"},
			sentinel: validity.ErrEmptyProgram,
			prog:     wallet.Transfer(),
		},
		{
			// The asset-whitelist site. Everything else about this move is in
			// order — a positive amount, two distinct persistent addresses —
			// so the asset id is the only thing left to refuse it, which is
			// what makes the input separating rather than merely refused. The
			// id is a one-shot address: a well-formed address of a version
			// that is known (V9 admits it) and that no asset can ever carry,
			// so this separates the asset whitelist from the version
			// whitelist rather than riding on it.
			//
			// It shares its sentinel with deriveMint's ErrBadAsset and is a
			// distinct site under the (enclosing function, sentinel) key this
			// file uses; per limit (2) the runtime observable that keeps the
			// two apart is the program kind, TRANSFER against MINT.
			what:     "a TRANSFER of an asset id no asset can have",
			site:     deriveSite{"deriveTransfer", "ErrBadAsset"},
			sentinel: validity.ErrBadAsset,
			prog:     wallet.Tip(alice.OneShot(), a, b, drops(1)),
		},
		{
			what:     "a TRANSFER move of zero",
			site:     deriveSite{"deriveTransfer", "ErrZeroAmount"},
			sentinel: validity.ErrZeroAmount,
			prog:     wallet.Tip(types.NativeAsset, a, b, u256.Zero),
		},
		{
			what:     "a TRANSFER out of an asset address",
			site:     deriveSite{"deriveTransfer", "ErrBadSrc"},
			sentinel: validity.ErrBadSrc,
			prog:     wallet.Tip(types.NativeAsset, asset, b, drops(1)),
		},
		{
			what:     "a TRANSFER into the protocol address",
			site:     deriveSite{"deriveTransfer", "ErrBadDst"},
			sentinel: validity.ErrBadDst,
			prog:     wallet.Tip(types.NativeAsset, a, crypto.ProtocolAddress, drops(1)),
		},
		{
			what:     "a TRANSFER from an address to itself",
			site:     deriveSite{"deriveTransfer", "ErrSelfMove"},
			sentinel: validity.ErrSelfMove,
			prog:     wallet.Tip(types.NativeAsset, a, a, drops(1)),
		},
		{
			what:     "a routed TRANSFER, debiting and crediting one slot",
			site:     deriveSite{"deriveTransfer", "ErrSlotBothWays"},
			sentinel: validity.ErrSlotBothWays,
			prog: wallet.Transfer(
				types.Move{Asset: types.NativeAsset, Src: a, Dst: b, Amount: drops(5)},
				types.Move{Asset: types.NativeAsset, Src: b, Dst: c, Amount: drops(5)},
			),
		},
		// slotSums.add — the inflation site. Two moves out of one source whose
		// amounts sum to exactly 2^256. Every other clause of deriveTransfer is
		// satisfied: three distinct user addresses, no zero amount, no slot
		// both ways. What is left is the accumulation, and the checked addition
		// inside it is the only thing that refuses this program.
		{
			what:     "a TRANSFER whose moves sum to exactly 2^256",
			site:     deriveSite{"add", "ErrAmountOverCap"},
			sentinel: validity.ErrAmountOverCap,
			prog: wallet.Transfer(
				types.Move{Asset: types.NativeAsset, Src: a, Dst: b, Amount: u256.One},
				types.Move{Asset: types.NativeAsset, Src: a, Dst: c, Amount: u256.Max},
			),
		},
		// deriveIssue.
		{
			what:     "an ISSUE by an asset address",
			site:     deriveSite{"deriveIssue", "ErrBadIssuer"},
			sentinel: validity.ErrBadIssuer,
			prog:     wallet.Issue(asset, drops(10), 2, types.Hash{}, alice.PubKey()),
		},
		{
			what:     "an ISSUE with a zero cap",
			site:     deriveSite{"deriveIssue", "ErrZeroCap"},
			sentinel: validity.ErrZeroCap,
			prog:     wallet.Issue(a, u256.Zero, 2, types.Hash{}, alice.PubKey()),
		},
		// deriveMint, in source order. Each of these five satisfies every
		// clause above it, which is what makes it separating rather than merely
		// refused.
		{
			what:     "a MINT of a non-asset id",
			site:     deriveSite{"deriveMint", "ErrBadAsset"},
			sentinel: validity.ErrBadAsset,
			prog:     wallet.Mint(a, b, drops(1), drops(10), alice.PubKey()),
		},
		{
			what:     "a MINT crediting an asset address",
			site:     deriveSite{"deriveMint", "ErrBadDst"},
			sentinel: validity.ErrBadDst,
			prog:     wallet.Mint(asset, asset, drops(1), drops(10), alice.PubKey()),
		},
		{
			what:     "a MINT of zero",
			site:     deriveSite{"deriveMint", "ErrZeroAmount"},
			sentinel: validity.ErrZeroAmount,
			prog:     wallet.Mint(asset, b, u256.Zero, drops(10), alice.PubKey()),
		},
		{
			// cap zero with a non-zero amount: ErrZeroAmount cannot answer, and
			// ErrAmountOverCap below cannot pre-empt a clause above it. This is
			// the over-determined pair this enrolment exists for — delete
			// ErrZeroCap and the same program is refused by ErrAmountOverCap
			// instead, which is exactly why the term needs an input of its own.
			what:     "a MINT against a zero cap",
			site:     deriveSite{"deriveMint", "ErrZeroCap"},
			sentinel: validity.ErrZeroCap,
			prog:     wallet.Mint(asset, b, drops(1), u256.Zero, alice.PubKey()),
		},
		{
			what:     "a MINT above its declared cap",
			site:     deriveSite{"deriveMint", "ErrAmountOverCap"},
			sentinel: validity.ErrAmountOverCap,
			prog:     wallet.Mint(asset, b, drops(11), drops(10), alice.PubKey()),
		},
		// deriveRetire.
		{
			what:     "a RETIRE of nothing",
			site:     deriveSite{"deriveRetire", "ErrEmptyProgram"},
			sentinel: validity.ErrEmptyProgram,
			prog:     wallet.Retire(),
		},
		{
			what:     "a RETIRE of a persistent address",
			site:     deriveSite{"deriveRetire", "ErrRetireNotOwned"},
			sentinel: validity.ErrRetireNotOwned,
			prog:     wallet.Retire(a),
		},
		{
			// Built by hand rather than through wallet.Retire, which sorts and
			// deduplicates: the canonical constructor cannot express the
			// non-canonical list this clause exists to refuse.
			what:     "a RETIRE whose targets are out of order",
			site:     deriveSite{"deriveRetire", "ErrRetireOrder"},
			sentinel: validity.ErrRetireOrder,
			prog: types.Program{
				Kind:   types.ProgramRetire,
				Retire: &types.RetireArgs{Addrs: []types.Address{oneShotHi, oneShotLo}},
			},
		},
	}
}

// selectedBodyIsSet reports whether the body a program's kind selects is
// non-nil — the conjunct that makes every case arm of CheckShape pass, leaving
// the body-count guard as the only clause able to refuse the program.
func selectedBodyIsSet(p types.Program) bool {
	switch p.Kind {
	case types.ProgramTransfer:
		return p.Transfer != nil
	case types.ProgramIssue:
		return p.Issue != nil
	case types.ProgramMint:
		return p.Mint != nil
	case types.ProgramRetire:
		return p.Retire != nil
	}
	// An unknown kind selects no arm at all; the default arm answers instead,
	// so no body can make the count guard the only clause left.
	return false
}

// kindName names a program kind for a diagnostic. core/types spells no String
// method for the type, and adding one would be a production change made to fit
// a test.
func kindName(k types.ProgramKind) string {
	switch k {
	case types.ProgramTransfer:
		return "TRANSFER"
	case types.ProgramIssue:
		return "ISSUE"
	case types.ProgramMint:
		return "MINT"
	case types.ProgramRetire:
		return "RETIRE"
	}
	return "kind " + strconv.Itoa(int(k))
}

// orderedOneShots returns two one-shot addresses in ascending byte order, so
// that reversing them is a list out of order and nothing else.
func orderedOneShots(t *testing.T) (lo, hi types.Address) {
	t.Helper()
	x, y := key(t, 5).OneShot(), key(t, 6).OneShot()
	for i := range x {
		if x[i] != y[i] {
			if x[i] < y[i] {
				return x, y
			}
			return y, x
		}
	}
	t.Fatal("two one-shot addresses derived from different seeds are equal")
	return
}

// TestEveryProgramShapeTermIsSeparated is the same enrolment's deliverable for
// V1's delegate.
//
// Program.CheckShape is in core/types, so terms_test.go's *outward* limit
// already covers it — a site in another package is not scanned and no input is
// demanded. It is closed here rather than filed separately because it is the
// same defect one delegate further out, and this file is the one place the
// pass-through problem is counted.
//
// The five ErrProgramShape sites cannot be told apart by the error they return,
// so the key is the switch arm each sits in, read from the AST. The inputs are
// held to it by construction: each case arm fires only when exactly one body is
// set and the kind selects that arm, and the count guard is separated only by
// two or more bodies **of which the kind-selected one is non-nil** — so each
// input asserts both alongside the sentinel.
//
// Both halves of that were got wrong once, in successive drafts, which is why
// they are asserted rather than described. First the input carried NO body: a
// zero-body program fails the count guard and *also* fails whichever arm its
// kind selects, so `if false && n != 1` left it green while the same mutant made
// CheckShape return nil for a two-body program. Then the fix asserted only
// `bodies >= 2`, which is necessary and not sufficient — {MINT, Transfer,
// Issue} and {RETIRE, Transfer, Issue, Mint} carry two and three bodies and are
// still refused by their own arm. Over-determination twice inside the file that
// exists to find over-determination.
func TestEveryProgramShapeTermIsSeparated(t *testing.T) {
	sites := shapeSites(t)

	type shapeInput struct {
		what string
		site shapeSite
		err  error
		prog types.Program
	}
	moves := &types.TransferArgs{Moves: []types.Move{{
		Asset: types.NativeAsset, Src: key(t, 2).Persistent(),
		Dst: key(t, 3).Persistent(), Amount: drops(1),
	}}}
	issue := &types.IssueArgs{Issuer: key(t, 2).Persistent(), Cap: drops(10)}

	cases := []shapeInput{
		{
			// TWO bodies, not zero, and the difference is the whole point.
			//
			// The first version of this input carried no body at all, and it
			// was defeated: with `if false && n != 1` applied to the count
			// guard, a zero-body TRANSFER is still refused — by the
			// ProgramTransfer arm, whose `p.Transfer == nil` test a program
			// with no body also fails. The input kept passing while the guard
			// it names did nothing, and the same mutant let a *two*-body
			// program through CheckShape entirely, with no input in this table
			// to see it.
			//
			// Two bodies separate the count guard from every arm below it,
			// because each arm tests one pointer for nil and both of these are
			// non-nil. This is the over-determination the file warns about,
			// found in the file's own table.
			what: "a program carrying two bodies",
			site: shapeSite{"", "ErrProgramShape"},
			err:  types.ErrProgramShape,
			prog: types.Program{Kind: types.ProgramTransfer, Transfer: moves, Issue: issue},
		},
		{
			what: "a TRANSFER carrying an ISSUE body",
			site: shapeSite{"ProgramTransfer", "ErrProgramShape"},
			err:  types.ErrProgramShape,
			prog: types.Program{Kind: types.ProgramTransfer, Issue: issue},
		},
		{
			what: "an ISSUE carrying a TRANSFER body",
			site: shapeSite{"ProgramIssue", "ErrProgramShape"},
			err:  types.ErrProgramShape,
			prog: types.Program{Kind: types.ProgramIssue, Transfer: moves},
		},
		{
			what: "a MINT carrying a TRANSFER body",
			site: shapeSite{"ProgramMint", "ErrProgramShape"},
			err:  types.ErrProgramShape,
			prog: types.Program{Kind: types.ProgramMint, Transfer: moves},
		},
		{
			what: "a RETIRE carrying a TRANSFER body",
			site: shapeSite{"ProgramRetire", "ErrProgramShape"},
			err:  types.ErrProgramShape,
			prog: types.Program{Kind: types.ProgramRetire, Transfer: moves},
		},
		{
			what: "a program of an unknown kind",
			site: shapeSite{"default", "ErrProgramKind"},
			err:  types.ErrProgramKind,
			prog: types.Program{Kind: types.ProgramKind(0xff), Transfer: moves},
		},
	}

	covered := map[shapeSite]string{}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			if _, ok := sites[c.site]; !ok {
				t.Fatalf("Program.CheckShape spells no %s; the site this input was written "+
					"for has moved and the input now separates nothing", c.site)
			}
			// The discriminator the sentinel cannot supply. One body means the
			// count guard above the switch cannot be what answered; the kind
			// then selects exactly one arm.
			bodies := 0
			for _, set := range []bool{c.prog.Transfer != nil, c.prog.Issue != nil,
				c.prog.Mint != nil, c.prog.Retire != nil} {
				if set {
					bodies++
				}
			}
			if c.site.arm != "" && bodies != 1 {
				t.Fatalf("this input carries %d bodies and is written for %s; a case arm is "+
					"reached only with exactly one body, so it cannot be reaching the site it "+
					"names", bodies, c.site)
			}
			// Two conjuncts, and the count is the weaker of them.
			//
			// More than one body is necessary: a zero-body program fails the
			// count guard and *also* fails whichever arm its kind selects, so
			// it stays refused with the count guard neutered and separates
			// nothing. But it is **not sufficient**, which an earlier version
			// of this comment claimed and was wrong about — {MINT, Transfer,
			// Issue} carries two bodies and {RETIRE, Transfer, Issue, Mint}
			// carries three, and both are still refused by their own arm under
			// the same mutant. What actually separates the count guard is that
			// **the body the kind selects is non-nil**, so every arm passes and
			// the count is the only clause left with anything to say.
			//
			// Asserted rather than left to the input's shape: without it a
			// later edit that keeps two bodies but drops the selected one
			// passes this check and silently restores the over-determination it
			// was written to remove.
			if c.site.arm == "" {
				if bodies < 2 {
					t.Fatalf("this input carries %d bodies and is written for %s; with fewer "+
						"than two, the arm its kind selects refuses it as well and the input "+
						"survives the count guard being neutered", bodies, c.site)
				}
				if !selectedBodyIsSet(c.prog) {
					t.Fatalf("this input is written for %s but leaves the body its kind (%s) "+
						"selects nil, so that arm refuses it too and the input survives the "+
						"count guard being neutered", c.site, kindName(c.prog.Kind))
				}
			}
			err := c.prog.CheckShape()
			if err == nil {
				t.Fatalf("CheckShape accepts this program, so %s is separated by nothing", c.site)
			}
			if !errors.Is(err, c.err) {
				t.Fatalf("CheckShape rejects with %v, and this input is written for %s", err, c.site)
			}
			if prev, dup := covered[c.site]; dup {
				t.Errorf("%q and %q both key to %s; some other site is then separated by "+
					"nothing while the count still adds up", prev, c.what, c.site)
			} else {
				covered[c.site] = c.what
			}
		})
	}

	var uncovered []string
	for s := range sites {
		if _, ok := covered[s]; !ok {
			uncovered = append(uncovered, s.String())
		}
	}
	if len(uncovered) > 0 {
		sort.Strings(uncovered)
		t.Errorf("%d of Program.CheckShape's %d rejection sites are separated by no input: %s. "+
			"V1 forwards all of them as one term", len(uncovered), len(sites),
			strings.Join(uncovered, "; "))
	}
}

// ---------------------------------------------------------------------------
// The one site whose consequence is unbounded
// ---------------------------------------------------------------------------

// TestATransferSummingPastTheWordIsRefusedByCheck pins slotSums.add's guard at
// the whole predicate rather than at the delegate.
//
// It is stated separately from the table above because the consequence is not a
// peer of the other sixteen. With the guard deleted, this certificate derives
// GUARD_GE operand 0 and DELTA_SUB 0 against the source while crediting 1 and
// 2^256−1 to two destinations: validity.Check returns nil, UnmarshalCertificate
// returns nil so the bytes reach the wire, and fold.ApplyBlock returns APPLIED
// on a valid block — the sender pays the fee alone and a three-address total
// goes from 10^9 to 2^256−1 in one block. Nothing downstream catches it:
// stageWrites checks per-cell overflow only, and every conservationFailure site
// in core/fold is a fee, subsidy or treasury accumulator. core/fold's own
// overflow-unreachability argument rests on conservation (I1-L8), which is the
// invariant this one guard upholds — so the guard is load-bearing for a proof
// written in another package.
//
// The control is what makes this a statement about the sum crossing 2^256 and
// not about the two-move shape: the same two moves with amounts that do not
// wrap derive a single merged GUARD_GE and a single DELTA_SUB of their exact
// total, and the certificate is accepted.
func TestATransferSummingPastTheWordIsRefusedByCheck(t *testing.T) {
	p := spec.Devnet()
	alice, bob, carol := key(t, 2), key(t, 3), key(t, 4)
	a, b, c := alice.Persistent(), bob.Persistent(), carol.Persistent()

	wrapping := wallet.Transfer(
		types.Move{Asset: types.NativeAsset, Src: a, Dst: b, Amount: u256.One},
		types.Move{Asset: types.NativeAsset, Src: a, Dst: c, Amount: u256.Max},
	)

	// The whole predicate, on a certificate a peer could hand us. The program
	// is swapped into an otherwise accepted certificate, so V1 passes (the
	// shape is well formed and two moves are inside the limit) and V3 is the
	// first rule with anything to say.
	cert := termCert(t, p, transferProgram(t), selfDeposit(t), signers(t),
		func(c *types.Certificate) { c.Program = wrapping })
	err := validity.Check(cert, p)
	wantRule(t, err, "V3")
	if !errors.Is(err, validity.ErrAmountOverCap) {
		t.Fatalf("V3 rejects with %v; the term that must answer here is ErrAmountOverCap, and "+
			"a different one answering means the accumulation guard is no longer what refuses "+
			"a wrapped total", err)
	}

	// The control: the same shape, amounts that do not wrap.
	reads, writes, derr := validity.DeriveCert(
		wallet.Transfer(
			types.Move{Asset: types.NativeAsset, Src: a, Dst: b, Amount: drops(1)},
			types.Move{Asset: types.NativeAsset, Src: a, Dst: c, Amount: drops(2)},
		), p.ChainID, 0, a)
	if derr != nil {
		t.Fatalf("two moves out of one source that do not wrap must derive: %v", derr)
	}
	src := types.NativeBalanceSlot(a)
	var guards, debits int
	for _, r := range reads {
		if r.Slot == src {
			guards++
			if r.Access != types.AccessGuardGE || !r.Operand.Eq(drops(3)) {
				t.Fatalf("guard on the source is %d/%s, want GUARD_GE 3", r.Access, r.Operand)
			}
		}
	}
	for _, w := range writes {
		if w.Slot == src {
			debits++
			if w.Op != types.OpDeltaSub || !w.Value.Eq(drops(3)) {
				t.Fatalf("debit on the source is %d/%s, want DELTA_SUB 3", w.Op, w.Value)
			}
		}
	}
	if guards != 1 || debits != 1 {
		t.Fatalf("got %d guards and %d debits on the source, want one of each", guards, debits)
	}
}

// TestDerivationEmitsExactSumsOrRefuses is the property the guard above upholds,
// stated over a swept domain rather than at one point.
//
// The question is whether the guard can be *bypassed* rather than deleted —
// whether some program reaches DeriveCert and produces a wrapped total
// without anyone editing derive.go. slotSums.add is the only place derivation
// adds two certificate-supplied amounts (the only other arithmetic in the
// file is deriveMint's cap − amount, whose underflow flag is discarded under
// the ErrAmountOverCap guard two lines above it), and every value
// deriveTransfer emits is a slot's accumulated total. So the question has an
// answer that can be checked: **for every TRANSFER derivation accepts, each
// emitted operand and delta must equal the exact sum of its contributing
// moves computed in the integers.** A bypass is precisely a program where it
// does not.
//
// **The lemma is exactness, and monotonicity is its corollary rather than its
// premise.** slotSums.add returns *before* it stores (derive.go: the `return
// ErrAmountOverCap` precedes `s.sums[slot] = sum`), so no wrapped value ever
// enters the map; by induction over the move loop, every stored total is the
// exact integer sum of the amounts folded into it, and conservation is exact
// rather than modular. From exactness plus the non-zero-amount check above it,
// the partial sums are strictly increasing — which is *why* an exact total at
// or above 2^256 has a minimal crossing prefix, and that prefix's four-limb Add
// carries out. So the guard sees every wrap, at the single step where it
// happens. Stating monotonicity first, as an earlier draft of this comment did,
// assumes what exactness supplies.
//
// The sweep is exhaustive over one and two moves across an alphabet chosen so
// that wraps occur — three user addresses, two assets, and amounts 1, 2, 2^255
// and 2^256−1, whose pairwise sums cross the word. **The three-move sweep on
// top is REDUCED, not exhaustive**, and what it drops is stated rather than
// implied: one of the three addresses (`addrs[:2]` keeps two), one of the two
// assets, and the amount 2.
// Two moves is where a wrap can first appear and, by the lemma above, where
// every wrap must appear, so the three-move pass is insurance rather than
// coverage.
//
// math/big appears here and nowhere near core/. The exact sum is the thing
// being compared *against* u256, so computing it in u256 would compare the
// arithmetic with itself.
func TestDerivationEmitsExactSumsOrRefuses(t *testing.T) {
	p := spec.Devnet()
	addrs := []types.Address{
		key(t, 2).Persistent(), key(t, 3).Persistent(), key(t, 4).Persistent(),
	}
	assets := []types.Address{
		types.NativeAsset, types.DeriveAssetAddress(p.ChainID, addrs[0], 0),
	}
	amounts := []u256.U256{
		u256.One,
		u256.FromUint64(2),
		u256.Max, // 2^256 − 1
		exp2(255),
	}

	var alphabet []types.Move
	for _, asset := range assets {
		for _, src := range addrs {
			for _, dst := range addrs {
				for _, amt := range amounts {
					alphabet = append(alphabet, types.Move{
						Asset: asset, Src: src, Dst: dst, Amount: amt,
					})
				}
			}
		}
	}

	accepted := 0
	check := func(moves []types.Move) {
		prog := types.Program{Kind: types.ProgramTransfer,
			Transfer: &types.TransferArgs{Moves: append([]types.Move(nil), moves...)}}
		reads, writes, err := validity.Derive(prog, p.ChainID, 0)
		if err != nil {
			return
		}
		accepted++
		assertExactSums(t, moves, reads, writes)
	}

	for i := range alphabet {
		check(alphabet[i : i+1])
		for j := range alphabet {
			check([]types.Move{alphabet[i], alphabet[j]})
		}
	}
	// Three moves over a reduced alphabet: two addresses, one asset, three
	// amounts. Enough to reach a total above 2^256 by three different routes to
	// it, without the cube of the full alphabet.
	var small []types.Move
	for _, src := range addrs[:2] {
		for _, dst := range addrs[:2] {
			for _, amt := range []u256.U256{u256.One, u256.Max, exp2(255)} {
				small = append(small, types.Move{
					Asset: types.NativeAsset, Src: src, Dst: dst, Amount: amt,
				})
			}
		}
	}
	for i := range small {
		for j := range small {
			for k := range small {
				check([]types.Move{small[i], small[j], small[k]})
			}
		}
	}

	if accepted == 0 {
		t.Fatal("the sweep accepted no program at all, so it asserted nothing about what an " +
			"accepted derivation emits")
	}
	t.Logf("%d of the swept TRANSFER programs derive; each emits exact integer sums", accepted)
}

// assertExactSums checks the derived read and write sets of an accepted
// TRANSFER against sums computed in the integers.
func assertExactSums(t *testing.T, moves []types.Move, reads []types.Read, writes []types.Write) {
	t.Helper()
	wordCeiling := new(big.Int).Lsh(big.NewInt(1), 256)

	debits := map[types.Slot]*big.Int{}
	credits := map[types.Slot]*big.Int{}
	addTo := func(m map[types.Slot]*big.Int, s types.Slot, v u256.U256) {
		cur, ok := m[s]
		if !ok {
			cur = new(big.Int)
			m[s] = cur
		}
		cur.Add(cur, toBig(v))
	}
	for _, m := range moves {
		addTo(debits, types.BalanceSlot(m.Src, m.Asset), m.Amount)
		addTo(credits, types.BalanceSlot(m.Dst, m.Asset), m.Amount)
	}

	// Acceptance implies no total crossed the word. This is the bypass
	// question stated as an assertion: a wrapped total that reached the write
	// set would be a slot whose exact sum is at or above 2^256.
	for slot, want := range debits {
		if want.Cmp(wordCeiling) >= 0 {
			t.Fatalf("derivation accepted a program whose debits on one slot sum to %s, at or "+
				"above 2^256; the emitted delta cannot be that number and is therefore a "+
				"wrapped total that reached the write set (slot addr %x)", want, slot.Addr[:4])
		}
	}
	for slot, want := range credits {
		if want.Cmp(wordCeiling) >= 0 {
			t.Fatalf("derivation accepted a program whose credits on one slot sum to %s, at or "+
				"above 2^256 (slot addr %x)", want, slot.Addr[:4])
		}
	}

	// And the emitted values are those sums, not some other number: one
	// GUARD_GE and one DELTA_SUB per debited slot, one DELTA_ADD per credited
	// slot, each equal to the exact total.
	seenGuard := map[types.Slot]bool{}
	for _, r := range reads {
		want, ok := debits[r.Slot]
		if !ok {
			t.Fatalf("derivation emitted a read on a slot no move debits")
		}
		if r.Access != types.AccessGuardGE || toBig(r.Operand).Cmp(want) != 0 {
			t.Fatalf("guard on a debited slot is %d/%s, want GUARD_GE %s", r.Access, r.Operand, want)
		}
		if seenGuard[r.Slot] {
			t.Fatalf("two guards on one slot; the merge R1-M1 requires has not happened")
		}
		seenGuard[r.Slot] = true
	}
	if len(seenGuard) != len(debits) {
		t.Fatalf("%d debited slots and %d guards", len(debits), len(seenGuard))
	}

	seenDelta := map[types.Slot]bool{}
	for _, w := range writes {
		var want *big.Int
		switch w.Op {
		case types.OpDeltaSub:
			want = debits[w.Slot]
		case types.OpDeltaAdd:
			want = credits[w.Slot]
		case types.OpMarkSpent:
			continue
		default:
			t.Fatalf("a TRANSFER derived op %d, which deriveTransfer does not emit", w.Op)
		}
		if want == nil {
			t.Fatalf("derivation emitted a delta on a slot no move touches")
		}
		if toBig(w.Value).Cmp(want) != 0 {
			t.Fatalf("delta on a slot is %s, want the exact total %s", w.Value, want)
		}
		if seenDelta[w.Slot] {
			t.Fatalf("two deltas on one slot")
		}
		seenDelta[w.Slot] = true
	}
	if len(seenDelta) != len(debits)+len(credits) {
		t.Fatalf("%d touched slots and %d deltas", len(debits)+len(credits), len(seenDelta))
	}

	// Conservation, which is the invariant core/fold's own overflow argument
	// rests on: what leaves the debited slots is exactly what arrives at the
	// credited ones, in the integers and not modulo anything.
	out, in := new(big.Int), new(big.Int)
	for _, v := range debits {
		out.Add(out, v)
	}
	for _, v := range credits {
		in.Add(in, v)
	}
	if out.Cmp(in) != 0 {
		t.Fatalf("an accepted TRANSFER debits %s and credits %s", out, in)
	}
}

func toBig(v u256.U256) *big.Int {
	b := v.Bytes()
	return new(big.Int).SetBytes(b[:])
}

// exp2 returns 2^n for n < 256.
func exp2(n uint) u256.U256 {
	var b [32]byte
	b[31-n/8] = 1 << (n % 8)
	return u256.FromBytes(b)
}

// ---------------------------------------------------------------------------
// The scans
// ---------------------------------------------------------------------------

// derivationSites reads derive.go's rejection sites, keyed by enclosing
// function and sentinel, and separates out the ones inside a `default:` arm.
//
// The discovery rule is namedErrorReturns'. What is added is the key: that scan
// counts sites and collects sentinel names, and a count cannot say which site
// an input covers.
func derivationSites(t *testing.T) (map[deriveSite]bool, []deriveSite) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "derive.go", nil, 0)
	if err != nil {
		t.Fatalf("derive.go does not parse, so this scan reads nothing: %v", err)
	}

	firing := map[deriveSite]bool{}
	var defaultArm []deriveSite
	for _, d := range f.Decls {
		decl, ok := d.(*ast.FuncDecl)
		if !ok || decl.Body == nil {
			continue
		}
		inDefault := map[*ast.ReturnStmt]bool{}
		ast.Inspect(decl.Body, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok || cc.List != nil {
				return true
			}
			for _, st := range cc.Body {
				if ret, ok := st.(*ast.ReturnStmt); ok {
					inDefault[ret] = true
				}
			}
			return true
		})
		ast.Inspect(decl.Body, func(n ast.Node) bool {
			ret, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			name, ok := returnedSentinel(ret)
			if !ok {
				return true
			}
			s := deriveSite{fn: decl.Name.Name, sentinel: name}
			if inDefault[ret] {
				defaultArm = append(defaultArm, s)
				return true
			}
			if firing[s] {
				t.Fatalf("derive.go has two %s sites, so one input would silently cover both "+
					"and the other term would be separated by nothing. Give the second a "+
					"function of its own, or this key stops being one", s)
			}
			firing[s] = true
			return true
		})
	}
	if len(firing) == 0 {
		t.Fatal("derive.go returns no named error anywhere; the call shape has changed and " +
			"this scan now counts nothing")
	}
	return firing, defaultArm
}

// shapeSites reads Program.CheckShape's rejection sites, keyed by the switch arm
// each sits in.
func shapeSites(t *testing.T) map[shapeSite]bool {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), "../types/types.go", nil, 0)
	if err != nil {
		t.Fatalf("core/types/types.go does not parse: %v", err)
	}
	var body *ast.BlockStmt
	for _, d := range f.Decls {
		if decl, ok := d.(*ast.FuncDecl); ok && decl.Name.Name == "CheckShape" && decl.Body != nil {
			body = decl.Body
		}
	}
	if body == nil {
		t.Fatal("core/types declares no CheckShape; V1's delegate has moved and this scan read " +
			"nothing")
	}

	arm := map[*ast.ReturnStmt]string{}
	ast.Inspect(body, func(n ast.Node) bool {
		cc, ok := n.(*ast.CaseClause)
		if !ok {
			return true
		}
		label := "default"
		if len(cc.List) == 1 {
			if id, ok := cc.List[0].(*ast.Ident); ok {
				label = id.Name
			}
		}
		ast.Inspect(cc, func(m ast.Node) bool {
			if ret, ok := m.(*ast.ReturnStmt); ok {
				arm[ret] = label
			}
			return true
		})
		return true
	})

	sites := map[shapeSite]bool{}
	ast.Inspect(body, func(n ast.Node) bool {
		ret, ok := n.(*ast.ReturnStmt)
		if !ok {
			return true
		}
		name, ok := returnedSentinel(ret)
		if !ok {
			return true
		}
		s := shapeSite{arm: arm[ret], sentinel: name}
		if sites[s] {
			t.Fatalf("CheckShape has two %s sites; one input would cover both and the other "+
				"term would be separated by nothing", s)
		}
		sites[s] = true
		return true
	})
	if len(sites) == 0 {
		t.Fatal("CheckShape returns no named error; the call shape has changed and this scan " +
			"now counts nothing")
	}
	return sites
}

// returnedSentinel reports the Err… value a return statement hands back, under
// namedErrorReturns' discovery rule: an identifier or selector named Err…, at
// any arity.
func returnedSentinel(ret *ast.ReturnStmt) (string, bool) {
	for _, r := range ret.Results {
		switch v := r.(type) {
		case *ast.Ident:
			if strings.HasPrefix(v.Name, "Err") {
				return v.Name, true
			}
		case *ast.SelectorExpr:
			if strings.HasPrefix(v.Sel.Name, "Err") {
				return v.Sel.Name, true
			}
		}
	}
	return "", false
}
