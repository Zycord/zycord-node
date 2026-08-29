package validity_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
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
// The count, not the instances: every rejection term of an enrolled rule is
// separated by an input of its own
// ---------------------------------------------------------------------------
//
// This file is a sibling of spec/invalid_rules_test.go, one level down. That
// file asks whether every V-rule §7 defines is armed at all, and arms an
// exemption by counting the rule's rejection *sites* in this package's source
// (vRuleGuardedRoutes) and demanding one certificate per site. The same counting
// is what a rule needs internally, and this is what its absence costs: V6 has
// seven rejection terms and had three separating inputs, so deleting an entire
// `case types.OpDeltaSub:` block from CheckSelfConsistency survived
// core/validity, core/fold, spec and sim, and so did inverting one comparison
// inside it.
//
// A test per survivor would have closed those two mutants and left the shape.
// What is enforced here instead is the *count*: the enrolled rules' rejection
// sites are read out of core/validity's own source, every site must be produced
// by some input below, and every input must be traceable to exactly one site. A
// term added to an enrolled rule fails this test until it has an input; an input
// that stops separating the term it was written for stops matching that site and
// fails as an uncovered site rather than passing as a green assertion about a
// different term. That is the failure this project has hit four times in one
// run — a test name generalising over a conjunction while one term goes unvaried
// — expressed as a check rather than as a habit.

// enrolledRules are the rules whose rejection terms are counted here.
//
// **Stated limits, in the shape spec/invalid_rules_test.go states its own,
// because a promise wider than the check is worse than no promise.**
//
// (1) The enrolment is V1 through V6 — every rule this package rejects by whose
// terms nothing else counts. V7 and V9 are deliberately outside it: their one
// and four sites are already armed per-site by spec/invalid_rules_test.go's
// vRuleGuardedRoutes, and enrolling them here would be a second demand for the
// same routes rather than coverage of a new one. V8 is not this package's rule
// at all — the fold enforces it as B2. So no V-rule term is counted by nothing
// and none is counted twice, which is what the enrolment is for.
//
// (2) The site scan reads `fail`/`failf` calls in this package's non-test
// sources. **That is the discovery rule, and it is where this test's promise
// stops.** A rejection site in *another* package is not seen and no input is
// demanded for it — and that is not hypothetical: V1's list bounds and fee-bid
// canonicity are enforced a second time in types.UnmarshalCertificate, where
// this scan does not look, so the inputs below pin the in-memory clauses of
// CheckCanonical and say nothing about the decoder's.
//
// **And the scan's call shape, which is the one silent miss and used to be
// denied here.** It matches `call.Fun.(*ast.Ident)`, so it sees `failf(…)`
// spelled with that identifier and nothing else. **A `fail`/`failf` reached
// through a function-valued variable is skipped without a word** — measured: a
// package-level `var aliasFailf = failf` with an eighth V6 site behind it left
// the demand at thirty-eight and the suite green, while the identical site
// spelled inline went red at thirty-eight naming the uncovered term. A call
// through a selector (`pkg.failf`) is outside it for the same reason. This
// paragraph previously said that *everything* other than the cross-package limit
// was "a loud refusal rather than a silent skip", and that sentence was simply
// false; no such call exists at head, so the miss is latent rather than live,
// but a limits paragraph that denies a hole is worse than one that names it.
// **Prefer stating this to widening the match** — resolving a function-valued
// identifier means tracking assignments, which is a shape assumption of its own.
//
// Everything else that could make the scan read less than it claims IS a loud
// refusal, and those are worth separating from the above because only the silent
// kind is survivable: a `fail`/`failf` whose rule id is not a string literal, a
// second formatless site for one rule, a duplicated format, and an enrolled rule
// the scan cannot find all fail this test. Method bodies are *not* a hole —
// ast.FuncDecl covers them, and a rejection site inside one raises the demand
// like any other; nor is extracting the three DELTA_SUB terms into a helper,
// which is the ordinary refactor and keeps every term counted and every input
// separating. Both were checked by adding the site and watching the count move.
//
// (3) A term is keyed by its format string, so two sites sharing one format
// would be indistinguishable and one input would silently cover both. That is
// refused below rather than assumed away. The one site shape that has no format
// — `fail(rule, err)`, which forwards a delegated check's error, as V1 does for
// Program.CheckShape and V3 for DeriveCert — is keyed by elimination instead of
// being refused, under the two guards passThroughSite states: one such site per
// rule, and one input landing there per rule. Elimination is the weakest key in
// this file and it is named as such rather than dressed up; the alternative was
// to rewrite two production call sites to carry a format, which would move an
// error string to fit a test.
//
// (3b) **And the inward limit that follows from it: a pass-through counts its
// delegate's whole interior as ONE term.** Limit (2) is about a clause
// enforced outside this package; this is a clause enforced *inside* it and
// still invisible to THIS test, which is the worse of the two because nothing
// about the enrolment suggests it. It is a limit on the enrolment below and
// not a hole in the tree: derive_terms_test.go is the second enrolment, and
// it counts both interiors site by site. What stays true here is that the
// count this file produces — thirty-eight — treats each delegate as one. Both
// pass-throughs have an interior:
//
//   - V3 forwards DeriveCert, which is in this package and spells thirteen
//     distinct sentinels across EIGHTEEN return sites, all reported as one.
//     Seventeen of the eighteen both fire and are deletable; the eighteenth is
//     Derive's own `default:` arm, which is neither. It is unreachable —
//     CheckShape runs first and its switch already refuses every kind outside
//     the four — so it is a Go exhaustiveness stub with no protocol content,
//     and that is also why removing it is a compile error rather than a mutant.
//     That unreachability is not asserted here: TestSpecReadmeNumbersAreDerived-
//     NotAsserted sweeps all 256 program kinds against all 16 subsets of the
//     four body pointers, the complete domain, and fails if one ever escapes.
//     SEVEN of the seventeen live sites used to survive deletion with
//     core/validity, core/types and spec all green; each now has an input in
//     derive_terms_test.go.
//   - V1 forwards types.Program.CheckShape, which spells two sentinels across
//     six return sites — five ErrProgramShape and one ErrProgramKind — also
//     reported as one. That delegate is in another package, so limit (2) covers
//     it as well; it is named here because the same mechanism produces it, and
//     derive_terms_test.go separates its six sites for the same reason.
//
// The severity is NOT uniform across the seven, and flattening them would be
// its own defect. Three are over-determined — a neighbouring sentinel or
// another V-rule answers in their place, and the certificate stays invalid.
// Three make validity.Check accept a malformed certificate. **And one is
// committed inflation:** deleting slotSums.add's `return ErrAmountOverCap`
// makes a two-move TRANSFER summing to exactly 2^256 derive GUARD_GE operand
// 0 and DELTA_SUB 0 against the source while crediting 2^256-1 to a
// destination. Measured end to end: validity.Check returns nil,
// UnmarshalCertificate returns nil so it reaches the wire, **fold.ApplyBlock
// returns APPLIED on a valid block**, the sender pays only the fee, and a
// three-address total goes from 10^9 to 2^256-1. Nothing downstream catches
// it — stageWrites checks per-cell overflow only, every conservationFailure
// site is a fee, subsidy or treasury accumulator, and core/fold's own comment
// rests its overflow-unreachability proof on conservation (I1-L8), which is
// the invariant this one guard upholds. That guard is present and correct
// today, and since the second enrolment landed its removal is noticed twice:
// by the input keyed to its site, and by
// TestDerivationEmitsExactSumsOrRefuses, which sweeps TRANSFER programs whose
// amounts cross the word and requires every accepted derivation to emit exact
// integer sums.
//
// **Where "eighteen" came from, because the number is now published in
// spec/README.md and a count is only as good as the scan behind it.** It is a
// grep over derive.go for a `return` of a named error, at any arity, methods
// included. That scan has already been wrong once: the first version matched
// only `return nil, nil, Err...` and missed slotSums.add's bare
// `return ErrAmountOverCap` — the inflation site above, found only because the
// count was re-derived. So eighteen is the number a return-shape scan can see,
// which is the same class of assumption as limit (2) and is stated for the same
// reason.
//
// All of this is closed by the second enrolment in derive_terms_test.go, and
// it is why "thirty-eight terms" below is the number of sites this scan can
// SEE and not the number of clauses the predicate contains. Stating it here
// is the point: the previous version of this paragraph named only the outward
// limit, and a limits paragraph that names one direction reads as if it named
// both.
//
// (4) Every certificate here is a devnet, Era-0 certificate. A term reachable
// only under other parameters or a later program set is outside what these
// inputs exercise — which is the point of the `check` column, not a caveat on
// it: four of V6's seven terms are unreachable through validity.Check in Era 0,
// and the column records which rule answers instead so that the day one becomes
// reachable, the recorded answer moves and this test says so.
//
// (5) This counts separation, not correctness. An input that reaches a term
// for the wrong reason still covers it. What the count buys is that no term
// is reached by *nothing*, which is the state the surviving mutants above
// measured.
//
// (6) An input is proved separating by the bijection this test enforces, not by
// a claim beside it: there are as many inputs as sites, every site is covered,
// and no two inputs may key to the same site. So each input reaches exactly one
// term and each term is reached by exactly one input, and muting any term leaves
// its site uncovered — which is the property "this input separates the term it
// names" means. What it does not prove is that the input reaches the term for
// the reason its `what` string gives; that is limit (5) again.
var enrolledRules = []string{"V1", "V2", "V3", "V4", "V5", "V6"}

// TestEveryRejectionTermIsSeparated is the count-enforcing half.
func TestEveryRejectionTermIsSeparated(t *testing.T) {
	p := spec.Devnet()
	sites := rejectionSites(t, enrolledRules)

	// Landmarks, one per enrolled rule, at the two sites this file was written
	// for. A source-derived count can only demand what the source still
	// spells, so deleting a term deletes its own demand: these two say so out
	// loud for the two terms this file was written for, and the inputs below say
	// it for the other thirteen, since a term with no site left produces no
	// rejection for its input to key.
	//
	// Reported rather than fatal, so that removing a term produces the whole
	// diagnosis — the missing site and the input that stopped separating
	// anything — instead of only the first line of it.
	for _, want := range []string{
		"V6: DELTA_SUB bounded only from above",
		"V5: deposit cell is not owned by a user address",
		// One per rule brought into the enrolment, each at a term that was
		// counted by nothing: V1's two decoder-shadowed clauses, V3's
		// element-wise write comparison, V4's minimality, and V2's single term.
		"V1: %d moves exceeds the limit of %d",
		"V1: sequential priority %s exceeds the maximum of %s",
		"V2: signature %d does not verify",
		"V3: declared write %d does not match the derived write",
		"V4: signature %d authorises nothing",
	} {
		parts := strings.SplitN(want, ": ", 2)
		if _, ok := sites[siteKey{rule: parts[0], format: parts[1]}]; !ok {
			t.Errorf("the rejection-site scan found no %q in core/validity; the rule has been "+
				"reworded, deleted, or the call shape has changed, and this test now demands a "+
				"different set of inputs than it documents", want)
		}
	}
	// And the two delegated checks, whose sites spell no format and are keyed by
	// elimination. Named here because elimination is the weakest key in this
	// file: if one of these stops being a pass-through the demand silently
	// becomes a different one, and this is where that is said out loud.
	for _, want := range []siteKey{
		{rule: "V1", format: "CheckCanonical", passThrough: true},
		{rule: "V3", format: "CheckDerivation", passThrough: true},
	} {
		if _, ok := sites[want]; !ok {
			t.Errorf("the rejection-site scan found no %s in core/validity; %s no longer "+
				"forwards a delegated check's error, so the site matched by elimination is "+
				"not the one this file documents", want.label(), want.rule)
		}
	}

	cases := separatingInputs(t, p)
	if len(cases) == 0 {
		t.Fatal("no separating input is built; this test would assert nothing")
	}

	// The baseline every case below edits must itself be accepted, by the whole
	// predicate and by both entry points. Otherwise a case could be answered by
	// a rule its edit did not cause, and the arming would pass having proved
	// nothing about the term it names.
	base := termCert(t, p, transferProgram(t), selfDeposit(t), signers(t), func(*types.Certificate) {})
	if err := validity.Check(base, p); err != nil {
		t.Fatalf("the unedited baseline certificate is already invalid (%v); every input "+
			"below could then be answered by a rule its edit did not cause", err)
	}

	covered := map[siteKey]string{}
	// Inputs that matched none of their rule's spelled formats and were keyed to
	// its pass-through site by elimination. More than one per rule is the drift
	// this key cannot otherwise see; see passThroughSite.
	eliminated := map[string][]string{}
	for _, c := range cases {
		t.Run(c.what, func(t *testing.T) {
			// The rule's own function: this is where the term is separated, and
			// for four of V6's seven it is the only place it can be.
			err := c.direct(c.cert, p)
			if err == nil {
				t.Fatalf("%s does not reject this certificate, so the term it is written for "+
					"is separated by nothing", c.entry)
			}
			if got := validity.Rule(err); got != c.rule {
				t.Fatalf("%s answers %s, want %s", c.entry, ruleOrNothing(got), c.rule)
			}
			key, ok := matchSite(t, sites, c.rule, err)
			if !ok {
				// The message belongs to no format this package spells for the
				// rule, so either it came from the rule's delegated check — the
				// one site that has no format — or the input has drifted off the
				// term it was written for.
				key, ok = passThroughSite(sites, c.rule)
				if !ok {
					t.Fatalf("%s rejects with %q, which matches no rejection site core/validity "+
						"spells for %s — this input has stopped separating a term and now covers "+
						"none", c.entry, err.Error(), c.rule)
				}
				eliminated[c.rule] = append(eliminated[c.rule], c.what)
			}
			// Two inputs keyed to one site is a defect, not a note. It used to be
			// a t.Logf, and the limits paragraph above already claimed "no two
			// inputs may key to the same site" while the code merely mentioned
			// it — a limit claiming more than the check enforces, in the file
			// whose whole purpose is to find exactly that.
			//
			// It is also what let three deletion mutants live. Removing
			// `if len(c.Reads) > p.MaxReads { … }` *whole* deletes the site along
			// with the guard, so the count drops to match; the orphaned input
			// then falls through to the read-ordering site, which a note tolerated
			// and every other check found green. The same held for max_writes and
			// max_sigs. Condition mutants (`if false && …`) never showed it,
			// because they leave the site in the source and the demand with it —
			// and the surviving mutants' actual shape was deletion.
			//
			// There are zero collisions at head, so this costs nothing today. If a
			// term ever genuinely needs two inputs, the second is not a duplicate
			// of the first: give it a site of its own, or say which one it covers.
			if prev, dup := covered[key]; dup {
				t.Errorf("%q and %q both key to the %s term %q. Two inputs on one site means "+
					"some other term is separated by nothing while the count still adds up — "+
					"and if a site was deleted along with its guard, the count adds up because "+
					"the demand went with it", prev, c.what, c.rule, key.label())
			} else {
				covered[key] = c.what
			}

			// And what the whole predicate says about the same certificate. For a
			// term Era 0 can reach this is the same rule; for one it cannot, it is
			// the rule that answers first, recorded so that the unreachability is
			// data rather than a comment.
			got := ruleOrNothing(validity.Rule(validity.Check(c.cert, p)))
			if got != c.check {
				t.Errorf("validity.Check answers %s on this certificate and the table records "+
					"%s — either a term that could not be reached through the whole predicate "+
					"in Era 0 now can, or an earlier rule has stopped answering first; both "+
					"change what this input separates", got, c.check)
			}
		})
	}

	// Elimination admits exactly one input per rule. Two mean one of them
	// stopped matching the format it was written for and was absorbed here,
	// which would leave its own term separated by nothing with the count still
	// met — the failure elimination would otherwise introduce.
	for rule, inputs := range eliminated {
		if len(inputs) > 1 {
			sort.Strings(inputs)
			t.Errorf("%d inputs reject under %s with a message matching none of the formats "+
				"core/validity spells for it (%s), and %s has one site keyed by elimination. "+
				"One of these has drifted off the term it was written for and is now covering "+
				"the delegated site instead", len(inputs), rule, strings.Join(inputs, "; "), rule)
		}
	}

	// The count itself. A term with no input is the defect this file exists to
	// name, and it is reported by name so the missing input is obvious.
	var uncovered []string
	for k := range sites {
		if _, ok := covered[k]; !ok {
			uncovered = append(uncovered, k.rule+": "+k.label())
		}
	}
	if len(uncovered) > 0 {
		sort.Strings(uncovered)
		t.Errorf("%d of the %d rejection terms core/validity spells for %v are separated by "+
			"no input: %s. A guard with k terms needs k separating inputs; deleting or "+
			"inverting an unseparated one is invisible to every test in this tree",
			len(uncovered), len(sites), enrolledRules, strings.Join(uncovered, "; "))
	}
}

// TestV5NarrowsTheDepositToUserAddresses states V5's narrowing as the boundary
// rather than as a reachability count.
//
// CheckDeposit's `crypto.IsUserAddress(d.Cell.Addr)` narrows the deposit cell
// away from 0x00 — the protocol address, where the treasury accrues — and away
// from 0x03. Widening it to crypto.IsKnownAddressVersion, the edit a refactor
// unifying two nearby version tests would make, used to move validity.Check
// from V5 to *accepted* on a re-signed certificate depositing from the treasury
// cell, with no test in the tree moving.
//
// **It is no longer the only narrowing, and the shape of this test is what
// changed with it.** V4 now requires an authorising signature for any deposit
// cell rather than only for a user one, so the treasury is refused by two
// rules that share no call. A test that asserted only what validity.Check
// answers would be satisfied by either rule alone and would keep passing
// after the other was deleted — one predicate wearing two names, which is the
// state this pair of rules exists to avoid. So each rule is asked on its own,
// and what Check answers is recorded beside them rather than standing in for
// them.
//
// The two arms do not cover the same ground, and the input below the loop is
// where that asymmetry is separated rather than caveated: no key hashes to
// crypto.ProtocolAddress, but AddressFromPubKey(0x03, pub) is an ordinary
// derived address anyone can hold, so at 0x03 V5's clause is still the sole
// gate.
//
// The term-count test above cannot catch that on its own: a single 0x04 deposit
// cell covers the site, and 0x04 is refused by V9 as well, so an input at 0x04
// alone would keep the site covered under the widened predicate. The boundary is
// what has to be pinned, so both versions inside IsKnownAddressVersion and
// outside IsUserAddress are asserted, for the deposit cell and for RefundTo,
// which carries the identical clause.
func TestV5NarrowsTheDepositToUserAddresses(t *testing.T) {
	p := spec.Devnet()

	// Derived from the predicates themselves rather than written out, so that a
	// fifth address version added to crypto arrives here as a case instead of as
	// a gap. 0x04 is deliberately not in this set: it is outside both predicates,
	// so it cannot tell them apart, and it is already covered by spec's V9
	// arming.
	var between []byte
	for v := 0; v <= 0xff; v++ {
		var a types.Address
		a[0] = byte(v)
		if crypto.IsKnownAddressVersion(a) && !crypto.IsUserAddress(a) {
			between = append(between, byte(v))
		}
	}
	if len(between) == 0 {
		t.Fatal("no address version is known but not a user address, so IsUserAddress and " +
			"IsKnownAddressVersion no longer differ and this test separates nothing")
	}
	for _, want := range []byte{crypto.AddrVersionProtocol, crypto.AddrVersionAsset} {
		if !containsByte(between, want) {
			t.Fatalf("version 0x%02x is no longer known-but-not-user; the two predicates have "+
				"moved and this test is not about the clause it names", want)
		}
	}

	for _, version := range between {
		name := "0x" + strconv.FormatUint(uint64(version), 16)
		t.Run("deposit cell at "+name, func(t *testing.T) {
			c := termCert(t, p, transferProgram(t), selfDeposit(t), signers(t),
				func(c *types.Certificate) { c.Deposit.Cell.Addr = versionOf(t, version, 31) })
			// Each rule on its own, which is the whole point. V5's clause is
			// asked directly, and so is V4's, and both must refuse — because a
			// seal that survives one edit is a seal made of two predicates, not
			// one predicate asserted twice. Asserting only what the whole
			// predicate answers would be satisfied by either rule alone and
			// would go on passing after the other was deleted, which is the
			// exact state asking each rule separately exists to avoid.
			//
			// The V4 arm's reach is not uniform across these versions, and the
			// case below the loop is where that is said with an input rather
			// than in prose. versionOf overwrites byte 0 of a persistent
			// address, and the version byte is part of the address hash's own
			// input, so what it produces is derived from no key at any version
			// — which is why V4 refuses it at 0x03 as well as at 0x00.
			//
			// Reported rather than fatal, and that is the arming rather than a
			// style preference. wantRule calls t.Fatalf, so with it the first
			// arm to die would stop the subtest and the second would never run
			// — and a mutation probe breaking V5 could then not observe that V4
			// still fires, which is exactly the claim these two lines exist to
			// make. Both arms run on every certificate, so a mutant that kills
			// one leaves the other's silence as evidence.
			reportRule(t, "V5, asked directly", validity.CheckDeposit(c, p), "V5")
			reportRule(t, "V4, asked directly", validity.CheckAuthorization(c), "V4")

			// And what the whole predicate answers, recorded rather than
			// claimed: V4 runs before V5 in CheckStructural and no key hashes
			// to a non-user address, so Check now stops at V4. The value of
			// this line is that it moves if the rule order does.
			reportRule(t, "the whole predicate", validity.Check(c, p), "V4")
		})
		t.Run("refund target at "+name, func(t *testing.T) {
			c := termCert(t, p, transferProgram(t), selfDeposit(t), signers(t),
				func(c *types.Certificate) { c.Deposit.RefundTo.Addr = versionOf(t, version, 32) })
			wantRule(t, validity.Check(c, p), "V5")
			wantRule(t, validity.CheckDeposit(c, p), "V5")
		})
	}

	// Where the two arms stop being interchangeable, stated as the one input
	// that separates them rather than as a caveat beside them.
	//
	// crypto.ProtocolAddress is 0x00 followed by 31 zero bytes and is
	// deliberately not a hash, so no key satisfies a V4 requirement naming it
	// and the treasury is sealed twice over. An asset address is an ordinary
	// derived address: AddressFromPubKey(0x03, pub) is one anybody can hold,
	// and a deposit cell at such an address carries a signature V4 accepts. So
	// at 0x03 — and at 0x03 only — V5's narrowing is still the sole gate, and
	// this is the assertion that fails the day someone widens it believing V4
	// covers the case.
	assetKey := key(t, 34)
	keyDerivedAsset := assetKey.Address(crypto.AddrVersionAsset)
	if !crypto.IsKnownAddressVersion(keyDerivedAsset) || crypto.IsUserAddress(keyDerivedAsset) {
		t.Fatal("a key-derived 0x03 address is no longer known-but-not-user, so this case " +
			"no longer separates the two arms it is written for")
	}
	held := termCert(t, p, transferProgram(t), selfDeposit(t), signers(t),
		func(c *types.Certificate) { c.Deposit.Cell.Addr = keyDerivedAsset })
	resign(p, held, key(t, 2), assetKey)
	sortSigs(held)
	if err := validity.CheckAuthorization(held); err != nil {
		t.Fatalf("V4 is satisfied by a signature over a key-derived 0x03 deposit cell, so it "+
			"cannot be the rule that refuses one; this case claims the opposite: %v", err)
	}
	wantRule(t, validity.CheckDeposit(held, p), "V5")
	wantRule(t, validity.Check(held, p), "V5")

	// The control, which is what makes the statements above about the
	// *version* byte and not about the edit: the same certificate with a user
	// address in the same field is accepted.
	ok := termCert(t, p, transferProgram(t), selfDeposit(t), signers(t),
		func(c *types.Certificate) { c.Deposit.RefundTo.Addr = key(t, 33).Persistent() })
	if err := validity.Check(ok, p); err != nil {
		t.Fatalf("refunding to an untouched persistent address must stay valid: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The numbers spec/README.md publishes are derived here, not restated
// ---------------------------------------------------------------------------

// TestSpecReadmeNumbersAreDerivedNotAsserted binds every count spec/README.md
// states about this package to what a scan of the source actually finds.
//
// It exists because the sentence it replaces was false. This file and
// spec/README.md carried the same numbers written twice by hand, under a claim
// that "the two cannot drift" — and nothing bound them. No test read the
// document's numbers, so two hand-written copies drifted independently and the
// claim was exactly the defect this file's own limits paragraph names: *a
// promise wider than the check is worse than no promise*. Rather than delete the
// sentence, this makes it true.
//
// The precedent is spec/invalid_rules_test.go, which reads V-rule ids out
// of ARCHITECTURE.md §7 rather than restating them, for the same reason: the
// document is normative for a second implementation, so the tree must be checked
// against the document rather than the document maintained alongside the tree.
//
// **What is bound, and what is not.** Bound: the thirty-eight-term count and how
// many of those are pass-throughs; derive.go's eighteen return sites and
// their thirteen distinct sentinels; Program.CheckShape's six sites and two
// sentinels; and the seventeen-versus-eighteen split, whose unreachable
// member is identified structurally AND proven unreachable by exhaustive
// sweep below. NOT bound, and named here rather than covered by the claim:
// **the seven that used to survive.** That number is a mutation-testing
// result — it says what happens when a guard is deleted — and no passing test
// can derive it, because deriving it would mean writing the mutants into the
// tree. It is a statement about the tree before the second enrolment; with
// derive_terms_test.go in place all seventeen are killed, both by deleting
// the return and by neutering the condition. Both measurements are by hand,
// and spec/README.md should be read as citing derive_terms_test.go for them.
func TestSpecReadmeNumbersAreDerivedNotAsserted(t *testing.T) {
	raw, err := os.ReadFile("../../spec/README.md")
	if err != nil {
		t.Fatal(err)
	}
	doc := string(raw)

	sites := rejectionSites(t, enrolledRules)
	var passThroughs int
	for k := range sites {
		if k.passThrough {
			passThroughs++
		}
	}
	deriveSites, deriveSentinels := namedErrorReturns(t, "derive.go", "")
	shapeSites, shapeSentinels := namedErrorReturns(t, "../types/types.go", "CheckShape")

	// The one site that does not fire, established two ways: it is the default
	// arm of Derive's switch (structure), and no program kind reaches it
	// (behaviour, swept exhaustively below).
	unreachable := deriveDefaultArmIsUnreachable(t)

	for _, c := range []struct {
		what string
		re   *regexp.Regexp
		want []int
	}{
		{"the enrolled term count and its pass-throughs",
			regexp.MustCompile(`([a-z-]+) of the ([a-z-]+) sites are formatless`),
			[]int{passThroughs, len(sites)}},
		{"derive.go's sentinels and sites",
			regexp.MustCompile(`([a-z-]+) distinct sentinels across \*\*([a-z-]+)\*\* return sites`),
			[]int{len(deriveSentinels), deriveSites}},
		{"derive.go's deletable sites",
			regexp.MustCompile(`([a-z-]+) are deletable without a compile error`),
			[]int{deriveSites - unreachable}},
		{"derive.go's firing sites",
			regexp.MustCompile(`([a-z-]+) of the ([a-z-]+) sites fire today`),
			[]int{deriveSites - unreachable, deriveSites}},
		{"CheckShape's sentinels and sites",
			regexp.MustCompile(`([a-z-]+) sentinels across ([a-z-]+) sites`),
			[]int{len(shapeSentinels), shapeSites}},
	} {
		m := c.re.FindStringSubmatch(doc)
		if m == nil {
			t.Errorf("spec/README.md no longer states %s in the shape this test reads "+
				(`(%s); the document has been reworded and this claim is now bound by `+
					"nothing — reword the regexp with it, or the number goes unchecked"),
				c.what, c.re)
			continue
		}
		for i, want := range c.want {
			got, ok := numberWord(m[i+1])
			if !ok {
				t.Errorf("%s: spec/README.md says %q where this test expects a number word",
					c.what, m[i+1])
				continue
			}
			if got != want {
				t.Errorf("%s: spec/README.md says %s (%d), the source has %d — the document "+
					"and the tree disagree, which is the drift this test exists to make "+
					"impossible", c.what, m[i+1], got, want)
			}
		}
	}
}

// namedErrorReturns counts the return sites that hand back a named error value,
// and the distinct values among them.
//
// This is the AST form of the grep whose provenance spec/README.md states, and
// it is deliberately the same shape: a `return` whose results include an
// identifier or selector named Err…, at any arity, methods included. The grep
// version of it was wrong once — it matched only `return nil, nil, Err…` and
// missed a bare return inside a method — which is why the count is derived here
// instead of typed.
//
// fn empty means the whole file; otherwise only the function or method of that
// name.
func namedErrorReturns(t *testing.T, path, fn string) (int, map[string]bool) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	if err != nil {
		t.Fatalf("%s does not parse, so this scan reads nothing: %v", path, err)
	}
	isErr := func(e ast.Expr) (string, bool) {
		switch v := e.(type) {
		case *ast.Ident:
			if strings.HasPrefix(v.Name, "Err") {
				return v.Name, true
			}
		case *ast.SelectorExpr:
			if strings.HasPrefix(v.Sel.Name, "Err") {
				return v.Sel.Name, true
			}
		}
		return "", false
	}
	sites, names := 0, map[string]bool{}
	var found bool
	for _, d := range f.Decls {
		decl, ok := d.(*ast.FuncDecl)
		if !ok || decl.Body == nil {
			continue
		}
		if fn != "" && decl.Name.Name != fn {
			continue
		}
		found = true
		ast.Inspect(decl.Body, func(n ast.Node) bool {
			ret, ok := n.(*ast.ReturnStmt)
			if !ok {
				return true
			}
			for _, r := range ret.Results {
				if name, ok := isErr(r); ok {
					sites++
					names[name] = true
					break
				}
			}
			return true
		})
	}
	if !found {
		t.Fatalf("%s declares no func %q; this scan read nothing", path, fn)
	}
	if sites == 0 {
		t.Fatalf("%s (%s) returns no named error anywhere; the call shape has changed and "+
			"this scan now counts nothing", path, fn)
	}
	return sites, names
}

// deriveDefaultArmIsUnreachable returns how many of derive.go's return sites
// cannot fire, and proves it rather than assuming it.
//
// One does: Derive's `default:` arm. It is identified structurally — the default
// clause of Derive's switch, returning a named error — and then proven
// unreachable over the whole input domain, because a structural claim alone
// would not survive CheckShape being weakened.
//
// The sweep is exhaustive rather than a sample: all 256 program kinds against
// all 16 subsets of the four body pointers, which is every Program shape the
// type admits up to the identity of the bodies. If CheckShape ever admits an
// unknown kind, Derive's default arm becomes live, the count of firing sites
// moves from seventeen to eighteen, and this test says so before
// spec/README.md's sentence becomes false.
func deriveDefaultArmIsUnreachable(t *testing.T) int {
	t.Helper()

	// Structure: Derive's switch still has a default arm returning an error.
	f, err := parser.ParseFile(token.NewFileSet(), "derive.go", nil, 0)
	if err != nil {
		t.Fatal(err)
	}
	var hasDefault bool
	for _, d := range f.Decls {
		decl, ok := d.(*ast.FuncDecl)
		if !ok || decl.Name.Name != "Derive" || decl.Body == nil {
			continue
		}
		ast.Inspect(decl.Body, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if ok && cc.List == nil {
				hasDefault = true
			}
			return true
		})
	}
	if !hasDefault {
		t.Fatal("validity.Derive no longer has a default arm; spec/README.md's " +
			"seventeen-of-eighteen split names it, and the split has to be recounted")
	}

	// Behaviour: no program kind reaches it, over the entire domain.
	known := map[types.ProgramKind]bool{
		types.ProgramTransfer: true, types.ProgramIssue: true,
		types.ProgramMint: true, types.ProgramRetire: true,
	}
	var swept, escaped int
	for v := 0; v <= 0xff; v++ {
		for bodies := 0; bodies < 16; bodies++ {
			prog := types.Program{Kind: types.ProgramKind(v)}
			if bodies&1 != 0 {
				prog.Transfer = &types.TransferArgs{}
			}
			if bodies&2 != 0 {
				prog.Issue = &types.IssueArgs{}
			}
			if bodies&4 != 0 {
				prog.Mint = &types.MintArgs{}
			}
			if bodies&8 != 0 {
				prog.Retire = &types.RetireArgs{}
			}
			swept++
			if prog.CheckShape() == nil && !known[prog.Kind] {
				escaped++
			}
		}
	}
	if swept != 256*16 {
		t.Fatalf("swept %d shapes, want %d; the domain this proof covers has changed", swept, 256*16)
	}
	if escaped > 0 {
		t.Fatalf("CheckShape admits an unknown program kind on %d of %d shapes, so Derive's "+
			"default arm is reachable and eighteen of eighteen sites fire — spec/README.md "+
			"says seventeen", escaped, swept)
	}
	return 1
}

// numberWord converts the English number words spec/README.md uses into
// integers. The document is prose for a second implementer and spells its counts
// out; this is the cost of binding prose rather than a table.
func numberWord(s string) (int, bool) {
	n, ok := map[string]int{
		"one": 1, "two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
		"seven": 7, "eight": 8, "nine": 9, "ten": 10, "eleven": 11,
		"twelve": 12, "thirteen": 13, "fourteen": 14, "fifteen": 15,
		"sixteen": 16, "seventeen": 17, "eighteen": 18, "nineteen": 19,
		"twenty": 20, "thirty-seven": 37, "thirty-six": 36, "thirty-eight": 38,
	}[s]
	return n, ok
}

// ---------------------------------------------------------------------------
// The inputs
// ---------------------------------------------------------------------------

// termInput is one separating input: a certificate, the entry point that asks
// the rule directly, and what the whole predicate answers on the same bytes.
type termInput struct {
	// what names the property the input separates, not the function it calls.
	what   string
	cert   *types.Certificate
	entry  string
	direct func(*types.Certificate, *params.Params) error
	rule   string
	// check is the rule validity.Check answers on this certificate, or "nothing"
	// if the whole predicate accepts it. For a term Era 0 cannot reach through
	// Check it is the rule that answers first, and recording it is how the
	// unreachability stays measured instead of asserted.
	check string
}

func selfConsistency(c *types.Certificate, _ *params.Params) error {
	return validity.CheckSelfConsistency(c)
}

func deposit(c *types.Certificate, p *params.Params) error { return validity.CheckDeposit(c, p) }

func canonical(c *types.Certificate, p *params.Params) error { return validity.CheckCanonical(c, p) }

func derivation(c *types.Certificate, _ *params.Params) error { return validity.CheckDerivation(c) }

func authorization(c *types.Certificate, _ *params.Params) error {
	return validity.CheckAuthorization(c)
}

func signatures(c *types.Certificate, p *params.Params) error { return validity.CheckSignatures(c, p) }

// separatingInputs builds one input per rejection term of the enrolled rules.
//
// Every V6 entry below is answered by V3 through the whole predicate, and that
// is not a weakness of the inputs: Era-0 derivation pins the write set exactly,
// so any edit that reaches V6 has already made the declaration disagree with
// what the program derives. Four of the terms are unreachable through Check for
// a stronger reason still, given at CheckSelfConsistency: derivation emits a
// GUARD_GE whose operand equals the subtracted total, so no Era-0 certificate
// can carry a DELTA_SUB that is unread, over its bound, or bounded only from
// above, and MINT's is the only DELTA_ADD with a read of its own slot. Phase 1's
// cEVM at H1_VM is the era that reaches them.
func separatingInputs(t *testing.T, p *params.Params) []termInput {
	t.Helper()
	alice, bob := key(t, 2), key(t, 3)
	carol := key(t, 4)
	asset := types.DeriveAssetAddress(p.ChainID, alice.Persistent(), 0)

	v6 := func(what string, edit func(*types.Certificate)) termInput {
		return termInput{
			what:  what,
			cert:  termCert(t, p, transferProgram(t), selfDeposit(t), signers(t), edit),
			entry: "CheckSelfConsistency", direct: selfConsistency, rule: "V6", check: "V3",
		}
	}
	v5 := func(what string, edit func(*types.Certificate)) termInput {
		return termInput{
			what:  what,
			cert:  termCert(t, p, transferProgram(t), selfDeposit(t), signers(t), edit),
			entry: "CheckDeposit", direct: deposit, rule: "V5", check: "V5",
		}
	}
	// V1's terms are the only ones whose `check` column is uniformly the rule
	// itself, because CheckCanonical is the first thing CheckStructural runs.
	v1 := func(what string, edit func(*types.Certificate)) termInput {
		return termInput{
			what:  what,
			cert:  termCert(t, p, transferProgram(t), selfDeposit(t), signers(t), edit),
			entry: "CheckCanonical", direct: canonical, rule: "V1", check: "V1",
		}
	}
	v3 := func(what string, edit func(*types.Certificate)) termInput {
		return termInput{
			what:  what,
			cert:  termCert(t, p, transferProgram(t), selfDeposit(t), signers(t), edit),
			entry: "CheckDerivation", direct: derivation, rule: "V3", check: "V3",
		}
	}

	inputs := []termInput{
		// --- V1, thirteen terms --------------------------------------------
		//
		// Eleven of these are *repeats* of a bound types.UnmarshalCertificate
		// already enforces, and CheckCanonical says at the top of itself why it
		// repeats them: a certificate built in memory by a wallet, a test or a
		// fuzzer has passed no decoder. So each input below is built in memory
		// and edited after wallet.Builder's own round-trip, which is the only
		// population these clauses can fire on — and, per limit (2), the reason
		// this test says nothing about the decoder's copy of the same bound.
		v1("a certificate bound to another network's chain id",
			func(c *types.Certificate) { c.ChainID = p.ChainID + 1 }),
		v1("a program carrying a body its declared kind does not name",
			// Two non-nil bodies: CheckShape's own error, forwarded by V1's one
			// formatless site. Kind stays TRANSFER so the encoding is unchanged
			// and the shape is the only thing wrong.
			func(c *types.Certificate) { c.Program.Issue = &types.IssueArgs{} }),
		v1("a transfer carrying more moves than max_moves_per_transfer",
			func(c *types.Certificate) {
				for i := 0; i < p.MaxMovesPerTransfer; i++ {
					c.Program.Transfer.Moves = append(c.Program.Transfer.Moves, types.Move{
						Asset:  types.NativeAsset,
						Src:    key(t, byte(100+i)).Persistent(),
						Dst:    key(t, byte(150+i)).Persistent(),
						Amount: drops(1),
					})
				}
			}),
		v1("a retire naming more addresses than max_retire_addrs",
			func(c *types.Certificate) {
				addrs := make([]types.Address, 0, p.MaxRetireAddrs+1)
				for i := 0; i <= p.MaxRetireAddrs; i++ {
					addrs = append(addrs, key(t, byte(i+1)).OneShot())
				}
				c.Program = types.Program{
					Kind:   types.ProgramRetire,
					Retire: &types.RetireArgs{Addrs: addrs},
				}
			}),
		v1("more declared reads than max_reads",
			func(c *types.Certificate) {
				for len(c.Reads) <= p.MaxReads {
					c.Reads = append(c.Reads, c.Reads[0])
				}
			}),
		v1("more declared writes than max_writes",
			func(c *types.Certificate) {
				for len(c.Writes) <= p.MaxWrites {
					c.Writes = append(c.Writes, c.Writes[0])
				}
			}),
		v1("reads that are not strictly ascending by slot",
			func(c *types.Certificate) { c.Reads = append(c.Reads, c.Reads[0]) }),
		v1("writes that are not strictly ascending by slot",
			func(c *types.Certificate) { c.Writes[0], c.Writes[1] = c.Writes[1], c.Writes[0] }),
		v1("a sequential priority above the maximum it is a tip within",
			func(c *types.Certificate) {
				c.FeeBid.SeqPriority = c.FeeBid.SeqMax.SatAdd(u256.One)
			}),
		v1("a parallel priority above the maximum it is a tip within",
			func(c *types.Certificate) {
				c.FeeBid.ParPriority = c.FeeBid.ParMax.SatAdd(u256.One)
			}),

		// --- V3, five terms ------------------------------------------------
		v3("a program that derives no read/write set at all",
			// deriveTransfer's own error, forwarded by V3's one formatless site.
			func(c *types.Certificate) { c.Program.Transfer.Moves[0].Amount = u256.Zero }),
		v3("fewer declared reads than the program derives",
			func(c *types.Certificate) { c.Reads = nil }),
		v3("a declared read the program derives differently",
			func(c *types.Certificate) { c.Reads[0].Operand = u256.Zero }),
		v3("more declared writes than the program derives",
			func(c *types.Certificate) {
				c.Writes = append(c.Writes, types.Write{
					Slot:  types.NativeBalanceSlot(key(t, 8).Persistent()),
					Op:    types.OpDeltaAdd,
					Value: drops(1),
				})
				sortWrites(c)
			}),
		v3("a declared write the program derives differently",
			func(c *types.Certificate) {
				for i := range c.Writes {
					if c.Writes[i].Op == types.OpDeltaAdd {
						c.Writes[i].Value = c.Writes[i].Value.SatAdd(u256.One)
					}
				}
			}),

		v6("a MARK_SPENT aimed at an address that has no signing authority to burn",
			func(c *types.Certificate) {
				c.Writes = append(c.Writes, types.Write{Slot: types.SpentSlot(asset), Op: types.OpMarkSpent})
				sortWrites(c)
			}),
		v6("a subtraction with no read of its own slot to bound it from below",
			func(c *types.Certificate) { c.Reads = nil }),
		v6("a subtraction larger than the balance its own read bounds",
			func(c *types.Certificate) {
				c.Reads[0].Operand = c.Reads[0].Operand.SatSub(u256.One)
			}),
		v6("a subtraction whose only read bounds the slot from above",
			func(c *types.Certificate) { c.Reads[0].Access = types.AccessGuardLE }),
		v6("a credit that provably overflows the upper bound its own read states",
			func(c *types.Certificate) {
				c.Reads = append(c.Reads, types.Read{
					Slot:    types.NativeBalanceSlot(bob.Persistent()),
					Access:  types.AccessGuardLE,
					Operand: u256.Max,
				})
				sortReads(c)
			}),
		v6("a one-shot deposit cell debited without the MARK_SPENT that burns it",
			func(c *types.Certificate) {
				c.Deposit.Cell = types.NativeBalanceSlot(alice.OneShot())
			}),
		v6("value written to an address the same certificate marks spent",
			func(c *types.Certificate) {
				c.Writes = append(c.Writes, types.Write{
					Slot: types.SpentSlot(bob.Persistent()), Op: types.OpMarkSpent,
				})
				sortWrites(c)
			}),

		v5("a deposit cell that is not the native-coin balance word",
			func(c *types.Certificate) { c.Deposit.Cell.Word[0] ^= 0xff }),
		// The one input in this table whose `check` column is not its own rule for
		// an ordering reason rather than a reachability one, and V4's unconditional
		// deposit signature is why. V5's clause still refuses this certificate —
		// the `direct` call below proves it — but V4 now requires an authorising
		// signature for any deposit cell, not only a user one, and
		// CheckAuthorization runs before CheckDeposit in CheckStructural. No key
		// hashes to crypto.ProtocolAddress, so V4 answers first. That the two
		// refusals are independent rather than one rule wearing two names is what
		// TestV5NarrowsTheDepositToUserAddresses asserts.
		termInput{
			what: "a deposit cell at the protocol address, where the treasury accrues",
			cert: termCert(t, p, transferProgram(t), selfDeposit(t), signers(t),
				func(c *types.Certificate) { c.Deposit.Cell.Addr = crypto.ProtocolAddress }),
			entry: "CheckDeposit", direct: deposit, rule: "V5", check: "V4",
		},
		v5("a refund slot that is not the native-coin balance word",
			func(c *types.Certificate) { c.Deposit.RefundTo.Word[0] ^= 0xff }),
		v5("a refund target at an asset address, which no key can spend",
			func(c *types.Certificate) { c.Deposit.RefundTo.Addr = asset }),
		v5("a fee ceiling no deposit can cover because it does not fit 256 bits",
			func(c *types.Certificate) { c.FeeBid.SeqMax = u256.Max }),
	}

	// The three V1 signature-list terms and V2's single term cannot be `edit`
	// closures: termCert re-signs after the edit, which is exactly what would
	// undo them. They are applied to a finished certificate instead.
	sigList := func(what string, edit func(*types.Certificate)) termInput {
		c := termCert(t, p, transferProgram(t), selfDeposit(t), signers(t), func(*types.Certificate) {})
		edit(c)
		return termInput{
			what: what, cert: c,
			entry: "CheckCanonical", direct: canonical, rule: "V1", check: "V1",
		}
	}
	inputs = append(inputs,
		sigList("more signatures than max_sigs", func(c *types.Certificate) {
			for len(c.Sigs) <= p.MaxSigs {
				c.Sigs = append(c.Sigs, c.Sigs[0])
			}
		}),
		sigList("a certificate carrying no signature at all", func(c *types.Certificate) {
			c.Sigs = nil
		}),
		sigList("signatures that are not strictly ascending by public key", func(c *types.Certificate) {
			resign(p, c, alice, carol)
			sortSigs(c)
			if c.Sigs[0].PubKey == c.Sigs[1].PubKey {
				t.Fatal("the two signers collided, so reversing them is not a sort violation")
			}
			c.Sigs[0], c.Sigs[1] = c.Sigs[1], c.Sigs[0]
		}),
	)

	// --- V2, one term -------------------------------------------------------
	forged := termCert(t, p, transferProgram(t), selfDeposit(t), signers(t), func(*types.Certificate) {})
	forged.Sigs[0].Sig[0] ^= 0xff
	inputs = append(inputs, termInput{
		what: "a signature that does not verify over the body it is attached to",
		cert: forged, entry: "CheckSignatures", direct: signatures, rule: "V2", check: "V2",
	})

	// --- V4, three terms -----------------------------------------------------
	//
	// The frozen corpus separates V4's sufficiency clause and neither of the
	// other two, and minimality is load-bearing for the reason the id's preimage
	// gives: sufficiency and minimality together make the legal signer set a
	// pure function of the body, so one id is one cost. All three are separated
	// here, which is where a rule's interior is counted.
	//
	// Both of the terms the corpus does not carry need a certificate
	// wallet.Builder refuses to build — it will not sign a mint without the
	// minter, and it will not attach a signature that authorises nothing — so
	// each is an edit of a certificate the builder did produce.
	unauthorised := termCert(t, p, transferProgram(t), selfDeposit(t), signers(t), func(*types.Certificate) {})
	resign(p, unauthorised, key(t, 9))
	inputs = append(inputs, termInput{
		what: "a debit no signature present authorises",
		cert: unauthorised, entry: "CheckAuthorization", direct: authorization, rule: "V4", check: "V4",
	})

	superfluous := termCert(t, p, transferProgram(t), selfDeposit(t), signers(t), func(*types.Certificate) {})
	resign(p, superfluous, alice, key(t, 9))
	sortSigs(superfluous)
	inputs = append(inputs, termInput{
		what: "a signature that authorises nothing in the certificate carrying it",
		cert: superfluous, entry: "CheckAuthorization", direct: authorization, rule: "V4", check: "V4",
	})

	// The privileged-key term: MINT names its minter in the body, and only a
	// signature by that exact key may authorise it. The declared minter is moved
	// to a key that signed nothing, and the EXACT read of the minter cell is
	// moved with it, so that V3 still agrees with the derivation and V4 is what
	// answers rather than V3.
	issuer, thief, holder := key(t, 5), key(t, 6), key(t, 7)
	minted := types.DeriveAssetAddress(p.ChainID, issuer.Persistent(), 0)
	unminted := termCert(t, p,
		wallet.Mint(minted, holder.Persistent(), drops(10), drops(100), issuer.PubKey()),
		wallet.SelfDeposit(issuer.Persistent(), issuer.Persistent()),
		[]*wallet.Key{issuer},
		func(c *types.Certificate) {
			c.Program.Mint.Minter = thief.PubKey()
			for i := range c.Reads {
				if c.Reads[i].Slot == types.AssetMinterSlot(minted) {
					c.Reads[i].Operand = u256.FromBytes(thief.PubKey())
				}
			}
		})
	inputs = append(inputs, termInput{
		what: "a mint whose declared minter authorised nothing",
		cert: unminted, entry: "CheckAuthorization", direct: authorization, rule: "V4", check: "V4",
	})

	// The refund-into-the-deposit-cell's-own-burn term needs a one-shot deposit
	// cell, so it cannot be an edit of the persistent baseline.
	burned := oneShotDeposit(t, p,
		wallet.Issue(alice.OneShot(), drops(1_000), 0, types.Hash{}, alice.PubKey()),
		alice.OneShot(), alice.Persistent(), alice)
	burned.Deposit.RefundTo = types.NativeBalanceSlot(alice.OneShot())
	resign(p, burned, alice)
	inputs = append(inputs, termInput{
		what: "a refund into the one-shot cell the deposit itself burns",
		cert: burned, entry: "CheckDeposit", direct: deposit, rule: "V5", check: "V5",
	})

	// And the general form: a refund into an address the certificate's write set
	// marks spent, which need not be the deposit cell at all (F-FOLD-1).
	swept := termCert(t, p,
		wallet.Tip(types.NativeAsset, carol.OneShot(), bob.Persistent(), drops(1_000_000)),
		wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		[]*wallet.Key{alice, carol},
		func(c *types.Certificate) {
			c.Deposit.RefundTo = types.NativeBalanceSlot(carol.OneShot())
		})
	inputs = append(inputs, termInput{
		what: "a refund into a one-shot address the certificate burns as a move source",
		cert: swept, entry: "CheckDeposit", direct: deposit, rule: "V5", check: "V5",
	})

	// The under-reservation is applied after the ceiling top-up termCert
	// performs, because that top-up exists to keep every other edit from being
	// answered by this term.
	under := termCert(t, p, transferProgram(t), selfDeposit(t), signers(t), func(*types.Certificate) {})
	ceiling, ok := under.FeeCeiling(p)
	if !ok {
		t.Fatal("the baseline certificate's fee ceiling does not fit 256 bits")
	}
	under.Deposit.Amount = ceiling.SatSub(u256.One)
	resign(p, under, key(t, 2))
	inputs = append(inputs, termInput{
		what: "a deposit one drop short of the fee ceiling it must cover",
		cert: under, entry: "CheckDeposit", direct: deposit, rule: "V5", check: "V5",
	})

	// And the other end of the same field: a deposit declaring more coin
	// than §14.2's schedule can have issued by the last height at which this
	// certificate may be committed. u256.Max is above the cumulative emission
	// at every height and every shipped set — the mainnet schedule tops out
	// around 2.6e16 drops — so the input separates the term without depending
	// on the baseline's TTL, and it is the exact value the audit named.
	over := termCert(t, p, transferProgram(t), selfDeposit(t), signers(t), func(*types.Certificate) {})
	over.Deposit.Amount = u256.Max
	resign(p, over, key(t, 2))
	inputs = append(inputs, termInput{
		what: "a deposit declaring more coin than the schedule can have issued by its TTL",
		cert: over, entry: "CheckDeposit", direct: deposit, rule: "V5", check: "V5",
	})

	return inputs
}

// ---------------------------------------------------------------------------
// Reading the terms out of the source
// ---------------------------------------------------------------------------

// siteKey identifies one rejection site by the rule it names and the format
// string it rejects with. The format is the only thing that distinguishes two
// sites of one rule from outside the package, which is why two sites sharing one
// is refused rather than tolerated.
//
// A `fail(rule, err)` site has no format: it passes another function's error
// through, so its message is whatever the delegate said and nothing in this
// package spells it. Such a site is marked passThrough and carries the name of
// the enclosing function in `format` for diagnostics only — it is never matched
// against a message. See passThroughSite for how an input reaches it.
type siteKey struct {
	rule, format string
	passThrough  bool
}

// label renders a site for a diagnostic. A pass-through site has no message to
// name it by, so it is named by the check whose error it forwards.
func (k siteKey) label() string {
	if k.passThrough {
		return "the error forwarded by " + k.format
	}
	return k.format
}

// rejectionSites collects every `failf(rule, format, …)` site core/validity
// spells for the enrolled rules.
//
// It reads the source for the same reason spec/invalid_rules_test.go's
// vRuleGuardedRoutes does: a number written by hand beside the inputs is the
// same statement the inputs already are, and drifts with them. Counting where
// the rule actually rejects ties the demand to the rule instead — an eighth
// `failf("V6", …)` fails the test until an input for it exists.
func rejectionSites(t *testing.T, rules []string) map[siteKey]bool {
	t.Helper()
	if len(rules) == 0 {
		t.Fatal("no rule is enrolled; this scan would demand nothing")
	}
	enrolled := map[string]bool{}
	for _, r := range rules {
		enrolled[r] = true
	}

	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[siteKey]bool{}
	perRule := map[string]int{}
	passThrough := map[string]siteKey{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("core/validity/%s does not parse, so this scan reads nothing: %v", name, err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Body == nil {
				continue
			}
			ast.Inspect(fn.Body, func(n ast.Node) bool {
				call, ok := n.(*ast.CallExpr)
				if !ok {
					return true
				}
				id, ok := call.Fun.(*ast.Ident)
				if !ok || len(call.Args) == 0 {
					return true
				}
				if id.Name != "fail" && id.Name != "failf" {
					return true
				}
				// A rule id that is not a string literal — `failf(ruleV6, …)`
				// against a package constant, say — cannot be read here, and the
				// scan has no way to tell whether it names an enrolled rule. That
				// was disclosed as a limit and it was the only *silent* one:
				// measured, a `const ruleSelfConsistency = "V6"` with an eighth
				// site behind it left the demand at fifteen and the suite green,
				// while a formatless site and a duplicated format both failed
				// loudly. A silent miss and a loud refusal are different objects,
				// so this is now the second kind.
				rule, ok := stringLit(call.Args[0])
				if !ok {
					t.Fatalf("a %s call in %s names its rule with something other than a "+
						"string literal; this scan reads the id from the source and cannot "+
						"tell whether that site belongs to an enrolled rule, so the count it "+
						"reports may be lower than the number of terms. Spell the id inline, "+
						"or teach this scan to resolve it", id.Name, fn.Name.Name)
				}
				if !enrolled[rule] {
					return true
				}
				perRule[rule]++
				// A `fail(rule, err)` site carries no format of its own: it
				// forwards the error of a check this package delegates to —
				// V1's Program.CheckShape and V3's DeriveCert are the two.
				// Until V1 and V3 were enrolled this was a loud refusal, on the
				// ground that a message with no format cannot be keyed back and
				// the count would silently understate the rule. Enrolling them
				// makes that refusal a wall rather than a limit, so the site is
				// counted here and matched by elimination instead: it is the
				// site an input reaches when its message matches none of the
				// rule's spelled formats.
				//
				// Elimination is only sound while a rule has ONE such site — two
				// would make "matched no format" ambiguous between them — so a
				// second is refused, exactly as a duplicated format is.
				if id.Name == "fail" || len(call.Args) < 2 {
					key := siteKey{rule: rule, format: fn.Name.Name, passThrough: true}
					if prev, dup := passThrough[rule]; dup {
						t.Fatalf("core/validity forwards a delegated error under %s at two sites "+
							"(in %s and in %s); an input that matches neither of the rule's spelled "+
							"formats could not be told apart between them, so the count could be met "+
							"with one of the two separated by nothing. Give one of them a format",
							rule, prev.format, fn.Name.Name)
					}
					passThrough[rule] = key
					out[key] = true
					return true
				}
				format, ok := stringLit(call.Args[1])
				if !ok {
					t.Fatalf("a %s rejection site in %s builds its message from something "+
						"other than a string literal; this scan cannot key it and the count "+
						"understates the rule", rule, fn.Name.Name)
				}
				if out[siteKey{rule: rule, format: format}] {
					t.Fatalf("core/validity spells the %s message %q at two rejection sites; "+
						"one input would cover both and the count would be met without both "+
						"terms being separated", rule, format)
				}
				out[siteKey{rule: rule, format: format}] = true
				return true
			})
		}
	}
	// Every enrolled rule must have been found, or a rule that moved out of this
	// package turns "every term has an input" into "no term was looked for".
	for _, r := range rules {
		if perRule[r] == 0 {
			t.Fatalf("core/validity contains no rejection site spelled %q; the rule has been "+
				"rewritten or moved and this scan now demands nothing of it", r)
		}
	}
	return out
}

func stringLit(e ast.Expr) (string, bool) {
	lit, ok := e.(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	s, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return s, true
}

var formatVerb = regexp.MustCompile(`%[#+\- 0]*[0-9.]*[a-zA-Z]`)

// matchSite keys a produced rejection back to the source site that produced it,
// by matching the message against the site's format with its verbs widened.
//
// Exactly one site may match. A message matching two would mean the count could
// be met by an input that separates neither term unambiguously.
func matchSite(t *testing.T, sites map[siteKey]bool, rule string, err error) (siteKey, bool) {
	t.Helper()
	msg := strings.TrimPrefix(err.Error(), rule+": ")
	var hits []siteKey
	for k := range sites {
		if k.rule != rule || k.passThrough {
			continue
		}
		re := regexp.MustCompile("^" + formatVerb.ReplaceAllString(regexp.QuoteMeta(k.format), ".*") + "$")
		if re.MatchString(msg) {
			hits = append(hits, k)
		}
	}
	switch len(hits) {
	case 0:
		return siteKey{}, false
	case 1:
		return hits[0], true
	default:
		t.Fatalf("the %s rejection %q matches %d rejection sites; two terms of one rule are "+
			"not told apart and the count can be met without separating either", rule, msg, len(hits))
		return siteKey{}, false
	}
}

// passThroughSite is the elimination half of matchSite: the one site of a rule
// that spells no format of its own, reached by an input whose message matches
// none of the formats the rule does spell.
//
// Elimination is the only key such a site can have — the message belongs to the
// delegate, so nothing in this package predicts it — and it is safe only because
// rejectionSites refuses a second pass-through site per rule, and because the
// caller refuses a second *input* landing here. Without that second refusal
// elimination would be a hiding place rather than a key: an input written for a
// spelled term whose message drifted would stop matching its format and be
// silently re-attributed here, leaving its own term separated by nothing while
// the count stayed met. With it, the drift produces two occupants and says so.
func passThroughSite(sites map[siteKey]bool, rule string) (siteKey, bool) {
	for k := range sites {
		if k.rule == rule && k.passThrough {
			return k, true
		}
	}
	return siteKey{}, false
}

// ---------------------------------------------------------------------------
// Building the certificates
// ---------------------------------------------------------------------------

// termCert is a certificate a wallet would emit, edited once, re-covered and
// re-signed — the same order spec/gen's buildUncheckedEdited and spec's
// vRuleBaseline use, and for the same reason: an edit that moves the encoded
// length moves the fee ceiling, and V5's under-reservation term would answer
// before the term under test.
func termCert(t *testing.T, p *params.Params, prog types.Program, dep types.Deposit,
	keys []*wallet.Key, edit func(*types.Certificate)) *types.Certificate {
	t.Helper()
	c, err := (&wallet.Builder{
		Params:  p,
		Program: prog,
		TTL:     100,
		Deposit: dep,
		FeeBid:  bid(),
		Signers: keys,
	}).Build()
	if err != nil {
		t.Fatalf("the baseline certificate does not build: %v", err)
	}
	edit(c)
	if ceiling, ok := c.FeeCeiling(p); ok && c.Deposit.Amount.Lt(ceiling) {
		c.Deposit.Amount = ceiling
	}
	resign(p, c, keys...)
	sortSigs(c)
	return c
}

func transferProgram(t *testing.T) types.Program {
	t.Helper()
	return wallet.Tip(types.NativeAsset, key(t, 2).Persistent(), key(t, 3).Persistent(),
		drops(1_000_000))
}

func selfDeposit(t *testing.T) types.Deposit {
	t.Helper()
	a := key(t, 2).Persistent()
	return wallet.SelfDeposit(a, a)
}

func signers(t *testing.T) []*wallet.Key { return []*wallet.Key{key(t, 2)} }

// versionOf is a real derived address wearing another version byte, so that the
// only thing separating it from an accepted one is the byte the clause tests.
// reportRule is wantRule without the Fatal: it names the arm it is checking and
// keeps going, so that a subtest asserting two independent rules reports both
// verdicts instead of stopping at the first one that moves. See
// TestV5NarrowsTheDepositToUserAddresses, where the whole point is that neither
// arm depends on the other.
func reportRule(t *testing.T, arm string, err error, rule string) {
	t.Helper()
	if err == nil {
		t.Errorf("%s: nothing rejects this certificate, want %s", arm, rule)
		return
	}
	if got := validity.Rule(err); got != rule {
		t.Errorf("%s: rejected by %s (%v), want %s", arm, ruleOrNothing(got), err, rule)
	}
}

func versionOf(t *testing.T, version, seed byte) types.Address {
	t.Helper()
	a := key(t, seed).Persistent()
	a[0] = version
	return a
}

func sortReads(c *types.Certificate) {
	sort.Slice(c.Reads, func(i, j int) bool { return c.Reads[i].Slot.Less(c.Reads[j].Slot) })
}

func containsByte(all []byte, want byte) bool {
	for _, v := range all {
		if v == want {
			return true
		}
	}
	return false
}

func ruleOrNothing(rule string) string {
	if rule == "" {
		return "nothing"
	}
	return rule
}
