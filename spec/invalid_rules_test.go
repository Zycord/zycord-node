package spec_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/spec"
	"zycord/wallet"
)

// rejectedBy names, for every invalid vector in the corpus, the rule that
// vector exists to pin.
//
// It borrows one half of the discipline `pinnedBy` applies to the difficulty
// corpus and not the other, and the difference matters. `pinnedBy` earns the
// word *discriminates*: it removes the clause and requires the answer to move
// (difficulty_mutation_test.go). This table removes nothing. What it enforces
// is membership — every invalid vector states the rule it is for, in Go,
// beside its name, or it does not arrive — and agreement between three
// statements of that rule. Single-rule-ness is held elsewhere and is listed in
// spec/README.md under "An invalid vector's block breaks exactly one rule";
// the load-bearing part of it is sim's TestBothFoldsAgreeOnTheRuleTheCorpusRecords,
// which replays these same vectors through a fold that checks the rules in a
// different order.
//
// The table is a *third* statement, independent of the two the corpus already
// carries:
//
//   - `core/fold` decides which rule rejects a block. That is the protocol.
//   - `expect.rule` in the committed JSON is what the fold decided when
//     spec/gen last ran, and TestGoldenVectors compares the two on replay.
//   - this table is what the vector was *for*, written by hand beside the
//     vector's name.
//
// The third catches what the first two cannot. A newly added invalid vector
// whose block turns out to break some rule other than the one its name claims
// produces a JSON and a fold that agree with each other perfectly, and both
// are wrong about the point of the vector. So the check below folds the block
// itself and compares the *fold's* answer against this table, rather than
// reading `expect.rule` and comparing that: a check that derived its signal
// from the artifact it is checking would report all clear on a corpus
// generated wrongly (CONTRIBUTING's mirror rule). `expect.rule` is compared
// too, as a separate assertion, because the committed artifact is what a
// second implementation replays.
//
// The distinction is not hypothetical. `044-mainnet-invalid-cert-count-over-
// ceiling` clears B13's byte ceiling by 537 bytes while breaking B12, and a
// RETIRE certificate is 562 bytes: one more certificate and the same block
// breaks both rules, at which point which id the corpus records is decided by
// the order core/fold happens to check them in and not by the protocol — and
// nothing here would notice, because on a two-rule block all three statements
// this test compares are the same first-fired rule and they agree.
var rejectedBy = map[string]string{
	"invalid-replay":                            "B3",
	"invalid-expired":                           "B1",
	"invalid-ttl-unbounded":                     "B2",
	"invalid-cap-below-base":                    "B4",
	"invalid-refund-into-own-mark-spent":        "V5",
	"invalid-duplicate-in-block":                "B8",
	"invalid-low-order-signer":                  "V2",
	"invalid-cert-root":                         "B14",
	"invalid-cert-count-over-ceiling":           "B12",
	"mainnet-invalid-cert-count-over-ceiling":   "B12",
	"cites-invalid-version":                     "C0",
	"cites-invalid-height":                      "C1",
	"cites-invalid-grandparent":                 "C2",
	"cites-invalid-self-citation":               "C3",
	"cites-invalid-target":                      "C4",
	"cites-invalid-unsorted":                    "C5",
	"cites-invalid-at-height-one":               "B17",
	"invalid-seed-epoch-stale":                  "B0b",
	"invalid-seed-epoch-early":                  "B0b",
	"invalid-seed-epoch-stale-devnet":           "B0b",
	"invalid-seed-epoch-early-devnet":           "B0b",
	"invalid-resigned-duplicate-in-block":       "B8",
	"invalid-resigned-replay":                   "B3",
	"invalid-foreign-chain-id":                  "V1",
	"invalid-write-the-program-does-not-derive": "V3",
	"invalid-debit-nobody-authorised":           "V4",
	"invalid-mint-into-its-own-burn":            "V6",
	"invalid-transfer-of-a-non-asset-id":        "V3",
	"invalid-signature-count-over-the-ceiling":  "B18",
	"invalid-mixed-order-signer":                "V2",
}

// TestInvalidVectorsPinTheRuleTheyAreNamedFor folds every invalid vector and
// requires the rule that actually rejects it to be the rule the table above
// says the vector is for — in both directions, so neither a vector without an
// entry nor an entry without a vector survives.
func TestInvalidVectorsPinTheRuleTheyAreNamedFor(t *testing.T) {
	vectors, err := spec.LoadVectors("vectors")
	if err != nil {
		t.Fatal(err)
	}
	// A table with nothing in it, or a corpus with no invalid vector in it,
	// would make every assertion below unreachable and the test green. Refuse
	// both: an instrument that passes by having nothing to look at is the
	// failure mode this whole change exists to remove.
	if len(rejectedBy) == 0 {
		t.Fatal("rejectedBy is empty; this test would assert nothing")
	}

	seen := make(map[string]bool, len(rejectedBy))
	for _, v := range vectors {
		if v.Expect.Valid {
			// A valid block was rejected by nothing, and a rule id on one
			// would be a claim with no referent.
			if v.Expect.Rule != "" {
				t.Errorf("%s: a valid vector names rule %q", v.Name, v.Expect.Rule)
			}
			continue
		}
		seen[v.Name] = true
		want, ok := rejectedBy[v.Name]
		if !ok {
			t.Errorf("%s: no rule listed in rejectedBy — an invalid vector arrives with "+
				"the rule it pins stated, or it does not arrive", v.Name)
			continue
		}
		t.Run(v.Name, func(t *testing.T) {
			p, err := spec.ParamsFor(v.Params)
			if err != nil {
				t.Fatal(err)
			}
			s, err := v.Pre.BuildState()
			if err != nil {
				t.Fatal(err)
			}
			b, err := v.DecodeBlock(p)
			if err != nil {
				t.Fatalf("the block does not decode: %v", err)
			}
			// Fold it. The rule this vector pins is the rule the fold applies
			// to this block, not the one the JSON remembers.
			_, applyErr := fold.ApplyBlock(s, b, p)
			if applyErr == nil {
				t.Fatalf("the block was accepted; this table says it breaks %s", want)
			}
			if got := fold.Rule(applyErr); got != want {
				t.Errorf("the fold rejects this block by %s, the table says the vector is "+
					"for %s (%v)", ruleOrNone(got), want, applyErr)
			}
			// And the committed artifact — what a second implementation
			// actually replays — must carry the same id.
			if v.Expect.Rule != want {
				t.Errorf("the corpus records %q, this table says the vector is for %q — "+
					"either the vector now tests a different rule, or the table is stale",
					v.Expect.Rule, want)
			}
		})
	}
	if len(seen) == 0 {
		t.Fatal("the corpus holds no invalid vector; this test asserted nothing")
	}
	for name := range rejectedBy {
		if !seen[name] {
			t.Errorf("rejectedBy names %q, which is not an invalid vector in the corpus", name)
		}
	}
}

// TestVectorRulesAreDefinedInTheArchitectureSpec keeps the ids the corpus uses
// from becoming private vocabulary.
//
// A vector's `expect.rule` is a conformance requirement, so a second
// implementation has to be able to look the id up. docs/ARCHITECTURE.md §7 and
// §8 are where it is obliged to look, and an id that appears in a vector and
// nowhere in that document is a requirement nobody outside this tree can
// discover. The check is for a rule-list *definition*, not a mention in prose,
// because the prose names ids freely.
func TestVectorRulesAreDefinedInTheArchitectureSpec(t *testing.T) {
	raw, err := os.ReadFile("../docs/ARCHITECTURE.md")
	if err != nil {
		t.Fatal(err)
	}
	// Two definition shapes and no others. The B/C/F rules are lines of §8's
	// pseudocode blocks, which begin with the id; the V-rules are §7's bullets,
	// of the form "- **V1 — Canonical form.**".
	block := regexp.MustCompile(`(?m)^\s*(B[0-9]+b?|C[0-9]+|F[0-9]+)\s`)
	bullet := regexp.MustCompile(`(?m)^- \*\*(V[0-9]+) `)
	defined := map[string]bool{}
	for _, m := range block.FindAllStringSubmatch(string(raw), -1) {
		defined[m[1]] = true
	}
	for _, m := range bullet.FindAllStringSubmatch(string(raw), -1) {
		defined[m[1]] = true
	}
	// The scan must find the shapes it is looking for, or this test passes by
	// having read nothing: a document reformatted out of these two shapes
	// would silently turn "every id is defined" into "no id was looked for".
	// One landmark per shape, chosen from opposite ends of each list.
	for _, want := range []string{"B0b", "B4", "B17", "C0", "C5", "F13", "F14", "V1", "V9"} {
		if !defined[want] {
			t.Fatalf("the definition scan found no %s in docs/ARCHITECTURE.md; "+
				"the document's rule lists have been reformatted and this test now "+
				"reads nothing", want)
		}
	}

	vectors, err := spec.LoadVectors("vectors")
	if err != nil {
		t.Fatal(err)
	}
	var checked int
	var undefined []string
	for _, v := range vectors {
		if v.Expect.Rule == "" {
			continue
		}
		checked++
		if !defined[v.Expect.Rule] {
			undefined = append(undefined, v.Name+" ("+v.Expect.Rule+")")
		}
	}
	if checked == 0 {
		t.Fatal("no vector names a rule; this test asserted nothing")
	}
	if len(undefined) > 0 {
		sort.Strings(undefined)
		t.Errorf("these vectors name rules docs/ARCHITECTURE.md does not define: %s",
			strings.Join(undefined, ", "))
	}

	// Every id the tree can EMIT, not only the twenty-one some vector happens
	// to name. The tree emits thirty-four distinct ids and the corpus names
	// twenty-one of them, so thirteen sites are uncovered — the V-rules among
	// them are accounted for by TestEveryVRuleIsSeparatedByTheCorpus below and
	// the rest are block rules no vector reaches. ARCHITECTURE §8 says every
	// rejection carries the id of the rule that produced it, and a mistyped id
	// at a site no vector covers would ship into operator logs and into
	// SECURITY.md's "which rule is broken, by number if possible" channel with
	// nothing to catch it. The corpus is the reason the ids exist; it is not
	// the extent of them.
	emitted, err := emittedRuleIDs("../core/fold", "../core/validity")
	if err != nil {
		t.Fatal(err)
	}
	// Landmarks at sites no vector reaches, one per source file and one per
	// rule family, so a regex that stops matching fails here instead of
	// quietly scanning nothing.
	for _, want := range []string{"B5", "B11", "B12", "B16", "F13", "V1", "V7"} {
		if !emitted[want] {
			t.Fatalf("the emitted-id scan found no %s in core/fold or core/validity; "+
				"the call shape has changed and this scan now reads nothing", want)
		}
	}
	var orphan []string
	for id := range emitted {
		if !defined[id] {
			orphan = append(orphan, id)
		}
	}
	if len(orphan) > 0 {
		sort.Strings(orphan)
		t.Errorf("core/fold or core/validity emits rule ids docs/ARCHITECTURE.md does not "+
			"define: %s", strings.Join(orphan, ", "))
	}
}

// emittedRuleIDs collects every rule id spelled as a literal at a rejection
// site in core/fold and core/validity.
//
// It reads the source rather than exercising the code because most of these
// sites are unreachable from any input a test can hand the fold — that is what
// makes them the ones a typo survives in.
func emittedRuleIDs(dirs ...string) (map[string]bool, error) {
	// invalid("B12", …) in core/fold and sim/refold; fail("V1", …) and
	// failf("V1", …) in core/validity; and invalidCert(i, "B8", …) in
	// core/fold, where the rule id follows the certificate index that
	// attributes the rejection to one certificate. The id is the same
	// literal at the same kind of rejection site either way, so the scan has to
	// see both shapes: a scan that knows only the older one stops reading
	// whichever rules moved to the newer one, and then compares — or checks
	// against ARCHITECTURE.md — less than it claims to.
	//
	// The dynamic calls in blockrules.go — invalid(rule, …) and
	// invalidCert(i, rule, …), which pass the V-rule through — carry no literal
	// and are covered by core/validity's own sites instead.
	call := regexp.MustCompile(
		`\b(?:invalid|fail|failf)\("([A-Z][0-9]+[a-z]?)"` +
			`|\binvalidCert\([^,)]*,\s*"([A-Z][0-9]+[a-z]?)"`)
	out := map[string]bool{}
	for _, dir := range dirs {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return nil, err
		}
		for _, e := range entries {
			n := e.Name()
			if !strings.HasSuffix(n, ".go") || strings.HasSuffix(n, "_test.go") {
				continue
			}
			raw, err := os.ReadFile(filepath.Join(dir, n))
			if err != nil {
				return nil, err
			}
			for _, m := range call.FindAllStringSubmatch(string(raw), -1) {
				// Exactly one of the two alternatives matched, so the
				// other group is empty.
				if m[1] != "" {
					out[m[1]] = true
				} else if m[2] != "" {
					out[m[2]] = true
				}
			}
		}
	}
	return out, nil
}

// TestBothFoldsEmitTheSameRuleIDs keeps the sweep's fold and the corpus's fold
// speaking one vocabulary.
//
// expect.rule is produced by core/fold, but sim's
// TestEveryInvalidVectorsRuleIsNecessary proves that id necessary by deleting
// it from sim/refold. The two are only the same claim while the two folds spell
// the rule the same way. An id core/fold emits and refold does not would make
// refold.WithoutRule delete nothing at all, and the vector recording it would
// pass the sweep by having had no rule removed — a gate reporting all clear on
// the one vector it never tested. Nothing else in the tree compares the two
// sets, and a rule added to one fold and spelled differently in the other is an
// ordinary thing to do.
//
// V-rules are excluded because neither fold spells them: both pass validity's
// answer through a dynamic invalid(rule, …) with no literal to scan, so
// core/validity is the single source for those and the two folds share it.
func TestBothFoldsEmitTheSameRuleIDs(t *testing.T) {
	fast, err := emittedRuleIDs("../core/fold")
	if err != nil {
		t.Fatal(err)
	}
	naive, err := emittedRuleIDs("../sim/refold")
	if err != nil {
		t.Fatal(err)
	}
	// Both scans must have found something, or a changed call shape turns this
	// into a comparison of two empty sets.
	for _, want := range []string{"B0b", "B8", "C5", "F14"} {
		if !fast[want] || !naive[want] {
			t.Fatalf("the id scan found no %s in one of the two folds (core/fold %v, "+
				"sim/refold %v); a call shape has changed and this test now compares "+
				"what it did not read", want, fast[want], naive[want])
		}
	}
	var only []string
	for id := range fast {
		if !naive[id] {
			only = append(only, "core/fold only: "+id)
		}
	}
	for id := range naive {
		if !fast[id] {
			only = append(only, "sim/refold only: "+id)
		}
	}
	if len(only) > 0 {
		sort.Strings(only)
		t.Errorf("the two folds do not emit the same rule ids, so a vector recording "+
			"one of these is proved necessary against a fold that cannot reject by "+
			"it: %s", strings.Join(only, ", "))
	}
}

// ---------------------------------------------------------------------------
// The class, not the instances: every V-rule §7 defines is separated
// ---------------------------------------------------------------------------

// vRuleExemption records why a rule §7 defines carries no invalid vector.
//
// Each kind is *armed* below rather than believed. A reason nobody re-derives
// is how a corpus drifts back out of coverage: the audit that produced this
// table found V1, V3, V4, V6, V7 and V9 pinned by nothing at all, and the prose
// explaining why some of them were "already covered" was, for three of them,
// simply absent.
type vRuleExemption struct {
	// kind is how the exemption is checked. "delegated" means another rule
	// enforces this one and the corpus pins that rule instead; "subsumed"
	// means a certificate breaking this rule is refused by an earlier rule in
	// Era 0, so a vector aimed at it would record that earlier rule and pin
	// the wrong thing.
	//
	// The two are not interchangeable and the test does not take this field's
	// word for which applies: a rule core/validity rejects by under its own id
	// is refused the weaker kind. Otherwise every guard here is optional, since
	// any rule could be relabelled delegated-by-V3 and armed by nothing.
	//
	// Neither kind is satisfied by naming a rule that happens to have a vector.
	// A delegated exemption must produce a *witness*: a committed block that
	// actually breaks the exempt rule and that the fold rejects under the id
	// this entry names. Without one, "delegated" costs a map entry — the rule
	// §7 states and the predicate never reports (V8's class, and precisely what
	// a future era adds) could name any pinned id and be armed by nothing —
	// measured, by relabelling an exemption and watching the package stay green.
	kind string
	// by names the rules that stand in front of this one — one entry per
	// distinct rule that answers on some route, not one per exemption.
	//
	// It is a set rather than a single id because a rule is not reached by one
	// route, and the routes need not be blocked by the same rule: V9's own
	// reason names four routes and two different rules answering across them.
	// While this was a single id, `armVRuleSubsumption` could only ask one
	// question of every route, so a route subsumed by some *other* rule could
	// not be expressed and was simply left out of the arming — which is how a
	// route the exemption's prose named went unchecked.
	by     []string
	reason string
}

// vRulesWithoutAVector is the closed list. A rule §7 defines that is neither
// recorded by an invalid vector nor named here fails the test below, which is
// the whole point: the rule set grows every era, and a corpus that covers
// today's nine rules and silently ignores the tenth is the state the audit
// behind this table found.
var vRulesWithoutAVector = map[string]vRuleExemption{
	"V7": {
		kind: "subsumed", by: []string{"V3"},
		reason: "a write to a 0x00 protocol cell is a write no Era-0 program derives, " +
			"so V3 refuses the certificate before V7 is reached. A vector aimed at V7 " +
			"would record V3 and pin nothing about V7. Held directly by " +
			"core/validity's TestV7 against CheckProtocolExclusion; this exemption " +
			"expires the moment a program set exists whose derivation could produce " +
			"such a write.",
	},
	"V8": {
		kind: "delegated", by: []string{"B2"},
		reason: "V8 is stated in §7 but enforced as a block rule — it is a claim about " +
			"a certificate's position, not about the certificate — so the corpus pins " +
			"it under the id the fold actually reports.",
	},
	"V9": {
		kind: "subsumed", by: []string{"V3", "V4", "V5"},
		reason: "an unknown address version can reach a certificate by a read or write, " +
			"where V3 refuses it because no Era-0 derivation produces one; by the " +
			"refund target, where V5's narrower IsUserAddress test refuses it first; " +
			"or by the deposit cell, where V4 refuses it first because an authorising " +
			"signature over the deposit cell is unconditional and no key " +
			"hashes to a 0x04 address — V5 still refuses that route too, asked " +
			"directly, and the arming below asks it. None of the four routes reaches V9 in Era 0, which is " +
			"what V9's own doc comment says it is for: the certificate that was never " +
			"derived at all, which Era S's 0x04 hidden cells would introduce. Held " +
			"directly by core/validity's TestV9 against CheckAddressVersions — but " +
			"TestV9 asks CheckAddressVersions, not the whole predicate, so it is this " +
			"arming and not that test that keeps the four routes from becoming " +
			"reachable through validity.Check.",
	},
}

// TestEveryVRuleIsSeparatedByTheCorpus is the class-closing half of the
// coverage audit: the instances are vectors, this is the property.
//
// The instances — one invalid vector each for V1, V3, V4 and V6 — are in
// spec/gen. Without this test they are a patch: the next rule added to §7
// arrives with no vector, nothing notices, and the corpus is back where the
// audit found it. What this test asserts is the *property*, so that the patch
// cannot drift back out of coverage.
//
// It is deliberately one-sided in the same direction the gap was. The corpus's
// existing checks all ask whether a vector's rejection is correct; this one
// asks whether a rule has any vector at all, which is the question an
// over-acceptance gap answers "no" to while every other check stays green.
//
// What this test does not catch, stated rather than chased. Its inputs are §7's
// bullet list, the corpus, and core/validity's source, and an author willing to
// falsify one of them defeats it: an exemption whose reason is untrue, armed by
// a witness or a route written to match the untruth, passes. That is not a hole
// to be closed by another guard — a test cannot outrun someone editing its own
// inputs, and each round of trying has bought a narrower guard rather than a
// stronger gate. Five limits are real and known within honest inputs. (1) The
// route count reads `fail`/`failf` calls in core/validity whose rule id is a
// string literal, so a rejection site in another package, or one whose id
// arrives in a variable, is not counted and its route is not demanded; and
// vRuleValidityFuncs collects top-level functions only, so a site inside a
// method body is outside the count as well. (2) vRuleIsInThePredicate proves a
// subsumed rule's call is written in CheckStructural, not that control reaches
// it; a dead branch around it still passes. (3) vRuleDelegationWitness is this
// file's restatement of what §7 requires, so a delegated rule whose §7 sentence
// changes drifts silently until someone updates the witness — the same expiry
// every exemption's reason carries, and the reason the witness sits next to the
// sentence it restates. (4) Every certificate built here is a devnet, Era-0
// certificate, so a route that opens only under other parameters or a later
// program set is outside what the arming exercises.
//
// (5) And the one that reaches furthest, because it is the limit of the
// *discovery* rule the rest of this test stands on. vRulesDefinedInSection7
// finds a rule by matching a top-level markdown bullet — column zero, `- **`,
// the id, a space — so "a rule added in a future era arrives already counted"
// is true of a rule written in the shape its neighbours are written in, and of
// no other. A rule stated in §7 as an indented sub-bullet, inside a table, or
// in prose is never counted, no exemption is demanded of it, and this test
// passes: measured, by adding a V10 sub-bullet with no exemption and no vector
// and watching the whole package stay green. The landmarks and
// the nine-rule floor below catch the document being reformatted wholesale;
// neither can see a single non-conforming addition. This is stated rather than
// chased on purpose — a stricter parser would have a shape assumption of its
// own, and the honest response to "the discovery rule assumes a shape" is to
// name the assumption everywhere the promise is made. It is named in
// spec/README.md as well as here, for the same reason: a second implementer
// reads that document, and the sentence they read must not promise more than
// the match delivers.
//
// None of the five is a reason to weaken the exemptions; they are the boundary
// of the claim this test is entitled to make.
func TestEveryVRuleIsSeparatedByTheCorpus(t *testing.T) {
	defined := vRulesDefinedInSection7(t)

	// The corpus, keyed by the rule each invalid vector records.
	vectors, err := spec.LoadVectors("vectors")
	if err != nil {
		t.Fatal(err)
	}
	covered := map[string][]string{}
	for _, v := range vectors {
		if v.Expect.Valid || v.Expect.Rule == "" {
			continue
		}
		covered[v.Expect.Rule] = append(covered[v.Expect.Rule], v.Name)
	}
	if len(covered) == 0 {
		t.Fatal("no invalid vector records a rule; this test would assert nothing")
	}

	for _, rule := range defined {
		ex, exempt := vRulesWithoutAVector[rule]
		switch {
		case len(covered[rule]) > 0 && exempt:
			t.Errorf("%s is listed as having no vector (%s), but %v records it — the "+
				"exemption is stale and its reason no longer describes the corpus",
				rule, ex.kind, covered[rule])
		case len(covered[rule]) == 0 && !exempt:
			t.Errorf("docs/ARCHITECTURE.md §7 defines %s and no invalid vector in the "+
				"corpus records it. A second implementation can omit this rule and "+
				"replay the whole corpus green, which is the gap this check closes. Add a vector, or add "+
				"%s to vRulesWithoutAVector with a reason this test can arm.", rule, rule)
		}
	}

	// An exemption for a rule §7 does not define is a reason for nothing, and
	// it would hide the rule's disappearance from the document.
	for rule := range vRulesWithoutAVector {
		if !contains(defined, rule) {
			t.Errorf("vRulesWithoutAVector names %s, which docs/ARCHITECTURE.md §7 no "+
				"longer defines", rule)
		}
	}

	// Which V-rules core/validity rejects by under their own id. This is what
	// separates the two exemption kinds from each other, and separating them is
	// what stops the weaker one from being an escape hatch: see the "delegated"
	// branch below.
	emitted, err := emittedRuleIDs("../core/validity")
	if err != nil {
		t.Fatal(err)
	}
	// Landmarks at both ends of the V-rule list, or a changed call shape turns
	// every emitted[rule] question below into "no", which is the answer that
	// asks for nothing.
	for _, want := range []string{"V1", "V9"} {
		if !emitted[want] {
			t.Fatalf("the emitted-id scan found no %s in core/validity; the call shape has "+
				"changed and the exemption kinds below are no longer told apart", want)
		}
	}

	// And now arm each exemption, so that none of them is a sentence.
	for rule, ex := range vRulesWithoutAVector {
		t.Run(rule+"-"+ex.kind+"-by-"+strings.Join(ex.by, "-"), func(t *testing.T) {
			// An exemption naming no subsuming rule at all would make both
			// branches below check nothing.
			if len(ex.by) == 0 {
				t.Fatalf("the %s exemption names no rule standing in front of it", rule)
			}
			switch ex.kind {
			case "delegated":
				// Which rules may claim this kind is decided by the tree rather
				// than by the entry. A rule core/validity rejects by under its
				// own id is enforced *here*, so a certificate breaking it gets
				// that id back and the exemption has to be armed against the
				// predicate. Only a rule §7 states but core/validity never
				// reports — V8, which the fold enforces as B2 — is a candidate
				// for being carried under another id.
				//
				// Without this line "delegated" is the escape hatch that makes
				// every other guard in this file optional: relabelling the V9
				// exemption from subsumed to delegated-by-V3 passed, because V3
				// does have a vector, and not one certificate was built.
				if emitted[rule] {
					t.Fatalf("%s is listed as delegated to %v, but core/validity rejects by "+
						"%s under its own id — a rule the predicate reports itself is not "+
						"carried by another rule's vector, and this exemption has to be "+
						"armed as subsumed", rule, ex.by, rule)
				}
				// The rule the corpus pins instead must actually be pinned.
				for _, by := range ex.by {
					if len(covered[by]) == 0 {
						t.Fatalf("%s is exempt because %s carries it, and no vector records "+
							"%s either — so neither rule is pinned by anything", rule, by, by)
					}
				}
				// And "carries it" has to mean something. Passing the line above
				// is the whole cost of this kind for exactly the rules a future
				// era adds, so the delegation is armed against the corpus rather
				// than believed.
				armVRuleDelegation(t, rule, ex.by, vectors)
			case "subsumed":
				armVRuleSubsumption(t, rule, ex.by)
			default:
				t.Fatalf("unknown exemption kind %q", ex.kind)
			}
		})
	}
}

// armVRuleDelegation requires a delegated exemption to be arming something.
//
// Delegation is the claim that the corpus pins this rule under a different id.
// Nothing in the entry establishes that: `by` names an id, and before the
// witness requirement below the only questions asked were that core/validity does not
// report the exempt rule itself and that `by` has a vector. Both are true of
// *any* rule §7 states and the predicate never emits — V8's class, and exactly
// the shape a future era adds — paired with *any* id that happens to be pinned.
// Changing V8's `by` from B2 to V3 was green, and adding a synthetic V10 to §7
// with a delegated entry was green with no certificate built anywhere.
//
// The evidence that ties a delegate to its enforcer is a witness: a block the
// corpus already commits that (a) actually breaks the exempt rule, judged by
// this file's own restatement of what §7 requires rather than by the id the
// artifact records, and (b) the fold rejects under the id `by` names. That is
// the delegation itself, executed. A `by` that answers for something else finds
// no witness among its vectors; a rule with no witness written at all — the
// future era's V10 — reaches the fatal below and has to arrive with a vector,
// which is what the coverage rule asks for in the first place.
func armVRuleDelegation(t *testing.T, rule string, by []string, vectors []*spec.Vector) {
	t.Helper()
	breaks := vRuleDelegationWitness(rule)
	if breaks == nil {
		t.Fatalf("the %s exemption says another rule carries it and nothing here says what "+
			"breaking %s looks like, so the claim is armed by nothing. A rule §7 states "+
			"that core/validity never reports can name any id that happens to have a "+
			"vector: write the witness, or give %s a vector of its own", rule, rule, rule)
	}
	for _, want := range by {
		var witness string
		for _, v := range vectors {
			if v.Expect.Valid || v.Expect.Rule != want {
				continue
			}
			p, err := spec.ParamsFor(v.Params)
			if err != nil {
				t.Fatal(err)
			}
			b, err := v.DecodeBlock(p)
			if err != nil {
				t.Fatalf("%s: the block does not decode: %v", v.Name, err)
			}
			if !breaks(b, p) {
				continue
			}
			// This block does break the exempt rule, so the id the exemption
			// names has to be the id the fold actually answers with — otherwise
			// the delegation points at a rule that responds to something else.
			s, err := v.Pre.BuildState()
			if err != nil {
				t.Fatal(err)
			}
			_, applyErr := fold.ApplyBlock(s, b, p)
			if applyErr == nil {
				t.Fatalf("%s breaks %s and the fold accepts the block; %s is enforced by "+
					"nothing and no vector carries it", v.Name, rule, rule)
			}
			if got := fold.Rule(applyErr); got != want {
				t.Errorf("%s breaks %s and the fold rejects it by %s, but the exemption says "+
					"%s is carried by %s", v.Name, rule, ruleOrNone(got), rule, want)
				continue
			}
			witness = v.Name
			break
		}
		if witness == "" {
			t.Fatalf("%s is exempt because %s carries it, and no invalid vector recording %s "+
				"holds a block that breaks %s — so %s is pinned by a vector that is about "+
				"something else, and %s by nothing", rule, want, want, rule, want, rule)
		}
	}
}

// vRuleDelegationWitness says what breaking one delegated rule looks like, so
// that a vector claimed to carry it can be checked rather than counted.
//
// It restates §7's sentence in Go, deliberately: reading `expect.rule` off the
// candidate vector would derive the signal from the artifact under test, and
// asking core/validity is not available — a delegated rule is by construction
// one the predicate never reports. A rule with no entry here is armed by
// nothing and the caller says so.
func vRuleDelegationWitness(rule string) func(*types.Block, *params.Params) bool {
	switch rule {
	case "V8":
		// §7: TTL ≤ inclusion_height + TTL_MAX. Written as the distance rather
		// than the sum for the reason core/fold's B2 gives — the sum wraps at a
		// ttl_max params.Validate accepts, and a wrapped ceiling is not a
		// ceiling. A TTL below the height satisfies this rule and breaks
		// B1, which is a different vector.
		return func(b *types.Block, p *params.Params) bool {
			for _, c := range b.Certs {
				if c.TTL >= b.Header.Height && c.TTL-b.Header.Height > p.TTLMax {
					return true
				}
			}
			return false
		}
	}
	return nil
}

// armVRuleSubsumption builds every certificate the exemption claims cannot
// reach its rule, and requires the claim to still be true in both directions:
// the full predicate answers with the rule that route says stands in front of
// it, and the exempt rule's own function does reject the certificate when asked
// directly.
//
// The second half is what stops this from being a test of nothing. "V3 answers
// first" is also true of a certificate that breaks V3 and nothing else, and an
// exemption resting on that would survive V7 being deleted from the tree
// entirely.
//
// The subsuming rule is per *route*, not per exemption. It was per exemption
// first, and that is precisely why the hole existed: V9's reason
// named four routes and two rules, the two routes V3 answers were the only ones
// that could be written down, and swapping CheckDeposit and CheckAddressVersions
// in CheckStructural made V9 reachable through validity.Check with this test
// still green. The set of rules the routes actually produce is compared against
// the exemption's own `by` below, so the prose and the code cannot drift apart
// in either direction.
func armVRuleSubsumption(t *testing.T, rule string, by []string) {
	t.Helper()
	p := spec.Devnet()

	// Every case below is the baseline with one field edited, so the baseline
	// itself has to be valid. If it were not, a case could be answered by the
	// expected rule for a reason the edit did not cause — the arming would
	// still pass and would have proved nothing about the route.
	if err := validity.Check(vRuleBaseline(t, p, func(*types.Certificate) {}), p); err != nil {
		t.Fatalf("the unedited baseline certificate is already invalid (%v); every route "+
			"below could then be answered by a rule its edit did not cause", err)
	}

	cases := vRuleCertificates(t, p, rule)
	produced := map[string]bool{}
	for _, c := range cases {
		got := validity.Rule(validity.Check(c.cert, p))
		produced[got] = true
		if got != c.by {
			t.Errorf("%s: this route says %s answers first, the predicate answers %s — "+
				"either %s is reachable now and needs a vector of its own, or the route "+
				"names the wrong rule", c.what, c.by, ruleOrNone(got), rule)
		}
		if got := validity.Rule(c.direct(c.cert, p)); got != rule {
			t.Errorf("%s: asked directly, %s does not reject this certificate (%s) — "+
				"the exemption describes a rule that no longer does what it says",
				c.what, rule, ruleOrNone(got))
		}
	}

	// The routes and the reason must name the same rules. A rule in `by` that
	// no route produces is a sentence with nothing behind it; a rule a route
	// produces that `by` does not name is the reason having aged out of the
	// code it describes.
	for _, want := range by {
		if !produced[want] {
			t.Errorf("the %s exemption is subsumed by %s, and no route it lists is answered "+
				"by %s — the reason names a rule that stands in front of nothing",
				rule, want, want)
		}
	}
	for _, c := range cases {
		if !contains(by, c.by) {
			t.Errorf("%s is answered by %s, which the %s exemption does not name — the "+
				"reason no longer describes the routes", c.what, c.by, rule)
		}
	}
}

// vRuleCase is one route to breaking `rule`: a certificate that takes it, the
// rule that stands in front of `rule` on this route, and the rule's own entry
// point, so the arming can ask both the whole predicate and the single rule.
type vRuleCase struct {
	what string
	cert *types.Certificate
	// by is the rule the whole predicate answers with on THIS route. Two
	// routes to the same rule need not be blocked by the same rule — V9's
	// reads and writes are refused by V3 and its deposit cell and refund
	// target by V5 — and a single id per exemption could not say so.
	by     string
	direct func(*types.Certificate, *params.Params) error
}

// vRuleCertificates builds the routes by which a certificate can break a rule
// the corpus cannot carry a vector for.
//
// Every rejection site core/validity spells for the rule is listed, and that is
// checked rather than asserted: vRuleGuardedRoutes counts them across the whole
// package and the caller requires one case per site. The sentence used to be a
// claim on its own authority, and it was false — V9 guards four routes and only
// the two V3 answers were built, so the deposit cell and the refund target were
// exempt by a reason nothing re-derived. A rule that grows a fifth
// route now fails here instead of silently leaving it unarmed.
//
// The count is package-wide rather than confined to the entry point, and that
// widening is deliberate: counting inside CheckAddressVersions caught
// a fifth inline site and missed a fifth site reached through a helper called
// from its first line, which is the ordinary way a function with four
// near-identical clauses gets refactored. Where the site sits does not change
// that it is a route; a site anywhere in core/validity now demands a case, and
// if that case's `direct` entry point no longer answers for it, the arming says
// so rather than passing.
func vRuleCertificates(t *testing.T, p *params.Params, rule string) []vRuleCase {
	t.Helper()
	protocolExclusion := func(c *types.Certificate, _ *params.Params) error {
		return validity.CheckProtocolExclusion(c)
	}
	addressVersions := func(c *types.Certificate, _ *params.Params) error {
		return validity.CheckAddressVersions(c)
	}
	var cases []vRuleCase
	var entryPoint string
	switch rule {
	case "V7":
		entryPoint = "CheckProtocolExclusion"
		c := vRuleBaseline(t, p, func(c *types.Certificate) {
			vRuleInsertWrite(c, types.Write{
				Slot: types.SeqBaseFeeSlot(), Op: types.OpSet, Value: u256.One,
			})
		})
		cases = []vRuleCase{
			{"a certificate writing the sequential base-fee cell", c, "V3", protocolExclusion},
		}
	case "V9":
		entryPoint = "CheckAddressVersions"
		// 0x04 is reserved for Era S's hidden-value cells (§6) and is the
		// version V9's own doc comment says the rule exists for. A distinct
		// seed per route keeps the four certificates from colliding on one
		// address, which would let one route stand in for another.
		unknown := func(seed byte) types.Address {
			a := vRuleKey(t, seed).Persistent()
			a[0] = 0x04
			return a
		}
		read := vRuleBaseline(t, p, func(c *types.Certificate) { c.Reads[0].Slot.Addr = unknown(21) })
		write := vRuleBaseline(t, p, func(c *types.Certificate) {
			w := c.Writes[0]
			c.Writes = c.Writes[1:]
			w.Slot.Addr = unknown(22)
			vRuleInsertWrite(c, w)
		})
		// The deposit cell and the refund target are the two routes V3 cannot
		// see: neither is derived, so CheckDerivation compares nothing against
		// them. The refund target is refused by V5, whose IsUserAddress test is
		// narrower than V9's version range. The deposit cell used to be refused
		// by the same clause and is now refused by V4 first: V4 requires
		// an authorising signature for any deposit cell rather than only for a
		// user one, no key hashes to a 0x04 address, and CheckAuthorization
		// runs before CheckDeposit. V5 still refuses it when asked directly —
		// the seal is two predicates, not one — but the rule the *predicate*
		// answers with on this route is V4, and that is what this route
		// records. The deposit cell is edited to a
		// 0x04 address rather than to a one-shot one so that DeriveCert adds no
		// MARK_SPENT and V3 still passes — the point of the route is that a
		// deposit-shaped rule, not V3, is what stands in front of V9 here.
		deposit := vRuleBaseline(t, p, func(c *types.Certificate) {
			c.Deposit.Cell.Addr = unknown(23)
		})
		refund := vRuleBaseline(t, p, func(c *types.Certificate) {
			c.Deposit.RefundTo.Addr = unknown(24)
		})
		cases = []vRuleCase{
			{"a certificate reading an unknown-version address", read, "V3", addressVersions},
			{"a certificate writing an unknown-version address", write, "V3", addressVersions},
			{"a certificate depositing from an unknown-version address", deposit, "V4", addressVersions},
			{"a certificate refunding to an unknown-version address", refund, "V5", addressVersions},
		}
	default:
		t.Fatalf("no certificate is built for the %s exemption, so it is armed by nothing", rule)
		return nil
	}
	if guarded := vRuleGuardedRoutes(t, rule); guarded != len(cases) {
		t.Fatalf("%s rejects on %d routes in core/validity and this arming builds %d "+
			"certificate(s); a route nobody exercises is a route that can become "+
			"reachable in silence", rule, guarded, len(cases))
	}
	vRuleIsInThePredicate(t, entryPoint)
	return cases
}

// vRuleIsInThePredicate requires CheckStructural to still call the exempt
// rule's entry point.
//
// Everything else here is behavioural, and this one cannot be, which is the
// whole reason it is needed. A subsumed rule is by definition one no
// certificate can reach through validity.Check, so deleting its *call* from
// CheckStructural — as opposed to deleting its body — changes no answer any
// certificate can produce: the routes still hand back V3 and V5, the rule's own
// function still rejects when asked directly, and the exemption's sentence
// stays literally true while the rule has left the predicate. Nothing can
// observe that from outside, so this reads the wiring instead.
//
// It asks the parser for a call expression rather than the source text for an
// identifier, which is what closes the routine edit that defeated the text
// version: deleting the call and leaving the name behind in the comment that
// explained it kept `strings.Contains` satisfied. What remains is
// that this proves the call is written down, not that control reaches it —
// hiding it behind a dead branch still passes, and that is a deliberate act
// rather than the refactor this catches.
func vRuleIsInThePredicate(t *testing.T, fn string) {
	t.Helper()
	funcs := vRuleValidityFuncs(t)
	pred, ok := funcs["CheckStructural"]
	if !ok {
		t.Fatal("core/validity has no func CheckStructural; this check would read nothing")
	}
	if _, ok := funcs[fn]; !ok {
		t.Fatalf("core/validity has no func %s; this check would read nothing", fn)
	}
	called := false
	ast.Inspect(pred.Body, func(n ast.Node) bool {
		call, ok := n.(*ast.CallExpr)
		if !ok {
			return true
		}
		if id, ok := call.Fun.(*ast.Ident); ok && id.Name == fn {
			called = true
		}
		return true
	})
	if !called {
		t.Fatalf("core/validity's CheckStructural no longer calls %s; the rule is exempt "+
			"from the corpus because the predicate refuses its routes earlier, and a "+
			"predicate that does not run it at all is not that", fn)
	}
}

// vRuleGuardedRoutes counts the rejection sites core/validity spells for one
// rule, which is how many distinct routes that rule guards.
//
// It reads the source because the alternative is a number written by hand next
// to the cases, which is the same statement the cases already are and would
// drift with them. Counting where the rule actually rejects ties the arming to
// the rule instead: a fifth `failf("V9", …)` fails this test until a
// certificate for that route exists.
//
// The count is over every function in the package, not over one entry point, so
// that extracting a helper out of a rule that has grown four near-identical
// clauses — the ordinary refactor, not an attack — moves the sites without
// hiding them.
func vRuleGuardedRoutes(t *testing.T, rule string) int {
	t.Helper()
	lit := `"` + rule + `"`
	n := 0
	for _, fn := range vRuleValidityFuncs(t) {
		ast.Inspect(fn.Body, func(node ast.Node) bool {
			call, ok := node.(*ast.CallExpr)
			if !ok {
				return true
			}
			id, ok := call.Fun.(*ast.Ident)
			if !ok || (id.Name != "fail" && id.Name != "failf") || len(call.Args) == 0 {
				return true
			}
			if arg, ok := call.Args[0].(*ast.BasicLit); ok && arg.Kind == token.STRING && arg.Value == lit {
				n++
			}
			return true
		})
	}
	if n == 0 {
		t.Fatalf("core/validity contains no rejection site spelled %s; the rule has been "+
			"rewritten and this count now reads nothing", rule)
	}
	return n
}

// vRuleValidityFuncs parses core/validity's non-test sources and returns its
// top-level functions by name.
//
// It replaced a pair of string scans over validity.go, for two concrete
// reasons. The parser has no comments in it — mode 0 drops
// them — so deleting the CheckAddressVersions *call* from CheckStructural while
// leaving the identifier behind in a comment no longer satisfies
// vRuleIsInThePredicate, and a rejection site quoted in a comment no longer
// inflates a route count. And it reads the package rather than one file, so a
// rule whose sites or whose entry point move to a neighbouring file are still
// found. A parse error or an empty package fails loudly here: a scan that
// silently reads nothing turns every check built on it into a check of nothing.
func vRuleValidityFuncs(t *testing.T) map[string]*ast.FuncDecl {
	t.Helper()
	const dir = "../core/validity"
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	fset := token.NewFileSet()
	out := map[string]*ast.FuncDecl{}
	for _, e := range entries {
		name := e.Name()
		if !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		f, err := parser.ParseFile(fset, filepath.Join(dir, name), nil, 0)
		if err != nil {
			t.Fatalf("core/validity/%s does not parse, so this scan reads nothing: %v", name, err)
		}
		for _, d := range f.Decls {
			fn, ok := d.(*ast.FuncDecl)
			if !ok || fn.Recv != nil || fn.Body == nil {
				continue
			}
			out[fn.Name.Name] = fn
		}
	}
	// Landmarks at both ends of the predicate, or a package that stopped
	// parsing into the shape this reads would turn every question below into
	// "not found", which is the answer that asks for nothing.
	for _, want := range []string{"Check", "CheckStructural", "CheckAddressVersions"} {
		if _, ok := out[want]; !ok {
			t.Fatalf("core/validity declares no func %s; the predicate has been "+
				"restructured and this scan now reads nothing", want)
		}
	}
	return out
}

// vRuleBaseline is a certificate a wallet would emit, edited once, re-sized and
// re-signed — the same order spec/gen's buildUncheckedEdited uses and for the
// same reason: an edit that moves the encoded length moves the fee ceiling, and
// V5 would answer before the rule under test.
func vRuleBaseline(t *testing.T, p *params.Params, edit func(*types.Certificate)) *types.Certificate {
	t.Helper()
	alice, bob := vRuleKey(t, 2), vRuleKey(t, 3)
	c, err := (&wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), u256.FromUint64(1_000_000)),
		TTL:     100,
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		FeeBid: wallet.Bid(u256.FromUint64(50_000), u256.FromUint64(1_000),
			u256.FromUint64(500), u256.FromUint64(10)),
		Signers: []*wallet.Key{alice},
	}).Build()
	if err != nil {
		t.Fatalf("the baseline certificate does not build: %v", err)
	}
	edit(c)
	if ceiling, ok := c.FeeCeiling(p); ok && c.Deposit.Amount.Lt(ceiling) {
		c.Deposit.Amount = ceiling
	}
	c.Sigs = []types.Sig{{PubKey: alice.PubKey(), Sig: alice.Sign(c.SigningMessage(p))}}
	return c
}

func vRuleKey(t *testing.T, n byte) *wallet.Key {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = n
	}
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// vRuleInsertWrite keeps the write list in the strictly sorted order V1
// requires, so that an edited certificate is refused for the rule it is about
// rather than for its ordering.
func vRuleInsertWrite(c *types.Certificate, w types.Write) {
	c.Writes = append(c.Writes, w)
	sort.Slice(c.Writes, func(i, j int) bool { return c.Writes[i].Slot.Less(c.Writes[j].Slot) })
}

// vRulesDefinedInSection7 reads the rule ids out of the document that is
// normative for them, rather than from a list in this file — a list here would
// be the same statement the corpus already fails to keep current.
//
// It discovers a rule by its *shape*: a top-level bullet at column zero. That
// assumption is the fifth limit stated on TestEveryVRuleIsSeparatedByTheCorpus,
// and it is the load-bearing one — a rule §7 states in any other shape is not
// counted here and is asked for nothing anywhere. The checks below catch the
// list being reformatted wholesale and cannot catch one addition that does not
// match.
func vRulesDefinedInSection7(t *testing.T) []string {
	t.Helper()
	raw, err := os.ReadFile("../docs/ARCHITECTURE.md")
	if err != nil {
		t.Fatal(err)
	}
	bullet := regexp.MustCompile(`(?m)^- \*\*(V[0-9]+) `)
	var out []string
	for _, m := range bullet.FindAllStringSubmatch(string(raw), -1) {
		out = append(out, m[1])
	}
	// The scan must find the shape it is looking for at both ends of the list,
	// or a reformatted document turns "every rule has a vector" into "no rule
	// was looked for" and this test passes by reading nothing.
	for _, want := range []string{"V1", "V9"} {
		if !contains(out, want) {
			t.Fatalf("the §7 scan found no %s in docs/ARCHITECTURE.md; the V-rule list "+
				"has been reformatted and this test now reads nothing", want)
		}
	}
	if len(out) < 9 {
		t.Fatalf("the §7 scan found only %d V-rules (%v); the document defines at least "+
			"nine and this test is reading a fragment of the list", len(out), out)
	}
	return out
}

func contains(all []string, want string) bool {
	for _, v := range all {
		if v == want {
			return true
		}
	}
	return false
}
