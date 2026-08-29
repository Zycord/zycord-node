package p2p_test

import (
	"testing"

	"zycord/core/crypto"
)

// TestAnAdmittedCertificateIsVerifiedExactlyOnceEndToEnd: a certificate that
// gossip admits costs exactly one Ed25519 pass over its signatures, measured
// across the whole engine call rather than inside any one package.
//
// This is the headline property of removing the engine's own validity.Check,
// and it is a claim about a NUMBER OF EVALUATIONS. That is why it is counted
// here and not read off the source. Every source-shaped guard written for this
// property was defeated in turn, and each escape was a shape the codebase
// itself uses rather than an adversarial one:
//
//   - `vcheck := validity.Check` — a function value, the idiom
//     node/mempool/mempool.go:481-487 introduces deliberately for its own
//     verification counter.
//   - `var recheckV2 = validity.CheckSignatures` at package scope, invoked
//     after a successful Add — outside any one function body.
//   - `verify.Sequential{}.Verify(certs, e.Chain.Params())` — node/verify runs
//     the identical predicate (verify.go:57) and engine.go already imports it
//     for the proof-of-work cache, so core/validity is never named.
//   - a second `mempool.New(p, mempool.DefaultPolicy()).Add(cert, …)` — which
//     does not read as re-verification at all; it reads as pooling, using the
//     very API that should run the predicate. THE POLICY IS PART OF THE
//     MUTANT, not an incidental of one construction: with mempool.Policy{} the
//     shadow pool has MaxPerUnderwriter == 0 and refuses at a step-3 gate
//     inside screen(), ahead of verifySignatures, so it buys ZERO extra
//     Ed25519 passes and this counter is blind to it at any placement. Measured
//     both ways: Policy{} -> `mempool: the underwriter has too many
//     certificates in flight`, counter PASSES; DefaultPolicy() -> shadow Add
//     returns nil, counter reports `cost 2 ... want exactly 1`. DefaultPolicy
//     is the honest construction because cmd/zycordd/main.go:135 builds the
//     node's real pool with it. A mutant whose verdict depends on an unstated
//     parameter is the row-level form of a reused -run filter.
//
// The last two defeat a PACKAGE-granularity guard — one that asks only which
// packages this file may import — because engine.go legitimately imports both
// node/verify and node/mempool. They do NOT defeat the symbol-granularity
// reference set that ships beside this test, and that was measured rather than
// argued: engine.go never legitimately names verify.Sequential or mempool.New,
// so neither is in an allowed set and both die in
// TestP2PNamesNoRouteToASecondVerification, with distinct signatures — allowed
// sets [NewWorkCache WorkWasChecked] and [Pool] respectively.
//
// So the reason to count is NOT that a reference set is worthless. It is that
// **an enumeration of spellings is not the property**: that guard is blind by
// construction to a route through a package its table does not name, and
// extending the table is not the property either. A count of evaluations is.
//
// The two are complementary and both ship. Over the four escapes above plus the
// asynchronous hop, the reference set kills all five and this counter kills
// three; what the counter alone reaches is a SYNCHRONOUS route through a
// package nobody has listed, which THE AUTHORED table beside it cannot — its
// reach is bounded by the rows someone wrote down. That is a claim about THIS
// guard and not about reference sets in general, and the distinction is not
// academic: a set DERIVED from the measured import closure, deny-by-default
// over every package in node/p2p's closure that reaches crypto.VerifyStrict
// and requiring a row before such a package may be imported, WOULD reach that
// route. That is the `replace a match with a structure` repair, it is not
// written here, and saying `no reference set can` would foreclose it for the
// next reader. Neither of the two that ship is sufficient:
// this counter is blind to a verification that avoids crypto.VerifyStrict or
// runs after the delta closes, and the reference set is blind to any package
// outside its table. See vrule_reference_set_test.go and the PR body.
//
// crypto.VerifyStrict is the choke point that makes counting possible: it is
// the only non-test caller of ed25519.Verify on the node path, and
// core/validity's V2 loop (validity.go:105) is its only non-test caller in
// turn — verified with a parser over all 90 non-test .go files in the tree, not
// with a text search, because two of grep's hits were comments. So every
// certificate signature this node checks, by whatever route and through however
// many packages, is counted exactly once here. That is what makes this test
// hop-count-independent: it catches a re-verification through a package nobody
// has thought of yet, because it never asks which package.
//
// The counter is process-wide, so this measures a DELTA and no test in this
// package calls t.Parallel() — checked, and the only occurrence in the package
// is this sentence. See the PR body for
// that accepted cost stated in full.
func TestAnAdmittedCertificateIsVerifiedExactlyOnceEndToEnd(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "a", p, key(t, 1).Persistent())
	n.mine(t, int(p.CoinbaseMaturity)+2)

	cert := buildCert(t, n, key(t, 1), 0)

	// Non-vacuity of the expectation itself: a certificate with no signatures
	// would make "exactly one pass" the same number as "no passes at all".
	want := uint64(len(cert.Sigs))
	if want == 0 {
		t.Fatal("the fixture certificate carries no signatures; one pass and " +
			"zero passes are the same count and this test asserts nothing")
	}

	// Everything above verifies signatures too — building the certificate, and
	// mining blocks that fold them — so the delta is taken here, around the one
	// call under test, and not from zero.
	before := crypto.VerificationCount()
	v := n.engine.OnCertificate("honest:1", cert.MarshalSSZ())
	got := crypto.VerificationCount() - before

	// Anti-vacuity floor: if the certificate were refused, the count below would
	// be a fact about a rejection rather than about an admission.
	if !v.Forward {
		t.Fatalf("the honest certificate was not admitted and forwarded: %v", v.Err)
	}
	if got != want {
		t.Fatalf("an admitted certificate cost %d Ed25519 verifications, want "+
			"exactly %d (one pass over its %d signature(s)).\n"+
			"Pool.Add runs the whole stateless predicate itself — structural "+
			"rules, then every O(1) policy gate, then V2 last and outside the "+
			"pool lock (cost discipline, step 2) — so the engine reads the verdict off "+
			"Add's error and must never evaluate it again. %d means a second "+
			"pass is back, whatever spelling it arrived in.",
			got, want, len(cert.Sigs), got)
	}
}

// TestACheapRefusalBuysNoSignatureVerificationInTheEngine: a certificate this
// node refuses on a policy gate costs ZERO Ed25519 verifications, measured
// through the engine's own entry point.
//
// docs/spec/wire.md §10.1 states this as a normative consequence — "a message
// that fails at step 1, 2 or 3 MUST NOT have caused a signature verification or
// a proof-of-work evaluation" — and until now it was the one half of §10.1 this
// tree could not measure. sim/wiring's TestSignatureWorkIsOrderedAfterTheCheapChecks
// says so in its own comment: proof of work has a counter behind pow.Engine and
// "signature verification has no such counter", so the ordering was asserted on
// engine.go's syntax tree instead. It has a counter now, and this is the
// measurement that comment was standing in for.
//
// The separating input is the same expired certificate the verdict-based test
// uses, so the two are about one scenario from two angles: that one asserts the
// node does not CHARGE for a verdict it never reached, this one asserts it does
// not PAY for it either.
func TestACheapRefusalBuysNoSignatureVerificationInTheEngine(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, "a", p, key(t, 1).Persistent())
	n.mine(t, int(p.CoinbaseMaturity)+2)

	stale := buildCert(t, n, key(t, 1), 0)
	n.mine(t, 11)
	if n.chain.Height() <= stale.TTL {
		t.Fatalf("tip %d has not passed the certificate's TTL %d; the gate under "+
			"test would not fire and the assertion would be vacuous",
			n.chain.Height(), stale.TTL)
	}

	before := crypto.VerificationCount()
	v := n.engine.OnCertificate("attacker:1", stale.MarshalSSZ())
	got := crypto.VerificationCount() - before

	if v.Err == nil {
		t.Fatal("the expired certificate was accepted; this test is no longer " +
			"measuring a refusal")
	}
	if got != 0 {
		t.Fatalf("a certificate refused by the TTL gate cost %d Ed25519 "+
			"verifications, want 0. wire.md §10.1: a message refused at step 1, "+
			"2 or 3 MUST NOT have caused a signature verification. The expired "+
			"certificate is the cheapest refusal the pool has — it needs no "+
			"funds and is replayable forever — so a signature pass here is the "+
			"double-verification defect in its original form.", got)
	}

	// The non-vacuity control, and it is the one this whole file turns on: the
	// zero above must be a zero the instrument could have failed to produce.
	// Same node, same counter, same call — an honest certificate that IS
	// admitted moves it.
	// key(t, 1) is the node's payout address and therefore the one with a
	// funded deposit cell; the expired certificate above was refused rather
	// than pooled, so sequence 0 is still free, and the tip has moved so the
	// fresh certificate's TTL and id both differ from it.
	live := buildCert(t, n, key(t, 1), 0)
	before = crypto.VerificationCount()
	if v := n.engine.OnCertificate("honest:1", live.MarshalSSZ()); !v.Forward {
		t.Fatalf("the control certificate was refused: %v", v.Err)
	}
	if moved := crypto.VerificationCount() - before; moved == 0 {
		t.Fatal("an admitted certificate also cost 0 verifications; the counter " +
			"is blind and the zero asserted above is vacuous")
	}
}
