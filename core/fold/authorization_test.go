package fold_test

import (
	"bytes"
	"fmt"
	"testing"

	"zycord/core/crypto"
	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/sim/harness"
	"zycord/wallet"
)

// The re-signing suite: one authorization, many signatures.
//
// The griefing suite next door replays *bytes*. Every test in it hands the fold
// a certificate it has already seen, and every one of them is closed by the
// seen set. That is a uniform input in exactly CONTRIBUTING's sense: none of
// them can fire a rule about two *different* encodings of one authorization,
// because none of them ever produces a second signature.
//
// This file produces one. RFC 8032 verification accepts any (R, S) satisfying
// [S]B = R + [h(R‖A‖M)]A; the determinism of crypto/ed25519 is a signer-side
// convention and not a verification rule, so any signer can emit unboundedly
// many valid signatures over one message. Nothing an encoding rule can say
// reaches that — every [r]B is a canonically encodable prime-order point — so
// the defence has to be that the *authorization*, not the signature bytes,
// is what the billing law is keyed on.

// resigned is harness.ReSignCertificate with the test's error handling: a copy
// of c whose signature by k is a different valid signature over the same body,
// with every other signer's bytes carried across untouched.
func resigned(t *testing.T, p *params.Params, c *types.Certificate, k *wallet.Key, nonce byte) *types.Certificate {
	t.Helper()
	out, err := harness.ReSignCertificate(c, p, k.Seed(), nonce)
	if err != nil {
		t.Fatalf("re-signing: %v", err)
	}
	return out
}

// assertSameAuthorization pins what the fixture is before any rule is asked
// about it: two *different encodings* carrying one authorization — same body,
// same signer set, both stateless-valid, both surviving a wire round trip.
//
// The two halves are both load-bearing. If the encodings were identical the
// scenario would be the byte replay the griefing suite already covers and the
// seen set has always closed; if the authorizations differed it would be a
// signer authorising two payments, which is not a finding.
func assertSameAuthorization(t *testing.T, w *world, a, b *types.Certificate) {
	t.Helper()

	if a.BodyRoot() != b.BodyRoot() {
		t.Fatal("the two certificates do not share a body root; they are not one authorization")
	}
	if a.ExemplarHash() == b.ExemplarHash() {
		t.Fatal("the two certificates are the same bytes; this is a byte replay, not a re-signing")
	}
	if err := validity.Check(a, w.p); err != nil {
		t.Fatalf("the original is not stateless-valid: %v", err)
	}
	if err := validity.Check(b, w.p); err != nil {
		t.Fatalf("the re-signed copy is not stateless-valid: %v", err)
	}
	// A rule that only holds for certificates this process built is not a
	// consensus rule. Both must survive the decoder an attacker would send
	// them through.
	for _, c := range []*types.Certificate{a, b} {
		got, err := types.UnmarshalCertificate(c.MarshalSSZ(), w.p)
		if err != nil {
			t.Fatalf("the certificate does not round-trip: %v", err)
		}
		if got.ID() != c.ID() {
			t.Fatal("the certificate does not round-trip to the same id")
		}
	}
	if len(a.Sigs) != len(b.Sigs) {
		t.Fatal("the signer sets differ")
	}
	for i := range a.Sigs {
		if a.Sigs[i].PubKey != b.Sigs[i].PubKey {
			t.Fatal("the signer sets differ")
		}
	}
}

// sponsored builds the Era-0 shape that makes this theft rather than
// self-harm: Alice authorises a payment to Bob, and Bob's cell pays the
// deposit. V5 permits a third-party deposit; V4 therefore requires both
// signatures, and Bob holds one of them.
func (w *world) sponsored(t *testing.T, from *wallet.Key, fromAddr, to types.Address, sponsor *wallet.Key, amount u256.U256, seq uint64) *types.Certificate {
	t.Helper()
	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, fromAddr, to, amount),
		Seq:     seq,
		TTL:     w.chain.NextHeight() + 10,
		Deposit: wallet.SelfDeposit(sponsor.Persistent(), sponsor.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{from, sponsor},
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// TestACoSignerCannotReSignOneBodyIntoASecondBillInOneBlock is the theft case
// keeping signatures out of the id closes. Alice signs one payment of
// 100_000_000 to Bob; Bob sponsors the deposit, so his signature is required
// and he holds it. He replaces his own signature with a second valid one over
// the same body, carrying Alice's signature across byte-identical, and puts
// both copies in one block.
//
// The property: **one authorization is billable once, however many ways it is
// signed.** The signer set and the body are the authorization; the signature
// bytes are only evidence that it was given.
func TestACoSignerCannotReSignOneBodyIntoASecondBillInOneBlock(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	aliceAddr, bobAddr := alice.Persistent(), bob.Persistent()
	w.fund(aliceAddr, drops(900_000_000))
	w.fund(bobAddr, drops(900_000_000))

	amount := drops(100_000_000)
	first := w.sponsored(t, alice, aliceAddr, bobAddr, bob, amount, 0)
	second := resigned(t, w.p, first, bob, 0xC0)
	assertSameAuthorization(t, w, first, second)

	// Alice's authority rides across untouched. If this ever stops holding the
	// test has become a test of Alice signing twice, which is not the finding.
	aliceFirst, aliceSecond := sigOf(t, first, alice), sigOf(t, second, alice)
	if !bytes.Equal(aliceFirst[:], aliceSecond[:]) {
		t.Fatal("Alice's signature changed; the fixture no longer shows a co-signer acting alone")
	}

	beforeAlice := w.chain.Balance(aliceAddr)
	_, res, err := w.chain.AddBlock(w.payout, first, second)
	reportDoubleBill(t, w, res, aliceAddr, beforeAlice, amount)
	mustBeInvalidBlock(t, err, "one body signed twice, both copies in one block")

	spent := beforeAlice.SatSub(w.chain.Balance(aliceAddr))
	if !spent.IsZero() {
		t.Fatalf("the rejected block moved %s out of the authorising signer's cell", spent.String())
	}
}

// TestACoSignerCannotReSignOneBodyIntoASecondBillAcrossBlocks is the same
// attack spread over two blocks, which is the form that survives any
// within-block deduplication: the first copy commits and is marked billed, and
// the second arrives afterwards against a state that has already seen the
// authorization.
func TestACoSignerCannotReSignOneBodyIntoASecondBillAcrossBlocks(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	aliceAddr, bobAddr := alice.Persistent(), bob.Persistent()
	w.fund(aliceAddr, drops(900_000_000))
	w.fund(bobAddr, drops(900_000_000))

	amount := drops(100_000_000)
	first := w.sponsored(t, alice, aliceAddr, bobAddr, bob, amount, 0)
	second := resigned(t, w.p, first, bob, 0xEE)
	assertSameAuthorization(t, w, first, second)

	res := w.chain.MustAddBlock(w.payout, first)
	if res.Outcomes[0].Outcome != fold.Applied {
		t.Fatalf("setup: outcome = %s", res.Outcomes[0].Outcome)
	}

	// One exemplar per block, over consecutive blocks, is the form that needs
	// no cooperative proposer at all: each block carries a single certificate
	// and looks entirely ordinary. B3 is the only rule standing in front of it,
	// and B3 is the rule keyed on the id.
	beforeAlice := w.chain.Balance(aliceAddr)
	for i, nonce := range []byte{0xEE, 0xE1, 0xE2, 0xE3, 0xE4} {
		copyN := resigned(t, w.p, first, bob, nonce)
		assertSameAuthorization(t, w, first, copyN)

		_, resN, err := w.chain.AddBlock(w.payout, copyN)
		reportDoubleBill(t, w, resN, aliceAddr, beforeAlice, amount)
		mustBeInvalidBlock(t, err,
			fmt.Sprintf("re-signed copy %d of an already-billed authorization", i+1))
	}

	spent := beforeAlice.SatSub(w.chain.Balance(aliceAddr))
	if !spent.IsZero() {
		t.Fatalf("the later blocks billed the authorising signer a further %s", spent.String())
	}
}

// TestOneAuthorizationCannotBeAmplifiedAcrossOneBlock is the amplification
// bound, exercised rather than reasoned about. Sixteen exemplars of one
// authorization go into one block; the ceiling on how many an attacker could
// afford is MaxCertsPerBlock, and across a TTL window it is that times TTLMax.
//
// Sixteen rather than two on purpose: a rule that dedupes pairwise but leaks on
// the third copy would pass a two-copy test, and this finding exists because
// tests were built from inputs too uniform to fire the rule they claimed to pin.
func TestOneAuthorizationCannotBeAmplifiedAcrossOneBlock(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	aliceAddr, bobAddr := alice.Persistent(), bob.Persistent()
	w.fund(aliceAddr, drops(900_000_000))
	w.fund(bobAddr, drops(900_000_000))

	amount := drops(1_000_000)
	first := w.sponsored(t, alice, aliceAddr, bobAddr, bob, amount, 0)

	certs := []*types.Certificate{first}
	ids := map[types.Hash]struct{}{first.ID(): {}}
	exemplars := map[types.Hash]struct{}{first.ExemplarHash(): {}}
	for i := 0; i < 15; i++ {
		c := resigned(t, w.p, first, bob, byte(0x10+i))
		assertSameAuthorization(t, w, first, c)
		certs = append(certs, c)
		ids[c.ID()] = struct{}{}
		exemplars[c.ExemplarHash()] = struct{}{}
	}
	// The fixture is only worth anything if the copies really are distinct
	// bytes carrying one authorization.
	if len(exemplars) != len(certs) {
		t.Fatalf("only %d distinct encodings among %d copies", len(exemplars), len(certs))
	}
	if len(ids) != 1 {
		t.Fatalf("%d distinct ids for one authorization", len(ids))
	}

	beforeAlice := w.chain.Balance(aliceAddr)
	_, res, err := w.chain.AddBlock(w.payout, certs...)
	reportDoubleBill(t, w, res, aliceAddr, beforeAlice, amount)
	mustBeInvalidBlock(t, err, "sixteen exemplars of one authorization in one block")

	spent := beforeAlice.SatSub(w.chain.Balance(aliceAddr))
	if !spent.IsZero() {
		t.Fatalf("the rejected block moved %s against one authorization of %s",
			spent.String(), amount.String())
	}
}

// TestASingleSignerCannotReSignOneBodyIntoTwoBills is the no-attacker variant.
// It needs no second party at all: a wallet or HSM that randomises or hedges
// its Ed25519 nonce produces exactly this on a retry of a stuck payment, and
// nothing in the protocol or in spec/wire.md ever told it not to. Under the
// old id the retry is a second payment; under the fixed one it is refused as
// the duplicate it is.
func TestASingleSignerCannotReSignOneBodyIntoTwoBills(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	aliceAddr := alice.Persistent()
	w.fund(aliceAddr, drops(900_000_000))

	first := w.transfer(alice, aliceAddr, bob.Persistent(), drops(10_000_000), 0)
	second := resigned(t, w.p, first, alice, 0x5A)
	assertSameAuthorization(t, w, first, second)

	beforeAlice := w.chain.Balance(aliceAddr)
	_, res, err := w.chain.AddBlock(w.payout, first, second)
	reportDoubleBill(t, w, res, aliceAddr, beforeAlice, drops(10_000_000))
	mustBeInvalidBlock(t, err, "a wallet retry re-signed at a fresh nonce")

	spent := beforeAlice.SatSub(w.chain.Balance(aliceAddr))
	if !spent.IsZero() {
		t.Fatalf("the retry moved a further %s", spent.String())
	}
}

// reportDoubleBill prints what a block that should not have been accepted
// actually did. It exists so that a failure of these tests is a transcript of
// the theft rather than the word "accepted": the number that matters is how
// much left the authorising signer's cell against one authorization.
func reportDoubleBill(t *testing.T, w *world, res *fold.Result, victim types.Address, before, authorised u256.U256) {
	t.Helper()
	if res == nil {
		return
	}
	for _, o := range res.Outcomes {
		t.Logf("outcome %x -> %s (charged %s)", o.ID[:8], o.Outcome, o.Charged.String())
	}
	t.Logf("authorised %s; the signer's cell lost %s",
		authorised.String(), before.SatSub(w.chain.Balance(victim)).String())
}

// TestAPayeeCannotGrindTheFoldOrderToCaptureAContestedPayment is the second
// half of that defect, and it survives any fix that only moves the seen set.
//
// F1 sorts by (underwriter, seq, id). Two certificates of one underwriter at
// one Seq tie on both leading components, so the tiebreak alone decides which
// folds first — which, against a contended balance, decides which one applies
// and which one is billed a skip. State the defect structurally:
//
//	fee incidence and the ordering key are the same address — the fold reserves
//	the deposit from, and settles against, c.Deposit.Cell, which *is*
//	UnderwriterID() — while the grindable input, any signature slot, is tied to
//	neither. The key is named for one party and, while it covered signature
//	bytes, was settable by several others, none of whom need be that party.
//
// Which gives, in one sentence:
//
//	a consensus ordering key that any signer of either certificate can set at
//	will after the competitor is public, capturing the contested payment at
//	zero marginal cost, in self-insured Era 0.
//
// Be exact about the harm, because it has been stated wrongly here twice, in
// opposite directions.
//
// The grind does not *cause* the skip. Erin's balance covers one of two
// obligations, so one is skipped and its SKIP_FEE burned against her cell
// whichever way the tie falls, and SKIP_FEE is a constant. That much of the
// first telling — "the cost of the skip it causes" — was wrong.
//
// But "the grinder adds nothing to Erin's bill" was wrong too, and measurably.
// The winner's APPLIED charge is a function of its own gas, and two
// certificates tying on (underwriter, Seq) need not be the same size: here
// toAlice is 1363 bytes at 1600 seq / 3226 par gas against toDave's 848 at
// 600 / 1946. Under the shipped order toDave applies at 727282 while toAlice's
// SKIP_FEE is 1000000, and Erin's cell loses 101727282 in total. Flip the tie
// and the applied half is the larger certificate's.
//
// So the grind moves two things: who is paid 100,000,000 drops, decided after
// Dave's certificate is public — and what the deposit-cell owner pays for the
// privilege, decided by a key she does not hold. Theft of priority first, and a
// bill she did not agree to on top of it.
//
// And "third party" would be the wrong word for the grinder, which is why this
// test is not named with it. Alice must hold a key: the value she re-signs is
// her own signature, and no one holding no key can produce a second valid one.
// She is a stranger to the certificate she is racing and to the cell that pays
// for the race, and that is the whole of her outsider status.
//
// Every clause is deliberate, because the weaker shapes are uniform inputs in
// exactly the sense above and cannot fire it:
//
//   - **self-insured.** Both deposits are Erin's own cells, which is Era 0's
//     only mode (whitepaper §14). No sponsor, no Phase-1 machinery. A test
//     needing a third-party deposit would understate how reachable this is.
//   - **the grinder signs ONE certificate.** Alice's signature is in the
//     certificate that pays her because it also moves a drop between two of her
//     own addresses; Dave's certificate does not contain her at all.
//   - **the grinder pays exactly zero.** She owns no deposit cell, so the
//     loser's burned skip fee falls on Erin, and her own move is between two
//     addresses she owns, so her holdings are unchanged by it.
//   - **nobody is dishonest.** Erin signs two legitimate obligations against a
//     balance that covers one. The griefing suite already produces that state
//     (TestReplayOfASkippedCertificateInvalidatesTheBlock funds one signer and
//     sends two transfers it cannot both cover), and whitepaper §5 makes
//     skip-on-contention the designed-for case rather than an accident.
//
// Nothing enforces one certificate per (underwriter, seq): block validity does
// not, and node/mempool says so outright — Seq is an ordering key rather than a
// nonce, and replace-by-fee pools several at one Seq by design.
//
// The property: the fold order is a function of the authorizations, and no
// signature anybody can produce moves it — nor, therefore, moves who gets paid.
func TestAPayeeCannotGrindTheFoldOrderToCaptureAContestedPayment(t *testing.T) {
	w := newWorld(t)
	erin, alice, dave := key(t, 6), key(t, 4), key(t, 5)
	erinAddr, aliceAddr, daveAddr := erin.Persistent(), alice.Persistent(), dave.Persistent()
	aliceOneShot := alice.OneShot()

	// Erin can cover one of the two payments, not both. That is the contention
	// the tiebreak resolves, and it is the whole stake.
	contested := drops(100_000_000)
	w.fund(erinAddr, drops(150_000_000))
	w.fund(aliceOneShot, drops(1_000))

	// Erin pays Alice, and Alice moves a single drop between two addresses of
	// her own — which is what puts her signature in the certificate without
	// putting any of her value at risk. Erin pays Dave in the competing one,
	// which carries no signature of Alice's. Both are insured by Erin herself.
	toAlice := w.selfInsured(t, erin, wallet.Transfer(
		types.Move{Asset: types.NativeAsset, Src: erinAddr, Dst: aliceAddr, Amount: contested},
		types.Move{Asset: types.NativeAsset, Src: aliceOneShot, Dst: aliceAddr, Amount: drops(1)},
	), 0, alice)
	toDave := w.selfInsured(t, erin, wallet.Tip(types.NativeAsset, erinAddr, daveAddr, contested), 0)

	if toAlice.UnderwriterID() != toDave.UnderwriterID() || toAlice.Seq != toDave.Seq {
		t.Fatal("setup: the two certificates do not tie on (underwriter, seq)")
	}
	if toAlice.Deposit.Cell.Addr != erinAddr || toDave.Deposit.Cell.Addr != erinAddr {
		t.Fatal("setup: this is not the self-insured shape")
	}
	if signs(toDave, alice) {
		t.Fatal("setup: the grinder signs the competing certificate, which is the shape this test exists to avoid")
	}
	if !signs(toAlice, alice) {
		t.Fatal("setup: the grinder does not sign its own certificate")
	}

	baseline := foldedIDs(t, w, toAlice, toDave)
	baselineWinner, baselineCost := contestOutcome(t, w, toAlice, toDave, aliceAddr, daveAddr, alice)
	if !baselineCost.IsZero() {
		t.Fatalf("setup: the grinder is out %s, so this measures a cost the real shape does not have",
			baselineCost.String())
	}
	// CONTRIBUTING's anti-vacuity rule, and it doubles as the attacker's own
	// algorithm: grind nonces until the rejected key — the exemplar hash, which
	// is what the id used to be — puts this certificate on the other side of the
	// tie. If no nonce does, the two keys are indistinguishable in this scenario
	// and everything below asserts nothing. Hashing only; the fold does not run
	// in this loop.
	rejectedBaseline := lessByExemplar(toAlice, toDave)
	flipped := byte(0)
	for n := 1; n < 256; n++ {
		if lessByExemplar(resigned(t, w.p, toAlice, alice, byte(n)), toDave) != rejectedBaseline {
			flipped = byte(n)
			break
		}
	}
	if flipped == 0 {
		t.Fatal("no nonce in 255 flipped the order the rejected key would have produced, " +
			"so this scenario cannot tell the two keys apart and asserts nothing")
	}
	t.Logf("the rejected key flips after %d re-signs of the grinder's own signature", flipped)

	// The nonce that flips the rejected key, plus a spread of others, run
	// through the fold. Under the shipped key none of them moves anything.
	for _, nonce := range []byte{flipped, 0xA1, 0xA2, 0xA3, 0xA4, 0xA5, 0xA6, 0xA7, 0xA8} {
		ground := resigned(t, w.p, toAlice, alice, nonce)
		assertSameAuthorization(t, w, toAlice, ground)

		got := foldedIDs(t, w, ground, toDave)
		if len(got) != len(baseline) {
			t.Fatalf("nonce %#x changed how many certificates folded", nonce)
		}
		for i := range got {
			if got[i] != baseline[i] {
				t.Fatalf("nonce %#x moved the fold order: position %d became %x",
					nonce, i, got[i][:8])
			}
		}
		won, cost := contestOutcome(t, w, ground, toDave, aliceAddr, daveAddr, alice)
		if won != baselineWinner {
			t.Fatalf("nonce %#x moved the contested payment to %x, at a cost to the grinder of %s",
				nonce, won[:4], cost.String())
		}
		if !cost.IsZero() {
			t.Fatalf("nonce %#x cost the grinder %s; the zero-cost claim does not hold here",
				nonce, cost.String())
		}
	}
}

// selfInsured builds a certificate whose deposit is the signer's own cell —
// Era 0's only insurance mode — optionally co-signed by others.
func (w *world) selfInsured(t *testing.T, payer *wallet.Key, prog types.Program, seq uint64, cosigners ...*wallet.Key) *types.Certificate {
	t.Helper()
	b := &wallet.Builder{
		Params:  w.p,
		Program: prog,
		Seq:     seq,
		TTL:     w.chain.NextHeight() + 10,
		Deposit: wallet.SelfDeposit(payer.Persistent(), payer.Persistent()),
		FeeBid:  bid(),
		Signers: append([]*wallet.Key{payer}, cosigners...),
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return cert
}

// contestOutcome folds the block without committing it and reports which payee
// the contested amount reached, and what the grind cost the grinder — measured
// across every address the grinder holds, so an outlay cannot hide in a second
// cell of the same key.
func contestOutcome(t *testing.T, w *world, a, b *types.Certificate, left, right types.Address, grinder *wallet.Key) (types.Address, u256.U256) {
	t.Helper()
	blk, err := w.chain.Propose(w.payout, a, b)
	if err != nil {
		t.Fatal(err)
	}
	trial := w.chain.State.Clone()
	before := heldBy(w.chain.State, grinder)
	if _, err := fold.ApplyBlock(trial, blk, w.p); err != nil {
		t.Fatal(err)
	}
	after := heldBy(trial, grinder)

	gotLeft := trial.Get(types.NativeBalanceSlot(left))
	gotRight := trial.Get(types.NativeBalanceSlot(right))
	var winner types.Address
	switch {
	case gotLeft.Lt(gotRight):
		winner = right
	case gotRight.Lt(gotLeft):
		winner = left
	default:
		t.Fatal("neither payee ended ahead: the scenario is not contended and asserts nothing")
	}
	return winner, before.SatSub(after)
}

// heldBy sums the native balance across every address a key controls.
func heldBy(s *state.State, k *wallet.Key) u256.U256 {
	total := u256.Zero
	for _, v := range []byte{crypto.AddrVersionPersistent, crypto.AddrVersionOneShot} {
		total = total.SatAdd(s.Get(types.NativeBalanceSlot(k.Address(v))))
	}
	return total
}

// signs reports whether k contributed a signature to c.
func signs(c *types.Certificate, k *wallet.Key) bool {
	pub := k.PubKey()
	for _, s := range c.Sigs {
		if s.PubKey == pub {
			return true
		}
	}
	return false
}

// paidTo folds the block without committing it and reports which of the two
// candidate payees the contested amount reached.
func paidTo(t *testing.T, w *world, a, b *types.Certificate, left, right types.Address) types.Address {
	t.Helper()
	blk, err := w.chain.Propose(w.payout, a, b)
	if err != nil {
		t.Fatal(err)
	}
	trial := w.chain.State.Clone()
	if _, err := fold.ApplyBlock(trial, blk, w.p); err != nil {
		t.Fatal(err)
	}
	gotLeft := trial.Get(types.NativeBalanceSlot(left))
	gotRight := trial.Get(types.NativeBalanceSlot(right))
	switch {
	case gotLeft.Lt(gotRight):
		return right
	case gotRight.Lt(gotLeft):
		return left
	default:
		t.Fatal("neither payee ended ahead: the scenario is not contended and asserts nothing")
		return types.Address{}
	}
}

// foldedIDs runs the block through the fold without committing it and returns
// the certificate ids in fold order, which is the order Result.Outcomes is in.
//
// It also insists the scenario is genuinely contended — one certificate applies
// and one is skipped — because an ordering test in which both certificates
// apply is measuring nothing: the order would be unobservable in the ledger and
// the assertions below would hold under any tiebreak at all.
func foldedIDs(t *testing.T, w *world, certs ...*types.Certificate) []types.Hash {
	t.Helper()
	b, err := w.chain.Propose(w.payout, certs...)
	if err != nil {
		t.Fatal(err)
	}
	res, err := fold.SealOutcomes(w.chain.State, b, w.p)
	if err != nil {
		t.Fatal(err)
	}
	applied, skipped := 0, 0
	out := make([]types.Hash, len(res.Outcomes))
	for i, o := range res.Outcomes {
		switch o.Outcome {
		case fold.Applied:
			applied++
		case fold.SkippedStale:
			skipped++
		default:
			t.Fatalf("setup: certificate %d was %s", i, o.Outcome)
		}
		out[i] = o.ID
	}
	if applied != 1 || skipped != 1 {
		t.Fatalf("setup: %d applied and %d skipped; the scenario is not contended", applied, skipped)
	}
	return out
}

// lessByExemplar is the ordering the id used to give: the tiebreak keyed on
// the whole encoding, signatures included.
func lessByExemplar(a, b *types.Certificate) bool {
	x, y := a.ExemplarHash(), b.ExemplarHash()
	return bytes.Compare(x[:], y[:]) < 0
}

// sigOf returns the signature a given key contributed to a certificate.
func sigOf(t *testing.T, c *types.Certificate, k *wallet.Key) types.SigBytes {
	t.Helper()
	pub := k.PubKey()
	for _, s := range c.Sigs {
		if s.PubKey == pub {
			return s.Sig
		}
	}
	t.Fatal("the key is not among the signers")
	return types.SigBytes{}
}
