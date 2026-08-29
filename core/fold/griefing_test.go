package fold_test

import (
	"errors"
	"testing"

	"zycord/core/crypto"
	"zycord/core/fold"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/wallet"
)

// The griefing suite.
//
// Every test here plays a malicious block producer trying to make one signature
// pay twice, or to bill a signature at a position its signer could not avoid.
// The suite exists to break the billing law and must fail to. It pins R1-C1,
// R1-C2 and R1-C3, and the poisoning-immunity theorem of §9.
//
// If a change to the fold makes any of these pass, the change is an existential
// economic hole, not a regression.

func mustBeInvalidBlock(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: the block was accepted", what)
	}
	if !errors.Is(err, fold.ErrInvalidBlock) {
		t.Fatalf("%s: got %v, want an invalid-block error", what, err)
	}
}

// TestReplayOfAnAppliedCertificateInvalidatesTheBlock is R1-C1(b): a miner
// re-includes an already-applied certificate. The refunded deposit cell still
// has a balance, so the reservation would succeed and the victim would be
// billed a second time — unless including a seen id is itself invalid.
func TestReplayOfAnAppliedCertificateInvalidatesTheBlock(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	w.fund(alice.Persistent(), drops(900_000_000))

	cert := w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(10_000_000), 0)
	res := w.chain.MustAddBlock(w.payout, cert)
	if res.Outcomes[0].Outcome != fold.Applied {
		t.Fatalf("setup: outcome = %s", res.Outcomes[0].Outcome)
	}

	before := w.chain.Balance(alice.Persistent())
	_, _, err := w.chain.AddBlock(w.payout, cert)
	mustBeInvalidBlock(t, err, "replay of an applied certificate")
	if !w.chain.Balance(alice.Persistent()).Eq(before) {
		t.Fatal("the rejected block moved the victim's balance")
	}
}

// TestReplayOfASkippedCertificateInvalidatesTheBlock is R1-C1(c), the worst of
// the family: a stale-skipped certificate stays includable for its whole TTL
// window, so a miner could bill the same signature once per block. Every billed
// outcome marks the id seen, which closes it.
func TestReplayOfASkippedCertificateInvalidatesTheBlock(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	w.fund(alice.Persistent(), drops(700_000_000))

	half := drops(400_000_000)
	first := w.transfer(alice, alice.Persistent(), bob.Persistent(), half, 0)
	second := w.transfer(alice, alice.Persistent(), bob.Persistent(), half, 1)
	res := w.chain.MustAddBlock(w.payout, first, second)
	if res.Outcomes[1].Outcome != fold.SkippedStale {
		t.Fatalf("setup: second outcome = %s, want SKIPPED_STALE", res.Outcomes[1].Outcome)
	}
	if _, seen := w.chain.State.Seen(second.ID()); !seen {
		t.Fatal("a billed skip did not mark the certificate seen")
	}

	before := w.chain.Balance(alice.Persistent())
	_, _, err := w.chain.AddBlock(w.payout, second)
	mustBeInvalidBlock(t, err, "replay of a skipped certificate")
	if !w.chain.Balance(alice.Persistent()).Eq(before) {
		t.Fatal("the rejected block billed the victim a second time")
	}
}

// TestWithholdingUntilExpiryInvalidatesTheBlock is R1-C1(a): the miner sits on
// a certificate until its TTL passes, then includes it expired to burn the
// skip fee. A signer accepts staleness risk by signing; it never accepts
// miner-manufactured expiry.
func TestWithholdingUntilExpiryInvalidatesTheBlock(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	w.fund(alice.Persistent(), drops(900_000_000))

	cert := w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(10_000_000), 0)
	if err := w.chain.Mine(w.payout, 11); err != nil {
		t.Fatal(err)
	}
	if w.chain.NextHeight() <= cert.TTL {
		t.Fatal("setup: the certificate has not expired yet")
	}

	before := w.chain.Balance(alice.Persistent())
	_, _, err := w.chain.AddBlock(w.payout, cert)
	mustBeInvalidBlock(t, err, "inclusion of an expired certificate")
	if !w.chain.Balance(alice.Persistent()).Eq(before) {
		t.Fatal("an expired certificate was billed")
	}
}

// TestUnboundedTTLInvalidatesTheBlock is R1-H4: a miner self-includes
// certificates whose seen entries would never prune, buying permanent state
// growth for pennies.
func TestUnboundedTTLInvalidatesTheBlock(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	w.fund(alice.Persistent(), drops(900_000_000))

	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), drops(1_000_000)),
		TTL:     ^uint64(0),
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = w.chain.AddBlock(w.payout, cert)
	mustBeInvalidBlock(t, err, "inclusion of an immortal TTL")
}

// TestCapBelowBaseInvalidatesTheBlock is R1-H3: the base fee moved after signing.
// Billing the gap would punish the signer for market motion; silently dropping
// would invite stuffing. The certificate is simply unincludable.
func TestCapBelowBaseInvalidatesTheBlock(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	w.fund(alice.Persistent(), drops(900_000_000))

	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), drops(1_000_000)),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		// A maximum one below the sequential base fee currently in state: B4
		// makes it unincludable however large its priority.
		FeeBid: wallet.Bid(
			w.chain.State.Get(types.SeqBaseFeeSlot()).SatSub(u256.One), u256.Zero,
			drops(500), drops(10)),
		Signers: []*wallet.Key{alice},
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = w.chain.AddBlock(w.payout, cert)
	mustBeInvalidBlock(t, err, "inclusion of a certificate capped below the base fee")
}

// TestDuplicateInOneBlockInvalidatesTheBlock closes the same-block variant of
// replay, which the seen set alone would only catch on the second pass.
func TestDuplicateInOneBlockInvalidatesTheBlock(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	w.fund(alice.Persistent(), drops(900_000_000))

	cert := w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(1_000_000), 0)
	_, _, err := w.chain.AddBlock(w.payout, cert, cert)
	mustBeInvalidBlock(t, err, "the same certificate twice in one block")
}

// TestOneShotDepositRefundsCleanly is R1-C3(i): the deposit cell is the very
// one-shot address the certificate burns. MARK_SPENT applies at F8, settlement
// happens at F9 and is exempt from the registry, and the remainder lands in the
// nominated refund cell rather than being stranded in a burned one.
//
// "Nothing stranded" is the claim the architecture spec makes for this case,
// so the test asserts it of the whole cell and not only of the remainder: the
// certificate burns the address, and every drop the address held must leave
// it in the same certificate. That is what SweepDeposit is for — reserving
// less than the balance would leave the difference under a spent address,
// which is the same silent loss F-FOLD-1 is about, arriving through the
// deposit rather than through the refund.
func TestOneShotDepositRefundsCleanly(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	oneShot := alice.OneShot()
	balance := drops(900_000_000)
	w.fund(oneShot, balance)

	amount := drops(500_000_000)
	// Reserve everything the move does not take. Since both markets charge the
	// full bid, the ceiling is tight and a certificate reserving exactly the
	// ceiling owes exactly the ceiling — leaving no remainder to observe.
	// Over-reserving is what R1-C3-i is about: the remainder must land in the
	// nominated cell rather than the burned one.
	rest, _ := balance.Sub(amount)
	deposit := wallet.SweepDeposit(oneShot, alice.Persistent(), rest)
	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, oneShot, bob.Persistent(), amount),
		TTL:     w.chain.NextHeight() + 5,
		// Refund to the persistent address: refunding into the burned cell
		// would strand the remainder forever.
		Deposit: deposit,
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}

	res := w.chain.MustAddBlock(w.payout, cert)
	out := res.Outcomes[0]
	if out.Outcome != fold.Applied {
		t.Fatalf("outcome = %s, want APPLIED", out.Outcome)
	}
	if !w.chain.State.IsSpent(oneShot) {
		t.Fatal("the one-shot address was debited without being burned")
	}
	if got := w.chain.Balance(alice.Persistent()); !got.Eq(out.Refunded) {
		t.Fatalf("refund landed as %s, want %s", got.String(), out.Refunded.String())
	}
	if out.Refunded.IsZero() {
		t.Fatal("nothing was refunded; the test proves nothing")
	}
	if got := w.chain.Balance(bob.Persistent()); !got.Eq(amount) {
		t.Fatalf("recipient got %s, want %s", got.String(), amount.String())
	}
	if got := w.chain.Balance(oneShot); !got.IsZero() {
		t.Fatalf("%s is stranded under a burned address; the cell must be empty", got.String())
	}
	// And nothing was destroyed on the way: what the address held is now
	// split between the recipient, the refund cell, and the fee.
	total, _ := w.chain.Balance(bob.Persistent()).Add(w.chain.Balance(alice.Persistent()))
	total, _ = total.Add(out.Charged)
	if !total.Eq(balance) {
		t.Fatalf("recipient + refund + fee = %s, want the %s the address held",
			total.String(), balance.String())
	}
}

// TestOneShotDepositFundsAnIssue is F-VAL-5 end to end: a wallet whose funds
// are all under one-shot addresses can issue an asset without first sweeping
// into a persistent address, which is the linkage the one-shot pattern exists
// to avoid (§12). ISSUE has no moves, so its deposit cell can never be a move
// source — the case that had no satisfiable certificate at all before the
// fix.
//
// The deposit sweeps the balance, so the burned address ends the block empty:
// the whole of what it held is either charged as fees or refunded.
func TestOneShotDepositFundsAnIssue(t *testing.T) {
	w := newWorld(t)
	alice := key(t, 2)
	oneShot := alice.OneShot()
	balance := drops(900_000_000)
	w.fund(oneShot, balance)

	cert, err := (&wallet.Builder{
		Params:  w.p,
		Program: wallet.Issue(oneShot, drops(1_000_000), 6, types.Hash{'O', 'N', 'E'}, alice.PubKey()),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SweepDeposit(oneShot, alice.Persistent(), balance),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}).Build()
	if err != nil {
		t.Fatalf("a wallet holding funds only under a one-shot address could not build an ISSUE: %v", err)
	}

	res := w.chain.MustAddBlock(w.payout, cert)
	out := res.Outcomes[0]
	if out.Outcome != fold.Applied {
		t.Fatalf("outcome = %s, want APPLIED", out.Outcome)
	}
	if !w.chain.State.IsSpent(oneShot) {
		t.Fatal("the one-shot deposit cell was debited without being burned")
	}
	if got := w.chain.Balance(oneShot); !got.IsZero() {
		t.Fatalf("%s is stranded under the burned deposit cell", got.String())
	}
	refunded, _ := balance.Sub(out.Charged)
	if got := w.chain.Balance(alice.Persistent()); !got.Eq(refunded) {
		t.Fatalf("refund landed as %s, want %s", got.String(), refunded.String())
	}
}

// TestUnsweptOneShotDepositReturnsTheRest is the scenario that used to be this
// suite's counterfactual, with the opposite expectation.
//
// A one-shot address burns on its first debit (whitepaper §4 — a signature
// from its key moves the cell to spent, permanently), so a deposit that
// reserves less than the cell holds used to leave the difference under an
// address no key could open again, on a certificate reporting APPLIED. The old
// comment said no stateless rule could catch it, which was true and beside the
// point: the fold is not stateless, and F8b moves whatever a burned
// address still holds to the certificate's own refund address instead of
// leaving it there.
//
// wallet.SweepDeposit is still the tidier way to write this certificate — it
// says what it does — but it is no longer the difference between keeping the
// money and losing it.
func TestUnsweptOneShotDepositReturnsTheRest(t *testing.T) {
	w := newWorld(t)
	alice := key(t, 2)
	oneShot := alice.OneShot()
	balance := drops(900_000_000)
	w.fund(oneShot, balance)

	// SelfDeposit leaves the amount to Build's fee-ceiling top-up, so the
	// reservation is the ceiling and the rest of the balance stays put.
	cert, err := (&wallet.Builder{
		Params:  w.p,
		Program: wallet.Issue(oneShot, drops(1_000_000), 6, types.Hash{'O', 'N', 'E'}, alice.PubKey()),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(oneShot, alice.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if !cert.Deposit.Amount.Lt(balance) {
		t.Fatal("the reservation already empties the cell; the test proves nothing")
	}
	unreserved, _ := balance.Sub(cert.Deposit.Amount)

	res := w.chain.MustAddBlock(w.payout, cert)
	out := res.Outcomes[0]
	if out.Outcome != fold.Applied {
		t.Fatalf("outcome = %s, want APPLIED", out.Outcome)
	}
	if !w.chain.State.IsSpent(oneShot) {
		t.Fatal("the deposit cell was debited without being burned")
	}
	if got := w.chain.Balance(oneShot); !got.IsZero() {
		t.Fatalf("%s is stranded under the burned deposit cell", got.String())
	}
	if !out.Swept.Eq(unreserved) {
		t.Fatalf("swept %s, want the %s the reservation did not take",
			out.Swept.String(), unreserved.String())
	}
	// Every drop the address held is now in the refund cell, less the fee.
	want, _ := balance.Sub(out.Charged)
	if got := w.chain.Balance(alice.Persistent()); !got.Eq(want) {
		t.Fatalf("refund cell holds %s, want %s", got.String(), want.String())
	}
}

// TestBurnedRefundIsReported is F-FOLD-1's other half. V5 and V6 now reject
// every certificate that would burn a remainder into an address of its own
// write set, which leaves exactly one way to reach settlement's burn branch:
// a refund target some *earlier* certificate retired (I1-M2). No stateless
// rule can see that, and the fold is right to destroy the remainder rather
// than write it into a cell nobody can read (§6) — but it must not call the
// loss a refund.
func TestBurnedRefundIsReported(t *testing.T) {
	w := newWorld(t)
	payer, stale, bob := key(t, 2), key(t, 4), key(t, 3)
	w.fund(payer.Persistent(), drops(2_000_000_000))
	w.fund(stale.OneShot(), drops(100_000_000))

	retire, err := (&wallet.Builder{
		Params:  w.p,
		Program: wallet.Retire(stale.OneShot()),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(payer.Persistent(), payer.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{payer, stale},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	w.chain.MustAddBlock(w.payout, retire)

	// Signed against a refund address that was alive when it was signed.
	doomed, err := (&wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, payer.Persistent(), bob.Persistent(), drops(1_000_000)),
		Seq:     1,
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(payer.Persistent(), stale.OneShot()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{payer},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}

	before := w.chain.Balance(stale.OneShot())
	res := w.chain.MustAddBlock(w.payout, doomed)
	out := res.Outcomes[0]
	if out.Outcome != fold.Applied {
		t.Fatalf("outcome = %s, want APPLIED", out.Outcome)
	}
	if !out.Refunded.IsZero() {
		t.Fatalf("reported %s refunded; nothing was credited anywhere", out.Refunded.String())
	}
	if out.RefundBurned.IsZero() {
		t.Fatal("the remainder was destroyed and the outcome does not say so")
	}
	want, _ := doomed.Deposit.Amount.Sub(out.Charged)
	if !out.RefundBurned.Eq(want) {
		t.Fatalf("burned refund %s, want %s", out.RefundBurned.String(), want.String())
	}
	if got := w.chain.Balance(stale.OneShot()); !got.Eq(before) {
		t.Fatalf("the burned address's cell moved to %s; nothing may be written there",
			got.String())
	}
}

// TestSpentAddressCannotFundADeposit pins the pruning-determinism rule: a
// reservation is exempt from every guard except its own, but not from the
// registry. Cell values under a spent address may be pruned after the undo
// horizon, so a reservation that could read one would make the fold depend on
// when a node pruned.
func TestSpentAddressCannotFundADeposit(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	oneShot := alice.OneShot()
	w.fund(oneShot, drops(900_000_000))

	w.chain.MustAddBlock(w.payout, w.sweep(alice, oneShot, bob.Persistent(), alice.Persistent(), 0))
	if !w.chain.State.IsSpent(oneShot) {
		t.Fatal("setup: the address was not burned")
	}

	// The leftover is placed by hand, and that is the point rather than a
	// shortcut. Since F7b no rule can *produce* native drops under a
	// burned address — the burn itself requires the cell to be empty, F7 fails
	// every write under a spent address, and settlement and the maturity ring
	// burn what they owe one. F3's registry check is therefore about pruning
	// determinism and nothing else: cell values under a spent address may be
	// deleted after the undo horizon, so a reservation that could read one
	// would make the fold depend on when a node pruned. This constructs the
	// state that check exists for, because the rules will no longer hand it
	// over.
	w.chain.State.Set(types.NativeBalanceSlot(oneShot), drops(900_000_000))

	// A second certificate depositing from the burned address must drop, not
	// skip: nothing was reserved, so there is nothing to bill.
	again := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, oneShot, bob.Persistent(), drops(1_000_000)),
		Seq:     1,
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(oneShot, alice.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}
	cert2, err := again.Build()
	if err != nil {
		t.Fatal(err)
	}
	res := w.chain.MustAddBlock(w.payout, cert2)
	if res.Outcomes[0].Outcome != fold.Dropped {
		t.Fatalf("outcome = %s, want DROPPED", res.Outcomes[0].Outcome)
	}
	if !res.Outcomes[0].Charged.IsZero() {
		t.Fatal("a burned address was billed")
	}
}

// TestCreditStormCausesNoBilledSkips is the poisoning-immunity theorem under
// load: many third parties credit a cell that a pending transfer guards, and
// not one of them can make it skip.
func TestCreditStormCausesNoBilledSkips(t *testing.T) {
	// Both cell kinds, and the second one is the point. The original test
	// stormed a *persistent* victim, where a credit cannot reach any rule that
	// decides an outcome — so it was structurally incapable of observing the
	// first design of the burn-scope fix, which refused to burn an address
	// whose cell was not empty and therefore let any of these stormers bill
	// the victim. A test named for the poisoning-immunity theorem has to storm
	// the cell kind the theorem's one carve-out lives on.
	for _, tc := range []struct {
		name                        string
		victimIsOneShot, stormFirst bool
	}{
		{"persistent victim", false, false},
		{"one-shot victim, storm in the same block", true, false},
		// The armed one. In the same block the victim's sweep sorts *first* —
		// F1 orders by underwriter address and a 0x01 underwriter precedes
		// every 0x02 one — so a storm of persistent stormers can never be
		// evaluated before it, whatever the rule under test. Only a credit
		// that has already committed can reach a rule that reads the cell,
		// which is why this case exists and why the same-block one alone would
		// leave the storm testing the fold's sort rather than its rules.
		{"one-shot victim, storm in a prior block", true, true},
	} {
		victimIsOneShot := tc.victimIsOneShot
		t.Run(tc.name, func(t *testing.T) {
			w := newWorld(t)
			alice, carol := key(t, 2), key(t, 4)
			src := alice.Persistent()
			if victimIsOneShot {
				src = alice.OneShot()
			}
			w.fund(src, drops(900_000_000))

			var pending *types.Certificate
			if victimIsOneShot {
				pending = w.sweep(alice, src, carol.Persistent(), alice.Persistent(), 0)
			} else {
				pending = w.transfer(alice, src, carol.Persistent(), drops(100_000_000), 0)
			}

			const stormers = 8
			storm := make([]*types.Certificate, stormers)
			for i := 0; i < stormers; i++ {
				k := key(t, byte(40+i))
				w.fund(k.Persistent(), drops(500_000_000))
				storm[i] = w.transfer(k, k.Persistent(), src, drops(1_000_000), 0)
			}
			block := append(storm, pending)
			if tc.stormFirst {
				w.chain.MustAddBlock(w.payout, storm...)
				block = []*types.Certificate{pending}
			}
			res := w.chain.MustAddBlock(w.payout, block...)

			for _, o := range res.Outcomes {
				if o.Outcome == fold.Applied {
					continue
				}
				// The victim is what this test is about, and nothing the storm
				// does may bill it.
				if o.ID == pending.ID() {
					t.Fatalf("the victim was %s in a credit storm; every billed skip in "+
						"Era 0 must be self-inflicted", o.Outcome)
				}
				// A *stormer* may be billed, and with a one-shot victim exactly
				// one of them is: the victim's sweep sorts first (a 0x01
				// underwriter precedes every 0x02 one) and burns the address
				// the stormers are paying, so their credit fails at F7. That is
				// case (3) of the theorem — destination burn — and it is the
				// carve-out this file exists to bound, not a new one. It is
				// also the whole content of wallet rule 3.
				if !victimIsOneShot || tc.stormFirst {
					t.Fatalf("a stormer was %s though the destination was alive when it "+
						"committed; nothing can be billed here", o.Outcome)
				}
				if !w.chain.State.IsSpent(src) {
					t.Fatalf("a stormer was %s and the destination is not burned; "+
						"the bill is outside case (3)", o.Outcome)
				}
			}
			if victimIsOneShot {
				if !w.chain.State.IsSpent(src) {
					t.Fatal("the sweep applied and the address was not burned")
				}
				if got := w.chain.Balance(src); !got.IsZero() {
					t.Fatalf("%s of the storm is stranded under the burned address", got.String())
				}
			}
		})
	}
}

// TestMintCapRaceBillsOnlyWillingMinters: two mints that each fit under the cap
// but together exceed it. The loser is billed — but it is a certificate the
// minter signed, racing against a certificate the same minter signed. No third
// party is involved and none could be.
func TestMintCapRaceBillsOnlyWillingMinters(t *testing.T) {
	w := newWorld(t)
	issuer := key(t, 5)
	holder := key(t, 6)
	w.fund(issuer.Persistent(), drops(3_000_000_000))

	const issueSeq = 0
	cap := drops(1_000)
	asset := types.DeriveAssetAddress(w.p.ChainID, issuer.Persistent(), issueSeq)

	issue := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Issue(issuer.Persistent(), cap, 2, types.Hash{'C', 'A', 'P'}, issuer.PubKey()),
		Seq:     issueSeq,
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(issuer.Persistent(), issuer.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{issuer},
	}
	issueCert, err := issue.Build()
	if err != nil {
		t.Fatal(err)
	}
	if res := w.chain.MustAddBlock(w.payout, issueCert); res.Outcomes[0].Outcome != fold.Applied {
		t.Fatalf("issue was %s", res.Outcomes[0].Outcome)
	}
	if got := w.chain.State.Get(types.AssetCapSlot(asset)); !got.Eq(cap) {
		t.Fatalf("asset cap cell = %s, want %s", got.String(), cap.String())
	}

	mint := func(seq uint64, amount u256.U256) *types.Certificate {
		b := &wallet.Builder{
			Params:  w.p,
			Program: wallet.Mint(asset, holder.Persistent(), amount, cap, issuer.PubKey()),
			Seq:     seq,
			TTL:     w.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(issuer.Persistent(), issuer.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{issuer},
		}
		c, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	a := mint(1, drops(600))
	b := mint(2, drops(600))
	res := w.chain.MustAddBlock(w.payout, a, b)

	if res.Outcomes[0].Outcome != fold.Applied {
		t.Fatalf("first mint = %s, want APPLIED", res.Outcomes[0].Outcome)
	}
	if res.Outcomes[1].Outcome != fold.SkippedStale {
		t.Fatalf("second mint = %s, want SKIPPED_STALE at the cap", res.Outcomes[1].Outcome)
	}
	if got := w.chain.AssetBalance(holder.Persistent(), asset); !got.Eq(drops(600)) {
		t.Fatalf("holder balance = %s, want 600", got.String())
	}
	if got := w.chain.State.Get(types.AssetMintedSlot(asset)); got.Gt(cap) {
		t.Fatalf("minted %s exceeds the cap %s", got.String(), cap.String())
	}
}

// TestConcurrentMintsCannotBreachTheCap: many mints in one block, each valid on
// its own, must sum to at most the cap. Guarded deltas hold under unlimited
// concurrency; that is the whole point of the discipline.
func TestConcurrentMintsCannotBreachTheCap(t *testing.T) {
	w := newWorld(t)
	issuer, holder := key(t, 5), key(t, 6)
	// Enough for the issue plus six mints and their deposits, with room to
	// spare, and inside a single matured coinbase — deposits are reserved and
	// refunded within one fold step, so they never stack.
	w.fund(issuer.Persistent(), drops(1_000_000_000))

	cap := drops(1_000)
	asset := types.DeriveAssetAddress(w.p.ChainID, issuer.Persistent(), 0)
	issue := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Issue(issuer.Persistent(), cap, 0, types.Hash{}, issuer.PubKey()),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(issuer.Persistent(), issuer.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{issuer},
	}
	issueCert, err := issue.Build()
	if err != nil {
		t.Fatal(err)
	}
	w.chain.MustAddBlock(w.payout, issueCert)

	const mints = 6
	certs := make([]*types.Certificate, mints)
	for i := 0; i < mints; i++ {
		b := &wallet.Builder{
			Params:  w.p,
			Program: wallet.Mint(asset, holder.Persistent(), drops(300), cap, issuer.PubKey()),
			Seq:     uint64(i + 1),
			TTL:     w.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(issuer.Persistent(), issuer.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{issuer},
		}
		c, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		certs[i] = c
	}
	w.chain.MustAddBlock(w.payout, certs...)

	minted := w.chain.State.Get(types.AssetMintedSlot(asset))
	if minted.Gt(cap) {
		t.Fatalf("minted %s breached the cap of %s under concurrency", minted.String(), cap.String())
	}
	if !minted.Eq(drops(900)) {
		t.Fatalf("minted %s, want the largest multiple of 300 below the cap", minted.String())
	}
}

// TestReorgBillsExactlyOnce: a certificate applied on an abandoned branch is
// undone completely — balance, seen entry and registry alike — and may be
// re-included on the new branch, where it is billed once. Never twice, never
// zero times.
func TestReorgBillsExactlyOnce(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	w.fund(alice.Persistent(), drops(900_000_000))

	before := w.chain.Balance(alice.Persistent())
	beforeRoot := w.chain.State.Root()

	cert := w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(10_000_000), 0)
	res := w.chain.MustAddBlock(w.payout, cert)
	afterOnce := w.chain.Balance(alice.Persistent())
	if res.Outcomes[0].Outcome != fold.Applied {
		t.Fatalf("setup: outcome = %s", res.Outcomes[0].Outcome)
	}

	if err := w.chain.Rollback(); err != nil {
		t.Fatal(err)
	}
	if _, seen := w.chain.State.Seen(cert.ID()); seen {
		t.Fatal("undo left the certificate marked seen; it can never be re-included")
	}
	if !w.chain.Balance(alice.Persistent()).Eq(before) {
		t.Fatal("undo did not restore the balance")
	}
	if w.chain.State.Root() != beforeRoot {
		t.Fatal("undo did not restore the state exactly")
	}

	// Re-include on the new branch: one bill in total, not two.
	w.chain.MustAddBlock(w.payout, cert)
	if got := w.chain.Balance(alice.Persistent()); !got.Eq(afterOnce) {
		t.Fatalf("balance after reorg + re-inclusion = %s, want %s", got.String(), afterOnce.String())
	}
}

// TestRetireBurnsWithoutSpending: RETIRE is state compaction and privacy
// hygiene. It moves no value and needs no counterparty.
func TestRetireBurnsWithoutSpending(t *testing.T) {
	w := newWorld(t)
	alice := key(t, 2)
	spare := key(t, 7).OneShot()
	w.fund(alice.Persistent(), drops(900_000_000))

	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Retire(spare, alice.OneShot()),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice, key(t, 7)},
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	res := w.chain.MustAddBlock(w.payout, cert)
	if res.Outcomes[0].Outcome != fold.Applied {
		t.Fatalf("outcome = %s, want APPLIED", res.Outcomes[0].Outcome)
	}
	for _, a := range []types.Address{spare, alice.OneShot()} {
		if !w.chain.State.IsSpent(a) {
			t.Fatalf("address %x was not retired", a[:4])
		}
	}
}

// TestProtocolCellsAreUnreachable is V7 and F13: there is no code path by which
// a certificate can write a protocol cell, so no certificate can mint, rewrite
// the beacon, or move the fee market.
func TestProtocolCellsAreUnreachable(t *testing.T) {
	w := newWorld(t)
	alice := key(t, 2)
	w.fund(alice.Persistent(), drops(900_000_000))

	// The protocol address is not a user address, so a transfer naming it is
	// rejected at derivation — the write set that would reach the fold cannot
	// be constructed in the first place.
	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, alice.Persistent(), crypto.ProtocolAddress, drops(1)),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}
	if _, err := b.Build(); err == nil {
		t.Fatal("a certificate naming the protocol address was built")
	}
}

// TestWriteToABurnedAddressSkipsStale pins the one exception to the
// poisoning-immunity theorem (I1-H3), so that its exact scope is a test rather
// than a footnote.
//
// A payee who retires a one-shot address after handing it out bills the payer a
// skip fee. The behaviour is deliberate: the permanent registry exists so that
// a payment to a dead address is loud rather than silently burned (R1-C3-iii),
// and a loud failure at commit is a billed skip. The window is empty under the
// default wallet pattern — one-shot addresses are generated fresh per payment
// received — and the fee is burned rather than paid to anyone, so nobody
// profits. If this test ever reports SKIPPED_OVERFLOW or a second exception
// appears, the theorem's statement is wrong and must be restated again.
func TestWriteToABurnedAddressSkipsStale(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	w.fund(alice.Persistent(), drops(2_000_000_000))

	// Alice signs a payment to a one-shot address of Bob's.
	target := bob.OneShot()
	pending := w.transfer(alice, alice.Persistent(), target, drops(10_000_000), 0)

	// Bob retires it before her certificate commits.
	w.fund(bob.Persistent(), drops(900_000_000))
	retire := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Retire(target),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(bob.Persistent(), bob.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{bob},
	}
	retireCert, err := retire.Build()
	if err != nil {
		t.Fatal(err)
	}
	w.chain.MustAddBlock(w.payout, retireCert)
	if !w.chain.State.IsSpent(target) {
		t.Fatal("setup: the address was not retired")
	}

	res := w.chain.MustAddBlock(w.payout, pending)
	if got := res.Outcomes[0].Outcome; got != fold.SkippedStale {
		t.Fatalf("outcome = %s, want SKIPPED_STALE: a write to a burned address "+
			"is a staleness failure, not an arithmetic one", got)
	}
	if !res.Outcomes[0].Charged.Eq(w.p.SkipFee) {
		t.Fatalf("charged %s, want the constant skip fee", res.Outcomes[0].Charged.String())
	}
	// The value did not move: a payment to a dead address fails loudly instead
	// of being silently burned.
	if !w.chain.Balance(target).IsZero() {
		t.Fatal("value landed under a burned address")
	}
}

// TestUnderstatedBalanceReturnsTheRemainder is the understated-sweep case, and
// it is the test that was said would fail by name whichever way that trade was
// decided. F8b decided it, and this is the new expectation.
//
// The scenario is unchanged: a wallet is told the one-shot cell holds less than
// it does, and sizes a full sweep against that number. The certificate it
// builds is well formed and passes every wallet policy check, because the
// wallet's view *is* the lie — that tautology is the finding's own and it is
// reproduced here rather than asserted.
//
// What changed is the fold. The debit's read is still AccessGuardGE ("this
// cell holds at least what I am taking"), which an understated figure
// satisfies by construction, and no read was added: V3 requires declared reads
// to equal what derivation returns, so a read could never have covered the
// deposit cell anyway. Instead F8b moves what the burn would have stranded to
// the certificate's own refund address. The lie costs the victim nothing at
// all — not even a skip fee — because the difference lands in a cell they
// control.
//
// The trade was measured as unavoidable: protecting the understated sweep
// meant skipping when an honest credit landed mid-sweep, because the two are
// the same event to the fold. That is true of any rule whose *verdict* reads
// the balance. It is false of one that only changes what the certificate
// moves, which is why this costs nothing on the honest path — see
// TestDustBeforeASweepCostsTheVictimNothing and
// docs/decisions/one-shot-burn-scope.md.
func TestUnderstatedBalanceReturnsTheRemainder(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	oneShot := alice.OneShot()

	// What the cell really holds, and what a lying, stale, or losing-fork
	// node reports instead. The gap is what gets destroyed.
	held := drops(900_000_000)
	understated := drops(300_000_000)
	w.fund(oneShot, held)

	// The wallet's own sweep arithmetic, run against the number it was given:
	// probe once for the ceiling, then send everything the reservation does
	// not take. This is cmd/zcd's sweep path, not an invented shape.
	probe := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, oneShot, bob.Persistent(), u256.One),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(oneShot, alice.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}
	probed, err := probe.Build()
	if err != nil {
		t.Fatal(err)
	}
	ceiling, ok := probed.FeeCeiling(w.p)
	if !ok {
		t.Fatal("fee ceiling overflows")
	}
	amount := understated.SatSub(ceiling)
	if amount.IsZero() {
		t.Fatal("the understated balance does not exceed the ceiling; the test proves nothing")
	}

	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, oneShot, bob.Persistent(), amount),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(oneShot, alice.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}

	// The wallet's own view is the lie, so its checks pass: that tautology is
	// reproduced rather than asserted.
	//
	// The owned set is passed rather than omitted, and that is the point of
	// the assertion. CheckBurnedResidualComesHome is the one rule here
	// that does not read a balance, so it is the one rule a lying node cannot
	// talk round — and it is vacuous when the caller names no addresses. Alice
	// refunds to her own persistent cell, so it passes on the merits; a caller
	// that dropped the set would get the same green from a check that never
	// ran, which is exactly the shape of tautology this test exists to expose.
	view := state.New()
	view.Set(types.NativeBalanceSlot(oneShot), understated)
	owned := []types.Address{alice.OneShot(), alice.Persistent()}
	if err := wallet.CheckAll(cert, view, w.p, owned); err != nil {
		t.Fatalf("the wallet refused its own understated view, so the tautology is gone: %v", err)
	}

	// The debit's read is a lower bound, which is why nothing catches this.
	var guard *types.Read
	for i := range cert.Reads {
		if cert.Reads[i].Slot == types.NativeBalanceSlot(oneShot) {
			guard = &cert.Reads[i]
		}
	}
	if guard == nil {
		t.Fatal("no read against the source cell at all")
	}
	if guard.Access != types.AccessGuardGE {
		t.Fatalf("source read is access %d, want AccessGuardGE (%d) — the burn-scope fix is "+
			"a commit-time effect, not a read; if the derived read moved, re-derive what "+
			"the chain now catches and update docs/WALLET.md rule 1",
			guard.Access, types.AccessGuardGE)
	}

	res := w.chain.MustAddBlock(w.payout, cert)
	out := res.Outcomes[0]
	if out.Outcome != fold.Applied {
		t.Fatalf("outcome = %s, want APPLIED: a lying node must not be able to change a "+
			"verdict either", out.Outcome)
	}
	if !w.chain.State.IsSpent(oneShot) {
		t.Fatal("the one-shot address was debited without being burned")
	}

	// The measured recovery. What the node hid is exactly what F8b moved out.
	want, _ := held.Sub(understated)
	if !out.Swept.Eq(want) {
		t.Fatalf("swept %s, want exactly the understatement %s",
			out.Swept.String(), want.String())
	}
	if !out.SweptStranded.IsZero() {
		t.Fatalf("%s of the remainder was destroyed", out.SweptStranded.String())
	}
	if got := w.chain.Balance(oneShot); !got.IsZero() {
		t.Fatalf("the burned address still reads %s", got.String())
	}

	// Nothing was destroyed: everything the cell held reached the payee, the
	// refund cell, or the fee.
	reached := w.chain.Balance(bob.Persistent())
	reached = reached.SatAdd(w.chain.Balance(alice.Persistent()))
	reached = reached.SatAdd(out.Charged)
	if !reached.Eq(held) {
		t.Fatalf("payee + refund + fee = %s, want the %s the address held",
			reached.String(), held.String())
	}
}
