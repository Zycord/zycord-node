package fold_test

import (
	"testing"

	"zycord/core/fold"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/wallet"
)

// The one-shot burn scope suite.
//
// A one-shot burn is address-scoped: MARK_SPENT names SpentSlot(addr), and
// after it lands every read and write under the address fails forever
// (whitepaper §4). Every guard Era 0 derives is slot-scoped and a lower bound:
// deriveTransfer emits GUARD_GE on BalanceSlot(src, asset), and the deposit
// cell carries no read at all. The two scopes do not meet, so a certificate
// could burn an address while accounting for only part of what was under it —
// value destroyed in silence with nothing in the fold failing, which is what
// the staging step of whitepaper §3 exists to prevent.
//
// F8b closes it as an *effect* rather than as a verdict: whatever a burned
// address still holds in a cell the fold can name leaves with the certificate,
// to Deposit.RefundTo. Refusing the burn instead would have made the verdict a
// function of a balance any stranger can raise, which is the fourth
// attribution case whitepaper §5 forbids — see
// TestLemmaNoUnsignedCreditChangesAnOutcome and
// docs/decisions/one-shot-burn-scope.md.
//
// The invariant these tests pin:
//
//	a certificate that burns a one-shot address strands nothing the fold can
//	name — its native balance cell, and every cell under it the certificate
//	itself names.
func TestBurningAnAddressStrandsNothingItCanName(t *testing.T) {
	// Route 1 — a moveless program funded by a one-shot deposit cell that
	// reserves only the fee ceiling. ISSUE has no moves at all, so before F8b
	// the reservation was the only thing that could empty the cell.
	t.Run("moveless program with an unswept one-shot deposit", func(t *testing.T) {
		w := newWorld(t)
		alice := key(t, 2)
		oneShot := alice.OneShot()
		held := drops(900_000_000)
		w.fund(oneShot, held)

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
		if !cert.Deposit.Amount.Lt(held) {
			t.Fatal("the reservation already empties the cell; the route is not armed")
		}
		assertBurnStrandsNothing(t, w, cert, oneShot, alice.Persistent(), held)
	})

	// Route 2 — a TRANSFER whose one-shot deposit cell is not a move source.
	// withDepositMarkSpent burns the cell; derivation guards only move sources.
	t.Run("transfer whose one-shot deposit cell is not a move source", func(t *testing.T) {
		w := newWorld(t)
		alice, bob := key(t, 2), key(t, 3)
		oneShot := alice.OneShot()
		held := drops(900_000_000)
		w.fund(oneShot, held)
		w.fund(alice.Persistent(), drops(500_000_000))

		cert, err := (&wallet.Builder{
			Params: w.p,
			Program: wallet.Tip(types.NativeAsset, alice.Persistent(),
				bob.Persistent(), drops(10_000_000)),
			TTL:     w.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(oneShot, alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}).Build()
		if err != nil {
			t.Fatal(err)
		}
		for _, wr := range cert.Writes {
			if wr.Op == types.OpDeltaSub && wr.Slot.Addr == oneShot {
				t.Fatal("the deposit cell is a move source; the route is not armed")
			}
		}
		// The refund address is credited by the moves too, so the arithmetic
		// is checked against the whole block rather than one cell.
		assertBurnStrandsNothingLoose(t, w, cert, oneShot)
	})

	// Route 4, the understated-balance route — a sweep sized against a balance a
	// single unaudited node understated. GUARD_GE is satisfied by any figure
	// at or below the truth, so the certificate applies; before F8b the
	// difference was stranded under the burned address.
	t.Run("sweep sized against an understated balance", func(t *testing.T) {
		w := newWorld(t)
		alice, bob := key(t, 2), key(t, 3)
		oneShot := alice.OneShot()
		held := drops(900_000_000)
		understated := drops(300_000_000)
		w.fund(oneShot, held)

		probe, err := (&wallet.Builder{
			Params:  w.p,
			Program: wallet.Tip(types.NativeAsset, oneShot, bob.Persistent(), u256.One),
			TTL:     w.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(oneShot, alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}).Build()
		if err != nil {
			t.Fatal(err)
		}
		ceiling, ok := probe.FeeCeiling(w.p)
		if !ok {
			t.Fatal("fee ceiling overflows")
		}
		amount := understated.SatSub(ceiling)
		if amount.IsZero() {
			t.Fatal("the understated balance does not clear the ceiling")
		}
		cert, err := (&wallet.Builder{
			Params:  w.p,
			Program: wallet.Tip(types.NativeAsset, oneShot, bob.Persistent(), amount),
			TTL:     w.chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(oneShot, alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}).Build()
		if err != nil {
			t.Fatal(err)
		}
		assertBurnStrandsNothingLoose(t, w, cert, oneShot)
	})

	// RETIRE — the same loss with no debit anywhere in the certificate. The
	// target is burned by a write whose whole purpose is to burn it.
	t.Run("retire of an address that still holds a balance", func(t *testing.T) {
		w := newWorld(t)
		payer, stale := key(t, 2), key(t, 4)
		w.fund(payer.Persistent(), drops(2_000_000_000))
		held := drops(100_000_000)
		w.fund(stale.OneShot(), held)

		cert, err := (&wallet.Builder{
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
		before := w.chain.Balance(payer.Persistent())
		res := w.chain.MustAddBlock(w.payout, cert)
		out := res.Outcomes[0]
		if out.Outcome != fold.Applied {
			t.Fatalf("outcome = %s, want APPLIED: RETIRE is an unconditional pure "+
				"write (whitepaper §11) and must not become state-conditional", out.Outcome)
		}
		if !w.chain.State.IsSpent(stale.OneShot()) {
			t.Fatal("the retire applied and the address was not burned")
		}
		if got := w.chain.Balance(stale.OneShot()); !got.IsZero() {
			t.Fatalf("%s left under the retired address", got.String())
		}
		if !out.Swept.Eq(held) {
			t.Fatalf("swept %s, want the %s the address held", out.Swept.String(), held.String())
		}
		// The retired address's balance reached the refund address, on top of
		// the deposit remainder settlement credits there.
		want := before.SatSub(cert.Deposit.Amount).SatAdd(out.Refunded).SatAdd(held)
		if got := w.chain.Balance(payer.Persistent()); !got.Eq(want) {
			t.Fatalf("refund address holds %s, want %s", got.String(), want.String())
		}
	})
}

// assertBurnStrandsNothing checks the whole arithmetic for the case where the
// refund address is credited by nothing but settlement and the sweep.
func assertBurnStrandsNothing(t *testing.T, w *world, cert *types.Certificate,
	burned, refundTo types.Address, held u256.U256) {
	t.Helper()
	before := w.chain.Balance(refundTo)
	res := w.chain.MustAddBlock(w.payout, cert)
	out := res.Outcomes[0]
	if out.Outcome != fold.Applied {
		t.Fatalf("outcome = %s, want APPLIED", out.Outcome)
	}
	assertBurnedAndEmpty(t, w, burned)

	// Everything the address held is now either the fee or in the refund cell.
	got := w.chain.Balance(refundTo)
	if !got.Eq(before.SatAdd(held).SatSub(out.Charged)) {
		t.Fatalf("refund cell holds %s, want %s + %s - %s",
			got.String(), before.String(), held.String(), out.Charged.String())
	}
	if out.Swept.IsZero() {
		t.Fatal("nothing was swept; the route is not armed")
	}
	if !out.SweptStranded.IsZero() {
		t.Fatalf("%s of the residual was left behind", out.SweptStranded.String())
	}
}

// assertBurnStrandsNothingLoose is the same property where the block moves
// value to the refund address by other routes as well: the address burns, its
// cell is empty, and the outcome reports a non-zero sweep that was delivered
// rather than destroyed.
func assertBurnStrandsNothingLoose(t *testing.T, w *world, cert *types.Certificate,
	burned types.Address) {
	t.Helper()
	res := w.chain.MustAddBlock(w.payout, cert)
	out := res.Outcomes[0]
	if out.Outcome != fold.Applied {
		t.Fatalf("outcome = %s, want APPLIED", out.Outcome)
	}
	assertBurnedAndEmpty(t, w, burned)
	if out.Swept.IsZero() {
		t.Fatal("nothing was swept; the route is not armed")
	}
	if !out.SweptStranded.IsZero() {
		t.Fatalf("%s of the residual was left behind", out.SweptStranded.String())
	}
}

func assertBurnedAndEmpty(t *testing.T, w *world, burned types.Address) {
	t.Helper()
	if !w.chain.State.IsSpent(burned) {
		t.Fatal("the certificate applied and the address was not burned")
	}
	if got := w.chain.Balance(burned); !got.IsZero() {
		t.Fatalf("%s is stranded under a burned address; the certificate destroyed "+
			"value it never accounted for", got.String())
	}
}

// TestPartialAssetSweepStrandsNothingItNames is the second family of cell F8b
// covers, and it exists because deleting that half of the rule left the whole
// suite green once already.
//
// A TRANSFER moves *part* of an asset balance out of a one-shot address whose
// native cell the reservation empties. The native half of the rule is
// satisfied, the address burns, and before F8b the rest of the asset balance
// stayed under it forever. It is the only case that reaches the "every cell
// this certificate names" clause, so it is the only thing that can fail if
// that clause is removed.
func TestPartialAssetSweepStrandsNothingItNames(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	oneShot := alice.OneShot()
	w.fund(alice.Persistent(), drops(4_000_000_000))
	asset := w.issueAsset(alice, 0)

	// Move the asset to the one-shot cell, and fund it with drops.
	held := drops(500_000)
	w.chain.MustAddBlock(w.payout, w.assetTip(alice, alice.Persistent(), oneShot, asset, held))
	w.fund(oneShot, drops(900_000_000))
	if got := w.chain.AssetBalance(oneShot, asset); !got.Eq(held) {
		t.Fatalf("setup: the cell holds %s of the asset, want %s", got.String(), held.String())
	}

	// A certificate that moves only *part* of the asset out, and empties the
	// native cell through the reservation.
	part := drops(100_000)
	balance := w.chain.Balance(oneShot)
	cert, err := (&wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(asset, oneShot, bob.Persistent(), part),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SweepDeposit(oneShot, alice.Persistent(), balance),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}

	beforeRefund := w.chain.AssetBalance(alice.Persistent(), asset)
	res := w.chain.MustAddBlock(w.payout, cert)
	out := res.Outcomes[0]
	if out.Outcome != fold.Applied {
		t.Fatalf("outcome = %s, want APPLIED", out.Outcome)
	}
	if !w.chain.State.IsSpent(oneShot) {
		t.Fatal("the asset debit did not burn the one-shot source")
	}
	if got := w.chain.Balance(oneShot); !got.IsZero() {
		t.Fatalf("%s of drops left under the burned address", got.String())
	}
	remainder, _ := held.Sub(part)
	if got := w.chain.AssetBalance(oneShot, asset); !got.IsZero() {
		t.Fatalf("%s of the asset is stranded under the burned address, want 0 — the "+
			"'every cell this certificate names' half of F8b is missing", got.String())
	}
	if got := w.chain.AssetBalance(alice.Persistent(), asset); !got.Eq(beforeRefund.SatAdd(remainder)) {
		t.Fatalf("refund address holds %s of the asset, want %s",
			got.String(), beforeRefund.SatAdd(remainder).String())
	}
	if got := w.chain.AssetBalance(bob.Persistent(), asset); !got.Eq(part) {
		t.Fatalf("payee got %s, want %s", got.String(), part.String())
	}
}

// TestForeignAssetsUnderABurnedAddressAreStillLost is the deliberate limit of
// the rule, pinned so that it is a decision rather than an oversight.
//
// A balance in an asset the certificate never names is not reachable by any
// rule the fold can afford: BalanceWord is a hash of the asset id, so the set
// of assets under an address is not derivable from a slot, and core/state has
// no per-address cell index a burn could consult without a scan.
//
// So the loss stays, and the answer stays docs/WALLET.md rule 1: name every
// asset in the certificate that burns the address.
func TestForeignAssetsUnderABurnedAddressAreStillLost(t *testing.T) {
	w := newWorld(t)
	alice := key(t, 2)
	oneShot := alice.OneShot()
	w.fund(alice.Persistent(), drops(4_000_000_000))
	asset := w.issueAsset(alice, 0)
	w.chain.MustAddBlock(w.payout,
		w.assetTip(alice, alice.Persistent(), oneShot, asset, drops(500_000)))
	w.fund(oneShot, drops(900_000_000))

	balance := w.chain.Balance(oneShot)
	cert, err := (&wallet.Builder{
		Params: w.p,
		Program: wallet.Issue(oneShot, drops(1_000_000), 6,
			types.Hash{'T', 'W', 'O'}, alice.PubKey()),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SweepDeposit(oneShot, alice.Persistent(), balance),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	res := w.chain.MustAddBlock(w.payout, cert)
	if res.Outcomes[0].Outcome != fold.Applied {
		t.Fatalf("outcome = %s, want APPLIED", res.Outcomes[0].Outcome)
	}
	if !w.chain.State.IsSpent(oneShot) {
		t.Fatal("the deposit cell was debited without being burned")
	}
	if w.chain.Balance(oneShot).IsZero() != true {
		t.Fatal("drops left under the burned address")
	}
	if w.chain.AssetBalance(oneShot, asset).IsZero() {
		t.Fatal("the asset balance is gone; this test documents that it is NOT")
	}
}

// TestDustBeforeASweepCostsTheVictimNothing is what replaced the dust-griefing
// scenario.
//
// That trade was measured as unavoidable: any rule that protects an
// understated sweep must also skip when an honest credit lands mid-sweep,
// because the two are the same event to the fold. That is true of any rule
// whose *verdict* reads the balance, and false of one that only changes what
// the certificate moves. Under F8b the dust is not a grief at all — it is a
// gift, delivered to the victim's own refund address.
func TestDustBeforeASweepCostsTheVictimNothing(t *testing.T) {
	w := newWorld(t)
	alice, bob, griefer := key(t, 2), key(t, 3), key(t, 7)
	oneShot := alice.OneShot()
	held := drops(900_000_000)
	w.fund(oneShot, held)
	w.fund(griefer.Persistent(), drops(2_000_000_000))

	cert := w.sweep(alice, oneShot, bob.Persistent(), alice.Persistent(), 0)

	// A griefer with no reason to tip: F1 orders by underwriter, never by fee.
	cheap := wallet.Bid(drops(50_000), u256.Zero, drops(500), u256.Zero)
	dust, err := (&wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, griefer.Persistent(), oneShot, u256.One),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(griefer.Persistent(), griefer.Persistent()),
		FeeBid:  cheap,
		Signers: []*wallet.Key{griefer},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	dustRes := w.chain.MustAddBlock(w.payout, dust)
	if dustRes.Outcomes[0].Outcome != fold.Applied {
		t.Fatalf("the dust was %s; the grief never landed", dustRes.Outcomes[0].Outcome)
	}

	beforeRefund := w.chain.Balance(alice.Persistent())
	res := w.chain.MustAddBlock(w.payout, cert)
	out := res.Outcomes[0]
	if out.Outcome != fold.Applied {
		t.Fatalf("outcome = %s, want APPLIED: a stranger's credit must not change a "+
			"verdict (whitepaper §5)", out.Outcome)
	}
	assertBurnedAndEmpty(t, w, oneShot)
	if out.Swept.IsZero() {
		t.Fatal("nothing was swept; the dust was not in the cell")
	}
	// The drop reached the victim, and the victim paid an ordinary applied fee
	// rather than a skip fee.
	if out.Charged.Eq(w.p.SkipFee) {
		t.Fatal("the victim was charged the skip fee")
	}
	after := w.chain.Balance(alice.Persistent())
	if !after.Eq(beforeRefund.SatAdd(out.Refunded).SatAdd(out.Swept)) {
		t.Fatalf("refund cell holds %s, want %s + %s refunded + %s swept",
			after.String(), beforeRefund.String(), out.Refunded.String(), out.Swept.String())
	}
	t.Logf("griefer paid %s to hand the victim %s; victim outcome %s, nothing stranded",
		dustRes.Outcomes[0].Charged.String(), out.Swept.String(), out.Outcome)
}

// TestBurnWithADeadRefundAddressStrandsAndAccountsForNothing covers the one
// branch of F8b that does not move value, and it exists because that branch
// had no coverage at all in the revision that introduced it: replacing it with
// a silent `return` left `go test ./...` green across 32 packages.
//
// Two defects lived in the gap, and both are pinned here.
//
// **A stateless-valid certificate could make every block carrying it invalid.**
// The branch used to *destroy* what it could not deliver and add the amount to
// `res.Burned`, the block's native burn accumulator. An asset cap is an
// arbitrary u256 — deriveMint rejects only `amount > cap` and `cap == 0` — so
// minting ~2^256 of an asset to a one-shot cell, naming an already-burned
// address as RefundTo and moving one unit out overflowed that accumulator into
// a conservation failure. The certificate passes V1–V9, so it relays and any
// miner including it produced a block every peer rejected. Permissionless, and
// repeatable at will.
//
// **And it broke the native conservation identity**, because an asset amount
// counted as destroyed native supply.
//
// Both are closed the same way: F8b delivers or it leaves the value exactly
// where it already was, which is what the fold did before F8b existed. Nothing
// enters `res.Burned` and no accumulator can overflow.
func TestBurnWithADeadRefundAddressStrandsAndAccountsForNothing(t *testing.T) {
	w := newWorld(t)
	alice, bob, dead := key(t, 2), key(t, 3), key(t, 8)
	w.fund(alice.Persistent(), drops(3_000_000_000))

	// An asset whose cap is the entire u256 range, minted whole into the
	// one-shot cell. Nothing forbids either.
	asset := types.DeriveAssetAddress(w.p.ChainID, alice.Persistent(), 0)
	w.chain.MustAddBlock(w.payout, mustBuild(t, &wallet.Builder{
		Params:  w.p,
		Program: wallet.Issue(alice.Persistent(), u256.Max, 0, types.Hash{'M', 'A', 'X'}, alice.PubKey()),
		Seq:     0, TTL: w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		FeeBid:  bid(), Signers: []*wallet.Key{alice},
	}))
	w.chain.MustAddBlock(w.payout, mustBuild(t, &wallet.Builder{
		Params:  w.p,
		Program: wallet.Mint(asset, alice.OneShot(), u256.Max, u256.Max, alice.PubKey()),
		Seq:     1, TTL: w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		FeeBid:  bid(), Signers: []*wallet.Key{alice},
	}))
	if got := w.chain.AssetBalance(alice.OneShot(), asset); !got.Eq(u256.Max) {
		t.Fatalf("setup: the one-shot cell holds %s of the asset", got.String())
	}

	// The refund address is killed by an *earlier* certificate — the only way
	// this branch is reachable, because V5 rejects the same-certificate case.
	w.chain.MustAddBlock(w.payout, mustBuild(t, &wallet.Builder{
		Params: w.p, Program: wallet.Retire(dead.OneShot()),
		Seq: 2, TTL: w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		FeeBid:  bid(), Signers: []*wallet.Key{alice, dead},
	}))
	if !w.chain.State.IsSpent(dead.OneShot()) {
		t.Fatal("setup: the refund address is not burned")
	}
	held := drops(900_000_000)
	w.fund(alice.OneShot(), held)

	cert := mustBuild(t, &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(asset, alice.OneShot(), bob.Persistent(), u256.One),
		TTL:     w.chain.NextHeight() + 5,
		// SelfDeposit reserves only the fee ceiling, so a native residual is
		// stranded alongside the asset one and both branches are exercised.
		Deposit: wallet.SelfDeposit(alice.OneShot(), dead.OneShot()),
		FeeBid:  bid(), Signers: []*wallet.Key{alice},
	})
	if err := validity.Check(cert, w.p); err != nil {
		t.Fatalf("the certificate is not stateless-valid, so it would never relay: %v", err)
	}

	before := nativeSupply(w.chain.State, w.p.CoinbaseMaturity)
	_, res, err := w.chain.AddBlock(w.payout, cert)
	if err != nil {
		t.Fatalf("the block was rejected: %v — a stateless-valid certificate must never "+
			"make a block invalid through F8b", err)
	}
	out := res.Outcomes[0]
	if out.Outcome != fold.Applied {
		t.Fatalf("outcome = %s, want APPLIED", out.Outcome)
	}

	// Nothing was delivered and nothing was destroyed: the residual stays put,
	// exactly where the fold left it before F8b existed, and says so.
	if !out.Swept.IsZero() {
		t.Fatalf("swept %s into a burned refund address", out.Swept.String())
	}
	if out.SweptStranded.IsZero() {
		t.Fatal("nothing reported as stranded; the branch is not armed")
	}
	// Two cells were left: the native one, whose amount SweptStranded carries,
	// and the asset one, whose amount no drop counter can express.
	if out.StrandedCells != 2 {
		t.Fatalf("%d cells reported stranded, want 2 (native and asset)", out.StrandedCells)
	}
	if got := w.chain.AssetBalance(alice.OneShot(), asset); got.IsZero() {
		t.Fatal("the asset residual was moved into a cell nobody can read")
	}
	if got := w.chain.Balance(alice.OneShot()); got.IsZero() {
		t.Fatal("the native residual was moved into a cell nobody can read")
	}
	if got := w.chain.Balance(dead.OneShot()); !got.IsZero() {
		t.Fatalf("%s was written under the burned refund address", got.String())
	}

	// The native conservation identity still holds to the drop. It is the
	// whole of the second defect: an asset amount counted as burned native
	// supply falsifies this, and both implementations agreed on the wrong
	// answer, so the differential could not see it either.
	after := nativeSupply(w.chain.State, w.p.CoinbaseMaturity)
	want := before.SatAdd(w.p.Emission(w.chain.Height())).SatSub(res.Burned)
	if !after.Eq(want) {
		t.Fatalf("native supply = %s, the identity wants %s (before + emission - burned); "+
			"F8b put a non-native amount into the native burn accumulator",
			after.String(), want.String())
	}
}

func mustBuild(t *testing.T, b *wallet.Builder) *types.Certificate {
	t.Helper()
	c, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// TestAnAssetOnlyStrandIsStillReported is the half of the stranded branch that
// no amount can carry, and it had no signal at all until StrandedCells existed.
//
// The reservation empties the native cell, so SweptStranded is zero and every
// drop counter in the outcome reads zero — while an asset balance is left
// under the burned address because the refund address is dead. A count needs
// no currency, which is exactly why it is the right shape here.
func TestAnAssetOnlyStrandIsStillReported(t *testing.T) {
	w := newWorld(t)
	alice, bob, dead := key(t, 2), key(t, 3), key(t, 8)
	w.fund(alice.Persistent(), drops(4_000_000_000))
	asset := w.issueAsset(alice, 0)
	w.chain.MustAddBlock(w.payout,
		w.assetTip(alice, alice.Persistent(), alice.OneShot(), asset, drops(500_000)))

	w.chain.MustAddBlock(w.payout, mustBuild(t, &wallet.Builder{
		Params: w.p, Program: wallet.Retire(dead.OneShot()),
		Seq: w.strangerSeq(alice), TTL: w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		FeeBid:  bid(), Signers: []*wallet.Key{alice, dead},
	}))
	w.fund(alice.OneShot(), drops(900_000_000))

	// SweepDeposit empties the native cell through the reservation, so the
	// only thing left under the burn is the asset.
	balance := w.chain.Balance(alice.OneShot())
	cert := mustBuild(t, &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(asset, alice.OneShot(), bob.Persistent(), drops(100_000)),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SweepDeposit(alice.OneShot(), dead.OneShot(), balance),
		FeeBid:  bid(), Signers: []*wallet.Key{alice},
	})
	res := w.chain.MustAddBlock(w.payout, cert)
	out := res.Outcomes[0]
	if out.Outcome != fold.Applied {
		t.Fatalf("outcome = %s, want APPLIED", out.Outcome)
	}
	if !out.Swept.IsZero() || !out.SweptStranded.IsZero() {
		t.Fatalf("drop counters are %s / %s; the native cell was emptied by the "+
			"reservation, so both must be zero and only the count can report the loss",
			out.Swept.String(), out.SweptStranded.String())
	}
	if got := w.chain.AssetBalance(alice.OneShot(), asset); got.IsZero() {
		t.Fatal("the asset residual moved into a cell nobody can read")
	}
	if out.StrandedCells != 1 {
		t.Fatalf("%d cells reported stranded, want 1 — an asset left under a burned "+
			"address with no drops beside it had no signal at all before this",
			out.StrandedCells)
	}
}
