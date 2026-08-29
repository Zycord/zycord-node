package fold_test

import (
	"fmt"
	"math/rand"
	"testing"

	"zycord/core/fold"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/sim/harness"
	"zycord/spec"
	"zycord/wallet"
)

// Property tests. These do not check a scenario; they check a law.

// nativeSupply sums every unit of the native coin that exists anywhere: the
// spendable balances plus the rewards still sitting in the maturity ring.
//
// Deposits never straddle a block boundary — a reservation is settled and
// refunded within the same fold step — so there is nothing else to count.
func nativeSupply(s *state.State, maturity uint64) u256.U256 {
	total := u256.Zero
	nativeWord := types.BalanceWord(types.NativeAsset)
	for _, slot := range s.SortedCells() {
		if slot.Word == nativeWord {
			total = total.SatAdd(s.Get(slot))
		}
	}
	for i := uint64(0); i < maturity; i++ {
		total = total.SatAdd(s.Get(types.PendingCoinbaseAmountSlot(i)))
	}
	return total
}

// TestConservation is the accounting identity the whole fee model rests on:
// value is created only by emission and destroyed only by burning. Every other
// movement — deposits, refunds, tips, maturation — is a transfer.
func TestConservation(t *testing.T) {
	w := newWorld(t)
	alice, bob, carol := key(t, 2), key(t, 3), key(t, 4)
	w.fund(alice.Persistent(), drops(2_000_000_000))
	w.fund(bob.Persistent(), drops(2_000_000_000))

	// A block containing an applied transfer, a self-inflicted skip, and a
	// drop: every outcome the fold can produce, in one accounting check.
	applied := w.transfer(alice, alice.Persistent(), carol.Persistent(), drops(10_000_000), 0)
	skipped := w.transfer(alice, alice.Persistent(), carol.Persistent(), drops(1_999_000_000), 1)
	dropped := w.transfer(key(t, 8), key(t, 8).Persistent(), carol.Persistent(), drops(1), 0)

	before := nativeSupply(w.chain.State, w.p.CoinbaseMaturity)
	_, res, err := w.chain.AddBlock(w.payout, applied, skipped, dropped)
	if err != nil {
		t.Fatal(err)
	}
	after := nativeSupply(w.chain.State, w.p.CoinbaseMaturity)

	want := before.SatAdd(w.p.Emission(w.chain.Height())).SatSub(res.Burned)
	if !after.Eq(want) {
		t.Fatalf("supply = %s, want %s (before + emission - burned)", after.String(), want.String())
	}
	if res.Burned.IsZero() {
		t.Fatal("nothing was burned; the identity is untested")
	}

	// The identity above already covers the treasury, and that is the point of
	// where the cell lives: it is an ordinary native balance, so nativeSupply
	// sums it without being told it exists, and the subsidy split moves coins
	// between two places inside the total rather than changing the total. What
	// is asserted here is the split itself — that the treasury took exactly
	// its share of the subsidy and nothing from the fees.
	subsidy := w.p.Emission(w.chain.Height())
	wantTreasury := subsidy.MulDiv64(w.p.TreasuryShareBps, 10000)
	if !res.Treasury.Eq(wantTreasury) {
		t.Fatalf("treasury credit = %s, want %s", res.Treasury.String(), wantTreasury.String())
	}
	if sum, over := res.Treasury.Add(res.MinerReward); over || sum.Lt(subsidy) {
		t.Fatalf("treasury %s plus reward %s does not cover the subsidy %s",
			res.Treasury.String(), res.MinerReward.String(), subsidy.String())
	}
}

// TestFoldOrderErasesProposerChoice: the canonical sort must make the state
// transition independent of how a proposer interleaved the block.
func TestFoldOrderErasesProposerChoice(t *testing.T) {
	build := func(shuffle func([]*types.Certificate)) types.Hash {
		w := newWorld(t)
		certs := make([]*types.Certificate, 0, 10)
		for i := 0; i < 10; i++ {
			k := key(t, byte(50+i))
			w.fund(k.Persistent(), drops(600_000_000))
			certs = append(certs, w.transfer(k, k.Persistent(), key(t, 99).Persistent(), drops(1_000_000), 0))
		}
		shuffle(certs)
		w.chain.MustAddBlock(w.payout, certs...)
		return w.chain.State.Root()
	}

	base := build(func([]*types.Certificate) {})
	for seed := int64(0); seed < 5; seed++ {
		rng := rand.New(rand.NewSource(seed))
		got := build(func(c []*types.Certificate) {
			rng.Shuffle(len(c), func(i, j int) { c[i], c[j] = c[j], c[i] })
		})
		if got != base {
			t.Fatalf("seed %d: shuffling the block changed the state", seed)
		}
	}
}

// TestUndoIsExact: apply then undo must be the identity on every piece of
// consensus state, including the pieces that are easy to forget — the spent
// registry and the seen set.
func TestUndoIsExact(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	oneShot := key(t, 11).OneShot()
	w.fund(alice.Persistent(), drops(2_000_000_000))
	w.fund(oneShot, drops(900_000_000))

	root := w.chain.State.Root()
	spentBefore := w.chain.State.SpentCount()
	seenBefore := w.chain.State.SeenCount()

	// A block that touches cells, the registry and the seen set at once.
	burn := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, oneShot, bob.Persistent(), drops(1_000_000)),
		TTL:     w.chain.NextHeight() + 5,
		Deposit: wallet.SelfDeposit(oneShot, alice.Persistent()),
		FeeBid:  bid(),
		// Only the one-shot's key is required: the refund destination is
		// credited, not debited, so it authorises nothing and V4 would reject a
		// signature from it as superfluous.
		Signers: []*wallet.Key{key(t, 11)},
	}
	burnCert, err := burn.Build()
	if err != nil {
		t.Fatal(err)
	}
	ok := w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(5_000_000), 0)

	w.chain.MustAddBlock(w.payout, burnCert, ok)
	if w.chain.State.SpentCount() == spentBefore {
		t.Fatal("setup: the registry did not grow")
	}

	if err := w.chain.Rollback(); err != nil {
		t.Fatal(err)
	}
	if w.chain.State.Root() != root {
		t.Fatal("undo did not restore the cells and the registry")
	}
	if w.chain.State.SpentCount() != spentBefore {
		t.Fatal("undo did not restore the spent registry")
	}
	if w.chain.State.SeenCount() != seenBefore {
		t.Fatal("undo did not restore the seen set")
	}
}

// TestSeenSetPrunes: seen entries must not accumulate forever, or the seen set
// becomes the state growth the TTL bound exists to prevent (R1-H4).
func TestSeenSetPrunes(t *testing.T) {
	w := newWorld(t)
	alice, bob := key(t, 2), key(t, 3)
	w.fund(alice.Persistent(), drops(2_000_000_000))

	w.chain.MustAddBlock(w.payout, w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(1_000_000), 0))
	if w.chain.State.SeenCount() == 0 {
		t.Fatal("setup: nothing was marked seen")
	}

	// Mine past the TTL of everything committed so far.
	if err := w.chain.Mine(w.payout, 12); err != nil {
		t.Fatal(err)
	}
	if got := w.chain.State.SeenCount(); got != 0 {
		t.Fatalf("%d seen entries survived their TTL window", got)
	}
}

// TestSkipsAreNotDemand is R2-H2: the base fees respond to what the chain
// actually did, not to what was attempted.
//
// Counting included gas rather than applied gas would hand a griefer a
// constant-cost lever — stuff blocks with self-conflicting certificates, which
// is self-inflicted and so leaves the billing law untouched, at SKIP_FEE each,
// and price everyone else's certificates upward. A skip is a failed attempt to
// use the chain, not evidence of demand for it.
//
// The gas ceiling is tightened for this test on purpose. At devnet's ceiling a
// handful of certificates is a rounding error against the target, and the base
// fee update would land on the same value whether their gas counted or not —
// the test would pass without testing anything. A ceiling the traffic can
// actually move is what makes the assertion sharp.
func TestSkipsAreNotDemand(t *testing.T) {
	tight := *spec.Devnet()
	tight.SeqGasTargetGenesis = 2_000 // ceiling 2T = 4,000: a few certificates move it
	tight.ParGasRatio = 3             // ceiling ParGasRatio*2T = 12,000, as before

	chain := harness.MustNew(&tight)
	miner, alice, bob := key(t, 1), key(t, 2), key(t, 3)
	payout := miner.Persistent()
	if err := chain.MineUntilFunded(payout); err != nil {
		t.Fatal(err)
	}

	send := func(k *wallet.Key, from, to types.Address, amount u256.U256, seq uint64) *types.Certificate {
		b := &wallet.Builder{
			Params:  &tight,
			Program: wallet.Tip(types.NativeAsset, from, to, amount),
			Seq:     seq,
			TTL:     chain.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(from, from),
			FeeBid:  bid(),
			Signers: []*wallet.Key{k},
		}
		c, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	if _, _, err := chain.AddBlock(payout, send(miner, payout, alice.Persistent(), drops(700_000_000), 1)); err != nil {
		t.Fatal(err)
	}

	// Drain Alice, then commit a block containing nothing but her failed
	// follow-ups.
	first := send(alice, alice.Persistent(), bob.Persistent(), drops(600_000_000), 0)
	second := send(alice, alice.Persistent(), bob.Persistent(), drops(600_000_000), 1)
	third := send(alice, alice.Persistent(), bob.Persistent(), drops(600_000_000), 2)
	if _, _, err := chain.AddBlock(payout, first); err != nil {
		t.Fatal(err)
	}

	seqBefore := chain.State.Get(types.SeqBaseFeeSlot())
	parBefore := chain.State.Get(types.ParBaseFeeSlot())

	_, res, err := chain.AddBlock(payout, second, third)
	if err != nil {
		t.Fatal(err)
	}
	for i, o := range res.Outcomes {
		if o.Outcome != fold.SkippedStale {
			t.Fatalf("setup: outcome %d = %s, want a skip", i, o.Outcome)
		}
	}
	if res.SeqGasApplied != 0 || res.ParGasApplied != 0 {
		t.Fatalf("a block of skips reported %d/%d applied gas, want none",
			res.SeqGasApplied, res.ParGasApplied)
	}

	seqAfter := chain.State.Get(types.SeqBaseFeeSlot())
	parAfter := chain.State.Get(types.ParBaseFeeSlot())

	t0 := tight.SeqGasTargetGenesis
	wantSeq := tight.NextBaseFee(seqBefore, 0, t0)
	wantPar := tight.NextBaseFee(parBefore, 0, tight.ParGasTarget(t0))
	if !seqAfter.Eq(wantSeq) || !parAfter.Eq(wantPar) {
		t.Fatalf("a block of skips moved the base fees to %s/%s, want the empty-block "+
			"values %s/%s: skipped gas is being counted as demand (R2-H2)",
			seqAfter.String(), parAfter.String(), wantSeq.String(), wantPar.String())
	}

	// The assertion is only meaningful if counting the skipped gas *would* have
	// produced a different answer. Prove that here, so the test cannot pass by
	// the two values happening to coincide.
	ifCounted := tight.NextBaseFee(seqBefore, res.SeqGasUsed, t0)
	if ifCounted.Eq(wantSeq) {
		t.Fatalf("counting the skipped gas would have given the same base fee (%s); "+
			"the parameters make this test vacuous", ifCounted.String())
	}
}

// assetSupplyViolation checks the supply-conservation invariant the Era-0
// overflow argument rests on, over folded state: for any asset, the sum of
// every balance cell of that asset equals its `minted` cell, and `minted` is
// at or below the asset's immutable `cap`.
//
// That conjunction is what makes `SkippedOverflow` unreachable in Era 0, and
// three things lean on it — ARCHITECTURE §9's poisoning-immunity sketch, the
// attribution theorem's case split, and `moveResidual`'s untestable
// carry-past-2^256 branch — so it is asserted here rather than argued.
//
// It returns "" when the invariant holds, plus the number of *distinct*
// non-zero balance cells it summed, so a caller can refuse a state too thin
// for the sum to be a sum.
func assetSupplyViolation(s *state.State, asset types.Address) (string, int) {
	word := types.BalanceWord(asset)
	sum, cells := u256.Zero, 0
	for _, slot := range s.SortedCells() {
		if slot.Word != word {
			continue
		}
		v := s.Get(slot)
		if v.IsZero() {
			continue
		}
		next, over := sum.Add(v)
		if over {
			return fmt.Sprintf("the balance cells of asset %x sum past 2^256", asset[:6]), cells
		}
		sum, cells = next, cells+1
	}
	minted := s.Get(types.AssetMintedSlot(asset))
	supplyCap := s.Get(types.AssetCapSlot(asset))
	switch {
	case !sum.Eq(minted):
		return fmt.Sprintf("balances of asset %x sum to %s, its minted cell says %s",
			asset[:6], sum.String(), minted.String()), cells
	case minted.Gt(supplyCap):
		return fmt.Sprintf("asset %x has minted %s, past its cap %s",
			asset[:6], minted.String(), supplyCap.String()), cells
	}
	return "", cells
}

// TestAssetSupplyEqualsMintedOverFoldedState is the law that conjunction
// needs, and the one the old TestOverflowSkipsAreUnreachableInEraZero was
// named for but never checked: it added a MINT's amount to a constant zero,
// an addition no u256 can overflow, so it pinned nothing.
//
// The property is stated where the fold's state is enumerable — `state.State`
// keeps every cell, and an asset's balance cells share one storage word — so
// the invariant can be read off the state after a fold instead of argued about
// a constant. It is driven over a state that has exercised every way asset
// units move or fail to move: mints to four holders, transfers that create new
// cells and empty old ones, a transfer that skips for want of balance, and a
// mint refused by the minted cell's GUARD_LE at the cap.
//
// Non-vacuous three ways: the state must carry at least four distinct non-zero
// balance cells of the asset (a single cell would make the sum trivial), the
// cap-breaching mint must actually skip, and the checker is run against two
// perturbed clones — one balance cell one unit high, and a cap below minted —
// each of which it must reject.
func TestAssetSupplyEqualsMintedOverFoldedState(t *testing.T) {
	w := newWorld(t)
	issuer := key(t, 21)
	alice, bob, carol := key(t, 22), key(t, 23), key(t, 24)
	for _, k := range []*wallet.Key{issuer, alice, bob, carol} {
		w.fund(k.Persistent(), drops(2_000_000_000))
	}

	// Two assets from one issuer. The second is not decoration: balances of
	// different assets under one address are different cells, and a sum that
	// confused them would be caught by the second asset's own check.
	issue := func(symbol types.Hash, supplyCap u256.U256) types.Address {
		seq := w.strangerSeq(issuer)
		asset := types.DeriveAssetAddress(w.p.ChainID, issuer.Persistent(), seq)
		if out := w.submit(issuer, wallet.Issue(issuer.Persistent(), supplyCap, 6,
			symbol, issuer.PubKey()), seq); out != fold.Applied {
			t.Fatalf("issue of %x was %s, want Applied", symbol[:3], out)
		}
		return asset
	}
	assetCap := drops(1_000_000)
	asset := issue(types.Hash{'S', 'U', 'M'}, assetCap)
	other := issue(types.Hash{'O', 'T', 'H'}, assetCap)

	mint := func(a types.Address, dst types.Address, amount u256.U256) fold.Outcome {
		return w.submit(issuer, wallet.Mint(a, dst, amount, assetCap, issuer.PubKey()),
			w.strangerSeq(issuer))
	}

	// Four holders, so the sum is over four cells rather than one.
	minted := u256.Zero
	for _, dst := range []types.Address{
		issuer.Persistent(), alice.Persistent(), bob.Persistent(), carol.Persistent(),
	} {
		if out := mint(asset, dst, drops(200_000)); out != fold.Applied {
			t.Fatalf("mint to %x was %s, want Applied", dst[:6], out)
		}
		minted = minted.SatAdd(drops(200_000))
	}
	if out := mint(other, alice.Persistent(), drops(300_000)); out != fold.Applied {
		t.Fatalf("mint of the second asset was %s, want Applied", out)
	}

	// Movement: a transfer that opens a new cell, and one that empties an old
	// one. Neither creates or destroys a unit, so neither may move the sum.
	fresh := key(t, 25).OneShot()
	w.chain.MustAddBlock(w.payout,
		w.assetTip(alice, alice.Persistent(), fresh, asset, drops(50_000)))
	w.chain.MustAddBlock(w.payout,
		w.assetTip(carol, carol.Persistent(), bob.Persistent(), asset, drops(200_000)))

	// A transfer that skips for want of balance: a failed move must not move
	// the sum either.
	res := w.chain.MustAddBlock(w.payout,
		w.assetTip(carol, carol.Persistent(), bob.Persistent(), asset, drops(1)))
	if got := res.Outcomes[0].Outcome; got == fold.Applied {
		t.Fatal("setup: a transfer out of an emptied asset cell applied")
	}

	// The cap is what bounds the supply, and therefore what bounds every credit
	// below 2^256. Prove the guard is live before resting the invariant on it.
	if out := mint(asset, alice.Persistent(), assetCap); out == fold.Applied {
		t.Fatal("a mint past the cap applied; the bound the invariant rests on is gone")
	}

	for _, a := range []types.Address{asset, other} {
		why, cells := assetSupplyViolation(w.chain.State, a)
		if why != "" {
			t.Fatalf("supply invariant broken after the fold: %s", why)
		}
		if a == asset && cells < 4 {
			t.Fatalf("only %d non-zero balance cells of the asset exist; "+
				"the sum is not a sum and the check is vacuous", cells)
		}
	}
	if got := w.chain.State.Get(types.AssetMintedSlot(asset)); !got.Eq(minted) {
		t.Fatalf("minted cell = %s, want %s", got.String(), minted.String())
	}

	// The checker must reject the states the invariant forbids, or the run
	// above proves only that it says yes to everything.
	high := w.chain.State.Clone()
	slot := types.BalanceSlot(alice.Persistent(), asset)
	high.Set(slot, high.Get(slot).SatAdd(u256.One))
	if why, _ := assetSupplyViolation(high, asset); why == "" {
		t.Fatal("one balance cell a unit above the minted total passed the check")
	}

	overCap := w.chain.State.Clone()
	overCap.Set(types.AssetCapSlot(asset), minted.SatSub(u256.One))
	if why, _ := assetSupplyViolation(overCap, asset); why == "" {
		t.Fatal("a minted total above the cap passed the check")
	}
}
