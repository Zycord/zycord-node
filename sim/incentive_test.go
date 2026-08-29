package sim_test

import (
	"testing"

	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/sim"
	"zycord/sim/harness"
	"zycord/spec"
	"zycord/wallet"
)

// Incentive property tests for I1-H2.
//
// These do not test the fold. They test what a rational miner *does* under the
// fold's fee rules, which is a different question and the one that decides
// whether the two-market thesis survives contact with a block builder.
//
// The invariant: the miner's ordering incentive must track the scarce resource.
// The constraint: nothing routed to the miner may come from a skip.

func key(t *testing.T, n byte) *wallet.Key {
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

func drops(n uint64) u256.U256 { return u256.FromUint64(n) }

// tightSeq returns devnet parameters whose sequential ceiling binds long before
// the parallel one, which is the regime the whole design assumes: state
// mutation is scarce, verification is abundant.
func tightSeq() *params.Params {
	p := *spec.Devnet()
	p.SeqGasTargetGenesis = 3_000 // ceiling 2T = 6,000: about ten simple transfers
	p.ParGasRatio = 10_000        // ceiling ratio*2T = 60,000,000: stays abundant
	return &p
}

func cert(t *testing.T, p *params.Params, k *wallet.Key, seq uint64, fee types.FeeBid) *types.Certificate {
	t.Helper()
	b := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, k.Persistent(), key(t, 99).Persistent(), drops(1_000)),
		Seq:     seq,
		TTL:     100,
		Deposit: wallet.SelfDeposit(k.Persistent(), k.Persistent()),
		FeeBid:  fee,
		Signers: []*wallet.Key{k},
	}
	c, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return c
}

// roomy is a bid with generous maxima — the free safety buffer — and the given
// priorities, which are what a miner is actually paid.
func roomy(seqPriority, parPriority u256.U256) types.FeeBid {
	return wallet.Bid(drops(1_000_000), seqPriority, drops(1_000_000), parPriority)
}

// TestSequentialBidCarriesAPriceSignal is the direct statement of I1-H2. Under
// the rule as originally implemented — sequential base fee charged, the excess
// never collected — this test fails flat: raising a sequential bid changed
// nothing a miner could see, so the scarce resource had no market at all.
func TestSequentialBidCarriesAPriceSignal(t *testing.T) {
	p := tightSeq()
	base, parBase := drops(1_000), drops(10)
	k := key(t, 2)

	low := cert(t, p, k, 0, roomy(u256.Zero, u256.Zero))
	high := cert(t, p, k, 1, roomy(drops(5_000), u256.Zero))

	lowTip := low.MinerTip(p, base, parBase)
	highTip := high.MinerTip(p, base, parBase)

	if !lowTip.IsZero() {
		t.Fatalf("a certificate offering no priority tipped %s, want nothing",
			lowTip.String())
	}
	if !highTip.Gt(lowTip) {
		t.Fatal("raising the sequential priority did not raise the miner's revenue; " +
			"the scarce resource has no price signal (I1-H2)")
	}

	// And the signal is proportional to sequential gas, not to parallel gas.
	wantTip, _ := u256.FromUint64(high.SeqGas(p)).Mul(drops(5_000))
	if !highTip.Eq(wantTip) {
		t.Fatalf("sequential tip = %s, want seq_gas × priority = %s",
			highTip.String(), wantTip.String())
	}
	_ = base
	_ = parBase
}

// TestSafetyBufferIsFree is R2-H1, and it is the property pay-your-bid fails.
//
// B4 makes a certificate unincludable once the base fee passes its maximum, and
// a certificate may wait TTL_MAX blocks while the base fee moves 12.5% a block.
// A signer must therefore name a maximum far above today's base fee. Raising
// that maximum must cost nothing unless the market actually moves into it —
// otherwise every certificate pays its own risk margin in full, forever.
func TestSafetyBufferIsFree(t *testing.T) {
	p := tightSeq()
	seqBase, parBase := drops(1_000), drops(10)
	k := key(t, 2)

	priority := drops(500)
	var reference u256.U256
	for i, headroom := range []uint64{1, 10, 100, 10_000, 1_000_000} {
		fee := wallet.Bid(
			seqBase.SatAdd(priority).SatAdd(drops(headroom)), priority,
			parBase.SatAdd(priority).SatAdd(drops(headroom)), priority)
		c := cert(t, p, k, 0, fee)
		charge, _, _, ok := c.Fees(p, seqBase, parBase)
		if !ok {
			t.Fatal("fee arithmetic overflowed")
		}
		if i == 0 {
			reference = charge
			continue
		}
		if !charge.Eq(reference) {
			t.Fatalf("headroom of %d changed the charge from %s to %s; the signer is "+
				"paying for its own safety buffer (R2-H1)",
				headroom, reference.String(), charge.String())
		}
	}
}

// TestEarlyInclusionNeverCostsMore: the charge is non-decreasing in the base
// fee, so a certificate included promptly never pays more than the same
// certificate included after the market has risen. Under pay-your-bid the
// charge ignored the base fee entirely and the buffer was paid either way.
func TestEarlyInclusionNeverCostsMore(t *testing.T) {
	p := tightSeq()
	k := key(t, 2)
	c := cert(t, p, k, 0, roomy(drops(500), drops(5)))

	var prev u256.U256
	for i, base := range []uint64{1, 10, 100, 1_000, 10_000} {
		charge, burn, tip, ok := c.Fees(p, drops(base), drops(base))
		if !ok {
			t.Fatalf("fee arithmetic overflowed at base %d", base)
		}
		if !burn.SatAdd(tip).Eq(charge) {
			t.Fatal("burn + tip != charge")
		}
		if i > 0 && charge.Lt(prev) {
			t.Fatalf("the charge fell from %s to %s as the base fee rose; "+
				"late inclusion is cheaper than early", prev.String(), charge.String())
		}
		prev = charge
	}
}

// TestBuilderAllocatesScarceGasByScarceBid: with the sequential ceiling
// binding, a revenue-maximising builder must select the certificates that bid
// most for *sequential* gas — not those that bid most for verification.
func TestBuilderAllocatesScarceGasByScarceBid(t *testing.T) {
	p := tightSeq()
	seqBase, parBase := drops(1_000), drops(10)

	// Two classes with identical gas profiles, differing only in which market
	// they bid up. The parallel bidder pays more in absolute terms — parallel
	// gas is the larger number — so a builder that ignored the sequential
	// market would take them all and leave the sequential bidders out.
	var pool []*types.Certificate
	var seqBidders, parBidders []*types.Certificate
	for i := 0; i < 8; i++ {
		s := cert(t, p, key(t, byte(10+i)), 0, roomy(drops(100_000), u256.Zero))
		q := cert(t, p, key(t, byte(30+i)), 0, roomy(u256.Zero, drops(1_000)))
		seqBidders = append(seqBidders, s)
		parBidders = append(parBidders, q)
		pool = append(pool, s, q)
	}

	// The ceiling admits only about half the pool, so the builder must choose.
	selected := sim.Select(pool, p, seqBase, parBase, p.SeqGasTargetGenesis)
	if len(selected) == 0 || len(selected) >= len(pool) {
		t.Fatalf("the ceiling did not bind: %d of %d selected", len(selected), len(pool))
	}

	chosen := map[types.Hash]bool{}
	for _, c := range selected {
		chosen[c.ID()] = true
	}
	var seqIn, parIn int
	for _, c := range seqBidders {
		if chosen[c.ID()] {
			seqIn++
		}
	}
	for _, c := range parBidders {
		if chosen[c.ID()] {
			parIn++
		}
	}
	if seqIn <= parIn {
		t.Fatalf("under a binding sequential ceiling the builder took %d sequential "+
			"bidders and %d parallel bidders; the scarce resource is being "+
			"allocated by the abundant market (I1-H2)", seqIn, parIn)
	}

	// And the selection is revenue-maximal against the obvious alternative.
	if !sim.Revenue(selected, p, seqBase, parBase).Gt(sim.Revenue(parBidders, p, seqBase, parBase)) {
		t.Fatal("the builder's selection earns less than taking the parallel bidders alone")
	}
}

// TestInclusionIsMonotoneInTheSequentialBid: raising your own sequential priority
// must never remove you from the block. A market where paying more can hurt is
// not a market.
func TestInclusionIsMonotoneInTheSequentialBid(t *testing.T) {
	p := tightSeq()
	seqBase, parBase := drops(1_000), drops(10)

	var pool []*types.Certificate
	for i := 0; i < 12; i++ {
		pool = append(pool, cert(t, p, key(t, byte(40+i)), 0,
			roomy(drops(uint64(i)*1_000), u256.Zero)))
	}

	subject := key(t, 80)
	bids := []uint64{0, 500, 5_000, 50_000, 500_000}
	inclusion := make([]bool, len(bids))
	for i, extra := range bids {
		c := cert(t, p, subject, 0, roomy(drops(extra), u256.Zero))
		selected := sim.Select(append(append([]*types.Certificate{}, pool...), c), p, seqBase, parBase, p.SeqGasTargetGenesis)
		for _, s := range selected {
			if s.ID() == c.ID() {
				inclusion[i] = true
			}
		}
	}

	// Monotone: once included, raising the bid further must never exclude.
	for i := 1; i < len(inclusion); i++ {
		if inclusion[i-1] && !inclusion[i] {
			t.Fatalf("raising the sequential priority from %d to %d removed the "+
				"certificate from the block; paying more must never hurt", bids[i-1], bids[i])
		}
	}
	if !inclusion[len(inclusion)-1] {
		t.Fatal("the highest sequential bidder in the pool was excluded")
	}
	if inclusion[0] {
		t.Fatal("the ceiling did not bind: even a base-fee bid was included, " +
			"so the test cannot observe monotonicity")
	}
}

// TestNoRevenueFromSkips is the constraint the fix must not break. Whatever
// reaches the miner comes only from applied certificates, so a builder
// maximising revenue is maximising application and can never profit by
// assembling blocks that trigger other people's skips.
func TestNoRevenueFromSkips(t *testing.T) {
	p := spec.Devnet()
	c, err := harness.New(p)
	if err != nil {
		t.Fatal(err)
	}
	miner, alice, bob := key(t, 1), key(t, 2), key(t, 3)
	payout := miner.Persistent()
	if err := c.MineUntilFunded(payout); err != nil {
		t.Fatal(err)
	}
	// Three more matured coinbases. The bids below are deliberately
	// extravagant — that is the harvesting incentive the test is hunting for —
	// and a deposit reserves against gas times the *maximum* price, so the
	// ceilings here run to a couple of block subsidies. One coinbase does not
	// cover them.
	if err := c.Mine(payout, 3); err != nil {
		t.Fatal(err)
	}

	fund := func(to types.Address, amount u256.U256, seq uint64) {
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, payout, to, amount),
			Seq:     seq,
			TTL:     c.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(payout, payout),
			FeeBid:  wallet.Bid(drops(1_000_000), drops(1_000), drops(1_000_000), drops(10)),
			Signers: []*wallet.Key{miner},
		}
		cert, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		c.MustAddBlock(payout, cert)
	}
	// Enough for one of the two spends she signs, plus the deposits. The bid is
	// deliberately extravagant, so the ceiling — and therefore the reservation —
	// is large.
	// The deposit reserves against the *maximum*, not the priority, so a lavish
	// maximum means a lavish reservation. That is the cost of the free buffer:
	// paid in locked balance for one fold step, not in fees (R2-H1).
	//
	// Only the relation matters: Alice can afford one spend and not two, and
	// what is left after the first still covers a deposit — otherwise the
	// second certificate would be DROPPED, and a drop is not the skip under
	// test.
	fund(alice.Persistent(), drops(6_000_000_000), 1)

	spend := func(seq uint64) *types.Certificate {
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), drops(3_000_000_000)),
			Seq:     seq,
			TTL:     c.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			// A very generous priority: if a skip could tip, this is what a
			// harvester would target.
			FeeBid:  wallet.Bid(drops(501_000), drops(500_000), drops(501_000), drops(500_000)),
			Signers: []*wallet.Key{alice},
		}
		cert, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}

	// The base fees the block will be judged against are the ones in state
	// before it is applied.
	seqBase := c.State.Get(types.SeqBaseFeeSlot())
	parBase := c.State.Get(types.ParBaseFeeSlot())

	applied, skipped := spend(0), spend(1)
	before := c.Balance(payout)
	res := c.MustAddBlock(payout, applied, skipped)
	if res.Outcomes[1].Outcome != fold.SkippedStale {
		t.Fatalf("setup: second outcome = %s, want a skip", res.Outcomes[1].Outcome)
	}

	// The block's reward is the producer's share of the subsidy plus the tip of
	// the certificate that applied. The skipped one contributes exactly
	// nothing, however lavishly it bid — which is what stops a builder from
	// ever wanting to cause a skip. The treasury's share is taken from the
	// subsidy before this and never from the tips, so it moves the baseline
	// without touching the property under test.
	subsidy := p.Emission(c.Height())
	producer, _ := subsidy.Sub(subsidy.MulDiv64(p.TreasuryShareBps, 10000))
	want := producer.SatAdd(applied.MinerTip(p, seqBase, parBase))
	if !res.MinerReward.Eq(want) {
		t.Fatalf("miner reward = %s, want emission + the applied tip = %s; "+
			"a skip contributed to the miner's revenue",
			res.MinerReward.String(), want.String())
	}
	if skipped.MinerTip(p, seqBase, parBase).IsZero() {
		t.Fatal("the skipped certificate bid nothing above base; the test proves nothing")
	}

	// The skip fee is burned in full, and burned value never reaches anyone:
	// charge = burned + tip holds block-wide.
	_, appliedBurn, appliedTip, ok := applied.Fees(p, seqBase, parBase)
	if !ok {
		t.Fatal("fee arithmetic overflowed")
	}
	if wantBurn := appliedBurn.SatAdd(p.SkipFee); !res.Burned.Eq(wantBurn) {
		t.Fatalf("burned %s, want the applied base fees plus the whole skip fee (%s)",
			res.Burned.String(), wantBurn.String())
	}
	if !res.MinerReward.Eq(producer.SatAdd(appliedTip)) {
		t.Fatal("the miner's reward is not exactly the producer share plus applied tips")
	}
	// The treasury's share came out of the subsidy and not out of the tips:
	// the two add back up to the whole subsidy, and the fee markets are
	// untouched by the split.
	if sum, over := res.Treasury.Add(producer); over || !sum.Eq(subsidy) {
		t.Fatalf("treasury %s plus producer %s is not the subsidy %s",
			res.Treasury.String(), producer.String(), subsidy.String())
	}
	// This block's reward is not spendable yet: the payout balance moved by
	// exactly what matured from COINBASE_MATURITY blocks ago, and this block's
	// reward is still sitting in the ring.
	gained := c.Balance(payout).SatSub(before)
	if !gained.Eq(res.Matured) {
		t.Fatalf("the payout balance moved by %s, want the matured amount %s",
			gained.String(), res.Matured.String())
	}
	if res.Matured.Eq(res.MinerReward) {
		t.Fatal("this block's reward matured in the same block that earned it")
	}
}

// TestBuilderPrefersApplyingCertificates: including a certificate the builder
// knows will skip is strictly worse than leaving it out, because it consumes
// ceiling space and earns nothing. This is what makes "no profit from skips"
// an active preference rather than mere indifference.
func TestBuilderPrefersApplyingCertificates(t *testing.T) {
	p := tightSeq()
	seqBase, parBase := drops(1_000), drops(10)

	good := cert(t, p, key(t, 2), 0, roomy(drops(10_000), u256.Zero))
	// A certificate offering no priority tips nothing, so it is the stand-in for
	// one that will not pay the builder — a skipper.
	worthless := cert(t, p, key(t, 3), 0, roomy(u256.Zero, u256.Zero))

	withBoth := sim.Revenue(sim.Select([]*types.Certificate{good, worthless}, p, seqBase, parBase, p.SeqGasTargetGenesis), p, seqBase, parBase)
	withGood := sim.Revenue(sim.Select([]*types.Certificate{good}, p, seqBase, parBase, p.SeqGasTargetGenesis), p, seqBase, parBase)
	if !withBoth.Eq(withGood) {
		t.Fatal("a certificate that tips nothing changed the builder's revenue")
	}

	// The tipping certificate is ranked first, so a full block never displaces
	// it in favour of one that pays nothing.
	selected := sim.Select([]*types.Certificate{worthless, good}, p, seqBase, parBase, p.SeqGasTargetGenesis)
	if selected[0].ID() != good.ID() {
		t.Fatal("the builder ranked a zero-tip certificate above a paying one")
	}
}

// TestBaseFeesAreBurnedNotPaid pins the other half of the design: a miner may
// not receive the base fee, or it could stuff its own block with self-paying
// certificates to drive the base fee up for everyone else at no cost.
func TestBaseFeesAreBurnedNotPaid(t *testing.T) {
	p := spec.Devnet()
	k := key(t, 2)
	seqBase, parBase := drops(1_000), drops(10)

	c := cert(t, p, k, 0, roomy(u256.Zero, u256.Zero))
	charge, burned, tip, ok := c.Fees(p, seqBase, parBase)
	if !ok {
		t.Fatal("fee arithmetic overflowed")
	}
	if !tip.IsZero() {
		t.Fatalf("a certificate offering no priority tipped %s", tip.String())
	}
	if !burned.Eq(charge) {
		t.Fatalf("burned %s of a %s charge; the base fees must be burned in full",
			burned.String(), charge.String())
	}

	// And the split is exact for any bid: charge = burned + tip, always.
	for _, extra := range []uint64{1, 7, 1_000, 999_983} {
		c := cert(t, p, k, 0, roomy(drops(extra), drops(extra)))
		charge, burned, tip, ok := c.Fees(p, seqBase, parBase)
		if !ok {
			t.Fatal("fee arithmetic overflowed")
		}
		if sum := burned.SatAdd(tip); !sum.Eq(charge) {
			t.Fatalf("burned + tip = %s, charge = %s: value appears or vanishes",
				sum.String(), charge.String())
		}
	}
}
