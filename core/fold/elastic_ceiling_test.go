package fold_test

import (
	"errors"
	"strings"
	"testing"

	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/sim/harness"
	"zycord/spec"
	"zycord/wallet"
)

// Whitepaper §8.1: the elastic sequential ceiling.
//
// These scenarios need a small, custom SeqGasTargetGenesis so a handful of
// certificates — not thousands — bind the ceiling, and they are Go tests
// rather than golden vectors for exactly that reason: the vector format
// records a params *name* ("mainnet" or "devnet"), resolved back to the
// canonical, unmodified parameter set at conformance-test time
// (spec.ParamsFor) — a vector generated against a locally tightened copy
// would silently be replayed against different numbers and fail for reasons
// that have nothing to do with the property under test. A custom-params
// scenario belongs here, in the same shape TestSkipsAreNotDemand already
// uses in property_test.go.

// tightWorld is fold_test's world (fold_test.go), parameterised: newWorld
// hardcodes spec.Devnet(), and every test below needs its own copy.
type tightWorld struct {
	t        *testing.T
	p        *params.Params
	chain    *harness.Chain
	miner    *wallet.Key
	payout   types.Address
	minerSeq uint64
}

func newTightWorld(t *testing.T, p *params.Params) *tightWorld {
	t.Helper()
	c := harness.MustNew(p)
	miner := key(t, 1)
	w := &tightWorld{t: t, p: p, chain: c, miner: miner, payout: miner.Persistent()}
	if err := c.MineUntilFunded(w.payout); err != nil {
		t.Fatal(err)
	}
	return w
}

func (w *tightWorld) transfer(from *wallet.Key, fromAddr, to types.Address, amount u256.U256, seq uint64) *types.Certificate {
	w.t.Helper()
	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, fromAddr, to, amount),
		Seq:     seq,
		TTL:     w.chain.NextHeight() + 10,
		Deposit: wallet.SelfDeposit(fromAddr, fromAddr),
		FeeBid:  bid(),
		Signers: []*wallet.Key{from},
	}
	cert, err := b.Build()
	if err != nil {
		w.t.Fatal(err)
	}
	return cert
}

func (w *tightWorld) fund(to types.Address, amount u256.U256) {
	w.t.Helper()
	cert := w.transfer(w.miner, w.payout, to, amount, w.minerSeq)
	w.minerSeq++
	res := w.chain.MustAddBlock(w.payout, cert)
	if res.Outcomes[0].Outcome != fold.Applied {
		w.t.Fatalf("funding transfer was %s, want APPLIED", res.Outcomes[0].Outcome)
	}
}

func (w *tightWorld) currentT() uint64 {
	w.t.Helper()
	v, ok := w.chain.State.Get(types.SeqGasTargetSlot()).Uint64()
	if !ok {
		w.t.Fatal("T does not fit in 64 bits")
	}
	return v
}

// mustAddBlockApplied is w.chain.MustAddBlock, checked: every certificate
// passed must apply, so a scenario's own setup failure (an unexpected skip)
// is a test failure at the point it happened, not a confusing mismatch three
// assertions later.
func (w *tightWorld) mustAddBlockApplied(certs ...*types.Certificate) *fold.Result {
	w.t.Helper()
	res := w.chain.MustAddBlock(w.payout, certs...)
	for i, o := range res.Outcomes {
		if o.Outcome != fold.Applied {
			w.t.Fatalf("certificate %d was %s, want APPLIED", i, o.Outcome)
		}
	}
	return res
}

// TestElasticCeilingGrowsByTheClampedStep pins the epoch controller's growth
// arithmetic against the fold actually running it, not merely the formula in
// isolation (params_test.go's TestNextSeqGasTargetRespectsItsClamps already
// covers the formula; this is the wiring — the sample ring, the boundary
// timing, the write to state).
//
// T0=1000 and Gamma=512 (the genesis default) give a clamped step of exactly
// 1 — the smallest possible nonzero step, chosen so "did T move by the right
// amount" has one unambiguous right answer rather than a range to eyeball.
func TestElasticCeilingGrowsByTheClampedStep(t *testing.T) {
	ep := *spec.Devnet()
	ep.SeqGasTargetGenesis = 1000
	w := newTightWorld(t, &ep)

	alice, bob := key(t, 2), key(t, 3)
	w.fund(alice.Persistent(), drops(2_000_000_000))

	seq := uint64(0)
	for w.chain.NextHeight() < ep.EpochLength {
		seq++
		w.mustAddBlockApplied(w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(1_000_000), seq))
	}

	before := w.currentT()
	if before != ep.SeqGasTargetGenesis {
		t.Fatalf("T moved before the boundary: %d", before)
	}

	if _, _, err := w.chain.AddBlock(w.payout); err != nil {
		t.Fatal(err)
	}
	after := w.currentT()
	if want := before + before/ep.CeilingGrowthDivisor; after != want {
		t.Fatalf("T after a full epoch = %d, want the clamped step %d", after, want)
	}
}

// TestElasticCeilingDecaysAfterGrowth is the property that only shows up
// across two epochs: decay is masked by the genesis floor for as long as T
// sits on it (whitepaper §8.1's floor is a hard "never below", and the floor
// clamp runs last), so the only way to observe a real decay step is to grow
// T above the floor first.
//
// Gamma=2 and Delta=4 here are deliberately aggressive — nothing this
// pronounced belongs in spec/params.json — chosen only so one epoch of
// growth clears the floor by enough that the following epoch's decay step
// is unambiguous rather than immediately reabsorbed by the floor.
func TestElasticCeilingDecaysAfterGrowth(t *testing.T) {
	dp := *spec.Devnet()
	dp.SeqGasTargetGenesis = 2048
	dp.CeilingGrowthDivisor = 2
	dp.CeilingDecayDivisor = 4
	w := newTightWorld(t, &dp)

	alice, bob := key(t, 2), key(t, 3)
	w.fund(alice.Persistent(), drops(2_000_000_000))

	// Epoch 1: full blocks, so T grows to its clamped ceiling. Growth needs
	// 2*median >= T+T/Gamma = 3072, i.e. a median applied gas of at least
	// 1536 — one transfer (600 gas) does not clear that here the way it
	// does at T0=1000 in the growth test above, so each block carries three.
	seq := uint64(0)
	for w.chain.NextHeight() < dp.EpochLength {
		certs := make([]*types.Certificate, 3)
		for i := range certs {
			seq++
			certs[i] = w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(1_000_000), seq)
		}
		w.mustAddBlockApplied(certs...)
	}
	if _, _, err := w.chain.AddBlock(w.payout); err != nil {
		t.Fatal(err)
	}
	grown := w.currentT()
	if want := dp.SeqGasTargetGenesis + dp.SeqGasTargetGenesis/dp.CeilingGrowthDivisor; grown != want {
		t.Fatalf("T after epoch 1 = %d, want %d", grown, want)
	}

	// Epoch 2: empty blocks, so T decays back toward (not below) the floor.
	for w.chain.NextHeight() < 2*dp.EpochLength {
		if _, _, err := w.chain.AddBlock(w.payout); err != nil {
			t.Fatal(err)
		}
	}
	if _, _, err := w.chain.AddBlock(w.payout); err != nil {
		t.Fatal(err)
	}
	decayed := w.currentT()
	if want := grown - grown/dp.CeilingDecayDivisor; decayed != want {
		t.Fatalf("T after an idle epoch = %d, want %d", decayed, want)
	}
	if decayed <= dp.SeqGasTargetGenesis {
		t.Fatal("test setup did not clear the floor; this decay step is degenerate, not a real measurement")
	}
}

// TestBurstValve is the table §8.1 describes: valid and unpenalised at or
// below 2T, valid and penalised quadratically between 2T and 4T, valid and
// fully forfeited to the producer at 4T exactly, invalid above it.
//
// "Fully forfeited" means the whole of what the block credits its producer —
// the subsidy share AND the block's fees — the base the forfeiture is
// denominated in. At 4T exactly the producer is paid nothing at all, however
// its certificates bid.
//
// The expected reward is reconstructed from first principles — subsidy,
// split, the exact two-step forfeiture F11 computes, plus tips read directly
// off each certificate via MinerTip against the block's own base fees — so
// the assertion is a real check of the arithmetic rather than a restatement
// of whatever the fold happened to produce.
func TestBurstValve(t *testing.T) {
	cases := []struct {
		name      string
		certs     int // 600 sequential gas each
		wantValid bool
	}{
		{"at the soft ceiling: 1800 = 2T, no penalty", 3, true},
		{"between the ceilings: 2400, inside the burst band", 4, true},
		{"at the hard bound: 3600 = 4T, full forfeiture", 6, true},
		{"above the hard bound: 4200 > 4T, invalid", 7, false},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			w, alice, bob := validatedBurstScenario(t)
			seqBase := w.chain.State.Get(types.SeqBaseFeeSlot())
			parBase := w.chain.State.Get(types.ParBaseFeeSlot())

			certs := make([]*types.Certificate, c.certs)
			wantTips := u256.Zero
			for i := range certs {
				certs[i] = w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(1_000_000), uint64(i))
				wantTips = wantTips.SatAdd(certs[i].MinerTip(w.p, seqBase, parBase))
			}

			b, err := w.chain.Propose(w.payout, certs...)
			if err != nil {
				t.Fatal(err)
			}
			res, applyErr := fold.ApplyBlock(w.chain.State.Clone(), b, w.p)

			if !c.wantValid {
				if applyErr == nil {
					t.Fatal("the block applied; want it rejected for exceeding the burst bound")
				}
				if !errors.Is(applyErr, fold.ErrInvalidBlock) {
					t.Fatalf("got %v, want an invalid-block error", applyErr)
				}
				return
			}
			if applyErr != nil {
				t.Fatalf("the block was rejected: %v", applyErr)
			}

			seqLimit := w.p.SeqGasLimit(900) // T is unchanged from genesis this early
			subsidy := w.p.Emission(b.Header.Height)
			treasury := subsidy.MulDiv64(w.p.TreasuryShareBps, 10000)
			producer, _ := subsidy.Sub(treasury)

			if got := res.Treasury; !got.Eq(treasury) {
				t.Fatalf("treasury = %s, want %s (unaffected by the burst valve)", got.String(), treasury.String())
			}

			// The exact two-step floor F11 computes: forfeit =
			// floor(floor(base*excess/2T)*excess/2T) — deliberately not
			// the single combined division, which rounds differently. See
			// fold.go's comment on the burst valve for why.
			//
			// **The base is the producer's subsidy share PLUS the block's
			// fees, not the subsidy share alone**, and this expression
			// is where that is pinned: reverting fold.go to forfeit against
			// `producer` and adding the tips afterwards moves the reward on
			// both bursting rows below — by 275,315 drops in the burst band
			// and by the whole 3,716,760 of tips at the hard bound, where the
			// old base left the tips untouched and the new one takes them
			// with the subsidy. The tips are non-zero here because the
			// scenario's certificates carry a priority bid, which is what
			// makes the two denominations separable at all.
			base := producer.SatAdd(wantTips)
			forfeit := u256.Zero
			if res.SeqGasUsed > seqLimit {
				excess := res.SeqGasUsed - seqLimit
				forfeit = base.MulDiv64(excess, seqLimit).MulDiv64(excess, seqLimit)
			}
			wantReward := base.SatSub(forfeit)
			if !res.MinerReward.Eq(wantReward) {
				t.Fatalf("miner reward = %s, want %s (producer %s + tips %s - forfeit %s)",
					res.MinerReward.String(), wantReward.String(), producer.String(), wantTips.String(), forfeit.String())
			}
			if wantTips.IsZero() {
				t.Fatal("the block's tips are zero, so this row cannot tell the subsidy-only " +
					"forfeiture base from the subsidy-plus-fees one, and the re-denomination " +
					"goes unpinned")
			}
		})
	}
}

// TestBurstForfeitureIsConserved is the identity TestBurstValve does not
// check and TestConservation (property_test.go) cannot reach: conservation
// is stated against the *schedule* — supply_after = supply_before +
// Emission(height) − burned, where Emission is what §14.2's curve says the
// height pays, not what was actually credited — so a burst forfeiture that
// reduced the producer's credit without registering as burned would leave
// exactly its own value unaccounted for.
//
// It is a regression test in the strict sense: the first implementation of
// the burst valve did precisely that, and neither TestConservation (whose
// blocks never burst under stock devnet parameters) nor the differential
// fuzzer (sim/refold mirrored the same omission, so both implementations
// agreed on the wrong answer) could see it. Conservation had to be checked
// against a bursting block specifically, which is what this does.
func TestBurstForfeitureIsConserved(t *testing.T) {
	w, alice, bob := validatedBurstScenario(t)

	// Four transfers: 2400 sequential gas against 2T = 1800, inside the
	// burst band, so a forfeiture actually occurs.
	certs := make([]*types.Certificate, 4)
	for i := range certs {
		certs[i] = w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(1_000_000), uint64(i))
	}

	before := nativeSupply(w.chain.State, w.p.CoinbaseMaturity)
	_, res, err := w.chain.AddBlock(w.payout, certs...)
	if err != nil {
		t.Fatal(err)
	}
	after := nativeSupply(w.chain.State, w.p.CoinbaseMaturity)

	seqLimit := w.p.SeqGasLimit(900)
	if res.SeqGasUsed <= seqLimit {
		t.Fatalf("setup: %d sequential gas does not exceed 2T = %d, so nothing is forfeited "+
			"and this test is vacuous", res.SeqGasUsed, seqLimit)
	}

	want := before.SatAdd(w.p.Emission(w.chain.Height())).SatSub(res.Burned)
	if !after.Eq(want) {
		t.Fatalf("supply = %s, want %s (before + emission - burned): the burst forfeiture "+
			"is not accounted for", after.String(), want.String())
	}

	// And the burn is strictly larger than it would be without a forfeiture,
	// so the identity above cannot be satisfied by the forfeit being zero.
	subsidy := w.p.Emission(w.chain.Height())
	treasury := subsidy.MulDiv64(w.p.TreasuryShareBps, 10000)
	producer, _ := subsidy.Sub(treasury)
	excess := res.SeqGasUsed - seqLimit
	forfeit := producer.MulDiv64(excess, seqLimit).MulDiv64(excess, seqLimit)
	if forfeit.IsZero() {
		t.Fatal("setup: the forfeiture rounded to zero, so the identity is untested")
	}
	if res.Burned.Lt(forfeit) {
		t.Fatalf("burned %s is less than the forfeiture %s alone", res.Burned.String(), forfeit.String())
	}
}

// TestCitationCannotExploitTheGenesisWorkExemption pins a safety property
// that holds only by an interaction between two files, and therefore has no
// natural home in either.
//
// pow.CheckWork returns nil unconditionally for a header at height 0 —
// genesis carries no proof of work, deliberately (I1-L1) — so a *cited*
// header claiming height 0 costs an attacker nothing to fabricate and
// sails through the work check that node/p2p and node/sync apply to
// citations. What stops it is checkCites' rule 1, in this package: a
// citation must name the citing block's parent's height, and a block low
// enough for that to be 0 (height 1) may carry no citations at all.
//
// Neither half is obviously load-bearing on its own. If rule 1 were ever
// relaxed to a window — the widening §8's note describes as the fix for the
// health gate's blind spot — this exemption becomes a free way to inflate
// the citation count, and this test is what should fail first.
func TestCitationCannotExploitTheGenesisWorkExemption(t *testing.T) {
	p := spec.Devnet()
	c := harness.MustNew(p)
	payout := key(t, 1).Persistent()

	// Get to height 2, the lowest height at which citations are permitted.
	for c.Height() < 2 {
		if _, _, err := c.AddBlock(payout); err != nil {
			t.Fatal(err)
		}
	}

	// A fabricated header at height 0: no work needed, since pow.CheckWork
	// exempts genesis. Give it the parentage and target a citation at this
	// height would otherwise need, so that rule 1 is the only thing left to
	// reject it.
	forged := &types.Header{
		Version:  types.HeaderVersion,
		Height:   0,
		ParentID: c.State.Get(types.PrevParentIDSlot()).Bytes(),
		Target:   c.State.Get(types.PrevTargetSlot()),
	}
	if pow.CheckWork(pow.Dev{}, *forged, p) != nil {
		t.Fatal("setup: the forged header was expected to pass the work check for free")
	}

	tip := c.Tip()
	b := &types.Block{
		Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       tip.Height + 1,
			ParentID:     tip.ID(),
			Time:         tip.Time + p.TargetBlockSeconds,
			EmissionAddr: payout,
			Target:       tip.Target,
		},
		Cites: []*types.Header{forged},
	}
	b.Header.CertRoot = b.ComputeCertRoot(p)
	b.Header.CitesRoot = b.ComputeCitesRoot(p)

	_, err := fold.ApplyBlock(c.State.Clone(), b, p)
	if err == nil {
		t.Fatal("a block citing a fabricated height-0 header was accepted; the genesis " +
			"work exemption is reachable through citations")
	}
	if !errors.Is(err, fold.ErrInvalidBlock) {
		t.Fatalf("got %v, want an invalid-block error", err)
	}
}

// TestBurstValveAtGenesisParameters is the measurement §21's decisions log
// cites, and it exists because that paragraph makes a claim about *cost* that
// nothing else in the tree pins.
//
// The claim is about the cost of a bursting block at STOCK mainnet parameters,
// and that is all this test measures. The controller's tightened-params
// scenarios cannot be vectors at all — the vector format records a params
// *name*, so a locally tightened SeqGasTargetGenesis is silently replayed
// against the canonical numbers. The burst valve has no such problem: it is
// perfectly reachable under stock mainnet parameters. It is simply enormous
// there, and this test says how enormous.
//
// **What that measurement was taken to mean, and no longer does.** It was read
// as "too expensive to be a vector", and §21 recorded the consequence that the
// corpus therefore held nobody to the valve's arithmetic. The step that does
// not follow is that T is not a parameter: it is a pre-state cell, which a
// vector carries and spec.ParamsFor never overwrites, so the params-name trap
// above does not reach it. At a seeded T one certificate of this same family
// crosses 2T, and spec/vectors/064-burst-forfeiture-where-two-floors-are-not-
// one-division is that vector. This test keeps its job — the stock-
// parameter cost — and no longer carries the corpus's.
//
// **And it never held the rounding, which is the part worth writing down.**
// Nothing below asserts a forfeited amount, so replacing F11's two nested
// floors with the exact single division leaves this whole package green; what
// killed that mutant was sim's differential against sim/refold. A test named
// for a valve is not a test of the valve's arithmetic.
//
// RETIRE is the densest sequential gas per byte the Era-0 operation set can
// express, and not by a little: it is the only program that charges
// GasSeqPerRegistryInsert on every word it writes, so each retired address
// costs 700 sequential gas (200 write + 500 registry insert) against 32 bytes
// of program body plus one 97-byte write and one 96-byte signature. MaxSigs
// caps a certificate at sixteen of them, because every MARK_SPENT on a user
// address needs that address's own signature (V4).
func TestBurstValveAtGenesisParameters(t *testing.T) {
	// Ten seconds, and almost all of it is what the block's 5,664 signatures
	// cost: 5,664 signings in Build, then strict verification of all of them
	// twice — once in Build's closing validity.Check, once in the fold's B0.
	// (Propose is not a third: harness.ProposeWithCites only merkleises the
	// cert ids and seals a root on an epoch boundary. It verifies nothing.)
	// That price *is* the finding, so the test is skipped rather than shrunk
	// under -short.
	if testing.Short() {
		t.Skip("builds a 1.4 MB block; -short skips it")
	}
	p := spec.Mainnet()
	T := p.SeqGasTargetGenesis
	softCeiling := p.SeqGasLimit(T)

	c := harness.MustNew(p)
	miner := key(t, 1)
	if err := c.MineUntilFunded(miner.Persistent()); err != nil {
		t.Fatal(err)
	}

	// Fund each deposit cell directly rather than through funding blocks: this
	// is a measurement of the block, not of how its inputs got there.
	const perCert = 16
	seed := 0
	nextKey := func() *wallet.Key {
		seed++
		s := make([]byte, 32)
		s[0], s[1], s[2] = byte(seed), byte(seed>>8), byte(seed>>16)
		k, err := wallet.KeyFromSeed(s)
		if err != nil {
			t.Fatal(err)
		}
		return k
	}

	var certs []*types.Certificate
	var seqGas uint64
	for seqGas <= softCeiling {
		keys := make([]*wallet.Key, perCert)
		addrs := make([]types.Address, perCert)
		for i := range keys {
			keys[i] = nextKey()
			addrs[i] = keys[i].OneShot()
		}
		// The deposit is taken from one of the retired addresses. A seventeenth
		// signer would exceed MaxSigs, and V6 is satisfied because RETIRE
		// already derives that address's own MARK_SPENT.
		c.State.Set(types.BalanceSlot(keys[0].OneShot(), types.NativeAsset), u256.FromUint64(1_000_000_000_000))
		cert, err := (&wallet.Builder{
			Params:  p,
			Program: wallet.Retire(addrs...),
			Seq:     1,
			TTL:     c.NextHeight() + 5,
			Deposit: wallet.SelfDeposit(keys[0].OneShot(), keys[0].Persistent()),
			FeeBid:  wallet.Bid(u256.FromUint64(50_000), u256.FromUint64(1_000), u256.FromUint64(500), u256.FromUint64(10)),
			Signers: keys,
		}).Build()
		if err != nil {
			t.Fatal(err)
		}
		certs = append(certs, cert)
		seqGas += cert.SeqGas(p)
	}

	// Every figure §21 quotes for mainnet, exactly. They are pure functions of
	// a frozen parameter set, so an equality here can only break when those
	// parameters move — which is exactly when the paragraph has to be
	// rewritten rather than re-pinned.
	if got, want := certs[0].SeqGas(p), uint64(perCert*700+p.GasSeqPerSeenInsert); got != want {
		t.Fatalf("a %d-address RETIRE costs %d sequential gas, want %d", perCert, got, want)
	}
	if got := certs[0].SeqGas(p); got != 11_300 {
		t.Fatalf("per-certificate sequential gas is %d; §21's decisions log says 11,300", got)
	}
	if got := certs[0].SizeBytes(); got != 3_933 {
		t.Fatalf("per-certificate size is %d bytes; §21's decisions log says 3,933", got)
	}

	b, err := c.Propose(miner.Persistent(), certs...)
	if err != nil {
		t.Fatal(err)
	}
	res, err := fold.ApplyBlock(c.State.Clone(), b, p)
	if err != nil {
		t.Fatalf("the cheapest bursting block is not even valid: %v", err)
	}

	// It is in the band, not above it: valid, and penalised.
	if res.SeqGasUsed <= softCeiling {
		t.Fatalf("SeqGasUsed = %d, want above the 2T ceiling of %d", res.SeqGasUsed, softCeiling)
	}
	if res.SeqGasUsed > p.SeqGasBurst(T) {
		t.Fatalf("SeqGasUsed = %d, above the 4T bound of %d — this block should have been rejected",
			res.SeqGasUsed, p.SeqGasBurst(T))
	}
	for i, o := range res.Outcomes {
		if o.Outcome != fold.Applied {
			t.Fatalf("certificate %d was %s, want APPLIED: the measurement is of a block that does work", i, o.Outcome)
		}
	}

	size := len(b.MarshalSSZ())
	t.Logf("cheapest bursting block at genesis parameters: %d RETIRE certificates, "+
		"%d sequential gas against a 2T ceiling of %d, %d bytes (byte ceiling %d)",
		len(certs), res.SeqGasUsed, softCeiling, size, p.BlockByteLimit(T))

	if len(certs) != 284 {
		t.Fatalf("%d certificates; §21's decisions log says 284 — restate it or explain the move", len(certs))
	}
	if res.SeqGasUsed != 3_209_200 {
		t.Fatalf("SeqGasUsed = %d; §21's decisions log says 3,209,200", res.SeqGasUsed)
	}
	// The block is 236 bytes of header and 4 offset bytes per certificate on
	// top of the bodies — the framing an earlier draft of §21 forgot, which is
	// how it quoted a devnet block 380 bytes over the ceiling as if it fit.
	if want := types.HeaderSize + 8 + len(certs)*(certs[0].SizeBytes()+4); size != want {
		t.Fatalf("block is %d bytes, want %d = HeaderSize + 8 + %d x (%d + 4): the framing is part of the ceiling",
			size, want, len(certs), certs[0].SizeBytes())
	}
	if size != 1_118_344 {
		t.Fatalf("block is %d bytes; §21's decisions log says 1,118,344 — restate it or explain the move", size)
	}
	// And the reason it is a Go test rather than a vector: it fits the block,
	// but the vector carrying it is hex plus two state snapshots.
	if size > p.BlockByteLimit(T) {
		t.Fatalf("block is %d bytes, over the ceiling of %d: the claim that it is *reachable* is wrong",
			size, p.BlockByteLimit(T))
	}
}

// TestBurstDoesNotRatchetTheBaseFee pins the clamp: F12b's sequential input is
// clamped at 2T, so the burst band cannot drive the fee market.
//
// The controller's step is deviation/target/BaseFeeMaxChangeDenominator,
// which is the intended ±12.5% only while applied gas is capped at 2T. §8.1's
// burst valve raised the per-block bound to 4T, so an unclamped input reaches
// +37.5% up against −12.5% down — and alternating full and empty blocks then
// ratchet the fee ×1.203 per pair, for free, with no change in demand.
//
// Two properties, because either alone can pass for the wrong reason. First,
// a 4T block must move the fee exactly as far as a 2T block does: that is the
// clamp binding, and it fails loudly if the input ever reaches the controller
// unclamped. Second, the alternating pair must not be net-upward — the
// property the arithmetic above is actually about, and the one a reader cares
// about — checked against a genuinely bursting block so it cannot pass
// vacuously on a block that never entered the band.
func TestBurstDoesNotRatchetTheBaseFee(t *testing.T) {
	// feeAfter mines one block of n transfers and reports the sequential base
	// fee before and after it, plus the sequential gas the block applied.
	feeAfter := func(t *testing.T, n int) (before, after u256.U256, applied uint64) {
		t.Helper()
		w, alice, bob := validatedBurstScenario(t)
		certs := make([]*types.Certificate, n)
		for i := range certs {
			certs[i] = w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(1_000_000), uint64(i))
		}
		before = w.chain.State.Get(types.SeqBaseFeeSlot())
		_, res, err := w.chain.AddBlock(w.payout, certs...)
		if err != nil {
			t.Fatal(err)
		}
		return before, w.chain.State.Get(types.SeqBaseFeeSlot()), res.SeqGasApplied
	}

	// 3 certs = 1800 = 2T exactly; 6 certs = 3600 = 4T, the hard bound.
	atCeiling, atCeilingAfter, ceilingGas := feeAfter(t, 3)
	atBound, atBoundAfter, boundGas := feeAfter(t, 6)

	seqLimit := 2 * uint64(900)
	if ceilingGas != seqLimit {
		t.Fatalf("setup: a 3-certificate block applied %d sequential gas, want 2T = %d", ceilingGas, seqLimit)
	}
	if boundGas <= seqLimit {
		t.Fatalf("setup: a 6-certificate block applied %d sequential gas, which does not exceed 2T = %d, "+
			"so nothing is clamped and this test is vacuous", boundGas, seqLimit)
	}

	// The clamp binding: twice the gas, identical fee movement.
	if !atCeiling.Eq(atBound) {
		t.Fatalf("the two scenarios started from different base fees (%s vs %s); "+
			"the comparison below is only meaningful from a common start",
			atCeiling.String(), atBound.String())
	}
	if !atCeilingAfter.Eq(atBoundAfter) {
		t.Fatalf("a 4T block moved the base fee to %s but a 2T block moved it to %s: "+
			"F12b's input is not clamped at 2T, so the burst band is repricing the market",
			atBoundAfter.String(), atCeilingAfter.String())
	}

	// The ratchet itself: a full block then an empty one must not end above
	// where it started. Unclamped this pair is ×1.375 then ×0.875 = ×1.203.
	w, alice, bob := validatedBurstScenario(t)
	start := w.chain.State.Get(types.SeqBaseFeeSlot())
	certs := make([]*types.Certificate, 6)
	for i := range certs {
		certs[i] = w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(1_000_000), uint64(i))
	}
	if _, res, err := w.chain.AddBlock(w.payout, certs...); err != nil {
		t.Fatal(err)
	} else if res.SeqGasApplied <= seqLimit {
		t.Fatalf("setup: the full block applied %d sequential gas, not a burst", res.SeqGasApplied)
	}
	if _, _, err := w.chain.AddBlock(w.payout); err != nil {
		t.Fatal(err)
	}
	if end := w.chain.State.Get(types.SeqBaseFeeSlot()); end.Gt(start) {
		t.Fatalf("a 4T block followed by an empty one left the base fee at %s, above the %s it started "+
			"from: the fee ratchets upward on demand-neutral alternation", end.String(), start.String())
	}
}

// TestCertCountCeilingRejects pins core/fold's certificate-count rule
// (blockrules.go): a block carrying more certificates than
// MaxCertsPerBlock(T) allows is invalid, and it is invalid for its COUNT
// rather than for its size.
//
// This rule had neither a conformance vector nor a Go test until this one.
// The 22 MaxCertsPerBlock call sites across twelve files that predate this
// one all cover something else — the CertListCapacity clamp (core/params),
// the announce bound (node/p2p), an RPC field — and none builds a block that
// trips blockrules.go's check. sim/refold/refold.go:710 is the one that comes
// closest: it re-implements the rule for the differential runner, so the two
// implementations are compared against each other, but only over blocks the
// simulation happens to produce, and it never manufactures one over the
// ceiling. A divergence there is caught; the rule being absent from both is
// not. The golden vectors added alongside this test cover both parameter sets
// (spec/vectors 030 and 041), each by seeding T low so that ceiling+1
// certificates is a readable number. This test covers what that format
// cannot: a vector records a params *name*, resolved back to the canonical
// set at replay time (see this file's header comment), so it can only reach a
// small ceiling through a seeded T. Tightening max_certs_per_block_genesis
// instead observes the rule at each set's genuine genesis T, with no
// off-manifold pre-state at all.
//
// The ceiling scales with T, so the test does not need thousands of
// certificates at mainnet's genesis ceiling of 4000: it tightens
// SeqGasTargetGenesis until the ceiling is a handful, exactly as every other
// scenario in this file does.
func TestCertCountCeilingRejects(t *testing.T) {
	for _, tc := range []struct {
		name string
		base *params.Params
	}{
		{"devnet", spec.Devnet()},
		{"mainnet", spec.Mainnet()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// Tighten the ceiling to 4 certificates at either set. It has to
			// be max_certs_per_block_genesis that moves, not T0:
			// MaxCertsPerBlock(T0) is max_certs_per_block_genesis * T0/T0 by
			// construction, so scaling T0 moves both sides of the fraction
			// and leaves the ceiling exactly where it was.
			p := *tc.base
			p.MaxCertsPerBlockGenesis = 4

			ceiling := p.MaxCertsPerBlock(p.SeqGasTargetGenesis)
			if ceiling != 4 {
				t.Fatalf("setup: ceiling is %d, want 4", ceiling)
			}

			w := newTightWorld(t, &p)
			alice, bob := key(t, 2), key(t, 3)
			w.fund(alice.Persistent(), drops(900_000_000))

			certs := make([]*types.Certificate, 0, ceiling+1)
			for i := 0; i <= ceiling; i++ {
				certs = append(certs, w.transfer(alice, alice.Persistent(), bob.Persistent(), drops(1_000), uint64(i)))
			}

			// The byte ceiling must not bind first, or this test would pass
			// while the count rule was broken.
			blk, err := w.chain.Propose(w.payout, certs...)
			if err != nil {
				t.Fatal(err)
			}
			if size, limit := blk.SizeBytes(), p.BlockByteLimit(p.SeqGasTargetGenesis); size > limit {
				t.Fatalf("setup: block of %d bytes is over the byte ceiling of %d, so the byte rule "+
					"would reject before the count rule and this test would be vacuous", size, limit)
			}

			_, _, err = w.chain.AddBlock(w.payout, certs...)
			if err == nil {
				t.Fatalf("a block of %d certificates was accepted at a ceiling of %d", len(certs), ceiling)
			}
			if !strings.Contains(err.Error(), "certificates exceeds the ceiling") {
				t.Fatalf("block of %d certificates at a ceiling of %d was rejected as %q, "+
					"want the certificate-count rule", len(certs), ceiling, err)
			}

			// And the ceiling itself is accepted: the rule is >, not >=.
			w2 := newTightWorld(t, &p)
			alice2, bob2 := key(t, 2), key(t, 3)
			w2.fund(alice2.Persistent(), drops(900_000_000))
			atCeiling := make([]*types.Certificate, 0, ceiling)
			for i := 0; i < ceiling; i++ {
				atCeiling = append(atCeiling, w2.transfer(alice2, alice2.Persistent(), bob2.Persistent(), drops(1_000), uint64(i)))
			}
			if _, _, err := w2.chain.AddBlock(w2.payout, atCeiling...); err != nil {
				t.Fatalf("a block of exactly %d certificates was rejected at a ceiling of %d: %v",
					len(atCeiling), ceiling, err)
			}
		})
	}
}
