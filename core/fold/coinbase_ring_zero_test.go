package fold_test

import (
	"testing"

	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/sim/harness"
	"zycord/spec"
	"zycord/wallet"
)

// TestAZeroBlockRewardClearsTheRingEntryInsteadOfNamingItsProducer pins F12's
// zero-reward arm: when producer + Σtips is zero the maturity ring entry is
// cleared to (0, 0) rather than overwritten with (Header.EmissionAddr, 0).
//
// This is a rule and a state root, not a preference. ARCHITECTURE's F12 used
// to specify the overwrite unconditionally, so at any parameter set that can
// produce a zero reward the document and both folds committed different roots
// — measured at treasury_share_bps = 10000 as a013610d… against b36879cd…,
// and at the epoch boundary of height 64 as bf75a8d7… against 9859e2a6…
// The folds are right and the text was wrong; the reason is in
// rollCoinbaseRing's doc comment, and the short form is that the release side
// gates on the AMOUNT, so an address written against a zero amount is a payout
// address standing in consensus state — inside the root, for CoinbaseMaturity
// blocks — against a payment nothing can ever make.
//
// Until this test the arm had no separating input at all: replacing its
// condition with `if false` left core/fold and spec fully green, which
// is what let the disagreement survive.
//
// **The zero arm's route changed when treasury_share_bps was bounded, and the
// arm did not.** This test used to reach a zero reward by setting
// treasury_share_bps to 10000, and said in as many words that a bound on the
// parameter would mean revisiting the test rather than deleting it, "because
// the zero arm stays reachable by F11's burst valve". That bound was taken —
// 10000 makes the producer's share zero on every block, which leaves the
// burst valve nothing to forfeit, so Validate now refuses it — and this is
// the revisit. The zero arm below is driven through F11 instead, at devnet's
// own shipped treasury share of 300, on the same witness
// TestAProducerCanBePaidNothingAtDevnetsOwnTreasuryShare measures. The rule
// under test, and the state roots that separated it, are untouched.
//
// **What holds this and what does not.** sim/refold states the same rule a
// second time and agrees, but the differential runner cannot hold that
// agreement: it drives spec.Devnet() and nothing else
// (sim/differential_test.go), and on devnet the reward is non-zero at every
// height above 0, so neither implementation's zero arm is ever entered.
// **That is distinct from the shared-ceiling finding** and is worth keeping
// distinct: that one measured rules checked by ONE implementation called
// twice; this arm is written twice, independently, and the two agree by never
// being asked. Jointly unexercised, not shared. Same blindness the health
// gate's comparator was found in. So the port lives in
// sim/refold/coinbase_ring_zero_test.go, driven directly, rather than being
// inferred from a green differential.
func TestAZeroBlockRewardClearsTheRingEntryInsteadOfNamingItsProducer(t *testing.T) {
	payout := key(t, 1).Persistent()
	if payout == (types.Address{}) {
		t.Fatal("the payout address is the zero address, so the two arms below write the " +
			"same bytes and this test cannot tell them apart")
	}

	// The zero arm, reached through F11's burst valve at devnet's own treasury
	// share: the forfeiture at exactly 4T takes the producer's whole share and
	// the certificates declare priority 0, so the reward is zero.
	t.Run("a zero reward clears the entry", func(t *testing.T) {
		w, alice, bob := validatedBurstScenario(t)
		b, res := mustApplyBurstBlockAtTheHardBound(t, w, alice, bob)

		if !res.MinerReward.IsZero() {
			t.Fatalf("MinerReward = %s, want zero; the arm is on the wrong side of "+
				"the branch and asserts nothing", res.MinerReward.String())
		}
		if w.payout == (types.Address{}) {
			t.Fatal("the witness pays a zero address, so the cleared cell below and the " +
				"overwrite F12 used to specify write the same bytes")
		}

		index := b.Header.Height % w.p.CoinbaseMaturity
		if addr := w.chain.State.Get(types.PendingCoinbaseAddrSlot(index)); !addr.IsZero() {
			t.Fatalf("a zero reward wrote %s into the ring's address cell; F12 clears "+
				"the entry, and a live address against an absent amount is a payment "+
				"nothing can ever make", addr.String())
		}
		if amount := w.chain.State.Get(types.PendingCoinbaseAmountSlot(index)); !amount.IsZero() {
			t.Fatalf("a zero reward wrote %s into the ring's amount cell", amount.String())
		}
	})

	// The other side of the same branch, at one basis point short of Validate's
	// bound on treasury_share_bps: the producer keeps a remainder, so the entry
	// names it. This is what the cleared arm above is compared against — without
	// it "clears" would be indistinguishable from "never writes".
	t.Run("a non-zero reward names its producer", func(t *testing.T) {
		p := *spec.Devnet()
		p.TreasuryShareBps = 9999

		// A rule pinned at parameters the protocol refuses is pinned at
		// nothing: 9999 is the largest share Validate still admits, and
		// this fails loudly rather than quietly if that ever moves again.
		if err := p.Validate(); err != nil {
			t.Fatalf("treasury_share_bps = %d is not a parameter set params.Validate "+
				"accepts (%v)", p.TreasuryShareBps, err)
		}

		c := harness.MustNew(&p)
		b, res := mustApplyEmptyBlock(t, c, payout)
		if res.MinerReward.IsZero() {
			t.Fatal("the reward is zero at treasury_share_bps = 9999, so this arm is on " +
				"the wrong side of the branch and asserts nothing")
		}

		index := b.Header.Height % p.CoinbaseMaturity
		addr := c.State.Get(types.PendingCoinbaseAddrSlot(index))
		amount := c.State.Get(types.PendingCoinbaseAmountSlot(index))
		if want := u256.FromBytes(payout); !addr.Eq(want) {
			t.Fatalf("a non-zero reward left the ring's address cell at %s, want the "+
				"producer's payout address %s", addr.String(), want.String())
		}
		if !amount.Eq(res.MinerReward) {
			t.Fatalf("the ring holds %s against a reward of %s",
				amount.String(), res.MinerReward.String())
		}
	})
}

// TestAProducerCanBePaidNothingAtDevnetsOwnTreasuryShare is the measurement
// that decides the option taken for F12's zero arm, and it is the one claim
// the whole decision rests on: **bounding treasury_share_bps would not make
// F12's zero arm unreachable**, so the bound cannot remove the question the
// way refusing an out-of-range parameter usually does.
//
// The witness does not touch treasury_share_bps at all — it runs at devnet's
// own shipped 300 — and reaches a zero reward through F11 instead:
//
//   - the burst valve forfeits floor(floor(producer×excess/2T)×excess/2T), and
//     excess == 2T is admitted (B5 rejects seq_gas_USED strictly ABOVE 4T), so
//     at exactly 4T the forfeit is the producer's whole share;
//   - tips are zero whenever the block's certificates declare priority 0,
//     which costs a self-dealing proposer nothing — §21 measures exactly this
//     evasion against the rejected tip-forfeiture variant.
//
// This is an existential and is stated as one (§21): there EXISTS a
// params.Validate-accepted parameter set and a block the fold ACCEPTS at a
// height above 0 whose reward is zero with treasury_share_bps well under
// 10000. It claims nothing about which parameter sets do not admit one, and it
// survives someone finding a cheaper witness.
//
// **The parameter set is one params.Validate accepts, and the test asserts
// that before it asserts anything else.** This package's own standard, stated
// in health_gate_internal_test.go: *"a rule pinned at parameters the protocol
// refuses is pinned at nothing"*. Moving seq_gas_target_genesis alone — which
// is where the 4T block shape comes from — breaks Validate's
// seq_gas_capacity/block_byte_capacity pairing, so this test draws its block
// shape from validatedBurstScenario below, which carries the same 2T = 1800 and
// 4T = 3600 at a set Validate accepts.
func TestAProducerCanBePaidNothingAtDevnetsOwnTreasuryShare(t *testing.T) {
	w, alice, bob := validatedBurstScenario(t)

	if w.p.TreasuryShareBps >= 10000 {
		t.Fatalf("treasury_share_bps is %d here; this witness is only worth anything "+
			"BELOW the bound the zero arm is about", w.p.TreasuryShareBps)
	}
	seqLimit := w.p.SeqGasLimit(900)
	b, res := mustApplyBurstBlockAtTheHardBound(t, w, alice, bob)

	// The premises, each failing loudly rather than quietly making the
	// conclusion vacuous.
	if want := 2 * seqLimit; res.SeqGasUsed != want {
		t.Fatalf("SeqGasUsed = %d, want exactly %d (4T); anywhere below it the forfeiture "+
			"is a fraction and the producer keeps a remainder", res.SeqGasUsed, want)
	}
	subsidy := w.p.Emission(b.Header.Height)
	treasury := subsidy.MulDiv64(w.p.TreasuryShareBps, 10000)
	producer, under := subsidy.Sub(treasury)
	if under || producer.IsZero() {
		t.Fatalf("the producer's share is already zero from the split alone (subsidy %s, "+
			"treasury %s); then this measures the parameter and not the burst valve",
			subsidy.String(), treasury.String())
	}

	if !res.MinerReward.IsZero() {
		t.Fatalf("MinerReward = %s at 4T with zero-priority certificates, want zero: "+
			"either the forfeiture no longer reaches the whole share at the bound, or "+
			"the block earned tips it should not have", res.MinerReward.String())
	}

	// And F12 therefore takes its zero arm, at a treasury share no bound on
	// that parameter would refuse.
	index := b.Header.Height % w.p.CoinbaseMaturity
	if addr := w.chain.State.Get(types.PendingCoinbaseAddrSlot(index)); !addr.IsZero() {
		t.Fatalf("the ring's address cell holds %s after a zero reward", addr.String())
	}
	if amount := w.chain.State.Get(types.PendingCoinbaseAmountSlot(index)); !amount.IsZero() {
		t.Fatalf("the ring's amount cell holds %s after a zero reward", amount.String())
	}
}

// TestEveryShippedNetworkTakesF12sZeroArmAtGenesis states the other half of
// why the zero arm cannot be argued away as unreachable: it is entered by
// block 0 of every chain that has ever run.
//
// Emission(0) is zero unconditionally — "there is no miner to pay, and a
// reproducible genesis must not credit an address" — and checkGenesisShape
// forbids the genesis block certificates, so there are no tips either. No
// parameter influences this, treasury_share_bps included.
//
// The two candidate rules AGREE here, because B10 also forces the genesis
// EmissionAddr to zero, and that is precisely the point: at genesis the arm is
// reached and unobservable, so it can neither be deleted as dead code nor
// pinned by anything at genesis. It has to be written down and pinned above
// height 0, which is what the two tests above do.
func TestEveryShippedNetworkTakesF12sZeroArmAtGenesis(t *testing.T) {
	sets := map[string]*params.Params{
		"mainnet": spec.Mainnet(),
		"testnet": spec.Testnet(),
		"devnet":  spec.Devnet(),
	}
	if len(sets) == 0 {
		t.Fatal("no shipped parameter set was examined")
	}
	for name, p := range sets {
		if !p.Emission(0).IsZero() {
			t.Fatalf("%s pays %s at height 0, so genesis does not take F12's zero arm and "+
				"this test's premise is false for it", name, p.Emission(0).String())
		}
		c := harness.MustNew(p)
		if got := c.Tip().EmissionAddr; got != (types.Address{}) {
			t.Fatalf("%s's genesis block names a payout address (%x); B10 forbids it, and "+
				"without that the two candidate F12 rules would already differ at genesis",
				name, got[:8])
		}
		// Nothing under a non-protocol address, the ring's address cells
		// included: the "no allocations of any kind" §19 promises.
		for _, slot := range c.State.SortedCells() {
			if slot == types.PendingCoinbaseAddrSlot(0) {
				t.Fatalf("%s's genesis state carries a coinbase ring address cell", name)
			}
		}
	}
}

// validatedBurstScenario is the shared burst fixture: a devnet copy whose
// sequential target is small enough that a handful of certificates bind the
// ceilings, so 2T = 1800 and 4T = 3600 — at a parameter set params.Validate
// ACCEPTS. §8.1's three burst-valve tests (TestBurstValve,
// TestBurstForfeitureIsConserved, TestBurstDoesNotRatchetTheBaseFee) draw on it
// too, so the whole of the tree's burst coverage is pinned at a set the
// protocol admits rather than one it refuses.
//
// Moving seq_gas_target_genesis alone does not qualify, and the difference is
// not cosmetic. It breaks Validate's pairing rule: seq_gas_capacity ×
// block_byte_limit_genesis must equal seq_gas_target_genesis ×
// block_byte_capacity, "or whichever binds later stops being priced". Devnet
// ships 5,120,000 × 2,500,000 == 1,600,000 × 8,000,000; with the target alone
// dropped to 900 the right-hand side falls by four orders of magnitude and
// Validate refuses the set. Restoring the pairing takes three more fields,
// all scaled by devnet's own two ratios (capacity/target = 3.2 and
// byte_capacity/byte_limit = 3.2 -- unchanged by the parameter respin, which
// moved devnet's target and capacity together and so left both ratios exactly
// where they were), so the set stays a devnet in proportion and is not a
// different protocol. Validate then adds a fourth: the ceiling decay divisor
// may not exceed the genesis target, so devnet's 1024 comes down with it
// (growth's 512 already clears the tightened 900). None of these divisors
// fires here — every consumer stays inside epoch 0, where T is the genesis
// 900 — so the arithmetic below is untouched.
//
// Why it matters: the claim is about what params.Validate admits. A witness
// drawn from a set Validate refuses would be a witness about nothing — it
// would prove that a bound on treasury_share_bps leaves the arm reachable at
// parameters no operator can ship, which is not the question the zero arm
// asks. The Validate check below is asserted before anything else,
// non-vacuously: revert to the single-field set and it fails loudly.
func validatedBurstScenario(t *testing.T) (*tightWorld, *wallet.Key, *wallet.Key) {
	t.Helper()
	bp := *spec.Devnet()
	bp.SeqGasTargetGenesis = 900
	bp.SeqGasCapacity = 2880 // 3.2 × T0, devnet's own capacity ratio
	bp.BlockByteLimitGenesis = 250_000
	bp.BlockByteCapacity = 800_000 // 3.2 × the byte limit, restoring the pairing
	// Validate refuses a ceiling divisor larger than the genesis target, since the
	// controller's step t/Δ would then floor to zero and the elastic ceiling
	// could never fall. Devnet's decay divisor is 1024, above the tightened
	// target of 900, so it comes down with the target; growth's 512 already
	// clears it. The divisors never fire here — every consumer stays inside
	// epoch 0, where T is the genesis 900 — so this only keeps Validate happy
	// and moves no measured number.
	bp.CeilingDecayDivisor = 512
	// And the parameter respin adds a fifth. This fixture drives the SEQUENTIAL
	// burst valve, so the parallel ceiling must not bind first or the witness
	// stops being a witness about F11 at all: ParGasLimit(T) is par_gas_ratio ×
	// 2T, and the six-certificate block at the 4T bound carries 11,676 parallel
	// gas. Devnet used to ship par_gas_ratio 10, which put that ceiling at
	// 18,000 and out of the way; the respin moved devnet onto mainnet's ratio of
	// 3, which puts it at 5,400 and rejects the block under B6 before F11 is
	// reached. So the ratio is now pinned here rather than inherited, and it is
	// pinned at the value that makes the parallel side inert -- which is exactly
	// what a ratio of 10 was found to be on mainnet, and exactly what this
	// fixture wants of it.
	bp.ParGasRatio = 10

	if err := bp.Validate(); err != nil {
		t.Fatalf("the burst fixture is not a parameter set params.Validate accepts (%v); "+
			"a rule pinned at parameters the protocol refuses is pinned at nothing", err)
	}
	if got, want := bp.SeqGasLimit(900), uint64(1800); got != want {
		t.Fatalf("2T = %d, want %d; the six-certificate arithmetic below is written "+
			"against 1800", got, want)
	}
	if got, want := bp.SeqGasBurst(900), uint64(3600); got != want {
		t.Fatalf("4T = %d, want %d", got, want)
	}

	w := newTightWorld(t, &bp)
	alice, bob := key(t, 2), key(t, 3)
	w.fund(alice.Persistent(), drops(2_000_000_000))
	return w, alice, bob
}

// mustApplyBurstBlockAtTheHardBound folds the one block both zero-reward arms
// rest on: six 600-gas transfers, so included sequential gas is 3600 == 4T ==
// SeqGasBurst, the bound at which F11's forfeiture is the entire producer
// share. The priorities are zero in both markets, so the block credits its
// producer no tips either and the reward is zero without touching
// treasury_share_bps at all.
//
// It is shared rather than written twice because the two callers assert
// different things about the same block — one the ring cells F12 wrote, the
// other that the forfeiture and not the parameter split is what emptied the
// reward — and a second copy could drift into measuring a different block.
func mustApplyBurstBlockAtTheHardBound(t *testing.T, w *tightWorld,
	alice, bob *wallet.Key) (*types.Block, *fold.Result) {
	t.Helper()
	if got := w.currentT(); got != 900 {
		t.Fatalf("T = %d, want the fixture's 900; the ceilings here are computed "+
			"against T and this would be measuring a different block", got)
	}

	certs := make([]*types.Certificate, 6)
	for i := range certs {
		certs[i] = zeroPriorityTransfer(t, w.p, w.chain,
			alice, alice.Persistent(), bob.Persistent(), drops(1_000_000), uint64(i))
	}

	b, err := w.chain.Propose(w.payout, certs...)
	if err != nil {
		t.Fatal(err)
	}
	res, err := w.chain.Apply(b)
	if err != nil {
		t.Fatalf("the 4T block was rejected (%v); the witness needs a block the fold "+
			"ACCEPTS, not one it refuses", err)
	}
	if b.Header.Height == 0 {
		t.Fatal("the block under test is genesis, where the reward is zero for a reason " +
			"that has nothing to do with the burst valve")
	}
	return b, res
}

// mustApplyEmptyBlock folds one certificate-free block onto the tip and
// returns it with its result. Certificate-free matters: it is what makes
// Σtips zero, so the reward is the producer's share alone.
func mustApplyEmptyBlock(t *testing.T, c *harness.Chain, payout types.Address) (*types.Block, *fold.Result) {
	t.Helper()
	b, res, err := c.AddBlock(payout)
	if err != nil {
		t.Fatal(err)
	}
	if b.Header.Height == 0 {
		t.Fatal("the block under test is genesis, where the reward is zero for a reason " +
			"that has nothing to do with the parameter under test")
	}
	return b, res
}

// zeroPriorityTransfer is tightWorld.transfer with the priorities set to zero
// in both markets.
//
// The maxima stay generous — they are a solvency bound and cost nothing (R2-H1)
// — while the priority is what the miner is actually paid, so a certificate
// built here applies, pays its base fee, and contributes nothing to Σtips.
// §21 measures that this is free to the proposer that matters: `market()`
// computes effective = min(priority, headroom), so a proposer authoring its own
// filler traffic is both signer and beneficiary and sets this side to zero.
func zeroPriorityTransfer(t *testing.T, p *params.Params, c *harness.Chain,
	from *wallet.Key, fromAddr, to types.Address, amount u256.U256, seq uint64) *types.Certificate {
	t.Helper()
	b := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, fromAddr, to, amount),
		Seq:     seq,
		TTL:     c.NextHeight() + 10,
		Deposit: wallet.SelfDeposit(fromAddr, fromAddr),
		FeeBid:  wallet.Bid(drops(50_000), u256.Zero, drops(500), u256.Zero),
		Signers: []*wallet.Key{from},
	}
	cert, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	return cert
}
