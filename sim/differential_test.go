package sim_test

import (
	"testing"

	"zycord/core/types"
	"zycord/sim"
	"zycord/spec"
)

// TestDifferentialFold is the release gate for core/fold: two independent
// implementations, one written for speed and one for obviousness, must agree on
// every observable of every block.
//
// Seeds are fixed so that a failure is reproducible from the test output alone.
// The continuous fuzz farm runs the same generator with fresh seeds; this test
// is the part that runs on every commit.
func TestDifferentialFold(t *testing.T) {
	p := spec.Devnet()
	for seed := int64(1); seed <= 8; seed++ {
		t.Run(seedName(seed), func(t *testing.T) {
			r, err := sim.NewRunner(p, seed)
			if err != nil {
				t.Fatalf("seed %d: %v", seed, err)
			}
			for i := 0; i < 120; i++ {
				if err := r.Step(); err != nil {
					t.Fatalf("seed %d, step %d: %v", seed, i, err)
				}
			}
			if r.Rejected == 0 {
				t.Errorf("seed %d never produced a block both implementations rejected; "+
					"the block rules went untested", seed)
			}
			if r.Chain.Height() < 100 {
				t.Errorf("seed %d only reached height %d; the run was mostly rejections",
					seed, r.Chain.Height())
			}
			if r.OneShotFunded == 0 {
				t.Errorf("seed %d never produced a moveless certificate funded from a "+
					"one-shot deposit cell; that class is legal (F-VAL-5) and the "+
					"generator attempts it, so zero means the builder is silently "+
					"discarding every attempt again", seed)
			}
			if r.NamedAssetBurns == 0 {
				t.Errorf("seed %d never burned an address whose certificate also named a "+
					"non-native cell under it; that is the only traffic reaching F8b's "+
					"second clause, and without it deleting the clause from sim/refold "+
					"alone leaves this entire suite green", seed)
			}
			if r.ReSigned == 0 {
				t.Errorf("seed %d never probed a re-signed encoding of an authorization "+
					"the block already carried; wallet.Builder signs deterministically, so "+
					"that input exists in this corpus by no other path, and a run without "+
					"it cannot tell an id over the authorization from an id over the "+
					"bytes", seed)
			}
			if r.ForgedSeedEpoch == 0 {
				t.Errorf("seed %d never probed a forged proof-of-work key epoch; the "+
					"seed-epoch rule is the one rule this generator cannot reach by "+
					"producing honest blocks, so a run that never probes it is a run "+
					"in which core/fold could have dropped the rule entirely and "+
					"still gone green", seed)
			}
		})
	}
}

// TestDifferentialLong is the same check over a longer horizon, so that epoch
// boundaries, seen-set pruning and the maturity ring all wrap at least once.
func TestDifferentialLong(t *testing.T) {
	if testing.Short() {
		t.Skip("long differential run")
	}
	p := spec.Devnet()
	r, err := sim.NewRunner(p, 424242)
	if err != nil {
		t.Fatal(err)
	}
	// Devnet epochs are 64 blocks and the maturity ring is 10, so 400 blocks
	// crosses six epoch boundaries and wraps the ring forty times.
	for i := 0; i < 400; i++ {
		if err := r.Step(); err != nil {
			t.Fatalf("step %d: %v", i, err)
		}
	}
	if r.Chain.Height() < 300 {
		t.Fatalf("only reached height %d", r.Chain.Height())
	}
}

func seedName(seed int64) string {
	return "seed" + string(rune('0'+seed))
}

// TestDifferentialElasticCeiling is the release gate for the code whitepaper
// §8.1 added, and it exists because the gate above cannot reach it.
//
// Under stock devnet parameters the new consensus code is unreachable by the
// fuzzer, and not by luck — by arithmetic. `seq_gas_target_genesis` is
// 1,600,000 — devnet has run mainnet's target since the gas-schedule respin
// that put testnet and devnet on mainnet's fee market, and this paragraph read
// 2,000,000 before it — while the most sequential gas a devnet block can hold
// is a few thousand, so `2·median` never approaches the decay floor `T − T/Δ`:
// the controller clamps T to the floor, the floor clamps to genesis, and T sits
// at its starting value for every seed, forever. The burst valve needs 2T =
// 3,200,000 against blocks carrying thousands. The respin narrowed the gap by a
// fifth and closed nothing: the argument is an order-of-magnitude one, and both
// figures are three orders above what these blocks carry. And a harness that
// never cites produces an empty citation list in both implementations, which
// agree trivially.
//
// So growth, the burst valve's two-floor forfeiture and all six citation rules
// were verified only by hand-written Go tests written separately against each
// implementation — never by the one mechanism whose whole job is catching an
// error *shared* between them. That is not hypothetical: it is exactly how the
// unaccounted burst forfeiture survived (I6-H1), both folds agreeing on the
// same wrong number while the fuzzer stayed correctly silent.
//
// Two parameter changes make the code reachable, and one traffic change makes
// the controller's input non-zero:
//
//   - a small target and a short epoch, so ordinary generated blocks span the
//     ceiling, the burst band and the hard bound;
//   - an aggressive Γ/Δ, so a step that happens is unmistakably a step;
//   - Dense traffic, because the default certificate mix is adversarial by
//     design and more than half of its committed blocks apply nothing at all,
//     which pins the lower median at zero however small the target is made.
//     Rejection coverage is not lost — the citation generator stays
//     adversarial, so both folds must still refuse the same blocks.
//
// The assertions are anti-vacuity checks. Burst and citation coverage is
// asserted per seed because it is reliable; T movement is asserted across the
// suite rather than per seed, because whether a given seed grows depends on
// whether its tips apply or skip — a block can burst on included gas while
// applying almost none — and demanding it of every seed would be asserting a
// property of the traffic generator rather than of the fold.
func TestDifferentialElasticCeiling(t *testing.T) {
	p := *spec.Devnet()
	p.SeqGasTargetGenesis = 1_000 // 2T = 2,000 and 4T = 4,000
	p.EpochLength = 16            // frequent boundaries, so the controller runs often
	p.CoinbaseMaturity = 8        // the ring must wrap inside an epoch
	p.CeilingGrowthDivisor = 4    // aggressive on purpose: a visible step, not +1
	p.CeilingDecayDivisor = 4
	// Tuned so all three arms of the controller run: low enough that the
	// citation rate crosses it sometimes (the `hi = t` withheld-growth branch,
	// which is the entire subject of §8.1's health gate and is dead code at
	// the stock 200 bps against this run's citation rate), high enough that it
	// does not veto every epoch and leave growth itself unexercised.
	p.HealthGateBps = 1_500
	// The parallel ceiling must not be the binding one, for the same reason the
	// target is tightened rather than the block filled: ParGasLimit(T) is
	// par_gas_ratio x 2T, so at this T0 mainnet's re-derived ratio of 3 caps a
	// block at 6,000 parallel gas -- a couple of transfers -- and the dense
	// generator can no longer put enough applied gas in a block to move the
	// median. That reports as "the growth arm went undifferentiated", which would
	// be a statement about this fixture and not about either fold. Devnet carries
	// mainnet's ratio of 3, so this run pins 10 explicitly rather than inheriting
	// a shipped value that would silence the arm.
	p.ParGasRatio = 10
	// The clamp under test elsewhere, kept in proportion so this run exercises
	// the controller rather than the capacity wall.
	p.SeqGasCapacity = p.SeqGasTargetGenesis *
		uint64(p.BlockByteCapacity) / uint64(p.BlockByteLimitGenesis)

	var grew, decayed, withheld int
	for seed := int64(1); seed <= 6; seed++ {
		t.Run(seedName(seed), func(t *testing.T) {
			r, err := sim.NewRunner(&p, seed)
			if err != nil {
				t.Fatalf("seed %d: %v", seed, err)
			}
			r.Dense = true
			start, _ := r.Chain.State.Get(types.SeqGasTargetSlot()).Uint64()
			for i := 0; i < 300; i++ {
				if err := r.Step(); err != nil {
					t.Fatalf("seed %d, step %d: %v", seed, i, err)
				}
			}
			end, _ := r.Chain.State.Get(types.SeqGasTargetSlot()).Uint64()
			grew += r.Grew
			decayed += r.Decayed
			withheld += r.GateWithheld
			t.Logf("seed %d: height=%d T %d->%d grew=%d decayed=%d withheld=%d burst=%d cited=%d rejected=%d",
				seed, r.Chain.Height(), start, end,
				r.Grew, r.Decayed, r.GateWithheld, r.Burst, r.Cited, r.Rejected)

			if r.Burst == 0 {
				t.Errorf("seed %d: no committed block exceeded 2T, so the burst valve and its "+
					"forfeiture went undifferentiated", seed)
			}
			if r.Cited == 0 {
				t.Errorf("seed %d: no committed block carried a citation, so checkCites saw only "+
					"empty lists — which agree trivially", seed)
			}
			if r.Rejected == 0 {
				t.Errorf("seed %d: nothing was ever rejected, so the reject paths went "+
					"undifferentiated", seed)
			}
		})
	}
	// Suite-level, because which arm a given seed reaches depends on whether
	// its tips apply or skip — a block can burst on included gas while
	// applying almost none — and demanding all three of every seed would be
	// asserting a property of the traffic generator rather than of the fold.
	// Each is a separate branch of NextSeqGasTarget, and a run that reached
	// only one has left the others agreeing trivially.
	if grew == 0 {
		t.Error("T never grew in any seed: the controller's growth arm went undifferentiated")
	}
	if decayed == 0 {
		t.Error("T never decayed in any seed: the controller's decay arm went undifferentiated")
	}
	if withheld == 0 {
		t.Error("the health gate never withheld growth in any seed: the `hi = t` branch — " +
			"the whole subject of §8.1's health signal — went undifferentiated")
	}
}

// TestNoBurnedAddressHoldsDrops is the consequence of F7b, stated as a law over
// the whole state rather than as an outcome of one certificate.
//
// It exists because one-shot burns are address-scoped while every guard derived
// around them was slot-scoped, which let a certificate destroy value under an
// address it never accounted for.
//
// A one-shot burn is address-scoped, so once F8b empties the native cell as
// the burn lands, four other rules keep it empty: F7 fails every write under a
// spent address, settlement burns a remainder owed to one, the maturity ring
// burns a reward owed to one, and F3 refuses to reserve from one. The
// invariant they add up to is the one this test states.
//
// The law has one stated exception, and it is the branch F8b cannot deliver
// through: a certificate whose Deposit.RefundTo was burned by an *earlier*
// certificate leaves the residual where it is rather than destroying it, so
// that address keeps its drops. The generator does not produce that shape, and
// TestBurnWithADeadRefundAddressStrandsAndAccountsForNothing covers it
// directly; if a future generator starts producing it, this law needs the
// exception written into it rather than the rule changed.
//
// It is run against the adversarial generator rather than a scripted scenario
// because the generator is what produces partial spends, unswept one-shot
// deposits and retires of funded addresses without being asked to.
func TestNoBurnedAddressHoldsDrops(t *testing.T) {
	p := spec.Devnet()
	var burned int
	for seed := int64(1); seed <= 8; seed++ {
		r, err := sim.NewRunner(p, seed)
		if err != nil {
			t.Fatalf("seed %d: %v", seed, err)
		}
		for i := 0; i < 120; i++ {
			if err := r.Step(); err != nil {
				t.Fatalf("seed %d, step %d: %v", seed, i, err)
			}
			for _, a := range r.Chain.State.SortedSpent() {
				if got := r.Chain.State.Get(types.NativeBalanceSlot(a)); !got.IsZero() {
					t.Fatalf("seed %d, height %d: %x is burned and still holds %s drops; "+
						"a certificate destroyed value it never accounted for",
						seed, r.Chain.Height(), a[:6], got.String())
				}
			}
		}
		burned += r.Chain.State.SpentCount()
	}
	if burned == 0 {
		t.Fatal("no address was burned across any seed; the law was never exercised")
	}
	t.Logf("%d burned addresses across 8 seeds, none holding drops", burned)
}
