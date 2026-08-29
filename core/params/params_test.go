package params_test

import (
	"math"
	"math/big"
	"math/bits"
	"reflect"
	"strings"
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/u256"
	"zycord/spec"
)

// paramsCopy is an alias so the negative cases can mutate a copy of the frozen
// set without reaching for a builder that does not exist.
type paramsCopy = params.Params

func parse(raw []byte) (*params.Params, error) { return params.Parse(raw) }

// TestEmissionHalvesEveryTwoYears checks the claim the whitepaper makes in
// words (§14.2) against the integer schedule that implements it. The decay is
// exact integer arithmetic — one part in EMISSION_DECAY_DIVISOR per epoch —
// and the two-year factor is whatever that compounds to, which must be 0.5 to
// within a fraction of a percent.
//
// The measured value comes out a shade above the real-valued curve because the
// per-epoch step is a floored division: rounding the step down decays slightly
// slower than the ideal. That is the schedule, not an error in it — the
// integers are the protocol and the smooth curve is the description.
func TestEmissionHalvesEveryTwoYears(t *testing.T) {
	p := spec.Mainnet()
	blocksPerYear := 365 * 24 * 3600 / p.TargetBlockSeconds

	start := p.Emission(1)
	if !start.Eq(p.GenesisEmission) {
		t.Fatalf("emission at height 1 = %s, want the genesis rate %s",
			start.String(), p.GenesisEmission.String())
	}

	after := p.Emission(2 * blocksPerYear)
	ratio := new(big.Rat).SetFrac(toBig(after), toBig(start))
	want := big.NewRat(1, 2)
	diff := new(big.Rat).Sub(ratio, want)
	diff.Abs(diff)
	if diff.Cmp(big.NewRat(1, 100)) > 0 {
		f, _ := ratio.Float64()
		t.Fatalf("the two-year emission factor is %f, want 0.50", f)
	}
}

// TestTreasurySplitConservesTheSubsidy is the arithmetic the whole treasury
// rests on: the share and the remainder must add back up to what was split.
//
// It is checked at every epoch's rate rather than at one, because the failure
// mode it guards against — computing the producer's share as a second
// independent ratio, so that two floors each round down and a drop falls
// between them — shows up only at rates where the division is inexact.
func TestTreasurySplitConservesTheSubsidy(t *testing.T) {
	p := spec.Mainnet()
	for epoch := uint64(0); ; epoch++ {
		height := epoch * p.EpochLength
		if height == 0 {
			height = 1
		}
		subsidy := p.Emission(height)
		treasury := subsidy.MulDiv64(p.TreasuryShareBps, 10000)
		producer, under := subsidy.Sub(treasury)
		if under {
			t.Fatalf("epoch %d: the treasury share exceeds the subsidy", epoch)
		}
		sum, over := producer.Add(treasury)
		if over || !sum.Eq(subsidy) {
			t.Fatalf("epoch %d: %s + %s = %s, want the subsidy %s",
				epoch, producer.String(), treasury.String(), sum.String(), subsidy.String())
		}
		if subsidy.Eq(p.TailEmission) {
			return // the tail is constant from here on; nothing new to check
		}
	}
}

// TestTreasuryShareIsExactlyThreePercent pins the number itself. The identity
// above holds for any share; this is the one that would notice a parameter
// silently moving.
func TestTreasuryShareIsExactlyThreePercent(t *testing.T) {
	p := spec.Mainnet()
	if p.TreasuryShareBps != 300 {
		t.Fatalf("treasury share = %d bps, want 300", p.TreasuryShareBps)
	}
	subsidy := p.Emission(1)
	got := subsidy.MulDiv64(p.TreasuryShareBps, 10000)
	if want := u256.MustFromDecimal("63000000"); !got.Eq(want) {
		t.Fatalf("treasury share of the genesis subsidy = %s, want %s",
			got.String(), want.String())
	}
}

// TestValidateRefusesATreasuryShareThatDisablesTheBurstValve pins the upper end
// of treasury_share_bps at 9999.
//
// The bound above 10000 was always there — the producer's remainder would
// underflow in the fold. 10000 itself was accepted, and that is the case worth
// a check of its own: the arithmetic is fine and the mechanism is not. F11's
// burst valve forfeits *producer* subsidy; the treasury share is taken first
// from the unreduced subsidy and is never forfeited (§8.1). A share of 10000
// makes the producer's share zero on every block, so the valve has nothing to
// forfeit and B5's hard bound stands alone in the burst band — a safety
// mechanism switched off by a parameter file, with nothing saying so.
//
// Nothing shipped is affected: every set uses 300.
func TestValidateRefusesATreasuryShareThatDisablesTheBurstValve(t *testing.T) {
	base := *spec.Mainnet()
	if base.TreasuryShareBps != 300 {
		t.Fatalf("shipped treasury_share_bps is %d, not 300; this test's premise "+
			"that no shipped set is affected no longer holds", base.TreasuryShareBps)
	}

	// Anti-vacuity for the *reason*, not just the refusal: at 10000 the
	// producer's share really is zero at the genesis subsidy, so the forfeiture
	// below has nothing to reduce. If the split ever stopped working this way
	// the row below would be testing a rule with no mechanism behind it.
	subsidy := base.Emission(1)
	if producer, under := subsidy.Sub(subsidy.MulDiv64(10000, 10000)); under || !producer.Eq(u256.Zero) {
		t.Fatalf("at treasury_share_bps = 10000 the producer's share of the genesis "+
			"subsidy is %s (underflow=%v), not zero; the burst valve would still "+
			"have something to forfeit", producer.String(), under)
	}

	for _, c := range []struct {
		name   string
		bps    uint64
		accept bool
	}{
		{"one below the bound is accepted", 9999, true},
		{"the shipped share is accepted", 300, true},
		{"a zero producer share is refused", 10000, false},
		{"a share above the subsidy is refused", 10001, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := base
			p.TreasuryShareBps = c.bps
			err := p.Validate()
			if c.accept {
				if err != nil {
					t.Fatalf("Validate refused treasury_share_bps %d: %v", c.bps, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate accepted treasury_share_bps %d, under which the "+
					"producer's subsidy share is zero on every block and F11's burst "+
					"forfeiture is a no-op", c.bps)
			}
		})
	}
}

// TestEmissionReachesTheTailAndStays: the tail is perpetual, so the schedule
// must floor rather than pass through zero.
func TestEmissionReachesTheTailAndStays(t *testing.T) {
	p := spec.Mainnet()

	var tailHeight uint64
	for h := uint64(0); h < 40_000_000; h += p.EpochLength {
		if p.Emission(h).Eq(p.TailEmission) {
			tailHeight = h
			break
		}
	}
	if tailHeight == 0 {
		t.Fatal("the emission never reaches the tail")
	}
	for _, h := range []uint64{tailHeight, tailHeight * 2, tailHeight * 10, 1 << 40} {
		if got := p.Emission(h); !got.Eq(p.TailEmission) {
			t.Fatalf("emission at height %d = %s, want the tail %s",
				h, got.String(), p.TailEmission.String())
		}
	}
}

// TestEmissionIsMonotone: the schedule may never rise. A rising emission is an
// unbounded supply promise nobody made.
func TestEmissionIsMonotone(t *testing.T) {
	p := spec.Mainnet()
	prev := p.Emission(1)
	for h := p.EpochLength; h < 6_000_000; h += p.EpochLength {
		got := p.Emission(h)
		if got.Gt(prev) {
			t.Fatalf("emission rose at height %d: %s > %s", h, got.String(), prev.String())
		}
		prev = got
	}
}

// TestGenesisPaysNoCoinbase: block 0 credits nobody, which is what "zero
// premine, zero founder allocation" means at the level of code.
func TestGenesisPaysNoCoinbase(t *testing.T) {
	if !spec.Mainnet().Emission(0).IsZero() {
		t.Fatal("the genesis block pays a coinbase")
	}
}

// TestBaseFeeSteersTowardsTheTarget exercises both directions of the EIP-1559
// update, its floor, and the property that a full block always raises the fee
// by at least one unit.
func TestBaseFeeSteersTowardsTheTarget(t *testing.T) {
	p := spec.Mainnet()
	target := p.SeqGasTargetGenesis
	base := p.InitialSeqBaseFee

	if got := p.NextBaseFee(base, target, target); !got.Eq(base) {
		t.Fatalf("a block exactly on target moved the base fee to %s", got.String())
	}
	if got := p.NextBaseFee(base, p.SeqGasLimit(target), target); !got.Gt(base) {
		t.Fatal("a full block did not raise the base fee")
	}
	if got := p.NextBaseFee(base, 0, target); !got.Lt(base) {
		t.Fatal("an empty block did not lower the base fee")
	}

	// A full block must raise the fee even when the proportional step rounds to
	// zero, or a chain sitting at the floor can be congested for free.
	if got := p.NextBaseFee(u256.One, target+1, target); !got.Gt(u256.One) {
		t.Fatal("a full block at the floor did not raise the base fee")
	}

	// Repeated empty blocks converge. Integer division stops the descent at a
	// small constant rather than at MinBaseFee exactly — the same behaviour
	// EIP-1559 has.
	low := base
	for i := 0; i < 500; i++ {
		next := p.NextBaseFee(low, 0, target)
		if next.Gt(low) {
			t.Fatalf("an empty block raised the base fee from %s to %s", low.String(), next.String())
		}
		low = next
	}
	if !p.NextBaseFee(low, 0, target).Eq(low) {
		t.Fatal("the base fee never settles under an empty chain")
	}

	// What stands here is the resting point, and NOT the floor. The assertion
	// this replaces was `low.Lt(p.MinBaseFee)`, and it was doubly unable to
	// fail: every descending return is MaxOf(·, MinBaseFee), so it is
	// unfalsifiable by construction; and stripping that MaxOf still leaves
	// b − floor(b/8) ≥ 1 = MinBaseFee at all three shipped sets, so the mutant
	// survived core/params, core/fold and the spec vectors alike. An assertion
	// that cannot fail reads as coverage of the floor while pinning nothing,
	// which is worse than an absent one — it is why nobody looked here.
	//
	// The observable claim at this fixture is the resting point itself: the
	// descent halts at the largest fee whose proportional step rounds to zero,
	// which is BaseFeeMaxChangeDenominator − 1, strictly above the floor. That
	// is a magnitude that varies with the parameter set, so it is asserted at
	// the shipped set about the shipped set and claims nothing elsewhere.
	// TestTheBaseFeeFloorStopsTheDescentAtTwoLegalWitnesses pins the floor,
	// where the antecedent is not vacuous.
	rest := u256.FromUint64(p.BaseFeeMaxChangeDenominator - 1)
	if !low.Eq(rest) {
		t.Fatalf("an empty chain rests at %s; the proportional step rounds to zero at "+
			"and below %s, so that is where the descent must halt",
			low.String(), rest.String())
	}
	if !low.Gt(p.MinBaseFee) {
		t.Fatalf("the resting point %s is not above the floor %s, so at this parameter "+
			"set the two are no longer distinguishable and the descent's floor would "+
			"have to be pinned here rather than at a witness", low.String(), p.MinBaseFee.String())
	}
}

// TestTheBaseFeeFloorStopsTheDescentAtTwoLegalWitnesses pins MIN_BASE_FEE
// against NextBaseFee's descent, which no shipped parameter set can exhibit.
//
// **Why a witness is the right instrument.** The floor is quantified over
// MIN_BASE_FEE: "an empty chain's base fee never falls below MIN_BASE_FEE" has
// the same truth value at every parameter set, and a shipped set makes its
// antecedent vacuous rather than making it false. MinBaseFee is 1 and the
// change denominator is 8 on all three networks, so integer division halts the
// descent at 7 — above the floor, which therefore never binds and cannot be
// observed. A legal-but-unshipped set SUPPLIES the antecedent; it does not
// SUBSTITUTE the subject, which is the opposite shape and the defect this form
// exists to avoid — a sweep that swaps the subject proves something about a
// different rule. Other witness-based pins in this tree are the precedent, and
// §21 sanctions the form.
//
// **Two witnesses, because one witness is a fixture.** A conclusion that
// depended on the fixture could not hold at both; both are written down here
// so the next reader can check that rather than trust a run nobody can repeat.
// They differ in the floor, in the change denominator and in both initial
// fees, so they share no arithmetic beyond the rule itself.
//
// Each witness must pass params.Validate — a set the protocol would refuse
// pins nothing — and must separate the two candidate implementations, which is
// asserted rather than assumed: at the floor the unclamped proportional step
// has to be at least one unit, or a fold with no floor at all would rest at
// the same place and the witness would be as vacuous as the shipped set.
func TestTheBaseFeeFloorStopsTheDescentAtTwoLegalWitnesses(t *testing.T) {
	for _, w := range []struct {
		name                                      string
		minBaseFee, denominator, initSeq, initPar uint64
	}{
		{"floor 10 under a denominator of 8", 10, 8, 1000, 10},
		{"floor 4096 under a denominator of 16", 4096, 16, 1_000_000, 4096},
	} {
		t.Run(w.name, func(t *testing.T) {
			p := *spec.Mainnet()
			p.MinBaseFee = u256.FromUint64(w.minBaseFee)
			p.BaseFeeMaxChangeDenominator = w.denominator
			p.InitialSeqBaseFee = u256.FromUint64(w.initSeq)
			p.InitialParBaseFee = u256.FromUint64(w.initPar)
			if err := p.Validate(); err != nil {
				t.Fatalf("this witness is not a set a network could run, so it pins "+
					"nothing about the protocol: %v", err)
			}

			// The witness must separate. Without this the test would pass at
			// the shipped set too, where 1/8 is zero and the floor is
			// indistinguishable from the rounding.
			step, _ := p.MinBaseFee.Div64(p.BaseFeeMaxChangeDenominator)
			if step.IsZero() {
				t.Fatalf("the proportional step at the floor (%s / %d) rounds to zero, so a "+
					"fold with no floor would rest at the floor as well and this witness "+
					"separates nothing", p.MinBaseFee.String(), p.BaseFeeMaxChangeDenominator)
			}

			target := p.SeqGasTargetGenesis

			// An empty chain descends to the floor and stops there — not below
			// it, and not at the rounding constant it would stop at with the
			// floor removed.
			low := p.InitialSeqBaseFee
			settled := false
			for i := 0; i < 10_000; i++ {
				next := p.NextBaseFee(low, 0, target)
				if next.Gt(low) {
					t.Fatalf("an empty block raised the base fee from %s to %s",
						low.String(), next.String())
				}
				if next.Eq(low) {
					settled = true
					break
				}
				low = next
			}
			if !settled {
				t.Fatalf("the base fee had not settled after 10,000 empty blocks (at %s)",
					low.String())
			}
			if !low.Eq(p.MinBaseFee) {
				t.Fatalf("an empty chain rests at %s, want the floor %s",
					low.String(), p.MinBaseFee.String())
			}

			// The same statement one step at a time, so the kill does not
			// depend on the loop: at the floor the proportional step is a whole
			// unit, so only the floor can be returning the floor.
			if got := p.NextBaseFee(p.MinBaseFee, 0, target); !got.Eq(p.MinBaseFee) {
				t.Fatalf("an empty block at the floor moved the base fee to %s, want %s",
					got.String(), p.MinBaseFee.String())
			}

			// And the guard against a benign pass: an implementation that
			// returned MinBaseFee unconditionally, or that had stopped
			// descending at all, would satisfy everything above. At twice the
			// floor the descent is still live and still proportional.
			twice := p.MinBaseFee.SatAdd(p.MinBaseFee)
			got := p.NextBaseFee(twice, 0, target)
			if !got.Lt(twice) || !got.Gt(p.MinBaseFee) {
				t.Fatalf("an empty block at twice the floor returned %s; it must fall below "+
					"%s and stay above %s, or the arms above are not the floor doing the work",
					got.String(), twice.String(), p.MinBaseFee.String())
			}
		})
	}
}

// TestBaseFeeCannotWrap: saturation is deterministic, wrapping is a chain split.
func TestBaseFeeCannotWrap(t *testing.T) {
	p := spec.Mainnet()
	target := p.SeqGasTargetGenesis
	got := p.NextBaseFee(u256.Max, p.SeqGasLimit(target), target)
	if got.Lt(u256.Max.SatSub(u256.One)) {
		t.Fatalf("the base fee wrapped to %s", got.String())
	}
}

// TestValidateRejectsBrokenParameters: a typo in a consensus parameter must not
// be silently accepted.
func TestValidateRejectsBrokenParameters(t *testing.T) {
	cases := map[string]func(p *paramsCopy){
		"zero chain id":      func(p *paramsCopy) { p.ChainID = 0 },
		"even median window": func(p *paramsCopy) { p.MedianTimeBlocks = 10 },
		"free skips":         func(p *paramsCopy) { p.SkipFee = u256.Zero },
		"free fees":          func(p *paramsCopy) { p.MinBaseFee = u256.Zero },
		"tail above genesis": func(p *paramsCopy) { p.TailEmission = p.GenesisEmission.SatAdd(u256.One) },
		"no epoch":           func(p *paramsCopy) { p.EpochLength = 0 },
		"vm before bonds":    func(p *paramsCopy) { p.H1VM = 1 },
		"unset phases":       func(p *paramsCopy) { p.H2PoS = 0 },
		"structural capacity smaller than the genesis ceiling it must clamp": func(p *paramsCopy) {
			p.CertListCapacity = p.MaxCertsPerBlockGenesis - 1
		},
		"byte capacity smaller than the genesis byte ceiling": func(p *paramsCopy) {
			p.BlockByteCapacity = p.BlockByteLimitGenesis - 1
		},
		// Above the pairing point, which the saturating form of the check
		// would wave through: BlockByteLimit clamps, so comparing it to the
		// capacity passes for *every* value at or above the pairing point.
		// A capacity above it is not slack — it puts the gas wall after the
		// byte wall and reinstates the failure the parameter exists to stop.
		"gas capacity above the pairing point": func(p *paramsCopy) {
			p.SeqGasCapacity *= 3
		},
		"gas capacity below the pairing point": func(p *paramsCopy) {
			p.SeqGasCapacity = p.SeqGasTargetGenesis + 1
		},
		"health gate above 100%": func(p *paramsCopy) { p.HealthGateBps = 10001 },
		"no work function":       func(p *paramsCopy) { p.PoWEngine = "" },
		// The lag is slack inside one interval, not a second interval. At the
		// interval the shifted boundary lands exactly on the next unshifted
		// one, and above it the arithmetic skips epochs outright — either way
		// the schedule stops re-keying once per interval, which is the one
		// thing the pair is for.
		"key lag at the interval": func(p *paramsCopy) {
			p.RandomXKeyLag = p.RandomXKeyInterval
		},
		"key lag above the interval": func(p *paramsCopy) {
			p.RandomXKeyLag = p.RandomXKeyInterval + 1
		},
		// The pair is only ever used as the boundary interval+lag, so a pair
		// whose sum is not representable does not name a boundary -- see
		// TestValidateRefusesAKeyScheduleBoundaryThatCannotBeWrittenDown for
		// what the chain computed while it was accepted.
		"key schedule boundary that overflows uint64": func(p *paramsCopy) {
			p.RandomXKeyInterval, p.RandomXKeyLag = math.MaxUint64, 1
		},
		// A chain that starts above its own target ceiling is pinned against
		// the clamp from block 1 (F-PARAM-1).
		"genesis target above the maximum": func(p *paramsCopy) {
			p.MaxTarget = p.GenesisTarget.SatSub(u256.One)
		},
		// At 2^255 and above, BlockWork returns one for every header and
		// accumulated work stops ordering branches — a ceiling there is not a
		// ceiling.
		"maximum target at the point block work collapses": func(p *paramsCopy) {
			p.MaxTarget = u256.MustFromDecimal(
				"57896044618658097711785492504343953926634992332820282019728792003956564819968")
		},
		"maximum target at saturation": func(p *paramsCopy) { p.MaxTarget = u256.Max },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			p := *spec.Mainnet()
			mutate(&p)
			if err := p.Validate(); err == nil {
				t.Fatal("a broken parameter set validated")
			}
		})
	}
}

// TestUnknownFieldsAreRejected: a parameter that nothing reads is a parameter
// somebody thought was doing something.
func TestUnknownFieldsAreRejected(t *testing.T) {
	raw := []byte(`{"name":"x","chain_id":1,"nonsense":true}`)
	if _, err := parse(raw); err == nil {
		t.Fatal("an unknown parameter was accepted")
	}
}

func toBig(u u256.U256) *big.Int {
	b := u.Bytes()
	return new(big.Int).SetBytes(b[:])
}

// TestEveryNumericParameterMustBePositive is the R2-S3 sweep, done by
// reflection so that a parameter added later is covered without anybody
// remembering to cover it.
//
// Zero is never a meaningful value in this file: a zero modulus divides by zero
// inside the fold on every block, a zero denominator does the same in the fee
// update, a zero bound makes an operation unusable, and a zero price makes a
// resource free. One rule, no exceptions, checked mechanically.
func TestEveryNumericParameterMustBePositive(t *testing.T) {
	base := spec.Mainnet()
	v := reflect.ValueOf(base).Elem()
	typ := v.Type()

	checked := 0
	for i := 0; i < typ.NumField(); i++ {
		field := typ.Field(i)
		name := field.Tag.Get("json")
		if name == "" || !field.IsExported() {
			continue
		}
		var zero reflect.Value
		switch v.Field(i).Interface().(type) {
		case uint64:
			zero = reflect.ValueOf(uint64(0))
		case int:
			zero = reflect.ValueOf(0)
		case u256.U256:
			zero = reflect.ValueOf(u256.Zero)
		default:
			continue
		}

		t.Run(name, func(t *testing.T) {
			mutated := *spec.Mainnet()
			reflect.ValueOf(&mutated).Elem().Field(i).Set(zero)
			if err := mutated.Validate(); err == nil {
				t.Fatalf("a parameter set with %s = 0 validated; every numeric "+
					"parameter must be rejected at zero", name)
			}
		})
		checked++
	}

	// A guard against the sweep silently covering nothing.
	if checked < 25 {
		t.Fatalf("the sweep only checked %d parameters; the reflection walk is broken", checked)
	}
}

// TestElasticCeilingDerivation pins the arithmetic of whitepaper §8.1: the
// sequential ceiling is 2T, the burst bound is 4T, the parallel ceiling is a
// fixed multiple of the sequential one, and none of it is zero at the
// genesis target — the base fee and the epoch controller both use these as
// divisors.
func TestElasticCeilingDerivation(t *testing.T) {
	p := spec.Mainnet()
	t0 := p.SeqGasTargetGenesis
	if t0 == 0 {
		t.Fatal("seq_gas_target_genesis is zero, so T never leaves the floor")
	}
	if got, want := p.SeqGasLimit(t0), 2*t0; got != want {
		t.Fatalf("SeqGasLimit(T0) = %d, want 2*T0 = %d", got, want)
	}
	if got, want := p.SeqGasBurst(t0), 4*t0; got != want {
		t.Fatalf("SeqGasBurst(T0) = %d, want 4*T0 = %d", got, want)
	}
	if got, want := p.ParGasLimit(t0), p.ParGasRatio*2*t0; got != want {
		t.Fatalf("ParGasLimit(T0) = %d, want ratio*2*T0 = %d", got, want)
	}
	if p.ParGasTarget(t0) == 0 {
		t.Fatal("ParGasTarget(T0) is zero, so the parallel base fee cannot respond to demand")
	}
	// The dynamic certificate-count ceiling can never exceed the static
	// structural capacity CertRoot's merkle depth is fixed to, at T0 or at
	// any T reachable from it.
	if got := p.MaxCertsPerBlock(t0); got > p.CertListCapacity {
		t.Fatalf("MaxCertsPerBlock(T0) = %d exceeds cert_list_capacity = %d", got, p.CertListCapacity)
	}
	if got := p.MaxCertsPerBlock(t0 * 1_000_000); got > p.CertListCapacity {
		t.Fatalf("MaxCertsPerBlock at a large T = %d exceeds cert_list_capacity = %d", got, p.CertListCapacity)
	}
}

// TestNextSeqGasTargetRespectsItsClamps exercises §8.1's controller directly:
// growth is bounded by Γ, decay by Δ, the floor is never crossed, and an
// unhealthy epoch withholds growth without also forcing decay.
func TestNextSeqGasTargetRespectsItsClamps(t *testing.T) {
	p := spec.Mainnet()
	t0 := p.SeqGasTargetGenesis
	// Comfortably inside the band: above the genesis floor so that clamp does
	// not mask the growth/decay steps this first block of cases isolates, and
	// below SeqGasCapacity so that one does not either. Both end clamps get
	// their own cases below, where masking is the behaviour under test.
	above := 2 * t0

	if got, want := p.NextSeqGasTarget(above, 100*above, true), above+above/p.CeilingGrowthDivisor; got != want {
		t.Fatalf("growth not clamped to T + T/Gamma: got %d, want %d", got, want)
	}
	if got, want := p.NextSeqGasTarget(above, 0, true), above-above/p.CeilingDecayDivisor; got != want {
		t.Fatalf("decay not clamped to T - T/Delta: got %d, want %d", got, want)
	}
	if got := p.NextSeqGasTarget(above, 100*above, false); got != above {
		t.Fatalf("an unhealthy epoch grew: got %d, want T unchanged at %d", got, above)
	}
	if got, want := p.NextSeqGasTarget(above, 0, false), above-above/p.CeilingDecayDivisor; got != want {
		t.Fatalf("an unhealthy epoch blocked decay, not just growth: got %d, want %d", got, want)
	}
	// At the floor itself, decay must not push T below it — even though the
	// decay clamp alone (T0 - T0/Delta) would, which is exactly what makes
	// this case different from the one above rather than redundant with it.
	if got := p.NextSeqGasTarget(t0, 0, true); got != t0 {
		t.Fatalf("T fell below its genesis floor: got %d, floor %d", got, t0)
	}

	// And at the other end, T may not grow past SeqGasCapacity however much
	// demand asks for. That clamp is what keeps the base-fee target inside
	// what a physically full block can deliver once the byte ceiling binds:
	// without it T settles at twice the achievable and the fee market stops
	// pricing anything (see the parameter's own comment).
	atCap := p.SeqGasCapacity
	if got := p.NextSeqGasTarget(atCap, 100*atCap, true); got != atCap {
		t.Fatalf("T grew past its capacity: got %d, capacity %d", got, atCap)
	}
	if got := p.NextSeqGasTarget(atCap-1, 100*atCap, true); got > atCap {
		t.Fatalf("a step from just below the capacity overshot it: got %d", got)
	}
}

// TestSeqGasCapacityPairsWithTheByteCeiling pins the property that makes the
// terminal state as well calibrated as block 0: the sequential target may
// grow exactly as far as the byte ceiling does, so both walls arrive together.
//
// If they arrived at different points, whichever bound later would stop being
// priced — the fee market's target would sit above anything a full block could
// deliver, the base fee would decay to its resting point, and block space
// would ration by priority tip with no burn. Checked here as an identity
// rather than trusted as an arithmetic coincidence.
func TestSeqGasCapacityPairsWithTheByteCeiling(t *testing.T) {
	for _, name := range spec.Networks() {
		p, err := spec.ParamsFor(name)
		if err != nil {
			t.Fatal(err)
		}
		if got := p.BlockByteLimit(p.SeqGasCapacity); got != p.BlockByteCapacity {
			t.Fatalf("%s: at T = seq_gas_capacity (%d) the byte ceiling is %d, not its "+
				"capacity %d: the two walls do not arrive together",
				name, p.SeqGasCapacity, got, p.BlockByteCapacity)
		}
		// The ratio the genesis parameters chose, preserved at the top. Stated
		// as a cross-multiplication so integer division cannot round it away.
		if p.SeqGasCapacity*uint64(p.BlockByteLimitGenesis) !=
			p.SeqGasTargetGenesis*uint64(p.BlockByteCapacity) {
			t.Fatalf("%s: seq_gas_capacity/seq_gas_target_genesis != "+
				"block_byte_capacity/block_byte_limit_genesis; the elastic band is not the "+
				"same width in gas and in bytes", name)
		}
		// The density-independence the pairing buys is an identity, not a
		// sampled result, so it is asserted as one rather than swept: where
		// the clamp does not bite, BlockByteLimit(T)/T is the constant
		// BlockByteLimitGenesis/SeqGasTargetGenesis, and the cross-
		// multiplication above puts both walls exactly on that constant.
		// A full block therefore prices identically against target at the
		// terminal state and at block 0, at *every* density — which is the
		// property, and which three sampled points would understate.
	}
}

// TestElasticCeilingsAreStructurallyBounded pins the two clamps that keep an
// unbounded controller from producing a block nothing can carry.
//
// The certificate clamp protects CertRoot's merkle depth; the byte clamp
// protects the transport. The second was missing in the first draft of the
// elastic ceiling, and the consequence was not a rough edge: the byte ceiling
// scales with T, T rises at its maximum rate whenever the fee market is
// working, and the ceiling crossed an 8 MiB frame limit in about 620 epochs
// of ordinary healthy operation — a block every node calls valid and no node
// can send, unfixable after genesis without a hard fork.
//
// Growth is driven here at the maximum clamped rate for far longer than the
// chain could sustain in practice, on purpose: what is being asserted is that
// no reachable T produces an unbounded ceiling, not that a particular T is
// reached.
func TestElasticCeilingsAreStructurallyBounded(t *testing.T) {
	for _, name := range spec.Networks() {
		p, err := spec.ParamsFor(name)
		if err != nil {
			t.Fatal(err)
		}
		target := p.SeqGasTargetGenesis
		for e := 0; e < 20_000; e++ {
			target += target / p.CeilingGrowthDivisor
			if got := p.BlockByteLimit(target); got > p.BlockByteCapacity {
				t.Fatalf("%s epoch %d: BlockByteLimit(%d) = %d exceeds capacity %d",
					name, e, target, got, p.BlockByteCapacity)
			}
			if got := p.MaxCertsPerBlock(target); got > p.CertListCapacity {
				t.Fatalf("%s epoch %d: MaxCertsPerBlock(%d) = %d exceeds capacity %d",
					name, e, target, got, p.CertListCapacity)
			}
		}
		// Anti-vacuity: growth must actually have reached both clamps, or the
		// loop proved nothing about the clamps and only about small numbers.
		if p.BlockByteLimit(target) != p.BlockByteCapacity {
			t.Fatalf("%s: the byte ceiling never reached its clamp; this test is vacuous", name)
		}
		if p.MaxCertsPerBlock(target) != p.CertListCapacity {
			t.Fatalf("%s: the certificate ceiling never reached its clamp; this test is vacuous", name)
		}
	}
}

// TestValidateRefusesAKeyScheduleBoundaryThatCannotBeWrittenDown pins the
// bound as a bound on a *boundary*, not as a bound on a number.
//
// The property: Validate refuses exactly those (interval, lag) pairs for which
// interval+lag is not a uint64, and accepts every pair up to and including the
// largest one that is.
//
// The refusal is not decoration. The accepted pair below was found on a
// consensus function: interval+lag wrapped to 0, pow.SeedEpochFor's underflow
// guard was therefore never taken, and genesis -- the one height that carries
// no proof of work -- was assigned a different key epoch from every other
// height on the chain. The assertion here is that the wrapped boundary gives a
// *different answer* in this test's own scenario than the true one does, so
// the row above cannot be a rule nobody can violate: with the reordered guard
// in pow.SeedEpochFor the function is total on its own, and this bound is what
// makes the pair unrepresentable rather than merely survivable.
func TestValidateRefusesAKeyScheduleBoundaryThatCannotBeWrittenDown(t *testing.T) {
	for _, c := range []struct {
		name     string
		interval uint64
		lag      uint64
		want     bool
	}{
		{"mainnet", 2048, 64, true},
		{"the largest boundary that fits", math.MaxUint64 - 1, 1, true},
		{"the largest boundary that fits, with a large lag", math.MaxUint64 - (1 << 32), 1 << 32, true},
		{"one past it", math.MaxUint64, 1, false},
		{"one past it, with a large lag", math.MaxUint64 - (1 << 32) + 1, 1 << 32, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := *spec.Mainnet()
			p.RandomXKeyInterval, p.RandomXKeyLag = c.interval, c.lag
			err := p.Validate()
			if got := err == nil; got != c.want {
				t.Fatalf("Validate accepted=%v, want %v (err %v)", got, c.want, err)
			}
			if c.want {
				return
			}
			// What the refusal is for: the boundary this pair names is not the
			// one it computes. Asserted here rather than left to the comment,
			// because a bound whose consequence is not observable in the test
			// that installs it is a bound nobody can tell is load-bearing.
			if c.interval+c.lag >= c.interval {
				t.Fatalf("the refused pair %d/%d does not actually wrap; this row asserts nothing",
					c.interval, c.lag)
			}
			// And the guard inside the function holds independently of this
			// bound: genesis is in epoch 0 even for the pair Validate refuses.
			if e := pow.SeedEpochFor(0, &p); e != 0 {
				t.Fatalf("genesis reports key epoch %d under the refused pair, want 0", e)
			}
		})
	}
}

// TestValidateRefusesACapacityWhoseDerivedCeilingsDoNotFit is that
// wrapped-boundary sweep carried past the key schedule into the other place a
// Validate rule is itself an arithmetic: the seq_gas_capacity /
// block_byte_capacity pairing.
//
// The property: Validate refuses a parameter set in which the pairing identity
// only holds modulo 2^64, or in which a ceiling derived from the capacity is
// not representable at that capacity.
//
// Found by mutating that sweep outward rather than by reading: the pairing
// was compared as two uint64 products, and seq_gas_capacity = 2^63+2000 with
// block_byte_limit_genesis = 2, seq_gas_target_genesis = 1000 and
// block_byte_capacity = 4 satisfies it exactly — both sides wrap to 4000. The
// set Validate accepted put SeqGasLimit(T) at 4000 gas for T = 9.2e18: the
// sequential market stops pricing, which is precisely the state seq_gas_capacity
// is documented as existing to prevent. Same class as the wrapped key-schedule
// boundary, one rule over.
func TestValidateRefusesACapacityWhoseDerivedCeilingsDoNotFit(t *testing.T) {
	// The row that pins the 128-bit comparison, and the only row that can:
	// the first draft of this test used a witness whose capacity was also
	// unrepresentable, so the representability rule refused it before the
	// pairing rule ever ran and `if lhsLo != rhsLo` (the high words dropped)
	// survived the whole file. This witness is chosen against that mutant --
	// the capacity is comfortably representable, every other Validate rule
	// passes, and the products differ by a factor of two while agreeing in
	// every bit a uint64 keeps.
	t.Run("a pairing that only holds modulo 2^64", func(t *testing.T) {
		p := *spec.Mainnet()
		p.SeqGasTargetGenesis, p.SeqGasCapacity = 1<<59, 1<<59
		p.BlockByteLimitGenesis, p.BlockByteCapacity = 32, 64
		// Anti-vacuity 1: the 64-bit comparison this replaced does accept it.
		if p.SeqGasCapacity*uint64(p.BlockByteLimitGenesis) !=
			p.SeqGasTargetGenesis*uint64(p.BlockByteCapacity) {
			t.Fatal("the wrapped pairing no longer holds; this row asserts nothing")
		}
		// Anti-vacuity 2: the ratios really are different, so what the low
		// words agree on is an accident and not the pairing.
		if uint64(p.BlockByteCapacity)/uint64(p.BlockByteLimitGenesis) == 1 {
			t.Fatal("the two ratios are equal; this row asserts nothing")
		}
		// Anti-vacuity 3: no earlier rule may reach this set first, or the
		// high-word comparison is untested and the test says so instead.
		if p.SeqGasCapacity > math.MaxUint64/(2*p.ParGasRatio) {
			t.Fatal("the representability rule pre-empts this row; it asserts nothing")
		}
		if err := p.Validate(); err == nil {
			t.Fatal("Validate accepted a pairing that holds only modulo 2^64")
		} else if !strings.Contains(err.Error(), "not paired") {
			t.Fatalf("refused by the wrong rule, so the pairing is still unpinned: %v", err)
		}
	})
	// par_gas_ratio bounds itself before it is used to bound the capacity.
	// Not an equivalent mutant of the capacity rule: at this value 2*ratio
	// wraps to 8, so deleting this check makes the capacity bound MaxUint64/8
	// -- permissive, in the direction the rule exists to close.
	t.Run("a par_gas_ratio whose own doubling wraps", func(t *testing.T) {
		p := *spec.Mainnet()
		p.ParGasRatio = 1<<63 + 4
		if w := 2 * p.ParGasRatio; w != 8 {
			t.Fatalf("2*par_gas_ratio = %d, want the wrapped 8; this row asserts nothing", w)
		}
		if err := p.Validate(); err == nil {
			t.Fatalf("Validate accepted par_gas_ratio %d, so the capacity bound it "+
				"feeds is MaxUint64/8 = %d instead of MaxUint64/(2*%d); a capacity "+
				"anywhere under that wraps ParGasLimit and is admitted",
				p.ParGasRatio, uint64(math.MaxUint64)/8, p.ParGasRatio)
		} else if !strings.Contains(err.Error(), "par_gas_ratio") {
			t.Fatalf("refused by the wrong rule: %v", err)
		}
	})
	t.Run("a capacity whose burst bound does not fit", func(t *testing.T) {
		p := *spec.Mainnet()
		// Paired exactly in 128 bits, so only the representability rule can
		// refuse this one.
		p.BlockByteLimitGenesis, p.BlockByteCapacity = 1, 1
		p.SeqGasTargetGenesis = math.MaxUint64 / 4
		p.SeqGasCapacity = math.MaxUint64 / 4
		if err := p.Validate(); err == nil {
			t.Fatalf("Validate accepted seq_gas_capacity %d: ParGasLimit there is %d",
				p.SeqGasCapacity, p.ParGasLimit(p.SeqGasCapacity))
		}
	})
	t.Run("every shipped network still validates", func(t *testing.T) {
		for _, name := range spec.Networks() {
			p, err := spec.ParamsFor(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
	})
}

// TestValidatePairsCertListCapacityUpward pins the count ceiling's half of
// the pairing: Validate must refuse a parameter set in which
// MaxCertsPerBlock's structural clamp to cert_list_capacity can bind at some
// T <= seq_gas_capacity, mirroring the byte pairing one rule above.
//
// The asymmetry this closes was real and unwatched. cert_list_capacity is
// frozen for the life of the chain -- it fixes CertRoot's merkle width, so no
// era boundary can re-pin it -- while the scaled count ceiling grows with every
// era re-pin of seq_gas_capacity, and nothing in Validate looked at the new
// pair. The rule converts that into a refusal at the moment such a set would be
// chosen.
//
// The direction is >= and not ==: the capacity is deliberately oversized, so
// headroom must stay legal and only the binding regime is refused.
func TestValidatePairsCertListCapacityUpward(t *testing.T) {
	// The boundary, at the shipped mainnet genesis ratio of
	// seq_gas_capacity/seq_gas_target_genesis = 3.2: the scaled ceiling at the
	// capacity is 4000 * 3.2 = 12,800, so 12,800 is the least capacity under
	// which the clamp never binds and 12,799 is the greatest under which it does.
	base := *spec.Mainnet()
	const (
		boundary = 12800
		shipped  = 1 << 25
	)
	// Anti-vacuity: the boundary is recomputed from the shipped set's own
	// numbers, so a change to any of the three fails here with the recomputed
	// figure instead of silently moving what the rows below test.
	if got := uint64(base.MaxCertsPerBlockGenesis) * base.SeqGasCapacity / base.SeqGasTargetGenesis; got != boundary {
		t.Fatalf("the mainnet count ceiling at the capacity is %d, not the %d these rows assume", got, boundary)
	}
	if base.CertListCapacity != shipped {
		t.Fatalf("shipped cert_list_capacity is %d, not %d", base.CertListCapacity, shipped)
	}

	for _, c := range []struct {
		name     string
		capacity int
		accept   bool
	}{
		{"one below the pairing point is refused", boundary - 1, false},
		{"the pairing point itself is accepted", boundary, true},
		{"the shipped oversized capacity is accepted", shipped, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := base
			p.CertListCapacity = c.capacity
			// Anti-vacuity: the pre-existing lower bound (cert_list_capacity >=
			// max_certs_per_block_genesis) must not be what decides any row, or
			// the new rule is untested and this says so instead.
			if p.CertListCapacity < p.MaxCertsPerBlockGenesis {
				t.Fatalf("the lower bound pre-empts this row at capacity %d; it asserts nothing", c.capacity)
			}
			err := p.Validate()
			if c.accept {
				if err != nil {
					t.Fatalf("Validate refused cert_list_capacity %d: %v", c.capacity, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("Validate accepted cert_list_capacity %d, under which "+
					"MaxCertsPerBlock clamps at T=%d (scaled %d) while the byte and gas "+
					"ceilings are still tracking T",
					c.capacity, p.SeqGasCapacity,
					uint64(p.MaxCertsPerBlockGenesis)*p.SeqGasCapacity/p.SeqGasTargetGenesis)
			}
			if !strings.Contains(err.Error(), "cert_list_capacity") ||
				!strings.Contains(err.Error(), "not paired") {
				t.Fatalf("refused by the wrong rule, so the count pairing is still unpinned: %v", err)
			}
		})
	}

	// The consequence the rule exists for, asserted directly rather than left to
	// the comment: under an accepted set the clamp is inert across the whole
	// domain, and under the refused one it is not. Without this row every case
	// above could pass with the rule pointed at the wrong quantity.
	t.Run("the clamp is inert across the domain exactly when the set is accepted", func(t *testing.T) {
		for _, c := range []struct {
			capacity  int
			wantBinds bool
		}{{boundary - 1, true}, {boundary, false}, {shipped, false}} {
			p := base
			p.CertListCapacity = c.capacity
			binds := p.MaxCertsPerBlock(p.SeqGasCapacity) == c.capacity &&
				uint64(p.MaxCertsPerBlockGenesis)*p.SeqGasCapacity/p.SeqGasTargetGenesis > uint64(c.capacity)
			if binds != c.wantBinds {
				t.Fatalf("at cert_list_capacity %d the clamp binds=%v at T=%d, want %v",
					c.capacity, binds, p.SeqGasCapacity, c.wantBinds)
			}
			if err := p.Validate(); (err == nil) == c.wantBinds {
				t.Fatalf("at cert_list_capacity %d Validate and the clamp disagree (err=%v, binds=%v)",
					c.capacity, err, c.wantBinds)
			}
		}
	})

	// The 128-bit half, and the only row that can pin it: a pair whose products
	// agree in every bit a uint64 keeps while the true products differ by a
	// factor of two, so a 64-bit comparison accepts a set in which the count
	// clamp is pinned from block 0's own target upward. Same class as the wrapped
	// key-schedule boundary.
	t.Run("a count pairing that only holds modulo 2^64", func(t *testing.T) {
		p := *spec.Mainnet()
		// Keep the byte pairing exact in 128 bits so the rule above cannot be
		// what refuses, and keep the capacity representable so the
		// representability bound cannot be either.
		p.BlockByteLimitGenesis, p.BlockByteCapacity = 1, 2
		p.SeqGasTargetGenesis, p.SeqGasCapacity = 1<<59, 1<<60
		p.MaxCertsPerBlockGenesis, p.CertListCapacity = 32, 32
		// lhs = 32 * 2^59 = 2^64 and rhs = 32 * 2^60 = 2^65: both low words are
		// zero, so a 64-bit >= comparison passes on an off-by-a-factor-of-two.
		if uint64(p.CertListCapacity)*p.SeqGasTargetGenesis !=
			uint64(p.MaxCertsPerBlockGenesis)*p.SeqGasCapacity {
			t.Fatal("the wrapped products no longer agree; this row asserts nothing")
		}
		if p.SeqGasCapacity > math.MaxUint64/(2*p.ParGasRatio) {
			t.Fatal("the representability rule pre-empts this row; it asserts nothing")
		}
		if err := p.Validate(); err == nil {
			t.Fatal("Validate accepted a count pairing that holds only modulo 2^64")
		} else if !strings.Contains(err.Error(), "cert_list_capacity") ||
			!strings.Contains(err.Error(), "not paired") {
			t.Fatalf("refused by the wrong rule, so the high word is still unpinned: %v", err)
		}
	})

	// The other side of the 128-bit comparison, and the row that pins its shape
	// rather than its width: a set with enormous headroom whose LOW words point
	// the wrong way. lhs = 2^25 x 2^59 = 2^84 has low word zero; rhs = 3 x 2^59
	// fits in 64 bits entirely. The set must be accepted -- the capacity is
	// 2^59/3 times the scaled ceiling at the top of the domain -- and a
	// comparison written `hi < hi || lo < lo`, which is the natural typo and
	// which every other row here tolerates, refuses it.
	t.Run("headroom whose low words point the wrong way is accepted", func(t *testing.T) {
		p := *spec.Mainnet()
		p.SeqGasTargetGenesis, p.SeqGasCapacity = 1<<59, 1<<59
		p.BlockByteCapacity = p.BlockByteLimitGenesis
		p.MaxCertsPerBlockGenesis = 3
		hi, lo := bits.Mul64(uint64(p.CertListCapacity), p.SeqGasTargetGenesis)
		rHi, rLo := bits.Mul64(uint64(p.MaxCertsPerBlockGenesis), p.SeqGasCapacity)
		if !(hi > rHi && lo < rLo) {
			t.Fatalf("the products are (%d,%d) and (%d,%d); this row needs a greater high "+
				"word with a smaller low word and asserts nothing otherwise", hi, lo, rHi, rLo)
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("Validate refused a set with 2^59/3 of count headroom: %v", err)
		}
	})
}

// TestValidateRefusesTwoFreezeUnsafeControllerValues pins the two guards that
// keep §8.1's elastic-ceiling controller (NextSeqGasTarget) from being frozen
// by a parameter value Validate would otherwise accept. Both are
// freeze-unsafe values Validate accepts today: the embedded sets are safe,
// the guard only catches a value nobody should freeze the chain with, and the
// direction is declared before the assertion -- the three shipped sets must
// keep passing, a capacity in the 2*median wrap window must be refused, and a
// divisor that floors the controller's step to zero must be refused.
func TestValidateRefusesTwoFreezeUnsafeControllerValues(t *testing.T) {
	// (a) The guard that decides everything: the three embedded sets still pass.
	// Stated first, and separately from the "every shipped network still
	// validates" row of the capacity test, because a freeze guard that rejected
	// a live network would be worse than the hole it closes.
	t.Run("the three embedded sets still validate", func(t *testing.T) {
		for _, name := range spec.Networks() {
			p, err := spec.ParamsFor(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("%s was rejected by a freeze guard: %v", name, err)
			}
		}
	})

	// (b) Guard 1 -- the 2*median term. NextSeqGasTarget is fed 2*median as a
	// plain uint64; median is a sample of applied sequential gas, at most
	// SeqGasBurst(T) = 4T <= 4*seq_gas_capacity, so 2*median reaches
	// 8*seq_gas_capacity. The representability line proves 4T and 6T but not the
	// 8T this term needs unless the floor is 8.
	//
	// Rule 27 -- the rival hypothesis, stated and then falsified: "the
	// cross-multiplication pairing already excludes this window, so Guard 1 is
	// redundant." It does not. The pairing is a ratio constraint on
	// (seq_gas_capacity : seq_gas_target_genesis) == (block_byte_capacity :
	// block_byte_limit_genesis); it fixes no magnitude. This witness satisfies
	// the pairing exactly (2^61 * 1 == 2^60 * 2) and still sits in the wrap
	// window, so the pairing accepts what Guard 1 must refuse. Guard 1 is not
	// redundant, and this row is where that is shown rather than asserted.
	t.Run("a capacity in the 2*median wrap window is refused", func(t *testing.T) {
		p := *spec.Mainnet()
		p.SeqGasTargetGenesis = 1 << 60
		p.SeqGasCapacity = 1 << 61
		p.BlockByteLimitGenesis, p.BlockByteCapacity = 1, 2

		// Anti-vacuity 1: the pre-fix bound (widest = max(4, 2*par_gas_ratio) = 6
		// at mainnet's par_gas_ratio of 3) accepts this capacity, so the row
		// exercises the change from 4 to 8 rather than a bound both versions
		// share.
		if p.SeqGasCapacity > math.MaxUint64/6 {
			t.Fatal("the pre-fix bound already refused this capacity; the row asserts nothing")
		}
		// Anti-vacuity 2: the post-fix bound refuses it -- 2*median = 8*capacity
		// does not fit in a uint64, which is the whole point.
		if p.SeqGasCapacity <= math.MaxUint64/8 {
			t.Fatal("this capacity fits under MaxUint64/8; it is not in the wrap window")
		}
		// Anti-vacuity 3 (rule 27): the pairing this capacity would have to fail
		// for the rival hypothesis to hold actually holds, so the pairing does
		// not exclude the window and Guard 1 is not redundant.
		lhs := p.SeqGasCapacity * uint64(p.BlockByteLimitGenesis)
		rhs := p.SeqGasTargetGenesis * uint64(p.BlockByteCapacity)
		if lhs != rhs {
			t.Fatalf("the pairing does not hold for this witness (%d vs %d); pick one that "+
				"does, or the rival hypothesis is untested", lhs, rhs)
		}

		if err := p.Validate(); err == nil {
			t.Fatal("Validate accepted a capacity whose 2*median input wraps uint64")
		} else if !strings.Contains(err.Error(), "do not fit") {
			t.Fatalf("refused by the wrong rule, so the 2*median window is still open: %v", err)
		}
	})

	// (c) Guard 2 -- a divisor that freezes the step. Both divisors are used as
	// t/divisor (floor). A divisor above the smallest T the controller admits
	// (seq_gas_target_genesis, its permanent floor) makes that step zero, and
	// NextSeqGasTarget returns t unchanged forever. The boundary is pinned in
	// both directions: divisor == T0 leaves a one-unit step and validates;
	// divisor == T0+1 floors the step to zero and is refused.
	t.Run("a growth divisor that freezes the ceiling is refused", func(t *testing.T) {
		p := *spec.Mainnet()
		t0 := p.SeqGasTargetGenesis
		p.CeilingGrowthDivisor = t0 + 1

		// Anti-vacuity: the step really does floor to zero and the controller
		// really does freeze at the genesis floor for a maximal-demand epoch.
		if t0/p.CeilingGrowthDivisor != 0 {
			t.Fatal("the growth step is non-zero here; this row does not exercise the freeze")
		}
		if got := p.NextSeqGasTarget(t0, math.MaxUint64, true); got != t0 {
			t.Fatalf("NextSeqGasTarget grew to %d despite a zero step; the witness is wrong", got)
		}
		if err := p.Validate(); err == nil {
			t.Fatal("Validate accepted a ceiling_growth_divisor that freezes the elastic ceiling")
		} else if !strings.Contains(err.Error(), "ceiling_growth_divisor") {
			t.Fatalf("refused by the wrong rule: %v", err)
		}

		// The boundary: divisor == T0 is the largest value that still moves T,
		// and it must validate, or the guard is off by one against a live set.
		p.CeilingGrowthDivisor = t0
		if t0/p.CeilingGrowthDivisor != 1 {
			t.Fatal("the boundary step is not one unit; the boundary is mis-stated")
		}
		if err := p.Validate(); err != nil {
			t.Fatalf("Validate refused ceiling_growth_divisor == seq_gas_target_genesis, "+
				"which still steps by one: %v", err)
		}
	})

	t.Run("a decay divisor that freezes the ceiling is refused", func(t *testing.T) {
		p := *spec.Mainnet()
		t0 := p.SeqGasTargetGenesis
		p.CeilingDecayDivisor = t0 + 1

		if t0/p.CeilingDecayDivisor != 0 {
			t.Fatal("the decay step is non-zero here; this row does not exercise the freeze")
		}
		if err := p.Validate(); err == nil {
			t.Fatal("Validate accepted a ceiling_decay_divisor that freezes the elastic ceiling")
		} else if !strings.Contains(err.Error(), "ceiling_decay_divisor") {
			t.Fatalf("refused by the wrong rule: %v", err)
		}

		p.CeilingDecayDivisor = t0
		if err := p.Validate(); err != nil {
			t.Fatalf("Validate refused ceiling_decay_divisor == seq_gas_target_genesis, "+
				"which still steps by one: %v", err)
		}
	})
}

// decayEpochs re-derives the length of the emission schedule from the published
// recurrence (E(n) = max(tail, E(n-1) - E(n-1)/divisor), the one-unit floor
// included) using only exported arithmetic, and gives up at limit. It exists so
// each row below asserts why it is on the side of the bound it is on, rather
// than only that Validate agreed with it -- Validate's own answer is the thing
// under test and cannot also be the justification for it.
func decayEpochs(p *params.Params, limit int) int {
	e := p.GenesisEmission
	n := 1
	for e.Gt(p.TailEmission) {
		if n >= limit {
			return n
		}
		step, _ := e.Div64(p.EmissionDecayDivisor)
		if step.IsZero() {
			step = u256.One
		}
		e = e.SatSub(step)
		if e.Lt(p.TailEmission) {
			e = p.TailEmission
		}
		n++
	}
	return n
}

// TestValidateRefusesAnEmissionScheduleItCannotBuild is that wrapped-boundary
// sweep carried into the one Validate rule that is not a comparison but a
// walk: the unconditional buildEmissionTable at the end of Validate.
//
// The property: Validate refuses a parameter set whose emission schedule it
// cannot build, instead of building it. Termination was the property
// buildEmissionTable's comment claimed and it is not the property that was
// needed -- emission_decay_divisor was bounded only from below, and once it
// exceeds the emission every step is the forced one-unit step, so the walk runs
// GenesisEmission-TailEmission times. At the shipped mainnet numbers that is
// ~2.07e9 iterations and a ~2.07e9-element slice: Validate, whose job is to
// refuse a parameter file rather than run it, was instead run by it.
//
// maxEmissionEpochs is unexported; 1<<20 is written out here on purpose. The
// boundary pair below is what keeps the two in step: raise the constant and the
// refused row starts being accepted, lower it and the accepted row starts being
// refused. Either way this test fails rather than quietly asserting nothing.
func TestValidateRefusesAnEmissionScheduleItCannotBuild(t *testing.T) {
	const bound = 1 << 20
	for _, c := range []struct {
		name    string
		divisor uint64
		want    bool
	}{
		{"the shipped divisor", 1054, true},
		{"the largest divisor whose schedule fits", 252246, true},
		{"one past it", 252247, false},
		// The witness from the issue: unbounded, this divisor makes Validate
		// walk ~2.07e9 epochs and it does not return within two minutes.
		{"a divisor above the emission itself", 1 << 62, false},
	} {
		t.Run(c.name, func(t *testing.T) {
			p := *spec.Mainnet()
			p.EmissionDecayDivisor = c.divisor
			// The independent reason this row belongs on its side of the
			// bound, computed before Validate is consulted.
			n := decayEpochs(&p, bound+1)
			if fits := n <= bound; fits != c.want {
				t.Fatalf("divisor %d needs %d epochs (limit %d), so this row is on the "+
					"wrong side of the bound and asserts nothing", c.divisor, n, bound)
			}
			err := p.Validate()
			if got := err == nil; got != c.want {
				t.Fatalf("Validate accepted=%v, want %v (schedule is %d epochs, err %v)",
					got, c.want, n, err)
			}
			if !c.want {
				return
			}
			// An accepted set must carry a schedule that actually reaches the
			// tail, not a prefix of a walk that was cut off and installed
			// anyway: the entry before the last is still above the tail, and
			// the last one is the tail.
			if e := p.Emission(uint64(n-2) * p.EpochLength); !e.Gt(p.TailEmission) {
				t.Fatalf("divisor %d: emission at epoch %d is already the tail", c.divisor, n-2)
			}
			if e := p.Emission(uint64(n-1) * p.EpochLength); e != p.TailEmission {
				t.Fatalf("divisor %d: emission at epoch %d is %s, want the tail %s",
					c.divisor, n-1, e.String(), p.TailEmission.String())
			}
		})
	}
	// The comparison AT the bound -- `len(table) >= maxEmissionEpochs`, not `>`
	// -- needs its own pair, and the divisor axis cannot supply one: adjacent
	// divisors jump the length by four either side of the bound (252246 gives
	// 1,048,575, 252247 gives 1,048,579), so no divisor lands on the operator.
	// Sweeping that axis alone concludes the operator is unreachable, and this
	// test recorded exactly that until the emission pair was looked at. Once the
	// proportional step floors at one unit the length is precisely
	// genesis_emission - tail_emission + 1, so the pair dials any length at all,
	// including both sides of the comparison. An unreachability claim has to
	// enumerate every input feeding the expression, not the one under discussion.
	t.Run("the bound's comparison is pinned by the emission pair", func(t *testing.T) {
		for _, c := range []struct {
			name   string
			length int
			want   bool
		}{
			{"a schedule of exactly maxEmissionEpochs entries", bound, true},
			{"one entry longer", bound + 1, false},
		} {
			t.Run(c.name, func(t *testing.T) {
				p := *spec.Mainnet()
				// A divisor above the emission makes every step the forced
				// one-unit step, so the schedule is the gap plus the genesis
				// entry and the length is chosen exactly.
				p.EmissionDecayDivisor = 1 << 62
				p.GenesisEmission = p.TailEmission.SatAdd(u256.FromUint64(uint64(c.length - 1)))
				if step, _ := p.GenesisEmission.Div64(p.EmissionDecayDivisor); !step.IsZero() {
					t.Fatalf("the proportional step is %s, not zero, so the length is not "+
						"the emission gap and this row does not sit where it claims",
						step.String())
				}
				// Derived from the recurrence, before Validate is consulted.
				if n := decayEpochs(&p, c.length+1); n != c.length {
					t.Fatalf("the schedule is %d epochs, not the %d this row is built to "+
						"place either side of the bound %d", n, c.length, bound)
				}
				err := p.Validate()
				if got := err == nil; got != c.want {
					t.Fatalf("a %d-epoch schedule against a bound of %d: Validate "+
						"accepted=%v, want %v (err %v)", c.length, bound, got, c.want, err)
				}
			})
		}
	})
	t.Run("a set refused before the walk is not left holding a schedule", func(t *testing.T) {
		// The walk clears the cache on its own refusal, but the walk is the LAST
		// thing Validate does. Every earlier return -- this one is the ttl_max
		// floor -- also leaves a Params the caller may still read, and what it
		// would read is a complete schedule for whatever field set was validated
		// before. The "it looks like an answer" argument that made the walk
		// clear its cache applies to those paths identically, so Validate drops
		// the table on the way in rather than on one way out.
		p := *spec.Mainnet()
		p.EmissionDecayDivisor = 1 << 62 // never reached; the ttl_max floor returns first
		p.TTLMax = 1
		if err := p.Validate(); err == nil {
			t.Fatal("ttl_max 1 was accepted; this row asserts nothing")
		} else if !strings.Contains(err.Error(), "ttl_max") {
			t.Fatalf("refused by the walk rather than before it, so this row does not "+
				"test an early return: %v", err)
		}
		if e := p.Emission(p.EpochLength); e != p.TailEmission {
			t.Fatalf("emission at epoch 1 of a set refused before the walk is %s; a "+
				"schedule for other parameters survived the refusal", e.String())
		}
	})
	t.Run("a refused schedule is not left half-cached", func(t *testing.T) {
		// The other half of the refusal, and the half a passing Validate can
		// never show: a set Validate refused must not still answer Emission
		// from a schedule. There are two ways it could. The walk could install
		// the truncated prefix it built; or a complete schedule for the
		// PREVIOUS field set could survive the refusal, since a Params is
		// normally parsed and validated before a caller edits a field on a copy
		// of it. The second is what this row actually caught: mainnet arrives
		// with divisor 1054's 4377-entry table built, and a refused divisor
		// left it in place. Either way a caller that ignored the error read a
		// mid-decay emission the parameters it holds never reach -- worse than
		// the saturating tail an absent table gives, because it looks like an
		// answer.
		//
		// Both are closed by Validate clearing the field on the way in. This
		// row alone does not prove that, because the walk's own clear covers it
		// redundantly; the row below, whose set is refused before the walk ever
		// runs, is the one only the entry clear can satisfy.
		p := *spec.Mainnet()
		p.EmissionDecayDivisor = 252247
		if err := p.Validate(); err == nil {
			t.Fatal("Validate accepted a schedule that does not fit; this row asserts nothing")
		}
		// Epoch 1 is inside the range a half-cached table would have covered,
		// and its cached value would be the first decayed emission -- distinct
		// from both the tail and the genesis value, so this tells the two
		// apart.
		first, _ := p.GenesisEmission.Div64(p.EmissionDecayDivisor)
		decayed := p.GenesisEmission.SatSub(first)
		if decayed == p.TailEmission || decayed == p.GenesisEmission {
			t.Fatalf("the first decayed emission %s is not distinct from the tail %s "+
				"and the genesis %s, so this row cannot tell a cached table from an "+
				"absent one", decayed.String(), p.TailEmission.String(), p.GenesisEmission.String())
		}
		if e := p.Emission(p.EpochLength); e != p.TailEmission {
			t.Fatalf("emission at epoch 1 of a refused set is %s; a schedule survived "+
				"the refusal instead of being discarded", e.String())
		}
	})
	t.Run("above the emission the decay is a fixed decrement", func(t *testing.T) {
		// The claim the refusal message makes, checked against the arithmetic
		// rather than asserted in prose: at a divisor above genesis_emission
		// the proportional step is zero from the very first epoch, so what the
		// walk actually runs is a subtraction of one unit per epoch and the
		// parameter no longer names a decay at all.
		p := spec.Mainnet()
		step, _ := p.GenesisEmission.Div64(1 << 62)
		if !step.IsZero() {
			t.Fatalf("the first proportional step at divisor 2^62 is %s, not zero; "+
				"the refusal message's reasoning does not hold for this witness",
				step.String())
		}
	})
	t.Run("every shipped network still validates", func(t *testing.T) {
		for _, name := range spec.Networks() {
			p, err := spec.ParamsFor(name)
			if err != nil {
				t.Fatal(err)
			}
			if err := p.Validate(); err != nil {
				t.Fatalf("%s: %v", name, err)
			}
		}
	})
}
