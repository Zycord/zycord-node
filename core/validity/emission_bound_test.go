package validity_test

import (
	"testing"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/spec"
	"zycord/wallet"
)

// TestV5BoundsTheDepositByTheCumulativeEmissionAtItsTTL is the deposit-bound
// half of the three genesis-frozen decisions, driven at the boundary rather
// than at a round number.
//
// **What the rule is.** `V5` bounded `Deposit.Amount` only from below — it had
// to cover the certificate's fee ceiling — so `Amount = 2^256-1` from an
// unfunded fresh key passed every stateless rule and failed only at `F3`'s
// state check, where nothing is charged, nothing is burned and `markSeen` is
// never reached. The upper bound is the total coinbase §14.2's schedule can
// have paid by `TTL`, the last height at which `B1` admits this certificate.
//
// **The height is the certificate's own, which is what keeps the rule
// stateless.** Cumulative emission is a pure function of a height and the four
// issuance constants; `TTL` comes out of the bytes being checked. Since the
// schedule is non-decreasing, cumulative emission at `TTL` is the supremum of
// the supply over every height at which this certificate can still commit, so
// the bound is the loosest one that is sound without reading a tip.
//
// **What this test is NOT evidence for.** It is not a fix for drop-stuffing.
// The stuffing primitive works identically with `Amount = 1` from an unfunded
// fresh key, and what bounds the receiver-side cost is `B18`. The bound
// exists because a consensus-valid object declaring more coin than can exist
// is an absurdity the cheap gate should refuse. docs/ARCHITECTURE.md §10 says
// both halves and this comment must not be trimmed to only the first.
//
// EXPECTED DIRECTION (PROTOCOL rule 22), declared before the run: a deposit of
// exactly the cumulative emission at the TTL is ACCEPTED and one drop above it
// is REFUSED naming V5. Acceptance of the second means the clause is absent or
// inverted; refusal of the first means it is off by one in the direction that
// refuses legal certificates, which is the direction that costs a user money.
func TestV5BoundsTheDepositByTheCumulativeEmissionAtItsTTL(t *testing.T) {
	p := spec.Devnet()

	c, alice := validCert(t, p)
	supply := p.CumulativeEmission(c.TTL)
	if supply.IsZero() {
		t.Fatal("the schedule has issued nothing by this certificate's TTL, so every deposit " +
			"fails the bound and the boundary below is not a boundary")
	}

	// The certificate's own fee ceiling must sit strictly inside the bound, or
	// the two clauses meet and the acceptance below proves nothing about the
	// upper one.
	ceiling, ok := c.FeeCeiling(p)
	if !ok {
		t.Fatal("the fee ceiling overflows 256 bits")
	}
	if !ceiling.Lt(supply) {
		t.Fatalf("the fee ceiling %s is not below the cumulative emission %s at TTL %d; the "+
			"lower and upper bounds of V5 have met and this test cannot separate them",
			ceiling.String(), supply.String(), c.TTL)
	}

	c.Deposit.Amount = supply
	resign(p, c, alice)
	if err := validity.Check(c, p); err != nil {
		t.Fatalf("a deposit of exactly the cumulative emission at its TTL was refused: %v", err)
	}

	over, over256 := supply.Add(u256.One)
	if over256 {
		t.Fatal("the cumulative emission is the largest 256-bit value, so there is no drop above it")
	}
	c.Deposit.Amount = over
	resign(p, c, alice)
	wantRule(t, validity.Check(c, p), "V5")
	wantRule(t, validity.CheckDeposit(c, p), "V5")

	// And the value the audit named, which is the whole class the bound
	// closes: an unfunded fresh key declaring every coin that could ever
	// exist.
	c.Deposit.Amount = u256.Max
	resign(p, c, alice)
	wantRule(t, validity.Check(c, p), "V5")
}

// TestTheStatelessDepositBoundIsStateless is the property that makes the rule
// above legal as a V-rule rather than a fold rule: the same certificate gets
// the same answer from a parameter set alone, with no chain, no tip and no
// state of any kind in scope. It is stated by construction — `CheckDeposit`
// takes only a certificate and a `*params.Params` — so what is left to check
// is that the bound it consults is a function of the height and nothing else.
func TestTheStatelessDepositBoundIsStateless(t *testing.T) {
	for _, name := range []string{"mainnet", "testnet", "devnet"} {
		t.Run(name, func(t *testing.T) {
			p, err := spec.ParamsFor(name)
			if err != nil {
				t.Fatal(err)
			}
			// A second, independently parsed copy of the same file: the
			// cumulative table is a lazily built cache, and a cache that
			// answered differently on a cold set than on a warm one would be a
			// fork nobody could see.
			raw, err := spec.RawFor(name)
			if err != nil {
				t.Fatal(err)
			}
			cold, err := params.Parse(raw)
			if err != nil {
				t.Fatal(err)
			}
			for _, h := range []uint64{0, 1, 2, p.EpochLength - 1, p.EpochLength,
				p.EpochLength + 1, 7 * p.EpochLength, 1 << 40, ^uint64(0)} {
				if a, b := p.CumulativeEmission(h), cold.CumulativeEmission(h); !a.Eq(b) {
					t.Fatalf("height %d: warm set says %s, a freshly parsed one says %s",
						h, a.String(), b.String())
				}
			}
		})
	}
}

// TestCumulativeEmissionIsTheSumOfEmission is the second computation the bound
// rests on, and it is deliberately the slow one: it adds `Emission(h)` up, one
// height at a time, and compares against the prefix table `CumulativeEmission`
// reads. A closed form checked against itself is not checked.
//
// The range covers the two places the arithmetic can be wrong by exactly one
// block: height 0, which pays nothing while every later height in epoch 0
// does, and the epoch boundaries, where the rate changes.
func TestCumulativeEmissionIsTheSumOfEmission(t *testing.T) {
	p := spec.Devnet()
	acc := u256.Zero
	for h := uint64(0); h <= 5*p.EpochLength+3; h++ {
		acc = acc.SatAdd(p.Emission(h))
		if got := p.CumulativeEmission(h); !got.Eq(acc) {
			t.Fatalf("height %d: CumulativeEmission says %s, summing Emission gives %s",
				h, got.String(), acc.String())
		}
	}
	if acc.IsZero() {
		t.Fatal("the summation is zero, so the comparison above held vacuously")
	}
}

// TestTheDepositBoundRefusesTheAuditsWitness builds the exact object the
// audit describes — a fresh key with no balance anywhere, depositing 2^256-1
// — through the wallet rather than by hand, so that what is refused is a
// certificate the network would otherwise have accepted as stateless-valid
// and dropped for free at F3.
func TestTheDepositBoundRefusesTheAuditsWitness(t *testing.T) {
	p := spec.Devnet()
	fresh, payee := key(t, 41), key(t, 42)
	c, err := (&wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, fresh.Persistent(), payee.Persistent(), drops(1)),
		TTL:     100,
		Deposit: wallet.SelfDeposit(fresh.Persistent(), fresh.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{fresh},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	// As built it is valid: the deposit is unfunded, but no stateless rule
	// knows a balance, which is the property the whole drop path rests on.
	if err := validity.Check(c, p); err != nil {
		t.Fatalf("the baseline certificate is already invalid (%v), so the edit below would be "+
			"answered by a rule it did not cause", err)
	}
	c.Deposit.Amount = u256.Max
	resign(p, c, fresh)
	wantRule(t, validity.Check(c, p), "V5")
}
