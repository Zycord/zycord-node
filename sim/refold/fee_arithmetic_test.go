package refold

import (
	"encoding/hex"
	"math/big"
	"strings"
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
)

// TestTheBaseFeeFloorStopsTheDescentAtTwoLegalWitnesses pins MIN_BASE_FEE in
// *this* fold, against this package's own statement of the descent —
// `maxBig(out, minFee)` here against core/params' `u256.MaxOf(base.SatSub(delta),
// p.MinBaseFee)` there.
//
// It is the port of core/params' test of the same name. Both copies were open:
// no shipped parameter set can exhibit the floor, because MinBaseFee is 1 and
// the change denominator is 8 on all three networks, so integer division halts
// an empty chain's descent at 7 — above the floor, which therefore never binds.
// Measured: stripping the clamp from either copy leaves core/params, core/fold,
// the spec vectors and sim's differential all green.
//
// **Why a witness is legitimate.** The floor is quantified over MIN_BASE_FEE:
// "an empty chain's base fee never falls below MIN_BASE_FEE" has the same truth
// value at every parameter set, and the shipped sets merely make its antecedent
// vacuous. The fixture supplies the antecedent; it does not substitute the
// subject, which is the opposite shape from the defect that ran the other way:
// a fixture that leaves the shipped ratio behind measures a different protocol
// and reports the answer as if it were this one's.
//
// **Two witnesses, because one witness is a fixture.** They differ in the
// floor, in the change denominator and in both initial fees, so a conclusion
// that turned on either could not hold at both. Both are in the tree, so the
// next reader can check the fixture-independence rather than trust a run.
func TestTheBaseFeeFloorStopsTheDescentAtTwoLegalWitnesses(t *testing.T) {
	for _, w := range []struct {
		name                                      string
		minBaseFee, denominator, initSeq, initPar uint64
	}{
		{"floor_10_under_a_denominator_of_8", 10, 8, 1000, 10},
		{"floor_4096_under_a_denominator_of_16", 4096, 16, 1_000_000, 4096},
	} {
		t.Run(w.name, func(t *testing.T) {
			p := *spec.Mainnet()
			p.MinBaseFee = u256.FromUint64(w.minBaseFee)
			p.BaseFeeMaxChangeDenominator = w.denominator
			p.InitialSeqBaseFee = u256.FromUint64(w.initSeq)
			p.InitialParBaseFee = u256.FromUint64(w.initPar)
			if err := p.Validate(); err != nil {
				t.Fatalf("this witness is not a set params.Validate accepts (%v); a rule "+
					"pinned at parameters the protocol refuses is pinned at nothing", err)
			}

			floor := new(big.Int).SetUint64(w.minBaseFee)
			target := p.SeqGasTargetGenesis

			// The witness must separate the two candidates. At the shipped set
			// the proportional step at the floor is 1/8 = 0, so a fold with no
			// floor at all rests in the same place and every arm below would
			// pass on both implementations.
			if new(big.Int).Quo(floor, new(big.Int).SetUint64(w.denominator)).Sign() == 0 {
				t.Fatalf("the proportional step at the floor (%d / %d) rounds to zero, so this "+
					"witness separates nothing", w.minBaseFee, w.denominator)
			}

			low := new(big.Int).SetUint64(w.initSeq)
			settled := false
			for i := 0; i < 10_000; i++ {
				next := nextBaseFee(&p, low, 0, target)
				if next.Cmp(low) > 0 {
					t.Fatalf("an empty block raised the base fee from %s to %s", low, next)
				}
				if next.Cmp(low) == 0 {
					settled = true
					break
				}
				low = next
			}
			if !settled {
				t.Fatalf("the base fee had not settled after 10,000 empty blocks (at %s)", low)
			}
			if low.Cmp(floor) != 0 {
				t.Fatalf("an empty chain rests at %s, want the floor %s", low, floor)
			}

			// The same statement one step at a time, so the kill does not
			// depend on the loop: at the floor the proportional step is a whole
			// unit, so only the floor can be returning the floor.
			if got := nextBaseFee(&p, floor, 0, target); got.Cmp(floor) != 0 {
				t.Fatalf("an empty block at the floor moved the base fee to %s, want %s", got, floor)
			}

			// The guard against a benign pass: a fold that returned MinBaseFee
			// unconditionally, or that had stopped descending at all, would
			// satisfy every arm above. At twice the floor the descent is still
			// live and still proportional.
			twice := new(big.Int).Lsh(floor, 1)
			got := nextBaseFee(&p, twice, 0, target)
			if got.Cmp(twice) >= 0 || got.Cmp(floor) <= 0 {
				t.Fatalf("an empty block at twice the floor returned %s; it must fall below %s "+
					"and stay above %s, or the arms above are not the floor doing the work",
					got, twice, floor)
			}
		})
	}
}

// TestAFeeCapBelowTheBaseFeePaysNoPriorityInThisFold pins marketFees' headroom
// clamp, which is a guard this fold needs and core/fold does not.
//
// **Why there is no witness for this one, and that is the finding.** B4 refuses
// a certificate whose cap is below the market's base fee, so in core/fold the
// subtraction can never underflow and its own re-check is dead code. Here it is
// not: sweep.go deletes rules one at a time for
// sim's TestEveryInvalidVectorsRuleIsNecessary, and the corpus records a B4
// vector, so this fold is *routinely driven* into the state B4 exists to
// prevent. That is PROTOCOL rule 12's exact shape — a guard the second copy
// needs and the first does not.
//
// The condition is `maxPrice < base`, a fact about state rather than about a
// parameter, so no parameter file can supply the antecedent and the witness
// technique that pins the base-fee floor above has nothing to attach to. The
// honest instrument is a unit test over the state itself.
//
// **What the clamp is.** Not a consensus rule — B4 owns the rule, and there is
// no protocol sentence about a state B4 forbids. It is this fold's own
// well-formedness contract: with the rule it has been asked to pretend not to
// have deleted, its arithmetic still terminates in non-negative money. An
// unclamped subtraction returns a negative headroom, `min(priority, headroom)`
// picks it up, and the fold pays the producer a negative tip and refunds the
// signer more than they deposited — silently, because nothing downstream
// checks a sign. Measured: with the clamp deleted, the necessity sweep still
// passes and the vector's charge drops from 140,482 to 139,882.
func TestAFeeCapBelowTheBaseFeePaysNoPriorityInThisFold(t *testing.T) {
	gas := big.NewInt(600)
	base := big.NewInt(100)
	priority := big.NewInt(7)
	wantBurn := new(big.Int).Mul(gas, base)

	// The arms that need the clamp: every cap at or below the base fee.
	for _, capPrice := range []int64{99, 50, 1, 0} {
		burn, tip := marketFees(gas, base, big.NewInt(capPrice), priority)
		if tip.Sign() != 0 {
			t.Fatalf("a cap of %d against a base fee of %s tipped %s; a cap below the base "+
				"fee buys no priority, and a negative tip is money the fold invented",
				capPrice, base, tip)
		}
		if burn.Cmp(wantBurn) != 0 {
			t.Fatalf("a cap of %d burned %s, want %s: the clamp must not touch the burn",
				capPrice, burn, wantBurn)
		}
	}
	// The boundary from the other side: at a cap exactly equal to the base fee
	// the headroom is zero and no clamp is involved, so the two arms astride
	// the boundary agree and the clamp is continuous rather than a step.
	if _, tip := marketFees(gas, base, base, priority); tip.Sign() != 0 {
		t.Fatalf("a cap exactly at the base fee tipped %s, want nothing", tip)
	}

	// The guard against a benign pass. Everything above is satisfied by a
	// marketFees that always tips zero, so the market has to be shown paying:
	// once above the base fee the tip is min(priority, headroom) and both
	// sides of that minimum have to be reachable.
	for _, c := range []struct {
		name     string
		capPrice int64
		wantTip  int64
		boundBy  string
	}{
		{"headroom binds", 103, 3 * 600, "the headroom"},
		{"priority binds", 200, 7 * 600, "the priority"},
	} {
		if _, tip := marketFees(gas, base, big.NewInt(c.capPrice), priority); tip.Int64() != c.wantTip {
			t.Fatalf("%s: a cap of %d tipped %s, want %d — the tip must be bounded by %s here, "+
				"or the zero-tip arms above are vacuous", c.name, c.capPrice, tip, c.wantTip, c.boundBy)
		}
	}
}

// TestTheCorpusDrivesThisFoldIntoAFeeCapBelowTheBaseFee is what makes the
// clamp above structural rather than dead code here too.
//
// A unit test over a private helper says nothing about whether the fold ever
// reaches that helper with that input. This shows the corpus doing it: the
// recorded B4 vector's certificate really does cap below the base fee this
// fold reads from the pre-state, and with B4 deleted — which is exactly what
// sim's necessity sweep does to it on every run — the block is accepted and
// settled through marketFees in that state.
//
// Limits, stated rather than left to be discovered: this arm asserts
// reachability and acceptance, not the settled amounts. The amounts are the
// arm above's job, and asserting them here would mean writing the same formula
// down a third time.
func TestTheCorpusDrivesThisFoldIntoAFeeCapBelowTheBaseFee(t *testing.T) {
	vectors, err := spec.LoadVectors("../../spec/vectors")
	if err != nil {
		t.Fatal(err)
	}
	var v *spec.Vector
	for _, c := range vectors {
		if c.Name == "invalid-cap-below-base" {
			v = c
			break
		}
	}
	if v == nil {
		t.Fatal("the cap-below-base vector is gone from the corpus; nothing drives this fold " +
			"into a negative headroom any more and the clamp above is pinning dead code")
	}
	if v.Expect.Rule != "B4" {
		t.Fatalf("this vector now records %q, not B4; the sweep would delete a different rule "+
			"and would not reach the clamp", v.Expect.Rule)
	}

	p, err := spec.ParamsFor(v.Params)
	if err != nil {
		t.Fatal(err)
	}
	b, err := v.DecodeBlock(p)
	if err != nil {
		t.Fatalf("the block does not decode: %v", err)
	}
	s := vectorState(t, v.Pre)

	// Reachability, read off the state rather than assumed from the rule id.
	seqBase := s.Get(types.SeqBaseFeeSlot())
	if seqBase.Sign() == 0 {
		seqBase = toBig(p.InitialSeqBaseFee.Bytes())
	}
	parBase := s.Get(types.ParBaseFeeSlot())
	if parBase.Sign() == 0 {
		parBase = toBig(p.InitialParBaseFee.Bytes())
	}
	under := 0
	for _, c := range b.Certs {
		if toBig(c.FeeBid.SeqMax.Bytes()).Cmp(seqBase) < 0 {
			under++
		}
		if toBig(c.FeeBid.ParMax.Bytes()).Cmp(parBase) < 0 {
			under++
		}
	}
	if under == 0 {
		t.Fatalf("no certificate in this block caps below a base fee (sequential %s, parallel %s), "+
			"so deleting B4 does not drive this fold into a negative headroom", seqBase, parBase)
	}

	// And with B4 deleted the block is accepted, so the settlement really runs
	// in that state instead of being short-circuited by the rule.
	restore := WithoutRule("B4")
	defer restore()
	if _, err := ApplyBlock(s, b, p); err != nil {
		t.Fatalf("with B4 deleted this block is still rejected (%v), so this fold never "+
			"settles a cap-below-base certificate and the clamp is unreachable", err)
	}
}

// vectorState materialises a vector's pre-state into this fold's storage. It is
// the same job sim's naiveState does, written out here so this package's tests
// do not have to import sim's test helpers.
func vectorState(t *testing.T, pre spec.PreState) *State {
	t.Helper()
	s := New()
	for _, c := range pre.Cells {
		v, ok := new(big.Int).SetString(c.Value, 10)
		if !ok {
			t.Fatalf("bad decimal cell value %q", c.Value)
		}
		s.Set(types.Slot{Addr: types.Address(vectorHash(t, c.Addr)), Word: vectorHash(t, c.Word)}, v)
	}
	for _, a := range pre.Spent {
		s.MarkSpent(types.Address(vectorHash(t, a)))
	}
	for _, e := range pre.Seen {
		s.MarkSeen(vectorHash(t, e.ID), e.TTL)
	}
	return s
}

func vectorHash(t *testing.T, s string) types.Hash {
	t.Helper()
	raw, err := hex.DecodeString(strings.TrimPrefix(s, "0x"))
	if err != nil || len(raw) != 32 {
		t.Fatalf("bad 32-byte hex %q: %v", s, err)
	}
	var h types.Hash
	copy(h[:], raw)
	return h
}
