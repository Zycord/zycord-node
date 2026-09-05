package refold

import (
	"math/big"
	"testing"

	"zycord/core/types"
	"zycord/spec"
)

// TestAZeroBlockRewardClearsTheRingEntryInsteadOfNamingItsProducer pins F12's
// zero-reward arm in *this* fold: a reward of zero clears the maturity ring
// entry to (0, 0) rather than overwriting it with (Header.EmissionAddr, 0).
//
// It is the port of core/fold's test of the same name, and it exists for the
// reason the health-gate comparator taught rather than for symmetry: an arm
// that nothing anywhere can distinguish from its own negation is held by
// nobody, however many implementations happen to state it. The differential
// runner cannot hold this rule: it drives spec.Devnet() and nothing else
// (sim/differential_test.go), and on devnet the block reward is non-zero at
// every height above 0, so neither implementation's zero arm is ever entered
// and the two agree by never being asked.
//
// **That is a different defect from the shared-surface one, and the two should
// not be merged.** The shared-surface finding measured rules that only LOOK
// independent because one implementation is called twice: tripling the
// per-write term in the gas schedule left the differential green on all eight
// seeds, because both folds read one Certificate.SeqGas. This arm really is
// written twice — `IsZero()` there, `Sign() == 0` here — and is still unheld,
// because no input the runner generates reaches either copy. Jointly
// unexercised, not shared. Both folds special-casing the same way is therefore
// no evidence that the special case is right.
//
// The rule itself is not in question any more. ARCHITECTURE's F12 specified an
// unconditional overwrite and both folds disagreed with it on a committed
// state root at parameter values params.Validate accepts; the folds were right
// and the document has been corrected. The reason is that the release side
// gates on the AMOUNT — an entry whose amount is zero can never pay anybody —
// and Set deletes a cell given zero, so the unconditional write would leave a
// payout address live in the root against an absent amount.
func TestAZeroBlockRewardClearsTheRingEntryInsteadOfNamingItsProducer(t *testing.T) {
	p := spec.Devnet()

	var payout types.Address
	for i := range payout {
		payout[i] = 0x11
	}
	if payout == (types.Address{}) {
		t.Fatal("the payout address is zero, so the two arms below write the same bytes")
	}

	const height = 1
	index := uint64(height) % p.CoinbaseMaturity
	addrSlot := types.PendingCoinbaseAddrSlot(index)
	amountSlot := types.PendingCoinbaseAmountSlot(index)
	emptyRoot := New().Root()

	for _, arm := range []struct {
		what        string
		reward      *big.Int
		wantCleared bool
	}{
		{"a zero reward", big.NewInt(0), true},
		{"a reward of one drop", big.NewInt(1), false},
	} {
		t.Run(arm.what, func(t *testing.T) {
			s := New()
			b := &types.Block{Header: types.Header{Height: height, EmissionAddr: payout}}
			res := &Result{Burned: big.NewInt(0), MinerReward: arm.reward}

			if matured := rollRing(s, b, p, res); matured.Sign() != 0 {
				t.Fatalf("the ring released %s from an empty state; the arm under test is "+
					"the WRITE side and this one has already gone wrong", matured.String())
			}

			addr := s.Get(addrSlot)
			amount := s.Get(amountSlot)

			if arm.wantCleared {
				if addr.Sign() != 0 {
					t.Fatalf("a zero reward wrote %s into the ring's address cell; F12 clears "+
						"the entry", addr.String())
				}
				if amount.Sign() != 0 {
					t.Fatalf("a zero reward wrote %s into the ring's amount cell", amount.String())
				}
				// Stated over the whole state and not only over two cells:
				// this package's own Root() — a second implementation of the
				// commitment, sharing only BLAKE3 — must not be able to tell
				// the result apart from a state the ring never touched.
				if got := s.Root(); got != emptyRoot {
					t.Fatalf("the state root moved to %x on a zero reward; something was "+
						"committed that should have left no trace", got[:8])
				}
				return
			}

			want := new(big.Int).SetBytes(payout[:])
			if addr.Cmp(want) != 0 {
				t.Fatalf("a non-zero reward left the address cell at %s, want the producer's "+
					"payout address", addr.String())
			}
			if amount.Cmp(arm.reward) != 0 {
				t.Fatalf("the ring holds %s against a reward of %s",
					amount.String(), arm.reward.String())
			}
			if s.Root() == emptyRoot {
				t.Fatal("a non-zero reward left the state root unchanged, so the cleared arm " +
					"above is not being compared against anything")
			}
		})
	}
}
