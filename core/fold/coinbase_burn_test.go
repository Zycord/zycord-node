package fold_test

import (
	"testing"

	"zycord/core/crypto"
	"zycord/core/fold"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/sim/harness"
	"zycord/spec"
	"zycord/wallet"
)

// TestARewardIsBurnedWhenItsPayeeIsSpentByTheBlockThatWouldReleaseIt pins F12's
// burn arm and, with it, the stage order that decides which block loses the
// money.
//
// # The property
//
// rollCoinbaseRing runs AFTER the certificate loop. So a certificate in block H
// that burns the address block H − CoinbaseMaturity paid is seen by the release
// side of the ring in that same block: the reward is added to res.Burned and no
// balance cell is written for it. docs/RUNNING.md states the operator-facing
// half — "the maturity ring rolls after the block's certificates land, so the
// block carrying the spend is already the first block that loses money" — and
// that sentence is a claim about the ORDER, true only while F12 sits where it
// sits. A fold that rolled the ring first would find the payee unspent, credit
// the reward, and lose nothing until the next block.
//
// # Why nothing pinned it
//
// The arm was reached by no test and no golden vector in this tree, and the
// reason is structural rather than an omission in the suite: every mining
// payout anywhere here is a PERSISTENT address — the harness pays
// key(n).Persistent(), spec/gen pays scenario.payout(), and cmd/zycordd refuses
// anything else at the command line (TestParsePayoutRequiresPersistent) — and a
// persistent address can never enter the spent registry, so the branch's
// question is never asked. Measured rather than assumed: with the arm replaced
// by a panic, every package that can reach core/fold stayed green. sim/refold's
// second statement of F12 carries the same arm and was dead for the same
// reason, so the differential could not see it either — jointly unexercised,
// the same jointly-dead shape the F12 overwrite arm and the health gate's
// comparator were already found in by this package.
//
// Consensus permits the payout address to be one-shot: B11 admits any user
// address (crypto.IsUserAddress), and the 0x02 requirement lives in the wallet
// and the command line, not in the fold. That is exactly why the arm exists.
//
// # Why two arms, and why they differ in one thing only
//
// The control block carries a certificate of the same shape retiring a
// DIFFERENT one-shot address, so both blocks include the same gas and pay the
// same fee. Everything the two folds do is identical except which address the
// registry gains, which makes the difference in res.Burned exactly the reward
// and leaves nothing for a fee to explain.
func TestARewardIsBurnedWhenItsPayeeIsSpentByTheBlockThatWouldReleaseIt(t *testing.T) {
	p := spec.Devnet()
	victim, bystander := key(t, 7), key(t, 8)
	payee := victim.OneShot()
	if payee[0] != crypto.AddrVersionOneShot {
		t.Fatal("the payout under test is not a one-shot address, so no certificate can " +
			"burn it and neither arm reaches the branch")
	}
	if !crypto.IsUserAddress(payee) {
		t.Fatal("B11 refuses this payout address, so the block that writes it into the ring " +
			"cannot be mined and the test would assert nothing")
	}
	if bystander.OneShot() == payee {
		t.Fatal("the control retires the same address as the arm under test, so the two " +
			"arms are one arm")
	}

	type arm struct {
		burnThePayee bool
		res          *fold.Result
		balance      u256.U256
		pending      u256.U256
	}
	arms := map[bool]*arm{true: {burnThePayee: true}, false: {burnThePayee: false}}

	var certGas, certPar uint64
	for _, a := range []*arm{arms[true], arms[false]} {
		c := harness.MustNew(p)
		miner := key(t, 1)
		payout := miner.Persistent()
		if err := c.MineUntilFunded(payout); err != nil {
			t.Fatal(err)
		}

		// One block pays its producer share to the one-shot address, and the
		// ring holds it for CoinbaseMaturity blocks.
		if _, _, err := c.AddBlock(payee); err != nil {
			t.Fatal(err)
		}
		payHeight := c.Height()
		for h := uint64(1); h < p.CoinbaseMaturity; h++ {
			if _, _, err := c.AddBlock(payout); err != nil {
				t.Fatal(err)
			}
		}

		height := c.NextHeight()
		if height != payHeight+p.CoinbaseMaturity {
			t.Fatalf("the block under test is at height %d, and the reward was written at "+
				"%d with a maturity of %d; it is not the block that releases it",
				height, payHeight, p.CoinbaseMaturity)
		}
		index := height % p.CoinbaseMaturity
		a.pending = c.State.Get(types.PendingCoinbaseAmountSlot(index))
		if a.pending.IsZero() {
			t.Fatal("the ring slot this block rolls is empty, so F12's release side is not " +
				"entered at all and neither arm says anything")
		}
		if got, want := c.State.Get(types.PendingCoinbaseAddrSlot(index)), u256.FromBytes(payee); !got.Eq(want) {
			t.Fatalf("the ring slot this block rolls names %s, not the one-shot payout %s",
				got.String(), want.String())
		}
		// The precondition that makes the order observable. If the payee were
		// already spent when the block arrived, both orderings would burn.
		if c.State.IsSpent(payee) {
			t.Fatal("the payee is already spent before the block under test, so the reward " +
				"is burned under any ordering and this test cannot see the order")
		}

		retired := bystander
		if a.burnThePayee {
			retired = victim
		}
		cert, err := (&wallet.Builder{
			Params:  p,
			Program: wallet.Retire(retired.OneShot()),
			TTL:     height + 5,
			Deposit: wallet.SelfDeposit(payout, payout),
			FeeBid:  bid(),
			Signers: []*wallet.Key{miner, retired},
		}).Build()
		if err != nil {
			t.Fatal(err)
		}
		// Armed: the two arms must cost the same, or the difference in burn
		// below is a fee difference wearing the reward's name.
		if certGas == 0 {
			certGas, certPar = cert.SeqGas(p), cert.ParGas(p)
		} else if cert.SeqGas(p) != certGas || cert.ParGas(p) != certPar {
			t.Fatalf("the two arms' certificates declare (%d, %d) and (%d, %d) gas; they are "+
				"not the same shape and the burn difference is not the reward",
				certGas, certPar, cert.SeqGas(p), cert.ParGas(p))
		}

		_, res, err := c.AddBlock(payout, cert)
		if err != nil {
			t.Fatalf("the block under test is invalid: %v", err)
		}
		if len(res.Outcomes) != 1 || res.Outcomes[0].Outcome != fold.Applied {
			t.Fatalf("the RETIRE did not apply (%v), so nothing was burned and F12 takes its "+
				"release side in both arms", res.Outcomes)
		}
		if got := c.State.IsSpent(payee); got != a.burnThePayee {
			t.Fatalf("after the block the payee's spent flag is %v, want %v", got, a.burnThePayee)
		}
		a.res, a.balance = res, c.Balance(payee)
	}

	burned, matured := arms[true], arms[false]
	if !burned.pending.Eq(matured.pending) {
		t.Fatalf("the two arms hold different rewards in the ring, %s and %s, so their "+
			"results are not comparable", burned.pending.String(), matured.pending.String())
	}
	reward := burned.pending

	// The two assertions the burn arm needs, in that order.
	if !burned.res.Matured.IsZero() {
		t.Fatalf("the ring released %s to an address burned by this very block; F12's burn "+
			"arm was not taken, and docs/RUNNING.md's claim that the block carrying the spend "+
			"is the first block that loses money is false", burned.res.Matured.String())
	}
	delta, under := burned.res.Burned.Sub(matured.res.Burned)
	if under || !delta.Eq(reward) {
		t.Fatalf("burning the payee changed the block's burn by %s (%s against %s); the "+
			"reward of %s did not go to Burned", delta.String(), burned.res.Burned.String(),
			matured.res.Burned.String(), reward.String())
	}
	if !burned.balance.IsZero() {
		t.Fatalf("the burned payee holds %s; a reward whose payee cannot read a cell must "+
			"be destroyed, not written into one", burned.balance.String())
	}

	// The control arm is what makes the three above a statement about the
	// order rather than about this fold refusing to pay anybody.
	if !matured.res.Matured.Eq(reward) {
		t.Fatalf("with a bystander retired instead, the ring released %s, want the whole "+
			"reward %s; the control does not establish that the reward was payable",
			matured.res.Matured.String(), reward.String())
	}
	if !matured.balance.Eq(reward) {
		t.Fatalf("with a bystander retired instead, the payee holds %s, want %s",
			matured.balance.String(), reward.String())
	}
}
