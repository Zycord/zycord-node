package wallet_test

import (
	"errors"
	"testing"

	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
	"zycord/wallet"
)

// The wallet rules, tested as behaviour rather than as prose (M1-G6).
//
// Each of these describes a way to lose money that the protocol permits on
// purpose. If any stops failing, the CLI has quietly moved the problem back to
// the user.

func fundedState(t *testing.T, entries map[types.Slot]u256.U256) *state.State {
	t.Helper()
	s := state.New()
	for slot, v := range entries {
		s.Set(slot, v)
	}
	return s
}

func TestRefusesPartialOneShotSpend(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 2), key(t, 3)
	oneShot := alice.OneShot()

	s := fundedState(t, map[types.Slot]u256.U256{
		types.NativeBalanceSlot(oneShot): drops(1_000_000_000),
	})

	deposit := wallet.SelfDeposit(oneShot, alice.Persistent())
	b := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, oneShot, bob.Persistent(), drops(1_000)),
		TTL:     100,
		Deposit: deposit,
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}
	c, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.CheckAll(c, s, p, nil); !errors.Is(err, wallet.ErrPartialOneShotSpend) {
		t.Fatalf("got %v, want a partial-spend refusal (I1-L4)", err)
	}

	// Sweeping the whole cell passes.
	ceiling, _ := c.FeeCeiling(p)
	sweep := wallet.SweepAmount(oneShot, types.NativeAsset, deposit, s, ceiling)
	b.Program = wallet.Tip(types.NativeAsset, oneShot, bob.Persistent(), sweep)
	swept, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.CheckAll(swept, s, p, nil); err != nil {
		t.Fatalf("a full sweep was refused: %v", err)
	}
}

// TestRefusesPartialOneShotDepositOnAMovelessProgram is rule 1 for the
// programs that have no moves. Once a one-shot address could fund an ISSUE or
// a MINT at all (F-VAL-5), the deposit reservation became the only thing that
// can empty the cell — and the sweep rule used to look at moves alone, so it
// passed a certificate that burned an address holding almost its whole
// balance.
func TestRefusesPartialOneShotDepositOnAMovelessProgram(t *testing.T) {
	p := spec.Devnet()
	alice := key(t, 2)
	oneShot := alice.OneShot()
	balance := drops(1_000_000_000)

	s := fundedState(t, map[types.Slot]u256.U256{
		types.NativeBalanceSlot(oneShot): balance,
	})

	prog := wallet.Issue(oneShot, drops(1_000), 0, types.Hash{}, alice.PubKey())
	b := &wallet.Builder{
		Params:  p,
		Program: prog,
		TTL:     100,
		// SelfDeposit reserves only the fee ceiling, so the rest of the
		// balance would stay under an address this certificate burns.
		Deposit: wallet.SelfDeposit(oneShot, alice.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}
	c, err := b.Build()
	if err != nil {
		t.Fatalf("an ISSUE funded from a one-shot address should build: %v", err)
	}
	if err := wallet.CheckAll(c, s, p, nil); !errors.Is(err, wallet.ErrPartialOneShotSpend) {
		t.Fatalf("got %v, want a partial-spend refusal (I1-L4)", err)
	}

	// Sweeping the cell into the reservation passes: settlement charges the
	// fee and refunds the rest to the persistent address.
	b.Deposit = wallet.SweepDeposit(oneShot, alice.Persistent(), balance)
	swept, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.CheckAll(swept, s, p, nil); err != nil {
		t.Fatalf("a sweeping deposit was refused: %v", err)
	}
}

// TestRefusesABurnWhoseResidualGoesToSomebodyElse is the check that does not
// read a balance, which is exactly what makes it useful against a source node
// that understates one.
//
// Since F8b the chain delivers a burned address's residual to the
// certificate's single Deposit.RefundTo instead of destroying it. A
// certificate may burn addresses belonging to several signers, so a residual
// under my cell can be delivered to somebody else's — and if my node
// understated my balance, CheckSweepsWholeCell agrees with the lie and passes,
// because it can only check that node's number against itself.
//
// Before F8b an understated sweep destroyed the difference and nobody gained.
// Now the holder of RefundTo gains exactly the understatement, which turns a
// loss into a transfer and gives the understating node a beneficiary. This
// refusal reads only the certificate's own bytes, so no lie about state can
// get past it.
func TestRefusesABurnWhoseResidualGoesToSomebodyElse(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 2), key(t, 3)

	// Alice's view says her one-shot cell holds 300,000,000 — the node's lie. It
	// really holds more, but nothing here can know that, and that is the point:
	// the certificate is refused without consulting a balance at all.
	view := fundedState(t, map[types.Slot]u256.U256{
		types.NativeBalanceSlot(alice.OneShot()):  drops(300_000_000),
		types.NativeBalanceSlot(bob.Persistent()): drops(2_000_000_000),
	})

	deposit := wallet.SelfDeposit(bob.Persistent(), bob.Persistent())
	b := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, alice.OneShot(), bob.Persistent(), drops(300_000_000)),
		TTL:     100,
		Deposit: deposit,
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice, bob},
	}
	c, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	// Checked as ALICE: her cell burns and the change goes to bob.
	aliceOwns := []types.Address{alice.OneShot(), alice.Persistent()}
	if err := wallet.CheckAll(c, view, p, aliceOwns); !errors.Is(err, wallet.ErrBurnedResidualGoesElsewhere) {
		t.Fatalf("got %v, want a refusal: alice burns her cell and bob takes the change", err)
	}
	// And as BOB, who is not exposed: nothing of his is burned, so the rule
	// has nothing to say and the other rules decide.
	bobOwns := []types.Address{bob.OneShot(), bob.Persistent()}
	if err := wallet.CheckAll(c, view, p, bobOwns); errors.Is(err, wallet.ErrBurnedResidualGoesElsewhere) {
		t.Fatal("refused on bob's behalf; nothing of bob's is burned by this certificate")
	}

	// The same sweep with alice's own refund address is fine.
	b.Deposit = wallet.SelfDeposit(bob.Persistent(), alice.Persistent())
	ceiling, _ := c.FeeCeiling(p)
	b.Program = wallet.Tip(types.NativeAsset, alice.OneShot(), bob.Persistent(),
		wallet.SweepAmount(alice.OneShot(), types.NativeAsset, b.Deposit, view, ceiling))
	home, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.CheckAll(home, view, p, aliceOwns); err != nil {
		t.Fatalf("a sweep whose change comes home was refused: %v", err)
	}
}

// TestAcceptsAMultiKeyConsolidatingSweep is the false positive the same-key
// form of the rule had, and the reason it is membership of a set.
//
// Whitepaper §4 generates a one-shot address per payment received and §12's
// stealth outputs ride the same rail, so a wallet that derives per-payment
// keys consolidates several of its own one-shot cells into one certificate.
// Every burned cell is the wallet's; the change is the wallet's; nothing
// leaves. A rule comparing each burned address against the key RefundTo
// derives from refuses this outright, and forces the change into
// persistent(K_payment) — a fresh account per payment, which is exactly the
// linkage the one-shot rail exists to avoid.
func TestAcceptsAMultiKeyConsolidatingSweep(t *testing.T) {
	p := spec.Devnet()
	main, pay1, pay2 := key(t, 2), key(t, 20), key(t, 21)
	bob := key(t, 3)

	cells := map[types.Slot]u256.U256{
		types.NativeBalanceSlot(pay1.OneShot()):    drops(400_000_000),
		types.NativeBalanceSlot(pay2.OneShot()):    drops(500_000_000),
		types.NativeBalanceSlot(main.Persistent()): drops(2_000_000_000),
	}
	view := fundedState(t, cells)

	deposit := wallet.SelfDeposit(main.Persistent(), main.Persistent())
	b := &wallet.Builder{
		Params: p,
		Program: wallet.Transfer(
			types.Move{Asset: types.NativeAsset, Src: pay1.OneShot(),
				Dst: bob.Persistent(), Amount: drops(400_000_000)},
			types.Move{Asset: types.NativeAsset, Src: pay2.OneShot(),
				Dst: bob.Persistent(), Amount: drops(500_000_000)},
		),
		TTL:     100,
		Deposit: deposit,
		FeeBid:  bid(),
		Signers: []*wallet.Key{main, pay1, pay2},
	}
	c, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	owned := []types.Address{
		main.OneShot(), main.Persistent(),
		pay1.OneShot(), pay1.Persistent(),
		pay2.OneShot(), pay2.Persistent(),
	}
	if err := wallet.CheckAll(c, view, p, owned); err != nil {
		t.Fatalf("a wallet consolidating its own per-payment cells was refused: %v", err)
	}

	// The same certificate is still refused when the change leaves the wallet.
	b.Deposit = wallet.SelfDeposit(main.Persistent(), bob.Persistent())
	away, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.CheckAll(away, view, p, owned); !errors.Is(err, wallet.ErrBurnedResidualGoesElsewhere) {
		t.Fatalf("got %v, want a refusal when the change goes to a counterparty", err)
	}
}

// TestSweepAmountAccountsForTheWholeReservation pins the other half of the
// same arithmetic: a deposit that reserves more than the fee ceiling takes
// more out of its cell, so a move sized against the ceiling would ask for more
// than the cell holds and the certificate would skip against its own guard.
func TestSweepAmountAccountsForTheWholeReservation(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 2), key(t, 3)
	oneShot := alice.OneShot()
	balance := drops(1_000_000_000)

	s := fundedState(t, map[types.Slot]u256.U256{
		types.NativeBalanceSlot(oneShot): balance,
	})

	probe, err := (&wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, oneShot, bob.Persistent(), drops(1)),
		TTL:     100,
		Deposit: wallet.SelfDeposit(oneShot, alice.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	ceiling, _ := probe.FeeCeiling(p)

	// Reserve well above the ceiling on purpose.
	reserved := drops(500_000_000)
	if !reserved.Gt(ceiling) {
		t.Fatalf("the test's reservation of %s is not above the ceiling of %s",
			reserved.String(), ceiling.String())
	}
	deposit := wallet.SweepDeposit(oneShot, alice.Persistent(), reserved)

	sweep := wallet.SweepAmount(oneShot, types.NativeAsset, deposit, s, ceiling)
	want, _ := balance.Sub(reserved)
	if !sweep.Eq(want) {
		t.Fatalf("sweep amount %s, want %s", sweep.String(), want.String())
	}

	c, err := (&wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, oneShot, bob.Persistent(), sweep),
		TTL:     100,
		Deposit: deposit,
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.CheckAll(c, s, p, nil); err != nil {
		t.Fatalf("a sweep sized against the real reservation was refused: %v", err)
	}
}

// TestRefusesRetiringAFundedAddress is rule 1 for RETIRE. The program moves no
// value by construction (whitepaper §11), so a retired address that still holds
// a balance loses it — the same stranding as a partial spend, arriving through
// the one program that cannot sweep anything.
func TestRefusesRetiringAFundedAddress(t *testing.T) {
	p := spec.Devnet()
	alice := key(t, 2)
	target := alice.OneShot()

	funded := fundedState(t, map[types.Slot]u256.U256{
		types.NativeBalanceSlot(target):             drops(7_000_000),
		types.NativeBalanceSlot(alice.Persistent()): drops(1_000_000_000),
	})

	// The deposit is alice's own, which is what `zcd wallet retire` builds:
	// a retire funded by somebody else would send alice's residual to them
	// under F8b, and CheckBurnedResidualComesHome refuses that separately.
	build := func() *types.Certificate {
		t.Helper()
		c, err := (&wallet.Builder{
			Params:  p,
			Program: wallet.Retire(target),
			TTL:     100,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}).Build()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	if err := wallet.CheckAll(build(), funded, p, nil); !errors.Is(err, wallet.ErrPartialOneShotSpend) {
		t.Fatalf("got %v, want a refusal to retire a funded address (I1-L4)", err)
	}

	// Swept first, retired after: nothing is left to strand.
	swept := fundedState(t, map[types.Slot]u256.U256{
		types.NativeBalanceSlot(alice.Persistent()): drops(1_000_000_000),
	})
	if err := wallet.CheckAll(build(), swept, p, nil); err != nil {
		t.Fatalf("retiring an empty address should be allowed: %v", err)
	}
}

// TestRetiringTheAddressFundingIt is the case where the two roles coincide:
// the retire target is also the deposit cell, so the reservation is what
// empties it and it is not required to be empty beforehand.
func TestRetiringTheAddressFundingIt(t *testing.T) {
	p := spec.Devnet()
	alice := key(t, 2)
	target := alice.OneShot()
	balance := drops(900_000_000)

	s := fundedState(t, map[types.Slot]u256.U256{
		types.NativeBalanceSlot(target): balance,
	})

	c, err := (&wallet.Builder{
		Params:  p,
		Program: wallet.Retire(target),
		TTL:     100,
		Deposit: wallet.SweepDeposit(target, alice.Persistent(), balance),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.CheckAll(c, s, p, nil); err != nil {
		t.Fatalf("a RETIRE swept through its own deposit should be allowed: %v", err)
	}
}

func TestRefusesBurnedRefundDestination(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 2), key(t, 3)
	dead := key(t, 4).OneShot()

	s := fundedState(t, map[types.Slot]u256.U256{
		types.NativeBalanceSlot(alice.Persistent()): drops(5_000_000_000),
	})
	s.MarkSpent(dead)

	deposit := types.Deposit{
		Cell:     types.NativeBalanceSlot(alice.Persistent()),
		RefundTo: types.NativeBalanceSlot(dead),
	}
	b := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), drops(1_000)),
		TTL:     100,
		Deposit: deposit,
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}
	c, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.CheckAll(c, s, p, nil); !errors.Is(err, wallet.ErrRefundToBurned) {
		t.Fatalf("got %v, want a burned-refund refusal (I1-M2)", err)
	}
}

func TestRefusesPayingAUsedOneShot(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 2), key(t, 3)
	used := bob.OneShot()

	base := map[types.Slot]u256.U256{
		types.NativeBalanceSlot(alice.Persistent()): drops(5_000_000_000),
	}

	build := func() *types.Certificate {
		b := &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.Persistent(), used, drops(1_000)),
			TTL:     100,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}
		c, err := b.Build()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	// Already credited: paying again races whatever the payee does next.
	credited := fundedState(t, base)
	credited.Set(types.NativeBalanceSlot(used), drops(7))
	if err := wallet.CheckAll(build(), credited, p, nil); !errors.Is(err, wallet.ErrPayingUsedOneShot) {
		t.Fatalf("got %v, want a used-payee refusal (I1-H3)", err)
	}

	// Already spent: the payment would skip outright.
	spent := fundedState(t, base)
	spent.MarkSpent(used)
	if err := wallet.CheckAll(build(), spent, p, nil); !errors.Is(err, wallet.ErrPayingUsedOneShot) {
		t.Fatalf("got %v, want a spent-payee refusal (I1-H3)", err)
	}

	// A fresh address is fine.
	fresh := fundedState(t, base)
	if err := wallet.CheckAll(build(), fresh, p, nil); err != nil {
		t.Fatalf("paying a fresh one-shot was refused: %v", err)
	}
}

// TestPersistentPayeesHaveNoSurface: rule 3's escape. A 0x02 address can never
// be burned, so paying one twice is unremarkable.
func TestPersistentPayeesHaveNoSurface(t *testing.T) {
	p := spec.Devnet()
	alice, merchant := key(t, 2), key(t, 3)

	s := fundedState(t, map[types.Slot]u256.U256{
		types.NativeBalanceSlot(alice.Persistent()):    drops(5_000_000_000),
		types.NativeBalanceSlot(merchant.Persistent()): drops(999),
	})

	b := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, alice.Persistent(), merchant.Persistent(), drops(1_000)),
		TTL:     100,
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}
	c, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.CheckAll(c, s, p, nil); err != nil {
		t.Fatalf("paying an already-credited persistent address was refused: %v", err)
	}
}

// TestHeadroomMustFitTheBalance is R2-H1's accepted cost made actionable: the
// maximum is free in fees but reserved from the balance, so a small holder must
// shrink the window rather than the safety.
func TestHeadroomMustFitTheBalance(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 2), key(t, 3)

	s := fundedState(t, map[types.Slot]u256.U256{
		types.NativeBalanceSlot(alice.Persistent()): drops(2_000_000),
	})

	b := &wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), drops(1_000)),
		TTL:     100,
		Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
		// A hundredfold buffer: free in fees, unaffordable in reserve.
		FeeBid:  wallet.BidWithHeadroom(drops(1_000), drops(10), drops(100), drops(5), 100),
		Signers: []*wallet.Key{alice},
	}
	c, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.CheckAll(c, s, p, nil); !errors.Is(err, wallet.ErrHeadroomExceedsBalance) {
		t.Fatalf("got %v, want an unaffordable-headroom refusal (R2-H1)", err)
	}

	// The escape hatch: a narrower maximum fits, at the cost of being stranded
	// sooner if the market moves.
	b.FeeBid = wallet.BidWithHeadroom(drops(1_000), drops(10), drops(100), drops(5), 2)
	narrow, err := b.Build()
	if err != nil {
		t.Fatal(err)
	}
	if err := wallet.CheckAll(narrow, s, p, nil); err != nil {
		t.Fatalf("a narrow maximum was still refused: %v", err)
	}
}
