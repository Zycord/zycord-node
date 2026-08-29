package wallet_test

import (
	"bytes"
	"errors"
	"fmt"
	"strings"
	"testing"

	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/core/validity"
	"zycord/spec"
	"zycord/wallet"
)

// The property this file pins, in one sentence: **the wallet refuses what the
// network refuses** — the codec's rules as well as the fold's, before anything
// is signed or submitted.

// TestBuildRefusesABidThatIsNotCanonical.
//
// Canonical form is "at most Max, of which Priority is the tip"
// (types.FeeBid), and UnmarshalFeeBid enforces it. At one point neither
// Builder.Build nor validity.Check did, so a wallet could build and locally
// validate bytes its own node would refuse to decode. V1 is where the rule
// belongs: CheckCanonical's whole stated purpose is to repeat the decoder's
// rules for certificates that were built in memory rather than decoded.
//
// The control is the anti-vacuity half and it is the same builder with one
// field changed: an in-range bid on the identical fixture builds and
// round-trips, so the refusal is the rule firing and not the fixture being
// unbuildable for some unrelated reason.
func TestBuildRefusesABidThatIsNotCanonical(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 2), key(t, 3)

	newBuilder := func(fb types.FeeBid) *wallet.Builder {
		return &wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, alice.Persistent(), bob.Persistent(), drops(1_000)),
			TTL:     100,
			Deposit: wallet.SelfDeposit(alice.Persistent(), alice.Persistent()),
			FeeBid:  fb,
			Signers: []*wallet.Key{alice},
		}
	}

	// Both markets, because canonical form is stated of each and a rule that
	// covered only the sequential one would leave the identical divergence in
	// the parallel one.
	for _, tc := range []struct {
		name string
		fb   types.FeeBid
	}{
		{"sequential priority above its maximum", wallet.Bid(drops(1_000_000), drops(1_000_000_000), drops(500), drops(10))},
		{"parallel priority above its maximum", wallet.Bid(drops(50_000), drops(1_000), drops(500), drops(500_000))},
	} {
		c, err := newBuilder(tc.fb).Build()
		if err == nil {
			t.Fatalf("%s: Build accepted a certificate no peer could decode (id %x)", tc.name, c.ID())
		}
		// Not merely "an error": the V1 rule, so the test cannot pass
		// because the fixture failed to sign, failed to derive, or ran out
		// of deposit.
		if got := validity.Rule(err); got != "V1" {
			t.Fatalf("%s: refused by rule %q (%v), want V1", tc.name, got, err)
		}
		// And the decoder must agree, which is the whole point of repeating
		// its rule here rather than inventing one.
		bad := newBuilder(tc.fb)
		reads, writes, derr := validity.DeriveCert(bad.Program, p.ChainID, 0, bad.Deposit.Cell.Addr)
		if derr != nil {
			t.Fatal(derr)
		}
		raw := &types.Certificate{
			ChainID: p.ChainID, Program: bad.Program, Reads: reads, Writes: writes,
			Deposit: bad.Deposit, TTL: bad.TTL, FeeBid: tc.fb,
			Sigs: []types.Sig{{PubKey: alice.PubKey()}},
		}
		ceiling, ok := raw.FeeCeiling(p)
		if !ok {
			t.Fatal("fee ceiling overflows")
		}
		raw.Deposit.Amount = ceiling
		raw.Sigs[0].Sig = alice.Sign(raw.SigningMessage(p))
		if _, err := types.UnmarshalCertificate(raw.MarshalSSZ(), p); err == nil {
			t.Fatalf("%s: the decoder accepted it, so V1 would be inventing a rule", tc.name)
		}
	}

	// The control: the same builder, an in-range bid, accepted and decodable.
	good, err := newBuilder(bid()).Build()
	if err != nil {
		t.Fatalf("the control fixture does not build, so the refusals above prove nothing: %v", err)
	}
	if _, err := types.UnmarshalCertificate(good.MarshalSSZ(), p); err != nil {
		t.Fatalf("the control does not round-trip: %v", err)
	}
}

// TestBuildEmitsNothingItsOwnEncodingCannotDecode is the general form of the
// builder-versus-codec divergence, on the move-list axis rather than the
// fee-bid one.
//
// It used to assert a live *divergence*: UnmarshalProgram enforced
// params.MaxMovesPerTransfer and validity.Check did not, so a TRANSFER of
// MaxMovesPerTransfer+1 moves out of one source derived only 34 writes against
// a limit of 64, passed every V-rule, and was refused by the codec alone. That
// is what made Build's round-trip guard load-bearing rather than decorative,
// and the test was written to fail if the guard were removed.
//
// That divergence is now closed — CheckCanonical bounds the program's own
// lists against the same two parameters UnmarshalProgram is given — so this
// test asserts the *convergence* instead, on the same fixture: both
// authorities refuse the same certificate, and Build refuses it by the rule.
// Deliberately not deleted and deliberately not re-pointed at some other
// witness: the two authorities agreeing on this shape is the property this
// file exists for, and a change that takes either refusal away fails here.
//
// Build's round-trip guard is left in place with no known live witness, which
// is the state the guard was written for. It asserts the property — what Build
// emits, a peer can decode — rather than enumerating the codec's rules, so a
// rule the codec gains tomorrow is covered on the day it is added.
func TestBuildEmitsNothingItsOwnEncodingCannotDecode(t *testing.T) {
	p := spec.Devnet()
	alice := key(t, 4)
	src := alice.Persistent()

	program := func(n int) types.Program {
		moves := make([]types.Move, 0, n)
		for i := 0; i < n; i++ {
			moves = append(moves, types.Move{
				Asset:  types.NativeAsset,
				Src:    src,
				Dst:    key(t, byte(100+i)).Persistent(),
				Amount: drops(uint64(i + 1)),
			})
		}
		return wallet.Transfer(moves...)
	}
	newBuilder := func(n int) *wallet.Builder {
		return &wallet.Builder{
			Params:  p,
			Program: program(n),
			TTL:     100,
			Deposit: wallet.SelfDeposit(src, src),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}
	}

	over := p.MaxMovesPerTransfer + 1

	// The convergence, on the raw certificate rather than through Build, so
	// that each authority is asked separately.
	b := newBuilder(over)
	reads, writes, err := validity.DeriveCert(b.Program, p.ChainID, 0, b.Deposit.Cell.Addr)
	if err != nil {
		t.Fatal(err)
	}
	raw := &types.Certificate{
		ChainID: p.ChainID, Program: b.Program, Reads: reads, Writes: writes,
		Deposit: b.Deposit, TTL: b.TTL, FeeBid: bid(),
		Sigs: []types.Sig{{PubKey: alice.PubKey()}},
	}
	ceiling, ok := raw.FeeCeiling(p)
	if !ok {
		t.Fatal("fee ceiling overflows")
	}
	raw.Deposit.Amount = ceiling
	raw.Sigs[0].Sig = alice.Sign(raw.SigningMessage(p))
	// The rule side, and named rather than merely non-nil: V1 is where the
	// codec's length limits belong, so a refusal from some other rule would
	// mean this fixture is unbuildable for an unrelated reason.
	if got := validity.Rule(validity.Check(raw, p)); got != "V1" {
		t.Fatalf("validity.Check refused this shape by rule %q, want V1: %v", got, validity.Check(raw, p))
	}
	// The codec side. Both must refuse, or V1 is inventing a rule the network
	// does not have — the same builder/codec divergence, with the sign flipped.
	if _, err := types.UnmarshalCertificate(raw.MarshalSSZ(), p); err == nil {
		t.Fatal("the decoder accepts it, so V1 is now refusing a certificate a peer would take")
	}

	// And Build, which is the surface a user reaches, refuses it before
	// anything is signed or submitted.
	if c, err := newBuilder(over).Build(); err == nil {
		t.Fatalf("Build emitted a certificate no peer can decode (id %x)", c.ID())
	} else if got := validity.Rule(err); got != "V1" {
		t.Fatalf("Build refused by %q rather than V1: %v", got, err)
	}

	// The control: one move fewer is inside the limit and must still build.
	if _, err := newBuilder(p.MaxMovesPerTransfer).Build(); err != nil {
		t.Fatalf("the control at the limit does not build, so the refusal above proves nothing: %v", err)
	}
}

// TestRefusesATransferTheFoldCouldOnlySkip is the overspend property.
//
// A transfer above the source's balance breaks no rule: it is admitted
// everywhere, skipped by the fold at whatever height it is included, and so
// included nowhere and evicted at TTL. The signer is told `submitted` and
// learns nothing. The balance is already fetched on this path for the
// fee-reserve check; the comparison against the amount was simply absent.
func TestRefusesATransferTheFoldCouldOnlySkip(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 5), key(t, 6)
	from := alice.Persistent()

	build := func(amount u256.U256) *types.Certificate {
		t.Helper()
		c, err := (&wallet.Builder{
			Params:  p,
			Program: wallet.Tip(types.NativeAsset, from, bob.Persistent(), amount),
			TTL:     100,
			Deposit: wallet.SelfDeposit(from, from),
			FeeBid:  bid(),
			Signers: []*wallet.Key{alice},
		}).Build()
		if err != nil {
			t.Fatal(err)
		}
		return c
	}

	amount := drops(1_000_000)
	c := build(amount)
	ceiling, ok := c.FeeCeiling(p)
	if !ok {
		t.Fatal("fee ceiling overflows")
	}
	// Exactly what this certificate takes out of the cell: the amount plus
	// the reservation, which comes out of the same cell here.
	need, overflow := amount.Add(ceiling)
	if overflow {
		t.Fatal("fixture overflows")
	}

	funded := func(held u256.U256) *state.State {
		return fundedState(t, map[types.Slot]u256.U256{types.NativeBalanceSlot(from): held})
	}

	// One drop short is refused, and refused by the amount rule rather than
	// by the fee-reserve rule that already existed — the cell comfortably
	// covers the reserve on its own.
	short := funded(need.SatSub(u256.One))
	err := wallet.CheckAll(c, short, p, nil)
	if !errors.Is(err, wallet.ErrMoveExceedsBalance) {
		t.Fatalf("got %v, want ErrMoveExceedsBalance", err)
	}
	if errors.Is(err, wallet.ErrHeadroomExceedsBalance) {
		t.Fatal("the fee-reserve rule fired, so this test would pass without the amount comparison")
	}
	if err := wallet.CheckHeadroomAffordable(c.Deposit, short, ceiling); err != nil {
		t.Fatalf("the fixture's cell does not even cover the reserve, so the refusal is not about the amount: %v", err)
	}

	// Exactly enough passes. This is the mutation that kills a guard which
	// fires for a benign reason: nothing about the fixture changed except the
	// single drop the rule is comparing.
	if err := wallet.CheckAll(c, funded(need), p, nil); err != nil {
		t.Fatalf("a fully funded transfer was refused: %v", err)
	}

	// And the amount is the discriminator, not the fee: on the *same* state,
	// a smaller amount passes.
	smaller := build(amount.SatSub(u256.One))
	if err := wallet.CheckAll(smaller, funded(need.SatSub(u256.One)), p, nil); err != nil {
		t.Fatalf("one drop less is affordable and was refused: %v", err)
	}
}

// TestTheOverridableRuleRunsLast is the property session.SendOptions.Force
// rests on, and it is the reason Force can be narrowed to one sentinel
// safely.
//
// CheckAll stops at the first refusal. If the rule a caller is allowed to
// override stood in front of the others, overriding it would silently skip
// them. Running it last makes "everything else passed" a fact about any error
// Force is permitted to swallow. Here the certificate violates both the
// one-shot sweep rule and the coverage rule, and CheckAll must report the
// one Force cannot touch.
func TestTheOverridableRuleRunsLast(t *testing.T) {
	p := spec.Devnet()
	alice, bob := key(t, 7), key(t, 8)
	oneShot := alice.OneShot()

	c, err := (&wallet.Builder{
		Params:  p,
		Program: wallet.Tip(types.NativeAsset, oneShot, bob.Persistent(), drops(5_000_000)),
		TTL:     100,
		Deposit: wallet.SelfDeposit(oneShot, alice.Persistent()),
		FeeBid:  bid(),
		Signers: []*wallet.Key{alice},
	}).Build()
	if err != nil {
		t.Fatal(err)
	}
	ceiling, _ := c.FeeCeiling(p)

	// The cell holds more than the reserve — so CheckHeadroomAffordable
	// passes — but less than amount+reserve, and it is a one-shot spent in
	// part. Both rules have something to say.
	held, _ := ceiling.Add(drops(1_000))
	s := fundedState(t, map[types.Slot]u256.U256{types.NativeBalanceSlot(oneShot): held})

	if err := wallet.CheckMovesAreCovered(c.Program, c.Deposit, s, ceiling); !errors.Is(err, wallet.ErrMoveExceedsBalance) {
		t.Fatalf("the fixture does not violate the coverage rule, so the ordering is untested: %v", err)
	}
	if err := wallet.CheckAll(c, s, p, nil); !errors.Is(err, wallet.ErrPartialOneShotSpend) {
		t.Fatalf("CheckAll reported %v; the overridable rule must not stand in front of I1-L4", err)
	}
}

// TestCoverageIsCheckedAgainstTheCellTheMoveActuallyDebits.
//
// The overspend rule is per (source, asset) balance cell, and that is not
// decoration: a TRANSFER may move several assets out of several sources while
// the deposit is paid from a cell that has nothing to do with any of them. Two
// ways of getting this wrong both look correct on the single-move,
// native-asset, source-is-the-deposit-cell shape `zcd wallet send` builds —
// charging every move to the deposit cell, and charging every move to its
// source's *native* cell whatever asset it moves. Both survived the rest of
// this file; each half below kills one of them.
func TestCoverageIsCheckedAgainstTheCellTheMoveActuallyDebits(t *testing.T) {
	payer := key(t, 30).Persistent()
	srcA := key(t, 31).Persistent()
	srcB := key(t, 32).Persistent()
	dst := key(t, 33).Persistent()
	asset := key(t, 34).Persistent()

	ceiling := drops(10_000)
	ample := drops(1_000_000_000)
	deposit := wallet.SelfDeposit(payer, payer)
	prog := wallet.Transfer(
		types.Move{Asset: types.NativeAsset, Src: srcA, Dst: dst, Amount: drops(1_000)},
		types.Move{Asset: asset, Src: srcB, Dst: dst, Amount: drops(500)},
	)

	// The deposit cell is ample throughout, so nothing below can be the
	// reservation firing, and neither source is the deposit cell.
	base := func() map[types.Slot]u256.U256 {
		return map[types.Slot]u256.U256{
			types.NativeBalanceSlot(payer): ample,
			types.NativeBalanceSlot(srcA):  ample,
			types.NativeBalanceSlot(srcB):  ample,
			types.BalanceSlot(srcB, asset): ample,
		}
	}
	names := func(err error, a types.Address) bool {
		return err != nil && strings.Contains(err.Error(), fmt.Sprintf("%x", a[:6]))
	}

	// The control first: fully funded, this program is covered. If it were
	// not, every refusal below would prove nothing.
	if err := wallet.CheckMovesAreCovered(prog, deposit, fundedState(t, base()), ceiling); err != nil {
		t.Fatalf("the fully funded control was refused: %v", err)
	}

	// A move is charged to its own source, not to whatever cell pays the
	// deposit. srcA is one drop short; the deposit cell could absorb it a
	// hundred thousand times over.
	shortSrc := base()
	shortSrc[types.NativeBalanceSlot(srcA)] = drops(999)
	err := wallet.CheckMovesAreCovered(prog, deposit, fundedState(t, shortSrc), ceiling)
	if !errors.Is(err, wallet.ErrMoveExceedsBalance) {
		t.Fatalf("a move above its own source's balance was accepted because another cell was rich: %v", err)
	}
	if !names(err, srcA) {
		t.Fatalf("the refusal names the wrong cell (want %x): %v", srcA[:6], err)
	}

	// And to its own *asset's* cell. srcB is one drop short of the asset it
	// moves while holding a fortune in the native coin, so a check that read
	// the native cell would let it through.
	shortAsset := base()
	shortAsset[types.BalanceSlot(srcB, asset)] = drops(499)
	err = wallet.CheckMovesAreCovered(prog, deposit, fundedState(t, shortAsset), ceiling)
	if !errors.Is(err, wallet.ErrMoveExceedsBalance) {
		t.Fatalf("a move above the source's balance in the asset it moves was accepted: %v", err)
	}
	if !names(err, srcB) {
		t.Fatalf("the refusal names the wrong cell (want %x): %v", srcB[:6], err)
	}
}

// TestTheRefusalNamesTheSameCellWhenTwoAreShort.
//
// CheckMovesAreCovered keeps an explicit `order` slice beside its map, and the
// comment on it claims the refusal "names the same cell every run". Nothing
// pinned that: every other fixture in this file leaves exactly one cell short,
// and with one candidate a map iteration and an ordered one agree. Replacing
// the ordered loop with `for slot, want := range need` passes the whole suite
// unless two cells are short at once.
//
// The cell named is the first one the certificate itself reaches — the deposit
// cell, then the moves in the order wallet.Transfer sorted them — so the
// expected answer is derived from the program rather than hardcoded, and the
// loop is what makes a randomized map iteration fail rather than flake: Go
// randomizes map order per range, so a hundred agreeing runs is not a
// coincidence a non-deterministic implementation can produce.
func TestTheRefusalNamesTheSameCellWhenTwoAreShort(t *testing.T) {
	payer := key(t, 40).Persistent()
	srcA := key(t, 41).Persistent()
	srcB := key(t, 42).Persistent()
	dst := key(t, 43).Persistent()

	ceiling := drops(10_000)
	amount := drops(1_000)
	deposit := wallet.SelfDeposit(payer, payer)
	prog := wallet.Transfer(
		types.Move{Asset: types.NativeAsset, Src: srcA, Dst: dst, Amount: amount},
		types.Move{Asset: types.NativeAsset, Src: srcB, Dst: dst, Amount: amount},
	)

	// Both sources are one drop short; the deposit cell is ample, so the
	// refusal is about a move and there are exactly two candidates for it.
	s := fundedState(t, map[types.Slot]u256.U256{
		types.NativeBalanceSlot(payer): drops(1_000_000_000),
		types.NativeBalanceSlot(srcA):  amount.SatSub(u256.One),
		types.NativeBalanceSlot(srcB):  amount.SatSub(u256.One),
	})

	// The two candidates are real: each cell on its own is short enough to be
	// refused, so neither is a decoy that only one iteration order could reach.
	for _, src := range []types.Address{srcA, srcB} {
		one := wallet.Transfer(types.Move{Asset: types.NativeAsset, Src: src, Dst: dst, Amount: amount})
		if err := wallet.CheckMovesAreCovered(one, deposit, s, ceiling); !errors.Is(err, wallet.ErrMoveExceedsBalance) {
			t.Fatalf("%x is not short on its own, so it cannot be a second candidate: %v", src[:6], err)
		}
	}

	// wallet.Transfer sorts by asset, then source; the assets and destinations
	// match, so the lower source address is the move the certificate reaches
	// first, and the deposit cell is reached before either.
	want := srcA
	if bytes.Compare(srcB[:], srcA[:]) < 0 {
		want = srcB
	}
	wantHex := fmt.Sprintf("%x", want[:6])

	for i := 0; i < 100; i++ {
		err := wallet.CheckMovesAreCovered(prog, deposit, s, ceiling)
		if !errors.Is(err, wallet.ErrMoveExceedsBalance) {
			t.Fatalf("run %d: got %v, want ErrMoveExceedsBalance", i, err)
		}
		if !strings.Contains(err.Error(), wantHex) {
			t.Fatalf("run %d: the refusal named a different cell than the run before (want %s): %v", i, wantHex, err)
		}
	}
}
