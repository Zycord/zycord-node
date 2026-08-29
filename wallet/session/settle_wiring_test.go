package session

import (
	"errors"
	"testing"

	"zycord/core/crypto"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
	"zycord/wallet"
)

// TestSettleAsksTheViewBeforeTheBalanceRules pins the property that the
// coverage question is answered where it can be answered, and answered first.
//
// It is white-box on purpose. settle is unexported and its two callers, Send
// and Retire, both build certificates over cells FetchState has just fetched,
// so no exported path can reach an uncovered certificate today; the guard is
// there for the first one that can — a multi-asset transfer, or any caller
// that assembles its own View. Driving settle directly is the only way to
// assert the wiring exists, and without it the call can be deleted with every
// other test in this package still passing.
//
// The ordering is the second half of the property and it is what the two
// assertions below separate. An unfetched cell reads as an empty one, so the
// balance rules would refuse the same certificate with ErrMoveExceedsBalance:
// the wrong claim about whose state is short, and — under Force — the one
// refusal this package is allowed to swallow.
func TestSettleAsksTheViewBeforeTheBalanceRules(t *testing.T) {
	p := spec.Devnet()
	var src, dst types.Address
	src[0], dst[0] = crypto.AddrVersionPersistent, crypto.AddrVersionPersistent
	src[19], dst[19] = 0xAA, 0xBB

	cert := &types.Certificate{
		Deposit: types.Deposit{Cell: types.NativeBalanceSlot(src), RefundTo: types.NativeBalanceSlot(src)},
		Program: wallet.Tip(types.NativeAsset, src, dst, u256.FromUint64(1_500_000)),
	}
	// A view that fetched nothing at all: state.State cannot tell that apart
	// from a view whose cells are empty, which is the whole point. The source
	// carries enough to clear the fee reserve and not enough to cover the
	// move, so the rule that would answer instead of this one is exactly
	// ErrMoveExceedsBalance — the refusal Force is allowed to swallow.
	st := state.New()
	st.Set(types.NativeBalanceSlot(src), u256.FromUint64(2_000_000))
	view := &View{Params: p, State: st, fetched: map[types.Slot]struct{}{}}

	s := &Session{}
	if _, err := s.settle(cert, view, src, dst, src, u256.FromUint64(1_500_000), DefaultSendOptions()); !errors.Is(err, ErrCellNotFetched) {
		t.Fatalf("settle did not ask the view first; it refused with %v", err)
	}

	// And Force does not reach past it. If the coverage question were asked
	// after wallet.CheckAll, this is the case that would have been overridden
	// rather than refused.
	forced := DefaultSendOptions()
	forced.Force = true
	_, err := s.settle(cert, view, src, dst, src, u256.FromUint64(1_500_000), forced)
	if !errors.Is(err, ErrCellNotFetched) {
		t.Fatalf("Force swallowed an uncovered cell: %v", err)
	}
	if errors.Is(err, wallet.ErrMoveExceedsBalance) {
		t.Fatal("an uncovered cell was reported as an underfunded one")
	}
}
