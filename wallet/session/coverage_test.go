package session

import (
	"errors"
	"strings"
	"testing"

	"zycord/core/crypto"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
	"zycord/wallet"
)

// The property, in one sentence: a session view refuses a certificate whose
// policy rules would read an answer it does not hold, and it names which
// answer — separately for every read those rules perform.
//
// These are white-box on purpose. The two sets a View records are unexported
// and FetchState always fills both together for the same address, so no
// exported constructor can produce a view that holds one answer about an
// address and not the other. That combination is exactly what separates the
// conjuncts of the coverage guard, and a test that could not build it would be
// asserting the conjunction rather than its terms. The end-to-end separating
// input — the same certificate against FetchState(from) and
// FetchState(from, payee) — is in session_test.go, where it belongs.

func oneShot(b byte) types.Address {
	var a types.Address
	a[0], a[19] = crypto.AddrVersionOneShot, b
	return a
}

func persistent(b byte) types.Address {
	var a types.Address
	a[0], a[19] = crypto.AddrVersionPersistent, b
	return a
}

// coverageFixture is one source, one refund, one payee and the certificate
// paying it, plus a view builder that starts fully covered. Every case below
// removes exactly one answer from that view, so the term under test is the
// only difference between it and a view that passes.
type coverageFixture struct {
	src, refund, payee types.Address
	cert               *types.Certificate
	asset              types.Address
}

func newCoverageFixture(payee types.Address, asset types.Address) coverageFixture {
	f := coverageFixture{src: persistent(0xAA), refund: persistent(0xCC), payee: payee, asset: asset}
	f.cert = &types.Certificate{
		Deposit: types.Deposit{
			Cell:     types.NativeBalanceSlot(f.src),
			RefundTo: types.NativeBalanceSlot(f.refund),
		},
		Program: wallet.Tip(asset, f.src, f.payee, u256.FromUint64(1_000)),
	}
	return f
}

// full builds the view that holds every answer the rules will ask for. The
// balances are irrelevant to coverage — what is under test is which questions
// the view can answer at all, not what the answers are — but the source is
// funded so that a mutant which lets the certificate through to
// wallet.CheckAll is not rescued by a balance rule refusing for its own
// reasons.
func (f coverageFixture) full() *View {
	st := state.New()
	st.Set(types.NativeBalanceSlot(f.src), u256.FromUint64(1_000_000_000))
	return &View{
		Params: spec.Devnet(),
		State:  st,
		fetched: map[types.Slot]struct{}{
			types.NativeBalanceSlot(f.src):      {},
			types.BalanceSlot(f.src, f.asset):   {},
			types.BalanceSlot(f.payee, f.asset): {},
			types.NativeBalanceSlot(f.payee):    {},
			types.NativeBalanceSlot(f.refund):   {},
		},
		fetchedSpent: map[types.Address]struct{}{
			f.src: {}, f.payee: {}, f.refund: {},
		},
	}
}

// TestEachCoverageAxisRefusesOnItsOwnSeparatingInput separates each term of
// the coverage guard on its own input.
//
// The name is deliberately about the AXES and not about completeness. This
// test pins that every axis CoversCertificate has today refuses on an input
// that isolates it; it does NOT and cannot pin that the axes cover every read
// wallet.CheckAll performs, because a rule added tomorrow that reads a new
// cell would leave this green. That completeness claim is the enumeration in
// CoversCertificate's doc comment, and it is pinned separately and
// structurally by wallet.TestEveryStateReadInPackageWalletIsPinnedToACoverageAxis, which
// derives CheckAll's reads from the source and fails when a new one appears
// without an axis. Deliberately two tests: one asserts the axes SEPARATE, the
// other asserts they are COMPLETE, and a single test claiming both would be
// named for a property half of it cannot check.
//
// The guard is a conjunction over six reads — three debited cells, three
// credited destinations — and a single failing certificate would satisfy a
// conjunction's name while exercising one of its terms. Each case below starts
// from a view that covers everything, deletes exactly one answer, and asserts
// both that the refusal happens and that it names the axis — because with more
// than one axis able to return the same sentinel, "some error came back" does
// not identify which clause ran.
func TestEachCoverageAxisRefusesOnItsOwnSeparatingInput(t *testing.T) {
	f := newCoverageFixture(oneShot(0xBB), types.NativeAsset)

	// The control. If this ever fails, every case below is passing for the
	// wrong reason and none of them separates anything.
	if err := f.full().CoversCertificate(f.cert); err != nil {
		t.Fatalf("a view holding every answer must cover the certificate: %v", err)
	}

	cases := []struct {
		name string
		// drop removes exactly one answer from an otherwise complete view.
		drop func(*View)
		want error
		// names is a fragment of the message that only the intended clause
		// can produce, so a different clause returning the same sentinel is
		// not mistaken for this one.
		names string
	}{
		{
			// Debited term 1. CheckHeadroomAffordable and CheckMovesAreCovered read the
			// deposit cell.
			name: "deposit cell",
			drop: func(v *View) { delete(v.fetched, types.NativeBalanceSlot(f.src)) },
			want: ErrCellNotFetched, names: "deposit cell",
		},
		// Debited term 2, the TRANSFER move source, is NOT in this table and that is
		// deliberate rather than an omission: under the native asset
		// BalanceSlot(src, NativeAsset) IS the deposit cell here, so dropping it
		// would exercise term 1 above under term 2's name. Its own separating input
		// — a move under an asset the view never fetched, with the deposit cell held
		// fixed and fetched — is TestSessionViewRefusesACellItNeverFetched in
		// session_test.go.
		{
			// Credited term 4. CheckPayeeIsFresh reads s.IsSpent(m.Dst). The payee's
			// BALANCE cell stays fetched, so the term below cannot be the one that
			// fires — this input separates the spent flag from the credited cell, which
			// FetchState always supplies together.
			name: "payee spent flag",
			drop: func(v *View) { delete(v.fetchedSpent, f.payee) },
			want: ErrSpentFlagNotFetched, names: "one-shot payee",
		},
		{
			// Credited term 5. CheckPayeeIsFresh reads s.Get(BalanceSlot(m.Dst,
			// m.Asset)). The payee's spent flag stays known, so the term above cannot
			// be the one that fires.
			name: "payee credited cell",
			drop: func(v *View) { delete(v.fetched, types.BalanceSlot(f.payee, f.asset)) },
			want: ErrCellNotFetched, names: "one-shot payee",
		},
		{
			// Credited term 6. CheckRefundDestination reads s.IsSpent(RefundTo.Addr).
			// Its own address, distinct from both the source and the payee, so neither
			// of their clauses can answer for it.
			name: "refund destination spent flag",
			drop: func(v *View) { delete(v.fetchedSpent, f.refund) },
			want: ErrSpentFlagNotFetched, names: "refund destination",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			v := f.full()
			tc.drop(v)
			err := v.CoversCertificate(f.cert)
			if !errors.Is(err, tc.want) {
				t.Fatalf("dropping the %s answer must be refused as %v, got %v", tc.name, tc.want, err)
			}
			if !strings.Contains(err.Error(), tc.names) {
				t.Fatalf("the refusal must name the %s clause; got %q, which does not mention %q",
					tc.name, err.Error(), tc.names)
			}
		})
	}

	// Debited term 3, on its own program kind: a RETIRE target. Kept here rather
	// than in the table because it needs a different certificate, and its
	// separating input is the same certificate against a view that did fetch the
	// target (that half is pinned in session_test.go).
	burn := oneShot(0xDD)
	retire := &types.Certificate{
		Deposit: f.cert.Deposit,
		Program: wallet.Retire(burn),
	}
	v := f.full()
	if err := v.CoversCertificate(retire); !errors.Is(err, ErrCellNotFetched) {
		t.Fatalf("a retire target this view never fetched must be refused as uncovered, got %v", err)
	}
	v.fetched[types.NativeBalanceSlot(burn)] = struct{}{}
	if err := v.CoversCertificate(retire); err != nil {
		t.Fatalf("a retire target this view fetched must be covered: %v", err)
	}
}

// TestPayeeCoverageDoesNotFireForAPayeeNoRuleReads is the anti-vacuity half of
// the payee axis: the guard must mirror wallet.CheckPayeeIsFresh's own
// one-shot test exactly.
//
// A persistent address can never be burned, so that rule reads nothing about
// it and this view must require nothing about it. Without this, the payee axis
// would refuse every ordinary transfer to an address the session did not
// happen to fetch — a check firing for a benign reason, which is the failure
// mode the testing discipline names outright.
func TestPayeeCoverageDoesNotFireForAPayeeNoRuleReads(t *testing.T) {
	f := newCoverageFixture(persistent(0xBB), types.NativeAsset)
	v := f.full()
	// The persistent payee is unknown on BOTH axes: neither its spent flag
	// nor its balance cell. This is precisely what a session that fetched
	// only the source and the refund holds.
	delete(v.fetchedSpent, f.payee)
	delete(v.fetched, types.BalanceSlot(f.payee, f.asset))
	delete(v.fetched, types.NativeBalanceSlot(f.payee))
	if err := v.CoversCertificate(f.cert); err != nil {
		t.Fatalf("a persistent payee is read by no rule, so it must not need covering: %v", err)
	}

	// And the separating input: the same view, the same missing answers, with
	// the payee's address version flipped to one-shot. If the version test
	// were dropped from the guard the case above would fail; if the guard
	// were dropped entirely this one would.
	oneShotPayee := newCoverageFixture(oneShot(0xBB), types.NativeAsset)
	v2 := oneShotPayee.full()
	delete(v2.fetchedSpent, oneShotPayee.payee)
	delete(v2.fetched, types.BalanceSlot(oneShotPayee.payee, oneShotPayee.asset))
	delete(v2.fetched, types.NativeBalanceSlot(oneShotPayee.payee))
	if err := v2.CoversCertificate(oneShotPayee.cert); !errors.Is(err, ErrSpentFlagNotFetched) {
		t.Fatalf("the same unfetched payee, one-shot, must be refused: %v", err)
	}
}

// TestSettleRefusesAPayeeTheViewNeverFetched pins that settle's single
// coverage call reaches the payee axis, and that Force does not swallow it.
//
// This is the wiring half, and it is why the promise and the check are one
// object rather than two: if the payee axis were a second exported question,
// this test would be asserting that settle remembers to call it. Here it
// asserts that the object settle already calls answers for the payee too, so
// there is no second call site to forget.
//
// The state is deliberately funded and the payee deliberately clean, so every
// balance rule and wallet.CheckPayeeIsFresh itself would PASS on this input.
// Nothing but the coverage question can produce a refusal here — which is the
// fail-open direction of an uncovered read, made visible.
func TestSettleRefusesAPayeeTheViewNeverFetched(t *testing.T) {
	f := newCoverageFixture(oneShot(0xBB), types.NativeAsset)

	covered := f.full()
	if err := covered.CoversCertificate(f.cert); err != nil {
		t.Fatalf("control: the covered view must cover the certificate: %v", err)
	}

	unfetchedPayee := f.full()
	delete(unfetchedPayee.fetchedSpent, f.payee)
	delete(unfetchedPayee.fetched, types.BalanceSlot(f.payee, f.asset))
	delete(unfetchedPayee.fetched, types.NativeBalanceSlot(f.payee))

	s := &Session{}
	amount := u256.FromUint64(1_000)
	_, err := s.settle(f.cert, unfetchedPayee, f.src, f.payee, f.refund, amount, DefaultSendOptions())
	if !errors.Is(err, ErrSpentFlagNotFetched) {
		t.Fatalf("settle accepted a one-shot payee the view never fetched; it refused with %v", err)
	}
	// Not misattributed to the chain: the payee really is fresh as far as
	// anyone knows, so reporting I1-H3 here would be an accusation the wallet
	// has not verified.
	if errors.Is(err, wallet.ErrPayingUsedOneShot) {
		t.Fatal("an unfetched payee was reported as a used one-shot")
	}

	forced := DefaultSendOptions()
	forced.Force = true
	if _, err := s.settle(f.cert, unfetchedPayee, f.src, f.payee, f.refund, amount, forced); !errors.Is(err, ErrSpentFlagNotFetched) {
		t.Fatalf("Force swallowed an unanswerable payee: %v", err)
	}
}
