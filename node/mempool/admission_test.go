package mempool_test

import (
	"errors"
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/mempool"
	"zycord/sim/harness"
	"zycord/wallet"
)

// The admission path (docs/adversarial/mempool.md).
//
// Eviction under pressure is pinned in eviction_test.go. These tests pin the
// two checks that decide whether a certificate is admitted in the first
// place: the deposit screen (a sum across a cell's pooled certificates, not a
// per-certificate maximum) and the byte budget (a second occupancy limit
// alongside the certificate count).

// bigCert builds a TRANSFER certificate with n moves, all debited from one
// signer against n distinct (synthetic) assets and credited to n fresh
// destinations. Distinct assets, not distinct sources, is what buys distinct
// read/write slots without needing more than one signature — the shape a
// byte-budget attacker would actually pick, since sigs are the one field
// bounded independently of moves (max_sigs=16 against max_moves=32).
func (w *world) bigCert(signer *wallet.Key, seq uint64, seqPriority uint64, n int) *types.Certificate {
	w.t.Helper()
	from := signer.Persistent()
	var moves []types.Move
	for i := 0; i < n; i++ {
		asset := types.DeriveAssetAddress(w.p.ChainID, key(w.t, 800_000+i).Persistent(), 0)
		dst := key(w.t, 900_000+i).Persistent()
		moves = append(moves, types.Move{Asset: asset, Src: from, Dst: dst, Amount: drops(1)})
	}
	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Transfer(moves...),
		Seq:     seq,
		TTL:     20,
		Deposit: wallet.SelfDeposit(from, from),
		// The bid MAXIMA are what set the fee ceiling, and therefore the
		// deposit V5 now bounds from above as well as below: a
		// certificate may not reserve more than the emission schedule can have
		// issued by its own TTL, which at TTL 20 is 20 blocks of subsidy. A
		// max of 1e9 per gas unit put the ceiling at 2.3e13 against a bound of
		// 4.2e10 -- a fixture nobody could have funded on a real chain either.
		// The PRIORITIES are what these tests order by and they are untouched.
		FeeBid: wallet.Bid(
			drops(1_000_000), drops(seqPriority),
			drops(1_000_000), drops(1)),
		Signers: []*wallet.Key{signer},
	}
	c, err := b.Build()
	if err != nil {
		w.t.Fatalf("bigCert(n=%d): %v", n, err)
	}
	w.fund(from, c)
	return c
}

// fund tops up a certificate's deposit cell by its ceiling plus a generous
// buffer, additively — not by overwriting — because the screen is a sum across
// everything a cell already backs. Overwriting would silently un-fund a
// signer's earlier certificates every time a later one is built.
func (w *world) fund(addr types.Address, c *types.Certificate) {
	w.t.Helper()
	ceiling, ok := c.FeeCeiling(w.p)
	if !ok {
		w.t.Fatal("ceiling overflow")
	}
	slot := types.NativeBalanceSlot(addr)
	w.state.Set(slot, w.state.Get(slot).SatAdd(ceiling).SatAdd(drops(1_000_000_000_000)))
}

// TestDepositScreenSumsAcrossPooledCertificates: a cell backs every
// certificate pooled against it at once, not just the newest arrival, so the
// screen must be a sum. Funding the cell for only what a per-certificate
// check would have required proves the old rule would have admitted the
// second certificate too — the anti-vacuity check.
func TestDepositScreenSumsAcrossPooledCertificates(t *testing.T) {
	w := newWorld(t, smallPolicy())
	signer := key(t, 1)
	addr := signer.Persistent()

	first := w.cert(signer, 0, 100, 1)
	second := w.cert(signer, 1, 100, 1)

	ceiling1, ok := first.FeeCeiling(w.p)
	if !ok {
		t.Fatal("ceiling overflow")
	}
	ceiling2, ok := second.FeeCeiling(w.p)
	if !ok {
		t.Fatal("ceiling overflow")
	}

	// Fund for 1.5x one ceiling: enough to cover either certificate alone
	// (anti-vacuity — a per-certificate screen would admit both), not enough
	// to cover the sum of both.
	buffer := ceiling1.MulDiv64(1, 2)
	w.state.Set(types.NativeBalanceSlot(addr), ceiling1.SatAdd(buffer))
	if w.state.Get(types.NativeBalanceSlot(addr)).Lt(ceiling2) {
		t.Fatalf("setup: funded balance does not even cover the second certificate alone; "+
			"a per-certificate screen would already refuse it, so this test would not "+
			"distinguish the two rules (ceiling1=%s ceiling2=%s balance=%s)",
			ceiling1.String(), ceiling2.String(), w.state.Get(types.NativeBalanceSlot(addr)).String())
	}

	if err := w.add(first); err != nil {
		t.Fatalf("first certificate refused: %v", err)
	}
	err := w.add(second)
	if !errors.Is(err, mempool.ErrUnderfunded) {
		t.Fatalf("got %v, want ErrUnderfunded: the cell covers either certificate alone but "+
			"not their sum, so a screen that checks only the arrival in isolation would wrongly "+
			"admit it", err)
	}
}

// TestDepositScreenAdmitsUpToWhatTheCellCovers is the positive half: once the
// cell covers the sum, the second certificate is admitted. Without this,
// TestDepositScreenSumsAcrossPooledCertificates could pass against a screen
// that refuses everything.
func TestDepositScreenAdmitsUpToWhatTheCellCovers(t *testing.T) {
	w := newWorld(t, smallPolicy())
	signer := key(t, 2)

	first := w.cert(signer, 0, 100, 1)
	if err := w.add(first); err != nil {
		t.Fatalf("first certificate refused: %v", err)
	}
	second := w.cert(signer, 1, 100, 1) // w.cert funds additively (see eviction_test.go)
	if err := w.add(second); err != nil {
		t.Fatalf("a certificate backed by a cell that covers the full sum was refused: %v", err)
	}
}

// TestRescreenReEnforcesTheAggregateDepositSum: the amplification the aggregate
// screen closes at admission must not come back on the next block. If a cell's balance
// falls below what it backs, rescreening must shed certificates until the
// sum fits again — from the tail, so a dependent chain is never holed.
func TestRescreenReEnforcesTheAggregateDepositSum(t *testing.T) {
	w := newWorld(t, smallPolicy())
	signer := key(t, 3)
	addr := signer.Persistent()

	var chain []*types.Certificate
	for seq := uint64(0); seq < 3; seq++ {
		c := w.cert(signer, seq, 100, 1)
		if err := w.add(c); err != nil {
			t.Fatalf("seq %d refused during setup: %v", seq, err)
		}
		chain = append(chain, c)
	}

	// Simulate spending elsewhere: the cell now covers only the base of the
	// chain, not all three.
	ceiling0, ok := chain[0].FeeCeiling(w.p)
	if !ok {
		t.Fatal("ceiling overflow")
	}
	w.state.Set(types.NativeBalanceSlot(addr), ceiling0.SatAdd(ceiling0.MulDiv64(1, 10)))

	w.pool.Rescreen(w.state, 1)

	if !w.pool.Has(chain[0].ID()) {
		t.Fatal("the base of the chain was dropped even though the cell still covers it; " +
			"rescreening should shed from the tail")
	}
	if w.pool.Has(chain[2].ID()) {
		t.Fatal("the tail survived rescreening on a cell that can no longer cover the full sum")
	}
}

// TestMaxPerUnderwriterBindsAfterAggregation: aggregating the deposit screen
// does not make MaxPerUnderwriter redundant (docs/adversarial/mempool.md
// §2.5). The cell here is funded generously enough to cover every
// certificate's ceiling many times over — proving the deposit screen is not
// what refuses the extra certificates — yet the quota still caps admission.
func TestMaxPerUnderwriterBindsAfterAggregation(t *testing.T) {
	pol := smallPolicy()
	pol.MaxPerUnderwriter = 3
	w := newWorld(t, pol)
	whale := key(t, 4)

	// w.cert funds additively (see eviction_test.go): each call tops up the
	// cell by that certificate's own ceiling plus a 1e9-drop buffer, on top of
	// whatever the previous calls already left there. By the sixth call the
	// cell covers the sum of all six many times over, so if anything refuses
	// a certificate here it is not the deposit screen.
	var admitted int
	for seq := uint64(0); seq < 6; seq++ {
		c := w.cert(whale, seq, 100, 1)
		if err := w.add(c); err == nil {
			admitted++
		} else if !errors.Is(err, mempool.ErrTooManyInFlight) {
			t.Fatalf("seq %d refused for the wrong reason (deposit should be a non-issue "+
				"here, only the quota should bind): %v", seq, err)
		}
	}
	if admitted != pol.MaxPerUnderwriter {
		t.Fatalf("admitted %d certificates against a quota of %d, with funding that is not "+
			"the constraint", admitted, pol.MaxPerUnderwriter)
	}
}

// fillToByteHighWater adds big certificates, each from a distinct signer,
// until the next arrival would trigger byte-based eviction, and returns their
// ids in admission order. The mirror of eviction_test.go's fillToHighWater,
// measured in bytes instead of count.
func (w *world) fillToByteHighWater(priority uint64, moves int) []types.Hash {
	w.t.Helper()
	limit := w.policy.MaxBytes * int(w.policy.EvictionHighWater) / 100
	var ids []types.Hash
	for i := 0; w.pool.Stats().Bytes < limit; i++ {
		c := w.bigCert(key(w.t, 3_000_000+i), 0, priority, moves)
		if err := w.add(c); err != nil {
			w.t.Fatalf("filling: %v", err)
		}
		ids = append(ids, c.ID())
	}
	return ids
}

// byteBudgetPolicy sizes MaxBytes off one real, measured certificate rather
// than a guessed constant — wide enough (40x) that draining to the low-water
// mark frees several certificates' worth of headroom, so a single
// same-sized arrival refilling part of that gap cannot mask whether eviction
// ran. MaxCertificates is set high enough that the count budget can never be
// what binds in these tests — isolating byte pressure from count pressure,
// which the byte budget is specifically about keeping distinct.
func byteBudgetPolicy(t *testing.T, moves int) mempool.Policy {
	t.Helper()
	probe := newWorld(t, mempool.DefaultPolicy())
	sample := probe.bigCert(key(t, 0), 0, 1, moves)

	pol := smallPolicy()
	pol.MaxCertificates = 100_000 // count must not bind in these tests
	pol.MaxBytes = sample.SizeBytes() * 40
	return pol
}

// TestByteBudgetEvictsFarBelowCountHighWater is the byte budget's version of
// §1's attack: a pool bounded only by count lets an attacker occupy unbounded
// memory by choosing an expensive certificate shape. This pins that a byte
// budget makes room the same way the count budget does — by evicting — and that
// it engages long before the count budget would have.
func TestByteBudgetEvictsFarBelowCountHighWater(t *testing.T) {
	pol := byteBudgetPolicy(t, 16)
	w := newWorld(t, pol)

	filled := w.fillToByteHighWater(1, 16)

	// Anti-vacuity: count is nowhere near its own high water, so any eviction
	// below cannot be attributed to it.
	countHighWater := pol.MaxCertificates * int(pol.EvictionHighWater) / 100
	if w.pool.Stats().Size >= countHighWater {
		t.Fatalf("setup: count reached its own high water (%d of %d); this test would not "+
			"isolate byte pressure from count pressure", w.pool.Stats().Size, countHighWater)
	}

	victim := w.bigCert(key(t, 999_000), 0, 10_000, 16)
	if err := w.add(victim); err != nil {
		t.Fatalf("a high-priority certificate was refused room by the byte budget: %v", err)
	}
	if !w.pool.Has(victim.ID()) {
		t.Fatal("the arrival was not pooled")
	}
	if w.pool.Stats().Evicted == 0 {
		t.Fatal("room was made without evicting anything; the test is not measuring byte eviction")
	}
	var survivors int
	for _, id := range filled {
		if w.pool.Has(id) {
			survivors++
		}
	}
	if survivors == len(filled) {
		t.Fatal("every certificate filled during setup still survives; nothing was actually " +
			"evicted to make room for the higher-priority arrival")
	}
	if w.pool.Stats().Bytes > pol.MaxBytes {
		t.Fatalf("pool holds %d bytes against a budget of %d", w.pool.Stats().Bytes, pol.MaxBytes)
	}
}

// TestByteBudgetRequiresABump: displacement by the byte budget must not be
// free, for the same reason count-based displacement isn't (the byte path reuses
// the count path's anti-churn guard rather than inventing a cheaper one).
func TestByteBudgetRequiresABump(t *testing.T) {
	pol := byteBudgetPolicy(t, 16)
	pol.EvictionBumpPercent = 10
	w := newWorld(t, pol)

	w.fillToByteHighWater(1_000, 16)

	if err := w.add(w.bigCert(key(t, 998_000), 0, 1_001, 16)); !errors.Is(err, mempool.ErrBelowEvictionFloor) {
		t.Fatalf("got %v, want a refusal: displacing byte-budget residents for one drop must not be free", err)
	}
	if err := w.add(w.bigCert(key(t, 998_001), 0, 1_100, 16)); err != nil {
		t.Fatalf("a certificate meeting the bump was refused: %v", err)
	}
}

// TestByteBudgetNeverStrandsADependentChain: the byte-budget path reuses
// evictionOrder, so it inherits §2.3's tail-safety — but the byte budget
// introduces a new way to reach eviction (pure byte pressure, count nowhere
// near its high water), so the invariant is pinned again on that path
// specifically rather than assumed from the count-based test.
func TestByteBudgetNeverStrandsADependentChain(t *testing.T) {
	pol := byteBudgetPolicy(t, 16)
	w := newWorld(t, pol)

	chainSigner := key(t, 42_000)
	var chainIDs []types.Hash
	for seq := uint64(0); seq < 3; seq++ {
		c := w.bigCert(chainSigner, seq, 1, 16)
		if err := w.add(c); err != nil {
			t.Fatalf("chain %d: %v", seq, err)
		}
		chainIDs = append(chainIDs, c.ID())
	}

	w.fillToByteHighWater(5, 16)
	for i := 0; i < 40; i++ {
		_ = w.add(w.bigCert(key(t, 6_000_000+i), 0, 100_000, 16))
	}

	var present []bool
	for _, id := range chainIDs {
		present = append(present, w.pool.Has(id))
	}
	seenAbsent := false
	for seq, ok := range present {
		if !ok {
			seenAbsent = true
			continue
		}
		if seenAbsent {
			t.Fatalf("Seq %d is pooled but a lower Seq from the same signer was evicted by the "+
				"byte budget: the chain has a hole and everything above it is stranded", seq)
		}
	}
}

// TestByteBudgetCountsTheArrival is the half of the byte budget the high water alone
// does not buy: MaxBytes must bound the pool, not bound it plus one worst-case
// certificate.
//
// A trigger that tests `totalBytes >= byteHighWater()` reads the pool *before*
// the arrival, so a pool resting one byte below the mark admits the arrival
// with no byte check at all — and a certificate's size is not one slot's worth
// but anything up to the V-rules' structural maximum. Sized here so one more
// minimal certificate would cross MaxBytes: the pool must refuse or evict, not
// admit and overshoot.
//
// Anti-vacuity: the pool must actually reach the mark first, so the assertion
// is about the rule and not about an empty pool.
func TestByteBudgetCountsTheArrival(t *testing.T) {
	pol := mempool.DefaultPolicy()
	pol.MaxCertificates = 10_000 // the count budget must never be what binds
	pol.MaxPerUnderwriter = 64
	pol.EvictionHighWater = 90
	pol.EvictionLowWater = 80

	// One minimal certificate's size, measured rather than assumed.
	probe := newWorld(t, pol).cert(key(t, 6_100), 0, 100, 1)
	size := probe.SizeBytes()

	// A budget that holds exactly one such certificate: the high water sits
	// just above one, so a pool holding one is *below* the mark and a
	// pre-arrival trigger would admit a second unchecked.
	pol.MaxBytes = size*100/90 + 10
	w := newWorld(t, pol)

	if err := w.add(w.cert(key(t, 6_101), 0, 100, 1)); err != nil {
		t.Fatalf("first certificate refused: %v", err)
	}
	if got := w.pool.Stats().Size; got != 1 {
		t.Fatalf("setup: pool holds %d certificates, want 1", got)
	}
	if size >= pol.MaxBytes*int(pol.EvictionHighWater)/100 {
		t.Fatalf("setup: one certificate (%d B) already crosses the byte high water (%d B), "+
			"so the second arrival would be checked even by a pre-arrival trigger and this "+
			"test would not distinguish the two rules", size, pol.MaxBytes*int(pol.EvictionHighWater)/100)
	}

	// Escalating priority, so nothing here is refused for want of a bump: if
	// the pool grows, it is the byte rule that failed, not the fee rule.
	//
	// The measurement is the *peak* across arrivals, not the final state. A
	// pre-arrival trigger overshoots transiently — the arrival that crosses
	// the budget is admitted unchecked, and the *next* one then finds the pool
	// over its high water and evicts back down — so a pool sampled only at the
	// end reads clean on every other step while having held twice its budget
	// in between. Resident memory is what MaxBytes bounds, and a peak is what
	// resident memory means.
	peak := 0
	for i := 0; i < 4; i++ {
		_ = w.add(w.cert(key(t, 6_200+i), 0, uint64(1_000*(i+1)), 1))
		total := 0
		for _, c := range w.pool.Candidates() {
			total += c.SizeBytes()
		}
		if total > peak {
			peak = total
		}
	}
	if peak > pol.MaxBytes {
		t.Fatalf("pool held %d bytes at its peak against MaxBytes %d: the byte trigger read "+
			"the pool before the arrival, so an arrival crossing the budget was admitted "+
			"unchecked", peak, pol.MaxBytes)
	}
}

// TestOneAuthorizationOccupiesOnePoolSlotHoweverItIsSigned is the pool's half
// of the certificate-id redefinition, and it needs no attacker to matter.
//
// The pool keys on the certificate id, and the id now names an
// authorization rather than an encoding of one. That is what makes every one of
// the following true at once, and each was broken while the id covered
// signature bytes:
//
//   - a re-signed copy cannot take a second slot, so `MaxPerUnderwriter`
//     bounds authorizations rather than exemplars;
//   - `Remove(c.ID())` after a block commits takes the entry out whichever
//     exemplar was mined, so no unminable variant is stranded behind a
//     committed one;
//   - a miner cannot be handed two exemplars of one authorization and build a
//     block its own dry run rejects, which is a self-inflicted halt with
//     nobody attacking.
//
// The scenario is a certificate the *signer themselves* re-signs — a wallet
// retrying a stuck payment from an HSM that hedges its nonce is enough.
func TestOneAuthorizationOccupiesOnePoolSlotHoweverItIsSigned(t *testing.T) {
	w := newWorld(t, smallPolicy())
	signer := key(t, 42)

	first := w.cert(signer, 0, 10, 1)
	if err := w.add(first); err != nil {
		t.Fatalf("admitting the original: %v", err)
	}

	for _, nonce := range []byte{0x31, 0x32, 0x33, 0x34} {
		copyN, err := harness.ReSignCertificate(first, w.p, signer.Seed(), nonce)
		if err != nil {
			t.Fatalf("re-signing: %v", err)
		}
		// The fixture is only worth anything if these really are two encodings
		// of one authorization.
		if copyN.ID() != first.ID() {
			t.Fatal("re-signing moved the certificate id; the pool is not being asked the question")
		}
		if copyN.ExemplarHash() == first.ExemplarHash() {
			t.Fatal("re-signing produced the same bytes, so this is a byte replay")
		}
		if err := w.add(copyN); !errors.Is(err, mempool.ErrAlreadyPooled) {
			t.Fatalf("nonce %#x: the pool admitted a second exemplar of one authorization (%v)", nonce, err)
		}
	}

	if got := w.pool.Stats().Size; got != 1 {
		t.Fatalf("one authorization occupies %d pool slots", got)
	}

	// And it leaves cleanly under the id the block carries, whichever exemplar
	// that block happened to carry.
	mined, err := harness.ReSignCertificate(first, w.p, signer.Seed(), 0x77)
	if err != nil {
		t.Fatalf("re-signing: %v", err)
	}
	w.pool.Remove(mined.ID())
	if got := w.pool.Stats().Size; got != 0 {
		t.Fatalf("removing the committed authorization left %d entries stranded", got)
	}
}

// overReservingCert builds a certificate whose deposit reserves `amount` — the
// quantity core/fold actually takes against the cell — while its FeeCeiling
// (what the aggregate screen once summed) stays at the floor. Distinct Seq
// values from one signer share a single deposit cell, so they are siblings
// under one underwriter: the shape a ceiling-summing screen lets through.
// wallet.Builder only raises Amount to the ceiling when the caller leaves it
// short, so a caller setting a larger Amount keeps it. V5 admits it up to the
// emission the schedule can have issued by the certificate's TTL, which is V5's
// upper bound; callers here stay well inside it, because the shape under test
// is a reservation larger than the CEILING, not one larger than the money
// supply.
func (w *world) overReservingCert(signer *wallet.Key, seq uint64, amount u256.U256) *types.Certificate {
	w.t.Helper()
	addr := signer.Persistent()
	dep := wallet.SelfDeposit(addr, addr)
	dep.Amount = amount
	b := &wallet.Builder{
		Params:  w.p,
		Program: wallet.Tip(types.NativeAsset, addr, key(w.t, 9999).Persistent(), drops(1)),
		Seq:     seq,
		TTL:     20,
		Deposit: dep,
		FeeBid:  wallet.Bid(drops(1_000_000), drops(1), drops(1_000_000), drops(1)),
		Signers: []*wallet.Key{signer},
	}
	c, err := b.Build()
	if err != nil {
		w.t.Fatalf("overReservingCert(seq=%d): %v", seq, err)
	}
	return c
}

// TestDepositScreenSumsTheReservationNotTheCeiling: the aggregate
// deposit screen must sum the reservation the fold takes — max(Amount,
// FeeCeiling) — not FeeCeiling alone. A certificate can declare a floor ceiling
// but a huge Amount; V5 only enforces Amount >= FeeCeiling, and the fold
// reserves the full Amount, dropping the siblings the cell can no longer cover
// *uncharged*. Summing FeeCeiling let those over-reservers pass admission, buy
// block slots, then drop for free — crowding honest certs out under contention.
//
// Anti-vacuity: the cell is funded for the sum of two FeeCeilings, which is
// exactly what the old ceiling-summing screen required to admit both siblings.
// The second is refused only because the screen now sums the reservation.
func TestDepositScreenSumsTheReservationNotTheCeiling(t *testing.T) {
	w := newWorld(t, smallPolicy())
	signer := key(t, 506)
	addr := signer.Persistent()

	// Learn the per-certificate FeeCeiling the old screen summed.
	probe := w.overReservingCert(signer, 0, drops(1))
	ceiling, ok := probe.FeeCeiling(w.p)
	if !ok {
		t.Fatal("ceiling overflow")
	}

	// Fund for two ceilings plus a drop: enough that a FeeCeiling-summing
	// screen admits both siblings. Each sibling, though, reserves this whole
	// balance as its Amount, so two of them reserve twice what the cell holds.
	balance := ceiling.MulDiv64(2, 1).SatAdd(drops(1))
	w.state.Set(types.NativeBalanceSlot(addr), balance)
	if balance.Lt(ceiling.MulDiv64(2, 1)) {
		t.Fatal("setup: the cell does not cover two ceilings, so the old screen would already refuse the second")
	}

	first := w.overReservingCert(signer, 0, balance)  // Amount == the whole cell
	second := w.overReservingCert(signer, 1, balance) // a sibling sharing the cell

	if err := w.add(first); err != nil {
		t.Fatalf("the first over-reserver was refused, though the cell covers its reservation: %v", err)
	}
	if err := w.add(second); !errors.Is(err, mempool.ErrUnderfunded) {
		t.Fatalf("got %v, want ErrUnderfunded: the two reservations sum to twice the balance, so a screen "+
			"that summed the reservation must refuse the second — a ceiling-summing screen would have admitted it", err)
	}
}

// TestHighAmountDepositAdmittedAlone is the other half of that fix: closing
// the flood must not reject an honest deposit that merely reserves a lot. A
// single certificate with a large Amount, backed by a cell that actually holds
// it, stays admitted; the screen refuses a large reservation only when the cell
// cannot cover it.
func TestHighAmountDepositAdmittedAlone(t *testing.T) {
	w := newWorld(t, smallPolicy())

	honest := key(t, 507)
	// Large against the certificate's own fee ceiling, which is what "high
	// Amount" means here -- and inside V5's upper bound, the emission the
	// schedule can have issued by this certificate's TTL.
	amount := drops(20_000_000_000)
	c := w.overReservingCert(honest, 0, amount)
	w.state.Set(types.NativeBalanceSlot(honest.Persistent()), amount.SatAdd(drops(1)))
	if err := w.add(c); err != nil {
		t.Fatalf("a single honest high-Amount deposit, backed by a cell that holds it, was refused: %v", err)
	}

	// A cell funded only to the small ceiling cannot back the same large
	// reservation — proving the screen now tracks the reservation, not the
	// ceiling, so the positive case above is not vacuous.
	starved := key(t, 508)
	c2 := w.overReservingCert(starved, 0, amount)
	ceiling, ok := c2.FeeCeiling(w.p)
	if !ok {
		t.Fatal("ceiling overflow")
	}
	w.state.Set(types.NativeBalanceSlot(starved.Persistent()), ceiling.SatAdd(drops(1)))
	if err := w.add(c2); !errors.Is(err, mempool.ErrUnderfunded) {
		t.Fatalf("got %v, want ErrUnderfunded: a cell covering only the ceiling must not back a huge reservation", err)
	}
}
