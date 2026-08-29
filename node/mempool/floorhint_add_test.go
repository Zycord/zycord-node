package mempool_test

import (
	"errors"
	"testing"

	"zycord/core/u256"
	"zycord/node/mempool"
)

// TestFloorHintBuiltThroughAddIsTheMinimumOverEvictableTails pins the wiring
// the unevictable-chain-base fix depends on and that no other test touches:
// that Add feeds the floor hint the *arriving certificate's own* underwriter
// and Seq.
//
// Every other test of this mechanism populates pool.byID by hand and calls
// pushFloorHint directly, so the single call site in Add is unpinned. Two
// mutations of it survive the whole package:
//
//   - passing 0 for c.Seq collapses every chain to "tail at Seq 0", so a
//     chain's tail is popped as an interior and its unevictable base sets the
//     bound again — the unevictable base disabling the cheap bound, exactly,
//     reintroduced one layer down;
//   - passing the zero Address collapses floorHintTailSeq to one global maximum
//     Seq, so every certificate not at that Seq is judged an interior and the
//     bound rises *above* the exact floor. That is the censorship direction —
//     the pool refusing arrivals the exact path would admit — and it is the
//     only correctness-grade failure this change can have.
//
// One fixture kills both, because the two mutants move the bound in opposite
// directions from the same pool: a fee-bumped chain (cheap base, dear tail)
// beside a cheaper single-certificate underwriter. The truth is the minimum
// over evictable tails, which is neither the pool-wide minimum nor the price
// at the globally-highest Seq.
func TestFloorHintBuiltThroughAddIsTheMinimumOverEvictableTails(t *testing.T) {
	w := newWorld(t, smallPolicy())

	// The fee bump from docs/adversarial/mempool.md §2.1: Seq 0 cheap, Seq 1
	// dear. Only the tail is evictable, so only 1_000 may bound the floor.
	bumper := key(t, 1)
	if err := w.add(w.cert(bumper, 0, 1, 1)); err != nil {
		t.Fatalf("admitting the chain base: %v", err)
	}
	if err := w.add(w.cert(bumper, 1, 1_000, 1)); err != nil {
		t.Fatalf("admitting the chain tail: %v", err)
	}

	// A single-certificate underwriter, cheaper than the chain's tail and
	// dearer than its base. It is its own tail, so it is the true bound.
	if err := w.add(w.cert(key(t, 2), 0, 5, 1)); err != nil {
		t.Fatalf("admitting the lone resident: %v", err)
	}

	// Ordinary market traffic around them, all single-Seq at the market rate.
	for i := 0; i < 20; i++ {
		if err := w.add(w.cert(key(t, 100+i), 0, 1_000, 1)); err != nil {
			t.Fatalf("admitting market resident %d: %v", i, err)
		}
	}
	if size := w.pool.Stats().Size; size != 23 {
		t.Fatalf("pool holds %d certificates, want 23 — the fixture evicted something "+
			"and no longer contains the chain this test is about", size)
	}

	hint, ok := w.pool.FloorLowerBound()
	if !ok {
		t.Fatal("no floor hint from a pool of 23 certificates")
	}
	if !hint.Eq(u256.FromUint64(5)) {
		t.Fatalf("floor hint = %s, want 5 — the minimum over evictable tails. "+
			"1 would mean the chain's unevictable base is bounding the floor again; "+
			"1000 would mean a live tail was popped as an interior, putting the bound "+
			"above the exact floor and refusing arrivals the exact path admits", hint)
	}

	// Soundness in this same fixture, stated against the authority rather than
	// against a constant: whatever the bound is, the exact path must not admit
	// what the bound refuses.
	arrival := w.cert(key(t, 3), 0, 6, 1)
	floor, ok := w.pool.ExactEvictionFloor(arrival)
	if !ok {
		t.Fatal("no eviction candidates in a pool of 23 certificates")
	}
	if floor.Lt(hint) {
		t.Fatalf("floor hint %s is above the exact floor %s: the fast path now refuses "+
			"arrivals the exact path would admit", hint, floor)
	}

	// Anti-vacuity for the assertion above. The hint must actually be doing the
	// refusing for a below-market arrival, or this is a test of a constant.
	bump := mempool.DefaultPolicy().EvictionBumpPercent
	if mempool.BeatsByBump(u256.FromUint64(2), hint, bump) {
		t.Fatalf("an arrival declaring 2 clears the bound %s, so the cheap-bound fast path does not "+
			"fire and the refusal walks the pool twice", hint)
	}
}

// TestASelfUnderwrittenArrivalIsRefusedWithoutWalkingThePool is the
// arrival-aware bound's acceptance criterion driven through Add, so the
// arrival-awareness is pinned at the one call site that matters rather than
// only in the heap unit tests.
//
// The shape: the pool at high water at the market rate, one cheap certificate
// planted by an underwriter while there was still room, and then that same
// underwriter extending its own chain below the market. The plant is a real
// tail at a real low price, so it legitimately holds the pool-wide bound — the
// pool-wide fix cannot and must not pop it. But for this one arrival it is
// excluded (evicting it would strand the arrival), so the exact floor is the
// market and the arrival is refused. Before the bound was made arrival-aware
// that refusal cost chainPrices + evictionCandidates, two O(len(byID)) walks
// under the write lock, to sort a candidate set the arrival could not use —
// replayable for the price of one gossip message, since the refusal returns
// Score 0 and neither dedupe path remembers it.
//
// Anti-vacuity: the refusal happens either way and with the same error, so the
// assertion is on the path. It also asserts that the pool-wide bound is still
// the plant, which is what makes this the arrival-relative exclusion and not
// the pool-wide one, and that a foreign arrival still sees that tight bound — a
// "fix" that popped the plant would refuse foreign arrivals the exact path
// admits, which is censorship.
func TestASelfUnderwrittenArrivalIsRefusedWithoutWalkingThePool(t *testing.T) {
	w := newWorld(t, smallPolicy())

	// Planted below high water, which is the only window in which a cheap
	// certificate can be admitted at all.
	planter := key(t, 7)
	if err := w.add(w.cert(planter, 0, 1, 1)); err != nil {
		t.Fatalf("planting the cheap tail: %v", err)
	}
	w.fillToHighWater(1_000)

	before := w.pool.Stats().Size

	// The plant is still the pool-wide minimum over evictable tails: this test is
	// about an exclusion the pool-wide value is not allowed to model, not about
	// removing the plant from it.
	if hint, ok := w.pool.FloorLowerBound(); !ok || !hint.Eq(u256.FromUint64(1)) {
		t.Fatalf("pool-wide floor hint = (%s, %v), want (1, true) — the plant is not "+
			"holding the bound, so this is not the scenario under test", hint, ok)
	}

	arrival := w.cert(planter, 1, 2, 1)
	floor, ok := w.pool.ExactEvictionFloor(arrival)
	if !ok {
		t.Fatal("no eviction candidates at high water")
	}
	if !floor.Eq(u256.FromUint64(1_000)) {
		t.Fatalf("exact floor for the self-underwritten arrival = %s, want 1000 — the "+
			"own-chain exclusion is not what is separating the two floors", floor)
	}

	// The property: the fast path fires, so the arrival never reaches the walks.
	bump := mempool.DefaultPolicy().EvictionBumpPercent
	hint, ok := w.pool.FloorLowerBoundFor(arrival)
	if !ok {
		t.Fatal("no arrival-aware floor hint at high water")
	}
	if mempool.BeatsByBump(u256.FromUint64(2), hint, bump) {
		t.Fatalf("the self-underwritten arrival clears the bound %s, so the cheap-bound fast path "+
			"does not fire and the refusal pays two O(n) walks", hint)
	}
	if floor.Lt(hint) {
		t.Fatalf("arrival-aware bound %s is above the exact floor %s: the fast path can "+
			"now refuse arrivals the exact path would admit", hint, floor)
	}

	// And the decision itself is unchanged: refused, with the same error, and
	// the plant survives — this is a cost fix, not an admission-policy change.
	if err := w.add(arrival); !errors.Is(err, mempool.ErrBelowEvictionFloor) {
		t.Fatalf("Add returned %v, want ErrBelowEvictionFloor", err)
	}
	if size := w.pool.Stats().Size; size != before {
		t.Fatalf("pool size %d after the refusal, want %d", size, before)
	}

	// A foreign arrival at the same price still sees the plant, because for it
	// the plant is a genuine candidate.
	if got, ok := w.pool.FloorLowerBoundFor(w.cert(key(t, 8), 0, 2, 1)); !ok || !got.Eq(u256.FromUint64(1)) {
		t.Fatalf("bound for a foreign arrival = (%s, %v), want (1, true): the own-chain "+
			"exclusion leaked out of the arrival it belongs to", got, ok)
	}

	// The second separating input for the guard's two terms: a foreign arrival
	// *above* the plant's Seq. The one above shares its Seq, so it cannot tell
	// an exclusion keyed on Seq alone from the real one — and an exclusion on
	// Seq alone lifts the bound to the market for every such arrival, above the
	// exact floor, which is censorship rather than a lost optimisation.
	if got, ok := w.pool.FloorLowerBoundFor(w.cert(key(t, 9), 1, 2, 1)); !ok || !got.Eq(u256.FromUint64(1)) {
		t.Fatalf("bound for a foreign arrival above the plant's Seq = (%s, %v), want "+
			"(1, true): the exclusion fired on Seq alone", got, ok)
	}
}

// TestAResidualSteerableArrivalIsRefusedWithoutWalkingThePool is the
// steerable residual's acceptance criterion, and the case the arrival-aware
// bound's own benchmark and tests never covered.
//
// That bound closed the fast path for a self-underwritten arrival whose own chain base
// is the *unique* heap root: the descend reads the root's two children and
// bounds the floor by them. The residual it left open is the *steerable* subset
// — an underwriter that owns the two or three cheapest floorHint slots, so the
// root's children are *also* its own excluded certificates. The old single-level
// descend then bounded the floor on one of the arrival's own cheap prices, the
// arrival cleared it, and admission fell through to chainPrices +
// evictionCandidates: two O(len(byID)) walks under the write lock, per replay,
// for a refusal that returns Score 0 and is remembered by no dedupe path.
//
// The shape: a single underwriter U* plants three same-Seq(0) replacements
// priced 1/2/3 while there is still room, then the pool fills to high water at
// the market rate, and U* replays a Seq-1 arrival priced between its own cheap
// tail and the market. U* now owns floorHint[0..2].
//
// Anti-vacuity, exactly as the sibling above: the refusal happens either
// way and with the same error, so the assertion is on the *path* —
// !beatsByBump(arrival, hint) — which fails on the single-level descend because the
// bound there is one of U*'s own prices (<= 2), below the arrival. The bounded
// descend fixes it: it skips past every one of U*'s excluded certificates and
// bounds on the market instead. The two closing checks are the trap to avoid:
// an honest below-floor self-underwritten arrival stays refused, and an honest
// admissible one stays admitted — the fix removes only the O(n)-under-lock
// lever, not any admission decision.
func TestAResidualSteerableArrivalIsRefusedWithoutWalkingThePool(t *testing.T) {
	const market = 1_000
	w := newWorld(t, smallPolicy())

	// U* owns the cheap end: three same-Seq replacements, cheapest last so the
	// min-heap sifts them to the top. Replace-by-fee admits several at one Seq,
	// and being the cheapest they take floorHint[0..2].
	uStar := key(t, 7)
	for _, p := range []uint64{3, 2, 1} {
		if err := w.add(w.cert(uStar, 0, p, 1)); err != nil {
			t.Fatalf("planting U* replacement at %d: %v", p, err)
		}
	}
	w.fillToHighWater(market)
	before := w.pool.Stats().Size

	// This is the steerable residual and not the plain self-underwritten case:
	// U* holds the pool-wide bound with its *cheapest* plant, and its
	// second-cheapest is necessarily a heap child of the root, which is what
	// the old descend bounded on.
	if hint, ok := w.pool.FloorLowerBound(); !ok || !hint.Eq(u256.FromUint64(1)) {
		t.Fatalf("pool-wide floor hint = (%s, %v), want (1, true) — U* is not holding the "+
			"bound, so this is not the steerable residual", hint, ok)
	}

	// The steerable arrival: U*, Seq 1, priced above its own plants and below the
	// market. Its exact floor is the market (all of U*'s certs are excluded).
	arrival := w.cert(uStar, 1, 50, 1)
	floor, ok := w.pool.ExactEvictionFloor(arrival)
	if !ok {
		t.Fatal("no eviction candidates at high water")
	}
	if !floor.Eq(u256.FromUint64(market)) {
		t.Fatalf("exact floor for the steerable arrival = %s, want %d — U*'s own certs are "+
			"not the thing being excluded", floor, market)
	}

	// The property: the descend skips all of U*'s excluded slots and the
	// fast path fires, so the arrival never reaches the two O(n) walks. With a
	// single-level descend the bound is <= 2 and the arrival clears it — this line is
	// what that regression trips.
	bump := mempool.DefaultPolicy().EvictionBumpPercent
	hint, ok := w.pool.FloorLowerBoundFor(arrival)
	if !ok {
		t.Fatal("no arrival-aware floor hint at high water")
	}
	if mempool.BeatsByBump(u256.FromUint64(50), hint, bump) {
		t.Fatalf("the steerable arrival clears the bound %s, so the cheap-bound fast path does not fire "+
			"and the refusal pays two O(n) walks under the write lock", hint)
	}
	// Soundness: the tightened bound must never rise above the exact floor.
	if floor.Lt(hint) {
		t.Fatalf("arrival-aware bound %s is above the exact floor %s: the fast path now "+
			"refuses arrivals the exact path would admit", hint, floor)
	}

	// The trap, half one: an honest below-floor self-underwritten arrival is
	// still refused, same error, and U*'s plants survive — a cost fix, not an
	// admission change. A refused arrival evicts nothing, so the pool is intact
	// for the two checks that follow.
	if err := w.add(arrival); !errors.Is(err, mempool.ErrBelowEvictionFloor) {
		t.Fatalf("Add returned %v, want ErrBelowEvictionFloor", err)
	}
	if size := w.pool.Stats().Size; size != before {
		t.Fatalf("pool size %d after the refusal, want %d", size, before)
	}

	// The foreign path is untouched: for an outsider U*'s cheap plants are
	// genuine candidates, so the tight pool-wide bound is still reported. Checked
	// on the intact pool, before the admission below mutates it.
	if got, ok := w.pool.FloorLowerBoundFor(w.cert(key(t, 8), 0, 2, 1)); !ok || !got.Eq(u256.FromUint64(1)) {
		t.Fatalf("bound for a foreign arrival = (%s, %v), want (1, true): the own-chain "+
			"exclusion leaked out of the arrival it belongs to", got, ok)
	}

	// The trap, half two: an honest *admissible* self-underwritten arrival — U*
	// extending its chain above the market — is still admitted. The bounded
	// descend defers it to the exact path, which evicts a market resident for it.
	// (This admission promotes U*'s Seq-0 plants to chain interiors, so it is
	// deliberately the last thing the test does.)
	admissible := w.cert(uStar, 1, market*2, 1)
	if h, ok := w.pool.FloorLowerBoundFor(admissible); !ok || h.Lt(u256.FromUint64(market)) {
		t.Fatalf("bound for the admissible arrival = (%s, %v): a bound below the market "+
			"would mean the descend stopped on one of U*'s own excluded prices", h, ok)
	}
	if err := w.add(admissible); err != nil {
		t.Fatalf("an admissible self-underwritten arrival was refused: %v — the fix broke "+
			"honest admission", err)
	}
}
