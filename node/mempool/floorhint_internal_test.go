package mempool

import (
	"math/rand"
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
)

// This file tests floorHint's bookkeeping in isolation, rather than through a
// live pool. The cheap check (makeRoomFor's call to floorLowerBound) is only as
// trustworthy as the invariant this file pins: the returned value is always
// exactly the smallest declared SeqPriority among certificates currently in
// pool.byID, however the heap got there.
//
// A bare *Pool with only its maps initialised is enough: floorLowerBound and
// pushFloorHint touch nothing else, so building certificates, states or a
// policy would only obscure what is under test.

func newTestPool() *Pool {
	return &Pool{
		byID:                 make(map[types.Hash]*entry),
		byUnderwriter:        make(map[types.Address]int),
		byUnderwriterReserve: make(map[types.Address]u256.U256),
		floorHintTailSeq:     make(map[types.Address]uint64),
	}
}

func idFor(n int) types.Hash {
	var h types.Hash
	h[0] = byte(n)
	h[1] = byte(n >> 8)
	h[2] = byte(n >> 16)
	h[3] = byte(n >> 24)
	return h
}

// insertForTest pools entry n at the given price, going through the same
// pushFloorHint call Add makes on admission.
func (pool *Pool) insertForTest(n int, price uint64) types.Hash {
	id := idFor(n)
	pool.byID[id] = &entry{id: id, cert: &types.Certificate{
		FeeBid: types.FeeBid{SeqPriority: u256.FromUint64(price)},
	}}
	pool.pushFloorHint(id, u256.FromUint64(price), types.Address{}, 0)
	return id
}

func (pool *Pool) removeForTest(id types.Hash) {
	delete(pool.byID, id)
}

// trueMinimum independently recomputes the minimum declared price over
// everything currently in byID, by a code path that shares nothing with
// floorLowerBound or the heap it reads. This is the ground truth the other
// tests in this file check floorLowerBound against.
func trueMinimum(pool *Pool) (u256.U256, bool) {
	var (
		min   u256.U256
		found bool
	)
	for _, e := range pool.byID {
		if !found || e.cert.FeeBid.SeqPriority.Lt(min) {
			min = e.cert.FeeBid.SeqPriority
			found = true
		}
	}
	return min, found
}

// TestFloorLowerBoundOnEmptyPool: nothing pooled, nothing to bound with.
func TestFloorLowerBoundOnEmptyPool(t *testing.T) {
	pool := newTestPool()
	if _, ok := pool.floorLowerBound(); ok {
		t.Fatal("an empty pool produced a floor hint")
	}
}

// TestFloorLowerBoundIsExactlyTheTrueMinimum drives a random sequence of
// admissions and removals — removals not necessarily of the minimum, so lazy
// cleanup is genuinely exercised rather than only ever popping the top — and
// after every step checks floorLowerBound against trueMinimum computed
// independently. The cheap bound's whole premise is that this holds cheaply; this test
// is what makes "holds" more than an assertion in a comment.
func TestFloorLowerBoundIsExactlyTheTrueMinimum(t *testing.T) {
	rng := rand.New(rand.NewSource(2))
	pool := newTestPool()

	var live []types.Hash
	next := 0
	for step := 0; step < 4000; step++ {
		if len(live) == 0 || rng.Intn(3) != 0 {
			// Admit. A small price range on purpose, so duplicate minimums are
			// common — the case where lazy cleanup must not stop at the first
			// popped entry and wrongly report "empty" or the wrong value.
			price := uint64(rng.Intn(20))
			id := pool.insertForTest(next, price)
			live = append(live, id)
			next++
		} else {
			// Remove a uniformly random live entry, not necessarily the cheapest,
			// so the heap accumulates realistic staleness rather than only ever
			// being popped from the top by construction.
			i := rng.Intn(len(live))
			pool.removeForTest(live[i])
			live[i] = live[len(live)-1]
			live = live[:len(live)-1]
		}

		wantPrice, wantOK := trueMinimum(pool)
		gotPrice, gotOK := pool.floorLowerBound()
		if gotOK != wantOK {
			t.Fatalf("step %d: floorLowerBound ok=%v, true minimum ok=%v", step, gotOK, wantOK)
		}
		if wantOK && !gotPrice.Eq(wantPrice) {
			t.Fatalf("step %d: floorLowerBound=%s, true minimum=%s", step, gotPrice, wantPrice)
		}
	}
}

// TestFloorLowerBoundTracksRemovalOfTheMinimum is the direct, non-random
// version of the property above: pin the exact sequence a stale cache bug
// would get wrong — the minimum-holder leaves, and the bound must move to
// the next-smallest live entry, not silently keep reporting the departed one
// (which would be unsound: it could then sit *above* the true floor after
// other admissions, and the cheap bound's soundness argument requires it never does).
func TestFloorLowerBoundTracksRemovalOfTheMinimum(t *testing.T) {
	pool := newTestPool()
	cheapest := pool.insertForTest(1, 10)
	pool.insertForTest(2, 20)
	pool.insertForTest(3, 30)

	if got, ok := pool.floorLowerBound(); !ok || !got.Eq(u256.FromUint64(10)) {
		t.Fatalf("floorLowerBound = (%s, %v), want (10, true)", got, ok)
	}

	pool.removeForTest(cheapest)
	if got, ok := pool.floorLowerBound(); !ok || !got.Eq(u256.FromUint64(20)) {
		t.Fatalf("after removing the minimum: floorLowerBound = (%s, %v), want (20, true)", got, ok)
	}

	// Drain the rest; the bound must fall back to "nothing to say" rather than
	// resurrecting a stale value.
	pool.removeForTest(idFor(2))
	pool.removeForTest(idFor(3))
	if _, ok := pool.floorLowerBound(); ok {
		t.Fatal("floorLowerBound reported a value for an empty pool")
	}
}

// TestFloorHintStaysBoundedInSize is the memory half of the cheap bound: floorHint
// is pushed to on every admission and never popped on removal, so left alone
// it would grow with total admissions over a node's lifetime rather than
// with the pool's current size. pushFloorHint's rebuild keeps it at O(n); this
// pins the bound the rebuild promises, immediately after every push, which is
// the only point the code commits to maintaining it.
func TestFloorHintStaysBoundedInSize(t *testing.T) {
	rng := rand.New(rand.NewSource(3))
	pool := newTestPool()

	var live []types.Hash
	next := 0
	for step := 0; step < 5000; step++ {
		if len(live) == 0 || rng.Intn(4) != 0 {
			id := pool.insertForTest(next, uint64(rng.Intn(1000)))
			live = append(live, id)
			next++

			bound := 2 * len(pool.byID)
			if bound < floorHintRebuildSlack {
				bound = floorHintRebuildSlack
			}
			if len(pool.floorHint) > bound {
				t.Fatalf("step %d: floorHint holds %d entries against %d pooled "+
					"(bound %d) — it is growing with total admissions, not pool size",
					step, len(pool.floorHint), len(pool.byID), bound)
			}
		} else {
			i := rng.Intn(len(live))
			pool.removeForTest(live[i])
			live[i] = live[len(live)-1]
			live = live[:len(live)-1]
		}
	}
}

// TestCheapBoundNeverRefusesWhatTheExactFloorWouldAdmit is the property the
// fast path in makeRoomFor actually rests on, checked against the exact floor
// rather than against the prose argument for it.
//
// The other tests in this file pin the heap's bookkeeping — that
// floorLowerBound is exactly min(byID). That is necessary but not sufficient:
// what makeRoomFor needs is the *relation* between that value and
// evictionCandidates' floor, and specifically that
//
//	!beatsByBump(arrival, hint)  =>  !beatsByBump(arrival, floor)
//
// so the cheap refusal is never a refusal the exact path would not also have
// made. That relation spans two functions this file does not otherwise touch,
// and it is the one a future change to evictionCandidates could break silently:
// widen its candidate set to include something not in byID, or otherwise let
// the exact floor fall *below* the pool-wide minimum, and the fast path starts
// refusing arrivals the exact path would admit — with no other test in the
// package failing.
//
// One direction only, stated so the next reader does not over-trust this: the
// property is an implication, so only mutations that *lower* the exact floor
// break it. Verified both ways — subtracting 3 from the floor fails this test
// ("exact floor 0 is below the supposed lower bound 3"), while adding 3 does
// not, because a higher floor only makes the exact path stricter and the
// implication still holds. A synthesised floor is caught if and only if it can
// come out below a resident's own declaration.
//
// So this builds real chains (multi-Seq, so evictable() genuinely excludes
// chain interiors and the two floors differ rather than coinciding trivially),
// sweeps arrival prices across and around both floors, and asserts the
// implication directly at every point.
func TestCheapBoundNeverRefusesWhatTheExactFloorWouldAdmit(t *testing.T) {
	const bump = 10

	rng := rand.New(rand.NewSource(20260819))

	// Anti-vacuity. A test that never sees the fast path fire, or that only
	// ever sees the two floors coincide, proves nothing about the relation
	// between them — so count both and fail if either never happened.
	var cheapRefusals, floorsDiffer int

	for trial := 0; trial < 400; trial++ {
		pool := newTestPool()

		// A handful of underwriters, each with a chain of 1..4 certificates at
		// ascending Seq. Prices are drawn from a deliberately narrow range so
		// duplicate minima and near-misses at the bump boundary are common.
		nUnder := 1 + rng.Intn(5)
		n := 0
		for u := 0; u < nUnder; u++ {
			var addr types.Address
			addr[0] = byte(u)
			chainLen := 1 + rng.Intn(4)
			for seq := 0; seq < chainLen; seq++ {
				price := uint64(rng.Intn(40))
				id := idFor(n)
				n++
				pool.byID[id] = &entry{id: id, cert: &types.Certificate{
					Seq:    uint64(seq),
					FeeBid: types.FeeBid{SeqPriority: u256.FromUint64(price)},
					Deposit: types.Deposit{
						Cell: types.Slot{Addr: addr},
					},
				}}
				pool.pushFloorHint(id, u256.FromUint64(price), addr, uint64(seq))
			}
		}

		// The arrival: its own underwriter and Seq matter, because
		// evictionCandidates excludes the arrival's own chain below its Seq.
		// Sweep both an existing identity and a fresh one.
		for _, arrivalUnder := range []int{0, nUnder} {
			var addr types.Address
			addr[0] = byte(arrivalUnder)
			for arrivalSeq := 0; arrivalSeq < 4; arrivalSeq++ {
				for price := uint64(0); price <= 60; price++ {
					arrival := &types.Certificate{
						Seq:     uint64(arrivalSeq),
						FeeBid:  types.FeeBid{SeqPriority: u256.FromUint64(price)},
						Deposit: types.Deposit{Cell: types.Slot{Addr: addr}},
					}

					prices := pool.chainPrices()
					_, floor, ok := pool.evictionCandidates(prices, arrival)

					// The arrival-aware bound is what makeRoomFor
					// actually reads, so it is what has to be sound. It is
					// recomputed per arrival because it is allowed to differ
					// per arrival — that is the whole of it.
					hint, haveHint := pool.floorLowerBoundFor(arrival)

					cheapRefuses := haveHint &&
						!beatsByBump(arrival.FeeBid.SeqPriority, hint, bump)
					if ok && hint.Lt(floor) {
						floorsDiffer++
					}
					if !cheapRefuses {
						continue // the fast path defers; nothing to prove here
					}
					cheapRefusals++

					// The fast path said no. The exact path must not say yes.
					if ok && beatsByBump(arrival.FeeBid.SeqPriority, floor, bump) {
						t.Fatalf(
							"trial %d: cheap bound refused an arrival the exact floor admits: "+
								"arrival price %d seq %d under %d, hint %s, floor %s",
							trial, price, arrivalSeq, arrivalUnder, hint, floor)
					}

					// And the bound must genuinely be a bound, not merely
					// agree by luck on this arrival.
					if ok && floor.Lt(hint) {
						t.Fatalf(
							"trial %d: exact floor %s is below the supposed lower bound %s",
							trial, floor, hint)
					}
				}
			}
		}
	}

	if cheapRefusals == 0 {
		t.Fatal("vacuous: the cheap bound never refused an arrival")
	}
	if floorsDiffer == 0 {
		t.Fatal("vacuous: the bound and the exact floor were never distinct, " +
			"so the sweep never exercised the gap the fast path lives in")
	}
	t.Logf("cheap refusals %d, strictly-loose bounds %d", cheapRefusals, floorsDiffer)
}

// plantForTest pools one certificate for the given underwriter at (seq, price),
// through the same pushFloorHint call Add makes on admission.
func (pool *Pool) plantForTest(n int, addr types.Address, seq, price uint64) types.Hash {
	id := idFor(n)
	pool.byID[id] = &entry{id: id, cert: &types.Certificate{
		Seq:     seq,
		FeeBid:  types.FeeBid{SeqPriority: u256.FromUint64(price)},
		Deposit: types.Deposit{Cell: types.Slot{Addr: addr}},
	}}
	pool.byUnderwriter[addr]++
	pool.pushFloorHint(id, u256.FromUint64(price), addr, seq)
	return id
}

// TestUnevictableChainBaseDoesNotDisableTheCheapBound: a single cheap
// certificate that §2.3 makes structurally unevictable — a chain interior —
// must not set the cheap bound, because it is not a price any arrival can ever
// be admitted against.
//
// The plant is one ordinary fee bump: Seq 0 declaring 1, Seq 1 at the market
// rate. Before the fix the bound was a minimum over *every* pooled
// certificate, so the base held it at 1 forever; every arrival declaring 2 or
// more cleared it and fell through to chainPrices + evictionCandidates — two
// O(len(byID)) walks under the write lock — only to be refused anyway by the
// exact floor. One 848-byte plant therefore removed the fast path from the
// whole price band below the market floor.
//
// Anti-vacuity, and this is the trap the issue names: asserting that the
// arrival is refused proves nothing, because it is refused either way, with
// the same error. So this asserts the *path*: makeRoomFor's fast-path
// condition — !beatsByBump(arrival, hint) — must hold for the below-market
// arrival, which is the only thing that makes the refusal cheap. It also
// checks the plant really is the pool minimum and really is unevictable, so
// the scenario cannot silently stop being the one under test.
func TestUnevictableChainBaseDoesNotDisableTheCheapBound(t *testing.T) {
	const (
		bump   = 10
		market = 1000
	)

	pool := newTestPool()

	var planter types.Address
	planter[0] = 0xAA
	base := pool.plantForTest(0, planter, 0, 1) // cheap, structurally unevictable
	pool.plantForTest(1, planter, 1, market)    // its tail, at the market rate

	// The rest of the pool: ordinary single-Seq residents at the market rate.
	for i := 2; i < 200; i++ {
		var addr types.Address
		addr[0] = byte(i)
		addr[1] = byte(i >> 8)
		pool.plantForTest(i, addr, 0, market)
	}

	// The scenario is the one claimed: the plant is the pool-wide minimum, and
	// it cannot leave at any price.
	if got, ok := trueMinimum(pool); !ok || !got.Eq(u256.FromUint64(1)) {
		t.Fatalf("pool-wide minimum = (%s, %v), want (1, true) — the plant is not the minimum", got, ok)
	}
	if evictable(pool.byID[base], pool.chainPrices()) {
		t.Fatal("the planted base is evictable, so it is not the structurally unevictable entry this test is about")
	}

	hint, ok := pool.floorLowerBound()
	if !ok {
		t.Fatal("no floor hint from a pool holding 200 certificates")
	}
	if hint.Eq(u256.FromUint64(1)) {
		t.Fatalf("floor hint = %s: the unevictable chain base still sets the bound", hint)
	}

	// The property. An arrival one drop above the plant is refused by the
	// exact floor; it must be refused by the cheap bound *first*, without the
	// pool being walked.
	var newcomer types.Address
	newcomer[0] = 0xBB
	arrival := &types.Certificate{
		Seq:     0,
		FeeBid:  types.FeeBid{SeqPriority: u256.FromUint64(2)},
		Deposit: types.Deposit{Cell: types.Slot{Addr: newcomer}},
	}
	if beatsByBump(arrival.FeeBid.SeqPriority, hint, bump) {
		t.Fatalf("an arrival declaring 2 clears the cheap bound %s, so the fast path does not fire "+
			"and the refusal costs two O(n) walks of the pool", hint)
	}

	// Soundness, in this same scenario: the cheap refusal is one the exact
	// path would also have made. A bound that refused more than the exact
	// floor would be a censorship bug, not an optimisation.
	_, floor, haveFloor := pool.evictionCandidates(pool.chainPrices(), arrival)
	if !haveFloor {
		t.Fatal("no eviction candidates in a pool of 200 certificates")
	}
	if floor.Lt(hint) {
		t.Fatalf("cheap bound %s is above the exact floor %s: the fast path can now refuse "+
			"arrivals the exact path would admit", hint, floor)
	}

	// And the pop is not a one-way loss of information: when the tail leaves,
	// the base becomes evictable and its price must come back into the bound,
	// or the fast path would start refusing arrivals priced at 1 that the exact
	// floor admits.
	pool.removeLocked(idFor(1))
	if got, ok := pool.floorLowerBound(); !ok || !got.Eq(u256.FromUint64(1)) {
		t.Fatalf("after the tail left, floor hint = (%s, %v), want (1, true): "+
			"the promoted chain base is missing from the bound", got, ok)
	}
}

// tailMinimum independently recomputes the minimum declared price over the
// entries §2.3 actually makes evictable — each underwriter's highest pooled
// Seq — by a path that shares nothing with floorHint, floorHintTailSeq or the
// stale flag. This is the exact quantity floorLowerBound claims to return.
func tailMinimum(pool *Pool) (u256.U256, bool) {
	max := make(map[types.Address]uint64, len(pool.byUnderwriter))
	for _, e := range pool.byID {
		u := e.cert.UnderwriterID()
		if s, seen := max[u]; !seen || e.cert.Seq > s {
			max[u] = e.cert.Seq
		}
	}
	var (
		min   u256.U256
		found bool
	)
	for _, e := range pool.byID {
		if e.cert.Seq != max[e.cert.UnderwriterID()] {
			continue
		}
		if p := e.cert.FeeBid.SeqPriority; !found || p.Lt(min) {
			min, found = p, true
		}
	}
	return min, found
}

// TestFloorHintSurvivesInterleavedAdmissionAndRemoval pins the invariant the
// whole of the unevictable-chain-base fix rests on, against the mutation
// sequence the fix's own reasoning is most exposed to: floorLowerBound is
// exactly the minimum over evictable tails, at *every* reachable state, and
// therefore never above makeRoomFor's exact floor.
//
// The heap's evictability pops are destructive, and their soundness depends on
// the claim that removal is the only event that can promote a chain interior
// to a tail — so removals here go through removeLocked, the sole path that
// deletes from byID and the sole setter of the stale flag. The sequence
// deliberately builds the states the O(1) tail index can most plausibly drift
// in: duplicate Seq (replace-by-fee, where several entries share maxSeq), an
// interior admitted *after* its tail, an underwriter emptied and then
// re-admitted at a *lower* Seq than it last held, and a re-admission of an id
// the heap already popped.
//
// Asserting equality rather than `hint <= floor` is deliberate: an
// over-conservative bound is the censorship direction and an
// under-conservative one is merely slow, and only equality catches both.
func TestFloorHintSurvivesInterleavedAdmissionAndRemoval(t *testing.T) {
	rng := rand.New(rand.NewSource(197))

	for trial := 0; trial < 300; trial++ {
		pool := newTestPool()
		live := make([]types.Hash, 0, 64)
		n := 0

		for step := 0; step < 60; step++ {
			if len(live) > 0 && rng.Intn(3) == 0 {
				i := rng.Intn(len(live))
				id := live[i]
				live = append(live[:i], live[i+1:]...)
				pool.removeLocked(id)
			} else {
				var addr types.Address
				addr[0] = byte(rng.Intn(4)) // few underwriters: chains and duplicates are common
				// Seq drawn independently of what is pooled, so interiors
				// arrive after tails and re-admissions land below the Seq the
				// underwriter last held.
				seq := uint64(rng.Intn(4))
				price := uint64(rng.Intn(30))
				id := idFor(n)
				n++
				pool.byID[id] = &entry{id: id, cert: &types.Certificate{
					Seq:     seq,
					FeeBid:  types.FeeBid{SeqPriority: u256.FromUint64(price)},
					Deposit: types.Deposit{Cell: types.Slot{Addr: addr}},
				}}
				pool.byUnderwriter[addr]++
				pool.pushFloorHint(id, u256.FromUint64(price), addr, seq)
				live = append(live, id)
			}

			hint, haveHint := pool.floorLowerBound()
			want, haveWant := tailMinimum(pool)
			if haveHint != haveWant || (haveWant && !hint.Eq(want)) {
				t.Fatalf("trial %d step %d: floor hint = (%s, %v), want (%s, %v)",
					trial, step, hint, haveHint, want, haveWant)
			}
			if !haveHint {
				continue
			}

			// Soundness against the authority itself, sweeping arrivals whose
			// own chain the exact floor excludes and ones it does not.
			for u := 0; u < 5; u++ {
				var addr types.Address
				addr[0] = byte(u)
				for seq := uint64(0); seq < 4; seq++ {
					arrival := &types.Certificate{
						Seq:     seq,
						FeeBid:  types.FeeBid{SeqPriority: u256.FromUint64(1)},
						Deposit: types.Deposit{Cell: types.Slot{Addr: addr}},
					}
					_, floor, ok := pool.evictionCandidates(pool.chainPrices(), arrival)
					if ok && floor.Lt(hint) {
						t.Fatalf("trial %d step %d: hint %s above exact floor %s for arrival (u=%d, seq=%d): "+
							"the fast path refuses arrivals the exact path admits", trial, step, hint, floor, u, seq)
					}
				}
			}
		}
	}
}

// TestASelfUnderwrittenArrivalDoesNotDisableTheCheapBound pins the arrival-relative
// half that a pool-wide hint could not close: the arrival's *own* chain below its own
// Seq is excluded from the exact floor, and that exclusion is relative to one
// arrival, so a pool-wide hint cannot represent it.
//
// The plant is legitimate in a way the chain interior was not: it is its own
// tail, so §2.3 really does allow evicting it and it really does belong in the
// hint. It is only the one arrival that underwrites it which may not take it —
// and for that arrival the hint sits below the exact floor by the whole width
// of the market.
//
// Anti-vacuity, same trap as the chain-interior test: the arrival is refused
// either way, with the same error, so refusal proves nothing. The assertion is
// on the *path* — !beatsByBump(arrival, hint) must hold, which is the only
// thing that keeps the refusal off chainPrices + evictionCandidates.
func TestASelfUnderwrittenArrivalDoesNotDisableTheCheapBound(t *testing.T) {
	const (
		bump   = 10
		market = 1000
	)

	pool := newTestPool()

	var planter types.Address
	planter[0] = 0xAA
	plant := pool.plantForTest(0, planter, 0, 1) // cheap, and its own tail

	for i := 1; i < 200; i++ {
		var addr types.Address
		addr[0] = byte(i)
		addr[1] = byte(i >> 8)
		pool.plantForTest(i, addr, 0, market)
	}

	// The scenario is the one claimed: unlike the chain-interior plant, this one is
	// structurally evictable, so the arrival-independent bound is right to
	// report it.
	if !evictable(pool.byID[plant], pool.chainPrices()) {
		t.Fatal("the plant is not evictable, so this is the chain-interior shape and not the arrival-relative one")
	}
	if got, ok := pool.floorLowerBound(); !ok || !got.Eq(u256.FromUint64(1)) {
		t.Fatalf("arrival-independent bound = (%s, %v), want (1, true)", got, ok)
	}

	// The arrival: the planter extending its own chain. The plant is below its
	// Seq, so evictionCandidates excludes it and the exact floor is the market.
	arrival := &types.Certificate{
		Seq:     1,
		FeeBid:  types.FeeBid{SeqPriority: u256.FromUint64(2)},
		Deposit: types.Deposit{Cell: types.Slot{Addr: planter}},
	}
	_, floor, haveFloor := pool.evictionCandidates(pool.chainPrices(), arrival)
	if !haveFloor || !floor.Eq(u256.FromUint64(market)) {
		t.Fatalf("exact floor for the self-underwritten arrival = (%s, %v), want (%d, true): "+
			"the own-chain exclusion is not the thing under test", floor, haveFloor, market)
	}

	// The property.
	hint, ok := pool.floorLowerBoundFor(arrival)
	if !ok {
		t.Fatal("no floor hint from a pool holding 200 certificates")
	}
	if beatsByBump(arrival.FeeBid.SeqPriority, hint, bump) {
		t.Fatalf("the arrival clears the cheap bound %s, so the fast path does not fire and "+
			"the refusal pays two O(n) walks to sort a candidate set it cannot use", hint)
	}
	// Soundness in this same scenario.
	if floor.Lt(hint) {
		t.Fatalf("cheap bound %s is above the exact floor %s", hint, floor)
	}

	// And the exclusion is arrival-relative, not a pop: a *foreign* arrival must
	// still see the plant, because for it the plant is a real candidate. A fix
	// that removed the plant from the hint would refuse foreign arrivals the
	// exact path admits, which is censorship rather than optimisation.
	var newcomer types.Address
	newcomer[0] = 0xBB
	foreign := &types.Certificate{
		Seq:     0,
		FeeBid:  types.FeeBid{SeqPriority: u256.FromUint64(2)},
		Deposit: types.Deposit{Cell: types.Slot{Addr: newcomer}},
	}
	if got, ok := pool.floorLowerBoundFor(foreign); !ok || !got.Eq(u256.FromUint64(1)) {
		t.Fatalf("bound for a foreign arrival = (%s, %v), want (1, true): the own-chain "+
			"exclusion leaked out of the one arrival it belongs to", got, ok)
	}

	// Counting the conjuncts: the guard is `seq < arrival.Seq AND same
	// underwriter`, so each term needs an input that separates it. The foreign
	// arrival above shares the plant's Seq, so it separates neither on its own.
	// This one sits *above* the plant's Seq and still underwrites nothing, so
	// only the underwriter term can keep the exclusion from firing — and if it
	// does fire, the bound leaves the plant out and rises to the market, above
	// the exact floor, which is the censorship direction.
	foreignAbove := &types.Certificate{
		Seq:     1,
		FeeBid:  types.FeeBid{SeqPriority: u256.FromUint64(2)},
		Deposit: types.Deposit{Cell: types.Slot{Addr: newcomer}},
	}
	if got, ok := pool.floorLowerBoundFor(foreignAbove); !ok || !got.Eq(u256.FromUint64(1)) {
		t.Fatalf("bound for a foreign arrival above the plant's Seq = (%s, %v), want "+
			"(1, true): the exclusion fired on Seq alone, so the bound is now above "+
			"the exact floor for every such arrival", got, ok)
	}

	// Same-Seq replacement is the other separating input for the `seq <` term:
	// an RBF arrival at the plant's own Seq *may* take it, so the plant is a
	// candidate for it and the tight bound must be reported.
	rbf := &types.Certificate{
		Seq:     0,
		FeeBid:  types.FeeBid{SeqPriority: u256.FromUint64(2)},
		Deposit: types.Deposit{Cell: types.Slot{Addr: planter}},
	}
	if got, ok := pool.floorLowerBoundFor(rbf); !ok || !got.Eq(u256.FromUint64(1)) {
		t.Fatalf("bound for a same-Seq replacement = (%s, %v), want (1, true): the "+
			"exclusion fired on an arrival that may take the resident", got, ok)
	}
}
