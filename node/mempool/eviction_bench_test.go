package mempool_test

import (
	"testing"

	"zycord/core/types"
	"zycord/node/mempool"
)

// The cost of the eviction path, by price distribution.
//
// Wall time is reported here for whoever wants it, but nothing in
// docs/adversarial/mempool.md is quoted from it: ns/op on a shared machine
// varies by 3-8x run to run, which is more than the effect being measured, and
// two independent reviewers duly measured two different answers. What §2.1
// quotes instead is TestEvictionPathCostIsCountedNotTimed, which reports the
// three quantities the wall time is a noisy function of — how many arrivals are
// admitted, how many eviction passes run, and how many certificates each pass
// sorts. Those are exact, machine-independent, and are what the argument is
// actually about.
//
// Key seeds are laid out so no two callers collide — wallet.KeyFromSeed reads
// only the low sixteen bits of the index, and key(9999) is the tip destination
// every certificate in this suite pays to, so an underwriter landing on it
// would be a self-move and fail validity.
// costPolicy is the fixture both the benchmark and the count test run against:
// a pool of 4,000, so high water is 3,600, low water 3,400, and the cut 200.
func costPolicy() mempool.Policy {
	pol := mempool.DefaultPolicy()
	pol.MaxCertificates = 4_000
	return pol
}

type priceShape struct {
	name     string
	resident func(i int) uint64
	arrival  func(i int) uint64
}

func priceShapes() []priceShape {
	return []priceShape{
		// Everybody at one price: an arrival that clears it clears the whole cut.
		{"flat", func(int) uint64 { return 1_000 }, func(int) uint64 { return 1_100 }},
		// Spread narrower than the bump: the cut is still one decision.
		{"tight-spread", func(i int) uint64 { return 1_000 + uint64(i%100) }, func(int) uint64 { return 1_300 }},
		// Spread wide enough that an arrival takes a slice, not the cut.
		{"wide-spread", func(i int) uint64 { return 1_000 + uint64(i)*10 }, func(i int) uint64 { return 1_400 + uint64(i)*10 }},
		// A ladder spaced wider than the bump: an arrival beats few residents.
		{"geometric-ladder", func(i int) uint64 {
			p := uint64(1_000)
			for j := 0; j < i%40; j++ {
				p = p * 5 / 4
			}
			return p
		}, func(i int) uint64 {
			p := uint64(1_100)
			for j := 0; j < i/10; j++ {
				p = p * 11 / 10
			}
			return p
		}},
		// The adversarial one: every resident declares a fortune, and a single
		// identity rents the cheapest slot and climbs it a drop at a time. Each
		// arrival clears the floor and can take exactly one certificate, so
		// this is the shape that prices an eviction pass per arrival. The
		// fortune is 1e6 rather than 1e9 because the bid maximum sets the fee
		// ceiling and therefore the deposit, and V5 bounds a deposit above by
		// the emission the schedule can have issued by the certificate's TTL --
		// 4.2e10 at the TTL of 20 these fixtures use. Only the ORDER matters
		// here: every resident still declares a fortune against arrivals priced
		// at i+2, so the shape and every count below are unchanged.
		{"marginal-ladder", func(i int) uint64 {
			if i == 0 {
				return 1
			}
			return 1_000_000
		}, func(i int) uint64 { return uint64(i) + 2 }},
	}
}

func BenchmarkEvictionPath(b *testing.B) {
	pol := costPolicy()
	for _, sh := range priceShapes() {
		b.Run(sh.name, func(b *testing.B) {
			t := &testing.T{}
			w := newWorld(t, pol)
			for i := 0; w.pool.Stats().Size < 3_600; i++ {
				if err := w.add(w.cert(key(t, 20_000+i), 0, sh.resident(i), 1)); err != nil {
					b.Fatalf("filling: %v", err)
				}
			}
			// Signing is not the subject; build the arrivals outside the timer.
			certs := make([]*types.Certificate, 0, b.N)
			for i := 0; i < b.N; i++ {
				certs = append(certs, w.cert(key(t, 40_000+i), 0, sh.arrival(i), 1))
			}
			admitted := 0
			b.ResetTimer()
			for _, c := range certs {
				if err := w.add(c); err == nil {
					admitted++
				}
			}
			b.StopTimer()
			b.ReportMetric(float64(admitted)/float64(b.N)*100, "%admitted")
		})
	}
}

// TestEvictionPathCostIsCountedNotTimed is the evidence §2.1 quotes for the
// cost of the floor rule, in quantities that do not depend on the machine.
//
// Wall time on a shared host moves by more than the effect being measured, so
// what is reported here is what the wall time is a function of:
//
//   - admitted — how much of the offered traffic gets in. A gate that looks
//     cheap because it refuses everything is not cheap, it is §1.
//   - passes — how many arrivals ran an eviction pass. Refusing an arrival does
//     not skip the pass; it runs the full floor computation and then says no,
//     and it leaves the pool at its high-water mark so the next arrival pays
//     again. This is the count that shows a refusing gate does not do less work.
//   - sorted — how many certificates those passes sorted in total. The rejected
//     rule sorts every removable resident, because it applies the invariant
//     while walking the order; this one applies it while building the list, so
//     the sort is bounded by what the arrival can take.
func TestEvictionPathCostIsCountedNotTimed(t *testing.T) {
	const arrivals = 300
	pol := costPolicy()
	high := pol.MaxCertificates * int(pol.EvictionHighWater) / 100

	type result struct{ admitted, passes, sorted, worstPass int }
	got := map[string]result{}

	for _, sh := range priceShapes() {
		w := newWorld(t, pol)
		for i := 0; w.pool.Stats().Size < high; i++ {
			if err := w.add(w.cert(key(t, 20_000+i), 0, sh.resident(i), 1)); err != nil {
				t.Fatalf("%s filling: %v", sh.name, err)
			}
		}
		var r result
		for i := 0; i < arrivals; i++ {
			c := w.cert(key(t, 40_000+i), 0, sh.arrival(i), 1)
			// A pass runs when the pool is at its high-water mark *and* the
			// arrival clears every earlier gate in Add — duplicate id, the three
			// TTL checks, Seen, the base fee, the deposit screen, the
			// per-underwriter quota. Each arrival here is a fresh key with a
			// unique id, a constant TTL and a funded deposit, so for this fixture
			// occupancy alone is exact; it is not a general identity. What the
			// pass sorts is exactly the candidates the arrival may take. Both are
			// observable from outside the pool, so neither needs the production
			// path instrumented.
			if w.pool.Stats().Size >= high {
				r.passes++
				n := w.pool.EvictionCandidateCount(c)
				r.sorted += n
				if n > r.worstPass {
					r.worstPass = n
				}
			}
			if err := w.add(c); err == nil {
				r.admitted++
			}
		}
		got[sh.name] = r
		t.Logf("%-17s admitted %3d/%d  passes %3d  sorted %6d  worst pass %5d",
			sh.name, r.admitted, arrivals, r.passes, r.sorted, r.worstPass)
	}

	// The numbers §2.1 quotes. Exact, not approximate: if the rule changes, this
	// fails and the doc is corrected with it rather than drifting.
	want := map[string]result{
		"flat":             {admitted: 300, passes: 2, sorted: 7000, worstPass: 3600},
		"tight-spread":     {admitted: 300, passes: 2, sorted: 7000, worstPass: 3600},
		"wide-spread":      {admitted: 300, passes: 5, sorted: 492, worstPass: 230},
		"geometric-ladder": {admitted: 300, passes: 3, sorted: 1620, worstPass: 1170},
		"marginal-ladder":  {admitted: 49, passes: 300, sorted: 49, worstPass: 1},
	}
	for name, w := range want {
		if got[name] != w {
			t.Errorf("%s: got %+v, want %+v — docs/adversarial/mempool.md §2.1 quotes these",
				name, got[name], w)
		}
	}

	// The claim the marginal ladder exists to pin: one identity renting the
	// cheapest slot forces a pass on every arrival, and each pass must sort
	// exactly one candidate. Sorting the removable set there instead is an
	// O(n log n) sort under the write lock per certificate, for one deposit cell.
	if r := got["marginal-ladder"]; r.worstPass != 1 {
		t.Errorf("the marginal ladder sorted up to %d candidates per pass, want 1", r.worstPass)
	}
}
