package mempool_test

import (
	"fmt"
	"testing"

	"zycord/node/mempool"
)

// BenchmarkRejectedArrivalIsSizeIndependent is the evidence for the cost of
// saying no.
//
// Every arrival above the high-water mark used to pay two unconditional O(n)
// walks of the pool (chainPrices, then the candidate/floor pass) before its
// price was ever compared against anything, so an arrival priced below the
// market was refused at full price. makeRoomFor's own comment recorded that as
// still open after the floor-pinning rework.
//
// makeRoomFor now tries floorLowerBound first: a sound lower bound on the
// floor, maintained for amortised O(1) per admission (see that function's doc
// comment for the soundness argument), so an arrival that was never going to
// clear the real floor is refused without the pool being walked at all.
//
// If that cheap check were not running first — if every rejection still fell
// through to the O(n) computation — the poolSize=18000 subtest would cost
// dozens of times what poolSize=500 does, since both walks are linear in the
// pool. Run this directly to see the shape:
//
//	go test -run XXX -bench BenchmarkRejectedArrivalIsSizeIndependent -benchtime 200x ./node/mempool/
//
// and compare ns/op across subtests: it should stay roughly flat rather than
// growing with poolSize.
//
// Measured on darwin/arm64 (8 cores, -benchtime 300x), against the same tree
// with the floorLowerBound call in makeRoomFor disabled and nothing else
// changed — the counterfactual matters, because absolute ns/op here is
// dominated by the Ed25519 verification in validity.Check that every arrival
// pays before the pool is reached at all, and that constant would hide the
// effect if only one column were reported:
//
//	poolSize   fast path    disabled   ratio
//	     500      2.09 ms     1.70 ms    0.8x
//	   4 000      1.67 ms     4.08 ms    2.4x
//	  18 000      2.23 ms    48.99 ms     22x
//
// Disabled, the cost tracks the pool and then some: 1.70 -> 4.08 -> 48.99 ms
// across a 36x range in size. That is the two O(n) passes over byID a refused
// arrival should never have paid, plus the allocation behaviour that comes
// with them at scale. With the fast path the same column reads 2.09 -> 1.67 ->
// 2.23 ms — flat inside the run-to-run spread of a shared box, and at 18,000
// it is 22x cheaper.
//
// At 500 the fast path measures *slower* than the version without it, and that
// is reported rather than trimmed: the difference is smaller than this box's
// spread between runs, and a small pool is exactly where two O(n) passes cost
// nothing to begin with. It is the right trade anyway, because the shape is
// what matters and not the constant — the claim is not "faster" but "no longer
// a function of how much is pooled", pool size being the attacker's only lever.
//
// Absolute ns/op is dominated throughout by the Ed25519 verification in
// validity.Check that every arrival pays before the pool is reached at all,
// which is why the disabled column is here: one column alone would have hidden
// the effect inside that constant.
//
// `make ci`'s bench-smoke target runs this once per subtest (-benchtime 1x)
// purely so a benchmark that stops compiling or panicking cannot go unnoticed
// (I6-H2); it does not assert on timing, which would make CI flaky rather than
// informative.
func BenchmarkRejectedArrivalIsSizeIndependent(b *testing.B) {
	for _, n := range []int{500, 4_000, 18_000} {
		b.Run(fmt.Sprintf("poolSize=%d", n), func(b *testing.B) {
			pol := mempool.DefaultPolicy()
			pol.MaxCertificates = n
			pol.EvictionHighWater = 100 // so the pool is at the floor-check regime
			pol.EvictionLowWater = 90   // once filled to exactly n, below

			w := newWorld(b, pol)
			w.fillToHighWater(1_000_000)

			// Far below every resident's declared price and the required bump, so
			// this is refused on every call — and being refused, it is never
			// inserted, so the same certificate can be resubmitted every iteration
			// without colliding with itself in the pool.
			arrival := w.cert(key(b, 999_999_999), 0, 1, 1)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := w.add(arrival); err == nil {
					b.Fatal("the arrival was admitted; the benchmark is not measuring a rejection")
				}
			}
		})
	}
}

// BenchmarkRejectedSteerableArrivalIsSizeIndependent is the residual sibling:
// the size-independence property measured where the arrival-aware bound left it
// failing rather than only where it held.
//
// The benchmark above submits its refused arrival under a fresh key, so its own
// chain base is never pooled, floorLowerBoundFor returns the true global-minimum
// bound, and the cheap-bound fast path fires O(1). That never exercises the steerable
// residual — an arrival whose own underwriter owns the cheapest floorHint slots.
//
// This one does. One underwriter U* plants the three cheapest replacements
// (floorHint[0..2]), the rest of the pool is the market, and U* replays a Seq-1
// arrival priced between its own tail and the market. Before the bounded
// descend the arrival cleared a bound read off U*'s own cheap children and fell
// through the two O(n) walks, so this column climbed with pool size exactly as
// the plain benchmark's did with the fast path disabled; the bounded descend
// now refuses it in time bounded by MaxPerUnderwriter, so it stays flat like
// its sibling.
//
// Run both and compare ns/op across subtests:
//
//	go test -run XXX -bench 'BenchmarkRejected.*SizeIndependent' -benchtime 200x ./node/mempool/
func BenchmarkRejectedSteerableArrivalIsSizeIndependent(b *testing.B) {
	const market = 1_000_000
	for _, n := range []int{500, 4_000, 18_000} {
		b.Run(fmt.Sprintf("poolSize=%d", n), func(b *testing.B) {
			pol := mempool.DefaultPolicy()
			pol.MaxCertificates = n
			pol.EvictionHighWater = 100
			pol.EvictionLowWater = 90

			w := newWorld(b, pol)

			// The market, filled to three below high water so U*'s plants can take
			// the last three slots without triggering an eviction pass.
			for i := 0; w.pool.Stats().Size < n-3; i++ {
				if err := w.add(w.cert(key(b, 1_000_000+i), 0, market, 1)); err != nil {
					b.Fatalf("market fill: %v", err)
				}
			}
			uStar := key(b, 7_000_000)
			for _, p := range []uint64{3, 2, 1} {
				if err := w.add(w.cert(uStar, 0, p, 1)); err != nil {
					b.Fatalf("U* plant at %d: %v", p, err)
				}
			}
			if got := w.pool.Stats().Size; got != n {
				b.Fatalf("pool not at high water: size=%d want=%d", got, n)
			}

			// U*, Seq 1, above its own plants and below the market: the steerable
			// arrival. Refused on every call, never pooled, so replayable.
			arrival := w.cert(uStar, 1, 50, 1)

			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				if err := w.add(arrival); err == nil {
					b.Fatal("the steerable arrival was admitted; not measuring a rejection")
				}
			}
		})
	}
}
