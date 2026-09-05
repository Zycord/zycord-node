package pow

import (
	"testing"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/spec"
)

// I8, part three: the rules that decide, against the rules that run.
//
// ARCHITECTURE §12 asserts that the two time rules and the target rule are
// enforced at three ingress sites — node/sync.ValidateHeaders, node/p2p's
// tip-extension branch, and node/chain.validateBranchDifficultyLocked — and
// concludes that they are therefore "path-independent". I5-H19 falsified
// exactly that shape of claim for pow.CheckWork, which had no call site at all
// on the path blocks actually arrive by, so the claim is worth testing rather
// than reading.
//
// A full three-path differential belongs in node/p2p, where the three call
// sites live, and it is expensive there — the p2p suite is ~23 minutes. What
// belongs HERE is the half the three sites share and the half a p2p test could
// not isolate: all three call the same two functions over a window they each
// construct, so path-independence reduces to a property of those functions
// given equivalent windows. If NextTarget or CheckMedianTime were sensitive to
// anything the three constructions differ in — length, capacity, the identity
// of the backing array — the sites would diverge no matter how carefully each
// was written.
//
// So this file tests the shared kernel: the rules must be pure functions of the
// window's VALUES. That is what makes three independently-built windows
// interchangeable, and it is a claim about core/pow rather than about any
// caller.

// buildWindow returns a plausible honest window of the given length ending at
// the given height.
func buildWindow(p *params.Params, n int, endHeight uint64) []types.Header {
	w := make([]types.Header, n)
	for i := 0; i < n; i++ {
		h := endHeight - uint64(n-1-i)
		w[i] = types.Header{
			Version: types.HeaderVersion,
			Height:  h,
			Time:    1_000_000 + h*p.TargetBlockSeconds,
			Target:  p.GenesisTarget,
		}
	}
	return w
}

// TestTheTimeAndTargetRulesArePureFunctionsOfTheWindowsValues is the property
// path-independence actually rests on.
//
// The three enforcement sites build their windows differently:
//
//	node/sync           accumulates st.window as it validates a range
//	node/p2p            calls Chain.RecentHeaders(DifficultyWindow+1)
//	node/chain          calls headersEndingAtHeightLocked, then appends
//
// Three constructions, three backing arrays, three capacities, three slice
// headers. They agree only if the rules read nothing but the values. This
// drives the same logical window through representations that differ in every
// way a Go slice can differ while holding equal values, and requires one
// answer.
//
// A rule that read cap(), or that mutated its input, or that retained the
// caller's array, would fail here — and would fail in production as a fork
// between two nodes fed the same blocks by different paths, which is the class
// this project calls unrecoverable.
func TestTheTimeAndTargetRulesArePureFunctionsOfTheWindowsValues(t *testing.T) {
	p := spec.Devnet()
	n := int(p.DifficultyWindow) + 1
	canonical := buildWindow(p, n, 500)

	want := NextTarget(canonical, p)
	wantMedian := MedianTime(canonical, p)

	// The candidate header every representation is judged against.
	cand := types.Header{
		Version: types.HeaderVersion,
		Height:  501,
		Time:    wantMedian + 1,
		Target:  want,
	}
	wantTimeErr := CheckMedianTime(cand, canonical, p)

	reps := map[string][]types.Header{}

	// 1. Exact copy into an exactly-sized array.
	exact := make([]types.Header, n)
	copy(exact, canonical)
	reps["exact"] = exact

	// 2. A slice with spare capacity behind it — what an append-built window
	//    looks like (node/sync's st.window, node/chain's append loop).
	spare := make([]types.Header, 0, n*3)
	spare = append(spare, canonical...)
	reps["spare capacity"] = spare

	// 3. A window that is the tail of a longer array, with unrelated headers
	//    in front of it — what a trimmed rolling window looks like. The
	//    headers in front carry wildly different targets and times, so a rule
	//    that reached before the slice start would produce a different answer.
	backing := make([]types.Header, 0, n*2)
	for i := 0; i < n; i++ {
		backing = append(backing, types.Header{
			Height: 1,
			Time:   7,
			Target: p.MaxTarget,
		})
	}
	backing = append(backing, canonical...)
	reps["tail of a longer array"] = backing[n:]

	// 4. A window with unrelated headers AFTER it, so a rule reading past the
	//    slice end is caught too.
	over := make([]types.Header, 0, n*2)
	over = append(over, canonical...)
	for i := 0; i < n; i++ {
		over = append(over, types.Header{Height: 9999, Time: 1, Target: p.MaxTarget})
	}
	reps["head of a longer array"] = over[:n]

	for name, w := range reps {
		if got := NextTarget(w, p); !got.Eq(want) {
			t.Errorf("%s: NextTarget gives %s, the canonical window gives %s —"+
				" the rule is not a pure function of the window's values, so two"+
				" ingress paths can derive different targets from the same blocks",
				name, got.String(), want.String())
		}
		if got := MedianTime(w, p); got != wantMedian {
			t.Errorf("%s: MedianTime gives %d, want %d", name, got, wantMedian)
		}
		if got := CheckMedianTime(cand, w, p); (got == nil) != (wantTimeErr == nil) {
			t.Errorf("%s: CheckMedianTime disagrees with the canonical window (%v vs %v)",
				name, got, wantTimeErr)
		}
	}
}

// TestTheRulesDoNotMutateTheirWindow is the other half of purity, and it is the
// half that would bite in production rather than in a test.
//
// node/p2p hands NextTarget the slice Chain.RecentHeaders returned. If the rule
// wrote through that slice, it would be writing into whatever the chain handed
// out — and the next caller would read a window the previous call had altered.
// The failure would be intermittent, ordering-dependent, and would present as
// two nodes disagreeing about a target for reasons no block explains.
func TestTheRulesDoNotMutateTheirWindow(t *testing.T) {
	p := spec.Devnet()
	n := int(p.DifficultyWindow) + 1
	w := buildWindow(p, n, 500)

	before := make([]types.Header, n)
	copy(before, w)

	_ = NextTarget(w, p)
	_ = MedianTime(w, p)
	_ = CheckMedianTime(types.Header{Height: 501, Time: 1 << 40}, w, p)

	for i := range w {
		if w[i] != before[i] {
			t.Fatalf("the window was mutated at index %d: %+v became %+v",
				i, before[i], w[i])
		}
	}
}

// TestMedianTimeSortsACopyRatherThanTheCallersSlice is the specific mutation
// the test above generalises, called out because it is the one a reasonable
// implementation gets wrong.
//
// MedianTime needs sorted timestamps. The cheap way to get them is to sort the
// window in place; the correct way is to extract the times and sort those. The
// current implementation does the latter. This pins it, because the cheap
// version passes every functional test — the median it returns is right — and
// only corrupts the CALLER's slice, whose next use is a difficulty computation
// that would then read headers in timestamp order rather than height order.
//
// That is a fork with no bad block in it, so it gets its own test rather than
// relying on the general one above.
func TestMedianTimeSortsACopyRatherThanTheCallersSlice(t *testing.T) {
	p := spec.Devnet()

	// Deliberately out of timestamp order, so an in-place sort visibly
	// reorders it. Heights ascend; times do not.
	w := []types.Header{
		{Height: 10, Time: 900, Target: p.GenesisTarget},
		{Height: 11, Time: 100, Target: p.GenesisTarget},
		{Height: 12, Time: 500, Target: p.GenesisTarget},
	}
	heightsBefore := []uint64{w[0].Height, w[1].Height, w[2].Height}

	_ = MedianTime(w, p)

	for i, want := range heightsBefore {
		if w[i].Height != want {
			t.Fatalf("MedianTime reordered the caller's window: index %d holds"+
				" height %d, was %d — a later NextTarget over this slice reads"+
				" headers in timestamp order and derives a target no other node does",
				i, w[i].Height, want)
		}
	}
}

// TestAShortWindowDoesNotCrashOrDegenerate covers the early-chain case every
// enforcement site reaches at different heights.
//
// A node syncing from genesis calls these rules with windows of length 0, 1, 2
// and so on. The three sites reach those lengths at different moments — sync
// accumulates, p2p asks the chain for as many as exist, fork choice takes what
// the ancestor has — so the short-window behaviour must be defined and equal.
func TestAShortWindowDoesNotCrashOrDegenerate(t *testing.T) {
	p := spec.Devnet()

	for n := 0; n <= 12; n++ {
		w := buildWindow(p, n, uint64(n))
		if n == 0 {
			w = nil
		}

		got := NextTarget(w, p)
		if got.IsZero() {
			t.Errorf("window of %d: NextTarget returned zero — no hash can satisfy it", n)
		}
		if got.Gt(p.MaxTarget) {
			t.Errorf("window of %d: NextTarget exceeded MaxTarget", n)
		}

		// The median rule must not reject a plausible header at any window
		// length, and must not panic at length 0 or 1.
		cand := types.Header{
			Version: types.HeaderVersion,
			Height:  uint64(n) + 1,
			Time:    1 << 40,
			Target:  got,
		}
		if err := CheckMedianTime(cand, w, p); err != nil {
			t.Errorf("window of %d: a far-future-dated header was refused by the"+
				" median rule (%v); the floor is above every plausible timestamp", n, err)
		}
	}
}
