package pow_test

import (
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/spec"
)

// ---------------------------------------------------------------------------
// What R1-H2 permits in the backward direction, derived from the rule rather
// than observed in a run.
//
// `future_time_limit_seconds` is the stated bound on the forward direction.
// The backward direction has never had one written down, and the substitute
// that grew up around it was a measured degradation curve — a statement about
// one attacker on one arrival distribution, which is not a bound at all.
//
// The bound is derivable, it is exact, and it is a bound on a RATE rather than
// on a DEPTH. That distinction is the whole finding, so it is stated first and
// then pinned one clause at a time below.
//
//	(1) DEPTH: unbounded, by any constant, IN VALIDITY. CheckMedianTime is the
//	    only lower bound on Header.Time and it compares against the median of
//	    the last MEDIAN_TIME_BLOCKS headers. Header.Time is never compared
//	    against its PARENT's, so a block may be dated arbitrarily far below its
//	    parent — the depth available is exactly (parent.Time − MedianTime), and
//	    since the future side is a withhold rather than a validity rule,
//	    nothing in consensus bounds the parent's own timestamp from above
//	    either. What bounds the depth is not validity but PROPAGATION, and the
//	    distinction is the point: a forward-dated parent is queued rather than
//	    relayed until the local clock passes Time−FTL, sync truncates a header
//	    range at the first header the local clock cannot reach, and past the
//	    one-hour withhold horizon it is dropped by every peer rather than held.
//	    So depth is bought with WALL-CLOCK WAIT, second for second. It is
//	    legal at every step and it is not free.
//
//	(2) RATE: bounded, and this is the bound that matters, because the RATE is
//	    what NextTarget integrates and the depth is not. MedianTime is
//	    NON-DECREASING under the rule (proved below by construction and pinned
//	    by TestMedianTimeNeverDecreasesUnderTheRuleThatBoundsIt), and raising
//	    it takes floor(M/2)+1 headers above the old value.
//
//	    THE HOLDER SUPPLIES ONLY THE ONES THE HONEST MINORITY DOES NOT. With h
//	    of M held, the M−h honest headers are already above the old median, so
//	    they contribute M−h of the floor(M/2)+1 needed for free and the holder
//	    contributes the remaining h−floor(M/2). So:
//
//	        the declared clock advances one second per h−floor(M/2) headers
//	        the holder produces,
//
//	    which per second of real time at a goal of g is h/((h−floor(M/2))·M·g).
//	    Both ends of that range matter and they are a factor of three apart on
//	    mainnet:
//
//	      - AT THE THRESHOLD, h = floor(M/2)+1 = 6 of 11: one second per ONE
//	        header it produces, a 55x compression of the declared clock.
//	      - AT TOTAL CAPTURE, h = M = 11: one second per SIX, a 180x
//	        compression. The infimum of one second per floor(M/2)+1 headers is
//	        reached ONLY by a producer that makes every one of them.
//
//	    An earlier revision of this file, and four documents that took the
//	    number from it, attributed the 180x to the THRESHOLD holder. It is off
//	    by need²/M = 3.27, the mechanism above is why, and the test named below
//	    now asserts the formula at every h on two parameter sets rather than at
//	    one h on one — because at h = floor(M/2)+1 alone the right derivation
//	    and the wrong one give the same number, so a single-point check could
//	    not have caught it and did not.
//
//	(3) The threshold is a COUNT OF HEADERS, not a share of hashrate, and it
//	    is sharp. At five of eleven the declared clock tracks real time
//	    exactly and the target settles near genesis; at six of eleven it
//	    collapses to 1/55 of real time and the target falls to its floor.
//	    Both sides are asserted below.
//
// WHAT THIS DOES NOT SAY. It does not say six-of-eleven is cheap: holding six
// of every eleven headers is a sustained majority of block production, and a
// stochastic miner at 54.5% holds the window only about 63% of the time.
// It does not say the chain dies: measured in
// TestTheDeclaredClockCollapseIsRecoverableWithoutAnOperator, the chain comes
// back on its own once the producer stops. And it says nothing about what a
// producer BELOW the threshold costs the chain — that is the measured curve in
// backdate_sweep_test.go, which is a different kind of statement and is
// labelled as one there.
// ---------------------------------------------------------------------------

// medianRun drives a window of headers under the real CheckMedianTime, with a
// producer that holds `num` of every `den` consecutive headers and dates every
// one of them at the earliest timestamp the rule admits. Everyone else declares
// the real clock.
//
// clock reports how long header i took, given genesis/target at that point. The
// only caller passes goalClock, which IGNORES the target: this file's rate
// statements are about the timestamp rule, and a clock that reacts to the
// difficulty would fold the controller's response into the number. The
// controller's response is measured separately, by the two tests below that
// build their own window and scale the interval by the target on purpose.
//
// Every header produced is checked against pow.CheckMedianTime before it is
// appended. That check is the anti-vacuity guard of this whole file: a harness
// that quietly produced a header the rule rejects would be measuring an attack
// that cannot happen, which is the failure mode the first two attempts at this
// measurement hit.
//
// THE FULL HISTORY IS RETURNED, NOT THE TRAILING WINDOW, and that is load-
// bearing rather than convenience. pow.MedianTime and pow.NextTarget both slice
// their own tail off whatever they are handed, so trimming here changes no
// consensus answer — but it changes what a caller measuring a RATE can see. An
// earlier revision trimmed to DifficultyWindow+1, so a caller asking "how far
// did the median move over this run" was reading 45 headers instead of 6,000
// and got an answer coarse enough to be wrong by 4% and smooth enough to look
// right. The range-wide assertion in
// TestTheDeclaredClockRateIsOnePerHeaderTheHolderMustSupply is what exposed it;
// the single-point version of that test passed on the broken instrument.
func medianRun(
	t *testing.T, p *params.Params, num, den, blocks int,
	clock func(i int, target float64) float64,
) []types.Header {
	t.Helper()
	w := make([]types.Header, 0, blocks+int(p.DifficultyWindow)+1)
	for i := 0; i <= int(p.DifficultyWindow); i++ {
		w = append(w, header(uint64(i), 1_000_000+uint64(i)*p.TargetBlockSeconds, p.GenesisTarget))
	}
	real := float64(w[len(w)-1].Time)
	for i := 0; i < blocks; i++ {
		target := pow.NextTarget(w, p)
		real += clock(i, ratioGenesisOver(target, p))

		m := pow.MedianTime(w, p)
		var ts uint64
		switch {
		case den > 0 && (i*num)%den < num:
			ts = m + 1 // the earliest timestamp the rule admits.
		case uint64(real) > m:
			ts = uint64(real)
		default:
			// An honest producer whose truthful reading is not legal posts the
			// minimum instead — node/miner.headerTime's ratchet.
			ts = m + 1
		}

		h := header(uint64(len(w)), ts, target)
		if err := pow.CheckMedianTime(h, w, p); err != nil {
			t.Fatalf("the harness produced a header the rule REJECTS at i=%d: %v. Every "+
				"header in this file must be one CheckMedianTime admits, or the file is "+
				"measuring an attack that cannot happen", i, err)
		}
		w = append(w, h)
	}
	return w
}

// goalClock is a fixed honest hashrate: every block takes the goal, whatever
// the target says. It isolates the TIMESTAMP rule from the controller.
func goalClock(p *params.Params) func(int, float64) float64 {
	return func(int, float64) float64 { return float64(p.TargetBlockSeconds) }
}

// TestMedianTimeNeverDecreasesUnderTheRuleThatBoundsIt is clause (2)'s
// foundation, and it is a property of the pair rather than of either half.
//
// The argument, so that the test is a check on a derivation and not a
// substitute for one: of the M headers in the window, at least ceil(M/2) are
// greater than or equal to the median. Dropping the oldest removes at most one
// of them, leaving at least ceil(M/2)−1; the new header is strictly greater
// than the old median by CheckMedianTime, which restores the count to
// ceil(M/2). A window with ceil(M/2) elements at or above a value has its own
// median at or above that value. So the median cannot fall.
//
// EXPECTED DIRECTION (PROTOCOL rule 22): the median must never decrease across
// any of these steps. The generator deliberately mixes the two inputs that
// would break it if anything could — the minimum legal value, which is the
// densest possible pressure downward, and an occasional enormous jump, which is
// what makes the window's contents disagree by orders of magnitude. If this
// test ever fails, clause (2) of this file's header is false and every rate
// statement below it is unsupported.
func TestMedianTimeNeverDecreasesUnderTheRuleThatBoundsIt(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *params.Params
	}{
		{"mainnet", spec.Mainnet()},
		{"devnet", spec.Devnet()},
		{"testnet", spec.Testnet()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.p
			var w []types.Header
			for i := 0; i < p.MedianTimeBlocks; i++ {
				w = append(w, header(uint64(i), 1_000_000+uint64(i)*7, p.GenesisTarget))
			}
			prev := pow.MedianTime(w, p)
			jumps := 0
			for i := 0; i < 5000; i++ {
				ts := pow.MedianTime(w, p) + 1
				if i%7 == 0 {
					ts += 100_000
					jumps++
				}
				h := header(uint64(len(w)), ts, p.GenesisTarget)
				if err := pow.CheckMedianTime(h, w, p); err != nil {
					t.Fatalf("i=%d: the generator produced an illegal header: %v", i, err)
				}
				w = append(w, h)
				if len(w) > 4*p.MedianTimeBlocks {
					w = w[len(w)-4*p.MedianTimeBlocks:]
				}
				now := pow.MedianTime(w, p)
				if now < prev {
					t.Fatalf("i=%d: MedianTime DECREASED, %d -> %d. Clause (2) of this "+
						"file's header rests on the median being non-decreasing", i, prev, now)
				}
				prev = now
			}
			if jumps == 0 {
				t.Fatal("VACUOUS: no jump header was generated, so the window never held " +
					"values that disagree and the monotonicity was never under pressure")
			}
		})
	}
}

// TestRaisingTheMedianTakesAMajorityOfTheWindow pins the count that clause (2)
// turns into a rate: floor(M/2)+1 headers above a value, and not one fewer.
//
// EXPECTED DIRECTIONS, both asserted, because only the pair identifies the
// number. With floor(M/2)+1 headers at the new value the median MUST have
// moved; with floor(M/2) it MUST NOT have. A test that checked only the first
// would pass for every count at or above the threshold and would not name it.
func TestRaisingTheMedianTakesAMajorityOfTheWindow(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *params.Params
	}{
		{"mainnet", spec.Mainnet()},
		{"devnet", spec.Devnet()},
		{"testnet", spec.Testnet()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.p
			m := p.MedianTimeBlocks
			need := m/2 + 1

			build := func(above int) []types.Header {
				var w []types.Header
				for i := 0; i < m-above; i++ {
					w = append(w, header(uint64(i), 1000, p.GenesisTarget))
				}
				for i := 0; i < above; i++ {
					w = append(w, header(uint64(m-above+i), 2000, p.GenesisTarget))
				}
				return w
			}
			if got := pow.MedianTime(build(need), p); got != 2000 {
				t.Fatalf("%d of %d headers at the new value left the median at %d, not 2000: "+
					"floor(M/2)+1 is not the count that raises it", need, m, got)
			}
			if got := pow.MedianTime(build(need-1), p); got != 1000 {
				t.Fatalf("%d of %d headers at the new value already moved the median to %d: "+
					"the count that raises it is smaller than floor(M/2)+1 and the rate in "+
					"clause (2) is wrong", need-1, m, got)
			}
		})
	}
}

// TestBackdateDepthHasNoBoundRelativeToTheParent is clause (1), and it is
// stated as an existential rather than as a maximum (PROTOCOL rule 21): there
// EXISTS a legal header dated an arbitrary distance below its parent, so no
// constant bounds the depth. It does not claim to have found the deepest one.
//
// The second half is the part a reader is most likely to get wrong. The depth
// available is (parent.Time − MedianTime), and the parent's own timestamp is
// not bounded above by any validity rule — a far-future header is WITHHELD and
// re-judged as the clock advances, never rejected (R1-H2). So a producer that
// wants a deeper backdate can buy one by dating the parent forward first, and
// the pair of blocks is legal at every step.
func TestBackdateDepthHasNoBoundRelativeToTheParent(t *testing.T) {
	p := spec.Mainnet()
	var w []types.Header
	for i := 0; i < p.MedianTimeBlocks; i++ {
		w = append(w, header(uint64(i), 1_000_000+uint64(i)*p.TargetBlockSeconds, p.GenesisTarget))
	}
	m := pow.MedianTime(w, p)
	parent := w[len(w)-1]
	if parent.Time <= m {
		t.Fatalf("the fixture's parent (%d) is not above the median (%d)", parent.Time, m)
	}

	// The deepest legal backdate against THIS window, by construction.
	deep := header(uint64(len(w)), m+1, p.GenesisTarget)
	if err := pow.CheckMedianTime(deep, w, p); err != nil {
		t.Fatalf("a header at median+1 was rejected: %v", err)
	}
	depth := parent.Time - deep.Time
	if depth == 0 {
		t.Fatal("VACUOUS: the median already equals the parent, so this window offers no " +
			"backdate at all and the test is about nothing")
	}
	t.Logf("a healthy window at goal offers a %d s backdate below the parent", depth)

	// Now buy a deeper one: date the parent forward. Nothing in consensus
	// refuses it — IsTooFarAhead is a withhold, checked by the node against its
	// own clock, and CheckMedianTime is indifferent to it.
	//
	// The depth is not push + 149: appending the forward-dated header also
	// advances the window by one slot, so the median rises by about one block
	// interval at the same time. What clause (1) claims is that the depth grows
	// WITHOUT BOUND in the push, and that is what is asserted — each push a
	// decade larger than the last must buy a strictly deeper backdate, with no
	// value of the push at which the rule starts refusing.
	prevDepth := uint64(0)
	for _, push := range []uint64{3600, 86_400, 365 * 86_400, 1_000_000 * 86_400} {
		fwd := w[:len(w):len(w)]
		ahead := header(uint64(len(w)), parent.Time+push, p.GenesisTarget)
		if err := pow.CheckMedianTime(ahead, fwd, p); err != nil {
			t.Fatalf("a header %d s ahead of its parent was REJECTED: %v. R1-H2 says the "+
				"future side is a withhold and not a validity rule", push, err)
		}
		fwd = append(fwd, ahead)
		next := header(uint64(len(fwd)), pow.MedianTime(fwd, p)+1, p.GenesisTarget)
		if err := pow.CheckMedianTime(next, fwd, p); err != nil {
			t.Fatalf("the block after a %d s forward-dated parent could not be backdated: %v",
				push, err)
		}
		got := ahead.Time - next.Time
		if got <= prevDepth || got < push {
			t.Fatalf("dating the parent %d s forward bought a %d s backdate, against %d s at "+
				"the previous push: clause (1) claims the depth grows without bound in the "+
				"parent's own timestamp and it did not", push, got, prevDepth)
		}
		prevDepth = got
	}
	t.Logf("a parent dated %d s forward makes a %d s backdate legal on the block after it",
		uint64(1_000_000*86_400), prevDepth)
}

// TestTheDeclaredClockRateIsOnePerHeaderTheHolderMustSupply is clause (2) and
// clause (3) together: the rate, the count that buys it, and — the part an
// earlier revision of this file got wrong — WHICH producer pays for each of the
// floor(M/2)+1 headers the median needs.
//
// The clock here is deliberately the one that IGNORES the target, so that what
// is measured is the timestamp rule alone rather than the timestamp rule plus
// the controller's reaction to it. The controller's reaction is the next test.
//
// EXPECTED DIRECTIONS, declared before the run (PROTOCOL rule 22):
//
//   - at floor(M/2) of M held, the median must advance at essentially the real
//     rate — the honest headers still decide it, so the declared clock is not
//     compressed at all.
//   - at EVERY h from floor(M/2)+1 to M, the median must advance at
//     h/((h−floor(M/2))·M·g) per second of real time: one second per
//     h−floor(M/2) headers the holder produces, because the M−h honest headers
//     in the window are already above the old median and supply that many of
//     the floor(M/2)+1 the rule needs.
//
// THE WHOLE RANGE AND NOT ONE POINT, and that is the repair rather than a
// thoroughness flourish. The earlier revision checked h = floor(M/2)+1 alone
// and read the answer as "one second per floor(M/2)+1 headers it produces".
// Those two coincide numerically at exactly that h — need/(den·g) is the same
// number either way when h−floor(M/2) = 1 — so a single-point check could not
// tell the right derivation from the wrong one, and the wrong one travelled
// into four documents. Every other h separates them, by up to the full
// need²/M factor between the two ends.
//
// If the first direction falls, the threshold is below the median position. If
// the second falls at any h, clause (2) has the wrong mechanism.
func TestTheDeclaredClockRateIsOnePerHeaderTheHolderMustSupply(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *params.Params
	}{
		{"mainnet", spec.Mainnet()},
		{"devnet", spec.Devnet()},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.p
			den := p.MedianTimeBlocks
			need := den/2 + 1
			const blocks = 6000
			goal := float64(p.TargetBlockSeconds)

			// The median is the quantity the rule bounds, so it is the one
			// measured: declared advance per second of real time. Measured over
			// the second half of the run, past the transient in which the
			// honest headers the fixture starts with age out of the window.
			advance := func(num int) float64 {
				w := medianRun(t, p, num, den, blocks, goalClock(p))
				half := len(w) / 2
				m0 := pow.MedianTime(w[:half], p)
				m1 := pow.MedianTime(w, p)
				realSpan := goal * float64(len(w)-half)
				return float64(m1-m0) / realSpan
			}

			below := advance(need - 1)
			if below < 0.99 {
				t.Fatalf("with %d of %d headers held the declared clock advanced at %.4f of "+
					"real time; below the median position the honest headers still decide "+
					"the median and it must track real time", need-1, den, below)
			}

			t.Logf("%s: %d/%d held -> %.4f of real time (uncompressed)", tc.name, need-1, den, below)
			t.Logf("%4s %8s %12s %12s %14s %12s", "held", "supplies", "measured", "derived",
				"1s per N held", "compression")
			var first, last float64
			for h := need; h <= den; h++ {
				supplies := h - den/2 // how many of the floor(M/2)+1 the holder must post
				want := float64(h) / (float64(supplies) * float64(den) * goal)
				got := advance(h)
				if got < 0.97*want || got > 1.03*want {
					t.Fatalf("with %d of %d held the declared clock advanced at %.6f of real "+
						"time; clause (2) derives %.6f. The holder supplies %d of the %d "+
						"headers the median needs — the honest %d are already above it — so "+
						"the rate is one second per %d headers the holder produces. If this "+
						"is off by the ratio between %d and %d, the derivation has gone back "+
						"to charging the holder for headers it does not post",
						h, den, got, want, supplies, need, den-h, supplies, supplies, need)
				}
				t.Logf("%4d %8d %12.6f %12.6f %14d %11.1fx", h, supplies, got, want, supplies, 1/got)
				if h == need {
					first = got
				}
				last = got
			}

			// The two ends are not the same number, and naming the ratio is what
			// stops the infimum being quoted for the threshold again. At h=need
			// the compression is den*g/need; at h=den it is need*g; the ratio is
			// need*need/den, independent of the goal.
			wantRatio := float64(need) * float64(need) / float64(den)
			if gotRatio := first / last; gotRatio < 0.97*wantRatio || gotRatio > 1.03*wantRatio {
				t.Fatalf("the declared clock at the threshold runs %.3fx faster than at total "+
					"capture; the derivation says need²/M = %.3f. These are the two ends the "+
					"file must keep apart: one second per ONE header at %d of %d, one second "+
					"per %d at %d of %d",
					gotRatio, wantRatio, need, den, need, den, den)
			}
			t.Logf("%s: the threshold holder's clock runs %.2fx faster than a total capture's "+
				"(derived need²/M = %.2f) — %.0fx compression against %.0fx",
				tc.name, first/last, wantRatio, 1/first, 1/last)
		})
	}
}

// TestTheDeclaredClockThresholdIsWhereTheControllerLeavesGenesis is the
// weighted consequence of clause (3), driven by the real NextTarget — which IS
// the weighted accumulator, so this is the weighted measurement and not a
// per-block count standing in for one.
//
// It also observes the BRANCH rather than a value that travels with it
// (PROTOCOL rule 24): the accumulator is recomputed here from the same window
// NextTarget saw, so "the weighted sum went non-positive" is read off the sum
// itself and not inferred from the target having moved.
//
// EXPECTED DIRECTIONS, declared before the run:
//
//   - at floor(M/2) held the weighted sum must stay positive on every block and
//     the target must stay within a factor of two of genesis. The controller
//     absorbs it; the signed clamp's cancellation is doing its job.
//   - at floor(M/2)+1 held the weighted sum must go NON-POSITIVE on a
//     substantial fraction of blocks and the target must fall by orders of
//     magnitude. That non-positive branch is the one core/pow's numerator
//     guard exists for.
//
// If the first fails, the threshold is not at the median position. If the
// second fails, the declared-clock collapse does not reach the controller and
// clause (3) is about nothing.
func TestTheDeclaredClockThresholdIsWhereTheControllerLeavesGenesis(t *testing.T) {
	p := spec.Mainnet()
	den := p.MedianTimeBlocks
	need := den/2 + 1
	const blocks = 1500
	const settle = 200

	// weightedSum recomputes NextTarget's accumulator over the same window.
	maxSolve := p.TargetBlockSeconds * p.DifficultyClampFactor
	weightedSum := func(w []types.Header) int64 {
		n := int(p.DifficultyWindow)
		if len(w) < n+1 {
			n = len(w) - 1
		}
		win := w[len(w)-(n+1):]
		var sum int64
		for i := 1; i < len(win); i++ {
			var solve int64
			if win[i].Time >= win[i-1].Time {
				d := win[i].Time - win[i-1].Time
				if d > maxSolve {
					d = maxSolve
				}
				solve = int64(d)
			} else {
				d := win[i-1].Time - win[i].Time
				if d > maxSolve {
					d = maxSolve
				}
				solve = -int64(d)
			}
			sum += solve * int64(i)
		}
		return sum
	}

	measure := func(num int) (nonPositive, total int, worstRatio float64) {
		w := make([]types.Header, 0, blocks+int(p.DifficultyWindow)+1)
		for i := 0; i <= int(p.DifficultyWindow); i++ {
			w = append(w, header(uint64(i), 1_000_000+uint64(i)*p.TargetBlockSeconds, p.GenesisTarget))
		}
		real := float64(w[len(w)-1].Time)
		worstRatio = 1
		for i := 0; i < blocks; i++ {
			target := pow.NextTarget(w, p)
			if i >= settle {
				total++
				if weightedSum(w) <= 0 {
					nonPositive++
				}
				if r := ratioFloatForTest(target, p); r < worstRatio {
					worstRatio = r
				}
			}
			real += float64(p.TargetBlockSeconds)
			m := pow.MedianTime(w, p)
			var ts uint64
			if (i*num)%den < num {
				ts = m + 1
			} else if uint64(real) > m {
				ts = uint64(real)
			} else {
				ts = m + 1
			}
			h := header(uint64(len(w)), ts, target)
			if err := pow.CheckMedianTime(h, w, p); err != nil {
				t.Fatalf("num=%d i=%d: illegal header: %v", num, i, err)
			}
			w = append(w, h)
			if len(w) > int(p.DifficultyWindow)+1 {
				w = w[len(w)-(int(p.DifficultyWindow)+1):]
			}
		}
		return nonPositive, total, worstRatio
	}

	np, tot, ratio := measure(need - 1)
	if tot == 0 {
		t.Fatal("VACUOUS: no block was measured below the threshold")
	}
	if np != 0 {
		t.Fatalf("with %d of %d held the weighted accumulator went non-positive on %d of %d "+
			"blocks; below the median position the honest headers still carry the window",
			need-1, den, np, tot)
	}
	if ratio < 0.5 {
		t.Fatalf("with %d of %d held the target fell to %.4g of genesis; below the threshold "+
			"the signed clamp's cancellation is supposed to absorb this", need-1, den, ratio)
	}
	t.Logf("%d/%d held: weighted sum positive on all %d blocks, worst target/genesis %.3f",
		need-1, den, tot, ratio)

	np, tot, ratio = measure(need)
	if np*10 < tot {
		t.Fatalf("with %d of %d held the weighted accumulator went non-positive on only %d of "+
			"%d blocks. Clause (3) says a window majority drives the accumulator negative; "+
			"if it does not, the collapse below has another cause", need, den, np, tot)
	}
	if ratio > 1e-3 {
		t.Fatalf("with %d of %d held the target only reached %.4g of genesis. Clause (3) "+
			"claims an unbounded fall and this is not one", need, den, ratio)
	}
	t.Logf("%d/%d held: weighted sum NON-POSITIVE on %d of %d blocks, target reached %.3g of "+
		"genesis", need, den, np, tot, ratio)
}

// TestTheDeclaredClockCollapseIsRecoverableWithoutAnOperator is the half that
// decides which gate this belongs to, and it is asserted rather than assumed.
//
// The collapse above is a liveness degradation and not a kill: the target's
// fall is bounded below by 1 rather than by anything the attacker chooses, and
// once the window majority stops the honest headers declare real time again,
// each of them measuring an enormous positive interval that the controller
// answers with the full relative clamp. The chain returns on its own.
//
// What it costs is real time, and the number is the point rather than a
// footnote: the recovery takes a bounded number of BLOCKS, and those blocks
// take as long as the damaged target says they take.
//
// EXPECTED DIRECTION: after the producer stops, the expected interval must
// return to within 1.1x the goal within a few hundred honest blocks. If it does
// not, this is a permanent freeze and belongs to a different list entirely.
func TestTheDeclaredClockCollapseIsRecoverableWithoutAnOperator(t *testing.T) {
	p := spec.Mainnet()
	den := p.MedianTimeBlocks
	need := den/2 + 1
	goal := float64(p.TargetBlockSeconds)

	w := make([]types.Header, 0, 4096)
	for i := 0; i <= int(p.DifficultyWindow); i++ {
		w = append(w, header(uint64(i), 1_000_000+uint64(i)*p.TargetBlockSeconds, p.GenesisTarget))
	}
	real := float64(w[len(w)-1].Time)
	// Its own counter, not len(w): the window is trimmed to DifficultyWindow+1
	// headers, so len(w) stops advancing and the interleave would freeze into a
	// single fixed pattern that never holds the window at all.
	produced := 0
	step := func(num int) float64 {
		target := pow.NextTarget(w, p)
		interval := goal * ratioGenesisOver(target, p)
		real += interval
		m := pow.MedianTime(w, p)
		var ts uint64
		if num > 0 && (produced*num)%den < num {
			ts = m + 1
		} else if uint64(real) > m {
			ts = uint64(real)
		} else {
			ts = m + 1
		}
		h := header(uint64(len(w)), ts, target)
		if err := pow.CheckMedianTime(h, w, p); err != nil {
			t.Fatalf("illegal header: %v", err)
		}
		w = append(w, h)
		if len(w) > int(p.DifficultyWindow)+1 {
			w = w[len(w)-(int(p.DifficultyWindow)+1):]
		}
		produced++
		return interval
	}

	// Attack until the expected interval is 100x the goal, which is far past
	// anything the measured curve reaches.
	attackBlocks, attackSeconds := 0, 0.0
	var damaged float64
	for i := 0; i < 2000; i++ {
		damaged = goal * ratioGenesisOver(pow.NextTarget(w, p), p)
		if damaged >= 100*goal {
			break
		}
		attackSeconds += step(need)
		attackBlocks++
	}
	if damaged < 100*goal {
		t.Fatalf("the window majority did not reach 100x the goal interval in 2000 blocks "+
			"(reached %.1fx); the collapse this test recovers from did not happen",
			damaged/goal)
	}
	t.Logf("%d/%d held: reached %.0fx the goal interval after %d blocks and %.2f hours",
		need, den, damaged/goal, attackBlocks, attackSeconds/3600)

	recoverBlocks, recoverSeconds := 0, 0.0
	for i := 0; i < 2000; i++ {
		if goal*ratioGenesisOver(pow.NextTarget(w, p), p) <= 1.1*goal {
			t.Logf("recovered to within 1.1x the goal after %d honest blocks and %.0f hours",
				recoverBlocks, recoverSeconds/3600)
			return
		}
		recoverSeconds += step(0)
		recoverBlocks++
	}
	t.Fatalf("the chain did not return to within 1.1x the goal in 2000 honest blocks after " +
		"the producer stopped. This test exists to establish that the collapse is a " +
		"liveness degradation and not a permanent freeze; if it fails, it is a permanent " +
		"freeze and the gate is a different one")
}
