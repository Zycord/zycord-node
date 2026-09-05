package pow_test

import (
	"fmt"
	"math"
	"math/rand"
	"os"
	"sort"
	"strconv"
	"sync"
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/spec"
)

// ---------------------------------------------------------------------------
// The backward direction has no stated bound, and the curve that stands in for
// one was measured at one seed per share.
//
// `future_time_limit_seconds` bounds forward-dating. Nothing bounds backdating
// except CheckMedianTime, which only requires a header to be strictly later
// than the median of the last MedianTimeBlocks headers. An attacker that dates
// every block it wins at exactly that minimum — median+1 — is never withheld,
// never rejected, and never has to skip a block it won.
//
// The reported degradation curve (median real block interval against attacker
// share) is what a genesis decision on median_time_blocks would rest on, and
// it was one sample per share. This file is the seed sweep that says how much
// of that curve is signal. It measures, and decides nothing: no parameter in
// this tree moves because of anything below.
//
// A CURVE IS NOT A BOUND, and the bound now exists elsewhere.
// core/pow/median_bound_test.go states what R1-H2 permits in this direction,
// derived from the rule rather than measured: no constant bounds the depth of a
// single backdate, and what IS bounded is the RATE at which declared time
// advances — one second per h−floor(M/2) headers a holder of h of M produces,
// since the M−h honest headers in the window already supply that many of the
// floor(M/2)+1 the median needs. At the threshold h = floor(M/2)+1 that is one
// second per ONE header it produces; only a producer that makes all M reaches
// one per floor(M/2)+1. Everything below is a statement about what a producer
// BELOW that threshold costs the chain, which is a different question and is
// answered by simulation because it has to be.
//
// WHAT THIS FILE DELIBERATELY DOES NOT REACH, because a knee measured under
// one attacker model is a knee under that model (PROTOCOL rule 21):
//
//   - One arrival distribution. Solve times are exponential at a hashrate the
//     simulation holds fixed (or steps once, for the recovery measurement).
//     Real hashrate wanders; a wandering hashrate is a different input to the
//     same controller and is not swept here.
//   - One clamp value. DifficultyClampFactor is mainnet's 16 throughout, so
//     ±maxSolve is ±480 s in every run below. The knee's dependence on the
//     clamp is not measured, and the mechanism section shows the clamp is
//     load-bearing, so that dependence is not obviously weak.
//   - One attacker policy, fixed for the whole run: win a block with
//     probability `share`, always date it median+1, never withhold, never
//     vary. An adaptive attacker that raises its share only while the median
//     window is already leaning its way is strictly stronger than this one and
//     is not simulated.
//   - One network. Mainnet parameters only. Devnet's 5 s goal against the same
//     11-header median is a different exposure, as the params.json note on
//     future_time_limit_seconds already records for the forward direction.
//   - Steady share. The recovery measurement steps the honest hashrate once
//     and holds the attacker's absolute share constant across the step.
//
// So every number below is a statement about THIS attacker on THIS input
// distribution, and the honest form of the headline is a lower bound on the
// damage rather than a maximum over attackers.
//
// WHAT IT MEASURED, recorded here because the sweep is gated out of the
// default build and a gated measurement nobody can read is not a measurement.
// Mainnet parameters, 24 seeds x 30,000 blocks per share:
//
//	share    0%     20%     30%     34%     36%     38%     40%     45%     50%
//	median 20.69   20.83   21.65   22.78   23.77   25.67   29.51   57.92   91.95
//	sd      0.15    0.11    0.14    0.17    0.32    0.63    1.02    2.77    2.07
//
// The knee, located per seed and then summarised, is where the reported one is,
// and the seed is NOT what its uncertainty is made of:
//
//	1.25x the honest baseline: share 0.381, sd 0.003
//	1.50x:                     share 0.404, sd 0.003
//	2.00x:                     share 0.425, sd 0.003
//
// Three tenths of a percentage point of share across seeds. The sd is FLAT in
// the seed count and mildly falling in chain length — 0.005/0.001/0.002 at 4
// seeds, 0.003/0.003/0.002 at 8, 0.003/0.003/0.003 at 24, and 0.002 at 90,000
// blocks — consistent with 1/sqrt(n) on a quantity that was already small.
// FOUR seeds already gave 0.380/0.402/0.425, inside the 0.02 grid spacing.
//
// SO SAY IT PLAINLY: THE SEED HALF OF THIS SWEEP IS NOT WHAT THE DECISION
// RESTS ON. It was the half the audit asked for, it was worth running once to
// find that out, and the honest label for the extra seeds is that they bought
// a roughly 2x tighter estimate of a spread that is already fifteen times
// smaller than the other source of uncertainty. That other source is the
// knee's DEFINITION: the crossing share moves from 38% to 43% depending on
// how much degradation is called the knee. A decision that quotes "40%" is
// quoting a threshold choice, not a sample, and no number of seeds narrows
// that.
//
// THE MECHANISM THE ISSUE OFFERS DOES NOT REPRODUCE AT THE KNEE, and this is
// the finding that matters most for anyone reasoning from the curve. The
// issue attributes the failure of the signed clamp's pairwise cancellation to
// attacker blocks arriving in RUNS: a run of k blocks gets one compensating
// positive interval however large k is, so the deleted mass should grow with
// run length rather than per block. The claim was made at 40% share, and at
// 40% share it is wrong. Priced directly over 168,000 maximal runs there,
// per-attacker-block deletion is flat in k:
//
//	k             1      2      3      4      6      8     10
//	runs     101425  40937  16461   6544   1055    154     32
//	mass/k    49.75  42.62  42.01  44.81  46.87  50.52  53.24
//
// Ten blocks in a row cost 1.07x per block what one block alone costs, and at
// the fixed k=3 the ratio is 0.844 — clustering costs the chain LESS per block
// there, not more.
//
// THE GENERALISATION DOES NOT HOLD, and an earlier revision of this header
// made it. "Intercept near zero at every share" was false. The weighted fits
// and the fixed-k ratio, full size, are:
//
//	share                      20%     30%     35%     40%     50%
//	fit slope (s per block)   3.40    8.40   15.58   43.25  167.68
//	fit intercept (s)        -1.95   -3.61   -4.31   +4.01  +92.09
//	(mass/k at k=3)/(k=1)    1.673   1.234   1.028   0.844   0.739
//
// The clustering effect CHANGES SIGN across the share axis: strongly
// super-additive below the knee, additive at ~35%, sub-additive above. So the
// audit's mechanism is refuted where the audit asserted it and is roughly
// right where the curve is flat and nobody was arguing.
//
// AND THE SIGN CHANGE IS NOT ABOUT SHARE. It is the clamp measured against the
// backdate depth, c/D, and share enters only because D grows with share: move
// the clamp and the crossing moves with it, at a fixed share. The derivation,
// the two experiments that separate the accounting from the chain, and the 2/3
// floor that falls out of it are with
// TestTheClusteringSignChangeIsTheClampOverTheBackdateDepth at the foot of this
// file. That is where the joint keying on median_time_blocks and
// difficulty_clamp_factor stops being an assertion and becomes a functional
// form.
//
// WHAT THE DELETION IS, shown by experiment rather than by identity. An
// earlier revision of this header argued from the fact that with the clamp
// removed from the accounting the deleted mass is identically zero. It is —
// and that is an identity of this harness's bookkeeping, not a measurement:
// honest blocks declare their honest time by construction, so a segment
// bounded by two honest blocks telescopes to zero whatever happened inside it.
// It is also unweighted where NextTarget accumulates solve*i. It proved
// nothing, and it survives below only as the segmentation control it is.
//
// The experiment that does prove it needs no mutation of pow.go at all: widen
// DifficultyClampFactor on a local copy of the parameters until the clamp
// cannot be reached (1e6, so ±3e7 s), and re-measure the real curve driven by
// the real NextTarget. 24 seeds x 30,000 blocks
// (TestLiftingTheAccumulatorClampRemovesTheDegradation):
//
//	share            shipped ±480 s        lifted out of reach
//	  0%      20.66 s   worst t/T0 2.33     20.66 s   t/T0 4.17
//	 40%      29.64 s   worst t/T0 2.16     20.27 s   t/T0  687
//	 50%      90.05 s   worst t/T0 2.05     16.97 s   t/T0 4096
//
// The degradation VANISHES. The honest baseline is 20.79 s (goal*ln2), so at
// 40% the excess falls from 8.9 s to under 0.5 s and at 50% the chain runs
// FASTER than its goal. Clamp truncation is the mechanism, and the exposure is
// median_time_blocks and difficulty_clamp_factor JOINTLY — demonstrated now,
// not inferred.
//
// TWO USES, AND THE TWO COLUMNS DO NOT SHARE A CAUSE. DifficultyClampFactor is
// both maxSolve and NextTarget's per-step target clamp, so widening it moves
// both; decoupling them by mutation attributes each column separately. The
// INTERVAL collapse is maxSolve alone — lifting only maxSolve gives the whole
// 29.64 -> 20.39 s at 40%, and lifting only the per-step clamp gives
// 30.07 -> 30.07 s and trips this file's own MECHANISM NOT DEMONSTRATED. The
// RUNAWAY column mixes them: the per-step clamp alone moves worst t/T0 from
// 2.343 to 3.462 at 40%, so the 687 and the 4096 above are both effects
// together and not maxSolve alone. The assertion is unaffected — it demands a
// 50x rise and the confound alone gives 1.48 — but the numbers are not
// attributable to one variable, and the full note is on the test itself.
//
// What makes the clamp bind is backdate depth: the attacker's
// own low timestamps enter the 11-header median window and drag the median
// further below the parent, so the correction the next honest block owes grows
// past ±480 s and is cut off.
//
//	share            20%     30%     35%     40%     50%
//	deleted (s)     1.84    5.89   12.78   45.63  213.78
//	depth (s)      151.9   162.3   181.1   267.8  1559.5
//	clamped -480   0.001   0.008   0.021   0.070   0.229
//
// THIS IS NOT AN ARGUMENT FOR A LARGER CLAMP, and the third column above is
// why. Lifting the clamp buys the freeze direction off against the mirror
// runaway the signed clamp exists to prevent: at 50% the worst target/genesis
// ratio goes to 4096, which is max_target/genesis_target EXACTLY — the chain
// is pinned at the absolute ceiling, where BlockWork is 63 for every header
// and fork choice degenerates toward a block count. The blocks are fast
// because the chain is compromised. The test asserts that blow-up rather than
// merely noting it, so this table cannot be quoted with its last column
// dropped.
//
// The conclusion the curve supports is therefore about how much of the
// MedianTimeBlocks window one miner can hold, against how hard the accumulator
// clamp cuts the correction that window's depth produces. That is a sharper
// statement about the parameters under decision than the run-length account
// was — and it is still a measurement: this file sets no value.
//
// RECOVERY FROM A HASHRATE DEPARTURE HOLDS AT EVERY DEPARTURE SIZE TESTED,
// and the multiplier is nearly flat in the departure — the issue's single
// K=10 point is not a special case. 24 seeds, attacker at 34%, recovery being
// the expected interval back within 1.1x the goal, in hours:
//
//	K              3      10      30     100
//	honest      1.14    1.87    3.12    6.94
//	attacked    3.17    5.60    9.70   22.41
//	ratio       2.79    3.00    3.11    3.23
//
// Every one of 192 runs recovered. The absolute hours are lower than the
// issue's because the recovery criterion here is the controller's own state
// rather than a realised interval; the RATIO is the transferable number, and
// it reproduces. It also creeps upward with K, so the deeper the departure the
// worse the attacker makes it — the opposite of the reassuring direction.
//
// ONE-SIDEDNESS OF THE HEADLINE METRIC, found by a probe that came out
// backwards. Flooring NextTarget's negative solve times at zero (the rule the
// signed accumulator retired) was expected to push the 40% median interval
// far ABOVE 29.5 s. It pushed it to 6.4 s, with the worst target/genesis
// ratio going from ~2.2 to ~11.9: that failure mode is the runaway toward
// MaxTarget, where blocks get FASTER and the median-interval curve reads as
// an improvement. So the median real interval sees the freeze direction only.
// The worst target/genesis ratio the sweep prints beside it is the mirror
// direction's witness, and reading the curve without it would call a
// compromised chain a fast one.
// ---------------------------------------------------------------------------

// backdateTrace is the full record of one simulated chain. Metrics are derived
// from it afterwards rather than accumulated inside the loop, so that a new
// question about an old run does not need the run repeated.
type backdateTrace struct {
	// headers is the chain as it was actually built and as NextTarget saw it:
	// declared timestamps, attacker lies included.
	headers []types.Header
	// honestTime[i] is what header i WOULD have declared had its winner been
	// truthful. It is the same physical chain — same solve times, same
	// targets — reported honestly. It is a bookkeeping counterfactual, not a
	// counterfactual chain: an honest chain would have retargeted differently
	// and so would not have had these solve times at all. That is exactly
	// what makes it the right baseline for "mass the LWMA did not integrate":
	// it differs from the real series in the reporting and in nothing else.
	honestTime []uint64
	// realSolve[i] is the physical solve time of block i, in seconds.
	realSolve []float64
	// attacker[i] reports whether the attacker won block i.
	attacker []bool
	// medianLag[i] is (parent declared time − MedianTime seen at block i) for
	// attacker blocks, and 0 elsewhere: how deep a backdate the median rule
	// was offering at that point.
	medianLag []float64
	// warmup is the number of leading blocks mined honestly, excluded from
	// every metric.
	warmup int
	// worstRatio is the largest target/GenesisTarget reached over the run.
	worstRatio float64
	// honestBumps counts honest blocks whose truthful clock reading was not a
	// legal timestamp (it tied the median at whole-second resolution) and
	// which therefore posted median+1 instead.
	honestBumps int
	// invalidTime counts headers that would fail CheckMedianTime. It must
	// stay zero: an attacker whose blocks the rule already rejects is not the
	// attacker this issue is about, and a non-zero count means the harness is
	// measuring an attack that cannot happen.
	invalidTime int
}

// simulateBackdate drives the real pow.NextTarget over `blocks` blocks in
// which the attacker wins each block independently with probability `share`
// and dates every block it wins at MedianTime+1 — the earliest timestamp
// CheckMedianTime admits.
//
// Independent per-block wins are not a modelling shortcut, they are the point:
// a miner with share p wins blocks in geometrically distributed runs, and the
// refutation this measurement overturns (the signed symmetric clamp cancels a
// backdate against the next honest block) is an argument about isolated
// blocks. Interleaving the attacker on a fixed period, as this package's
// existing simulateInterleavedAttacker does, holds every run at length one by
// construction and therefore cannot see a run-length effect at all.
//
// Two clocks, for the reason simulateInterleavedAttacker's comment gives: the
// attacker lies relative to the true clock, not relative to whatever its own
// parent declared, so the following honest block measures a real gap.
//
// hashrate(i) scales the honest solve-time expectation at block i: 1 is the
// hashrate that solves GenesisTarget in exactly the goal, and 0.1 is a
// ten-fold departure.
func simulateBackdate(
	p *params.Params, share float64, blocks, warmup int, seed int64, hashrate func(i int) float64,
) *backdateTrace {
	goal := float64(p.TargetBlockSeconds)
	rng := rand.New(rand.NewSource(seed))
	const base = 10_000_000_000 // headroom so a backdate never underflows uint64.

	tr := &backdateTrace{
		headers:    make([]types.Header, 1, blocks+1),
		honestTime: make([]uint64, 1, blocks+1),
		realSolve:  make([]float64, 1, blocks+1),
		attacker:   make([]bool, 1, blocks+1),
		medianLag:  make([]float64, 1, blocks+1),
		warmup:     warmup,
	}
	tr.headers[0] = header(0, base, p.GenesisTarget)
	tr.honestTime[0] = base
	realTime := float64(base)

	for i := 1; i <= blocks; i++ {
		target := pow.NextTarget(tr.headers, p)
		if r := ratioFloatForTest(target, p); r > tr.worstRatio {
			tr.worstRatio = r
		}

		hr := hashrate(i)
		expected := goal * ratioGenesisOver(target, p) / hr
		solve := rng.ExpFloat64() * expected
		realTime += solve

		// A truthful clock reading, made monotone: Header.Time is whole
		// seconds, so two blocks solved less than a second apart round to the
		// same value and a truthful series still never goes backwards.
		honest := uint64(realTime)
		if honest < tr.honestTime[i-1] {
			honest = tr.honestTime[i-1]
		}

		m := pow.MedianTime(tr.headers, p)
		declared := honest
		lag := 0.0
		isAttacker := i > warmup && rng.Float64() < share
		if isAttacker {
			declared = m + 1
			lag = float64(tr.headers[i-1].Time) - float64(m)
		} else if declared <= m {
			// An honest winner still has to produce a VALID header. When the
			// target has been eased far enough that whole seconds no longer
			// separate blocks, a truthful reading can tie the median, and the
			// rule requires strictly later — so an honest miner posts the
			// earliest legal timestamp instead, exactly as it would on a real
			// network. Counted, because if this were common the simulation
			// would be reporting the rounding of Header.Time rather than the
			// attack.
			declared = m + 1
			honest = declared
			tr.honestBumps++
		}

		h := header(uint64(i), declared, target)
		if err := pow.CheckMedianTime(h, tr.headers, p); err != nil {
			tr.invalidTime++
		}
		tr.headers = append(tr.headers, h)
		tr.honestTime = append(tr.honestTime, honest)
		tr.realSolve = append(tr.realSolve, solve)
		tr.attacker = append(tr.attacker, isAttacker)
		tr.medianLag = append(tr.medianLag, lag)
	}
	return tr
}

// clampSigned is NextTarget's per-sample accumulation, extracted so the
// measurement below integrates exactly what the rule integrates. Keeping it a
// separate function rather than reusing NextTarget is deliberate: NextTarget
// returns a target, and the quantity this file is about is the term inside it.
func clampSigned(now, prev uint64, maxSolve uint64) float64 {
	if now >= prev {
		d := now - prev
		if d > maxSolve {
			d = maxSolve
		}
		return float64(d)
	}
	d := prev - now
	if d > maxSolve {
		d = maxSolve
	}
	return -float64(d)
}

// realIntervals returns the physical solve times of the measured (post-warmup)
// blocks. The real interval is what a user waits for, and it is the quantity
// the issue's curve reports — not the declared interval, which is the
// attacker's own arithmetic.
func (tr *backdateTrace) realIntervals() []float64 {
	out := make([]float64, 0, len(tr.realSolve))
	for i := tr.warmup + 1; i < len(tr.realSolve); i++ {
		out = append(out, tr.realSolve[i])
	}
	return out
}

// runObservation is one maximal run of consecutive attacker blocks, together
// with the solve-time mass the LWMA failed to integrate over the segment that
// run occupies.
//
// The segment is the run PLUS the one honest block that follows it, because
// that honest block is where the compensating positive interval lands — it is
// the whole of the signed clamp's cancellation argument, and excluding it
// would delete the mass by construction.
type runObservation struct {
	length int
	// deleted is (mass the honest series contributes) − (mass the attacked
	// series contributes) over the segment, both accumulated with NextTarget's
	// own signed ±maxSolve clamp. Positive means the rule integrated less
	// elapsed time than really elapsed, which is what eases the target.
	deleted float64
	// deletedUnclamped is the same difference with the ±maxSolve clamp
	// removed from both series, and it is a SEGMENTATION CONTROL rather than a
	// result. It is identically zero, by telescoping: both series begin and
	// end on an HONEST block, where they agree by construction here, so the
	// intermediate declared times cancel however wildly they were lied about
	// and however long the run was. The harness could not have produced
	// another answer, and it is unweighted where NextTarget accumulates
	// solve*i — so it is evidence about the segment boundaries and about
	// nothing else. An earlier revision of this file offered it as the proof
	// that the deletion IS clamp truncation. That proof was circular; the
	// experiment that is not is
	// TestLiftingTheAccumulatorClampRemovesTheDegradation.
	deletedUnclamped float64
	// realSpan is the physical time the segment took, for scale.
	realSpan float64
}

// runObservations segments the trace into maximal attacker runs and prices
// each one. A run whose following honest block falls outside the measured
// range is dropped rather than priced short.
func (tr *backdateTrace) runObservations(p *params.Params) []runObservation {
	maxSolve := p.TargetBlockSeconds * p.DifficultyClampFactor
	var out []runObservation
	n := len(tr.headers)
	i := tr.warmup + 1
	for i < n {
		if !tr.attacker[i] {
			i++
			continue
		}
		s := i
		for i < n && tr.attacker[i] {
			i++
		}
		e := i - 1 // last attacker block of the run
		if e+1 >= n {
			break // the trailing honest block is off the end of the run
		}
		obs := runObservation{length: e - s + 1}
		const noClamp = ^uint64(0) >> 1
		for j := s; j <= e+1; j++ {
			obs.deleted += clampSigned(tr.honestTime[j], tr.honestTime[j-1], maxSolve)
			obs.deleted -= clampSigned(tr.headers[j].Time, tr.headers[j-1].Time, maxSolve)
			obs.deletedUnclamped += clampSigned(tr.honestTime[j], tr.honestTime[j-1], noClamp)
			obs.deletedUnclamped -= clampSigned(tr.headers[j].Time, tr.headers[j-1].Time, noClamp)
			obs.realSpan += tr.realSolve[j]
		}
		out = append(out, obs)
	}
	return out
}

// quantile returns the q-quantile of xs by nearest rank. xs is sorted in
// place.
func quantile(xs []float64, q float64) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	sort.Float64s(xs)
	k := int(q * float64(len(xs)))
	if k >= len(xs) {
		k = len(xs) - 1
	}
	return xs[k]
}

func meanOf(xs []float64) float64 {
	if len(xs) == 0 {
		return math.NaN()
	}
	s := 0.0
	for _, x := range xs {
		s += x
	}
	return s / float64(len(xs))
}

func stddevOf(xs []float64) float64 {
	if len(xs) < 2 {
		return 0
	}
	m := meanOf(xs)
	s := 0.0
	for _, x := range xs {
		s += (x - m) * (x - m)
	}
	return math.Sqrt(s / float64(len(xs)-1))
}

// ---------------------------------------------------------------------------
// Cost control.
//
// The sweep is CPU-heavy: NextTarget walks a 90-header window with 256-bit
// arithmetic once per block, and the sweep is (shares × seeds × blocks) of
// those. It is a RECORDED MEASUREMENT, not a regression guard — the curve
// changes only when a genesis parameter changes, which is exactly the event
// that is not allowed to happen quietly — so it is gated out of `go test ./...`
// and therefore out of `make ci`. The always-on tests in this file are the
// cheap ones, and they are the ones that would catch a harness that has
// stopped measuring what it claims.
// ---------------------------------------------------------------------------

// sweepEnabled reports whether the recorded sweep should run, and at what
// size. ZCD_BACKDATE_SWEEP is the gate; ZCD_BACKDATE_SEEDS and
// ZCD_BACKDATE_BLOCKS resize it.
func sweepEnabled() bool { return os.Getenv("ZCD_BACKDATE_SWEEP") != "" }

func envInt(name string, def int) int {
	if v := os.Getenv(name); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return def
}

// sweepParallelism bounds the goroutines the sweep runs at once. This machine
// hosts several agents at a time, so the default is deliberately small and the
// sweep never sizes itself from NumCPU.
func sweepParallelism() int { return envInt("ZCD_BACKDATE_PAR", 4) }

// forEachBounded runs fn over [0,n) with at most sweepParallelism goroutines.
func forEachBounded(n int, fn func(i int)) {
	sem := make(chan struct{}, sweepParallelism())
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			fn(i)
		}(i)
	}
	wg.Wait()
}

// sweepShares is the grid the curve is measured on. It is dense between 30%
// and 45% because that is where the reported knee is, and a grid that is
// coarse exactly where the answer lives cannot locate it to better than its
// own spacing.
// sweepCell holds one grid point's per-seed results.
type sweepCell struct {
	medians  []float64
	p99s     []float64
	worst    []float64
	bumpFrac float64
}

var sweepShares = []float64{0.00, 0.20, 0.25, 0.30, 0.32, 0.34, 0.36, 0.38, 0.40, 0.42, 0.45, 0.50}

// TestBackdatingDegradationCurveSeedSweep is the audit's requested
// measurement: the median and p99 real block interval against attacker share,
// at many seeds per share instead of one, so that the shape of the curve can
// be separated from the noise of a single sample.
//
// It ASSERTS only what must be true of any run of this harness — the ordering
// of the curve at its ends, and the 0% control staying flat. The knee itself is
// REPORTED, with its spread, because the knee is an owner's input to a genesis
// decision and not a property this tree is allowed to pin.
func TestBackdatingDegradationCurveSeedSweep(t *testing.T) {
	if !sweepEnabled() {
		t.Skip("recorded measurement; set ZCD_BACKDATE_SWEEP=1 to run (see this file's header for why it is not in CI)")
	}
	p := spec.Mainnet()
	seeds := envInt("ZCD_BACKDATE_SEEDS", 24)
	blocks := envInt("ZCD_BACKDATE_BLOCKS", 30000)
	const warmup = 500

	cells := make([]sweepCell, len(sweepShares))

	for si, share := range sweepShares {
		medians := make([]float64, seeds)
		p99s := make([]float64, seeds)
		worst := make([]float64, seeds)
		bad := make([]int, seeds)
		bumps := make([]float64, seeds)
		forEachBounded(seeds, func(k int) {
			tr := simulateBackdate(p, share, blocks, warmup, int64(1000*si+k+1), func(int) float64 { return 1 })
			iv := tr.realIntervals()
			medians[k] = quantile(iv, 0.50)
			p99s[k] = quantile(iv, 0.99)
			worst[k] = tr.worstRatio
			bad[k] = tr.invalidTime
			bumps[k] = float64(tr.honestBumps) / float64(blocks)
		})
		cells[si].medians, cells[si].p99s, cells[si].worst = medians, p99s, worst
		if b := meanOf(bumps); b > 0.01 {
			t.Fatalf("share %.0f%%: %.2f%% of honest blocks could not post a truthful "+
				"timestamp and posted median+1 instead. At that rate the curve is reporting "+
				"the whole-second resolution of Header.Time, not the attacker", share*100, 100*b)
		}
		cells[si].bumpFrac = meanOf(bumps)
		for k, b := range bad {
			if b != 0 {
				t.Fatalf("share %.0f%% seed %d: %d headers would fail CheckMedianTime; the harness "+
					"is simulating an attacker the rule already rejects, so nothing it reports is "+
					"about the shipped rule", share*100, k, b)
			}
		}
	}

	t.Logf("backdating degradation curve, mainnet params, %d seeds x %d blocks, Poisson arrivals, "+
		"attacker dates every block it wins at MedianTime+1", seeds, blocks)
	t.Logf("%6s  %-22s  %-22s  %10s %8s", "share", "median interval (s)", "p99 interval (s)", "worst t/T0", "bumped")
	for si, share := range sweepShares {
		c := cells[si]
		mm, ms := meanOf(c.medians), stddevOf(c.medians)
		pm, ps := meanOf(c.p99s), stddevOf(c.p99s)
		lo, hi := append([]float64(nil), c.medians...), append([]float64(nil), c.medians...)
		t.Logf("%5.0f%%  %7.2f +- %-5.2f [%5.2f,%5.2f]  %7.1f +- %-6.1f        %10.3g %7.4f%%",
			share*100, mm, ms, quantile(lo, 0), quantile(hi, 0.999),
			pm, ps, meanOf(c.worst), 100*c.bumpFrac)
	}

	// Direction, declared before the numbers are read (PROTOCOL rule 22).
	// The 0% control must not move: it is the same honest Poisson chain the
	// package's existing control test drives, and if IT drifts with seed
	// beyond ordinary sampling noise then the harness is measuring itself
	// rather than the attacker.
	base := cells[0]
	baseMean, baseSD := meanOf(base.medians), stddevOf(base.medians)
	if baseSD > 0.05*baseMean {
		t.Fatalf("CONTROL FAILED: at 0%% attacker share the median interval varies by %.3f s "+
			"(%.1f%% of its %.2f s mean) across %d seeds. With no attacker the only input is "+
			"Poisson noise on %d blocks; this much seed dependence means the sweep is measuring "+
			"the harness", baseSD, 100*baseSD/baseMean, baseMean, seeds, blocks)
	}
	if math.Abs(baseMean-float64(p.TargetBlockSeconds)*math.Ln2) > 0.15*baseMean {
		t.Fatalf("CONTROL FAILED: at 0%% share the median real interval is %.2f s, but an "+
			"exponential with mean equal to the %d s goal has median goal*ln2 = %.2f s. The "+
			"honest baseline is not the honest baseline", baseMean, p.TargetBlockSeconds,
			float64(p.TargetBlockSeconds)*math.Ln2)
	}

	// The curve must be monotone at its ends: 50% must be worse than 0%. This
	// is the weakest true statement about the sweep, and it is asserted
	// instead of the knee on purpose.
	top := meanOf(cells[len(cells)-1].medians)
	if !(top > baseMean) {
		t.Fatalf("at 50%% share the median interval (%.2f s) is not above the 0%% baseline "+
			"(%.2f s); the attack does not reproduce at all and every other number in this "+
			"file is describing something else", top, baseMean)
	}

	// The knee, located per seed and then summarised, rather than located
	// once on the seed-averaged curve. Averaging first would hide exactly the
	// quantity asked for: how much the knee itself moves with the seed.
	for _, factor := range []float64{1.25, 1.50, 2.00} {
		thr := factor * baseMean
		knees := make([]float64, 0, seeds)
		for k := 0; k < seeds; k++ {
			if kn, ok := kneeForSeed(cells, k, thr); ok {
				knees = append(knees, kn)
			}
		}
		if len(knees) == 0 {
			t.Logf("knee at %.2fx baseline (%.1f s): not reached on the grid by any seed", factor, thr)
			continue
		}
		sort.Float64s(knees)
		t.Logf("knee at %.2fx baseline (%5.1f s): mean %.3f, sd %.3f, min %.2f, max %.2f, "+
			"reached by %d/%d seeds",
			factor, thr, meanOf(knees), stddevOf(knees), knees[0], knees[len(knees)-1],
			len(knees), seeds)
	}
}

// kneeForSeed returns the share, linearly interpolated on the measured grid,
// at which seed k's median interval first crosses thr. Interpolation is why
// the grid density above matters: without it the knee is quantised to the grid
// and its reported spread is an artefact of the spacing.
func kneeForSeed(cells []sweepCell, k int, thr float64) (float64, bool) {
	for i := 1; i < len(cells); i++ {
		prev, cur := cells[i-1].medians[k], cells[i].medians[k]
		if cur < thr {
			continue
		}
		if cur == prev {
			return sweepShares[i], true
		}
		f := (thr - prev) / (cur - prev)
		if f < 0 {
			f = 0
		}
		if f > 1 {
			f = 1
		}
		return sweepShares[i-1] + f*(sweepShares[i]-sweepShares[i-1]), true
	}
	return 0, false
}

// TestDeletedSolveTimeMassAgainstAttackerRunLength measures the mechanism the
// issue offers for the curve, directly, instead of inferring it from the curve.
//
// The claim under test: the signed symmetric clamp cancels a backdate
// pairwise against the next honest block, and that cancellation FAILS because
// attacker blocks arrive in runs — a run of k blocks gets only one compensating
// positive interval however large k is, so the mass the LWMA does not integrate
// grows with k rather than staying bounded.
//
// EXPECTED DIRECTION, stated before the run (PROTOCOL rule 22): the mean
// deleted mass of a maximal attacker run must INCREASE with the run's length.
// If it does not — if long runs delete no more than short ones — then the
// run-length explanation is wrong, whatever the interval curve does, and this
// test says so rather than passing quietly. A test that only reported the
// numbers could not tell "the mechanism reproduced" from "the mechanism was
// never exercised".
func TestDeletedSolveTimeMassAgainstAttackerRunLength(t *testing.T) {
	p := spec.Mainnet()
	seeds, blocks := 3, 6000
	if sweepEnabled() {
		seeds = envInt("ZCD_BACKDATE_SEEDS", 24)
		blocks = envInt("ZCD_BACKDATE_BLOCKS", 30000)
	}
	const warmup = 500
	shares := []float64{0.20, 0.30, 0.35, 0.40, 0.50}
	// superK is the run length the super-additivity ratio is taken at. Fixed,
	// and small enough to be well populated at every share in both the cheap
	// and the full configuration, so the number means the same thing in every
	// row of the table below.
	const superK = 3
	supers := map[float64]float64{}

	t.Logf("deleted solve-time mass, mainnet params, %d seeds x %d blocks per share", seeds, blocks)
	t.Logf("A run of k attacker blocks is priced together with the ONE honest block that follows")
	t.Logf("it, because that honest block is where the signed clamp's compensating positive interval lands.")
	t.Logf("mass/k is the per-attacker-block deletion: if clustering is what breaks the")
	t.Logf("cancellation, mass/k must RISE with k. If mass/k is flat in k, the deletion is")
	t.Logf("additive per attacker block and run length is not the mechanism.")

	for _, share := range shares {
		byLen := map[int][]float64{}
		var profiles []deletionProfile
		unclamped := 0
		var mu sync.Mutex
		forEachBounded(seeds, func(k int) {
			tr := simulateBackdate(p, share, blocks, warmup, int64(770000)+int64(share*100)*1000+int64(k),
				func(int) float64 { return 1 })
			obs := tr.runObservations(p)
			prof := tr.deletionProfile(p)
			mu.Lock()
			defer mu.Unlock()
			profiles = append(profiles, prof)
			for _, o := range obs {
				byLen[o.length] = append(byLen[o.length], o.deleted)
				if o.deletedUnclamped != 0 {
					unclamped++
				}
			}
		})

		lens := make([]int, 0, len(byLen))
		for l := range byLen {
			lens = append(lens, l)
		}
		sort.Ints(lens)

		// EXPECTED DIRECTION (PROTOCOL rule 22), asserted before anything is
		// reported: with the clamp removed the deletion must be EXACTLY zero
		// on every run, by telescoping between the honest blocks that bound
		// it. A non-zero count here means the segment boundaries are wrong
		// and every mass number in this file is measuring the boundary.
		if unclamped != 0 {
			t.Fatalf("share %.0f%%: %d attacker runs show non-zero deleted mass with the "+
				"±maxSolve clamp REMOVED. That sum telescopes to zero between the honest "+
				"blocks bounding the run, so a non-zero value is a segmentation bug, not a "+
				"finding", share*100, unclamped)
		}
		var lags, perBlock, negF, posF []float64
		for _, pr := range profiles {
			lags = append(lags, pr.meanLag)
			perBlock = append(perBlock, pr.perAttackerBlock)
			negF = append(negF, pr.negClampFrac)
			posF = append(posF, pr.posClampFrac)
		}
		t.Logf("--- share %.0f%%: %.2f s deleted per attacker block; mean backdate depth "+
			"(parent - median) %.1f s; transitions clamped at -480 s: %.3f, at +480 s: %.3f "+
			"[that the clamp is the MECHANISM is shown by "+
			"TestLiftingTheAccumulatorClampRemovesTheDegradation, not by the unclamped "+
			"difference below, which is zero by construction]",
			share*100, meanOf(perBlock), meanOf(lags), meanOf(negF), meanOf(posF))
		t.Logf("%6s %8s %14s %14s %14s", "k", "runs", "mean deleted", "sd", "mass/k")
		for _, l := range lens {
			if len(byLen[l]) < 20 {
				continue
			}
			t.Logf("%6d %8d %14.2f %14.2f %14.2f",
				l, len(byLen[l]), meanOf(byLen[l]), stddevOf(byLen[l]), meanOf(byLen[l])/float64(l))
		}
		if slope, intercept, ok := weightedFit(byLen); ok {
			t.Logf("       fit: deleted = %.2f*k %+.2f  (goal %d s). The INTERCEPT carries the "+
				"sign of the clustering effect, and it is NOT near zero at every share — it is "+
				"negative below the knee and positive above it.",
				slope, intercept, p.TargetBlockSeconds)
		}

		// The direction assertion, at the share the issue names as the knee.
		// The literal claim first: longer runs must delete more in total.
		var short, long int
		for _, l := range lens {
			if len(byLen[l]) >= 20 {
				if short == 0 {
					short = l
				}
				long = l
			}
		}
		if short == 0 || long == short {
			t.Fatalf("VACUOUS: only run lengths %v were observed with enough samples to compare at "+
				"share %.0f%% over %d blocks. The run-length mechanism cannot be tested by a run "+
				"that contains no runs", lens, share*100, blocks)
		}
		if ms, ml := meanOf(byLen[short]), meanOf(byLen[long]); !(ml > ms) {
			t.Fatalf("MECHANISM DID NOT REPRODUCE at %.0f%%: a run of %d attacker blocks deletes "+
				"%.2f s of solve-time mass, no more than a run of %d deletes (%.2f s). The "+
				"issue's explanation for the degradation curve is that deleted mass grows with "+
				"run length rather than cancelling pairwise; measured here, it does not",
				share*100, long, ml, short, ms)
		}

		// And the statistic that literal claim does not settle. Super-additivity
		// is what "the deleted mass grows with RUN LENGTH, not pairwise" has to
		// mean if it is to explain a knee: k blocks together must cost MORE PER
		// BLOCK than k blocks apart. At a fixed k, comparable across shares.
		super, ok := superAdditivityAt(byLen, superK)
		if !ok {
			t.Fatalf("VACUOUS at %.0f%%: fewer than 20 runs at k=1 or k=%d, so the "+
				"super-additivity ratio has nothing to compare", share*100, superK)
		}
		supers[share] = super
		t.Logf("       super-additivity (mass/k at k=%d)/(mass/k at k=1) = %.3f  "+
			"[1.0 = clustering buys the attacker nothing beyond the block count]", superK, super)
	}

	// The guard on this file's header, and it is evaluated at BOTH ends of the
	// share axis on purpose. An earlier revision checked the ratio only at 40%
	// — the single share where it crosses 1.0 — so it could not trip, and a
	// guard positioned where it cannot trip is not a guard.
	//
	// EXPECTED DIRECTIONS, declared before the run (PROTOCOL rule 22):
	//
	//   - at 20% share the ratio must be clearly ABOVE 1: below the knee,
	//     clustering genuinely does cost extra per block, and the header says
	//     so. If this drops to 1 the header's "sign change across the share
	//     axis" is not there and half the header is wrong.
	//   - at 40% share the ratio must be at or below 1: this is where the
	//     audit made its claim and where the header says it is refuted. If
	//     this rises, the refutation the whole PR rests on has stopped being
	//     true and the header has to be rewritten rather than the bound
	//     relaxed.
	//
	// The bounds are "clearly above" and "not above", not values anyone
	// derived. A recorded number checked by the search that produced it is an
	// echo, not a verification (PROTOCOL rule 21).
	//
	// The low end is only measurable at the full sweep size, and saying so is
	// part of the guard rather than an excuse for skipping it. At 20% share
	// the runs that reach k=3 are rare and the mass on each is a couple of
	// seconds against a standard deviation of twenty, so the cheap
	// configuration estimates that ratio to about 60% — it reads 0.84 there
	// against 1.9 at full size, and a bound placed on it would fire on noise.
	// The knee end is stable in both (0.93 cheap against 0.84 full) and is
	// therefore always evaluated.
	if !sweepEnabled() {
		// NOTE ON HOW LOUD THIS IS, because it is not very. t.Logf on a
		// PASSING test is suppressed by `go test` unless -v is given, so under
		// the plain `go test ./...` that `make ci` runs this line is not
		// printed at all. It is better than skipping in silence — the record
		// exists and -v shows it — but it is not a warning anyone will see,
		// and the honest statement is that the low-end guard is simply not
		// part of the always-on suite. What IS always-on is the knee-end
		// guard immediately below, which is the one the refutation rests on.
		t.Logf("low-end (20%%) super-additivity guard NOT EVALUATED at this sample size: the " +
			"k=3 estimate there carries ~60%% relative error. Run with ZCD_BACKDATE_SWEEP=1 to " +
			"evaluate it. The knee-end guard below ran. (This line is a t.Logf on a passing " +
			"test, so it is invisible without -v.)")
	} else if v, seen := supers[0.20]; !seen {
		t.Fatal("the 20% share was not measured, so the low end of the guard never ran")
	} else if v <= 1.3 {
		t.Fatalf("this file's header records that per-attacker-block deletion is STRONGLY "+
			"SUPER-ADDITIVE below the knee — clustering costs extra there — from a measured "+
			"ratio of 1.673 at 20%% share. It now measures %.3f. The sign change the header "+
			"describes is "+
			"not in the data any more, and the header has to be rewritten before anything "+
			"cites it", v)
	}
	if v, seen := supers[0.40]; !seen {
		t.Fatal("the 40% share was not measured, so the knee end of the guard never ran")
	} else if v > 1.2 {
		t.Fatalf("this file's header concludes that at the knee — 40%% share, where the audit "+
			"made its run-length claim — per-attacker-block deletion is NOT super-additive, "+
			"from a measured ratio near 0.84. It now measures %.3f. That refutation is what "+
			"this whole measurement rests on; rewrite the header rather than relax this bound", v)
	}
}

// deletionProfile summarises a whole trace rather than its runs: how much
// solve-time mass the rule failed to integrate per attacker block, how deep a
// backdate CheckMedianTime was offering, and how often either arm of the
// symmetric clamp actually bound. The clamp fractions are the discriminator —
// the cancellation is EXACT while nothing clamps, so a regime where neither
// arm binds cannot be losing mass to the clamp at all.
type deletionProfile struct {
	attackerBlocks   int
	totalDeleted     float64
	perAttackerBlock float64
	meanLag          float64
	negClampFrac     float64
	posClampFrac     float64
}

func (tr *backdateTrace) deletionProfile(p *params.Params) deletionProfile {
	maxSolve := p.TargetBlockSeconds * p.DifficultyClampFactor
	var prof deletionProfile
	var lags []float64
	transitions := 0
	for i := tr.warmup + 1; i < len(tr.headers); i++ {
		prof.totalDeleted += clampSigned(tr.honestTime[i], tr.honestTime[i-1], maxSolve)
		prof.totalDeleted -= clampSigned(tr.headers[i].Time, tr.headers[i-1].Time, maxSolve)
		transitions++
		now, prev := tr.headers[i].Time, tr.headers[i-1].Time
		if now >= prev {
			if now-prev >= maxSolve {
				prof.posClampFrac++
			}
		} else if prev-now >= maxSolve {
			prof.negClampFrac++
		}
		if tr.attacker[i] {
			prof.attackerBlocks++
			lags = append(lags, tr.medianLag[i])
		}
	}
	if transitions > 0 {
		prof.negClampFrac /= float64(transitions)
		prof.posClampFrac /= float64(transitions)
	}
	if prof.attackerBlocks > 0 {
		prof.perAttackerBlock = prof.totalDeleted / float64(prof.attackerBlocks)
		prof.meanLag = meanOf(lags)
	}
	return prof
}

// weightedFit fits mean(deleted) = slope*k + intercept over the run lengths
// with at least 20 samples, weighting each length by its sample count.
func weightedFit(byLen map[int][]float64) (slope, intercept float64, ok bool) {
	var sw, swx, swy, swxx, swxy float64
	n := 0
	for l, v := range byLen {
		if len(v) < 20 {
			continue
		}
		w := float64(len(v))
		x, y := float64(l), meanOf(v)
		sw += w
		swx += w * x
		swy += w * y
		swxx += w * x * x
		swxy += w * x * y
		n++
	}
	if n < 2 {
		return 0, 0, false
	}
	den := sw*swxx - swx*swx
	if den == 0 {
		return 0, 0, false
	}
	slope = (sw*swxy - swx*swy) / den
	intercept = (swy - slope*swx) / sw
	return slope, intercept, true
}

// TestZeroShareControlDeletesNoMass is a BOOKKEEPING control, and naming it
// that is the point: with no attacker the two series are the same series, so
// its zero is a statement about the accounting and the segment boundaries, not
// about the chain. It cannot fail for an interesting reason, which is exactly
// what makes it useful — anything that does move it is a defect in the
// instrument.
//
// The STATISTICAL baseline lives elsewhere and is a different claim: the 0%
// row of TestBackdatingDegradationCurveSeedSweep, which requires the honest
// median to sit near goal*ln2 and to vary by under 5% across seeds, and this
// package's TestHonestChainWithPoissonSolveTimesStaysBounded, which requires
// an honest Poisson chain never to reach MaxTarget. Do not read this test as
// either of those.
//
// EXPECTED DIRECTION: with no attacker, the attacked series and the honest
// series are the same series, so the deleted mass must be exactly zero and the
// run segmentation must find no runs. If either moves, the harness is
// generating a difference out of its own bookkeeping — a float/uint rounding
// path, an off-by-one in the segment boundary — and every non-zero number this
// file reports would inherit it.
func TestZeroShareControlDeletesNoMass(t *testing.T) {
	p := spec.Mainnet()
	const blocks = 4000
	const warmup = 500

	for _, seed := range []int64{1, 2, 3} {
		tr := simulateBackdate(p, 0, blocks, warmup, seed, func(int) float64 { return 1 })
		if tr.invalidTime != 0 {
			t.Fatalf("seed %d: an HONEST chain produced %d headers that fail CheckMedianTime",
				seed, tr.invalidTime)
		}
		if obs := tr.runObservations(p); len(obs) != 0 {
			t.Fatalf("seed %d: run segmentation found %d attacker runs on a chain with no "+
				"attacker; the segmentation, not the attack, is producing them", seed, len(obs))
		}
		maxSolve := p.TargetBlockSeconds * p.DifficultyClampFactor
		total := 0.0
		for i := warmup + 1; i <= blocks; i++ {
			total += clampSigned(tr.honestTime[i], tr.honestTime[i-1], maxSolve)
			total -= clampSigned(tr.headers[i].Time, tr.headers[i-1].Time, maxSolve)
		}
		if total != 0 {
			t.Fatalf("seed %d: %.6f s of solve-time mass went missing on a chain where every "+
				"timestamp is truthful. The deleted-mass accounting has a source of its own",
				seed, total)
		}
	}
}

// TestBackdatingUnderHashrateDepartureSweep re-runs the audit's second result
// — an attacker at a share well below the interval knee multiplying the time
// the chain needs to recover from a hashrate departure — at several departure
// sizes and several seeds, because the single departure size is the number
// most likely to decide the parameter.
//
// Recovery is measured on the EXPECTED interval implied by the target and the
// surviving hashrate, not on realised intervals: the expected interval is a
// deterministic function of the chain's own state, so "recovered" is a
// statement about the controller rather than about whether the next coin flip
// happened to be short.
//
// EXPECTED DIRECTION: at every departure size, an attacker present must not
// make recovery FASTER. If it does, the harness has the sign of the effect
// backwards.
func TestBackdatingUnderHashrateDepartureSweep(t *testing.T) {
	if !sweepEnabled() {
		t.Skip("recorded measurement; set ZCD_BACKDATE_SWEEP=1 to run")
	}
	p := spec.Mainnet()
	seeds := envInt("ZCD_BACKDATE_SEEDS", 24)
	const warmup = 1000
	const blocks = 12000
	const departAt = 2000
	const share = 0.34

	t.Logf("recovery from a hashrate departure, mainnet params, %d seeds, attacker share %.0f%%, "+
		"departure at block %d, recovery = expected interval back within 1.1x goal", seeds, share*100, departAt)
	t.Logf("%4s %28s %28s %8s", "K", "no attacker (h)", "attacker at 34% (h)", "ratio")

	for _, K := range []float64{3, 10, 30, 100} {
		hr := func(i int) float64 {
			if i <= departAt {
				return 1
			}
			return 1 / K
		}
		clean := make([]float64, seeds)
		dirty := make([]float64, seeds)
		cleanOK := make([]bool, seeds)
		dirtyOK := make([]bool, seeds)
		forEachBounded(seeds, func(k int) {
			seed := int64(4200000) + int64(K)*1000 + int64(k)
			a := simulateBackdate(p, 0, blocks, warmup, seed, hr)
			clean[k], cleanOK[k] = recoveryHours(a, p, departAt, K)
			b := simulateBackdate(p, share, blocks, warmup, seed, hr)
			dirty[k], dirtyOK[k] = recoveryHours(b, p, departAt, K)
		})
		nc, nd := 0, 0
		var cs, ds []float64
		for k := 0; k < seeds; k++ {
			if cleanOK[k] {
				cs = append(cs, clean[k])
			} else {
				nc++
			}
			if dirtyOK[k] {
				ds = append(ds, dirty[k])
			} else {
				nd++
			}
		}
		if len(cs) == 0 || len(ds) == 0 {
			t.Fatalf("K=%.0f: %d/%d honest and %d/%d attacked runs never recovered within %d "+
				"blocks; the measurement has no baseline to report a ratio against",
				K, nc, seeds, nd, seeds, blocks-departAt)
		}
		cm, dm := meanOf(cs), meanOf(ds)
		t.Logf("%4.0f %14.2f +- %-5.2f (%2d/%2d) %14.2f +- %-5.2f (%2d/%2d) %8.2f",
			K, cm, stddevOf(cs), len(cs), seeds, dm, stddevOf(ds), len(ds), seeds, dm/cm)
		if dm < cm {
			t.Fatalf("K=%.0f: the attacked chain recovered FASTER (%.2f h) than the honest one "+
				"(%.2f h). Backdating cannot help the controller find a harder target; the sign "+
				"of the measurement is wrong", K, dm, cm)
		}
	}
}

// recoveryHours returns the real hours between the departure and the first
// block whose target implies an expected interval back within 1.1x the goal,
// and whether that happened at all within the run.
func recoveryHours(tr *backdateTrace, p *params.Params, departAt int, K float64) (float64, bool) {
	goal := float64(p.TargetBlockSeconds)
	elapsed := 0.0
	for i := departAt + 1; i < len(tr.realSolve); i++ {
		elapsed += tr.realSolve[i]
		expected := goal * ratioGenesisOver(tr.headers[i].Target, p) * K
		if expected <= 1.1*goal {
			return elapsed / 3600, true
		}
	}
	return 0, false
}

// superAdditivityAt returns (mass/k at k=kFix) / (mass/k at k=1): how much more
// an attacker block costs the chain when it arrives inside a run of kFix than
// when it arrives alone. 1.0 is exact additivity — clustering worth nothing.
//
// A note on what a probe of this statistic can and cannot show. Forcing kFix
// to 1 makes the ratio 1.000 BY DEFINITION, so a probe that does it proves the
// low-end bound is REACHABLE — it is wired up, it is evaluated, it fails when
// the number crosses — and it proves nothing about whether the bound responds
// to the chain's actual behaviour. Those are different claims and the second
// one is not available cheaply: making the real 20% ratio move requires
// changing the rule or the parameters, which the parameter pin already covers
// from the other side.
//
// A FIXED k is the point. An earlier revision of this file compared k=1 against
// "the longest well-populated run length", which is a function of how many
// blocks were simulated (k=6 in the cheap configuration, k=10 in the full one)
// and therefore is not comparable across shares or across run sizes. A number
// whose definition moves with the sample cannot pin anything.
func superAdditivityAt(byLen map[int][]float64, kFix int) (float64, bool) {
	one, many := byLen[1], byLen[kFix]
	if len(one) < 20 || len(many) < 20 {
		return 0, false
	}
	base := meanOf(one)
	if base <= 0 {
		return 0, false
	}
	return (meanOf(many) / float64(kFix)) / base, true
}

// TestTheRecordedCurveNamesTheParametersItWasMeasuredAt is four comparisons and
// costs microseconds, and it is the guard this file most needed.
//
// Everything recorded in this file's header — the curve, the knee, the deleted
// mass, the recovery ratios — is a measurement at ONE point in parameter space.
// A move in exactly these four values is also the only event that moves the
// curve, which is to say: the single change that invalidates every number above
// is the change this file exists to inform. Without this test that change lands
// with every test in the tree still green and the header quietly describing a
// network that no longer exists.
//
// This pins the parameters the RECORD was taken at. It is not a vote on what
// they should be — params.Validate and the spec corpus own that — and it must
// never be "fixed" by editing the constants here. If it fails, the header is
// stale and the sweep has to be re-run.
func TestTheRecordedCurveNamesTheParametersItWasMeasuredAt(t *testing.T) {
	p := spec.Mainnet()
	for _, c := range []struct {
		name      string
		got, want uint64
	}{
		{"median_time_blocks", uint64(p.MedianTimeBlocks), 11},
		{"difficulty_clamp_factor", p.DifficultyClampFactor, 16},
		{"target_block_seconds", p.TargetBlockSeconds, 30},
		{"difficulty_window", p.DifficultyWindow, 90},
	} {
		if c.got != c.want {
			t.Fatalf("THE HEADER WAS MEASURED AT OTHER PARAMETERS: %s is now %d, and every "+
				"number recorded at the top of this file was measured at %d. The curve, the "+
				"knee, the deleted-mass table and the recovery ratios are all statements about "+
				"the old value and none of them carries over. Re-run the sweep "+
				"(ZCD_BACKDATE_SWEEP=1) and rewrite the header before anything cites it; do "+
				"NOT update the constant in this test to match", c.name, c.got, c.want)
		}
	}
}

// TestLiftingTheAccumulatorClampRemovesTheDegradation is the experiment that
// replaces this file's first attempt at proving what the deletion is made of.
//
// That first attempt observed that with the ±maxSolve clamp removed, deleted
// mass is identically zero on every run. It is — and it is an IDENTITY OF THE
// BOOKKEEPING, not a measurement: honest blocks declare their honest time by
// construction here, so a segment bounded by two honest blocks telescopes to
// zero whatever happened inside it, at any run length, under any attacker. The
// harness could not have produced another answer. It is also UNWEIGHTED, while
// NextTarget accumulates solve*i over the window. So it proved nothing about
// the rule, and it is kept below only as the segmentation control it really is.
//
// This does prove it. The clamp is widened to a value it can never reach — no
// mutation of pow.go, the real NextTarget, the real controller, the real
// attacker, only a local copy of the parameters — and the curve is
// re-measured. If clamp truncation is what the degradation is made of, the
// degradation must disappear.
//
// EXPECTED DIRECTION (PROTOCOL rule 22), declared before the run:
//
//   - at 40% and 50% share the median real interval must collapse back toward
//     the honest baseline. If it does not, clamp truncation is NOT the
//     mechanism and this file's header is wrong;
//   - the 0% row must not move, because an honest chain never produces an
//     interval near ±480 s and so never touches the arm being widened;
//   - and the worst target/genesis ratio MUST BLOW UP, because removing the
//     clamp removes the symmetric protection against the mirror attack. A run
//     where it
//     does not is a run where the widened clamp was never in force, and the
//     interval comparison beside it would be measuring nothing.
//
// That third expectation is why this test is NOT an argument for a larger
// difficulty_clamp_factor, and it is asserted rather than merely noted: the
// clamp buys the freeze direction off against the runaway direction, and a
// reader who takes only the first two rows away from here would be reading an
// argument this file does not make.
func TestLiftingTheAccumulatorClampRemovesTheDegradation(t *testing.T) {
	seeds, blocks := 3, 8000
	if sweepEnabled() {
		seeds = envInt("ZCD_BACKDATE_SEEDS", 24)
		blocks = envInt("ZCD_BACKDATE_BLOCKS", 30000)
	}
	const warmup = 500

	// How much the runaway must have grown by the end of the run. It is
	// size-dependent because the runaway is CUMULATIVE — the unclamped
	// accumulator walks the target up over thousands of blocks — while the
	// interval collapse beside it is immediate. A short run catches the
	// direction; only the full-length run catches the magnitude the header
	// records.
	runawayFactor := 2.0
	if sweepEnabled() {
		runawayFactor = 50.0
	}

	shipped := spec.Mainnet()
	lifted := *spec.Mainnet()
	// Unreachable rather than absent: maxSolve becomes goal*this = 3e7 s, so
	// no interval this simulation can produce is ever truncated.
	//
	// DIFFICULTYCLAMPFACTOR HAS TWO USES IN NextTarget AND THIS MOVES BOTH.
	// An earlier revision of this comment claimed "every other line of
	// NextTarget runs exactly as shipped", and that was false: besides
	// maxSolve (pow.go, `maxSolve := goal * p.DifficultyClampFactor`) the
	// same value is the PER-STEP TARGET CLAMP a few dozen lines later
	// (`upper := last.MulDiv64(p.DifficultyClampFactor, 1)` and its `lower`
	// mirror), which bounds how far one block's target may move from its
	// parent's. Widening the factor widens that too.
	//
	// The two were decoupled by mutation and the conclusion survives,
	// attributed to the right variable. At 40% share:
	//
	//   - maxSolve lifted alone, per-step clamp fully intact:
	//     29.64 s -> 20.39 s. THE ENTIRE COLLAPSE.
	//   - per-step clamp lifted alone, maxSolve pinned at 480 s:
	//     30.07 s -> 30.07 s, which trips this test's own
	//     MECHANISM NOT DEMONSTRATED.
	//
	// So maxSolve is the whole operative variable for the interval collapse,
	// and the controller path either side of it is genuinely production. That
	// is a stronger claim than the one the earlier comment made, and unlike
	// that one it is measured.
	//
	// THE RUNAWAY COLUMN IS THE ONE THAT MIXES THEM, and it is a column this
	// test asserts on, so it has to say so: the per-step clamp ALONE moves the
	// worst target/genesis ratio from 2.343 to 3.462 at 40% share. The 687
	// and 4096 recorded in this file's header are therefore both effects
	// together, not maxSolve alone. The assertion below still means what it
	// says — it demands lw > 50*sw under the gate, and the confound alone
	// yields lw/sw = 1.48, so it cannot be satisfied by the confound — but a
	// reader attributing all of 687 to maxSolve would be wrong.
	lifted.DifficultyClampFactor = 1_000_000

	t.Logf("median real interval and worst target/genesis, %d seeds x %d blocks, "+
		"shipped clamp (+-%d s) against a clamp lifted out of reach (+-%d s)",
		seeds, blocks, shipped.TargetBlockSeconds*shipped.DifficultyClampFactor,
		lifted.TargetBlockSeconds*lifted.DifficultyClampFactor)
	t.Logf("%6s %11s %11s | %11s %11s", "share", "median", "median'", "worst t/T0", "worst t/T0'")

	for _, share := range []float64{0.00, 0.40, 0.50} {
		shipMed := make([]float64, seeds)
		liftMed := make([]float64, seeds)
		shipWorst := make([]float64, seeds)
		liftWorst := make([]float64, seeds)
		forEachBounded(seeds, func(k int) {
			seed := int64(9100000) + int64(share*100)*1000 + int64(k)
			a := simulateBackdate(shipped, share, blocks, warmup, seed, func(int) float64 { return 1 })
			b := simulateBackdate(&lifted, share, blocks, warmup, seed, func(int) float64 { return 1 })
			shipMed[k], liftMed[k] = quantile(a.realIntervals(), 0.50), quantile(b.realIntervals(), 0.50)
			shipWorst[k], liftWorst[k] = a.worstRatio, b.worstRatio
		})
		sm, lm := meanOf(shipMed), meanOf(liftMed)
		sw, lw := meanOf(shipWorst), meanOf(liftWorst)
		t.Logf("%5.0f%% %11.2f %11.2f | %11.4g %11.4g", share*100, sm, lm, sw, lw)

		if share == 0 {
			// This control asserts on the MEDIAN and not on the target ratio,
			// and the difference is not an oversight — it is where the
			// confound named above first showed itself.
			//
			// With no attacker, maxSolve provably cannot bind: an honest chain
			// never produces an interval near ±480 s. So the median must not
			// move, and it does not. But the worst target/genesis ratio in the
			// row logged above DOES move at 0% share, 2.331 to 4.168, and the
			// only thing that can move it there is the OTHER use of
			// DifficultyClampFactor — the per-step target clamp. The
			// instrument saw the confound before anyone was looking for it,
			// and reported it in the one column nothing was watching. Worth
			// leaving written down: the next reader to widen a parameter "just
			// for the mechanism" should check every use of it, and the cheapest
			// place that shows up is the control where the intended effect is
			// impossible.
			if math.Abs(lm-sm) > 0.10*sm {
				t.Fatalf("CONTROL FAILED: with no attacker, lifting the clamp moved the median "+
					"interval from %.2f s to %.2f s. An honest chain never produces an interval "+
					"near +-%d s, so maxSolve cannot bind here and the median cannot move. A "+
					"move means the lift is reaching the interval through something other than "+
					"maxSolve",
					sm, lm, shipped.TargetBlockSeconds*shipped.DifficultyClampFactor)
			}
			continue
		}
		// The whole claim, in one comparison: the degradation the shipped
		// clamp shows must be gone once the clamp cannot truncate.
		excessShipped := sm - baselineMedian(shipped)
		excessLifted := lm - baselineMedian(shipped)
		if !(excessLifted < 0.25*excessShipped) {
			t.Fatalf("MECHANISM NOT DEMONSTRATED at %.0f%% share: the shipped clamp gives a "+
				"median of %.2f s (%.2f s above the honest baseline) and lifting the clamp out "+
				"of reach still gives %.2f s (%.2f s above it). If clamp truncation were what "+
				"the degradation is made of, removing the truncation would remove the "+
				"degradation. This file's header says it is; it would be wrong",
				share*100, sm, excessShipped, lm, excessLifted)
		}
		if !(lw > runawayFactor*sw) {
			t.Fatalf("at %.0f%% share the worst target/genesis ratio only went %.4g -> %.4g when "+
				"the clamp was lifted. Removing the symmetric clamp must expose the mirror "+
				"runaway; a ratio that stays put means the lifted parameter never came into "+
				"force and the interval comparison above is measuring nothing",
				share*100, sw, lw)
		}
	}
}

// baselineMedian is the median of an exponential whose mean is the goal:
// goal*ln2, the honest chain's median real interval when the controller is on
// target. Used as the zero of "degradation" so the comparison above is against
// the chain's own design point rather than against a second simulated run
// whose noise would be added to the answer.
func baselineMedian(p *params.Params) float64 {
	return float64(p.TargetBlockSeconds) * math.Ln2
}

// ---------------------------------------------------------------------------
// WHY THE CLUSTERING EFFECT CHANGES SIGN, which the table in this file's header
// reports and which nothing so far explained.
//
// The sign change is not a fact about attacker share. It is a fact about
// maxSolve measured in units of the backdate depth, and share enters only
// because depth grows with share. Same clamp, deeper backdate: sub-additive.
// Same depth, tighter clamp: sub-additive. The two are the same knob.
//
// THE ACCOUNT. Segment a maximal run of k attacker blocks plus the one honest
// block after it, as runObservations does. Inside the run every declared step
// is a median advance, which is non-negative because MedianTime is
// non-decreasing (core/pow/median_bound_test.go proves that), and tiny, so the
// clamp never touches it. Only two transitions can be truncated:
//
//	D = the backdate depth at the run's first block: the parent's declared time
//	    minus median+1. Truncating it at -c makes the ATTACKED series look
//	    like MORE time elapsed, so it REDUCES the deletion by (D-c)+.
//	G = the climb the following honest block owes: real time now, minus the
//	    attacker's last declared time. Truncating it at +c makes the attacked
//	    series look like LESS time elapsed, so it INCREASES the deletion by
//	    (G-c)+. And G = D + realSpan, because the honest series telescopes.
//
// So deleted(k) = (D + S - c)+ - (D - c)+ where S is the segment's real span,
// and taking the expectation over the depth distribution turns that into
//
//	deleted(k) = integral from 0 to S(k) of P(D > c - u) du
//
// which is CONVEX in S with deleted(0) = 0, because the integrand rises with u
// for any survival function whatsoever. Two consequences, and they are the two
// this test asserts:
//
//  1. The clustering ratio (mass/k at k=3)/(mass/k at k=1) is g(4I)/(3*g(2I))
//     for a convex g through the origin, taking S(k) = (k+1)*I. Convexity gives
//     g(4I) >= 2*g(2I), so THE RATIO CANNOT GO BELOW 2/3 — for any share, any
//     clamp, any depth distribution. It approaches 2/3 exactly when g is
//     locally linear, which is when the depth distribution has most of its
//     mass already past the clamp.
//  2. It crosses 1.0 where the local elasticity of g is log2(3) = 1.585, which
//     is a statement about the shape of the depth distribution NEAR THE CLAMP
//     and about nothing else. Move the clamp and the crossing moves with it.
//
// MEASURED. Both tables below are PRINTED BY THIS TEST at its full size, so
// they are re-derivable rather than transcribed (LAUNCH §10). 8 seeds x 20,000
// blocks, mainnet. Re-pricing the SAME traces at a different accounting clamp c
// — which holds the chain fixed and moves only the truncation threshold, so the
// confound named on TestLiftingTheAccumulatorClampRemovesTheDegradation cannot
// enter:
//
//	share      c=120   c=240   c=480   c=960  | mean depth D
//	 20%       0.752   0.973       -       -  |   189.5
//	 30%       0.725   0.861   1.281       -  |   231.8
//	 40%       0.711   0.764   0.865   0.968  |   442.2
//	 50%       0.695   0.720   0.750   0.808  |  2024.3
//
// A DASH IS A CELL WHOSE RATIO DID NOT REPRODUCE ACROSS SEEDS, and the bar is
// the estimate's own across-seed spread rather than any threshold on the value.
// It matters, because the cells that fail it are exactly the ones a reader
// would most want to quote: at 20% share and c=480 the ratio read 1.57, 2.14
// and 2.82 on three configurations of this same measurement, while every cell
// reported above reproduced to about ±0.02. The direction there is not in
// doubt — every one of those readings is far above 1 — but the value is not a
// measurement and this test declines to print one.
//
// The hinge identity above reproduces the measured per-run deletion to a
// relative error of 0.0000 at 20% and 30% and 0.016 at 40%. At 50% it degrades
// badly and unstably — 0.14 to 0.58 across seed sets — and the reason is in the
// model rather than in the data: at 50% the mean real interval is a few hundred
// seconds, so the HONEST series starts hitting +480 s too and the account
// above, which assumes only the two named transitions truncate, stops being
// complete. The test therefore asserts the identity only at 40% and below, and
// the 50% row is printed rather than checked.
//
// AND THE SAME MOVE ON THE REAL CHAIN, changing difficulty_clamp_factor itself.
// This arm is confounded — that value is also NextTarget's per-step target
// clamp — and it is run anyway, because the clean arm above is an accounting
// counterfactual and this one is a chain. They have to agree in DIRECTION or
// the clean arm is measuring the bookkeeping:
//
//	clamp_factor    20%     30%     40%     50%
//	  8 (240 s)   0.765   0.734   0.701   0.685
//	 16 (480 s)       -       -   0.878   0.738
//	 32 (960 s)       -       -       -   0.960
//
// The reproducible column is 50%, and it rises 0.685 -> 0.738 -> 0.960 as the
// factor doubles twice: the crossing moves with the clamp on a real chain, in
// the same direction the accounting arm gives. The dashes have the same cause
// as above and thin out toward the top right, because a wider clamp deletes
// less and a lower share produces fewer long runs.
//
// SO THE SIGN CHANGE IS THE CROSSING OF c AGAINST D, at a c/D somewhere between
// 1.1 and 2.1 on the grid above — a finer share grid puts it at about 1.7 —
// and normalising the whole table by c/D collapses it onto one curve to within
// about ±0.05 over a decade of c and a 2.5x range of share. The residual spread
// is the SHAPE of the depth distribution, which its mean does not capture, and
// this file does not claim the collapse is exact.
//
// WHY THIS IS THE JOINT KEYING, AND ON WHICH TWO PARAMETERS. D is set by how
// far behind the parent the median sits, which is about half a
// median_time_blocks window of real intervals; c is
// target_block_seconds x difficulty_clamp_factor. Both scale with the goal, so
// c/D does NOT scale with it — which predicts that this crossing sits at the
// same SHARE on devnet as on mainnet, unlike the goal/FTL threshold, which
// moved by a factor of six between the two. That prediction is derived here and
// is NOT measured; anyone who needs it should run it rather than cite it.
// ---------------------------------------------------------------------------

// hingeObservation is one maximal attacker run priced at several notional
// accounting clamps at once, together with the two quantities the hinge account
// says decide the price.
type hingeObservation struct {
	length   int
	depth    float64 // D: the parent's declared time - the run's first declared time
	gap      float64 // G: the following honest block's climb back to real time
	realSpan float64
	deleted  map[uint64]float64
}

// hingeObservations is runObservations with the clamp made a free parameter.
// The trace it reads was produced under the SHIPPED clamp; only the accounting
// threshold moves. That is deliberate: it separates "how hard does the
// truncation cut" from "what chain does that truncation produce", which
// changing DifficultyClampFactor cannot do.
func (tr *backdateTrace) hingeObservations(clamps []uint64) []hingeObservation {
	var out []hingeObservation
	n := len(tr.headers)
	i := tr.warmup + 1
	for i < n {
		if !tr.attacker[i] {
			i++
			continue
		}
		s := i
		for i < n && tr.attacker[i] {
			i++
		}
		e := i - 1
		if e+1 >= n {
			break
		}
		o := hingeObservation{length: e - s + 1, deleted: map[uint64]float64{}}
		o.depth = float64(tr.headers[s-1].Time) - float64(tr.headers[s].Time)
		o.gap = float64(tr.headers[e+1].Time) - float64(tr.headers[e].Time)
		for j := s; j <= e+1; j++ {
			o.realSpan += tr.realSolve[j]
		}
		for _, c := range clamps {
			var d float64
			for j := s; j <= e+1; j++ {
				d += clampSigned(tr.honestTime[j], tr.honestTime[j-1], c)
				d -= clampSigned(tr.headers[j].Time, tr.headers[j-1].Time, c)
			}
			o.deleted[c] = d
		}
		out = append(out, o)
	}
	return out
}

func positivePart(x float64) float64 {
	if x > 0 {
		return x
	}
	return 0
}

// TestTheClusteringSignChangeIsTheClampOverTheBackdateDepth.
//
// EXPECTED DIRECTIONS, declared before the run (PROTOCOL rule 22), and each one
// is something this harness could easily have contradicted:
//
//  1. THE HINGE IDENTITY. Per run, deleted must equal (G-c)+ - (D-c)+ to within
//     a few percent at shares where the honest series itself does not clamp.
//     The harness computes `deleted` by walking every transition of the segment
//     through clampSigned; nothing makes that agree with a two-term expression
//     built from the run's endpoints. If it disagrees, the account above is
//     wrong and everything below it is decoration.
//
//  2. MONOTONICITY IN THE CLAMP. At a fixed share, re-pricing the same runs at
//     a larger accounting clamp must give a LARGER ratio. If the ratio is flat
//     in c, the sign change is not about the clamp at all and this file's
//     header attributes it to the wrong thing.
//
//  3. THE 2/3 FLOOR. The ratio must not fall below 2/3 anywhere the k=1 mean is
//     large enough to be a measurement. That floor is derived from convexity
//     alone, so a violation is a refutation of the derivation rather than a
//     surprising data point — and it is stated as a floor on the RATIO rather
//     than as the maximum damage clustering can do, because the super-additive
//     side has no bound from this argument at all (PROTOCOL rule 21).
//
//  4. THE SAME DIRECTION ON A REAL CHAIN. Re-pricing is an accounting
//     counterfactual: it asks what a different clamp would have charged for the
//     chain the shipped clamp produced. So the second arm builds the chain at a
//     different difficulty_clamp_factor and requires the ratio to move the same
//     way. If the two arms disagree, the clean one is measuring the bookkeeping
//     rather than the rule.
func TestTheClusteringSignChangeIsTheClampOverTheBackdateDepth(t *testing.T) {
	p := spec.Mainnet()
	seeds, blocks := 3, 8000
	if sweepEnabled() {
		seeds = envInt("ZCD_BACKDATE_SEEDS", 8)
		blocks = envInt("ZCD_BACKDATE_BLOCKS", 20000)
	}
	const warmup = 500
	const superK = 3

	// The shipped clamp is the goal times the clamp factor, derived rather than
	// typed: this test is about c as a free variable, and a hard 480 here would
	// silently stop tracking maxSolve the day either parameter moves — the
	// hinge identity would then be checked at a threshold the chain is not
	// using, which is the one way this measurement can be wrong and still pass.
	shipped := p.TargetBlockSeconds * p.DifficultyClampFactor
	clamps := []uint64{shipped / 4, shipped / 2, shipped, shipped * 2}
	shares := []float64{0.20, 0.30, 0.40, 0.50}

	t.Logf("clustering ratio (mass/k at k=%d)/(mass/k at k=1), the same traces re-priced at "+
		"several accounting clamps, %d seeds x %d blocks", superK, seeds, blocks)
	t.Logf("a dash is a cell whose ratio did not reproduce across seeds to %.0f%%; it is not "+
		"reported and nothing is asserted on it", 100*maxCellSpread)
	t.Logf("%6s %9s %9s %9s %9s %9s %12s", "share",
		fmt.Sprintf("c=%d", clamps[0]), fmt.Sprintf("c=%d", clamps[1]),
		fmt.Sprintf("c=%d*", clamps[2]), fmt.Sprintf("c=%d", clamps[3]),
		"mean D", "hinge rel.err")
	t.Logf("* is the shipped maxSolve, target_block_seconds x difficulty_clamp_factor = %d s",
		shipped)

	worstFloor := math.Inf(1)
	var worstFloorWhere string
	monotoneChecks := 0

	for _, share := range shares {
		// Per seed rather than pooled: the ratio's uncertainty is what decides
		// whether a cell is a measurement, and a pooled mean cannot report it.
		perSeed := make([]map[uint64]map[int][]float64, seeds)
		depths := make([][]float64, seeds)
		hingeErr := make([]float64, seeds)
		actualAbs := make([]float64, seeds)
		runs := make([]int, seeds)
		forEachBounded(seeds, func(k int) {
			tr := simulateBackdate(p, share, blocks, warmup,
				int64(4970000)+int64(share*100)*1000+int64(k), func(int) float64 { return 1 })
			obs := tr.hingeObservations(clamps)
			byLenC := map[uint64]map[int][]float64{}
			for _, c := range clamps {
				byLenC[c] = map[int][]float64{}
			}
			for _, o := range obs {
				for _, c := range clamps {
					byLenC[c][o.length] = append(byLenC[c][o.length], o.deleted[c])
				}
				depths[k] = append(depths[k], o.depth)
				c := float64(shipped)
				model := positivePart(o.gap-c) - positivePart(o.depth-c)
				hingeErr[k] += math.Abs(model - o.deleted[shipped])
				actualAbs[k] += math.Abs(o.deleted[shipped])
				runs[k]++
			}
			perSeed[k] = byLenC
		})

		var totalRuns int
		var he, aa float64
		var allDepths []float64
		for k := 0; k < seeds; k++ {
			totalRuns += runs[k]
			he += hingeErr[k]
			aa += actualAbs[k]
			allDepths = append(allDepths, depths[k]...)
		}
		if totalRuns == 0 {
			t.Fatalf("VACUOUS at %.0f%%: no attacker run was observed at all", share*100)
		}
		relErr := he / (aa + 1e-12)

		ratios := map[uint64]float64{}
		cells := ""
		for _, c := range clamps {
			per := make([]map[int][]float64, seeds)
			for k := 0; k < seeds; k++ {
				per[k] = perSeed[k][c]
			}
			r, spread, ok := reproducibleRatio(per, superK)
			if !ok {
				cells += fmt.Sprintf(" %9s", "-")
				continue
			}
			ratios[c] = r
			cells += fmt.Sprintf(" %9.3f", r)
			if r < worstFloor {
				worstFloor = r
				worstFloorWhere = fmt.Sprintf("share %.0f%%, c=%d, across-seed spread %.1f%%",
					share*100, c, 100*spread)
			}
		}
		t.Logf("%5.0f%%%s %9.1f %12.4f", share*100, cells, meanOf(allDepths), relErr)

		// (1) The hinge identity. Asserted where the account is complete: at
		// 50% the honest series clamps too and the two-term model is knowingly
		// incomplete, which the header states.
		if share <= 0.40 && relErr > 0.05 {
			t.Fatalf("THE HINGE ACCOUNT DOES NOT REPRODUCE at %.0f%% share: (G-%d)+ - "+
				"(D-%d)+ differs from the measured per-run deletion by %.1f%% of its own "+
				"magnitude over %d runs. This file's explanation of the sign change is "+
				"built on that identity; rewrite the explanation rather than relax this",
				share*100, shipped, shipped, relErr*100, totalRuns)
		}

		// (2) Monotonicity in the accounting clamp, over the adjacent pairs
		// that were both measurable.
		for i := 1; i < len(clamps); i++ {
			lo, hi := clamps[i-1], clamps[i]
			a, aok := ratios[lo]
			b, bok := ratios[hi]
			if !aok || !bok {
				continue
			}
			monotoneChecks++
			if b < a-0.02 {
				t.Fatalf("at %.0f%% share the clustering ratio FELL from %.3f at a %d s "+
					"accounting clamp to %.3f at %d s. The sign change is attributed here "+
					"to the clamp measured against the backdate depth, which requires the "+
					"ratio to rise with the clamp; it did not", share*100, a, lo, b, hi)
			}
		}
	}

	if monotoneChecks < 4 {
		t.Fatalf("VACUOUS: only %d adjacent clamp pairs reproduced across seeds, so the "+
			"monotonicity direction was barely tested. Raise the sample size rather than "+
			"trust this pass", monotoneChecks)
	}
	// (3) The derived floor.
	if worstFloor < 2.0/3.0 {
		t.Fatalf("the clustering ratio reached %.4f at %s, below the 2/3 floor this file "+
			"derives from the convexity of the deletion in the segment's real span. A "+
			"violation refutes the derivation, not the data: either S(k) is not affine in "+
			"k here, or the depth at a run's start is correlated with that run's length, "+
			"and the header has to say which",
			worstFloor, worstFloorWhere)
	}
	t.Logf("lowest ratio over every reproducible cell: %.4f at %s (derived floor 2/3 = %.4f)",
		worstFloor, worstFloorWhere, 2.0/3.0)

	// ---- Arm two: the same move, on a chain built at that clamp factor. ----
	//
	// EXPECTED DIRECTION: at every share where all three factors reproduce, the
	// ratio must RISE with the clamp factor, exactly as it does when only the
	// accounting threshold moves. That is expectation (4). The share is chosen
	// by which column reproduces rather than fixed in advance, because a fixed
	// column that happens not to reproduce would silently evaluate nothing —
	// and a check that cannot run is not a check (PROTOCOL rule 26).
	t.Logf("the same comparison on chains BUILT at each factor (confounded by the per-step " +
		"target clamp, and run anyway because the arm above is an accounting counterfactual)")
	t.Logf("%12s %9s %9s %9s %9s", "clamp_factor", "20%", "30%", "40%", "50%")
	factors := []uint64{8, 16, 32}
	byFactor := map[uint64]map[float64]float64{}
	for _, cf := range factors {
		local := *spec.Mainnet()
		local.DifficultyClampFactor = cf
		byFactor[cf] = map[float64]float64{}
		cells := ""
		for _, share := range shares {
			per := make([]map[int][]float64, seeds)
			forEachBounded(seeds, func(k int) {
				tr := simulateBackdate(&local, share, blocks, warmup,
					int64(5310000)+int64(share*100)*1000+int64(k), func(int) float64 { return 1 })
				byLen := map[int][]float64{}
				for _, o := range tr.runObservations(&local) {
					byLen[o.length] = append(byLen[o.length], o.deleted)
				}
				per[k] = byLen
			})
			r, _, ok := reproducibleRatio(per, superK)
			if !ok {
				cells += fmt.Sprintf(" %9s", "-")
				continue
			}
			cells += fmt.Sprintf(" %9.3f", r)
			byFactor[cf][share] = r
		}
		t.Logf("%12d%s", cf, cells)
	}

	checked := 0
	for _, share := range shares {
		lo, loOK := byFactor[8][share]
		mid, midOK := byFactor[16][share]
		hi, hiOK := byFactor[32][share]
		if !loOK || !midOK || !hiOK {
			continue
		}
		checked++
		if !(lo < mid && mid < hi) {
			t.Fatalf("at %.0f%% share the clustering ratio went %.3f / %.3f / %.3f at clamp "+
				"factors 8 / 16 / 32. The accounting arm above says the ratio rises with the "+
				"clamp; a chain built at each factor has to agree, or the accounting arm is "+
				"measuring the bookkeeping and not the rule", share*100, lo, mid, hi)
		}
		t.Logf("at %.0f%% share the ratio rises %.3f -> %.3f -> %.3f across clamp factors "+
			"8/16/32: the crossing moves with the clamp, which is the whole claim",
			share*100, lo, mid, hi)
	}
	if checked == 0 {
		// Loud rather than silent, and it says what would make it run: a
		// direction that is never evaluated is indistinguishable from one that
		// always holds (PROTOCOL rule 26).
		t.Logf("REAL-CHAIN DIRECTION NOT EVALUATED: no share reproduced at all three clamp " +
			"factors. This line is a t.Logf on a passing test, so it is invisible without " +
			"-v; run with ZCD_BACKDATE_SWEEP=1 to evaluate it")
	}
}

// maxCellSpread is how much a cell's clustering ratio may vary across seeds
// before this test refuses to report it. It is a bar on the ESTIMATE and not on
// the value: a ratio that swings by a third between seed sets is not a
// measurement, and the failure mode it exists for is real — the same cell read
// 1.57, 2.14 and 2.82 on three different configurations while the well-sampled
// cells beside it reproduced to about ±0.02.
const maxCellSpread = 0.25

// reproducibleRatio computes the clustering ratio once per seed and returns the
// mean, the relative spread across seeds, and whether the cell reproduced well
// enough to be reported. Every seed must have produced a ratio: a cell where
// some seeds saw no run of length superK at all is a cell whose pooled mean
// would be carried by whichever seed happened to.
func reproducibleRatio(perSeed []map[int][]float64, kFix int) (mean, spread float64, ok bool) {
	if len(perSeed) < 3 {
		return 0, 0, false
	}
	rs := make([]float64, 0, len(perSeed))
	for _, byLen := range perSeed {
		r, got := superAdditivityAt(byLen, kFix)
		if !got {
			return 0, 0, false
		}
		rs = append(rs, r)
	}
	mean = meanOf(rs)
	if mean <= 0 {
		return 0, 0, false
	}
	spread = stddevOf(rs) / mean
	return mean, spread, spread <= maxCellSpread
}
