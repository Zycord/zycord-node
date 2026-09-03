package pow_test

import (
	"math/big"
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
)

func header(height, time uint64, target u256.U256) types.Header {
	return types.Header{Version: types.HeaderVersion, Height: height, Time: time, Target: target}
}

// TestWorkIsCheckedAgainstTheDeclaredTarget.
func TestWorkIsCheckedAgainstTheDeclaredTarget(t *testing.T) {
	e := pow.Dev{}
	p := spec.Mainnet()

	// An impossible target: no nonce can satisfy it in a reasonable number of
	// tries, and the header must be rejected.
	hard := header(1, 100, u256.One)
	if err := pow.CheckWork(e, hard, p); err == nil {
		t.Fatal("a header with no work satisfied a near-impossible target")
	}

	// A trivial target: every nonce satisfies it.
	easy := header(1, 100, u256.Max)
	if err := pow.CheckWork(e, easy, p); err != nil {
		t.Fatalf("a trivial target rejected a header: %v", err)
	}

	// A zero target is not "impossible", it is malformed.
	if err := pow.CheckWork(e, header(1, 100, u256.Zero), p); err != pow.ErrTargetMissing {
		t.Fatalf("a zero target gave %v", err)
	}
}

// TestGenesisNeedsNoWork: solving block 0 would make it unreproducible without
// the miner's nonce, and a competing genesis is a different network rather than
// a fork.
func TestGenesisNeedsNoWork(t *testing.T) {
	if err := pow.CheckWork(pow.Dev{}, header(0, 0, u256.Zero), spec.Mainnet()); err != nil {
		t.Fatalf("genesis was asked for work: %v", err)
	}
}

// TestSolveFindsANonce exercises the miner's side of the same rule.
func TestSolveFindsANonce(t *testing.T) {
	p := spec.Mainnet()
	// A target of 2^248 accepts roughly one nonce in 256.
	target := u256.MustFromDecimal("452312848583266388373324160190187140051835877600158453279131187530910662656")
	h := header(1, 100, target)
	if !pow.Solve(pow.Dev{}, &h, p, 100_000) {
		t.Fatal("no nonce was found for an easy target")
	}
	if err := pow.CheckWork(pow.Dev{}, h, p); err != nil {
		t.Fatalf("the solved header does not verify: %v", err)
	}
	// The seal must bind to the header: changing anything invalidates it.
	h.Height++
	if err := pow.CheckWork(pow.Dev{}, h, p); err == nil {
		t.Fatal("the proof of work does not bind to the header")
	}
}

// TestMedianTimeIsTheOnlyTimeRule is R1-H2. There is no upper bound on
// validity: a future-dated block is withheld, never rejected, because wall
// clocks must not fork the network's view of validity.
func TestMedianTimeIsTheOnlyTimeRule(t *testing.T) {
	p := spec.Mainnet()
	var recent []types.Header
	for i := uint64(1); i <= 11; i++ {
		recent = append(recent, header(i, i*30, p.GenesisTarget))
	}
	median := pow.MedianTime(recent, p)

	if err := pow.CheckMedianTime(header(12, median, p.GenesisTarget), recent, p); err == nil {
		t.Fatal("a header at the median was accepted; the bound is strict")
	}
	if err := pow.CheckMedianTime(header(12, median+1, p.GenesisTarget), recent, p); err != nil {
		t.Fatalf("a header just above the median was rejected: %v", err)
	}

	// Far in the future is still valid — it is merely withheld until the local
	// clock catches up.
	far := header(12, median+1_000_000, p.GenesisTarget)
	if err := pow.CheckMedianTime(far, recent, p); err != nil {
		t.Fatal("a future-dated header was rejected instead of withheld")
	}
	if !pow.IsTooFarAhead(far, median, p) {
		t.Fatal("a far-future header was not flagged for withholding")
	}
	if pow.IsTooFarAhead(header(12, median+1, p.GenesisTarget), median, p) {
		t.Fatal("a header just above the median was flagged for withholding")
	}
}

// TestDifficultyRespondsToSolveTime: LWMA exists because a young chain cannot
// survive a 2016-block window. Fast blocks must make the next one harder within
// the window, not within a fortnight.
func TestDifficultyRespondsToSolveTime(t *testing.T) {
	p := spec.Mainnet()

	// Blocks arriving at exactly the goal leave the target where it is.
	onTime := chain(p, p.TargetBlockSeconds, int(p.DifficultyWindow)+1)
	steady := pow.NextTarget(onTime, p)
	if !steady.Eq(p.GenesisTarget) {
		t.Fatalf("on-time blocks moved the target to %s", steady.String())
	}

	// Blocks arriving twice as fast must make the work harder — a smaller
	// target — and blocks arriving twice as slow must make it easier.
	fast := pow.NextTarget(chain(p, p.TargetBlockSeconds/2, int(p.DifficultyWindow)+1), p)
	if !fast.Lt(p.GenesisTarget) {
		t.Fatal("fast blocks did not raise the difficulty")
	}
	slow := pow.NextTarget(chain(p, p.TargetBlockSeconds*2, int(p.DifficultyWindow)+1), p)
	if !slow.Gt(p.GenesisTarget) {
		t.Fatal("slow blocks did not lower the difficulty")
	}
}

// TestDifficultyClampsAgainstTimestampGames: one absurd timestamp must not be
// able to swing the window.
func TestDifficultyClampsAgainstTimestampGames(t *testing.T) {
	p := spec.Mainnet()
	headers := chain(p, p.TargetBlockSeconds, int(p.DifficultyWindow)+1)

	// A miner claims the last block took a century.
	headers[len(headers)-1].Time = headers[len(headers)-2].Time + 3_000_000_000
	got := pow.NextTarget(headers, p)

	ceiling := p.GenesisTarget.MulDiv64(p.DifficultyClampFactor, 1)
	if got.Gt(ceiling) {
		t.Fatalf("one timestamp moved the target to %s, above the clamp %s",
			got.String(), ceiling.String())
	}

	// Backwards time is now a genuinely negative solve time, clamped
	// symmetrically at -maxSolve — not floored at zero. The window has
	// 89 on-goal intervals (i=1..89, weight i, solve=goal) and one interval
	// pulled hard negative at the top of the window (i=90, weight 90): the
	// last header's parent is ~89*goal past 1_000_000 and the header itself
	// claims Time=0, so the raw gap saturates the clamp at -maxSolve=-480.
	//
	//	weighted = goal*(1+2+...+89) + (-480)*90 = 30*4005 - 43200 = 76950
	//	weights  = 1+2+...+90              = 4095
	//	next     = GenesisTarget * 76950 / (4095*30)   (MulDiv64 floors)
	//
	// The rejected rule (floor the negative interval at zero instead of
	// letting it go negative) gives a different answer *in this exact
	// scenario*: weighted_old = 30*4005 + 0*90 = 120150, next_old =
	// GenesisTarget * 120150/122850 ≈ 0.978*GenesisTarget — barely moved,
	// because discarding the compensating charge leaves only the ordinary
	// on-goal blocks pulling the average down. The signed rule's -480
	// contribution is what makes the single manipulated block visible in
	// the result instead of nearly invisible.
	headers[len(headers)-1].Time = 0
	got = pow.NextTarget(headers, p)
	if got.IsZero() {
		t.Fatal("a backwards timestamp produced a zero target")
	}
	want := p.GenesisTarget.MulDiv64(76950, 4095*p.TargetBlockSeconds)
	if !got.Eq(want) {
		t.Fatalf("backdated-block target = %s, want %s (the negative interval "+
			"was not weighted the way the signed clamp requires)", got.String(), want.String())
	}
}

// TestTargetNeverExceedsTheMaximum pins the absolute ceiling (F-PARAM-1).
//
// The relative clamp bounds each step at DifficultyClampFactor of the previous
// target, which bounds nothing at all in the limit: every block multiplies, and
// u256 saturates rather than erroring, so a sustained upward push arrives at
// 2^256-1 — where CheckWork accepts every hash and BlockWork returns one for
// every header. The property is that no input, however extreme and however long
// sustained, moves the target above MaxTarget.
//
// The scenario is built so that the rejected rule (no ceiling) gives a
// different answer *here*: the loop asserts that the relative clamp alone
// genuinely runs past MaxTarget, so a pass is the ceiling acting and not the
// input failing to reach it. Removing the clamp from NextTarget fails this.
func TestTargetNeverExceedsTheMaximum(t *testing.T) {
	p := spec.Mainnet()

	// Every solve time at the per-sample clamp: the fastest legal upward push.
	// Each result is fed back in as the window's target, which is what a real
	// chain does block after block.
	headers := chain(p, p.TargetBlockSeconds*p.DifficultyClampFactor, int(p.DifficultyWindow)+1)
	sawUnclampedOvershoot := false
	for step := 0; step < 64; step++ {
		got := pow.NextTarget(headers, p)
		if got.Gt(p.MaxTarget) {
			t.Fatalf("step %d: target %s exceeds max_target %s",
				step, got.String(), p.MaxTarget.String())
		}
		// What the rule would have produced with only the relative clamp.
		last := headers[len(headers)-1].Target
		if last.MulDiv64(p.DifficultyClampFactor, 1).Gt(p.MaxTarget) {
			sawUnclampedOvershoot = true
		}
		for i := range headers {
			headers[i].Target = got
		}
	}
	if !sawUnclampedOvershoot {
		t.Fatal("the input never pushed past max_target, so this scenario cannot " +
			"tell the ceiling from its absence")
	}

	// A single absurd window, from a target already at the ceiling.
	pinned := chain(p, p.TargetBlockSeconds, int(p.DifficultyWindow)+1)
	for i := range pinned {
		pinned[i].Target = p.MaxTarget
		pinned[i].Time = uint64(i) * 3_000_000_000
	}
	if got := pow.NextTarget(pinned, p); got.Gt(p.MaxTarget) {
		t.Fatalf("an absurd window moved the target to %s, above max_target %s",
			got.String(), p.MaxTarget.String())
	}
}

// TestMaxTargetKeepsBlockWorkMeaningful: the ceiling is only worth having if a
// header mined at it is still worth measurably more than one hash — otherwise
// accumulated work is a block count and fork choice stops measuring work. The
// relation is params.Validate's, restated here against the shipped values.
func TestMaxTargetKeepsBlockWorkMeaningful(t *testing.T) {
	for _, p := range []*params.Params{spec.Mainnet(), spec.Devnet()} {
		divisor, overflow := p.MaxTarget.Add(u256.One)
		if overflow {
			t.Fatalf("%s: max_target is 2^256-1", p.Name)
		}
		// BlockWork is floor(2^256 / (max_target+1)), and core cannot import
		// node/chain to call it. The same statement without a 256-bit
		// division: work is at least 16 exactly when 16·(max_target+1) still
		// fits in 256 bits.
		if _, overflow := divisor.Mul(u256.FromUint64(16)); overflow {
			t.Fatalf("%s: a header at max_target is worth fewer than 16 hashes; "+
				"fork choice can barely order branches", p.Name)
		}
	}
}

func chain(p *params.Params, interval uint64, n int) []types.Header {
	out := make([]types.Header, n)
	for i := 0; i < n; i++ {
		out[i] = header(uint64(i), uint64(i)*interval+1_000_000, p.GenesisTarget)
	}
	return out
}

// ---------------------------------------------------------------------------
// Interleaved-minority backdating, adaptive feedback.
// ---------------------------------------------------------------------------

// bugFloorNextTarget is the retired rule this file used to exercise: solve
// times floored at zero instead of signed. It is kept only so the tests below
// can show, on the exact same scenario, that the rejected rule behaves
// differently from the shipped one (CONTRIBUTING's mutation standard) —
// mirroring TestTargetNeverExceedsTheMaximum's existing "what the rule would
// have produced" pattern. It must never be called from non-test code, and it
// is not exported.
func bugFloorNextTarget(recent []types.Header, p *params.Params) u256.U256 {
	n := int(p.DifficultyWindow)
	if len(recent) < 2 {
		return p.GenesisTarget
	}
	if len(recent) < n+1 {
		n = len(recent) - 1
	}
	window := recent[len(recent)-(n+1):]

	goal := p.TargetBlockSeconds
	maxSolve := goal * p.DifficultyClampFactor
	var weighted, weights uint64
	for i := 1; i < len(window); i++ {
		solve := uint64(0)
		if window[i].Time > window[i-1].Time {
			solve = window[i].Time - window[i-1].Time
		}
		if solve > maxSolve {
			solve = maxSolve
		}
		w := uint64(i)
		weighted += solve * w
		weights += w
	}
	if weights == 0 {
		return window[len(window)-1].Target
	}

	last := window[len(window)-1].Target
	avgNumerator := weighted
	avgDenominator := weights * goal
	if avgNumerator == 0 {
		avgNumerator = 1
	}
	next := last.MulDiv64(avgNumerator, avgDenominator)

	upper := last.MulDiv64(p.DifficultyClampFactor, 1)
	lower, _ := last.Div64(p.DifficultyClampFactor)
	if next.Gt(upper) {
		next = upper
	}
	if next.Lt(lower) {
		next = lower
	}
	if next.Gt(p.MaxTarget) {
		next = p.MaxTarget
	}
	if next.IsZero() {
		next = u256.One
	}
	return next
}

// ratioTimes returns floor(mul * a/b) as a uint64, exact (math/big, no
// floating point), saturating at a large-but-safe sentinel instead of
// overflowing if the ratio is absurd — which only happens when a run has
// already blown through the bound the caller is about to check anyway.
func ratioTimes(a, b u256.U256, mul uint64) uint64 {
	ab, bb := a.Bytes(), b.Bytes()
	num := new(big.Int).Mul(new(big.Int).SetBytes(ab[:]), big.NewInt(int64(mul)))
	den := new(big.Int).SetBytes(bb[:])
	if den.Sign() == 0 {
		return 1 << 62
	}
	q := new(big.Int).Div(num, den)
	if !q.IsUint64() || q.Uint64() > 1<<62 {
		return 1 << 62
	}
	return q.Uint64()
}

// warmup is DifficultyWindow blocks of honest production before the attacker
// starts, so the measurement begins with a full, steady-state sliding window
// rather than the small-n window a chain has in its first 90 blocks. The
// small-n regime weighs a single sample far more heavily than the same sample
// gets once the window is full — a real and separate dynamic (the "launch
// transient" / integrator dead-time, a separate question this file
// deliberately does not touch) that would otherwise contaminate a measurement
// aimed at the backdating rule's steady-state equilibrium. Skipping it is not
// hiding the effect, it is not re-measuring an effect this test does not
// claim to be about.
const warmup = 90

// simulateInterleavedAttacker drives next (either the real pow.NextTarget or
// bugFloorNextTarget, so the two can be run on identical scenarios) over a
// long chain in which every period-th block is the attacker's.
//
// Two clocks are tracked, and keeping them separate is the point: realTime is
// the physical clock — every block, honest or not, actually takes
// goal*(GenesisTarget/target) seconds to solve for a fixed hashrate, because
// a larger (easier) target is solved faster. declaredTime is what the header
// claims. An honest miner reports realTime truthfully. The attacker instead
// reports realTime-maxSolve: a lie relative to the true clock, not relative
// to whatever its own parent happened to declare. That distinction is what
// produces the actual mechanism backdating exploits — collapsing the two
// clocks into one (as an earlier draft of this test did, by computing each
// declared time as parent.declared + solve) makes an attacker's backdating
// invisible to the following block, because the next honest gap is then
// measured from the attacker's own manipulated number rather than from real
// elapsed time, and the donation to the window never appears.
//
// With that in place: the transition into an attacker block sees
// declared_attacker - declared_prevHonest ≈ -maxSolve (deeply negative,
// clamps). The transition out of it, to the next honest block, sees
// declared_honest - declared_attacker = realElapsed + maxSolve (inflated by
// exactly the backdate, clamps at +maxSolve too). It returns the full header
// chain built, so callers can inspect any point in the run.
func simulateInterleavedAttacker(
	p *params.Params, next func([]types.Header, *params.Params) u256.U256, period, blocks int,
) []types.Header {
	goal := p.TargetBlockSeconds
	maxSolve := goal * p.DifficultyClampFactor
	const base = 10_000_000_000 // headroom so a backdate never underflows uint64.

	headers := make([]types.Header, 1, blocks+1)
	headers[0] = header(0, base, p.GenesisTarget)
	realTime := uint64(base)

	for i := 1; i <= blocks; i++ {
		target := next(headers, p)

		// The real clock always advances, for every block: solve time is
		// inversely proportional to the target (easier target, faster
		// solve, for the fixed hashrate this simulation models).
		solve := ratioTimes(p.GenesisTarget, target, goal)
		if solve == 0 {
			solve = 1
		}
		realTime += solve

		declared := realTime
		if i > warmup && (i-warmup)%period == 0 {
			declared = realTime - maxSolve
		}
		headers = append(headers, header(uint64(i), declared, target))
	}
	return headers
}

// TestInterleavedMinorityBackdatingHasABoundedEquilibrium is the empirical
// half of the signed-accumulator fix. F-PARAM-3 established analytically that
// the floored rule has no fixed point for any manipulated share strictly
// between goal/maxSolve = 1/DifficultyClampFactor = 6.25% and its mirror
// 93.75% (maxSolve is goal*C, so the ratio is 1/C exactly — the same on every
// parameter set, and it does not move with the goal): no real
// block-production rate makes the measured average equal the goal, so the
// target is driven, monotonically, to MaxTarget. The attacker here is
// interleaved throughout the run rather than front-loaded — a leading burst
// is a different, weaker adversary, as an earlier review's tiebreak record
// measured, because a burst ages out of the 90-block window and the
// controller recovers; an attacker present in every window never lets it.
//
// The scenario is built so the rejected rule (bugFloorNextTarget) gives a
// different answer here: at every share tested above the 6.25% threshold it
// must reach MaxTarget, or this test cannot tell the fix from its absence.
func TestInterleavedMinorityBackdatingHasABoundedEquilibrium(t *testing.T) {
	p := spec.Mainnet()
	const blocks = 3 * 90 * 20 // 20 window-lengths, in both directions of the interleave.

	for _, tc := range []struct {
		period int
		share  string
	}{
		{20, "5%"},   // below goal/maxSolve: the bug's own discount regime.
		{10, "10%"},  // inside the no-fixed-point zone the bug leaves open.
		{6, "16.7%"}, // deep inside it.
		{4, "25%"},   // An earlier reviewer measured this share against the real NextTarget.
		{3, "33%"},
		{2, "50%"},
	} {
		t.Run(tc.share, func(t *testing.T) {
			fixed := simulateInterleavedAttacker(p, pow.NextTarget, tc.period, blocks)
			buggy := simulateInterleavedAttacker(p, bugFloorNextTarget, tc.period, blocks)

			for i, h := range fixed {
				if h.Target.Eq(p.MaxTarget) {
					t.Fatalf("share %s: the fixed rule reached MaxTarget at block %d; "+
						"the equilibrium gap is not closed", tc.share, i)
				}
			}

			if tc.period == 20 {
				// Below the old threshold the bug is a bounded discount, not
				// a runaway — this iteration only confirms the fix does not
				// regress the case that was already survivable.
				return
			}
			reachedCeiling := false
			for _, h := range buggy {
				if h.Target.Eq(p.MaxTarget) {
					reachedCeiling = true
					break
				}
			}
			if !reachedCeiling {
				t.Fatalf("share %s: the retired floor-at-zero rule did not reach MaxTarget "+
					"within %d blocks, so this scenario cannot discriminate the fix from "+
					"its absence — strengthen it rather than trust the fixed side alone",
					tc.share, blocks)
			}
		})
	}
}

// TestRelativeClampAppliesPerBlockNotPerWindow pins the per-block reading:
// the relative clamp bounds each block's target to within
// ±DifficultyClampFactor of the immediately preceding block's target, and
// nothing bounds cumulative movement across a DifficultyWindow's worth of
// blocks the way "±16x per window" (the old docs/ARCHITECTURE.md wording)
// would require. Sustained pressure for exactly one window's length of blocks
// — fewer than DifficultyWindow, so the window is never fully populated by
// the pressure alone — still compounds past 16x, which a genuine per-window
// clamp would forbid.
//
// MaxTarget is widened for this test alone (a local copy of the params, never
// mutating spec.Mainnet()) so the absolute MaxTarget ceiling cannot mask
// the relative clamp's own behaviour — that interaction is already pinned by
// TestTargetNeverExceedsTheMaximum, and conflating the two here would leave
// this test unable to tell "per block" from "per window" on its own.
func TestRelativeClampAppliesPerBlockNotPerWindow(t *testing.T) {
	base := *spec.Mainnet()
	base.MaxTarget = u256.Max // this test is about the relative clamp, not the absolute ceiling.
	p := &base
	windowLen := int(p.DifficultyWindow)
	maxSolve := p.TargetBlockSeconds * p.DifficultyClampFactor

	// Grow the chain by appending real, historically distinct headers — not
	// by overwriting every existing header with the newest target — because
	// a genuine per-window clamp compares against the target that was
	// actually in force DifficultyWindow blocks ago, and that comparison is
	// meaningless if every header in the slice is kept in lockstep. Fewer
	// than one full window's worth of blocks are appended, so the window
	// never fully slides off genesis: a real per-window clamp would still be
	// measuring against GenesisTarget on every one of these steps.
	headers := []types.Header{header(0, 1_000_000, p.GenesisTarget)}
	for i := 1; i < windowLen; i++ {
		target := pow.NextTarget(headers, p)
		tm := headers[i-1].Time + maxSolve
		headers = append(headers, header(uint64(i), tm, target))
	}
	final := headers[len(headers)-1].Target

	perWindowBound := p.GenesisTarget.MulDiv64(p.DifficultyClampFactor, 1)
	if !final.Gt(perWindowBound) {
		t.Fatalf("after %d blocks of sustained per-sample-clamped pressure — fewer than "+
			"one DifficultyWindow (%d), so the window has not slid off genesis — the target "+
			"only reached %s, at or below the single ±%dx-from-genesis bound a genuine "+
			"per-window clamp would enforce (%s); the relative clamp is supposed to compound "+
			"every block against the *previous block's* target, not once per window against "+
			"the target the window started from",
			windowLen-1, windowLen, final.String(), p.DifficultyClampFactor, perWindowBound.String())
	}
}

// legalBackdate returns the timestamp a miner would declare to backdate a
// block by maxSolve seconds relative to realTime, floor-clamped to the
// smallest value that stays legal under the real pow.CheckMedianTime rule
// against headers — the same floor a real node enforces on every inbound
// block. A test-simulated attacker that declares realTime-maxSolve
// unconditionally instead can manufacture timestamps CheckMedianTime would
// reject outright, which is not a capability any real attacker has and would
// measure a strictly stronger-than-legal adversary rather than the real rule.
// Kept here as a shared building block for future backdating simulations in
// this package; not currently wired into any test in this file (see each
// simulator's own doc comment for why, where relevant).
func legalBackdate(headers []types.Header, i int, realTime, maxSolve uint64, p *params.Params) uint64 {
	wanted := realTime - maxSolve
	start := 0
	if i > int(p.MedianTimeBlocks) {
		start = i - int(p.MedianTimeBlocks)
	}
	floor := pow.MedianTime(headers[start:], p) + 1
	if wanted < floor {
		wanted = floor
	}
	return wanted
}

// fixedEngine returns one digest whatever it is asked, so that a test can put
// an exact 32-byte string in front of the comparison the rule performs. The
// rule is a comparison between a digest and a target; the only way to pin
// *how the digest is read* is to choose the digest.
type fixedEngine struct{ digest types.Hash }

func (fixedEngine) Name() string                         { return "fixed" }
func (e fixedEngine) Hash(types.Hash, []byte) types.Hash { return e.digest }

// TestTheDigestIsReadLittleEndian pins the consensus rule that the
// work-function digest is compared against the target as a LITTLE-endian
// 256-bit integer, byte 0 least significant — the one 256-bit quantity in this
// protocol that is not big-endian. checkWorkWith carries the full argument and
// docs/ARCHITECTURE.md §12 is normative; the short form is that RandomX is a
// Monero-family work function, the whole Monero-family ecosystem reads its
// digest little-endian, and the two conventions read opposite ends of an
// independent 32 bytes, so a big-endian node shares no valid nonce with any
// miner that exists.
//
// Every other proof-of-work test in this tree mines: it asks the engine for
// nonces until one passes and then asserts that it passes. Such a test is
// invariant under the endianness of the comparison — flip the rule and a
// different nonce wins, and the test still goes green. That is exactly how a
// convention mismatch with the entire Monero-family mining ecosystem survives
// a full suite, so this test does not mine at all. It hands the rule a chosen
// digest and a chosen target and asserts the verdict.
//
// The digest below is a "one-sided" string: it is small when read
// little-endian (the high-order bytes, at the END under LE, are zero) and
// enormous when read big-endian. A target between the two readings therefore
// separates them completely — the LE rule accepts, the BE rule rejects — and
// the second case is its mirror image. Neither can pass under the wrong rule
// by luck.
func TestTheDigestIsReadLittleEndian(t *testing.T) {
	p := spec.Mainnet()

	// leSmall reads as 0x01 little-endian and as 2^248 big-endian.
	var leSmall types.Hash
	leSmall[0] = 0x01
	// leHuge is the mirror: 2^248 little-endian, 0x01 big-endian.
	var leHuge types.Hash
	leHuge[31] = 0x01

	// A target of 2^128 sits strictly between 1 and 2^248, so it decides
	// both cases and decides them oppositely under the two conventions.
	target := u256.MustFromDecimal("340282366920938463463374607431768211456") // 2^128

	h := header(1, 100, target)

	if err := pow.CheckWork(fixedEngine{leSmall}, h, p); err != nil {
		t.Fatalf("a digest that is 1 little-endian was refused against 2^128: %v "+
			"(the rule is reading the digest big-endian, where it is 2^248)", err)
	}
	if err := pow.CheckWork(fixedEngine{leHuge}, h, p); err != pow.ErrWorkTooLow {
		t.Fatalf("a digest that is 2^248 little-endian was accepted against 2^128: %v "+
			"(the rule is reading the digest big-endian, where it is 1)", err)
	}
}

// TestTheSolverReadsTheDigestLittleEndianToo covers the second route to the
// same comparison. Solver.Try and checkWorkWith share no code — deliberately,
// see the Solver doc comment — so an endianness change applied to one and not
// the other produces a miner whose every block its own network rejects, and
// TestTheSolverAgreesWithCheckWork would not catch it if BOTH were flipped
// together into the wrong convention. This pins the absolute answer, not the
// agreement.
func TestTheSolverReadsTheDigestLittleEndianToo(t *testing.T) {
	p := spec.Mainnet()
	target := u256.MustFromDecimal("340282366920938463463374607431768211456") // 2^128

	var leSmall types.Hash
	leSmall[0] = 0x01
	var leHuge types.Hash
	leHuge[31] = 0x01

	s := pow.NewSolver(fixedEngine{leSmall}, header(1, 100, target), p)
	if !s.Try(0) {
		t.Fatal("the solver refused a digest that is 1 little-endian against 2^128")
	}
	s = pow.NewSolver(fixedEngine{leHuge}, header(1, 100, target), p)
	if s.Try(0) {
		t.Fatal("the solver accepted a digest that is 2^248 little-endian against 2^128")
	}
}

// TestAStratumJobTargetIsACleanTruncation states, as an executable claim, the
// property the little-endian rule buys: t64 = max(1, floor((target256 + 1) /
// 2^192)) selects exactly the digest bytes a Monero-dialect miner compares, so
// a share found under a 64-bit job target satisfies the full 256-bit rule up
// to a boundary sliver one part in 2^64 wide. Under a big-endian reading no
// such truncation exists at all, because the bytes a truncation keeps and the
// bytes the miner compares are then at opposite ends of the digest.
//
// It is here rather than in the pool-facing endpoint that will consume it
// because it is a property of the *consensus rule*, not of the endpoint: if
// this rule changes back, the truncation stops being sound and any endpoint
// resting on it is silently wrong — handing miners shares the node refuses.
// docs/ARCHITECTURE.md §12 records the same identity normatively. Written
// against the digest bytes directly for the same reason the test above does
// not mine.
func TestAStratumJobTargetIsACleanTruncation(t *testing.T) {
	p := spec.Mainnet()
	target := p.GenesisTarget

	// t64 as a Stratum job would carry it: floor((target256 + 1) / 2^192),
	// floored at one. Dividing by 2^192 is taking the top 64 bits, which the
	// canonical big-endian encoding puts in its first eight bytes.
	t256plus1, _ := target.Add(u256.One)
	beBytes := t256plus1.Bytes()
	var t64 uint64
	for i := 0; i < 8; i++ {
		t64 = t64<<8 | uint64(beBytes[i])
	}
	if t64 == 0 {
		t64 = 1
	}

	// A digest whose last eight bytes, read as an LE uint64, are strictly
	// below t64 is a share XMRig would submit. Build the extreme one — every
	// other digest byte 0xff — and assert the full rule accepts it. If the
	// full rule accepted only some such digests, a pool would be handing
	// miners shares the node then rejects.
	var d types.Hash
	for i := 0; i < 24; i++ {
		d[i] = 0xff
	}
	share := t64 - 1
	for i := 0; i < 8; i++ {
		d[24+i] = byte(share >> (8 * i))
	}
	if err := pow.CheckWork(fixedEngine{d}, header(1, 100, target), p); err != nil {
		t.Fatalf("a share at the very top of the 64-bit job target was refused by "+
			"the full rule: %v — the truncation is not clean", err)
	}

	// And the boundary sliver is on the other side: a digest whose top 64
	// bits equal t64 exactly is NOT guaranteed to pass, which is why the job
	// target is a strict-inequality filter and the node re-verifies every
	// submit. Assert the direction rather than a value.
	for i := 0; i < 8; i++ {
		d[24+i] = byte(t64 >> (8 * i))
	}
	if err := pow.CheckWork(fixedEngine{d}, header(1, 100, target), p); err == nil {
		t.Fatal("a digest above the truncated job target passed the full rule; " +
			"the truncation would then not be conservative")
	}
}
