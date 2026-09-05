package sim_test

import (
	"math/big"
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
)

// Forward-dating against the LWMA, observed in **both target directions**.
//
// BOTH OF WHAT — the phrase cost two documents a false coverage claim, so it is
// spelled out before anything else here. The two directions are the two ways
// the TARGET can move, and one attacker drives them: **how far can a miner
// drive the difficulty target down** (the median-push freeze: unbounded future
// timestamps ratchet the median, honest miners then backdate, and the target
// divides by 16 per block to the floor — which the FTL withhold rule closes)
// and **how far can it drive the target up** (the residual, which the FTL
// withhold rule does *not* close). They are NOT two attackers. `run`'s `push`
// is a `uint64` added to the real clock, so nothing in this file can date a
// header backwards, and no assertion here says anything about the backward
// direction. That direction lives in `core/pow/pow_test.go`'s
// interleaved-backdating test, in `core/pow/backdate_sweep_test.go` and in
// `core/pow/median_bound_test.go`.
//
// docs/ARCHITECTURE.md §18 has claimed since v0.2 that `sim/` covers "timestamp
// manipulation vs LWMA and the FTL withhold rule". It did not — there was no
// such scenario, and there was no withhold rule either — neither timestamp rule
// was enforced on the gossip block path and IsTooFarAhead had zero callers.
// This file is that scenario, for the forward half.
//
// The first version of this file could see only one of those two, and the
// reason was structural rather than a weak assertion. Its `hardness()` looped
// `for t.Lt(genesis)` and returned 1 for every target at or above genesis, so
// the modelled real interval was pinned at exactly the goal the moment the
// chain got *easier*. A model whose clock cannot speed up cannot observe a
// runaway upward, and every row of its "bounded" table was therefore a lower
// bound on damage in the downward direction only. Its attacker was also a
// leading burst — `lwmaRun` pushed the first `poisoned` blocks and then stopped
// — so its headline "200 of 200 sustained, 5 s, the goal exactly" was the
// universal-offset case, which cancels by algebra and describes no attacker at
// all. Both are repaired here.
//
// # The model
//
// Stated rather than buried, because the model *is* the finding:
//
//   - **Real solve time is inversely proportional to the target.** A chain at
//     half the genesis target takes twice as long per block; at twice the
//     genesis target, half as long. `realInterval` computes
//     `goal * genesis / target` in milliseconds, so the clock moves in *both*
//     directions and sub-second intervals are representable. This is the
//     feedback loop both attacks ride, and a model without it shows a chain
//     sailing through, which is CONTRIBUTING's mirror trap.
//   - **Honest miners run `node/miner.headerTime`'s ratchet**: the timestamp is
//     real time, floored at `median + 1`. That floor is the honest miner's own
//     ratchet and it is untouched by this PR — the model includes it because it
//     is what ships.
//   - **Two attacker shapes, because the two directions have two mechanisms.**
//     `burst(n)` is the freeze as filed: n consecutive blocks that capture the
//     median window outright, after which every honest block is floored one
//     second above a median that has been thrown into the future. `share(num,
//     den)` is an evenly interleaved minority, which is what a real minority
//     hashrate looks like and what the upward runaway needs. Using a burst for
//     the upward case would measure a step input to a moving average, which the
//     window walks past by construction.
//
// # Why a *bounded* push still moves the target, and only upward
//
// `pow.NextTarget` reads `max(0, Time[i] - Time[i-1])`. An attacker block dated
// `P = FTL - 1` ahead of real time donates `P` to the weighted sum. The block
// after it — honest, dated at real time — should donate `-P` and cancel it, but
// `max(0, ...)` clips that step to zero. The compensating negative is deleted,
// so the donation is `P` per attacker block, *cumulatively*, not `P` once per
// window.
//
// The reported mean solve is therefore about `d + p*max(0, P - d)` for a real
// interval `d` and an attacker share `p`. Equilibrium needs that to equal the
// goal; as the target rises `d` falls toward zero and the expression tends to
// `p*P`. So an equilibrium exists only when
//
//	p < goal / FTL
//
// which is **16.7 % on mainnet** (30 s goal, 180 s FTL) and **2.8 % on devnet**
// (5 s goal). Above it there is no fixed point at all, and the target walks to
// `MaxTarget`, the absolute clamp, and stays there. The threshold scales with
// `TargetBlockSeconds`, which is why devnet's fast blocks are six times more
// exposed to this than mainnet's.
//
// # What this model does not represent, and why the threshold is not a margin
//
// Every solve time here is the *mean* solve time for the target in force. That
// is deliberate — it is what makes `TestTheHonestBaselineDoesNotMove` an exact
// zero, so every excursion below is a difference from a known rest state rather
// than from noise — and it is also the model's one large omission: real
// proof-of-work arrivals are exponential, and this controller is sensitive to
// that in a way it is not sensitive to a bounded push.
//
// Measured, driving this same `pow.NextTarget` with exponential intervals and
// **no attacker at all**: roughly two thirds of 32 1500-block mainnet runs
// reach `MaxTarget`, and about as many still do with the modelled interval
// floored at one second, which rules out one-second timestamp granularity as
// the cause. (Counts, not the conclusion, move with the seed — two independent
// implementations of the driver measured 23/32 and 22/32, 18/32 and 17/32.) The
// cause is a different open issue: the retarget normalises against the window's
// *last* target rather than its average, so each correction is re-applied for a
// whole window. Against the branches proposing the two controller fixes, the
// signed accumulator alone changes the honest exponential rows not at all —
// honest timestamps never produce a negative interval, so there is nothing for
// a sign to fix — while the window-average normalisation on top of it pins in 0
// of 8 at every share from 0 % to 100 %.
//
// # And the attacker here is evenly spaced, which is its own assumption
//
// `share(num, den)` places the attacker's blocks at exact intervals. That is the
// *minimum-variance* placement, and it flatters the threshold in the same way
// the model above flatters it: the LWMA sees the same small donation every few
// blocks instead of clusters. Changing nothing but the placement — same
// dispersion-free clock, same share, chosen by a coin flip instead of an
// interleave — mainnet reaches `MaxTarget` at 16 % and at 10 % in most runs,
// both of which the even interleave keeps bounded.
//
// The share is not the only thing that was flattering it: **so was the run
// length.** Holding the share exactly (`floor(p·N)` attacker blocks, randomly
// permuted, so the realised share cannot overshoot the threshold by sampling)
// and lengthening the run, a **5 %** attacker reaches `MaxTarget` in none of 8
// runs at 1500 blocks, 2 of 8 at 5000, and 7 of 8 at 20000 — which at a 30 s
// goal is about a week. A share that looks bounded is often a share whose
// hitting time is longer than the simulation.
//
// So `p < goal/FTL` bounds what a *deterministically spaced* attacker needs
// against a *dispersion-free* chain. Neither assumption holds on a real network,
// and it is a necessary condition rather than a safe margin. Below the threshold
// an attacker cannot move the target deterministically; that is the whole of
// what it says.
//
// Nothing here asserts on any of that, on purpose. A test that asserted the
// honest chain *does* run away, or that a 16 % attacker *does* reach the
// ceiling, would be a test asserting a bug, and it would fail the day the
// window-average normalisation lands — which is the same objection this file
// raises against the version of itself it replaced. The assertions below are
// deliberately statements about this model, and the model is now stated in full
// so that they can be read as such.

// realInterval is the simulation's clock: how long, in milliseconds, a block
// really takes at this target, given that a block at the genesis target takes
// exactly the goal.
//
// Two-sided, and that is the whole repair. `goal * genesis / target` grows
// without bound as the target collapses (the freeze) and shrinks toward zero as
// the target rises (the residual), so the worst and the best real interval
// reached over a run witness the two directions separately.
func realInterval(goalMillis uint64, target, genesis u256.U256) uint64 {
	if target.IsZero() {
		return ^uint64(0)
	}
	gb, tb := genesis.Bytes(), target.Bytes()
	q := new(big.Int).SetBytes(gb[:])
	q.Mul(q, new(big.Int).SetUint64(goalMillis))
	q.Div(q, new(big.Int).SetBytes(tb[:]))
	if !q.IsUint64() {
		return ^uint64(0) // saturated: the chain is frozen
	}
	return q.Uint64()
}

// burst is the freeze's attacker: the first n blocks of the run, consecutively,
// which is what it takes to capture a MEDIAN_TIME_BLOCKS window outright.
func burst(n int) func(int) bool { return func(i int) bool { return i < n } }

// share is an attacker holding num/den of the hashrate, spread evenly across
// the run rather than bunched at the front.
func share(num, den int) func(int) bool {
	return func(i int) bool {
		switch {
		case num <= 0:
			return false
		case num >= den:
			return true
		default:
			return (i*num)%den < num
		}
	}
}

// outcome is what a run witnesses. Two intervals and two targets, because a
// one-sided summary is exactly what made the previous version of this file
// unable to see the bug it now reports.
type outcome struct {
	worstInterval uint64 // ms — the freeze direction
	bestInterval  uint64 // ms — the runaway direction
	minTarget     u256.U256
	maxTarget     u256.U256
	finalTarget   u256.U256
	pinnedAt      int // first block whose target is MaxTarget, or -1
}

// run mines `blocks` blocks on a healthy window against the real
// `pow.NextTarget`, with `attacker(i)` deciding who won block i and the winner
// dating it `push` seconds ahead of real time when it is the attacker.
//
// A push of `FutureTimeLimitSeconds - 1` is legal under the withhold rule this
// PR adds: never queued, never scored, forwarded normally. That is the point.
func run(p *params.Params, push uint64, attacker func(int) bool, blocks int) outcome {
	goalMillis := p.TargetBlockSeconds * 1000
	window := make([]types.Header, 0, int(p.DifficultyWindow)+1)
	for i := 0; i <= int(p.DifficultyWindow); i++ {
		window = append(window, types.Header{
			Height: uint64(i),
			Time:   p.GenesisTime + uint64(i)*p.TargetBlockSeconds,
			Target: p.GenesisTarget,
		})
	}
	realMillis := window[len(window)-1].Time * 1000

	out := outcome{
		bestInterval: ^uint64(0),
		minTarget:    p.GenesisTarget,
		maxTarget:    p.GenesisTarget,
		pinnedAt:     -1,
	}

	for i := 0; i < blocks; i++ {
		target := pow.NextTarget(window, p)
		if target.Lt(out.minTarget) {
			out.minTarget = target
		}
		if target.Gt(out.maxTarget) {
			out.maxTarget = target
		}
		if out.pinnedAt < 0 && target.Eq(p.MaxTarget) {
			out.pinnedAt = i
		}

		d := realInterval(goalMillis, target, p.GenesisTarget)
		if d > out.worstInterval {
			out.worstInterval = d
		}
		if d < out.bestInterval {
			out.bestInterval = d
		}
		if d == ^uint64(0) {
			realMillis = d
		} else {
			realMillis += d
		}

		ts := realMillis / 1000
		if attacker(i) {
			ts += push
		} else if floor := pow.MedianTime(window, p) + 1; ts < floor {
			// node/miner.headerTime's own ratchet, untouched by this PR.
			ts = floor
		}

		window = append(window, types.Header{
			Height: window[len(window)-1].Height + 1,
			Time:   ts,
			Target: target,
		})
		if len(window) > int(p.DifficultyWindow)+1 {
			window = window[len(window)-(int(p.DifficultyWindow)+1):]
		}
	}
	out.finalTarget = window[len(window)-1].Target
	return out
}

// ---------------------------------------------------------------------------
// The control: an honest chain must not move at all.
// ---------------------------------------------------------------------------

// TestTheHonestBaselineDoesNotMove is the model's own calibration. Every number
// below is a difference from this one, so if this drifts nothing else means
// anything.
func TestTheHonestBaselineDoesNotMove(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *params.Params
	}{{"devnet", spec.Devnet()}, {"mainnet", spec.Mainnet()}} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.p
			goalMillis := p.TargetBlockSeconds * 1000
			got := run(p, 0, share(0, 1), 600)
			t.Logf("%s honest worst=%d ms best=%d ms final=%s",
				tc.name, got.worstInterval, got.bestInterval, got.finalTarget.String())
			if got.worstInterval != goalMillis || got.bestInterval != goalMillis {
				t.Fatalf("an honest chain produced intervals between %d ms and %d ms "+
					"against a %d ms goal: the model is not at rest and every "+
					"excursion measured below is partly its own",
					got.bestInterval, got.worstInterval, goalMillis)
			}
			if !got.finalTarget.Eq(p.GenesisTarget) || !got.minTarget.Eq(p.GenesisTarget) ||
				!got.maxTarget.Eq(p.GenesisTarget) {
				t.Fatalf("an honest chain moved the target off genesis: min=%s max=%s",
					got.minTarget.String(), got.maxTarget.String())
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The downward direction: the median-push freeze, which this PR closes.
// ---------------------------------------------------------------------------

// TestAnUnboundedMedianPushNoLongerFreezesTheChain is the freeze as filed, run
// against the current controller. It used to be the control proving the model
// could still see the freeze at 60 blocks; the window-average normalisation
// closes it at that horizon, so the same scenario is kept as the regression
// guard that it stays closed.
func TestAnUnboundedMedianPushNoLongerFreezesTheChain(t *testing.T) {
	p := spec.Devnet()

	// The filed attack's own timestamp: 10^9 seconds ahead, which is what an
	// ingress path with no future-time bound accepts. Six consecutive blocks is a
	// majority of the eleven-block median window, which is all the attack
	// requires.
	got := run(p, 1_000_000_000, burst(6), 60)

	t.Logf("unbounded worst=%d ms min-target=%s final=%s",
		got.worstInterval, got.minTarget.String(), got.finalTarget.String())
	// What the controller fixes changed, and what they did not.
	//
	// This assertion used to require worstInterval >= one year at 60 blocks: the
	// unbounded push froze the chain almost immediately, because NextTarget
	// floored a backwards solve time at zero and then re-applied each ratchet on
	// top of the previous one by normalising against the window's last target.
	//
	// With the accumulator signed and the ratio normalised against the
	// window's average, the same attack is enormously slower: at 60 blocks the
	// worst real interval is ~21 s against a 5 s goal, where it used to be
	// beyond a year. It is NOT closed outright — an unbounded timestamp can
	// push the median forward indefinitely, and over 400 blocks the excursion
	// still reaches ~1.9 years (see TestTheFutureTimeLimitClosesTheDownwardCollapse,
	// which is what actually closes it and measures both arms). The bound
	// asserted here is the 60-block one, deliberately: it is the horizon at
	// which the old rule had already frozen, so a regression that restored
	// either controller defect fails here first.
	if got.worstInterval > 10*60*1000 {
		t.Fatalf("the worst real block interval was %d ms against a %d ms goal "+
			"within 60 blocks: the signed accumulator and the window-average "+
			"normalisation are supposed to keep a median push from ratcheting "+
			"the target down this fast", got.worstInterval, p.TargetBlockSeconds*1000)
	}
	if got.finalTarget.Lt(p.GenesisTarget.MulDiv64(1, 1<<3)) {
		t.Fatalf("the target ended at %s against a genesis of %s: more than 8x "+
			"harder within 60 blocks is the ratchet these fixes remove",
			got.finalTarget.String(), p.GenesisTarget.String())
	}
}

// TestTheFutureTimeLimitClosesTheDownwardCollapse is the half of the freeze
// this PR genuinely closes: the same burst, bounded by FTL, does not freeze the
// chain.
//
// The bounds are set within about a factor of two of the measurement rather
// than at a round "no worse than a day". The previous version asserted
// `worst > 24*3600` against a measured 40 s and would have passed a regression
// that made the excursion five hundred times larger.
func TestTheFutureTimeLimitClosesTheDownwardCollapse(t *testing.T) {
	for _, tc := range []struct {
		name        string
		p           *params.Params
		worstMillis uint64 // measured: devnet 91_532, mainnet 53_435
		minShift    uint64 // measured: devnet genesis/18.5, mainnet genesis/1.8
	}{
		{"devnet", spec.Devnet(), 200_000, 5},
		{"mainnet", spec.Mainnet(), 120_000, 2},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := tc.p
			got := run(p, p.FutureTimeLimitSeconds-1, burst(6), 400)
			t.Logf("%s bounded worst=%d ms (goal %d ms) min-target=%s final=%s genesis=%s",
				tc.name, got.worstInterval, p.TargetBlockSeconds*1000,
				got.minTarget.String(), got.finalTarget.String(), p.GenesisTarget.String())

			if got.worstInterval > tc.worstMillis {
				t.Fatalf("the worst real block interval was %d ms against a %d ms "+
					"goal and a %d ms bound: bounding the push by FTL did not bound "+
					"the freeze", got.worstInterval, p.TargetBlockSeconds*1000, tc.worstMillis)
			}
			if got.minTarget.Lt(p.GenesisTarget.MulDiv64(1, 1<<tc.minShift)) {
				t.Fatalf("the target reached %s, more than 2^%d below a genesis of "+
					"%s: the excursion is not bounded where the PR says it is",
					got.minTarget.String(), tc.minShift, p.GenesisTarget.String())
			}
			// And it recovers, rather than merely not collapsing.
			if got.finalTarget.Lt(p.GenesisTarget.MulDiv64(1, 2)) {
				t.Fatalf("the target ended at %s, below half of genesis: the chain "+
					"did not recover", got.finalTarget.String())
			}

			// The discrimination, in this test's own scenario: bounding the push
			// has to be what made the difference, not the model being placid.
			unbounded := run(p, 1_000_000_000, burst(6), 400)
			if unbounded.worstInterval/1000 <= got.worstInterval {
				t.Fatalf("bounded reached %d ms and unbounded %d ms: fewer than "+
					"three orders of magnitude apart, so this test is not measuring "+
					"the bound", got.worstInterval, unbounded.worstInterval)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The upward direction: the residual this PR does NOT close.
// ---------------------------------------------------------------------------

// TestTheEquilibriumThresholdIsGoalOverFTL fixes the threshold as arithmetic
// over the shipped params, so a params change that moves it cannot pass while
// the PR body, docs/ARCHITECTURE.md and the params commentary still quote the
// old number.
func TestTheEquilibriumThresholdIsGoalOverFTL(t *testing.T) {
	for _, tc := range []struct {
		name    string
		p       *params.Params
		permil  uint64
		quoting string
	}{
		{"mainnet", spec.Mainnet(), 166, "16.7%"},
		{"devnet", spec.Devnet(), 27, "2.8%"},
	} {
		got := tc.p.TargetBlockSeconds * 1000 / tc.p.FutureTimeLimitSeconds
		t.Logf("%s goal=%ds FTL=%ds threshold=%d per mille",
			tc.name, tc.p.TargetBlockSeconds, tc.p.FutureTimeLimitSeconds, got)
		if got != tc.permil {
			t.Fatalf("%s goal/FTL is %d per mille; the PR body, docs and the "+
				"params commentary all quote %s", tc.name, got, tc.quoting)
		}
	}
}

// TestTheSignedAccumulatorClosesTheUpwardRunaway is the inverted form of what
// this file asserted before the accumulator was signed.
//
// The finding it used to record was real: a minority dating every block it
// wins at `now + FTL - 1` is never withheld, never scored and perfectly legal,
// and each such block donated `FTL - 1` to the LWMA's weighted sum while the
// honest block after it donated nothing instead of the compensating negative,
// because `pow.NextTarget` clipped solve times at `max(0, delta)`. Above
// `p ≈ goal/FTL` the target walked to `MaxTarget` and stayed there, where
// `BlockWork` is 63 for every header and fork choice degenerates toward a
// block count.
//
// Signing the accumulator removed the clip: it is signed and clamped
// symmetrically, so the backdated (or forward-dated) interval's charge is no
// longer discarded, and the pair of intervals a manipulated timestamp touches
// cancels instead of donating. This test now asserts that closure directly, at
// the shares the old bracket said were doomed — and it is written so that
// restoring the clip fails it, which is the only property that makes it a
// regression guard rather than a record.
func TestTheSignedAccumulatorClosesTheUpwardRunaway(t *testing.T) {
	p := spec.Mainnet()
	push := p.FutureTimeLimitSeconds - 1
	goalMillis := p.TargetBlockSeconds * 1000

	// Every share the clipped rule drove to the ceiling — including the two the
	// old bracket asserted were unbounded (17 %, 25 %) — and 50 %, which is far
	// past anything the old threshold contemplated.
	for _, num := range []int{10, 16, 17, 25, 50} {
		got := run(p, push, share(num, 100), 600)
		t.Logf("mainnet p=%d%% pinned=%d best=%d ms max=%s final=%s",
			num, got.pinnedAt, got.bestInterval, got.maxTarget.String(), got.finalTarget.String())

		if got.pinnedAt >= 0 {
			t.Fatalf("a %d%% attacker dating at now+FTL-1 reached MaxTarget at "+
				"block %d. With the signed accumulator the donation each "+
				"manipulated timestamp makes is cancelled by the charge on the "+
				"interval that follows it, so no share below 100%% has a "+
				"runaway; reaching the ceiling means the clip is back",
				num, got.pinnedAt)
		}
		if got.bestInterval == 0 {
			t.Fatalf("a %d%% attacker drove the real block interval below one "+
				"millisecond: the target is still being walked upward", num)
		}
		// The bound that says the controller is still doing its job rather
		// than merely not saturating: the fastest block in the run is within
		// an order of magnitude of the goal. Under the retired clip this
		// collapses toward zero as the target runs away.
		if got.bestInterval*10 < goalMillis {
			t.Fatalf("a %d%% attacker pulled the fastest real interval to %d ms, "+
				"more than 10x below the %d ms goal: the target is being walked "+
				"upward even though it has not reached the ceiling",
				num, got.bestInterval, goalMillis)
		}
	}
}

// TestAUniversalOffsetIsNotAnAttack is the control, and it is here to be
// labelled rather than to be evidence.
//
// When *every* miner pushes by the same amount the offset is very nearly
// constant, so there is no sustained bias — only the single step where the
// pushed run begins. An older version of this file reported this case as
// "200 poisoned of 200, sustained: 5 s, the goal exactly" and read it as
// evidence that a sustained attacker does no damage. It is not evidence: it is
// the one share at which there is *no* attacker, because there is nobody left
// to be attacked.
//
// Before the accumulator was signed the honest statement was comparative — a
// universal offset stays put while a 25 % minority using the very same
// timestamps pins at the ceiling — and the contrast carried the test. With the
// accumulator signed, neither reaches the ceiling, so the contrast is gone and
// the control can no longer borrow its meaning from a runaway. What remains is
// the part that was always this test's own claim, and it is asserted directly:
// a constant added to every timestamp is not a derivative, so it must move the
// target by at most the single boundary step where the run begins.
func TestAUniversalOffsetIsNotAnAttack(t *testing.T) {
	p := spec.Mainnet()
	push := p.FutureTimeLimitSeconds - 1

	universal := run(p, push, share(1, 1), 600)
	t.Logf("mainnet p=100%% (universal offset) pinned=%d max-target=%s final=%s",
		universal.pinnedAt, universal.maxTarget.String(), universal.finalTarget.String())
	if universal.pinnedAt >= 0 {
		t.Fatalf("a universal offset reached MaxTarget at block %d; a constant "+
			"added to every timestamp is not a derivative and must not accumulate",
			universal.pinnedAt)
	}
	// Measured peak is ~1.13x genesis — the one-time step where the pushed run
	// begins, which the window then walks past. The 4x bound below is kept
	// deliberately loose around it: this assertion is about that single
	// boundary step being a step and not an accumulation, not about the
	// exact figure.
	if universal.maxTarget.Gt(p.GenesisTarget.MulDiv64(4, 1)) {
		t.Fatalf("a universal offset moved the target to %s, more than 4x a "+
			"genesis of %s: that is more than the single boundary step the "+
			"algebra allows", universal.maxTarget.String(), p.GenesisTarget.String())
	}

	// The minority no longer diverges to the ceiling — that is the signed
	// accumulator's whole point — so what is asserted is that it stays in the same
	// bounded regime the universal offset does, rather than that it escapes it.
	minority := run(p, push, share(25, 100), 600)
	t.Logf("mainnet p=25%% pinned=%d max-target=%s final=%s",
		minority.pinnedAt, minority.maxTarget.String(), minority.finalTarget.String())
	if minority.pinnedAt >= 0 {
		t.Fatalf("a 25%% attacker reached MaxTarget at block %d; with the signed "+
			"accumulator it must not", minority.pinnedAt)
	}
}

// TestDevnetsFasterGoalKeepsTheChainOffTheCeiling records the parameter-set
// half of the same closure.
//
// Devnet compounds two things that used to make it far more fragile than
// mainnet: a 5 s goal puts the old `p < goal/FTL` threshold at 2.8 %, a sixth
// of mainnet's, and devnet's `max_target` sits only 8x above its genesis target
// rather than mainnet's 4096x. Before it was signed a **1 %** attacker pinned
// devnet at the ceiling within ten blocks. It is worth keeping a devnet case
// here for exactly that reason — a rule that only holds on the parameter set
// with the most headroom has not been shown to hold.
func TestDevnetsFasterGoalKeepsTheChainOffTheCeiling(t *testing.T) {
	p := spec.Devnet()
	push := p.FutureTimeLimitSeconds - 1

	for _, num := range []int{1, 10, 25} {
		got := run(p, push, share(num, 100), 600)
		t.Logf("devnet p=%d%% pinned=%d final=%s (ceiling %s)",
			num, got.pinnedAt, got.finalTarget.String(), p.MaxTarget.String())
		if got.pinnedAt >= 0 {
			t.Fatalf("a %d%% attacker reached devnet's MaxTarget at block %d; "+
				"with the signed accumulator no share below 100%% may, and "+
				"devnet is the parameter set where the old rule failed at 1%%",
				num, got.pinnedAt)
		}
	}

	// And the chain stays off the ceiling with no attacker at all, so the
	// assertions above are about the rule and not about devnet's headroom.
	if honest := run(p, push, share(0, 1), 600); honest.pinnedAt >= 0 {
		t.Fatalf("an honest devnet chain reached MaxTarget at block %d; the "+
			"cases above are measuring the params, not the attack", honest.pinnedAt)
	}
}
