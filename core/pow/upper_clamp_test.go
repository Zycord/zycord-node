package pow_test

import (
	"testing"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
)

// diffWindowVaryingTargets mirrors spec/gen's helper of the same purpose: a
// window where each header can declare its own target, needed because most
// of this package's other helpers (chain, header repeated) hold Target
// uniform across the window, which cannot exercise the window-average
// normalization at all.
func diffWindowVaryingTargets(times []uint64, targets []u256.U256) []types.Header {
	out := make([]types.Header, len(times))
	var prev *types.Header
	for i, t := range times {
		out[i] = header(uint64(i), t, targets[i])
		if prev != nil {
			out[i].ParentID = prev.ID()
		}
		prev = &out[i]
	}
	return out
}

// TestUpperPerBlockClampIsReachable is the empirical half of the corrected
// comment in core/pow/pow.go's NextTarget: before the ratio was normalised
// against the window average, the per-block clamp's upper half
// (next.Gt(upper)) was provably dead code, because the ratio NextTarget
// computes was applied to `last` itself — the same value `upper` is derived
// from — so the ratio's own DifficultyClampFactor ceiling made next ≤ upper
// unconditionally.
//
// The window-average normalisation changes what the ratio is applied to:
// `mean`, the window's average target, not `last`. Once base and bound
// reference are different quantities, a window whose earlier
// (about-to-age-out) headers declare much larger targets than the window's
// own last header — i.e. the target has been falling — pulls `mean` above
// `last`. Applying even a neutral (multiplier ~1) ratio to that inflated
// mean can then land above last×DifficultyClampFactor, which is exactly what
// this test constructs and confirms: the per-block clamp's upper half must
// fire, or this scenario could not tell "the clamp is live" from "the clamp
// is dead code that happens not to matter here."
func TestUpperPerBlockClampIsReachable(t *testing.T) {
	p := spec.Mainnet()
	goal := p.TargetBlockSeconds
	window := int(p.DifficultyWindow)

	// Neutral solve times throughout (every gap exactly `goal`), so the
	// weighted-average-solve-time ratio contributes almost exactly 1 — this
	// scenario's whole point is that the CLAMP fires from the mean/last
	// divergence alone, not from any solve-time manipulation.
	times := make([]uint64, window+1)
	for i := range times {
		times[i] = uint64(i) * goal
	}

	// Every header except the last declares a target 20x the last header's —
	// the window "remembers" a much easier recent past that the difficulty
	// has since (legitimately) hardened away from. mean ≈ (90×20g + g)/91 ≈
	// 19.8g, comfortably above last×DifficultyClampFactor = last×16 = 16g
	// (last = g here), so an unclamped next (≈19.8g) would exceed upper
	// (16g) and the clamp must visibly act.
	targets := make([]u256.U256, window+1)
	inflated := p.GenesisTarget.MulDiv64(20, 1)
	for i := range targets {
		targets[i] = inflated
	}
	targets[len(targets)-1] = p.GenesisTarget // `last` is the small one.

	headers := diffWindowVaryingTargets(times, targets)
	got := pow.NextTarget(headers, p)

	last := p.GenesisTarget
	upper := last.MulDiv64(p.DifficultyClampFactor, 1)
	if got.Gt(upper) {
		t.Fatalf("next target %s exceeds the per-block upper clamp %s "+
			"(last×DifficultyClampFactor) — the clamp did not fire", got.String(), upper.String())
	}
	if !got.Eq(upper) {
		t.Fatalf("next target %s does not equal the upper clamp %s exactly — "+
			"the unclamped mean-based computation should exceed it here, so the clamp's "+
			"OWN value should be what answers", got.String(), upper.String())
	}
}
