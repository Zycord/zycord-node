package pow_test

import (
	"math"
	"math/big"
	"math/rand"
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
)

// simulateHonestPoisson is this package's other simulators with two changes
// and no others:
//
//  1. there is no attacker at all — every timestamp is truthful;
//  2. block solve times are exponentially distributed around their expected
//     value, which is what proof of work actually produces, instead of being
//     exactly equal to it.
//
// The expected value is the same one simulateInterleavedAttacker uses:
// goal*(GenesisTarget/target) for a fixed hashrate. Only the variance is new.
func simulateHonestPoisson(
	p *params.Params, next func([]types.Header, *params.Params) u256.U256, blocks int, seed int64,
) []types.Header {
	goal := float64(p.TargetBlockSeconds)
	rng := rand.New(rand.NewSource(seed))
	const base = 10_000_000_000

	headers := make([]types.Header, 1, blocks+1)
	headers[0] = header(0, base, p.GenesisTarget)
	realTime := float64(base)

	for i := 1; i <= blocks; i++ {
		target := next(headers, p)
		expected := goal * ratioGenesisOver(target, p)
		solve := rng.ExpFloat64() * expected
		if solve < 0 {
			solve = 0
		}
		realTime += solve
		headers = append(headers, header(uint64(i), uint64(realTime), target))
	}
	return headers
}

// TestHonestChainWithPoissonSolveTimesStaysBounded is the control this
// package's backdating and clamp measurements never ran: no attacker, no
// backdating, no clustering — just a truthful chain at constant hashrate with
// the solve-time variance proof of work always has.
//
// If the difficulty rule is a stable controller, the target stays near the
// value the hashrate implies. If it is not, this test reaches MaxTarget with
// nobody attacking anything, which means any failures other tests attribute
// to an attacker could equally be the controller's own instability being
// excited by whatever noise the simulation happens to contain. This is a
// permanent regression guard, not a one-off investigation: an honest chain
// must never reach MaxTarget from ordinary Poisson solve-time variance alone.
//
// Unskipped once the ratio was normalised against the window average. This
// test failed against the signed solve-time accumulator alone — an honest
// chain with realistic exponential solve-time variance reached MaxTarget in
// as few as ~464-2,159 blocks. The cause is not the sign convention and not
// the per-block/per-window clamp question: it is that normalising the ratio
// against the window's LAST target leaves the retarget loop only marginally
// stable (dominant pole |z| ~ 0.9993, a memory of ~1,500 blocks), so it
// integrates solve-time noise into a random walk wide enough to cross
// mainnet's 12 bits of headroom. Normalising against the window's AVERAGE
// target moves the pole to ~0.9785 and turning that walk into a stationary
// spread of ~0.15 bits — see core/pow/pow.go's NextTarget doc comment for
// the full derivation, and note that the fixed loop still has non-zero DC
// gain (it must, to track hashrate at all).
func TestHonestChainWithPoissonSolveTimesStaysBounded(t *testing.T) {
	p := spec.Mainnet()
	const blocks = 100000

	for _, seed := range []int64{1, 2, 3} {
		headers := simulateHonestPoisson(p, pow.NextTarget, blocks, seed)
		worst := 0.0
		for _, h := range headers {
			if r := ratioFloatForTest(h.Target, p); r > worst {
				worst = r
			}
		}
		for _, h := range headers {
			if h.Target.Eq(p.MaxTarget) {
				t.Errorf("seed %d: an HONEST chain — every timestamp truthful, hashrate "+
					"constant, only ordinary Poisson solve-time variance — reached the literal "+
					"MaxTarget ceiling at block %d (worst target/genesis ratio over the run: "+
					"%.4g). No attacker is present, so this is the controller's own stability, "+
					"not timestamp manipulation.", seed, h.Height, worst)
				break
			}
		}
	}
}

// TestHonestChainWithPoissonSolveTimesStaysBoundedLongRun sweeps more seeds
// and a longer run than the primary control test above, at the scale the
// root-cause analysis behind the window-average normalisation used for
// independent verification (1,000,000 blocks). Kept separate so `go test
// -short` still runs the fast version by default while the full suite also
// exercises the deeper sweep.
func TestHonestChainWithPoissonSolveTimesStaysBoundedLongRun(t *testing.T) {
	if testing.Short() {
		t.Skip("long-run honest-chain sweep skipped under -short")
	}
	p := spec.Mainnet()
	const blocks = 1_000_000

	for _, seed := range []int64{11, 22, 33} {
		headers := simulateHonestPoisson(p, pow.NextTarget, blocks, seed)
		for _, h := range headers {
			if h.Target.Eq(p.MaxTarget) {
				t.Fatalf("seed %d: honest chain reached MaxTarget at block %d over a "+
					"%d-block run", seed, h.Height, blocks)
			}
		}
	}
}

// ratioGenesisOver returns GenesisTarget/target as a float64: the factor by
// which a block is expected to take longer than the goal at the hashrate that
// solves GenesisTarget in exactly goal seconds.
func ratioGenesisOver(target u256.U256, p *params.Params) float64 {
	r := ratioFloatForTest(target, p)
	if r <= 0 || math.IsInf(r, 0) {
		return 1
	}
	return 1 / r
}

// ratioFloatForTest returns target/GenesisTarget as a float64.
func ratioFloatForTest(target u256.U256, p *params.Params) float64 {
	tb := target.Bytes()
	gb := p.GenesisTarget.Bytes()
	tf := new(big.Float).SetInt(new(big.Int).SetBytes(tb[:]))
	gf := new(big.Float).SetInt(new(big.Int).SetBytes(gb[:]))
	f, _ := new(big.Float).Quo(tf, gf).Float64()
	return f
}
