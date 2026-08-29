//go:build ceilingsweep

// The exhaustive form of the ceiling differential, kept out of `make ci`.
//
// `go test -tags ceilingsweep ./core/params/ -run TestEveryBlockCeiling`
//
// # Why this is gated and the targeted form is not
//
// Rule 21's argument for enumerating a space rather than sampling it is an
// argument about UNKNOWN-UNKNOWNS in a space nobody has bounded: the widest
// Era-0 certificate was published wrong three times because each search fixed
// a pair on an edge while the optimum sat in the interior of a two-dimensional
// region, and no amount of sweeping along a named axis finds an interior
// optimum. That is the right instinct there and it is the wrong one here.
//
// The block ceilings are a CLOSED-FORM scaling law with named clamps:
// floor(genesis × T / T₀) capped at a constant, plus four fixed multiples of
// T. The space IS bounded, the function is monotone between two named
// discontinuities, and the discontinuities have addresses — 0, T₀, the
// clamp edges, the overflow point, and the targets where each division stops
// dividing exactly. Targeted values at those addresses are not a weaker check
// than enumeration; they are the RIGHT check, and enumeration over a closed
// form is cost without coverage.
//
// Measured rather than argued, which is why this file exists at all instead of
// the sweep simply being deleted: of the nine production mutants in this
// branch's grid, the reviewer re-ran M5, M7 and M9 against the O(1) clamp test
// ALONE and all three still died; M2 and M4 are constant-multiple errors
// visible at a single T ≥ 1. The 133,679,934 comparisons killed nothing that
// a dozen targeted values do not, and they roughly doubled `core/params`'s
// test time on every `make ci` run, forever.
//
// What the sweep is still good for, and why it is gated rather than removed:
// it is the instrument to reach for when the scaling law itself CHANGES — a
// new clamp, a different rounding rule, a non-monotone term — because then the
// closed form the argument above rests on is the thing in question, and the
// addresses of the discontinuities are no longer known in advance.
package params_test

import (
	"fmt"
	"testing"
)

// TestEveryBlockCeilingAgreesWithASecondComputationAtEveryReachableTarget
// enumerates the ceiling table's whole domain rather than sampling it.
//
// Enumeration rather than a stride: MaxCertsPerBlock and BlockByteLimit both
// floor, and a sweep that steps by a round number samples only the exact
// divisions — which is how spec/params.json's own note on
// max_certs_per_block_genesis reported the wrong utilisation interval once.
// For EVERY sequential target ARCHITECTURE §15 admits — T = min(the epoch
// controller's output, SeqGasCapacity) — the six shipped ceilings equal the
// six computed a second time.
//
// The axes it covers: T, exhaustively; and the seven genesis constants, at
// seven points (three shipped, one ratified-and-pending, three synthetic). The
// axis it does NOT cover is the rest of that seven-dimensional space — a
// scaling law wrong only at constants no set here carries survives, and the
// sets were chosen for corners rather than sampled, so this is a statement
// about what was looked at and not a maximum.
func TestEveryBlockCeilingAgreesWithASecondComputationAtEveryReachableTarget(t *testing.T) {
	// Two of the three shipped networks carry byte-identical ceiling
	// constants, and sweeping the second one is 6.4 million comparisons that
	// restate the first. The duplicate is compared at the boundary targets and
	// its full sweep skipped — self-adjusting, because the day testnet's
	// constants diverge from mainnet's the sweep comes back on its own.
	swept := map[string]string{}

	for _, set := range ceilingSets(t) {
		t.Run(set.name, func(t *testing.T) {
			shipped, second := parseBoth(t, set.raw)
			if got, want := second.SeqGasCapacity(), shipped.SeqGasCapacity; got != want {
				t.Fatalf("the two computations disagree about the domain itself: naive %d, shipped %d", got, want)
			}
			domain := shipped.SeqGasCapacity

			key := fmt.Sprintf("%d/%d/%d/%d/%d/%d/%d",
				shipped.MaxCertsPerBlockGenesis, shipped.BlockByteLimitGenesis,
				shipped.SeqGasTargetGenesis, shipped.ParGasRatio,
				shipped.CertListCapacity, shipped.BlockByteCapacity, shipped.SeqGasCapacity)
			if first, dup := swept[key]; dup {
				for _, target := range boundaryTargets(shipped) {
					compareAt(t, shipped, second, target)
				}
				t.Logf("ceiling constants identical to %q; boundary targets compared, full sweep skipped", first)
				return
			}
			swept[key] = set.name

			// Anti-vacuity counters. A sweep that compared nothing, and one
			// that only ever saw a single value of a ceiling, both report the
			// same green as one that covered the domain.
			var comparisons uint64
			var certTruncations, byteTruncations uint64
			// The certificate ceiling is non-decreasing in T, so its distinct
			// values can be counted by comparing against the previous one
			// instead of by a set — tens of millions of map writes, avoided.
			distinctCerts, prevCerts := 0, ^uint64(0)

			for target := uint64(0); target <= domain; target++ {
				certs, blockBytes := compareAt(t, shipped, second, target)
				comparisons += 6
				if certs != prevCerts {
					distinctCerts++
					prevCerts = certs
				}
				if certs*shipped.SeqGasTargetGenesis != uint64(shipped.MaxCertsPerBlockGenesis)*target {
					certTruncations++
				}
				if blockBytes*shipped.SeqGasTargetGenesis != uint64(shipped.BlockByteLimitGenesis)*target {
					byteTruncations++
				}
			}

			if want := 6 * (domain + 1); comparisons != want {
				t.Fatalf("the sweep made %d comparisons, want %d — it did not cover the domain", comparisons, want)
			}
			// The floors carry their measured margin beside them, so that a
			// guard passing at exactly its threshold is visible as one edit
			// from vacuous. Measured at the shipped values: mainnet reaches
			// 12,801 distinct certificate ceilings and devnet 820, against a
			// floor of 64; the truncation counts are in the millions against a
			// floor of 1.
			if distinctCerts < 64 {
				t.Fatalf("the sweep saw only %d distinct certificate ceilings; the scaling law is barely being exercised", distinctCerts)
			}
			if certTruncations == 0 {
				t.Fatal("no target in the whole domain made the certificate ceiling's division truncate; the floor is untested")
			}
			if byteTruncations == 0 {
				t.Fatal("no target in the whole domain made the byte ceiling's division truncate; the floor is untested")
			}
			t.Logf("%d comparisons over T in [0,%d]; %d distinct certificate ceilings; %d and %d truncating targets (count, bytes)",
				comparisons, domain, distinctCerts, certTruncations, byteTruncations)
		})
	}
}
