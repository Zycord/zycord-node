// Package miner assembles blocks.
//
// The selection policy lives here and nowhere else. It used to exist twice —
// once in the simulator's incentive tests and once, notionally, in the node —
// and "mirroring by discipline" is how two implementations of one policy
// diverge a year later without anybody noticing (M1-G5). The simulator now
// imports this package, so there is one implementation and drift is not
// possible rather than merely discouraged.
//
// Nothing here is consensus. The fold judges blocks; it does not care how they
// were assembled. What this package must get right is the *incentive*: a
// builder maximising its own revenue has to be doing what the network needs,
// which is what the property tests in sim/ check.
package miner

import (
	"sort"

	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
)

// Select chooses a revenue-maximising subset of a pool under the block
// ceilings.
//
// t is the sequential target T (whitepaper §8.1) — the caller's state read,
// not a params constant any more. Selection targets the soft ceiling 2T
// (p.SeqGasLimit(t)), never the hard burst bound 4T: bursting trades a
// quadratic slice of the producer's own subsidy for extra tip revenue, a real
// optimisation this heuristic does not attempt, so the conservative default
// is to never trigger it. A builder that wants to burst deliberately is a
// future refinement, not a silent default.
//
// The problem is a two-dimensional knapsack — sequential and parallel gas have
// separate ceilings — which is NP-hard, so this greedily takes the highest
// revenue per unit of whichever resource a certificate consumes most of
// relative to its ceiling. That heuristic is what makes the sequential tip
// matter: under a binding sequential ceiling the ranking collapses to revenue
// per unit of sequential gas, which is the scarce resource (I1-H2).
func Select(pool []*types.Certificate, p *params.Params, seqBaseFee, parBaseFee u256.U256, t uint64) []*types.Certificate {
	seqLimit := p.SeqGasLimit(t)
	parLimit := p.ParGasLimit(t)

	type scored struct {
		cert *types.Certificate
		tip  u256.U256
		// weight is consumption of the scarcer resource on a common
		// denominator of seqLimit x parLimit, so two certificates compare
		// without floating point.
		weight u256.U256
		seqGas uint64
		parGas uint64
		// id is Certificate.ID cached once here. ID marshals the body and
		// BLAKE3-hashes it and is not memoised, so calling it from inside the
		// tie-break comparator would recompute it O(n log n) times per mining
		// attempt — the same recomputation the mempool removed from its own
		// sort comparator, which now reads its own cached entry.id.
		id types.Hash
	}

	candidates := make([]scored, 0, len(pool))
	for _, c := range pool {
		seqGas, parGas := c.SeqGas(p), c.ParGas(p)
		if seqGas > seqLimit || parGas > parLimit {
			continue // cannot fit in any block
		}
		if c.FeeBid.SeqMax.Lt(seqBaseFee) || c.FeeBid.ParMax.Lt(parBaseFee) {
			continue // B4 would make the block invalid
		}
		seqShare, _ := u256.FromUint64(seqGas).Mul(u256.FromUint64(parLimit))
		parShare, _ := u256.FromUint64(parGas).Mul(u256.FromUint64(seqLimit))
		candidates = append(candidates, scored{
			cert:   c,
			tip:    c.MinerTip(p, seqBaseFee, parBaseFee),
			weight: u256.MaxOf(seqShare, parShare),
			seqGas: seqGas,
			parGas: parGas,
			id:     c.ID(),
		})
	}

	// Rank by tip/weight, compared as tip_a x weight_b ? tip_b x weight_a to
	// stay in integers. Ties break by certificate id so the result is a pure
	// function of the pool.
	sort.SliceStable(candidates, func(i, j int) bool {
		a, b := candidates[i], candidates[j]
		left, leftOver := a.tip.Mul(b.weight)
		right, rightOver := b.tip.Mul(a.weight)
		if leftOver != rightOver {
			// leftOver means a's true cross product exceeded 2^256 while b's
			// did not, so a's fee density is the larger and a sorts first.
			return leftOver
		}
		if cmp := left.Cmp(right); cmp != 0 {
			return cmp > 0
		}
		return string(a.id[:]) < string(b.id[:])
	})

	var (
		out     []*types.Certificate
		seqUsed uint64
		parUsed uint64
		bytes   int
	)
	certCeiling := p.MaxCertsPerBlock(t)
	byteCeiling := p.BlockByteLimit(t)
	for _, c := range candidates {
		if len(out) >= certCeiling {
			break
		}
		if seqUsed+c.seqGas > seqLimit || parUsed+c.parGas > parLimit {
			continue
		}
		// The ceiling is measured against the encoded *block*, so the envelope
		// has to be reserved here or the builder packs a set that only its own
		// certificates fit into. Summing certificate sizes alone overshoots by
		// the header plus four bytes per certificate — 10,816 bytes at the
		// genesis ceilings, enough that `checkBlockRules` refuses the
		// candidate, `Assemble` errors, and the mining loop retries the same
		// set forever while the pool stays full.
		// MaxCitesPerBlock rather than the count this block will actually
		// carry: Select runs before the assembler chooses citations, and
		// reserving the maximum costs under a thousandth of the ceiling while
		// removing any chance of the two disagreeing.
		if types.BlockOverheadBytes(len(out)+1, p.MaxCitesPerBlock)+bytes+c.cert.SizeBytes() > byteCeiling {
			continue
		}
		out = append(out, c.cert)
		seqUsed += c.seqGas
		parUsed += c.parGas
		bytes += c.cert.SizeBytes()
	}
	return out
}

// Revenue is what a builder earns from a selected set, assuming every
// certificate applies. Emission is excluded: it is identical whatever the block
// contains, so it cannot influence ordering.
func Revenue(certs []*types.Certificate, p *params.Params, seqBaseFee, parBaseFee u256.U256) u256.U256 {
	total := u256.Zero
	for _, c := range certs {
		total = total.SatAdd(c.MinerTip(p, seqBaseFee, parBaseFee))
	}
	return total
}
