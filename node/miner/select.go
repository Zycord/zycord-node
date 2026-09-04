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
// Every block ceiling the fold enforces is enforced here too: B5 and B6 by the
// gas limits, B12 by the certificate count, B13 by the running byte total, and
// B18 by the running signature total. The list has to be complete rather than
// nearly complete, and B18 is the one that was missing (I8-M1). A ceiling this
// function ignores is not a packing inefficiency: the assembler dry-runs its
// own candidate, and a block-level ceiling has no culpable certificate to name,
// so the refusal comes back through invalid() with no index. dropTheDrops'
// recovery needs an index, finds none, and Assemble returns an error instead of
// a block — for every attempt, until the offending certificates age out of
// their own TTL window. One over-dense pool, no blocks at all.
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
		out      []*types.Certificate
		seqUsed  uint64
		parUsed  uint64
		sigsUsed uint64
		bytes    int
	)
	certCeiling := p.MaxCertsPerBlock(t)
	byteCeiling := p.BlockByteLimit(t)
	sigCeiling := p.MaxSigsPerBlock(t)
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
		// B18, the receiver-cost bound: the block's certificates may declare
		// at most MaxSigsPerBlock(T) signatures between them, counted before
		// the fold verifies any of them.
		//
		// Skipped rather than break, exactly like the two ceilings above: a
		// certificate that does not fit is passed over and a cheaper one
		// further down the ranking may still fit, which is the whole point of
		// packing greedily. No new policy is introduced by this line — which
		// certificates are dropped is decided where it always was, by the
		// tip-density ranking above, and B18 only says how many fit.
		//
		// The sum cannot overflow: certCeiling bounds the iterations and V1
		// bounds each certificate at max_sigs, so this is a product of two
		// int-sized ceilings, far inside uint64 — the same argument
		// checkBlockRules makes for its own accumulator.
		sigs := uint64(len(c.cert.Sigs))
		if sigsUsed+sigs > sigCeiling {
			continue
		}
		out = append(out, c.cert)
		seqUsed += c.seqGas
		parUsed += c.parGas
		sigsUsed += sigs
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
