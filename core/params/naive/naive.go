// Package naive computes whitepaper §8.1's block ceilings a second time,
// written from the specification rather than from the code that ships them.
//
// # Why a second computation exists at all
//
// The sixth external audit measured that both folds — core/fold and the
// deliberately re-implemented sim/refold — call ONE implementation of every
// block ceiling: MaxCertsPerBlock, MaxSigsPerBlock, BlockByteLimit,
// SeqGasLimit, SeqGasBurst, ParGasLimit and ParGasTarget are the same code
// object on both sides of what reads as a differential. Driven rather than
// argued: SeqGasBurst changed from 4T to 8T — B5's hard validity bound — left
// `go test ./spec` green, and only two Go tests holding literal constants
// noticed.
//
// The golden-vector corpus is not the missing second opinion either, and this
// is the part that makes the gap genesis-irreversible. A vector records a
// parameter set by NAME; at replay the name is resolved back through the same
// shared function, so for the ceilings the corpus is one computation performed
// twice rather than two computations compared. The scaling law
// X_genesis × T / T₀ has no frozen artefact anywhere in spec/vectors.
//
// # The boundary, and it is the point of the package
//
// This package MUST NOT reach zycord/core/params or zycord/core/u256 by any
// path. It therefore holds its own arithmetic — a 128-bit multiply-then-divide
// built from math/bits rather than u256.MulDiv64 — and, more importantly, its
// own copies of the eight parameter KEYS as string literals in its own struct
// tags. The literals are the load-bearing part, and they are the analogue of
// the domain tags in core/state/naive: a field read through core/params's
// struct moves when that struct's tag moves, and a differential that shares
// the tag cannot see a change to it. A ceiling scaled by the wrong parameter
// is precisely the divergence nothing else in the tree can observe.
//
// `make check-imports` enforces the boundary against the toolchain's own
// dependency graph rather than against a reading of this import block, in two
// stanzas: one forbidding zycord/core/params and zycord/core/u256 anywhere in
// the transitive closure, one pinning the in-tree dependency count at exactly
// one — itself. Every in-tree package this one gains is a primitive the
// differential stops covering.
//
// # Where the specification was and was not enough
//
// Derived from docs/ARCHITECTURE.md §15 (the ceiling table), spec/README.md
// (which states that MaxCertsPerBlock and BlockByteLimit "both floor" and
// works four numeric examples that pin multiply-before-divide), and
// spec/params.json's own notes on each constant. The ceiling table reads:
//
//	SeqGasLimit(T)      = 2T
//	SeqGasBurst(T)      = 4T
//	ParGasLimit(T)      = ParGasRatio × 2T
//	ParGasTarget(T)     = ParGasRatio × T
//	MaxCertsPerBlock(T) = min(MaxCertsPerBlockGenesis × T / SeqGasTargetGenesis, CertListCapacity)
//	MaxSigsPerBlock(T)  =     MaxSigsPerBlockGenesis  × T / SeqGasTargetGenesis
//	BlockByteLimit(T)   = min(BlockByteLimitGenesis   × T / SeqGasTargetGenesis, BlockByteCapacity)
//
// MaxSigsPerBlock carries no clamp, and the absence is part of the rule rather
// than an omission this package resolved: the count and byte ceilings are
// clamped because CertListCapacity fixes CertRoot's merkle width and
// BlockByteCapacity fixes what a network message can carry, and nothing plays
// either role for a signature count. A clamp invented here would be inert at
// every shipped set and would read as covered, which spec/params.json's note
// on the parameter argues is worse than absent. It saturates instead, at the
// point where the scaled ceiling stops fitting a uint64 — above every
// signature count any block can carry, so the saturated ceiling refuses
// exactly what a representable one would.
//
// Four things the prose does not fix, and how each was resolved here. This
// list is in the package comment rather than in a PR body so that it cannot
// drift out of the code:
//
//  1. The order of the multiply and the divide. Written as a formula it is
//     ambiguous, and it is not a rounding detail: divide-first collapses the
//     mainnet certificate ceiling to zero for every T below 500·T₀. Resolved
//     from spec/README.md's four worked examples, not from core/params — at
//     T = T₀/256 it states a mainnet ceiling of 15 (4000 × 6250 / 1600000 =
//     15.625) and a ceiling+1 block at 94.5% of the byte ceiling (562×16+236
//     = 9228 over 2500000 × 6250 / 1600000 = 9765). Divide-first reproduces
//     neither figure; multiply-then-floor reproduces all four. Both figures
//     are unchanged by the move of T₀ and par_gas_ratio: at T = T₀/D every
//     ceiling is
//     genesis_value/D and T₀ cancels, so only the intermediate literals here
//     moved.
//
//  2. The width of the intermediate product. §15 proves only that no derived
//     quantity overflows because T ≤ SeqGasCapacity. It does not say what an
//     implementation must carry. This package uses an exact 128-bit product
//     via math/bits, which is sufficient because both operands are uint64 and
//     therefore the product is exact in 128 bits — a derivation, not a copy of
//     the shipped 256-bit path.
//
//  3. The behaviour above SeqGasCapacity. §15 defines
//     T = min(controller output, SeqGasCapacity), so nothing in spec/ says
//     what a ceiling returns for a larger T — and the two readings differ
//     observably: re-clamping T inside the ceiling caps MaxCertsPerBlock at
//     12,800 forever, while clamping only the output lets it climb to
//     CertListCapacity. THIS IS THE ONE PLACE THIS PACKAGE IS NOT INDEPENDENT
//     OF THE ONE IT CHECKS: core/params was read, it clamps the output and
//     not the input, and that reading was adopted here. It is recorded as a
//     reading rather than a derivation, here and nowhere else.
//
//     What it costs, and the size of it, because an earlier wording of this
//     paragraph oversold the second half: a CHANGE to the shipped clamp is
//     still caught, since only one side moves, but the two agreeing above
//     SeqGasCapacity says nothing about which reading is right. That is a
//     silence over a domain NOTHING ENTERS, not a live fork. Validate requires
//     seq_gas_capacity >= seq_gas_target_genesis, NextSeqGasTarget clamps to
//     the capacity before flooring at T₀, genesis writes T₀, and spec/gen only
//     ever seeds T below T₀ — so no chain and no vector can present a T above
//     SeqGasCapacity. It is worth one sentence in §15 and no more.
//
//  4. Whether the gas ceilings are defined at all above SeqGasCapacity. They
//     are plain multiplications and §15's overflow proof is conditioned on
//     T ≤ SeqGasCapacity, so this package refuses rather than guessing:
//     SeqGasLimit, SeqGasBurst, ParGasLimit and ParGasTarget return
//     ErrOutOfDomain there. Guessing a wraparound convention and then pinning
//     the guess in a differential would manufacture agreement about an input
//     no chain can present.
package naive

import (
	"encoding/json"
	"errors"
	"fmt"
	"math/bits"
)

// ErrOutOfDomain reports a sequential target above SeqGasCapacity, where
// ARCHITECTURE §15's ceiling table is undefined for the gas ceilings: T is
// min(the epoch controller's output, SeqGasCapacity) by construction, so no
// chain can present one, and no reading of spec/ fixes what a plain
// multiplication should do there.
var ErrOutOfDomain = errors.New("naive: sequential target above seq_gas_capacity")

// Ceilings is the eight genesis constants whitepaper §8.1's ceiling table
// reads, and nothing else. It is deliberately not a parameter set: a second
// computation of the scaling law needs eight numbers, and every further field
// it carried would be a chance to read the wrong one.
type Ceilings struct {
	maxCertsPerBlockGenesis uint64
	maxSigsPerBlockGenesis  uint64
	blockByteLimitGenesis   uint64
	seqGasTargetGenesis     uint64
	parGasRatio             uint64
	certListCapacity        uint64
	blockByteCapacity       uint64
	seqGasCapacity          uint64
}

// wire is the on-disk spelling of those seven constants, with the keys written
// out as string literals. Nothing here may be shared with core/params: a key
// this package inherited would move with the shipped struct and the
// differential could not see it move.
//
// Every field is a pointer so that an ABSENT key is distinguishable from a
// zero one. A parameter file that has been renamed out from under this package
// must fail loudly, not silently scale every ceiling by zero.
type wire struct {
	MaxCertsPerBlockGenesis *uint64 `json:"max_certs_per_block_genesis"`
	MaxSigsPerBlockGenesis  *uint64 `json:"max_sigs_per_block_genesis"`
	BlockByteLimitGenesis   *uint64 `json:"block_byte_limit_genesis"`
	SeqGasTargetGenesis     *uint64 `json:"seq_gas_target_genesis"`
	ParGasRatio             *uint64 `json:"par_gas_ratio"`
	CertListCapacity        *uint64 `json:"cert_list_capacity"`
	BlockByteCapacity       *uint64 `json:"block_byte_capacity"`
	SeqGasCapacity          *uint64 `json:"seq_gas_capacity"`
}

// FromJSON reads the eight constants straight out of a spec/params*.json file.
//
// Taking raw bytes rather than a parsed parameter set is what keeps the two
// computations two: the shipped ceilings read fields off params.Params, and a
// second computation handed the same struct would be re-deriving from the
// first implementation's parse rather than from the protocol's own file.
func FromJSON(raw []byte) (*Ceilings, error) {
	var w wire
	if err := json.Unmarshal(raw, &w); err != nil {
		return nil, fmt.Errorf("naive: parameter file is not JSON: %w", err)
	}
	c := &Ceilings{}
	type field struct {
		key string
		got *uint64
		dst *uint64
	}
	for _, f := range []field{
		{"max_certs_per_block_genesis", w.MaxCertsPerBlockGenesis, &c.maxCertsPerBlockGenesis},
		{"max_sigs_per_block_genesis", w.MaxSigsPerBlockGenesis, &c.maxSigsPerBlockGenesis},
		{"block_byte_limit_genesis", w.BlockByteLimitGenesis, &c.blockByteLimitGenesis},
		{"seq_gas_target_genesis", w.SeqGasTargetGenesis, &c.seqGasTargetGenesis},
		{"par_gas_ratio", w.ParGasRatio, &c.parGasRatio},
		{"cert_list_capacity", w.CertListCapacity, &c.certListCapacity},
		{"block_byte_capacity", w.BlockByteCapacity, &c.blockByteCapacity},
		{"seq_gas_capacity", w.SeqGasCapacity, &c.seqGasCapacity},
	} {
		if f.got == nil {
			return nil, fmt.Errorf("naive: parameter file has no %q", f.key)
		}
		// Every one of the eight is a divisor, a multiplier or a bound, and
		// spec/params.json describes each as positive. Zero is rejected here
		// rather than allowed to divide by zero inside the scaling law.
		if *f.got == 0 {
			return nil, fmt.Errorf("naive: %q is zero", f.key)
		}
		*f.dst = *f.got
	}
	return c, nil
}

// SeqGasCapacity is the upper end of the domain over which ARCHITECTURE §15
// defines the ceiling table: T = min(the epoch controller's output, this).
func (c *Ceilings) SeqGasCapacity() uint64 { return c.seqGasCapacity }

// SeqGasLimit is 2T — B5's forfeiture threshold, the soft ceiling the fee
// market steers toward. It is not the bound a block is rejected for.
func (c *Ceilings) SeqGasLimit(t uint64) (uint64, error) {
	if t > c.seqGasCapacity {
		return 0, ErrOutOfDomain
	}
	return 2 * t, nil
}

// SeqGasBurst is 4T — B5's validity threshold, the bound a block IS rejected
// above. Between 2T and 4T a block is valid and F11 forfeits the producer's
// block revenue — subsidy share plus fees — quadratically against it.
func (c *Ceilings) SeqGasBurst(t uint64) (uint64, error) {
	if t > c.seqGasCapacity {
		return 0, ErrOutOfDomain
	}
	return 4 * t, nil
}

// ParGasLimit is ParGasRatio × 2T (B6). The parallel market has no burst
// valve: this is a hard bound always.
func (c *Ceilings) ParGasLimit(t uint64) (uint64, error) {
	if t > c.seqGasCapacity {
		return 0, ErrOutOfDomain
	}
	return c.parGasRatio * 2 * t, nil
}

// ParGasTarget is ParGasRatio × T — F12b's parallel-market target, exactly
// half of ParGasLimit, which is what bounds the parallel base fee's step to
// the ±12.5% the controller intends without a clamp of its own.
func (c *Ceilings) ParGasTarget(t uint64) (uint64, error) {
	if t > c.seqGasCapacity {
		return 0, ErrOutOfDomain
	}
	return c.parGasRatio * t, nil
}

// MaxCertsPerBlock is B12's certificate-count ceiling:
// min(MaxCertsPerBlockGenesis × T / SeqGasTargetGenesis, CertListCapacity),
// floored. The clamp is structural rather than policy — CertListCapacity fixes
// CertRoot's merkle width, which cannot move with height without changing what
// every earlier CertRoot commits to.
//
// Total over every uint64 T, because both the exact 128-bit product and the
// clamp are defined everywhere. See the package comment, item 3, for the one
// reading above SeqGasCapacity that was taken from core/params.
func (c *Ceilings) MaxCertsPerBlock(t uint64) uint64 {
	return scaleAndClamp(c.maxCertsPerBlockGenesis, t, c.seqGasTargetGenesis, c.certListCapacity)
}

// MaxSigsPerBlock is B18's signature-count ceiling:
// MaxSigsPerBlockGenesis × T / SeqGasTargetGenesis, floored, with no capacity
// clamp — see the package comment for why the absence is the rule.
//
// Total over every uint64 T. The saturation point is where the exact 128-bit
// quotient stops fitting a uint64, which scaleAndClamp expresses by clamping
// to the capacity it is given; here that capacity is the largest uint64, which
// is the same statement written as a bound.
func (c *Ceilings) MaxSigsPerBlock(t uint64) uint64 {
	const noCapacity = ^uint64(0)
	return scaleAndClamp(c.maxSigsPerBlockGenesis, t, c.seqGasTargetGenesis, noCapacity)
}

// BlockByteLimit is B13's block-size ceiling:
// min(BlockByteLimitGenesis × T / SeqGasTargetGenesis, BlockByteCapacity),
// floored. The clamp answers a transport question, not a policy one: a block
// consensus calls valid must still be one every node can move.
func (c *Ceilings) BlockByteLimit(t uint64) uint64 {
	return scaleAndClamp(c.blockByteLimitGenesis, t, c.seqGasTargetGenesis, c.blockByteCapacity)
}

// scaleAndClamp is floor(genesis × t / t0) clamped above at capacity.
//
// The product is taken exactly in 128 bits. bits.Mul64 is exact for any pair
// of uint64s, so no saturation, big.Int or 256-bit intermediate is needed: the
// only question is whether the QUOTIENT fits in 64 bits, which is exactly the
// condition bits.Div64 documents (hi < d) and which, when it fails, means the
// unclamped ceiling is astronomically above any capacity and the clamp is the
// answer regardless.
func scaleAndClamp(genesis, t, t0, capacity uint64) uint64 {
	hi, lo := bits.Mul64(genesis, t)
	if hi >= t0 {
		return capacity
	}
	q, _ := bits.Div64(hi, lo, t0)
	if q > capacity {
		return capacity
	}
	return q
}
