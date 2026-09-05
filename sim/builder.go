package sim

import (
	"zycord/core/params"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/miner"
)

// The block-selection policy lives in node/miner and only there (M1-G5).
//
// It used to exist here too, with the node's copy expected to "mirror" it. That
// is how two implementations of one policy diverge a year later without anybody
// noticing — so the duplicate is gone and these are aliases. The incentive
// property tests in this package therefore test the code that actually
// assembles blocks, which is the only version worth testing.

// Select chooses a revenue-maximising subset of a pool under the block
// ceilings. t is the sequential target T (whitepaper §8.1).
func Select(pool []*types.Certificate, p *params.Params, seqBaseFee, parBaseFee u256.U256, t uint64) []*types.Certificate {
	return miner.Select(pool, p, seqBaseFee, parBaseFee, t)
}

// Revenue is what a builder earns from a selected set, assuming every
// certificate applies.
func Revenue(certs []*types.Certificate, p *params.Params, seqBaseFee, parBaseFee u256.U256) u256.U256 {
	return miner.Revenue(certs, p, seqBaseFee, parBaseFee)
}
