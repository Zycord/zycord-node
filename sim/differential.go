// Package sim is the adversarial simulator: the differential runner, the
// scenario generator, and the seeds that make every run reproducible.
//
// Nothing here ships in a node. Everything here is what stands between a
// plausible fold and a correct one.
package sim

import (
	"errors"
	"fmt"
	"math/big"

	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/sim/refold"
)

// Divergence describes a disagreement between the reference fold and the naive
// re-implementation. Any divergence is a release blocker: the two were written
// to be different in every way except their answer.
type Divergence struct {
	Height uint64
	What   string
	Fast   string
	Naive  string
}

func (d *Divergence) Error() string {
	return fmt.Sprintf("divergence at height %d: %s: core/fold says %s, sim/refold says %s",
		d.Height, d.What, d.Fast, d.Naive)
}

// Differential runs one block through both implementations and reports the
// first disagreement. The bool reports whether the block was accepted, so a
// caller driving a chain knows whether to advance its tip.
//
// It compares the whole observable surface — validity verdict, per-certificate
// outcomes, fees charged and refunded, the value burned, the miner's reward,
// what matured, and the state root — because a fold that agrees on the root
// while disagreeing on who paid is not a fold that agrees.
//
// What agreement here does and does not mean is stated in full in sim/refold's
// package comment, and it is narrower than "two implementations agree" reads —
// both bounds below were measured rather than argued. Two things bound it. The
// two folds share ONE implementation of the whole gas schedule
// (Certificate.SeqGas, Certificate.ParGas), of F1's sort key (Certificate.ID,
// Certificate.UnderwriterID), of the block's committed shape (Block.SizeBytes,
// Block.ComputeCertRoot, Block.ComputeCitesRoot) and of every ceiling
// (params.MaxCertsPerBlock, params.BlockByteLimit, params.SeqGasLimit,
// params.SeqGasBurst, params.ParGasLimit, params.ParGasTarget) — a mutation
// inside any of those moves both sides equally and this runner sees nothing.
// And this runner drives spec.Devnet() only, so a branch no published parameter
// set reaches — F12's zero-reward arm is the measured case — is agreed on by
// never being asked.
func Differential(fast *state.State, naive *refold.State, b *types.Block, p *params.Params) (bool, error) {
	fastRes, fastErr := fold.ApplyBlock(fast, b, p)
	naiveRes, naiveErr := refold.ApplyBlock(naive, b, p)

	fastInvalid := fastErr != nil && errors.Is(fastErr, fold.ErrInvalidBlock)
	naiveInvalid := naiveErr != nil && errors.Is(naiveErr, refold.ErrInvalidBlock)

	if fastInvalid != naiveInvalid {
		return false, &Divergence{
			Height: b.Header.Height,
			What:   "block validity",
			Fast:   describeErr(fastErr),
			Naive:  describeErr(naiveErr),
		}
	}
	if fastInvalid {
		// Both rejected it. The reasons are allowed to read differently — the
		// protocol says a block is invalid, not why an implementation noticed.
		return false, nil
	}
	if fastErr != nil {
		return false, fastErr
	}
	if naiveErr != nil {
		return false, naiveErr
	}

	if len(fastRes.Outcomes) != len(naiveRes.Outcomes) {
		return false, &Divergence{
			Height: b.Header.Height,
			What:   "outcome count",
			Fast:   fmt.Sprint(len(fastRes.Outcomes)),
			Naive:  fmt.Sprint(len(naiveRes.Outcomes)),
		}
	}
	for i := range fastRes.Outcomes {
		f, n := fastRes.Outcomes[i], naiveRes.Outcomes[i]
		if f.ID != n.ID {
			return false, &Divergence{b.Header.Height, fmt.Sprintf("fold order at position %d", i),
				fmt.Sprintf("%x", f.ID[:8]), fmt.Sprintf("%x", n.ID[:8])}
		}
		if f.Outcome.String() != string(n.Outcome) {
			return false, &Divergence{b.Header.Height, fmt.Sprintf("outcome of %x", f.ID[:8]),
				f.Outcome.String(), string(n.Outcome)}
		}
		if !sameValue(f.Charged.Bytes(), n.Charged) {
			return false, &Divergence{b.Header.Height, fmt.Sprintf("charge on %x", f.ID[:8]),
				f.Charged.String(), n.Charged.String()}
		}
		if !sameValue(f.Refunded.Bytes(), n.Refunded) {
			return false, &Divergence{b.Header.Height, fmt.Sprintf("refund on %x", f.ID[:8]),
				f.Refunded.String(), n.Refunded.String()}
		}
		if !sameValue(f.Swept.Bytes(), n.Swept) {
			return false, &Divergence{b.Header.Height, fmt.Sprintf("sweep on %x", f.ID[:8]),
				f.Swept.String(), n.Swept.String()}
		}
		if f.StrandedCells != n.StrandedCells {
			return false, &Divergence{b.Header.Height, fmt.Sprintf("stranded cells on %x", f.ID[:8]),
				fmt.Sprint(f.StrandedCells), fmt.Sprint(n.StrandedCells)}
		}
		if !sameValue(f.SweptStranded.Bytes(), n.SweptStranded) {
			return false, &Divergence{b.Header.Height, fmt.Sprintf("stranded sweep on %x", f.ID[:8]),
				f.SweptStranded.String(), n.SweptStranded.String()}
		}
		if !sameValue(f.RefundBurned.Bytes(), n.RefundBurned) {
			return false, &Divergence{b.Header.Height, fmt.Sprintf("burned refund on %x", f.ID[:8]),
				f.RefundBurned.String(), n.RefundBurned.String()}
		}
	}

	if fastRes.SeqGasUsed != naiveRes.SeqGasUsed {
		return false, &Divergence{b.Header.Height, "sequential gas",
			fmt.Sprint(fastRes.SeqGasUsed), fmt.Sprint(naiveRes.SeqGasUsed)}
	}
	if fastRes.ParGasUsed != naiveRes.ParGasUsed {
		return false, &Divergence{b.Header.Height, "parallel gas",
			fmt.Sprint(fastRes.ParGasUsed), fmt.Sprint(naiveRes.ParGasUsed)}
	}
	if fastRes.SeqGasApplied != naiveRes.SeqGasApplied {
		return false, &Divergence{b.Header.Height, "applied sequential gas",
			fmt.Sprint(fastRes.SeqGasApplied), fmt.Sprint(naiveRes.SeqGasApplied)}
	}
	if fastRes.ParGasApplied != naiveRes.ParGasApplied {
		return false, &Divergence{b.Header.Height, "applied parallel gas",
			fmt.Sprint(fastRes.ParGasApplied), fmt.Sprint(naiveRes.ParGasApplied)}
	}
	if !sameValue(fastRes.Burned.Bytes(), naiveRes.Burned) {
		return false, &Divergence{b.Header.Height, "value burned",
			fastRes.Burned.String(), naiveRes.Burned.String()}
	}
	if !sameValue(fastRes.MinerReward.Bytes(), naiveRes.MinerReward) {
		return false, &Divergence{b.Header.Height, "miner reward",
			fastRes.MinerReward.String(), naiveRes.MinerReward.String()}
	}
	if !sameValue(fastRes.Treasury.Bytes(), naiveRes.Treasury) {
		return false, &Divergence{b.Header.Height, "treasury share",
			fastRes.Treasury.String(), naiveRes.Treasury.String()}
	}
	if !sameValue(fastRes.Matured.Bytes(), naiveRes.Matured) {
		return false, &Divergence{b.Header.Height, "matured coinbase",
			fastRes.Matured.String(), naiveRes.Matured.String()}
	}

	// The state root is the strongest single comparison: it commits to every
	// cell and every registry entry at once. It is checked last so that a
	// failure reports the specific difference above it when there is one.
	if fast.Root() != naive.Root() {
		return false, &Divergence{b.Header.Height, "state root",
			fmt.Sprintf("%x", fast.Root()), fmt.Sprintf("%x", naive.Root())}
	}
	return true, nil
}

func sameValue(fast [32]byte, naive *big.Int) bool {
	var n [32]byte
	naive.FillBytes(n[:])
	return fast == n
}

func describeErr(err error) string {
	if err == nil {
		return "valid"
	}
	return err.Error()
}
