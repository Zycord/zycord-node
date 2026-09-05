package sync

import (
	"errors"
	"fmt"

	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/checkpoints"
)

// The launch checkpoint defence, on the one path that needs it.
//
// `undo_depth` defends the tip: `chain.ConsiderBranch` refuses any reorg deeper
// than 1024 blocks, so a node online since genesis cannot be made to abandon
// more than about 8.5 hours of work at any hashrate. The node with **no
// history** has no tip to defend — a first sync from genesis, or a return after
// an outage longer than the undo horizon — and adopts whatever weighs most.
// That is the node an attacker mining a heavier chain *from genesis* takes,
// while the early network keeps its own chain, and it is the only case these
// two refusals are scoped to. See `node/checkpoints` for the full argument and
// for why none of it may enter `params.ConsensusRoot()`.
//
// Enforced here rather than in `node/chain` on purpose. A checkpoint is at
// least `MinAge` = 2,880 blocks old — 2.8x `undo_depth` — so a gossiped branch,
// bounded by the undo horizon, can never reach far enough back to cross one.
// Sync is the only ingress that can, so sync is the only place the check has to
// exist, and `node/chain` stays a package that answers to the parameters alone.
var (
	// ErrContradictsCheckpoint reports a candidate whose block at a pinned
	// height is not the block this release pins there.
	ErrContradictsCheckpoint = errors.New("sync: candidate contradicts a release checkpoint")
	// ErrBelowMinChainWork reports a candidate that reaches the height the
	// work floor is measured at carrying less work than the floor.
	ErrBelowMinChainWork = errors.New("sync: candidate chain is below the minimum chain work floor")
)

// Admit applies the release's checkpoint table and work floor to a validated
// candidate, before any body is requested for it.
//
// **Refused, not scored.** A peer serving a chain that contradicts a checkpoint
// is either lying or on the wrong chain, and this node cannot tell which — but
// unlike every other refusal in this package, the rule it broke is *this
// client's release policy* rather than a rule of the protocol. A checkpoint
// shipped wrong would then ban the honest network from every node that took the
// release, turning an editing mistake into a partition. So a contradiction
// costs this node its sync attempt and costs the peer nothing;
// `p2p.SyncPenalty` charges neither of these errors, and that omission is the
// decision rather than an oversight.
//
// A node that has already adopted blocks below the highest checkpoint on the
// wrong chain stops here and stays stopped: it cannot reorg back past
// `undo_depth` to reach the pinned chain, and it must be resynced from an empty
// data directory. That is the intended outcome — stuck and saying so beats
// following an attacker's history — and it is why the refusal names the height,
// the pinned id and the offered id, and why the same values are on `/status`.
func Admit(ch *chain.Chain, cand *Candidate) error {
	cps := checkpoints.Active()
	if cps.IsEmpty() || len(cand.Headers) == 0 {
		return nil
	}

	// Layer 2: the pins. Checked over the candidate's own headers, which have
	// already been validated against each other and against the difficulty
	// rule, so the ids compared here are ids of blocks that could exist.
	for i := range cand.Headers {
		h := &cand.Headers[i]
		if want, ok := cps.At(h.Height); ok {
			if got := h.ID(); got != want {
				return fmt.Errorf("%w: height %d is pinned to %x, this candidate offers %x",
					ErrContradictsCheckpoint, h.Height, want[:8], got[:8])
			}
		}
	}

	// Layer 1: the work floor, against the chain this node would be on if it
	// adopted the candidate — not against the candidate's own work, which is
	// only the segment, and not against the peer's advertised work, which is an
	// unverified claim and free to inflate.
	if !cps.MinChainWork.IsZero() {
		total, err := cand.totalWorkAfter(ch)
		if err != nil {
			return err
		}
		if tip := cand.Tip(); !cps.MeetsFloor(tip.Height, total) {
			return fmt.Errorf("%w: height %d would carry %s, the floor at height %d is %s",
				ErrBelowMinChainWork, tip.Height, total.String(),
				cps.MinChainWorkHeight, cps.MinChainWork.String())
		}
	}
	return nil
}

// totalWorkAfter is the accumulated work of the whole chain this node would be
// on if it adopted the candidate: what it holds now, less the suffix the
// candidate displaces, plus the candidate's own.
func (c *Candidate) totalWorkAfter(ch *chain.Chain) (u256.U256, error) {
	anchor, err := ch.CanonicalHeader(c.AttachesTo)
	if err != nil {
		return u256.Zero, ErrDoesNotAttach
	}
	replaced, err := replacedWork(ch, anchor.Height)
	if err != nil {
		return u256.Zero, err
	}
	return ch.TotalWork().SatSub(replaced).SatAdd(c.Work), nil
}
