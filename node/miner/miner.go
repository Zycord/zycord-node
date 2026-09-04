package miner

import (
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"zycord/core/fold"
	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/mempool"
)

// ErrNoSolution reports that the nonce budget ran out before the target was met.
var ErrNoSolution = errors.New("miner: no solution within the attempt budget")

// ErrNonceSpaceExhausted reports that every nonce under one template was tried
// and none met the target.
//
// It is wrapped alongside ErrNoSolution rather than replacing it, because from
// a caller's chair "no block this time" is the same outcome either way and no
// existing errors.Is(err, ErrNoSolution) should stop being true. What it adds
// is the one fact that changes the *response*: the 2^32 nonces this template
// owns are spent, so retrying the same template cannot succeed, and the search
// has to move to a seed the miner has not walked yet.
//
// It is reachable only from a caller that asks for a budget of 2^32 or more.
// At the hardware this milestone targets that is weeks of hashing for one
// 30-second block, so a live network never sees this; the sentinel exists so
// that the impossible case has a defined answer rather than an infinite loop,
// and so that answer is testable without waiting for the hardware to change.
var ErrNonceSpaceExhausted = errors.New(
	"miner: every nonce for this template has been tried; the search must move " +
		"to a fresh template rather than wrap onto nonces already rejected")

// ErrStaleTemplate reports that the tip moved while a block was being sealed.
//
// It is separated from real errors because it is not one. On a live network
// every miner loses this race regularly, and a node that logged it as a failure
// would be reporting healthy competition as a fault.
var ErrStaleTemplate = errors.New("miner: the tip moved while the block was being sealed")

// ErrSealDoesNotVerify reports that a header this node sealed itself does not
// satisfy the rule the network will judge it by.
//
// It is a defect in the engine or in the solver, never bad luck and never
// something a retry fixes, so it is worth its own name and its own sentence.
// The incident it exists for is the wrong-key seal: a RandomX engine answered
// for the wrong key epoch, the miner's Try accepted nonces that CheckWork
// rejects, and the node applied 1112 of its own blocks that every other node
// refused. Nothing anywhere noticed, because nothing anywhere asked.
var ErrSealDoesNotVerify = errors.New(
	"miner: the sealed header does not meet its target under the rule the network " +
		"checks it against; the solver and the work rule disagree, and every block " +
		"this node produces will be rejected by every peer")

// ErrTargetDoesNotVerify reports that the difficulty target this node wrote
// into a header it built itself does not equal the target the difficulty rule
// re-derives from the same window.
//
// Like ErrSealDoesNotVerify it is a construction defect, never bad luck: the
// miner set Header.Target at assembly, and by the time the block is about to be
// applied the rule every peer will re-derive it under disagrees. A retry does
// not fix it. It exists for the one header field the target re-derivation pass
// left behind: every ingress path re-derives the declared target, but the path
// a node's OWN block takes to Chain.Apply goes through none of them, so the
// target was applied there without re-derivation.
var ErrTargetDoesNotVerify = errors.New(
	"miner: the header's declared target does not equal the target the difficulty " +
		"rule re-derives from the same window; the block builder and the difficulty " +
		"rule disagree, and every block this node produces will be rejected by every peer")

// ErrTooEarly reports that this node's clock has not reached the earliest
// timestamp the next block on this chain may carry.
//
// Like ErrStaleTemplate it is separated from real errors because it is not one.
// A node started before its network's genesis is in exactly this state, on
// purpose and for hours, and a caller that logged it as a failure would be
// reporting a correctly waiting miner as a fault. The answer is to wait; see
// Miner.blockTime for what waiting prevents.
var ErrTooEarly = errors.New(
	"miner: this node's clock has not reached the earliest timestamp the next " +
		"block may carry, so there is no block to build yet")

// TooEarlyError carries the two readings the refusal came from, so a caller can
// report how long the wait is rather than only that there is one.
//
// The gap is the whole of what an operator needs — it is what stands between a
// node that looks idle and a node that has been told when it will start — and
// computing it for an error string and then discarding it is the mistake
// sync.WithheldError records having made on the other path.
type TooEarlyError struct {
	// NotBefore is the earliest timestamp a block may declare here: one second
	// past the median of the last MedianTimeBlocks headers. Before a network's
	// genesis that median is genesis_time itself.
	NotBefore uint64
	// Now is this node's clock at the moment of the refusal.
	Now uint64
}

// Remaining is how many seconds are left before mining can begin.
//
// Saturating rather than signed: the caller reaches this only when the refusal
// fired, which is `Now <= NotBefore-1`, so the subtraction cannot go negative —
// and a future caller who reaches it anyway gets zero rather than a duration
// underflowed to five hundred billion years.
func (e *TooEarlyError) Remaining() uint64 {
	if e.Now >= e.NotBefore {
		return 0
	}
	return e.NotBefore - e.Now
}

func (e *TooEarlyError) Error() string {
	return fmt.Sprintf("%s: the next block must be dated %d at the earliest, "+
		"this node's clock reads %d (%ds to wait)",
		ErrTooEarly.Error(), e.NotBefore, e.Now, e.Remaining())
}

// Unwrap keeps errors.Is(err, ErrTooEarly) true for callers that only need to
// know which case they are in.
func (e *TooEarlyError) Unwrap() error { return ErrTooEarly }

// Miner assembles and seals blocks on top of a chain.
//
// It runs no execution. It orders bytes whose validity it has already checked,
// dry-runs the fold over its own candidate once, and solves proof of work.
// Proposal is deliberately cheap and dumb — that is what lets a proposer be
// blind and still never produce an invalid block by including a stale
// certificate.
type Miner struct {
	Chain  *chain.Chain
	Pool   *mempool.Pool
	Engine pow.Engine
	// Payout receives the emission and the tips, through the maturity ring.
	Payout types.Address
	// Now supplies the header timestamp. Injected so tests are not at the mercy
	// of a clock, and so that the *only* clock in the node is visible here
	// rather than scattered.
	Now func() uint64
	// Threads is how many goroutines search nonces. **Zero means one**, and
	// that default is chosen against the obvious one on purpose.
	//
	// A parallel search returns whichever nonce a worker happens to reach
	// first, so the miner is NONDETERMINISTIC above one thread — and the block
	// a nonce produces is not interchangeable with the block another nonce
	// would have produced. F13 writes the parent id into state on EVERY block
	// (types.PrevParentIDSlot, for §8.1's citation rules), so two chains mined
	// from identical content with different nonces have different state roots
	// from the very next block.
	//
	// That is correct: a chain commits to its own history. But it means the
	// zero value of this type decides whether "mine the same blocks twice"
	// works, and a test comparing two independently mined chains is a
	// reasonable thing to write. So the zero value is the reproducible one and
	// cmd/zycordd asks for cores explicitly.
	//
	// It remains a miner setting rather than a consensus one either way: how
	// fast a node looks for a solution changes nothing about which solutions
	// are valid.
	Threads int
}

// Assemble builds a candidate block: select, seal, dry-run, drop what would
// drop, and fill in the roots.
//
// The dry run is not an optimisation. A DROPPED certificate pays the miner
// nothing and still consumes the block's ceilings, so a builder that skipped
// this would be donating space (§10). Because the builder holds state, the run
// is cheap — which is exactly the argument the spec makes for why drops need no
// consensus rule of their own.
func (m *Miner) Assemble() (*types.Block, error) {
	p := m.Chain.Params()

	// One snapshot for the whole assembly, taken atomically.
	//
	// Building against the chain's live state would mean the tip could move
	// between reading the base fee and sealing the state root, so the header
	// would commit to a root computed from a mixture of two chains — a root no
	// fold anywhere reproduces. The block is then rejected by every node
	// including its author, and because roots are only checked at epoch
	// boundaries, the failure appears far from its cause.
	//
	// A snapshot can go stale while the block is being hashed, and that is
	// fine: Apply re-checks the parent under the write lock and rejects a stale
	// template outright. Optimistic assembly, validated commit.
	view := m.Chain.Snapshot()
	tip, s := view.Tip, view.State

	// Is there an honest block to build at all? See blockTime — and note that
	// this asks the question about THIS parent, not about whatever the tip
	// happens to be by the time it is asked.
	//
	// **The order here is load-bearing and it is not the obvious one.** Asking
	// before the snapshot reads a median window ending at the tip *then*, and
	// the snapshot may hand back a later tip — so the header would be built on
	// a parent whose own window was never the one the timestamp was checked
	// against, and that window's floor can be higher. Nothing downstream would
	// catch it: Apply compares height and ParentID and never a time, the fold
	// reads Header.Time nowhere, and MineOneWhile's two self-checks cover the
	// proof of work and the declared target only. The node would commit a
	// block violating the median-past rule onto its own chain and announce it,
	// and every peer would refuse it at pow.CheckMedianTime and score the
	// sender down — a self-fork produced by the miner's own construction,
	// which is precisely the failure ErrSealDoesNotVerify and
	// ErrTargetDoesNotVerify exist to make impossible for the other two
	// header fields.
	//
	// Taken after the snapshot, and anchored at the snapshot's own tip, the
	// floor and the parent are the same chain by construction. A reorg that
	// replaces that height under us is then the ordinary stale template: the
	// ParentID no longer matches and Apply says so.
	now, err := m.blockTime(p, tip)
	if err != nil {
		return nil, err
	}

	seqBase := s.Get(types.SeqBaseFeeSlot())
	parBase := s.Get(types.ParBaseFeeSlot())
	// Genesis (height 0) is never assembled here — zcd genesis builds it —
	// so the block being assembled is always at least height 1, and the
	// sequential target T is always a real state cell by the time a miner
	// runs (F2b/the height-0 init in core/fold write it in block 0).
	t, _ := s.Get(types.SeqGasTargetSlot()).Uint64()

	selected := Select(m.Pool.Candidates(), p, seqBase, parBase, t)

	b := &types.Block{
		Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       tip.Height + 1,
			ParentID:     tip.ID(),
			Time:         now,
			EmissionAddr: m.Payout,
			Target:       pow.NextTarget(m.Chain.RecentHeaders(int(p.DifficultyWindow)+1), p),
			// The seed epoch is not a choice: the fold pins it to the one
			// this height implies, so declaring anything else produces a
			// block this miner's own rules reject.
			//
			// ExtraNonce is written explicitly, and at zero, even though the
			// zero value would give the same bytes. It is the solo-miner
			// policy of ARCHITECTURE §12 stated where a reader of this
			// assembler can see it, rather than inferred from a field's
			// absence: ExtraNonce shards a search space *across* miners, and
			// a solo miner walking one 2^32 space has nobody to be separated
			// from. Writing it also makes the field's value a decision this
			// code owns, so that a later edit adding a nonzero value is a
			// visible change of policy rather than the quiet removal of an
			// omission nobody recorded a reason for.
			PoW: types.PoWSeal{
				ExtraNonce: 0,
				SeedEpoch:  pow.SeedEpochFor(tip.Height+1, p),
			},
		},
		Certs: selected,
		// Cites is left empty: gathering competing headers to cite
		// (whitepaper §8.1's health signal) is not implemented by this
		// miner. An empty list is always valid — it is the safe default,
		// since an unhealthy-looking epoch only withholds *growth*, never
		// decay or the floor — but it does mean this miner's blocks never
		// themselves supply the health signal.
	}
	// CitesRoot depends only on b.Cites, fixed at nil for this block's whole
	// lifetime, so it is set once here rather than recomputed everywhere
	// CertRoot is. dropTheDrops below copies this Header into its own trial
	// block and must see a CitesRoot that already matches an empty Cites, or
	// its own dry run fails the same check this block is being built to pass.
	b.Header.CitesRoot = b.ComputeCitesRoot(p)

	// Dry-run and drop the drops — and the skips. A DROPPED certificate
	// pays the miner nothing because its deposit could never be reserved; a
	// SKIPPED_STALE or SKIPPED_OVERFLOW one pays the miner nothing because F9
	// only ever routes a tip through the Applied path (see Fees' doc comment).
	// All three are therefore the same case from the builder's chair: revenue
	// zero, ceiling spent. Select ranks by MinerTip, which is computed on the
	// assumption a certificate applies (its own doc comment says so), so
	// without this pass the ranking and the settlement disagree about which
	// certificates are worth anything. That disagreement — a guaranteed-skip
	// certificate ranked at a price the fold will never charge it — is the gap
	// this pass closes, and it is referred to below as the unpaid-outcome gap.
	//
	// One pass suffices for DROPPED, cleanly: a drop reserves nothing and
	// therefore touches no state, so removing it cannot change any other
	// certificate's outcome. A skip is not: it debits its deposit cell and
	// credits Deposit.RefundTo, which need not be the depositor, so removing a
	// skip can withdraw a credit a *later* certificate's GUARD_GE depended on
	// and turn that certificate into a skip in its turn. dropTheDrops
	// therefore iterates to a fixpoint rather than running once — see there
	// for the witness and for why it terminates.
	//
	// Either way the block is valid: Chain.Apply folds whatever the final
	// Certs list actually is and is authoritative regardless of what any dry
	// run predicted. The fixpoint is about the builder's own guarantee, not
	// about validity — one pass would have shipped exactly the unpaid
	// certificate this function exists to exclude.
	if len(b.Certs) > 0 {
		kept, err := m.dropTheDrops(b, s)
		if err != nil {
			return nil, err
		}
		b.Certs = kept
	}

	b.Header.CertRoot = b.ComputeCertRoot(p)
	if p.IsEpochBoundary(b.Header.Height) {
		// This fold cannot name a refused certificate, and the reason is
		// structural rather than a hope — it is the third call that goes
		// through checkBlockRules and the one place dropTheDrops' guarantee
		// has to carry. dropTheDrops returns either a list a fold accepted
		// whole, or a SUBSET of one, or nothing; and every per-certificate
		// rule (stateless validity, duplicate-in-block, B1-B4) is a property
		// of the certificate alone, while every block-level ceiling only falls
		// as certificates are removed. So a rule refusal here would mean
		// dropTheDrops broke that invariant, which is a builder bug and is
		// surfaced as one.
		root, err := fold.SealStateRoot(s, b, p)
		if err != nil {
			return nil, err
		}
		b.Header.StateRoot = root
	}
	return b, nil
}

// dropTheDrops runs against the caller's snapshot, not against the chain, so
// the dry run and the block it informs see exactly the same state.
//
// It converges to *a* fixpoint, not to the revenue-maximal certificate set,
// and the difference is worth stating because it looks like a bug and is not
// one this function can fix. Exclusion is judged on each certificate's outcome
// *in the set it was folded with*, and removals are never reconsidered. A skip
// debits its depositor by SkipFee, so a certificate can be stale only because
// a skip that has since been removed debited the cell it reads — and once
// removed it is never tried again, even though it would now apply and pay.
// Measured on a same-underwriter triple: the builder ships one certificate
// where two would have applied, giving up ~619,460 drops. Re-admitting
// excluded certificates after each removal would recover it, at strictly more
// folds — which is the budget maxDropPasses exists to protect. Note this is
// not introduced by the iteration: a single pass ships the identical block,
// because both certificates are non-Applied in the very first fold.
//
// Despite the name it removes every certificate whose dry-run outcome is not
// Applied — DROPPED, SKIPPED_STALE and SKIPPED_OVERFLOW alike. Applied
// is the only outcome that ever pays the miner (F9): the other three are
// billed a flat, deposit-funded charge that goes to res.Burned, never to the
// producer, so keeping one in the final block trades ceiling space a paying
// certificate could have used for revenue the fold will never deliver. Select
// has no way to tell these apart from a certificate that will actually apply
// — it ranks by MinerTip, which is computed under the assumption the
// certificate applies — so this dry run is the only point in assembly that
// knows the difference, and it is the last chance to act on it before the
// block is sealed.
func (m *Miner) dropTheDrops(b *types.Block, s *state.State) ([]*types.Certificate, error) {
	p := m.Chain.Params()
	certs := b.Certs

	// Iterated to a fixpoint, not run once, and the reason is a real witness
	// rather than caution. A skip is *not* state-neutral: F5 debits
	// Deposit.Cell by Deposit.Amount and settle credits Deposit.RefundTo with
	// Amount - SkipFee. Validity requires RefundTo to be a native balance slot
	// at a user address (V-rules, deposit section) and nothing requires it to
	// be the depositor, so a skip can be a net *credit* to a third party. A
	// later certificate declaring GUARD_GE on that party's balance can then
	// hold in the dry run only because the skip's refund landed — and removing
	// the skip makes it skip for real.
	//
	// One pass would therefore ship exactly what this function exists to
	// prevent: a certificate the fold pays the builder nothing for, in the
	// final block, having been proved unpayable by a dry run we then
	// invalidated ourselves. Reproduced with alice seq0 applying, alice seq1
	// skipping with RefundTo pointing at carol, and carol's own certificate
	// moving carolBalance+1 — admitted by a single pass, skipped on chain.
	//
	// Termination is structural: a pass either removes at least one
	// certificate or returns, and the set is finite, so this would run at most
	// len(b.Certs) times. That bound is not good enough, because it is
	// attacker-controlled. Chain the refunds — each certificate's RefundTo
	// pointing at the next one's balance cell, sized so its GUARD_GE clears
	// only because the previous refund landed — and every pass removes exactly
	// one link, so a depth-n cascade costs n full folds. Measured on this
	// repo's own BenchmarkApplyBlock, a fold of a full block is ~1.5 s at
	// 1,000 certificates and ~3.9 s at 2,900, and max_certs_per_block_genesis
	// is 4,000: a deep cascade would blow through a 30-second target block
	// time and the miner would miss its own slot. The attacker's side is cheap
	// and mostly refundable — only the head link is ever billed a SkipFee,
	// since the rest never reach a block — and the pool cannot screen it,
	// because every link is individually admissible, which is the unpaid-outcome
	// gap's premise.
	//
	// So the passes are capped. The cap is a cost bound, not a correctness
	// one: the block is valid at every iteration (Chain.Apply folds the final
	// list and is authoritative), so stopping early costs at most some unpaid
	// certificates left in a block, which is the status quo this pass replaced and
	// strictly better than not proposing a block at all. maxDropPasses is
	// small deliberately — honest traffic converges in one pass, the witness
	// in this repo's test needs two, and anything demanding more is a shape
	// nobody builds by accident.
	//
	// Stated plainly because it is the weak point of this function: the cap is
	// argued, not pinned. TestMinerDropsSkipsThatOnlyOtherSkipsPaidFor proves
	// the loop iterates at all, and nothing proves the cap holds under an
	// adversarial cascade, because a real n-deep cascade needs each link's
	// balance sized so its GUARD_GE clears only after the previous link's
	// refund lands — an arithmetic construction, not a shape a test builds by
	// accident. An attempt at one collapsed into a single pass (all links
	// stale from the start, all excluded together) and was removed rather than
	// kept as a test that asserts less than its name claims. A genuine
	// cascade witness is worth writing; until it exists, the cap rests on the
	// argument above and on the structural fact that the loop cannot run more
	// than maxDropPasses times whatever the input.
	// Certificates excluded because a *block* rule refuses them, as opposed to
	// because their outcome does not pay. Budgeted separately from the drop
	// passes below: a rule exclusion is not a step of that fixpoint, and
	// charging it against the same budget would let one refused certificate
	// silently cost the builder a revenue pass.
	ruleDrops := 0

	for pass := 0; pass < maxDropPasses; pass++ {
		trial := *b
		trial.Certs = certs
		trial.Header.CertRoot = trial.ComputeCertRoot(p)

		// Both folds below run checkBlockRules first, so both can name a
		// refused certificate, and the handling belongs to the error rather
		// than to either call site. It used to hang off SealOutcomes alone:
		// SealStateRoot ran first, returned its error raw, and at one height in
		// every EPOCH_LENGTH — the heights a stuck node cannot skip past — the
		// exclusion below was simply not reached and the miner built nothing.
		// One error value, one place that answers it.
		var res *fold.Result
		var err error
		if p.IsEpochBoundary(trial.Header.Height) {
			var root types.Hash
			if root, err = fold.SealStateRoot(s, &trial, p); err == nil {
				trial.Header.StateRoot = root
			}
		}
		if err == nil {
			res, err = fold.SealOutcomes(s, &trial, p)
		}
		if err != nil {
			// A block rule that names the certificate it refuses is a
			// certificate to leave out, not a reason to propose nothing. The
			// pool's screen mirrors the block rules rather than being them, and
			// a mirror can fall out of step — the witness is a height-lowering
			// reorg leaving a pooled certificate past B2's TTL ceiling, which
			// the pool can no longer remove — at which point one such
			// certificate used to cost this node every block it would otherwise
			// have produced. Worse, the node then never reached Pool.OnBlock,
			// which runs only downstream of a successful Apply, so it could not
			// clear the certificate either. Excluding it keeps that failure
			// local to one certificate whatever the divergence turns out to be.
			var cre *fold.CertRuleError
			if errors.As(err, &cre) && cre.Index >= 0 && cre.Index < len(certs) {
				if ruleDrops > maxRuleDrops {
					// The budget is spent AND the one confirming fold it buys
					// (below) refused as well, so there is no evidence left
					// that any bounded list here folds. An empty block is valid
					// at every height this miner assembles and needs no further
					// fold to prove it, so that is the floor: revenue gone,
					// block kept.
					return nil, nil
				}
				// At the budget the last exclusion is still made and the
				// remainder folded once more, rather than the block being
				// emptied on the spot. One extra fold — the unit the budget is
				// denominated in — and it is what makes the cap cost only the
				// certificates a rule actually named. Emptying immediately
				// would turn a transient divergence into a fully empty block:
				// the B3 window between Chain.Apply and Pool.OnBlock is as deep
				// as the certificate count of a block somebody else mined, so
				// it reaches past four with nobody paying for it.
				ruleDrops++
				certs = append(certs[:cre.Index:cre.Index], certs[cre.Index+1:]...)
				pass-- // not a step of the drop fixpoint; see ruleDrops
				continue
			}
			// Not attributable to any one certificate, so there is nothing to
			// exclude. That is a builder bug — everything here came from a pool
			// that ran the V-rules — so surface it rather than quietly shipping
			// a block the network will reject.
			return nil, fmt.Errorf("miner: candidate block is invalid: %w", err)
		}

		// Anything that is not Applied pays the builder nothing (see this
		// function's doc comment). Naming the excluded set as "not Applied"
		// rather than enumerating DROPPED/SKIPPED_STALE/SKIPPED_OVERFLOW is
		// deliberate: the invariant the whole package leans on is "only
		// application pays" (Fees' doc comment), and a filter stated the same way
		// stays correct if fold ever grows a fifth outcome, rather than silently
		// starting to pack an unpaid one.
		excluded := make(map[types.Hash]struct{})
		for _, o := range res.Outcomes {
			if o.Outcome != fold.Applied {
				excluded[o.ID] = struct{}{}
			}
		}
		if len(excluded) == 0 {
			return certs, nil
		}

		kept := make([]*types.Certificate, 0, len(certs))
		for _, c := range certs {
			if _, drop := excluded[c.ID()]; drop {
				continue
			}
			kept = append(kept, c)
		}
		certs = kept
	}

	// Cap reached with the last pass still finding certificates to exclude.
	// certs already reflects every removal made, so this returns the best
	// candidate the budget bought rather than discarding the work.
	return certs, nil
}

// maxDropPasses bounds dropTheDrops' fixpoint iteration. See there for why the
// structural bound (len(b.Certs)) is not usable and what stopping early costs.
//
// Four, with the headroom measured rather than guessed: the whole node suite
// (node/chain, node/miner, node/rpc) passes at 2 and fails at 1, so 2 is the
// deepest cascade anything in this repo actually builds — the domino witness
// in TestMinerDropsSkipsThatOnlyOtherSkipsPaidFor. Four is that doubled. Going
// higher buys nothing against an attacker, who can always add one more link
// than the cap; the cap's job is to make the cost constant, not to win a race
// with the cascade's depth.
const maxDropPasses = 4

// maxRuleDrops bounds how many certificates dropTheDrops will exclude because
// a block rule named them, and it is a cost bound in exactly the way
// maxDropPasses is: each exclusion costs one more full fold, and the number of
// refused certificates is attacker-influenced through the pool.
//
// Small on purpose. A pool whose screen mirrors the block rules should offer
// zero of these; the height-lowering-reorg witness above produces one per
// certificate that was pooled at the old ceiling. Hitting the cap does not
// empty the block on the spot: the last named certificate is excluded and the
// remainder folded once more, and only if THAT fold names another one does the
// builder fall back to an empty block — still a block, which is the property
// this exists for, rather than none.
//
// The count the constant states is the count of exclusions the budget is
// *spent* on; the test above it is `>` and runs before the increment, so
// maxRuleDrops + 1 = 5 certificates are actually excluded and the fallback is
// reached on the sixth refusal. That extra one IS the confirming fold
// described above, and it is deliberate — say the arithmetic out loud rather
// than leave the constant reading as the exclusion count. Worst case is
// therefore maxDropPasses + maxRuleDrops + 1 = 9 folds, and the cap costs the
// certificates a rule named rather than all of them.
const maxRuleDrops = 4

// blockTime returns the timestamp the next block will declare, or a
// *TooEarlyError if this node's clock has not reached it.
//
// The rule it enforces is one sentence: **a miner never declares a time it has
// not reached.** The median-past rule (R1-H2) fixes the earliest timestamp the
// next block on this chain may carry; until the local clock passes that floor,
// there is no honest block to build and this waits rather than inventing one.
//
// It used to clamp instead — `if now <= floor { return floor + 1 }` — and the
// clamp is what made a node started before its network's genesis mine a
// private, future-dated chain. Every consequence of that followed from this one
// expression:
//
//   - Before `genesis_time` the floor IS `genesis_time` (block 0 is the whole
//     median window), so the clamp dated block 1 at `genesis_time + 1` however
//     early the miner was started. The chain then advanced one declared second
//     per six blocks, which is all the median-past rule requires.
//   - Peers judged none of it. A block past the future-time limit is withheld
//     rather than rejected (R1-H2), and past `HorizonSeconds` it is dropped —
//     so an early miner is alone without being told so.
//   - `pow.NextTarget` reads *declared* solve times. Pinned near zero against a
//     30 s goal, they drive the target down by the per-block clamp every block,
//     with no feedback from real time, until the miner has priced itself out.
//     The chain it then hands the network at genesis carries a difficulty no
//     real hashrate supports.
//
// None of that needed an attacker. It is what an honest operator got for
// starting early and leaving it running, which is exactly what an operator is
// invited to do — so the refusal belongs here, in the one place that reads a
// clock (I2-L5), rather than in whichever caller happens to remember it.
//
// The clamp is gone rather than kept alongside: with the refusal in front of
// it, `now > floor` on every path that reaches the return, and `now` is the
// only value it could produce. There is still deliberately nothing bounding the
// future side here, because that side is not a validity rule.
// The window ends at `tip`, the parent this block will actually declare, and
// NOT at whatever the chain's tip is when this runs. That is the same anchoring
// checkDeclaredTarget uses and for the same reason: the rule a peer will judge
// this header by reads the window ending at its parent, so any other window is
// a different question with a different answer. `RecentHeaders` is the
// tip-anchored form and is the wrong one here.
func (m *Miner) blockTime(p *params.Params, tip types.Header) (uint64, error) {
	now := m.Now()
	window := m.Chain.HeadersEndingAt(tip.Height, p.MedianTimeBlocks)
	if floor := pow.MedianTime(window, p); now <= floor {
		return 0, &TooEarlyError{NotBefore: floor + 1, Now: now}
	}
	return now, nil
}

// Seal solves proof of work for a candidate, up to a budget of attempts.
func (m *Miner) Seal(b *types.Block, attempts uint64) error {
	return m.SealWhile(b, attempts, nil)
}

// SealWhile is Seal with an abandon condition, polled while the search runs.
//
// The condition exists because the attempt budget is the wrong instrument on a
// real network. Against pow.Dev a budget is a formality — every nonce is close
// to a solution — but against RandomX at mainnet difficulty a single core
// manages a few hundred hashes a second, so a budget large enough to be worth
// setting is also large enough to spend many block intervals inside. A miner
// that cannot notice the tip moved until its budget runs out mines on a dead
// parent, and every block it finds is stale on arrival.
//
// Polled rather than pushed: the caller supplies a predicate and it is checked
// once per pollAttempts nonces per worker. That is deliberately coarse. The
// alternative is a channel closed by whatever applies blocks, which means the
// miner subscribing to chain events — real machinery, for a signal a cheap
// read already carries.
func (m *Miner) SealWhile(b *types.Block, attempts uint64, abandon func() bool) error {
	// The nonce is 32 bits (types.PoWSeal), so a budget above 2^32 asks for
	// attempts there is no nonce to make. Clamped rather than wrapped, for the
	// reason pow.Solve clamps: the workers stride over a uint64 counter and a
	// wrapped one would re-test nonces already rejected, reporting hashrate it
	// was not converting into coverage.
	//
	// **This miner mines at ExtraNonce = 0, always**, and the policy question
	// the clamp used to leave open is now answered: a solo miner that reaches
	// the end of a space takes a FRESH TEMPLATE, not a fresh ExtraNonce.
	// MineOneWhile is where that happens; the reason lives there, with the
	// reassembly it describes.
	//
	// Clamped rather than wrapped, for the reason pow.Solve clamps and for one
	// more that matters here: exhaustion has to be *distinguishable*. A wrapped
	// counter re-tests nonces already rejected and can never terminate, so the
	// caller above could not tell a space genuinely walked to its end from a
	// search that will never finish, and the fresh-template answer would have
	// nothing to trigger on. Exhausting 2^32 RandomX hashes inside one
	// 30-second interval is far out of reach for the hardware this milestone
	// targets, so this is not a live limit today; it is here so that reaching
	// it is a bounded search with a defined outcome rather than an infinite
	// loop.
	exhaustive := attempts >= nonceSpace
	if attempts > nonceSpace {
		attempts = nonceSpace
	}
	threads := m.Threads
	if threads <= 0 {
		threads = 1
	}
	if uint64(threads) > attempts {
		threads = int(attempts)
	}
	if threads < 1 {
		threads = 1
	}

	base := pow.NewSolver(m.Engine, b.Header, m.Chain.Params())

	var (
		wg     sync.WaitGroup
		found  atomic.Bool
		winner atomic.Uint32
		// The winning digest, which is a header field now that the work rule
		// compares the commitment. Guarded by the same CompareAndSwap that
		// picks the winning nonce, so the pair cannot be torn: a header
		// carrying one worker's nonce and another's digest would fail its own
		// network's check.
		winnerHash atomic.Pointer[types.Hash]
		quit       atomic.Bool
	)
	for w := 0; w < threads; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			// Each worker gets its own Solver: Try writes the nonce into the
			// solver's own buffer and is not safe to share.
			s := base.Clone()
			// Strided rather than blocked, so that no worker is systematically
			// searching nonces a shorter run would never have reached. With
			// blocks, a search abandoned early would have covered only the
			// first worker's range densely and every other range not at all.
			// The counter stays uint64 so the stride and the bound cannot
			// wrap; the narrowing below is lossless because attempts was
			// clamped to nonceSpace above, so i is always under 2^32.
			for i := uint64(w); i < attempts; i += uint64(threads) {
				if i%pollAttempts < uint64(threads) {
					if found.Load() {
						return
					}
					if abandon != nil && abandon() {
						// Record that this worker LEFT rather than finished.
						// Without it a budget wide enough to cover the space
						// reports exhaustion for a search that was abandoned
						// on its first poll, and the caller then reassembles
						// and re-hashes on the strength of a space nobody
						// walked — during a shutdown, exactly when it must
						// stop.
						quit.Store(true)
						return
					}
				}
				if digest, ok := s.TryHash(uint32(i)); ok {
					// A concurrent winner is possible and harmless: both
					// nonces satisfy the target, so either is a valid seal.
					// CompareAndSwap only decides which one the block carries.
					//
					// The digest is stored BEFORE the flag, so that a reader
					// which observes `found` also observes the matching hash.
					// Storing it after would leave a window in which the
					// header takes a nonce with no digest.
					if found.CompareAndSwap(false, true) {
						d := digest
						winnerHash.Store(&d)
						winner.Store(uint32(i))
					}
					return
				}
			}
		}(w)
	}
	wg.Wait()

	if !found.Load() {
		// A budget that covered the whole nonce space and found nothing is a
		// different event from a budget that merely ran out, and the caller
		// acts on the difference: there is no nonce left to try under this
		// template, so retrying it is guaranteed to fail. Wrapping keeps
		// errors.Is(err, ErrNoSolution) true for every caller that only needs
		// "no block this time".
		//
		// An ABANDONED search is neither, however wide its budget was. The
		// workers stop at their next poll, so most of the space is untried,
		// and calling that exhaustion would tell the caller to reassemble and
		// hash again on the strength of a space nobody walked — during a
		// shutdown or a lost race, which are the two moments the miner is
		// being asked to stop.
		if exhaustive && !quit.Load() {
			return fmt.Errorf("%w: %w", ErrNoSolution, ErrNonceSpaceExhausted)
		}
		return ErrNoSolution
	}
	// Written after every worker has stopped, so the header this returns is
	// the one the winning nonce was tested against.
	b.Header.PoW.Nonce = winner.Load()
	// The digest the winning nonce produced. Carried rather than recomputed:
	// re-deriving it here would pay a second full RandomX evaluation, and would
	// be a second route to a consensus value — see pow.Solver.TryHash.
	if d := winnerHash.Load(); d != nil {
		b.Header.PoWHash = *d
	}
	return nil
}

// pollAttempts is how often each worker checks whether to give up. At RandomX
// speeds this is a fraction of a second per worker; against pow.Dev it is
// nothing at all.
const pollAttempts = 512

// nonceSpace is how many nonces one (template, ExtraNonce) pair holds, the
// width of types.PoWSeal's Nonce. It bounds the attempt budget rather than the
// header: a budget above it cannot buy a nonce that does not exist.
//
// A var rather than a const, and only so that the exhaustion path is testable.
// Reaching it honestly costs 2^32 hash evaluations — minutes even against an
// engine that does nothing but return a constant, and far too slow for a suite
// that runs on every commit — so the tests narrow the space instead of
// out-hashing it. Production never assigns it: the only writer is
// SetNonceSpaceForTest, which lives in a _test.go file and therefore does not
// exist in a built binary.
//
// The alternative considered and rejected was threading a space width through
// SealWhile's signature, which puts a knob no caller should turn into the
// public API of the miner in order to reach a branch no network can reach.
var nonceSpace uint64 = 1 << 32

// maxTemplateRetries bounds how many times MineOneWhile will reassemble after
// exhausting a template's whole nonce space.
//
// It is small on purpose. Reassembly buys a fresh seed only when something the
// header commits to has moved — the clock, the mempool, the tip — and a miner
// that has walked 2^32 nonces without any of the three moving is not going to
// be rescued by a fourth attempt at the same bytes; it is a node whose clock
// has stopped, and the honest answer to the caller is that there is no block,
// not an unbounded loop inside one call. The daemon's own mining loop
// reassembles on the next interval regardless, so a genuinely transient cause
// gets its retries there, where a shutdown signal can still be seen.
const maxTemplateRetries = 2

// MineOne assembles, seals and applies a single block.
func (m *Miner) MineOne(attempts uint64) (*types.Block, *fold.Result, error) {
	return m.MineOneWhile(attempts, nil)
}

// MineOneWhile is MineOne with an extra reason to give up, ORed with the one
// every caller wants anyway.
//
// That one is the tip moving. The template is built on a specific parent, and
// the moment something else extends that parent every remaining hash is spent
// on a block whose only possible outcome is ErrStaleTemplate. Against pow.Dev
// this never mattered — a solve is microseconds and the race is over before it
// starts — and against RandomX it is the difference between a miner that
// competes and one that is always a block behind.
//
// It is enforced here rather than left to callers because it is not a policy
// choice. A caller that forgot it would not fail; it would quietly mine
// yesterday's block, and the symptom is indistinguishable from bad luck.
//
// # Exhausting a template's nonce space
//
// A budget of 2^32 or more walks every nonce one template owns. If none met
// the target, this REASSEMBLES — it does not wrap onto nonces already
// rejected, and it does not roll ExtraNonce.
//
// Wrapping is excluded outright: re-testing a rejected nonce is a loop that
// reports hashrate it is not converting into coverage, and against a fixed
// template it cannot terminate.
//
// Between the two ways of reaching a seed nobody has walked, reassembly is the
// one the architecture already chose. docs/ARCHITECTURE.md §12 says a solo
// miner "sets it to 0 and loses nothing", because "a template refresh re-rolls
// the seed anyway" —
// through Time, through CertRoot as the mempool moves, and through the parent
// itself if the tip advanced. So reassembly reaches a fresh 2^32 space by the
// route the design already relies on, and it does it while picking up the
// transactions and the tip that arrived during the search — which a rolled
// ExtraNonce, hashing a template now minutes stale, would not.
//
// ExtraNonce is left at zero because its job is *separation between* miners,
// not depth for one: it is what lets a pool hand each connection a space no
// other connection is walking (ARCHITECTURE §12, types.PoWSeal). A solo miner
// has nobody to be separated from, and using it for depth here would give this
// loop a second mechanism doing the first one's job. That matches the
// Monero/XMRig precedent, where extra-nonce sharding is the pool's instrument
// — varied per connection or per job in the coinbase's tx_extra — while a
// miner that exhausts its nonce range asks for new work rather than rolling
// the pool's field itself.
//
// The loop is bounded rather than infinite. Reassembly is only progress if the
// template actually changed, and a node whose clock, mempool and tip are all
// static reassembles the identical header and would spin forever on it. So an
// exhausted space is retried a small fixed number of times and then reported,
// which is also what keeps this reachable in a test without 2^32 hashes.
//
// None of this is reachable on a live network. 2^32 RandomX hashes is weeks of
// work for the hardware this milestone targets, against a 30-second interval.
// It is written down because "unreachable" is a statement about hardware, and
// the alternative to defining the case is an infinite loop that appears when
// the statement stops being true.
func (m *Miner) MineOneWhile(attempts uint64, extra func() bool) (*types.Block, *fold.Result, error) {
	var b *types.Block
	for try := 0; ; try++ {
		var err error
		b, err = m.Assemble()
		if err != nil {
			return nil, nil, err
		}
		parent := b.Header.ParentID
		abandon := func() bool {
			if extra != nil && extra() {
				return true
			}
			return m.Chain.Tip().ID() != parent
		}
		err = m.SealWhile(b, attempts, abandon)
		if err == nil {
			break
		}
		// A search abandoned because the tip moved is the same event as a seal
		// that lost the race, and callers already know what to do with that.
		// Reporting it as ErrNoSolution would make healthy competition look
		// like a miner that cannot find blocks — which is the mistake I4-M3
		// records in the other direction.
		//
		// Checked before exhaustion: a moved tip makes the template stale for
		// a reason the caller already handles, and reassembling here would
		// hide a lost race behind a retry.
		if errors.Is(err, ErrNoSolution) && m.Chain.Tip().ID() != parent {
			return nil, nil, ErrStaleTemplate
		}
		// Every nonce under this template is spent. Take a fresh one.
		if errors.Is(err, ErrNonceSpaceExhausted) && try < maxTemplateRetries {
			continue
		}
		return nil, nil, err
	}
	// The block this node just found, checked against the rule everyone else
	// will check it against, BEFORE it goes anywhere.
	//
	// One hash, against a block that cost thousands of them — free in any
	// terms that matter — and it is the difference between a defect found by
	// the node that causes it and one found weeks later by a stranger whose
	// node cannot sync. Chain.Apply does not check work (node/chain's
	// fork-choice comment says why), so without this nothing local ever asks.
	//
	// What it can and cannot see, stated plainly because the difference is the
	// whole design. Try and CheckWork both go through Engine.Hash, so an
	// engine that is uniformly wrong is wrong on both sides of this comparison
	// and passes it — only a peer catches that one. What it catches is an
	// engine whose answer for one key MOVES between the seal and the check.
	// That is the wrong-key seal: a shared RandomX dataset refilled for another
	// key under the VMs already serving this one, and the block sealed while the refill
	// was in flight satisfied its target under neither key. That block was the
	// first of 1112 the node applied, announced and built on.
	if err := pow.CheckWork(m.Engine, b.Header, m.Chain.Params()); err != nil {
		return nil, nil, fmt.Errorf("%w: %v", ErrSealDoesNotVerify, err)
	}

	// The declared difficulty target, re-derived and checked against the same
	// rule every peer will re-derive it under, BEFORE the block goes anywhere —
	// the exact counterpart, four lines down, of the proof-of-work re-check
	// just above, and for the exact reason the wrong-key seal established
	// there: a producer must not trust its own construction. Without a sentence
	// saying so the next reader sees the PoW re-checked and the target not,
	// reads the asymmetry as an oversight, and removes this as redundant.
	//
	// This is the field that asymmetry was hiding. The target is re-derived on
	// all three ingress paths — p2p OnBlock, sync.ValidateHeaders,
	// chain.validateBranchDifficultyLocked — but those are the paths a block from
	// ANOTHER node takes; a block this node produces itself reaches Chain.Apply
	// through none of them, and Apply checks neither work nor target. So the
	// target was the one header field receiving the trust the PoW pointedly does
	// not. A self-inflicted wrong target — a bad clamp, a mis-scaled window — is
	// then committed verbatim into this node's own state root (F2c writes
	// Header.Target into PrevTargetSlot and the fold never validates it),
	// every peer rejects the block, and the node builds on a chain no one else
	// holds: it has forked itself, silently, from a bug in its own construction.
	if err := m.checkDeclaredTarget(b); err != nil {
		return nil, nil, err
	}

	res, err := m.Chain.Apply(b)
	if err != nil {
		if errors.Is(err, chain.ErrWrongParent) {
			// A block arrived while this one was being sealed, so the template
			// is stale. That is not a failure — it is what losing a race looks
			// like, and the answer is to build a new template on the new tip
			// rather than to force this one onto a chain it no longer extends.
			return nil, nil, ErrStaleTemplate
		}
		return nil, nil, err
	}
	m.Chain.Read(func(v chain.View) { m.Pool.OnBlock(b, v.State, v.Height) })
	return b, res, nil
}

// checkDeclaredTarget re-derives the difficulty target from the block's own
// parent window and returns ErrTargetDoesNotVerify if the header declares
// anything else. It is the target counterpart of the pow.CheckWork re-check in
// MineOneWhile; see the comment at its call site for why a producer re-derives
// a field it just wrote itself.
//
// The window ends at the block's PARENT height, not the live tip, and reuses
// the exact HeadersEndingAt / pow.NextTarget construction the ingress paths use
// (chain.validateBranchDifficultyLocked). Anchoring to the parent
// rather than the tip is deliberate: a tip that moved while the block was being
// sealed is a stale template, reported as such by Chain.Apply below, and must
// not be misread here as a forged target.
func (m *Miner) checkDeclaredTarget(b *types.Block) error {
	p := m.Chain.Params()
	window := m.Chain.HeadersEndingAt(b.Header.Height-1, int(p.DifficultyWindow)+1)
	if want := pow.NextTarget(window, p); !b.Header.Target.Eq(want) {
		return fmt.Errorf("%w: header declares %s, the rule gives %s",
			ErrTargetDoesNotVerify, b.Header.Target.String(), want.String())
	}
	return nil
}
