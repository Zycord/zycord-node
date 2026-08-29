// Package fold implements the stateful half of the protocol: the F-rules and
// the block-validity rules that protect them.
//
// The fold is sacred (P1). It has no I/O, no clocks, no goroutines, no map
// iteration in consensus order and no floating point. It is the only code in
// the tree whose bugs are unfixable after the fact.
//
// Its shape is one function over an ordered list of certificates:
//
//	reads still hold  → apply the writes, charge the fees
//	reads went stale  → skip, charge the skip fee, move on
//	deposit is gone   → drop, charge nothing, touch nothing
//
// Inclusion and application are different events, so a conflict never
// invalidates a block. What *does* invalidate a block is a proposer trying to
// bill a signature it should not be able to bill — that is what the B-rules
// are for.
package fold

import (
	"errors"
	"fmt"
	"sort"

	"zycord/core/crypto"
	"zycord/core/params"
	"zycord/core/state"
	"zycord/core/types"
	"zycord/core/u256"
)

// Outcome is what happened to one certificate at its committed position.
type Outcome uint8

// The four outcomes. Only the first three are billable events; DROPPED is a
// non-event.
const (
	// Applied: every declared read held, every write landed.
	Applied Outcome = iota
	// SkippedStale: a declared read no longer held. Billed to the deposit.
	SkippedStale
	// SkippedOverflow: a write left the 256-bit range. Billed to the deposit.
	SkippedOverflow
	// Dropped: the deposit could not be reserved. Nothing to bill, nothing
	// touched, and — critically — *not* marked seen, so the certificate can be
	// resubmitted once its depositor is funded again.
	Dropped
)

// String renders an outcome for vectors and logs.
func (o Outcome) String() string {
	switch o {
	case Applied:
		return "APPLIED"
	case SkippedStale:
		return "SKIPPED_STALE"
	case SkippedOverflow:
		return "SKIPPED_OVERFLOW"
	case Dropped:
		return "DROPPED"
	default:
		return "UNKNOWN"
	}
}

// CertOutcome records what the fold did with one certificate.
type CertOutcome struct {
	ID      types.Hash
	Outcome Outcome
	Charged u256.U256
	// Refunded is what settlement actually credited to RefundTo, and
	// RefundBurned is what it destroyed instead because RefundTo's authority
	// was already spent (§6). Exactly one of them can be non-zero: the
	// remainder is credited whole or burned whole.
	//
	// They are two fields rather than one because they are two events with
	// the same number, and reporting a destroyed remainder as "refunded" is
	// how a loss stays invisible to everything downstream — the reporting
	// half of F-FOLD-1. V5 and V6 now reject every certificate that
	// would burn a remainder into its *own* write set, so what remains here
	// is the case no stateless rule can see: an address some *earlier*
	// certificate retired (I1-M2).
	Refunded     u256.U256
	RefundBurned u256.U256

	// Swept is what F8b moved out of the addresses this certificate burned
	// and into the refund address; SweptStranded is what it had to leave
	// behind because the refund address was already spent.
	//
	// They are reported for the reason Refunded and RefundBurned are: a burn
	// used to leave whatever the address still held under it, readable and
	// unspendable forever, and nothing in the outcome said so. Both are
	// observational and enter no root.
	//
	// Both count **native drops only**, like every other number in this
	// record. F8b also moves asset residuals, and those are deliberately not
	// summed in here: one u256 cannot mean "400,000 of asset X plus 3 drops",
	// and no other outcome field reports an asset amount either — MINT and
	// TRANSFER move assets and say nothing about them here. Asset movement is
	// observed where every other asset movement is, in the cells, which is
	// what the golden vectors compare.
	Swept         u256.U256
	SweptStranded u256.U256

	// StrandedCells is how many cells F8b left behind, counting the asset
	// ones the two amounts above cannot express.
	//
	// It is a count and not a sum, and that is the whole reason it exists. A
	// residual under a burned address may be in any asset; the two counters
	// are drops, like every other number here, so an asset left behind had no
	// signal at all — the native half of this branch had a counter, a test and
	// a golden vector, and the asset half had nothing. A count needs no
	// currency: it says *something was left*, which is what makes the loss
	// loud, and a consumer that wants the amounts reads the cells under the
	// address the outcome already names as burned.
	//
	// Zero on every certificate that delivers, which is every certificate
	// whose refund address is still alive.
	StrandedCells uint32
}

// Result is everything the fold produces besides the new state.
type Result struct {
	// Outcomes are in fold order, not block order.
	Outcomes []CertOutcome

	// SeqGasUsed and ParGasUsed are the declared gas of every *included*
	// certificate, whatever its outcome. They measure physical work — a skip
	// still costs a verifier its signature checks and the fold its guard
	// evaluations — and they are what the block ceilings bound.
	SeqGasUsed uint64
	ParGasUsed uint64

	// SeqGasApplied and ParGasApplied are the declared gas of the certificates
	// that APPLIED, and they alone drive the base fees (R2-H2).
	//
	// Counting skips as demand would hand a griefer a constant-cost lever: stuff
	// blocks with certificates that conflict with themselves — self-inflicted,
	// so the billing law is untouched — at SKIP_FEE each, and drive the base fee
	// up for everyone. A skip is a failed attempt to use the chain, not a
	// signal that the chain is in demand.
	SeqGasApplied uint64
	ParGasApplied uint64
	// Burned is every unit of value destroyed by this block: base fees, skip
	// fees, credits to addresses that had already burned their authority, and
	// any subsidy the burst valve forfeited (§8.1). The last is not "value
	// destroyed" in the same literal sense as the others — it was never
	// credited in the first place — but conservation is stated against the
	// emission *schedule* rather than against what was actually paid, so a
	// shortfall against the schedule and a burn of paid-out value have to be
	// accounted identically or the identity does not close.
	Burned u256.U256
	// MinerReward is the producer's share of the subsidy plus parallel-market
	// tips. It is credited to a maturity cell, not to a spendable balance.
	MinerReward u256.U256
	// Treasury is this block's treasury share of the subsidy (§14.1). Tips are
	// not part of it: the share is taken from issuance and never from fees.
	// It is credited directly rather than through the maturity ring, which
	// would buy nothing for a cell that has no debit path at all.
	Treasury u256.U256
	// Matured is the reward, from COINBASE_MATURITY blocks ago, that this block
	// released into a spendable balance.
	Matured   u256.U256
	StateRoot types.Hash
	Undo      *state.UndoLog
}

// ErrInvalidBlock wraps every block-invalidity condition. A certificate-level
// problem is never an error — it is an outcome.
var ErrInvalidBlock = errors.New("fold: invalid block")

// RuleError names the protocol rule a block failed, alongside the wrapped
// ErrInvalidBlock every rejection already carries.
//
// The name is the point, not the message. A golden vector records the rule id
// and never the wording (spec/README.md), so the human half of a rejection can
// be improved — translated, given a measurement, shortened — without touching
// a conformance surface. It is the block-level twin of validity.RuleError,
// which has made the same promise about the V-rules since the package was
// written, and is spelled identically so that a reader who has met one has met
// both.
//
// The ids are the vocabulary of docs/ARCHITECTURE.md — §8's B0..B17 for the
// block rules, C0..C5 for a citation's, §7's V1..V9 for a certificate's, and
// §8's F3, F13 and F14 for the three fold rules that can reject (F3's
// non-user deposit cell included) — and that document is normative for them.
// An id invented here and written down nowhere would be a conformance
// requirement a second implementation could not discover.
type RuleError struct {
	Rule string
	Err  error
}

func (e *RuleError) Error() string { return e.Err.Error() }
func (e *RuleError) Unwrap() error { return e.Err }

// Rule reports which rule rejected a block, or "" if the error is not a rule
// failure.
//
// The empty answer is not a formality. conservationFailure below is
// deliberately *not* a rule: it reports arithmetic that no rule set can reach,
// and a block that trips it has found a hole in the rules rather than been
// caught by one. Keeping it nameless is what lets spec/gen refuse to commit a
// vector whose rejection came from an assertion instead of from a rule — the
// exact shape 028-invalid-cap-below-base was one deleted rule away from.
func Rule(err error) string {
	var re *RuleError
	if errors.As(err, &re) {
		return re.Rule
	}
	return ""
}

// invalid reports a block rejected by the named rule. The id is repeated in the
// message because a node operator reading a log, and a reporter following
// SECURITY.md's "which rule is broken, by number if possible", both need it in
// the text; the machine-readable copy is RuleError.Rule.
func invalid(rule, format string, args ...any) error {
	return &RuleError{
		Rule: rule,
		Err:  fmt.Errorf("%w: %s: %s", ErrInvalidBlock, rule, fmt.Sprintf(format, args...)),
	}
}

// CertRuleError names the certificate a block rule rejected the block for.
//
// The block is invalid exactly as before — this wraps ErrInvalidBlock and
// carries the same message — but a *builder* dry-running its own candidate can
// now act on it instead of abandoning the whole block: the offending
// certificate is identified, so it can be excluded and the block still
// proposed. Without that, any divergence between the mempool's screen and the
// block rules turns one unbuildable certificate into zero blocks, and a
// miner that cannot build never rescreens its own pool.
//
// Index is a position in the block's own Certs slice, valid only for the block
// that produced the error.
type CertRuleError struct {
	Index int
	Err   error
}

func (e *CertRuleError) Error() string { return e.Err.Error() }
func (e *CertRuleError) Unwrap() error { return e.Err }

// invalidCert is invalid, attributed to one certificate.
//
// The wrapped error is the ordinary *RuleError invalid would have produced, so
// Rule still names the rule through the attribution layer: a builder learns
// which certificate to drop without a verifier losing which rule it broke.
func invalidCert(i int, rule, format string, args ...any) error {
	return &CertRuleError{Index: i, Err: invalid(rule, format, args...)}
}

// conservationFailure reports an arithmetic condition that cannot occur unless
// value conservation itself has broken.
//
// It is an error rather than a panic (R2-M1). A block that trips it is rejected
// and the chain continues on other blocks; if every block trips it, the node
// halts loudly, which is the right failure mode for money and is strictly
// better than silently destroying value and discovering it in an audit.
//
// There is a self-referential reason to prefer this over saturating arithmetic:
// the proof that overflow is unreachable (I1-L8) rests on conservation, and
// saturation is precisely a conservation-violating operation. Were it ever to
// execute, it would erode the very invariant that proves it cannot.
func conservationFailure(what string) error {
	return fmt.Errorf("%w: conservation assertion failed: %s", ErrInvalidBlock, what)
}

// ApplyBlock is the state-transition function.
//
// It returns an error only when the *block* is invalid; per-certificate
// problems come back as outcomes. On error the state is left untouched: every
// block rule is checked before the first mutation.
func ApplyBlock(s *state.State, b *types.Block, p *params.Params) (*Result, error) {
	return apply(s, b, p, true)
}

// SealStateRoot returns the epoch state root a block would produce, without
// asserting anything about the root the header currently claims.
//
// It exists for the two parties that must fill a header in before it can be
// judged: a miner assembling a candidate block, and `zcd genesis` building
// block 0. It runs against a copy of the state and is deliberately not part of
// the state-transition function — the fold judges roots, it does not negotiate
// them.
func SealStateRoot(s *state.State, b *types.Block, p *params.Params) (types.Hash, error) {
	res, err := apply(s.Clone(), b, p, false)
	if err != nil {
		return types.Hash{}, err
	}
	return res.StateRoot, nil
}

// SealOutcomes reports what a block would do, without committing it.
//
// A miner dry-runs its own candidate to find the certificates that would be
// DROPPED and leave them out: a drop pays nothing and still consumes the
// block's ceilings (§10). Like SealStateRoot it runs against a copy and is not
// part of the state-transition function — the fold judges blocks, it does not
// help build them.
func SealOutcomes(s *state.State, b *types.Block, p *params.Params) (*Result, error) {
	return apply(s.Clone(), b, p, false)
}

func apply(s *state.State, b *types.Block, p *params.Params, checkRoot bool) (*Result, error) {
	// The block's certificate ids are computed once here and carried through
	// every stage that needs one (see carried).
	cc := carry(b.Certs)
	if err := checkBlockRules(s, b, p, cc); err != nil {
		return nil, err
	}

	res := &Result{Undo: &state.UndoLog{}}
	j := &journal{s: s, log: res.Undo}

	// T as it stood before this block, read before F2b has any chance to move
	// it: block rules already judged this block's ceilings against this exact
	// value (currentSeqGasTarget, blockrules.go), and F11's burst forfeiture
	// below is assessed against it too. The updated T — if this block is a
	// boundary — takes effect from the next block, never from this one.
	t := currentSeqGasTarget(s, p, b.Header.Height)

	// F2 — refresh the epoch beacon before any certificate runs, so that a
	// guard on beacon.epoch cannot go stale inside the block that advances it.
	if p.IsEpochBoundary(b.Header.Height) {
		writeBeacon(j, b, p)
	}

	// F2b — the epoch controller of whitepaper §8.1. At every boundary but
	// the first (there is no epoch before genesis to have measured), T moves
	// toward twice the applied sequential gas the epoch that just ended
	// actually used, clamped and gated on network health. Placed after F2's
	// beacon refresh and before anything reads T for this block's own
	// processing, mirroring where F2 itself sits relative to F3 onward.
	if p.IsEpochBoundary(b.Header.Height) && b.Header.Height > 0 {
		updateSeqGasTarget(j, p)
	}

	// Height 0 initialises the fee markets and the sequential target. Every
	// later block inherits them from state and updates them at the end.
	if b.Header.Height == 0 {
		j.set(types.SeqBaseFeeSlot(), p.InitialSeqBaseFee)
		j.set(types.ParBaseFeeSlot(), p.InitialParBaseFee)
		j.set(types.SeqGasTargetSlot(), u256.FromUint64(p.SeqGasTargetGenesis))
	}

	seqBaseFee := s.Get(types.SeqBaseFeeSlot())
	parBaseFee := s.Get(types.ParBaseFeeSlot())

	// F1 — canonical order. The proposer's interleaving is erased; a signer's
	// own dependent chain commits in the order it was signed (R1-C2).
	ordered := foldOrder(cc)

	minerTips := u256.Zero
	for _, cy := range ordered {
		c := cy.cert
		// Physical work is charged whatever the outcome; demand is not.
		res.SeqGasUsed += c.SeqGas(p)
		res.ParGasUsed += c.ParGas(p)

		out, tip, err := applyCertificate(j, c, cy.id, p, seqBaseFee, parBaseFee, res)
		if err != nil {
			s.Undo(res.Undo)
			return nil, err
		}
		if out.Outcome == Applied {
			res.SeqGasApplied += c.SeqGas(p)
			res.ParGasApplied += c.ParGas(p)
		}
		var over bool
		if minerTips, over = minerTips.Add(tip); over {
			s.Undo(res.Undo)
			return nil, conservationFailure("accumulated tips overflow 256 bits")
		}
		res.Outcomes = append(res.Outcomes, out)
	}

	// F2c — bookkeeping for §8.1's epoch controller, always run, boundary or
	// not. This block's own applied sequential gas joins the sample ring at
	// its epoch position; its own citations join the count for the epoch now
	// in progress (F2b already zeroed it if this block opened a new one); and
	// its ParentID and Target become what the next block's citations, if any,
	// are checked against. All four are consensus state, so all four are
	// journalled — a reorg that restored some but not others would fork the
	// chain silently.
	//
	// **PrevTargetSlot is written verbatim from a header field this package
	// never validates, and that value enters the state root**. Say it
	// here rather than leave it to be rediscovered: `pow.NextTarget` is a
	// function of the preceding DifficultyWindow+1 headers, ApplyBlock is
	// handed a state and one block, and no amount of care inside this function
	// can close that — the inputs are not present. So a block declaring a
	// fabricated target folds cleanly and the fabrication is *committed*, to be
	// read back by C4 (checkCites), counted into cited_count, and carried into
	// T by F2b.
	//
	// **Why this is not the B0b case**, which is the comparison that has to be
	// answered because checkSeedEpoch below moved a rule INTO the fold on
	// exactly this reasoning. B0b is total arithmetic over Height: it can be
	// stated as a (pre-state, block) claim, so moving it in bought golden-vector
	// coverage and path-independence for one comparison. The difficulty rule
	// cannot be stated in that shape at all — spec/gen says so, and the second,
	// parallel (params, headers) -> next_target corpus exists because of it.
	// Moving this rule in would need either a header window threaded through
	// ApplyBlock, which changes what a conformance vector IS, or the window
	// promoted into consensus state, which changes every state root from block
	// 0. Neither is a rule change; both are genesis-shaped.
	//
	// What actually protects it is that `Header.Target ==
	// pow.NextTarget(window)` is re-derived on every path by which a block
	// **from another node** reaches the chain — the ingress paths (node/p2p
	// Engine.OnBlock, and the announce path; node/sync.ValidateHeaders) and fork
	// choice (node/chain validateBranchDifficultyLocked, which was added after
	// the fact: that path once did NOT check, and the omission was itself a
	// finding). wire.md §9 states it exactly that way — "both requirements now
	// hold on every INGRESS path".
	//
	// **State it that precisely, because the qualifier is not decoration.** A
	// block this node produces itself does not take an ingress path:
	// node/miner's Seal calls Chain.Apply directly. Its target is *constructed*
	// by pow.NextTarget rather than compared against it, which is why wire.md §9
	// carries a separate normative clause for the producer — "a producer MUST
	// apply the ceiling when deriving a target" — instead of leaning on the
	// validator clause. The same function re-checks its own proof of work
	// locally four lines earlier, for the neighbouring reason (an engine whose
	// answer for one key can move between the seal and the check), so the
	// precedent for a producer re-checking what it just produced is already in
	// that file.
	//
	// The fold's own witness that it does not check is
	// TestTheEpochStateRootCommitsATargetTheFoldNeverChecks in this package.
	j.set(types.AppliedGasSampleSlot(b.Header.Height%p.EpochLength), u256.FromUint64(res.SeqGasApplied))
	if len(b.Cites) > 0 {
		cited, _ := j.s.Get(types.CitedCountSlot()).Uint64()
		j.set(types.CitedCountSlot(), u256.FromUint64(cited+uint64(len(b.Cites))))
	}
	j.set(types.PrevParentIDSlot(), u256.FromBytes(b.Header.ParentID))
	j.set(types.PrevTargetSlot(), b.Header.Target)

	// F10 — a seen entry is prunable once no valid block can include its
	// certificate again. B1 forbids inclusion above the TTL, so anything below
	// the current height is already unincludable; one block of slack costs
	// nothing and keeps the boundary obvious.
	if b.Header.Height >= 1 {
		res.Undo.SeenRemoved = s.PruneSeen(b.Header.Height - 1)
	}

	// F11 — the subsidy is split before anyone is paid: the treasury takes its
	// basis points and the producer takes the remainder, plus the
	// parallel-market tips of the certificates that applied. The producer's
	// share goes to the maturity ring, never straight to a spendable balance;
	// the treasury's is credited immediately.
	//
	// The remainder is computed by subtraction rather than by a second ratio.
	// Two independent floors would each round down and lose a drop between
	// them, and `treasury + producer == subsidy` is exactly the identity the
	// conservation property rests on.
	//
	// MulDiv64 saturates at Max, which the package otherwise forbids — but
	// saturation is unreachable here, and the proof is one line: Validate
	// rejects a share above 10000 bps, so floor(u*bps/10000) <= u for every u,
	// and a result bounded by its own input cannot overflow. It is used for
	// the ratio only; every addition and subtraction below reports its flag
	// and fails the block.
	subsidy := p.Emission(b.Header.Height)
	treasury := subsidy.MulDiv64(p.TreasuryShareBps, 10000)
	producer, under := subsidy.Sub(treasury)
	if under {
		s.Undo(res.Undo)
		return nil, conservationFailure("the treasury share exceeds the subsidy")
	}

	// The burst valve (whitepaper §8.1): a block whose included sequential
	// gas exceeds the target's ceiling 2T — block rules already reject
	// anything above the hard bound 4T — forfeits the producer's block
	// revenue quadratically in how far over it ran. Assessed on
	// res.SeqGasUsed, included gas, applied and skipped alike (§8.1: "the
	// excess cannot be stuffed with manufactured conflict at a discount").
	// The forfeited amount is credited to nobody: a permanent shortfall
	// against C, the same shape as a coinbase burned under I1-M2.
	//
	// **The base is `producer subsidy share + block fees`, not the subsidy
	// share alone, and the re-denomination onto that base is deliberate.** The
	// defect it corrects was a unit mismatch rather than a mis-sized penalty:
	// the deterrent was priced in a quantity §14.2's schedule decays to ~1.6%
	// of its genesis value, while the benefit it prices — fee revenue from
	// burst-band gas — does not decay at all. A deterrent §8.1 presents as "a
	// standing property" has to be denominated in something that tracks the
	// benefit, and `subsidy + fees` is the smallest base that does. At genesis
	// it changes almost nothing: fees are near zero, so the operating point
	// stays the 1,273-versus-1,000 drops/gas margin the audit confirmed works.
	// At the tail it tracks exactly the revenue a permanently bursting
	// producer is playing for, so the marginal cost of the last burst-band
	// unit stays coupled to the fee level whatever the era. The reasoning is
	// EIP-1559's: align what a producer stands to lose with the unit
	// manipulation would actually earn. Accepting the decay instead was
	// rejected, because "every rational producer bursts to 4T on every block,
	// forever" is not an acceptable terminal default for a mechanism §8.1
	// calls load bearing.
	//
	// **Two things this must not be misread as.** It is not a second
	// forfeiture on top of the subsidy one — §21 records that shape as
	// implemented, measured and rejected — it is the same single quadratic
	// with a wider base. And it does not touch the scenario's premise: the
	// epoch controller is hard-clamped, so what is being deterred is bursting
	// to 4T every block against a clamped controller, not runaway growth of T.
	//
	// **The treasury stays out of it.** §8.1's rule that the treasury share is
	// computed on the unreduced subsidy and is never forfeited is preserved
	// exactly: the base below is the producer's own subsidy remainder plus the
	// producer's own fee income, because bursting is the producer's choice and
	// the treasury is not a party to it.
	//
	// **Honest caveat, on the record:** no long-running economic simulation of
	// the fee market exists, so coupling the valve to fees is reasoned rather
	// than simulated. What makes that acceptable is that the genesis operating
	// point does not move — the coupling only becomes active in the regime
	// where the alternative is a decorative valve.
	//
	// Two successive MulDiv64 calls compute (excess/2T)² rather than
	// excess²/(2T)², because (2T)² can exceed 64 bits once T has grown for
	// decades and MulDiv64's divisor is a uint64. Two floors round slightly
	// in the producer's favour, deterministically on every node.
	//
	// The forfeit counts as BURNED, and that is not bookkeeping taste — it is
	// what keeps the conservation identity true. Conservation is stated
	// against the *schedule*: supply_after = supply_before + Emission(height)
	// − burned, where Emission is what §14.2's curve says this height pays,
	// not what was actually credited. A forfeit that reduced the credit
	// without registering here would leave exactly its own value unaccounted
	// for on every bursting block, and the property test would report the
	// chain silently destroying money. The precedent is I1-M2's burned
	// coinbase, a "permanent shortfall against C" recorded the same way. The
	// wider base does not change that: a forfeited tip is value the block
	// charged to a deposit and credited to nobody, which is a burn under the
	// same identity and by the same line.
	reward, over := producer.Add(minerTips)
	if over {
		s.Undo(res.Undo)
		return nil, conservationFailure("the block reward overflows 256 bits")
	}
	seqLimit := p.SeqGasLimit(t)
	if res.SeqGasUsed > seqLimit {
		excess := res.SeqGasUsed - seqLimit // ≤ 2T: block rules capped total usage at 4T
		forfeit := reward.MulDiv64(excess, seqLimit).MulDiv64(excess, seqLimit)
		reward = reward.SatSub(forfeit)
		if res.Burned, over = res.Burned.Add(forfeit); over {
			s.Undo(res.Undo)
			return nil, conservationFailure("the burst forfeiture overflows the accumulated burn")
		}
	}
	res.MinerReward = reward
	res.Treasury = treasury

	// A zero credit is skipped rather than written, so the genesis block —
	// whose subsidy is zero — leaves the treasury cell absent instead of
	// present-and-zero. That is what keeps `zcd genesis` able to report no
	// allocations of any kind, the treasury included.
	if !treasury.IsZero() {
		slot := types.TreasurySlot()
		credited, over := j.s.Get(slot).Add(treasury)
		if over {
			s.Undo(res.Undo)
			return nil, conservationFailure("the treasury cell overflows 256 bits")
		}
		j.set(slot, credited)
	}

	// F12 — the producer's share rolls through the maturity ring.
	matured, err := rollCoinbaseRing(j, b, p, res)
	if err != nil {
		s.Undo(res.Undo)
		return nil, err
	}
	res.Matured = matured

	// F12b — the two base fees are consensus state, so the fold updates them.
	// Genesis sets them; every later block steers them towards the targets.
	//
	// The target is t — the same pre-F2b value this block's ceilings and
	// burst forfeiture were measured against, since res.SeqGasApplied was
	// accumulated while processing against it. §8.1's elastic T and §8's
	// EIP-1559 base fee are two independent controllers over the same
	// number, and each must compare a block's usage to the target the block
	// actually operated under.
	//
	// The input is APPLIED gas, never included gas (R2-H2).
	//
	// The sequential input is clamped at 2T — §8.1's "hard elastic bound" —
	// before it reaches the controller. NextBaseFee's step is
	// deviation/target/BaseFeeMaxChangeDenominator, which is the intended
	// ±12.5% only while applied gas is capped at 2T; §8.1's burst valve
	// uncapped it at 4T, so an unclamped input makes the upward step reach
	// +37.5% against a downward step still bounded at −12.5% by an empty
	// block. That asymmetry ratchets: ×1.375 then ×0.875 is ×1.203 per
	// full/empty pair, a demand-independent upward drift any proposer can
	// produce for free by alternating. §8.1 asks for a step "bounded because
	// unbounded adjustment is known to oscillate rather than converge", and
	// three times the intended bound is not inside that.
	//
	// Clamping here rather than pricing the excess is deliberate. The burst
	// valve (F11 above) already charges for exceeding 2T, in subsidy, exactly
	// as §8.1 specifies. What the valve cannot do is bound this controller:
	// its price is paid in a currency the proposer chooses to earn or forgo,
	// so a proposer indifferent to revenue — self-dealing filler traffic
	// costs it only the base-fee burn it pays itself — moves the fee just as
	// far as a paying one. The clamp does not care why a block burst, which
	// is the property a consensus-state bound needs.
	//
	// The burst band is therefore priced by F11 and invisible to F12b: 2T is
	// the ceiling the fee market steers toward, and 4T is a per-block relief
	// valve that buys passage without also moving the price for everyone.
	if b.Header.Height > 0 {
		seqFeeInput := res.SeqGasApplied
		if seqLimit := p.SeqGasLimit(t); seqFeeInput > seqLimit {
			seqFeeInput = seqLimit
		}
		j.set(types.SeqBaseFeeSlot(), p.NextBaseFee(seqBaseFee, seqFeeInput, t))
		j.set(types.ParBaseFeeSlot(), p.NextBaseFee(parBaseFee, res.ParGasApplied, p.ParGasTarget(t)))
	}

	// F14 — the epoch state root is the differential guard between independent
	// implementations, and later the anchor Phase-1 checkpoints sign.
	if p.IsEpochBoundary(b.Header.Height) {
		res.StateRoot = s.Root()
		if checkRoot && res.StateRoot != b.Header.StateRoot {
			s.Undo(res.Undo)
			return nil, invalid("F14", "state root mismatch at epoch boundary height %d", b.Header.Height)
		}
	}

	return res, nil
}

// applyCertificate is F3 and F6 through F9 for one certificate.
func applyCertificate(
	j *journal,
	c *types.Certificate,
	id types.Hash,
	p *params.Params,
	seqBaseFee, parBaseFee u256.U256,
	res *Result,
) (CertOutcome, u256.U256, error) {

	// F3 — reserve first. Reserving before anything else is what makes every
	// non-dropped outcome billable, and the reservation is itself a guarded
	// delta: the deposit mechanism is built from the two primitives it exists
	// to protect.
	//
	// The reservation refuses a deposit cell that is not owned by a user
	// address, and it refuses the BLOCK rather than dropping the certificate.
	// This is F13's shape and deliberately not F3's other two refusals': those
	// two describe states an honest proposer can legitimately assemble against
	// — a burned underwriter, a balance that moved — whereas a certificate
	// arriving here with a 0x00 or 0x03 deposit cell is one V4 and V5 both
	// refuse statelessly, so reaching this line at all means a stateless rule
	// regressed. Dropping would bill nothing but would let the block stand on
	// a premise already known to be broken; F13 exists for exactly that
	// reasoning and answers it by refusing the block.
	//
	// It is the third predicate sealing the treasury cell, and it is dead code
	// in Era 0: CheckBlockRules runs V1..V9 over every certificate before the
	// fold sees one, and both V4 (an unconditional signature for
	// Deposit.Cell.Addr, which crypto.ProtocolAddress cannot satisfy because it
	// is not a hash) and V5 (IsUserAddress on the same field) reject first. It
	// changes no certificate's outcome and no state root; what it adds is that
	// the site which would drain types.TreasurySlot — F3 debits Deposit.Cell
	// directly, outside the declared write set, so V7 and F13 never see it —
	// now holds an opinion of its own instead of borrowing one from two rules
	// in another package. Reachable only by calling applyCertificate directly,
	// which is how deposit_version_internal_test.go separates it.
	if !crypto.IsUserAddress(c.Deposit.Cell.Addr) {
		return CertOutcome{}, u256.Zero, invalid("F3",
			"certificate %x deposits from a non-user address", id)
	}

	// The reservation refuses a deposit cell under a spent address. Billing is
	// otherwise exempt from spent checks, but not here: pruning may delete cell
	// values under spent addresses, and a reservation that could read a
	// prunable value would make the fold depend on when a node pruned.
	if j.s.IsSpent(c.Deposit.Cell.Addr) {
		return CertOutcome{ID: id, Outcome: Dropped}, u256.Zero, nil
	}
	balance := j.s.Get(c.Deposit.Cell)
	if balance.Lt(c.Deposit.Amount) {
		return CertOutcome{ID: id, Outcome: Dropped}, u256.Zero, nil
	}
	remaining, _ := balance.Sub(c.Deposit.Amount)
	j.set(c.Deposit.Cell, remaining)

	// F6 — applicability. Value equality, not versions: a slot that changed
	// and changed back is still applicable, because execution was a pure
	// function of the declared reads.
	if !readsHold(j.s, c) {
		out, err := settle(j, c, p, id, SkippedStale, p.SkipFee, res)
		return out, u256.Zero, err
	}

	// F7 — stage the writes. A certificate applies all of them or none; there
	// is no partial state visibility anywhere in the protocol.
	overlay, reason := stageWrites(j.s, c)
	if reason != Applied {
		out, err := settle(j, c, p, id, reason, p.SkipFee, res)
		return out, u256.Zero, err
	}

	// F8 — commit.
	for _, w := range overlay.cells {
		j.set(w.slot, w.value)
	}
	for _, a := range overlay.spend {
		j.markSpent(a)
	}

	// F8b — a burn strands nothing the fold can name.
	swept, sweptStranded, strandedCells := sweepBurned(j, c)

	// F9 — settle at actual cost. Both markets charge the full bid: the base
	// portion of each is burned, and the excess over base is a priority tip.
	// Tips are paid here and only here — on the applied path — so a builder
	// maximising revenue is maximising application and can never profit from a
	// skip (I1-H2).
	charge, burned, tip, ok := c.Fees(p, seqBaseFee, parBaseFee)
	if !ok {
		// Unreachable: V5 rejected a certificate whose ceiling overflows, and
		// B4 bounds the base fees by the maxima. Reported as block-invalidity
		// rather than a panic (R2-M1): the alternative to an assertion here is
		// a wrapped fee, and the alternative to an *error* is a halted process.
		return CertOutcome{}, u256.Zero,
			conservationFailure("fee arithmetic overflowed a certificate that passed V5 and B4")
	}

	var over bool
	if res.Burned, over = res.Burned.Add(burned); over {
		return CertOutcome{}, u256.Zero, conservationFailure("accumulated burn overflows 256 bits")
	}
	out, err := settle(j, c, p, id, Applied, charge, res)
	out.Swept, out.SweptStranded, out.StrandedCells = swept, sweptStranded, strandedCells
	return out, tip, err
}

// sweepBurned is F8b: when a certificate burns a one-shot address, whatever
// that address still holds in a cell the fold can name leaves with the
// certificate instead of staying under the burn.
//
// # Why this exists
//
// A burn is address-scoped. MARK_SPENT names SpentSlot(addr) and kills every
// cell under the address: after F8 every read and write under it fails
// forever (whitepaper §4). Every guard Era 0 derives is slot-scoped and a
// lower bound — deriveTransfer emits GUARD_GE on BalanceSlot(src, asset) —
// and the deposit cell carries no read at all, because F3 debits it outside
// the write set. The two scopes never met, so four certificate shapes could
// burn an address while accounting for only part of it: a moveless program
// whose one-shot deposit reserves less than the cell holds, a TRANSFER whose
// one-shot deposit cell is not a move source, a sweep sized against a balance
// a single unaudited node understated, and a RETIRE of an address that
// still holds a balance.
//
// # Why it is an effect and not a verdict
//
// The obvious rule is to refuse the burn — skip the certificate unless the
// address is empty. That rule cannot be written, and the reason is a proof
// rather than a preference: its verdict is a function of the cell's balance
// at commit, the balance is raised by any third party's unsigned credit, and
// therefore any such rule hands an unnamed third party the power to flip a
// verdict and bill a signature. That is exactly the fourth case whitepaper §5
// forbids — "no party the certificate does not name can cause it to be
// billed" — and it was measured before this was written: a griefer
// underwriting from a one-shot address that sorts below the victim's (found
// on the first key derivation) put one drop into the victim's cell in the
// same block and cost an honest whole-cell sweep the skip fee, for 107,822
// drops at zero priority against the victim's 1,000,000.
//
// Moving the residual instead changes no verdict at all. It runs after the
// certificate has already been decided APPLIED, so a credit can still only
// help: it lands in the refund address rather than being destroyed.
//
// # It touches slots the certificate does not declare, and that is deliberate
//
// Whitepaper §3 says the fold performs "one touch per declared slot", and F8b
// does not. The native half has precedent — settlement writes
// NativeBalanceSlot(RefundTo) on every certificate, as a fold-level primitive
// exempt from guards and from the registry, exactly as coinbase always had to
// be. The novelty is not undeclared slots as such — the fold writes the base
// fees, the gas target, the cited count, the treasury and the beacon every
// block, and declares none of them. It is that all of those are fixed protocol
// cells at fixed addresses, which anything can enumerate, while
// BalanceSlot(RefundTo.Addr, asset) is derived from certificate data: an
// address the signers chose, at a word taken from a declared source slot.
//
// Nothing about consensus depends on the declaration here. The fold is
// sequential and every touch is deterministic, the extra work is bounded by
// the certificate's own write count, and it is paid for by the schedule that
// already charges 700 gas for a MARK_SPENT
// (docs/decisions/one-shot-burn-scope.md §7a). What the declaration is load-
// bearing for is *scheduling*, and that is where a future reader has to be
// careful: whitepaper §10's forced queue takes "a deterministic lease on its
// slots", and a lease computed from declared sets cannot see this write.
// Whoever builds that lease has to widen it to cover F8b's destinations.
//
// # This rule never destroys value and never fails
//
// Both properties are deliberate, and the second is what makes the first
// safe. An earlier revision destroyed a residual it could not deliver and
// added it to res.Burned — which is the *native* burn accumulator, bounded in
// every other caller by total supply. An asset cap is an arbitrary u256
// (deriveMint rejects only amount > cap and cap == 0), so an attacker could
// mint ~2^256 of an asset to a one-shot cell, name an already-burned address
// as RefundTo, and move one unit out: the accumulator overflowed, the fold
// returned a conservation failure, and every block carrying that
// stateless-valid certificate was invalid — a permissionless way to make
// other people's blocks unacceptable. It also broke the native conservation
// identity outright, because an asset amount was being counted as destroyed
// native supply.
//
// So F8b delivers, or it leaves the value exactly where it already was, which
// is what the fold did before this rule existed. Nothing enters res.Burned,
// no accumulator can overflow, and no certificate can make a block invalid
// through this path. What is left behind is reported as SweptStranded rather
// than being silent, and it can only happen when Deposit.RefundTo's authority
// was burned by some *earlier* certificate — V5 forbids the same-certificate
// case statelessly, and settlement is burning that certificate's own deposit
// remainder into the same dead address at F9, so refund_burned is non-zero on
// exactly these certificates too.
//
// # Where the value goes, and why there
//
// Deposit.RefundTo — the certificate's own declared change address. It is
// signed over by every signer (it is inside SigningMessage), V5 requires it
// to be a native balance cell of a user address, and V5 forbids it from
// naming any address this certificate marks spent. So the destination is
// named by the certificate, chosen by its signers, and — for every burn this
// certificate performs — provably not one of the cells being swept. An asset
// residual lands at the same word under that address, which is
// BalanceSlot(RefundTo.Addr, asset).
//
// # Scope, stated exactly, because the gap is deliberate
//
// Two families of cell: the native balance cell of every burned address, and
// every cell under a burned address that this certificate itself names. A
// balance in an asset the certificate never names is NOT reachable and is
// still lost — BalanceWord is a hash of the asset id, so the assets under an
// address are not derivable from a slot, and core/state has no per-address
// index a burn could consult without a scan. See
// docs/decisions/one-shot-burn-scope.md.
//
// In Era 0 the second family is exactly the balance cells a TRANSFER debits:
// V6 forbids crediting an address the certificate burns, and OpSet reaches
// only an asset's own 0x03 cells, so a write under a 0x01 address is a
// DELTA_SUB on a balance slot or the MARK_SPENT itself. The rule is stated
// over "every cell this certificate writes there" rather than over balance
// slots because a balance word cannot be recognised — it is blake3 of an
// asset id — and because the wider form is the one that stays correct when
// the op set grows.
func sweepBurned(j *journal, c *types.Certificate) (u256.U256, u256.U256, uint32) {
	swept, stranded := u256.Zero, u256.Zero
	var cells uint32
	for _, w := range c.Writes {
		if w.Op != types.OpMarkSpent {
			continue
		}
		a := w.Slot.Addr
		moved, left := moveResidual(j, types.NativeBalanceSlot(a), c.Deposit.RefundTo.Addr)
		swept, stranded = swept.SatAdd(moved), stranded.SatAdd(left)
		if !left.IsZero() {
			cells++
		}
		for _, x := range c.Writes {
			if x.Slot.Addr != a || x.Op == types.OpMarkSpent || types.IsNativeBalanceSlot(x.Slot) {
				continue
			}
			// Asset residuals move under the same rule. Their amounts are
			// deliberately not added to the two drop counters — see
			// CertOutcome.Swept — so a cell left behind is counted instead,
			// which is the only signal a u256 of drops cannot carry.
			if _, assetLeft := moveResidual(j, x.Slot, c.Deposit.RefundTo.Addr); !assetLeft.IsZero() {
				cells++
			}
		}
	}
	return swept, stranded, cells
}

// moveResidual empties one cell under a burned address into the same word
// under dst, and reports what it moved and what it had to leave behind.
//
// Nothing is destroyed and nothing can fail. Two branches decline to move,
// and both leave the value exactly where the fold would have left it before
// F8b existed:
//
//   - dst's authority was burned by an *earlier* certificate. Writing there
//     would put the value in a cell nobody can read, which is the loss I1-M2
//     is about; leaving it under the burned source is the same loss, reported
//     honestly and with no accounting side effect.
//   - the destination cell would carry past 2^256. This is unreachable rather
//     than merely unlikely, and the proof is written down because the branch
//     cannot be tested: MINT is the only creator of asset units and its
//     GUARD_LE holds minted ≤ cap ≤ 2^256−1, while every other operation —
//     TRANSFER, settlement, and this function — only moves units between
//     balance cells. So the balances of one asset sum to its minted total,
//     and no two of them added together can exceed it. Native supply is
//     bounded far below 2^256 by the emission schedule. The branch exists
//     because a fold that reasons "this cannot happen" and then wraps is the
//     failure mode checked arithmetic is here to prevent.
func moveResidual(j *journal, src types.Slot, dst types.Address) (u256.U256, u256.U256) {
	v := j.s.Get(src)
	if v.IsZero() {
		return u256.Zero, u256.Zero
	}
	if j.s.IsSpent(dst) {
		return u256.Zero, v
	}
	target := types.Slot{Addr: dst, Word: src.Word}
	sum, over := j.s.Get(target).Add(v)
	if over {
		return u256.Zero, v
	}
	j.set(src, u256.Zero)
	j.set(target, sum)
	return v, u256.Zero
}

// settle charges the deposit, refunds the remainder, and marks the certificate
// seen.
//
// Settlement is a fold-level primitive: it is exempt from guards and from the
// spent registry, exactly as coinbase always had to be. The one place the
// registry still matters is the destination — crediting an address whose
// authority is burned would be a payment nobody can ever read, so the
// remainder is burned instead of being written into a dead cell — and the
// outcome says so, in RefundBurned rather than in Refunded.
func settle(
	j *journal,
	c *types.Certificate,
	p *params.Params,
	id types.Hash,
	outcome Outcome,
	charge u256.U256,
	res *Result,
) (CertOutcome, error) {
	var over bool
	if outcome != Applied {
		if res.Burned, over = res.Burned.Add(charge); over {
			return CertOutcome{}, conservationFailure("accumulated burn overflows 256 bits")
		}
	}
	refund, underflow := c.Deposit.Amount.Sub(charge)
	if underflow {
		return CertOutcome{}, conservationFailure("charge exceeded a deposit that passed V5")
	}
	var refunded, refundBurned u256.U256
	if !refund.IsZero() {
		if j.s.IsSpent(c.Deposit.RefundTo.Addr) {
			if res.Burned, over = res.Burned.Add(refund); over {
				return CertOutcome{}, conservationFailure("accumulated burn overflows 256 bits")
			}
			refundBurned = refund
		} else {
			credited, over := j.s.Get(c.Deposit.RefundTo).Add(refund)
			if over {
				return CertOutcome{}, conservationFailure("a refund overflows its destination cell")
			}
			j.set(c.Deposit.RefundTo, credited)
			refunded = refund
		}
	}
	j.markSeen(id, c.TTL)
	return CertOutcome{
		ID: id, Outcome: outcome, Charged: charge,
		Refunded: refunded, RefundBurned: refundBurned,
	}, nil
}

// readsHold evaluates F6's applicability predicate.
func readsHold(s *state.State, c *types.Certificate) bool {
	for _, r := range c.Reads {
		if s.IsSpent(r.Slot.Addr) {
			return false
		}
		v := s.Get(r.Slot)
		switch r.Access {
		case types.AccessExact, types.AccessGuardEQ:
			if !v.Eq(r.Operand) {
				return false
			}
		case types.AccessGuardGE:
			if v.Lt(r.Operand) {
				return false
			}
		case types.AccessGuardLE:
			if v.Gt(r.Operand) {
				return false
			}
		default:
			return false
		}
	}
	return true
}

type pendingCell struct {
	slot  types.Slot
	value u256.U256
}

type overlay struct {
	cells []pendingCell
	spend []types.Address
}

// stageWrites is F7: compute every write against the pre-certificate state on
// a scratch overlay, and discard the whole overlay if any of them fails.
//
// It returns Applied when every write landed, and otherwise the outcome the
// certificate takes. The two failure modes are genuinely different events and
// are reported as such: an address whose authority was burned between signing
// and commit is *stale*, while arithmetic that leaves [0, 2^256) is an
// *overflow* — a bound the signer could have checked and did not.
func stageWrites(s *state.State, c *types.Certificate) (overlay, Outcome) {
	var ov overlay
	for _, w := range c.Writes {
		if s.IsSpent(w.Slot.Addr) {
			// A write under a burned address fails rather than silently
			// vanishing: the permanent registry exists precisely so that a
			// payment to a dead address is loud instead of lost. This is the
			// one way a third party can cause another signer's certificate to
			// be billed, and the exact scope of the poisoning-immunity theorem
			// (I1-H3).
			return overlay{}, SkippedStale
		}
		switch w.Op {
		case types.OpMarkSpent:
			ov.spend = append(ov.spend, w.Slot.Addr)
		case types.OpSet:
			ov.cells = append(ov.cells, pendingCell{w.Slot, w.Value})
		case types.OpDeltaAdd:
			v, overflow := s.Get(w.Slot).Add(w.Value)
			if overflow {
				return overlay{}, SkippedOverflow
			}
			ov.cells = append(ov.cells, pendingCell{w.Slot, v})
		case types.OpDeltaSub:
			v, underflow := s.Get(w.Slot).Sub(w.Value)
			if underflow {
				return overlay{}, SkippedOverflow
			}
			ov.cells = append(ov.cells, pendingCell{w.Slot, v})
		default:
			// Unreachable: decoding rejects unknown operations.
			return overlay{}, SkippedOverflow
		}
	}
	return ov, Applied
}

// carried is a certificate together with its id, computed once for the whole
// block.
//
// The id is blake3 over the certificate's authorizing fields, so asking for it
// re-serialises the body — measured at ~6.7 µs against ~3.5 µs for everything
// else one certificate costs the sequential stage, when the preimage was the
// whole encoding. Three places need it: the duplicate and seen checks in the
// block rules, this order's final tiebreak, and the seen mark at settlement.
// Each used to compute it again, which made re-serialisation about eighty
// percent of a stage whose whole point is that it only touches memory.
//
// Carrying it is what keeps the body-derived id free. The alternative shape —
// leave the id over the whole encoding and key the rules on a second, body-
// derived hash — computes that hash somewhere, and computing it inside the loop
// was measured at 4.1x on the sequential stage, which is whitepaper §15's
// published throughput number missed by a factor of four.
//
// Carrying it changes no rule. The same bytes hash to the same id, so the fold
// order, the seen set and every state root are unchanged — which is exactly why
// the golden vectors must come out byte-identical after this, and why that is
// the check that matters rather than the benchmark.
type carried struct {
	cert *types.Certificate
	id   types.Hash
}

func carry(certs []*types.Certificate) []carried {
	out := make([]carried, len(certs))
	for i, c := range certs {
		out[i] = carried{cert: c, id: c.ID()}
	}
	return out
}

// foldOrder is F1: sort by (underwriter, seq, id).
//
// The certificate id breaks ties, so the order is total and no proposer choice
// survives into the state transition.
//
// The id being over the authorization rather than over the bytes is what
// makes that true of *signers* too, and it is the second half of taking
// signatures out of the id. Two certificates of one underwriter at one Seq
// tie on both leading components — block validity does not forbid the shape
// and the mempool pools it by design, because Seq is an ordering key and not
// a nonce — so the tiebreak alone decides which applies and which is billed a
// skip against a contended balance. While it was keyed on signature bytes,
// any signer of either certificate could set it at will after the competitor
// was public, and at zero cost to itself. Fee incidence and the ordering key
// were the same address; the grindable input was tied to neither. Reproduced
// in self-insured Era 0 by
// TestAPayeeCannotGrindTheFoldOrderToCaptureAContestedPayment.
//
// Two things move when the tie flips, and they are worth separating because
// each has been stated wrongly here once. The SKIP_FEE is a constant and falls
// on the deposit-cell owner either way, so the grind does not *cause* the skip:
// with a balance covering one of two obligations, one is skipped whichever way
// the tie goes. What the grind moves is who is paid — and, because the winner's
// APPLIED charge is a function of its own gas and two certificates tying on
// (underwriter, Seq) need not be the same size, it moves part of the bill too.
// Measured on the fixture: the two differ at 1363 bytes / 1600 seq / 3226 par
// against 848 / 600 / 1946, and under the shipped order the smaller applies at
// 727282 against the constant 1000000 skip. So it is theft of priority, and the
// deposit-cell owner pays a different total depending on a key it does not
// hold.
//
// Totality survives: within a valid block no two certificates share an id,
// because the duplicate check in the block rules is keyed on the same value.
func foldOrder(cc []carried) []carried {
	out := make([]carried, len(cc))
	copy(out, cc)
	sort.SliceStable(out, func(i, j int) bool {
		a, b := out[i], out[j]
		if cmp := compareAddr(a.cert.UnderwriterID(), b.cert.UnderwriterID()); cmp != 0 {
			return cmp < 0
		}
		if a.cert.Seq != b.cert.Seq {
			return a.cert.Seq < b.cert.Seq
		}
		return compareBytes(a.id[:], b.id[:]) < 0
	})
	return out
}

// writeBeacon is F2. Programs express time as ordinary guards on these cells,
// so the fold itself never reads a clock.
func writeBeacon(j *journal, b *types.Block, p *params.Params) {
	j.set(types.BeaconEpochSlot(), u256.FromUint64(p.Epoch(b.Header.Height)))
	j.set(types.BeaconHeightSlot(), u256.FromUint64(b.Header.Height))

	// Sixteen bytes of the last block of the previous epoch, zero-padded. It is
	// proof-of-work output and therefore miner-grindable (R1-L1).
	var entropy [32]byte
	copy(entropy[:16], b.Header.ParentID[:16])
	j.set(types.BeaconEntropySlot(), u256.FromBytes(entropy))
}

// updateSeqGasTarget is F2b: the epoch controller of whitepaper §8.1, run at
// every epoch boundary but the first.
//
// The median is deliberately not an average. L (EpochLength) is even at
// genesis, so "the median of an even-length list" needs a fixed convention
// or two implementations of this fold can disagree on the last bit of a
// number that gates real money — this function takes the **lower** median,
// element (L-1)/2 of the sorted ring, and no other definition may be
// substituted without moving every vector downstream of an epoch boundary.
// The choice mirrors the Monero penalty-median lineage the paper cites: one
// element, not an interpolation.
//
// The health check is done in u256 rather than plain uint64 multiplication
// on purpose: cited×10000 and HealthGateBps×L are both far inside uint64
// range under any genesis parameter set, but "far inside range under the
// parameters we shipped with" is not the same guarantee as "cannot overflow"
// (R2-S3), and the one comparison in this whole controller that multiplies
// two state-derived counters together is the one worth not taking on faith.
//
// The comparison is `≤`, and that is settled rather than open: §8's F2b writes
// it as `healthy ← cited_count × 10000 ≤ HEALTH_GATE_BPS × EpochLength`, and
// whitepaper §8.1 states the gate as "≤ 2%". sim/refold's `Cmp(...) <= 0` is
// the same sentence in this rule's second implementation. An epoch that meets
// the rate exactly is healthy.
//
// What no *shipped* parameter set can do is exhibit that boundary. cited is
// an integer, so citedRate is a multiple of 10000, and citedRate == gateRate
// has a solution only when HealthGateBps × EpochLength is itself a multiple
// of 10000. It is 200 × 2880 = 576,000 on mainnet and testnet and 200 × 64 =
// 12,800 on devnet: the boundary sits at 57.6 and 1.28 cited headers and no
// block can cite either. So on the parameters this release ships, `≤` and `<`
// return the same answer for every input, and a regression flipping this
// comparison would be invisible to the golden vectors and to sim's
// differential alike.
//
// Two tests stand where that leaves a hole, and they answer different
// questions. TestTheHealthGateAdmitsTheEpochThatExactlyMeetsItsRate pins the
// comparator itself, at a parameter set params.Validate accepts and chosen so
// the boundary has an integer — a custom-params unit test of the §21 kind
// (TestSkipsAreNotDemand, TestBurstValveAtGenesisParameters), not a sweep
// claiming to measure shipped behaviour. TestTheHealthGateBoundaryHasNoInteger-
// AtAnyShippedParameterSet then asserts the arithmetic above over every shipped
// set, so that a genesis parameter set which *would* exhibit the boundary — and
// at which one cited header decides whether a whole epoch may grow — is noticed
// while it can still be changed, and its consequences taken deliberately rather
// than inherited.
func updateSeqGasTarget(j *journal, p *params.Params) {
	l := p.EpochLength
	samples := make([]uint64, l)
	for i := uint64(0); i < l; i++ {
		v, _ := j.s.Get(types.AppliedGasSampleSlot(i)).Uint64()
		samples[i] = v
	}
	sort.Slice(samples, func(a, b int) bool { return samples[a] < samples[b] })
	median := samples[(l-1)/2]

	cited, _ := j.s.Get(types.CitedCountSlot()).Uint64()
	citedRate, _ := u256.FromUint64(cited).Mul(u256.FromUint64(10000))
	gateRate, _ := u256.FromUint64(p.HealthGateBps).Mul(u256.FromUint64(l))
	healthy := !citedRate.Gt(gateRate)

	t, _ := j.s.Get(types.SeqGasTargetSlot()).Uint64()
	next := p.NextSeqGasTarget(t, 2*median, healthy)

	j.set(types.SeqGasTargetSlot(), u256.FromUint64(next))
	// The counter served the epoch that just ended; the epoch beginning now
	// starts at zero and accumulates via F2c as blocks arrive.
	j.set(types.CitedCountSlot(), u256.Zero)
}

// rollCoinbaseRing implements coinbase maturity.
//
// The architecture spec calls maturity "a V-rule on spends", which cannot work:
// balances are fungible, so no stateless rule can tell a young coin from an old
// one. Instead the fold keeps a fixed-size ring of COINBASE_MATURITY pending
// rewards under the protocol address. At height H the slot for H mod maturity
// holds the reward written at H − maturity: releasing it and overwriting it in
// the same step is exact, is O(1), and needs no history.
//
// A reward whose payout address has burned its authority in the meantime is
// burned rather than written into a cell nobody can read. That burn falls on
// the producer's share alone: the treasury's was credited at F11 and never
// enters the ring, and the protocol address cannot burn its own authority.
//
// **A zero reward clears the entry instead of naming its producer.**
// ARCHITECTURE's F12 used to read as an unconditional overwrite, which
// disagreed with this line and with sim/refold on a committed state root at
// parameter values params.Validate accepts; the folds were right and the text
// has been corrected, so this is now the rule and not an undocumented liberty.
// The reason is the release side four lines above: it gates on the AMOUNT, so
// an entry whose amount is zero can never pay anybody at any future height.
// state.Set deletes a cell it is given zero — a drained cell and a cell that
// never existed are deliberately the same state — so the unconditional write
// would store the address half of a pair whose amount half is absent: a payout
// address standing in consensus state, inside the root, for CoinbaseMaturity
// blocks, against a payment that does not exist.
//
// **This is NOT the same thing as F11's zero-credit skip one screen above, and
// collapsing the two is what turns a rule into a preference.** F11's treasury
// cell is a single accumulator, so skipping a zero credit is state-EQUIVALENT
// to performing it — `cell + 0` is `cell`, and Set deletes on zero, so an
// absent cell stays absent either way. That skip moves no root; it is there so
// `zcd genesis` can report no allocations, and it is inert. F12's entry is a
// PAIR whose halves are written separately, so the amount half is absent under
// either rule while the address half differs — and the root differs with it.
// F11's is tidy; this one is load bearing.
//
// Block 0 is where it is not optional: Emission(0) is zero and
// checkGenesisShape forbids certificates, so EVERY chain takes this branch at
// genesis and `zcd genesis` has to be able to report no allocations of any
// kind.
//
// Reachability, because "unreachable" was the reason this went unnoticed and
// it is not true. Above height 0 a zero reward needs producer + tips to be
// zero. TreasuryShareBps = 10000 was one route, and it has since been closed
// — Validate now refuses a share at or above 10000, precisely because a zero
// producer share leaves the burst valve nothing to forfeit. That closes the
// route and does NOT make this branch unreachable, which was always the
// point: F11's burst valve forfeits the producer's whole block revenue at
// seq_gas_USED == 4T exactly. Since the forfeiture base was re-denominated to
// the subsidy share PLUS the block's fees, that route no longer needs the
// second condition it used to carry — it used to require tips of zero as
// well, which a self-dealing proposer declaring priority 0 supplied for free
// (§21) — because a 4T block now forfeits the tips along with the subsidy and
// pays its producer zero however its certificates bid. That surviving route
// is driven at devnet's own treasury share of 300 by
// coinbase_ring_zero_test.go.
func rollCoinbaseRing(j *journal, b *types.Block, p *params.Params, res *Result) (u256.U256, error) {
	index := b.Header.Height % p.CoinbaseMaturity
	addrSlot := types.PendingCoinbaseAddrSlot(index)
	amountSlot := types.PendingCoinbaseAmountSlot(index)

	matured := u256.Zero
	if amount := j.s.Get(amountSlot); !amount.IsZero() {
		payee := types.Address(j.s.Get(addrSlot).Bytes())
		if j.s.IsSpent(payee) {
			var over bool
			if res.Burned, over = res.Burned.Add(amount); over {
				return u256.Zero, conservationFailure("accumulated burn overflows 256 bits")
			}
		} else {
			target := types.NativeBalanceSlot(payee)
			credited, over := j.s.Get(target).Add(amount)
			if over {
				return u256.Zero, conservationFailure("a matured reward overflows its destination cell")
			}
			j.set(target, credited)
			matured = amount
		}
	}

	if res.MinerReward.IsZero() {
		j.set(addrSlot, u256.Zero)
		j.set(amountSlot, u256.Zero)
	} else {
		j.set(addrSlot, u256.FromBytes(b.Header.EmissionAddr))
		j.set(amountSlot, res.MinerReward)
	}
	return matured, nil
}

// journal wraps the state so that every mutation is recorded for undo. Undo is
// cheap because writes are declared: it is a reversed list of pairs, never a
// re-execution.
type journal struct {
	s   *state.State
	log *state.UndoLog
}

func (j *journal) set(slot types.Slot, v u256.U256) {
	j.log.Cells = append(j.log.Cells, state.CellUndo{Slot: slot, Old: j.s.Get(slot)})
	j.s.Set(slot, v)
}

func (j *journal) markSpent(a types.Address) {
	if j.s.IsSpent(a) {
		return
	}
	j.s.MarkSpent(a)
	j.log.SpentAdded = append(j.log.SpentAdded, a)
}

func (j *journal) markSeen(id types.Hash, ttl uint64) {
	if _, ok := j.s.Seen(id); ok {
		return
	}
	j.s.MarkSeen(id, ttl)
	j.log.SeenAdded = append(j.log.SeenAdded, id)
}

func compareAddr(a, b types.Address) int { return compareBytes(a[:], b[:]) }

func compareBytes(a, b []byte) int {
	for i := range a {
		if a[i] != b[i] {
			if a[i] < b[i] {
				return -1
			}
			return 1
		}
	}
	return 0
}

// UndoBlock reverses ApplyBlock exactly, restoring cells, registry entries and
// the seen set. Certificates from an abandoned branch whose TTLs are still live
// return to the mempool and may be re-included on the new branch — where they
// are billed once, never twice.
func UndoBlock(s *state.State, log *state.UndoLog) { s.Undo(log) }

// assertNoProtocolWrites is F13: defence in depth behind V7. A certificate that
// reached the fold with a protocol write means a V-rule regressed, and the only
// safe response is to refuse the block.
func assertNoProtocolWrites(certs []*types.Certificate) error {
	for _, c := range certs {
		for _, w := range c.Writes {
			if w.Slot.Addr[0] == crypto.AddrVersionProtocol {
				return invalid("F13", "certificate %x writes a protocol cell", c.ID())
			}
		}
	}
	return nil
}
