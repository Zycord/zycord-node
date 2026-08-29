// Package sync validates header chains before it fetches anything.
//
// This is the M3 gate, and the reason is R4-H1. Without it a node holds
// "orphan blocks" whose declared `Target` it cannot check — the LWMA rule needs
// the preceding window of ancestors, and an orphan by definition does not have
// them attached. An attacker therefore declares a trivial target, produces
// structurally-valid blocks at no cost, and prices the victim's memory. The
// declared accumulated work is forgeable by the same route, so work-based
// eviction does not close it either.
//
// Headers-first removes the concept rather than bounding it. A header chain can
// be validated link by link: each header's parent, its proof of work against
// its *declared* target, and — the part that matters — that the declared target
// is the one the LWMA rule computes from the headers before it. Once that
// holds, accumulated work is a fact rather than a claim, and bodies are fetched
// only along a chain that has already earned them.
//
// The rule that survives from M2-G5: **a syncing node never accepts state it
// did not re-derive.** There is no trusted snapshot path in Era 0, because a
// fair-launch chain whose new nodes trust somebody else's state is not one.
package sync

import (
	"errors"
	"fmt"
	gosync "sync"
	"time"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/verify"
)

// Errors returned by header validation. Each names a distinct lie a peer can
// tell, because "invalid headers" in a log is not something anyone can act on.
var (
	ErrNotContiguous   = errors.New("sync: headers are not a contiguous ascending chain")
	ErrBrokenLinkage   = errors.New("sync: a header does not name its predecessor")
	ErrBadWork         = errors.New("sync: a header does not meet its declared target")
	ErrForgedTarget    = errors.New("sync: a header declares a target the difficulty rule does not produce")
	ErrBadTime         = errors.New("sync: a header's time is not above the median of its predecessors")
	ErrBadVersion      = errors.New("sync: unknown header version")
	ErrEmpty           = errors.New("sync: no headers")
	ErrDoesNotAttach   = errors.New("sync: headers do not descend from a known block")
	ErrBodyUnavailable = errors.New("sync: peer will not serve a body for a header it advertised")
	// ErrHeadersWithheld reports that the *first* header of a range is dated
	// beyond the future-time limit, so there is nothing here to validate yet.
	// It is not a lie a peer told: it is a range this node cannot judge until
	// its clock advances, and it scores nobody.
	ErrHeadersWithheld = errors.New("sync: headers are dated beyond the future-time limit; withheld")
)

// WithheldError carries how far ahead the header that stopped a pass was, so a
// caller can report the gap rather than only the fact.
//
// The gap was already computed for the error text and then thrown away, which
// is most of why a node whose clock is slow past the future-time limit fell
// permanently behind in silence on this path: runOnce turns ErrHeadersWithheld
// into a successful empty Result — correctly, since it is neither a failure nor
// anybody's fault — and a Result carrying no reason is indistinguishable from a
// node that had nothing to do. The number is the one an operator needs, since
// it is what their clock is out by.
type WithheldError struct {
	// SkewSeconds is header 0's timestamp minus this node's clock.
	SkewSeconds uint64
	// Time and Now are the two readings it came from.
	Time, Now uint64
}

func (e *WithheldError) Error() string {
	return fmt.Sprintf("%s: header 0 is dated %d, this node's clock reads %d (%ds ahead)",
		ErrHeadersWithheld.Error(), e.Time, e.Now, e.SkewSeconds)
}

// Unwrap keeps errors.Is(err, ErrHeadersWithheld) true, which runOnce and
// SyncPenalty both depend on.
func (e *WithheldError) Unwrap() error { return ErrHeadersWithheld }

// Clock is the wall clock the future-time limit is read against, and the only
// clock in the sync path. It is a variable so a test can drive it; it is
// package-level rather than a parameter because every caller of
// ValidateHeaders would otherwise have to thread a clock it has no other use
// for, and because there is exactly one right answer per process.
//
// The future-time rule cannot be evaluated without a clock, and that is why it
// is not a validity rule (R1-H2): consensus never reads one. Sync therefore
// *truncates* rather than rejects — the range stops at the first header this
// node cannot yet judge, and the rest arrives on a later pass.
var Clock = time.Now

// Candidate is a validated header chain awaiting bodies.
//
// Every field is a conclusion, not a claim: the headers have been checked
// against each other and against the difficulty rule, and the work is computed
// from targets that were verified rather than asserted.
type Candidate struct {
	// AttachesTo is the known block these headers descend from.
	AttachesTo types.Hash
	// Headers are contiguous and ascending from AttachesTo's child.
	Headers []types.Header
	// Work is the accumulated work the chain would add. Because the targets
	// were validated, this number cannot be inflated by declaring easy blocks.
	Work u256.U256
}

// Tip returns the last header.
func (c *Candidate) Tip() types.Header { return c.Headers[len(c.Headers)-1] }

// ValidateHeaders checks a header sequence against a chain it descends from.
//
// The difficulty check is the load-bearing one, and it is what an orphan pool
// cannot do. `pow.NextTarget` is a pure function of the preceding window, so a
// receiver recomputes what each header's target *must* be and compares. A peer
// that declares an easier target to inflate its apparent work fails here, at
// the cost of one recomputation and before a single body is requested.
// workChecker is what ValidateHeaders uses to evaluate proof of work.
//
// It exists so extendToCover can hand in a memo across its own loop; see
// validateHeadersWith. verify.WorkWasChecked satisfies it, and a nil one means
// "evaluate every time", which is what every caller outside that loop wants.
type workChecker interface {
	Check(e pow.Engine, h types.Header, p *params.Params) error
}

func ValidateHeaders(c *chain.Chain, engine pow.Engine, headers []types.Header) (*Candidate, error) {
	return validateHeadersWith(c, engine, headers, nil)
}

func validateHeadersWith(c *chain.Chain, engine pow.Engine, headers []types.Header,
	memo workChecker) (*Candidate, error) {
	if len(headers) == 0 {
		return nil, ErrEmpty
	}
	p := c.Params()

	// CanonicalHeader, not Header: the question is whether this sequence
	// attaches to *this* chain, and the chain retains the headers of blocks a
	// reorg removed. Header answers for those too, so a candidate would anchor
	// on a block we are not built on — the headers would validate, the bodies
	// would be fetched, and ConsiderBranch would reject the lot with
	// ErrUnknownAncestor, which nothing scores. The loop would then retry from
	// the same place forever, downloading and discarding, with every diagnostic
	// reporting health. That is the minority-branch-rejoin defect arriving
	// through the door the
	// previous fix closed.
	anchor, err := c.CanonicalHeader(headers[0].ParentID)
	if err != nil {
		return nil, fmt.Errorf("%w: parent %x", ErrDoesNotAttach, headers[0].ParentID[:8])
	}

	st := newHeaderState(c, *anchor)
	accepted, err := st.accept(engine, p, headers, memo)
	if err != nil {
		return nil, err
	}
	return &Candidate{AttachesTo: anchor.ID(), Headers: accepted, Work: st.work}, nil
}

// headerState is the running state a header is checked against: the block it
// must name as its parent, the height it must claim, the window the difficulty
// rule reads, and the work accumulated so far. Nothing else decides a header,
// which is what makes validation resumable.
//
// Resumable is the point. `extendToCover` used to re-validate the whole
// accumulated candidate on every pass — the anchor lookup, the ancestor window,
// and then contiguity, linkage, the LWMA derivation and the median-time sort
// for every header it had already accepted — so the structural cost of one
// attempt was quadratic in the number of headers, and the header-replay grief
// audit measured what that buys a peer: 16.4 seconds and 373 MiB of allocation
// churn at height 6,000, adopting zero blocks. Carrying the state forward makes
// each header's checks run exactly once per attempt, and the checks themselves
// are unchanged.
type headerState struct {
	// prevID is the id the next header must name as its parent, and nextHeight
	// the height it must claim.
	prevID     types.Hash
	nextHeight uint64
	// window is up to DifficultyWindow+1 headers ending at the last accepted
	// one, oldest first — exactly what pow.NextTarget and pow.CheckMedianTime
	// read.
	window []types.Header
	// work is the accumulated work of the headers accepted so far, computed
	// from targets that were verified rather than asserted.
	work u256.U256
	// accepted counts them, and it is what separates "this range starts beyond
	// my clock" (withheld, nobody's fault) from "this range ends beyond my
	// clock" (truncate and keep the rest).
	accepted int
}

// newHeaderState starts validation from a block this chain already holds.
func newHeaderState(c *chain.Chain, anchor types.Header) *headerState {
	return &headerState{
		prevID:     anchor.ID(),
		nextHeight: anchor.Height + 1,
		window:     ancestorWindow(c, anchor, int(c.Params().DifficultyWindow)+1),
		work:       u256.Zero,
	}
}

// adopt folds headers that have ALREADY been validated into the state without
// re-checking them, and it is the whole of the incremental extension.
//
// Sound because the state is a pure function of the headers: the parent id, the
// height, the window and the sum are what a re-validation would have recomputed,
// and recomputing them proves nothing that accepting them the first time did not
// already prove. It is deliberately not exported and has exactly one caller —
// extendToCover, which passes headers this package validated itself in this same
// attempt. Handing it anything a peer said would be handing a peer the
// difficulty rule.
func (st *headerState) adopt(headers []types.Header, work u256.U256, p *params.Params) {
	if len(headers) == 0 {
		return
	}
	last := headers[len(headers)-1]
	st.prevID = last.ID()
	st.nextHeight = last.Height + 1
	st.work = work
	st.accepted += len(headers)

	n := int(p.DifficultyWindow) + 1
	if len(headers) >= n {
		st.window = append([]types.Header{}, headers[len(headers)-n:]...)
		return
	}
	st.window = append(append([]types.Header{}, st.window...), headers...)
	if len(st.window) > n {
		st.window = st.window[len(st.window)-n:]
	}
}

// accept validates headers as a continuation of the state and folds the ones
// that pass into it, returning them. A range that runs past this node's
// future-time limit is truncated rather than refused, exactly as before.
func (st *headerState) accept(engine pow.Engine, p *params.Params, headers []types.Header,
	memo workChecker) ([]types.Header, error) {
	now := uint64(Clock().Unix())
	for i, h := range headers {
		// The HEIGHT this position must hold, and every message below names it
		// rather than the loop index.
		//
		// The index reads exactly like a height and is not one, and the
		// wrong-key-seal incident reports what that costs first-hand. A node
		// syncing the poisoned chain printed `header 69`; the first invalid
		// block was at height 70. Two numbers one apart are worse than two
		// numbers far apart: the range happened to start near genesis, so the
		// index looked like a height that was almost right, and nothing in the
		// message says which of the two it is. A range fetched from a tip
		// thousands of blocks up would have made the same line point nowhere at
		// all.
		height := st.nextHeight
		if h.Version != types.HeaderVersion {
			return nil, fmt.Errorf("%w: header at height %d", ErrBadVersion, height)
		}
		if h.Height != height {
			return nil, fmt.Errorf("%w: header %d of the range claims height %d, not %d",
				ErrNotContiguous, i, h.Height, height)
		}
		if h.ParentID != st.prevID {
			return nil, fmt.Errorf("%w: header at height %d", ErrBrokenLinkage, height)
		}

		// The target must be the one the rule produces, not the one claimed.
		if want := pow.NextTarget(st.window, p); !h.Target.Eq(want) {
			return nil, fmt.Errorf("%w: header at height %d declares %s, the rule gives %s",
				ErrForgedTarget, height, h.Target.String(), want.String())
		}
		// The median lower bound BEFORE the work check, and the order is the
		// point.
		//
		// Both are consensus and both must pass, so the order cannot change
		// which headers are accepted — only what a peer feeding garbage costs
		// this node. Under pow.Dev that cost was one BLAKE3 pass and the order
		// was arbitrary. Under RandomX a work evaluation is memory-hard and
		// runs in milliseconds, roughly three orders of magnitude above the
		// median, which is a sort of eleven integers. Checking work first
		// means a peer can spend one byte of a wrong timestamp to buy a
		// millisecond of this node's CPU, per header, for as many headers as a
		// range holds.
		//
		// This does NOT close the DoS on its own and should not be read as
		// doing so: a header with a *plausible* timestamp still reaches the
		// work check, which is the whole design — proving work is what an
		// honest header does. What it removes is the free half.
		if err := pow.CheckMedianTime(h, st.window, p); err != nil {
			return nil, fmt.Errorf("%w: header at height %d: %v", ErrBadTime, height, err)
		}
		// And the work must actually have been done against it.
		checkWork := pow.CheckWork
		if memo != nil {
			checkWork = memo.Check
		}
		if err := checkWork(engine, h, p); err != nil {
			return nil, fmt.Errorf("%w: header at height %d: %v", ErrBadWork, height, err)
		}

		// The future-time limit, on the other ingress path — and
		// **last**, after every check that can be made without a clock.
		//
		// The gossip path withholds a future-dated *block* in a queue; here the
		// unit is a range of headers, and the equivalent of withholding is to
		// stop the range at the first header this node's clock cannot reach and
		// judge what precedes it. The peer is not scored, nothing is discarded,
		// and the next pass — the sync loop runs every few seconds — picks the
		// range up where the clock now allows.
		//
		// Without it the withhold rule would hold on one path and not the other,
		// which is the shape of the defect being fixed rather than the fix: a
		// node fed by sync would still fold a header dated 10^9 seconds ahead,
		// and the median-ratchet freeze — unbounded future timestamps dragging the
		// median forward until honest miners backdate and the target divides to the
		// floor — would still be reachable through it.
		//
		// **The ordering is the fix, not decoration.** This check used to run
		// first, before Version, Height, ParentID, NextTarget, CheckMedianTime
		// and CheckWork had looked at the header at all. `runOnce` converts
		// ErrHeadersWithheld into a successful empty Result — nothing to do
		// this pass, no score, nothing logged — so a peer could send one header
		// with zero proof of work, a fabricated height and a future date, and
		// turn every sync pass it was selected for into a silent no-op at a
		// cost of zero hashes and no reputational charge. That is the free,
		// unscored, indistinguishable-from-health shape of the
		// minority-branch-rejoin defect and of the whole-attempt stall, where
		// one peer holds the single-threaded sync loop indefinitely at no cost.
		// Ordered here, a garbage header is refused as garbage and scored as
		// garbage, and only a header that is *otherwise entirely valid* is
		// withheld. `node/p2p.OnBlock` has always been ordered this way, with a
		// comment saying why; this is its sibling agreeing with it.
		//
		// Truncation semantics are unchanged: the withheld header is dropped
		// from the range and contributes no work, exactly as before. The cost is
		// one extra work verification per truncated pass, which is the price of
		// not letting an unverified header decide anything.
		//
		// `st.accepted`, not `i`: an extension whose FIRST header is dated too far
		// ahead is not a withheld range — the headers before it were accepted on
		// an earlier batch of the same attempt, so the range this node can judge
		// simply ends here. Only a state that has accepted nothing at all is
		// looking at a range that starts beyond its clock.
		if pow.IsTooFarAhead(h, now, p) {
			if i == 0 && st.accepted == 0 {
				return nil, &WithheldError{SkewSeconds: h.Time - now, Time: h.Time, Now: now}
			}
			return headers[:i], nil
		}

		st.work = st.work.SatAdd(chain.BlockWork(h.Target))
		st.window = append(st.window, h)
		if len(st.window) > int(p.DifficultyWindow)+1 {
			st.window = st.window[len(st.window)-(int(p.DifficultyWindow)+1):]
		}
		st.prevID = h.ID()
		st.nextHeight++
		st.accepted++
	}

	return headers, nil
}

// ancestorWindow returns up to n headers ending at the anchor, oldest first.
func ancestorWindow(c *chain.Chain, anchor types.Header, n int) []types.Header {
	// One lock acquisition, not one per header.
	//
	// This used to call BlockAt in a loop — ninety-two separate acquisitions
	// for a mainnet difficulty window, each one a chance for a reorg to land
	// between two reads. The window then mixed headers from two branches,
	// pow.NextTarget derived a target from the mixture, and the honest peer
	// whose header did not match it was scored down for this node's own race:
	// silent, blaming the wrong party, and costing liveness rather than
	// reputation because a ban also removes a peer from sync candidacy
	// (I5-M5).
	//
	// **That defect is read-verified and was never observed.**
	// node/chain's TestTheDifficultyWindowIsOneSnapshot drives real reorgs
	// against the window and does not fail the old shape — the interleave is
	// too narrow to hit by chance. It is recorded that way rather than as a
	// caught bug, per the rule about not upgrading that
	// classification quietly.
	//
	// The other half needs no such caveat: it decoded ninety-two block bodies
	// to read ninety-two headers, and that stopped being free the moment work
	// did.
	return c.HeadersEndingAt(anchor.Height, n)
}

// replacedWork is the work of the blocks this chain holds above an anchor —
// exactly what a candidate attaching there would displace.
//
// One function, and that is the point rather than tidiness. Two places need
// this sum: the loop that decides how far to grow a candidate, and the check
// that decides whether the grown candidate wins. The whole of the
// minority-branch-rejoin defect
// mechanism B was those two disagreeing — one bounded by header *count*, the
// other deciding by *work* — so a candidate stopped growing one batch before it
// could have won and lost in silence.
//
// A fix that makes two computations agree, and leaves them as two copies, is
// one edit away from the defect it fixed. So there is one copy.
func replacedWork(ch *chain.Chain, anchorHeight uint64) (u256.U256, error) {
	total := u256.Zero
	for h := anchorHeight + 1; h <= ch.Height(); h++ {
		blk, err := ch.BlockAt(h)
		if err != nil {
			return u256.Zero, err
		}
		total = total.SatAdd(chain.BlockWork(blk.Header.Target))
	}
	return total, nil
}

// BetterThanTip reports whether a candidate is worth fetching bodies for.
func (c *Candidate) BetterThanTip(ch *chain.Chain) (bool, error) {
	anchor, err := ch.CanonicalHeader(c.AttachesTo)
	if err != nil {
		return false, ErrDoesNotAttach
	}
	replaced, err := replacedWork(ch, anchor.Height)
	if err != nil {
		return false, err
	}
	return c.Work.Gt(replaced), nil
}

// BodyFetcher supplies block bodies for validated headers.
//
// It is an interface so that the driver can be tested against a peer that
// serves, one that stalls, and one that lies — which are three different
// failure modes and only one of them is an error in the usual sense.
type BodyFetcher interface {
	// Body returns the block for a header, or an error if the peer will not or
	// cannot serve it.
	Body(id types.Hash) (*types.Block, error)
}

// forget tells a retaining fetcher to drop bodies the fold refused.
func forget(fetcher BodyFetcher, blocks []*types.Block) {
	r, ok := fetcher.(Retainer)
	if !ok || len(blocks) == 0 {
		return
	}
	ids := make([]types.Hash, 0, len(blocks))
	for _, b := range blocks {
		ids = append(ids, b.Header.ID())
	}
	r.Forget(ids)
}

// Retainer is a BodyFetcher that keeps bodies beyond the connection they
// arrived on.
//
// It exists so that retention is **offered rather than taken**. A fetcher that
// stored whatever it returned would store whatever a peer said, and the checks
// that decide whether a body is real live here in `Fetch` rather than at the
// transport. So `Fetch` validates first and then hands over what passed, and
// nothing unvalidated can reach a store that outlives its connection.
//
// The interface is optional on purpose: a plain fetcher is unaffected, and a
// caller that wants no retention simply does not implement it.
type Retainer interface {
	// Retain is called only for a body that matched its requested header id and
	// the certificate root that header commits to.
	Retain(id types.Hash, blk *types.Block)
	// Forget drops bodies the fold has since rejected.
	//
	// Retain runs before the fold does, because retention exists for the case
	// the fold cannot yet judge — a reorg whose branch is still incomplete. So a
	// body can pass every check `Fetch` can make and still be refused later as
	// block-invalid: a header carrying real work over a certificate its signer
	// never authorised, say. Keeping that body is I5-H16 through a second door
	// — a proven-bad block served from local memory to every future attempt, for
	// the life of the process.
	Forget(ids []types.Hash)
}

// Result reports what a sync attempt achieved.
type Result struct {
	Adopted bool
	// Undone carries blocks a reorg removed, so the caller can return their
	// certificates to the mempool. Dropping them loses transactions that were
	// confirmed and then reorged out.
	Undone []*types.Block
	// Applied is how many blocks were folded.
	Applied int
	// From and To bracket the range.
	From, To uint64
	// HeadersWithheld reports that a pass ended because the first header
	// offered was dated beyond this node's future-time limit, and
	// WithheldSkewSeconds is how far ahead it was.
	//
	// Carried rather than discarded because this is the sync half of the
	// slow-clock silent stall. The branch below returns a successful empty
	// Result — the right call, since the peer did nothing wrong and there is
	// genuinely nothing to do until the clock advances — and that made a node
	// whose clock is slow past FTL indistinguishable from a node that was
	// simply up to date. It stayed at a fixed lag behind the chain, every pass
	// a silent no-op, for as long as the skew lasted.
	HeadersWithheld     bool
	WithheldSkewSeconds uint64
}

// Fetch downloads bodies along a validated header chain and folds them.
//
// Bodies are requested **only** for headers that have already been validated
// and only for a chain that has already won on work, so a peer cannot make this
// node do work by describing one. Each body must match the header it was
// requested for — a peer that answers a body request with a different block is
// lying, not merely unhelpful.
//
// Body availability is consensus: a block whose bodies cannot be retrieved is
// not a valid block. A peer that advertised headers and will not serve their
// bodies is therefore reported, so the caller can score it down and try
// somebody else.
//
// **A link that dies partway through leaves the node further along than it
// started.** This used to be one all-or-nothing transfer: every body was
// downloaded and then a single branch was applied, so a sever on body 579 of
// 581 discarded 578 blocks that had already crossed the wire. That makes
// catching up a wager on one connection surviving a round trip per block — a
// wager whose odds fall as the gap grows, so a node that falls far enough
// behind can never get back, and every diagnostic reports it healthy. A
// ten-hour soak watched exactly that: a node at height 581 while the network
// reached 5,702, `peers=3`, `banned=0`, `ahead_peers=3`, and 166 sync attempts
// ending in EOF.
// engine checks proof of work for headers this function sees that
// ValidateHeaders never did: competing headers cited inside a body
// (whitepaper §8.1), which ride along with the block rather than on the
// canonical header chain ValidateHeaders already checked.
func Fetch(ch *chain.Chain, engine pow.Engine, cand *Candidate, fetcher BodyFetcher) (*Result, error) {
	// A candidate that *extends* the tip can be landed a piece at a time: every
	// prefix of it is a strict improvement on work, and applying one can never
	// leave this node on a chain nobody else has.
	//
	// A candidate that *replaces* blocks cannot. A partial branch loses to the
	// tip it would displace — correctly, and ConsiderBranch refuses it — so a
	// reorg stays all-or-nothing, and its progress is kept by not re-fetching
	// rather than by landing early. That is BodyCache, below.
	//
	// Two mechanisms because these are two cases, not one. A fix that covered
	// the first and looked complete is the exact shape of the defect this
	// project has shipped before — see `storage-fault-scored` in
	// docs/adversarial/I5.md, which was two code paths wearing one error.
	extends := cand.AttachesTo == ch.Tip().ID()

	res := &Result{From: cand.Headers[0].Height}
	blocks := make([]*types.Block, 0, len(cand.Headers))

	// land applies what has been downloaded so far. On the happy path it is
	// called once, at the end, so the ordinary case still commits one batch and
	// costs one fsync.
	land := func() error {
		if len(blocks) == 0 {
			return nil
		}
		reorg, err := ch.ConsiderBranch(chain.Branch{Blocks: blocks})
		if err != nil {
			return err
		}
		if reorg.Adopted {
			res.Adopted = true
			res.Applied += len(blocks)
			res.To = blocks[len(blocks)-1].Header.Height
			res.Undone = append(res.Undone, reorg.Undone...)
		}
		blocks = blocks[:0]
		return nil
	}

	// salvage lands the prefix in hand before reporting a failure, and only
	// where a prefix means anything. Its own error is deliberately dropped: the
	// failure worth reporting is the one the caller asked about, and a node
	// that could not land the prefix is exactly as far along as it already was.
	salvage := func() {
		if extends {
			if err := land(); err != nil {
				forget(fetcher, blocks)
			}
		}
	}

	for _, h := range cand.Headers {
		id := h.ID()
		blk, err := fetcher.Body(id)
		if err != nil {
			salvage()
			// Still ErrBodyUnavailable: at this interface a refusal and a dead
			// socket are both just an error, and body availability is
			// consensus — a peer that advertised headers and will not back them
			// has to be reportable.
			//
			// What must NOT happen is charging a peer for the network. That
			// distinction belongs where the knowledge is, in the transport: the
			// connection source marks its own failures, and the driver declines
			// to score those. Making it here would have meant Fetch guessing.
			//
			// `%w` on the inner error, and it is load-bearing rather than
			// tidy. The transport marks its own faults with a sentinel and the
			// driver tests for it with errors.Is; a `%v` here flattened that
			// sentinel into a string, so the guard never matched and every
			// severed socket charged an honest peer for this node's own packet
			// loss. The guard was written, reviewed and merged, and did
			// nothing, because one verb was wrong.
			return res, fmt.Errorf("%w: header at height %d (%x): %w",
				ErrBodyUnavailable, h.Height, id[:8], err)
		}
		if blk.Header.ID() != id {
			salvage()
			return res, fmt.Errorf("%w: header at height %d: peer served a different block",
				ErrBodyUnavailable, h.Height)
		}
		// And the body under that header must be the one the header commits to.
		//
		// The id check above proves the *header* is the header that was asked
		// for. It says nothing about the certificates carried beneath it, and a
		// peer can answer with the genuine header and a body it never had:
		// `types.UnmarshalBlock` does not verify the cert root, and the
		// cert-root check in `p2p` is on announcements rather than on served
		// bodies. The mismatch is caught by B1 inside `CheckBlockRules`, which
		// runs in `ApplyBlock` — after the body has been accepted here and
		// after anything downstream has retained it.
		//
		// Without retention that cost a liar one wasted attempt. With it, a
		// retained lie is served from local memory to every later attempt
		// against every peer, so one malicious response stops the node syncing
		// for the life of the process. Making a node able to catch up while
		// handing an attacker a way to stop it catching up forever is not an
		// improvement, and this is the line that keeps it one.
		if root := blk.ComputeCertRoot(ch.Params()); root != blk.Header.CertRoot {
			salvage()
			return res, fmt.Errorf("%w: header at height %d: body does not match the header's certificate root",
				ErrBodyUnavailable, h.Height)
		}
		// And likewise for the cited-competing-header list (whitepaper §8.1):
		// same reasoning as CertRoot, one line above.
		if root := blk.ComputeCitesRoot(ch.Params()); root != blk.Header.CitesRoot {
			salvage()
			return res, fmt.Errorf("%w: header at height %d: body does not match the header's cites root",
				ErrBodyUnavailable, h.Height)
		}
		// Structure before cost, exactly as p2p.Engine.OnBlock does it:
		// a citation's version and height are checked for the whole list before
		// a single work evaluation is paid for. A cited header's key comes from
		// its own height (pow.KeyFor), so a citation at an arbitrary height
		// names an arbitrary RandomX key epoch and costs a cache initialisation
		// rather than a hash. This path is defended by cost today — the header
		// stage checked h.Target against pow.NextTarget, so the carrier was
		// genuinely mined — but the shape is the same one, and the one place
		// the lesson was not applied is where it comes back.
		//
		// Not a consensus change, for the same reason as on the gossip path:
		// core/fold's checkCites already refuses all three of these
		// unconditionally (no block below height 2 may cite; above it a
		// citation must carry types.HeaderVersion and sit at the block's height
		// minus one), so this rejects earlier only bodies that were already
		// unconditionally invalid. The height-0 refusal that used to stand here
		// alone is subsumed by the height rule.
		//
		// This is a copy of the rule in p2p.Engine.OnBlock, not a call into it:
		// the two return different types and only this one has a salvage step,
		// and the height-0 rule it replaces was duplicated the same way. The
		// height rule is measured on both paths, because a policy with two
		// homes drifts toward whichever one nobody measures. Edit one, edit the
		// other. The may-not-cite rule below is measured on the gossip path
		// only (p2p's TestABlockAtHeightOneStillMayNotCiteGenesis): it is what
		// carries the genesis-height citation hole at a carrier height of 1,
		// where the height rule reads `0 != 0` and admits a genesis-height
		// citation that pow.CheckWork passes for free. On this path a height-1
		// carrier must first have been mined and accepted by the header stage,
		// so the same hole costs an attacker a block rather than a message; it
		// is refused here for parity rather than for price.
		if len(blk.Cites) != 0 && h.Height <= 1 {
			salvage()
			return res, fmt.Errorf("%w: header at height %d: a block at this height may not cite",
				ErrBodyUnavailable, h.Height)
		}
		for _, cited := range blk.Cites {
			if cited.Version != types.HeaderVersion {
				salvage()
				return res, fmt.Errorf("%w: header at height %d: cites a header of unknown version %d",
					ErrBodyUnavailable, h.Height, cited.Version)
			}
			if cited.Height != h.Height-1 {
				salvage()
				return res, fmt.Errorf("%w: header at height %d: cites a header at height %d",
					ErrBodyUnavailable, h.Height, cited.Height)
			}
		}
		// And only then the work. The header-validation stage above (Fetch)
		// checked proof of work for every header on the *canonical* chain being
		// synced; a cited header rides inside a body instead and was never part
		// of that chain, so its work is unchecked until here — the same gap
		// p2p.Engine.OnBlock closes on the gossip path, closed the same way on
		// this one.
		for _, cited := range blk.Cites {
			if err := pow.CheckWork(engine, *cited, ch.Params()); err != nil {
				salvage()
				return res, fmt.Errorf("%w: header at height %d: cited header fails proof of work: %v",
					ErrBodyUnavailable, h.Height, err)
			}
		}
		// Only now may it be kept. Retention is offered rather than taken: a
		// fetcher that keeps bodies across attempts is told what passed, so
		// nothing unvalidated can ever enter a store that outlives the
		// connection it came from.
		if r, ok := fetcher.(Retainer); ok {
			r.Retain(id, blk)
		}
		blocks = append(blocks, blk)
	}
	if err := land(); err != nil {
		forget(fetcher, blocks)
		return res, err
	}
	return res, nil
}

// HeaderSource supplies headers for sync.
type HeaderSource interface {
	// Headers returns up to count headers starting at a height.
	Headers(from uint64, count uint32) ([]types.Header, error)
	// Tip reports the source's advertised height and work.
	Tip() (height uint64, work u256.U256)
}

// Run performs one sync pass against a source: download headers forward from
// the point the chains diverge, validate them, and fetch bodies if they win.
//
// Forward from a known height rather than backward from the tip, because this
// node's chain is the anchor either way and forward is the direction the
// difficulty rule reads. The backward walk matters when the fork is deeper than
// the batch — handled by retrying from a lower height, which the caller drives.
func Run(ch *chain.Chain, engine pow.Engine, src HeaderSource, batch uint32) (*Result, error) {
	if batch == 0 {
		batch = 128
	}
	total := &Result{}
	for {
		res, err := runOnce(ch, engine, src, batch)
		// Merge before deciding, not after. A pass that landed blocks and then
		// hit a severed link returns both a result and an error, and the blocks
		// are on disk either way — so a caller told only about the error would
		// report no progress for a node that had just made some, and would skip
		// the readmission the blocks it *removed* require.
		total.merge(res)
		if err != nil {
			return total, err
		}
		if res == nil {
			// Unreachable today — every non-error return from runOnce carries a
			// result — and cheap insurance against a future path that does not.
			// A nil dereference in the sync loop is a crash on the one code path
			// a node uses when it is already in trouble.
			return total, nil
		}
		if !res.Adopted {
			return total, nil
		}
	}
}

// merge folds one pass's result into the running total.
//
// `Undone` is here because it was missing, and its absence was silent. Run
// copied Adopted, From, Applied and To and left Undone at nil, so the driver's
// readmission branch — `if len(res.Undone) > 0` — could never be entered, and
// every certificate a sync-driven reorg removed was dropped from the chain and
// the mempool in the same moment. That is the defect fixed for the gossip path,
// still open on this one, and nothing observed it because the code that would
// have acted on it was unreachable rather than wrong.
func (r *Result) merge(res *Result) {
	if res == nil {
		return
	}
	r.Undone = append(r.Undone, res.Undone...)
	if res.HeadersWithheld {
		// Before the Adopted early return, not after: a withheld pass adopts
		// nothing by definition, so merging it below would discard every one of
		// them and the flag would never reach a caller.
		r.HeadersWithheld = true
		if res.WithheldSkewSeconds > r.WithheldSkewSeconds {
			r.WithheldSkewSeconds = res.WithheldSkewSeconds
		}
	}
	if !res.Adopted {
		return
	}
	if !r.Adopted {
		r.Adopted, r.From = true, res.From
	}
	r.Applied += res.Applied
	r.To = res.To
}

// runOnce advances by at most one batch.
//
// Sync is a loop because a batch is a batch: a node joining a chain thousands
// of blocks long makes thousands of round trips, and each one has to be
// validated and folded before the next is requested. There is no shortcut, and
// the absence of one is the point — a syncing node never accepts state it did
// not re-derive.
func runOnce(ch *chain.Chain, engine pow.Engine, src HeaderSource, batch uint32) (*Result, error) {
	peerHeight, peerWork := src.Tip()
	if !peerWork.Gt(ch.TotalWork()) {
		return &Result{}, nil
	}

	// Walk back to the height both chains last agreed on — the true one, not a
	// batch boundary somewhere under it.
	//
	// This walk used to step back one whole `batch` per attempt, and the
	// fork-point overshoot is what that cost: a fork 1 deep and a fork 128 deep
	// landed on the same retry height, the reorg was performed *to that
	// height*, and on the run that found it 116 blocks byte-identical on both
	// branches were undone and re-applied to reach a fork 12 blocks deep. The
	// round trips were never the expense; the undo is, and `deepest_reorg`
	// records the undo.
	//
	// That counter is the instrument docs/decisions/testnet-measurements.md §1
	// names for sizing `undo_depth`, which is irreversible at genesis and,
	// below the real reorg-depth tail, a permanent partition boundary rather
	// than a margin. A stride built into the walk is a floor of `batch` built
	// into the instrument: collected as it was, the testnet's reorg-depth
	// distribution would have been a distribution of 128s wherever sync was
	// involved, and the parameter would have been sized against the sync
	// driver's batch size. So the retry height is now searched for rather than
	// stepped to — see forkPoint.
	//
	// Height 0 is the floor and is never requested: the genesis header's parent
	// slot carries the consensus root rather than a block (R3-1), so it can
	// never "attach" to anything and asking for it would loop.
	from := ch.Height() + 1
	if from > peerHeight {
		from = peerHeight
	}
	if from < 1 {
		from = 1
	}
	searches := 0
	for {
		headers, err := src.Headers(from, batch)
		if err != nil {
			return nil, err
		}
		if len(headers) == 0 {
			return &Result{}, nil
		}
		if servesOurOwnBlock(ch, headers[0]) {
			// The peer answered with a block this node already holds at that
			// height, so this range cannot carry anything to adopt. **This is
			// the header-replay grief's first line of defence and it costs one hash.**
			//
			// The grief it ends: a peer advertises `Work = 2^256-1` — free, since
			// a Hello's claim is unverified — and then answers the request with
			// this node's OWN headers from height 1. They validate, because they
			// are real: correct linkage, real proof of work, targets the LWMA rule
			// produces. The candidate anchors at genesis, weighs exactly what it
			// would replace so the extension loop can never exit on work, and the
			// node burns a core re-deriving its own chain to adopt nothing. The audit
			// measured 16.4 seconds and 373 MiB per attempt at height 6,000,
			// scaling quadratically, against a peer that spent nothing.
			//
			// Refused rather than scored, and that is not leniency. The same reply
			// arrives from an honest peer whenever this node's own tip advances
			// between choosing `from` and the answer coming back — a gossiped
			// block lands, and the peer's next header is now one we hold. Nothing
			// distinguishes the two from here, and a pass that does nothing costs
			// this node a single header request. The next pass starts from the new
			// tip.
			return &Result{}, nil
		}

		cand, err := ValidateHeaders(ch, engine, headers)
		if err == nil {
			// Extend the candidate until it outweighs what it would replace.
			//
			// This is the whole finding. One batch is 128 headers, and
			// BetterThanTip charges a candidate against *every* block from the
			// anchor to our tip — so a fork deeper than a batch compared 128 of
			// the peer's blocks against our entire divergent suffix and lost, no
			// matter how much heavier the peer's full chain was. The deeper the
			// fork, the more certainly it lost.
			//
			// And it lost in silence: not-better returns a nil error, so
			// SyncFrom logged nothing, scored nothing, and returned success.
			// Every diagnostic showed a healthy node — peers connected,
			// ahead_peers non-zero, no bans — retrying every three seconds
			// forever. That is how a node sat 216 blocks behind for an hour, and
			// how another held a different block at height 1 across 358 blocks.
			//
			// The bound is our own divergent suffix's WEIGHT, not the peer's
			// claim: the candidate grows until its work exceeds what ours
			// weighs, capped by extensionCap — a constant of the params, so
			// neither an asserted height nor the age of this chain decides how
			// far the loop runs.
			cand, err = extendToCover(ch, engine, src, cand, batch)
			if err != nil {
				return nil, err
			}
			better, err := cand.BetterThanTip(ch)
			if err != nil {
				return nil, err
			}
			if !better {
				return &Result{}, nil
			}
			// The launch checkpoint defence, after the candidate has won on
			// work and before a single body is requested for it. Both
			// orderings are deliberate: after, because a candidate that loses
			// on work is discarded anyway and a refusal here would be a
			// refusal nobody needed; before, because the whole point is that
			// this node never spends a round trip on, and never folds, a chain
			// its own release says cannot be the network's. See defence.go.
			if err := Admit(ch, cand); err != nil {
				return nil, err
			}
			return Fetch(ch, engine, cand, sourceFetcher{src})
		}
		if errors.Is(err, ErrHeadersWithheld) {
			// Not a disagreement about the rules and not about history: the
			// peer's chain starts further ahead than this node's clock. Do
			// nothing this pass, score nobody, and try again when the clock has
			// moved. A returned error here would be logged as a sync failure and
			// would eventually be read as the peer's fault.
			//
			// The *reason* travels on the Result even though the outcome is
			// "nothing to do", so the caller can tell this apart from a node
			// that was already up to date. That distinction is the slow-clock
			// stall on this path: the two look identical from the outside and
			// only one of them means the node will never catch up.
			out := &Result{HeadersWithheld: true}
			var we *WithheldError
			if errors.As(err, &we) {
				out.WithheldSkewSeconds = we.SkewSeconds
			}
			return out, nil
		}
		if !errors.Is(err, ErrDoesNotAttach) {
			// A real disagreement about the rules, not about history.
			return nil, err
		}
		if from <= 1 {
			// Back to the first block and still nothing in common: this peer is
			// on a different chain from the same genesis, which is a fork so
			// deep that resync from scratch is the only answer.
			return nil, ErrDoesNotAttach
		}
		searches++
		if searches > maxForkSearches {
			// The peer's probe answers and its bulk answers cannot both be
			// true, and this is the line that stops it charging this node for
			// the contradiction.
			//
			// `forkPoint` is bounded; the loop around it was not. A peer that
			// answers every probe out of THIS node's own chain — so each
			// search agrees at `from-2` and returns it — while answering every
			// full-batch request with a branch that does not attach, moves
			// `from` down by exactly one per pass. Measured before this bound
			// existed: 65 header requests at `undo_depth` 32, 2*undo_depth+1
			// exactly, which is ~2049 at mainnet's 1024 — for one rotation
			// slot, ending in the refusal it could have reached in three.
			//
			// Two, not one, because a chain that reorganises under the search
			// is a real and blameless way for the second request to miss: the
			// anchor was canonical when it was found and is not by the time it
			// is used. That peer is
			// TestAPeerThatReorganisesUnderTheSearchIsGivenASecondAttempt, and
			// it adopts only because the second search is there. Two concurrent
			// reorgs inside one pass is not a case to keep a peer's slot open
			// for. An honest peer needs exactly one search at any fork depth,
			// which TestAnHonestPeerNeedsOneForkSearchAtAnyDepth counts rather
			// than infers, at every depth either side of a batch.
			//
			// ErrDoesNotAttach rather than a new error: SyncPenalty charges
			// nothing for it, and it should stay that way. A contradiction is
			// what a lying peer produces, and it is also what a peer that
			// reorganised twice produces, and nothing here can tell them
			// apart — so the peer loses the slot and keeps its score.
			return nil, fmt.Errorf(
				"%w: the peer's headers do not attach at the fork point its own answers named",
				ErrDoesNotAttach)
		}
		at, ok, err := forkPoint(ch, src, from-1, batch)
		if err != nil {
			return nil, err
		}
		if !ok {
			// The peer stopped answering partway through the search. Same
			// verdict as an empty first answer: nothing to do this pass, and
			// nobody at fault.
			return &Result{}, nil
		}
		from = at + 1
	}
}

// maxForkSearches bounds how many times one sync pass may search for the fork
// point before it gives up on the peer. See the refusal in runOnce for why the
// number is two.
//
// Pinned from both sides, because a bound held in only one direction is a
// number the next reader is free to raise. Below: at one, a peer whose own
// chain reorganised under the search is refused instead of adopted, which is
// the blameless case the second search exists for. Above: the refusal against
// a contradicting peer costs exactly 2*maxForkSearches+1 header requests —
// measured 5, 7, 9 at two, three and four — and the contradicting-peer test
// asserts the literal 5, so a third search fails it.
const maxForkSearches = 2

// servesOurOwnBlock reports whether a header a peer served is byte-identical to
// the block this node already holds at that height.
//
// The id, not a re-derivation: one hash of the header answers it, which is what
// makes the refusal in runOnce O(1) per batch rather than O(range) — the whole
// point of putting it before ValidateHeaders rather than inside it.
//
// It says nothing about honesty. Our own chain is the most valid answer there
// is, and probeShared asks for exactly these headers on purpose. It says only
// that this particular range has nothing in it for us.
func servesOurOwnBlock(ch *chain.Chain, h types.Header) bool {
	id, ok := ch.CanonicalIDAt(h.Height)
	return ok && id == h.ID()
}

// sharedWindow is what one probe learned about a window of heights.
type sharedWindow struct {
	// served is false only when the peer returned nothing at all, which is not
	// evidence about the fork and is not something to descend on.
	served bool
	// top is the highest height in the window carrying the same block id on
	// both chains, and matched says whether any did.
	top     uint64
	matched bool
	// diverged says a header arrived AT THE HEIGHT IT WAS ASKED FOR and named
	// a different block than ours. Together with matched that makes top the
	// fork point *exactly* rather than a lower bound on it, and it is what lets
	// one batch-sized answer end the search.
	//
	// It is deliberately narrower than "the window ended early". A reply that
	// goes off the rails — a height other than the one requested — is not
	// evidence about the height it failed to describe, and a window that simply
	// stops short is not evidence either: Headers is documented to return *up
	// to* count headers, so a short reply is a peer being terse, not a peer
	// disagreeing. Concluding from either would put the anchor below the true
	// fork point and re-open the overshoot through a second door, so both end
	// the window instead and the search keeps narrowing on what it actually
	// verified.
	diverged bool
}

// probeShared asks the peer for one window of headers and reports how much of
// it this node already holds.
//
// Block ids, not a re-derivation of consensus: the question is only "is the
// peer's block at this height the block I have at this height", and the id
// answers it outright. Nothing here decides anything a peer could exploit —
// the range this search selects is validated in full by ValidateHeaders on the
// way back up and weighed by ConsiderBranch after that, so a peer that lies to
// a probe buys itself a rejected candidate and one wasted pass, never an
// unchecked block and never a deeper undo than its own headers can pay for.
//
// A window rather than a single header because the peer already answers this
// request shape and a batch response covers `count` heights for one round
// trip. A window that straddles the fork therefore names it exactly, which is
// what keeps the search below a dozen requests without a new wire message.
func probeShared(ch *chain.Chain, src HeaderSource, at uint64, count uint32) (sharedWindow, error) {
	headers, err := src.Headers(at, count)
	if err != nil {
		return sharedWindow{}, err
	}
	w := sharedWindow{served: len(headers) > 0}
	for i, h := range headers {
		if uint64(i) >= uint64(count) {
			// A peer that answers with more than it was asked for does not get
			// to decide how much of its answer is read. Without this the search
			// could return a height at or above the one it started from, and
			// `runOnce` would request the same range again for ever — the walk
			// terminates because `from` strictly decreases, and that is the
			// line that keeps it true.
			break
		}
		if h.Height != at+uint64(i) {
			// A reply about heights other than the ones asked for says nothing
			// about the ones asked for — including nothing about whether the
			// peer diverges there. The window ends at the last height this node
			// actually checked; the search narrows from that rather than
			// concluding from a garbled answer.
			break
		}
		id, ok := ch.CanonicalIDAt(h.Height)
		if !ok || id != h.ID() {
			w.diverged = true
			break
		}
		w.top, w.matched = h.Height, true
	}
	return w, nil
}

// forkPoint finds the highest height at which this node and the peer hold the
// same block, given one height they are known to disagree at.
//
// **Exponential back-off, then a bisect over windows**, and the shape is the
// answer to three demands at once.
//
// *Minimal.* The height it returns is the true common ancestor, so the reorg
// performed is the smallest one that reaches the peer's branch and
// `deepest_reorg` records the fork rather than the driver's stride.
//
// *Proportional.* Agreement is monotone in height — a block commits to its
// whole ancestry, so agreeing at h means agreeing everywhere below h — which
// is what makes both halves sound. The back-off probes 1, 2, 4, … below the
// known-divergent height, so a fork one deep costs one probe and a fork twelve
// deep costs four; the walk never reaches for ancient headers to resolve a
// recent split, which the fixed stride did every time.
//
// *Bounded, and bounded by something real.* The floor is the undo horizon, not
// genesis. `ConsiderBranch` refuses a reorg anchored below `height -
// undo_depth` with ErrBeyondUndoHorizon whatever the headers say, so every
// probe under that line is spent looking for an ancestor this node could not
// use if it found it. With the floor there the worst case is log2(undo_depth)
// probes to bracket plus log2(undo_depth/batch) to bisect: about fifteen
// requests at mainnet's undo_depth of 1024 and a batch of 128, against the
// eight a fixed stride takes to cover the same ground — and against the ~8,200
// the old walk would have taken to read a year-old chain back to genesis, at
// 2,880 blocks a day and 128 blocks a stride. A peer that simply denies every
// height it is asked about cannot buy more than those fifteen, and it is
// charged nothing either way, exactly as before.
//
// **A block locator is the classical shape and is deliberately not what this
// is.** A locator is one round trip instead of fifteen, but it is a new wire
// message and a new method on HeaderSource, whose only production
// implementation is in node/p2p — so it would be a protocol change to fix a
// measurement defect. `Headers(from, count)` already carries the same
// information; this reads it out of the request the peer can answer today. If
// the round trips ever start to matter, the locator is the upgrade and this
// search is what it would replace.
func forkPoint(ch *chain.Chain, src HeaderSource, disagreesAt uint64, batch uint32) (uint64, bool, error) {
	p := ch.Params()
	floor := uint64(0)
	if h := ch.Height(); h > p.UndoDepth {
		floor = h - p.UndoDepth
	}

	// hi is the lowest height known to be on the peer's branch and lo the
	// highest known to be shared, so the answer is always in [lo, hi).
	hi := disagreesAt
	var lo uint64

	for step := uint64(1); ; step *= 2 {
		if hi <= floor {
			// Nothing in common inside the horizon. Still ErrDoesNotAttach —
			// SyncPenalty charges nothing for it, and it is the same verdict
			// the old walk reached the expensive way, by fetching a whole
			// branch and having ConsiderBranch refuse it.
			return 0, false, fmt.Errorf(
				"%w: no block in common within the undo horizon of %d blocks",
				ErrDoesNotAttach, p.UndoDepth)
		}
		if hi == 1 {
			// Every height above genesis is on the peer's branch, and genesis
			// is shared by definition: a peer on another genesis is a peer on
			// another network (R3-1). It is never requested.
			return 0, true, nil
		}
		at := floor
		if hi-floor > step {
			at = hi - step
		}
		if at < 1 {
			at = 1
		}
		count := hi - at
		if count > uint64(batch) {
			count = uint64(batch)
		}
		w, err := probeShared(ch, src, at, uint32(count))
		if err != nil {
			return 0, false, err
		}
		if !w.served || (!w.matched && !w.diverged) {
			// Nothing, or nothing this node could read. Either way the probe
			// decided nothing, and a probe that decided nothing must not be
			// turned into a claim about a height — so the pass ends here and
			// the next one starts from a fresh tip.
			return 0, false, nil
		}
		if !w.matched {
			// Monotonicity: the peer's block at `at` is not ours, so none above
			// it is either, whatever the rest of this window said.
			hi = at
			continue
		}
		if w.diverged || w.top+1 == hi {
			// The window holds both sides of the split, or its shared run
			// reaches a height already known to be on the far side. Either way
			// its last shared height is the fork point itself.
			//
			// `w.top+1`, not `at+count`: count is what was ASKED for, and
			// Headers returns up to that many. A peer that replies with fewer
			// — entirely within its contract — would otherwise have a short
			// window read as one that reached hi, and the anchor would be set
			// below the true fork point. That is the fork-point overshoot again, in a
			// smaller size and reachable without anybody lying.
			return w.top, true, nil
		}
		// The shared run stopped short of hi, either because the back-off
		// outran one batch or because the peer was terse. lo is now a lower
		// bound on the answer; bisect the gap that is left.
		lo = w.top
		break
	}

	for hi-lo > 1 {
		mid := lo + (hi-lo)/2 // strictly inside (lo, hi), so both arms narrow
		count := hi - mid
		if count > uint64(batch) {
			count = uint64(batch)
		}
		w, err := probeShared(ch, src, mid, uint32(count))
		if err != nil {
			return 0, false, err
		}
		if !w.served || (!w.matched && !w.diverged) {
			// The peer went quiet mid-search, or answered something this node
			// could not read. lo is a height it served and agreed on, so
			// anchoring there is honest and never deeper than the truth; the
			// next pass narrows from a nearer tip.
			return lo, true, nil
		}
		if !w.matched {
			hi = mid
			continue
		}
		if w.diverged || w.top+1 == hi {
			return w.top, true, nil
		}
		lo = w.top
	}
	return lo, true, nil
}

// extendToCover grows a validated candidate until its accumulated work exceeds
// the work of the suffix it would replace, or the peer has no more to give.
//
// Until work, not until length, and the difference is the
// minority-branch-rejoin defect's mechanism
// B. This loop used to stop when the candidate had as many headers as the
// replaced suffix — but the decision that follows is `BetterThanTip`, which
// weighs *work*, and under LWMA two branches from one fork take different
// difficulty trajectories. A candidate whose first `need` blocks carried less
// work than our `need` blocks stopped growing and then lost, silently, when one
// more batch of headers would have won. The deeper truth is the same as the
// deep-fork defect this loop was built to fix: a bound that stops before the
// comparison can succeed.
//
// Every extension is validated exactly as the first batch was — contiguity,
// linkage, the difficulty rule recomputed from the growing window, the work
// actually done, the median time. A longer candidate is therefore not a
// weaker-checked one; it is the same check applied further.
//
// The bound is derived from the PARAMS, never from the peer's claim and no
// longer from this node's height either, so neither a peer's assertion nor the
// age of the chain decides how much work this node does. The work target is what
// our suffix actually weighs; the header cap is extensionCap. A candidate that
// is a whole horizon longer than anything it could replace and *still* lighter
// is not one more batch from winning — it is a branch so much thinner than ours
// that fetching it forever is the attack, not the sync. Validated-but-cheap
// headers are exactly what a difficulty-decayed griefing chain is made of, and
// the cap is what keeps this loop from being the buyer.
func extendToCover(ch *chain.Chain, engine pow.Engine, src HeaderSource,
	cand *Candidate, batch uint32) (*Candidate, error) {
	maxHeaders := extensionCap(ch.Params())
	// One memo for the whole extension, and it is what keeps the work function
	// off a header this attempt has already judged.
	//
	// A header's work verdict is a pure function of its bytes (the key comes
	// from the height), so a repeat costs a map lookup. Under RandomX an
	// evaluation is memory-hard and runs in milliseconds — three orders of
	// magnitude above every other per-header check — which is why this one is
	// memoised even though the structural checks are now incremental and never
	// repeat at all.
	//
	// Scoped to this call, deliberately: no lifetime question, no bound to
	// choose, and nothing retained between sync attempts.
	return extendToCoverWith(ch, engine, src, cand, batch,
		verify.NewWorkCache(maxHeaders+int(batch)+1), maxExtendRounds)
}

// extensionCap bounds how long a candidate may grow inside one attempt.
//
// A function of the params ALONE, and that is the fix for the header-replay
// grief's second half. The bound used to be `(our height - the anchor's height)
// + undo_depth`, which on a mature chain is the whole chain: a peer that
// anchored a candidate at genesis — by replaying this node's own early headers,
// which validate because they are real — bought a cap of ~H, and the loop above
// walked to it. `ConsiderBranch` refuses any branch anchored below `height -
// undo_depth` whatever its work, so every header past that horizon was bought
// and then thrown away.
//
// Twice the horizon plus the difficulty window because that is what a candidate
// could ever need: the deepest suffix it may replace is `undo_depth` blocks, the
// LWMA trajectories of two branches diverge over `difficulty_window` blocks, and
// double leaves a full horizon of slack for a branch that is winning slowly. At
// mainnet's 1024 and 90 that is 2,228 headers, above the 2,048 the old bound
// reached at the undo horizon — so nothing that could have been adopted stops
// being adoptable. It is only the part that could never have been adopted, the
// part that grows with the chain, that is gone.
func extensionCap(p *params.Params) int {
	n := 2 * (int(p.DifficultyWindow) + int(p.UndoDepth))
	if n < 1 {
		n = 1
	}
	return n
}

// maxExtendRounds caps the header requests one extension may make, however few
// headers each answer carries.
//
// The header cap alone is not a bound on round trips: a peer that answers every
// request with a single header makes the loop run once per header. The number is
// deliberately far above what an honest peer needs — a mainnet-shaped extension
// covers extensionCap's 2,228 headers in 18 requests at a batch of 128 — and far
// below what an unbounded loop would grant a peer that drips.
const maxExtendRounds = 256

// extendToCoverWith is extendToCover with its memo and its round budget passed
// in, so a test can watch both.
func extendToCoverWith(ch *chain.Chain, engine pow.Engine, src HeaderSource,
	cand *Candidate, batch uint32, memo workChecker, maxRounds int) (*Candidate, error) {
	// Canonical for the same reason as the other two, but with a caveat worth
	// stating: no test can kill this one, and that is a property rather than a
	// gap. extendToCover runs only after ValidateHeaders succeeded, and that
	// success already established the anchor was canonical. The two answers can
	// differ only if the chain reorganises between the two lock acquisitions —
	// a TOCTOU window no single-threaded test reaches. Reverting this line
	// leaves the whole suite green.
	//
	// It closes a real window and is kept, but it is defence in depth, not a
	// guarded invariant. Recording which of the two a line is costs nothing and
	// stops a later reader from trusting a test that was never there.
	anchor, err := ch.CanonicalHeader(cand.AttachesTo)
	if err != nil {
		return nil, ErrDoesNotAttach
	}

	// What the candidate must outweigh: our own blocks past the anchor. Not a
	// second copy of that sum — the *same* function BetterThanTip calls, so the
	// bound and the decision cannot drift apart again.
	replaced, err := replacedWork(ch, anchor.Height)
	if err != nil {
		return nil, err
	}

	p := ch.Params()
	maxHeaders := extensionCap(p)
	if cand.Work.Gt(replaced) || len(cand.Headers) >= maxHeaders {
		return cand, nil
	}

	// The validation state at the candidate's tip, carried rather than rebuilt.
	// This is what makes the loop below linear in the headers it accepts: the
	// candidate's own headers were validated when they arrived and are folded in
	// without being re-checked.
	st := newHeaderState(ch, *anchor)
	st.adopt(cand.Headers, cand.Work, p)

	headers := append(make([]types.Header, 0, len(cand.Headers)+int(batch)), cand.Headers...)
	for rounds := 0; !st.work.Gt(replaced) && len(headers) < maxHeaders; rounds++ {
		if rounds >= maxRounds {
			break
		}
		more, err := src.Headers(st.nextHeight, batch)
		if err != nil {
			return nil, err
		}
		if len(more) == 0 {
			// The peer has nothing further. Judge what we have; a candidate
			// shorter than the suffix it would replace can still win on work.
			break
		}
		if servesOurOwnBlock(ch, more[0]) {
			// The extension continues along a block this node already holds at
			// that height, so there is nothing here to adopt. Unreachable through
			// an honest branch — a candidate that diverges from our chain cannot
			// have a child of ours — and defence in depth against the replay in
			// the header-replay grief reaching this loop by some other door.
			break
		}
		accepted, err := st.accept(engine, p, more, memo)
		if err != nil {
			if errors.Is(err, ErrHeadersWithheld) {
				// Only reachable if the clock moved backwards between passes,
				// since cand's own headers already validated. Keep what we have.
				break
			}
			return nil, err
		}
		if len(accepted) == 0 {
			// No progress: a peer that answers a forward request without
			// extending the chain would otherwise loop this forever.
			break
		}
		headers = append(headers, accepted...)
	}
	if len(headers) == len(cand.Headers) {
		return cand, nil
	}
	return &Candidate{AttachesTo: cand.AttachesTo, Headers: headers, Work: st.work}, nil
}

// sourceFetcher adapts a HeaderSource that also serves bodies.
type sourceFetcher struct{ src HeaderSource }

func (s sourceFetcher) Body(id types.Hash) (*types.Block, error) {
	if bf, ok := s.src.(BodyFetcher); ok {
		return bf.Body(id)
	}
	return nil, errors.New("sync: source cannot serve bodies")
}

// Retain forwards to the source when the source keeps bodies.
//
// Without this the adapter silently swallows retention: `runOnce` hands `Fetch`
// a `sourceFetcher`, not the caching source underneath it, so the type
// assertion in `Fetch` failed and nothing was ever kept. The retention was
// wired to a wrapper that did not forward it — a defect that leaves every test
// about *correctness* green, because a cache that never stores anything is
// indistinguishable from no cache except in how long catching up takes.
//
// It was caught by an anti-vacuity guard asserting that the first severed
// attempt retained something, which is the whole argument for writing those
// guards.
func (s sourceFetcher) Retain(id types.Hash, blk *types.Block) {
	if r, ok := s.src.(Retainer); ok {
		r.Retain(id, blk)
	}
}

func (s sourceFetcher) Forget(ids []types.Hash) {
	if r, ok := s.src.(Retainer); ok {
		r.Forget(ids)
	}
}

// BodyCache keeps bodies that were downloaded but could not be applied, so the
// next attempt does not fetch them again.
//
// It exists for the one case `Fetch` cannot land incrementally: a reorg, where
// a partial branch loses to the tip it would replace and therefore must be
// applied whole. Without retention that case is an all-or-nothing transfer of
// the node's entire divergent suffix over one connection, retried from zero
// every time — which is how a node that lands on a minority branch stops being
// able to leave it.
//
// **A peer cannot price this node's memory with it**, which is the R4-H1
// question and the reason the cache lives here rather than at the transport. A
// body only enters after its header passed `ValidateHeaders` — contiguity,
// linkage, the difficulty rule recomputed from the preceding window, and proof
// of work actually done against the target the rule produces — and only along a
// candidate that already beat this node's tip. Filling it therefore costs real
// proof of work per entry, at the current difficulty. The caps below bound it
// anyway, because "expensive for the attacker" is a reason to be unafraid and
// not a reason to be unbounded.
//
// It is memory, not storage, and that is a real limit rather than an oversight:
// a node killed mid-catch-up loses the cache and re-fetches. Making it durable
// means keeping non-canonical blocks in the block store, which is a schema
// change — `switchTo` deletes a block the moment it leaves the chain — and it
// is the next move in this area rather than this one.
type BodyCache struct {
	mu        gosync.Mutex
	maxBlocks int
	maxBytes  int

	bytes int
	have  map[types.Hash]*types.Block
	size  map[types.Hash]int
	// order is insertion order, for eviction. Which entry goes is close to
	// irrelevant — a retry fetches by header id and any survivor saves a round
	// trip wherever it sits — so the simplest policy that cannot leak is right.
	order []types.Hash
}

// The caps.
//
// 32 MiB matches the orphan pool's byte bound (node/p2p/engine.go), for the
// same reason and against the same adversary; there is no argument for these
// two differing. The block count is the deepest reorg worth retaining: mainnet
// `undo_depth` is 1024 and `ConsiderBranch` refuses anything deeper, so beyond
// that a retained body could never be applied by any route.
//
// A reorg too large for the caps thrashes and makes no progress — exactly the
// behaviour before this existed, so the failure mode degrades to the old one
// rather than to a new one.
const (
	DefaultBodyCacheBlocks = 1024
	DefaultBodyCacheBytes  = 32 << 20
)

// NewBodyCache returns a cache with the default bounds.
func NewBodyCache() *BodyCache {
	return &BodyCache{
		maxBlocks: DefaultBodyCacheBlocks,
		maxBytes:  DefaultBodyCacheBytes,
		have:      map[types.Hash]*types.Block{},
		size:      map[types.Hash]int{},
	}
}

// Source wraps a header source so bodies already downloaded are served from
// memory. The wrapper is what a sync attempt is given; the cache outlives it.
func (c *BodyCache) Source(src HeaderSource) HeaderSource {
	return &cachedSource{HeaderSource: src, cache: c}
}

// Reset drops everything. The driver calls it once a branch lands, because at
// that moment the blocks are on the chain and holding them twice is waste.
// Forget drops specific bodies. Used when the fold has proven them bad.
func (c *BodyCache) Forget(ids []types.Hash) {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, id := range ids {
		if _, held := c.have[id]; !held {
			continue
		}
		c.bytes -= c.size[id]
		delete(c.have, id)
		delete(c.size, id)
		for i, o := range c.order {
			if o == id {
				c.order = append(c.order[:i], c.order[i+1:]...)
				break
			}
		}
	}
}

func (c *BodyCache) Reset() {
	if c == nil {
		return
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.have = map[types.Hash]*types.Block{}
	c.size = map[types.Hash]int{}
	c.order = nil
	c.bytes = 0
}

// Len reports how many bodies are retained, so a test can assert the retention
// happened rather than infer it from convergence.
func (c *BodyCache) Len() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.have)
}

func (c *BodyCache) get(id types.Hash) (*types.Block, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	blk, ok := c.have[id]
	return blk, ok
}

func (c *BodyCache) put(id types.Hash, blk *types.Block, size int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, dup := c.have[id]; dup {
		return
	}
	c.have[id] = blk
	c.size[id] = size
	c.order = append(c.order, id)
	c.bytes += size
	for (len(c.order) > c.maxBlocks || c.bytes > c.maxBytes) && len(c.order) > 1 {
		oldest := c.order[0]
		c.order = c.order[1:]
		if _, ok := c.have[oldest]; ok {
			// The size is remembered rather than recomputed: re-encoding a block
			// to find out how big it was is a second full serialisation per
			// eviction, on the path a node uses when it is already behind.
			c.bytes -= c.size[oldest]
			delete(c.size, oldest)
			delete(c.have, oldest)
		}
	}
}

// cachedSource is a HeaderSource whose bodies pass through the cache. Headers
// are never cached: they are cheap, and a stale header set is a way to sync
// against a chain the peer has already abandoned.
type cachedSource struct {
	HeaderSource
	cache *BodyCache
}

func (s *cachedSource) Body(id types.Hash) (*types.Block, error) {
	if blk, ok := s.cache.get(id); ok {
		return blk, nil
	}
	bf, ok := s.HeaderSource.(BodyFetcher)
	if !ok {
		return nil, errors.New("sync: source cannot serve bodies")
	}
	return bf.Body(id)
}

// Retain keeps a body that `Fetch` has already checked against its header.
//
// Nothing is stored on the way *out* of Body, and that is the whole design. A
// peer can answer with the genuine header and certificates that header never
// committed to — the header id still matches, and the mismatch is not caught
// until the fold runs. Storing on the way out therefore stored a lie, and a
// stored lie is served back to every later attempt against every peer, for the
// life of the process: one malicious response, permanent failure to sync.
//
// So the store is written only by the code that has done the checking.
func (s *cachedSource) Retain(id types.Hash, blk *types.Block) {
	s.cache.put(id, blk, len(blk.MarshalSSZ()))
}

func (s *cachedSource) Forget(ids []types.Hash) { s.cache.Forget(ids) }
