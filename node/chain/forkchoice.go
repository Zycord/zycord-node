package chain

import (
	"errors"
	"fmt"

	"zycord/core/fold"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/storage"
)

// Fork choice: greatest accumulated work (M2-G1).
//
// This has been theory since the whitepaper. Here it runs, and its edge cases
// become real code with real failure modes:
//
//   - **Work, not height.** A longer chain of easier blocks must lose to a
//     shorter chain of harder ones, or difficulty means nothing.
//   - **Ties.** Equal work is broken by first-seen, and that is a real rule
//     with real consequences, not an implementation detail — see §Ties.
//   - **The undo horizon.** UNDO_DEPTH bounds how far back the undo logs reach.
//     A deeper reorg must be *refused*, forcing a resync, never silently
//     pretended to. An undo log that does not extend past the horizon must not
//     act as though it does.
//   - **Epoch boundaries.** A reorg across one rewrites the beacon and both
//     base-fee cells. Undo has to restore them exactly, or the chain the node
//     converges on is not the chain everyone else converged on.
//   - **The declared target and timestamp are re-derived, not trusted.**
//     `node/sync.ValidateHeaders` and the tip-extension branch of
//     `node/p2p.Engine.OnBlock` both recompute a header's target from the
//     difficulty rule and check its time against the median of its
//     predecessors before accepting it; this package, reached through the
//     orphan pool, used to weigh whatever a branch declared. A header is valid
//     or it is not — it cannot depend on which of three doors it arrived
//     through — so the same two checks run here too, against the same
//     preceding-window construction `RecentHeaders` already uses for the tip.
//     This is the first file in `node/chain` to import `core/pow`. Nothing
//     ever forbade it: `core/fold` avoids the package for a cost reason
//     specific to itself — proof of work is memory-hard, and the fold has no
//     budget to evaluate it per citation, so that check runs in `node/p2p` and
//     `node/sync` instead (see `core/fold/blockrules.go`'s `checkCites`) — and
//     that reasoning is about *running* an `Engine`, not about depending on the
//     package. `NextTarget` and `CheckMedianTime` take no engine and evaluate
//     no hash; they are pure functions of headers and params, exactly the
//     shape this package already computes `BlockWork` and the difficulty
//     window with. `CheckWork` itself is deliberately not called here: every
//     block reaching `ConsiderBranch` already had its own proof of work
//     checked before admission — unconditionally in `node/p2p.Engine.OnBlock`,
//     and inside `node/sync.ValidateHeaders` for a synced chain — so
//     re-checking it a second time here would cost a hash evaluation per block
//     for a fact this package can already assume.

// Errors returned by fork choice.
var (
	// ErrBeyondUndoHorizon reports a reorg deeper than the undo logs reach.
	// Recovering from it needs a resync, which is a node-operator event rather
	// than something the chain can paper over.
	ErrBeyondUndoHorizon = errors.New("chain: reorg is deeper than the undo horizon; resync required")
	// ErrPrunedUndoHorizon reports a reorg the depth gate *admits* — it is
	// within UNDO_DEPTH of the current tip — whose unwind needs an undo log this
	// node already deleted while its tip stood higher.
	//
	// It is separated from ErrUndoUnavailable because a missing undo log is one
	// symptom with two opposite diagnoses, and the code could not tell them
	// apart. "The disk lost it" is a damaged store, which is what
	// ErrUndoUnavailable says and what node/storage's repair path exists for.
	// "This node deleted it on purpose" is a *healthy* store doing exactly what
	// ARCHITECTURE.md §14 told it to, and no repair will bring the log back.
	// metaUndoPruned answers which one it is exactly, so the answer was already
	// in the struct — see missingUndoCauseLocked.
	//
	// Reporting the first for the second sends an operator to check a disk with
	// nothing wrong with it, while the actual remedy — a resync — goes unnamed.
	//
	// The refusal itself is unchanged and remains correct: switchTo puts every
	// block it already unwound back before returning, so this leaves tip, height
	// and state exactly where they were. What this error carries that
	// ErrUndoUnavailable did not is the *instruction*, and the reason it needs
	// one is that unlike a damaged store this state does not clear itself. The
	// fork point is fixed, so a node that is not extending its own chain keeps
	// the same reorg depth as the branch it is refusing grows: the gate admits
	// it every time, the unwind dies at the same height every time, and it never
	// degrades into ErrBeyondUndoHorizon — the one error that would have told
	// the operator what to do.
	ErrPrunedUndoHorizon = errors.New("chain: reorg is within the undo depth but its undo logs were pruned while the tip stood higher; resync required")
	// ErrNotBetter reports a candidate branch that does not beat the current
	// tip on accumulated work.
	ErrNotBetter = errors.New("chain: candidate branch does not exceed the tip's accumulated work")
	// ErrUnknownAncestor reports a branch that does not attach to this chain.
	ErrUnknownAncestor = errors.New("chain: branch does not attach to any known block")
	// ErrForgedTarget reports a branch header whose declared target is not the
	// one the difficulty rule computes from the preceding window.
	// Declaring an easier target buys no work — BlockWork is measured against
	// the same declared value — so this is not a work-inflation defence; it is
	// what keeps two nodes that received the same blocks through different
	// doors from settling on different chains (wire.md §9).
	ErrForgedTarget = errors.New("chain: branch header declares a target the difficulty rule does not produce")
	// ErrBadTime reports a branch header whose time does not exceed the median
	// of its predecessors — the fork-choice slice of the timestamp rules. There
	// is deliberately no upper bound paired with it: a future-dated header is
	// withheld rather than rejected (R1-H2), which is a gossip/sync-layer
	// concern with its own queue and its own issue, not a fork-choice one — see
	// pow.CheckMedianTime's own doc comment.
	ErrBadTime = errors.New("chain: branch header time is at or below the median of its predecessors")
)

// BlockWork is the expected number of hashes needed to solve a header, which is
// what accumulated work sums.
//
// Work is inverse to the target: a smaller target is harder. The standard
// estimate is 2^256 / (target + 1), computed here without a 512-bit division by
// using the identity
//
//	floor(2^256 / (t+1)) = floor((2^256 - (t+1)) / (t+1)) + 1
//
// where the numerator fits in 256 bits. A zero target — which block rules
// reject — would be infinite work, so it is clamped to the maximum.
func BlockWork(target u256.U256) u256.U256 {
	if target.IsZero() {
		return u256.Max
	}
	divisor, overflow := target.Add(u256.One)
	if overflow {
		// target == 2^256-1: the easiest possible target, one hash expected.
		return u256.One
	}
	numerator, _ := u256.Max.Sub(target) // 2^256-1 - target == 2^256 - (target+1)
	q := divWide(numerator, divisor)
	return q.SatAdd(u256.One)
}

// divWide divides a 256-bit value by a 256-bit divisor.
//
// Long division, bit by bit. It is used once per header during fork choice, so
// clarity beats speed — and a subtly wrong division here silently picks the
// wrong chain, which is the one failure mode fork choice must not have.
func divWide(n, d u256.U256) u256.U256 {
	if d.IsZero() {
		return u256.Max
	}
	if n.Lt(d) {
		return u256.Zero
	}

	quotient := u256.Zero
	remainder := u256.Zero
	nb := n.Bytes()
	for i := 0; i < 256; i++ {
		remainder = shiftLeftOne(remainder)
		if bitAt(nb, i) {
			remainder = remainder.SatAdd(u256.One)
		}
		quotient = shiftLeftOne(quotient)
		if remainder.Gte(d) {
			remainder, _ = remainder.Sub(d)
			quotient = quotient.SatAdd(u256.One)
		}
	}
	return quotient
}

func shiftLeftOne(v u256.U256) u256.U256 { return v.SatAdd(v) }

// bitAt returns bit i of a big-endian 32-byte value, counting from the most
// significant.
func bitAt(b [32]byte, i int) bool {
	return b[i/8]&(1<<(7-uint(i%8))) != 0
}

// TotalWork is the accumulated work of the chain up to and including the tip.
func (c *Chain) TotalWork() u256.U256 {
	c.assertNotInRead("TotalWork")
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.totalWorkLocked()
}

func (c *Chain) totalWorkLocked() u256.U256 {
	if raw, ok := c.store.Get([]byte(metaWork)); ok && len(raw) == 32 {
		var v [32]byte
		copy(v[:], raw)
		return u256.FromBytes(v)
	}
	return u256.Zero
}

// Branch is a candidate chain segment: blocks in ascending height order, all
// descending from a block this chain already has.
type Branch struct {
	Blocks []*types.Block
}

// Work returns the accumulated work the branch would add.
func (b Branch) Work() u256.U256 {
	total := u256.Zero
	for _, blk := range b.Blocks {
		total = total.SatAdd(BlockWork(blk.Header.Target))
	}
	return total
}

// ConsiderBranch applies a candidate branch if it beats the current tip on
// accumulated work, rolling back to the common ancestor first.
//
// It is all-or-nothing. If any block on the branch turns out to be invalid, the
// original chain is restored — a node must never be left on a partial branch,
// because a partial branch is a chain nobody else has.
// Reorg reports what a branch switch did.
//
// Undone carries the blocks that were removed, and it exists because the
// certificates in them are otherwise lost: the mempool dropped them when the
// blocks were applied, and undoing the blocks does not put them back. A user
// whose transaction was confirmed and then reorged out would watch it disappear
// from the chain and from every mempool at once.
//
// The chain cannot readmit them itself — `node/mempool` must stay unreachable
// from here, because that import is what fixes the lock order (see
// `make check-imports`). So it reports, and the caller that owns both puts them
// back.
type Reorg struct {
	Adopted bool
	Undone  []*types.Block
}

func (c *Chain) ConsiderBranch(br Branch) (Reorg, error) {
	c.assertNotInRead("ConsiderBranch")
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.considerBranchLocked(br)
}

func (c *Chain) considerBranchLocked(br Branch) (Reorg, error) {
	if len(br.Blocks) == 0 {
		return Reorg{}, nil
	}

	first := br.Blocks[0]
	ancestorID := first.Header.ParentID
	depth, err := c.depthOf(ancestorID)
	if err != nil {
		return Reorg{}, err
	}
	if depth == 0 && ancestorID != c.tip.ID() {
		return Reorg{}, ErrUnknownAncestor
	}

	// The undo horizon is a hard boundary, not a preference. Past it the undo
	// logs simply do not exist, and a node that pretended otherwise would
	// silently produce a state no fold ever computed.
	if depth > c.params.UndoDepth {
		return Reorg{}, fmt.Errorf("%w: %d blocks deep, horizon is %d",
			ErrBeyondUndoHorizon, depth, c.params.UndoDepth)
	}

	// The branch must be a chain: every block links to the one before it, at
	// the next height — including the first block against the ancestor.
	//
	// The first block's *parent* was checked (that is how ancestorID was
	// derived), but until this fix its *height* was not: nothing anywhere
	// compared first.Header.Height against ancestorHeight+1. A branch could
	// declare an arbitrary height on its first block and it would sail
	// through depthOf (keyed on ancestorID, not on the declared height),
	// through this loop (which started at i=1 and so never looked at block
	// 0), and into switchTo, which sets c.height directly from whatever the
	// last-applied block's Header.Height says — and into
	// core/fold.ApplyBlock, which computes the block subsidy from that same
	// unchecked field (fold.go's Emission(b.Header.Height)). A forged height
	// on block 0 therefore forged both this chain's reported height and the
	// era-dependent emission rate paid on every block in the branch. Reached
	// on the production gossip path: node/p2p's assembleBranch links orphans
	// by ParentID only, never checks Height, and hands the result straight
	// to ConsiderBranch. ancestorHeight is c.height - depth in both cases
	// depthOf returns — depth 0 means ancestorID is the tip, so
	// ancestorHeight is c.height itself; otherwise depthOf already computed
	// it as c.height - ancestorHeight — so this costs no extra lookup.
	//
	// `fold.ApplyBlock` takes no parent and cannot check it, and `switchTo`
	// applies each block in turn setting the tip to whatever it says — so an
	// unlinked or mis-heighted set would be applied as though it were a real
	// chain, leaving a state no fold ever produced from one.
	//
	// Both callers happen to build correctly-heighted branches today: sync's
	// come from headers that passed `ValidateHeaders` (which independently
	// checks height contiguity), and the engine's are assembled by walking
	// parent links with each orphan's own stored height. That is an argument
	// about callers, and this is an exported entry point on the consensus
	// boundary — the invariant belongs where it is relied on, not in the
	// habits of the two places that currently call it.
	ancestorHeight := c.height - depth
	if first.Header.Height != ancestorHeight+1 {
		return Reorg{}, fmt.Errorf("chain: branch block 0 is at height %d, ancestor %x is at height %d",
			first.Header.Height, ancestorID[:8], ancestorHeight)
	}
	for i := 1; i < len(br.Blocks); i++ {
		prev, cur := br.Blocks[i-1], br.Blocks[i]
		if cur.Header.ParentID != prev.Header.ID() {
			return Reorg{}, fmt.Errorf("chain: branch block %d does not name block %d as its parent", i, i-1)
		}
		if cur.Header.Height != prev.Header.Height+1 {
			return Reorg{}, fmt.Errorf("chain: branch block %d is at height %d, after height %d",
				i, cur.Header.Height, prev.Header.Height)
		}
	}

	// Every block's target and time are re-derived against the window they
	// would actually have been mined under, not trusted as declared. This runs
	// before Work() below is trusted for anything: Branch.Work sums
	// BlockWork(declared target), and that sum is only a fact — rather than a
	// peer's claim — once every declared target has been checked against the
	// rule that was supposed to produce it, exactly the property
	// sync.Candidate.Work already documents for its own path.
	if err := c.validateBranchDifficultyLocked(ancestorID, br); err != nil {
		return Reorg{}, err
	}

	// Work of the branch against the work it would replace.
	replaced, err := c.workSince(ancestorID)
	if err != nil {
		return Reorg{}, err
	}
	if !br.Work().Gt(replaced) {
		return Reorg{}, ErrNotBetter
	}

	return c.switchTo(ancestorID, br)
}

// validateBranchDifficultyLocked re-derives the difficulty target and checks
// the median-time floor for every block on a branch, against the exact
// preceding-window construction node/sync.ValidateHeaders uses for the same
// headers.
//
// The window this walks is real: by the time considerBranchLocked reaches
// here, depthOf has already established that ancestorID names a block on
// *this* chain, within the undo horizon — which is exactly the ancestor
// window a difficulty computation needs, and exactly the precondition the
// in-code comment above `pow.NextTarget` and both issues' own analysis say
// closes the "validating against a chain we do not have" objection that kept
// this check off this path. The node demonstrably holds the ancestor chain
// at the point a reorg becomes possible at all.
//
// Proof of work itself is deliberately not re-checked here — see the package
// doc comment's note on why `core/pow` is safe to import from this file at
// all, immediately above the package-level error variables.
func (c *Chain) validateBranchDifficultyLocked(ancestorID types.Hash, br Branch) error {
	ancestor, err := c.headerLocked(ancestorID)
	if err != nil {
		return ErrUnknownAncestor
	}
	window := c.headersEndingAtHeightLocked(ancestor.Height, int(c.params.DifficultyWindow)+1)

	for i, blk := range br.Blocks {
		h := blk.Header
		if want := pow.NextTarget(window, c.params); !h.Target.Eq(want) {
			return fmt.Errorf("%w: branch block %d declares %s, the rule gives %s",
				ErrForgedTarget, i, h.Target.String(), want.String())
		}
		if err := pow.CheckMedianTime(h, window, c.params); err != nil {
			return fmt.Errorf("%w: branch block %d: %v", ErrBadTime, i, err)
		}

		// The window a real chain would present to the next block: this
		// header appended, trimmed to the same width sync and the tip
		// extension use. Validating block i+1 without this would compare it
		// against the ancestor's window forever, which is not the rule.
		window = append(window, h)
		if len(window) > int(c.params.DifficultyWindow)+1 {
			window = window[len(window)-(int(c.params.DifficultyWindow)+1):]
		}
	}
	return nil
}

// mutationBudget bounds how large a single part of a reorg's storage
// transaction is allowed to grow before batchGroup starts a new one.
//
// It is a var, not a const, so a test can shrink it and force the chunked
// path with a handful of small blocks instead of the roughly UNDO_DEPTH *
// BLOCK_BYTE_CAPACITY worth of real data that would otherwise take to reach
// it — see SetMutationBudgetForTest.
//
// Set well under storage.MaxRecordLen, and the gap is now DERIVED rather than
// absorbed by a margin, because the escaping of recordMagic out of every
// payload — the fix for a forged terminal record inside a crashed tail's own
// payload — put a second multiplier inside it.
//
// Two things sit between what this counts and what the log holds. The
// per-mutation encoding overhead — an op byte and one or two 4-byte length
// prefixes — used to be the margin's job; it is now counted exactly, by
// batchGroup.Put and Delete, so g.size IS the encoded payload length. And
// storage escapes recordMagic out of every payload it writes, which expands it
// by at most 5/4 (see storage.escapePayload; the bound is charged four input
// bytes per stuffed byte and is reached by a payload of repeated magic).
//
// So the largest record a part can produce is mutationBudget * 5/4, and at 3/4
// of MaxRecordLen that is 15/16 of the limit. The bound closes with the
// constants as they stand, and no whitepaper number moves — which is what makes
// the escape a node-local change. TestTheEscapeExpansionLeavesMutationBudget-
// UnderMaxRecordLen pins the arithmetic, so raising this var without redoing it
// fails loudly rather than turning a valid block into ErrBatchTooBig on the
// commit path.
var mutationBudget = storage.MaxRecordLen * 3 / 4

// What one mutation costs in the log on top of its key and value bytes:
// storage writes an op byte and a 4-byte length prefix before the key, and a
// second prefix before a value. Counted rather than estimated, so
// mutationBudget bounds the record and not an approximation of it.
const (
	mutationPutOverhead    = 1 + 4 + 4
	mutationDeleteOverhead = 1 + 4
)

// batchGroup accumulates mutations into size-bounded parts and commits them
// as one atomic transaction (R4-M1).
//
// A reorg's total size is not bounded by anything this package controls —
// UNDO_DEPTH blocks at BLOCK_BYTE_CAPACITY each can run to several
// gigabytes, comfortably past what a single storage record may hold
// (storage.MaxRecordLen exists so a corrupt length field cannot make the
// reader allocate arbitrarily, which is a reason to bound one record, not a
// reason a legal reorg should fail outright). batchGroup starts a new part
// whenever the current one would cross mutationBudget, and commit lands
// every part it produced as a single atomic, durable transaction via
// storage.Store.CommitGroup, which writes a single ordinary record — the
// byte-for-byte equivalent of what an unchunked switchTo has always written
// — whenever everything fit in one part.
type batchGroup struct {
	parts   []*storage.Batch
	current *storage.Batch
	size    int
}

func newBatchGroup() *batchGroup {
	b := &storage.Batch{}
	return &batchGroup{parts: []*storage.Batch{b}, current: b}
}

func (g *batchGroup) rollIfNeeded(n int) {
	if g.current.Len() > 0 && g.size+n > mutationBudget {
		g.current = &storage.Batch{}
		g.parts = append(g.parts, g.current)
		g.size = 0
	}
}

// Put implements recordWriter.
func (g *batchGroup) Put(key, value []byte) {
	n := mutationPutOverhead + len(key) + len(value)
	g.rollIfNeeded(n)
	g.current.Put(key, value)
	g.size += n
}

// Delete implements recordWriter.
func (g *batchGroup) Delete(key []byte) {
	n := mutationDeleteOverhead + len(key)
	g.rollIfNeeded(n)
	g.current.Delete(key)
	g.size += n
}

// commit lands every part as one atomic transaction.
//
// It always calls CommitGroup, including for the one-part case every
// ordinary reorg produces: CommitGroup's own single-batch fallback is
// commitOneLocked, the same code Commit runs, and it writes a byte-identical
// record. A second copy of that decision here would only be a second place
// for the two to drift apart.
func (g *batchGroup) commit(s *storage.Store) error {
	return s.CommitGroup(g.parts)
}

// switchTo performs the whole reorg as **one atomic storage transaction**
// (R4-M1) — one record when it fits, and a size-bounded group of records,
// landed together or not at all, when it does not (see batchGroup).
//
// The error path is not the only way to end up on neither chain. A crash
// mid-reorg — unwound the old branch, applied half the new one, then SIGKILL —
// would leave a restarting node in a state no fold ever produced, which is the
// storage-schedule split of I1-C3 reached through a third door.
//
// So the transition happens entirely in memory first: unwind to the ancestor,
// apply the branch, collecting every touched key along the way. Then the
// transaction carries the final value of every one of those keys, the block
// records, and the head metadata. Until it lands the node is wholly on the
// old chain; once it lands it is wholly on the new one. There is no
// in-between to crash into — chunking the bytes across more than one physical
// record does not chunk that guarantee, because CommitGroup applies every
// part or none.
func (c *Chain) switchTo(ancestorID types.Hash, br Branch) (Reorg, error) {
	startTip, startHeight, startWork := c.tip, c.height, c.totalWorkLocked()
	t := newTouched()

	// Unwind in memory, remembering what came off so it can be put back.
	//
	// Every failure below routes through restore, which redoes whatever this
	// loop already undid and puts c.tip/c.height back to where they started —
	// matching the one path that already did so before this fix. Without
	// it an error here left c.state desynced from c.tip and c.height (and from
	// disk, which never moved): the chain would report the old tip and height
	// while c.state reflected some or all of the unwind, a divergence with no
	// crash required to reach it, only an ordinary storage fault — and undo
	// logs were at the time never pruned, so the reachable trigger is a corrupt
	// or missing record — which a discarded log write, an interior log
	// corruption read as a torn tail, or a swallowed fsync error can all
	// produce.
	var undone []*types.Block
	var undoneWork u256.U256 = u256.Zero
	cursor := c.tip
	for cursor.ID() != ancestorID {
		blk, err := c.blockLocked(cursor.ID())
		if err != nil {
			// The body is what is missing here, not the undo log; reporting
			// ErrUndoUnavailable (as this path did before the undo-pruning
			// review) points an operator at the wrong record entirely.
			return Reorg{}, c.unwound(startTip, startHeight, undone, err)
		}
		raw, ok := c.store.Get(hashKey(prefixUndo, cursor.ID()))
		if !ok {
			// Every exit from this loop after the first iteration has already
			// rolled state back in memory, so it must put it back before
			// reporting — c.tip still names the old tip, and returning here
			// with a partially unwound state would leave the node claiming a
			// tip whose state it no longer holds, which is silent divergence,
			// not a refusal. This path only became reachable once the node started
			// pruning undo logs: a reorg within UNDO_DEPTH of the *current*
			// tip can still ask for a height pruned while the tip was higher
			// (see pruneUndoLocked's doc comment), which is accepted as a
			// refusal precisely because it is one.
			//
			// That acceptance is about the *decision*, and it still stands. It
			// was never an argument for reporting the two ways to get here
			// under one name: missingUndoCauseLocked separates them, so
			// the refusal an operator can act on says so.
			return Reorg{}, c.unwound(startTip, startHeight, undone,
				c.missingUndoCauseLocked(cursor.Height))
		}
		log, err := decodeUndo(raw)
		if err != nil {
			return Reorg{}, c.unwound(startTip, startHeight, undone, err)
		}
		t.record(log)
		fold.UndoBlock(c.state, log)
		undone = append(undone, blk)
		undoneWork = undoneWork.SatAdd(BlockWork(cursor.Target))

		parent, err := c.headerLocked(cursor.ParentID)
		if err != nil {
			return Reorg{}, c.unwound(startTip, startHeight, undone, err)
		}
		cursor = *parent
	}

	// Apply the branch in memory.
	c.tip, c.height = cursor, cursor.Height
	applied := make([]*fold.Result, 0, len(br.Blocks))
	addedWork := u256.Zero
	for i, blk := range br.Blocks {
		res, err := fold.ApplyBlock(c.state, blk, c.params)
		if err != nil {
			// Nothing has been written, so restoring is a memory operation:
			// undo what applied, redo what was unwound, and leave no trace.
			if rerr := c.restore(startTip, startHeight, undone, applied); rerr != nil {
				return Reorg{}, fmt.Errorf("%w: reorg failed and could not be undone: %w", ErrLocal, rerr)
			}
			c.recordRejection()
			return Reorg{}, fmt.Errorf("chain: branch block %d is invalid: %w", i, err)
		}
		t.record(res.Undo)
		applied = append(applied, res)
		addedWork = addedWork.SatAdd(BlockWork(blk.Header.Target))
		c.tip, c.height = blk.Header, blk.Header.Height
	}

	// One atomic transition, whether it ends up as one storage record or
	// several — see batchGroup.
	group := newBatchGroup()
	c.writeState(group, t)
	for _, blk := range undone {
		id := blk.Header.ID()
		group.Delete(hashKey(prefixUndo, id))
		group.Delete(hashKey(prefixBlock, id))
		group.Delete(heightKey(blk.Header.Height))
		// The header stays, and it is the only thing that does.
		//
		// A block that loses a reorg does not stop having existed: an observer
		// that saw it at the tip has to be able to resolve the id again, learn
		// that it is no longer on the chain, and walk its parent links back to
		// the fork point. Deleting the header made that id a permanent 404, so
		// the honest answer — "this block was reorged away" — was indexable
		// only by whoever happened to be watching at the time, and every
		// later reader got silence instead.
		//
		// Header-only is the whole of the retention on purpose. Headers are
		// fixed-width, so the cost is bounded by the fork rate and is a few
		// hundred bytes apiece; bodies are not, and node/storage holds every
		// key in a live map, so retaining orphaned bodies would grow this
		// process's memory by up to a block ceiling per orphan, forever. The
		// body is the observer's to keep — it had the bytes when the block was
		// canonical — and the identity is the node's.
	}
	// pending records this batch's own height -> id assignments for the branch
	// it is applying, so pruneUndoLocked below can resolve them correctly
	// instead of falling back to storage's stale, pre-batch view of heightKey —
	// which, for any height this reorg also rolled a block off of, would
	// resolve to the *old* chain's id there rather than the new one this loop
	// is writing (a branch longer than UNDO_DEPTH, which node/sync's resync
	// path deliberately allows, can put the pruning horizon inside this very
	// range).
	pending := make(map[uint64]types.Hash, len(br.Blocks))
	for i, blk := range br.Blocks {
		id := blk.Header.ID()
		group.Put(hashKey(prefixHeader, id), blk.Header.MarshalSSZ())
		group.Put(hashKey(prefixBlock, id), blk.MarshalSSZ())
		group.Put(heightKey(blk.Header.Height), id[:])
		group.Put(hashKey(prefixUndo, id), encodeUndo(applied[i].Undo))
		pending[blk.Header.Height] = id
	}
	// The counters that will be true once this batch lands.
	next := c.stats.withReorg(len(undone))
	for _, res := range applied {
		next = next.withBlock(res)
	}
	// Pruning rides the same transaction as the rest of the transition, for
	// the same reason the reorg itself does: c.tip.Height is the new tip in
	// memory, exactly as writeHead below is about to persist it. It
	// stages into the group like everything else, so a reorg whose pruning
	// pushes it past one record's worth of mutations still lands atomically.
	c.pruneUndoLocked(group, c.tip.Height, pending)
	c.writeHead(group, c.tip, startWork.SatSub(undoneWork).SatAdd(addedWork), next)

	if err := group.commit(c.store); err != nil {
		// The commit did not land, so disk is still on the old chain. Memory
		// must go back to match it.
		if rerr := c.restore(startTip, startHeight, undone, applied); rerr != nil {
			return Reorg{}, fmt.Errorf("%w: reorg commit failed and memory could not be restored: %w", ErrLocal, rerr)
		}
		// The storage layer's error, marked as ours: a commit that did not land
		// is this node's problem and nobody else's.
		return Reorg{}, fmt.Errorf("%w: commit: %w", ErrLocal, err)
	}

	// The batch carried these to disk; memory follows only now, so the two agree
	// whether or not the commit landed.
	c.stats = next
	return Reorg{Adopted: true, Undone: undone}, nil
}

// restore puts memory back after a failure that has written nothing: undo what
// was applied, redo what was unwound, put the tip back. It reports only
// whether memory made it back, and names no failure of its own — the three
// callers are reporting three different things (a local data gap, a peer's
// invalid block, a commit that did not land) and the distinction is what
// node/p2p scores on, so each of them wraps its own cause.
//
// Redoing an undone block is fold.ApplyBlock, not its undo log: the log was
// only ever needed to get *off* the block, and a restoration that read it back
// would make putting memory right depend on the very storage read that may
// have just failed.
func (c *Chain) restore(tip types.Header, height uint64, undone []*types.Block, applied []*fold.Result) error {
	for j := len(applied) - 1; j >= 0; j-- {
		fold.UndoBlock(c.state, applied[j].Undo)
	}
	for j := len(undone) - 1; j >= 0; j-- {
		if _, err := fold.ApplyBlock(c.state, undone[j], c.params); err != nil {
			return err
		}
	}
	c.tip, c.height = tip, height
	return nil
}

// unwound restores memory after a failure inside switchTo's unwind loop and
// returns the refusal to report: cause, marked ErrLocal, because everything
// that can go wrong while walking this node's own undo logs is this node's
// problem and not the sending peer's.
func (c *Chain) unwound(tip types.Header, height uint64, undone []*types.Block, cause error) error {
	if err := c.restore(tip, height, undone, nil); err != nil {
		return fmt.Errorf("%w: reorg failed and could not be undone: %w", ErrLocal, err)
	}
	return fmt.Errorf("%w: %w", ErrLocal, cause)
}

// missingUndoCauseLocked names why an undo log the unwind needed is not there
// — a horizon that is a high-water mark can refuse a legitimate reorg, and an
// operator needs to be told which of the two happened.
//
// The question it answers is the one the bare lookup cannot: did the disk lose
// this record, or did this node delete it on purpose? metaUndoPruned is exactly
// that fact written down. pruneUndoLocked deletes heights at or below the
// bookmark and never above it, and the bookmark is inclusive — the height it
// names is itself pruned — so `h <= through` is the separator, and the
// boundary case h == through belongs to the pruned side.
//
// The two returns are diagnoses, not a claim that these are the only ways a
// record can go missing. What is asserted is narrower and is what the tests
// drive: this comparison distinguishes the two cases that are reachable here,
// in both directions, at the boundary. A height above the bookmark keeps
// ErrUndoUnavailable and its existing meaning, unchanged.
//
// Both are wrapped in ErrLocal by the caller and that is deliberate. Neither is
// the sending peer's doing, so nothing here changes what a peer is charged: a
// node with a retreated horizon must not start fining whoever delivered the
// branch that exposed it.
func (c *Chain) missingUndoCauseLocked(h uint64) error {
	if through, ok := c.undoPrunedThroughLocked(); ok && h <= through {
		return ErrPrunedUndoHorizon
	}
	return ErrUndoUnavailable
}

// depthOf returns how many blocks separate the tip from an ancestor.
//
// Every check here reads a header, never a body: the question is height and
// identity, both of which the header alone answers, and both depthOf and
// workSince below run under c.mu — an exclusive lock every other goroutine
// touching this chain queues behind — so a full SSZ block decode here was paid
// by everyone, on every candidate branch, for bytes this function never looked
// at.
func (c *Chain) depthOf(ancestor types.Hash) (uint64, error) {
	if ancestor == c.tip.ID() {
		return 0, nil
	}
	hdr, err := c.headerLocked(ancestor)
	if err != nil {
		return 0, ErrUnknownAncestor
	}
	if hdr.Height > c.height {
		return 0, ErrUnknownAncestor
	}
	// The ancestor must be on this chain, not merely known: a block from an
	// abandoned branch has a height but is not something to roll back to.
	// The height index alone answers that — it names the one id that won at
	// that height — so there is no need to open the body it points at.
	onChainID, ok := c.canonicalIDAtLocked(hdr.Height)
	if !ok || onChainID != ancestor {
		return 0, ErrUnknownAncestor
	}
	return c.height - hdr.Height, nil
}

// workSince sums the work of the blocks after an ancestor, up to the tip.
//
// Header-only, for the same reason as depthOf: BlockWork is a pure
// function of Header.Target, and c.blockAtLocked's full SSZ decode of every
// intervening block bought nothing a header did not already have.
func (c *Chain) workSince(ancestor types.Hash) (u256.U256, error) {
	hdr, err := c.headerLocked(ancestor)
	if err != nil {
		return u256.Zero, ErrUnknownAncestor
	}
	total := u256.Zero
	for h := hdr.Height + 1; h <= c.height; h++ {
		at, err := c.canonicalHeaderAtLocked(h)
		if err != nil {
			return u256.Zero, err
		}
		total = total.SatAdd(BlockWork(at.Target))
	}
	return total, nil
}
