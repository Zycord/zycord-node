package chain_test

import (
	"errors"
	"fmt"
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/storage"
)

// Fork choice and reorg torture (M2-G1).
//
// Greatest accumulated work has been theory since the whitepaper. These tests
// are where it has to be true — including at the edges that only exist once it
// runs: work against height, the undo horizon, and reorgs that cross an epoch
// boundary and rewrite the beacon and both base-fee cells.

// TestWorkIsInverseToTarget: a smaller target is harder, and the accumulated
// work must reflect that. If it did not, difficulty would mean nothing and a
// chain of trivial blocks would win.
func TestWorkIsInverseToTarget(t *testing.T) {
	// Realistic targets. At the extremes the floor in 2^256/(t+1) swallows the
	// difference — every target above about 2^255 costs "one hash" — which is
	// standard and harmless, because real targets live near 2^238.
	pow2 := func(n uint) u256.U256 {
		v := u256.One
		for i := uint(0); i < n; i++ {
			v = v.SatAdd(v)
		}
		return v
	}

	easy := chain.BlockWork(u256.Max)
	medium := chain.BlockWork(pow2(240))
	hard := chain.BlockWork(pow2(230))

	if !medium.Gt(easy) {
		t.Fatalf("a harder target produced less work: %s vs %s", medium.String(), easy.String())
	}
	if !hard.Gt(medium) {
		t.Fatalf("a much harder target produced less work: %s vs %s", hard.String(), medium.String())
	}
	if !easy.Eq(u256.One) {
		t.Fatalf("the easiest possible target costs %s hashes, want 1", easy.String())
	}

	// Halving the target doubles the work. This is the property the whole
	// ordering rests on: without it, difficulty would not translate into chain
	// weight and a chain of trivial blocks could outweigh a hard one.
	//
	// "Doubles" is exact up to the floor in 2^256/(t+1), which costs at most one
	// unit at each of the two points being compared. Asserting exact equality
	// would be asserting that integer division does not round.
	half := chain.BlockWork(pow2(239))
	doubled := medium.SatAdd(medium)
	if half.Lt(doubled.SatSub(u256.FromUint64(2))) || half.Gt(doubled.SatAdd(u256.FromUint64(2))) {
		t.Fatalf("halving the target gave %s work, want about %s",
			half.String(), doubled.String())
	}
}

// TestMoreWorkWinsOverMoreBlocks is the rule itself: a shorter, harder branch
// must displace a longer, easier one.
func TestMoreWorkWinsOverMoreBlocks(t *testing.T) {
	p := devnetEasy()
	payout := key(t, 1).Persistent()

	// The incumbent: four easy blocks.
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)
	n.mine(t, 4)
	easyTip := n.chain.Tip().ID()
	easyWork := n.chain.TotalWork()

	// A challenger of two blocks at a much harder target, forking three blocks
	// back — so adopting it makes the chain *shorter* while making it heavier,
	// which is the case that separates work from height.
	ancestor := ancestorAt(t, n, 3)
	branch := buildBranch(t, n, payout, ancestor, 2, fastSolveSeconds)

	if !branch.Work().Gt(worthOf(t, n, 3)) {
		t.Fatal("setup: the challenger does not carry more work than what it replaces")
	}
	reorg, err := n.chain.ConsiderBranch(branch)
	if err != nil {
		t.Fatalf("considering the harder branch: %v", err)
	}
	if !reorg.Adopted {
		t.Fatal("a shorter branch with more work did not win")
	}
	if n.chain.Tip().ID() == easyTip {
		t.Fatal("the tip did not move")
	}
	if n.chain.Height() != 3 {
		t.Fatalf("height is %d, want 3: the chain got shorter and that is correct", n.chain.Height())
	}
	if !n.chain.TotalWork().Gt(easyWork) {
		t.Fatal("accumulated work did not increase after adopting the heavier branch")
	}
}

// TestEqualWorkKeepsTheIncumbent pins the tie-break: first-seen wins.
//
// This is a real rule with real consequences, not an implementation detail. It
// means a miner who publishes first keeps the block on an equal-work tie, which
// is the incentive that makes propagation speed matter — and, less comfortably,
// it is a lever a well-connected miner can pull. Documented rather than hidden.
func TestEqualWorkKeepsTheIncumbent(t *testing.T) {
	p := devnetEasy()
	payout := key(t, 1).Persistent()

	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)
	n.mine(t, 3)
	incumbent := n.chain.Tip().ID()

	// One block replacing one block, mined at the honest chain's own pace:
	// the difficulty rule computes the same target for it as it did for the
	// block it would replace, so the work is equal exactly.
	ancestor := ancestorAt(t, n, 1)
	branch := buildBranch(t, n, key(t, 2).Persistent(), ancestor, 1, p.TargetBlockSeconds)

	reorg, err := n.chain.ConsiderBranch(branch)
	if !errors.Is(err, chain.ErrNotBetter) {
		t.Fatalf("got (%v, %v), want a refusal on equal work", reorg.Adopted, err)
	}
	if n.chain.Tip().ID() != incumbent {
		t.Fatal("an equal-work branch displaced the incumbent")
	}
}

// TestReorgBeyondTheUndoHorizonIsRefused: past UNDO_DEPTH the undo logs do not
// exist, and a node that pretended otherwise would silently produce a state no
// fold ever computed. The correct answer is a refusal that forces a resync.
func TestReorgBeyondTheUndoHorizonIsRefused(t *testing.T) {
	p := devnetEasy()
	p.UndoDepth = 3 // a horizon a test can reach
	payout := key(t, 1).Persistent()

	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)
	n.mine(t, 8)
	tipBefore := n.chain.Tip().ID()

	// A branch forking from well beyond the horizon, and carrying more work, so
	// the refusal cannot be mistaken for "not better".
	ancestor := ancestorAt(t, n, 5)
	branch := buildBranch(t, n, payout, ancestor, 6, fastSolveSeconds)

	reorg, err := n.chain.ConsiderBranch(branch)
	if !errors.Is(err, chain.ErrBeyondUndoHorizon) {
		t.Fatalf("got (%v, %v), want a refusal at the undo horizon", reorg.Adopted, err)
	}
	if n.chain.Tip().ID() != tipBefore {
		t.Fatal("the chain moved despite refusing the reorg")
	}
	// And the node is still usable: refusing a reorg is not a fatal condition.
	n.mine(t, 1)
}

// TestReorgAcrossEpochBoundary is the case the post-M1 review named
// specifically.
//
// An epoch-boundary block rewrites the three beacon cells, and every block
// rewrites both base-fee cells. A reorg across a boundary must restore all of
// them exactly — otherwise the node converges on a chain nobody else has, and
// the divergence is invisible until the next state root.
func TestReorgAcrossEpochBoundary(t *testing.T) {
	p := devnetEasy()
	p.EpochLength = 4 // boundaries at 4, 8, 12 — reachable in a test
	payout := key(t, 1).Persistent()

	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)

	// Stop just before a boundary and record everything a reorg must restore.
	n.mine(t, 3)
	ancestor := n.chain.Tip().ID()
	rootBefore := n.chain.StateRoot()
	beaconBefore := [3]u256.U256{
		n.chain.Snapshot().State.Get(types.BeaconEpochSlot()),
		n.chain.Snapshot().State.Get(types.BeaconHeightSlot()),
		n.chain.Snapshot().State.Get(types.BeaconEntropySlot()),
	}
	seqFeeBefore := n.chain.Snapshot().State.Get(types.SeqBaseFeeSlot())
	parFeeBefore := n.chain.Snapshot().State.Get(types.ParBaseFeeSlot())
	workBefore := n.chain.TotalWork()

	// Cross the boundary, which rewrites the beacon.
	n.mine(t, 3)
	if n.chain.Snapshot().State.Get(types.BeaconEpochSlot()).Eq(beaconBefore[0]) &&
		n.chain.Snapshot().State.Get(types.BeaconHeightSlot()).Eq(beaconBefore[1]) {
		t.Fatal("setup: mining across the boundary did not move the beacon")
	}

	// Roll all the way back to the ancestor.
	for n.chain.Tip().ID() != ancestor {
		if err := n.chain.Rollback(); err != nil {
			t.Fatal(err)
		}
	}

	if got := n.chain.StateRoot(); got != rootBefore {
		t.Fatal("a reorg across an epoch boundary did not restore the state root")
	}
	for i, slot := range []types.Slot{
		types.BeaconEpochSlot(), types.BeaconHeightSlot(), types.BeaconEntropySlot(),
	} {
		if got := n.chain.Snapshot().State.Get(slot); !got.Eq(beaconBefore[i]) {
			t.Fatalf("beacon cell %d is %s after the reorg, want %s",
				i, got.String(), beaconBefore[i].String())
		}
	}
	if !n.chain.Snapshot().State.Get(types.SeqBaseFeeSlot()).Eq(seqFeeBefore) ||
		!n.chain.Snapshot().State.Get(types.ParBaseFeeSlot()).Eq(parFeeBefore) {
		t.Fatal("a reorg did not restore the base-fee cells")
	}
	if !n.chain.TotalWork().Eq(workBefore) {
		t.Fatalf("accumulated work is %s after the reorg, want %s",
			n.chain.TotalWork().String(), workBefore.String())
	}

	// And the restored chain still extends: a reorg must leave a working node.
	n.mine(t, 5)
	if n.chain.Height() != 8 {
		t.Fatalf("height is %d after re-mining, want 8", n.chain.Height())
	}
}

// TestInvalidBranchLeavesTheChainIntact: a node must never be left on a partial
// branch, because a partial branch is a chain nobody else has.
func TestInvalidBranchLeavesTheChainIntact(t *testing.T) {
	p := devnetEasy()
	payout := key(t, 1).Persistent()

	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)
	n.mine(t, 4)
	tipBefore := n.chain.Tip().ID()
	rootBefore := n.chain.StateRoot()
	heightBefore := n.chain.Height()

	// A heavier branch whose *third* block is corrupt, so the first two apply
	// and the restore path has real work to undo.
	ancestor := ancestorAt(t, n, 2)
	branch := buildBranch(t, n, payout, ancestor, 3, fastSolveSeconds)
	branch.Blocks[2].Header.CertRoot[0] ^= 0xff

	reorg, err := n.chain.ConsiderBranch(branch)
	if reorg.Adopted || err == nil {
		t.Fatal("an invalid branch was adopted")
	}
	if n.chain.Tip().ID() != tipBefore || n.chain.Height() != heightBefore {
		t.Fatal("the original chain was not restored after a failed branch")
	}
	if n.chain.StateRoot() != rootBefore {
		t.Fatal("the state was not restored after a failed branch")
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// fastSolveSeconds times a buildBranch block far below TargetBlockSeconds, so
// the difficulty rule computes a genuinely harder target for it — the same
// way a faster miner would in reality, and the only way left to make a
// hand-built branch outweigh another now that ConsiderBranch re-derives every
// declared target instead of trusting it.
const fastSolveSeconds = 1

// ancestorAt returns the header of the block `back` blocks below the tip.
func ancestorAt(t *testing.T, n *node, back uint64) types.Header {
	t.Helper()
	b, err := n.chain.BlockAt(n.chain.Height() - back)
	if err != nil {
		t.Fatal(err)
	}
	return b.Header
}

// worthOf returns the accumulated work of the last `back` blocks of a chain.
func worthOf(t *testing.T, n *node, back uint64) u256.U256 {
	t.Helper()
	total := u256.Zero
	for h := n.chain.Height() - back + 1; h <= n.chain.Height(); h++ {
		b, err := n.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		total = total.SatAdd(chain.BlockWork(b.Header.Target))
	}
	return total
}

// buildBranch constructs a branch of empty blocks descending from an
// ancestor on n's own chain, each carrying the target and time the
// difficulty rule and the median-time floor actually require for it.
//
// ConsiderBranch now re-derives both the target and the time bounds for every
// block on a branch, so a hand-built header can no longer declare an arbitrary
// target and pass: this runs the same LWMA computation the real chain does,
// walking the same preceding window pow.NextTarget reads — built from n's own
// stored headers, exactly as node/sync.ValidateHeaders or a real miner would
// build it.
//
// solveSeconds is the gap between each block's time and its parent's, and is
// the one knob callers actually want. A gap at TargetBlockSeconds reproduces
// the target the honest chain would itself have computed for the same blocks
// — an "equal work" branch, useful for testing a tie. A gap well below it
// drives the LWMA target down the way a faster miner would, producing a
// branch that is genuinely, not just declaratively, harder — see
// fastSolveSeconds.
//
// Empty blocks keep the test about fork choice rather than about the fold —
// which is exercised exhaustively elsewhere — and they are genuinely valid:
// the block rules accept an empty block at any non-boundary height, which is
// where these branches live.
func buildBranch(t *testing.T, n *node, payout types.Address,
	ancestor types.Header, count int, solveSeconds uint64) chain.Branch {
	t.Helper()
	p := n.p

	window := headersEndingAt(t, n, ancestor.ID(), int(p.DifficultyWindow)+1)

	var blocks []*types.Block
	parent := ancestor.ID()
	parentTime := ancestor.Time
	for i := 0; i < count; i++ {
		height := ancestor.Height + uint64(i) + 1
		if p.IsEpochBoundary(height) {
			t.Fatalf("buildBranch would cross an epoch boundary at height %d, "+
				"which needs a folded state root; choose a shorter branch", height)
		}

		target := pow.NextTarget(window, p)
		when := parentTime + solveSeconds
		if floor := pow.MedianTime(window, p); when <= floor {
			when = floor + 1
		}

		b := &types.Block{Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       height,
			ParentID:     parent,
			Time:         when,
			EmissionAddr: payout,
			Target:       target,
		}}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		b.Header.CitesRoot = b.ComputeCitesRoot(p)
		blocks = append(blocks, b)

		parent = b.Header.ID()
		parentTime = b.Header.Time
		window = append(window, b.Header)
		if len(window) > int(p.DifficultyWindow)+1 {
			window = window[len(window)-(int(p.DifficultyWindow)+1):]
		}
	}
	return chain.Branch{Blocks: blocks}
}

// headersEndingAt walks n's own chain from id back toward genesis via parent
// links, returning up to want headers oldest-first — the shape pow.NextTarget
// and pow.CheckMedianTime read. Header resolves an id whether or not it is
// still canonical (node/chain's own doc comment on Header vs CanonicalHeader
// explains why), so this works for an ancestor on the live chain today just
// as it would for one a test later reorgs away from under it.
func headersEndingAt(t *testing.T, n *node, id types.Hash, want int) []types.Header {
	t.Helper()
	var out []types.Header
	cursor := id
	for len(out) < want {
		hdr, err := n.chain.Header(cursor)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, *hdr)
		if hdr.Height == 0 {
			break
		}
		cursor = hdr.ParentID
	}
	for i, j := 0, len(out)-1; i < j; i, j = i+1, j-1 {
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// TestReorgIsCrashAtomic is R4-M1.
//
// The ConsiderBranch bug was an *error* path leaving a node on neither chain.
// The same shape exists one layer down: a crash mid-reorg — unwound the old
// branch, applied half the new one, then SIGKILL — would leave a restarting
// node in a state no fold ever produced.
//
// The reorg is therefore one storage commit, and this drives a simulated crash
// through every byte offset of it. On every restart the node must be wholly on
// one branch, with that branch's exact state, work and seen set.
func TestReorgIsCrashAtomic(t *testing.T) {
	p := devnetEasy()
	payout := key(t, 1).Persistent()

	// Size the reorg's commit record once, so the loop knows how far to go.
	probe := reorgFixture(t, p, payout, nil)
	recordLen := probe.commitBytes
	probe.close(t)
	if recordLen == 0 {
		t.Fatal("the reorg produced no commit; the test cannot measure it")
	}

	for offset := 0; offset <= recordLen; offset += 1 + recordLen/48 {
		t.Run(fmt.Sprintf("offset=%d", offset), func(t *testing.T) {
			// The crash lands at a cumulative byte offset across *every* commit
			// the reorg performs, not at an offset within the first one. That
			// distinction is the test: an implementation that split the
			// transition into two commits would survive a crash inside the
			// first one and fail only when the crash lands between them.
			remaining := offset
			fixture := reorgFixture(t, p, payout, func(record []byte) ([]byte, error) {
				if remaining >= len(record) {
					remaining -= len(record)
					return record, nil // this commit lands whole
				}
				cut := record[:remaining]
				remaining = 0
				return cut, errSimulatedCrash
			})

			oldTip, oldRoot := fixture.oldTip, fixture.oldRoot
			newTip := fixture.newTip
			dir := fixture.dir
			fixture.abandon()

			// Restart. The node must be wholly on one branch.
			reopened, err := chain.Open(dir, p)
			if err != nil {
				t.Fatalf("crash at offset %d left the chain unopenable: %v", offset, err)
			}
			defer reopened.Close()

			tip := reopened.Tip().ID()
			switch tip {
			case oldTip:
				if reopened.StateRoot() != oldRoot {
					t.Fatalf("crash at offset %d: on the old tip with the wrong state", offset)
				}
			case newTip:
				// The branch landed; its state must match what the fold
				// produces from the same blocks.
				if reopened.StoredStateRoot() != reopened.StateRoot() {
					t.Fatalf("crash at offset %d: on the new tip with an inconsistent state", offset)
				}
			default:
				t.Fatalf("crash at offset %d left the node on neither branch (tip %x)", offset, tip[:6])
			}

			// And the node still works: a crash is not a terminal condition.
			if _, err := reopened.BlockAt(reopened.Height()); err != nil {
				t.Fatalf("crash at offset %d: the tip block is not readable", offset)
			}
		})
	}
}

var errSimulatedCrash = errors.New("simulated crash")

type reorgState struct {
	dir         string
	chain       *chain.Chain
	oldTip      types.Hash
	newTip      types.Hash
	oldRoot     types.Hash
	commitBytes int
}

func (r *reorgState) close(t *testing.T) {
	t.Helper()
	if err := r.chain.Close(); err != nil {
		t.Fatal(err)
	}
}

// abandon drops the chain without a clean close, which is what a crash looks
// like from the filesystem's point of view.
func (r *reorgState) abandon() { _ = r.chain.Close() }

// reorgFixture builds a chain with a heavier competing branch and attempts the
// switch, optionally crashing part-way through the commit.
func reorgFixture(t *testing.T, p *params.Params, payout types.Address,
	fault func([]byte) ([]byte, error)) *reorgState {
	t.Helper()

	dir := t.TempDir()
	n := openNodeWith(t, dir, p, payout, storage.Options{})
	n.mine(t, 4)
	oldTip := n.chain.Tip().ID()
	oldRoot := n.chain.StateRoot()

	ancestor := ancestorAt(t, n, 2)
	branch := buildBranch(t, n, payout, ancestor, 3, fastSolveSeconds)
	newTip := branch.Blocks[len(branch.Blocks)-1].Header.ID()
	n.close(t)

	// Reopen with the fault injector armed, then attempt the reorg.
	measured := 0
	var opts storage.Options
	if fault != nil {
		opts.FaultInjector = fault
	} else {
		// The measuring pass sums every commit the reorg makes, so the crash
		// loop covers the whole transition rather than only its first batch.
		opts.FaultInjector = func(record []byte) ([]byte, error) {
			measured += len(record)
			return record, nil
		}
	}
	reopened := openNodeWith(t, dir, p, payout, opts)
	_, _ = reopened.chain.ConsiderBranch(branch)

	return &reorgState{
		dir: dir, chain: reopened.chain,
		oldTip: oldTip, newTip: newTip, oldRoot: oldRoot,
		commitBytes: measured,
	}
}

// TestConsiderBranchAcrossEpochBoundary closes the gap the chaos soak found.
//
// `buildBranch` refuses to cross an epoch boundary, because a boundary block
// carries a folded state root and a hand-built header cannot produce one. That
// made the restriction invisible: `TestReorgAcrossEpochBoundary` exercises
// `Rollback` across a boundary, and nothing exercised `ConsiderBranch` across
// one — which is the path every real reorg and every sync takes.
//
// The branch here is mined by a second node from the same ancestor, so its
// state roots are real. A four-minute chaos soak produced exactly this shape
// and failed with "state root mismatch at epoch boundary"; a twenty-five second
// soak never reached a boundary at all.
func TestConsiderBranchAcrossEpochBoundary(t *testing.T) {
	p := devnetEasy()
	p.EpochLength = 4 // boundaries at 0, 4, 8, 12
	payout := key(t, 1).Persistent()

	// The node under test, stopped just short of the boundary at 4.
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)
	n.mine(t, 2)
	ancestor := n.chain.Tip()

	// A rival mining the same history, then diverging past the boundary. It is a
	// separate node with its own directory, so its blocks are as independent as
	// a peer's — but the same payout, so the shared prefix is byte-identical and
	// the fork is where the test puts it rather than at height 1.
	rival := openNode(t, t.TempDir(), p, payout)
	defer rival.close(t)
	rival.mine(t, 2)
	if rival.chain.Tip().ID() != ancestor.ID() {
		t.Fatalf("setup: the two nodes disagree at the fork point (%x vs %x)",
			rival.chain.Tip().ID(), ancestor.ID())
	}

	// Nudge the rival's clock so its next block differs from the node's. This is
	// what makes it a fork rather than the same chain mined twice.
	rival.clock += p.TargetBlockSeconds

	// Six more blocks on the rival: past the boundary at 4 and on to 8.
	rival.mine(t, 6)
	if !p.IsEpochBoundary(4) || rival.chain.Height() < 8 {
		t.Fatalf("setup: the branch does not cross a boundary (height %d)", rival.chain.Height())
	}

	// The node takes two blocks of its own, so this is a genuine reorg — the
	// branch must unwind something before it applies anything.
	n.mine(t, 2)
	if n.chain.Height() != 4 {
		t.Fatalf("setup: node is at height %d, want 4", n.chain.Height())
	}

	var branch chain.Branch
	for h := ancestor.Height + 1; h <= rival.chain.Height(); h++ {
		blk, err := rival.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		branch.Blocks = append(branch.Blocks, blk)
	}

	reorg, err := n.chain.ConsiderBranch(branch)
	if err != nil {
		t.Fatalf("a valid branch across an epoch boundary was rejected: %v", err)
	}
	if !reorg.Adopted {
		t.Fatal("the heavier branch was not adopted")
	}
	if n.chain.Tip().ID() != rival.chain.Tip().ID() {
		t.Fatal("the node did not end up on the branch it adopted")
	}
	if n.chain.StateRoot() != rival.chain.StateRoot() {
		t.Fatalf("the node's state diverged from the branch it adopted:\n  node  %x\n  rival %x",
			n.chain.StateRoot(), rival.chain.StateRoot())
	}
	// The stored root must agree too, or the divergence is only invisible until
	// the next restart.
	if n.chain.StoredStateRoot() != n.chain.StateRoot() {
		t.Fatal("the committed state root does not match the in-memory one")
	}
}

// TestReorgStatsActuallyMove is the anti-vacuity guard on the reorg metric.
//
// `deepest_reorg` was exposed on /metrics from M1 and was never once recorded:
// the function that wrote it existed and nothing called it. It reported zero
// through every partition, every kill and every fork, and a soak check that
// validated its horizon against that number was therefore validating it against
// a constant.
//
// A metric that cannot be non-zero is the observability form of a test that
// cannot fail, so this asserts it moves — and asserts the shape of the movement,
// because a counter that increments on every block would be just as useless in
// the other direction.
func TestReorgStatsActuallyMove(t *testing.T) {
	p := devnetEasy()
	p.EpochLength = 4
	payout := key(t, 1).Persistent()

	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)
	n.mine(t, 2)
	ancestor := n.chain.Tip()

	rival := openNode(t, t.TempDir(), p, payout)
	defer rival.close(t)
	rival.mine(t, 2)
	rival.clock += p.TargetBlockSeconds
	rival.mine(t, 6)

	n.mine(t, 2) // two blocks of our own, so the switch must unwind them

	before := n.chain.Stats()
	if before.ReorgEvents != 0 {
		t.Fatalf("setup: %d reorgs before any fork existed", before.ReorgEvents)
	}
	if before.BlocksApplied == 0 {
		t.Fatal("blocks applied was never counted; the counter is dead in the " +
			"ordinary path too")
	}

	var branch chain.Branch
	for h := ancestor.Height + 1; h <= rival.chain.Height(); h++ {
		blk, err := rival.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		branch.Blocks = append(branch.Blocks, blk)
	}
	if _, err := n.chain.ConsiderBranch(branch); err != nil {
		t.Fatal(err)
	}

	after := n.chain.Stats()
	if after.ReorgEvents != 1 {
		t.Fatalf("reorg events %d after exactly one branch switch, want 1", after.ReorgEvents)
	}
	// Two blocks were unwound, so the depth is two — not the branch length, and
	// not zero.
	if after.DeepestReorg != 2 {
		t.Fatalf("deepest reorg recorded as %d, want 2 (the blocks unwound)", after.DeepestReorg)
	}
	if after.BlocksUndone != 2 {
		t.Fatalf("blocks undone recorded as %d, want 2", after.BlocksUndone)
	}
	if after.BlocksApplied <= before.BlocksApplied {
		t.Fatal("the branch's blocks were not counted as applied")
	}

	// And a plain extension must NOT count as a reorg, or the deepest-reorg
	// number drowns in zeroes and stops meaning anything.
	eventsAfterReorg := after.ReorgEvents
	n.mine(t, 1)
	if got := n.chain.Stats().ReorgEvents; got != eventsAfterReorg {
		t.Fatalf("extending the tip counted as a reorg (%d -> %d)", eventsAfterReorg, got)
	}
}

// TestStatsSurviveARestart pins the counters against the event they exist to
// describe.
//
// They were in memory only. The soak that asserts on them kills nodes at
// random, so `deepest_reorg` and `blocks_rejected` reported only what had
// happened since the last crash — a metric that resets on the event it is meant
// to survive is measuring uptime, not the thing it names.
func TestStatsSurviveARestart(t *testing.T) {
	p := devnetEasy()
	p.EpochLength = 4
	payout := key(t, 1).Persistent()
	dir := t.TempDir()

	n := openNode(t, dir, p, payout)
	n.mine(t, 2)
	ancestor := n.chain.Tip()

	rival := openNode(t, t.TempDir(), p, payout)
	defer rival.close(t)
	rival.mine(t, 2)
	rival.clock += p.TargetBlockSeconds
	rival.mine(t, 6)

	n.mine(t, 2)
	var branch chain.Branch
	for h := ancestor.Height + 1; h <= rival.chain.Height(); h++ {
		blk, err := rival.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		branch.Blocks = append(branch.Blocks, blk)
	}
	if _, err := n.chain.ConsiderBranch(branch); err != nil {
		t.Fatal(err)
	}

	before := n.chain.Stats()
	if before.ReorgEvents == 0 || before.DeepestReorg == 0 || before.BlocksApplied == 0 {
		t.Fatalf("setup produced nothing to lose: %+v", before)
	}
	n.close(t)

	reopened := openNode(t, dir, p, payout)
	defer reopened.close(t)

	after := reopened.chain.Stats()
	if after != before {
		t.Fatalf("counters did not survive a restart:\n  before %+v\n  after  %+v", before, after)
	}
}

// TestReorgKeepsOrphanedHeadersResolvableByID is R3.
//
// The property: a block that loses a reorg does not stop having existed. Its
// id must still resolve, it must not be reported as canonical, and its parent
// link must still point where it pointed — including at the fork point, so a
// reader can walk the losing segment back to where the two chains meet.
//
// Without it the only record of a reorg is held by whoever happened to be
// watching while it happened. Every later reader asks the node about an id it
// saw at the tip and is told the block never existed, which is the one answer
// that is definitely wrong.
//
// The retention is headers and nothing else, and that is also asserted here:
// node/storage keeps every key in a live map, so retaining orphaned *bodies*
// would make this process's memory a function of the network's fork rate,
// forever. Headers are fixed-width and cost a few hundred bytes apiece.
func TestReorgKeepsOrphanedHeadersResolvableByID(t *testing.T) {
	p := devnetEasy()
	payout := key(t, 1).Persistent()
	n := openNode(t, t.TempDir(), p, payout)
	defer n.close(t)
	n.mine(t, 4)

	// The segment that is about to lose, remembered while it is still winning.
	var losing []types.Header
	for h := uint64(2); h <= 4; h++ {
		b, err := n.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		losing = append(losing, b.Header)
	}

	ancestor := ancestorAt(t, n, 3)
	branch := buildBranch(t, n, payout, ancestor, 2, fastSolveSeconds)
	reorg, err := n.chain.ConsiderBranch(branch)
	if err != nil {
		t.Fatalf("considering the harder branch: %v", err)
	}
	if !reorg.Adopted || len(reorg.Undone) != len(losing) {
		t.Fatalf("setup: adopted=%v with %d undone, want a %d-block reorg",
			reorg.Adopted, len(reorg.Undone), len(losing))
	}

	// Anti-vacuity: the heights those blocks held are now held by other blocks,
	// so nothing below can be satisfied by the height index answering instead.
	for _, hdr := range losing[:2] {
		got, ok := n.chain.CanonicalIDAt(hdr.Height)
		if !ok || got == hdr.ID() {
			t.Fatalf("height %d still resolves to the block the reorg displaced; "+
				"the branch did not actually replace it", hdr.Height)
		}
	}
	if _, ok := n.chain.CanonicalIDAt(4); ok {
		t.Fatal("height 4 is still committed after a reorg that made the chain shorter")
	}

	for i, hdr := range losing {
		id := hdr.ID()
		got, err := n.chain.Header(id)
		if err != nil {
			t.Fatalf("the block orphaned at height %d is unreachable by id: %v", hdr.Height, err)
		}
		if got.ID() != id {
			t.Fatalf("Header(%x) answered with a different block", id[:8])
		}
		want := ancestor.ID()
		if i > 0 {
			want = losing[i-1].ID()
		}
		if got.ParentID != want {
			t.Fatalf("the block orphaned at height %d lost its parent link, so the "+
				"losing segment cannot be walked back to the fork point", hdr.Height)
		}
		if canonicalID, ok := n.chain.CanonicalIDAt(got.Height); ok && canonicalID == id {
			t.Fatalf("the block orphaned at height %d is still reported as canonical", got.Height)
		}
		if _, err := n.chain.Block(id); err == nil {
			t.Fatalf("the body of the block orphaned at height %d was retained: the "+
				"node's memory would grow with the network's fork rate", hdr.Height)
		}
	}

	// The fork point is where both segments meet, and it stayed canonical.
	if got, ok := n.chain.CanonicalIDAt(ancestor.Height); !ok || got != ancestor.ID() {
		t.Fatal("the fork point left the canonical chain")
	}
}
