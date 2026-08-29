package sync_test

import (
	"errors"
	"fmt"
	"runtime"
	gosync "sync"
	"sync/atomic"
	"testing"
	"time"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/node/sync"
	"zycord/spec"
	"zycord/wallet"
)

// Headers-first sync (M2-G5 / the M3 gate).
//
// The property that matters is not that sync works — it is that a peer cannot
// make this node do anything by *describing* a chain. Every header is checked
// against the difficulty rule before a single body is requested, so declared
// work is a fact rather than a claim, and that is exactly what an orphan pool
// cannot establish (R4-H1).

func key(t *testing.T, n byte) *wallet.Key {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = n
	}
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func devnetEasy() *params.Params {
	// Devnet's real GENESIS_TARGET (2^248), deliberately NOT u256.Max.
	//
	// This used to override it to u256.Max to make mining free. That is 31x
	// ABOVE devnet's own MAX_TARGET (2^251) — a value params.Validate rejects
	// on a real chain — and it was invisible only because NextTarget
	// normalised against the window's LAST target and so never read an older
	// one. Now that the ratio applies to the window's AVERAGE target, a
	// genesis target that far out of range dominates the mean for a full
	// DIFFICULTY_WINDOW after any fork, pinning every branch to MAX_TARGET and
	// making two branches carry identical work — which silently destroys the
	// work difference these tests exist to observe.
	//
	// The real value is still trivial to mine: 2^256/2^248 = ~256 expected
	// attempts against the 1<<20 budget these tests give MineOne, a margin of
	// ~4000x, and it is only 8x below devnet's MAX_TARGET rather than an
	// out-of-range outlier.
	p := *spec.Devnet()
	return &p
}

type node struct {
	p     *params.Params
	chain *chain.Chain
	miner *miner.Miner
	clock uint64
}

func newNode(t *testing.T, p *params.Params, payout types.Address) *node {
	t.Helper()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	n := &node{p: p, chain: c, clock: p.GenesisTime}
	n.miner = &miner.Miner{
		Chain: c, Pool: mempool.New(p, mempool.DefaultPolicy()),
		Engine: pow.Dev{}, Payout: payout,
		Now: func() uint64 { n.clock += p.TargetBlockSeconds; return n.clock },
	}
	return n
}

func (n *node) mine(t *testing.T, blocks int) {
	t.Helper()
	for i := 0; i < blocks; i++ {
		if _, _, err := n.miner.MineOne(1 << 20); err != nil {
			t.Fatalf("mining: %v", err)
		}
	}
}

// peer serves headers and bodies from a chain, with hooks for the ways a peer
// can misbehave.
type peer struct {
	t     *testing.T
	chain *chain.Chain
	// starveBodies makes the peer advertise headers it will not serve bodies
	// for, which is the failure mode body-availability-as-consensus exists to
	// name.
	starveBodies bool
	// swapBodies makes the peer answer a body request with a different block.
	swapBodies bool
	// cheapChain, when set, is served instead of the real chain: a
	// self-consistent sequence of headers mined at a trivially easy target,
	// with correct linkage and genuine proof of work against that target.
	//
	// This is the R4-H1 adversary. Rewriting targets after the fact breaks
	// linkage and is caught by the wrong rule; producing an internally
	// consistent chain that simply ignores the difficulty rule is the attack
	// the LWMA check exists to stop, and it is cheap — every block costs a
	// handful of hashes.
	cheapChain   []types.Header
	bodyRequests int
	// headerRequests counts calls and lowestAsked is the deepest height ever
	// requested. Both exist for the fork-point overshoot: the search is only as good as
	// its bound, and a bound nothing counts is a bound nothing keeps. A walk
	// that reads down to genesis and a walk that stops at the undo horizon are
	// indistinguishable from the outside — same error, same non-adoption —
	// which is exactly how the fixed stride went unnoticed.
	headerRequests int
	lowestAsked    uint64
}

func (p *peer) Tip() (uint64, u256.U256) {
	if p.cheapChain != nil {
		// The attacker advertises more work than it has, which is what makes
		// the victim start syncing at all.
		last := p.cheapChain[len(p.cheapChain)-1]
		return last.Height, u256.Max
	}
	return p.chain.Height(), p.chain.TotalWork()
}

func (p *peer) Headers(from uint64, count uint32) ([]types.Header, error) {
	p.headerRequests++
	if p.lowestAsked == 0 || from < p.lowestAsked {
		p.lowestAsked = from
	}
	if p.cheapChain != nil {
		var out []types.Header
		for _, h := range p.cheapChain {
			if h.Height >= from && len(out) < int(count) {
				out = append(out, h)
			}
		}
		return out, nil
	}
	var out []types.Header
	for h := from; h <= p.chain.Height() && len(out) < int(count); h++ {
		blk, err := p.chain.BlockAt(h)
		if err != nil {
			break
		}
		out = append(out, blk.Header)
	}
	return out, nil
}

// mineCheapChain produces a self-consistent header chain that ignores the
// difficulty rule: correct linkage, genuine proof of work, and a target the
// rule would never produce. Every block costs a handful of hashes.
func mineCheapChain(t *testing.T, p *params.Params, parent types.Header, n int) []types.Header {
	t.Helper()
	out := make([]types.Header, 0, n)
	prev := parent
	for i := 0; i < n; i++ {
		h := types.Header{
			Version:      types.HeaderVersion,
			Height:       prev.Height + 1,
			ParentID:     prev.ID(),
			Time:         prev.Time + p.TargetBlockSeconds,
			EmissionAddr: key(t, 9).Persistent(),
			Target:       u256.Max, // trivially easy: the whole point
		}
		if !pow.Solve(pow.Dev{}, &h, p, 1<<16) {
			t.Fatal("could not solve a trivially easy target")
		}
		out = append(out, h)
		prev = h
	}
	return out
}

func (p *peer) Body(id types.Hash) (*types.Block, error) {
	p.bodyRequests++
	if p.starveBodies {
		return nil, errors.New("not serving")
	}
	blk, err := p.chain.Block(id)
	if err != nil {
		return nil, err
	}
	if p.swapBodies {
		other, err := p.chain.BlockAt(1)
		if err == nil {
			return other, nil
		}
	}
	return blk, nil
}

// errSevered is the link dying, not the peer refusing. The distinction is the
// whole subject of the tests below: a peer that will not serve is a fact about
// the peer, and a connection that dies is a fact about the world.
var errSevered = errors.New("test: the connection was severed")

// severingLink is an honest peer behind a connection that dies partway through.
//
// It is the shape the chaos proxy produces and the shape a home connection has:
// a fixed number of exchanges survive, then the socket is gone. One
// `sync.Run` is one connection, so a test opens a new one by calling
// reconnect — which is exactly what the sync driver does on its next tick.
//
// Deterministic rather than random on purpose. A random sever rate makes the
// question "how likely is convergence"; a fixed budget makes it "is convergence
// possible at all", and that is the property in dispute.
type severingLink struct {
	*peer
	// budget is how many responses one connection survives before it dies.
	budget int
	served int
	// attempts counts connections opened, and delivered counts responses that
	// actually arrived, so a failure can say whether the peer was ever asked.
	attempts  int
	delivered int
}

func (l *severingLink) reconnect() { l.served = 0; l.attempts++ }

func (l *severingLink) spend() error {
	if l.served >= l.budget {
		return errSevered
	}
	l.served++
	l.delivered++
	return nil
}

// Tip is free: it comes from the handshake, which completed before the budget
// started being spent.
func (l *severingLink) Headers(from uint64, count uint32) ([]types.Header, error) {
	if err := l.spend(); err != nil {
		return nil, err
	}
	return l.peer.Headers(from, count)
}

func (l *severingLink) Body(id types.Hash) (*types.Block, error) {
	if err := l.spend(); err != nil {
		return nil, err
	}
	return l.peer.Body(id)
}

// TestSyncProgressSurvivesALinkThatDiesMidTransfer arms the property below.
//
// The property, stated before the code was read: **a sync attempt that dies
// partway through must leave the node further along than it started.** Without
// it, catching up is an all-or-nothing wager on one connection surviving a
// number of round trips proportional to how far behind the node is — so the
// further behind it falls, the *less* likely it is to ever get back. That is a
// trap with a threshold: cross it and the node is stranded for good, with every
// diagnostic reporting health.
//
// This is what a ten-hour soak observed and could not diagnose: node `d` at
// height 581 while the network reached 5,702, `peers=3`, `banned=0`,
// `blocks_rejected=0`, `ahead_peers=3`, and 166 sync attempts ending in EOF.
// It knew it was behind, it knew who was ahead, and it could not close the gap.
func TestSyncProgressSurvivesALinkThatDiesMidTransfer(t *testing.T) {
	p := devnetEasy()
	const (
		gap    = 40
		budget = 8
		rounds = 200
	)
	source := newNode(t, p, key(t, 1).Persistent())
	source.mine(t, gap)

	// Anti-vacuity, first half: the gap must be more than one connection can
	// carry. If a single attempt could finish, this test would pass on a tree
	// that discards everything and would be measuring the budget, not the
	// property.
	if gap <= budget {
		t.Fatalf("setup: a gap of %d fits inside a connection budget of %d, so no "+
			"attempt is ever cut short and the scenario arms nothing", gap, budget)
	}

	// Anti-vacuity, second half: the peer can serve this chain. Proven on a
	// link that does not sever, so a failure below is about progress being
	// discarded rather than about a peer that was never able to help.
	control := newNode(t, p, key(t, 2).Persistent())
	if _, err := sync.Run(control.chain, pow.Dev{}, &peer{t: t, chain: source.chain}, 128); err != nil {
		t.Fatalf("setup: the peer could not serve its chain over an intact link: %v", err)
	}
	if control.chain.Tip().ID() != source.chain.Tip().ID() {
		t.Fatal("setup: an intact link did not reach the source's tip, so the " +
			"severed link is not the variable under test")
	}

	behind := newNode(t, p, key(t, 3).Persistent())
	link := &severingLink{peer: &peer{t: t, chain: source.chain}, budget: budget}

	var best uint64
	for i := 0; i < rounds; i++ {
		link.reconnect()
		// The error is expected and is not the finding: every attempt dies.
		_, _ = sync.Run(behind.chain, pow.Dev{}, link, 128)
		if h := behind.chain.Height(); h > best {
			best = h
		}
		if behind.chain.Tip().ID() == source.chain.Tip().ID() {
			t.Logf("converged after %d severed connections (%d responses delivered)",
				link.attempts, link.delivered)
			return
		}
	}
	t.Fatalf("after %d connections, each surviving %d responses, the node reached "+
		"height %d of %d and never arrived — %d responses were delivered, enough "+
		"for the whole chain several times over. Every attempt starts from zero, "+
		"so catching up is a wager on one connection outlasting a round trip per "+
		"block, and the further behind a node falls the less likely it is to win. "+
		"That is a threshold beyond which a node is stranded permanently while "+
		"every diagnostic reports health.",
		link.attempts, budget, best, source.chain.Height(), link.delivered)
}

// TestDivergentSyncProgressSurvivesALinkThatDiesMidTransfer is the same
// property for the case the soak actually observed: a node not merely behind
// but on a branch nobody else holds, whose state root differs from everyone's.
//
// Separate from the test above because the two are separate mechanisms. An
// extension can be adopted a piece at a time — every prefix is a strict
// improvement. A reorg cannot: a partial branch loses to the tip it would
// replace, correctly, so keeping the progress has to mean something other than
// applying it. A fix that covers one and looks complete is exactly the failure
// `storage-fault-scored` taught: its first fix wrapped one of the two paths the
// error could take, and the scenario still fired.
func TestDivergentSyncProgressSurvivesALinkThatDiesMidTransfer(t *testing.T) {
	p := devnetEasy()
	const (
		shared = 10
		budget = 8
		rounds = 200
	)

	theirs := newNode(t, p, key(t, 1).Persistent())
	theirs.mine(t, shared)

	// Ours shares a prefix and then goes its own way: a minority branch, which
	// is the state `d` was in — its state root matched nobody's.
	ours := newNode(t, p, key(t, 2).Persistent())
	for h := uint64(1); h <= shared; h++ {
		blk, err := theirs.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ours.chain.Apply(blk); err != nil {
			t.Fatal(err)
		}
	}
	ours.clock = theirs.clock
	ours.mine(t, 20)
	theirs.mine(t, 50) // strictly heavier, so adopting it is correct

	if ours.chain.Tip().ID() == theirs.chain.Tip().ID() {
		t.Fatal("setup: the two nodes are on one chain, so there is no reorg to survive")
	}
	if !theirs.chain.TotalWork().Gt(ours.chain.TotalWork()) {
		t.Fatal("setup: the challenger is not heavier, so refusing it would be correct")
	}
	suffix := ours.chain.Height() - shared
	if suffix <= budget {
		t.Fatalf("setup: our divergent suffix is %d blocks, inside a budget of %d; "+
			"nothing is ever cut short", suffix, budget)
	}

	link := &severingLink{peer: &peer{t: t, chain: theirs.chain}, budget: budget}

	// Composed exactly as the driver composes it (node/p2p/syncdriver.go's
	// SyncFrom): the link is per-attempt and the retention outlives it. That
	// asymmetry is the fix — the thing that keeps dying cannot be the thing
	// that remembers.
	cache := sync.NewBodyCache()

	var best uint64
	for i := 0; i < rounds; i++ {
		link.reconnect()
		_, _ = sync.Run(ours.chain, pow.Dev{}, cache.Source(link), 128)
		if h := ours.chain.Height(); h > best {
			best = h
		}
		if ours.chain.Tip().ID() == theirs.chain.Tip().ID() {
			t.Logf("reorged home after %d severed connections (%d responses delivered)",
				link.attempts, link.delivered)
			return
		}
		// Retention is the mechanism under test, so it is asserted rather than
		// inferred from convergence. A run that converged by some other route —
		// a budget large enough after all, a candidate shorter than expected —
		// would otherwise pass while proving nothing about the cache.
		if i == 0 && cache.Len() == 0 {
			t.Fatal("the first severed attempt retained no bodies at all: the " +
				"cache is not in the path, and any convergence below is happening " +
				"for a reason this test is not measuring")
		}
	}
	t.Fatalf("after %d connections, each surviving %d responses, a node on a minority "+
		"branch never reached the heavier chain: height %d of %d, %d responses "+
		"delivered. A node that lands on an abandoned branch cannot get back, "+
		"which is the failure a ten-hour soak reported and could not explain.",
		link.attempts, budget, best, theirs.chain.Height(), link.delivered)
}

// TestAWithheldPassCarriesItsReason is the sync half of the slow-clock silent
// stall, end to end through Run rather than through ValidateHeaders alone.
//
// A node whose clock is slow past FTL is offered a range that begins ahead of
// it, so ValidateHeaders can take nothing and runOnce turns that into a
// successful empty Result. That is the right outcome — the peer did nothing
// wrong, and there is genuinely nothing to do until the clock advances — but an
// empty Result is also what an up-to-date node returns, and only one of the two
// means the node will stay behind for as long as the skew lasts. Every pass a
// silent no-op, forever, is that defect's "reports no failure, and never names
// the cause" on this path.
//
// Driven through Run because that is where the reason has to survive: Result
// merges pass by pass, and merge returns early for anything that adopted
// nothing — which a withheld pass never does, by definition.
func TestAWithheldPassCarriesItsReason(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, p, key(t, 1).Persistent())
	source.mine(t, 12)

	fresh := newNode(t, p, key(t, 2).Persistent())

	// This node's clock reads an hour before genesis: every header it is
	// offered is ahead of its future-time limit, including the first.
	const slowBy = 3600
	restore := sync.Clock
	sync.Clock = func() time.Time { return time.Unix(int64(p.GenesisTime-slowBy), 0) }
	t.Cleanup(func() { sync.Clock = restore })

	res, err := sync.Run(fresh.chain, pow.Dev{}, &peer{t: t, chain: source.chain}, 8)
	if err != nil {
		t.Fatalf("a range this node's clock cannot reach is not the peer's fault: %v", err)
	}
	if res.Adopted || res.Applied != 0 {
		t.Fatalf("the pass applied %d blocks; nothing here is judgeable yet", res.Applied)
	}
	if !res.HeadersWithheld {
		t.Fatal("the pass reports nothing to do and does not say why; that is " +
			"indistinguishable from an up-to-date node, and it is how a node " +
			"stuck at a fixed lag stayed silent")
	}
	if res.WithheldSkewSeconds == 0 {
		t.Fatal("the pass carries no skew: the gap was computed for the error " +
			"text and is the number an operator would set their clock by")
	}
	// Genesis is at GenesisTime and the node reads slowBy seconds earlier, so
	// the first header it cannot reach is at least that far ahead.
	if res.WithheldSkewSeconds < slowBy {
		t.Fatalf("skew reported as %ds against a clock %ds slow", res.WithheldSkewSeconds, slowBy)
	}

	// And with the clock correct the same source syncs clean, so the flag is
	// about the clock and not about this peer.
	sync.Clock = restore
	ok, err := sync.Run(fresh.chain, pow.Dev{}, &peer{t: t, chain: source.chain}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if ok.HeadersWithheld {
		t.Fatal("a pass with a correct clock still reports headers withheld")
	}
	if !ok.Adopted {
		t.Fatal("setup: the same source did not sync once the clock was right")
	}
}

// TestSyncAdoptsAHeavierChain is the happy path: a fresh node joins and
// re-derives every block rather than trusting anybody's state.
func TestSyncAdoptsAHeavierChain(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, p, key(t, 1).Persistent())
	source.mine(t, 12)

	fresh := newNode(t, p, key(t, 2).Persistent())
	res, err := sync.Run(fresh.chain, pow.Dev{}, &peer{t: t, chain: source.chain}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Adopted {
		t.Fatal("a fresh node did not adopt the only chain there is")
	}
	if fresh.chain.Tip().ID() != source.chain.Tip().ID() {
		t.Fatalf("synced to height %d, source is at %d", fresh.chain.Height(), source.chain.Height())
	}
	// Re-derived, not trusted: the state root is what the fold produced here.
	if fresh.chain.StateRoot() != source.chain.StateRoot() {
		t.Fatal("the synced node's state does not match the source's")
	}
	if !fresh.chain.TotalWork().Eq(source.chain.TotalWork()) {
		t.Fatal("accumulated work does not match after sync")
	}
}

// TestForgedTargetsAreRejectedBeforeAnyBodyIsFetched is the R4-H1 fix.
//
// A peer declaring easy targets to inflate its apparent work must be caught by
// the difficulty rule — and caught *before* a body is requested, so the lie
// costs the liar rather than the victim.
func TestForgedTargetsAreRejectedBeforeAnyBodyIsFetched(t *testing.T) {
	p := *devnetEasy()
	// A real target — about one hash in 256 succeeds — so "the rule produces
	// this" is a statement with content, while still being mineable in a test.
	p.GenesisTarget = u256.MustFromDecimal(
		"452312848583266388373324160190187140051835877600158453279131187530910662656")
	real := &p

	victim := newNode(t, real, key(t, 1).Persistent())
	victim.mine(t, 6)

	// A chain that forks from the victim's own history and simply declares an
	// easy target from there. Internally consistent, genuinely mined, and
	// entirely against the rule.
	anchor, err := victim.chain.BlockAt(3)
	if err != nil {
		t.Fatal(err)
	}
	cheap := mineCheapChain(t, real, anchor.Header, 40)
	liar := &peer{t: t, chain: victim.chain, cheapChain: cheap}

	fresh := newNode(t, real, key(t, 2).Persistent())
	for h := uint64(1); h <= 3; h++ {
		blk, err := victim.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fresh.chain.Apply(blk); err != nil {
			t.Fatal(err)
		}
	}

	_, err = sync.Run(fresh.chain, pow.Dev{}, liar, 8)
	if !errors.Is(err, sync.ErrForgedTarget) {
		t.Fatalf("got %v, want a forged-target rejection", err)
	}
	if liar.bodyRequests != 0 {
		t.Fatalf("%d bodies were requested for a chain whose headers do not check out; "+
			"the lie cost the victim, not the liar", liar.bodyRequests)
	}
	if fresh.chain.Height() != 3 {
		t.Fatalf("the node advanced to height %d on rule-breaking headers", fresh.chain.Height())
	}
}

// TestStarvedBodiesAreReported: body availability is consensus, so a peer that
// advertises headers and will not serve their bodies must be named rather than
// waited on.
func TestStarvedBodiesAreReported(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, p, key(t, 1).Persistent())
	source.mine(t, 6)

	starver := &peer{t: t, chain: source.chain, starveBodies: true}
	fresh := newNode(t, p, key(t, 2).Persistent())

	_, err := sync.Run(fresh.chain, pow.Dev{}, starver, 8)
	if !errors.Is(err, sync.ErrBodyUnavailable) {
		t.Fatalf("got %v, want a body-unavailable report", err)
	}
	if fresh.chain.Height() != 0 {
		t.Fatal("the node advanced without bodies")
	}
}

// TestSwappedBodiesAreRejected: a peer answering a body request with a
// different block is lying, not merely unhelpful.
func TestSwappedBodiesAreRejected(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, p, key(t, 1).Persistent())
	source.mine(t, 6)

	liar := &peer{t: t, chain: source.chain, swapBodies: true}
	fresh := newNode(t, p, key(t, 2).Persistent())

	_, err := sync.Run(fresh.chain, pow.Dev{}, liar, 8)
	if !errors.Is(err, sync.ErrBodyUnavailable) {
		t.Fatalf("got %v, want a rejection of the substituted body", err)
	}
}

// TestSyncRefusesALighterChain: a peer with less work must not be able to make
// this node do anything at all.
func TestSyncRefusesALighterChain(t *testing.T) {
	p := devnetEasy()
	mine := newNode(t, p, key(t, 1).Persistent())
	mine.mine(t, 10)
	tipBefore := mine.chain.Tip().ID()

	weak := newNode(t, p, key(t, 2).Persistent())
	weak.mine(t, 3)

	res, err := sync.Run(mine.chain, pow.Dev{}, &peer{t: t, chain: weak.chain}, 8)
	if err != nil {
		t.Fatal(err)
	}
	if res.Adopted {
		t.Fatal("a lighter chain was adopted")
	}
	if mine.chain.Tip().ID() != tipBefore {
		t.Fatal("the tip moved for a lighter peer")
	}
}

// TestFreshNodeJoinsADivergedNetwork is the scenario the M3 gate names: a new
// node arrives after the network has already forked and healed, and must reach
// the canonical chain through the noise.
func TestFreshNodeJoinsADivergedNetwork(t *testing.T) {
	p := devnetEasy()

	// Two miners diverge from a shared prefix.
	a := newNode(t, p, key(t, 1).Persistent())
	a.mine(t, 4)

	b := newNode(t, p, key(t, 2).Persistent())
	for h := uint64(1); h <= 2; h++ {
		blk, err := a.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := b.chain.Apply(blk); err != nil {
			t.Fatal(err)
		}
	}
	b.clock = a.clock
	b.mine(t, 6) // b is heavier

	// a heals by syncing from b.
	if _, err := sync.Run(a.chain, pow.Dev{}, &peer{t: t, chain: b.chain}, 8); err != nil {
		t.Fatalf("healing: %v", err)
	}
	if a.chain.Tip().ID() != b.chain.Tip().ID() {
		t.Fatalf("the fork did not heal: a at %d, b at %d", a.chain.Height(), b.chain.Height())
	}

	// Now a fresh node arrives and syncs from the node that lost the fork. It
	// must still land on the canonical chain, because that node healed too.
	fresh := newNode(t, p, key(t, 3).Persistent())
	if _, err := sync.Run(fresh.chain, pow.Dev{}, &peer{t: t, chain: a.chain}, 8); err != nil {
		t.Fatalf("fresh sync: %v", err)
	}
	if fresh.chain.Tip().ID() != b.chain.Tip().ID() {
		t.Fatal("a fresh node did not reach the canonical chain")
	}
	if fresh.chain.StateRoot() != b.chain.StateRoot() {
		t.Fatal("a fresh node reached the canonical chain with a different state")
	}
}

// TestAForkDeeperThanOneBatchIsStillAdopted is the root cause of every
// non-convergence this project chased for a full milestone.
//
// `runOnce` requested one batch of headers — 128 — and then asked
// `BetterThanTip`, which charges a candidate against *every* block from the
// anchor to our tip. So a fork deeper than a batch weighed 128 of the peer's
// blocks against our entire divergent suffix and lost, and the deeper the fork
// the more certainly it lost. A fork past the batch size was permanent.
//
// It failed silently: not-better returns a nil error, so the driver logged
// nothing, scored nothing, and returned success. Every instrument showed a
// healthy node — peers connected, `ahead_peers` non-zero, no bans, sync retrying
// every three seconds — while it sat on the wrong chain indefinitely. One node
// was observed 216 blocks behind for an hour; another held a different block at
// height 1 across 358 blocks.
//
// The chains here are deliberately more than `syncBatch` apart. At any depth
// below it the old code worked, which is exactly why every short test passed.
func TestAForkDeeperThanOneBatchIsStillAdopted(t *testing.T) {
	p := devnetEasy()
	// Mainnet's undo horizon, because devnet's happens to equal syncBatch (both
	// 128) and a test that collided them would be measuring the wrong refusal.
	// A fork deeper than undo_depth is refused by design — correctly, and see
	// the note below about what that implies.
	p.UndoDepth = 1024

	// Two chains from the same genesis, diverging at height 1, both far longer
	// than one batch of headers.
	ours := newNode(t, p, key(t, 1).Persistent())
	ours.mine(t, 150)

	theirs := newNode(t, p, key(t, 2).Persistent())
	theirs.clock += p.TargetBlockSeconds
	theirs.mine(t, 300)

	if blockIDAtHeight(t, ours, 1) == blockIDAtHeight(t, theirs, 1) {
		t.Fatal("setup: the two chains share block 1, so this is not a fork at all")
	}
	depth := ours.chain.Height()
	if depth <= 128 {
		t.Fatalf("setup: the fork is %d deep, not past the 128-header batch", depth)
	}
	if !theirs.chain.TotalWork().Gt(ours.chain.TotalWork()) {
		t.Fatal("setup: the challenger is not heavier, so refusing it would be correct")
	}

	res, err := sync.Run(ours.chain, pow.Dev{}, &peer{t: t, chain: theirs.chain}, 128)
	if err != nil {
		t.Fatalf("syncing a deeper, heavier chain failed: %v", err)
	}
	if !res.Adopted {
		t.Fatalf("a chain %d blocks heavier, forked %d deep, was silently refused: "+
			"one batch of headers cannot outweigh a suffix longer than a batch, so "+
			"every fork past %d blocks is permanent — and it returns no error, so "+
			"nothing anywhere reports it", theirs.chain.Height()-ours.chain.Height(),
			depth, 128)
	}
	if ours.chain.Tip().ID() != theirs.chain.Tip().ID() {
		t.Fatalf("sync reported adoption but the chains still differ: ours %x theirs %x",
			ours.chain.Tip().ID(), theirs.chain.Tip().ID())
	}
}

// TestAHeavierChainLighterOverTheComparisonWindowIsStillAdopted arms mechanism
// B of the minority-branch-rejoin defect: the extension bound is a count, the
// decision is work, and
// the two disagree.
//
// `extendToCover` grows a candidate until it has as many headers as the suffix
// it would replace. `BetterThanTip` then weighs it by accumulated work. Under
// LWMA two branches from one fork can take different difficulty trajectories,
// so the candidate's first `need` blocks can carry less work than our `need`
// blocks even when the candidate's full chain is strictly heavier — and the
// loop stops before the comparison can succeed. One more batch would have won.
//
// And it fails silently: not-better returns a nil error, so the driver logs
// nothing, scores nothing, and reports success. That is byte-for-byte the
// signature of the deep-fork defect fixed in the previous milestone — a bound
// that stops before the comparison can succeed — in a second costume.
//
// The scenario: our divergent suffix is mined *fast*, so the difficulty rule
// raises the difficulty and each of our blocks carries more work than a
// genesis-target block. The peer's branch is mined at the target pace — one
// unit of work per block — but is long enough to be strictly heavier in total.
// Weighed count-for-count it loses; weighed whole it wins.
func TestAHeavierChainLighterOverTheComparisonWindowIsStillAdopted(t *testing.T) {
	p := devnetEasy()
	const (
		shared     = 20
		oursSuffix = 10
		theirsLen  = 60
	)

	theirs := newNode(t, p, key(t, 1).Persistent())
	theirs.mine(t, shared)

	ours := newNode(t, p, key(t, 2).Persistent())
	for h := uint64(1); h <= shared; h++ {
		blk, err := theirs.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ours.chain.Apply(blk); err != nil {
			t.Fatal(err)
		}
	}
	ours.clock = theirs.clock

	// Ours mines fast — two seconds against a five-second goal — so LWMA lowers
	// the target and every block past the fork is worth more than one unit.
	ours.miner.Now = func() uint64 { ours.clock += 2; return ours.clock }
	ours.mine(t, oursSuffix)

	// Theirs keeps the target pace: the target stays at genesis and every block
	// is worth exactly one unit, but there are many more of them.
	theirs.mine(t, theirsLen)

	if blockIDAtHeight(t, ours, shared+1) == blockIDAtHeight(t, theirs, shared+1) {
		t.Fatal("setup: the chains share the first post-fork block, so there is no fork")
	}
	// The arming condition, asserted rather than assumed: count-for-count over
	// the divergent window, theirs is lighter. Any anchor the sync's walk-back
	// finds is at or below the fork, so the shared headers above it contribute
	// equally to both sides and the decision reduces to exactly this window.
	ourWindow := workBetween(t, ours, shared+1, ours.chain.Height())
	theirWindow := workBetween(t, theirs, shared+1, theirs.chain.Height()-uint64(theirsLen-oursSuffix))
	if !ourWindow.Gt(theirWindow) {
		t.Fatalf("setup: over the equal-count window our suffix (%s) does not outweigh "+
			"theirs (%s), so the count bound and the work decision agree and nothing is armed",
			ourWindow.String(), theirWindow.String())
	}
	// And the whole of theirs is strictly heavier, so refusing it is the defect
	// rather than the rule.
	if !theirs.chain.TotalWork().Gt(ours.chain.TotalWork()) {
		t.Fatal("setup: the challenger is not heavier in total, so refusing it would be correct")
	}

	res, err := sync.Run(ours.chain, pow.Dev{}, &peer{t: t, chain: theirs.chain}, 8)
	if err != nil {
		t.Fatalf("syncing a strictly heavier chain failed: %v", err)
	}
	if !res.Adopted {
		t.Fatalf("a chain heavier in total was silently refused because its first "+
			"blocks are lighter than ours count-for-count: the extension stops at "+
			"%d headers — the *length* of the suffix it would replace — but the "+
			"decision is by *work*, and under LWMA the two disagree. One more batch "+
			"of headers would have won. No error, no log line, no score: every "+
			"diagnostic reports a healthy node, forever (minority-branch rejoin, mechanism B)",
			ours.chain.Height()-shared)
	}
	if ours.chain.Tip().ID() != theirs.chain.Tip().ID() {
		t.Fatalf("sync reported adoption but the chains still differ: ours at %d, theirs at %d",
			ours.chain.Height(), theirs.chain.Height())
	}
	if ours.chain.StateRoot() != theirs.chain.StateRoot() {
		t.Fatal("the node reached the peer's tip with a different state root")
	}
}

// workBetween sums BlockWork over an inclusive height range of a node's chain.
func workBetween(t *testing.T, n *node, from, to uint64) u256.U256 {
	t.Helper()
	total := u256.Zero
	for h := from; h <= to; h++ {
		blk, err := n.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		total = total.SatAdd(chain.BlockWork(blk.Header.Target))
	}
	return total
}

func blockIDAtHeight(t *testing.T, n *node, h uint64) types.Hash {
	t.Helper()
	b, err := n.chain.BlockAt(h)
	if err != nil {
		t.Fatal(err)
	}
	return b.Header.ID()
}

// TestSyncReportsTheBlocksAReorgRemoved pins the report a reorg owes its caller.
//
// `Result.Undone` exists so the certificates in the removed blocks can go back
// to the mempool. The chain cannot do it — `node/mempool` must stay unreachable
// from `node/chain`, which is what fixes the lock order — so the chain reports
// and the caller that owns both puts them back.
//
// `runOnce` filled the field and `Run` did not copy it, so the driver's
// readmission branch — `if len(res.Undone) > 0` — was unreachable code for every
// sync-driven reorg there has ever been. A user whose transaction was confirmed
// and then reorged out by a sync would watch it vanish from the chain and from
// every mempool in the same moment, and nothing anywhere reported it, because
// the code that would have acted was never entered rather than wrong.
//
// It is pinned here rather than at the driver because this is where it was
// dropped, and because a report nobody makes is invisible at every layer above.
func TestSyncReportsTheBlocksAReorgRemoved(t *testing.T) {
	p := devnetEasy()
	const shared = 4

	theirs := newNode(t, p, key(t, 1).Persistent())
	theirs.mine(t, shared)

	ours := newNode(t, p, key(t, 2).Persistent())
	for h := uint64(1); h <= shared; h++ {
		blk, err := theirs.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ours.chain.Apply(blk); err != nil {
			t.Fatal(err)
		}
	}
	ours.clock = theirs.clock
	ours.mine(t, 3)   // our own suffix: heights 5, 6, 7
	theirs.mine(t, 9) // heavier

	// Anti-vacuity: there must be blocks to remove, or "Undone is empty" would
	// be the correct answer and this test would pass on any tree.
	ourSuffix := ours.chain.Height() - shared
	if ourSuffix == 0 {
		t.Fatal("setup: we hold no blocks past the fork, so no reorg removes anything")
	}
	// Everything we hold, so a reported block can be checked against what was
	// actually ours. The assertion below is a containment rather than an
	// equality because this test is about the *report* a reorg owes its caller
	// and not about how deep the reorg went; the depth is pinned next door, in
	// TestAShallowForkIsUndoneToItsTrueDepth.
	//
	// What used to stand here was "undoing and re-applying a shared block is
	// legal and costs nothing", and that sentence is how the overshoot stayed
	// invisible. It is legal. It is not free: it is the number `deepest_reorg`
	// reports, and that counter is what sizes undo_depth.
	held := map[uint64]types.Hash{}
	for h := uint64(1); h <= ours.chain.Height(); h++ {
		blk, err := ours.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		held[h] = blk.Header.ID()
	}
	// Our divergent suffix: the blocks only we ever had. These are the ones
	// whose certificates exist nowhere else, and every one of them must be
	// reported.
	ourOwn := map[uint64]types.Hash{}
	for h := uint64(shared) + 1; h <= ours.chain.Height(); h++ {
		ourOwn[h] = held[h]
	}

	res, err := sync.Run(ours.chain, pow.Dev{}, &peer{t: t, chain: theirs.chain}, 128)
	if err != nil {
		t.Fatal(err)
	}
	if !res.Adopted {
		t.Fatal("setup: the heavier chain was not adopted, so no reorg happened")
	}

	reported := map[uint64]types.Hash{}
	for _, blk := range res.Undone {
		want, ok := held[blk.Header.Height]
		if !ok || blk.Header.ID() != want {
			t.Fatalf("a block at height %d was reported removed and is not one we held",
				blk.Header.Height)
		}
		reported[blk.Header.Height] = blk.Header.ID()
	}
	for h, id := range ourOwn {
		if reported[h] != id {
			t.Fatalf("a reorg removed our block at height %d and did not report it "+
				"(%d of %d blocks past the fork reported). The caller returns the "+
				"certificates in these blocks to the mempool, and these are the "+
				"blocks whose certificates exist nowhere else — unreported means "+
				"dropped from the chain and the pool at the same moment, silently, "+
				"for every sync-driven reorg there has ever been.",
				h, len(reported), len(ourOwn))
		}
	}
}

// TestAShallowForkIsUndoneToItsTrueDepth pins the fork-point overshoot, and it
// is a measurement defect before it is a wasted-work one.
//
// The backward walk to the common ancestor moved in one fixed `batch` stride
// with no narrowing, so a fork one deep and a fork a whole batch deep landed on
// the same retry height — and the reorg was then performed TO THAT HEIGHT. On
// the testnet run that found it, a 12-block fork was undone as a 128-block
// reorg, and 116 blocks byte-identical on both branches were discarded and
// re-applied to reach it. `deepest_reorg` faithfully records what the chain
// unwound, so it reported 128: the batch size, exactly.
//
// docs/decisions/testnet-measurements.md §1 names that counter as the
// instrument for sizing `undo_depth` — irreversible at genesis, and below the
// real reorg-depth tail a permanent partition boundary rather than a margin. A
// stride inside the walk is a floor inside the instrument, so the distribution
// the public testnet is being run to collect would have been a distribution of
// one constant wherever sync was involved. Worse, that constant is unreadable:
// §1's censored observation of exactly 128 is the harness's `undo_depth`, and
// `syncBatch` is 128 as well, so two unrelated mechanisms produce the same
// number and the observation cannot separate them. This is the mirror rule in
// CONTRIBUTING — an instrument that derives its signal from the state the bug
// corrupts inherits the bug's blindness — arriving through the sync driver.
//
// The assertion is therefore an equality and not a bound: what the chain
// unwinds, and what the counter records, must be the depth of the fork.
func TestAShallowForkIsUndoneToItsTrueDepth(t *testing.T) {
	p := devnetEasy()
	const (
		shared      = 40 // heights 1..40, byte-identical on both branches
		ourSuffix   = 12 // the true fork depth — the figure the testnet run measured
		theirSuffix = 30 // longer, so their branch is strictly heavier
		batch       = 16 // the stride; small only to keep the chains cheap
	)

	theirs := newNode(t, p, key(t, 1).Persistent())
	theirs.mine(t, shared)

	ours := newNode(t, p, key(t, 2).Persistent())
	for h := uint64(1); h <= shared; h++ {
		blk, err := theirs.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ours.chain.Apply(blk); err != nil {
			t.Fatal(err)
		}
	}
	ours.clock = theirs.clock
	ours.mine(t, ourSuffix)
	theirs.mine(t, theirSuffix)

	// Anti-vacuity. Each of these decides something the assertions below would
	// otherwise reach by accident.
	if blockIDAtHeight(t, ours, shared) != blockIDAtHeight(t, theirs, shared) {
		t.Fatalf("setup: the branches do not share block %d, so there is no identical "+
			"prefix for an overshooting walk to destroy", uint64(shared))
	}
	if blockIDAtHeight(t, ours, shared+1) == blockIDAtHeight(t, theirs, shared+1) {
		t.Fatal("setup: the branches agree at the first divergent height, so this is not a fork")
	}
	if got := ours.chain.Height(); got != shared+ourSuffix {
		t.Fatalf("setup: our tip is %d, not %d", got, shared+ourSuffix)
	}
	if !theirs.chain.TotalWork().Gt(ours.chain.TotalWork()) {
		t.Fatal("setup: the challenger is not heavier, so refusing it would be correct")
	}
	// And the condition that makes this test discriminating at all: the fork is
	// SHALLOWER than one stride. At any depth past a stride the old walk was
	// right by accident, which is why every short fork test in this file passed
	// while the metric was wrong.
	if ourSuffix >= batch {
		t.Fatal("setup: the fork is at least one stride deep, so a fixed stride would not overshoot it")
	}

	src := &peer{t: t, chain: theirs.chain}
	res, err := sync.Run(ours.chain, pow.Dev{}, src, batch)
	if err != nil {
		t.Fatalf("healing a %d-block fork: %v", ourSuffix, err)
	}
	if !res.Adopted {
		t.Fatal("the heavier branch was not adopted, so no reorg happened and there is nothing to measure")
	}
	if ours.chain.Tip().ID() != theirs.chain.Tip().ID() {
		t.Fatal("sync reported adoption but the chains still differ")
	}

	if got := len(res.Undone); got != ourSuffix {
		t.Errorf("the reorg undid %d blocks to heal a fork %d deep: %d blocks that were "+
			"byte-identical on both branches were discarded and re-applied. The walk "+
			"back to the common ancestor overshot it and the undo was performed to the "+
			"overshoot", got, ourSuffix, got-ourSuffix)
	}
	deepest := ours.chain.Height() + 1
	for _, blk := range res.Undone {
		if h := blk.Header.Height; h < deepest {
			deepest = h
		}
	}
	if deepest != shared+1 {
		t.Errorf("the deepest block removed was at height %d, and the two branches are "+
			"identical up to %d: nothing at or below %d had any reason to move",
			deepest, shared, shared)
	}
	if got := ours.chain.Stats().DeepestReorg; got != ourSuffix {
		t.Errorf("deepest_reorg recorded %d for a fork %d deep. That counter is the "+
			"instrument docs/decisions/testnet-measurements.md §1 sizes undo_depth "+
			"from, undo_depth cannot be revisited after genesis, and a number that "+
			"reports the sync driver's stride sizes the parameter against the driver",
			got, ourSuffix)
	}
}

// TestTheForkSearchStaysInsideTheUndoHorizon pins the bound on the search that
// replaced the fixed stride.
//
// A narrowing search is cheaper per unit of depth than a stride, and that cuts
// both ways: the same doubling that finds a 12-block fork in four probes finds
// genesis in about a dozen, so a peer that simply denies every height it is
// asked about would have this node read its whole history for the price of one
// connection. The floor that stops it is not genesis. `ConsiderBranch` refuses
// any reorg anchored below `height - undo_depth` with ErrBeyondUndoHorizon
// whatever the headers say, so every probe under that line is spent looking for
// an ancestor this node could not use if it found it.
//
// The old walk did the opposite: it reached block 1, attached there, and
// downloaded an entire branch — bodies and all — before the chain refused it at
// the last step. So the assertions are: not one request under the horizon, not
// one body, and a refusal costing a handful of round trips.
func TestTheForkSearchStaysInsideTheUndoHorizon(t *testing.T) {
	p := devnetEasy()
	// Deliberately shallow, so the horizon binds well above genesis and
	// "stopped at the horizon" is distinguishable from "walked to block 1" at
	// all. Devnet's own value is 128, which at these heights is no bound.
	p.UndoDepth = 32
	const (
		ourHeight   = 120
		theirHeight = 200
		batch       = 8
	)

	ours := newNode(t, p, key(t, 1).Persistent())
	ours.mine(t, ourHeight)

	// Same pace on both branches, deliberately. A branch mined off-pace takes a
	// different LWMA trajectory and can be heavier in total while its first
	// `maxHeaders` blocks are lighter than our suffix — and then extendToCover's
	// cap refuses it before the horizon is ever consulted, which would make the
	// assertions below pass for a reason that has nothing to do with the overshoot.
	theirs := newNode(t, p, key(t, 2).Persistent())
	theirs.mine(t, theirHeight)

	if blockIDAtHeight(t, ours, 1) == blockIDAtHeight(t, theirs, 1) {
		t.Fatal("setup: the chains share block 1, so there is a usable ancestor and nothing to bound")
	}
	if !theirs.chain.TotalWork().Gt(ours.chain.TotalWork()) {
		t.Fatal("setup: the challenger is not heavier, so sync declines before it searches")
	}
	horizon := ours.chain.Height() - p.UndoDepth

	src := &peer{t: t, chain: theirs.chain}
	if _, err := sync.Run(ours.chain, pow.Dev{}, src, batch); !errors.Is(err, sync.ErrDoesNotAttach) {
		t.Errorf("a peer with no ancestor inside the undo horizon must be refused as "+
			"ErrDoesNotAttach — the search knows that before a body is requested; got %v", err)
	}
	if src.lowestAsked < horizon {
		t.Errorf("a header was requested at height %d with the undo horizon at %d. A reorg "+
			"anchored below the horizon is refused by ConsiderBranch whatever the "+
			"headers say, so every request under that line lets a peer decide how far "+
			"back this node reads", src.lowestAsked, horizon)
	}
	if src.bodyRequests != 0 {
		t.Errorf("%d bodies were downloaded for a branch that cannot be adopted at any "+
			"depth: the walk attached to an anchor the chain refuses and paid for the "+
			"whole branch to find that out", src.bodyRequests)
	}
	// Bracketing 32 blocks of horizon takes six doublings, plus the opening
	// request and the probe that lands on the floor. Pinned rather than bounded
	// loosely, so a regression to a linear walk fails here instead of being
	// absorbed by a generous constant.
	if src.headerRequests > 12 {
		t.Errorf("refusing this peer cost %d header requests; a narrowing search over a "+
			"horizon of %d blocks needs about eight, and a fixed stride of %d needs %d",
			src.headerRequests, p.UndoDepth, batch, ourHeight/batch)
	}
}

// forkedPair builds the fixture the fork-search tests below share: `shared`
// byte-identical blocks, then `ourSuffix` blocks only this node holds and
// `theirSuffix` blocks only the peer holds, with the peer's branch strictly
// heavier so sync must adopt it. The reorg that heals it is exactly `ourSuffix`
// blocks deep, and that number is what those tests measure.
//
// The anti-vacuity checks live here rather than in each caller because all of
// them rest on the same four facts. A fixture that quietly stopped being a
// fork — branches that never met, or a challenger that was not heavier — would
// turn every test using it green while measuring nothing.
func forkedPair(t *testing.T, p *params.Params, shared, ourSuffix, theirSuffix int) (ours, theirs *node) {
	t.Helper()
	theirs = newNode(t, p, key(t, 1).Persistent())
	theirs.mine(t, shared)

	ours = newNode(t, p, key(t, 2).Persistent())
	for h := uint64(1); h <= uint64(shared); h++ {
		blk, err := theirs.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := ours.chain.Apply(blk); err != nil {
			t.Fatal(err)
		}
	}
	ours.clock = theirs.clock
	ours.mine(t, ourSuffix)
	theirs.mine(t, theirSuffix)

	if blockIDAtHeight(t, ours, uint64(shared)) != blockIDAtHeight(t, theirs, uint64(shared)) {
		t.Fatalf("setup: the branches do not share block %d, so there is no identical "+
			"prefix for a misplaced anchor to destroy", shared)
	}
	if blockIDAtHeight(t, ours, uint64(shared+1)) == blockIDAtHeight(t, theirs, uint64(shared+1)) {
		t.Fatal("setup: the branches agree at the first divergent height, so this is not a fork")
	}
	if got := ours.chain.Height(); got != uint64(shared+ourSuffix) {
		t.Fatalf("setup: our tip is %d, not %d, so the fork is not %d deep",
			got, shared+ourSuffix, ourSuffix)
	}
	if !theirs.chain.TotalWork().Gt(ours.chain.TotalWork()) {
		t.Fatal("setup: the challenger is not heavier, so refusing it would be correct")
	}
	return ours, theirs
}

// tersePeer answers with fewer headers than it was asked for: real headers, in
// order, starting where the request did, just not as many of them.
//
// This is not misbehaviour. `HeaderSource.Headers` returns *up to* count
// headers, and a peer under load, near its own tip, or enforcing a response
// budget serves short replies as a matter of course.
type tersePeer struct {
	*peer
	atMost int
}

func (p *tersePeer) Headers(from uint64, count uint32) ([]types.Header, error) {
	if int(count) > p.atMost {
		count = uint32(p.atMost)
	}
	return p.peer.Headers(from, count)
}

// TestATersePeerStillYieldsTheTrueForkDepth pins the fork point against the one
// thing every peer is allowed to do: reply with less than it was asked for.
//
// `forkPoint` decided a window had reached the far side of the split by
// comparing `at+count == hi` — the count it ASKED for. A short reply was
// therefore read as a window that reached `hi`, its last shared height was
// declared the fork point, and the anchor was set BELOW the true one. The undo
// then ran to that anchor. Measured against a peer serving at most one header
// per reply, a fork 12 deep was undone as 15 blocks and `deepest_reorg`
// recorded 15; the comparison is now `w.top+1 == hi`, against what the peer
// actually served, and both numbers are 12.
//
// That is the fork-point overshoot arriving through a second door, and this door needs
// nobody to lie: it is reachable against a peer that is inside its contract at
// every step. The caps run down to 1 because one header per reply is the
// extreme of that contract and the case where every single window is short.
//
// The assertion is equality on both `Undone` and `deepest_reorg`, for the
// reason TestAShallowForkIsUndoneToItsTrueDepth states: that counter is the
// instrument undo_depth is sized from, and a counter that reports how generous
// a peer felt sizes the parameter against the peer.
func TestATersePeerStillYieldsTheTrueForkDepth(t *testing.T) {
	const (
		shared      = 40 // heights 1..40, byte-identical on both branches
		ourSuffix   = 12 // the true fork depth — the figure the testnet run measured
		theirSuffix = 30 // longer, so their branch is strictly heavier
		batch       = 16
	)
	// The fork must be shallower than one window, or a search that read every
	// short reply as a full one would still land on the right height by
	// accident and this test would pass on the broken code.
	if ourSuffix >= batch {
		t.Fatal("setup: the fork is at least one window deep, so a window read as full " +
			"cannot overshoot it and the truncation decides nothing")
	}
	for _, atMost := range []int{1, 2, 3, 5} {
		t.Run(fmt.Sprintf("cap=%d", atMost), func(t *testing.T) {
			p := devnetEasy()
			ours, theirs := forkedPair(t, p, shared, ourSuffix, theirSuffix)

			src := &tersePeer{peer: &peer{t: t, chain: theirs.chain}, atMost: atMost}
			res, err := sync.Run(ours.chain, pow.Dev{}, src, batch)
			if err != nil {
				t.Fatalf("a peer serving at most %d headers per reply is answering inside "+
					"the Headers contract; healing a %d-block fork against it failed: %v",
					atMost, ourSuffix, err)
			}
			if !res.Adopted {
				t.Fatal("the heavier branch was not adopted, so no reorg happened and there " +
					"is nothing to measure")
			}
			if ours.chain.Tip().ID() != theirs.chain.Tip().ID() {
				t.Fatal("sync reported adoption but the chains still differ")
			}
			if got := len(res.Undone); got != ourSuffix {
				t.Errorf("a peer serving at most %d headers per reply made a fork %d deep "+
					"undo %d blocks: the search read a short window as one that reached "+
					"the far side of the split and anchored %d blocks below the fork, "+
					"discarding and re-applying blocks that were byte-identical on both "+
					"branches", atMost, ourSuffix, got, got-ourSuffix)
			}
			if got := ours.chain.Stats().DeepestReorg; got != ourSuffix {
				t.Errorf("deepest_reorg recorded %d for a fork %d deep against a peer "+
					"serving at most %d headers per reply. That counter is what "+
					"docs/decisions/testnet-measurements.md §1 sizes undo_depth from, and "+
					"undo_depth cannot be revisited after genesis: a number that records "+
					"how many headers a peer felt like sending sizes the parameter "+
					"against the peers, not against the reorgs",
					got, ourSuffix, atMost)
			}
		})
	}
}

// echoingPeer answers narrow probes out of the VICTIM's own chain and every
// full-width request out of a branch that attaches to nothing the victim holds.
//
// Every header it serves is real and sits at the height it claims, and the two
// halves cannot both be true: the probes say the chains agree at the height
// just below our tip, and the bulk answer says they do not. There is no reply
// the victim can act on, and the only question is how much it pays to find out.
type echoingPeer struct {
	victim   *peer
	real     *peer
	batch    uint32
	requests int
}

func (p *echoingPeer) Tip() (uint64, u256.U256) { return p.real.Tip() }

func (p *echoingPeer) Headers(from uint64, count uint32) ([]types.Header, error) {
	p.requests++
	if p.requests > 500 {
		// A breaker rather than an assertion: the test's own ceiling is what
		// reports the defect, and this only stops an unbounded walk from
		// running the whole suite out while it does so.
		return nil, fmt.Errorf("circuit breaker: %d header requests", p.requests)
	}
	if count < p.batch {
		return p.victim.Headers(from, count)
	}
	return p.real.Headers(from, count)
}

// TestAContradictingPeerIsRefusedInABoundedNumberOfRequests pins the bound on
// the loop AROUND the fork search.
//
// `forkPoint` is bounded and always was. The loop in `runOnce` that calls it
// was not, and the two together are what a peer is actually charged for. A peer
// that answers every probe truthfully out of this node's own chain agrees at
// `from-2` every time, so every search succeeds and returns that height; its
// full-width answers are a branch that does not attach, so every retry fails
// and `from` drops by exactly one. Nothing is ever wrong, nothing is ever
// resolved, and the walk grinds down to the undo horizon one block per round
// trip.
//
// Measured before the bound existed: 65 header requests at an undo_depth of 32
// — 2*undo_depth+1 exactly, which is ~2049 at mainnet's undo_depth of 1024,
// spent on one peer, for one rotation slot, to reach a refusal available in
// three. The ceiling here is the assertion; the error is checked too because
// the refusal must stay ErrDoesNotAttach, which SyncPenalty charges nothing
// for: a peer that reorganised under the search produces the same contradiction
// as one that manufactured it, and nothing here can tell them apart.
func TestAContradictingPeerIsRefusedInABoundedNumberOfRequests(t *testing.T) {
	p := devnetEasy()
	// Shallow, so 2*undo_depth+1 is a number this test can afford to reach if
	// the bound is gone. Devnet's own value is 128 and mainnet's is 1024; the
	// mechanism does not care which.
	p.UndoDepth = 32
	const (
		ourHeight   = 120
		theirHeight = 200
		batch       = 8
	)

	ours := newNode(t, p, key(t, 1).Persistent())
	ours.mine(t, ourHeight)
	theirs := newNode(t, p, key(t, 2).Persistent())
	theirs.mine(t, theirHeight)

	if blockIDAtHeight(t, ours, 1) == blockIDAtHeight(t, theirs, 1) {
		t.Fatal("setup: the chains share block 1, so the peer's bulk answers would attach " +
			"and there is no contradiction to bound")
	}
	if !theirs.chain.TotalWork().Gt(ours.chain.TotalWork()) {
		t.Fatal("setup: the challenger is not heavier, so sync declines before it searches")
	}

	adv := &echoingPeer{
		victim: &peer{t: t, chain: ours.chain},
		real:   &peer{t: t, chain: theirs.chain},
		batch:  batch,
	}
	_, err := sync.Run(ours.chain, pow.Dev{}, adv, batch)
	if !errors.Is(err, sync.ErrDoesNotAttach) {
		t.Errorf("a peer whose probes contradict its bulk answers must be refused as "+
			"ErrDoesNotAttach — the verdict a peer that reorganised twice would also "+
			"get, and one SyncPenalty charges nothing for; got %v", err)
	}
	// Five, and the number is measured rather than chosen — it is what pins
	// maxForkSearches from ABOVE. Against this adversary each search costs one
	// bulk request and one probe, and one bulk request opens the pass, so the
	// refusal costs exactly 2*maxForkSearches+1: measured 5 at two, 7 at three,
	// 9 at four. The literal is deliberate. Deriving it from the constant would
	// make the assertion move with the thing it is supposed to hold still, and
	// a ceiling loose enough to absorb a third search leaves sync.go's claim
	// there — "two concurrent reorgs inside one pass is not a case to keep a
	// peer's slot open for" — held by nothing.
	//
	// The other direction is held next door by the reorganising-peer test: at
	// one, a peer that reorganised under the search is refused instead of
	// adopted. Between them the constant is pinned from both sides.
	const maxRequests = 5
	if adv.requests > maxRequests {
		t.Errorf("refusing this peer cost %d header requests, want at most %d "+
			"(2*maxForkSearches+1). The contradiction is visible in three: the loop "+
			"around the fork search moves `from` down one block per pass, so an "+
			"unbounded loop pays 2*undo_depth+1 — 65 at the undo_depth of %d used "+
			"here, ~2049 at mainnet's 1024 — for one peer, for one rotation slot, to "+
			"reach the same refusal", adv.requests, maxRequests, p.UndoDepth)
	}
}

// forkSearchPeer is an honest peer that separates the three request shapes one
// sync pass makes, so what the fork search costs can be counted rather than
// inferred from the width of a request.
//
// Width does not separate them, and the counter this replaces assumed it did.
// `runOnce` and `extendToCover` do ask for exactly `batch` every time — but
// `probeShared` asks for `min(hi-at, batch)`, and that IS `batch` once the
// back-off step reaches a whole batch. Counting narrow requests therefore
// undercounts the probes, by half at the deepest rows of the table below.
//
// Position separates them exactly, because the three shapes look in different
// directions: a probe only ever looks BELOW the attempt it is searching under,
// and an extension only ever climbs ABOVE the height the pass landed at. So a
// pass is one attempt that misses, the probes under it, the attempt that lands,
// and then the extensions — and:
//
//   - Every `forkPoint` call opens with a request for exactly ONE header two
//     heights below the attempt that just missed: `step` starts at 1 and `at`
//     is `hi-1`, with `hi` the height that attempt could not attach to. Nothing
//     else in sync asks for a single header straight after a full-width one, so
//     counting that pair counts the searches.
//   - The attempt that lands is the LAST full-width request at `fork+1`. The
//     extensions climb from there, so nothing after it repeats that height, and
//     a probe that asked there asked earlier — which is not hypothetical: at
//     depths 16 and 32 below, the back-off probes `fork+1` at exactly a batch's
//     width, the same request in both `from` and `count`. Everything before the
//     attempt that landed which is not itself an attempt is a probe.
type forkSearchPeer struct {
	*peer
	batch uint32
	// fork is the height the two chains last agree at. The fixture knows it
	// outright, and it is where the attempt that lands must ask from.
	fork uint64

	served   int
	prevFrom uint64
	prevWide bool
	// searches counts calls to forkPoint; landed is the position, in requests
	// served, of the attempt that reached the fork point.
	searches int
	landed   int
}

func (p *forkSearchPeer) Headers(from uint64, count uint32) ([]types.Header, error) {
	p.served++
	if count == 1 && p.prevWide && p.prevFrom == from+2 {
		p.searches++
	}
	if count == p.batch && from == p.fork+1 {
		p.landed = p.served
	}
	p.prevFrom, p.prevWide = from, count == p.batch
	return p.peer.Headers(from, count)
}

// probes is how many windows the searches asked for: every request before the
// attempt that landed, less the attempts themselves — the opening one, and one
// more per search.
func (p *forkSearchPeer) probes() int { return p.landed - 1 - p.searches }

// TestAnHonestPeerNeedsOneForkSearchAtAnyDepth is why maxForkSearches can be
// two, and it is cited from that refusal in runOnce.
//
// The bound is only safe if an honest peer never needs more than one search, so
// the searches are COUNTED here. The earlier version of this test inferred them
// from `err == nil` and `len(Undone) == depth` — and those two hold just as
// well for a pass that searched TWICE and landed on the second, which is
// exactly the case the bound of two allows and which this test exists to rule
// out for an honest peer.
//
// The anchor is still asserted alongside, because one search is worth nothing
// unless that search lands exactly. An anchor ABOVE the fork produces headers
// that do not attach and costs another search; an anchor BELOW it attaches and
// undoes blocks byte-identical on both branches, which is the overshoot, and
// `deepest_reorg` — the instrument undo_depth is sized from — records the
// overshoot.
//
// The depths straddle a power of two on both sides — 7/8/9, 15/16/17, 31/32/33
// — because the back-off doubles, so those are the depths where the window that
// brackets the fork changes shape and every off-by-one in the narrowing shows
// up first. They straddle the batch and its multiples for the same reason from
// the other end: a window is capped at `batch`, so past a fork one batch deep
// the bracketing window can stop short of the height it is narrowing towards.
//
// The probe count is the second half of the same property, pinned per depth and
// exactly rather than under a ceiling — a constant with room in it absorbs
// exactly the regression it was put there to catch, which is the reason
// TestTheForkSearchStaysInsideTheUndoHorizon gives for pinning tightly too.
// Every number in the table was measured. What they record is the shape the
// `diverged` half of the terminating test in forkPoint buys: while the back-off
// step is still inside one batch, the window that brackets the fork holds both
// sides of the split and ENDS the search — depths 1 to 15, and 31, where the
// bracketing is the whole cost. Only where the step has outrun a batch can the
// bracketing window land wholly below the fork and leave a range for the
// bisect: 16 and 17 pay one bisect probe on top of five, 32 and 33 pay two on
// top of six. A search that could not tell a window that disagreed from a
// window that merely ended would bisect at every one of these depths and still
// find the right height; it would just pay the difference in round trips
// against every honest peer, at every fork, for ever.
func TestAnHonestPeerNeedsOneForkSearchAtAnyDepth(t *testing.T) {
	const (
		shared     = 60
		theirExtra = 25 // their branch is this much longer, so strictly heavier
		batch      = 8
	)
	for _, tc := range []struct{ depth, probes int }{
		{1, 1}, {2, 2}, {3, 2}, {7, 3}, {8, 4}, {9, 4}, {12, 4},
		{15, 4}, {16, 6}, {17, 6}, {31, 5}, {32, 8}, {33, 8},
	} {
		t.Run(fmt.Sprintf("depth=%d", tc.depth), func(t *testing.T) {
			p := devnetEasy()
			ours, theirs := forkedPair(t, p, shared, tc.depth, tc.depth+theirExtra)

			src := &forkSearchPeer{
				peer:  &peer{t: t, chain: theirs.chain},
				batch: batch,
				fork:  shared,
			}
			res, err := sync.Run(ours.chain, pow.Dev{}, src, batch)
			if err != nil {
				t.Fatalf("an honest peer at a fork %d deep was refused: %v. A refusal here "+
					"is the maxForkSearches bound firing, which means one search did not "+
					"reach the fork point and the bound of two is not safe", tc.depth, err)
			}
			if !res.Adopted {
				t.Fatalf("the heavier branch was not adopted at a fork %d deep, so no reorg "+
					"happened and there is nothing to measure", tc.depth)
			}
			if ours.chain.Tip().ID() != theirs.chain.Tip().ID() {
				t.Fatal("sync reported adoption but the chains still differ")
			}
			if src.landed == 0 {
				t.Fatalf("no attempt ever asked for a batch at height %d, the block after "+
					"the fork point, so the pass anchored somewhere else and every count "+
					"below would be measuring a different sync", shared+1)
			}
			if got := len(res.Undone); got != tc.depth {
				t.Errorf("healing a fork %d deep undid %d blocks. The anchor was %d blocks "+
					"below the fork point, so blocks byte-identical on both branches were "+
					"discarded and re-applied, and deepest_reorg — the instrument "+
					"undo_depth is sized from — records the overshoot",
					tc.depth, got, got-tc.depth)
			}
			if got := ours.chain.Stats().DeepestReorg; got != uint64(tc.depth) {
				t.Errorf("deepest_reorg recorded %d for a fork %d deep", got, tc.depth)
			}
			if src.searches != 1 {
				t.Errorf("an honest peer at a fork %d deep cost %d fork searches. One has to "+
					"be enough at every depth or maxForkSearches has no honest headroom "+
					"left: the second search is reserved for a chain that reorganised under "+
					"the first, and a peer that needs it for anything else is a peer this "+
					"node refuses for a defect of its own", tc.depth, src.searches)
			}
			if got := src.probes(); got != tc.probes {
				t.Errorf("naming a fork %d deep took %d probes, not %d. The doubling "+
					"back-off brackets a fork this deep in a fixed number of windows, and "+
					"the window that brackets it also NAMES it whenever it holds both sides "+
					"of the split — so a count that grew is a search that handed what was "+
					"left to the bisect instead of ending where it stood, and it pays that "+
					"difference against every honest peer, at every fork",
					tc.depth, got, tc.probes)
			}
		})
	}
}

// branchFrom builds a chain that holds src's first `upto` blocks and then mines
// `extra` of its own, so the two agree everywhere at or below `upto` and differ
// above it. forkedPair does this for the two-chain case; this exists because
// the reorg below needs three chains cut from one prefix at two depths.
func branchFrom(t *testing.T, p *params.Params, src *node,
	upto, extra int, payout types.Address) *node {
	t.Helper()
	n := newNode(t, p, payout)
	for h := uint64(1); h <= uint64(upto); h++ {
		blk, err := src.chain.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := n.chain.Apply(blk); err != nil {
			t.Fatal(err)
		}
	}
	// Resume the miner's clock where the copied prefix left off. Timestamps are
	// what the difficulty rule reads, so a branch that restarts from genesis
	// time takes a different LWMA trajectory and stops being comparable in work
	// to the branch it was cut from — which is the same trap forkedPair avoids
	// by mining both suffixes at one pace.
	n.clock = p.GenesisTime + uint64(upto)*p.TargetBlockSeconds
	n.mine(t, extra)
	return n
}

// reorganisingPeer serves one branch until the fork search has named an anchor
// on it and then serves another: the peer's own chain reorganising in the
// window between the probe that found the anchor and the request that uses it.
//
// The switch fires on the first request narrower than a batch, which is the
// search's opening probe. `first` forks one block below the victim's tip, so
// that one probe IS the whole search — the anchor it names was canonical when
// the probe read it and is on an abandoned branch by the time `runOnce` asks
// for a batch at anchor+1.
type reorganisingPeer struct {
	batch uint32
	// first is the branch the search reads and then is what replaces it. Both
	// outweigh the victim, so either would be worth adopting.
	first, then *chain.Chain
	served      int
	// reorganisedAfter is the request the switch happened on. Without it a peer
	// that never reorganised, or reorganised somewhere harmless, would leave
	// the assertions below true and vacuous.
	reorganisedAfter int
}

func (p *reorganisingPeer) current() *chain.Chain {
	if p.reorganisedAfter != 0 {
		return p.then
	}
	return p.first
}

func (p *reorganisingPeer) Tip() (uint64, u256.U256) {
	c := p.current()
	return c.Height(), c.TotalWork()
}

func (p *reorganisingPeer) Headers(from uint64, count uint32) ([]types.Header, error) {
	c := p.current()
	p.served++
	var out []types.Header
	for h := from; h <= c.Height() && len(out) < int(count); h++ {
		blk, err := c.BlockAt(h)
		if err != nil {
			break
		}
		out = append(out, blk.Header)
	}
	if p.reorganisedAfter == 0 && count < p.batch {
		p.reorganisedAfter = p.served
	}
	return out, nil
}

func (p *reorganisingPeer) Body(id types.Hash) (*types.Block, error) {
	if blk, err := p.then.Block(id); err == nil {
		return blk, nil
	}
	return p.first.Block(id)
}

// TestAPeerThatReorganisesUnderTheSearchIsGivenASecondAttempt is why
// maxForkSearches is two rather than one.
//
// One search is enough for an honest peer at every fork depth, which is what
// TestAnHonestPeerNeedsOneForkSearchAtAnyDepth counts and what makes a bound
// this tight safe at all. The second is not slack on top of that: it is the one
// blameless way a peer's own answers can contradict each other. A chain that
// reorganises while it is being searched hands back an anchor that WAS
// canonical when the probe read it, and by the time `runOnce` asks for a batch
// at anchor+1 the peer is on another branch and those headers do not attach.
// Nothing on this path can tell that peer from one that manufactured the
// contradiction — which is why the refusal charges neither — but refusing on
// the first miss would drop a peer that did nothing wrong and had a heavier
// chain to hand over.
//
// The reorg is timed rather than sprinkled: the peer's first branch forks one
// block below this node's tip, so the search is exactly one probe and the
// switch fires the moment that probe has been answered. That is the narrowest
// form of the window runOnce's comment describes. A reorg anywhere else either
// changes nothing the search read or is a second reorg inside one pass, which
// the bound deliberately does not cover.
//
// Adoption is the assertion rather than the error, because that is what the
// value buys: with the bound at one this pass ends in ErrDoesNotAttach and the
// node stays behind a peer that was always going to serve it.
func TestAPeerThatReorganisesUnderTheSearchIsGivenASecondAttempt(t *testing.T) {
	p := devnetEasy()
	const (
		shared    = 60
		ourSuffix = 12
		nearExtra = 3  // forks one below our tip, so the search is one probe
		deepExtra = 30 // forks at `shared`, and is what the pass must end on
		batch     = 8
	)
	base := newNode(t, p, key(t, 1).Persistent())
	base.mine(t, shared)
	ours := branchFrom(t, p, base, shared, ourSuffix, key(t, 2).Persistent())
	near := branchFrom(t, p, ours, shared+ourSuffix-1, nearExtra, key(t, 3).Persistent())
	deep := branchFrom(t, p, base, shared, deepExtra, key(t, 4).Persistent())

	ourTip := uint64(shared + ourSuffix)
	if blockIDAtHeight(t, near, ourTip-1) != blockIDAtHeight(t, ours, ourTip-1) ||
		blockIDAtHeight(t, near, ourTip) == blockIDAtHeight(t, ours, ourTip) {
		t.Fatalf("setup: the first branch does not fork at %d, so the search that reads "+
			"it is not the single probe this test times the reorg against", ourTip)
	}
	if blockIDAtHeight(t, deep, shared) != blockIDAtHeight(t, ours, shared) ||
		blockIDAtHeight(t, deep, shared+1) == blockIDAtHeight(t, ours, shared+1) {
		t.Fatalf("setup: the second branch does not fork at %d, so the retry would "+
			"attach and there is no contradiction to survive", shared)
	}
	if !near.chain.TotalWork().Gt(ours.chain.TotalWork()) {
		t.Fatal("setup: the first branch is not heavier, so the pass declines before it searches")
	}
	if !deep.chain.TotalWork().Gt(ours.chain.TotalWork()) {
		t.Fatal("setup: the second branch is not heavier, so refusing it would be correct")
	}

	src := &reorganisingPeer{batch: batch, first: near.chain, then: deep.chain}
	res, err := sync.Run(ours.chain, pow.Dev{}, src, batch)
	if err != nil {
		t.Fatalf("a peer that reorganised between the probe that named its anchor and the "+
			"request that used it was refused: %v. That contradiction is what the second "+
			"fork search exists for — the anchor was canonical when it was found and is "+
			"not by the time it is used — and a bound of one spends the whole allowance "+
			"on the miss", err)
	}
	if src.reorganisedAfter != 2 {
		t.Fatalf("the peer switched branches on request %d, not on the second. The window "+
			"this test is about is the one between the search and the retry: a switch "+
			"anywhere else is a peer that reorganised where nothing was reading",
			src.reorganisedAfter)
	}
	if !res.Adopted {
		t.Fatal("the branch the peer reorganised onto was not adopted, so the second " +
			"attempt bought nothing and the pass ended where a bound of one would end it")
	}
	if ours.chain.Tip().ID() != deep.chain.Tip().ID() {
		t.Fatal("sync reported adoption but this node is not on the branch the peer moved to")
	}
	if got := len(res.Undone); got != ourSuffix {
		t.Errorf("healing a fork %d deep across a reorg under the search undid %d blocks: "+
			"the second search anchored %d blocks off the fork point, and deepest_reorg "+
			"records the difference", ourSuffix, got, got-ourSuffix)
	}
}

// overServingPeer keeps talking past the end of the window it was asked for,
// and everything it says is true: the extra headers are the victim's own
// blocks, at the heights they claim, in order, continuing the reply.
//
// It over-serves only where it already agrees — a reply that ended on a block
// the victim also holds is continued with the victim's next blocks. That is the
// only way over-served headers can MATCH anything the probe checks, and
// matching is the whole mechanism: a probe that reads past `count` sees the
// shared run run on past the height it was narrowing towards.
type overServingPeer struct {
	*peer
	victim *chain.Chain
	slack  uint32
	// overServed counts the replies that actually ran past `count`. Nothing
	// else in this test can tell whether the peer ever did the thing it exists
	// to do, and a search that stopped asking for windows it agrees with all
	// the way across would leave the assertions below true and vacuous.
	overServed int
}

func (p *overServingPeer) Headers(from uint64, count uint32) ([]types.Header, error) {
	out, err := p.peer.Headers(from, count)
	if err != nil || len(out) == 0 {
		return out, err
	}
	last := out[len(out)-1]
	if id, ok := p.victim.CanonicalIDAt(last.Height); !ok || id != last.ID() {
		return out, nil
	}
	before := len(out)
	for h := last.Height + 1; h <= last.Height+uint64(p.slack); h++ {
		blk, err := p.victim.BlockAt(h)
		if err != nil {
			break
		}
		out = append(out, blk.Header)
	}
	if len(out) > before {
		p.overServed++
	}
	return out, nil
}

// TestAnOverServingPeerDoesNotDerailTheForkSearch pins the guard in probeShared
// that stops reading a reply at `count`.
//
// The guard's own comment calls it the line that keeps the walk terminating,
// and until this test nothing exercised it. What it stops is not a lie: every
// header this peer serves past the window is a real block at its real height —
// they are the victim's OWN blocks, so every one of them matches the probe's
// check. A probe that reads them lets its shared run climb past `hi`, the
// height the search had already established is on the peer's branch, and then
// returns an anchor at or above the height the pass started from. `runOnce`
// requests the same range again, and the walk that terminates because `from`
// strictly decreases no longer decreases. Before the guard this cost thousands
// of requests for a fork twelve blocks deep.
//
// The assertion is adoption at the true depth rather than a bare "it stopped":
// with the reply capped, this peer is a peer that talks too much and nothing
// more, and the fork behind its verbosity is found exactly.
func TestAnOverServingPeerDoesNotDerailTheForkSearch(t *testing.T) {
	p := devnetEasy()
	const (
		shared      = 40
		ourSuffix   = 12
		theirSuffix = 30
		batch       = 4
	)
	// The fork must be DEEPER than one window. The over-serve is only ever read
	// by a probe that agreed all the way across its window, and a window only
	// stops short of the divergent height once the back-off has outrun the
	// batch — which needs a fork deeper than one window to happen at all.
	if ourSuffix <= batch {
		t.Fatal("setup: the fork fits inside one window, so every probe either reaches " +
			"the divergent height or diverges inside itself, and no reply is ever read " +
			"past its window")
	}
	ours, theirs := forkedPair(t, p, shared, ourSuffix, theirSuffix)

	src := &overServingPeer{
		peer:   &peer{t: t, chain: theirs.chain},
		victim: ours.chain,
		slack:  2 * batch,
	}
	res, err := sync.Run(ours.chain, pow.Dev{}, src, batch)
	if err != nil {
		t.Fatalf("a peer that answers with more than it was asked for still described a "+
			"fork %d deep truthfully; syncing from it failed: %v", ourSuffix, err)
	}
	if src.overServed == 0 {
		t.Fatal("no reply ever ran past the window it was asked for, so this test exercised " +
			"the guard it exists for exactly zero times")
	}
	if !res.Adopted {
		t.Fatal("the heavier branch was not adopted, so no reorg happened and there is " +
			"nothing to measure")
	}
	if got := len(res.Undone); got != ourSuffix {
		t.Errorf("healing a fork %d deep against an over-serving peer undid %d blocks: the "+
			"probe read past the window it asked for and anchored on a height the peer's "+
			"extra headers named rather than the one it narrowed to", ourSuffix, got)
	}
	if got := ours.chain.Stats().DeepestReorg; got != ourSuffix {
		t.Errorf("deepest_reorg recorded %d for a fork %d deep against an over-serving peer",
			got, ourSuffix)
	}
	// Fifteen requests here. Stated at the strength it has: this is a tripwire,
	// not the assertion that holds termination. With the over-serve guard
	// removed the pass now ends on ErrDoesNotAttach — `from` reaches 1 and the
	// bail above it fires — so the `t.Fatalf` on the error a few lines up
	// speaks first and this comparison is never reached. Confirmed by removing
	// the guard AND raising maxForkSearches to 100000 to rule out the search
	// bound being what caps it: still the error, never this line.
	//
	// It is kept because the failure it watches for is the one the guard's own
	// comment in sync.go names — a probe that reads past `count` returning an
	// anchor at or above the height the pass started from, so the same range is
	// requested for ever — and a future change that reopens that path without
	// reopening the ErrDoesNotAttach path would have nothing else looking.
	if src.headerRequests > 20 {
		t.Errorf("syncing a fork %d deep from an over-serving peer cost %d header requests "+
			"where fifteen is the whole job. A search that reads a reply past the window "+
			"it asked for can hand `runOnce` an anchor that does not descend, and a walk "+
			"whose `from` stops descending stops terminating: thousands of requests, "+
			"measured, for this same twelve-block fork", ourSuffix, src.headerRequests)
	}
}

// jumblingPeer answers narrow requests — the shape the fork search probes with
// — by dropping a header out of the middle of the window, so the reply arrives
// at heights other than the ones asked for. Every header is real and in order;
// the reply simply stops describing the range it was asked about partway
// through.
//
// Full-width requests are answered honestly on purpose. A corrupted bulk answer
// would be refused by ValidateHeaders and the pass would end on that, hiding
// the thing this test is here to observe, which is the ANCHOR the search chose.
type jumblingPeer struct {
	*peer
	batch uint32
	skip  int
	// jumbled counts the replies that actually skipped a height, for the same
	// reason overServingPeer counts its over-serves: without it, a search that
	// stopped asking for windows wide enough to skip inside would leave this
	// test green and empty.
	jumbled int
}

func (p *jumblingPeer) Headers(from uint64, count uint32) ([]types.Header, error) {
	out, err := p.peer.Headers(from, count)
	if err != nil || count >= p.batch || len(out) <= p.skip+1 {
		return out, err
	}
	p.jumbled++
	return append(out[:p.skip:p.skip], out[p.skip+1:]...), nil
}

// TestAnOutOfOrderReplyIsNarrowedOnRatherThanConcludedFrom pins the difference
// between a peer that disagrees and a reply that stopped making sense.
//
// probeShared used to treat both the same way: a header arriving at a height
// other than the one requested set the same flag as a header arriving AT the
// requested height naming a different block, and `forkPoint` reads that flag as
// "this window holds both sides of the split, so its last shared height is the
// fork point" and returns it. But a reply that went off the rails says nothing
// about the height it failed to describe. The last height actually checked is a
// lower bound on the fork point and nothing more, and treating it as the answer
// anchors the reorg below the true fork — the fork-point overshoot, from a peer that
// never claimed to disagree with us anywhere.
//
// So the flag now means only "a header AT the height I asked for named a
// different block", and a window that merely ended is narrowed on instead. The
// assertion is the true depth, because the wrong anchor still attaches, still
// adopts and still reports success: the only trace it leaves is blocks undone
// that had no reason to move.
//
// What this peer pins is the FLAG and not the height check that raises it. A
// dropped height cannot tell the two apart: agreement is monotone in height, so
// every header still in the reply is one this node either holds or does not
// hold at its own height, and reading them there reaches the same verdict as
// refusing to read them at all. Removing the check outright leaves this test
// green, which is why
// TestAReplyFromAForeignHeightRangeDecidesNothingAboutTheRangeAsked exists
// alongside it.
func TestAnOutOfOrderReplyIsNarrowedOnRatherThanConcludedFrom(t *testing.T) {
	p := devnetEasy()
	const (
		shared      = 40
		ourSuffix   = 12
		theirSuffix = 30
		batch       = 16
	)
	ours, theirs := forkedPair(t, p, shared, ourSuffix, theirSuffix)

	src := &jumblingPeer{peer: &peer{t: t, chain: theirs.chain}, batch: batch, skip: 2}
	res, err := sync.Run(ours.chain, pow.Dev{}, src, batch)
	if err != nil {
		t.Fatalf("a peer whose narrow replies skip a height still holds a branch %d blocks "+
			"past a fork this node can reach; syncing from it failed: %v", theirSuffix, err)
	}
	if src.jumbled == 0 {
		t.Fatal("no reply ever skipped a height, so the search never saw an out-of-order " +
			"answer and this test decided nothing")
	}
	if !res.Adopted {
		t.Fatal("the heavier branch was not adopted, so no reorg happened and there is " +
			"nothing to measure")
	}
	if got := len(res.Undone); got != ourSuffix {
		t.Errorf("healing a fork %d deep undid %d blocks against a peer whose narrow "+
			"replies skip a height. A reply that arrives at heights other than the ones "+
			"asked for is not evidence about the heights it skipped: read as a "+
			"disagreement it makes the last height checked the fork point, and the "+
			"anchor lands %d blocks below the true one",
			ourSuffix, got, got-ourSuffix)
	}
	if got := ours.chain.Stats().DeepestReorg; got != ourSuffix {
		t.Errorf("deepest_reorg recorded %d for a fork %d deep against a peer whose narrow "+
			"replies skip a height", got, ourSuffix)
	}
}

// foreignRangePeer answers narrow requests — the shape the fork search probes
// with — by describing the range it was asked about for one header and then
// continuing out of a completely different part of its chain. Every header is
// real, in order, and at its own true height; the reply simply stops being
// about the window it was asked for.
//
// Full-width requests are answered honestly, for jumblingPeer's reason: a
// corrupted bulk answer is refused by ValidateHeaders and the pass ends on
// that, hiding the thing under test, which is the ANCHOR the search chose.
type foreignRangePeer struct {
	*peer
	batch uint32
	// foreign is where the tail of a reply comes from, and it is above the fork
	// on purpose. That is what makes the two readings of the reply differ: the
	// heights it names are ones this node holds a DIFFERENT block at, so a
	// probe that reads the tail as an answer about the window concludes the
	// peer disagrees — inside a window where it never said so.
	foreign uint64
	victim  *chain.Chain
	// readIntoForeign counts the replies a probe actually reads into: the ones
	// whose first header the victim also holds, so the shared run is still open
	// when the foreign tail arrives. A reply that diverged at its own first
	// height is dropped before the tail is reached, and counting those would
	// leave this test green while the check it exists for never ran.
	readIntoForeign int
}

func (p *foreignRangePeer) Headers(from uint64, count uint32) ([]types.Header, error) {
	out, err := p.peer.Headers(from, count)
	if err != nil || count >= p.batch || len(out) < 2 {
		return out, err
	}
	tail := make([]types.Header, 0, len(out)-1)
	for h := p.foreign; h <= p.chain.Height() && len(tail) < len(out)-1; h++ {
		blk, err := p.chain.BlockAt(h)
		if err != nil {
			return nil, err
		}
		tail = append(tail, blk.Header)
	}
	if len(tail) != len(out)-1 {
		return out, nil
	}
	if id, ok := p.victim.CanonicalIDAt(out[0].Height); ok && id == out[0].ID() {
		p.readIntoForeign++
	}
	return append(out[:1:1], tail...), nil
}

// TestAReplyFromAForeignHeightRangeDecidesNothingAboutTheRangeAsked is the test
// that holds the height check in probeShared, and it is deliberately not the
// same shape as TestAnOutOfOrderReplyIsNarrowedOnRatherThanConcludedFrom.
//
// That test drops a height out of the middle of a window, and a dropped height
// cannot show the check is load-bearing: agreement is monotone in height, so
// every header still in the reply is a header this node either holds or does
// not hold AT ITS OWN HEIGHT, and reading them at their own heights reaches the
// same verdict as refusing to read them at all. Delete the check entirely and
// that test stays green.
//
// This one names heights from another range. The tail of every narrow reply is
// real headers of the peer's real chain from ABOVE the fork — heights this node
// holds different blocks at — arriving at the positions a window had reserved
// for heights the two chains still agree on. Read as an answer about the
// window, they say the peer diverges there; the window then looks like one
// holding both sides of the split, `forkPoint` takes its last shared height for
// the fork point, and the anchor lands below the true one. That is the
// fork-point overshoot again, produced by a peer that never claimed to disagree
// with this node anywhere.
//
// So the assertion is the depth of the reorg, not an error: the wrong anchor
// attaches, adopts and reports success. The only trace it leaves is blocks
// undone that had no reason to move — which is exactly what deepest_reorg, the
// instrument undo_depth is sized from, would then be recording.
func TestAReplyFromAForeignHeightRangeDecidesNothingAboutTheRangeAsked(t *testing.T) {
	p := devnetEasy()
	const (
		shared      = 40
		ourSuffix   = 12
		theirSuffix = 30
		batch       = 16
	)
	ours, theirs := forkedPair(t, p, shared, ourSuffix, theirSuffix)

	src := &foreignRangePeer{
		peer:    &peer{t: t, chain: theirs.chain},
		batch:   batch,
		foreign: shared + 1,
		victim:  ours.chain,
	}
	res, err := sync.Run(ours.chain, pow.Dev{}, src, batch)
	if err != nil {
		t.Fatalf("a peer whose narrow replies wander into another height range still holds "+
			"a branch %d blocks past a fork this node can reach; syncing from it failed: %v",
			theirSuffix, err)
	}
	if src.readIntoForeign == 0 {
		t.Fatal("no probe ever agreed at its first height and then ran into the foreign " +
			"range, so the search never read a header from heights it had not asked " +
			"about and this test decided nothing")
	}
	if !res.Adopted {
		t.Fatal("the heavier branch was not adopted, so no reorg happened and there is " +
			"nothing to measure")
	}
	if got := len(res.Undone); got != ourSuffix {
		t.Errorf("healing a fork %d deep undid %d blocks against a peer whose narrow replies "+
			"continue out of another height range. Those headers are evidence about the "+
			"heights they name and about nothing else: read as evidence about the window "+
			"they arrived in, they end the search at the last height checked and the "+
			"anchor lands %d blocks below the true fork",
			ourSuffix, got, got-ourSuffix)
	}
	if got := ours.chain.Stats().DeepestReorg; got != ourSuffix {
		t.Errorf("deepest_reorg recorded %d for a fork %d deep against a peer whose narrow "+
			"replies continue out of another height range", got, ourSuffix)
	}
}

// TestSyncLandsWhileGossipApplies drives the one interleaving that was flagged
// as unexercised when the incremental landing was written.
//
// `Fetch` decides once, before it lands anything, whether the candidate extends
// the tip — and the chain it asks is shared with the gossip engine, which
// applies blocks from its own goroutines. So the decision can be stale by the
// time the landing happens. I argued that is safe, because `ConsiderBranch`
// re-checks the ancestor under the chain's own lock and answers
// `ErrUnknownAncestor` or `ErrNotBetter` rather than corrupting anything. That
// was an argument, not evidence.
//
// CONTRIBUTING is explicit about the difference: a tool observes only the
// executions it is given, and `-race` passed across this whole suite while
// `chain.Chain` had no lock at all, because every test drove it from one
// goroutine. So this test drives the two paths concurrently, deliberately, in
// the shape the process actually uses.
//
// What it asserts is the invariant, not a schedule: however the two interleave,
// the node ends on the source's chain with the source's state root, and nothing
// panics. Which of them landed any given block is genuinely unspecified.
func TestSyncLandsWhileGossipApplies(t *testing.T) {
	p := devnetEasy()
	const blocks = 60

	source := newNode(t, p, key(t, 1).Persistent())
	source.mine(t, blocks)

	// The interleaving is asked for repeatedly, and the repetition is the fix
	// for a scheduler that declines to interleave rather than a convenience.
	//
	// Everything an attempt asserts before its last guard is a property of this
	// node. The last guard is a property of the *schedule*, and a test cannot
	// demand a schedule — it can only ask and look at what it got. The margin
	// is one block: idle and without `-race`, the applier lands exactly one
	// block in about four attempts in five, so an attempt that interleaved and
	// one that did not are a single slot apart. How narrow that slot is was
	// measured by widening it — a uniform 0-2 ms delay injected into the
	// applier goroutine's start, nothing else changed, takes a single-attempt
	// run from passing to failing 23 times in 30. The window this test's whole
	// verdict rests on is under a millisecond of goroutine start latency, and
	// no test owns that. A run that fails there has found nothing about this
	// node: every invariant the attempt checks held, and what did not is that
	// the operating system arranged two goroutines the way the attempt wanted.
	// CONTRIBUTING names the shape — a check that can fire for a benign reason
	// is noise with authority — so the coin is flipped until it lands.
	//
	// Eight, and the number comes from the same injected delay rather than from
	// taste. Swept, single attempt against eight, 50 runs each: at delays where
	// one attempt missed up to a fifth of the time (1, 6 and 10 failures in 50),
	// eight attempts failed 0 in 50; it takes a per-attempt miss rate past 40%
	// before eight fail at all (21 -> 1), and at 86% eight still fail 20 in 50.
	// So this is a reduction of one to two orders of magnitude across the range
	// that resembles a real machine, and an honest degradation past it. What it
	// is not is p^8: the misses are not independent, because how wide the window
	// is on a given run is partly a property of that run, and the sweep shows it
	// — so the bound is the measurement, not the arithmetic. This machine sits
	// at 4 misses in ~3,000 attempts, three orders of magnitude below where
	// eight begins to struggle; `windows-latest` cannot be measured until there
	// are credits, and eight is what a 4-core runner two orders of magnitude
	// worse than this one would still survive. Being generous costs nothing:
	// attempts stop at the first success, so the expected cost is one attempt
	// and the eighth is only ever paid on a run that is failing anyway. A miss
	// is not wasted either — it asserted the full invariant first, so it buys
	// another concurrent execution of the thing under test, which CONTRIBUTING
	// names as the only currency a race detector spends.
	//
	// The teeth are unchanged, and that is why this retries rather than
	// relaxes. An attempt misses because a schedule went one way; a build where
	// one path does the whole job by construction misses *every* attempt,
	// because there is no schedule under which it does not. Measured against
	// both halves — the applier gated behind the sync, and the applier run to
	// completion before it — 8 of 8 attempts miss and the test still fails.
	//
	// Rejected: `t.Skip` on a miss, which is how the first draft's degenerate
	// 60-of-60 pass comes back, since a green run that exercised nothing reads
	// exactly like one that exercised everything. Also rejected: giving the
	// applier a head start by waiting for it to signal it is running before the
	// sync starts. That makes the miss impossible rather than unlikely, and
	// impossible is the objection — `gossiped > 0` becomes true by
	// construction, the half of the guard that catches an all-sync run stops
	// being able to fire, and the guard measures the head start, not the race.
	const attempts = 8
	for attempt := 1; attempt <= attempts; attempt++ {
		gossiped, synced := raceSyncAgainstApplier(t, p, source, blocks)
		// Anti-vacuity, and it is the whole question. BOTH paths must have
		// landed something: either alone is a legal schedule and neither alone
		// is the interleaving this test is named for — all-gossip means the
		// sync arrived to find nothing to do, and all-sync means the applier
		// never got in. The first draft of this guard asked only that the
		// applier landed more than zero, and it passed at 60 of 60, the
		// degenerate case: satisfying the guard while exercising nothing.
		if gossiped > 0 && synced > 0 {
			t.Logf("interleaved on attempt %d of %d: %d blocks landed by the "+
				"applier, %d by the racing sync", attempt, attempts, gossiped, synced)
			return
		}
		// Loud on every miss, even on a run that goes on to pass. A regression
		// to "one path does everything" would otherwise arrive as a silent
		// change in how many attempts this test needs, which is exactly the
		// kind of drift nobody reads a log to find.
		t.Logf("attempt %d of %d did not interleave: the competing applier "+
			"landed %d blocks and the racing sync landed %d",
			attempt, attempts, gossiped, synced)
	}
	t.Fatalf("no interleaving in %d attempts: in every one of them a single "+
		"path did the whole job, so the stale-`extends` window this test exists "+
		"for was never open. One miss is a schedule; %d consecutive misses is "+
		"the two paths no longer competing for the same blocks.", attempts, attempts)
}

// raceSyncAgainstApplier runs one attempt at the interleaving against a node
// built for this attempt alone — the victim's chain is the thing the race
// mutates, so an attempt cannot be replayed on a chain a previous one already
// filled. The source is mined once and only read, by both paths, which is the
// same sharing the process does.
//
// It asserts the invariant in full and returns what each path landed, leaving
// only the question of whether the schedule was worth having to the caller.
func raceSyncAgainstApplier(t *testing.T, p *params.Params, source *node, blocks int) (gossiped int64, synced int) {
	t.Helper()
	victim := newNode(t, p, key(t, 2).Persistent())

	// The competing applier: the same canonical blocks, one at a time, exactly
	// as the gossip path delivers them. It races the sync deliberately.
	var wg gosync.WaitGroup
	var landedByGossip atomic.Int64
	stop := make(chan struct{})
	wg.Add(1)
	go func() {
		defer wg.Done()
		for h := uint64(1); h <= uint64(blocks); h++ {
			select {
			case <-stop:
				return
			default:
			}
			blk, err := source.chain.BlockAt(h)
			if err != nil {
				return
			}
			// Errors are the point of the test rather than a failure of it: a
			// block the sync has already landed loses on work, and one whose
			// parent the sync has not reached yet does not attach. Both are
			// correct answers and both must be answers rather than panics.
			reorg, _ := victim.chain.ConsiderBranch(chain.Branch{Blocks: []*types.Block{blk}})
			if reorg.Adopted {
				landedByGossip.Add(1)
			}
			// Paced, and the pacing is load-bearing. Unpaced, this goroutine
			// lands all sixty blocks before the sync fetches its first body —
			// which is a legal schedule but not an interleaving, and a test
			// that accepted it would be asserting "gossip won the race" under
			// the name of "the two overlap".
			time.Sleep(300 * time.Microsecond)
		}
	}()

	// A source that yields on every body, so the two goroutines interleave
	// inside the fetch loop rather than one finishing before the other starts.
	slow := &yieldingPeer{peer: &peer{t: t, chain: source.chain}}
	raced, err := sync.Run(victim.chain, pow.Dev{}, slow, 16)
	close(stop)
	wg.Wait()

	// Whatever the interleaving did, finish the job: the assertion is about the
	// state the node ends in, not about which path got there.
	if _, err2 := sync.Run(victim.chain, pow.Dev{}, &peer{t: t, chain: source.chain}, 16); err2 != nil {
		t.Fatalf("settling sync after the race: %v (first pass: %v)", err2, err)
	}

	if victim.chain.Tip().ID() != source.chain.Tip().ID() {
		t.Fatalf("after a sync racing a gossip applier the node is on a different "+
			"chain: height %d vs %d", victim.chain.Height(), source.chain.Height())
	}
	// The check that matters. Two nodes can agree on a tip while holding
	// different state, and that is the failure the epoch state root exists to
	// catch — a torn read during a concurrent landing would surface here.
	if victim.chain.StateRoot() != source.chain.StateRoot() {
		t.Fatal("the node reached the source's tip with a different state root: " +
			"a concurrent landing produced state no fold reproduces")
	}
	if !victim.chain.TotalWork().Eq(source.chain.TotalWork()) {
		t.Fatal("accumulated work disagrees after the race")
	}

	// What each path landed is reported rather than judged here. Everything
	// above is a property of this node and is settled inside the attempt;
	// whether the schedule was worth having is a property of the run, and it
	// belongs to the caller, which is the one that can ask for another.
	if raced != nil {
		synced = raced.Applied
	}
	return landedByGossip.Load(), synced
}

// yieldingPeer hands control away on every body, widening the window in which
// the competing applier can land a block between this sync's fetch and its
// commit. Without it the fetch loop usually runs to completion uninterrupted
// and the interleaving under test never happens.
type yieldingPeer struct{ *peer }

func (y *yieldingPeer) Body(id types.Hash) (*types.Block, error) {
	runtime.Gosched()
	return y.peer.Body(id)
}

// poisoningPeer serves genuine headers and, at one height, a body whose header
// is genuine but whose certificates are not the ones that header commits to.
//
// This is a sharper lie than the one `swapBodies` tells. A swapped body carries
// a *different header*, so the header-id check catches it. This one carries the
// **right header** — so the id matches, and the only thing that says the body is
// wrong is the cert root, which is checked much later, inside the fold.
type poisoningPeer struct {
	*peer
	at       uint64
	poisoned int
}

func (l *poisoningPeer) Body(id types.Hash) (*types.Block, error) {
	blk, err := l.peer.Body(id)
	if err != nil {
		return nil, err
	}
	if blk.Header.Height == l.at {
		l.poisoned++
		// Same header, different body. The header id still matches; the cert
		// root no longer does.
		return &types.Block{Header: blk.Header, Certs: []*types.Certificate{{
			ChainID: 1, Seq: 1, TTL: 1000,
			Program: types.Program{Kind: types.ProgramTransfer, Transfer: &types.TransferArgs{}},
		}}}, nil
	}
	return blk, nil
}

// citingPeer serves genuine headers except at its tip, where it serves a header
// committing to a citation list of one genesis-height header, and a body that
// matches it.
//
// Forging only the tip keeps the rest of the chain honest: the tip's CitesRoot
// is the sole field that changes, its parent linkage and its declared target
// are the real ones, and nothing links *forward* from a tip, so the header
// stage — version, contiguity, linkage, declared target, proof of work, median
// time, none of which reads CitesRoot — accepts it exactly as it accepts the
// genuine one.
type citingPeer struct {
	*peer
	forged types.Header
	body   *types.Block
}

func newCitingPeer(t *testing.T, base *peer, p *params.Params) *citingPeer {
	t.Helper()
	tip, err := base.chain.BlockAt(base.chain.Height())
	if err != nil {
		t.Fatal(err)
	}
	// A citation carrying no work at all. CheckWork never looks at it: the
	// height short-circuits the function before it reads the target.
	cited := types.Header{
		Version:      types.HeaderVersion,
		Height:       0,
		ParentID:     types.Hash{0xee},
		Time:         p.GenesisTime,
		EmissionAddr: key(t, 9).Persistent(),
		Target:       u256.One,
	}
	body := &types.Block{Header: tip.Header, Certs: tip.Certs, Cites: []*types.Header{&cited}}
	body.Header.CitesRoot = body.ComputeCitesRoot(p)
	// CitesRoot is a PoW input, so the tip's own nonce no longer solves. Re-mine
	// it at the target the rule actually requires — the declared target is left
	// untouched, so the header stage's target re-derivation still passes and
	// the forgery costs the same work the honest tip cost.
	if !pow.Solve(pow.Dev{}, &body.Header, p, 1<<24) {
		t.Fatal("setup: could not re-solve the forged tip at the real target")
	}
	return &citingPeer{peer: base, forged: body.Header, body: body}
}

func (c *citingPeer) Headers(from uint64, count uint32) ([]types.Header, error) {
	out, err := c.peer.Headers(from, count)
	if err != nil {
		return nil, err
	}
	for i := range out {
		if out[i].Height == c.forged.Height {
			out[i] = c.forged
		}
	}
	return out, nil
}

func (c *citingPeer) Body(id types.Hash) (*types.Block, error) {
	if id == c.forged.ID() {
		c.bodyRequests++
		return c.body, nil
	}
	return c.peer.Body(id)
}

// TestASyncedBodyCitingAGenesisHeightHeaderIsRefused is the sync half of the
// genesis-height citation hole's citation guard, and the reason it exists is
// that the gossip half alone makes the rule path-dependent — the one-door-open
// shape this repository treats as the serious class, not a missing nicety.
//
// `pow.CheckWork` returns nil for a height-0 header before it reads the target,
// so the citation loop here gave a genesis-height citation a free pass exactly
// as `p2p.Engine.OnBlock` did, while the comment above that loop claimed the
// two paths were closed the same way.
//
// **What the guard buys is where the refusal happens, and that is the whole
// property.** The fold refuses such a block either way — `checkCites` permits
// no citation below height 2 and requires `cited.Height == h.Height-1` above
// it — so a test that only asserted "sync fails" would pass without the guard
// and measure nothing. What changes is that the body is refused at ingress,
// before `Retain`, so it never enters the body cache. A body that reaches the
// cache and is rejected afterwards is the failure
// `TestAPoisonedBodyDoesNotPersistInTheCache` exists for.
func TestASyncedBodyCitingAGenesisHeightHeaderIsRefused(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, p, key(t, 1).Persistent())
	source.mine(t, 6)

	// Anti-vacuity: the same peer without the forged tip syncs to the tip
	// through the same cache, so a failure below is the citation and not the
	// harness.
	control := newNode(t, p, key(t, 2).Persistent())
	ctl := sync.NewBodyCache()
	if _, err := sync.Run(control.chain, pow.Dev{}, ctl.Source(&peer{t: t, chain: source.chain}), 128); err != nil {
		t.Fatalf("setup: an honest sync through a cache failed: %v", err)
	}

	victim := newNode(t, p, key(t, 3).Persistent())
	cache := sync.NewBodyCache()
	liar := newCitingPeer(t, &peer{t: t, chain: source.chain}, p)

	_, err := sync.Run(victim.chain, pow.Dev{}, cache.Source(liar), 128)
	if !errors.Is(err, sync.ErrBodyUnavailable) {
		t.Fatalf("got %v, want the body refused at ingress as unavailable", err)
	}
	if liar.bodyRequests == 0 {
		t.Fatal("setup: the forged tip was never requested, so nothing was exercised")
	}

	// The property the error alone does not pin: the body never reached the
	// cache. Without the guard the citation loop passes, `Retain` runs, and the
	// block is refused later by the fold — the same failed sync, but with the
	// forgery now served back out of local memory on every later attempt.
	// Honest peers from here. The node must reach the tip, which it cannot do
	// if the forged body is being served back out of local memory.
	honest := &peer{t: t, chain: source.chain}
	for i := 0; i < 10; i++ {
		if _, err := sync.Run(victim.chain, pow.Dev{}, cache.Source(honest), 128); err == nil {
			break
		}
	}
	if victim.chain.Tip().ID() != source.chain.Tip().ID() {
		t.Fatalf("after ten honest syncs the node is stuck at height %d of %d: a "+
			"body citing a genesis-height header was retained and is being served "+
			"back from local memory", victim.chain.Height(), source.chain.Height())
	}
}

// TestAPoisonedBodyDoesNotPersistInTheCache is the defect the retention
// introduced, and it is worse than what it replaced.
//
// `Fetch` promised in its own doc comment that "each body must match the header
// it was requested for". It checked `blk.Header.ID() != id`, which proves the
// *header* is the right header and says nothing about whether the body under it
// is the one that header commits to. Nothing else on the path closes that:
// `types.UnmarshalBlock` does not verify the cert root, and `p2p`'s cert-root
// check is on announcements rather than on served bodies. The mismatch is
// caught by B1 inside `CheckBlockRules` — which runs in `ApplyBlock`, long
// after the body has been retained.
//
// Without a cache that cost a peer one wasted attempt. With one it is
// permanent: the poisoned body is served from local memory to every subsequent
// attempt, against every peer, for the life of the process. One malicious
// response and the node never syncs again.
//
// A fix that makes a node able to catch up, and hands an attacker a way to stop
// it catching up forever, is not an improvement. This is the test that says so.
func TestAPoisonedBodyDoesNotPersistInTheCache(t *testing.T) {
	p := devnetEasy()
	source := newNode(t, p, key(t, 1).Persistent())
	source.mine(t, 6)

	// Anti-vacuity: an honest peer through a fresh cache reaches the tip, so a
	// failure below is the poison rather than the retention being broken.
	control := newNode(t, p, key(t, 2).Persistent())
	ctl := sync.NewBodyCache()
	if _, err := sync.Run(control.chain, pow.Dev{}, ctl.Source(&peer{t: t, chain: source.chain}), 128); err != nil {
		t.Fatalf("setup: an honest sync through a cache failed: %v", err)
	}
	if control.chain.Tip().ID() != source.chain.Tip().ID() {
		t.Fatal("setup: an honest sync through a cache did not reach the tip")
	}

	victim := newNode(t, p, key(t, 3).Persistent())
	cache := sync.NewBodyCache()
	liar := &poisoningPeer{peer: &peer{t: t, chain: source.chain}, at: 3}

	if _, err := sync.Run(victim.chain, pow.Dev{}, cache.Source(liar), 128); err == nil {
		t.Fatal("a body that does not match its header's cert root was accepted")
	}
	if liar.poisoned == 0 {
		t.Fatal("setup: the liar never got to serve its poisoned body")
	}

	// The liar is gone. Only honest peers from here, and the node must recover:
	// a lie told once must not outlive the connection that told it.
	honest := &peer{t: t, chain: source.chain}
	for i := 0; i < 10; i++ {
		if _, err := sync.Run(victim.chain, pow.Dev{}, cache.Source(honest), 128); err == nil {
			break
		}
	}
	if victim.chain.Tip().ID() != source.chain.Tip().ID() {
		t.Fatalf("after ten syncs against honest peers the node is stuck at height "+
			"%d of %d. One malicious response was retained in local memory and is "+
			"now served to every future attempt against every peer, for the life "+
			"of the process — so the retention that lets a node catch up also lets "+
			"one lie stop it catching up permanently, which is strictly worse than "+
			"having no retention at all.",
			victim.chain.Height(), source.chain.Height())
	}
}

// TestARetainedHeaderIsNeverASyncAnchor.
//
// The property: sync attaches to blocks that are on this chain, never to blocks
// this chain merely remembers.
//
// The two used to be the same test by accident. A reorg deleted the loser's
// header, so `chain.Header` succeeding meant "this is on my chain", and sync's
// three attachment checks were written against that meaning while asking the
// other question. Retaining orphaned headers — which an observer needs, so that
// a block that left the chain does not become a permanent 404 — separated the
// two and left every one of those checks answering wrongly.
//
// The cost of that is not a rejected sync. It is a sync that *proceeds*: the
// headers validate, the bodies are fetched, ConsiderBranch rejects the branch
// with ErrUnknownAncestor, and SyncPenalty does not score that error — so
// nothing is banned, nothing is logged as wrong, and the loop retries from the
// same anchor forever. A node that cannot rejoin, in silence, with every
// diagnostic reporting health. That is the shape of the minority-branch-rejoin
// defect, arriving
// through the door the previous fix closed.
//
// Reaching it needs the landing to fall inside the retained range, since the
// search steps down by a batch at a time and a shallower fork simply steps over
// it. That is inside the documented envelope rather than hypothetical: the undo
// horizon is 1024 and the qualifying soak observed a 136-block reorg under
// contention,
// against a default batch of 128.
func TestARetainedHeaderIsNeverASyncAnchor(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, p, key(t, 1).Persistent())
	n.mine(t, 4)

	losing, err := n.chain.BlockAt(3)
	if err != nil {
		t.Fatal(err)
	}
	losingID := losing.Header.ID()

	// A heavier branch takes heights 3 and 4 off the chain: the first block
	// ties the honest chain's own (a block's target has no freedom relative to
	// a fixed ancestor), the second is mined fast enough that the pair
	// outweighs the two blocks it replaces.
	ancestor, err := n.chain.BlockAt(2)
	if err != nil {
		t.Fatal(err)
	}
	branch := buildHarderBranch(t, n.chain, p, key(t, 7).Persistent(), ancestor.Header, 2, fastSolveSeconds)
	reorg, err := n.chain.ConsiderBranch(branch)
	if err != nil {
		t.Fatalf("considering the harder branch: %v", err)
	}
	if !reorg.Adopted {
		t.Fatal("setup: the heavier branch was not adopted, so nothing was orphaned")
	}

	// Setup check: the header is retained, or there is nothing here to get
	// wrong and the assertions below would pass against any implementation.
	if _, err := n.chain.Header(losingID); err != nil {
		t.Fatalf("setup: the orphaned header was not retained: %v", err)
	}
	if _, err := n.chain.CanonicalHeader(losingID); err == nil {
		t.Fatal("setup: an orphaned header is reported as canonical")
	}

	descendant := types.Header{
		Version:  types.HeaderVersion,
		Height:   losing.Header.Height + 1,
		ParentID: losingID,
		Time:     losing.Header.Time + p.TargetBlockSeconds,
		Target:   losing.Header.Target,
	}

	_, err = sync.ValidateHeaders(n.chain, pow.Dev{}, []types.Header{descendant})
	if !errors.Is(err, sync.ErrDoesNotAttach) {
		t.Fatalf("headers descending from a block this node reorged away were "+
			"accepted for body fetch (err=%v): the bodies would be downloaded and "+
			"then rejected by ConsiderBranch with an error nothing scores, and the "+
			"loop would retry from the same anchor forever", err)
	}

	cand := &sync.Candidate{
		AttachesTo: losingID,
		Headers:    []types.Header{descendant},
		Work:       u256.Max,
	}
	if _, err := cand.BetterThanTip(n.chain); !errors.Is(err, sync.ErrDoesNotAttach) {
		t.Fatalf("a candidate anchored on an orphaned block was weighed against "+
			"this chain (err=%v)", err)
	}

	// Anti-vacuity: the same shape anchored on a block that *is* on the chain
	// must fail for some other reason, or this is asserting that the headers
	// are junk rather than that the anchor is not ours.
	tip := n.chain.Tip()
	attached := types.Header{
		Version:  types.HeaderVersion,
		Height:   tip.Height + 1,
		ParentID: tip.ID(),
		Time:     tip.Time + p.TargetBlockSeconds,
		Target:   tip.Target,
	}
	if _, err := sync.ValidateHeaders(n.chain, pow.Dev{}, []types.Header{attached}); errors.Is(err, sync.ErrDoesNotAttach) {
		t.Fatal("a header descending from the tip was reported as not attaching, " +
			"so the assertions above are measuring the headers and not the anchor")
	}
}

// TestRollbackAndReorgAgreeOnWhatSurvives: both take a block off this chain,
// so a block id must survive both or neither. A rule that holds for one and not
// the other is a rule nobody can state, and the inconsistency would be
// inherited on the day Rollback gets a caller outside the tests.
func TestRollbackAndReorgAgreeOnWhatSurvives(t *testing.T) {
	p := devnetEasy()
	n := newNode(t, p, key(t, 1).Persistent())
	n.mine(t, 3)

	tip, err := n.chain.BlockAt(3)
	if err != nil {
		t.Fatal(err)
	}
	id := tip.Header.ID()

	if err := n.chain.Rollback(); err != nil {
		t.Fatalf("rolling back the tip: %v", err)
	}

	if _, err := n.chain.Header(id); err != nil {
		t.Fatalf("a rolled-back block's id stopped resolving, while a reorged-out "+
			"block's id still does: %v", err)
	}
	if _, err := n.chain.CanonicalHeader(id); err == nil {
		t.Fatal("a rolled-back block is still reported as being on this chain")
	}
	if _, err := n.chain.Block(id); err == nil {
		t.Fatal("a rolled-back block kept its body, so the node's memory grows " +
			"with every rollback")
	}
}

// fastSolveSeconds times a buildHarderBranch block far below
// TargetBlockSeconds, so the difficulty rule computes a genuinely harder
// target for it — the only way left to make a hand-built branch outweigh
// another now that ConsiderBranch re-derives every declared target
// instead of trusting it.
const fastSolveSeconds = 1

// buildHarderBranch constructs a branch of empty blocks descending from an
// ancestor on ch, each carrying the target and time the difficulty rule and
// the median-time floor actually require for it.
//
// ConsiderBranch re-derives both the target and the time bounds for every block
// on a branch — a branch adopted by fork choice used to be checked for neither
// — so a hand-built header can no longer declare an arbitrary target and pass:
// this runs the same LWMA computation the real chain does, walking the same
// preceding window pow.NextTarget reads. A block's own target is fixed entirely
// by the window that precedes it, so the *first* block after a shared ancestor
// always ties whatever the honest chain computed for the same position — a
// branch meant to beat more than one replaced block needs more than one block
// of its own, with solveSeconds compounding from the second on.
func buildHarderBranch(t *testing.T, ch *chain.Chain, p *params.Params, payout types.Address,
	ancestor types.Header, count int, solveSeconds uint64) chain.Branch {
	t.Helper()

	window := headersEndingAt(t, ch, ancestor.ID(), int(p.DifficultyWindow)+1)

	var blocks []*types.Block
	parent := ancestor.ID()
	parentTime := ancestor.Time
	for i := 0; i < count; i++ {
		target := pow.NextTarget(window, p)
		when := parentTime + solveSeconds
		if floor := pow.MedianTime(window, p); when <= floor {
			when = floor + 1
		}

		b := &types.Block{Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       ancestor.Height + uint64(i) + 1,
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

// headersEndingAt walks ch from id back toward genesis via parent links,
// returning up to want headers oldest-first — the shape pow.NextTarget and
// pow.CheckMedianTime read.
func headersEndingAt(t *testing.T, ch *chain.Chain, id types.Hash, want int) []types.Header {
	t.Helper()
	var out []types.Header
	cursor := id
	for len(out) < want {
		hdr, err := ch.Header(cursor)
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

// The future-time limit on the sync ingress path.
//
// The gossip path holds a future-dated block in a queue; a header range has no
// body to hold, so the equivalent is to stop the range where this node's clock
// stops. Both paths must bound it, because a rule enforced on one ingress and
// not the other is the defect itself.
func TestHeaderRangeStopsAtTheFutureTimeLimit(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, p, key(t, 1).Persistent())
	victim := newNode(t, p, key(t, 2).Persistent())
	a.mine(t, 60)

	headers, err := (&peer{t: t, chain: a.chain}).Headers(1, 100)
	if err != nil {
		t.Fatal(err)
	}
	if len(headers) != 60 {
		t.Fatalf("the harness served %d headers", len(headers))
	}

	// Blocks are TargetBlockSeconds apart from genesis_time, so a clock reading
	// genesis_time reaches FTL/TargetBlockSeconds of them and no further.
	want := int(p.FutureTimeLimitSeconds / p.TargetBlockSeconds)
	restore := sync.Clock
	t.Cleanup(func() { sync.Clock = restore })
	sync.Clock = func() time.Time { return time.Unix(int64(p.GenesisTime), 0) }

	cand, err := sync.ValidateHeaders(victim.chain, pow.Dev{}, headers)
	if err != nil {
		t.Fatalf("a range whose first headers are judgeable was refused: %v", err)
	}
	if len(cand.Headers) != want {
		t.Fatalf("the range was truncated to %d headers, want %d: the future-time "+
			"limit is not bounding what sync folds", len(cand.Headers), want)
	}

	// The clock moves on and the rest of the range becomes judgeable. Nothing
	// was discarded and no peer was blamed.
	sync.Clock = func() time.Time { return time.Unix(int64(p.GenesisTime+60*p.TargetBlockSeconds), 0) }
	cand, err = sync.ValidateHeaders(victim.chain, pow.Dev{}, headers)
	if err != nil {
		t.Fatal(err)
	}
	if len(cand.Headers) != 60 {
		t.Fatalf("with the clock caught up the range is still %d headers", len(cand.Headers))
	}

	// A range that is *entirely* ahead is not an error about the peer.
	sync.Clock = func() time.Time { return time.Unix(int64(p.GenesisTime-3600), 0) }
	_, err = sync.ValidateHeaders(victim.chain, pow.Dev{}, headers)
	if !errors.Is(err, sync.ErrHeadersWithheld) {
		t.Fatalf("got %v, want a withhold", err)
	}

	// And it carries how far ahead, which is the sync half of the slow-clock
	// stall. runOnce turns this into a successful empty Result — right, since
	// the peer did nothing wrong — and that made "stuck at a fixed lag behind
	// the chain" indistinguishable from "already up to date". The gap was
	// computed for the error text and then thrown away; it is the number an
	// operator would set their clock by.
	var we *sync.WithheldError
	if !errors.As(err, &we) {
		t.Fatalf("the withhold carries no skew: %T. A Result with no reason on it "+
			"reads exactly like a node with nothing to do", err)
	}
	wantSkew := headers[0].Time - (p.GenesisTime - 3600)
	if we.SkewSeconds != wantSkew {
		t.Fatalf("skew reported as %ds, want %ds (header 0 at %d against a clock "+
			"reading %d)", we.SkewSeconds, wantSkew, headers[0].Time, p.GenesisTime-3600)
	}
}

// TestAFutureDatedGarbageHeaderIsScoredRatherThanWithheld pins the *order* of
// the future-time check against every check that does not need a clock.
//
// ErrHeadersWithheld is not a judgement: `runOnce` turns it into a successful
// empty Result — no score, no progress, nothing logged as a failure. So if the
// future-time check runs before Version, Height, ParentID, NextTarget,
// CheckWork and CheckMedianTime, one header costing zero hashes buys an
// unauthenticated peer a silent no-op out of every sync pass it is selected
// for, forever, and it is never charged for it. That is the free-and-unscored
// shape of the minority-branch-rejoin defect and of the whole-attempt stall,
// where one peer holds the single-threaded sync loop indefinitely at no cost,
// and it is exactly what this test refuses.
//
// The discrimination is the pair: the *same* header, dated the same way, is
// withheld when it is otherwise valid and refused as garbage when it is not.
// A node that simply rejected everything future-dated would fail the first
// half; a node that withheld first would fail the second.
func TestAFutureDatedGarbageHeaderIsScoredRatherThanWithheld(t *testing.T) {
	p := devnetEasy()
	a := newNode(t, p, key(t, 1).Persistent())
	victim := newNode(t, p, key(t, 2).Persistent())
	a.mine(t, 4)

	headers, err := (&peer{t: t, chain: a.chain}).Headers(1, 4)
	if err != nil {
		t.Fatal(err)
	}

	restore := sync.Clock
	t.Cleanup(func() { sync.Clock = restore })
	// Far enough behind that every header in the range is past the limit.
	sync.Clock = func() time.Time { return time.Unix(int64(p.GenesisTime-3600), 0) }

	// The honest case, first, so the mutation below is measured against a
	// baseline rather than against nothing: a valid range that is entirely
	// ahead is withheld.
	if _, err := sync.ValidateHeaders(victim.chain, pow.Dev{}, headers); !errors.Is(err, sync.ErrHeadersWithheld) {
		t.Fatalf("a valid future-dated range gave %v, want a withhold", err)
	}

	// Now the same range with header 0 replaced by garbage: a fabricated
	// height, no proof of work, and the same future date. It must be refused as
	// what it is, not laundered into "nothing to do this pass".
	for _, tc := range []struct {
		name  string
		spoil func(h *types.Header)
	}{
		{"no proof of work", func(h *types.Header) { h.PoW.Nonce = 0; h.Target = u256.One }},
		{"fabricated height", func(h *types.Header) { h.Height = 999999 }},
		// Not a broken ParentID on header 0: that is refused by the anchor
		// lookup above the loop, on either ordering, so it would discriminate
		// nothing. A forged target is checked inside the loop, which is where
		// the ordering lives.
		{"forged target", func(h *types.Header) { h.Target = u256.MustFromDecimal("7") }},
		{"wrong version", func(h *types.Header) { h.Version = types.HeaderVersion + 1 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			spoiled := append([]types.Header(nil), headers...)
			tc.spoil(&spoiled[0])

			_, err := sync.ValidateHeaders(victim.chain, pow.Dev{}, spoiled)
			if err == nil {
				t.Fatal("a garbage header dated ahead was accepted")
			}
			if errors.Is(err, sync.ErrHeadersWithheld) {
				t.Fatalf("a header with %s was withheld rather than refused: %v.\n"+
					"runOnce converts a withhold into a successful empty pass, so "+
					"this peer just spent zero hashes to make every sync pass it "+
					"is selected for a silent no-op, and was not scored for it",
					tc.name, err)
			}
		})
	}
}

// wholeForeignPeer answers every narrow request — the shape the fork search
// probes with — entirely out of a different part of its chain. Unlike
// foreignRangePeer it does not keep the first header honest, so the reply is
// not about the window from its very first position.
//
// Full-width requests stay honest, for the reason its two siblings state: a
// corrupted bulk answer is refused by ValidateHeaders and the pass ends there,
// hiding the anchor this test is about.
type wholeForeignPeer struct {
	*peer
	batch uint32
	// foreign is where every narrow reply comes from instead, and it is above
	// the fork so the heights it names are ones the victim holds different
	// blocks at.
	foreign uint64
	// replaced counts the replies that were actually substituted, so a change
	// that stopped this peer being hostile cannot leave the test green.
	replaced int
}

func (p *wholeForeignPeer) Headers(from uint64, count uint32) ([]types.Header, error) {
	out, err := p.peer.Headers(from, count)
	if err != nil || count >= p.batch || len(out) == 0 {
		return out, err
	}
	var sub []types.Header
	for h := p.foreign; h <= p.chain.Height() && len(sub) < len(out); h++ {
		blk, err := p.chain.BlockAt(h)
		if err != nil {
			return nil, err
		}
		sub = append(sub, blk.Header)
	}
	if len(sub) != len(out) || sub[0].Height == from {
		return out, nil
	}
	p.replaced++
	return sub, nil
}

// TestAProbeThatDecidedNothingIsNotTurnedIntoAClaim holds the one guard in
// forkPoint that no other test reaches: the arm that treats a served-but-
// unreadable probe as a probe that decided nothing.
//
// Every other adversary in this file lets the shared run open before it goes
// wrong — foreignRangePeer keeps the first header honest on purpose, and
// jumblingPeer drops from the middle — so in all of them `matched` is already
// true by the time the reply stops making sense, and the guard is never
// consulted. This peer answers from the wrong range at position zero, which is
// the only way to reach it: the height check ends the window before anything
// matched, so the probe learned nothing at all.
//
// What the guard prevents is the arm below it firing on that. `!matched` alone
// means "the peer's block at `at` is not ours", and the search descends on the
// strength of monotonicity — sound when a header at `at` really was examined,
// and an invention when none was. Without the guard the anchor walks below the
// true fork on evidence that was never gathered, and the pass then adopts and
// reports success: measured on this fixture, a fork 12 deep undone as 16 with
// `deepest_reorg` recording 16, which is the fork-point overshoot reached through a
// probe rather than through a stride.
//
// The assertion is therefore that the pass declines rather than that it heals.
// A probe that decided nothing leaves the search with nothing to narrow on, and
// ending the pass costs one interval — the next one starts from a fresh tip.
// Adopting on a fabricated anchor costs the instrument.
func TestAProbeThatDecidedNothingIsNotTurnedIntoAClaim(t *testing.T) {
	p := devnetEasy()
	const (
		shared      = 40
		ourSuffix   = 12
		theirSuffix = 30
		batch       = 16
	)
	ours, theirs := forkedPair(t, p, shared, ourSuffix, theirSuffix)

	src := &wholeForeignPeer{
		peer:    &peer{t: t, chain: theirs.chain},
		batch:   batch,
		foreign: shared + 1,
	}
	res, err := sync.Run(ours.chain, pow.Dev{}, src, batch)
	if err != nil && !errors.Is(err, sync.ErrDoesNotAttach) {
		t.Fatalf("a probe answered out of the wrong range is not a disagreement about the "+
			"rules; the pass may decline but it must not fail: %v", err)
	}
	if src.replaced == 0 {
		t.Fatal("no narrow reply was ever substituted, so no probe was answered out of the " +
			"wrong range and this test decided nothing")
	}
	if res != nil && res.Adopted {
		t.Errorf("the pass adopted a branch on an anchor no probe established. Every narrow "+
			"reply named heights other than the ones asked for, so no probe examined a "+
			"header at the height it asked about — and `!matched` was then read as "+
			"\"the peer's block there is not ours\" and descended on. It undid %d blocks "+
			"to heal a fork %d deep", len(res.Undone), ourSuffix)
	}
	if got := ours.chain.Stats().DeepestReorg; got != 0 {
		t.Errorf("deepest_reorg recorded %d after a pass in which no probe ever read a "+
			"header at a height it had asked about. That counter sizes undo_depth, and a "+
			"reorg anchored on a probe that established nothing is not a fork depth",
			got)
	}
}
