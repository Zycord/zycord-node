package sync_test

import (
	gosync "sync"
	"testing"
	"time"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/sync"
)

// countingEngine records every proof-of-work evaluation the sync path asks for.
//
// The unit that matters: under RandomX one of these is memory-hard and runs in
// milliseconds, so a count is a wall-clock statement that does not depend on the
// machine the test runs on.
type countingEngine struct {
	mu gosync.Mutex
	n  int
}

func (c *countingEngine) Name() string { return pow.Dev{}.Name() }

func (c *countingEngine) Hash(key types.Hash, in []byte) types.Hash {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return pow.Dev{}.Hash(key, in)
}

func (c *countingEngine) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// replayPeer is the header-replay griefer, and everything it does is free.
//
// It advertises the maximum possible work and an enormous height — a Hello's
// claim is read unverified, so both cost nothing — and then answers the victim's
// request with the VICTIM'S OWN headers, starting at height 1 whatever height
// was asked for. Those headers validate: correct linkage, real proof of work,
// targets the LWMA rule produces, because the victim mined them itself. The
// candidate anchors at genesis and weighs exactly what it would replace, so the
// extension loop's work test can never be satisfied, and before this was fixed
// the victim walked its own chain to the top re-validating everything it had
// accepted on every pass. The audit measured 16.4 seconds and 373 MiB per
// attempt at height 6,000, scaling quadratically, adopting zero blocks.
type replayPeer struct {
	victim   *chain.Chain
	requests int
	anchored bool
}

func (p *replayPeer) Tip() (uint64, u256.U256) { return 1 << 30, u256.Max }

func (p *replayPeer) Headers(from uint64, count uint32) ([]types.Header, error) {
	p.requests++
	at := from
	if !p.anchored {
		// The one lie, and it is not even a lie about a header: the first answer
		// simply describes a lower range than the one requested. That is what
		// anchors the candidate at genesis.
		at, p.anchored = 1, true
	}
	var out []types.Header
	for h := at; h <= p.victim.Height() && len(out) < int(count); h++ {
		blk, err := p.victim.BlockAt(h)
		if err != nil {
			return nil, err
		}
		out = append(out, blk.Header)
	}
	return out, nil
}

func (p *replayPeer) Body(id types.Hash) (*types.Block, error) {
	return p.victim.Block(id)
}

// TestAPeerReplayingOurOwnChainCostsOneRequestAndNoWork.
//
// The assertions are costs, not verdicts, and that is the point: the old code
// reached the same verdict — nothing adopted, no error, no peer scored — while
// burning a core to get there, so every diagnostic reported a healthy node.
// Only a measurement can tell the fix from the defect.
//
// One header request and zero work evaluations. Before the short-circuit the
// same attempt spent a request per batch all the way to `height + undo_depth`
// and validated every header of the victim's own chain along the way, over and
// over.
func TestAPeerReplayingOurOwnChainCostsOneRequestAndNoWork(t *testing.T) {
	p := devnetEasy()
	victim := newNode(t, p, key(t, 1).Persistent())
	const height = 240
	victim.mine(t, height)

	engine := &countingEngine{}
	attacker := &replayPeer{victim: victim.chain}

	before := victim.chain.Height()
	start := time.Now()
	res, err := sync.Run(victim.chain, engine, attacker, 128)
	elapsed := time.Since(start)
	if err != nil {
		t.Fatalf("a peer replaying our own chain should be a no-op, not an error: %v", err)
	}
	if res.Adopted {
		t.Fatal("adopted something from a peer serving this node's own blocks back to it")
	}
	if got := victim.chain.Height(); got != before {
		t.Fatalf("the chain moved from %d to %d", before, got)
	}
	if attacker.requests != 1 {
		t.Errorf("the attempt spent %d header requests on a replay of this node's own "+
			"chain; one is enough to see it. The walk used to run to "+
			"height+undo_depth, re-validating everything accepted so far on every "+
			"pass", attacker.requests)
	}
	if n := engine.count(); n != 0 {
		t.Errorf("the attempt spent %d proof-of-work evaluations on headers this node "+
			"mined itself. At RandomX's ~55ms each that is %s of CPU bought with a "+
			"free identity and no hashes", n, time.Duration(n)*55*time.Millisecond)
	}
	t.Logf("replay attempt at height %d: %d header requests, %d work evaluations, %s",
		height, attacker.requests, engine.count(), elapsed.Round(time.Millisecond))
}

// TestABranchCoveringHeightsWeHoldIsStillAdopted guards the short-circuit
// against the obvious way to break it.
//
// The refusal keys on the block IDENTITY of a reply's first header, never on its
// height. A reorg reply necessarily describes heights this node already holds —
// that is what a reorg is — and every header in it is a different block from
// ours. Keyed on height instead ("this range is below my tip, refuse it"), or
// widened to "this reply contains a height I hold", every reorg in the package
// stops happening and the minority-branch-rejoin defect comes straight back.
func TestABranchCoveringHeightsWeHoldIsStillAdopted(t *testing.T) {
	p := devnetEasy()
	ours := newNode(t, p, key(t, 1).Persistent())
	ours.mine(t, 3)

	// A heavier branch from the same genesis, holding a different block at every
	// height this node holds one at.
	theirs := newNode(t, p, key(t, 2).Persistent())
	theirs.mine(t, 8)

	res, err := sync.Run(ours.chain, pow.Dev{}, &peer{t: t, chain: theirs.chain}, 128)
	if err != nil {
		t.Fatalf("sync: %v", err)
	}
	if !res.Adopted {
		t.Fatal("adopted nothing from a heavier branch that happens to cover heights we hold")
	}
	if got, want := ours.chain.Height(), theirs.chain.Height(); got != want {
		t.Fatalf("synced to height %d, the peer is at %d", got, want)
	}
}
