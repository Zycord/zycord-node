package p2p

import (
	"sync"
	"testing"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/spec"
)

// countingPoW records how often the work function is actually evaluated.
//
// Without it, wiring a cache in and watching the suite stay green proves
// nothing: a cache that never hits and a cache that always hits are
// indistinguishable from the outside, because neither changes a verdict.
type countingPoW struct {
	mu sync.Mutex
	n  int
}

func (c *countingPoW) Name() string { return pow.Dev{}.Name() }
func (c *countingPoW) Hash(key types.Hash, in []byte) types.Hash {
	c.mu.Lock()
	c.n++
	c.mu.Unlock()
	return pow.Dev{}.Hash(key, in)
}
func (c *countingPoW) count() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.n
}

// TestHashFirstRelayVerifiesAHeaderOnce pins the saving the cache exists for,
// and drives it through the ENGINE'S OWN ENTRY POINTS rather than through the
// cache.
//
// That distinction is the test. A first version called e.work.Check directly
// and claimed in its comment to be doing this; mutation-checking exposed the
// lie — routing the announcement path back around the cache left it green,
// because the test never went near that path. It now sends a real announcement
// and a real block, so a refactor that stops routing either one through the
// cache fails here.
//
// Hash-first relay checks an announcement's header before fetching any body
// (R1-M3) and checks the same header again when the block arrives. Both checks
// are required — different messages, possibly different peers — but the second
// EVALUATION is waste, and against RandomX it is about 55 ms per relayed block
// on every node, forever.
func TestHashFirstRelayVerifiesAHeaderOnce(t *testing.T) {
	p := spec.Devnet()
	c, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	peers, err := NewPeerStore("")
	if err != nil {
		t.Fatal(err)
	}
	pool := mempool.New(p, mempool.DefaultPolicy())

	work := &countingPoW{}
	e := NewEngine(c, pool, peers, work, "n:1")

	// A real block on this chain's tip, sealed against the rule the engine
	// will judge it by.
	m := &miner.Miner{
		Chain: c, Pool: pool, Engine: work,
		Payout: [32]byte{0x02, 9, 9, 9},
		Now:    func() uint64 { return c.Tip().Time + p.TargetBlockSeconds },
	}
	blk, err := m.Assemble()
	if err != nil {
		t.Fatal(err)
	}
	if err := m.Seal(blk, 1<<20); err != nil {
		t.Fatal(err)
	}

	const peer = "10.9.0.1:44444"

	// The announcement. Its header must be verified: that is what makes a
	// ghost announcement cost the announcer real work.
	before := work.count()
	ann := BlockAnnounce{Header: blk.Header, CertExemplars: blk.CertExemplars()}
	if v := e.OnBlockAnnounce(peer, ann.MarshalAnnounce()); v.Err != nil {
		t.Fatalf("announcement refused: %v", v.Err)
	}
	if got := work.count() - before; got != 1 {
		t.Fatalf("the announcement cost %d work evaluations, want exactly 1; "+
			"0 means the work check was skipped, which is R1-M3", got)
	}

	// The body for that same announcement. Every check it makes is still made;
	// the one thing it must not do is hash the header again.
	mid := work.count()
	if v := e.OnBlock(peer, blk.MarshalSSZ()); v.Err != nil {
		t.Fatalf("block refused: %v", v.Err)
	}
	if got := work.count() - mid; got != 0 {
		t.Fatalf("the body cost %d further work evaluations; hash-first relay "+
			"still pays for every block twice", got)
	}

	// Anti-vacuity: a header the engine has not seen must still cost a full
	// evaluation, or the counter is measuring nothing.
	other := blk.Header
	other.Time++
	mid = work.count()
	_ = e.work.Check(e.Engine, other, p)
	if got := work.count() - mid; got == 0 {
		t.Fatal("a distinct header was answered from the cache; the key does " +
			"not distinguish headers")
	}
}
