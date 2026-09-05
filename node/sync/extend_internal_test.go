package sync

import (
	"sync"
	"testing"

	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/spec"
)

// countingPoW records how often the work function is evaluated. Without it this
// file measures nothing: the memo changes no verdict, only how many times the
// same verdict is computed.
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

// sliceSource serves headers from a fixed slice, one batch at a time.
type sliceSource struct{ headers []types.Header }

func (s *sliceSource) Headers(from uint64, count uint32) ([]types.Header, error) {
	var out []types.Header
	for _, h := range s.headers {
		if h.Height >= from && uint32(len(out)) < count {
			out = append(out, h)
		}
	}
	return out, nil
}
func (s *sliceSource) Tip() (uint64, u256.U256) {
	if len(s.headers) == 0 {
		return 0, u256.Zero
	}
	last := s.headers[len(s.headers)-1]
	return last.Height, chain.BlockWork(last.Target)
}

// TestExtendToCoverHashesEachHeaderOnce is I5-L12 re-measured under the cost
// that made it matter.
//
// extendToCover re-validates every header it has so far on every pass, so the
// STRUCTURAL checks are quadratic in the gap. I5-L12 measured 4.4x linear at
// the shipping batch size and chose to keep it — `need` is bounded by
// undo_depth, and splitting the difficulty loop is the most load-bearing check
// in the package. That trade was made against pow.Dev, one BLAKE3 pass, and
// the trade was recorded as one that FLIPS when RandomX lands:
// the same ratio is 4,638 memory-hard evaluations where 1,054 would do, spent
// exactly when a node is furthest behind.
//
// The memo flips it back without touching the difficulty loop. This test is
// what says so with a count rather than a claim, and it is the measurement a
// successor was asked to re-take rather than trust.
func TestExtendToCoverHashesEachHeaderOnce(t *testing.T) {
	p := spec.Devnet()
	work := &countingPoW{}

	// A source chain, mined honestly, that a candidate will be grown along.
	src, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	clock := p.GenesisTime
	m := &miner.Miner{
		Chain: src, Pool: mempool.New(p, mempool.DefaultPolicy()), Engine: work,
		Payout: [32]byte{0x02, 4, 4, 4},
		Now:    func() uint64 { clock += p.TargetBlockSeconds; return clock },
	}
	const chainLen = 40
	var headers []types.Header
	for i := 0; i < chainLen; i++ {
		b, _, err := m.MineOne(1 << 20)
		if err != nil {
			t.Fatalf("mining %d: %v", i, err)
		}
		headers = append(headers, b.Header)
	}

	// Our own branch from the same genesis. It has to exist and it has to carry
	// work: extendToCover grows a candidate only while it does not yet outweigh
	// what it would replace, so against a node holding only genesis the loop
	// exits on the first comparison and measures nothing. That is how the first
	// version of this test was written, and it reported "grew to 5 headers from
	// 5" rather than passing vacuously — which is the anti-vacuity guard below
	// doing its job.
	ours, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	defer ours.Close()
	ourClock := p.GenesisTime
	om := &miner.Miner{
		Chain: ours, Pool: mempool.New(p, mempool.DefaultPolicy()), Engine: work,
		Payout: [32]byte{0x02, 5, 5, 5},
		Now:    func() uint64 { ourClock += p.TargetBlockSeconds; return ourClock },
	}
	const oursLen = 25
	for i := 0; i < oursLen; i++ {
		if _, _, err := om.MineOne(1 << 20); err != nil {
			t.Fatalf("mining our branch %d: %v", i, err)
		}
	}

	// A candidate holding the first batch, as Run would have produced.
	const batch = 5
	first, err := validateHeadersWith(ours, work, headers[:batch], nil)
	if err != nil {
		t.Fatalf("seeding the candidate: %v", err)
	}

	before := work.count()
	grown, err := extendToCover(ours, work, &sliceSource{headers: headers}, first, batch)
	if err != nil {
		t.Fatalf("extendToCover: %v", err)
	}
	evals := work.count() - before

	distinct := len(grown.Headers) - batch // the ones extendToCover itself saw
	if distinct <= batch {
		t.Fatalf("the candidate only grew to %d headers from %d; the loop ran too "+
			"few passes for the quadratic to be observable",
			len(grown.Headers), batch)
	}

	// Linear, with slack for the batch boundaries. The quadratic shape would be
	// about distinct^2/(2*batch) evaluations, which at these numbers is several
	// times this bound.
	if max := 2 * len(grown.Headers); evals > max {
		t.Errorf("extendToCover cost %d work evaluations to grow a candidate to "+
			"%d headers (bound %d). The memo is not being consulted, and at "+
			"RandomX's ~55 ms per evaluation this is the difference between "+
			"seconds and minutes per sync attempt",
			evals, len(grown.Headers), max)
	}
	t.Logf("grew to %d headers over %d passes for %d work evaluations",
		len(grown.Headers), (distinct+batch-1)/batch, evals)
}
