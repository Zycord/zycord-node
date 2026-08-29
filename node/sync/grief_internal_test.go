package sync

import (
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/node/chain"
	"zycord/node/mempool"
	"zycord/node/miner"
	"zycord/node/verify"
	"zycord/spec"
)

// countingChecker records how many header verdicts the extension asks for.
//
// Not how many hashes are computed — the memo already made that linear, and
// TestExtendToCoverHashesEachHeaderOnce measures it. This counts the CALLS,
// which is the number of headers the loop looked at at all, and it is the
// quantity the header-replay grief audit found to be quadratic: the old loop
// handed the whole accumulated candidate back to the validator on every pass,
// so the structural checks (the LWMA derivation, the median-time sort, linkage,
// contiguity) ran again for every header already accepted. A memo hides that in
// the hash count and nowhere else.
type countingChecker struct {
	inner workChecker
	n     int
}

func (c *countingChecker) Check(e pow.Engine, h types.Header, p *params.Params) error {
	c.n++
	return c.inner.Check(e, h, p)
}

// countingSource counts the header requests one extension makes.
type countingSource struct {
	*sliceSource
	requests int
}

func (s *countingSource) Headers(from uint64, count uint32) ([]types.Header, error) {
	s.requests++
	return s.sliceSource.Headers(from, count)
}

// griefFixture is a node holding its own branch and a longer foreign branch to
// grow a candidate along — the shape extendToCover exists for.
type griefFixture struct {
	ours    *chain.Chain
	headers []types.Header
	engine  pow.Engine
}

func newGriefFixture(t *testing.T, foreign, mine int) *griefFixture {
	t.Helper()
	p := spec.Devnet()
	engine := pow.Dev{}

	src, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { src.Close() })
	clock := p.GenesisTime
	m := &miner.Miner{
		Chain: src, Pool: mempool.New(p, mempool.DefaultPolicy()), Engine: engine,
		Payout: [32]byte{0x02, 4, 4, 4},
		Now:    func() uint64 { clock += p.TargetBlockSeconds; return clock },
	}
	var headers []types.Header
	for i := 0; i < foreign; i++ {
		b, _, err := m.MineOne(1 << 20)
		if err != nil {
			t.Fatalf("mining the foreign branch at %d: %v", i, err)
		}
		headers = append(headers, b.Header)
	}

	// Our own branch from the same genesis, carrying work: extendToCover grows a
	// candidate only while it does not yet outweigh what it would replace, so
	// against a node holding only genesis the loop exits on the first comparison
	// and measures nothing.
	ours, err := chain.Open(t.TempDir(), p)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ours.Close() })
	ourClock := p.GenesisTime
	om := &miner.Miner{
		Chain: ours, Pool: mempool.New(p, mempool.DefaultPolicy()), Engine: engine,
		Payout: [32]byte{0x02, 5, 5, 5},
		Now:    func() uint64 { ourClock += p.TargetBlockSeconds; return ourClock },
	}
	for i := 0; i < mine; i++ {
		if _, _, err := om.MineOne(1 << 20); err != nil {
			t.Fatalf("mining our branch at %d: %v", i, err)
		}
	}
	return &griefFixture{ours: ours, headers: headers, engine: engine}
}

// TestExtendToCoverValidatesEachHeaderOnce holds the incremental half of the
// header-replay grief: a peer replaying this node's own header chain from
// genesis pegs a core and gets nothing adopted.
//
// The audit measured the quadratic directly: at height 6,000 one attempt cost
// 16.4 seconds and 373 MiB of allocation churn and adopted zero blocks, and the
// shape came from this loop re-validating every header it had already accepted
// on every pass. This test counts the verdicts instead of the seconds, because a
// count fails the same way on a fast machine and on a slow one.
//
// The bound is exact rather than generous: every header the extension accepts is
// judged once, so the number of calls is the number of headers it added. The old
// shape produced roughly distinct^2/(2*batch) of them.
func TestExtendToCoverValidatesEachHeaderOnce(t *testing.T) {
	f := newGriefFixture(t, 40, 25)
	const batch = 5

	first, err := validateHeadersWith(f.ours, f.engine, f.headers[:batch], nil)
	if err != nil {
		t.Fatalf("seeding the candidate: %v", err)
	}

	memo := &countingChecker{inner: verify.NewWorkCache(64)}
	grown, err := extendToCoverWith(f.ours, f.engine, &sliceSource{headers: f.headers},
		first, batch, memo, maxExtendRounds)
	if err != nil {
		t.Fatalf("extendToCover: %v", err)
	}

	added := len(grown.Headers) - batch
	if added <= batch {
		t.Fatalf("the candidate only grew to %d headers from %d; the loop ran too "+
			"few passes for the quadratic to be observable",
			len(grown.Headers), batch)
	}
	if memo.n != added {
		t.Errorf("extendToCover judged %d headers to add %d of them. Each header must "+
			"be validated exactly once per attempt: re-validating the accumulated "+
			"candidate on every pass is the quadratic measured at 16.4s and "+
			"373 MiB per attempt at height 6,000", memo.n, added)
	}
	t.Logf("grew to %d headers for %d header verdicts", len(grown.Headers), memo.n)
}

// TestOneExtensionCannotBeDrippedPastItsRoundBudget holds maxExtendRounds.
//
// The header cap bounds how much a candidate may grow; it does not bound the
// round trips, because a peer decides how many headers each answer carries. One
// header per reply turns a 2,228-header cap into 2,228 requests, each with its
// own validation pass and its own allocation, for a peer that spends nothing.
func TestOneExtensionCannotBeDrippedPastItsRoundBudget(t *testing.T) {
	f := newGriefFixture(t, 40, 25)
	const batch = 5
	const budget = 2

	first, err := validateHeadersWith(f.ours, f.engine, f.headers[:batch], nil)
	if err != nil {
		t.Fatalf("seeding the candidate: %v", err)
	}

	src := &countingSource{sliceSource: &sliceSource{headers: f.headers}}
	grown, err := extendToCoverWith(f.ours, f.engine, src, first, batch,
		verify.NewWorkCache(64), budget)
	if err != nil {
		t.Fatalf("extendToCover: %v", err)
	}
	if src.requests != budget {
		t.Errorf("the extension made %d header requests under a budget of %d",
			src.requests, budget)
	}
	if want := batch + budget*batch; len(grown.Headers) != want {
		t.Errorf("the extension grew the candidate to %d headers; a budget of %d "+
			"rounds at a batch of %d allows %d", len(grown.Headers), budget, batch, want)
	}
}

// TestTheExtensionCapIsAConstantOfTheParams holds the structural half of the
// same header-replay grief.
//
// The old cap was `(our height - the anchor's height) + undo_depth`, which on a
// mature chain is the chain: a candidate anchored at genesis — which a peer buys
// by replaying this node's own early headers, since they are real — was allowed
// to grow to about the full height. `ConsiderBranch` refuses anything anchored
// below `height - undo_depth` whatever its work, so every header past that
// horizon was validated and then discarded.
//
// Two properties, and the second is the one that keeps the fix safe: the cap
// does not grow with the chain, and it is never below what the old bound allowed
// inside the undo horizon, so nothing that could have been adopted stops being
// adoptable.
func TestTheExtensionCapIsAConstantOfTheParams(t *testing.T) {
	for _, tc := range []struct {
		name string
		p    *params.Params
	}{
		{"mainnet", spec.Mainnet()},
		{"devnet", spec.Devnet()},
		{"testnet", spec.Testnet()},
	} {
		got := extensionCap(tc.p)
		// The deepest reorg ConsiderBranch will ever apply is undo_depth blocks,
		// and the old bound at that anchor was undo_depth + undo_depth.
		if min := 2 * int(tc.p.UndoDepth); got < min {
			t.Errorf("%s: the extension cap is %d, below the %d the old height-derived "+
				"bound reached at the undo horizon; a branch that could have been "+
				"adopted would now stop growing short of winning", tc.name, got, min)
		}
		if want := 2 * (int(tc.p.DifficultyWindow) + int(tc.p.UndoDepth)); got != want {
			t.Errorf("%s: extension cap %d, want %d", tc.name, got, want)
		}
	}
}

// TestAnExtensionAlongOurOwnChainIsRefused is the loop's half of the O(1)
// short-circuit. runOnce refuses the first batch of a replay; this is the door
// the same reply would come back through if it ever reached the extension.
func TestAnExtensionAlongOurOwnChainIsRefused(t *testing.T) {
	f := newGriefFixture(t, 40, 25)
	const batch = 5

	// A candidate over our OWN early headers, which is what a replaying peer
	// hands the victim: real work, real targets, anchored at genesis.
	var mine []types.Header
	for h := uint64(1); h <= uint64(batch); h++ {
		blk, err := f.ours.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		mine = append(mine, blk.Header)
	}
	cand, err := validateHeadersWith(f.ours, f.engine, mine, nil)
	if err != nil {
		t.Fatalf("seeding the replayed candidate: %v", err)
	}

	replay := &countingSource{sliceSource: &sliceSource{headers: ourHeaders(t, f.ours)}}
	grown, err := extendToCoverWith(f.ours, f.engine, replay, cand, batch,
		verify.NewWorkCache(64), maxExtendRounds)
	if err != nil {
		t.Fatalf("extendToCover: %v", err)
	}
	if replay.requests != 1 {
		t.Errorf("the extension spent %d header requests on a peer replaying this "+
			"node's own chain; one is enough to see it", replay.requests)
	}
	if len(grown.Headers) != len(cand.Headers) {
		t.Errorf("the candidate grew to %d headers along this node's own chain",
			len(grown.Headers))
	}
}

// ourHeaders reads a chain's canonical headers, oldest first.
func ourHeaders(t *testing.T, c *chain.Chain) []types.Header {
	t.Helper()
	var out []types.Header
	for h := uint64(1); h <= c.Height(); h++ {
		blk, err := c.BlockAt(h)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, blk.Header)
	}
	return out
}
