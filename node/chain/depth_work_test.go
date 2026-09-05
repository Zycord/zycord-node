package chain

// White-box regression test for the body-decoding header reads: depthOf and
// workSince used to decode a full block body at every height they walked, under
// the chain's exclusive lock, to read a two-field header sitting right beside
// it in storage. This file is package chain (internal) rather than chain_test,
// because it needs to call depthOf and workSince directly — they are
// unexported, and this is the one thing the black-box ConsiderBranch tests in
// forkchoice_test.go cannot isolate: switchTo's own unwind loop genuinely needs
// the bodies of whatever it unwinds, to return them for mempool re-admission,
// so a black-box test that deletes the same bodies depthOf/workSince walk past
// would fail for an unrelated reason before ever reaching them. Calling the two
// functions directly, before switchTo runs at all, is what isolates the
// property this issue is actually about.
//
// It cannot import node/miner or the chain_test package's helpers (node/miner
// imports node/chain, and chain_test is a different package), so blocks are
// built here directly — the same handful of fields buildBranch and the miner
// both set, with core/pow.NextTarget providing a real target rather than a
// declared one.

import (
	"testing"

	"zycord/core/params"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/node/storage"
	"zycord/spec"
	"zycord/wallet"
)

func devnetEasyForTest() *params.Params {
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

func testPayoutAddress(t *testing.T, b byte) types.Address {
	t.Helper()
	seed := make([]byte, 32)
	for i := range seed {
		seed[i] = b
	}
	k, err := wallet.KeyFromSeed(seed)
	if err != nil {
		t.Fatal(err)
	}
	return k.Persistent()
}

// mineEmptyBlocksForTest extends c by n empty blocks with a real,
// rule-derived target and time, mirroring node/miner.Miner.Assemble closely
// enough for a test that never needs a mempool.
func mineEmptyBlocksForTest(t *testing.T, c *Chain, p *params.Params, payout types.Address, n int, clock *uint64) {
	t.Helper()
	for i := 0; i < n; i++ {
		tip := c.Tip()
		*clock += p.TargetBlockSeconds
		when := *clock
		if floor := pow.MedianTime(c.RecentHeaders(p.MedianTimeBlocks), p); when <= floor {
			when = floor + 1
		}
		b := &types.Block{Header: types.Header{
			Version:      types.HeaderVersion,
			Height:       tip.Height + 1,
			ParentID:     tip.ID(),
			Time:         when,
			EmissionAddr: payout,
			Target:       pow.NextTarget(c.RecentHeaders(int(p.DifficultyWindow)+1), p),
		}}
		b.Header.CertRoot = b.ComputeCertRoot(p)
		b.Header.CitesRoot = b.ComputeCitesRoot(p)
		if _, err := c.Apply(b); err != nil {
			t.Fatalf("applying block %d: %v", i, err)
		}
	}
}

// TestDepthOfAndWorkSinceNeedNoBlockBody is the regression pin for those reads:
// both functions must answer using headers alone. This deletes the body of
// every block between an ancestor and the tip and confirms depthOf and
// workSince still answer correctly — possible only if neither ever needed a
// body, since a body that was decoded would fail outright once deleted.
func TestDepthOfAndWorkSinceNeedNoBlockBody(t *testing.T) {
	p := devnetEasyForTest()
	payout := testPayoutAddress(t, 1)
	dir := t.TempDir()

	c, err := Open(dir, p)
	if err != nil {
		t.Fatal(err)
	}
	clock := p.GenesisTime
	mineEmptyBlocksForTest(t, c, p, payout, 4, &clock)

	ancestorHdr, err := c.Header(mustBlockIDAt(t, c, 1))
	if err != nil {
		t.Fatal(err)
	}
	ancestorID := ancestorHdr.ID()

	// Capture what depth and work *should* be before the bodies that would
	// otherwise answer the question are gone.
	wantWork := u256.Zero
	var deletedIDs []types.Hash
	for h := uint64(2); h <= 4; h++ {
		hdr, err := c.headerLocked(mustBlockIDAt(t, c, h))
		if err != nil {
			t.Fatal(err)
		}
		wantWork = wantWork.SatAdd(BlockWork(hdr.Target))
		deletedIDs = append(deletedIDs, hdr.ID())
	}
	if err := c.Close(); err != nil {
		t.Fatal(err)
	}

	s, err := storage.Open(dir, storage.Options{})
	if err != nil {
		t.Fatal(err)
	}
	batch := &storage.Batch{}
	for _, id := range deletedIDs {
		batch.Delete(hashKey(prefixBlock, id))
	}
	if err := s.Commit(batch); err != nil {
		t.Fatal(err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}

	c, err = Open(dir, p)
	if err != nil {
		t.Fatalf("reopening after deleting bodies failed: %v", err)
	}
	defer c.Close()

	c.mu.Lock()
	defer c.mu.Unlock()

	// Setup check: the bodies really are gone, so a function that tried to
	// decode one would fail rather than silently succeed.
	for _, id := range deletedIDs {
		if _, err := c.blockLocked(id); err == nil {
			t.Fatalf("setup: block %x still has a body; the deletion did not take", id[:8])
		}
	}

	depth, err := c.depthOf(ancestorID)
	if err != nil {
		t.Fatalf("depthOf failed with bodies deleted: %v", err)
	}
	if depth != 3 {
		t.Fatalf("depth is %d, want 3", depth)
	}

	work, err := c.workSince(ancestorID)
	if err != nil {
		t.Fatalf("workSince failed with bodies deleted: %v", err)
	}
	if !work.Eq(wantWork) {
		t.Fatalf("workSince = %s, want %s", work.String(), wantWork.String())
	}
}

func mustBlockIDAt(t *testing.T, c *Chain, h uint64) types.Hash {
	t.Helper()
	id, ok := c.CanonicalIDAt(h)
	if !ok {
		t.Fatalf("no canonical block at height %d", h)
	}
	return id
}
