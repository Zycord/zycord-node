package sync

import (
	"testing"

	"zycord/core/types"
)

// The retention cache's bookkeeping, tested from inside the package.
//
// Internal rather than external because the interesting cases are about the
// caps, and exporting a constructor that takes caps purely so a test can reach
// them would be API surface invented for a test. The bounds are the point: a
// cache on the sync path is memory a peer's behaviour can influence, and
// "bounded" has to be a fact rather than an intention.
//
// This exists because of an argument that was made and not tested — that a
// reorg larger than the cache degrades to the behaviour from before the cache
// existed, rather than to something worse. An untested argument is a
// promissory note.

func blockOfSize(height uint64, filler int) *types.Block {
	b := &types.Block{Header: types.Header{
		Version: types.HeaderVersion,
		Height:  height,
		// Distinct per height, so ids differ and nothing collides by accident.
		Time: 1000 + height,
	}}
	_ = filler
	return b
}

// TestBodyCacheStaysInsideItsCaps is the bound, stated as a fact.
func TestBodyCacheStaysInsideItsCaps(t *testing.T) {
	c := &BodyCache{
		maxBlocks: 4,
		maxBytes:  1 << 20,
		have:      map[types.Hash]*types.Block{},
		size:      map[types.Hash]int{},
	}

	for h := uint64(1); h <= 100; h++ {
		blk := blockOfSize(h, 0)
		c.put(blk.Header.ID(), blk, 100)
	}

	if got := len(c.have); got > 4 {
		t.Fatalf("the cache holds %d blocks against a cap of 4: the bound is an "+
			"intention rather than a fact, and this is memory on a path a peer "+
			"influences", got)
	}
	// The two maps and the counter must agree, or the byte cap is enforced
	// against a number that has drifted away from what is actually held.
	if len(c.size) != len(c.have) {
		t.Fatalf("size bookkeeping holds %d entries and the cache holds %d",
			len(c.size), len(c.have))
	}
	want := 0
	for id := range c.have {
		want += c.size[id]
	}
	if c.bytes != want {
		t.Fatalf("byte counter says %d, the entries sum to %d: after enough "+
			"eviction the cap is enforced against a number that means nothing",
			c.bytes, want)
	}
	if len(c.order) != len(c.have) {
		t.Fatalf("eviction order holds %d ids and the cache holds %d: the two "+
			"have drifted, so eviction will eventually delete nothing",
			len(c.order), len(c.have))
	}
}

// TestBodyCacheEvictsOnBytesNotJustCount: the block cap alone is not a memory
// bound, because block size is not fixed.
func TestBodyCacheEvictsOnBytesNotJustCount(t *testing.T) {
	c := &BodyCache{
		maxBlocks: 1000, // deliberately not the binding constraint
		maxBytes:  500,
		have:      map[types.Hash]*types.Block{},
		size:      map[types.Hash]int{},
	}

	for h := uint64(1); h <= 50; h++ {
		blk := blockOfSize(h, 0)
		c.put(blk.Header.ID(), blk, 100)
	}

	if len(c.have) > 1000 {
		t.Fatal("setup: the block cap became the binding constraint")
	}
	if c.bytes > 500+100 {
		t.Fatalf("the cache holds %d bytes against a cap of 500: a peer serving "+
			"large blocks prices this node's memory through a cap that only "+
			"counts blocks", c.bytes)
	}
}

// TestBodyCacheKeepsOneOversizedEntry pins the degenerate case rather than
// leaving it to be discovered.
//
// A single body larger than the whole byte cap cannot be evicted below one
// entry — the loop stops at `len(c.order) > 1` deliberately, because evicting
// to empty would mean a cache that can never hold the thing it exists to hold.
// So the cache may exceed its byte cap by at most one entry, and must not spin
// forever trying not to.
func TestBodyCacheKeepsOneOversizedEntry(t *testing.T) {
	c := &BodyCache{
		maxBlocks: 10,
		maxBytes:  10,
		have:      map[types.Hash]*types.Block{},
		size:      map[types.Hash]int{},
	}

	huge := blockOfSize(1, 0)
	c.put(huge.Header.ID(), huge, 1_000_000) // one entry, far over the cap

	if len(c.have) != 1 {
		t.Fatalf("an oversized entry left %d entries, want exactly 1", len(c.have))
	}

	// A second put must evict the first rather than accumulate: the excess is
	// bounded at one entry, not at one entry per put.
	second := blockOfSize(2, 0)
	c.put(second.Header.ID(), second, 1_000_000)
	if len(c.have) != 1 {
		t.Fatalf("two oversized entries left %d in the cache: the byte cap is "+
			"exceeded by one entry per put rather than by one entry total, which "+
			"is unbounded growth wearing a bound's clothes", len(c.have))
	}
	if c.bytes < 0 {
		t.Fatalf("the byte counter went negative (%d): eviction is double-counting",
			c.bytes)
	}
}

// TestBodyCacheResetClearsEverything: a reset that leaves the size map behind
// leaks one map entry per body for the life of the process, and the process is
// meant to run for months.
func TestBodyCacheResetClearsEverything(t *testing.T) {
	c := NewBodyCache()
	for h := uint64(1); h <= 20; h++ {
		blk := blockOfSize(h, 0)
		c.put(blk.Header.ID(), blk, 100)
	}
	if c.Len() == 0 {
		t.Fatal("setup: nothing was retained, so clearing it proves nothing")
	}

	c.Reset()

	if c.Len() != 0 || len(c.size) != 0 || len(c.order) != 0 || c.bytes != 0 {
		t.Fatalf("after Reset: %d blocks, %d sizes, %d order entries, %d bytes — "+
			"a partial reset leaks for the life of a process meant to run for months",
			c.Len(), len(c.size), len(c.order), c.bytes)
	}
}

// TestBodyCacheIgnoresDuplicates: a repeated put must not double-count bytes,
// or the byte cap drifts away from the memory actually held.
func TestBodyCacheIgnoresDuplicates(t *testing.T) {
	c := NewBodyCache()
	blk := blockOfSize(1, 0)
	id := blk.Header.ID()

	c.put(id, blk, 100)
	c.put(id, blk, 100)
	c.put(id, blk, 100)

	if c.Len() != 1 {
		t.Fatalf("three puts of one body left %d entries", c.Len())
	}
	if c.bytes != 100 {
		t.Fatalf("byte counter says %d after three puts of one 100-byte body: "+
			"the cap is enforced against a number that grows without the memory",
			c.bytes)
	}
}
