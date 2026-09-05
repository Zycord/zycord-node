package ssz

import (
	"encoding/binary"
	"sync"
	"testing"

	"zycord/core/crypto"
)

func internalChunk(i int) crypto.Hash {
	var h crypto.Hash
	binary.BigEndian.PutUint64(h[:8], uint64(i)*0x9e3779b97f4a7c15)
	binary.BigEndian.PutUint64(h[24:], uint64(i))
	return h
}

// TestTreeCloneCopiesEveryLayer: Clone must produce a tree that shares no
// memory with the one it came from.
//
// The black-box test next door, TestTreeCloneDoesNotShareNodes, was written to
// assert this and could not: replacing the whole body of Clone with `return t`
// — no copy whatsoever — left it passing, and left ./core/state passing too.
// The reason is a real and load-bearing property of Tree rather than a mistake
// in the test. Root diffs the chunk slice it is handed against its stored leaf
// layer and rewrites whatever disagrees, and it leaves the layers internally
// consistent every time, so the answer is a pure function of (chunks, limit).
// A tree shared between two states therefore still returns the correct root for
// both; sharing costs recomputation and never correctness. No assertion about
// root *values* can see the difference.
//
// What the copy actually buys is memory safety. Chain.Snapshot hands a cloned
// state to another goroutine — a miner assembling a block, a mempool
// re-screening — and that goroutine calls Root, which writes the layer arrays
// in place. If those arrays are the live chain's, the write lands in memory the
// chain owns. So the property to assert is the one that cannot be inferred from
// output: distinct backing arrays, checked by address, plus a -race witness
// that two goroutines rooting a tree and its clone do not collide.
func TestTreeCloneCopiesEveryLayer(t *testing.T) {
	chunks := make([]crypto.Hash, 40)
	for i := range chunks {
		chunks[i] = internalChunk(i)
	}
	orig := NewTree()
	orig.Root(chunks, 64)
	if len(orig.layers) < 2 {
		t.Fatal("the tree has no layers; the test would assert nothing")
	}

	clone := orig.Clone()
	if clone == orig {
		t.Fatal("Clone returned the original tree itself")
	}
	if len(clone.layers) != len(orig.layers) {
		t.Fatalf("clone has %d layers, original has %d", len(clone.layers), len(orig.layers))
	}
	if clone.depth != orig.depth {
		t.Fatalf("clone depth %d, original %d", clone.depth, orig.depth)
	}
	if &clone.layers[0] == &orig.layers[0] {
		t.Fatal("Clone shares the outer layers slice")
	}
	for d := range orig.layers {
		if len(clone.layers[d]) != len(orig.layers[d]) {
			t.Fatalf("layer %d: clone holds %d nodes, original %d",
				d, len(clone.layers[d]), len(orig.layers[d]))
		}
		if len(orig.layers[d]) == 0 {
			continue
		}
		if &clone.layers[d][0] == &orig.layers[d][0] {
			t.Fatalf("layer %d shares its backing array with the original", d)
		}
		for j := range orig.layers[d] {
			if clone.layers[d][j] != orig.layers[d][j] {
				t.Fatalf("layer %d node %d was not copied", d, j)
			}
		}
	}

	// The direct demonstration of the hazard: write through the clone and the
	// original's stored nodes must not move. Root is what writes, so drive it.
	before := make([][]crypto.Hash, len(orig.layers))
	for d, l := range orig.layers {
		before[d] = append([]crypto.Hash(nil), l...)
	}
	other := append([]crypto.Hash(nil), chunks...)
	other[7] = internalChunk(9999)
	clone.Root(other, 64)
	for d := range orig.layers {
		for j := range orig.layers[d] {
			if orig.layers[d][j] != before[d][j] {
				t.Fatalf("using the clone rewrote the original's layer %d node %d", d, j)
			}
		}
	}
}

// TestTreeCloneIsSafeForAnotherGoroutine is the same property as a -race
// witness, in the shape Chain.Snapshot actually produces: one goroutine keeps
// rooting the live tree while another roots the clone it was handed.
//
// Against a Clone that returns the original — or that copies the outer slice
// and shares the layers — this reports a data race on the layer arrays. It is
// the assertion that ties the copy to the reason for the copy.
func TestTreeCloneIsSafeForAnotherGoroutine(t *testing.T) {
	chunks := make([]crypto.Hash, 40)
	for i := range chunks {
		chunks[i] = internalChunk(i)
	}
	live := NewTree()
	live.Root(chunks, 64)
	snapshot := live.Clone()

	mine := append([]crypto.Hash(nil), chunks...)
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			chunks[i%len(chunks)] = internalChunk(i)
			live.Root(chunks, 64)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < 200; i++ {
			mine[i%len(mine)] = internalChunk(5000 + i)
			snapshot.Root(mine, 64)
		}
	}()
	wg.Wait()

	// And the snapshot still answers for its own chunks, unaffected by the
	// live tree having moved underneath it.
	if got, wantSnap := snapshot.Root(mine, 64), ListRoot(mine, 64); got != wantSnap {
		t.Fatalf("snapshot roots to %x, ListRoot says %x", got[:8], wantSnap[:8])
	}
}
