package chain_test

import (
	"testing"
)

// TestAHeaderRangeReservesTheChainsRangeNotTheRequestedCount pins the sizing
// half of the get-headers amplifier: the answer buffer a header-range read
// allocates is bounded by the heights this chain actually has, not by the
// number the caller named.
//
// This is a separate property from "it reads headers, not bodies" (pinned in
// node/p2p) and it survives that fix. node/p2p clamps a get-headers Count to
// MaxHeadersPerResponse and passes it straight through, so a peer 12 bytes
// from a freshly started node could still make it reserve MaxHeadersPerResponse
// x types.HeaderSize of buffer per frame off a three-block chain. Bounded, but
// still an asymmetry the sender does not pay for, and the available range is
// known at the read for free.
//
// The scenario deliberately spans both directions, because a clamp written the
// wrong way round would satisfy only one: when the chain is shorter than the
// request the capacity must follow the chain, and when the request is shorter
// than the chain the capacity must follow the request. A test that only asked
// the first would pass against `count = int(avail)` unconditionally, which
// reserves 512 headers for a 4-header request on a long chain.
func TestAHeaderRangeReservesTheChainsRangeNotTheRequestedCount(t *testing.T) {
	p := devnetEasy()
	n := openNode(t, t.TempDir(), p, key(t, 1).Persistent())
	defer n.close(t)

	n.mine(t, 3) // heights 0..3 exist: genesis plus three

	if got := n.chain.Height(); got != 3 {
		t.Fatalf("fixture height %d, want 3", got)
	}

	// Chain shorter than the request: capacity follows the chain.
	const oversized = 512 // p2p's MaxHeadersPerResponse, the clamped ceiling
	short := n.chain.CanonicalHeadersFrom(0, oversized)
	if len(short) != 4 {
		t.Fatalf("served %d headers for heights 0..3, want 4", len(short))
	}
	if cap(short) != 4 {
		t.Fatalf("a %d-header request against a 4-header chain reserved capacity %d; "+
			"the buffer is sized from the count the peer asked for, not the range that exists",
			oversized, cap(short))
	}

	// Request shorter than the chain: capacity follows the request. Without
	// this half, sizing unconditionally from the available range would pass
	// the assertion above and reserve the whole chain for every small read.
	n.mine(t, 500)
	small := n.chain.CanonicalHeadersFrom(10, 4)
	if len(small) != 4 {
		t.Fatalf("served %d headers for a 4-header request on a %d-high chain, want 4",
			len(small), n.chain.Height())
	}
	if cap(small) != 4 {
		t.Fatalf("a 4-header request against a %d-high chain reserved capacity %d; "+
			"the buffer is sized from the chain, not from what was asked for",
			n.chain.Height(), cap(small))
	}

	// The stopping rules the p2p loop this replaced had: a request that starts
	// past the tip answers empty rather than erroring, and a non-positive
	// count answers empty rather than panicking on make().
	if got := n.chain.CanonicalHeadersFrom(n.chain.Height()+1, 8); len(got) != 0 {
		t.Fatalf("a request starting past the tip served %d headers", len(got))
	}
	// The tip itself is inside the range, not past it. The loop this replaced
	// served height == tip, and a peer that asks from the last height it has
	// learns nothing new if the answer is empty — an off-by-one in the guard
	// above turns that into a silent stall, and every other assertion here
	// passes with it.
	if got := n.chain.CanonicalHeadersFrom(n.chain.Height(), 8); len(got) != 1 {
		t.Fatalf("a request starting exactly at the tip served %d headers, want 1", len(got))
	}
	if got := n.chain.CanonicalHeadersFrom(0, 0); len(got) != 0 {
		t.Fatalf("a zero-count request served %d headers", len(got))
	}
	if got := n.chain.CanonicalHeadersFrom(0, -1); len(got) != 0 {
		t.Fatalf("a negative-count request served %d headers", len(got))
	}
}
