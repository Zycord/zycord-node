package ssz_test

import (
	"encoding/binary"
	"testing"

	"zycord/core/crypto"
	"zycord/core/ssz"
)

func chunk(i int) crypto.Hash {
	var h crypto.Hash
	binary.BigEndian.PutUint64(h[:8], uint64(i)*0x9e3779b97f4a7c15)
	binary.BigEndian.PutUint64(h[24:], uint64(i))
	return h
}

// TestTreeMatchesListRoot is Tree's entire contract: it is ListRoot with the
// internal nodes kept.
//
// The property, stated first: for any sequence of calls, Tree.Root(chunks,
// limit) == ListRoot(chunks, limit). The cases that a cache can get wrong and
// a fresh computation cannot are all about *history* — growing, shrinking,
// changing a leaf in place, and changing the limit under the tree, which is
// what nextPow2 does to the state root when the live count crosses a power of
// two. So one tree is reused across every case below.
func TestTreeMatchesListRoot(t *testing.T) {
	tr := ssz.NewTree()
	check := func(chunks []crypto.Hash, limit int, what string) {
		t.Helper()
		got := tr.Root(chunks, limit)
		if want := ssz.ListRoot(chunks, limit); got != want {
			t.Fatalf("%s (n=%d limit=%d): tree %x, ListRoot %x",
				what, len(chunks), limit, got[:8], want[:8])
		}
	}

	// Every length up to 40 against its own nextPow2 limit, growing — so the
	// limit steps under a tree that already holds nodes.
	var chunks []crypto.Hash
	for n := 0; n <= 40; n++ {
		check(chunks, pow2(n), "growing")
		chunks = append(chunks, chunk(n))
	}
	// And shrinking back down through the same limits: the leaves that fall
	// off have to revert to padding, not keep their old values.
	for n := len(chunks); n >= 0; n-- {
		check(chunks[:n], pow2(n), "shrinking")
	}
	// A leaf changed in place, at every position, with the limit fixed.
	chunks = chunks[:32]
	for i := range chunks {
		chunks[i] = chunk(1000 + i)
		check(chunks, 32, "in place")
	}
	// A slack limit: the list is far shorter than its capacity, which is the
	// shape every other root in the protocol uses.
	check(chunks[:5], 1024, "slack limit")
	check(chunks[:5], 1024, "slack limit repeated")
	check(chunks[:31], 1024, "slack limit grown")

	// A tree that has never been asked anything must agree too.
	if got, want := ssz.NewTree().Root(nil, 1), ssz.ListRoot(nil, 1); got != want {
		t.Fatalf("empty: tree %x, ListRoot %x", got[:8], want[:8])
	}
}

// TestTreeCloneDoesNotShareNodes: a clone answers for its own chunks and using
// it does not move the original's answer.
//
// This is a value-level check and it cannot detect a missing copy: `Tree` is
// self-healing, so `Clone` reduced to `return t` leaves this test — and
// ./core/state — passing. Kept because the two roots it pins are worth pinning;
// the property the copy actually exists for is memory safety, and that is
// asserted by address and under -race in tree_internal_test.go.
func TestTreeCloneDoesNotShareNodes(t *testing.T) {
	chunks := make([]crypto.Hash, 16)
	for i := range chunks {
		chunks[i] = chunk(i)
	}
	a := ssz.NewTree()
	want := a.Root(chunks, 16)
	b := a.Clone()

	other := append([]crypto.Hash(nil), chunks...)
	other[3] = chunk(999)
	if b.Root(other, 16) == want {
		t.Fatal("the clone returned the original's root for different chunks")
	}
	if got := a.Root(chunks, 16); got != want {
		t.Fatalf("the original moved to %x after the clone was used; want %x", got[:8], want[:8])
	}
}

func pow2(n int) int {
	p := 1
	for p < n {
		p <<= 1
	}
	return p
}
