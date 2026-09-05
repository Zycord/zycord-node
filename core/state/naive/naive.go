// Package naive is the epoch state root computed a second time, written from
// the specification rather than from the code that ships it.
//
// # Why a second implementation exists at all
//
// The third external audit measured that of the 59 golden vectors, the 9 that
// carry a non-zero Header.StateRoot all have an empty spent registry, so every
// state root any conformance artefact commits to is taken over ListRoot([], 1)
// — a constant. Nothing committed anywhere exercises the spent leaf tag,
// the registry's sort order, the spent subtree's padding, or its dynamic
// capacity rule.
//
// The checks that looked like differentials were not. sim/refold and
// core/state/root_identity_test.go both import zycord/core/ssz and call
// ssz.ListRoot, so the tag, the tree, zeroHashes, MixInLength and nextPow2 are
// the *same code object* on both sides: one implementation agreeing with
// itself. A second implementation that gets the spent-leaf tag, the comparator
// or the capacity rule wrong passed 100% of spec/vectors when this package was
// written, and then diverged at F14 the first time an epoch boundary landed
// with any address ever burned — a consensus fork, on the first day of real
// traffic, since mainnet epochs are 2,880 blocks and registry entries are never
// pruned (R1-C3-iii).
//
// The corpus half of that finding has since landed and the past tense above
// is exact: spec/vectors/059-epoch-boundary-over-a-spent-registry commits a
// state root over a two-entry registry, so the tag, the comparator and the
// capacity are each separated by a committed artefact and a wrong one no
// longer replays green. A second vector,
// 063-coinbase-burned-into-a-payee-spent-in-the-same- block, commits over a
// ONE-entry registry, which separates the tag and the capacity a second time
// and the comparator not at all.
//
// That does not retire this package. Both registries are exactly filled — one
// entry at capacity 1, two at capacity 2 — so the padding of a partially filled
// subtree and every capacity above two are still held here and nowhere else,
// and this is still the only merkleisation in the tree that does not import
// zycord/core/ssz.
//
// # The boundary, and it is the point of the package
//
// This package MUST NOT reach zycord/core/ssz by any path. It therefore holds
// its own tree, its own padding, its own capacity rule and its own copies of
// the four domain tags as string literals — a tag referenced through
// core/crypto's constant would move with the constant and could not catch a
// change to it. `make check-imports` enforces the boundary against the
// toolchain's own dependency graph rather than against a reading of the
// imports; see the stanza that names this package.
//
// The primitives it does still share are named here rather than left to be
// discovered: BLAKE3 itself (core/crypto/blake3), and nothing else. A defect
// inside BLAKE3 is invisible to any differential built on this package.
//
// # The definition, from docs/ARCHITECTURE.md §14, fold rule F14
//
// Two independent SSZ list-roots, not one merged tree, each over its leaves
// sorted by slot (cell addr‖word) or by address, with capacity = nextPow2 of
// the leaf count:
//
//	cell_root  ← ListRoot({blake3("zcd/stateleaf/v1"‖addr‖word‖value) : live cells},
//	                      nextPow2(#live cells))
//	spent_root ← ListRoot({blake3("zcd/spentleaf/v1"‖addr) : spent-registry entries},
//	                      nextPow2(#spent entries))
//	state_root ← blake3("zcd/stateroot/v1" ‖ cell_root ‖ spent_root)
//
// The capacity is DYNAMIC, unlike every other merkleised list in the protocol:
// an implementation that gives either subtree a fixed capacity computes a
// different root the moment the live count crosses a power of two. The seen set
// is excluded by rule.
//
// Three things the prose above does not fix, and where each was resolved — this
// list is the honest account of what "independent" does not cover:
//
//  1. The internal node function. core/crypto documents TagSSZNode,
//     "zcd/node/v1", as "the internal node tag of every merkle tree in the
//     protocol"; the tagged form blake3(tag ‖ left ‖ right) then follows from
//     crypto.Sum's own contract, blake3(tag ‖ payload). Taken from core/crypto,
//     not from core/ssz.
//  2. What "SSZ list-root" mixes in. SSZ fixes the shape —
//     mix_in_length(merkleize(chunks, limit), len) — but not that this protocol
//     spells mix_in_length with the same tagged node function rather than a tag
//     of its own, nor that the length occupies the low eight bytes of a 32-byte
//     chunk little-endian. Both were read off core/ssz/ssz.go's MixInLength.
//     This is the one place this package is not independent of the code it
//     checks. A differential built on it still catches a *change* to the shipped
//     mix-in, since only one side moves; what it cannot do is say that either
//     side matches SSZ, because one was copied from the other.
//  3. The capacity of an empty list. capacityFor returns 1, which was this
//     package's own choice while nextPow2(0) was unstated — unobservable either
//     way, because a tree of one zero chunk and a tree of zero chunks both root
//     at the zero hash. It is no longer a choice: spec/README.md's "How a list
//     is rooted" fixes nextPow2(0) = 1 normatively, and core/ssz's
//     TestTheDocumentFixesTheListRootSpellingByValue reads that value back out
//     of the document and holds an empty state's root to it.
//
// # Deliberately naive
//
// The tree is materialised in full, padding chunks included, and reduced one
// layer at a time. There is no zero-subtree table and no incremental cache,
// because the cost of the shipped implementation's cleverness is exactly what a
// differential is for. It is Θ(capacity) in memory and is not meant to be used
// on state larger than a test builds.
package naive

import (
	"bytes"
	"encoding/binary"
	"sort"

	"zycord/core/crypto/blake3"
)

// The four domain tags, as literals. They are duplicated from core/crypto on
// purpose: a tag read through the shipped constant moves when the constant
// moves, and a differential that shares the constant cannot see a change to it
// — which is precisely the hole the audit named for "zcd/spentleaf/v1".
const (
	cellLeafTag  = "zcd/stateleaf/v1"
	spentLeafTag = "zcd/spentleaf/v1"
	stateRootTag = "zcd/stateroot/v1"
	nodeTag      = "zcd/node/v1"
)

// Cell is one live cell: the slot it occupies, addr‖word, and the 32-byte
// big-endian value stored there.
type Cell struct {
	Addr  [32]byte
	Word  [32]byte
	Value [32]byte
}

// Root is the epoch state root over the live cells and the spent registry.
//
// The caller owns the inputs' contents but not their order: Root sorts copies.
// It panics on a duplicate slot, a duplicate registry entry, or a cell whose
// value is zero — none of which a well-formed state can present, and each of
// which would otherwise let a broken caller feed this a state the shipped
// implementation cannot hold and get an answer anyway.
func Root(cells []Cell, spent [][32]byte) [32]byte {
	cells32 := cellRoot(cells)
	spent32 := spentRoot(spent)
	return sum(stateRootTag, cells32[:], spent32[:])
}

// cellRoot is the first of the two subtrees.
func cellRoot(cells []Cell) [32]byte {
	ordered := make([]Cell, len(cells))
	copy(ordered, cells)
	sort.Slice(ordered, func(i, j int) bool { return cellLess(ordered[i], ordered[j]) })

	var zero [32]byte
	leaves := make([][32]byte, len(ordered))
	for i, c := range ordered {
		if c.Value == zero {
			panic("naive: a drained cell is not a live cell")
		}
		if i > 0 && !cellLess(ordered[i-1], c) {
			panic("naive: duplicate slot in the cell set")
		}
		leaves[i] = sum(cellLeafTag, c.Addr[:], c.Word[:], c.Value[:])
	}
	return listRoot(leaves)
}

// spentRoot is the second, and the one nothing in spec/vectors commits to.
func spentRoot(spent [][32]byte) [32]byte {
	ordered := make([][32]byte, len(spent))
	copy(ordered, spent)
	sort.Slice(ordered, func(i, j int) bool {
		return bytes.Compare(ordered[i][:], ordered[j][:]) < 0
	})

	leaves := make([][32]byte, len(ordered))
	for i, a := range ordered {
		if i > 0 && bytes.Compare(ordered[i-1][:], a[:]) >= 0 {
			panic("naive: duplicate address in the spent registry")
		}
		leaves[i] = sum(spentLeafTag, a[:])
	}
	return listRoot(leaves)
}

// cellLess orders slots by the concatenation addr‖word, which is what F14 means
// by "sorted by slot".
func cellLess(a, b Cell) bool {
	if c := bytes.Compare(a.Addr[:], b.Addr[:]); c != 0 {
		return c < 0
	}
	return bytes.Compare(a.Word[:], b.Word[:]) < 0
}

// listRoot is the SSZ list root: merkleise against the capacity, then bind the
// actual length, so that a shorter list can never root the same as a longer one
// whose tail happens to be zero.
func listRoot(leaves [][32]byte) [32]byte {
	root := merkleise(leaves)
	var length [32]byte
	binary.LittleEndian.PutUint64(length[:8], uint64(len(leaves)))
	return sum(nodeTag, root[:], length[:])
}

// merkleise materialises every chunk, padding included, and reduces the layer
// pairwise until one node is left.
//
// The reduction is in place over one buffer. That is the only concession to
// cost in this package, and it is not a concession to cleverness: the padding
// chunks are still real, still hashed, and still cost what they cost — which is
// the property that makes this a check on the shipped implementation's
// zero-subtree table rather than a second copy of it.
func merkleise(leaves [][32]byte) [32]byte {
	layer := make([][32]byte, capacityFor(len(leaves)))
	copy(layer, leaves)
	for n := len(layer); n > 1; n /= 2 {
		for i := 0; i < n/2; i++ {
			layer[i] = sum(nodeTag, layer[2*i][:], layer[2*i+1][:])
		}
	}
	return layer[0]
}

// capacityFor is the smallest power of two that holds n leaves. See the third
// note in the package comment for the n == 0 case.
func capacityFor(n int) int {
	c := 1
	for c < n {
		c *= 2
	}
	return c
}

// sum is blake3(tag ‖ parts), the one hash shape the protocol has.
func sum(tag string, parts ...[]byte) [32]byte {
	h := blake3.New()
	h.Write([]byte(tag))
	for _, p := range parts {
		h.Write(p)
	}
	var out [32]byte
	h.XOF(out[:])
	return out
}
