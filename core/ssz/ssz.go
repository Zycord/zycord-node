// Package ssz implements the subset of SSZ that Zycord's consensus objects
// need, plus the merkleisation used by the certificate root and the epoch
// state root.
//
// There is no reflection here and no code generation. Every consensus type
// spells out its own encoding in core/types, using these helpers for the two
// parts that are easy to get subtly wrong: the fixed/variable offset dance and
// the merkle tree.
//
// The property this package exists to guarantee is *canonicality*: for every
// value there is exactly one byte string, and every byte string that decodes
// does so to exactly one value. Decoding therefore rejects short reads, long
// reads, offsets that do not start immediately after the fixed section,
// offsets that move backwards, and lists whose length is not a whole number of
// elements. A decoded object is structurally valid by construction, so the
// V-rules and F-rules never re-check shape.
package ssz

import (
	"encoding/binary"
	"errors"
	"fmt"

	"zycord/core/crypto"
)

// BytesPerLengthOffset is the width of a variable-field offset.
const BytesPerLengthOffset = 4

// Errors returned by the decoders. They are deliberately coarse: a peer
// sending malformed bytes gets scored down, not diagnosed.
var (
	ErrShort        = errors.New("ssz: input too short")
	ErrTrailing     = errors.New("ssz: trailing bytes")
	ErrOffset       = errors.New("ssz: non-canonical offset")
	ErrElementCount = errors.New("ssz: input is not a whole number of elements")
	ErrLimit        = errors.New("ssz: list exceeds its genesis-fixed maximum length")
)

// Variable marks a container field as variable-size in a layout descriptor.
const Variable = -1

// Encode assembles a container from its already-encoded fields. Fields whose
// layout entry is Variable are moved to the variable section and replaced by a
// 4-byte offset, in declaration order.
//
// layout must have one entry per field: a non-negative fixed width, or
// Variable. Encode panics on a layout that disagrees with the field widths,
// because that is a programming error in this repository, never an input.
func Encode(layout []int, fields [][]byte) []byte {
	if len(layout) != len(fields) {
		panic("ssz: layout/field count mismatch")
	}

	fixedLen := 0
	for i, w := range layout {
		if w == Variable {
			fixedLen += BytesPerLengthOffset
			continue
		}
		if w != len(fields[i]) {
			panic(fmt.Sprintf("ssz: field %d encoded %d bytes, layout says %d", i, len(fields[i]), w))
		}
		fixedLen += w
	}

	out := make([]byte, fixedLen, fixedLen*2)
	pos := 0
	for i, w := range layout {
		if w == Variable {
			binary.LittleEndian.PutUint32(out[pos:], uint32(len(out)))
			pos += BytesPerLengthOffset
			out = append(out, fields[i]...)
			continue
		}
		copy(out[pos:], fields[i])
		pos += w
	}
	return out
}

// FixedLen is the width of a layout's fixed section, and therefore the least
// number of bytes any encoding of that layout can occupy: a variable field
// still costs its four offset bytes even when it is empty. Decoders of lists
// of such containers pass it as minElemSize, which is what stops a claimed
// element count from exceeding what the payload could actually carry.
func FixedLen(layout []int) int {
	fixedLen := 0
	for _, w := range layout {
		if w == Variable {
			fixedLen += BytesPerLengthOffset
			continue
		}
		fixedLen += w
	}
	return fixedLen
}

// Decode splits a container encoding into its fields, enforcing canonical
// offsets. The returned slices alias data; callers copy what they keep.
func Decode(layout []int, data []byte) ([][]byte, error) {
	fixedLen := FixedLen(layout)
	varCount := 0
	for _, w := range layout {
		if w == Variable {
			varCount++
		}
	}
	if len(data) < fixedLen {
		return nil, ErrShort
	}
	if varCount == 0 && len(data) != fixedLen {
		return nil, ErrTrailing
	}

	fields := make([][]byte, len(layout))
	// Held unsigned so that no int width can make an offset negative;
	// they are narrowed only after being bounded by len(data) below.
	offsets := make([]uint64, 0, varCount)
	varIdx := make([]int, 0, varCount)

	pos := 0
	for i, w := range layout {
		if w == Variable {
			off := uint64(binary.LittleEndian.Uint32(data[pos:]))
			offsets = append(offsets, off)
			varIdx = append(varIdx, i)
			pos += BytesPerLengthOffset
			continue
		}
		fields[i] = data[pos : pos+w]
		pos += w
	}

	// Canonical offsets: the first points at the end of the fixed section, they
	// never move backwards, and the last variable field runs to the end of the
	// input exactly.
	for i, off := range offsets {
		if i == 0 {
			if off != uint64(fixedLen) {
				return nil, ErrOffset
			}
		} else if off < offsets[i-1] {
			return nil, ErrOffset
		}
		if off > uint64(len(data)) {
			return nil, ErrOffset
		}
	}
	for i := range offsets {
		end := len(data)
		if i+1 < len(offsets) {
			end = int(offsets[i+1])
		}
		fields[varIdx[i]] = data[int(offsets[i]):end]
	}
	return fields, nil
}

// DecodeFixedList splits the encoding of a list whose elements are fixed-size.
func DecodeFixedList(data []byte, elemSize int, limit int) ([][]byte, error) {
	if elemSize <= 0 {
		panic("ssz: element size must be positive")
	}
	if len(data)%elemSize != 0 {
		return nil, ErrElementCount
	}
	n := len(data) / elemSize
	if n > limit {
		return nil, ErrLimit
	}
	out := make([][]byte, n)
	for i := 0; i < n; i++ {
		out[i] = data[i*elemSize : (i+1)*elemSize]
	}
	return out, nil
}

// EncodeVariableList concatenates variable-size elements behind an offset
// table, as SSZ requires for lists of variable-size containers.
func EncodeVariableList(elems [][]byte) []byte {
	head := BytesPerLengthOffset * len(elems)
	out := make([]byte, head)
	pos := 0
	for _, e := range elems {
		binary.LittleEndian.PutUint32(out[pos:], uint32(len(out)))
		pos += BytesPerLengthOffset
		out = append(out, e...)
	}
	return out
}

// offsetAt reads the i'th entry of an offset table as an unsigned value. Every
// offset in this package is compared unsigned and narrowed only afterwards,
// because the width of int is a property of the build target and a wire offset
// must not be able to change sign by being converted to one.
func offsetAt(data []byte, i int) uint64 {
	return uint64(binary.LittleEndian.Uint32(data[i*BytesPerLengthOffset:]))
}

// DecodeVariableList splits the encoding of a list of variable-size elements.
//
// minElemSize is the least number of bytes one element of this list can
// encode to — FixedLen of the element's layout — or 0 for a list whose
// elements have no such floor. It is what makes the element count bounded by
// the payload rather than by the sender's claim; see the comment on the check
// itself. Passing 0 where a floor exists is not wrong, only unbounded.
func DecodeVariableList(data []byte, limit, minElemSize int) ([][]byte, error) {
	if len(data) == 0 {
		return nil, nil
	}
	if len(data) < BytesPerLengthOffset {
		return nil, ErrShort
	}
	// Offsets are validated unsigned, before anything narrows them.
	//
	// int(uint32) is implementation-sized: where int is 32 bits, a wire offset
	// of 0xFFFFFFFC narrows to -4 and passes every signed guard here — Go's %
	// keeps the sign of its left operand, so -4%4 is 0, and a negative value is
	// not greater than any length — reaching make([][]byte, n) with n == -1.
	// Four peer-supplied bytes would then panic the decoder, and this package
	// promises that a decoded object is structurally valid by construction: a
	// panic is not a refusal. Comparing unsigned makes the negative
	// unrepresentable rather than merely unreached, so the accept/reject set is
	// the same on every int width instead of being one build target away from
	// differing.
	firstOff := offsetAt(data, 0)
	if firstOff%BytesPerLengthOffset != 0 || firstOff == 0 || firstOff > uint64(len(data)) {
		return nil, ErrOffset
	}
	first := int(firstOff) // in [BytesPerLengthOffset, len(data)] by the check above
	n := first / BytesPerLengthOffset
	if n > limit {
		return nil, ErrLimit
	}
	// The claimed count must fit in the payload that claims it.
	//
	// n is not a length prefix: it comes from a wire-supplied offset. Whether
	// `limit` above catches an inflated one is entirely the caller's business —
	// MaxCitesPerBlock (4) binds hard, while CertListCapacity (2^25) is three
	// orders of magnitude above what any message frame can carry and so refuses
	// nothing a peer can actually send. For a list of the second kind the
	// payload's own length in *offsets* was the only bound, and four payload
	// bytes bought forty bytes of receiver memory: a private []int of offsets
	// (8 B), the returned slice header (24 B), and the caller's own per-element
	// table (8 B).
	//
	// minElemSize closes that. n elements of at least minElemSize bytes each,
	// behind n offsets, need n*(BytesPerLengthOffset+minElemSize) bytes; a
	// payload shorter than that holds an element below the floor, which that
	// element's own decoder refuses anyway, so this moves no accept/reject
	// boundary — it only refuses before anything is sized. Everything after it
	// is then bounded by the payload: the offsets are validated in a pass that
	// allocates nothing, and the single table charged is the slice headers the
	// caller is handed. The validation rule itself is byte-identical to the
	// one that stood before minElemSize existed — every offset within data, none
	// moving backwards, checked in the same ascending order, so that a claim
	// still buys no work until it has been checked.
	if minElemSize > 0 && n > len(data)/(BytesPerLengthOffset+minElemSize) {
		return nil, ErrOffset
	}

	prev := firstOff
	for i := 1; i < n; i++ {
		off := offsetAt(data, i)
		if off > uint64(len(data)) {
			return nil, ErrOffset
		}
		if off < prev {
			return nil, ErrOffset
		}
		prev = off
	}

	out := make([][]byte, n)
	start := first
	for i := 0; i < n; i++ {
		end := len(data)
		if i+1 < n {
			// Offset i+1 was bounded by len(data) unsigned in the loop above,
			// so this narrowing cannot go negative.
			end = int(offsetAt(data, i+1))
		}
		out[i] = data[start:end]
		start = end
	}
	return out, nil
}

// Uint32 encodes a little-endian uint32.
func Uint32(v uint32) []byte {
	var b [4]byte
	binary.LittleEndian.PutUint32(b[:], v)
	return b[:]
}

// Uint64 encodes a little-endian uint64.
func Uint64(v uint64) []byte {
	var b [8]byte
	binary.LittleEndian.PutUint64(b[:], v)
	return b[:]
}

// ReadUint32 decodes a little-endian uint32 field.
func ReadUint32(b []byte) uint32 { return binary.LittleEndian.Uint32(b) }

// ReadUint64 decodes a little-endian uint64 field.
func ReadUint64(b []byte) uint64 { return binary.LittleEndian.Uint64(b) }

// zeroHashes[i] is the root of a perfect subtree of height i whose leaves are
// all zero. Precomputing them is what lets a list be merkleised against its
// genesis-fixed maximum length without materialising the padding.
var zeroHashes [64]crypto.Hash

func init() {
	for i := 1; i < len(zeroHashes); i++ {
		zeroHashes[i] = node(zeroHashes[i-1], zeroHashes[i-1])
	}
}

func node(l, r crypto.Hash) crypto.Hash {
	return crypto.Sum(crypto.TagSSZNode, l[:], r[:])
}

// Merkleize returns the root of a binary tree over chunks, padded with zero
// subtrees to limit leaves. limit is the list's genesis-fixed maximum length,
// so the tree depth — and therefore the meaning of a root — never depends on
// how full a particular list happens to be.
func Merkleize(chunks []crypto.Hash, limit int) crypto.Hash {
	if len(chunks) > limit {
		panic("ssz: chunk count exceeds limit")
	}
	depth := 0
	for 1<<depth < limit {
		depth++
	}

	layer := append([]crypto.Hash(nil), chunks...)
	for d := 0; d < depth; d++ {
		next := make([]crypto.Hash, 0, (len(layer)+1)/2)
		for i := 0; i < len(layer); i += 2 {
			// A missing right sibling is a subtree of zeros at this height.
			r := zeroHashes[d]
			if i+1 < len(layer) {
				r = layer[i+1]
			}
			next = append(next, node(layer[i], r))
		}
		layer = next
	}
	if len(layer) == 0 {
		// An empty list: the tree is entirely virtual padding.
		return zeroHashes[depth]
	}
	return layer[0]
}

// MixInLength binds a list root to its actual length, so that a shorter list
// can never merkleise to the same root as a longer one padded with zeros.
func MixInLength(root crypto.Hash, length uint64) crypto.Hash {
	var l crypto.Hash
	binary.LittleEndian.PutUint64(l[:8], length)
	return node(root, l)
}

// ListRoot is the SSZ root of a list of 32-byte chunks: merkleised against the
// list's maximum length, then mixed with the actual length.
func ListRoot(chunks []crypto.Hash, limit int) crypto.Hash {
	return MixInLength(Merkleize(chunks, limit), uint64(len(chunks)))
}

// Tree is a merkleised chunk list that keeps its internal nodes, so that a
// list which mostly did not change can be re-rooted without rehashing the
// parts that did not.
//
// It is an optimisation and nothing else: `Tree.Root(chunks, limit)` returns
// exactly what `ListRoot(chunks, limit)` returns, for every input and whatever
// sequence of calls preceded it. TestTreeMatchesListRoot holds the two against
// each other; the equivalence is by construction, because the tree stores the
// leaf layer padded out to `limit` with `zeroHashes[0]` and every node above
// it as `node(left, right)` — and `node(zeroHashes[d], zeroHashes[d])` is
// `zeroHashes[d+1]`, which is precisely the padding Merkleize substitutes.
//
// The caller does not declare what changed. The tree diffs the chunk slice it
// is given against the leaf layer it is holding, which is a 32-byte compare
// per leaf against a BLAKE3 per internal node — two orders of magnitude
// cheaper, and it cannot go stale the way a caller-supplied dirty set can.
//
// That makes the tree **self-healing**, which is the load-bearing safety
// property of everything built on it: every Root leaves the layers internally
// consistent, and given that invariant the answer is a pure function of
// (chunks, limit). A tree that is stale, or shared between two states, costs
// recomputation and never correctness. It is also why no assertion about root
// *values* can detect a Clone that failed to copy — the reason the copy matters
// is memory safety when a clone is handed to another goroutine, and that is
// what tree_internal_test.go asserts, by address.
//
// It costs memory: 64 B of internal nodes per leaf slot of capacity, which for
// the state root is a bounded multiple of the state it commits to. Callers
// that root a list once should use ListRoot and pay nothing.
type Tree struct {
	depth  int
	layers [][]crypto.Hash // layers[0] is the padded leaf layer; layers[depth] is the root
}

// NewTree returns an empty tree. The first Root call builds it.
func NewTree() *Tree { return &Tree{depth: -1} }

// Clone returns an independent copy, so that a cloned state does not share
// internal nodes with the state it was cloned from.
func (t *Tree) Clone() *Tree {
	if t == nil {
		return nil
	}
	out := &Tree{depth: t.depth, layers: make([][]crypto.Hash, len(t.layers))}
	for i, l := range t.layers {
		out.layers[i] = append([]crypto.Hash(nil), l...)
	}
	return out
}

// Root returns ListRoot(chunks, limit), reusing every internal node whose
// subtree is unchanged since the previous call.
//
// A change of limit re-shapes the tree — the state root's capacity moves with
// its live count — and is handled by a full rebuild, which is the only
// correct answer and is why the cost is Θ(N) on those blocks.
func (t *Tree) Root(chunks []crypto.Hash, limit int) crypto.Hash {
	if len(chunks) > limit {
		panic("ssz: chunk count exceeds limit")
	}
	depth := 0
	for 1<<depth < limit {
		depth++
	}

	if t.depth != depth {
		t.rebuild(chunks, depth)
		return MixInLength(t.layers[depth][0], uint64(len(chunks)))
	}

	// Which leaves moved? Everything past len(chunks) is padding and must read
	// as zeroHashes[0], which is how the tree stores it.
	var dirty []int
	leaf := t.layers[0]
	for i := range leaf {
		var want crypto.Hash
		if i < len(chunks) {
			want = chunks[i]
		}
		if leaf[i] != want {
			leaf[i] = want
			dirty = append(dirty, i)
		}
	}
	for d := 0; d < depth && len(dirty) > 0; d++ {
		up := dirty[:0:0]
		for _, i := range dirty {
			j := i >> 1
			if len(up) > 0 && up[len(up)-1] == j {
				continue // the sibling was dirty too; the parent is already queued
			}
			up = append(up, j)
		}
		for _, j := range up {
			t.layers[d+1][j] = node(t.layers[d][2*j], t.layers[d][2*j+1])
		}
		dirty = up
	}
	return MixInLength(t.layers[depth][0], uint64(len(chunks)))
}

func (t *Tree) rebuild(chunks []crypto.Hash, depth int) {
	t.depth = depth
	t.layers = make([][]crypto.Hash, depth+1)
	leaf := make([]crypto.Hash, 1<<depth)
	copy(leaf, chunks)
	t.layers[0] = leaf
	for d := 0; d < depth; d++ {
		next := make([]crypto.Hash, len(t.layers[d])/2)
		for j := range next {
			next[j] = node(t.layers[d][2*j], t.layers[d][2*j+1])
		}
		t.layers[d+1] = next
	}
}
