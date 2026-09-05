// Package blake3 implements the BLAKE3 cryptographic hash function.
//
// This is a portable, dependency-free implementation written for auditability
// rather than speed: it follows the reference specification structure exactly
// (chunk state, chaining-value stack, parent nodes) with no SIMD, no unsafe
// and no assembly. Consensus code may import nothing outside the standard
// library, and a hash function is not something to take on trust from a
// third party, so it lives in the tree.
//
// Only the modes Zycord needs are implemented: unkeyed hashing and keyed
// hashing, both with extendable output. Derive-key mode is intentionally
// absent — unreachable code is unauditable code.
package blake3

import (
	"encoding/binary"
	"errors"
	"hash"
	"math/bits"
)

const (
	// BlockSize is the internal compression block size in bytes.
	BlockSize = 64
	// ChunkSize is the size of a leaf chunk in bytes.
	ChunkSize = 1024
	// Size is the default digest length in bytes.
	Size = 32
	// KeySize is the length of a keyed-hashing key in bytes.
	KeySize = 32
)

// Domain flags, per the BLAKE3 specification.
const (
	flagChunkStart uint32 = 1 << 0
	flagChunkEnd   uint32 = 1 << 1
	flagParent     uint32 = 1 << 2
	flagRoot       uint32 = 1 << 3
	flagKeyedHash  uint32 = 1 << 4
)

// iv is the BLAKE3 initialisation vector (the first eight SHA-256 constants).
var iv = [8]uint32{
	0x6A09E667, 0xBB67AE85, 0x3C6EF372, 0xA54FF53A,
	0x510E527F, 0x9B05688C, 0x1F83D9AB, 0x5BE0CD19,
}

// msgPermutation is the message schedule permutation applied between rounds.
var msgPermutation = [16]uint8{2, 6, 3, 10, 7, 0, 4, 13, 1, 11, 12, 5, 9, 14, 15, 8}

// g is the BLAKE3 quarter-round.
func g(s *[16]uint32, a, b, c, d int, mx, my uint32) {
	s[a] = s[a] + s[b] + mx
	s[d] = bits.RotateLeft32(s[d]^s[a], -16)
	s[c] = s[c] + s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], -12)
	s[a] = s[a] + s[b] + my
	s[d] = bits.RotateLeft32(s[d]^s[a], -8)
	s[c] = s[c] + s[d]
	s[b] = bits.RotateLeft32(s[b]^s[c], -7)
}

func round(s *[16]uint32, m *[16]uint32) {
	// Columns.
	g(s, 0, 4, 8, 12, m[0], m[1])
	g(s, 1, 5, 9, 13, m[2], m[3])
	g(s, 2, 6, 10, 14, m[4], m[5])
	g(s, 3, 7, 11, 15, m[6], m[7])
	// Diagonals.
	g(s, 0, 5, 10, 15, m[8], m[9])
	g(s, 1, 6, 11, 12, m[10], m[11])
	g(s, 2, 7, 8, 13, m[12], m[13])
	g(s, 3, 4, 9, 14, m[14], m[15])
}

// compress runs the seven-round permutation and returns the full 16-word
// output state. The first eight words are the chaining value; all sixteen are
// used when producing extended output.
func compress(cv *[8]uint32, block *[16]uint32, counter uint64, blockLen, flags uint32) [16]uint32 {
	s := [16]uint32{
		cv[0], cv[1], cv[2], cv[3], cv[4], cv[5], cv[6], cv[7],
		iv[0], iv[1], iv[2], iv[3],
		uint32(counter), uint32(counter >> 32), blockLen, flags,
	}
	m := *block
	for i := 0; i < 7; i++ {
		round(&s, &m)
		if i < 6 {
			var p [16]uint32
			for j := 0; j < 16; j++ {
				p[j] = m[msgPermutation[j]]
			}
			m = p
		}
	}
	for i := 0; i < 8; i++ {
		s[i] ^= s[i+8]
		s[i+8] ^= cv[i]
	}
	return s
}

// output is a node of the hash tree that has not yet been finalised. Keeping
// it as an explicit value (rather than collapsing to a chaining value) is what
// makes extendable output possible: the root node is expanded, every other
// node is collapsed.
type output struct {
	inputCV  [8]uint32
	block    [16]uint32
	counter  uint64
	blockLen uint32
	flags    uint32
}

func (o output) chainingValue() [8]uint32 {
	full := compress(&o.inputCV, &o.block, o.counter, o.blockLen, o.flags)
	var cv [8]uint32
	copy(cv[:], full[:8])
	return cv
}

// rootBytes fills out with the extendable root output stream.
func (o output) rootBytes(out []byte) {
	var counter uint64
	for len(out) > 0 {
		words := compress(&o.inputCV, &o.block, counter, o.blockLen, o.flags|flagRoot)
		var buf [64]byte
		for i, w := range words {
			binary.LittleEndian.PutUint32(buf[i*4:], w)
		}
		n := copy(out, buf[:])
		out = out[n:]
		counter++
	}
}

// chunkState accumulates input for one 1024-byte leaf of the tree.
type chunkState struct {
	cv      [8]uint32
	counter uint64
	buf     [BlockSize]byte
	bufLen  int
	blocks  int // complete blocks already compressed into cv
	flags   uint32
}

func newChunkState(key [8]uint32, counter uint64, flags uint32) chunkState {
	return chunkState{cv: key, counter: counter, flags: flags}
}

func (c *chunkState) length() int { return c.blocks*BlockSize + c.bufLen }

func (c *chunkState) startFlag() uint32 {
	if c.blocks == 0 {
		return flagChunkStart
	}
	return 0
}

func (c *chunkState) compressBuf() {
	var block [16]uint32
	for i := 0; i < 16; i++ {
		block[i] = binary.LittleEndian.Uint32(c.buf[i*4:])
	}
	full := compress(&c.cv, &block, c.counter, BlockSize, c.flags|c.startFlag())
	copy(c.cv[:], full[:8])
	c.blocks++
	c.bufLen = 0
}

func (c *chunkState) update(p []byte) {
	for len(p) > 0 {
		if c.bufLen == BlockSize {
			c.compressBuf()
		}
		n := copy(c.buf[c.bufLen:], p)
		c.bufLen += n
		p = p[n:]
	}
}

// output finalises the chunk into a tree node.
func (c *chunkState) output() output {
	var block [16]uint32
	var padded [BlockSize]byte
	copy(padded[:], c.buf[:c.bufLen])
	for i := 0; i < 16; i++ {
		block[i] = binary.LittleEndian.Uint32(padded[i*4:])
	}
	return output{
		inputCV:  c.cv,
		block:    block,
		counter:  c.counter,
		blockLen: uint32(c.bufLen),
		flags:    c.flags | c.startFlag() | flagChunkEnd,
	}
}

func parentOutput(left, right [8]uint32, key [8]uint32, flags uint32) output {
	var block [16]uint32
	copy(block[:8], left[:])
	copy(block[8:], right[:])
	return output{inputCV: key, block: block, counter: 0, blockLen: BlockSize, flags: flags | flagParent}
}

// Hasher is an incremental BLAKE3 state. The zero value is not usable; obtain
// one from New or NewKeyed.
type Hasher struct {
	key        [8]uint32
	chunk      chunkState
	stack      [54][8]uint32 // one slot per possible subtree height (2^54 chunks)
	stackLen   int
	chunkCount uint64
	flags      uint32
}

// New returns an unkeyed BLAKE3 hasher.
func New() *Hasher {
	h := &Hasher{key: iv, flags: 0}
	h.chunk = newChunkState(iv, 0, 0)
	return h
}

// NewKeyed returns a keyed BLAKE3 hasher. It reports an error if the key is
// not exactly KeySize bytes.
func NewKeyed(key []byte) (*Hasher, error) {
	if len(key) != KeySize {
		return nil, errors.New("blake3: key must be 32 bytes")
	}
	var kw [8]uint32
	for i := 0; i < 8; i++ {
		kw[i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	h := &Hasher{key: kw, flags: flagKeyedHash}
	h.chunk = newChunkState(kw, 0, flagKeyedHash)
	return h, nil
}

// pushCV merges the new subtree chaining value into the stack. The number of
// completed chunks determines how many merges are due: this is exactly binary
// counter arithmetic, and it is what keeps the tree canonical regardless of
// how the input was chunked across Write calls.
func (h *Hasher) pushCV(cv [8]uint32, totalChunks uint64) {
	for totalChunks&1 == 0 && h.stackLen > 0 {
		h.stackLen--
		left := h.stack[h.stackLen]
		out := parentOutput(left, cv, h.key, h.flags)
		cv = out.chainingValue()
		totalChunks >>= 1
	}
	h.stack[h.stackLen] = cv
	h.stackLen++
}

// Write absorbs more input. It never returns an error.
func (h *Hasher) Write(p []byte) (int, error) {
	total := len(p)
	for len(p) > 0 {
		if h.chunk.length() == ChunkSize {
			cv := h.chunk.output().chainingValue()
			h.chunkCount++
			h.pushCV(cv, h.chunkCount)
			h.chunk = newChunkState(h.key, h.chunkCount, h.flags)
		}
		want := ChunkSize - h.chunk.length()
		n := len(p)
		if n > want {
			n = want
		}
		h.chunk.update(p[:n])
		p = p[n:]
	}
	return total, nil
}

// rootOutput collapses the current stack plus the in-flight chunk into the
// single root node.
func (h *Hasher) rootOutput() output {
	out := h.chunk.output()
	for i := h.stackLen - 1; i >= 0; i-- {
		out = parentOutput(h.stack[i], out.chainingValue(), h.key, h.flags)
	}
	return out
}

// XOF fills dst with the extendable root output. Calling it does not change
// the hasher state, so it may be called repeatedly.
func (h *Hasher) XOF(dst []byte) {
	out := h.rootOutput()
	out.rootBytes(dst)
}

// Sum appends the 32-byte digest to b.
func (h *Hasher) Sum(b []byte) []byte {
	var d [Size]byte
	h.XOF(d[:])
	return append(b, d[:]...)
}

// Size returns the default digest length in bytes.
func (h *Hasher) Size() int { return Size }

// BlockSize returns the internal block size in bytes.
func (h *Hasher) BlockSize() int { return BlockSize }

// Reset returns the hasher to its initial state, preserving any key.
func (h *Hasher) Reset() {
	h.chunk = newChunkState(h.key, 0, h.flags)
	h.stackLen = 0
	h.chunkCount = 0
}

var _ hash.Hash = (*Hasher)(nil)

// Sum256 returns the unkeyed 32-byte BLAKE3 digest of data.
func Sum256(data []byte) [Size]byte {
	h := New()
	h.Write(data)
	var out [Size]byte
	h.XOF(out[:])
	return out
}

// Sum256Keyed returns the keyed 32-byte BLAKE3 digest of data. It panics if
// the key is not KeySize bytes; callers in consensus code pass fixed-size
// arrays, so the condition is unreachable there.
func Sum256Keyed(key [KeySize]byte, data []byte) [Size]byte {
	h, err := NewKeyed(key[:])
	if err != nil {
		panic(err)
	}
	h.Write(data)
	var out [Size]byte
	h.XOF(out[:])
	return out
}
