// Package blake2b implements the BLAKE2b cryptographic hash function
// (RFC 7693), unkeyed, with a 32-byte digest.
//
// # Why this exists at all, when the tree already has BLAKE3
//
// It is not here because anything in this protocol wanted a second hash
// function. It is here because **RandomX v2's commitment is defined in terms
// of BLAKE2b and the definition is not ours to change.** Upstream computes
// `blake2b-256(input ‖ H)`, XMRig's `randomx_calculate_commitment` is three
// lines that do exactly that, and every stock miner on the network will filter
// its shares on that number. A chain that substituted BLAKE3 there would
// compute a different commitment from every miner pointed at it, which is the
// same silent, total incompatibility docs/decisions/xmrig.md exists to
// document — a miner reporting healthy hashrate and having every share
// refused, with no error naming the cause.
//
// So the choice of function is upstream's. What this package decides is only
// where the implementation comes from, and `make check-imports` settles that:
// core/ may import nothing outside the standard library, the standard library
// has no BLAKE2b, and `golang.org/x/crypto/blake2b` is confined to wallet/.
// core/crypto/blake3 is the precedent and the reasoning transfers unchanged —
// a hash function in the consensus path is not something to take on trust from
// a third party, and a portable implementation written for auditability is
// short enough to read.
//
// # Scope, deliberately narrow
//
// Unkeyed, 32-byte output, one-shot. No keying, no salt, no personalisation,
// no streaming, no variable digest length. RandomX's commitment uses exactly
// one configuration and every other mode this package could offer would be
// unreachable code, which is unauditable code — the same rule blake3's doc
// comment states about derive-key mode.
//
// # What anchors it
//
// The test file carries RFC 7693's own appendix-A vector and the official
// BLAKE2b-256 vectors, and — the one that actually matters for consensus —
// tevador/RandomX's published commitment vector from src/tests/tests.cpp at
// v2.0.1, which pins this implementation against the exact call the miner
// makes rather than against BLAKE2b in the abstract.
package blake2b

import "encoding/binary"

// Size is the digest length in bytes. RandomX's commitment is 32 bytes
// (RANDOMX_HASH_SIZE) and this package offers no other width.
const Size = 32

// BlockSize is the compression block size in bytes.
const BlockSize = 128

// iv is the BLAKE2b initialisation vector: the first 64 bits of the fractional
// parts of the square roots of the first eight primes. Identical to SHA-512's.
var iv = [8]uint64{
	0x6a09e667f3bcc908, 0xbb67ae8584caa73b,
	0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
	0x510e527fade682d1, 0x9b05688c2b3e6c1f,
	0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
}

// sigma is the message-word permutation schedule, ten rounds of it; BLAKE2b
// runs twelve rounds and reuses rows 0 and 1 for rounds 10 and 11.
var sigma = [12][16]byte{
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
	{11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4},
	{7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8},
	{9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13},
	{2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9},
	{12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11},
	{13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10},
	{6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5},
	{10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0},
	{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15},
	{14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3},
}

// rotr is a 64-bit right rotation. Written out rather than taken from
// math/bits so that the four rotation constants below read as the
// specification's G function does.
func rotr(x uint64, n uint) uint64 { return x>>n | x<<(64-n) }

// compress is BLAKE2b's F function: twelve rounds of the G mix over a
// sixteen-word message block, with `t` the byte counter and `last` the
// finalisation flag.
func compress(h *[8]uint64, block *[BlockSize]byte, t uint64, last bool) {
	var m [16]uint64
	for i := 0; i < 16; i++ {
		m[i] = binary.LittleEndian.Uint64(block[i*8:])
	}

	var v [16]uint64
	copy(v[:8], h[:])
	copy(v[8:], iv[:])

	// The counter is 128-bit in the specification. This package hashes at most
	// a few hundred bytes (a 43-byte blob plus a 32-byte hash), so the high
	// half is always zero; it is written as a literal rather than omitted so
	// that a reader comparing this against RFC 7693 finds v[13] where the
	// specification puts it.
	v[12] ^= t
	v[13] ^= 0
	if last {
		v[14] = ^v[14]
	}

	g := func(a, b, c, d int, x, y uint64) {
		v[a] = v[a] + v[b] + x
		v[d] = rotr(v[d]^v[a], 32)
		v[c] = v[c] + v[d]
		v[b] = rotr(v[b]^v[c], 24)
		v[a] = v[a] + v[b] + y
		v[d] = rotr(v[d]^v[a], 16)
		v[c] = v[c] + v[d]
		v[b] = rotr(v[b]^v[c], 63)
	}

	for r := 0; r < 12; r++ {
		s := &sigma[r]
		g(0, 4, 8, 12, m[s[0]], m[s[1]])
		g(1, 5, 9, 13, m[s[2]], m[s[3]])
		g(2, 6, 10, 14, m[s[4]], m[s[5]])
		g(3, 7, 11, 15, m[s[6]], m[s[7]])
		g(0, 5, 10, 15, m[s[8]], m[s[9]])
		g(1, 6, 11, 12, m[s[10]], m[s[11]])
		g(2, 7, 8, 13, m[s[12]], m[s[13]])
		g(3, 4, 9, 14, m[s[14]], m[s[15]])
	}

	for i := 0; i < 8; i++ {
		h[i] ^= v[i] ^ v[i+8]
	}
}

// Sum256 returns the unkeyed BLAKE2b-256 digest of p.
//
// One-shot rather than a streaming hash.Hash, because the one caller hashes a
// short concatenation it already holds in full, and a streaming interface here
// would be three more states to get wrong for no reader's benefit.
func Sum256(p []byte) [Size]byte {
	var h [8]uint64
	copy(h[:], iv[:])
	// The parameter block, XORed into h[0]: digest length in byte 0, key
	// length (zero — unkeyed) in byte 1, fanout 1 in byte 2, depth 1 in byte
	// 3. Everything above is zero for this configuration.
	h[0] ^= 0x01010000 ^ uint64(Size)

	var block [BlockSize]byte
	var counter uint64

	// Every FULL block except the last one the message reaches. BLAKE2b's
	// finalisation flag belongs to the final compression, and an input whose
	// length is an exact multiple of the block size must therefore leave its
	// last full block for the tail below rather than consuming it here — the
	// classic off-by-one in this function, and the reason the loop condition
	// is `>` and not `>=`.
	for len(p) > BlockSize {
		copy(block[:], p[:BlockSize])
		counter += BlockSize
		compress(&h, &block, counter, false)
		p = p[BlockSize:]
	}

	// The tail: zero-padded to a full block, counted by its true length.
	// An empty input takes this path with counter 0, which is what RFC 7693
	// specifies for the empty message.
	block = [BlockSize]byte{}
	copy(block[:], p)
	counter += uint64(len(p))
	compress(&h, &block, counter, true)

	var out [Size]byte
	for i := 0; i < Size/8; i++ {
		binary.LittleEndian.PutUint64(out[i*8:], h[i])
	}
	return out
}
