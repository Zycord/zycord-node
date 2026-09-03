package pow

import (
	"bytes"
	"testing"

	"zycord/core/types"
	"zycord/spec"
)

// The miner and the verifier must hash the same bytes, and this file is what
// holds them to it *without* an engine that needs a 2 GiB dataset.
//
// The encoding rules — the seed at 0, seven reserved zeroes at 32, a
// little-endian nonce at 39 — are a property of the BLOB, not of the work
// function evaluated over it. Both engines take the same `(key, input []byte)`
// and neither inspects the layout, so a test that drives the blob through
// pow.Dev is testing exactly the encoding rule RandomX would be bound by, at
// microsecond cost and with no cgo, no build tag and no dataset. That is the
// whole reason this coverage is worth having on the dev path: it is not a
// cheaper approximation of the RandomX check, it is the same check, because
// the part being checked is upstream of the engine.
//
// What it is NOT is a substitute for the RandomX cross-checks in
// core/pow/randomx, which cover the things that genuinely differ between the
// engines — the digest, the key cache, the dataset. Those stay where they are.

// TestTheSolverHashesTheHeadersOwnBlob is the structural half of the guard, and
// it is the one that would have caught a drift the agreement test can miss.
//
// TestTheSolverAgreesWithCheckWork compares *verdicts*: it drives nonces
// through Try and through CheckWork and requires the same answer. That is
// strong, but it is an end-to-end comparison, and two blobs that differ only
// where the engine's digest is insensitive would still agree on every verdict
// while being different bytes — as would two blobs that differ in a byte no
// nonce in the sample reaches.
//
// This one compares the BYTES, for every nonce it tries: the buffer the solver
// is about to hash must equal, byte for byte, what the verifier will rebuild
// from the finished header. There is now only one function that knows the
// layout (types.Header.PoWInput) and NewSolver calls it, so this test's job is
// to keep it that way — a future optimisation that re-derives the buffer here
// "to save an allocation" fails on the first byte it gets wrong.
func TestTheSolverHashesTheHeadersOwnBlob(t *testing.T) {
	p := spec.Devnet()
	h := types.Header{
		Version: types.HeaderVersion,
		// Past a key boundary, so the solver's key is a derived one rather
		// than epoch zero's — the nonce write must not disturb it.
		Height: p.RandomXKeyInterval + p.RandomXKeyLag,
		Time:   1000,
		Target: p.GenesisTarget,
		PoW: types.PoWSeal{
			// A non-zero arriving nonce, because the solver overwrites it and
			// a test that started from zero could not tell "overwritten"
			// from "left alone". ExtraNonce is non-zero for a sharper reason:
			// it is inside PoWSeed, so a solver that zeroed it — the mistake
			// PoWSeed's own comment warns about — would produce a seed the
			// verifier never rebuilds, and every byte of the first 32 would
			// differ here.
			Nonce:      0xDEADBEEF,
			ExtraNonce: 0x12345678,
			SeedEpoch:  SeedEpochFor(p.RandomXKeyInterval+p.RandomXKeyLag, p),
		},
	}

	s := NewSolver(Dev{}, h, p)

	// The nonces that cross the byte and half-word edges of the little-endian
	// write, plus both ends of the space. A solver that wrote the wrong width
	// or at the wrong offset disagrees on one of these.
	for _, nonce := range []uint32{
		0, 1, 255, 256, 65535, 65536,
		1 << 23, 1 << 24, 1 << 31,
		0xFFFFFFFE, 0xFFFFFFFF,
	} {
		s.Try(nonce)

		// What the verifier will hash once this nonce is the header's.
		settled := h
		settled.PoW.Nonce = nonce
		want := settled.PoWInput()

		if !bytes.Equal(s.input, want) {
			t.Fatalf("nonce %#08x: the solver is about to hash bytes the verifier "+
				"will not rebuild.\n solver: %x\n header: %x",
				nonce, s.input, want)
		}
	}
}

// TestTheSolverLeavesTheReservedGapZero pins the one consensus rule in the blob
// that no header field can reach.
//
// The seven bytes at PoWInputReservedOffset are zero because the buffer is
// zero, and nothing in a header can make them anything else — which is exactly
// why they need a test on the MINER's buffer specifically. The verifier's
// PoWInput builds a fresh zeroed array every call, so it cannot get this wrong;
// the solver reuses one buffer across millions of Try calls, so it is the side
// where a stray write would land and persist. A miner whose gap drifted would
// hash a blob no verifier reproduces and would have every block it found
// rejected, with nothing logged.
func TestTheSolverLeavesTheReservedGapZero(t *testing.T) {
	p := spec.Devnet()
	h := types.Header{
		Version: types.HeaderVersion,
		Height:  1,
		Time:    1000,
		Target:  p.GenesisTarget,
	}
	s := NewSolver(Dev{}, h, p)

	zeroes := make([]byte, types.PoWInputReservedSize)
	for _, nonce := range []uint32{0, 1, 0xFFFFFFFF, 0x00FF00FF} {
		s.Try(nonce)
		gap := s.input[types.PoWInputReservedOffset:types.PoWInputNonceOffset]
		if !bytes.Equal(gap, zeroes) {
			t.Fatalf("nonce %#08x: the reserved gap is %x, not zero; a nonce write "+
				"has reached bytes that are pinned at zero by consensus", nonce, gap)
		}
	}
}

// TestTheDevEngineIsBoundByTheBlobLayout is the anti-vacuity arm, and without
// it the two tests above prove less than they appear to.
//
// They compare the solver's bytes against the verifier's. If the work function
// ignored most of the blob, those comparisons could pass while the encoding
// rules did nothing — a blob whose reserved gap or whose nonce offset moved
// would hash the same and no test would notice. So this pins the other half:
// pow.Dev's digest actually DEPENDS on the bytes at each position the layout
// fixes, which is what makes "the two agree on the bytes" a statement about
// consensus rather than about a buffer.
//
// It is the property that lets the dev engine stand in for RandomX here. Both
// engines are total functions of (key, input) and neither is told the layout,
// so "the digest moves when this byte moves" is engine-independent — proving it
// on Dev proves the blob is load-bearing for any engine the interface admits.
func TestTheDevEngineIsBoundByTheBlobLayout(t *testing.T) {
	p := spec.Devnet()
	h := types.Header{
		Version: types.HeaderVersion,
		Height:  1,
		Time:    1000,
		Target:  p.GenesisTarget,
	}
	key := KeyFor(h.Height, p)
	base := h.PoWInput()
	baseDigest := (Dev{}).Hash(key, base)

	// Every byte of the blob, one at a time. Each position the layout names is
	// covered by construction: 0..31 the seed, 32..38 the reserved gap,
	// 39..42 the nonce.
	for i := range base {
		mutated := append([]byte(nil), base...)
		mutated[i] ^= 0xFF
		if (Dev{}).Hash(key, mutated) == baseDigest {
			t.Errorf("byte %d of the blob does not affect the digest; the layout "+
				"pins a byte the work function ignores, so a verifier that filled "+
				"it differently would still agree and the rule would be untested", i)
		}
	}

	// And the key, for the same reason: it is what separates two networks at
	// the same height (KeyFor folds the chain id in), so a digest insensitive
	// to it would make the whole key schedule inert.
	var otherKey types.Hash
	otherKey[0] = 1
	if (Dev{}).Hash(otherKey, base) == baseDigest {
		t.Error("the dev engine's digest does not depend on the key; key rotation " +
			"and cross-network separation would both be inert")
	}
}
