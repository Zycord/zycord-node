package types_test

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"zycord/core/types"
)

// blobHeader is a header with every field non-zero and distinctive, so that a
// test asserting where the seed ends can fail when the seed moves rather than
// when it happens to be zero.
func blobHeader() types.Header {
	h := types.Header{
		Version: types.HeaderVersion,
		Height:  7,
		Time:    1_700_000_000,
		PoW: types.PoWSeal{
			Nonce:      0xA1B2C3D4,
			ExtraNonce: 0x0BADF00D,
			SeedEpoch:  3,
		},
	}
	for i := range h.ParentID {
		h.ParentID[i] = byte(i + 1)
	}
	for i := range h.CertRoot {
		h.CertRoot[i] = byte(i + 2)
	}
	return h
}

// TestThePoWBlobIsTheLayoutXMRigExpects is the whole of the consensus claim
// this file exists for, asserted byte by byte rather than by round trip.
//
// **A round trip cannot state this property.** PoWInput is the only producer of
// the blob in this tree, so a test that compared it against itself — or against
// anything derived from it — would agree with any layout at all, including the
// one that shipped before this change. The offsets have to be written down
// independently, as literals, and compared against what the function produced.
// That is why the numbers below are spelled out rather than taken from the
// constants they are pinning: a test that reads PoWInputNonceOffset to decide
// where to look for the nonce passes when somebody edits PoWInputNonceOffset.
//
// The numbers themselves are not ours. Stock XMRig writes a four-byte
// little-endian nonce at byte 39 of the blob it is given for rx/0, because that
// is the offset of the nonce in Monero's block-hashing blob, and it is compiled
// in rather than negotiated by the pool protocol. Moving it means shipping a
// forked miner.
func TestThePoWBlobIsTheLayoutXMRigExpects(t *testing.T) {
	h := blobHeader()
	in := h.PoWInput()

	if len(in) != 43 {
		t.Fatalf("the blob is %d bytes, want 43: XMRig's nonce write at byte 39 needs "+
			"four bytes to land in", len(in))
	}

	seed := h.PoWSeed()
	if !bytes.Equal(in[0:32], seed[:]) {
		t.Fatalf("bytes 0..31 are not PoWSeed(): got %x, want %x", in[0:32], seed[:])
	}

	if got := binary.LittleEndian.Uint32(in[39:43]); got != h.PoW.Nonce {
		t.Fatalf("bytes 39..42 read as %#x, want the nonce %#x little-endian",
			got, h.PoW.Nonce)
	}
}

// TestTheReservedBytesAreZero pins the consensus rule that bytes 32..38 of the
// blob are zero.
//
// **The rule binds implementations of PoWInput, not headers.** No header field
// can reach those seven bytes — they are written by the constructor and derived
// from nothing — so there is no block a node could receive that violates it and
// no fold rule that could reject one. That is exactly why the rule has to be
// stated somewhere a second implementation will look: an implementation that
// filled the gap with a nonce's high bytes, a version byte, or an
// uninitialised buffer would compute a different digest for the same header and
// fork on its first block, and nothing in the corpus of *blocks* can catch it.
// What would make it binding on an implementation that never runs this test is
// a golden vector over the blob itself — the 43 bytes and the digest they
// produce, cross-checked against stock XMRig. **That vector does not exist
// yet**, so this test and docs/ARCHITECTURE.md §12 are the whole of the hold
// today, and both reach only this tree.
//
// It is asserted over a header whose every field is non-zero, so that the gap
// being zero is a fact about the layout and not about the input.
func TestTheReservedBytesAreZero(t *testing.T) {
	h := blobHeader()
	in := h.PoWInput()

	for i := 32; i < 39; i++ {
		if in[i] != 0 {
			t.Fatalf("blob byte %d is %#x, want zero: bytes 32..38 are reserved and "+
				"pinned at zero, so that the gap between the seed and XMRig's nonce "+
				"offset can never become a place to put something", i, in[i])
		}
	}

	// The gap must stay zero across the whole nonce space, which is the way a
	// wider nonce would show up here: an eight-byte write at offset 32 puts the
	// nonce's low bytes in the gap and passes the loop above for small nonces.
	for _, n := range []uint32{0, 1, math.MaxUint32} {
		h.PoW.Nonce = n
		got := h.PoWInput()
		if !bytes.Equal(got[32:39], make([]byte, 7)) {
			t.Fatalf("nonce %#x leaked into the reserved bytes: %x", n, got[32:39])
		}
	}
}

// TestTheBlobConstantsMatchTheBytes closes the gap the test above leaves open
// on purpose: those assertions use literals so that editing a constant cannot
// make them pass, which means nothing yet says the constants describe the blob.
// This says it, and it is the only test here allowed to read them.
func TestTheBlobConstantsMatchTheBytes(t *testing.T) {
	if types.PoWInputSize != 43 {
		t.Fatalf("PoWInputSize is %d, want 43", types.PoWInputSize)
	}
	if types.PoWInputNonceOffset != 39 {
		t.Fatalf("PoWInputNonceOffset is %d, want 39", types.PoWInputNonceOffset)
	}
	if types.PoWInputReservedOffset != 32 {
		t.Fatalf("PoWInputReservedOffset is %d, want 32", types.PoWInputReservedOffset)
	}
	if types.PoWInputReservedSize != 7 {
		t.Fatalf("PoWInputReservedSize is %d, want 7", types.PoWInputReservedSize)
	}
	// The reserved run and the nonce must exactly tile the blob after the seed.
	// A layout whose pieces do not add up is one where some byte of the blob is
	// written by nobody, and an unwritten byte is a fork waiting for whichever
	// implementation initialises its buffer differently.
	if got := types.PoWInputReservedOffset + types.PoWInputReservedSize + 4; got != types.PoWInputSize {
		t.Fatalf("the layout does not tile: 32 + %d reserved + 4 nonce = %d, blob is %d",
			types.PoWInputReservedSize, got, types.PoWInputSize)
	}
}

// TestExtraNonceIsInsideTheSeedAndTheNonceIsNot is the property that makes a
// 32-bit nonce survivable, and it is a pair of claims that must both hold.
//
// Nonce is OUT of the seed: that is what lets a miner hash the header once per
// candidate block instead of once per attempt, and PoWSeed exists for it.
//
// ExtraNonce is IN: every value of it is a distinct seed, so a pool handing one
// value per connection hands each miner a disjoint 2^32 nonce space. Monero
// pools obtain the same separation by varying tx_extra in the coinbase
// transaction, which this chain does not have. Zeroing ExtraNonce here — the
// obvious symmetry, and the wrong one — would collapse every miner onto one
// seed and silently un-shard every pool on the network while breaking no test
// that was not looking for it. This is that test.
func TestExtraNonceIsInsideTheSeedAndTheNonceIsNot(t *testing.T) {
	h := blobHeader()
	h.PoW.Nonce = 0
	h.PoW.ExtraNonce = 0
	base := h.PoWSeed()

	h.PoW.Nonce = 0xFFFFFFFF
	if h.PoWSeed() != base {
		t.Fatal("the seed changed with the nonce; a miner would have to re-hash the " +
			"header once per attempt, which is the cost PoWSeed exists to avoid")
	}

	h.PoW.Nonce = 0
	h.PoW.ExtraNonce = 1
	if h.PoWSeed() == base {
		t.Fatal("the seed did not change with ExtraNonce; every pooled miner would " +
			"search the same 2^32 space as every other, and a pool would have no way " +
			"to shard work across stock miners")
	}
}

// TestTheSealStillFitsTheHeaderWidth is the invariant the whole seal split was
// drawn around: two uint32s where there was one uint64, so the encoding does
// not move.
//
// It is not a courtesy check. HeaderSize is the fixed frame node/p2p builds its
// header batches, its announce sizing and its egress ceilings on; a header that
// changed width would move every one of those offsets and turn a blob-layout
// change into a wire change. The number is asserted as a literal for the same
// reason the blob offsets are: reading HeaderSize to check HeaderSize proves
// nothing.
func TestTheSealStillFitsTheHeaderWidth(t *testing.T) {
	if types.PoWSealSize != 16 {
		t.Fatalf("PoWSealSize is %d, want 16: Nonce(4) + ExtraNonce(4) + SeedEpoch(8)",
			types.PoWSealSize)
	}
	if types.HeaderSize != 228 {
		t.Fatalf("HeaderSize is %d, want 228; the seal split must not move the header",
			types.HeaderSize)
	}
	if got := len(blobHeader().MarshalSSZ()); got != 228 {
		t.Fatalf("a marshalled header is %d bytes, want 228", got)
	}
}

// TestTheSealDecodesTheHalvesInOrder pins which four bytes of the seal are
// which. Nonce first, then ExtraNonce, then SeedEpoch — and the two 32-bit
// halves are interchangeable in width, so a codec that swapped them round-trips
// perfectly and is caught by nothing else in this package.
//
// The consequence of the swap is worth stating because it is not obvious: a
// verifier that read them backwards would zero the wrong half in PoWSeed, so
// the field the miner searches would be inside the seed and the field it never
// touches would be outside. Every block that node produced would still verify
// against itself and against nothing else.
func TestTheSealDecodesTheHalvesInOrder(t *testing.T) {
	s := types.PoWSeal{Nonce: 0x11223344, ExtraNonce: 0x55667788, SeedEpoch: 0x99}
	enc := s.MarshalSSZ()
	if len(enc) != types.PoWSealSize {
		t.Fatalf("the seal encoded to %d bytes, want %d", len(enc), types.PoWSealSize)
	}
	if got := binary.LittleEndian.Uint32(enc[0:4]); got != s.Nonce {
		t.Fatalf("bytes 0..3 are %#x, want the nonce %#x", got, s.Nonce)
	}
	if got := binary.LittleEndian.Uint32(enc[4:8]); got != s.ExtraNonce {
		t.Fatalf("bytes 4..7 are %#x, want ExtraNonce %#x", got, s.ExtraNonce)
	}
	if got := binary.LittleEndian.Uint64(enc[8:16]); got != s.SeedEpoch {
		t.Fatalf("bytes 8..15 are %#x, want SeedEpoch %#x", got, s.SeedEpoch)
	}

	back, err := types.UnmarshalPoWSeal(enc)
	if err != nil {
		t.Fatal(err)
	}
	if back != s {
		t.Fatalf("round trip gave %+v, want %+v", back, s)
	}
}
