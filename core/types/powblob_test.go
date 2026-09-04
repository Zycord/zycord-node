package types_test

import (
	"bytes"
	"encoding/binary"
	"math"
	"testing"

	"zycord/core/types"
	"zycord/core/u256"
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
// What makes it binding on an implementation that never runs this test is the
// cross-check in core/pow/randomx, which rebuilds these 43 bytes from XMRig's
// own published offsets and compares them byte for byte. This test still earns
// its place: it needs no cgo and no build tag, so it runs in every ordinary
// `go test` and fails first and fastest when the gap moves.
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

// TestPoWHashIsOutsideTheSeedAndEveryOtherFieldIsInside is the companion claim
// for the field the commitment rule added, and it is two properties that are
// wrong in opposite directions if either is dropped.
//
// **PoWHash is OUT of the seed, and without that the definition does not
// exist.** The seed is hashed to make the blob, the blob is hashed to make
// PoWHash — so a PoWHash inside the seed's preimage would make the seed a
// function of itself. Not merely awkward: there would be no value a miner could
// write into the field that satisfies it, every header would be invalid, and
// the chain would not start.
//
// **Every OTHER field is IN, and this is the half a reader is likely to assume
// rather than check.** PoWSeed zeroes exactly two fields — Nonce and PoWHash —
// and a third zeroing added by symmetry would be grinding space: a field the
// miner can vary without changing the seed is a field it can search for free,
// outside the 2^32 the nonce gives it. Sweeping every field is what makes this
// a claim about the whole header rather than about the two lines somebody
// happened to look at.
//
// **The ordering consequence is what a test author trips over**, so it is
// stated here where the property is: PoWSeed covers CertRoot, CitesRoot,
// StateRoot, Target, Time and the rest, so a header sealed BEFORE any of those
// is written carries a stale digest and fails CheckWork's identity half. Seal
// last.
func TestPoWHashIsOutsideTheSeedAndEveryOtherFieldIsInside(t *testing.T) {
	base := blobHeader()
	base.PoW.Nonce = 0
	base.PoWHash = types.Hash{}
	want := base.PoWSeed()

	// Out: changing the digest must not move the seed.
	moved := base
	for i := range moved.PoWHash {
		moved.PoWHash[i] = 0xA5
	}
	if moved.PoWSeed() != want {
		t.Fatal("the seed changed with PoWHash: the seed would then be a function " +
			"of the digest that is a function of the seed, no value would satisfy " +
			"it, and no header could ever be valid")
	}

	// In: every other field must move the seed. Each mutation is applied to a
	// fresh copy of the base, so a field that is silently ignored cannot be
	// masked by an earlier one.
	for _, m := range []struct {
		name string
		set  func(*types.Header)
	}{
		{"Version", func(h *types.Header) { h.Version ^= 1 }},
		{"Height", func(h *types.Header) { h.Height ^= 1 }},
		{"ParentID", func(h *types.Header) { h.ParentID[0] ^= 1 }},
		{"Time", func(h *types.Header) { h.Time ^= 1 }},
		{"CertRoot", func(h *types.Header) { h.CertRoot[0] ^= 1 }},
		{"CitesRoot", func(h *types.Header) { h.CitesRoot[0] ^= 1 }},
		{"StateRoot", func(h *types.Header) { h.StateRoot[0] ^= 1 }},
		{"EmissionAddr", func(h *types.Header) { h.EmissionAddr[0] ^= 1 }},
		{"PoW.ExtraNonce", func(h *types.Header) { h.PoW.ExtraNonce ^= 1 }},
		{"PoW.SeedEpoch", func(h *types.Header) { h.PoW.SeedEpoch ^= 1 }},
		// Target is ADDED to rather than subtracted from, because blobHeader
		// leaves it zero and a saturating subtraction from zero is a no-op —
		// which reports "Target is outside the seed" for a header that never
		// varied it. The first run of this test said exactly that, and the
		// field was innocent.
		{"Target", func(h *types.Header) { h.Target, _ = h.Target.Add(u256.One) }},
	} {
		h := base
		m.set(&h)
		if h.PoWSeed() == want {
			t.Errorf("the seed did not change with %s: that field is outside the "+
				"seed's preimage, so a miner can vary it for free — grinding space "+
				"beyond the 2^32 the nonce gives it, at no cost in hashes", m.name)
		}
	}
}

// TestTheSealStillFitsTheHeaderWidth pins the seal's width and the header's.
//
// The seal half is the invariant the seal split was drawn around: two uint32s
// where there was one uint64, so splitting Nonce from ExtraNonce moved nothing.
// That still holds and is still worth asserting on its own — it is a different
// claim from the header's total width, and it is the one the split was about.
//
// **The header width itself moved, from 228 to 260, and this test is where that
// is recorded as intended rather than discovered as a symptom.** The commitment
// work rule needs the RandomX digest present in the header (types.Header's
// PoWHash), because a verifier forms the commitment from it and the whole point
// is to do that without evaluating RandomX. 32 bytes is the price and there is
// no smaller one: the commitment is BLAKE2b over the full digest, so a
// truncated field would not reproduce it.
//
// What that costs is real and is not hidden. HeaderSize is the fixed frame
// node/p2p builds its header batches, its announce sizing and its egress
// ceilings on, so every one of those is 14% larger — a 512-header response goes
// from 116,736 to 133,120 bytes. It stays far under the wire ceilings, and the
// arithmetic is re-derived where it is quoted rather than left to drift.
//
// Both numbers are asserted as literals for the same reason the blob offsets
// are: reading HeaderSize to check HeaderSize proves nothing.
func TestTheSealStillFitsTheHeaderWidth(t *testing.T) {
	if types.PoWSealSize != 16 {
		t.Fatalf("PoWSealSize is %d, want 16: Nonce(4) + ExtraNonce(4) + SeedEpoch(8)",
			types.PoWSealSize)
	}
	if types.HeaderSize != 260 {
		t.Fatalf("HeaderSize is %d, want 260 (228 + the 32-byte PoWHash the "+
			"commitment rule needs); if this moved for any other reason, say why",
			types.HeaderSize)
	}
	if got := len(blobHeader().MarshalSSZ()); got != 260 {
		t.Fatalf("a marshalled header is %d bytes, want 260", got)
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
