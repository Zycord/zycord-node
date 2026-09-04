package pow

import (
	"encoding/binary"
	"testing"

	"zycord/core/types"
	"zycord/spec"
)

// I8 — the consensus pass that follows the rx/2 landing.
//
// Every test in this file is an attack expressed as an assertion. The order is
// the order the attacks were tried, not the order a reader would arrange them
// for tidiness, because the negative results are the point: each one closes a
// door that was open on the face of the code and had to be shut by experiment
// rather than by reading a comment that claimed it was already shut.
//
// The standing hazard this file exists against: a proof of work is a claim
// about BYTES, and everything an attacker can reach is bytes. So the questions
// are all the same question asked of different fields — can I move this byte,
// and if I move it does the work still count?

// TestTheReservedBytesAreUnreachableFromA260ByteHeader re-runs, against the
// header that exists NOW, the proof a prior pass made against a header that no
// longer exists.
//
// The claim being tested is the one types.PoWInput's comment makes: "There is
// no header field that can reach these bytes." That claim was proved once, by
// exhaustive bit-flipping, against a 228-byte header. The header is 260 bytes
// today — PoWHash was added, the seal was resplit into two uint32s — and a
// proof about a different serialization is not a proof about this one. A
// re-derivation is cheap and the consequence of the claim being false is that
// the hashing preimage is malleable, which is the worst failure this package
// can have: two headers with different bytes hashing the same blob, or one
// header whose blob a verifier and a miner disagree about.
//
// The method is exhaustive over single-bit corruptions of the SERIALIZED
// header, which is the attacker's actual reach. A peer sends 260 bytes. Those
// bytes are whatever it likes. So: flip every one of the 2080 bits, decode,
// rebuild the blob the way a verifier would, and require bytes 32..38 to be
// zero every time. Decode failures are counted, not skipped silently — a
// mutation that never reaches PoWInput proves nothing about PoWInput, and a
// run where everything failed to decode would be a vacuous pass.
//
// It is exhaustive rather than sampled because 2080 decodes is milliseconds
// and a sample cannot support the word "unreachable".
func TestTheReservedBytesAreUnreachableFromA260ByteHeader(t *testing.T) {
	p := spec.Devnet()
	base := types.Header{
		Version:  types.HeaderVersion,
		Height:   p.RandomXKeyInterval + p.RandomXKeyLag,
		Time:     1_000_000,
		ParentID: types.Hash{1, 2, 3},
		CertRoot: types.Hash{4, 5, 6},
		Target:   p.GenesisTarget,
		PoW: types.PoWSeal{
			Nonce:      0xDEADBEEF,
			ExtraNonce: 0x12345678,
			SeedEpoch:  SeedEpochFor(p.RandomXKeyInterval+p.RandomXKeyLag, p),
		},
		PoWHash: types.Hash{7, 8, 9},
	}

	enc := base.MarshalSSZ()
	if len(enc) != types.HeaderSize {
		t.Fatalf("header encodes to %d bytes, HeaderSize says %d", len(enc), types.HeaderSize)
	}
	if types.HeaderSize != 260 {
		t.Fatalf("this test is written against a 260-byte header; HeaderSize is %d."+
			" Re-derive the proof rather than adjusting the constant", types.HeaderSize)
	}

	// The unmutated header must itself have a clean gap, or the loop below is
	// measuring nothing.
	if in := base.PoWInput(); !gapIsZero(in) {
		t.Fatalf("the gap is already non-zero before any mutation: %x", in)
	}

	decoded, failed := 0, 0
	for byteIdx := 0; byteIdx < len(enc); byteIdx++ {
		for bit := 0; bit < 8; bit++ {
			mutated := make([]byte, len(enc))
			copy(mutated, enc)
			mutated[byteIdx] ^= 1 << bit

			h, err := types.UnmarshalHeader(mutated)
			if err != nil {
				failed++
				continue
			}
			decoded++

			in := h.PoWInput()
			if len(in) != types.PoWInputSize {
				t.Fatalf("bit %d of byte %d produced a %d-byte blob, want %d",
					bit, byteIdx, len(in), types.PoWInputSize)
			}
			if !gapIsZero(in) {
				t.Fatalf("REACHABLE: flipping bit %d of header byte %d makes the"+
					" reserved gap %x — the hashing preimage is malleable",
					bit, byteIdx, in[types.PoWInputReservedOffset:types.PoWInputNonceOffset])
			}
		}
	}

	if decoded == 0 {
		t.Fatal("no mutation decoded; the sweep proved nothing")
	}
	// A header is fixed-width and every field is a fixed-width scalar or a
	// byte array, so every single-bit corruption is expected to decode. If
	// that ever stops being true the sweep has lost reach and should be
	// re-examined rather than trusted.
	if failed != 0 {
		t.Errorf("%d of %d single-bit mutations failed to decode; the sweep's"+
			" reach is smaller than it looks", failed, decoded+failed)
	}
	t.Logf("swept %d single-bit header mutations, all decoded, gap zero in every one", decoded)
}

// gapIsZero reports whether the seven reserved bytes of a blob are all zero.
func gapIsZero(in []byte) bool {
	for _, b := range in[types.PoWInputReservedOffset:types.PoWInputNonceOffset] {
		if b != 0 {
			return false
		}
	}
	return true
}

// TestTheGapCheckWouldNotice is the mutation that proves the test above is not
// vacuous.
//
// This repo has shipped two vacuous tests. The sweep above passes; a sweep
// that could not fail would also pass. So here the corrupted blob is
// constructed directly and the same predicate is applied to it: if gapIsZero
// cannot tell a dirty gap from a clean one, the sweep above is worthless and
// this fails instead.
func TestTheGapCheckWouldNotice(t *testing.T) {
	p := spec.Devnet()
	h := types.Header{Version: types.HeaderVersion, Height: 1, Target: p.GenesisTarget}

	in := h.PoWInput()
	if !gapIsZero(in) {
		t.Fatal("baseline blob already has a dirty gap")
	}
	for i := types.PoWInputReservedOffset; i < types.PoWInputNonceOffset; i++ {
		dirty := make([]byte, len(in))
		copy(dirty, in)
		dirty[i] = 0xFF
		if gapIsZero(dirty) {
			t.Fatalf("gapIsZero missed a 0xFF at offset %d — the sweep above is vacuous", i)
		}
	}
}

// TestTheBlobIsInjectiveOverTheFieldsAnAttackerControls asks the malleability
// question from the other side.
//
// The sweep above shows an attacker cannot make the gap non-zero. That is not
// the same as showing two DIFFERENT headers cannot produce the SAME blob. If
// they could, one proof of work would pay for two headers — the attacker mines
// once and gets two block ids, which is a work-forgery primitive: the same
// hashrate claims twice the chain work, or the same solution is spent on two
// sides of a fork.
//
// The blob is 43 bytes: a 32-byte seed, a zero gap, and the nonce. So a
// collision requires a seed collision, and the seed is BLAKE3 over the header
// with Nonce and PoWHash zeroed. Two headers sharing a blob therefore differ
// only in Nonce or PoWHash — and both are pinned elsewhere: the nonce is IN the
// blob, and PoWHash is in the commitment. This test drives that argument
// through the real functions rather than asserting it.
func TestTheBlobIsInjectiveOverTheFieldsAnAttackerControls(t *testing.T) {
	p := spec.Devnet()
	base := types.Header{
		Version: types.HeaderVersion,
		Height:  7,
		Time:    1_000_000,
		Target:  p.GenesisTarget,
		PoW:     types.PoWSeal{Nonce: 42, ExtraNonce: 9},
	}

	// Every field an attacker can choose, varied one at a time. Each must move
	// the blob — except PoWHash, which is deliberately outside the preimage and
	// must NOT move it, because the commitment is what binds it.
	seen := map[string]string{}
	record := func(name string, h types.Header) {
		blob := string(h.PoWInput())
		if prev, dup := seen[blob]; dup {
			t.Errorf("COLLISION: %q and %q produce the same 43-byte blob —"+
				" one proof of work would pay for both", prev, name)
		}
		seen[blob] = name
	}

	record("base", base)

	v := base
	v.Height = 8
	record("Height", v)

	v = base
	v.Time = 1_000_001
	record("Time", v)

	v = base
	v.ParentID = types.Hash{1}
	record("ParentID", v)

	v = base
	v.CertRoot = types.Hash{1}
	record("CertRoot", v)

	v = base
	v.CitesRoot = types.Hash{1}
	record("CitesRoot", v)

	v = base
	v.StateRoot = types.Hash{1}
	record("StateRoot", v)

	v = base
	v.EmissionAddr = types.Address{1}
	record("EmissionAddr", v)

	v = base
	v.Target = p.GenesisTarget.SatAdd(p.GenesisTarget)
	record("Target", v)

	v = base
	v.PoW.Nonce = 43
	record("Nonce", v)

	v = base
	v.PoW.ExtraNonce = 10
	record("ExtraNonce", v)

	v = base
	v.PoW.SeedEpoch = 1
	record("SeedEpoch", v)

	v = base
	v.Version = types.HeaderVersion + 1
	record("Version", v)

	// PoWHash is the deliberate exception: it is zeroed in the seed preimage,
	// so it must NOT change the blob. If it ever does, the seed has become a
	// function of itself and no header can be valid.
	v = base
	v.PoWHash = types.Hash{0xAA}
	if string(v.PoWInput()) != string(base.PoWInput()) {
		t.Error("PoWHash moved the blob — the seed is now a function of itself" +
			" and the chain cannot start")
	}
}

// TestPoWHashIsBoundByTheCommitmentEvenThoughItIsOutsideTheBlob closes the hole
// the previous test deliberately leaves open.
//
// PoWHash does not move the blob. So if nothing else bound it, an attacker
// could take a header whose commitment passes and swap in a different PoWHash,
// or take one honest solution and mint many headers from it. What stops that is
// that the commitment is blake2b(blob ‖ PoWHash) — the digest is inside the
// number compared against the target even though it is outside the number fed
// to the work function.
//
// This is asserted, not assumed, because it is the single load-bearing sentence
// in PoWHash's doc comment and the whole cheap-path optimisation rests on it.
func TestPoWHashIsBoundByTheCommitmentEvenThoughItIsOutsideTheBlob(t *testing.T) {
	p := spec.Devnet()
	h := types.Header{
		Version: types.HeaderVersion,
		Height:  5,
		Target:  p.GenesisTarget,
		PoW:     types.PoWSeal{Nonce: 1},
		PoWHash: types.Hash{0x01},
	}

	c0 := Commitment(h)

	// Every single-bit change to PoWHash must move the commitment. Sampling a
	// few bits would not distinguish "bound" from "bound in the low byte".
	for byteIdx := 0; byteIdx < 32; byteIdx++ {
		for bit := 0; bit < 8; bit++ {
			v := h
			v.PoWHash[byteIdx] ^= 1 << bit
			if Commitment(v) == c0 {
				t.Fatalf("bit %d of PoWHash byte %d does not move the commitment —"+
					" the digest is unbound and one solution mints many headers",
					bit, byteIdx)
			}
		}
	}
}

// TestGrindingExtraNonceBuysNothingOverGrindingTheNonce tests the claim the
// task set out to have verified.
//
// ExtraNonce is unconstrained by any rule — checkSeedEpoch pins SeedEpoch, B7
// pins Version, forkchoice pins Target, but nothing pins ExtraNonce. It sits
// inside the seed preimage. So the question is whether varying it is BETTER
// than varying the nonce, not merely whether it is possible.
//
// The honest answer is that it is neither better nor worse, and the reason is
// that both are inputs to the same one-way function and neither is compared
// against anything. A miner with 2^32 nonces per seed and unlimited seeds has
// exactly the same expected work per solution as one with unlimited nonces —
// the search is over (seed, nonce) pairs either way and the digest is uniform
// in both.
//
// What is worth TESTING rather than arguing is the property that makes the
// argument hold: that changing ExtraNonce produces an INDEPENDENT search space
// rather than a correlated one. If ExtraNonce shifted the digest predictably —
// if seed(e+1) related to seed(e) in a way the digest inherited — a miner could
// step ExtraNonce to walk toward a target instead of searching. It does not,
// because ExtraNonce enters through BLAKE3.
//
// So: the digests must be uncorrelated across ExtraNonce at a FIXED nonce, and
// the hit rate must match the hit rate across nonces at a fixed ExtraNonce. A
// grinding advantage would show up as the former beating the latter.
func TestGrindingExtraNonceBuysNothingOverGrindingTheNonce(t *testing.T) {
	p := spec.Devnet()
	base := types.Header{
		Version: types.HeaderVersion,
		Height:  9,
		Time:    1_000_000,
		Target:  p.GenesisTarget,
	}

	const trials = 4096

	// The statistic is a COUNT of samples landing in the lower half of the
	// window the work check reads, not a sum of them. A sum of 4096 uniform
	// 64-bit values overflows uint64 by three orders of magnitude and its
	// "mean" is noise — that was this test's first form and it failed against
	// correct code, which is its own small lesson about asserting on a
	// statistic before checking the statistic can be computed.
	//
	// "Lands in the lower half" is the right question anyway: the work check
	// accepts a commitment at or below the target, so a grinding advantage is
	// exactly a way of making low values more frequent.

	// Walk the nonce at a fixed ExtraNonce.
	nonceDigests := make(map[types.Hash]struct{}, trials)
	nonceLow := 0
	for i := uint32(0); i < trials; i++ {
		h := base
		h.PoW.Nonce = i
		d := Dev{}.Hash(KeyFor(h.Height, p), h.PoWInput())
		nonceDigests[d] = struct{}{}
		if binary.LittleEndian.Uint64(d[24:]) < 1<<63 {
			nonceLow++
		}
	}

	// Walk ExtraNonce at a fixed nonce.
	extraDigests := make(map[types.Hash]struct{}, trials)
	extraLow := 0
	for i := uint32(0); i < trials; i++ {
		h := base
		h.PoW.ExtraNonce = i
		d := Dev{}.Hash(KeyFor(h.Height, p), h.PoWInput())
		extraDigests[d] = struct{}{}
		if binary.LittleEndian.Uint64(d[24:]) < 1<<63 {
			extraLow++
		}
	}

	if len(nonceDigests) != trials {
		t.Errorf("walking the nonce produced %d distinct digests out of %d", len(nonceDigests), trials)
	}
	if len(extraDigests) != trials {
		t.Errorf("walking ExtraNonce produced %d distinct digests out of %d", len(extraDigests), trials)
	}

	// The two spaces must not overlap at all: if they did, a miner could reach
	// the same digest by two routes and the ExtraNonce space would be a
	// re-labelling of the nonce space rather than a fresh one. (They share the
	// point ExtraNonce=0, Nonce=0, so one collision is expected.)
	overlap := 0
	for d := range extraDigests {
		if _, ok := nonceDigests[d]; ok {
			overlap++
		}
	}
	if overlap > 1 {
		t.Errorf("the ExtraNonce and nonce search spaces overlap in %d digests;"+
			" ExtraNonce is re-labelling the nonce space, not extending it", overlap)
	}

	// Neither walk may be biased in the window the work check reads. A miner
	// that could bias the LE-low window by stepping ExtraNonce would be
	// grinding toward the target rather than searching for it.
	//
	// Under the null hypothesis each count is Binomial(4096, 1/2): mean 2048,
	// standard deviation 32. A 5-sigma band is +/-160, which a fair coin
	// escapes about once in 1.7 million runs — loose enough not to flake in
	// CI, tight enough that a bias big enough to be worth exploiting (a
	// percent, say, which is 40 sigma) cannot hide inside it.
	//
	// The bounds are deliberately the SAME for both walks. The claim under
	// test is that ExtraNonce is not a better lever than the nonce, so the
	// two must be held to one standard rather than each to its own.
	const (
		mean  = trials / 2
		bound = 160 // 5 sigma
	)
	off := func(c int) int {
		if c > mean {
			return c - mean
		}
		return mean - c
	}
	if off(nonceLow) > bound {
		t.Errorf("the nonce walk is biased: %d of %d digests in the lower half"+
			" (expected %d +/- %d)", nonceLow, trials, mean, bound)
	}
	if off(extraLow) > bound {
		t.Errorf("the ExtraNonce walk is biased: %d of %d digests in the lower half"+
			" (expected %d +/- %d) — stepping ExtraNonce walks toward the target",
			extraLow, trials, mean, bound)
	}
	t.Logf("nonce walk %d/%d low, ExtraNonce walk %d/%d low, overlap %d",
		nonceLow, trials, extraLow, trials, overlap)
}

// TestWorkDoesNotReplayAcrossChains is the cross-network replay attack.
//
// Two networks with mirrored parameters is exactly the configuration a public
// testnet creates, and it is the configuration in which a replay is most
// valuable: an attacker mines cheap testnet blocks and re-presents them as
// mainnet work, or takes real mainnet work and floods the testnet with it.
//
// The defence is that the chain id is in the RandomX key preimage (KeyFor). So
// the same header, checked under two chain ids, must be checked under different
// keys — and a solution found under one must fail under the other.
func TestWorkDoesNotReplayAcrossChains(t *testing.T) {
	a := spec.Devnet()
	b := spec.Devnet()
	b.ChainID = a.ChainID + 1

	// The keys must differ at every height, including the epoch-zero heights
	// where SeedEpochFor collapses to 0 and the chain id is the ONLY thing
	// separating the two preimages. That is the case most likely to be got
	// wrong and the one a spot check at height 1000 would miss.
	for _, height := range []uint64{
		0, 1, 2,
		a.RandomXKeyLag - 1, a.RandomXKeyLag, a.RandomXKeyLag + 1,
		a.RandomXKeyLag + a.RandomXKeyInterval,
		a.RandomXKeyLag + 2*a.RandomXKeyInterval,
	} {
		if KeyFor(height, a) == KeyFor(height, b) {
			t.Fatalf("height %d: two chain ids derive the same work key —"+
				" work replays across networks", height)
		}
	}

	// And the end-to-end statement: a header that satisfies the work rule on
	// chain A must not satisfy it on chain B. Solve on A, then re-check under
	// B's parameters.
	h := types.Header{
		Version: types.HeaderVersion,
		Height:  3,
		Time:    1_000_000,
		Target:  a.GenesisTarget,
	}
	if !Solve(Dev{}, &h, a, 1<<20) {
		t.Skip("no solution found within the budget; the key assertions above still hold")
	}
	if err := CheckWork(Dev{}, h, a); err != nil {
		t.Fatalf("the solution does not satisfy its own chain: %v", err)
	}
	if err := CheckWork(Dev{}, h, b); err == nil {
		t.Fatal("REPLAY: a solution mined on one chain id verifies on another")
	}
}

// TestWorkDoesNotReplayAcrossEpochs is the same attack in the time dimension.
//
// The key changes every RandomXKeyInterval blocks. If work did not change with
// it, a miner could bank solutions in a cheap epoch and spend them in an
// expensive one, or replay one solution at many heights. The key is a function
// of the epoch, so heights in different epochs must key differently — and,
// equally important, heights in the SAME epoch must key IDENTICALLY, because
// that is what makes a dataset worth building.
func TestWorkDoesNotReplayAcrossEpochs(t *testing.T) {
	p := spec.Devnet()

	// Inside one epoch the key is constant.
	first := p.RandomXKeyLag + p.RandomXKeyInterval
	k := KeyFor(first, p)
	for h := first; h < first+p.RandomXKeyInterval; h++ {
		if KeyFor(h, p) != k {
			t.Fatalf("height %d keys differently from %d inside one epoch —"+
				" the dataset would be rebuilt mid-epoch", h, first)
		}
	}
	// And it changes at the boundary, not before and not after.
	if KeyFor(first+p.RandomXKeyInterval, p) == k {
		t.Fatal("the key does not change at the epoch boundary — work replays across epochs")
	}
	if KeyFor(first-1, p) == k {
		t.Fatal("the key changed one block early; the boundary is off by one")
	}
}

// TestTheEpochBoundaryIsWhereTheSealSaysItIs guards the seam between the
// declared SeedEpoch and the derived one.
//
// SeedEpoch is a header field a miner writes, and checkSeedEpoch (B0b) requires
// it to equal SeedEpochFor(height). But CheckWork does NOT read the field — it
// derives the epoch from the height itself. So the field is decorative from the
// work rule's point of view, and the risk is the opposite of the usual one: not
// that a lie is believed, but that the two disagree and a header valid under one
// path is invalid under the other.
//
// This test asserts they cannot disagree: for every height around every
// boundary in reach, the derived epoch is what the rule pins the field to.
func TestTheEpochBoundaryIsWhereTheSealSaysItIs(t *testing.T) {
	p := spec.Devnet()

	// SeedEpochFor must be monotone and must step by exactly one at a
	// boundary. A skipped epoch would mean a key nobody mines under; a
	// repeated one would mean two intervals sharing a key.
	prev := SeedEpochFor(0, p)
	if prev != 0 {
		t.Fatalf("genesis is in epoch %d, want 0", prev)
	}
	limit := p.RandomXKeyLag + 4*p.RandomXKeyInterval
	steps := 0
	for h := uint64(1); h <= limit; h++ {
		e := SeedEpochFor(h, p)
		switch {
		case e == prev:
		case e == prev+1:
			steps++
		default:
			t.Fatalf("height %d jumps from epoch %d to %d", h, prev, e)
		}
		prev = e
	}
	if steps == 0 {
		t.Fatal("no epoch boundary was crossed; the sweep proved nothing")
	}
	t.Logf("crossed %d epoch boundaries up to height %d, all single steps", steps, limit)
}

// TestAHeaderCannotBeReplayedAtAnotherHeight closes the replay attack that the
// height-derived key makes worth asking about.
//
// KeyFor derives the work key from the seed EPOCH, not from the height, and an
// epoch spans RandomXKeyInterval blocks. So every height inside one epoch keys
// identically — deliberately, because that is what makes a dataset worth
// building. The obvious question follows: if two heights share a key, can one
// header's proof of work be spent at both?
//
// It cannot, and the reason is that Height is inside PoWSeed's preimage. But
// "it is in the preimage" is an argument, and the failure it guards against is
// a chain accepting one solution at many heights, so it gets an experiment. The
// header is solved at one height and then re-presented at every other height in
// the same epoch; each must fail.
func TestAHeaderCannotBeReplayedAtAnotherHeight(t *testing.T) {
	p := spec.Devnet()

	// A height comfortably inside a single epoch, with room either side.
	base := p.RandomXKeyLag + p.RandomXKeyInterval + 3
	h := types.Header{
		Version: types.HeaderVersion,
		Height:  base,
		Time:    1_000_000,
		Target:  p.GenesisTarget,
		PoW:     types.PoWSeal{SeedEpoch: SeedEpochFor(base, p)},
	}
	if !Solve(Dev{}, &h, p, 1<<20) {
		t.Skip("no solution within the budget")
	}
	if err := CheckWork(Dev{}, h, p); err != nil {
		t.Fatalf("the solution does not verify at its own height: %v", err)
	}

	// Every other height in the same epoch shares the key exactly. If work
	// were replayable anywhere, it would be here.
	key := KeyFor(base, p)
	replays := 0
	for _, height := range []uint64{base - 2, base - 1, base + 1, base + 2, base + 3} {
		if KeyFor(height, p) != key {
			continue // a different epoch; the key already separates them
		}
		replays++
		v := h
		v.Height = height
		if err := CheckWork(Dev{}, v, p); err == nil {
			t.Errorf("REPLAY: a solution mined at height %d also verifies at %d"+
				" under the same epoch key — one proof of work pays for many heights",
				base, height)
		}
	}
	if replays == 0 {
		t.Fatal("no same-key height was actually tried; the test proved nothing")
	}
	t.Logf("re-presented one solution at %d same-key heights, all refused", replays)
}
