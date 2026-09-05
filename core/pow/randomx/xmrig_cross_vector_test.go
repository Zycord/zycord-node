//go:build randomx

package randomx

import (
	"encoding/binary"
	"encoding/hex"
	"testing"

	"zycord/core/crypto/blake2b"
	"zycord/core/pow"
	"zycord/core/types"
	"zycord/core/u256"
	"zycord/spec"
)

// The cross-vector file: "our RandomX is exactly rx/0, and our blob is exactly
// the blob a stock miner searches", enforced rather than asserted in prose.
//
// docs/ARCHITECTURE.md §12 and core/types.PoWInput both said, in as many words,
// that no vector fixed the 43 bytes and their digest against stock XMRig, so
// the layout bound this tree and nothing else. This file is what removes that
// sentence. It is the only place in the repository where the encoding rules of
// §12 are checked against numbers that did not come out of this tree.
//
// # Where every constant below came from, and why that matters
//
// A vector computed with the implementation it is meant to check proves
// nothing: it restates the code in hexadecimal. So each anchor here names its
// source, and none of them is this repository.
//
//   - The (key, input, digest) triples are tevador/RandomX's own, from
//     src/tests/tests.cpp at the tag PINNED names (v2.0.1, commit
//     aaafe71322df6602c21a5c72937ac284724ae561). They are reproduced rather
//     than linked because upstream's test programs have their own mains and
//     the tests/ directory is deliberately not vendored.
//   - The commitment vector — key "test key 000", input "This is a test",
//     commitment 133be717… — is upstream's "Commitment test" at the same tag,
//     and it is the anchor for the whole rx/2 share pipeline.
//   - The commitment CONSTRUCTION (unkeyed BLAKE2b-256 over `input ‖ H`) is
//     randomx_calculate_commitment's three lines, transcribed in
//     xmrigCommitment below.
//   - That the target is compared against the COMMITMENT rather than the raw
//     digest is CpuWorker.cpp's, and xmrigWins carries the full derivation
//     from XMRig's source. It contradicts what both commissioning issues
//     assumed, so it is written out at the point of use rather than cited.
//   - The nonce offset 39, the nonce width 4, and the 43-byte minimum blob are
//     read off XMRig's own source: Job::nonceOffset() returns 39 for every
//     RandomX-family algorithm (32 is KAWPOW, 76 GHOSTRIDER, 147 RX_YADA),
//     Job::nonceSize() returns 4 for everything but KAWPOW, and Job::setBlob
//     refuses a blob shorter than nonceOffset() + nonceSize().
//   - The comparison rule is CpuWorker::start's, verbatim:
//     `const uint64_t value = *reinterpret_cast<uint64_t*>(m_hash + i*32 + 24);
//     if (value < job.target())`. Eight bytes at offset 24 of a 32-byte digest,
//     read as a native little-endian uint64. That is the top limb of
//     le256(digest), and it is the whole reason the work check reads the digest
//     little-endian.
//
// # What each tier proves, and what it cannot
//
// There are THREE tiers, ordered by how much of this tree they involve, and the
// separation is the point: a failure in tier 1 means the engine is not rx/0,
// while a failure in tier 2 means the engine is fine and the blob is wrong.
// Collapsing them into one test would make every failure say "something is
// wrong with proof of work".
//
// Tier 1 drives upstream's vectors through pow.Engine.Hash — the CONSENSUS
// interface, keyed by a 32-byte types.Hash — rather than through hashRaw.
// TestOfficialVectorsV2 already covers hashRaw, and it has to, because every
// upstream v2 key is a short string that no types.Hash can carry. But hashRaw
// is not the function consensus calls, and an Engine.Hash that mangled its key
// on the way down would leave TestOfficialVectorsV2 green. **Tier 1 was
// re-designed for rx/2 rather than ported, because upstream publishes no v2
// variant of test_f; TestTheConsensusInterfaceComputesUpstreamsFunction's own
// comment says exactly what it now anchors and what it does not.**
//
// Tier 2 is the cross-check proper. It builds the blob the way a stock miner
// would — take the 32-byte seed a pool served, zero everything up to byte 39,
// write the nonce there as four little-endian bytes, hand the 43 bytes to
// RandomX — using only the offsets read off XMRig's source above, and asserts
// the result is BYTE-IDENTICAL to what types.Header.PoWInput produced. Neither
// side reads a constant from the other. This is the assertion that would have
// caught a nonce at offset 32, a big-endian nonce, an eight-byte nonce, or a
// reserved gap filled with anything but zero.
//
// Tier 3 carries the comparison rule the same way: the winning verdict is
// computed once by pow.CheckWork and once by XMRig's `hash[24:32] as LE u64 <
// target` line, and the two must agree on the same nonces rather than merely
// both be plausible.
//
// # There is deliberately no recorded 43-byte digest, and a reader should know why
//
// The obvious fourth thing to do is write down one blob's digest as a hex
// constant and assert it. This file does not, and the omission is a decision
// rather than an oversight.
//
// No upstream vector is 43 bytes long, so such a constant could only be taken
// from THIS engine — which makes it a vector generated by the implementation it
// is meant to check, and that proves nothing beyond restating the code in
// hexadecimal. It would also freeze the wrong thing: it pins one (seed, nonce)
// pair, so it fails loudly when the test's own fixture header changes and stays
// silent about every layout error the fixture happens not to reach.
//
// What tier 2 does instead is stronger on exactly the axis a recorded digest is
// weak: it derives the bytes a SECOND way, from XMRig's published offsets alone,
// and compares all 43 of them for five nonces including both ends of the space.
// A recorded digest would be one sample of one input; the byte comparison is the
// whole string, and it names which byte is wrong when it fails.
//
// # Proven non-vacuous, and by which mutations
//
// A test that cannot fail is worse than no test, and the whole reason this file
// exists is that the check it replaces could not fail: for most of its life
// TestTheSolverAgreesWithCheckWork compared two BOOLEANS, and for almost every
// nonce both are false, so a solver with the nonce at the wrong offset or the
// digest read from the wrong end agreed with the rule on all but a vanishing
// fraction of 2^32 inputs and passed. Every assertion below therefore compares
// bytes, or compares verdicts only over a target loose enough that both
// verdicts occur — and where it compares verdicts it also asserts that both
// occurred, so the comparison cannot degenerate into two constants.
//
// Each mutation below was applied to the tree, run, and reverted. The point of
// recording them is that the next person to change the blob layout can re-run
// them rather than re-derive them.
//
//	M1  nonce offset 39 -> 32, blob 43 -> 36   killed (blob length)
//	M2  nonce offset 39 -> 38, blob still 43   killed (byte 38, three tests)
//	M3  nonce written big-endian at 39         killed (byte 39)
//	M4  reserved byte 32 set to 0x01           killed (gap, three tests)
//	M5  checkWorkWith back to FromBytes        killed (a stock miner's share refused)
//	M6  Solver.Try back to FromBytes           killed (first nonce, disjoint sets)
//	M7  eight-byte nonce written at offset 33  killed (gap and byte 33)
//	M8  PoWSeed zeroes ExtraNonce too          SURVIVES — see below
//	M9  Engine.Hash truncates its key to 31 B  killed (tier 1 alone)
//
// M1–M9 were run against the rx/0 tree and are claims about it until re-run.
// The rx/2 move added its own, run against THIS tree and recorded with the
// same discipline:
//
//	V1  Options.V2 ignored (flag never ORed)      killed (TestOfficialVectorsV2, tier 1)
//	V2  V2 on fastFlags only, not on flags        killed (TestLightAndFastAgreeUnderV2)
//	V3  Commitment computed as H ‖ input          killed (tiers 3 and 4)
//	V4  target compared against the raw H         killed (a stock miner's share refused)
//	V5  Solver commits over a zeroed blob         killed (solver/miner sets disjoint)
//	V6  PoWSeed stops zeroing PoWHash             killed (every header invalid)
//	V7  CheckWork drops the digest-identity half  SURVIVES here — see below
//
// Two of those deserve a line rather than a row. **V2 was found by mutation
// and had no test at all**: setting the flag on `fastFlags` alone gives a miner
// whose dataset computes rx/2 and whose verifier computes rx/0, and every test
// in this package used light engines, so nothing saw it.
// TestLightAndFastAgreeUnderV2 was written for it. **V3 is not caught by
// core/crypto/blake2b**, which correctly tests its own function and has no
// opinion about operand order at the call site; it is caught here, by the two
// tiers that reproduce XMRig's pipeline from XMRig's source.
//
// **V7 is recorded as a survivor rather than omitted.** Removing the
// `e.Hash(...) != h.PoWHash` check from checkWorkWith leaves every test in this
// file green, because every header this file builds carries the digest its own
// blob produces — the mismatch case is never constructed here. That is correct
// scoping and not a hole: this file's subject is agreement with XMRig, and a
// stock miner never submits a mismatched digest either. Where V7 IS caught is
// core/pow.TestWorkIsCheckedAgainstTheDeclaredTarget, which perturbs PoWHash by
// one bit under a target nothing can fail and requires ErrHashMismatch —
// confirmed to fail under V7.
//
// M5 and M6 are the two halves of the change this file was written behind, and
// M6 is the one worth dwelling on: it fails on the FIRST nonce tried, where the
// verdict-comparing test it supersedes would have needed a lucky share to
// notice. M9 is the reason tier 1 is not redundant with TestOfficialVectors —
// under M9 TestOfficialVectors still PASSES, because it calls hashRaw, and
// hashRaw is not what consensus calls.
//
// M8 is recorded as a SURVIVOR rather than omitted, because a mutation nothing
// here catches is a boundary worth writing down. Making PoWSeed zero ExtraNonce
// as well as Nonce — the obvious symmetry, and the wrong one, which would
// collapse every pooled miner onto one seed and silently un-shard every pool —
// passes every test in this file. That is correct scoping rather than a hole:
// this file takes PoWSeed() as an opaque thirty-two bytes on BOTH sides of
// every comparison, so it cannot see inside the seed preimage, and a test that
// could would be duplicating core/types.
//
// Where M8 IS caught is worth stating precisely, because one plausible answer
// is wrong. It is caught by core/types.TestExtraNonceIsInsideTheSeedAndTheNonceIsNot,
// confirmed — and since the commitment change, by
// core/types.TestPoWHashIsOutsideTheSeedAndEveryOtherFieldIsInside as well,
// which sweeps every header field against the seed rather than naming two. The
// second guard is not redundant: the first names ExtraNonce and would not have
// noticed a THIRD field being zeroed by the same symmetry argument, which is
// exactly the edit the commitment field invited. It is NOT caught by core/pow.TestTheSolverHashesTheHeadersOwnBlob,
// which passes under M8 despite a comment predicting otherwise — and for the
// same structural reason this file misses it: both sides of that comparison
// reach PoWSeed(), so a change INSIDE the seed moves them together and the
// bytes still match. Any test whose two sides both call PoWSeed is blind to the
// seed's preimage by construction, and only a test that varies ExtraNonce and
// watches the seed can see it.
//
// # Bytes, not verdicts
//
// Every tier compares BYTES. The vacuity that TestTheSolverAgreesWithCheckWork
// carried for most of its life — comparing two booleans, both of which are
// false for almost every nonce, so a wrong-offset or big-endian solver agreed
// with the rule on 2^32 minus a handful of inputs — is the exact failure mode
// this file is written against. A digest comparison has no such escape: there
// is one right answer out of 2^256 and a wrong implementation does not stumble
// onto it.

// TestTheConsensusInterfaceComputesUpstreamsFunction drives upstream vectors
// through pow.Engine.Hash, which is the function every work check in the tree
// calls, rather than through hashRaw, which is the function TestOfficialVectors
// calls and which nothing in consensus calls.
//
// # The rx/0 anchor could not be ported, and this is what replaced it
//
// The rx/0 version of this test was built on upstream's `test_f`, the ISUB_R
// edge case, chosen for a property unrelated to that bug: it is the only
// upstream vector whose key is thirty-two bytes of raw material rather than a
// short ASCII string, so it is the only one that can be handed to a
// types.Hash-keyed interface without changing what "the key" means.
//
// **Upstream publishes no v2 variant of test_f.** At v2.0.1 it asserts
// `78af2a18…` unconditionally and runs only in the v1 block; tests.cpp carries
// paired v1/v2 expectations for `test_a` through `test_e` and for nothing else.
// So the anchor had to be re-designed rather than re-run, and the honest
// statement of what it now anchors is below rather than in a commit message.
//
// # What IS anchored, and by what
//
// Three upstream constants, all from tevador/RandomX v2.0.1
// (aaafe71322df6602c21a5c72937ac284724ae561), src/tests/tests.cpp:
//
//  1. **The v2 function itself.** `test_a` through `test_d` under
//     RANDOMX_FLAG_V2 — key "test key 000"/"test key 001", the same inputs the
//     v1 vectors use, and DIFFERENT published digests. Reproduced in
//     officialVectorsV2 and checked through hashRaw, which is where a short
//     ASCII key can go. This is what says the engine computes rx/2 and not
//     rx/0 or something else.
//  2. **That rx/2 and rx/0 are different functions computed by one build.**
//     Upstream's own `test_switch` asserts `639183aa…` under v1 and
//     `22ec6b86…` under v2 for the same key and input. Asserted here across
//     two engines rather than by toggling a flag on one VM, because two
//     engines is what this tree actually constructs.
//  3. **The commitment.** Upstream's "Commitment test" —
//     `calcStringCommitment("test key 000", "This is a test")` =
//     `133be717…` — is the one vector that binds the whole rx/2 share pipeline
//     end to end: the v2 hash, the concatenation order, and unkeyed BLAKE2b.
//     It is checked in core/crypto/blake2b against upstream's own intermediate
//     H, and here against the H THIS ENGINE produces, which is the join
//     between the two halves.
//
// # What is NOT anchored, stated plainly
//
// **The interface-key claim is weaker than it was under rx/0, and no upstream
// data exists to make it stronger.** Every published v2 vector has a short
// ASCII key, and a types.Hash is exactly thirty-two bytes, so no v2 vector can
// be driven through Engine.Hash with its own key. What this test asserts
// instead is that Hash(key) and hashRaw(string(key[:])) are the same function
// of the same thirty-two bytes — which is what makes the officialVectorsV2
// coverage of hashRaw transfer to the interface consensus uses, and which
// catches an Engine.Hash that truncated, padded, re-encoded or hex-ified its
// key. It is not itself checked against an upstream number, because there is
// no upstream number of that shape. Under rx/0 the same gap existed and was
// closed the same way — the thirty-two-byte form of test_f's key is not the
// thirty-one bytes upstream hashed either — so this is not a regression from
// v1; it is the same weakness, now without a neighbouring vector that shares
// the key material.
//
// **No 43-byte digest or commitment is recorded here**, for the reason the
// file header gives: no upstream vector is 43 bytes, so such a constant could
// only come from this engine, and a vector produced by the implementation it
// checks restates the code in hexadecimal.
func TestTheConsensusInterfaceComputesUpstreamsFunction(t *testing.T) {
	e := mustEngine(t, Options{Keys: 2, MaxVMs: 2, V2: true})

	// (1) The engine computes rx/2, against upstream's own published v2
	// digests. If this fails, nothing else in this file means anything.
	for _, v := range officialVectorsV2 {
		sum := e.hashRaw(v.key, []byte(v.input))
		if got := hex.EncodeToString(sum[:]); got != v.want {
			t.Fatalf("upstream's rx/2 vector does not reproduce here for key %q "+
				"input %q:\n got  %s\n want %s\nthis build is not computing rx/2",
				v.key, v.input, got, v.want)
		}
	}

	// (2) rx/2 is a DIFFERENT function from rx/0, and one build computes both.
	// Upstream's test_switch is the source of both constants; it toggles the
	// flag on one VM, and this toggles it between two engines, which is the
	// shape selectEngine actually produces.
	//
	// It matters beyond tidiness: if the V2 option were silently ignored — a
	// flag ORed into the wrong variable, say — every vector in (1) would fail
	// loudly, but a build where BOTH engines were v2 would pass (1) and would
	// have quietly made randomx-v1 unrunnable. This is what sees that.
	v1 := mustEngine(t, Options{Keys: 1, MaxVMs: 1})
	const (
		switchKey   = "test key 000"
		switchInput = "This is a test"
		wantV1      = "639183aae1bf4c9a35884cb46b09cad9175f04efd7684e7262a0ac1c2f0b4e3f"
		wantV2      = "22ec6b861b3eb23686b2efbad69513c967ecfce80983df66c9c5b4fbfb4cdb6f"
	)
	sumV1 := v1.hashRaw(switchKey, []byte(switchInput))
	if got := hex.EncodeToString(sumV1[:]); got != wantV1 {
		t.Fatalf("the v1 engine does not compute rx/0:\n got  %s\n want %s", got, wantV1)
	}
	sumV2 := e.hashRaw(switchKey, []byte(switchInput))
	if got := hex.EncodeToString(sumV2[:]); got != wantV2 {
		t.Fatalf("the v2 engine does not compute rx/2:\n got  %s\n want %s", got, wantV2)
	}
	if sumV1 == sumV2 {
		t.Fatal("the v1 and v2 engines computed the same digest for the same key " +
			"and input, so RANDOMX_FLAG_V2 is not reaching the VM and one of the " +
			"two engines is silently the other")
	}

	// (3) The commitment, joined to THIS engine's hash rather than to
	// upstream's recorded intermediate. core/crypto/blake2b checks the same
	// vector against upstream's H; checking it against ours is what says the
	// two halves compose into the number a stock miner filters on.
	const wantCommitment = "133be717399046b03ae82ce8ddd9d1ee4d3ea7fca03a50dec09b6848cbb98e18"
	gotCommitment := xmrigCommitment([]byte(switchInput), sumV2)
	if got := hex.EncodeToString(gotCommitment[:]); got != wantCommitment {
		t.Fatalf("upstream's commitment vector does not reproduce here:\n got  %s\n"+
			" want %s\nthis is the value stock XMRig compares against the job "+
			"target for every rx/2 nonce", got, wantCommitment)
	}

	// (4) The consensus interface is the same function as the raw path, so
	// that (1)'s coverage transfers to Engine.Hash. See the doc comment for
	// what this does and does not anchor.
	in, err := hex.DecodeString(
		"1010e1eaf8cf067b37b5f0ee031ab23ed1755e090a3af4415830145853e2be3e1f68" +
			"21fed84dae58d00e00da5214d6c1f2d0622e0abd51f9373d04e0b0f8e6d6514d906" +
			"89721c4aac5a9bb0d")
	if err != nil {
		t.Fatal(err)
	}
	var key types.Hash
	copy(key[:], []byte{
		0x77, 0x97, 0x37, 0x3e, 0xa4, 0x63, 0x31, 0x94, 0x64, 0x0b, 0xf8, 0xd8,
		0xc3, 0xb6, 0x67, 0x24, 0xd6, 0xaa, 0x7b, 0xd2, 0xdc, 0x20, 0xe0, 0x09,
		0xdf, 0x2f, 0x8f, 0x17, 0x10, 0xab, 0xe8, 0x00,
	})
	viaInterface := e.Hash(key, in)
	viaRaw := e.hashRaw(string(key[:]), in)
	if viaInterface != viaRaw {
		t.Fatalf("Engine.Hash and Engine.hashRaw disagree for the same thirty-two "+
			"byte key:\n  Hash    %x\n  hashRaw %x\n"+
			"officialVectorsV2 checks hashRaw, and nothing in consensus calls "+
			"hashRaw. If the two are different functions then the upstream vectors "+
			"cover a path this chain never takes.",
			viaInterface, viaRaw)
	}
}

// xmrigBlob assembles a hashing blob the way stock XMRig does, from XMRig's
// own numbers and from nothing in this repository.
//
// It is a deliberate, independent re-implementation of types.Header.PoWInput,
// and every constant in it is a literal read off XMRig's source rather than a
// symbol imported from core/types. Importing types.PoWInputNonceOffset here
// would make this function agree with PoWInput by construction and the
// comparison below would be a tautology — which is precisely the shape of test
// that let a wrong layout survive before.
//
// XMRig's side of the contract, restated:
//
//	Job::setBlob   accepts a blob of at least nonceOffset() + nonceSize() bytes
//	Job::nonceOffset()  == 39 for the RandomX family
//	Job::nonceSize()    == 4  for everything but KAWPOW
//	WorkerJob::nonce()  == reinterpret_cast<uint32_t*>(blob + nonceOffset())
//
// The last line is where the little-endian-ness comes from: XMRig writes the
// nonce through a uint32_t pointer into the blob, so on every machine XMRig
// supports the four bytes at offset 39 are the nonce in the host's byte order,
// and every host XMRig supports is little-endian.
func xmrigBlob(seed types.Hash, nonce uint32) []byte {
	const (
		xmrigNonceOffset = 39 // xmrig::Job::nonceOffset(), RandomX family
		xmrigNonceSize   = 4  // xmrig::Job::nonceSize()
	)
	blob := make([]byte, xmrigNonceOffset+xmrigNonceSize)
	// A pool serves the template; here the template is thirty-two bytes of seed
	// and then zeroes up to the nonce, which is what this chain's job blob is.
	copy(blob, seed[:])
	binary.LittleEndian.PutUint32(blob[xmrigNonceOffset:], nonce)
	return blob
}

// crossVectorHeader is a header with every field distinctive, so that a blob
// assertion fails when the layout moves rather than when a field happens to be
// zero. It is not a valid block and does not need to be: PoWInput is a total
// function of a header's bytes.
func crossVectorHeader() types.Header {
	h := types.Header{
		Version: types.HeaderVersion,
		Height:  4242,
		Time:    1_767_225_600,
		PoW: types.PoWSeal{
			Nonce:      0x1F2E3D4C,
			ExtraNonce: 0xC0FFEE01,
			SeedEpoch:  2,
		},
	}
	for i := range h.ParentID {
		h.ParentID[i] = byte(0x10 + i)
	}
	for i := range h.CertRoot {
		h.CertRoot[i] = byte(0x40 + i)
	}
	for i := range h.StateRoot {
		h.StateRoot[i] = byte(0x70 + i)
	}
	return h
}

// TestTheBlobThisTreeBuildsIsTheBlobXMRigSearches is the cross-check the
// blob-layout change shipped without, and the reason this file exists.
//
// Two byte strings are built for the same (seed, nonce): one by
// types.Header.PoWInput, one by xmrigBlob from XMRig's published offsets. They
// must be identical BYTE FOR BYTE, and then hash identically. Neither side
// reads a constant from the other, so there is no edit to core/types that can
// make both move together.
//
// This is the assertion that converts "our blob is XMRig's blob" from a
// paragraph in ARCHITECTURE §12 into a fact CI defends. It catches, and was
// checked to catch, all of: a nonce written at offset 32 or 40; a nonce written
// big-endian; an eight-byte nonce spilling into the reserved gap; a blob of 40
// or 44 bytes; and a reserved gap filled with anything but zero.
func TestTheBlobThisTreeBuildsIsTheBlobXMRigSearches(t *testing.T) {
	e := mustEngine(t, Options{Keys: 1, MaxVMs: 2, V2: true})

	var key types.Hash
	copy(key[:], "zycord xmrig cross-vector key")

	h := crossVectorHeader()
	// Sweep the nonce, including both ends of the space. A single nonce would
	// let a layout that happens to agree on one value through — an eight-byte
	// nonce write, for instance, is indistinguishable from a four-byte one for
	// every nonce whose high half is zero, which is every nonce a naive test
	// picks.
	for _, nonce := range []uint32{0, 1, 0x1F2E3D4C, 0x80000000, 0xFFFFFFFF} {
		h.PoW.Nonce = nonce
		ours := h.PoWInput()
		theirs := xmrigBlob(h.PoWSeed(), nonce)

		if len(ours) != len(theirs) {
			t.Fatalf("nonce %#x: this tree builds a %d-byte blob, XMRig's offsets "+
				"describe a %d-byte one. XMRig's Job::setBlob refuses anything "+
				"shorter than nonceOffset()+nonceSize(), and hashes every byte of "+
				"whatever is longer, so a length disagreement is a different work "+
				"function.", nonce, len(ours), len(theirs))
		}
		for i := range ours {
			if ours[i] != theirs[i] {
				t.Fatalf("nonce %#x: blob byte %d is %#x here and %#x under XMRig's "+
					"layout\n  ours   %x\n  xmrig  %x\n"+
					"a stock miner hashing its blob and this node hashing ours would "+
					"compute different digests for the same header, so every share "+
					"the miner found would be rejected and every block this node "+
					"sealed would be unmineable by anyone else.",
					nonce, i, ours[i], theirs[i], ours, theirs)
			}
		}

		// Identical bytes must hash identically; asserting it costs one hash and
		// closes the (absurd, but free to exclude) possibility that the engine is
		// reading something other than the slice it was handed.
		if a, b := e.Hash(key, ours), e.Hash(key, theirs); a != b {
			t.Fatalf("nonce %#x: identical blobs hashed to %x and %x", nonce, a, b)
		}
	}
}

// TestTheReservedGapIsZeroInTheBlobXMRigWouldBeServed states the zero-pad rule
// as a fact about the bytes a miner receives rather than as a fact about this
// tree's constructor.
//
// The rule binds implementations rather than blocks — no header field reaches
// bytes 32..38, so no block a node could receive violates it and no fold rule
// could reject one — which is exactly what makes it the rule most likely to be
// got wrong by a second implementation and least likely to be caught. The
// corpus in spec/ folds blocks and a block cannot express this gap.
//
// What binds it here is that the gap is checked on BOTH sides: on the blob this
// tree builds, and on the blob assembled from XMRig's offsets, where the gap is
// zero because the template stops at byte 32 and the nonce starts at 39. An
// implementation that put a version byte, a nonce's high bytes or an
// uninitialised buffer in the gap fails the byte comparison in the test above;
// this one says which seven bytes to look at when it does.
func TestTheReservedGapIsZeroInTheBlobXMRigWouldBeServed(t *testing.T) {
	h := crossVectorHeader()
	for _, nonce := range []uint32{0, 0x80000000, 0xFFFFFFFF} {
		h.PoW.Nonce = nonce
		for i, b := range h.PoWInput()[32:39] {
			if b != 0 {
				t.Fatalf("nonce %#x: blob byte %d is %#x, want zero", nonce, 32+i, b)
			}
		}
		for i, b := range xmrigBlob(h.PoWSeed(), nonce)[32:39] {
			if b != 0 {
				t.Fatalf("nonce %#x: XMRig's blob byte %d is %#x, want zero — the gap "+
					"between a thirty-two byte template and the nonce at 39 is seven "+
					"bytes of nothing, and both sides must agree it is zero",
					nonce, 32+i, b)
			}
		}
	}
}

// xmrigCommitment is `randomx_calculate_commitment`, transcribed from
// randomx.cpp at XMRig v6.26.0:
//
//	memcpy(buf, input, inputSize);
//	memcpy(buf + inputSize, hash_in, RANDOMX_HASH_SIZE);
//	rx_blake2b_wrapper::run(com_out, RANDOMX_HASH_SIZE, buf, inputSize + RANDOMX_HASH_SIZE);
//
// Unkeyed BLAKE2b-256 over the job blob followed by the hash. Written out here
// rather than routed through pow.Commitment for the same reason xmrigBlob does
// not import types.PoWInputNonceOffset: this side of the comparison must be
// assembled from XMRig's source alone, or the comparison is a tautology.
func xmrigCommitment(blob []byte, digest types.Hash) types.Hash {
	buf := make([]byte, 0, len(blob)+32)
	buf = append(buf, blob...)
	buf = append(buf, digest[:]...)
	return types.Hash(blake2b.Sum256(buf))
}

// xmrigWins is XMRig's share test, transcribed from CpuWorker::start:
//
//	const uint64_t value = *reinterpret_cast<uint64_t*>(m_hash + (i * 32) + 24);
//	if (value < job.target())
//
// Eight bytes at offset 24, read as a native (little-endian) uint64, strictly
// less than a 64-bit target. It is written out here rather than expressed
// through u256 so that the transcription is checkable against the C++ line
// above by eye.
//
// **The parameter is named `value` rather than `digest`, and under rx/2 it is
// the COMMITMENT.** That is not a rename: it is the finding this whole change
// rests on. Twelve lines above the comparison, CpuWorker.cpp does
//
//	memcpy(m_commitment, m_hash, RANDOMX_HASH_SIZE);
//	randomx_calculate_commitment(prev_job, prev_job_size, m_hash, m_hash);
//
// and randomx_calculate_commitment writes its output over `m_hash` in place
// while reading the same buffer as its input. From that line onward `m_hash`
// holds the commitment and `m_commitment` holds the raw digest — the two names
// are inverted relative to their contents, and the Stratum submission inverts
// them again in the same direction (`result` carries the commitment,
// `commitment` carries the hash). The line below reads `m_hash`.
//
// `Tweak_V2_COMMITMENT` is set unconditionally by
// RandomX_ConfigurationMoneroV2's constructor, and RxAlgo::base() returns that
// configuration for every RX_V2 job, so there is no rx/2 job for which this is
// not what happens.
func xmrigWins(value types.Hash, target64 uint64) bool {
	return binary.LittleEndian.Uint64(value[24:32]) < target64
}

// TestXMRigsShareTestAgreesWithTheConsensusRule closes the loop: the blob is
// right and the engine is right, and this says the COMPARISON is right too.
//
// The claim ARCHITECTURE §12 makes is that a 64-bit Stratum job target is a
// clean truncation of the 256-bit consensus target under the little-endian
// rule, so that every share a stock miner finds satisfies the full check. The
// executable form of the truncation identity itself lives in core/pow; what
// lives here is the other half — that the bytes XMRig compares are the bytes
// the rule's most significant limb is made of.
//
// It is asserted over nonces where the two CAN disagree rather than over random
// ones where they almost never can. A target of all-ones in the top limb makes
// XMRig's test pass for roughly half of all digests, so a rule reading the
// digest from the wrong end disagrees on about half the nonces tried instead of
// on one in 2^64 — which is the difference between a test that fails
// immediately under mutation and one that passes for years.
func TestXMRigsShareTestAgreesWithTheConsensusRule(t *testing.T) {
	e := mustEngine(t, Options{Keys: 1, MaxVMs: 2, V2: true})

	var key types.Hash
	copy(key[:], "zycord xmrig share-test key")

	// A target whose only non-zero part is the top limb, so that the 256-bit
	// comparison is decided entirely by the eight bytes XMRig looks at and the
	// two rules are answering exactly the same question.
	const target64 = uint64(0x8000_0000_0000_0000)
	var targetBytes [32]byte
	binary.BigEndian.PutUint64(targetBytes[0:8], target64)
	target := u256.FromBytes(targetBytes)

	h := crossVectorHeader()
	h.Target = target

	var agreed, wins int
	for nonce := uint32(0); nonce < 64; nonce++ {
		h.PoW.Nonce = nonce
		blob := h.PoWInput()
		digest := e.Hash(key, blob)
		// The header carries the digest under rx/2, and the rule forms its
		// commitment from it. An honest miner fills this field; here the test
		// fills it the same way, because the alternative — leaving it zero —
		// would have the rule compare a commitment over a digest no engine
		// produced, and both sides would still be "consistent" while measuring
		// nothing about XMRig.
		h.PoWHash = digest

		// The rule, by the same route consensus takes: le256(commitment) <= Target.
		ruleWins := !u256.FromLEBytes(pow.Commitment(h)).Gt(target)
		// XMRig, by its own lines: form the commitment over the blob that
		// produced the digest, then compare its last eight bytes little-endian.
		// Its test is strictly-less against a target the pool computed; the
		// rule's is less-or-equal against the consensus target. The boundary
		// between them is one value out of 2^64 and cannot be reached by
		// sixty-four nonces, so a disagreement here is a disagreement about
		// WHICH VALUE or which END, which is the thing worth catching.
		minerWins := xmrigWins(xmrigCommitment(blob, digest), target64)

		if ruleWins != minerWins {
			t.Fatalf("nonce %d: the consensus rule says %v and XMRig's own share "+
				"test says %v for digest %x\n"+
				"the two read opposite ends of the value, or different values, and "+
				"either way they are independent — so a chain where they disagree "+
				"is a chain no stock miner can mine and no pool can proxy for.",
				nonce, ruleWins, minerWins, digest)
		}
		agreed++
		if ruleWins {
			wins++
		}
	}

	// ANTI-VACUITY. The loop above compares two booleans, and the lesson of
	// TestTheSolverAgreesWithCheckWork is that two booleans agree trivially when
	// one of the values never occurs. With the top-limb target above, each
	// reading should win about half the time; if every nonce lost, the loop
	// proved only that two functions both said no.
	if wins == 0 {
		t.Fatalf("none of the %d nonces met a target that half of all digests "+
			"should meet: this test compared %d pairs of `false` and cannot fail",
			agreed, agreed)
	}
	if wins == agreed {
		t.Fatalf("all %d nonces met the target: this test compared %d pairs of "+
			"`true` and cannot fail", agreed, agreed)
	}
}

// TestCheckWorkAcceptsWhatAStockMinerWouldSubmit runs the whole path — header,
// blob, engine, little-endian comparison — through the exported rule, for a
// nonce found the way a stock miner finds one.
//
// The nonce is searched with xmrigWins over blobs built by xmrigBlob: XMRig's
// offsets, XMRig's share test, nothing of this tree's except the seed the pool
// would have served and the engine. pow.CheckWork must then accept the header
// carrying that nonce. A tree in which it does not is a tree whose chain is
// unmineable by the only miner anybody runs.
//
// The converse is asserted too, and it is the half that carries the weight: a
// nonce the stock miner REJECTED must be rejected by CheckWork. Without it the
// test passes against a rule that accepts everything.
func TestCheckWorkAcceptsWhatAStockMinerWouldSubmit(t *testing.T) {
	e := mustEngine(t, Options{Keys: 2, MaxVMs: 2, V2: true})
	p := spec.Devnet()

	h := crossVectorHeader()
	h.Height = 4242
	h.PoW.SeedEpoch = pow.SeedEpochFor(h.Height, p)

	// The key the rule will use. The stock miner is served it as a Stratum
	// seed_hash and never derives it; that is the schedule's whole integration
	// advantage and ARCHITECTURE §12 states it.
	key := pow.KeyFor(h.Height, p)

	// A top-limb-only target, as above, so that a search terminates in a few
	// hashes and both readings are live.
	const target64 = uint64(0x0800_0000_0000_0000)
	var targetBytes [32]byte
	binary.BigEndian.PutUint64(targetBytes[0:8], target64)
	h.Target = u256.FromBytes(targetBytes)

	seed := h.PoWSeed()

	var found, rejected uint32
	var foundHash, rejectedHash types.Hash
	var haveFound, haveRejected bool
	for nonce := uint32(0); nonce < 4096; nonce++ {
		blob := xmrigBlob(seed, nonce)
		digest := e.Hash(key, blob)
		// The full stock-miner pipeline for one nonce: hash the blob, form the
		// commitment over that blob and that hash, filter on the commitment.
		if xmrigWins(xmrigCommitment(blob, digest), target64) {
			if !haveFound {
				found, foundHash, haveFound = nonce, digest, true
			}
		} else if !haveRejected {
			rejected, rejectedHash, haveRejected = nonce, digest, true
		}
		if haveFound && haveRejected {
			break
		}
	}

	// ANTI-VACUITY, and it is not a formality. If the search never finds a
	// share, everything below is skipped and the test passes having asserted
	// nothing — which is exactly how a test of a solver can rot into a test of
	// nothing when a parameter change moves the solve rate.
	if !haveFound {
		t.Fatalf("no nonce below 4096 met a target one part in 32 should meet in " +
			"about 32 tries: either the engine is not producing uniform digests or " +
			"this test has stopped being able to fail")
	}
	if !haveRejected {
		t.Fatal("every nonce below 4096 met the target; the target is not " +
			"discriminating and the acceptance below proves nothing")
	}

	// The share a stock miner would submit must be accepted by the rule.
	//
	// The digest goes into the header because that is what a miner submitting
	// this share sends: the raw hash travels in the Stratum field XMRig calls
	// `commitment` (the naming is inverted at every layer — see xmrigWins), and
	// it is what this chain's header carries so a verifier can form the
	// commitment without evaluating RandomX.
	h.PoW.Nonce = found
	h.PoWHash = foundHash
	if err := pow.CheckWork(e, h, p); err != nil {
		t.Fatalf("nonce %#x is a share stock XMRig would have submitted — its own "+
			"share test accepted it against the same target — and CheckWork "+
			"rejects it: %v\n"+
			"this is the failure that makes a chain unmineable: the miner works, "+
			"finds shares, submits them, and every one is refused.", found, err)
	}

	// And the nonce the miner discarded must be refused, or the acceptance above
	// is satisfied by a rule that accepts anything.
	h.PoW.Nonce = rejected
	h.PoWHash = rejectedHash
	if err := pow.CheckWork(e, h, p); err == nil {
		t.Fatalf("nonce %#x is one stock XMRig's own share test REJECTED against "+
			"this target, and CheckWork accepted it: the rule is not discriminating "+
			"and its acceptance of nonce %#x above means nothing", rejected, found)
	}
}

// TestTheSolverFindsWhatAStockMinerFindsForTheSameHeader compares the miner
// path against a stock miner BY NONCE rather than by verdict.
//
// pow.Solver.Try and pow.checkWorkWith share no code, which is why
// TestTheSolverAgreesWithCheckWork exists; but for most of its life that test
// compared two booleans, and for almost every nonce both are false, so a solver
// with the nonce at the wrong offset or the digest read from the wrong end
// agreed with the rule on all but a vanishing fraction of inputs and passed.
//
// This compares the SET of winning nonces against a stock miner's, over a
// target loose enough that the set is large. Two implementations that disagree
// about the blob or about the digest's byte order produce disjoint sets, not
// slightly different ones, so the comparison fails on the first nonce either
// finds.
func TestTheSolverFindsWhatAStockMinerFindsForTheSameHeader(t *testing.T) {
	e := mustEngine(t, Options{Keys: 2, MaxVMs: 2, V2: true})
	p := spec.Devnet()

	h := crossVectorHeader()
	h.Height = 4242
	h.PoW.SeedEpoch = pow.SeedEpochFor(h.Height, p)

	// A quarter of all digests win, so a hundred nonces give about twenty-five
	// members on each side.
	const target64 = uint64(0x4000_0000_0000_0000)
	var targetBytes [32]byte
	binary.BigEndian.PutUint64(targetBytes[0:8], target64)
	h.Target = u256.FromBytes(targetBytes)

	seed := h.PoWSeed()
	key := pow.KeyFor(h.Height, p)
	s := pow.NewSolver(e, h, p)

	var solverWins, minerWins int
	for nonce := uint32(0); nonce < 128; nonce++ {
		ours := s.Try(nonce)
		blob := xmrigBlob(seed, nonce)
		theirs := xmrigWins(xmrigCommitment(blob, e.Hash(key, blob)), target64)
		if ours != theirs {
			t.Fatalf("nonce %#x: this tree's solver says %v, a stock miner says %v\n"+
				"the two searched the same header against the same target and "+
				"disagree about the answer, so a miner running this solver and a "+
				"miner running XMRig would find disjoint sets of blocks.",
				nonce, ours, theirs)
		}
		if ours {
			solverWins++
		}
		if theirs {
			minerWins++
		}
	}

	// ANTI-VACUITY, and this one is the whole point of the test. The bug being
	// guarded against is a comparison of two constants: if neither side ever
	// won, the loop above compared `false` with `false` 128 times and would pass
	// against a solver reading the nonce from the wrong offset.
	if solverWins == 0 || minerWins == 0 {
		t.Fatalf("solver won %d and stock miner won %d of 128 nonces against a "+
			"target a quarter of digests should meet: this test compared constants "+
			"and cannot fail", solverWins, minerWins)
	}
	if solverWins == 128 || minerWins == 128 {
		t.Fatalf("solver won %d and stock miner won %d of 128: the target is not "+
			"discriminating and this test cannot fail", solverWins, minerWins)
	}
}
